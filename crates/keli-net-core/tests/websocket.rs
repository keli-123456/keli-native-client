use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use keli_net_core::{
    websocket_accept_for_key, OutboundTarget, OwnedWebSocketClientStream, TrojanWsOutbound,
    VlessWsOutbound, WebSocketClientStream,
};
use keli_protocol::Endpoint;

#[test]
fn websocket_client_performs_upgrade_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ws server");
    let port = listener.local_addr().expect("ws addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept ws");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /answer HTTP/1.1\r\n"));
        assert!(request.contains("Host: example.com\r\n"));
        assert!(request.contains("Upgrade: websocket\r\n"));
        assert!(request.contains("Connection: Upgrade\r\n"));
        assert!(request.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(request.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
        let accept = websocket_accept_for_key("dGhlIHNhbXBsZSBub25jZQ==");
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .expect("write ws response");
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect ws server");
    WebSocketClientStream::connect_with_key(
        stream,
        "example.com",
        "/answer",
        "dGhlIHNhbXBsZSBub25jZQ==",
    )
    .expect("websocket handshake");

    server.join().expect("server thread");
}

#[test]
fn websocket_client_writes_masked_binary_frames() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ws server");
    let port = listener.local_addr().expect("ws addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept ws");
        let request = read_http_request(&mut stream);
        let key = header_value(&request, "Sec-WebSocket-Key").expect("client key");
        let accept = websocket_accept_for_key(&key);
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .expect("write ws response");

        let mut frame = [0; 10];
        stream.read_exact(&mut frame).expect("read ws frame");
        assert_eq!(frame[0], 0x82);
        assert_eq!(frame[1], 0x80 | 4);
        let mask = [frame[2], frame[3], frame[4], frame[5]];
        let payload = [
            frame[6] ^ mask[0],
            frame[7] ^ mask[1],
            frame[8] ^ mask[2],
            frame[9] ^ mask[3],
        ];
        assert_eq!(&payload, b"ping");
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect ws server");
    let mut websocket =
        WebSocketClientStream::connect(stream, "example.com", "/answer").expect("ws connect");
    websocket.write_all(b"ping").expect("write frame");

    server.join().expect("server thread");
}

#[test]
fn websocket_client_reads_binary_frames_as_plain_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ws server");
    let port = listener.local_addr().expect("ws addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept ws");
        let request = read_http_request(&mut stream);
        let key = header_value(&request, "Sec-WebSocket-Key").expect("client key");
        let accept = websocket_accept_for_key(&key);
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .expect("write ws response");
        stream.write_all(b"\x82\x04pong").expect("write frame");
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect ws server");
    let mut websocket =
        WebSocketClientStream::connect(stream, "example.com", "/answer").expect("ws connect");
    let mut payload = [0; 4];
    websocket.read_exact(&mut payload).expect("read frame");

    assert_eq!(&payload, b"pong");
    server.join().expect("server thread");
}

#[test]
fn owned_websocket_client_stream_works_without_cloneable_transport() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ws server");
    let port = listener.local_addr().expect("ws addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept ws");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /owned HTTP/1.1\r\n"));
        let key = header_value(&request, "Sec-WebSocket-Key").expect("client key");
        let accept = websocket_accept_for_key(&key);
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .expect("write ws response");
        let payload = read_masked_client_frame(&mut stream);
        assert_eq!(&payload, b"ping");
        stream.write_all(b"\x82\x04pong").expect("write pong");
    });
    let tcp = TcpStream::connect(("127.0.0.1", port)).expect("connect ws server");
    let mut stream =
        OwnedWebSocketClientStream::connect(NonCloneTcpStream(tcp), "edge.example", "/owned")
            .expect("owned ws connect");

    stream.write_all(b"ping").expect("write ping");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read pong");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn trojan_ws_outbound_sends_trojan_header_inside_websocket_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan ws server");
    let port = listener.local_addr().expect("trojan ws addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept ws");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /answer HTTP/1.1\r\n"));
        assert!(request.contains("Host: edge.example\r\n"));
        let key = header_value(&request, "Sec-WebSocket-Key").expect("client key");
        let accept = websocket_accept_for_key(&key);
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .expect("write ws response");

        let payload = read_masked_client_frame(&mut stream);
        assert_eq!(
            &payload[..],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x01\x03\x0bexample.com\x01\xbb\r\n"
        );
    });
    let outbound = TrojanWsOutbound::new(
        Endpoint::new("127.0.0.1", port),
        "edge.example",
        "/answer",
        "password",
    );

    outbound
        .connect(
            &OutboundTarget::new("example.com", 443),
            std::time::Duration::from_secs(1),
        )
        .expect("trojan ws connect");

    server.join().expect("server thread");
}

#[test]
fn trojan_ws_outbound_relays_udp_inside_websocket_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan ws udp server");
    let port = listener.local_addr().expect("trojan ws udp addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept trojan ws udp");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /answer HTTP/1.1\r\n"));
        assert!(request.contains("Host: edge.example\r\n"));
        let key = header_value(&request, "Sec-WebSocket-Key").expect("client key");
        let accept = websocket_accept_for_key(&key);
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .expect("write ws response");

        let request_header = read_masked_client_frame(&mut stream);
        assert_eq!(
            &request_header,
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x03\x01\x7f\x00\x00\x01\x005\r\n"
        );
        let request_payload = read_masked_client_frame(&mut stream);
        assert_eq!(
            &request_payload,
            b"\x01\x7f\x00\x00\x01\x005\x00\x04\r\nping"
        );
        stream
            .write_all(b"\x82\x0f\x01\x7f\x00\x00\x01\x005\x00\x04\r\npong")
            .expect("write trojan udp response packet");
    });
    let outbound = TrojanWsOutbound::new(
        Endpoint::new("127.0.0.1", port),
        "edge.example",
        "/answer",
        "password",
    );

    let response = outbound
        .relay_udp_datagram(
            &OutboundTarget::new("127.0.0.1", 53),
            b"ping",
            std::time::Duration::from_secs(1),
        )
        .expect("trojan ws UDP relay");

    assert_eq!(
        response.source,
        "127.0.0.1:53".parse().expect("response source")
    );
    assert_eq!(response.payload, b"pong");
    server.join().expect("server thread");
}

#[test]
fn vless_ws_outbound_sends_vless_header_inside_websocket_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vless ws server");
    let port = listener.local_addr().expect("vless ws addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept ws");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /vless HTTP/1.1\r\n"));
        assert!(request.contains("Host: edge.example\r\n"));
        let key = header_value(&request, "Sec-WebSocket-Key").expect("client key");
        let accept = websocket_accept_for_key(&key);
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .expect("write ws response");

        let payload = read_masked_client_frame(&mut stream);
        assert_eq!(
            &payload[..],
            &[
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x01, 0x01, 0xbb, 0x02, 0x0b, b'e', b'x', b'a', b'm', b'p',
                b'l', b'e', b'.', b'c', b'o', b'm',
            ]
        );
        stream
            .write_all(b"\x82\x02\x00\x00")
            .expect("write vless response header");
    });
    let outbound = VlessWsOutbound::new(
        Endpoint::new("127.0.0.1", port),
        "edge.example",
        "/vless",
        "00112233-4455-6677-8899-aabbccddeeff",
        None,
    );

    outbound
        .connect(
            &OutboundTarget::new("example.com", 443),
            std::time::Duration::from_secs(1),
        )
        .expect("vless ws connect");

    server.join().expect("server thread");
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut byte = [0; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read request byte");
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).expect("request utf8")
}

fn header_value(request: &str, header: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case(header)
            .then(|| value.trim().to_string())
    })
}

fn read_masked_client_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0; 2];
    stream.read_exact(&mut header).expect("read frame header");
    assert_eq!(header[0], 0x82);
    assert!(header[1] & 0x80 != 0);
    let payload_len = match header[1] & 0x7f {
        len @ 0..=125 => usize::from(len),
        126 => {
            let mut bytes = [0; 2];
            stream.read_exact(&mut bytes).expect("read extended len");
            usize::from(u16::from_be_bytes(bytes))
        }
        127 => panic!("test payload should not use 64-bit length"),
        _ => unreachable!(),
    };
    let mut mask = [0; 4];
    stream.read_exact(&mut mask).expect("read mask");
    let mut payload = vec![0; payload_len];
    stream.read_exact(&mut payload).expect("read payload");
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    payload
}

struct NonCloneTcpStream(TcpStream);

impl Read for NonCloneTcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buffer)
    }
}

impl Write for NonCloneTcpStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
