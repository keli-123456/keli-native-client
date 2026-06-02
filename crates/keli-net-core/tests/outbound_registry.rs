use std::io::{Read, Write};
use std::time::Duration;

use keli_net_core::{
    websocket_accept_for_key, OutboundProfileError, OutboundRegistry, OutboundTarget,
    TrojanTcpOutbound, VlessTcpOutbound,
};
use keli_protocol::{Endpoint, OutboundProfile, ProxyProtocol, SecurityKind, TransportKind};

#[test]
fn registered_direct_outbound_connects_to_target() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind target");
    let port = listener.local_addr().expect("target addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept target");
        let mut request = [0; 4];
        stream.read_exact(&mut request).expect("read request");
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").expect("write response");
    });
    let mut registry = OutboundRegistry::new();
    registry.add_direct("proxy");

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("127.0.0.1", port),
            Duration::from_secs(1),
        )
        .expect("registered direct outbound should connect");
    stream.write_all(b"ping").expect("write request");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read response");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn missing_outbound_tag_is_unsupported() {
    let registry = OutboundRegistry::new();

    let error = registry
        .connect(
            "missing",
            &OutboundTarget::new("127.0.0.1", 443),
            Duration::from_millis(10),
        )
        .expect_err("missing outbound should fail");

    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
}

#[test]
fn registered_vless_tcp_outbound_writes_header_and_relays_stream() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind vless server");
    let port = listener.local_addr().expect("vless addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vless server");
        let mut request_header = [0; 34];
        stream
            .read_exact(&mut request_header)
            .expect("read vless request header");
        assert_eq!(
            request_header,
            [
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x01, 0x01, 0xbb, 0x02, 0x0b, b'e', b'x', b'a', b'm', b'p',
                b'l', b'e', b'.', b'c', b'o', b'm',
            ]
        );
        stream
            .write_all(&[0x00, 0x00])
            .expect("write vless response header");
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).expect("read relay payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write relay payload");
    });
    let mut registry = OutboundRegistry::new();
    registry.add_vless_tcp(
        "proxy",
        VlessTcpOutbound::new(
            Endpoint::new("127.0.0.1", port),
            "00112233-4455-6677-8899-aabbccddeeff",
            None,
        ),
    );

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(1),
        )
        .expect("registered vless outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registered_trojan_tcp_outbound_writes_header_and_relays_stream() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind trojan server");
    let port = listener.local_addr().expect("trojan addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept trojan server");
        let mut request_header = [0; 76];
        stream
            .read_exact(&mut request_header)
            .expect("read trojan request header");
        assert_eq!(
            &request_header[..],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x01\x03\x0bexample.com\x01\xbb\r\n"
        );
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).expect("read relay payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write relay payload");
    });
    let mut registry = OutboundRegistry::new();
    registry.add_trojan_tcp(
        "proxy",
        TrojanTcpOutbound::new(Endpoint::new("127.0.0.1", port), "password"),
    );

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(1),
        )
        .expect("registered trojan outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vless_ws_profile_connects_with_profile_transport() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind vless ws server");
    let port = listener.local_addr().expect("vless ws addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vless ws server");
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
        let request_header = read_masked_client_frame(&mut stream);
        assert_eq!(
            &request_header[..],
            &[
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x01, 0x01, 0xbb, 0x02, 0x0b, b'e', b'x', b'a', b'm', b'p',
                b'l', b'e', b'.', b'c', b'o', b'm',
            ]
        );
        stream
            .write_all(b"\x82\x02\x00\x00")
            .expect("write vless response header");
        let payload = read_masked_client_frame(&mut stream);
        assert_eq!(&payload, b"ping");
        stream.write_all(b"\x82\x04pong").expect("write pong");
    });
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vless,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::WebSocket {
            path: "/vless".to_string(),
            host: Some("edge.example".to_string()),
        },
        security: SecurityKind::None,
        credential: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
    }])
    .expect("profile registry");

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(1),
        )
        .expect("registered profile outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn tls_tcp_profiles_are_rejected_until_tls_tcp_transport_is_implemented() {
    let error = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vless,
        endpoint: Endpoint::new("example.com", 443),
        transport: TransportKind::Tcp,
        security: SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: false,
        },
        credential: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
    }])
    .expect_err("tls tcp profile should be explicit unsupported");

    assert_eq!(
        error,
        OutboundProfileError::UnsupportedTransport {
            tag: "proxy".to_string(),
            protocol: ProxyProtocol::Vless,
            transport: TransportKind::Tcp,
            security: SecurityKind::Tls {
                sni: Some("edge.example".to_string()),
                skip_verify: false,
            },
        }
    );
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut byte = [0; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read request byte");
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).expect("http request")
}

fn header_value(request: &str, name: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

fn read_masked_client_frame(stream: &mut std::net::TcpStream) -> Vec<u8> {
    let mut header = [0; 2];
    stream.read_exact(&mut header).expect("read ws header");
    assert_eq!(header[0], 0x82);
    assert!(header[1] & 0x80 != 0);
    let len = usize::from(header[1] & 0x7f);
    let mut mask = [0; 4];
    stream.read_exact(&mut mask).expect("read ws mask");
    let mut payload = vec![0; len];
    stream.read_exact(&mut payload).expect("read ws payload");
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    payload
}
