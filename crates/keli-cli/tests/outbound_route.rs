use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use keli_cli::{handle_mixed_connection_with_routes, MixedProxyRuntime};
use keli_net_core::{
    websocket_accept_for_key, OutboundRegistry, RouteAction, RouteEngine, TrojanWsOutbound,
    VlessWsOutbound,
};
use keli_protocol::Endpoint;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[test]
fn http_connect_uses_registered_outbound_route() {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind target");
    let target_port = target.local_addr().expect("target addr").port();
    let target_thread = thread::spawn(move || {
        let (mut stream, _) = target.accept().expect("accept target");
        let mut request = [0; 4];
        stream.read_exact(&mut request).expect("read request");
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").expect("write response");
        stream.shutdown(Shutdown::Both).ok();
    });

    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let mut outbounds = OutboundRegistry::new();
    outbounds.add_direct("proxy");
    let runtime = MixedProxyRuntime::with_routes_and_outbounds(
        RouteEngine::new(RouteAction::Outbound("proxy".to_string())),
        outbounds,
    );
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_mixed_connection_with_routes(&mut stream, &runtime).expect("handle outbound route");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    write!(
        client,
        "CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
    )
    .expect("write CONNECT");

    let mut connect_response = Vec::new();
    read_until_header_end(&mut client, &mut connect_response);
    assert_eq!(
        connect_response,
        b"HTTP/1.1 200 Connection Established\r\n\r\n"
    );

    client.write_all(b"ping").expect("write ping");
    let mut response = [0; 4];
    client.read_exact(&mut response).expect("read pong");
    assert_eq!(&response, b"pong");
    client.shutdown(Shutdown::Both).ok();

    inbound_thread.join().expect("inbound thread");
    target_thread.join().expect("target thread");
}

#[test]
fn http_connect_relays_through_registered_trojan_ws_route() {
    let trojan_ws = TcpListener::bind("127.0.0.1:0").expect("bind trojan ws");
    let trojan_ws_port = trojan_ws.local_addr().expect("trojan ws addr").port();
    let trojan_ws_thread = thread::spawn(move || {
        let (mut stream, _) = trojan_ws.accept().expect("accept trojan ws");
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

        let trojan_header = read_masked_client_frame(&mut stream);
        assert_eq!(
            &trojan_header[..],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x01\x03\x0bexample.com\x01\xbb\r\n"
        );
        let payload = read_masked_client_frame(&mut stream);
        assert_eq!(&payload, b"ping");
        stream.write_all(b"\x82\x04pong").expect("write pong frame");
    });

    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let mut outbounds = OutboundRegistry::new();
    outbounds.add_trojan_ws(
        "proxy",
        TrojanWsOutbound::new(
            Endpoint::new("127.0.0.1", trojan_ws_port),
            "edge.example",
            "/answer",
            "password",
        ),
    );
    let runtime = MixedProxyRuntime::with_routes_and_outbounds(
        RouteEngine::new(RouteAction::Outbound("proxy".to_string())),
        outbounds,
    );
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_mixed_connection_with_routes(&mut stream, &runtime)
            .expect("handle trojan ws outbound route");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    write!(
        client,
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
    )
    .expect("write CONNECT");

    let mut connect_response = Vec::new();
    read_until_header_end(&mut client, &mut connect_response);
    assert_eq!(
        connect_response,
        b"HTTP/1.1 200 Connection Established\r\n\r\n"
    );

    client.write_all(b"ping").expect("write ping");
    let mut response = [0; 4];
    client.read_exact(&mut response).expect("read pong");
    assert_eq!(&response, b"pong");
    client.shutdown(Shutdown::Both).ok();

    inbound_thread.join().expect("inbound thread");
    trojan_ws_thread.join().expect("trojan ws thread");
}

#[test]
fn mixed_socks5_connect_relays_through_registered_trojan_ws_route() {
    let trojan_ws = TcpListener::bind("127.0.0.1:0").expect("bind trojan ws");
    let trojan_ws_port = trojan_ws.local_addr().expect("trojan ws addr").port();
    let trojan_ws_thread = thread::spawn(move || {
        let (mut stream, _) = trojan_ws.accept().expect("accept trojan ws");
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

        let trojan_header = read_masked_client_frame(&mut stream);
        assert_eq!(
            &trojan_header[..],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x01\x03\x0bexample.com\x01\xbb\r\n"
        );
        let payload = read_masked_client_frame(&mut stream);
        assert_eq!(&payload, b"ping");
        stream.write_all(b"\x82\x04pong").expect("write pong frame");
    });

    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let mut outbounds = OutboundRegistry::new();
    outbounds.add_trojan_ws(
        "proxy",
        TrojanWsOutbound::new(
            Endpoint::new("127.0.0.1", trojan_ws_port),
            "edge.example",
            "/answer",
            "password",
        ),
    );
    let runtime = MixedProxyRuntime::with_routes_and_outbounds(
        RouteEngine::new(RouteAction::Outbound("proxy".to_string())),
        outbounds,
    );
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_mixed_connection_with_routes(&mut stream, &runtime)
            .expect("handle trojan ws socks5 route");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    client.write_all(&[0x05, 0x01, 0x00]).expect("write hello");
    let mut hello = [0; 2];
    client.read_exact(&mut hello).expect("read hello response");
    assert_eq!(hello, [0x05, 0x00]);
    client
        .write_all(&[
            0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
            b'o', b'm', 0x01, 0xbb,
        ])
        .expect("write socks5 connect");
    let mut connect_response = [0; 10];
    client
        .read_exact(&mut connect_response)
        .expect("read connect response");
    assert_eq!(connect_response, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

    client.write_all(b"ping").expect("write ping");
    let mut response = [0; 4];
    client.read_exact(&mut response).expect("read pong");
    assert_eq!(&response, b"pong");
    client.shutdown(Shutdown::Both).ok();

    inbound_thread.join().expect("inbound thread");
    trojan_ws_thread.join().expect("trojan ws thread");
}

#[test]
fn http_connect_relays_through_registered_vless_ws_route() {
    let vless_ws = TcpListener::bind("127.0.0.1:0").expect("bind vless ws");
    let vless_ws_port = vless_ws.local_addr().expect("vless ws addr").port();
    let vless_ws_thread = thread::spawn(move || {
        let (mut stream, _) = vless_ws.accept().expect("accept vless ws");
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

        let vless_header = read_masked_client_frame(&mut stream);
        assert_eq!(
            &vless_header[..],
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
        stream.write_all(b"\x82\x04pong").expect("write pong frame");
    });

    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let mut outbounds = OutboundRegistry::new();
    outbounds.add_vless_ws(
        "proxy",
        VlessWsOutbound::new(
            Endpoint::new("127.0.0.1", vless_ws_port),
            "edge.example",
            "/vless",
            "00112233-4455-6677-8899-aabbccddeeff",
            None,
        ),
    );
    let runtime = MixedProxyRuntime::with_routes_and_outbounds(
        RouteEngine::new(RouteAction::Outbound("proxy".to_string())),
        outbounds,
    );
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_mixed_connection_with_routes(&mut stream, &runtime)
            .expect("handle vless ws outbound route");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    write!(
        client,
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
    )
    .expect("write CONNECT");

    let mut connect_response = Vec::new();
    read_until_header_end(&mut client, &mut connect_response);
    assert_eq!(
        connect_response,
        b"HTTP/1.1 200 Connection Established\r\n\r\n"
    );

    client.write_all(b"ping").expect("write ping");
    let mut response = [0; 4];
    client.read_exact(&mut response).expect("read pong");
    assert_eq!(&response, b"pong");
    client.shutdown(Shutdown::Both).ok();

    inbound_thread.join().expect("inbound thread");
    vless_ws_thread.join().expect("vless ws thread");
}

#[test]
fn mixed_socks5_connect_relays_through_registered_vless_ws_route() {
    let vless_ws = TcpListener::bind("127.0.0.1:0").expect("bind vless ws");
    let vless_ws_port = vless_ws.local_addr().expect("vless ws addr").port();
    let vless_ws_thread = thread::spawn(move || {
        let (mut stream, _) = vless_ws.accept().expect("accept vless ws");
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

        let vless_header = read_masked_client_frame(&mut stream);
        assert_eq!(
            &vless_header[..],
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
        stream.write_all(b"\x82\x04pong").expect("write pong frame");
    });

    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let mut outbounds = OutboundRegistry::new();
    outbounds.add_vless_ws(
        "proxy",
        VlessWsOutbound::new(
            Endpoint::new("127.0.0.1", vless_ws_port),
            "edge.example",
            "/vless",
            "00112233-4455-6677-8899-aabbccddeeff",
            None,
        ),
    );
    let runtime = MixedProxyRuntime::with_routes_and_outbounds(
        RouteEngine::new(RouteAction::Outbound("proxy".to_string())),
        outbounds,
    );
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_mixed_connection_with_routes(&mut stream, &runtime)
            .expect("handle vless ws socks5 route");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    client.write_all(&[0x05, 0x01, 0x00]).expect("write hello");
    let mut hello = [0; 2];
    client.read_exact(&mut hello).expect("read hello response");
    assert_eq!(hello, [0x05, 0x00]);
    client
        .write_all(&[
            0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
            b'o', b'm', 0x01, 0xbb,
        ])
        .expect("write socks5 connect");
    let mut connect_response = [0; 10];
    client
        .read_exact(&mut connect_response)
        .expect("read connect response");
    assert_eq!(connect_response, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

    client.write_all(b"ping").expect("write ping");
    let mut response = [0; 4];
    client.read_exact(&mut response).expect("read pong");
    assert_eq!(&response, b"pong");
    client.shutdown(Shutdown::Both).ok();

    inbound_thread.join().expect("inbound thread");
    vless_ws_thread.join().expect("vless ws thread");
}

#[test]
fn http_connect_relays_through_registered_hy2_route() {
    let (hy2_addr, hy2_thread) = spawn_hy2_echo_server();
    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let outbounds = OutboundRegistry::from_profiles([keli_protocol::OutboundProfile {
        tag: "proxy".to_string(),
        protocol: keli_protocol::ProxyProtocol::Hy2,
        endpoint: Endpoint::new("127.0.0.1", hy2_addr.port()),
        transport: keli_protocol::TransportKind::Quic {
            security: None,
            key: None,
            header_type: None,
        },
        security: keli_protocol::SecurityKind::Tls {
            sni: Some("localhost".to_string()),
            skip_verify: true,
        },
        credential: "secret".to_string(),
        cipher: None,
        flow: None,
    }])
    .expect("build HY2 outbound registry");
    let runtime = MixedProxyRuntime::with_routes_and_outbounds(
        RouteEngine::new(RouteAction::Outbound("proxy".to_string())),
        outbounds,
    );
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_mixed_connection_with_routes(&mut stream, &runtime)
            .expect("handle HY2 outbound route");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    write!(
        client,
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
    )
    .expect("write CONNECT");

    let mut connect_response = Vec::new();
    read_until_header_end(&mut client, &mut connect_response);
    assert_eq!(
        connect_response,
        b"HTTP/1.1 200 Connection Established\r\n\r\n"
    );

    client.write_all(b"ping").expect("write ping");
    let mut response = [0; 4];
    client.read_exact(&mut response).expect("read pong");
    assert_eq!(&response, b"pong");
    client.shutdown(Shutdown::Both).ok();

    inbound_thread.join().expect("inbound thread");
    hy2_thread.join().expect("hy2 thread");
}

#[test]
fn http_connect_relays_through_registered_tuic_route() {
    let (tuic_addr, tuic_thread) = spawn_tuic_echo_server();
    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let outbounds = OutboundRegistry::from_profiles([keli_protocol::OutboundProfile {
        tag: "proxy".to_string(),
        protocol: keli_protocol::ProxyProtocol::Tuic,
        endpoint: Endpoint::new("127.0.0.1", tuic_addr.port()),
        transport: keli_protocol::TransportKind::Quic {
            security: None,
            key: None,
            header_type: None,
        },
        security: keli_protocol::SecurityKind::Tls {
            sni: Some("localhost".to_string()),
            skip_verify: true,
        },
        credential: "00112233-4455-6677-8899-aabbccddeeff:secret".to_string(),
        cipher: None,
        flow: None,
    }])
    .expect("build TUIC outbound registry");
    let runtime = MixedProxyRuntime::with_routes_and_outbounds(
        RouteEngine::new(RouteAction::Outbound("proxy".to_string())),
        outbounds,
    );
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_mixed_connection_with_routes(&mut stream, &runtime)
            .expect("handle TUIC outbound route");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    write!(
        client,
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
    )
    .expect("write CONNECT");

    let mut connect_response = Vec::new();
    read_until_header_end(&mut client, &mut connect_response);
    assert_eq!(
        connect_response,
        b"HTTP/1.1 200 Connection Established\r\n\r\n"
    );

    client.write_all(b"ping").expect("write ping");
    let mut response = [0; 4];
    client.read_exact(&mut response).expect("read pong");
    assert_eq!(&response, b"pong");
    client.shutdown(Shutdown::Both).ok();

    inbound_thread.join().expect("inbound thread");
    tuic_thread.join().expect("tuic thread");
}

fn read_until_header_end(stream: &mut TcpStream, output: &mut Vec<u8>) {
    let mut byte = [0; 1];
    while !output.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read response byte");
        output.push(byte[0]);
    }
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

fn spawn_hy2_echo_server() -> (SocketAddr, thread::JoinHandle<()>) {
    let (addr_tx, addr_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build HY2 test runtime");
        runtime.block_on(async move {
            let endpoint = quinn::Endpoint::server(
                hy2_h3_test_server_config(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            )
            .expect("bind HY2 test server");
            addr_tx
                .send(endpoint.local_addr().expect("HY2 test server addr"))
                .expect("send HY2 addr");
            let incoming = endpoint.accept().await.expect("accept HY2 connection");
            let connection = incoming.await.expect("HY2 QUIC connection");
            let mut h3_connection: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
                h3::server::builder()
                    .build(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .expect("HY2 H3 server connection");
            let resolver = h3_connection
                .accept()
                .await
                .expect("accept HY2 auth")
                .expect("HY2 auth request exists");
            let (request, mut auth_stream) =
                resolver.resolve_request().await.expect("resolve HY2 auth");
            assert_eq!(request.headers()["Hysteria-Auth"], "secret");
            auth_stream
                .send_response(http::Response::builder().status(233).body(()).unwrap())
                .await
                .expect("send HY2 auth OK");
            auth_stream.finish().await.expect("finish HY2 auth OK");
            let (mut send, mut recv) = connection.accept_bi().await.expect("accept HY2 TCP");
            let mut request = [0; 19];
            recv.read_exact(&mut request)
                .await
                .expect("read HY2 TCP request");
            assert_eq!(
                request,
                [
                    0x44, 0x01, 0x0f, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
                    b'm', b':', b'4', b'4', b'3', 0x00,
                ]
            );
            send.write_all(&[0x00, 0x00, 0x00])
                .await
                .expect("write HY2 TCP OK response");
            let mut payload = [0; 4];
            recv.read_exact(&mut payload)
                .await
                .expect("read HY2 payload");
            assert_eq!(&payload, b"ping");
            send.write_all(b"pong").await.expect("write HY2 response");
            send.finish().expect("finish HY2 response stream");
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
    });
    (addr_rx.recv().expect("receive HY2 addr"), handle)
}

fn spawn_tuic_echo_server() -> (SocketAddr, thread::JoinHandle<()>) {
    let (addr_tx, addr_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build TUIC test runtime");
        runtime.block_on(async move {
            let endpoint = quinn::Endpoint::server(
                hy2_h3_test_server_config(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            )
            .expect("bind TUIC test server");
            addr_tx
                .send(endpoint.local_addr().expect("TUIC test server addr"))
                .expect("send TUIC addr");
            let incoming = endpoint.accept().await.expect("accept TUIC connection");
            let connection = incoming.await.expect("TUIC QUIC connection");
            let mut auth_recv = connection.accept_uni().await.expect("accept TUIC auth");
            let auth = auth_recv
                .read_to_end(64)
                .await
                .expect("read TUIC auth command");
            let expected_auth = keli_net_core::tuic_authenticate_command(
                &connection,
                "00112233-4455-6677-8899-aabbccddeeff",
                "secret",
            )
            .expect("expected TUIC auth");
            assert_eq!(auth, expected_auth);
            let (mut send, mut recv) = connection.accept_bi().await.expect("accept TUIC TCP");
            let expected_connect =
                keli_protocol::encode_tuic_connect_command(&Endpoint::new("example.com", 443))
                    .expect("expected TUIC connect");
            let mut connect = vec![0; expected_connect.len()];
            recv.read_exact(&mut connect)
                .await
                .expect("read TUIC connect command");
            assert_eq!(connect, expected_connect);
            let mut payload = [0; 4];
            recv.read_exact(&mut payload)
                .await
                .expect("read TUIC payload");
            assert_eq!(&payload, b"ping");
            send.write_all(b"pong").await.expect("write TUIC response");
            send.finish().expect("finish TUIC response stream");
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
    });
    (addr_rx.recv().expect("receive TUIC addr"), handle)
}

fn hy2_h3_test_server_config() -> quinn::ServerConfig {
    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let mut tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("server protocol versions")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .expect("server config");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("quic server config"),
    ))
}
