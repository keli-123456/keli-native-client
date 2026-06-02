use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use keli_net_core::{websocket_accept_for_key, OutboundRegistry, OutboundTarget};
use keli_protocol::{Endpoint, OutboundProfile, ProxyProtocol, SecurityKind, TransportKind};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[test]
fn registry_from_vless_tls_ws_profile_relays_over_tls_websocket() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls ws server");
    let port = listener.local_addr().expect("tls ws addr").port();
    let server_config = tls_server_config();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().expect("accept tls ws");
        let connection = rustls::ServerConnection::new(server_config).expect("server tls");
        let mut stream = rustls::StreamOwned::new(connection, tcp);
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
        security: SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: true,
        },
        credential: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
        cipher: None,
        flow: None,
    }])
    .expect("profile registry");

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(1),
        )
        .expect("registered tls ws outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_trojan_tls_ws_profile_relays_over_tls_websocket() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan tls ws server");
    let port = listener.local_addr().expect("trojan tls ws addr").port();
    let server_config = tls_server_config();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().expect("accept trojan tls ws");
        let connection = rustls::ServerConnection::new(server_config).expect("server tls");
        let mut stream = rustls::StreamOwned::new(connection, tcp);
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /trojan HTTP/1.1\r\n"));
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
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x01\x03\x0bexample.com\x01\xbb\r\n"
        );
        let payload = read_masked_client_frame(&mut stream);
        assert_eq!(&payload, b"ping");
        stream.write_all(b"\x82\x04pong").expect("write pong");
    });
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Trojan,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::WebSocket {
            path: "/trojan".to_string(),
            host: Some("edge.example".to_string()),
        },
        security: SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: true,
        },
        credential: "password".to_string(),
        cipher: None,
        flow: None,
    }])
    .expect("profile registry");

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(1),
        )
        .expect("registered tls ws outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

fn tls_server_config() -> Arc<rustls::ServerConfig> {
    let cert = generate_simple_self_signed(vec!["edge.example".to_string()]).expect("self cert");
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    Arc::new(
        rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("tls versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server config"),
    )
}

fn read_http_request(stream: &mut impl Read) -> String {
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

fn read_masked_client_frame(stream: &mut impl Read) -> Vec<u8> {
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
