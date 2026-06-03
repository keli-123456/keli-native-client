use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use keli_net_core::{OutboundRegistry, OutboundTarget};
use keli_protocol::{Endpoint, OutboundProfile, ProxyProtocol, SecurityKind, TransportKind};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

#[test]
fn registry_from_trojan_tls_tcp_profile_relays_over_tls() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan tls tcp server");
    let port = listener.local_addr().expect("server addr").port();
    let server_config = tls_server_config();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept trojan tls tcp");
        let connection = rustls::ServerConnection::new(server_config).expect("server tls");
        let mut stream = rustls::StreamOwned::new(connection, stream);
        let mut request_header = [0; 76];
        stream
            .read_exact(&mut request_header)
            .expect("read trojan request header");
        assert_eq!(
            &request_header[..],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x01\x03\x0bexample.com\x01\xbb\r\n"
        );
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).expect("read payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write pong");
    });
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Trojan,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Tcp,
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
        .expect("connect trojan tls tcp");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read response");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vless_tls_tcp_profile_relays_over_tls() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vless tls tcp server");
    let port = listener.local_addr().expect("server addr").port();
    let server_config = tls_server_config();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept vless tls tcp");
        let connection = rustls::ServerConnection::new(server_config).expect("server tls");
        let mut stream = rustls::StreamOwned::new(connection, stream);
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
        stream.read_exact(&mut payload).expect("read payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write pong");
    });
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vless,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Tcp,
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
        .expect("connect vless tls tcp");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read response");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_anytls_profile_authenticates_and_relays_single_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind anytls server");
    let port = listener.local_addr().expect("server addr").port();
    let server_config = tls_server_config();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept anytls tcp");
        let connection = rustls::ServerConnection::new(server_config).expect("server tls");
        let mut stream = rustls::StreamOwned::new(connection, stream);

        assert_anytls_auth(&mut stream, "secret");
        let (cmd, sid, settings) = read_anytls_frame(&mut stream);
        assert_eq!((cmd, sid), (4, 0));
        let settings = String::from_utf8(settings).expect("settings utf8");
        assert!(settings.contains("v=2"));
        assert!(settings.contains("client=keli-native-client/"));
        assert!(settings.contains("padding-md5="));

        let (cmd, sid, data) = read_anytls_frame(&mut stream);
        assert_eq!((cmd, sid, data.len()), (1, 1, 0));

        let (cmd, sid, target) = read_anytls_frame(&mut stream);
        assert_eq!((cmd, sid), (2, 1));
        assert_eq!(&target, b"\x03\x0bexample.com\x01\xbb");

        let (cmd, sid, payload) = read_anytls_frame(&mut stream);
        assert_eq!((cmd, sid), (2, 1));
        assert_eq!(&payload, b"ping");

        write_anytls_frame(&mut stream, 10, 0, b"v=2");
        write_anytls_frame(&mut stream, 7, 1, b"");
        write_anytls_frame(&mut stream, 2, 1, b"pong");
    });
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::AnyTls,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Tcp,
        security: SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: true,
        },
        credential: "secret".to_string(),
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
        .expect("connect anytls");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read response");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

fn tls_server_config() -> Arc<rustls::ServerConfig> {
    let cert = generate_simple_self_signed(vec!["edge.example".to_string()]).expect("cert");
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    Arc::new(
        rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("server protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server config"),
    )
}

fn assert_anytls_auth(stream: &mut impl Read, password: &str) {
    let mut header = [0; 34];
    stream.read_exact(&mut header).expect("read anytls auth");
    let expected = Sha256::digest(password.as_bytes());
    assert_eq!(&header[..32], expected.as_slice());
    let padding_len = u16::from_be_bytes([header[32], header[33]]) as usize;
    assert_eq!(padding_len, 30);
    let mut padding = vec![0; padding_len];
    stream
        .read_exact(&mut padding)
        .expect("read anytls auth padding");
}

fn read_anytls_frame(stream: &mut impl Read) -> (u8, u32, Vec<u8>) {
    let mut header = [0; 7];
    stream
        .read_exact(&mut header)
        .expect("read anytls frame header");
    let cmd = header[0];
    let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0; len];
    stream
        .read_exact(&mut data)
        .expect("read anytls frame data");
    (cmd, sid, data)
}

fn write_anytls_frame(stream: &mut impl Write, cmd: u8, sid: u32, data: &[u8]) {
    let mut header = [0; 7];
    header[0] = cmd;
    header[1..5].copy_from_slice(&sid.to_be_bytes());
    header[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    stream.write_all(&header).expect("write anytls header");
    stream.write_all(data).expect("write anytls data");
}
