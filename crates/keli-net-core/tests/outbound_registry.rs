use std::io::{Read, Write};
use std::str::FromStr;
use std::time::Duration;

use keli_net_core::{
    websocket_accept_for_key, OutboundProfileError, OutboundRegistry, OutboundTarget,
    ShadowsocksTcpOutbound, TrojanTcpOutbound, VlessTcpOutbound,
};
use keli_protocol::{Endpoint, OutboundProfile, ProxyProtocol, SecurityKind, TransportKind};
use shadowsocks_crypto::kind::CipherKind;
use shadowsocks_crypto::v1::{openssl_bytes_to_key, Cipher};

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
fn registered_direct_udp_outbound_relays_datagram() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp target");
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("target timeout");
    let port = socket.local_addr().expect("target addr").port();
    let server = std::thread::spawn(move || {
        let mut request = [0; 1500];
        let (size, from) = socket.recv_from(&mut request).expect("read udp request");
        assert_eq!(&request[..size], b"ping");
        socket.send_to(b"pong", from).expect("write udp response");
    });
    let mut registry = OutboundRegistry::new();
    registry.add_direct("proxy");

    let response = registry
        .relay_udp_datagram(
            "proxy",
            &OutboundTarget::new("127.0.0.1", port),
            b"ping",
            Duration::from_secs(1),
        )
        .expect("registered direct UDP outbound should relay");

    assert_eq!(
        response.source.ip(),
        "127.0.0.1".parse::<std::net::IpAddr>().expect("valid IP")
    );
    assert_eq!(response.source.port(), port);
    assert_eq!(response.payload, b"pong");
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
fn registered_shadowsocks_tcp_outbound_encrypts_header_and_relays_stream() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ss server");
    let port = listener.local_addr().expect("ss addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept ss server");
        let kind = CipherKind::from_str("aes-256-gcm").expect("cipher");
        let key = shadowsocks_key(kind, "secret");

        let mut client_salt = vec![0; kind.salt_len()];
        stream
            .read_exact(&mut client_salt)
            .expect("read client salt");
        let mut client_cipher = Cipher::new(kind, &key, &client_salt);

        let request_header = read_ss_chunk(&mut stream, &mut client_cipher);
        assert_eq!(
            request_header, b"\x03\x0bexample.com\x01\xbb",
            "SS request starts with SOCKS5-style target address"
        );

        let payload = read_ss_chunk(&mut stream, &mut client_cipher);
        assert_eq!(&payload, b"ping");

        let server_salt = vec![7; kind.salt_len()];
        stream.write_all(&server_salt).expect("write server salt");
        let mut server_cipher = Cipher::new(kind, &key, &server_salt);
        write_ss_chunk(&mut stream, &mut server_cipher, b"pong");
    });
    let mut registry = OutboundRegistry::new();
    registry.add_shadowsocks_tcp(
        "proxy",
        ShadowsocksTcpOutbound::new(Endpoint::new("127.0.0.1", port), "aes-256-gcm", "secret"),
    );

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(1),
        )
        .expect("registered shadowsocks outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registered_shadowsocks_udp_outbound_encrypts_datagram_and_relays_response() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ss udp server");
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("ss udp timeout");
    let port = socket.local_addr().expect("ss udp addr").port();
    let server = std::thread::spawn(move || {
        let kind = CipherKind::from_str("aes-256-gcm").expect("cipher");
        let key = shadowsocks_key(kind, "secret");
        let mut request = [0; 1500];
        let (size, from) = socket.recv_from(&mut request).expect("read ss udp request");
        let plaintext = decrypt_ss_udp_packet(kind, &key, &request[..size]);
        assert_eq!(
            plaintext, b"\x03\x0bexample.com\x005ping",
            "SS UDP request starts with SOCKS5-style target address"
        );

        let response =
            encrypt_ss_udp_packet(kind, &key, &[8; 32], b"\x01\x7f\x00\x00\x01\x005pong");
        socket
            .send_to(&response, from)
            .expect("write ss udp response");
    });
    let mut registry = OutboundRegistry::new();
    registry.add_shadowsocks_tcp(
        "proxy",
        ShadowsocksTcpOutbound::new(Endpoint::new("127.0.0.1", port), "aes-256-gcm", "secret"),
    );

    let response = registry
        .relay_udp_datagram(
            "proxy",
            &OutboundTarget::new("example.com", 53),
            b"ping",
            Duration::from_secs(1),
        )
        .expect("registered shadowsocks UDP outbound should relay");

    assert_eq!(
        response.source,
        "127.0.0.1:53".parse().expect("response source")
    );
    assert_eq!(response.payload, b"pong");
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
        .expect("registered profile outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vless_tcp_profile_preserves_flow() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind vless server");
    let port = listener.local_addr().expect("vless addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vless server");
        let mut request_header = [0; 52];
        stream
            .read_exact(&mut request_header)
            .expect("read vless request header");
        assert_eq!(
            &request_header[..37],
            b"\x00\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x12\x0a\x10xtls-rprx-vision\x01"
        );
        assert_eq!(&request_header[37..], b"\x01\xbb\x02\x0bexample.com");
        stream
            .write_all(&[0x00, 0x00])
            .expect("write vless response header");
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).expect("read relay payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write relay payload");
    });
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vless,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Tcp,
        security: SecurityKind::None,
        credential: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
        cipher: None,
        flow: Some("xtls-rprx-vision".to_string()),
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
fn unsupported_transports_report_security_context() {
    let error = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vless,
        endpoint: Endpoint::new("example.com", 443),
        transport: TransportKind::Quic,
        security: SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: false,
        },
        credential: "00112233-4455-6677-8899-aabbccddeeff".to_string(),
        cipher: None,
        flow: None,
    }])
    .expect_err("vless quic profile should be explicit unsupported");

    assert_eq!(
        error,
        OutboundProfileError::UnsupportedTransport {
            tag: "proxy".to_string(),
            protocol: ProxyProtocol::Vless,
            transport: TransportKind::Quic,
            security: SecurityKind::Tls {
                sni: Some("edge.example".to_string()),
                skip_verify: false,
            },
        }
    );
}

#[test]
fn hy2_outbound_from_profile_preserves_server_auth_and_sni() {
    let outbound = keli_net_core::Hy2Outbound::from_profile(OutboundProfile {
        tag: "hy2".to_string(),
        protocol: ProxyProtocol::Hy2,
        endpoint: Endpoint::new("hy2.example.com", 443),
        transport: TransportKind::Quic,
        security: SecurityKind::Tls {
            sni: Some("sni.example.com".to_string()),
            skip_verify: true,
        },
        credential: "secret".to_string(),
        cipher: None,
        flow: None,
    })
    .expect("hy2 outbound profile");

    assert_eq!(outbound.server(), &Endpoint::new("hy2.example.com", 443));
    assert_eq!(outbound.auth(), "secret");
    assert_eq!(outbound.sni(), "sni.example.com");
    assert!(outbound.skip_verify());
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

fn shadowsocks_key(kind: CipherKind, password: &str) -> Vec<u8> {
    let mut key = vec![0; kind.key_len()];
    openssl_bytes_to_key(password.as_bytes(), &mut key);
    key
}

fn read_ss_chunk(stream: &mut std::net::TcpStream, cipher: &mut Cipher) -> Vec<u8> {
    let tag_len = cipher.tag_len();
    let mut encrypted_len = vec![0; 2 + tag_len];
    stream
        .read_exact(&mut encrypted_len)
        .expect("read encrypted ss chunk length");
    assert!(cipher.decrypt_packet(&mut encrypted_len));
    let payload_len = u16::from_be_bytes([encrypted_len[0], encrypted_len[1]]) as usize;

    let mut encrypted_payload = vec![0; payload_len + tag_len];
    stream
        .read_exact(&mut encrypted_payload)
        .expect("read encrypted ss chunk payload");
    assert!(cipher.decrypt_packet(&mut encrypted_payload));
    encrypted_payload.truncate(payload_len);
    encrypted_payload
}

fn write_ss_chunk(stream: &mut std::net::TcpStream, cipher: &mut Cipher, payload: &[u8]) {
    let tag_len = cipher.tag_len();
    let mut encrypted_len = vec![0; 2 + tag_len];
    encrypted_len[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    cipher.encrypt_packet(&mut encrypted_len);
    stream
        .write_all(&encrypted_len)
        .expect("write encrypted ss chunk length");

    let mut encrypted_payload = vec![0; payload.len() + tag_len];
    encrypted_payload[..payload.len()].copy_from_slice(payload);
    cipher.encrypt_packet(&mut encrypted_payload);
    stream
        .write_all(&encrypted_payload)
        .expect("write encrypted ss chunk payload");
}

fn decrypt_ss_udp_packet(kind: CipherKind, key: &[u8], packet: &[u8]) -> Vec<u8> {
    let salt_len = kind.salt_len();
    let tag_len = kind.tag_len();
    let (salt, payload) = packet.split_at(salt_len);
    let mut payload = payload.to_vec();
    let mut cipher = Cipher::new(kind, key, salt);
    assert!(cipher.decrypt_packet(&mut payload));
    payload.truncate(payload.len() - tag_len);
    payload
}

fn encrypt_ss_udp_packet(kind: CipherKind, key: &[u8], salt: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let tag_len = kind.tag_len();
    let mut payload = vec![0; plaintext.len() + tag_len];
    payload[..plaintext.len()].copy_from_slice(plaintext);
    let mut cipher = Cipher::new(kind, key, salt);
    cipher.encrypt_packet(&mut payload);
    let mut packet = salt.to_vec();
    packet.extend_from_slice(&payload);
    packet
}
