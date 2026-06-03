use std::io::{Read, Write};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockDecrypt, KeyInit};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce as AesGcmNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChachaNonce, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use keli_net_core::{
    websocket_accept_for_key, OutboundRegistry, OutboundTarget, ShadowsocksTcpOutbound,
    TrojanTcpOutbound, VlessTcpOutbound,
};
use keli_protocol::{Endpoint, OutboundProfile, ProxyProtocol, SecurityKind, TransportKind};
use md5::{Digest as Md5Digest, Md5};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use shadowsocks_crypto::kind::CipherKind;
use shadowsocks_crypto::v1::{openssl_bytes_to_key, Cipher};

const VMESS_KDF_ROOT: &[u8] = b"VMess AEAD KDF";
const VMESS_AUTH_ID_KEY: &[u8] = b"AES Auth ID Encryption";
const VMESS_HEADER_LENGTH_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const VMESS_HEADER_LENGTH_NONCE: &[u8] = b"VMess Header AEAD Nonce_Length";
const VMESS_HEADER_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
const VMESS_HEADER_PAYLOAD_NONCE: &[u8] = b"VMess Header AEAD Nonce";
const VMESS_RESPONSE_HEADER_LENGTH_KEY: &[u8] = b"AEAD Resp Header Len Key";
const VMESS_RESPONSE_HEADER_LENGTH_IV: &[u8] = b"AEAD Resp Header Len IV";
const VMESS_RESPONSE_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const VMESS_RESPONSE_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";
const VMESS_CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const VMESS_OPTION_CHUNK_STREAM: u8 = 0x01;
const VMESS_OPTION_CHUNK_MASKING: u8 = 0x04;
const VMESS_SECURITY_AES_128_GCM: u8 = 0x03;
const VMESS_SECURITY_CHACHA20_POLY1305: u8 = 0x04;
const VMESS_SECURITY_NONE: u8 = 0x05;
const MIERU_NONCE_LEN: usize = 24;
const MIERU_METADATA_LEN: usize = 32;
const MIERU_TAG_LEN: usize = 16;
const MIERU_ENCRYPTED_METADATA_LEN: usize = MIERU_METADATA_LEN + MIERU_TAG_LEN;
const MIERU_KEY_WINDOW_SECS: i64 = 120;
const MIERU_OPEN_SESSION_REQUEST: u8 = 2;
const MIERU_OPEN_SESSION_RESPONSE: u8 = 3;
const MIERU_DATA_CLIENT_TO_SERVER: u8 = 6;
const MIERU_DATA_SERVER_TO_CLIENT: u8 = 7;
const MIERU_STATUS_OK: u8 = 0;
const MIERU_SOCKS_CONNECT_SUCCESS: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];

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
fn registry_from_trojan_httpupgrade_profile_relays_after_upgrade() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind trojan hu server");
    let port = listener.local_addr().expect("trojan hu addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept trojan hu server");
        let request = read_http_request(&mut stream);
        assert_httpupgrade_request(&request, "/trojan-upgrade", "edge.example");
        stream
            .write_all(httpupgrade_response().as_bytes())
            .expect("write httpupgrade response");

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
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Trojan,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::HttpUpgrade {
            path: "/trojan-upgrade".to_string(),
            host: Some("edge.example".to_string()),
        },
        security: SecurityKind::None,
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
        .expect("registered trojan httpupgrade outbound should connect");
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
fn registry_from_vless_httpupgrade_profile_relays_after_upgrade() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind vless hu server");
    let port = listener.local_addr().expect("vless hu addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vless hu server");
        let request = read_http_request(&mut stream);
        assert_httpupgrade_request(&request, "/vless-upgrade", "edge.example");
        stream
            .write_all(httpupgrade_response().as_bytes())
            .expect("write httpupgrade response");

        let mut request_header = [0; 34];
        stream
            .read_exact(&mut request_header)
            .expect("read vless request header");
        assert_eq!(
            &request_header[..],
            &[
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
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vless,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::HttpUpgrade {
            path: "/vless-upgrade".to_string(),
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
        .expect("registered vless httpupgrade outbound should connect");
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
fn registry_from_vmess_tcp_profile_relays_over_vmess_tcp() {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind vmess server");
    let port = listener.local_addr().expect("vmess addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vmess server");
        let request = read_vmess_aead_request(&mut stream, uuid);
        assert_eq!(request.target_host, "example.com");
        assert_eq!(request.target_port, 443);
        assert_eq!(request.command, 0x01);
        assert_eq!(request.security, VMESS_SECURITY_NONE);

        write_vmess_aead_response_header(&mut stream, &request);
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).expect("read relay payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write relay payload");
    });
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vmess,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Tcp,
        security: SecurityKind::None,
        credential: uuid.to_string(),
        cipher: Some("none".to_string()),
        flow: None,
    }])
    .expect("profile registry");

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(1),
        )
        .expect("registered vmess outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vmess_ws_profile_relays_over_websocket() {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind vmess ws server");
    let port = listener.local_addr().expect("vmess ws addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vmess ws server");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /vmess HTTP/1.1\r\n"));
        assert!(request.contains("Host: edge.example\r\n"));
        let key = header_value(&request, "Sec-WebSocket-Key").expect("client key");
        let accept = websocket_accept_for_key(&key);
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .expect("write ws response");
        let request_header = read_masked_client_frame(&mut stream);
        let mut cursor = std::io::Cursor::new(request_header);
        let request = read_vmess_aead_request(&mut cursor, uuid);
        assert_eq!(request.target_host, "example.com");
        assert_eq!(request.target_port, 443);
        assert_eq!(request.command, 0x01);
        assert_eq!(request.security, VMESS_SECURITY_NONE);

        let mut response_header = Vec::new();
        write_vmess_aead_response_header(&mut response_header, &request);
        write_server_binary_frame_for_vmess_test(&mut stream, &response_header);
        let payload = read_masked_client_frame(&mut stream);
        assert_eq!(&payload, b"ping");
        stream.write_all(b"\x82\x04pong").expect("write pong");
    });
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vmess,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::WebSocket {
            path: "/vmess".to_string(),
            host: Some("edge.example".to_string()),
        },
        security: SecurityKind::None,
        credential: uuid.to_string(),
        cipher: Some("none".to_string()),
        flow: None,
    }])
    .expect("profile registry");

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(1),
        )
        .expect("registered vmess ws outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vmess_httpupgrade_profile_relays_after_upgrade() {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind vmess hu server");
    let port = listener.local_addr().expect("vmess hu addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vmess hu server");
        let request = read_http_request(&mut stream);
        assert_httpupgrade_request(&request, "/vmess-upgrade", "edge.example");
        stream
            .write_all(httpupgrade_response().as_bytes())
            .expect("write httpupgrade response");

        let request = read_vmess_aead_request(&mut stream, uuid);
        assert_eq!(request.target_host, "example.com");
        assert_eq!(request.target_port, 443);
        assert_eq!(request.command, 0x01);
        assert_eq!(request.security, VMESS_SECURITY_NONE);

        write_vmess_aead_response_header(&mut stream, &request);
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).expect("read relay payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write relay payload");
    });
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vmess,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::HttpUpgrade {
            path: "/vmess-upgrade".to_string(),
            host: Some("edge.example".to_string()),
        },
        security: SecurityKind::None,
        credential: uuid.to_string(),
        cipher: Some("none".to_string()),
        flow: None,
    }])
    .expect("profile registry");

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(1),
        )
        .expect("registered vmess httpupgrade outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vmess_auto_cipher_profile_relays_over_aes_gcm_chunks() {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind vmess server");
    let port = listener.local_addr().expect("vmess addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vmess server");
        let request = read_vmess_aead_request(&mut stream, uuid);
        assert_eq!(request.target_host, "example.com");
        assert_eq!(request.target_port, 443);
        assert_eq!(request.command, 0x01);
        assert_eq!(
            request.option,
            VMESS_OPTION_CHUNK_STREAM | VMESS_OPTION_CHUNK_MASKING
        );
        assert_eq!(request.security, VMESS_SECURITY_AES_128_GCM);

        write_vmess_aead_response_header(&mut stream, &request);
        let payload = read_vmess_aes128_gcm_chunk_for_test(&mut stream, &request);
        assert_eq!(&payload, b"ping");
        write_vmess_aes128_gcm_response_chunk_for_test(&mut stream, &request, b"pong");
    });
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vmess,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Tcp,
        security: SecurityKind::None,
        credential: uuid.to_string(),
        cipher: Some("auto".to_string()),
        flow: None,
    }])
    .expect("profile registry");

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(1),
        )
        .expect("registered vmess outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vmess_chacha20_poly1305_profile_relays_over_chacha_chunks() {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind vmess server");
    let port = listener.local_addr().expect("vmess addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vmess server");
        let request = read_vmess_aead_request(&mut stream, uuid);
        assert_eq!(request.target_host, "example.com");
        assert_eq!(request.target_port, 443);
        assert_eq!(request.command, 0x01);
        assert_eq!(
            request.option,
            VMESS_OPTION_CHUNK_STREAM | VMESS_OPTION_CHUNK_MASKING
        );
        assert_eq!(request.security, VMESS_SECURITY_CHACHA20_POLY1305);

        write_vmess_aead_response_header(&mut stream, &request);
        let payload = read_vmess_chacha20_poly1305_chunk_for_test(&mut stream, &request);
        assert_eq!(&payload, b"ping");
        write_vmess_chacha20_poly1305_response_chunk_for_test(&mut stream, &request, b"pong");
    });
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vmess,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Tcp,
        security: SecurityKind::None,
        credential: uuid.to_string(),
        cipher: Some("chacha20-poly1305".to_string()),
        flow: None,
    }])
    .expect("profile registry");

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(1),
        )
        .expect("registered vmess outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_mieru_tcp_profile_relays_over_mieru_tcp() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mieru server");
    let port = listener.local_addr().expect("mieru addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Mieru,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Tcp,
        security: SecurityKind::None,
        credential: "user:pass".to_string(),
        cipher: None,
        flow: None,
    }])
    .expect("profile registry");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept mieru server");
        let key = derive_mieru_key_for_test("user", "pass");
        let mut read_nonce = None;
        let open = read_mieru_segment_for_test(&mut stream, &key, &mut read_nonce);
        assert_eq!(open.protocol_type, MIERU_OPEN_SESSION_REQUEST);
        assert_eq!(open.payload, b"\x05\x01\x00\x03\x0bexample.com\x01\xbb");

        let mut writer =
            MieruTestWriter::new(stream.try_clone().expect("clone"), key, open.session_id);
        writer.write_segment(MIERU_OPEN_SESSION_RESPONSE, b"");
        writer.write_segment(MIERU_DATA_SERVER_TO_CLIENT, &MIERU_SOCKS_CONNECT_SUCCESS);

        let data = read_mieru_segment_for_test(&mut stream, &key, &mut read_nonce);
        assert_eq!(data.protocol_type, MIERU_DATA_CLIENT_TO_SERVER);
        assert_eq!(data.payload, b"ping");
        writer.write_segment(MIERU_DATA_SERVER_TO_CLIENT, b"pong");
    });

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(1),
        )
        .expect("registered mieru outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[derive(Debug)]
struct MieruTestSegment {
    protocol_type: u8,
    session_id: u32,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct MieruTestWriter {
    stream: std::net::TcpStream,
    key: [u8; 32],
    nonce: [u8; MIERU_NONCE_LEN],
    session_id: u32,
    sequence: u32,
    sent_nonce: bool,
}

impl MieruTestWriter {
    fn new(stream: std::net::TcpStream, key: [u8; 32], session_id: u32) -> Self {
        let mut nonce = [7u8; MIERU_NONCE_LEN];
        apply_mieru_nonce_user_hint_for_test(&mut nonce, "user");
        Self {
            stream,
            key,
            nonce,
            session_id,
            sequence: 0,
            sent_nonce: false,
        }
    }

    fn write_segment(&mut self, protocol_type: u8, payload: &[u8]) {
        let metadata =
            mieru_metadata_for_test(protocol_type, self.session_id, self.sequence, payload.len());
        self.sequence = self.sequence.saturating_add(1);
        let mut segment = Vec::new();
        if !self.sent_nonce {
            segment.extend_from_slice(&self.nonce);
            self.sent_nonce = true;
        }
        segment.extend(mieru_xchacha_seal_for_test(
            &self.key,
            &self.nonce,
            &metadata,
        ));
        increment_mieru_nonce_for_test(&mut self.nonce);
        if !payload.is_empty() {
            segment.extend(mieru_xchacha_seal_for_test(&self.key, &self.nonce, payload));
            increment_mieru_nonce_for_test(&mut self.nonce);
        }
        self.stream
            .write_all(&segment)
            .expect("write mieru segment");
    }
}

fn read_mieru_segment_for_test(
    stream: &mut std::net::TcpStream,
    key: &[u8; 32],
    nonce: &mut Option<[u8; MIERU_NONCE_LEN]>,
) -> MieruTestSegment {
    let mut buffer = Vec::new();
    loop {
        if let Some(segment) = try_read_mieru_segment_for_test(&buffer, key, nonce) {
            return segment;
        }
        let mut temp = [0; 4096];
        let read = stream.read(&mut temp).expect("read mieru segment");
        assert_ne!(read, 0, "mieru stream closed before segment");
        buffer.extend_from_slice(&temp[..read]);
    }
}

fn try_read_mieru_segment_for_test(
    buffer: &[u8],
    key: &[u8; 32],
    nonce_state: &mut Option<[u8; MIERU_NONCE_LEN]>,
) -> Option<MieruTestSegment> {
    let has_nonce = nonce_state.is_none();
    let metadata_offset = if has_nonce {
        if buffer.len() < MIERU_NONCE_LEN {
            return None;
        }
        let mut nonce = [0; MIERU_NONCE_LEN];
        nonce.copy_from_slice(&buffer[..MIERU_NONCE_LEN]);
        *nonce_state = Some(nonce);
        MIERU_NONCE_LEN
    } else {
        0
    };
    if buffer.len() < metadata_offset + MIERU_ENCRYPTED_METADATA_LEN {
        return None;
    }
    let nonce = nonce_state.as_mut().expect("nonce initialized");
    let metadata = mieru_xchacha_open_for_test(
        key,
        nonce,
        &buffer[metadata_offset..metadata_offset + MIERU_ENCRYPTED_METADATA_LEN],
    );
    let protocol_type = metadata[0];
    let session_id = u32::from_be_bytes([metadata[6], metadata[7], metadata[8], metadata[9]]);
    increment_mieru_nonce_for_test(nonce);
    let payload_len = if matches!(
        protocol_type,
        MIERU_OPEN_SESSION_REQUEST | MIERU_OPEN_SESSION_RESPONSE
    ) {
        u16::from_be_bytes([metadata[15], metadata[16]]) as usize
    } else {
        u16::from_be_bytes([metadata[22], metadata[23]]) as usize
    };
    let encrypted_payload_len = if payload_len == 0 {
        0
    } else {
        payload_len + MIERU_TAG_LEN
    };
    let payload_offset = metadata_offset + MIERU_ENCRYPTED_METADATA_LEN;
    if buffer.len() < payload_offset + encrypted_payload_len {
        return None;
    }
    let payload = if payload_len == 0 {
        Vec::new()
    } else {
        let payload = mieru_xchacha_open_for_test(
            key,
            nonce,
            &buffer[payload_offset..payload_offset + encrypted_payload_len],
        );
        increment_mieru_nonce_for_test(nonce);
        payload
    };
    Some(MieruTestSegment {
        protocol_type,
        session_id,
        payload,
    })
}

fn mieru_metadata_for_test(
    protocol_type: u8,
    session_id: u32,
    sequence: u32,
    payload_len: usize,
) -> [u8; MIERU_METADATA_LEN] {
    let mut output = [0; MIERU_METADATA_LEN];
    output[0] = protocol_type;
    output[2..6].copy_from_slice(&((now_unix_secs_for_mieru_test() / 60) as u32).to_be_bytes());
    output[6..10].copy_from_slice(&session_id.to_be_bytes());
    output[10..14].copy_from_slice(&sequence.to_be_bytes());
    if matches!(
        protocol_type,
        MIERU_OPEN_SESSION_REQUEST | MIERU_OPEN_SESSION_RESPONSE
    ) {
        output[14] = MIERU_STATUS_OK;
        output[15..17].copy_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        output[18..20].copy_from_slice(&(64u16).to_be_bytes());
        output[22..24].copy_from_slice(&(payload_len as u16).to_be_bytes());
    }
    output
}

fn derive_mieru_key_for_test(username: &str, password: &str) -> [u8; 32] {
    let mut password_hasher = Sha256::new();
    Sha2Digest::update(&mut password_hasher, password.as_bytes());
    Sha2Digest::update(&mut password_hasher, [0]);
    Sha2Digest::update(&mut password_hasher, username.as_bytes());
    let hashed_password = password_hasher.finalize();

    let mut time_hasher = Sha256::new();
    Sha2Digest::update(
        &mut time_hasher,
        (rounded_unix_time_for_mieru_test(now_unix_secs_for_mieru_test()) as u64).to_be_bytes(),
    );
    let time_salt = time_hasher.finalize();

    let mut key = [0; 32];
    pbkdf2_hmac_sha256_for_mieru_test(&hashed_password, &time_salt, 64, &mut key);
    key
}

fn pbkdf2_hmac_sha256_for_mieru_test(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output: &mut [u8],
) {
    let mut block_index = 1u32;
    let mut offset = 0usize;
    while offset < output.len() {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(password).expect("hmac key");
        Mac::update(&mut mac, salt);
        Mac::update(&mut mac, &block_index.to_be_bytes());
        let mut u = mac.finalize().into_bytes().to_vec();
        let mut block = u.clone();
        for _ in 1..iterations {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(password).expect("hmac key");
            Mac::update(&mut mac, &u);
            u = mac.finalize().into_bytes().to_vec();
            for (left, right) in block.iter_mut().zip(&u) {
                *left ^= *right;
            }
        }
        let take = (output.len() - offset).min(block.len());
        output[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
        block_index = block_index.saturating_add(1);
    }
}

fn apply_mieru_nonce_user_hint_for_test(nonce: &mut [u8; MIERU_NONCE_LEN], username: &str) {
    let mut hasher = Sha256::new();
    Sha2Digest::update(&mut hasher, username.as_bytes());
    Sha2Digest::update(&mut hasher, &nonce[..16]);
    let digest = hasher.finalize();
    nonce[20..24].copy_from_slice(&digest[..4]);
}

fn increment_mieru_nonce_for_test(nonce: &mut [u8; MIERU_NONCE_LEN]) {
    for byte in nonce.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
}

fn mieru_xchacha_seal_for_test(
    key: &[u8; 32],
    nonce: &[u8; MIERU_NONCE_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    XChaCha20Poly1305::new_from_slice(key)
        .expect("xchacha key")
        .encrypt(XNonce::from_slice(nonce), plaintext)
        .expect("seal mieru segment")
}

fn mieru_xchacha_open_for_test(
    key: &[u8; 32],
    nonce: &[u8; MIERU_NONCE_LEN],
    ciphertext: &[u8],
) -> Vec<u8> {
    XChaCha20Poly1305::new_from_slice(key)
        .expect("xchacha key")
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .expect("open mieru segment")
}

fn rounded_unix_time_for_mieru_test(unix_secs: i64) -> i64 {
    ((unix_secs + MIERU_KEY_WINDOW_SECS / 2) / MIERU_KEY_WINDOW_SECS) * MIERU_KEY_WINDOW_SECS
}

fn now_unix_secs_for_mieru_test() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

struct VmessRequestForTest {
    target_host: String,
    target_port: u16,
    command: u8,
    option: u8,
    security: u8,
    request_body_key: [u8; 16],
    request_body_iv: [u8; 16],
    response_header: u8,
}

fn read_vmess_aead_request(stream: &mut impl Read, uuid: &str) -> VmessRequestForTest {
    let uuid = parse_uuid_bytes_for_vmess_test(uuid);
    let cmd_key = vmess_cmd_key_for_test(&uuid);
    let mut auth_id = [0; 16];
    let mut encrypted_len = [0; 18];
    let mut nonce = [0; 8];
    stream.read_exact(&mut auth_id).expect("read auth id");
    assert!(vmess_auth_id_is_valid_for_test(&cmd_key, &auth_id));
    stream
        .read_exact(&mut encrypted_len)
        .expect("read header length");
    stream.read_exact(&mut nonce).expect("read nonce");

    let len_key = vmess_kdf16_for_test(&cmd_key, &[VMESS_HEADER_LENGTH_KEY, &auth_id, &nonce]);
    let len_nonce = first_12_for_test(&vmess_kdf_for_test(
        &cmd_key,
        &[VMESS_HEADER_LENGTH_NONCE, &auth_id, &nonce],
    ));
    let len_plain = vmess_aes_gcm_open_for_test(&len_key, &len_nonce, &encrypted_len, &auth_id);
    let header_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
    let mut encrypted_header = vec![0; header_len + 16];
    stream
        .read_exact(&mut encrypted_header)
        .expect("read request header");
    let payload_key = vmess_kdf16_for_test(&cmd_key, &[VMESS_HEADER_PAYLOAD_KEY, &auth_id, &nonce]);
    let payload_nonce = first_12_for_test(&vmess_kdf_for_test(
        &cmd_key,
        &[VMESS_HEADER_PAYLOAD_NONCE, &auth_id, &nonce],
    ));
    let header =
        vmess_aes_gcm_open_for_test(&payload_key, &payload_nonce, &encrypted_header, &auth_id);

    assert_eq!(header[0], 0x01);
    let request_body_iv = header[1..17].try_into().expect("request iv");
    let request_body_key = header[17..33].try_into().expect("request key");
    let response_header = header[33];
    let option = header[34];
    let security = header[35] & 0x0f;
    let command = header[37];
    let target_port = u16::from_be_bytes([header[38], header[39]]);
    assert_eq!(header[40], 0x02, "test only expects a domain target");
    let domain_len = header[41] as usize;
    let target_host =
        String::from_utf8(header[42..42 + domain_len].to_vec()).expect("domain target");

    VmessRequestForTest {
        target_host,
        target_port,
        command,
        option,
        security,
        request_body_key,
        request_body_iv,
        response_header,
    }
}

fn write_vmess_aead_response_header(stream: &mut impl Write, request: &VmessRequestForTest) {
    let response_key = first_16_sha256_for_test(&request.request_body_key);
    let response_iv = first_16_sha256_for_test(&request.request_body_iv);
    let header = [request.response_header, 0x00, 0x00, 0x00];
    let len_key = vmess_kdf16_for_test(&response_key, &[VMESS_RESPONSE_HEADER_LENGTH_KEY]);
    let len_nonce = first_12_for_test(&vmess_kdf_for_test(
        &response_iv,
        &[VMESS_RESPONSE_HEADER_LENGTH_IV],
    ));
    let payload_key = vmess_kdf16_for_test(&response_key, &[VMESS_RESPONSE_HEADER_PAYLOAD_KEY]);
    let payload_nonce = first_12_for_test(&vmess_kdf_for_test(
        &response_iv,
        &[VMESS_RESPONSE_HEADER_PAYLOAD_IV],
    ));
    let encrypted_len = vmess_aes_gcm_seal_for_test(
        &len_key,
        &len_nonce,
        &(header.len() as u16).to_be_bytes(),
        &[],
    );
    let encrypted_payload = vmess_aes_gcm_seal_for_test(&payload_key, &payload_nonce, &header, &[]);
    stream
        .write_all(&encrypted_len)
        .expect("write response len");
    stream
        .write_all(&encrypted_payload)
        .expect("write response payload");
}

fn read_vmess_aes128_gcm_chunk_for_test(
    stream: &mut impl Read,
    request: &VmessRequestForTest,
) -> Vec<u8> {
    let mut encrypted_len = [0; 2];
    stream
        .read_exact(&mut encrypted_len)
        .expect("read vmess masked chunk length");
    let mask = vmess_chunk_mask_for_test(&request.request_body_iv);
    let len = u16::from_be_bytes(encrypted_len) ^ mask;
    let mut encrypted_payload = vec![0; usize::from(len)];
    stream
        .read_exact(&mut encrypted_payload)
        .expect("read vmess encrypted chunk");
    let nonce = vmess_body_nonce_for_test(&request.request_body_iv, 0);
    vmess_aes_gcm_open_for_test(&request.request_body_key, &nonce, &encrypted_payload, &[])
}

fn write_vmess_aes128_gcm_response_chunk_for_test(
    stream: &mut impl Write,
    request: &VmessRequestForTest,
    payload: &[u8],
) {
    let response_key = first_16_sha256_for_test(&request.request_body_key);
    let response_iv = first_16_sha256_for_test(&request.request_body_iv);
    let nonce = vmess_body_nonce_for_test(&response_iv, 0);
    let encrypted_payload = vmess_aes_gcm_seal_for_test(&response_key, &nonce, payload, &[]);
    let masked_len = (encrypted_payload.len() as u16) ^ vmess_chunk_mask_for_test(&response_iv);
    stream
        .write_all(&masked_len.to_be_bytes())
        .expect("write vmess masked chunk length");
    stream
        .write_all(&encrypted_payload)
        .expect("write vmess encrypted chunk");
}

fn read_vmess_chacha20_poly1305_chunk_for_test(
    stream: &mut impl Read,
    request: &VmessRequestForTest,
) -> Vec<u8> {
    let mut encrypted_len = [0; 2];
    stream
        .read_exact(&mut encrypted_len)
        .expect("read vmess masked chunk length");
    let mask = vmess_chunk_mask_for_test(&request.request_body_iv);
    let len = u16::from_be_bytes(encrypted_len) ^ mask;
    let mut encrypted_payload = vec![0; usize::from(len)];
    stream
        .read_exact(&mut encrypted_payload)
        .expect("read vmess encrypted chunk");
    let key = vmess_chacha20_poly1305_key_for_test(&request.request_body_key);
    let nonce = vmess_body_nonce_for_test(&request.request_body_iv, 0);
    vmess_chacha20_poly1305_open_for_test(&key, &nonce, &encrypted_payload)
}

fn write_vmess_chacha20_poly1305_response_chunk_for_test(
    stream: &mut impl Write,
    request: &VmessRequestForTest,
    payload: &[u8],
) {
    let response_key = first_16_sha256_for_test(&request.request_body_key);
    let response_iv = first_16_sha256_for_test(&request.request_body_iv);
    let key = vmess_chacha20_poly1305_key_for_test(&response_key);
    let nonce = vmess_body_nonce_for_test(&response_iv, 0);
    let encrypted_payload = vmess_chacha20_poly1305_seal_for_test(&key, &nonce, payload);
    let masked_len = (encrypted_payload.len() as u16) ^ vmess_chunk_mask_for_test(&response_iv);
    stream
        .write_all(&masked_len.to_be_bytes())
        .expect("write vmess masked chunk length");
    stream
        .write_all(&encrypted_payload)
        .expect("write vmess encrypted chunk");
}

fn vmess_chacha20_poly1305_key_for_test(input: &[u8; 16]) -> [u8; 32] {
    let mut key = [0; 32];
    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, input);
    let first = hasher.finalize();
    key[..16].copy_from_slice(&first);

    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, &key[..16]);
    let second = hasher.finalize();
    key[16..].copy_from_slice(&second);
    key
}

fn vmess_chunk_mask_for_test(nonce: &[u8; 16]) -> u16 {
    let mut shake = Shake128::default();
    Update::update(&mut shake, nonce);
    let mut reader = shake.finalize_xof();
    let mut mask = [0; 2];
    XofReader::read(&mut reader, &mut mask);
    u16::from_be_bytes(mask)
}

fn vmess_body_nonce_for_test(base: &[u8; 16], counter: u16) -> [u8; 12] {
    let mut nonce: [u8; 12] = base[..12].try_into().expect("vmess body nonce");
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn write_server_binary_frame_for_vmess_test(stream: &mut impl Write, payload: &[u8]) {
    assert!(
        payload.len() <= 125,
        "test frame payload should stay compact"
    );
    stream
        .write_all(&[0x82, payload.len() as u8])
        .expect("write ws frame header");
    stream.write_all(payload).expect("write ws frame payload");
}

fn parse_uuid_bytes_for_vmess_test(value: &str) -> [u8; 16] {
    let compact: String = value.chars().filter(|value| *value != '-').collect();
    let mut output = [0; 16];
    for (index, chunk) in compact.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk).expect("uuid hex");
        output[index] = u8::from_str_radix(hex, 16).expect("uuid byte");
    }
    output
}

fn vmess_cmd_key_for_test(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, uuid);
    Md5Digest::update(&mut hasher, VMESS_CMD_KEY_SALT);
    hasher.finalize().into()
}

fn vmess_auth_id_is_valid_for_test(cmd_key: &[u8; 16], auth_id: &[u8; 16]) -> bool {
    let key = vmess_kdf16_for_test(cmd_key, &[VMESS_AUTH_ID_KEY]);
    let cipher = aes::Aes128::new_from_slice(&key).expect("auth key");
    let mut block = aes::cipher::Block::<aes::Aes128>::clone_from_slice(auth_id);
    cipher.decrypt_block(&mut block);
    let crc = u32::from_be_bytes(block[12..16].try_into().expect("crc bytes"));
    crc == crc32fast::hash(&block[..12])
}

fn first_16_sha256_for_test(input: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    Sha2Digest::update(&mut hasher, input);
    let digest = hasher.finalize();
    digest[..16].try_into().expect("sha256 first 16")
}

fn first_12_for_test(input: &[u8; 32]) -> [u8; 12] {
    input[..12].try_into().expect("first 12")
}

fn vmess_kdf16_for_test(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    vmess_kdf_for_test(key, path)[..16]
        .try_into()
        .expect("kdf16")
}

fn vmess_kdf_for_test(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    if path.is_empty() {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(VMESS_KDF_ROOT).expect("hmac key");
        Mac::update(&mut mac, key);
        return mac.finalize().into_bytes().into();
    }
    let tail = path[path.len() - 1];
    vmess_hmac_with_hash_for_test(
        |input| vmess_kdf_for_test(input, &path[..path.len() - 1]),
        tail,
        key,
    )
}

fn vmess_hmac_with_hash_for_test<H>(hash: H, key: &[u8], message: &[u8]) -> [u8; 32]
where
    H: Fn(&[u8]) -> [u8; 32],
{
    let mut normalized_key = if key.len() > 64 {
        hash(key).to_vec()
    } else {
        key.to_vec()
    };
    normalized_key.resize(64, 0);
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for (index, key_byte) in normalized_key.iter().enumerate() {
        inner[index] ^= key_byte;
        outer[index] ^= key_byte;
    }
    let mut inner_input = Vec::with_capacity(64 + message.len());
    inner_input.extend_from_slice(&inner);
    inner_input.extend_from_slice(message);
    let inner_hash = hash(&inner_input);
    let mut outer_input = Vec::with_capacity(64 + inner_hash.len());
    outer_input.extend_from_slice(&outer);
    outer_input.extend_from_slice(&inner_hash);
    hash(&outer_input)
}

fn vmess_aes_gcm_open_for_test(
    key: &[u8; 16],
    nonce: &[u8; 12],
    input: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("aes-gcm key");
    cipher
        .decrypt(AesGcmNonce::from_slice(nonce), Payload { msg: input, aad })
        .expect("open vmess aes-gcm")
}

fn vmess_aes_gcm_seal_for_test(
    key: &[u8; 16],
    nonce: &[u8; 12],
    input: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("aes-gcm key");
    cipher
        .encrypt(AesGcmNonce::from_slice(nonce), Payload { msg: input, aad })
        .expect("seal vmess aes-gcm")
}

fn vmess_chacha20_poly1305_open_for_test(
    key: &[u8; 32],
    nonce: &[u8; 12],
    input: &[u8],
) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("chacha key");
    cipher
        .decrypt(
            ChachaNonce::from_slice(nonce),
            Payload {
                msg: input,
                aad: &[],
            },
        )
        .expect("open vmess chacha20-poly1305")
}

fn vmess_chacha20_poly1305_seal_for_test(
    key: &[u8; 32],
    nonce: &[u8; 12],
    input: &[u8],
) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("chacha key");
    cipher
        .encrypt(
            ChachaNonce::from_slice(nonce),
            Payload {
                msg: input,
                aad: &[],
            },
        )
        .expect("seal vmess chacha20-poly1305")
}

#[test]
fn hy2_outbound_from_profile_preserves_server_auth_and_sni() {
    let outbound = keli_net_core::Hy2Outbound::from_profile(OutboundProfile {
        tag: "hy2".to_string(),
        protocol: ProxyProtocol::Hy2,
        endpoint: Endpoint::new("hy2.example.com", 443),
        transport: TransportKind::Quic {
            security: None,
            key: None,
            header_type: None,
        },
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

fn assert_httpupgrade_request(request: &str, path: &str, host: &str) {
    assert!(request.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
    assert_eq!(header_value(request, "Host").as_deref(), Some(host));
    assert_eq!(
        header_value(request, "Connection").as_deref(),
        Some("Upgrade")
    );
    assert_eq!(
        header_value(request, "Upgrade").as_deref(),
        Some("websocket")
    );
    assert!(
        header_value(request, "Sec-WebSocket-Key").is_none(),
        "HTTPUpgrade should not send a WebSocket frame key"
    );
}

fn httpupgrade_response() -> &'static str {
    "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
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
