use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use keli_net_core::{websocket_accept_for_key, OutboundRegistry, OutboundTarget};
use keli_protocol::{Endpoint, OutboundProfile, ProxyProtocol, SecurityKind, TransportKind};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

mod support;

use support::vmess::{
    read_vmess_aead_request, read_vmess_aes128_gcm_chunk, write_vmess_aead_response_header,
    write_vmess_aes128_gcm_response_chunk,
};

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
fn registry_from_vless_tls_ws_profile_relays_udp_over_tls_websocket() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vless tls ws udp server");
    let port = listener.local_addr().expect("vless tls ws udp addr").port();
    let server_config = tls_server_config();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().expect("accept vless tls ws udp");
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
                0xdd, 0xee, 0xff, 0x00, 0x02, 0x00, 0x35, 0x01, 0x7f, 0x00, 0x00, 0x01,
            ]
        );
        stream
            .write_all(b"\x82\x02\x00\x00")
            .expect("write vless response header");

        let mut request_payload = read_masked_client_frame(&mut stream);
        if request_payload.len() == 2 {
            request_payload.extend(read_masked_client_frame(&mut stream));
        }
        assert_eq!(&request_payload, b"\x00\x04ping");
        stream
            .write_all(b"\x82\x06\x00\x04pong")
            .expect("write vless udp response payload");
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

    let response = registry
        .relay_udp_datagram(
            "proxy",
            &OutboundTarget::new("127.0.0.1", 53),
            b"ping",
            Duration::from_secs(1),
        )
        .expect("registered VLESS TLS WS UDP outbound should relay");

    assert_eq!(
        response.source,
        "127.0.0.1:53".parse().expect("response source")
    );
    assert_eq!(response.payload, b"pong");
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

#[test]
fn registry_from_vmess_tls_ws_profile_relays_over_tls_websocket() {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vmess tls ws server");
    let port = listener.local_addr().expect("vmess tls ws addr").port();
    let server_config = tls_server_config();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().expect("accept vmess tls ws");
        let connection = rustls::ServerConnection::new(server_config).expect("server tls");
        let mut stream = rustls::StreamOwned::new(connection, tcp);
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
        let vmess = read_vmess_aead_request(&mut cursor, uuid);
        assert_eq!(vmess.target_host, "example.com");
        assert_eq!(vmess.target_port, 443);
        assert_eq!(vmess.command, 0x01);
        assert_eq!(vmess.security, 0x05);

        let mut response_header = Vec::new();
        write_vmess_aead_response_header(&mut response_header, &vmess);
        write_server_binary_frame(&mut stream, &response_header);
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
        security: SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: true,
        },
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
        .expect("registered vmess tls ws outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vmess_tls_ws_profile_relays_udp_over_tls_websocket_aes_gcm_chunks() {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vmess tls ws udp server");
    let port = listener.local_addr().expect("vmess tls ws udp addr").port();
    let server_config = tls_server_config();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().expect("accept vmess tls ws udp");
        let connection = rustls::ServerConnection::new(server_config).expect("server tls");
        let mut stream = rustls::StreamOwned::new(connection, tcp);
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
        let vmess = read_vmess_aead_request(&mut cursor, uuid);
        assert_eq!(vmess.target_host, "127.0.0.1");
        assert_eq!(vmess.target_port, 53);
        assert_eq!(vmess.command, 0x02);
        assert_eq!(vmess.security, 0x03);

        let mut response_header = Vec::new();
        write_vmess_aead_response_header(&mut response_header, &vmess);
        write_server_binary_frame(&mut stream, &response_header);

        let mut request_chunk = read_masked_client_frame(&mut stream);
        if request_chunk.len() == 2 {
            request_chunk.extend(read_masked_client_frame(&mut stream));
        }
        let mut cursor = std::io::Cursor::new(request_chunk);
        let payload = read_vmess_aes128_gcm_chunk(&mut cursor, &vmess);
        assert_eq!(&payload, b"ping");

        let mut response_chunk = Vec::new();
        write_vmess_aes128_gcm_response_chunk(&mut response_chunk, &vmess, b"pong");
        write_server_binary_frame(&mut stream, &response_chunk);
    });
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vmess,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::WebSocket {
            path: "/vmess".to_string(),
            host: Some("edge.example".to_string()),
        },
        security: SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: true,
        },
        credential: uuid.to_string(),
        cipher: Some("auto".to_string()),
        flow: None,
    }])
    .expect("profile registry");

    let response = registry
        .relay_udp_datagram(
            "proxy",
            &OutboundTarget::new("127.0.0.1", 53),
            b"ping",
            Duration::from_secs(1),
        )
        .expect("registered VMess TLS WS UDP outbound should relay");

    assert_eq!(
        response.source,
        "127.0.0.1:53".parse().expect("response source")
    );
    assert_eq!(response.payload, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vless_tls_httpupgrade_profile_relays_over_tls_upgrade() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vless tls hu server");
    let port = listener.local_addr().expect("vless tls hu addr").port();
    let server_config = tls_server_config();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().expect("accept vless tls hu");
        let connection = rustls::ServerConnection::new(server_config).expect("server tls");
        let mut stream = rustls::StreamOwned::new(connection, tcp);
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
        transport: TransportKind::HttpUpgrade {
            path: "/vless-upgrade".to_string(),
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
        .expect("registered vless tls httpupgrade outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read response");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_trojan_tls_httpupgrade_profile_relays_over_tls_upgrade() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan tls hu server");
    let port = listener.local_addr().expect("trojan tls hu addr").port();
    let server_config = tls_server_config();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().expect("accept trojan tls hu");
        let connection = rustls::ServerConnection::new(server_config).expect("server tls");
        let mut stream = rustls::StreamOwned::new(connection, tcp);
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
        stream.read_exact(&mut payload).expect("read payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write pong");
    });
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Trojan,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::HttpUpgrade {
            path: "/trojan-upgrade".to_string(),
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
        .expect("registered trojan tls httpupgrade outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read response");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vmess_tls_httpupgrade_profile_relays_over_tls_upgrade() {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vmess tls hu server");
    let port = listener.local_addr().expect("vmess tls hu addr").port();
    let server_config = tls_server_config();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().expect("accept vmess tls hu");
        let connection = rustls::ServerConnection::new(server_config).expect("server tls");
        let mut stream = rustls::StreamOwned::new(connection, tcp);
        let request = read_http_request(&mut stream);
        assert_httpupgrade_request(&request, "/vmess-upgrade", "edge.example");
        stream
            .write_all(httpupgrade_response().as_bytes())
            .expect("write httpupgrade response");

        let vmess = read_vmess_aead_request(&mut stream, uuid);
        assert_eq!(vmess.target_host, "example.com");
        assert_eq!(vmess.target_port, 443);
        assert_eq!(vmess.command, 0x01);
        assert_eq!(vmess.security, 0x05);

        write_vmess_aead_response_header(&mut stream, &vmess);
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).expect("read payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write pong");
    });
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vmess,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::HttpUpgrade {
            path: "/vmess-upgrade".to_string(),
            host: Some("edge.example".to_string()),
        },
        security: SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: true,
        },
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
        .expect("registered vmess tls httpupgrade outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read response");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vmess_tls_httpupgrade_profile_relays_udp_over_tls_aes_gcm_chunks() {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vmess tls hu udp server");
    let port = listener.local_addr().expect("vmess tls hu udp addr").port();
    let server_config = tls_server_config();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().expect("accept vmess tls hu udp");
        let connection = rustls::ServerConnection::new(server_config).expect("server tls");
        let mut stream = rustls::StreamOwned::new(connection, tcp);
        let request = read_http_request(&mut stream);
        assert_httpupgrade_request(&request, "/vmess-upgrade", "edge.example");
        stream
            .write_all(httpupgrade_response().as_bytes())
            .expect("write httpupgrade response");

        let vmess = read_vmess_aead_request(&mut stream, uuid);
        assert_eq!(vmess.target_host, "127.0.0.1");
        assert_eq!(vmess.target_port, 53);
        assert_eq!(vmess.command, 0x02);
        assert_eq!(vmess.security, 0x03);

        write_vmess_aead_response_header(&mut stream, &vmess);
        let payload = read_vmess_aes128_gcm_chunk(&mut stream, &vmess);
        assert_eq!(&payload, b"ping");
        write_vmess_aes128_gcm_response_chunk(&mut stream, &vmess, b"pong");
    });
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vmess,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::HttpUpgrade {
            path: "/vmess-upgrade".to_string(),
            host: Some("edge.example".to_string()),
        },
        security: SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: true,
        },
        credential: uuid.to_string(),
        cipher: Some("auto".to_string()),
        flow: None,
    }])
    .expect("profile registry");

    let response = registry
        .relay_udp_datagram(
            "proxy",
            &OutboundTarget::new("127.0.0.1", 53),
            b"ping",
            Duration::from_secs(1),
        )
        .expect("registered VMess TLS HTTPUpgrade UDP outbound should relay");

    assert_eq!(
        response.source,
        "127.0.0.1:53".parse().expect("response source")
    );
    assert_eq!(response.payload, b"pong");
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

fn write_server_binary_frame(stream: &mut impl Write, payload: &[u8]) {
    assert!(
        payload.len() <= 125,
        "test frame payload should stay compact"
    );
    stream
        .write_all(&[0x82, payload.len() as u8])
        .expect("write frame header");
    stream.write_all(payload).expect("write frame payload");
}
