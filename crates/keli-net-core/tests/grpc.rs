mod support;

use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use h2::RecvStream;
use http::{HeaderMap, Request, Response, StatusCode};
use keli_net_core::{OutboundRegistry, OutboundTarget};
use keli_protocol::{Endpoint, OutboundProfile, ProxyProtocol, SecurityKind, TransportKind};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use support::vmess::{
    read_vmess_aead_request, read_vmess_aes128_gcm_chunk, write_vmess_aead_response_header,
    write_vmess_aes128_gcm_response_chunk,
};
use tokio::io::{AsyncRead, AsyncWrite};

const VLESS_UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const VMESS_UUID: &str = "11111111-1111-1111-1111-111111111111";

#[test]
fn registry_from_vless_grpc_profile_relays_over_h2_grpc() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind grpc server");
    let port = listener.local_addr().expect("grpc addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vless,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Grpc {
            service_name: Some("GunService".to_string()),
        },
        security: SecurityKind::None,
        credential: VLESS_UUID.to_string(),
        cipher: None,
        flow: None,
    }])
    .expect("profile registry");
    let server = spawn_grpc_server(listener, "/GunService/Tun", |mut stream| {
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

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(2),
        )
        .expect("registered vless grpc outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vless_grpc_profile_relays_udp_over_h2_grpc() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind grpc udp server");
    let port = listener.local_addr().expect("grpc udp addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vless,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Grpc {
            service_name: Some("GunService".to_string()),
        },
        security: SecurityKind::None,
        credential: VLESS_UUID.to_string(),
        cipher: None,
        flow: None,
    }])
    .expect("profile registry");
    let server = spawn_grpc_server(listener, "/GunService/Tun", |mut stream| {
        let mut request_header = [0; 26];
        stream
            .read_exact(&mut request_header)
            .expect("read vless udp request header");
        assert_eq!(
            request_header,
            [
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x02, 0x00, 0x35, 0x01, 0x7f, 0x00, 0x00, 0x01,
            ]
        );
        stream
            .write_all(&[0x00, 0x00])
            .expect("write vless response header");
        let mut request_payload = [0; 6];
        stream
            .read_exact(&mut request_payload)
            .expect("read vless udp payload");
        assert_eq!(&request_payload, b"\x00\x04ping");
        stream
            .write_all(b"\x00\x04pong")
            .expect("write vless udp response payload");
    });

    let response = registry
        .relay_udp_datagram(
            "proxy",
            &OutboundTarget::new("127.0.0.1", 53),
            b"ping",
            Duration::from_secs(2),
        )
        .expect("registered VLESS gRPC UDP outbound should relay");

    assert_eq!(
        response.source,
        "127.0.0.1:53".parse().expect("response source")
    );
    assert_eq!(response.payload, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_trojan_grpc_profile_relays_over_h2_grpc() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind grpc server");
    let port = listener.local_addr().expect("grpc addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Trojan,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Grpc {
            service_name: Some("GunService".to_string()),
        },
        security: SecurityKind::None,
        credential: "password".to_string(),
        cipher: None,
        flow: None,
    }])
    .expect("profile registry");
    let server = spawn_grpc_server(listener, "/GunService/Tun", |mut stream| {
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

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(2),
        )
        .expect("registered trojan grpc outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_trojan_grpc_profile_relays_udp_over_h2_grpc() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan grpc udp server");
    let port = listener.local_addr().expect("trojan grpc udp addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Trojan,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Grpc {
            service_name: Some("GunService".to_string()),
        },
        security: SecurityKind::None,
        credential: "password".to_string(),
        cipher: None,
        flow: None,
    }])
    .expect("profile registry");
    let server = spawn_grpc_server(listener, "/GunService/Tun", |mut stream| {
        let mut request_header = [0; 68];
        stream
            .read_exact(&mut request_header)
            .expect("read trojan udp associate header");
        assert_eq!(
            &request_header[..],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x03\x01\x7f\x00\x00\x01\x005\r\n"
        );
        let mut request_payload = [0; 15];
        stream
            .read_exact(&mut request_payload)
            .expect("read trojan udp packet");
        assert_eq!(
            &request_payload,
            b"\x01\x7f\x00\x00\x01\x005\x00\x04\r\nping"
        );
        stream
            .write_all(b"\x01\x7f\x00\x00\x01\x005\x00\x04\r\npong")
            .expect("write trojan udp response packet");
    });

    let response = registry
        .relay_udp_datagram(
            "proxy",
            &OutboundTarget::new("127.0.0.1", 53),
            b"ping",
            Duration::from_secs(2),
        )
        .expect("registered Trojan gRPC UDP outbound should relay");

    assert_eq!(
        response.source,
        "127.0.0.1:53".parse().expect("response source")
    );
    assert_eq!(response.payload, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vmess_grpc_profile_relays_over_h2_grpc() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind grpc server");
    let port = listener.local_addr().expect("grpc addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vmess,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Grpc {
            service_name: Some("GunService".to_string()),
        },
        security: SecurityKind::None,
        credential: VMESS_UUID.to_string(),
        cipher: Some("aes-128-gcm".to_string()),
        flow: None,
    }])
    .expect("profile registry");
    let server = spawn_grpc_server(listener, "/GunService/Tun", |mut stream| {
        let request = read_vmess_aead_request(&mut stream, VMESS_UUID);
        assert_eq!(request.target_host, "example.com");
        assert_eq!(request.target_port, 443);
        assert_eq!(request.command, 0x01);
        assert_eq!(request.security, 0x03);
        write_vmess_aead_response_header(&mut stream, &request);
        let payload = read_vmess_aes128_gcm_chunk(&mut stream, &request);
        assert_eq!(&payload, b"ping");
        write_vmess_aes128_gcm_response_chunk(&mut stream, &request, b"pong");
    });

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(2),
        )
        .expect("registered vmess grpc outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vmess_grpc_profile_relays_udp_over_h2_grpc() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind grpc udp server");
    let port = listener.local_addr().expect("grpc udp addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vmess,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Grpc {
            service_name: Some("GunService".to_string()),
        },
        security: SecurityKind::None,
        credential: VMESS_UUID.to_string(),
        cipher: Some("aes-128-gcm".to_string()),
        flow: None,
    }])
    .expect("profile registry");
    let server = spawn_grpc_server(listener, "/GunService/Tun", |mut stream| {
        let request = read_vmess_aead_request(&mut stream, VMESS_UUID);
        assert_eq!(request.target_host, "127.0.0.1");
        assert_eq!(request.target_port, 53);
        assert_eq!(request.command, 0x02);
        assert_eq!(request.security, 0x03);
        write_vmess_aead_response_header(&mut stream, &request);
        let payload = read_vmess_aes128_gcm_chunk(&mut stream, &request);
        assert_eq!(&payload, b"ping");
        write_vmess_aes128_gcm_response_chunk(&mut stream, &request, b"pong");
    });

    let response = registry
        .relay_udp_datagram(
            "proxy",
            &OutboundTarget::new("127.0.0.1", 53),
            b"ping",
            Duration::from_secs(2),
        )
        .expect("registered VMess gRPC UDP outbound should relay");

    assert_eq!(
        response.source,
        "127.0.0.1:53".parse().expect("response source")
    );
    assert_eq!(response.payload, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vless_tls_grpc_profile_relays_over_tls_h2_grpc() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls grpc server");
    let port = listener.local_addr().expect("tls grpc addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vless,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Grpc {
            service_name: Some("GunService".to_string()),
        },
        security: SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: true,
        },
        credential: VLESS_UUID.to_string(),
        cipher: None,
        flow: None,
    }])
    .expect("profile registry");
    let server = spawn_tls_grpc_server(listener, "/GunService/Tun", |mut stream| {
        let mut request_header = [0; 34];
        stream
            .read_exact(&mut request_header)
            .expect("read vless request header");
        assert_eq!(
            &request_header[2..18],
            &[
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                0xff, 0x00
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

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(2),
        )
        .expect("registered vless tls grpc outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vless_tls_grpc_profile_relays_udp_over_tls_h2_grpc() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls grpc udp server");
    let port = listener.local_addr().expect("tls grpc udp addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vless,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Grpc {
            service_name: Some("GunService".to_string()),
        },
        security: SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: true,
        },
        credential: VLESS_UUID.to_string(),
        cipher: None,
        flow: None,
    }])
    .expect("profile registry");
    let server = spawn_tls_grpc_server(listener, "/GunService/Tun", |mut stream| {
        let mut request_header = [0; 26];
        stream
            .read_exact(&mut request_header)
            .expect("read vless udp request header");
        assert_eq!(
            request_header,
            [
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x02, 0x00, 0x35, 0x01, 0x7f, 0x00, 0x00, 0x01,
            ]
        );
        stream
            .write_all(&[0x00, 0x00])
            .expect("write vless response header");
        let mut request_payload = [0; 6];
        stream
            .read_exact(&mut request_payload)
            .expect("read vless udp payload");
        assert_eq!(&request_payload, b"\x00\x04ping");
        stream
            .write_all(b"\x00\x04pong")
            .expect("write vless udp response payload");
    });

    let response = registry
        .relay_udp_datagram(
            "proxy",
            &OutboundTarget::new("127.0.0.1", 53),
            b"ping",
            Duration::from_secs(2),
        )
        .expect("registered VLESS TLS gRPC UDP outbound should relay");

    assert_eq!(
        response.source,
        "127.0.0.1:53".parse().expect("response source")
    );
    assert_eq!(response.payload, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_trojan_tls_grpc_profile_relays_over_tls_h2_grpc() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls grpc server");
    let port = listener.local_addr().expect("tls grpc addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Trojan,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Grpc {
            service_name: Some("GunService".to_string()),
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
    let server = spawn_tls_grpc_server(listener, "/GunService/Tun", |mut stream| {
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

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(2),
        )
        .expect("registered trojan tls grpc outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_trojan_tls_grpc_profile_relays_udp_over_tls_h2_grpc() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan tls grpc udp server");
    let port = listener
        .local_addr()
        .expect("trojan tls grpc udp addr")
        .port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Trojan,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Grpc {
            service_name: Some("GunService".to_string()),
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
    let server = spawn_tls_grpc_server(listener, "/GunService/Tun", |mut stream| {
        let mut request_header = [0; 68];
        stream
            .read_exact(&mut request_header)
            .expect("read trojan udp associate header");
        assert_eq!(
            &request_header[..],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x03\x01\x7f\x00\x00\x01\x005\r\n"
        );
        let mut request_payload = [0; 15];
        stream
            .read_exact(&mut request_payload)
            .expect("read trojan udp packet");
        assert_eq!(
            &request_payload,
            b"\x01\x7f\x00\x00\x01\x005\x00\x04\r\nping"
        );
        stream
            .write_all(b"\x01\x7f\x00\x00\x01\x005\x00\x04\r\npong")
            .expect("write trojan udp response packet");
    });

    let response = registry
        .relay_udp_datagram(
            "proxy",
            &OutboundTarget::new("127.0.0.1", 53),
            b"ping",
            Duration::from_secs(2),
        )
        .expect("registered Trojan TLS gRPC UDP outbound should relay");

    assert_eq!(
        response.source,
        "127.0.0.1:53".parse().expect("response source")
    );
    assert_eq!(response.payload, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vmess_tls_grpc_profile_relays_over_tls_h2_grpc() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls grpc server");
    let port = listener.local_addr().expect("tls grpc addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vmess,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Grpc {
            service_name: Some("GunService".to_string()),
        },
        security: SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: true,
        },
        credential: VMESS_UUID.to_string(),
        cipher: Some("aes-128-gcm".to_string()),
        flow: None,
    }])
    .expect("profile registry");
    let server = spawn_tls_grpc_server(listener, "/GunService/Tun", |mut stream| {
        let request = read_vmess_aead_request(&mut stream, VMESS_UUID);
        assert_eq!(request.target_host, "example.com");
        assert_eq!(request.target_port, 443);
        write_vmess_aead_response_header(&mut stream, &request);
        let payload = read_vmess_aes128_gcm_chunk(&mut stream, &request);
        assert_eq!(&payload, b"ping");
        write_vmess_aes128_gcm_response_chunk(&mut stream, &request, b"pong");
    });

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(2),
        )
        .expect("registered vmess tls grpc outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vmess_tls_grpc_profile_relays_udp_over_tls_h2_grpc() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls grpc udp server");
    let port = listener.local_addr().expect("tls grpc udp addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vmess,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Grpc {
            service_name: Some("GunService".to_string()),
        },
        security: SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: true,
        },
        credential: VMESS_UUID.to_string(),
        cipher: Some("aes-128-gcm".to_string()),
        flow: None,
    }])
    .expect("profile registry");
    let server = spawn_tls_grpc_server(listener, "/GunService/Tun", |mut stream| {
        let request = read_vmess_aead_request(&mut stream, VMESS_UUID);
        assert_eq!(request.target_host, "127.0.0.1");
        assert_eq!(request.target_port, 53);
        assert_eq!(request.command, 0x02);
        assert_eq!(request.security, 0x03);
        write_vmess_aead_response_header(&mut stream, &request);
        let payload = read_vmess_aes128_gcm_chunk(&mut stream, &request);
        assert_eq!(&payload, b"ping");
        write_vmess_aes128_gcm_response_chunk(&mut stream, &request, b"pong");
    });

    let response = registry
        .relay_udp_datagram(
            "proxy",
            &OutboundTarget::new("127.0.0.1", 53),
            b"ping",
            Duration::from_secs(2),
        )
        .expect("registered VMess TLS gRPC UDP outbound should relay");

    assert_eq!(
        response.source,
        "127.0.0.1:53".parse().expect("response source")
    );
    assert_eq!(response.payload, b"pong");
    server.join().expect("server thread");
}

fn spawn_grpc_server(
    listener: TcpListener,
    expected_path: &'static str,
    handler: impl FnOnce(GrpcTestStream) + Send + 'static,
) -> thread::JoinHandle<()> {
    listener
        .set_nonblocking(true)
        .expect("listener nonblocking");
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            let (stream, _) = listener.accept().await.expect("accept grpc tcp");
            serve_grpc_h2_connection(stream, expected_path, handler).await;
        });
    })
}

fn spawn_tls_grpc_server(
    listener: TcpListener,
    expected_path: &'static str,
    handler: impl FnOnce(GrpcTestStream) + Send + 'static,
) -> thread::JoinHandle<()> {
    listener
        .set_nonblocking(true)
        .expect("listener nonblocking");
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            let (stream, _) = listener.accept().await.expect("accept grpc tcp");
            let acceptor = tokio_rustls::TlsAcceptor::from(h2_tls_server_config());
            let stream = acceptor.accept(stream).await.expect("accept grpc tls");
            serve_grpc_h2_connection(stream, expected_path, handler).await;
        });
    })
}

async fn serve_grpc_h2_connection<S>(
    stream: S,
    expected_path: &'static str,
    handler: impl FnOnce(GrpcTestStream) + Send + 'static,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = h2::server::handshake(stream).await.expect("h2 handshake");
    let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let mut handler = Some(handler);
    loop {
        tokio::select! {
            request = connection.accept() => {
                let Some(request) = request else {
                    break;
                };
                let (request, respond) = request.expect("valid h2 request");
                let handler = handler.take().expect("single grpc request handler");
                let done_tx = done_tx.clone();
                tokio::spawn(async move {
                    serve_grpc_request(request, respond, expected_path, handler).await;
                    let _ = done_tx.send(());
                });
            }
            _ = done_rx.recv() => break,
        }
    }
}

async fn serve_grpc_request(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    expected_path: &str,
    handler: impl FnOnce(GrpcTestStream) + Send + 'static,
) {
    assert_eq!(request.method(), http::Method::POST);
    assert_eq!(request.uri().path(), expected_path);
    assert_eq!(
        request
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc")
    );
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .body(())
        .expect("grpc response");
    let mut send = respond
        .send_response(response, false)
        .expect("send response");
    let (input_tx, input_rx) = mpsc::channel();
    let (output_tx, mut output_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let mut body = request.into_body();
    let read_task = tokio::spawn(async move {
        let mut buffer = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.expect("read grpc body");
            let len = chunk.len();
            buffer.extend_from_slice(&chunk);
            let _ = body.flow_control().release_capacity(len);
            while let Some(payload) = take_grpc_payload(&mut buffer).expect("grpc payload") {
                if input_tx.send(payload).is_err() {
                    return;
                }
            }
        }
    });
    let write_task = tokio::spawn(async move {
        while let Some(payload) = output_rx.recv().await {
            send_h2_data(&mut send, Bytes::from(encode_grpc_hunk(&payload)), false)
                .await
                .expect("write grpc hunk");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().expect("grpc-status"));
        send.send_trailers(trailers).expect("write grpc trailers");
    });
    tokio::task::spawn_blocking(move || handler(GrpcTestStream::new(input_rx, output_tx)))
        .await
        .expect("handler task");
    write_task.await.expect("write task");
    read_task.abort();
}

struct GrpcTestStream {
    input_rx: mpsc::Receiver<Vec<u8>>,
    output_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    buffer: Vec<u8>,
}

impl GrpcTestStream {
    fn new(
        input_rx: mpsc::Receiver<Vec<u8>>,
        output_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        Self {
            input_rx,
            output_tx,
            buffer: Vec::new(),
        }
    }
}

impl Read for GrpcTestStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        while self.buffer.is_empty() {
            self.buffer = self
                .input_rx
                .recv()
                .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "grpc input closed"))?;
        }
        let len = output.len().min(self.buffer.len());
        output[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Ok(len)
    }
}

impl Write for GrpcTestStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.output_tx
            .send(input.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "grpc output closed"))?;
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_grpc_hunk(payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(2 + payload.len());
    message.push(0x0a);
    encode_varint(payload.len() as u64, &mut message);
    message.extend_from_slice(payload);
    let mut output = Vec::with_capacity(5 + message.len());
    output.push(0);
    output.extend_from_slice(&(message.len() as u32).to_be_bytes());
    output.extend_from_slice(&message);
    output
}

async fn send_h2_data(
    send: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
    end_stream: bool,
) -> io::Result<()> {
    if data.is_empty() {
        return send
            .send_data(data, end_stream)
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()));
    }
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let capacity = loop {
            match poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(capacity)) if capacity > 0 => break capacity,
                Some(Ok(_)) => continue,
                Some(Err(error)) => {
                    return Err(io::Error::new(io::ErrorKind::Other, error.to_string()));
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "stream closed before capacity",
                    ));
                }
            }
        };
        let chunk_len = capacity.min(data.len());
        let chunk = data.split_to(chunk_len);
        let chunk_ends_stream = end_stream && data.is_empty();
        send.send_data(chunk, chunk_ends_stream)
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
    }
    Ok(())
}

fn take_grpc_payload(buffer: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    if buffer.len() < 5 {
        return Ok(None);
    }
    if buffer[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "compressed grpc messages are not supported",
        ));
    }
    let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
    if buffer.len() < 5 + len {
        return Ok(None);
    }
    let message = buffer[5..5 + len].to_vec();
    buffer.drain(..5 + len);
    decode_hunk_message(&message).map(Some)
}

fn decode_hunk_message(message: &[u8]) -> io::Result<Vec<u8>> {
    let mut cursor = 0usize;
    let mut data = None;
    while cursor < message.len() {
        let key = decode_varint(message, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (1, 2) => {
                let len = decode_varint(message, &mut cursor)? as usize;
                if cursor + len > message.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated hunk data",
                    ));
                }
                data = Some(message[cursor..cursor + len].to_vec());
                cursor += len;
            }
            (_, 0) => {
                let _ = decode_varint(message, &mut cursor)?;
            }
            (_, 2) => {
                let len = decode_varint(message, &mut cursor)? as usize;
                if cursor + len > message.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated hunk field",
                    ));
                }
                cursor += len;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported hunk wire type",
                ));
            }
        }
    }
    Ok(data.unwrap_or_default())
}

fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn decode_varint(input: &[u8], cursor: &mut usize) -> io::Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    while *cursor < input.len() && shift < 64 {
        let byte = input[*cursor];
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid hunk varint",
    ))
}

fn h2_tls_server_config() -> Arc<rustls::ServerConfig> {
    let cert = generate_simple_self_signed(vec!["edge.example".to_string()]).expect("self cert");
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let mut config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .expect("tls versions")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .expect("server config");
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}
