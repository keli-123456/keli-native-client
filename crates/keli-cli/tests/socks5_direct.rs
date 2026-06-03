use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::str::FromStr;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use keli_cli::{handle_socks5_connection, handle_socks5_connection_with_routes, MixedProxyRuntime};
use keli_net_core::{
    encode_socks5_udp_datagram, parse_socks5_udp_datagram, OutboundRegistry, RouteAction,
    RouteEngine, Socks5Address,
};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use shadowsocks_crypto::kind::CipherKind;
use shadowsocks_crypto::v1::{openssl_bytes_to_key, Cipher};

#[test]
fn socks5_connect_relays_to_direct_tcp_target() {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind target");
    let target_port = target.local_addr().expect("target addr").port();
    let target_thread = thread::spawn(move || {
        let (mut stream, _) = target.accept().expect("accept target");
        let mut request = [0; 4];
        stream
            .read_exact(&mut request)
            .expect("read target request");
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").expect("write target response");
        stream.shutdown(Shutdown::Both).ok();
    });

    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_socks5_connection(&mut stream).expect("handle socks5");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    client.write_all(&[0x05, 0x01, 0x00]).expect("write hello");
    let mut hello = [0; 2];
    client.read_exact(&mut hello).expect("read hello response");
    assert_eq!(hello, [0x05, 0x00]);

    let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    request.extend_from_slice(&target_port.to_be_bytes());
    client.write_all(&request).expect("write connect request");
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
    target_thread.join().expect("target thread");
}

#[test]
fn socks5_udp_associate_relays_direct_ipv4_datagram() {
    let target = UdpSocket::bind("127.0.0.1:0").expect("bind udp target");
    target
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("target timeout");
    let target_port = target.local_addr().expect("target addr").port();
    let target_thread = thread::spawn(move || {
        let mut request = [0; 1500];
        let (size, from) = target.recv_from(&mut request).expect("read udp target");
        assert_eq!(&request[..size], b"ping");
        target
            .send_to(b"pong", from)
            .expect("write udp target response");
    });

    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_socks5_connection(&mut stream).expect("handle socks5");
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
        .write_all(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00])
        .expect("write udp associate request");
    let mut reply = [0; 10];
    client.read_exact(&mut reply).expect("read udp reply");
    assert_eq!(&reply[..4], &[0x05, 0x00, 0x00, 0x01]);
    assert_eq!(&reply[4..8], &[127, 0, 0, 1]);
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    assert_ne!(relay_port, 0);

    let udp_client = UdpSocket::bind("127.0.0.1:0").expect("bind udp client");
    udp_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("udp client timeout");
    let request = encode_socks5_udp_datagram(
        &Socks5Address::Ipv4(Ipv4Addr::LOCALHOST),
        target_port,
        b"ping",
    )
    .expect("encode udp request");
    udp_client
        .send_to(&request, ("127.0.0.1", relay_port))
        .expect("send udp request");

    let mut response = [0; 1500];
    let (size, _) = udp_client
        .recv_from(&mut response)
        .expect("read udp response");
    let response = parse_socks5_udp_datagram(&response[..size]).expect("parse udp response");
    assert_eq!(response.address, Socks5Address::Ipv4(Ipv4Addr::LOCALHOST));
    assert_eq!(response.port, target_port);
    assert_eq!(response.payload, b"pong");

    client.shutdown(Shutdown::Both).ok();

    inbound_thread.join().expect("inbound thread");
    target_thread.join().expect("target thread");
}

#[test]
fn socks5_udp_associate_relays_multiple_direct_ipv4_datagrams() {
    let target = UdpSocket::bind("127.0.0.1:0").expect("bind udp target");
    target
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("target timeout");
    let target_port = target.local_addr().expect("target addr").port();
    let target_thread = thread::spawn(move || {
        let exchanges: [(&[u8], &[u8]); 2] = [(b"ping", b"pong"), (b"next", b"done")];
        for (expected, response) in exchanges {
            let mut request = [0; 1500];
            let (size, from) = target.recv_from(&mut request).expect("read udp target");
            assert_eq!(&request[..size], expected);
            target
                .send_to(response, from)
                .expect("write udp target response");
        }
    });

    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_socks5_connection(&mut stream).expect("handle socks5");
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
        .write_all(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00])
        .expect("write udp associate request");
    let mut reply = [0; 10];
    client.read_exact(&mut reply).expect("read udp reply");
    assert_eq!(&reply[..4], &[0x05, 0x00, 0x00, 0x01]);
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    assert_ne!(relay_port, 0);

    let udp_client = UdpSocket::bind("127.0.0.1:0").expect("bind udp client");
    udp_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("udp client timeout");
    for (payload, expected_response) in [(b"ping".as_slice(), b"pong"), (b"next", b"done")] {
        let request = encode_socks5_udp_datagram(
            &Socks5Address::Ipv4(Ipv4Addr::LOCALHOST),
            target_port,
            payload,
        )
        .expect("encode udp request");
        udp_client
            .send_to(&request, ("127.0.0.1", relay_port))
            .expect("send udp request");

        let mut response = [0; 1500];
        let (size, _) = udp_client
            .recv_from(&mut response)
            .expect("read udp response");
        let response = parse_socks5_udp_datagram(&response[..size]).expect("parse udp response");
        assert_eq!(response.address, Socks5Address::Ipv4(Ipv4Addr::LOCALHOST));
        assert_eq!(response.port, target_port);
        assert_eq!(response.payload, expected_response);
    }

    client.shutdown(Shutdown::Both).ok();

    inbound_thread.join().expect("inbound thread");
    target_thread.join().expect("target thread");
}

#[test]
fn socks5_udp_associate_relays_registered_direct_outbound_route() {
    let target = UdpSocket::bind("127.0.0.1:0").expect("bind udp target");
    target
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("target timeout");
    let target_port = target.local_addr().expect("target addr").port();
    let target_thread = thread::spawn(move || {
        let mut request = [0; 1500];
        let (size, from) = target.recv_from(&mut request).expect("read udp target");
        assert_eq!(&request[..size], b"ping");
        target
            .send_to(b"pong", from)
            .expect("write udp target response");
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
        handle_socks5_connection_with_routes(&mut stream, &runtime).expect("handle socks5");
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
        .write_all(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00])
        .expect("write udp associate request");
    let mut reply = [0; 10];
    client.read_exact(&mut reply).expect("read udp reply");
    assert_eq!(&reply[..4], &[0x05, 0x00, 0x00, 0x01]);
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    assert_ne!(relay_port, 0);

    let udp_client = UdpSocket::bind("127.0.0.1:0").expect("bind udp client");
    udp_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("udp client timeout");
    let request = encode_socks5_udp_datagram(
        &Socks5Address::Ipv4(Ipv4Addr::LOCALHOST),
        target_port,
        b"ping",
    )
    .expect("encode udp request");
    udp_client
        .send_to(&request, ("127.0.0.1", relay_port))
        .expect("send udp request");

    let mut response = [0; 1500];
    let (size, _) = udp_client
        .recv_from(&mut response)
        .expect("read udp response");
    let response = parse_socks5_udp_datagram(&response[..size]).expect("parse udp response");
    assert_eq!(response.address, Socks5Address::Ipv4(Ipv4Addr::LOCALHOST));
    assert_eq!(response.port, target_port);
    assert_eq!(response.payload, b"pong");

    client.shutdown(Shutdown::Both).ok();

    inbound_thread.join().expect("inbound thread");
    target_thread.join().expect("target thread");
}

#[test]
fn socks5_udp_associate_relays_registered_hy2_outbound_route() {
    let (hy2_addr, hy2_thread) = spawn_hy2_udp_echo_server();
    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let outbounds = OutboundRegistry::from_profiles([keli_protocol::OutboundProfile {
        tag: "proxy".to_string(),
        protocol: keli_protocol::ProxyProtocol::Hy2,
        endpoint: keli_protocol::Endpoint::new("127.0.0.1", hy2_addr.port()),
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
        handle_socks5_connection_with_routes(&mut stream, &runtime).expect("handle socks5");
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
        .write_all(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00])
        .expect("write udp associate request");
    let mut reply = [0; 10];
    client.read_exact(&mut reply).expect("read udp reply");
    assert_eq!(&reply[..4], &[0x05, 0x00, 0x00, 0x01]);
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    assert_ne!(relay_port, 0);

    let udp_client = UdpSocket::bind("127.0.0.1:0").expect("bind udp client");
    udp_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("udp client timeout");
    let request = encode_socks5_udp_datagram(
        &Socks5Address::Domain("example.com".to_string()),
        53,
        b"ping",
    )
    .expect("encode udp request");
    udp_client
        .send_to(&request, ("127.0.0.1", relay_port))
        .expect("send udp request");

    let mut response = [0; 1500];
    let (size, _) = udp_client
        .recv_from(&mut response)
        .expect("read udp response");
    let response = parse_socks5_udp_datagram(&response[..size]).expect("parse udp response");
    assert_eq!(response.address, Socks5Address::Ipv4(Ipv4Addr::LOCALHOST));
    assert_eq!(response.port, 53);
    assert_eq!(response.payload, b"pong");

    client.shutdown(Shutdown::Both).ok();

    inbound_thread.join().expect("inbound thread");
    hy2_thread.join().expect("hy2 thread");
}

#[test]
fn socks5_udp_associate_relays_registered_shadowsocks_outbound_route() {
    let (ss_port, ss_thread) = spawn_shadowsocks_udp_echo_server();
    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let outbounds = OutboundRegistry::from_profiles([keli_protocol::OutboundProfile {
        tag: "proxy".to_string(),
        protocol: keli_protocol::ProxyProtocol::Shadowsocks,
        endpoint: keli_protocol::Endpoint::new("127.0.0.1", ss_port),
        transport: keli_protocol::TransportKind::Tcp,
        security: keli_protocol::SecurityKind::None,
        credential: "secret".to_string(),
        cipher: Some("aes-256-gcm".to_string()),
        flow: None,
    }])
    .expect("build Shadowsocks outbound registry");
    let runtime = MixedProxyRuntime::with_routes_and_outbounds(
        RouteEngine::new(RouteAction::Outbound("proxy".to_string())),
        outbounds,
    );
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_socks5_connection_with_routes(&mut stream, &runtime).expect("handle socks5");
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
        .write_all(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00])
        .expect("write udp associate request");
    let mut reply = [0; 10];
    client.read_exact(&mut reply).expect("read udp reply");
    assert_eq!(&reply[..4], &[0x05, 0x00, 0x00, 0x01]);
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    assert_ne!(relay_port, 0);

    let udp_client = UdpSocket::bind("127.0.0.1:0").expect("bind udp client");
    udp_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("udp client timeout");
    let request = encode_socks5_udp_datagram(
        &Socks5Address::Domain("example.com".to_string()),
        53,
        b"ping",
    )
    .expect("encode udp request");
    udp_client
        .send_to(&request, ("127.0.0.1", relay_port))
        .expect("send udp request");

    let mut response = [0; 1500];
    let (size, _) = udp_client
        .recv_from(&mut response)
        .expect("read udp response");
    let response = parse_socks5_udp_datagram(&response[..size]).expect("parse udp response");
    assert_eq!(response.address, Socks5Address::Ipv4(Ipv4Addr::LOCALHOST));
    assert_eq!(response.port, 53);
    assert_eq!(response.payload, b"pong");

    client.shutdown(Shutdown::Both).ok();

    inbound_thread.join().expect("inbound thread");
    ss_thread.join().expect("ss thread");
}

#[test]
fn socks5_connect_relays_registered_shadowsocks_outbound_route() {
    let (ss_port, ss_thread) = spawn_shadowsocks_tcp_echo_server();
    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let outbounds = OutboundRegistry::from_profiles([keli_protocol::OutboundProfile {
        tag: "proxy".to_string(),
        protocol: keli_protocol::ProxyProtocol::Shadowsocks,
        endpoint: keli_protocol::Endpoint::new("127.0.0.1", ss_port),
        transport: keli_protocol::TransportKind::Tcp,
        security: keli_protocol::SecurityKind::None,
        credential: "secret".to_string(),
        cipher: Some("aes-256-gcm".to_string()),
        flow: None,
    }])
    .expect("build Shadowsocks outbound registry");
    let runtime = MixedProxyRuntime::with_routes_and_outbounds(
        RouteEngine::new(RouteAction::Outbound("proxy".to_string())),
        outbounds,
    );
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_socks5_connection_with_routes(&mut stream, &runtime).expect("handle socks5");
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
        .expect("write connect request");
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
    ss_thread.join().expect("ss thread");
}

#[test]
fn socks5_connect_relays_registered_anytls_outbound_route() {
    let (anytls_port, anytls_thread) = spawn_anytls_tcp_echo_server();
    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let outbounds = OutboundRegistry::from_profiles([keli_protocol::OutboundProfile {
        tag: "proxy".to_string(),
        protocol: keli_protocol::ProxyProtocol::AnyTls,
        endpoint: keli_protocol::Endpoint::new("127.0.0.1", anytls_port),
        transport: keli_protocol::TransportKind::Tcp,
        security: keli_protocol::SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: true,
        },
        credential: "secret".to_string(),
        cipher: None,
        flow: None,
    }])
    .expect("build AnyTLS outbound registry");
    let runtime = MixedProxyRuntime::with_routes_and_outbounds(
        RouteEngine::new(RouteAction::Outbound("proxy".to_string())),
        outbounds,
    );
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_socks5_connection_with_routes(&mut stream, &runtime).expect("handle socks5");
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
        .expect("write connect request");
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
    anytls_thread.join().expect("anytls thread");
}

#[test]
fn socks5_udp_associate_relays_registered_tuic_outbound_route() {
    let (tuic_addr, tuic_thread) = spawn_tuic_udp_echo_server();
    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let outbounds = OutboundRegistry::from_profiles([keli_protocol::OutboundProfile {
        tag: "proxy".to_string(),
        protocol: keli_protocol::ProxyProtocol::Tuic,
        endpoint: keli_protocol::Endpoint::new("127.0.0.1", tuic_addr.port()),
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
        handle_socks5_connection_with_routes(&mut stream, &runtime).expect("handle socks5");
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
        .write_all(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00])
        .expect("write udp associate request");
    let mut reply = [0; 10];
    client.read_exact(&mut reply).expect("read udp reply");
    assert_eq!(&reply[..4], &[0x05, 0x00, 0x00, 0x01]);
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    assert_ne!(relay_port, 0);

    let udp_client = UdpSocket::bind("127.0.0.1:0").expect("bind udp client");
    udp_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("udp client timeout");
    let request = encode_socks5_udp_datagram(
        &Socks5Address::Domain("example.com".to_string()),
        53,
        b"ping",
    )
    .expect("encode udp request");
    udp_client
        .send_to(&request, ("127.0.0.1", relay_port))
        .expect("send udp request");

    let mut response = [0; 1500];
    let (size, _) = udp_client
        .recv_from(&mut response)
        .expect("read udp response");
    let response = parse_socks5_udp_datagram(&response[..size]).expect("parse udp response");
    assert_eq!(response.address, Socks5Address::Ipv4(Ipv4Addr::LOCALHOST));
    assert_eq!(response.port, 53);
    assert_eq!(response.payload, b"pong");

    client.shutdown(Shutdown::Both).ok();

    inbound_thread.join().expect("inbound thread");
    tuic_thread.join().expect("tuic thread");
}

fn spawn_shadowsocks_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ss udp server");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("ss udp timeout");
    let port = socket.local_addr().expect("ss udp addr").port();
    let handle = thread::spawn(move || {
        let kind = CipherKind::from_str("aes-256-gcm").expect("cipher");
        let key = shadowsocks_key(kind, "secret");
        let mut request = [0; 1500];
        let (size, from) = socket.recv_from(&mut request).expect("read ss udp request");
        let plaintext = decrypt_ss_udp_packet(kind, &key, &request[..size]);
        assert_eq!(plaintext, b"\x03\x0bexample.com\x005ping");

        let salt = vec![9; kind.salt_len()];
        let response = encrypt_ss_udp_packet(kind, &key, &salt, b"\x01\x7f\x00\x00\x01\x005pong");
        socket
            .send_to(&response, from)
            .expect("write ss udp response");
    });
    (port, handle)
}

fn spawn_anytls_tcp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind anytls tcp server");
    let port = listener.local_addr().expect("anytls tcp addr").port();
    let server_config = tls_server_config();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept anytls tcp server");
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
        stream.conn.send_close_notify();
        stream.flush().expect("flush anytls close notify");
    });
    (port, handle)
}

fn spawn_shadowsocks_tcp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ss tcp server");
    let port = listener.local_addr().expect("ss tcp addr").port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept ss tcp server");
        let kind = CipherKind::from_str("aes-256-gcm").expect("cipher");
        let key = shadowsocks_key(kind, "secret");

        let mut client_salt = vec![0; kind.salt_len()];
        stream
            .read_exact(&mut client_salt)
            .expect("read client salt");
        let mut client_cipher = Cipher::new(kind, &key, &client_salt);
        let request_header = read_ss_chunk(&mut stream, &mut client_cipher);
        assert_eq!(request_header, b"\x03\x0bexample.com\x01\xbb");
        let payload = read_ss_chunk(&mut stream, &mut client_cipher);
        assert_eq!(&payload, b"ping");

        let server_salt = vec![7; kind.salt_len()];
        stream.write_all(&server_salt).expect("write server salt");
        let mut server_cipher = Cipher::new(kind, &key, &server_salt);
        write_ss_chunk(&mut stream, &mut server_cipher, b"pong");
    });
    (port, handle)
}

fn spawn_tuic_udp_echo_server() -> (SocketAddr, thread::JoinHandle<()>) {
    let (addr_tx, addr_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build TUIC UDP test runtime");
        runtime.block_on(async move {
            let endpoint = quinn::Endpoint::server(
                hy2_h3_test_server_config(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            )
            .expect("bind TUIC UDP test server");
            addr_tx
                .send(endpoint.local_addr().expect("TUIC UDP test server addr"))
                .expect("send TUIC UDP addr");
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

            let packet = keli_net_core::tuic_read_packet_datagram(&connection)
                .await
                .expect("read TUIC UDP request");
            assert_eq!(
                packet.source,
                keli_protocol::Endpoint::new("example.com", 53)
            );
            assert_eq!(packet.payload, b"ping");
            keli_net_core::tuic_send_packet_datagram(
                &connection,
                packet.associate_id,
                packet.packet_id,
                packet.fragment_total,
                packet.fragment_id,
                &keli_protocol::Endpoint::new("127.0.0.1", 53),
                b"pong",
            )
            .expect("send TUIC UDP response");
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
    });
    (addr_rx.recv().expect("receive TUIC UDP addr"), handle)
}

fn spawn_hy2_udp_echo_server() -> (SocketAddr, thread::JoinHandle<()>) {
    let (addr_tx, addr_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build HY2 UDP test runtime");
        runtime.block_on(async move {
            let endpoint = quinn::Endpoint::server(
                hy2_h3_test_server_config(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            )
            .expect("bind HY2 UDP test server");
            addr_tx
                .send(endpoint.local_addr().expect("HY2 UDP test server addr"))
                .expect("send HY2 UDP addr");
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

            let message = keli_net_core::hy2_read_udp_datagram(&connection)
                .await
                .expect("read HY2 UDP request");
            assert_eq!(
                message.address,
                keli_protocol::Endpoint::new("example.com", 53)
            );
            assert_eq!(message.payload, b"ping");
            keli_net_core::hy2_send_udp_datagram(
                &connection,
                message.session_id,
                message.packet_id,
                message.fragment_id,
                message.fragment_count,
                &keli_protocol::Endpoint::new("127.0.0.1", 53),
                b"pong",
            )
            .expect("send HY2 UDP response");
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
    });
    (addr_rx.recv().expect("receive HY2 UDP addr"), handle)
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

fn shadowsocks_key(kind: CipherKind, password: &str) -> Vec<u8> {
    let mut key = vec![0; kind.key_len()];
    openssl_bytes_to_key(password.as_bytes(), &mut key);
    key
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

fn read_ss_chunk(stream: &mut TcpStream, cipher: &mut Cipher) -> Vec<u8> {
    let mut encrypted_len = vec![0; 2 + cipher.tag_len()];
    stream
        .read_exact(&mut encrypted_len)
        .expect("read encrypted ss chunk length");
    assert!(cipher.decrypt_packet(&mut encrypted_len));
    encrypted_len.truncate(2);
    let len = u16::from_be_bytes([encrypted_len[0], encrypted_len[1]]) as usize;
    let mut encrypted_payload = vec![0; len + cipher.tag_len()];
    stream
        .read_exact(&mut encrypted_payload)
        .expect("read encrypted ss chunk payload");
    assert!(cipher.decrypt_packet(&mut encrypted_payload));
    encrypted_payload.truncate(len);
    encrypted_payload
}

fn write_ss_chunk(stream: &mut TcpStream, cipher: &mut Cipher, payload: &[u8]) {
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
