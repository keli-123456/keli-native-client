use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
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
        transport: keli_protocol::TransportKind::Quic,
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
