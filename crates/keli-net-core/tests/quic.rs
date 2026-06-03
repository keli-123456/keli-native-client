use std::future::poll_fn;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use keli_net_core::{h3_quic_client_config, h3_rustls_client_config};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[test]
fn h3_tls_config_advertises_http3_alpn() {
    let config = h3_rustls_client_config(false).expect("build h3 rustls config");

    assert_eq!(config.alpn_protocols, vec![b"h3".to_vec()]);
    assert!(config.enable_early_data);
}

#[test]
fn h3_quic_config_supports_normal_and_insecure_tls_modes() {
    h3_quic_client_config(false).expect("build verified h3 quic client config");
    h3_quic_client_config(true).expect("build insecure h3 quic client config");
}

#[test]
fn hy2_auth_http_request_matches_official_h3_shape() {
    let request =
        keli_net_core::hy2_auth_http_request("secret", 0, "pad").expect("build HY2 auth request");

    assert_eq!(request.method(), http::Method::POST);
    assert_eq!(request.uri(), "https://hysteria/auth");
    assert_eq!(request.headers()["Hysteria-Auth"], "secret");
    assert_eq!(request.headers()["Hysteria-CC-RX"], "0");
    assert_eq!(request.headers()["Hysteria-Padding"], "pad");
}

#[test]
fn hy2_h3_client_handles_are_send() {
    fn assert_send<T: Send>() {}

    assert_send::<keli_net_core::Hy2H3Connection>();
    assert_send::<keli_net_core::Hy2H3SendRequest>();
}

#[test]
fn hy2_blocking_tcp_stream_can_be_used_by_owned_relay() {
    fn assert_owned<T: keli_net_core::OwnedRelayStream>() {}

    assert_owned::<keli_net_core::Hy2BlockingTcpStream>();
}

#[tokio::test]
async fn h3_quic_client_endpoint_binds_to_requested_local_addr() {
    let endpoint = keli_net_core::h3_quic_client_endpoint(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        true,
    )
    .expect("build HY2 H3 client endpoint");

    assert_eq!(
        endpoint.local_addr().expect("local addr").ip(),
        Ipv4Addr::LOCALHOST
    );
}

#[tokio::test]
async fn tuic_export_token_matches_on_both_quic_peers() {
    let server_endpoint = quinn::Endpoint::server(
        hy2_h3_test_server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind local TUIC token server");
    let server_addr = server_endpoint.local_addr().expect("server local addr");
    let server = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("server accepts connection");
        incoming.await.expect("server QUIC connection")
    });

    let client_endpoint = keli_net_core::h3_quic_client_endpoint(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        true,
    )
    .expect("build client endpoint");
    let client_connection =
        keli_net_core::h3_quic_connect(&client_endpoint, server_addr, "localhost")
            .await
            .expect("connect local QUIC peer");
    let server_connection = server.await.expect("server task");

    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let password = "secret";
    let client_token =
        keli_net_core::tuic_export_token(&client_connection, uuid, password).expect("client token");
    let server_token =
        keli_net_core::tuic_export_token(&server_connection, uuid, password).expect("server token");

    assert_eq!(client_token, server_token);
    assert_ne!(client_token, [0; 32]);

    let auth_command = keli_net_core::tuic_authenticate_command(&client_connection, uuid, password)
        .expect("tuic auth command");
    assert_eq!(&auth_command[18..], client_token);
}

#[tokio::test]
async fn tuic_authenticate_sends_valid_unidirectional_command() {
    let server_endpoint = quinn::Endpoint::server(
        hy2_h3_test_server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind local TUIC auth server");
    let server_addr = server_endpoint.local_addr().expect("server local addr");
    let server = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("server accepts connection");
        let connection = incoming.await.expect("server QUIC connection");
        let mut recv = connection.accept_uni().await.expect("accept TUIC auth");
        let command = recv.read_to_end(64).await.expect("read TUIC auth command");
        (connection, command)
    });

    let client_endpoint = keli_net_core::h3_quic_client_endpoint(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        true,
    )
    .expect("build client endpoint");
    let client_connection =
        keli_net_core::h3_quic_connect(&client_endpoint, server_addr, "localhost")
            .await
            .expect("connect local QUIC peer");
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let password = "secret";

    keli_net_core::tuic_authenticate(&client_connection, uuid, password)
        .await
        .expect("send TUIC auth");

    let (server_connection, command) = server.await.expect("server task");
    let expected = keli_net_core::tuic_authenticate_command(&server_connection, uuid, password)
        .expect("expected TUIC auth command");
    assert_eq!(command, expected);
}

#[tokio::test]
async fn tuic_open_tcp_stream_sends_connect_command_and_relays_payload() {
    let server_endpoint = quinn::Endpoint::server(
        hy2_h3_test_server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind local TUIC TCP server");
    let server_addr = server_endpoint.local_addr().expect("server local addr");
    let server = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("server accepts connection");
        let connection = incoming.await.expect("server QUIC connection");

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
        .expect("expected auth");
        assert_eq!(auth, expected_auth);

        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .expect("accept TUIC TCP stream");
        let mut connect = [0; 17];
        recv.read_exact(&mut connect)
            .await
            .expect("read TUIC connect command");
        assert_eq!(
            connect,
            [
                0x05, 0x01, 0x00, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
                b'm', 0x01, 0xbb,
            ]
        );

        let mut payload = [0; 4];
        recv.read_exact(&mut payload)
            .await
            .expect("read relayed payload");
        assert_eq!(&payload, b"ping");
        send.write_all(b"pong").await.expect("write response");
        send.finish().expect("finish TUIC response stream");
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let client_endpoint = keli_net_core::h3_quic_client_endpoint(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        true,
    )
    .expect("build client endpoint");
    let connection = keli_net_core::h3_quic_connect(&client_endpoint, server_addr, "localhost")
        .await
        .expect("connect local QUIC peer");
    keli_net_core::tuic_authenticate(
        &connection,
        "00112233-4455-6677-8899-aabbccddeeff",
        "secret",
    )
    .await
    .expect("authenticate TUIC connection");

    let target = keli_protocol::Endpoint::new("example.com", 443);
    let mut stream = keli_net_core::tuic_open_tcp_stream(&connection, &target)
        .await
        .expect("open TUIC TCP stream");
    stream.write_all(b"ping").await.expect("write payload");
    let mut response = [0; 4];
    stream
        .read_exact(&mut response)
        .await
        .expect("read payload");
    assert_eq!(&response, b"pong");

    server.await.expect("server task");
}

#[tokio::test]
async fn tuic_packet_datagram_round_trips_udp_payload() {
    let server_endpoint = quinn::Endpoint::server(
        hy2_h3_test_server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind local TUIC UDP server");
    let server_addr = server_endpoint.local_addr().expect("server local addr");
    let server = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("server accepts connection");
        let connection = incoming.await.expect("server QUIC connection");
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
        .expect("expected auth");
        assert_eq!(auth, expected_auth);

        let packet = tokio::time::timeout(
            Duration::from_secs(2),
            keli_net_core::tuic_read_packet_datagram(&connection),
        )
        .await
        .expect("server waits for TUIC packet")
        .expect("server reads TUIC packet");
        assert_eq!(packet.associate_id, 0x1234);
        assert_eq!(packet.packet_id, 0x0001);
        assert_eq!(packet.fragment_total, 1);
        assert_eq!(packet.fragment_id, 0);
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
        .expect("server sends TUIC packet response");
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let client_endpoint = keli_net_core::h3_quic_client_endpoint(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        true,
    )
    .expect("build client endpoint");
    let connection = keli_net_core::h3_quic_connect(&client_endpoint, server_addr, "localhost")
        .await
        .expect("connect local QUIC peer");
    keli_net_core::tuic_authenticate(
        &connection,
        "00112233-4455-6677-8899-aabbccddeeff",
        "secret",
    )
    .await
    .expect("authenticate TUIC connection");

    keli_net_core::tuic_send_packet_datagram(
        &connection,
        0x1234,
        0x0001,
        1,
        0,
        &keli_protocol::Endpoint::new("example.com", 53),
        b"ping",
    )
    .expect("client sends TUIC packet");
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        keli_net_core::tuic_read_packet_datagram(&connection),
    )
    .await
    .expect("client waits for TUIC response")
    .expect("client reads TUIC response");
    assert_eq!(response.associate_id, 0x1234);
    assert_eq!(response.packet_id, 0x0001);
    assert_eq!(
        response.source,
        keli_protocol::Endpoint::new("127.0.0.1", 53)
    );
    assert_eq!(response.payload, b"pong");

    server.await.expect("server task");
}

#[test]
fn hy2_auth_response_requires_official_233_status() {
    keli_net_core::validate_hy2_auth_response(
        &http::Response::builder().status(233).body(()).unwrap(),
    )
    .expect("233 auth response is accepted");

    let error = keli_net_core::validate_hy2_auth_response(
        &http::Response::builder().status(401).body(()).unwrap(),
    )
    .expect_err("non-233 auth response should fail");

    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("401"));
}

#[tokio::test]
async fn h3_quic_connect_rejects_empty_server_name_before_network() {
    let endpoint = keli_net_core::h3_quic_client_endpoint(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        true,
    )
    .expect("build HY2 H3 client endpoint");

    let error = keli_net_core::h3_quic_connect(
        &endpoint,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        "",
    )
    .await
    .expect_err("empty server name should fail before network connect");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("server name"));
}

#[tokio::test]
async fn hy2_h3_authenticate_round_trips_against_local_h3_server() {
    let server_endpoint = quinn::Endpoint::server(
        hy2_h3_test_server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind local h3 server");
    let server_addr = server_endpoint.local_addr().expect("server local addr");
    let server = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("server accepts connection");
        let connection = incoming.await.expect("server QUIC connection");
        let mut h3_connection: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
            h3::server::builder()
                .build(h3_quinn::Connection::new(connection))
                .await
                .expect("server h3 connection");
        let resolver = h3_connection
            .accept()
            .await
            .expect("accept h3 request")
            .expect("h3 request exists");
        let (request, mut stream) = resolver.resolve_request().await.expect("resolve request");

        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.uri().path(), "/auth");
        assert_eq!(request.headers()["Hysteria-Auth"], "secret");
        assert_eq!(request.headers()["Hysteria-CC-RX"], "0");
        assert_eq!(request.headers()["Hysteria-Padding"], "pad");

        stream
            .send_response(http::Response::builder().status(233).body(()).unwrap())
            .await
            .expect("send auth response");
        stream.finish().await.expect("finish auth response");
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let client_endpoint = keli_net_core::h3_quic_client_endpoint(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        true,
    )
    .expect("build HY2 H3 client endpoint");
    let connection = keli_net_core::h3_quic_connect(&client_endpoint, server_addr, "localhost")
        .await
        .expect("connect local HY2 H3 server");
    let (mut h3_connection, mut send_request) =
        keli_net_core::h3_client_from_quinn_connection(connection)
            .await
            .expect("build h3 client");
    let client_driver =
        tokio::spawn(async move { poll_fn(|cx| h3_connection.poll_close(cx)).await });

    keli_net_core::hy2_authenticate_h3(&mut send_request, "secret", 0, "pad")
        .await
        .expect("HY2 H3 auth succeeds");

    drop(send_request);
    client_driver.abort();
    server.await.expect("server task");
}

#[tokio::test]
async fn hy2_quic_tcp_stream_sends_request_and_relays_payload() {
    let server_endpoint = quinn::Endpoint::server(
        hy2_h3_test_server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind local hy2 tcp server");
    let server_addr = server_endpoint.local_addr().expect("server local addr");
    let server = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("server accepts connection");
        let connection = incoming.await.expect("server QUIC connection");
        let (mut send, mut recv) = connection.accept_bi().await.expect("accept HY2 TCP stream");

        let mut request = [0; 19];
        recv.read_exact(&mut request)
            .await
            .expect("read HY2 TCP request");
        assert_eq!(
            request,
            [
                0x44, 0x01, 0x0f, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
                b':', b'4', b'4', b'3', 0x00,
            ]
        );
        send.write_all(&[0x00, 0x00, 0x00])
            .await
            .expect("write HY2 TCP OK response");

        let mut payload = [0; 4];
        recv.read_exact(&mut payload)
            .await
            .expect("read relayed payload");
        assert_eq!(&payload, b"ping");
        send.write_all(b"pong")
            .await
            .expect("write relayed payload");
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let client_endpoint = keli_net_core::h3_quic_client_endpoint(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        true,
    )
    .expect("build HY2 QUIC client endpoint");
    let connection = keli_net_core::h3_quic_connect(&client_endpoint, server_addr, "localhost")
        .await
        .expect("connect local HY2 server");
    let target = keli_protocol::Endpoint::new("example.com", 443);
    let mut stream = keli_net_core::hy2_open_tcp_stream(&connection, &target, b"")
        .await
        .expect("open HY2 TCP stream");

    stream.write_all(b"ping").await.expect("write payload");
    let mut response = [0; 4];
    stream
        .read_exact(&mut response)
        .await
        .expect("read payload");

    assert_eq!(&response, b"pong");
    server.await.expect("server task");
}

#[tokio::test]
async fn hy2_authenticated_quic_connection_opens_tcp_stream_after_h3_auth() {
    let server_endpoint = quinn::Endpoint::server(
        hy2_h3_test_server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind local authenticated hy2 server");
    let server_addr = server_endpoint.local_addr().expect("server local addr");
    let server = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("server accepts connection");
        let connection = incoming.await.expect("server QUIC connection");
        let mut h3_connection: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
            h3::server::builder()
                .build(h3_quinn::Connection::new(connection.clone()))
                .await
                .expect("server h3 connection");
        let resolver = h3_connection
            .accept()
            .await
            .expect("accept auth request")
            .expect("auth request exists");
        let (request, mut auth_stream) = resolver
            .resolve_request()
            .await
            .expect("resolve auth request");
        assert_eq!(request.uri().path(), "/auth");
        assert_eq!(request.headers()["Hysteria-Auth"], "secret");
        auth_stream
            .send_response(http::Response::builder().status(233).body(()).unwrap())
            .await
            .expect("send auth OK");
        auth_stream.finish().await.expect("finish auth OK");

        let (mut send, mut recv) = connection.accept_bi().await.expect("accept HY2 TCP stream");
        let mut request = [0; 19];
        recv.read_exact(&mut request)
            .await
            .expect("read HY2 TCP request");
        assert_eq!(
            request,
            [
                0x44, 0x01, 0x0f, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
                b':', b'4', b'4', b'3', 0x00,
            ]
        );
        send.write_all(&[0x00, 0x00, 0x00])
            .await
            .expect("write HY2 TCP OK response");
        send.write_all(b"pong").await.expect("write first payload");
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let client_endpoint = keli_net_core::h3_quic_client_endpoint(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        true,
    )
    .expect("build HY2 QUIC client endpoint");
    let connection = keli_net_core::h3_quic_connect(&client_endpoint, server_addr, "localhost")
        .await
        .expect("connect local authenticated HY2 server");
    let (mut h3_connection, mut send_request) =
        keli_net_core::h3_client_from_quinn_connection(connection.clone())
            .await
            .expect("build h3 client");
    let client_driver =
        tokio::spawn(async move { poll_fn(|cx| h3_connection.poll_close(cx)).await });
    let target = keli_protocol::Endpoint::new("example.com", 443);
    let mut stream = keli_net_core::hy2_open_authenticated_tcp_stream(
        &connection,
        &mut send_request,
        "secret",
        0,
        "pad",
        &target,
        b"",
    )
    .await
    .expect("auth then open HY2 TCP stream");
    let mut response = [0; 4];
    stream
        .read_exact(&mut response)
        .await
        .expect("read first payload");

    assert_eq!(&response, b"pong");
    drop(send_request);
    client_driver.abort();
    server.await.expect("server task");
}

#[tokio::test]
async fn hy2_client_session_reuses_authenticated_connection_for_tcp_streams() {
    let server_endpoint = quinn::Endpoint::server(
        hy2_h3_test_server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind local reusable hy2 server");
    let server_addr = server_endpoint.local_addr().expect("server local addr");
    let server = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("server accepts connection");
        let connection = incoming.await.expect("server QUIC connection");
        let mut h3_connection: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
            h3::server::builder()
                .build(h3_quinn::Connection::new(connection.clone()))
                .await
                .expect("server h3 connection");
        let resolver = h3_connection
            .accept()
            .await
            .expect("accept auth request")
            .expect("auth request exists");
        let (request, mut auth_stream) = resolver
            .resolve_request()
            .await
            .expect("resolve auth request");
        assert_eq!(request.uri().path(), "/auth");
        assert_eq!(request.headers()["Hysteria-Auth"], "secret");
        auth_stream
            .send_response(http::Response::builder().status(233).body(()).unwrap())
            .await
            .expect("send auth OK");
        auth_stream.finish().await.expect("finish auth OK");

        for expected_payload in [b"one".as_slice(), b"two".as_slice()] {
            let (mut send, mut recv) = connection.accept_bi().await.expect("accept HY2 TCP stream");
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
            let mut payload = vec![0; expected_payload.len()];
            recv.read_exact(&mut payload)
                .await
                .expect("read relayed payload");
            assert_eq!(payload, expected_payload);
            send.write_all(expected_payload)
                .await
                .expect("echo relayed payload");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let session = keli_net_core::Hy2ClientSession::connect(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        server_addr,
        "localhost",
        true,
        "secret",
        0,
        "pad",
    )
    .await
    .expect("connect HY2 client session");
    let target = keli_protocol::Endpoint::new("example.com", 443);

    let mut first = session
        .open_tcp_stream(&target, b"")
        .await
        .expect("open first HY2 TCP stream");
    first.write_all(b"one").await.expect("write first stream");
    let mut first_response = [0; 3];
    first
        .read_exact(&mut first_response)
        .await
        .expect("read first stream");

    let mut second = session
        .open_tcp_stream(&target, b"")
        .await
        .expect("open second HY2 TCP stream");
    second.write_all(b"two").await.expect("write second stream");
    let mut second_response = [0; 3];
    second
        .read_exact(&mut second_response)
        .await
        .expect("read second stream");

    assert_eq!(&first_response, b"one");
    assert_eq!(&second_response, b"two");
    server.await.expect("server task");
}

#[tokio::test]
async fn hy2_client_session_rejects_failed_h3_auth() {
    let server_endpoint = quinn::Endpoint::server(
        hy2_h3_test_server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind local rejecting hy2 server");
    let server_addr = server_endpoint.local_addr().expect("server local addr");
    let server = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("server accepts connection");
        let connection = incoming.await.expect("server QUIC connection");
        let mut h3_connection: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
            h3::server::builder()
                .build(h3_quinn::Connection::new(connection))
                .await
                .expect("server h3 connection");
        let resolver = h3_connection
            .accept()
            .await
            .expect("accept auth request")
            .expect("auth request exists");
        let (_request, mut auth_stream) = resolver
            .resolve_request()
            .await
            .expect("resolve auth request");
        auth_stream
            .send_response(http::Response::builder().status(401).body(()).unwrap())
            .await
            .expect("send auth rejection");
        auth_stream.finish().await.expect("finish auth rejection");
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let error = match keli_net_core::Hy2ClientSession::connect(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        server_addr,
        "localhost",
        true,
        "bad-secret",
        0,
        "pad",
    )
    .await
    {
        Ok(_) => panic!("HY2 session must reject failed auth"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("401"));
    server.await.expect("server task");
}

#[tokio::test]
async fn hy2_blocking_tcp_stream_bridges_into_std_read_write() {
    let server_endpoint = quinn::Endpoint::server(
        hy2_h3_test_server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind local blocking hy2 server");
    let server_addr = server_endpoint.local_addr().expect("server local addr");
    let server = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("server accepts connection");
        let connection = incoming.await.expect("server QUIC connection");
        let mut h3_connection: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
            h3::server::builder()
                .build(h3_quinn::Connection::new(connection.clone()))
                .await
                .expect("server h3 connection");
        let resolver = h3_connection
            .accept()
            .await
            .expect("accept auth request")
            .expect("auth request exists");
        let (_request, mut auth_stream) = resolver
            .resolve_request()
            .await
            .expect("resolve auth request");
        auth_stream
            .send_response(http::Response::builder().status(233).body(()).unwrap())
            .await
            .expect("send auth OK");
        auth_stream.finish().await.expect("finish auth OK");

        let (mut send, mut recv) = connection.accept_bi().await.expect("accept HY2 TCP stream");
        let mut request = [0; 19];
        recv.read_exact(&mut request)
            .await
            .expect("read HY2 TCP request");
        send.write_all(&[0x00, 0x00, 0x00])
            .await
            .expect("write HY2 TCP OK response");
        let mut payload = [0; 4];
        recv.read_exact(&mut payload)
            .await
            .expect("read relayed payload");
        assert_eq!(&payload, b"ping");
        send.write_all(b"pong").await.expect("write response");
        send.finish().expect("finish HY2 response stream");
        tokio::time::sleep(Duration::from_millis(50)).await;
    });
    let client = tokio::task::spawn_blocking(move || {
        let target = keli_protocol::Endpoint::new("example.com", 443);
        let mut stream = keli_net_core::Hy2BlockingTcpStream::connect(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            server_addr,
            "localhost",
            true,
            "secret",
            0,
            "pad",
            &target,
            b"",
        )
        .expect("connect blocking HY2 stream");
        stream.write_all(b"ping").expect("write payload");
        let mut response = [0; 4];
        stream.read_exact(&mut response).expect("read payload");
        response
    });

    assert_eq!(client.await.expect("client task"), *b"pong");
    server.await.expect("server task");
}

#[tokio::test]
async fn registry_from_hy2_profile_relays_over_quic_tcp_stream() {
    let server_endpoint = quinn::Endpoint::server(
        hy2_h3_test_server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind local registry hy2 server");
    let server_addr = server_endpoint.local_addr().expect("server local addr");
    let server = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("server accepts connection");
        let connection = incoming.await.expect("server QUIC connection");
        let mut h3_connection: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
            h3::server::builder()
                .build(h3_quinn::Connection::new(connection.clone()))
                .await
                .expect("server h3 connection");
        let resolver = h3_connection
            .accept()
            .await
            .expect("accept auth request")
            .expect("auth request exists");
        let (request, mut auth_stream) = resolver
            .resolve_request()
            .await
            .expect("resolve auth request");
        assert_eq!(request.headers()["Hysteria-Auth"], "secret");
        auth_stream
            .send_response(http::Response::builder().status(233).body(()).unwrap())
            .await
            .expect("send auth OK");
        auth_stream.finish().await.expect("finish auth OK");

        let (mut send, mut recv) = connection.accept_bi().await.expect("accept HY2 TCP stream");
        let mut request = [0; 19];
        recv.read_exact(&mut request)
            .await
            .expect("read HY2 TCP request");
        send.write_all(&[0x00, 0x00, 0x00])
            .await
            .expect("write HY2 TCP OK response");
        let mut payload = [0; 4];
        recv.read_exact(&mut payload)
            .await
            .expect("read relayed payload");
        assert_eq!(&payload, b"ping");
        send.write_all(b"pong").await.expect("write response");
        send.finish().expect("finish HY2 response stream");
        tokio::time::sleep(Duration::from_millis(50)).await;
    });
    let client = tokio::task::spawn_blocking(move || {
        let registry =
            keli_net_core::OutboundRegistry::from_profiles([keli_protocol::OutboundProfile {
                tag: "hy2".to_string(),
                protocol: keli_protocol::ProxyProtocol::Hy2,
                endpoint: keli_protocol::Endpoint::new("127.0.0.1", server_addr.port()),
                transport: keli_protocol::TransportKind::Quic,
                security: keli_protocol::SecurityKind::Tls {
                    sni: Some("localhost".to_string()),
                    skip_verify: true,
                },
                credential: "secret".to_string(),
                cipher: None,
                flow: None,
            }])
            .expect("build HY2 registry");
        let mut stream = registry
            .connect(
                "hy2",
                &keli_net_core::OutboundTarget::new("example.com", 443),
                Duration::from_secs(2),
            )
            .expect("connect HY2 outbound");
        stream.write_all(b"ping").expect("write payload");
        let mut response = [0; 4];
        stream.read_exact(&mut response).expect("read payload");
        response
    });

    assert_eq!(client.await.expect("client task"), *b"pong");
    server.await.expect("server task");
}

#[tokio::test]
async fn registry_from_tuic_profile_relays_over_quic_tcp_stream() {
    let server_endpoint = quinn::Endpoint::server(
        hy2_h3_test_server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind local registry tuic server");
    let server_addr = server_endpoint.local_addr().expect("server local addr");
    let server = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("server accepts connection");
        let connection = incoming.await.expect("server QUIC connection");
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
        .expect("expected auth");
        assert_eq!(auth, expected_auth);

        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .expect("accept TUIC TCP stream");
        let expected_connect = keli_protocol::encode_tuic_connect_command(
            &keli_protocol::Endpoint::new("example.com", 443),
        )
        .expect("expected TUIC connect");
        let mut connect = vec![0; expected_connect.len()];
        recv.read_exact(&mut connect)
            .await
            .expect("read TUIC connect command");
        assert_eq!(connect, expected_connect);

        let mut payload = [0; 4];
        recv.read_exact(&mut payload)
            .await
            .expect("read relayed payload");
        assert_eq!(&payload, b"ping");
        send.write_all(b"pong").await.expect("write response");
        send.finish().expect("finish TUIC response stream");
        tokio::time::sleep(Duration::from_millis(50)).await;
    });
    let client = tokio::task::spawn_blocking(move || {
        let registry =
            keli_net_core::OutboundRegistry::from_profiles([keli_protocol::OutboundProfile {
                tag: "tuic".to_string(),
                protocol: keli_protocol::ProxyProtocol::Tuic,
                endpoint: keli_protocol::Endpoint::new("127.0.0.1", server_addr.port()),
                transport: keli_protocol::TransportKind::Quic,
                security: keli_protocol::SecurityKind::Tls {
                    sni: Some("localhost".to_string()),
                    skip_verify: true,
                },
                credential: "00112233-4455-6677-8899-aabbccddeeff:secret".to_string(),
                cipher: None,
                flow: None,
            }])
            .expect("build TUIC registry");
        let mut stream = registry
            .connect(
                "tuic",
                &keli_net_core::OutboundTarget::new("example.com", 443),
                Duration::from_secs(2),
            )
            .expect("connect TUIC outbound");
        stream.write_all(b"ping").expect("write payload");
        let mut response = [0; 4];
        stream.read_exact(&mut response).expect("read payload");
        response
    });

    assert_eq!(client.await.expect("client task"), *b"pong");
    server.await.expect("server task");
}

#[tokio::test]
async fn registry_from_tuic_profile_relays_udp_over_quic_datagram() {
    let server_endpoint = quinn::Endpoint::server(
        hy2_h3_test_server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind local registry tuic UDP server");
    let server_addr = server_endpoint.local_addr().expect("server local addr");
    let server = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("server accepts connection");
        let connection = incoming.await.expect("server QUIC connection");
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
        .expect("expected auth");
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

    let client = tokio::task::spawn_blocking(move || {
        let registry =
            keli_net_core::OutboundRegistry::from_profiles([keli_protocol::OutboundProfile {
                tag: "tuic".to_string(),
                protocol: keli_protocol::ProxyProtocol::Tuic,
                endpoint: keli_protocol::Endpoint::new("127.0.0.1", server_addr.port()),
                transport: keli_protocol::TransportKind::Quic,
                security: keli_protocol::SecurityKind::Tls {
                    sni: Some("localhost".to_string()),
                    skip_verify: true,
                },
                credential: "00112233-4455-6677-8899-aabbccddeeff:secret".to_string(),
                cipher: None,
                flow: None,
            }])
            .expect("build TUIC registry");
        registry
            .relay_udp_datagram(
                "tuic",
                &keli_net_core::OutboundTarget::new("example.com", 53),
                b"ping",
                Duration::from_secs(2),
            )
            .expect("relay TUIC UDP datagram")
    });

    let response = client.await.expect("client task");
    assert_eq!(
        response.source,
        "127.0.0.1:53".parse().expect("source addr")
    );
    assert_eq!(response.payload, b"pong");
    server.await.expect("server task");
}

#[tokio::test]
async fn registry_from_tuic_profile_times_out_waiting_for_udp_response() {
    let server_endpoint = quinn::Endpoint::server(
        hy2_h3_test_server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind local registry tuic UDP timeout server");
    let server_addr = server_endpoint.local_addr().expect("server local addr");
    let server = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("server accepts connection");
        let connection = incoming.await.expect("server QUIC connection");
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
        .expect("expected auth");
        assert_eq!(auth, expected_auth);

        let packet = keli_net_core::tuic_read_packet_datagram(&connection)
            .await
            .expect("read TUIC UDP request");
        assert_eq!(packet.payload, b"ping");
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let client = tokio::task::spawn_blocking(move || {
        let registry =
            keli_net_core::OutboundRegistry::from_profiles([keli_protocol::OutboundProfile {
                tag: "tuic".to_string(),
                protocol: keli_protocol::ProxyProtocol::Tuic,
                endpoint: keli_protocol::Endpoint::new("127.0.0.1", server_addr.port()),
                transport: keli_protocol::TransportKind::Quic,
                security: keli_protocol::SecurityKind::Tls {
                    sni: Some("localhost".to_string()),
                    skip_verify: true,
                },
                credential: "00112233-4455-6677-8899-aabbccddeeff:secret".to_string(),
                cipher: None,
                flow: None,
            }])
            .expect("build TUIC registry");
        registry
            .relay_udp_datagram(
                "tuic",
                &keli_net_core::OutboundTarget::new("example.com", 53),
                b"ping",
                Duration::from_millis(50),
            )
            .expect_err("slow TUIC UDP response should time out")
    });

    let error = client.await.expect("client task");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    server.await.expect("server task");
}

#[tokio::test]
async fn hy2_blocking_tcp_stream_relays_via_owned_nonblocking_loop() {
    let server_endpoint = quinn::Endpoint::server(
        hy2_h3_test_server_config(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind local relay hy2 server");
    let server_addr = server_endpoint.local_addr().expect("server local addr");
    let server = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .expect("server accepts connection");
        let connection = incoming.await.expect("server QUIC connection");
        let mut h3_connection: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
            h3::server::builder()
                .build(h3_quinn::Connection::new(connection.clone()))
                .await
                .expect("server h3 connection");
        let resolver = h3_connection
            .accept()
            .await
            .expect("accept auth request")
            .expect("auth request exists");
        let (_request, mut auth_stream) = resolver
            .resolve_request()
            .await
            .expect("resolve auth request");
        auth_stream
            .send_response(http::Response::builder().status(233).body(()).unwrap())
            .await
            .expect("send auth OK");
        auth_stream.finish().await.expect("finish auth OK");

        let (mut send, mut recv) = connection.accept_bi().await.expect("accept HY2 TCP stream");
        let mut request = [0; 19];
        recv.read_exact(&mut request)
            .await
            .expect("read HY2 TCP request");
        send.write_all(&[0x00, 0x00, 0x00])
            .await
            .expect("write HY2 TCP OK response");
        let mut payload = [0; 4];
        recv.read_exact(&mut payload)
            .await
            .expect("read relayed payload");
        assert_eq!(&payload, b"ping");
        send.write_all(b"pong").await.expect("write response");
        send.finish().expect("finish HY2 response stream");
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let (addr_tx, addr_rx) = mpsc::channel();
    let relay = thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local relay client");
        addr_tx
            .send(listener.local_addr().expect("local relay addr"))
            .expect("send relay addr");
        let (client, _) = listener.accept().expect("accept relay client");
        let target = keli_protocol::Endpoint::new("example.com", 443);
        let stream = keli_net_core::Hy2BlockingTcpStream::connect(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            server_addr,
            "localhost",
            true,
            "secret",
            0,
            "pad",
            &target,
            b"",
        )
        .expect("connect blocking HY2 stream");
        keli_net_core::relay_owned_bidirectional_with_options(
            client,
            stream,
            keli_net_core::RelayOptions {
                first_byte_timeout: Some(Duration::from_secs(2)),
                idle_timeout: Some(Duration::from_secs(2)),
            },
        )
    });

    let response = tokio::task::spawn_blocking(move || {
        let addr = addr_rx.recv().expect("receive relay addr");
        let mut client = TcpStream::connect(addr).expect("connect relay client");
        client.write_all(b"ping").expect("write client payload");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("close client write side");
        let mut response = [0; 4];
        client
            .read_exact(&mut response)
            .expect("read relay response");
        response
    })
    .await
    .expect("client task");

    assert_eq!(response, *b"pong");
    let stats = relay
        .join()
        .expect("relay thread")
        .expect("relay completes over HY2 stream");
    assert_eq!(stats.client_to_remote_bytes, 4);
    assert_eq!(stats.remote_to_client_bytes, 4);
    server.await.expect("server task");
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
