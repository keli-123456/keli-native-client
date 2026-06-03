use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
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
