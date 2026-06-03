use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use keli_net_core::{h3_quic_client_config, h3_rustls_client_config};

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
