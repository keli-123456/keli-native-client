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
