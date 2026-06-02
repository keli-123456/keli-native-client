use std::time::Duration;

use keli_cli::mixed_runtime_from_mihomo_config_text;
use keli_net_core::{RelayOptions, RouteAction, RouteTarget};

#[test]
fn mihomo_profile_config_sets_default_outbound_route() {
    let yaml = r#"
proxies:
  - name: 美国-TROJAN-54
    type: trojan
    server: 127.0.0.1
    port: 443
    password: password
    sni: edge.example
    network: ws
    ws-opts:
      path: /answer
"#;

    let runtime = mixed_runtime_from_mihomo_config_text(
        yaml,
        Vec::new(),
        relay_options(),
        Some("美国-TROJAN-54".to_string()),
    )
    .expect("runtime from profile config");

    let decision = runtime
        .routes
        .decide(&RouteTarget::Domain("youtube.com".to_string()));
    assert_eq!(
        decision.action,
        RouteAction::Outbound("美国-TROJAN-54".to_string())
    );
}

#[test]
fn mihomo_profile_config_rejects_unknown_outbound_tag() {
    let yaml = r#"
proxies:
  - name: 德国-VLESS-21
    type: vless
    server: edge.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
"#;

    let error = mixed_runtime_from_mihomo_config_text(
        yaml,
        Vec::new(),
        relay_options(),
        Some("missing".to_string()),
    )
    .expect_err("unknown outbound tag should fail");

    assert!(error.contains("outbound tag not found"));
    assert!(error.contains("missing"));
}

fn relay_options() -> RelayOptions {
    RelayOptions {
        first_byte_timeout: Some(Duration::from_secs(1)),
        idle_timeout: Some(Duration::from_secs(1)),
    }
}
