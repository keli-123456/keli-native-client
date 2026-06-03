use std::time::Duration;

use keli_cli::{
    mixed_runtime_from_mihomo_config_text, mixed_runtime_from_subscription_config_text,
};
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

#[test]
fn mihomo_profile_config_accepts_hy2_proxy() {
    let yaml = r#"
proxies:
  - name: HY2-READY
    type: hy2
    server: hy2.example.com
    port: 443
    password: secret
    sni: sni.example.com
    skip-cert-verify: true
"#;

    let runtime = mixed_runtime_from_mihomo_config_text(
        yaml,
        Vec::new(),
        relay_options(),
        Some("HY2-READY".to_string()),
    )
    .expect("runtime from HY2 mihomo config");

    let decision = runtime
        .routes
        .decide(&RouteTarget::Domain("youtube.com".to_string()));
    assert_eq!(
        decision.action,
        RouteAction::Outbound("HY2-READY".to_string())
    );
}

#[test]
fn mihomo_profile_config_accepts_tuic_proxy() {
    let yaml = r#"
proxies:
  - name: TUIC-READY
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    password: secret
    sni: sni.example.com
    skip-cert-verify: true
"#;

    let runtime = mixed_runtime_from_mihomo_config_text(
        yaml,
        Vec::new(),
        relay_options(),
        Some("TUIC-READY".to_string()),
    )
    .expect("runtime from TUIC mihomo config");

    let decision = runtime
        .routes
        .decide(&RouteTarget::Domain("youtube.com".to_string()));
    assert_eq!(
        decision.action,
        RouteAction::Outbound("TUIC-READY".to_string())
    );
}

#[test]
fn subscription_profile_config_accepts_base64_share_links() {
    let base64_links = "dHJvamFuOi8vcGFzc3dvcmRAZXhhbXBsZS5jb206NDQzP3NlY3VyaXR5PXRscyZzbmk9ZWRnZS5leGFtcGxlJnR5cGU9d3MmaG9zdD1lZGdlLmV4YW1wbGUmcGF0aD0lMkZhbnN3ZXImYWxsb3dJbnNlY3VyZT0xI3Ryb2phbi13cw==";

    let runtime = mixed_runtime_from_subscription_config_text(
        base64_links,
        Vec::new(),
        relay_options(),
        None,
    )
    .expect("runtime from base64 share config");

    let decision = runtime
        .routes
        .decide(&RouteTarget::Domain("youtube.com".to_string()));
    assert_eq!(
        decision.action,
        RouteAction::Outbound("trojan-ws".to_string())
    );
}

#[test]
fn subscription_profile_config_accepts_hy2_share_links() {
    let links = "hysteria2://secret@hy2.example.com:443/?insecure=1&sni=sni.example.com#hy2-ready";

    let runtime =
        mixed_runtime_from_subscription_config_text(links, Vec::new(), relay_options(), None)
            .expect("runtime from HY2 share config");

    let decision = runtime
        .routes
        .decide(&RouteTarget::Domain("youtube.com".to_string()));
    assert_eq!(
        decision.action,
        RouteAction::Outbound("hy2-ready".to_string())
    );
}

#[test]
fn subscription_profile_config_accepts_tuic_share_links() {
    let links = "tuic://00112233-4455-6677-8899-aabbccddeeff:secret@tuic.example.com:443?sni=sni.example.com&allowInsecure=1#tuic-ready";

    let runtime =
        mixed_runtime_from_subscription_config_text(links, Vec::new(), relay_options(), None)
            .expect("runtime from TUIC share config");

    let decision = runtime
        .routes
        .decide(&RouteTarget::Domain("youtube.com".to_string()));
    assert_eq!(
        decision.action,
        RouteAction::Outbound("tuic-ready".to_string())
    );
}

fn relay_options() -> RelayOptions {
    RelayOptions {
        first_byte_timeout: Some(Duration::from_secs(1)),
        idle_timeout: Some(Duration::from_secs(1)),
    }
}
