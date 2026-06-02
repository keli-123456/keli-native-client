use keli_protocol::{
    parse_mihomo_outbound_profiles, Endpoint, ProxyProtocol, SecurityKind, TransportKind,
};

#[test]
fn parses_trojan_ws_tls_proxy_from_mihomo_yaml() {
    let yaml = r#"
proxies:
  - name: 美国-TROJAN-54
    type: trojan
    server: 123.dnscloudcloud.top
    port: 443
    password: 0b700559-6e2a-493a-acca-fdea6190ce07
    udp: true
    skip-cert-verify: false
    sni: 675441.123903.xyz
    network: ws
    ws-opts:
      path: /answer
      headers:
        Host: 675441.123903.xyz
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "美国-TROJAN-54");
    assert_eq!(profile.protocol, ProxyProtocol::Trojan);
    assert_eq!(
        profile.endpoint,
        Endpoint::new("123.dnscloudcloud.top", 443)
    );
    assert_eq!(
        profile.transport,
        TransportKind::WebSocket {
            path: "/answer".to_string(),
            host: Some("675441.123903.xyz".to_string()),
        }
    );
    assert_eq!(
        profile.security,
        SecurityKind::Tls {
            sni: Some("675441.123903.xyz".to_string()),
            skip_verify: false,
        }
    );
    assert_eq!(profile.credential, "0b700559-6e2a-493a-acca-fdea6190ce07");
    profile.validate().expect("valid profile");
}

#[test]
fn parses_vless_ws_tls_proxy_from_mihomo_yaml() {
    let yaml = r#"
proxies:
  - name: 德国-VLESS-21
    type: vless
    server: edge.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    tls: true
    servername: sni.example.com
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vless
      headers:
        host: host.example.com
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "德国-VLESS-21");
    assert_eq!(profile.protocol, ProxyProtocol::Vless);
    assert_eq!(profile.endpoint, Endpoint::new("edge.example.com", 443));
    assert_eq!(
        profile.transport,
        TransportKind::WebSocket {
            path: "/vless".to_string(),
            host: Some("host.example.com".to_string()),
        }
    );
    assert_eq!(
        profile.security,
        SecurityKind::Tls {
            sni: Some("sni.example.com".to_string()),
            skip_verify: true,
        }
    );
    assert_eq!(profile.credential, "00112233-4455-6677-8899-aabbccddeeff");
    profile.validate().expect("valid profile");
}

#[test]
fn reports_unsupported_proxy_without_dropping_supported_entries() {
    let yaml = r#"
proxies:
  - name: ss-not-yet
    type: ss
    server: ss.example.com
    port: 8388
    cipher: 2022-blake3-aes-128-gcm
    password: secret
  - name: tcp-vless
    type: vless
    server: vless.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert_eq!(parsed.profiles.len(), 1);
    assert_eq!(parsed.profiles[0].tag, "tcp-vless");
    assert_eq!(parsed.skipped.len(), 1);
    assert_eq!(parsed.skipped[0].name, "ss-not-yet");
    assert!(parsed.skipped[0].reason.contains("unsupported protocol"));
}
