use keli_cli::ProbeOutputFormat;
use serde_json::Value;

#[test]
fn profile_check_json_reports_supported_and_skipped_profiles() {
    let config = r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
  - name: VMESS-OLD
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
  - name: NAIVE-TLS
    type: naive
    server: naive.example.com
    port: 443
    username: user
    password: pass
    tls: true
    sni: edge.example.com
    skip-cert-verify: true
  - name: MIERU-TCP
    type: mieru
    server: mieru.example.com
    port-range: 30000-30002
    username: user
    password: pass
    transport: TCP
    udp: true
"#;
    let mut output = Vec::new();

    keli_cli::write_profile_check_report_from_subscription_config_text(
        config,
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect("profile check");

    let report: serde_json::Value = serde_json::from_slice(&output).expect("json report");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["supported_count"], 4);
    assert_eq!(report["skipped_count"], 0);
    assert_eq!(report["default_outbound"], "SS-READY");
    assert_eq!(report["udp_supported_count"], 3);
    assert_eq!(report["supported_tags"][0], "SS-READY");
    assert_eq!(report["supported_tags"][1], "VMESS-OLD");
    assert_eq!(report["supported_tags"][2], "NAIVE-TLS");
    assert_eq!(report["supported_tags"][3], "MIERU-TCP");
    assert_eq!(report["udp_supported_tags"][0], "SS-READY");
    assert_eq!(report["udp_supported_tags"][1], "VMESS-OLD");
    assert_eq!(report["udp_supported_tags"][2], "MIERU-TCP");
    assert_eq!(report["supported"][0]["udp_supported"], true);
    assert_eq!(report["supported"][1]["udp_supported"], true);
    assert_eq!(report["supported"][2]["protocol"], "Naive");
    assert_eq!(report["supported"][2]["udp_supported"], false);
    assert_eq!(report["supported"][3]["protocol"], "Mieru");
    assert_eq!(report["supported"][3]["udp_supported"], true);
}

#[test]
fn profile_check_text_reports_protocol_capability_matrix() {
    let config = r#"
proxies:
  - name: NAIVE-TLS
    type: naive
    server: naive.example.com
    port: 443
    username: user
    password: pass
    tls: true
    sni: edge.example.com
  - name: MIERU-TCP
    type: mieru
    server: mieru.example.com
    port-range: 30000-30002
    username: user
    password: pass
    transport: TCP
    udp: true
"#;
    let mut output = Vec::new();

    keli_cli::write_profile_check_report_from_subscription_config_text(
        config,
        ProbeOutputFormat::Text,
        &mut output,
    )
    .expect("profile check");

    let output = String::from_utf8(output).expect("utf8 output");
    assert!(output.contains(
        "profile status=ok source_format=mihomo_yaml supported=2 skipped=0 default_outbound=NAIVE-TLS registry_error=- udp_supported=1 protocol_capabilities=2"
    ));
    assert!(output.contains(
        "profile capability protocol=Naive tcp_relay_supported=true udp_supported=false tags=NAIVE-TLS"
    ));
    assert!(output.contains(
        "profile capability protocol=Mieru tcp_relay_supported=true udp_supported=true tags=MIERU-TCP"
    ));
}

#[test]
fn profile_check_json_reports_share_link_source_format() {
    let links = "ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#ss-ready";
    let mut output = Vec::new();

    keli_cli::write_profile_check_report_from_subscription_config_text(
        links,
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect("profile check");

    let report: Value = serde_json::from_slice(&output).expect("json report");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["source_format"], "share_links");
    assert_eq!(report["supported_count"], 1);
    assert_eq!(report["protocol_capability_count"], 1);
    assert_eq!(
        protocol_capability(&report, "Shadowsocks")["udp_supported"],
        true
    );
}

#[test]
fn profile_check_json_reports_protocol_capability_matrix() {
    let config = r#"
proxies:
  - name: TROJAN-WS
    type: trojan
    server: trojan.example.com
    port: 443
    password: password
    sni: sni.example.com
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /answer
  - name: VLESS-WS
    type: vless
    server: vless.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    tls: true
    servername: sni.example.com
    network: ws
    ws-opts:
      path: /vless
  - name: VMESS-TCP
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    alterId: 0
    cipher: none
  - name: SS-AEAD
    type: ss
    server: ss.example.com
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: secret
  - name: ANYTLS
    type: anytls
    server: anytls.example.com
    port: 443
    password: secret
    sni: sni.example.com
    skip-cert-verify: true
  - name: NAIVE-TLS
    type: naive
    server: naive.example.com
    port: 443
    username: user
    password: pass
    tls: true
    sni: edge.example.com
  - name: MIERU-TCP
    type: mieru
    server: mieru.example.com
    port-range: 30000-30002
    username: user
    password: pass
    transport: TCP
    udp: true
  - name: HY2
    type: hy2
    server: hy2.example.com
    port: 443
    password: secret
    sni: sni.example.com
    skip-cert-verify: true
  - name: TUIC
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    token: secret
  - name: SOCKS5
    type: socks5
    server: socks.example.com
    port: 1080
    username: user
    password: pass
  - name: HTTP
    type: http
    server: http.example.com
    port: 8080
    username: user
    password: pass
"#;
    let mut output = Vec::new();

    keli_cli::write_profile_check_report_from_subscription_config_text(
        config,
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect("profile check");

    let report: Value = serde_json::from_slice(&output).expect("json report");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["supported_count"], 11);
    assert_eq!(report["protocol_capability_count"], 11);
    assert_eq!(
        protocol_capability(&report, "Trojan")["tags"][0],
        "TROJAN-WS"
    );
    assert_eq!(
        protocol_capability(&report, "Trojan")["tcp_relay_supported"],
        true
    );
    assert_eq!(
        protocol_capability(&report, "Trojan")["udp_supported"],
        true
    );
    for protocol in [
        "Vless",
        "Vmess",
        "Shadowsocks",
        "AnyTls",
        "Mieru",
        "Hy2",
        "Tuic",
        "Socks",
    ] {
        assert_eq!(
            protocol_capability(&report, protocol)["udp_supported"],
            true
        );
    }
    assert_eq!(
        protocol_capability(&report, "Naive")["tcp_relay_supported"],
        true
    );
    assert_eq!(
        protocol_capability(&report, "Naive")["udp_supported"],
        false
    );
    assert_eq!(
        protocol_capability(&report, "Http")["tcp_relay_supported"],
        true
    );
    assert_eq!(protocol_capability(&report, "Http")["udp_supported"], false);
}

fn protocol_capability<'a>(report: &'a Value, protocol: &str) -> &'a Value {
    report["protocol_capabilities"]
        .as_array()
        .expect("protocol capabilities array")
        .iter()
        .find(|capability| capability["protocol"] == protocol)
        .expect("protocol capability")
}
