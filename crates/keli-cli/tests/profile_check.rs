use keli_cli::ProbeOutputFormat;

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
