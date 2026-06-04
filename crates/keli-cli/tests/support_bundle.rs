use serde_json::Value;

#[test]
fn support_bundle_includes_doctor_and_redacted_profile_summary() {
    let config = r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
  - name: WG-SKIPPED
    type: wireguard
    server: wg.example.com
    port: 51820
    password: ignored
  - name: VLESS-EDGE
    type: vless
    server: vless.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    network: ws
    tls: true
    skip-cert-verify: true
    servername: private-sni.example.com
    ws-opts:
      path: /private-ws-path
      headers:
        Host: private-host.example.com
"#;
    let mut output = Vec::new();

    keli_cli::write_support_bundle_report(Some(config), &mut output).expect("write support bundle");

    let report: Value = serde_json::from_slice(&output).expect("support bundle json");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["kind"], "keli_support_bundle");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["doctor"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["doctor"]["platform"], "Windows");
    assert_eq!(report["doctor"]["route_rule_capabilities"][3], "ip-cidr");
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][7],
        "relay-plan"
    );
    assert_eq!(report["tun_preflight"]["status"], "lifecycle-unavailable");
    assert_eq!(report["tun_preflight"]["ready"], false);
    assert_eq!(
        report["tun_preflight"]["config"]["interface_name"],
        "keli-tun0"
    );
    assert_eq!(
        report["tun_preflight"]["config"]["address_cidr"],
        "10.7.0.1/24"
    );
    assert_eq!(
        report["tun_preflight"]["device"]["lifecycle_available"],
        false
    );
    assert_eq!(report["profile"]["status"], "ok");
    assert_eq!(report["profile"]["source_format"], "mihomo_yaml");
    assert_eq!(report["profile"]["supported_count"], 2);
    assert_eq!(report["profile"]["skipped_count"], 1);
    assert_eq!(report["profile"]["supported_tags"][0], "SS-READY");
    assert_eq!(report["profile"]["supported_tags"][1], "VLESS-EDGE");
    assert_eq!(report["profile"]["supported"][0]["tag"], "SS-READY");
    assert_eq!(report["profile"]["supported"][0]["protocol"], "Shadowsocks");
    assert_eq!(report["profile"]["supported"][0]["transport"], "tcp");
    assert_eq!(report["profile"]["supported"][0]["security"], "none");
    assert_eq!(report["profile"]["supported"][0]["udp_supported"], true);
    assert!(report["profile"]["supported"][0]["tls_skip_verify"].is_null());
    assert_eq!(report["profile"]["supported"][1]["tag"], "VLESS-EDGE");
    assert_eq!(report["profile"]["supported"][1]["protocol"], "Vless");
    assert_eq!(report["profile"]["supported"][1]["transport"], "ws");
    assert_eq!(report["profile"]["supported"][1]["security"], "tls");
    assert_eq!(report["profile"]["supported"][1]["udp_supported"], true);
    assert_eq!(report["profile"]["supported"][1]["tls_skip_verify"], true);
    assert_eq!(
        report["profile"]["skipped_summary"][0]["reason"],
        "unsupported protocol: wireguard"
    );
    assert_eq!(report["redaction"]["credentials"], "omitted");

    let output = String::from_utf8(output).expect("support bundle utf8");
    assert!(!output.contains("secret"));
    assert!(!output.contains("00112233-4455-6677-8899-aabbccddeeff"));
    assert!(!output.contains("ss.example.com"));
    assert!(!output.contains("wg.example.com"));
    assert!(!output.contains("vless.example.com"));
    assert!(!output.contains("private-sni.example.com"));
    assert!(!output.contains("private-host.example.com"));
    assert!(!output.contains("/private-ws-path"));
}

#[test]
fn support_bundle_reports_profile_parse_error_without_failing_bundle() {
    let mut output = Vec::new();

    keli_cli::write_support_bundle_report(Some("not a valid subscription : :"), &mut output)
        .expect("write support bundle");

    let report: Value = serde_json::from_slice(&output).expect("support bundle json");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["profile"]["status"], "error");
    assert!(report["profile"]["error"]
        .as_str()
        .expect("profile error")
        .contains("profile config parse failed"));
}

#[test]
fn support_bundle_allows_missing_profile() {
    let mut output = Vec::new();

    keli_cli::write_support_bundle_report(None, &mut output).expect("write support bundle");

    let report: Value = serde_json::from_slice(&output).expect("support bundle json");
    assert_eq!(report["status"], "ok");
    assert!(report["profile"].is_null());
}
