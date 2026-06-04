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
"#;
    let mut output = Vec::new();

    keli_cli::write_support_bundle_report(Some(config), &mut output).expect("write support bundle");

    let report: Value = serde_json::from_slice(&output).expect("support bundle json");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["kind"], "keli_support_bundle");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["doctor"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["doctor"]["platform"], "Windows");
    assert_eq!(report["profile"]["status"], "ok");
    assert_eq!(report["profile"]["source_format"], "mihomo_yaml");
    assert_eq!(report["profile"]["supported_count"], 1);
    assert_eq!(report["profile"]["skipped_count"], 1);
    assert_eq!(report["profile"]["supported_tags"][0], "SS-READY");
    assert_eq!(
        report["profile"]["skipped_summary"][0]["reason"],
        "unsupported protocol: wireguard"
    );
    assert_eq!(report["redaction"]["credentials"], "omitted");

    let output = String::from_utf8(output).expect("support bundle utf8");
    assert!(!output.contains("secret"));
    assert!(!output.contains("ss.example.com"));
    assert!(!output.contains("wg.example.com"));
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
