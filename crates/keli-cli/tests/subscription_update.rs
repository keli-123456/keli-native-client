use keli_cli::{write_subscription_update_report_from_config_text, ProbeOutputFormat};
use serde_json::Value;

fn ss_config(entries: &[(&str, &str)]) -> String {
    let mut config = String::from("proxies:\n");
    for (tag, server) in entries {
        config.push_str(&format!(
            r#"  - name: {tag}
    type: ss
    server: {server}
    port: 8388
    cipher: aes-256-gcm
    password: secret-{tag}
"#
        ));
    }
    config
}

#[test]
fn subscription_update_json_preserves_selected_outbound_and_redacts_profiles() {
    let current = ss_config(&[
        ("SS-OLD", "old.example.com"),
        ("SS-STAY", "stay.example.com"),
    ]);
    let new = format!(
        r#"{}
  - name: WG-SKIPPED
    type: wireguard
    server: wg.example.com
    port: 51820
    password: ignored-secret
"#,
        ss_config(&[
            ("SS-STAY", "stay-next.example.com"),
            ("SS-NEW", "new.example.com"),
        ])
    );
    let mut output = Vec::new();

    write_subscription_update_report_from_config_text(
        Some(&current),
        &new,
        Some("SS-STAY"),
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect("subscription update report");

    let output_text = String::from_utf8(output).expect("utf8 output");
    let report: Value = serde_json::from_str(&output_text).expect("json report");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["kind"], "keli_subscription_update");
    assert_eq!(report["update"]["usable"], true);
    assert_eq!(report["update"]["reason"], "selected-outbound-preserved");
    assert_eq!(report["update"]["current_supported_count"], 2);
    assert_eq!(report["update"]["new_supported_count"], 2);
    assert_eq!(report["update"]["new_skipped_count"], 1);
    assert_eq!(report["update"]["current_default_outbound"], "SS-OLD");
    assert_eq!(report["update"]["new_default_outbound"], "SS-STAY");
    assert_eq!(report["update"]["current_selected_outbound"], "SS-STAY");
    assert_eq!(report["update"]["planned_selected_outbound"], "SS-STAY");
    assert_eq!(report["update"]["selected_outbound_preserved"], true);
    assert_eq!(report["update"]["selected_outbound_changed"], false);
    assert_eq!(report["update"]["added_tags"][0], "SS-NEW");
    assert_eq!(report["update"]["removed_tags"][0], "SS-OLD");
    assert_eq!(report["update"]["retained_tags"][0], "SS-STAY");
    assert_eq!(report["current_profile"]["supported_count"], 2);
    assert_eq!(report["new_profile"]["supported_count"], 2);
    assert_eq!(report["new_profile"]["skipped_count"], 1);
    assert_eq!(report["redaction"]["credentials"], "omitted");

    for secret in [
        "secret-SS-OLD",
        "secret-SS-STAY",
        "secret-SS-NEW",
        "ignored-secret",
        "old.example.com",
        "stay.example.com",
        "stay-next.example.com",
        "new.example.com",
        "wg.example.com",
    ] {
        assert!(!output_text.contains(secret), "leaked {secret}");
    }
}

#[test]
fn subscription_update_text_reports_default_fallback_when_selected_is_removed() {
    let current = ss_config(&[("SS-A", "a.example.com"), ("SS-B", "b.example.com")]);
    let new = ss_config(&[("SS-C", "c.example.com"), ("SS-D", "d.example.com")]);
    let mut output = Vec::new();

    write_subscription_update_report_from_config_text(
        Some(&current),
        &new,
        Some("SS-B"),
        ProbeOutputFormat::Text,
        &mut output,
    )
    .expect("subscription update report");

    let output = String::from_utf8(output).expect("utf8 output");
    assert!(output.contains("subscription-update status=ok usable=true"));
    assert!(output.contains("reason=selected-outbound-missing-use-default"));
    assert!(output.contains("current_selected=SS-B"));
    assert!(output.contains("planned_selected=SS-C"));
    assert!(output.contains("preserved=false"));
    assert!(output.contains("changed=true"));
    assert!(output.contains("added=SS-C,SS-D"));
    assert!(output.contains("removed=SS-A,SS-B"));
}

#[test]
fn subscription_update_json_reports_unusable_new_subscription() {
    let current = ss_config(&[("SS-READY", "ready.example.com")]);
    let new = r#"
proxies:
  - name: WG-SKIPPED
    type: wireguard
    server: wg.example.com
    port: 51820
    password: ignored
"#;
    let mut output = Vec::new();

    write_subscription_update_report_from_config_text(
        Some(&current),
        new,
        Some("SS-READY"),
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect("subscription update report");

    let report: Value = serde_json::from_slice(&output).expect("json report");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["update"]["usable"], false);
    assert_eq!(report["update"]["reason"], "no-supported-outbounds");
    assert_eq!(report["update"]["new_supported_count"], 0);
    assert_eq!(report["update"]["new_skipped_count"], 1);
    assert!(report["update"]["planned_selected_outbound"].is_null());
    assert_eq!(report["new_profile"]["status"], "error");
}
