use std::time::Duration;

use keli_cli::{write_readiness_check_report, ProbeOutputFormat, READINESS_CHECK_SCHEMA_VERSION};
use serde_json::Value;

#[test]
fn readiness_check_json_reports_default_core_gates_with_skipped_soak() {
    let mut output = Vec::new();

    write_readiness_check_report(
        ProbeOutputFormat::Json,
        2,
        Duration::from_secs(2),
        2,
        true,
        &mut output,
    )
    .expect("write readiness check");

    let report: Value = serde_json::from_slice(&output).expect("readiness JSON");
    assert_eq!(report["kind"], "keli_default_core_readiness");
    assert_eq!(report["schema_version"], READINESS_CHECK_SCHEMA_VERSION);
    assert_eq!(report["ready_for_default_core"], false);
    assert_eq!(report["status"], "not-ready");
    assert_eq!(report["summary"]["total_gate_count"], 11);
    assert_eq!(report["summary"]["skipped_gate_count"], 2);

    let gates = report["gates"].as_array().expect("gates");
    let interop = gate(gates, "interop-matrix");
    assert_eq!(interop["category"], "protocols");
    assert_eq!(interop["status"], "passed");
    assert!(interop["detail"]
        .as_str()
        .expect("interop detail")
        .contains("registry_profiles=27/27"));

    let socks5_soak = gate(gates, "mixed-soak-socks5");
    assert_eq!(socks5_soak["status"], "skipped");
    assert!(socks5_soak["detail"]
        .as_str()
        .expect("soak detail")
        .contains("planned_connections=2"));

    let tun = gate(gates, "tun-preflight");
    assert_eq!(tun["category"], "platform");
    assert!(tun["detail"]
        .as_str()
        .expect("tun detail")
        .contains("status="));

    let tun_backend = gate(gates, "tun-backend");
    assert_eq!(tun_backend["category"], "platform");
    assert_eq!(tun_backend["status"], "failed");
    assert!(tun_backend["detail"]
        .as_str()
        .expect("tun backend detail")
        .contains("backend=wintun"));
}

#[test]
fn readiness_check_json_runs_local_soak_gates() {
    let mut output = Vec::new();

    write_readiness_check_report(
        ProbeOutputFormat::Json,
        2,
        Duration::from_secs(2),
        2,
        false,
        &mut output,
    )
    .expect("write readiness check");

    let report: Value = serde_json::from_slice(&output).expect("readiness JSON");
    assert_eq!(report["summary"]["skipped_gate_count"], 0);
    let gates = report["gates"].as_array().expect("gates");
    assert_eq!(gate(gates, "mixed-soak-socks5")["status"], "passed");
    assert_eq!(gate(gates, "mixed-soak-http-connect")["status"], "passed");
}

#[test]
fn readiness_check_text_reports_gate_summary() {
    let mut output = Vec::new();

    write_readiness_check_report(
        ProbeOutputFormat::Text,
        2,
        Duration::from_secs(2),
        2,
        true,
        &mut output,
    )
    .expect("write text readiness check");

    let output = String::from_utf8(output).expect("readiness text");
    assert!(output.contains("readiness status=not-ready schema_version=1 gates=11"));
    assert!(output.contains("readiness gate=interop-matrix category=protocols status=passed"));
    assert!(output.contains("readiness gate=tun-backend category=platform status=failed"));
    assert!(
        output.contains("readiness gate=mixed-soak-http-connect category=stability status=skipped")
    );
}

fn gate<'a>(gates: &'a [Value], name: &str) -> &'a Value {
    gates
        .iter()
        .find(|gate| gate["name"] == name)
        .unwrap_or_else(|| panic!("missing gate {name}"))
}
