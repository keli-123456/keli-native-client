use std::time::Duration;

use keli_cli::{
    write_default_core_certification_report, write_readiness_check_report, ProbeOutputFormat,
    DEFAULT_CORE_CERTIFICATION_SCHEMA_VERSION, READINESS_CHECK_SCHEMA_VERSION,
};
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
    let blocking_gates = report["blocking_gates"].as_array().expect("blocking gates");
    assert_eq!(
        report["summary"]["blocking_gate_count"].as_u64(),
        Some(blocking_gates.len() as u64)
    );

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
    assert_eq!(
        gate(blocking_gates, "mixed-soak-socks5")["status"],
        "skipped"
    );
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
    assert_eq!(gate(blocking_gates, "tun-backend")["status"], "failed");
    assert!(tun_backend["detail"]
        .as_str()
        .expect("tun backend detail")
        .contains("backend=wintun"));
    assert!(tun_backend["detail"]
        .as_str()
        .expect("tun backend detail")
        .contains("route_takeover_wired=true"));
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
    assert!(output.contains("readiness status=not-ready schema_version=2 gates=11"));
    assert!(output.contains("blockers="));
    assert!(output.contains("readiness gate=interop-matrix category=protocols status=passed"));
    assert!(output.contains("readiness gate=tun-backend category=platform status=failed"));
    assert!(output.contains("readiness blocker=tun-backend category=platform status=failed"));
    assert!(
        output.contains("readiness gate=mixed-soak-http-connect category=stability status=skipped")
    );
    assert!(output
        .contains("readiness blocker=mixed-soak-http-connect category=stability status=skipped"));
}

#[test]
fn default_core_certification_json_embeds_readiness_and_backend_evidence() {
    let mut output = Vec::new();

    write_default_core_certification_report(
        ProbeOutputFormat::Json,
        2,
        Duration::from_secs(2),
        2,
        &mut output,
    )
    .expect("write default core certification");

    let report: Value = serde_json::from_slice(&output).expect("certification JSON");
    assert_eq!(report["kind"], "keli_default_core_certification");
    assert_eq!(
        report["schema_version"],
        DEFAULT_CORE_CERTIFICATION_SCHEMA_VERSION
    );
    assert_eq!(report["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["certification"]["soak_connections"], 2);
    assert_eq!(report["certification"]["first_byte_timeout_ms"], 2000);
    assert_eq!(report["certification"]["max_connection_workers"], 2);
    let promotion_blockers = report["promotion_blockers"]
        .as_array()
        .expect("promotion blockers");
    assert_eq!(
        report["certification"]["blocking_gate_count"].as_u64(),
        Some(promotion_blockers.len() as u64)
    );
    assert_eq!(report["readiness"]["kind"], "keli_default_core_readiness");
    assert_eq!(report["readiness"]["summary"]["skipped_gate_count"], 0);
    assert_eq!(
        report["readiness"]["summary"]["blocking_gate_count"].as_u64(),
        Some(
            report["readiness"]["blocking_gates"]
                .as_array()
                .expect("readiness blockers")
                .len() as u64
        )
    );
    assert_eq!(
        report["readiness"]["schema_version"],
        READINESS_CHECK_SCHEMA_VERSION
    );
    assert!(report["tun_backend"]["backend"].is_string());
    assert!(report["tun_backend_status"].is_string());

    let ready = report["ready_for_default_core"]
        .as_bool()
        .expect("ready boolean");
    assert_eq!(report["certification"]["ready_for_default_core"], ready);
    assert_eq!(
        report["status"].as_str().expect("status"),
        if ready { "ready" } else { "not-ready" }
    );

    let gates = report["readiness"]["gates"].as_array().expect("gates");
    assert_eq!(gate(gates, "mixed-soak-socks5")["status"], "passed");
    assert_eq!(gate(gates, "mixed-soak-http-connect")["status"], "passed");
}

#[test]
fn default_core_certification_text_reports_summary_and_gates() {
    let mut output = Vec::new();

    write_default_core_certification_report(
        ProbeOutputFormat::Text,
        2,
        Duration::from_secs(2),
        2,
        &mut output,
    )
    .expect("write default core certification");

    let output = String::from_utf8(output).expect("certification text");
    assert!(output.contains("default_core_certification status="));
    assert!(output.contains("schema_version=2"));
    assert!(output.contains("blockers="));
    assert!(output.contains("tun_backend_status="));
    assert!(output.contains("parameters soak_connections=2 first_byte_timeout_ms=2000"));
    assert!(output.contains("default_core_certification promotion_blocker="));
    assert!(output.contains(
        "default_core_certification readiness_gate=mixed-soak-socks5 category=stability status=passed"
    ));
}

fn gate<'a>(gates: &'a [Value], name: &str) -> &'a Value {
    gates
        .iter()
        .find(|gate| gate["name"] == name)
        .unwrap_or_else(|| panic!("missing gate {name}"))
}
