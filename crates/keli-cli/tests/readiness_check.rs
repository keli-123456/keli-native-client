use std::time::Duration;

use keli_cli::{
    write_default_core_certification_report,
    write_default_core_certification_report_with_soak_min_duration, write_readiness_check_report,
    write_readiness_check_report_with_soak_min_duration, ProbeOutputFormat,
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
    assert_eq!(report["soak_min_duration_ms"], 0);
    assert_eq!(
        report["tun_preflight"]["config"]["interface_name"],
        "keli-tun0"
    );
    assert!(report["tun_preflight"]["status"].is_string());
    assert!(report["tun_preflight"]["ready"].is_boolean());
    assert_eq!(report["tun_runtime_smoke"]["included"], false);
    assert_eq!(report["tun_runtime_smoke"]["status"], "not-run");
    assert_eq!(report["tun_runtime_smoke"]["min_duration_ms"], 50);
    assert!(report["tun_runtime_smoke"]["elapsed_ms"].is_null());
    assert!(report["tun_runtime_smoke"]["duration_target_met"].is_null());
    assert!(report["tun_runtime_smoke"]["loop_activity_observed"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_expected_prefixes_present"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_expected_prefixes"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_observed_prefixes"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_missing_prefixes"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_error"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_snapshot"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_cleanup_observed"].is_null());
    assert!(
        report["tun_runtime_smoke"]["route_takeover_cleanup_expected_prefixes_absent"].is_null()
    );
    assert!(report["tun_runtime_smoke"]["route_takeover_cleanup_expected_prefixes"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_cleanup_observed_prefixes"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_cleanup_missing_prefixes"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_cleanup_error"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_cleanup_snapshot"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_attempted"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_addresses_command"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_addresses_exit_success"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_addresses_exit_code"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_addresses_stdout"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_addresses_stderr"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_addresses_error"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_interfaces_command"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_interfaces_exit_success"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_interfaces_exit_code"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_interfaces_stdout"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_interfaces_stderr"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_interfaces_error"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_required"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_observed"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_packets_observed"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_drop_observed"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_drop_observed"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_attempted"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_source"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_target"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_attempts"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_sent_packets"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_payload_bytes"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_error_count"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_errors"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_route_lookup_attempted"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_route_lookup_command"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_route_lookup_exit_success"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_route_lookup_exit_code"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_route_lookup_stdout"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_route_lookup_stderr"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_route_lookup_error"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_ping_attempted"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_ping_command"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_ping_timeout_ms"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_ping_exit_success"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_ping_exit_code"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_ping_stdout"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_ping_stderr"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_ping_error"].is_null());
    assert!(report["tun_runtime_smoke"]["processed_packets"].is_null());
    assert!(report["tun_runtime_smoke"]["idle_events"].is_null());
    assert!(report["tun_runtime_smoke"]["dropped_packets"].is_null());
    assert!(report["tun_runtime_smoke"]["recent_dropped_routes"].is_null());
    assert!(report["tun_runtime_smoke"]["last_dropped_flow"].is_null());
    assert!(report["tun_runtime_smoke"]["last_dropped_route_action"].is_null());
    assert!(report["tun_runtime_smoke"]["last_dropped_matched_rule"].is_null());
    assert!(report["tun_runtime_smoke"]["unsupported_packets"].is_null());
    assert!(report["tun_runtime_smoke"]["last_unsupported_flow"].is_null());
    assert!(report["tun_runtime_smoke"]["last_unsupported_route_action"].is_null());
    assert!(report["tun_runtime_smoke"]["last_unsupported_matched_rule"].is_null());
    assert!(report["tun_runtime_smoke"]["clean_stop_observed"].is_null());
    assert!(report["tun_runtime_smoke"]["residual_state_clean"].is_null());
    assert!(report["tun_runtime_smoke"]["exit_reason"].is_null());
    assert!(report["tun_runtime_smoke"]["stop_requested"].is_null());
    assert!(report["tun_runtime_smoke"]["tcp_sessions_open"].is_null());
    assert!(report["tun_runtime_smoke"]["tcp_server_close_markers_open"].is_null());
    assert!(report["tun_runtime_smoke"]["tcp_post_close_markers_open"].is_null());
    assert!(report["tun_runtime_smoke"]["report"].is_null());
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
    assert!(socks5_soak["detail"]
        .as_str()
        .expect("soak detail")
        .contains("planned_min_duration_ms=0"));

    let tun = gate(gates, "tun-preflight");
    assert_eq!(tun["category"], "platform");
    assert!(tun["detail"]
        .as_str()
        .expect("tun detail")
        .contains("status="));

    let tun_backend = gate(gates, "tun-backend");
    assert_eq!(tun_backend["category"], "platform");
    assert!(
        tun_backend["status"] == "passed" || tun_backend["status"] == "failed",
        "unexpected tun backend status: {}",
        tun_backend["status"]
    );
    if tun_backend["status"] == "failed" {
        assert_eq!(gate(blocking_gates, "tun-backend")["status"], "failed");
    } else {
        assert!(find_gate(blocking_gates, "tun-backend").is_none());
    }
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
    assert_eq!(report["soak_min_duration_ms"], 0);
    let gates = report["gates"].as_array().expect("gates");
    assert_eq!(gate(gates, "mixed-soak-socks5")["status"], "passed");
    assert_eq!(gate(gates, "mixed-soak-http-connect")["status"], "passed");
    assert!(gate(gates, "mixed-soak-socks5")["detail"]
        .as_str()
        .expect("socks5 detail")
        .contains("min_duration_ms=0"));
    assert!(gate(gates, "mixed-soak-socks5")["detail"]
        .as_str()
        .expect("socks5 detail")
        .contains("duration_target_met=true"));
}

#[test]
fn readiness_check_json_can_hold_soak_gates_for_min_duration() {
    let mut output = Vec::new();

    write_readiness_check_report_with_soak_min_duration(
        ProbeOutputFormat::Json,
        1,
        Duration::from_secs(2),
        1,
        Duration::from_millis(50),
        false,
        &mut output,
    )
    .expect("write readiness check with min duration");

    let report: Value = serde_json::from_slice(&output).expect("readiness JSON");
    assert_eq!(report["soak_min_duration_ms"], 50);
    let gates = report["gates"].as_array().expect("gates");
    for gate_name in ["mixed-soak-socks5", "mixed-soak-http-connect"] {
        let soak = gate(gates, gate_name);
        assert_eq!(soak["status"], "passed");
        let detail = soak["detail"].as_str().expect("soak detail");
        assert!(detail.contains("min_duration_ms=50"));
        assert!(detail.contains("duration_target_met=true"));
    }
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
    assert!(output.contains(&format!(
        "readiness status=not-ready schema_version={} gates=11",
        READINESS_CHECK_SCHEMA_VERSION
    )));
    assert!(output.contains("blockers="));
    assert!(output.contains("readiness gate=interop-matrix category=protocols status=passed"));
    assert!(output.contains("readiness gate=tun-backend category=platform status="));
    assert!(output.contains("readiness tun_preflight status="));
    assert!(output.contains("readiness tun_runtime_smoke status=not-run included=false"));
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
    assert_eq!(report["certification"]["soak_min_duration_ms"], 0);
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
    assert!(report["tun_preflight"]["status"].is_string());
    assert!(report["tun_preflight"]["ready"].is_boolean());
    assert_eq!(report["tun_runtime_smoke"]["included"], false);
    assert_eq!(report["tun_runtime_smoke"]["status"], "not-run");
    assert_eq!(report["tun_runtime_smoke"]["min_duration_ms"], 50);
    assert!(report["tun_runtime_smoke"]["elapsed_ms"].is_null());
    assert!(report["tun_runtime_smoke"]["duration_target_met"].is_null());
    assert!(report["tun_runtime_smoke"]["loop_activity_observed"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_expected_prefixes_present"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_expected_prefixes"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_observed_prefixes"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_missing_prefixes"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_error"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_snapshot"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_cleanup_observed"].is_null());
    assert!(
        report["tun_runtime_smoke"]["route_takeover_cleanup_expected_prefixes_absent"].is_null()
    );
    assert!(report["tun_runtime_smoke"]["route_takeover_cleanup_expected_prefixes"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_cleanup_observed_prefixes"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_cleanup_missing_prefixes"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_cleanup_error"].is_null());
    assert!(report["tun_runtime_smoke"]["route_takeover_cleanup_snapshot"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_attempted"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_addresses_command"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_addresses_exit_success"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_addresses_exit_code"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_addresses_stdout"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_addresses_stderr"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_addresses_error"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_interfaces_command"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_interfaces_exit_success"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_interfaces_exit_code"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_interfaces_stdout"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_interfaces_stderr"].is_null());
    assert!(report["tun_runtime_smoke"]["interface_snapshot_interfaces_error"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_required"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_observed"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_packets_observed"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_drop_observed"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_drop_observed"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_attempted"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_source"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_target"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_attempts"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_sent_packets"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_payload_bytes"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_error_count"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_errors"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_route_lookup_attempted"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_route_lookup_command"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_route_lookup_exit_success"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_route_lookup_exit_code"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_route_lookup_stdout"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_route_lookup_stderr"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_route_lookup_error"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_ping_attempted"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_ping_command"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_ping_timeout_ms"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_ping_exit_success"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_ping_exit_code"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_ping_stdout"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_ping_stderr"].is_null());
    assert!(report["tun_runtime_smoke"]["traffic_stimulus_ping_error"].is_null());
    assert!(report["tun_runtime_smoke"]["processed_packets"].is_null());
    assert!(report["tun_runtime_smoke"]["idle_events"].is_null());
    assert!(report["tun_runtime_smoke"]["dropped_packets"].is_null());
    assert!(report["tun_runtime_smoke"]["recent_dropped_routes"].is_null());
    assert!(report["tun_runtime_smoke"]["last_dropped_flow"].is_null());
    assert!(report["tun_runtime_smoke"]["last_dropped_route_action"].is_null());
    assert!(report["tun_runtime_smoke"]["last_dropped_matched_rule"].is_null());
    assert!(report["tun_runtime_smoke"]["unsupported_packets"].is_null());
    assert!(report["tun_runtime_smoke"]["last_unsupported_flow"].is_null());
    assert!(report["tun_runtime_smoke"]["last_unsupported_route_action"].is_null());
    assert!(report["tun_runtime_smoke"]["last_unsupported_matched_rule"].is_null());
    assert!(report["tun_runtime_smoke"]["clean_stop_observed"].is_null());
    assert!(report["tun_runtime_smoke"]["residual_state_clean"].is_null());
    assert!(report["tun_runtime_smoke"]["exit_reason"].is_null());
    assert!(report["tun_runtime_smoke"]["stop_requested"].is_null());
    assert!(report["tun_runtime_smoke"]["tcp_sessions_open"].is_null());
    assert!(report["tun_runtime_smoke"]["tcp_server_close_markers_open"].is_null());
    assert!(report["tun_runtime_smoke"]["tcp_post_close_markers_open"].is_null());
    assert!(report["tun_runtime_smoke"]["report"].is_null());
    assert_eq!(report["certification"]["tun_runtime_smoke_included"], false);
    assert_eq!(
        report["certification"]["tun_runtime_smoke_min_duration_ms"],
        50
    );
    assert!(report["certification"]["tun_runtime_smoke_passed"].is_null());
    assert_eq!(
        report["certification"]["tun_preflight_ready"],
        report["tun_preflight"]["ready"]
    );

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
    assert!(output.contains(&format!(
        "schema_version={}",
        DEFAULT_CORE_CERTIFICATION_SCHEMA_VERSION
    )));
    assert!(output.contains("blockers="));
    assert!(output.contains("tun_backend_status="));
    assert!(output.contains("default_core_certification tun_preflight status="));
    assert!(output
        .contains("default_core_certification tun_runtime_smoke status=not-run included=false"));
    assert!(output.contains(
        "parameters soak_connections=2 first_byte_timeout_ms=2000 max_connection_workers=2 soak_min_duration_ms=0"
    ));
    assert!(output.contains(
        "default_core_certification readiness_gate=mixed-soak-socks5 category=stability status=passed"
    ));
}

#[test]
fn default_core_certification_json_records_soak_min_duration() {
    let mut output = Vec::new();

    write_default_core_certification_report_with_soak_min_duration(
        ProbeOutputFormat::Json,
        1,
        Duration::from_secs(2),
        1,
        Duration::from_millis(50),
        &mut output,
    )
    .expect("write default core certification with min duration");

    let report: Value = serde_json::from_slice(&output).expect("certification JSON");
    assert_eq!(report["certification"]["soak_min_duration_ms"], 50);
    assert_eq!(report["readiness"]["soak_min_duration_ms"], 50);
    let gates = report["readiness"]["gates"].as_array().expect("gates");
    assert!(gate(gates, "mixed-soak-socks5")["detail"]
        .as_str()
        .expect("socks5 detail")
        .contains("min_duration_ms=50"));
}

fn gate<'a>(gates: &'a [Value], name: &str) -> &'a Value {
    find_gate(gates, name).unwrap_or_else(|| panic!("missing gate {name}"))
}

fn find_gate<'a>(gates: &'a [Value], name: &str) -> Option<&'a Value> {
    gates.iter().find(|gate| gate["name"] == name)
}
