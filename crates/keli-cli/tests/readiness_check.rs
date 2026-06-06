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
    assert_eq!(report["summary"]["total_gate_count"], 15);
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
    assert_eq!(report["system_proxy_smoke"]["included"], false);
    assert_eq!(report["system_proxy_smoke"]["status"], "not-run");
    assert!(report["system_proxy_smoke"]["passed"].is_null());
    assert_eq!(report["route_rule_smoke"]["status"], "passed");
    assert_eq!(report["route_rule_smoke"]["passed"], true);
    assert_eq!(report["route_rule_smoke"]["case_count"], 3);
    assert_eq!(report["route_rule_smoke"]["failed_case_count"], 0);
    let route_cases = report["route_rule_smoke"]["cases"]
        .as_array()
        .expect("route rule smoke cases");
    let route_case_names: Vec<_> = route_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in ["domain-suffix-block", "cidr-block", "port-block"] {
        assert!(
            route_case_names.contains(&expected),
            "missing route smoke case {expected}: {route_case_names:?}"
        );
    }
    let port_case = route_cases
        .iter()
        .find(|case| case["name"] == "port-block")
        .expect("port route smoke case");
    assert_eq!(port_case["target_contacted"], false);
    assert_eq!(report["dns_policy_smoke"]["status"], "passed");
    assert_eq!(report["dns_policy_smoke"]["passed"], true);
    assert_eq!(report["dns_policy_smoke"]["case_count"], 4);
    assert_eq!(report["dns_policy_smoke"]["failed_case_count"], 0);
    let dns_cases = report["dns_policy_smoke"]["cases"]
        .as_array()
        .expect("DNS policy smoke cases");
    let dns_case_names: Vec<_> = dns_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "prevent-public-leak-http-connect",
        "address-family-http-connect",
        "hijack-localhost-a",
        "hijack-public-leak-nxdomain",
    ] {
        assert!(
            dns_case_names.contains(&expected),
            "missing DNS policy smoke case {expected}: {dns_case_names:?}"
        );
    }
    let dns_address_family = dns_cases
        .iter()
        .find(|case| case["name"] == "address-family-http-connect")
        .expect("address family DNS policy smoke case");
    assert_eq!(dns_address_family["target_contacted"], false);
    assert_eq!(report["subscription_reload_smoke"]["status"], "passed");
    assert_eq!(report["subscription_reload_smoke"]["passed"], true);
    assert_eq!(report["subscription_reload_smoke"]["case_count"], 4);
    assert_eq!(report["subscription_reload_smoke"]["failed_case_count"], 0);
    assert_eq!(report["subscription_reload_smoke"]["initial_generation"], 1);
    assert_eq!(report["subscription_reload_smoke"]["final_generation"], 3);
    assert_eq!(
        report["subscription_reload_smoke"]["final_selected_outbound"],
        "SS-FALLBACK"
    );
    assert_eq!(
        report["subscription_reload_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["subscription_reload_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["subscription_reload_smoke"]["stop_timed_out"], false);
    let subscription_cases = report["subscription_reload_smoke"]["cases"]
        .as_array()
        .expect("subscription reload smoke cases");
    let subscription_case_names: Vec<_> = subscription_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-subscription-runtime",
        "preserve-selected-outbound",
        "fallback-to-new-default",
        "stop-subscription-runtime",
    ] {
        assert!(
            subscription_case_names.contains(&expected),
            "missing subscription reload smoke case {expected}: {subscription_case_names:?}"
        );
    }
    let preserve = subscription_cases
        .iter()
        .find(|case| case["name"] == "preserve-selected-outbound")
        .expect("preserve subscription reload smoke case");
    assert_eq!(preserve["observed_reason"], "selected-outbound-preserved");
    assert_eq!(preserve["observed_selected_outbound"], "SS-STAY");
    assert_eq!(preserve["stale_health_pruned"], true);
    assert_eq!(preserve["selected_health_state"], "healthy");
    let fallback = subscription_cases
        .iter()
        .find(|case| case["name"] == "fallback-to-new-default")
        .expect("fallback subscription reload smoke case");
    assert_eq!(
        fallback["observed_reason"],
        "selected-outbound-missing-use-default"
    );
    assert_eq!(fallback["observed_selected_outbound"], "SS-FALLBACK");
    assert_eq!(fallback["stale_health_pruned"], true);
    assert_eq!(fallback["selected_health_state"], "unknown");
    assert_eq!(report["runtime_recovery_smoke"]["status"], "passed");
    assert_eq!(report["runtime_recovery_smoke"]["passed"], true);
    assert_eq!(report["runtime_recovery_smoke"]["case_count"], 4);
    assert_eq!(report["runtime_recovery_smoke"]["failed_case_count"], 0);
    assert_eq!(report["runtime_recovery_smoke"]["initial_generation"], 1);
    assert_eq!(report["runtime_recovery_smoke"]["final_generation"], 1);
    assert_eq!(
        report["runtime_recovery_smoke"]["final_selected_outbound"],
        "SS-READY"
    );
    assert_eq!(
        report["runtime_recovery_smoke"]["preserved_after_failures"],
        true
    );
    assert_eq!(
        report["runtime_recovery_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["runtime_recovery_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["runtime_recovery_smoke"]["stop_timed_out"], false);
    let recovery_cases = report["runtime_recovery_smoke"]["cases"]
        .as_array()
        .expect("runtime recovery smoke cases");
    let recovery_case_names: Vec<_> = recovery_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-runtime",
        "reject-unknown-outbound-reload",
        "reject-unusable-subscription-update",
        "stop-runtime-after-recovery",
    ] {
        assert!(
            recovery_case_names.contains(&expected),
            "missing runtime recovery smoke case {expected}: {recovery_case_names:?}"
        );
    }
    let unknown = recovery_cases
        .iter()
        .find(|case| case["name"] == "reject-unknown-outbound-reload")
        .expect("unknown outbound recovery case");
    assert_eq!(unknown["observed_error_kind"], "outbound-not-found");
    assert_eq!(unknown["observed_selected_outbound"], "SS-READY");
    assert_eq!(unknown["observed_generation"], 1);
    assert_eq!(unknown["runtime_still_running"], true);
    let unusable = recovery_cases
        .iter()
        .find(|case| case["name"] == "reject-unusable-subscription-update")
        .expect("unusable subscription recovery case");
    assert_eq!(unusable["observed_error_kind"], "no-supported-outbounds");
    assert_eq!(unusable["applied"], false);
    assert_eq!(unusable["observed_selected_outbound"], "SS-READY");
    assert_eq!(unusable["runtime_still_running"], true);
    assert!(report["system_proxy_smoke"]["config"].is_null());
    assert!(report["system_proxy_smoke"]["original_snapshot"].is_null());
    assert!(report["system_proxy_smoke"]["applied_snapshot"].is_null());
    assert!(report["system_proxy_smoke"]["restored_snapshot"].is_null());
    assert!(report["system_proxy_smoke"]["restore_attempted"].is_null());
    assert!(report["system_proxy_smoke"]["restore_succeeded"].is_null());
    assert!(report["system_proxy_smoke"]["restored_original_snapshot_match"].is_null());
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
    assert!(report["tun_runtime_smoke"]["dns_stimulus_required"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_observed"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_hijack_route_observed"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_attempted"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_source"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_target"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_query_name"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_query_type"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_query_id"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_query_bytes"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_response_received"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_response_source"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_response_bytes"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_response_id"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_response_id_matches"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_response_rcode"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_error_count"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_errors"].is_null());
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
    assert!(report["tun_runtime_smoke"]["dns_responses_written"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_hijacked_route_count"].is_null());
    assert!(report["tun_runtime_smoke"]["recent_dropped_routes"].is_null());
    assert!(report["tun_runtime_smoke"]["recent_dns_hijacked_routes"].is_null());
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

    let route_rule = gate(gates, "route-rule-smoke");
    assert_eq!(route_rule["category"], "routing");
    assert_eq!(route_rule["status"], "passed");
    assert!(route_rule["detail"]
        .as_str()
        .expect("route rule detail")
        .contains("cases=3"));

    let dns_policy = gate(gates, "dns-policy-smoke");
    assert_eq!(dns_policy["category"], "dns");
    assert_eq!(dns_policy["status"], "passed");
    assert!(dns_policy["detail"]
        .as_str()
        .expect("DNS policy detail")
        .contains("cases=4"));

    let subscription_reload = gate(gates, "subscription-reload-smoke");
    assert_eq!(subscription_reload["category"], "managed-runtime");
    assert_eq!(subscription_reload["status"], "passed");
    assert!(subscription_reload["detail"]
        .as_str()
        .expect("subscription reload detail")
        .contains("final_selected=SS-FALLBACK"));

    let runtime_recovery = gate(gates, "runtime-recovery-smoke");
    assert_eq!(runtime_recovery["category"], "stability");
    assert_eq!(runtime_recovery["status"], "passed");
    assert!(runtime_recovery["detail"]
        .as_str()
        .expect("runtime recovery detail")
        .contains("preserved_after_failures=true"));

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
        "readiness status=not-ready schema_version={} gates=15",
        READINESS_CHECK_SCHEMA_VERSION
    )));
    assert!(output.contains("blockers="));
    assert!(output.contains("readiness gate=interop-matrix category=protocols status=passed"));
    assert!(output.contains("readiness gate=route-rule-smoke category=routing status=passed"));
    assert!(output.contains("readiness gate=dns-policy-smoke category=dns status=passed"));
    assert!(output.contains(
        "readiness gate=subscription-reload-smoke category=managed-runtime status=passed"
    ));
    assert!(
        output.contains("readiness gate=runtime-recovery-smoke category=stability status=passed")
    );
    assert!(output.contains("readiness gate=tun-backend category=platform status="));
    assert!(output.contains("readiness tun_preflight status="));
    assert!(output.contains("readiness route_rule_smoke status=passed cases=3"));
    assert!(output.contains("readiness dns_policy_smoke status=passed cases=4"));
    assert!(output.contains("readiness subscription_reload_smoke status=passed cases=4"));
    assert!(output.contains("readiness runtime_recovery_smoke status=passed cases=4"));
    assert!(output.contains("readiness system_proxy_smoke status=not-run included=false"));
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
    assert_eq!(report["system_proxy_smoke"]["included"], false);
    assert_eq!(report["system_proxy_smoke"]["status"], "not-run");
    assert!(report["system_proxy_smoke"]["passed"].is_null());
    assert_eq!(report["certification"]["route_rule_smoke_passed"], true);
    assert_eq!(report["route_rule_smoke"]["status"], "passed");
    assert_eq!(report["route_rule_smoke"]["case_count"], 3);
    assert_eq!(report["route_rule_smoke"]["failed_case_count"], 0);
    assert_eq!(report["readiness"]["route_rule_smoke"]["status"], "passed");
    assert_eq!(report["readiness"]["route_rule_smoke"]["case_count"], 3);
    assert_eq!(report["certification"]["dns_policy_smoke_passed"], true);
    assert_eq!(report["dns_policy_smoke"]["status"], "passed");
    assert_eq!(report["dns_policy_smoke"]["case_count"], 4);
    assert_eq!(report["dns_policy_smoke"]["failed_case_count"], 0);
    assert_eq!(report["readiness"]["dns_policy_smoke"]["status"], "passed");
    assert_eq!(report["readiness"]["dns_policy_smoke"]["case_count"], 4);
    assert_eq!(
        report["certification"]["subscription_reload_smoke_passed"],
        true
    );
    assert_eq!(report["subscription_reload_smoke"]["status"], "passed");
    assert_eq!(report["subscription_reload_smoke"]["case_count"], 4);
    assert_eq!(report["subscription_reload_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["subscription_reload_smoke"]["final_selected_outbound"],
        "SS-FALLBACK"
    );
    assert_eq!(
        report["subscription_reload_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["subscription_reload_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["subscription_reload_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["runtime_recovery_smoke_passed"],
        true
    );
    assert_eq!(report["runtime_recovery_smoke"]["status"], "passed");
    assert_eq!(report["runtime_recovery_smoke"]["case_count"], 4);
    assert_eq!(report["runtime_recovery_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["runtime_recovery_smoke"]["final_selected_outbound"],
        "SS-READY"
    );
    assert_eq!(
        report["runtime_recovery_smoke"]["preserved_after_failures"],
        true
    );
    assert_eq!(
        report["runtime_recovery_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["runtime_recovery_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["runtime_recovery_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["system_proxy_smoke_included"],
        false
    );
    assert!(report["certification"]["system_proxy_smoke_passed"].is_null());
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
    assert!(report["tun_runtime_smoke"]["dns_stimulus_required"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_observed"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_hijack_route_observed"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_attempted"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_source"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_target"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_query_name"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_query_type"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_query_id"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_query_bytes"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_response_received"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_response_source"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_response_bytes"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_response_id"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_response_id_matches"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_response_rcode"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_error_count"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_stimulus_errors"].is_null());
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
    assert!(report["tun_runtime_smoke"]["dns_responses_written"].is_null());
    assert!(report["tun_runtime_smoke"]["dns_hijacked_route_count"].is_null());
    assert!(report["tun_runtime_smoke"]["recent_dropped_routes"].is_null());
    assert!(report["tun_runtime_smoke"]["recent_dns_hijacked_routes"].is_null());
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
    assert_eq!(gate(gates, "route-rule-smoke")["status"], "passed");
    assert_eq!(gate(gates, "dns-policy-smoke")["status"], "passed");
    assert_eq!(gate(gates, "subscription-reload-smoke")["status"], "passed");
    assert_eq!(gate(gates, "runtime-recovery-smoke")["status"], "passed");
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
    assert!(output.contains("default_core_certification route_rule_smoke status=passed cases=3"));
    assert!(output.contains("default_core_certification dns_policy_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification subscription_reload_smoke status=passed cases=4"));
    assert!(
        output.contains("default_core_certification runtime_recovery_smoke status=passed cases=4")
    );
    assert!(output
        .contains("default_core_certification system_proxy_smoke status=not-run included=false"));
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
