use std::time::Duration;

use keli_cli::{
    SupportBundleOptions, DEFAULT_CORE_CERTIFICATION_SCHEMA_VERSION,
    DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS, DOCTOR_REPORT_SCHEMA_VERSION,
    INTEROP_MATRIX_SCHEMA_VERSION, MANAGED_CONNECTION_REPORT_HISTORY_LIMIT,
    MANAGED_MIXED_RECENT_EVENT_LIMIT, MANAGED_MIXED_STATUS_SCHEMA_VERSION,
    READINESS_CHECK_SCHEMA_VERSION, SUPPORT_BUNDLE_SCHEMA_VERSION,
};
use keli_client_core::DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT;
use keli_net_core::DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS;
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
    assert_eq!(report["schema_version"], SUPPORT_BUNDLE_SCHEMA_VERSION);
    assert_eq!(
        report["doctor"]["schema_version"],
        DOCTOR_REPORT_SCHEMA_VERSION
    );
    assert_eq!(
        report["doctor"]["schema_versions"]["support_bundle"],
        SUPPORT_BUNDLE_SCHEMA_VERSION
    );
    assert_eq!(
        report["doctor"]["schema_versions"]["interop_matrix"],
        INTEROP_MATRIX_SCHEMA_VERSION
    );
    assert_eq!(
        report["doctor"]["schema_versions"]["readiness_check"],
        READINESS_CHECK_SCHEMA_VERSION
    );
    assert_eq!(
        report["doctor"]["schema_versions"]["default_core_certification"],
        DEFAULT_CORE_CERTIFICATION_SCHEMA_VERSION
    );
    assert_eq!(
        report["doctor"]["schema_versions"]["managed_mixed_status"],
        MANAGED_MIXED_STATUS_SCHEMA_VERSION
    );
    assert_eq!(report["interop_matrix"]["status"], "ok");
    assert_eq!(report["interop_matrix"]["kind"], "keli_interop_matrix");
    assert_eq!(
        report["interop_matrix"]["schema_version"],
        INTEROP_MATRIX_SCHEMA_VERSION
    );
    assert_eq!(report["interop_matrix"]["summary"]["protocol_count"], 12);
    assert_eq!(
        report["interop_matrix"]["summary"]["registry_supported_count"],
        12
    );
    assert_eq!(
        report["interop_matrix"]["summary"]["registry_profile_count"],
        27
    );
    assert_eq!(report["interop_matrix"]["entries"][1]["protocol"], "trojan");
    assert_eq!(
        report["interop_matrix"]["entries"][1]["registry_supported"],
        true
    );
    assert_eq!(report["doctor"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["doctor"]["platform"], "Windows");
    assert_eq!(report["doctor"]["tun_backend"]["platform"], "Windows");
    assert_eq!(report["doctor"]["tun_backend"]["backend"], "wintun");
    assert_eq!(report["doctor"]["tun_backend"]["supported"], true);
    assert_eq!(report["doctor"]["tun_backend"]["lifecycle_wired"], true);
    assert_eq!(report["doctor"]["tun_backend"]["packet_io_wired"], true);
    assert_eq!(
        report["doctor"]["tun_backend"]["route_takeover_wired"],
        true
    );
    assert!(report["doctor"]["tun_backend"]["driver_api_available"].is_boolean());
    assert_eq!(report["doctor"]["route_rule_capabilities"][3], "ip-cidr");
    assert_eq!(
        report["doctor"]["subscription_fetch_capabilities"][0],
        "http"
    );
    assert_eq!(
        report["doctor"]["subscription_fetch_capabilities"][1],
        "https"
    );
    assert_eq!(
        report["doctor"]["subscription_fetch_capabilities"][5],
        "profile-check-summary"
    );
    assert_eq!(
        report["doctor"]["subscription_update_capabilities"][0],
        "current-config"
    );
    assert_eq!(
        report["doctor"]["subscription_update_capabilities"][6],
        "redacted-profile-summary"
    );
    assert_eq!(
        report["doctor"]["subscription_update_capabilities"][7],
        "managed-reload-plan"
    );
    assert_eq!(
        report["doctor"]["subscription_update_capabilities"][8],
        "managed-url-reload"
    );
    assert_eq!(
        report["doctor"]["subscription_update_capabilities"][9],
        "managed-url-update-status"
    );
    assert_eq!(
        report["doctor"]["resource_limits"]["runtime_event_history"],
        DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT
    );
    assert_eq!(
        report["doctor"]["resource_limits"]["managed_status_recent_events"],
        MANAGED_MIXED_RECENT_EVENT_LIMIT
    );
    assert_eq!(
        report["doctor"]["resource_limits"]["managed_connection_report_history"],
        MANAGED_CONNECTION_REPORT_HISTORY_LIMIT
    );
    assert_eq!(
        report["doctor"]["resource_limits"]["managed_connection_workers"],
        DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS
    );
    assert_eq!(
        report["doctor"]["resource_limits"]["tun_tcp_max_active_sessions"],
        DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS
    );
    assert_eq!(
        report["doctor"]["managed_connection_metric_capabilities"][0],
        "total-connection-count"
    );
    assert_eq!(
        report["doctor"]["managed_connection_metric_capabilities"][5],
        "route-action-counts"
    );
    assert_eq!(
        report["doctor"]["managed_connection_metric_capabilities"][6],
        "inbound-counts"
    );
    assert_eq!(
        report["doctor"]["managed_connection_metric_capabilities"][19],
        "history-limit"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][0],
        "schema-version"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][1],
        "runtime-status"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][11],
        "runtime-event-diagnostics"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][16],
        "node-health-coverage"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][17],
        "node-health-switch-readiness"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][18],
        "node-health-switch-reason"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][19],
        "node-health-sweep-diagnostic"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][20],
        "node-health-udp-probe"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][21],
        "node-health-udp-aware-recommendation"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][25],
        "panel-state"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][26],
        "subscription-url-update-status"
    );
    assert_eq!(
        report["doctor"]["stability_diagnostic_capabilities"][0],
        "local-mixed-soak"
    );
    assert_eq!(
        report["doctor"]["stability_diagnostic_capabilities"][2],
        "managed-metrics"
    );
    assert_eq!(
        report["doctor"]["stability_diagnostic_capabilities"][5],
        "http-connect"
    );
    assert_eq!(
        report["doctor"]["stability_diagnostic_capabilities"][6],
        "min-duration"
    );
    assert_eq!(
        report["doctor"]["interop_matrix_capabilities"][0],
        "protocol-summary"
    );
    assert_eq!(
        report["doctor"]["interop_matrix_capabilities"][7],
        "support-bundle-export"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][0],
        "doctor-schema"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][8],
        "json-gates"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][9],
        "blocker-summary"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][10],
        "soak-min-duration"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][11],
        "tun-preflight-evidence"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][12],
        "tun-runtime-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][13],
        "tun-runtime-smoke-min-duration"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][14],
        "tun-runtime-smoke-clean-stop"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][15],
        "tun-runtime-smoke-residual-state"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][16],
        "tun-runtime-smoke-traffic-stimulus"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][17],
        "tun-runtime-smoke-icmp-stimulus"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][18],
        "tun-runtime-smoke-dropped-route-evidence"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][19],
        "tun-runtime-smoke-route-takeover-snapshot"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][20],
        "tun-runtime-smoke-route-selection-evidence"
    );
    assert_eq!(
        report["doctor"]["tun_backend_check_capabilities"][0],
        "backend-kind"
    );
    assert_eq!(
        report["doctor"]["tun_backend_check_capabilities"][2],
        "driver-api-load"
    );
    assert_eq!(
        report["doctor"]["tun_backend_check_capabilities"][6],
        "route-takeover-wiring"
    );
    assert_eq!(
        report["doctor"]["tun_backend_check_capabilities"][8],
        "readiness-blocker-detail"
    );
    assert_eq!(
        report["doctor"]["tun_backend_check_capabilities"][9],
        "validated-runtime-install"
    );
    assert_eq!(
        report["doctor"]["tun_backend_check_capabilities"][10],
        "package-dir-source"
    );
    assert_eq!(
        report["doctor"]["tun_backend_check_capabilities"][11],
        "install-plan"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][0],
        "schema-version"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][2],
        "tun-backend-evidence"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][3],
        "tun-preflight-evidence"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][4],
        "tun-runtime-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][5],
        "tun-runtime-smoke-min-duration"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][6],
        "tun-runtime-smoke-clean-stop"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][7],
        "tun-runtime-smoke-residual-state"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][8],
        "tun-runtime-smoke-traffic-stimulus"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][9],
        "tun-runtime-smoke-icmp-stimulus"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][10],
        "tun-runtime-smoke-dropped-route-evidence"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][11],
        "tun-runtime-smoke-route-takeover-snapshot"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][12],
        "tun-runtime-smoke-route-selection-evidence"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][13],
        "non-skipped-soak"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][14],
        "soak-parameters"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][15],
        "soak-min-duration"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][17],
        "promotion-blockers"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][19],
        "text-summary"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][20],
        "support-bundle-export"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][8],
        "dns-query-plan"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][9],
        "dns-engine-response"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][10],
        "packet-process-action"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][12],
        "dns-response-packet"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][13],
        "ipv4-fragment-guard"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][14],
        "ipv6-extension-traversal"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][15],
        "ipv6-extension-guard"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][16],
        "packet-loop"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][17],
        "packet-loop-summary"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][18],
        "managed-packet-loop"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][19],
        "direct-udp-relay"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][20],
        "outbound-udp-relay"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][21],
        "registry-udp-relay"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][22],
        "managed-registry-udp-relay"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][23],
        "listen-mixed-tun-runtime"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][24],
        "concurrent-tun-runtime"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][25],
        "background-runtime-report"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][26],
        "tun-runtime-status-note"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][27],
        "packet-io-readiness"
    );
    assert!(report["doctor"]["tun_packet_pipeline_capabilities"]
        .as_array()
        .expect("TUN packet pipeline capabilities")
        .iter()
        .any(|capability| capability.as_str() == Some("packet-loop-drop-detail")));
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][28],
        "tcp-segment-parse"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][29],
        "tcp-response-packet"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][30],
        "tcp-reset-response"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][31],
        "tcp-syn-ack-response"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][32],
        "tcp-syn-retransmit-guard"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][33],
        "tcp-session-table"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][34],
        "tcp-client-payload-ack"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][35],
        "tcp-client-duplicate-ack"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][36],
        "tcp-client-out-of-order-ack"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][37],
        "tcp-client-overlap-ack"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][38],
        "tcp-client-stale-server-ack"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][39],
        "tcp-client-ack-keepalive"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][40],
        "tcp-server-payload-packet"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][41],
        "tcp-server-payload-retransmit"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][42],
        "tcp-server-payload-ack-clear"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][43],
        "tcp-server-mss-read-clamp"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][44],
        "tcp-session-step-runner"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][45],
        "tcp-session-device-loop"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][46],
        "tcp-server-payload-poll"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][47],
        "tcp-fin-close-ack"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][48],
        "tcp-fin-payload-close"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][49],
        "registry-tcp-fin-payload-close"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][50],
        "tcp-client-fin-half-close"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][51],
        "tcp-client-fin-stale-server-ack"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][52],
        "tcp-client-fin-server-payload-retransmit"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][53],
        "tcp-client-fin-server-payload-ack-clear"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][54],
        "tcp-client-fin-duplicate-poll"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][55],
        "tcp-client-fin-duplicate-payload-poll"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][56],
        "tcp-client-fin-payload-duplicate-poll"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][57],
        "tcp-client-fin-post-close-ack"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][58],
        "tcp-client-fin-post-close-payload-ack"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][59],
        "tcp-close-sequence-guard"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][60],
        "tcp-close-latest-ack-guard"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][61],
        "tcp-unknown-session-reset"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][62],
        "tcp-server-eof-fin-ack"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][63],
        "tcp-server-fin-retransmit"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][64],
        "tcp-server-fin-final-ack"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][65],
        "tcp-server-fin-client-fin-ack"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][66],
        "tcp-server-fin-post-close-guard"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][67],
        "tcp-session-idle-cleanup"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][68],
        "tcp-close-marker-prune-summary"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][69],
        "registry-tcp-session-relay"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][70],
        "combined-tun-relay-loop"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][71],
        "managed-registry-tcp-session-relay"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][72],
        "tcp-relay-plan-summary"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][73],
        "relay-plan"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][74],
        "tun-runtime-last-error-note"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][75],
        "tcp-close-marker-rst-clear"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][76],
        "tcp-close-marker-rst-summary"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][77],
        "tcp-session-state-summary"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][78],
        "tcp-session-state-peak"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][79],
        "tcp-session-limit"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][80],
        "tcp-session-limit-config"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][81],
        "tun-runtime-exit-reason"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][82],
        "tun-runtime-exit-reason-label"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][83],
        "tun-runtime-structured-diagnostic"
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
    assert_eq!(
        report["tun_preflight"]["device"]["packet_io_available"],
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
    assert!(report["default_core_certification"].is_null());

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
fn support_bundle_can_embed_default_core_certification_evidence() {
    let mut output = Vec::new();

    keli_cli::write_support_bundle_report_with_options(
        None,
        SupportBundleOptions {
            include_default_core_certification: true,
            certification_soak_connections: 2,
            certification_first_byte_timeout: Duration::from_secs(2),
            certification_max_connection_workers: 2,
            certification_soak_min_duration: Duration::from_millis(50),
            certification_include_tun_runtime_smoke: false,
            certification_tun_runtime_smoke_min_duration: Duration::from_millis(50),
        },
        &mut output,
    )
    .expect("write support bundle with certification");

    let report: Value = serde_json::from_slice(&output).expect("support bundle json");
    let certification = &report["default_core_certification"];
    assert_eq!(report["schema_version"], SUPPORT_BUNDLE_SCHEMA_VERSION);
    assert_eq!(certification["kind"], "keli_default_core_certification");
    assert_eq!(
        certification["schema_version"],
        DEFAULT_CORE_CERTIFICATION_SCHEMA_VERSION
    );
    assert_eq!(certification["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(certification["certification"]["soak_connections"], 2);
    assert_eq!(
        certification["certification"]["first_byte_timeout_ms"],
        2000
    );
    assert_eq!(certification["certification"]["max_connection_workers"], 2);
    assert_eq!(certification["certification"]["soak_min_duration_ms"], 50);
    assert_eq!(certification["readiness"]["soak_min_duration_ms"], 50);
    let promotion_blockers = certification["promotion_blockers"]
        .as_array()
        .expect("promotion blockers");
    assert_eq!(
        certification["certification"]["blocking_gate_count"].as_u64(),
        Some(promotion_blockers.len() as u64)
    );
    assert_eq!(
        certification["readiness"]["kind"],
        "keli_default_core_readiness"
    );
    assert_eq!(
        certification["readiness"]["summary"]["skipped_gate_count"],
        0
    );
    assert_eq!(
        certification["readiness"]["summary"]["blocking_gate_count"].as_u64(),
        Some(
            certification["readiness"]["blocking_gates"]
                .as_array()
                .expect("readiness blockers")
                .len() as u64
        )
    );
    assert!(certification["tun_backend"]["backend"].is_string());
    assert!(certification["tun_backend_status"].is_string());
    assert!(certification["tun_preflight"]["status"].is_string());
    assert!(certification["tun_preflight"]["ready"].is_boolean());
    assert_eq!(certification["tun_runtime_smoke"]["included"], false);
    assert_eq!(certification["tun_runtime_smoke"]["status"], "not-run");
    assert_eq!(certification["tun_runtime_smoke"]["min_duration_ms"], 50);
    assert!(certification["tun_runtime_smoke"]["elapsed_ms"].is_null());
    assert!(certification["tun_runtime_smoke"]["duration_target_met"].is_null());
    assert!(certification["tun_runtime_smoke"]["loop_activity_observed"].is_null());
    assert!(
        certification["tun_runtime_smoke"]["route_takeover_expected_prefixes_present"].is_null()
    );
    assert!(certification["tun_runtime_smoke"]["route_takeover_expected_prefixes"].is_null());
    assert!(certification["tun_runtime_smoke"]["route_takeover_observed_prefixes"].is_null());
    assert!(certification["tun_runtime_smoke"]["route_takeover_missing_prefixes"].is_null());
    assert!(certification["tun_runtime_smoke"]["route_takeover_error"].is_null());
    assert!(certification["tun_runtime_smoke"]["route_takeover_snapshot"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_required"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_observed"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_packets_observed"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_drop_observed"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_drop_observed"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_attempted"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_source"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_target"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_attempts"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_sent_packets"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_payload_bytes"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_error_count"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_errors"].is_null());
    assert!(
        certification["tun_runtime_smoke"]["traffic_stimulus_route_lookup_attempted"].is_null()
    );
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_route_lookup_command"].is_null());
    assert!(
        certification["tun_runtime_smoke"]["traffic_stimulus_route_lookup_exit_success"].is_null()
    );
    assert!(
        certification["tun_runtime_smoke"]["traffic_stimulus_route_lookup_exit_code"].is_null()
    );
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_route_lookup_stdout"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_route_lookup_stderr"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_route_lookup_error"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_ping_attempted"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_ping_command"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_ping_timeout_ms"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_ping_exit_success"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_ping_exit_code"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_ping_stdout"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_ping_stderr"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_ping_error"].is_null());
    assert!(certification["tun_runtime_smoke"]["processed_packets"].is_null());
    assert!(certification["tun_runtime_smoke"]["idle_events"].is_null());
    assert!(certification["tun_runtime_smoke"]["dropped_packets"].is_null());
    assert!(certification["tun_runtime_smoke"]["last_dropped_flow"].is_null());
    assert!(certification["tun_runtime_smoke"]["last_dropped_route_action"].is_null());
    assert!(certification["tun_runtime_smoke"]["last_dropped_matched_rule"].is_null());
    assert!(certification["tun_runtime_smoke"]["unsupported_packets"].is_null());
    assert!(certification["tun_runtime_smoke"]["last_unsupported_flow"].is_null());
    assert!(certification["tun_runtime_smoke"]["last_unsupported_route_action"].is_null());
    assert!(certification["tun_runtime_smoke"]["last_unsupported_matched_rule"].is_null());
    assert!(certification["tun_runtime_smoke"]["clean_stop_observed"].is_null());
    assert!(certification["tun_runtime_smoke"]["residual_state_clean"].is_null());
    assert!(certification["tun_runtime_smoke"]["exit_reason"].is_null());
    assert!(certification["tun_runtime_smoke"]["stop_requested"].is_null());
    assert!(certification["tun_runtime_smoke"]["tcp_sessions_open"].is_null());
    assert!(certification["tun_runtime_smoke"]["tcp_server_close_markers_open"].is_null());
    assert!(certification["tun_runtime_smoke"]["tcp_post_close_markers_open"].is_null());
    assert!(certification["tun_runtime_smoke"]["report"].is_null());
    assert_eq!(
        certification["certification"]["tun_runtime_smoke_included"],
        false
    );
    assert_eq!(
        certification["certification"]["tun_runtime_smoke_min_duration_ms"],
        50
    );
    assert!(certification["certification"]["tun_runtime_smoke_passed"].is_null());
    assert_eq!(
        certification["certification"]["tun_preflight_ready"],
        certification["tun_preflight"]["ready"]
    );
    assert_eq!(
        certification["readiness"]["tun_preflight"]["config"]["interface_name"],
        "keli-tun0"
    );

    let ready = certification["ready_for_default_core"]
        .as_bool()
        .expect("ready boolean");
    assert_eq!(
        certification["certification"]["ready_for_default_core"],
        ready
    );
    assert_eq!(
        certification["status"].as_str().expect("status"),
        if ready { "ready" } else { "not-ready" }
    );
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
