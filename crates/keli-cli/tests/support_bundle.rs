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
    assert_eq!(
        report["doctor"]["default_core_release_gate_preset"]["name"],
        "default-core-release-gate"
    );
    assert_eq!(
        report["doctor"]["default_core_release_gate_preset"]["require_machine_takeover_ready"],
        true
    );
    assert_eq!(
        report["doctor"]["default_core_release_gate_preset"]["include_system_proxy_smoke"],
        true
    );
    assert_eq!(
        report["doctor"]["default_core_release_gate_preset"]["include_tun_runtime_smoke"],
        true
    );
    assert_eq!(
        report["doctor"]["default_core_release_gate_preset"]["stability_window_ms"],
        60000
    );
    assert_eq!(
        report["doctor"]["default_core_release_gate_preset"]["stability_connections"],
        25
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
        report["doctor"]["managed_status_schema_capabilities"][12],
        "runtime-tun-drop-history"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][13],
        "runtime-tun-dns-hijack-history"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][18],
        "node-health-coverage"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][19],
        "node-health-switch-readiness"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][20],
        "node-health-switch-reason"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][21],
        "node-health-sweep-diagnostic"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][22],
        "node-health-udp-probe"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][23],
        "node-health-udp-aware-recommendation"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][27],
        "panel-state"
    );
    assert_eq!(
        report["doctor"]["managed_status_schema_capabilities"][28],
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
        report["doctor"]["readiness_check_capabilities"][4],
        "resource-limit-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][5],
        "route-rule-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][6],
        "dns-policy-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][7],
        "subscription-reload-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][8],
        "runtime-recovery-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][11],
        "system-proxy-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][12],
        "system-proxy-smoke-restore-evidence"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][15],
        "json-gates"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][16],
        "blocker-summary"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][17],
        "soak-min-duration"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][18],
        "tun-preflight-evidence"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][19],
        "tun-runtime-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][20],
        "tun-runtime-smoke-min-duration"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][21],
        "tun-runtime-smoke-clean-stop"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][22],
        "tun-runtime-smoke-residual-state"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][23],
        "tun-runtime-smoke-route-cleanup-evidence"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][24],
        "tun-runtime-smoke-dns-hijack-evidence"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][25],
        "tun-runtime-smoke-dns-hijack-route-evidence"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][26],
        "tun-runtime-smoke-interface-address-evidence"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][27],
        "tun-runtime-smoke-traffic-stimulus"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][28],
        "tun-runtime-smoke-required-traffic"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][29],
        "tun-runtime-smoke-icmp-stimulus"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][30],
        "tun-runtime-smoke-dropped-route-evidence"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][31],
        "tun-runtime-smoke-dropped-route-history"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][32],
        "tun-runtime-smoke-route-takeover-snapshot"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][33],
        "tun-runtime-smoke-route-selection-evidence"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][34],
        "panel-subscription-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][35],
        "udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][36],
        "socks5-udp-outbound-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][37],
        "tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][38],
        "socks5-tcp-outbound-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][39],
        "http-connect-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][40],
        "http-connect-outbound-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][41],
        "http-proxy-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][42],
        "trojan-tls-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][43],
        "trojan-ws-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][44],
        "trojan-httpupgrade-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][45],
        "trojan-grpc-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][46],
        "trojan-h2-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][47],
        "trojan-quic-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][48],
        "trojan-quic-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][49],
        "trojan-tls-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][50],
        "anytls-tls-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][51],
        "anytls-tls-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][52],
        "naive-h2-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][53],
        "naive-h3-quic-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][54],
        "hy2-quic-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][55],
        "tuic-quic-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][56],
        "vless-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][57],
        "vless-ws-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][58],
        "vless-ws-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][59],
        "vless-httpupgrade-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][60],
        "vless-httpupgrade-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][61],
        "vless-grpc-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][62],
        "vless-grpc-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][63],
        "vless-h2-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][64],
        "vless-h2-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][65],
        "vless-quic-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][66],
        "vless-quic-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][67],
        "vless-tcp-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][68],
        "vmess-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][69],
        "vmess-ws-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][70],
        "vmess-ws-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][71],
        "vmess-httpupgrade-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][72],
        "vmess-httpupgrade-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][73],
        "vmess-grpc-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][74],
        "vmess-grpc-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][75],
        "vmess-h2-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][76],
        "vmess-h2-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][77],
        "vmess-quic-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][78],
        "vmess-quic-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][79],
        "vmess-tcp-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][80],
        "mieru-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][81],
        "mieru-tcp-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][82],
        "tun-tcp-session-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][83],
        "tun-tcp-session-server-retransmit-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][84],
        "tun-tcp-session-server-fin-retransmit-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][85],
        "tun-tcp-session-post-close-guard-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][86],
        "tun-tcp-unknown-session-reset-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][87],
        "tun-tcp-session-limit-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][88],
        "tun-tcp-session-idle-prune-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][89],
        "tun-tcp-session-close-marker-prune-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][90],
        "tun-tcp-session-close-marker-rst-clear-smoke"
    );
    assert_eq!(
        report["doctor"]["readiness_check_capabilities"][91],
        "machine-takeover-smoke-mode"
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
        "resource-limit-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][3],
        "route-rule-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][4],
        "dns-policy-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][5],
        "subscription-reload-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][6],
        "runtime-recovery-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][7],
        "system-proxy-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][8],
        "system-proxy-smoke-restore-evidence"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][9],
        "tun-backend-evidence"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][10],
        "tun-preflight-evidence"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][11],
        "tun-runtime-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][12],
        "tun-runtime-smoke-min-duration"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][13],
        "tun-runtime-smoke-clean-stop"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][14],
        "tun-runtime-smoke-residual-state"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][15],
        "tun-runtime-smoke-route-cleanup-evidence"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][16],
        "tun-runtime-smoke-dns-hijack-evidence"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][17],
        "tun-runtime-smoke-dns-hijack-route-evidence"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][18],
        "tun-runtime-smoke-interface-address-evidence"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][19],
        "tun-runtime-smoke-traffic-stimulus"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][20],
        "tun-runtime-smoke-required-traffic"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][21],
        "tun-runtime-smoke-icmp-stimulus"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][22],
        "tun-runtime-smoke-dropped-route-evidence"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][23],
        "tun-runtime-smoke-dropped-route-history"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][24],
        "tun-runtime-smoke-route-takeover-snapshot"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][25],
        "tun-runtime-smoke-route-selection-evidence"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][26],
        "non-skipped-soak"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][27],
        "soak-parameters"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][28],
        "soak-min-duration"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][30],
        "promotion-blockers"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][32],
        "text-summary"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][33],
        "support-bundle-export"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][34],
        "panel-subscription-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][35],
        "udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][36],
        "socks5-udp-outbound-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][37],
        "tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][38],
        "socks5-tcp-outbound-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][39],
        "http-connect-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][40],
        "http-connect-outbound-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][41],
        "http-proxy-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][42],
        "trojan-tls-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][43],
        "trojan-ws-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][44],
        "trojan-httpupgrade-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][45],
        "trojan-grpc-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][46],
        "trojan-h2-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][47],
        "trojan-quic-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][48],
        "trojan-quic-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][49],
        "trojan-tls-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][50],
        "anytls-tls-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][51],
        "anytls-tls-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][52],
        "naive-h2-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][53],
        "naive-h3-quic-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][54],
        "hy2-quic-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][55],
        "tuic-quic-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][56],
        "vless-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][57],
        "vless-ws-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][58],
        "vless-ws-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][59],
        "vless-httpupgrade-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][60],
        "vless-httpupgrade-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][61],
        "vless-grpc-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][62],
        "vless-grpc-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][63],
        "vless-h2-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][64],
        "vless-h2-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][65],
        "vless-quic-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][66],
        "vless-quic-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][67],
        "vless-tcp-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][68],
        "vmess-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][69],
        "vmess-ws-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][70],
        "vmess-ws-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][71],
        "vmess-httpupgrade-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][72],
        "vmess-httpupgrade-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][73],
        "vmess-grpc-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][74],
        "vmess-grpc-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][75],
        "vmess-h2-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][76],
        "vmess-h2-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][77],
        "vmess-quic-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][78],
        "vmess-quic-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][79],
        "vmess-tcp-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][80],
        "mieru-tcp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][81],
        "mieru-tcp-udp-relay-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][82],
        "tun-tcp-session-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][83],
        "tun-tcp-session-server-retransmit-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][84],
        "tun-tcp-session-server-fin-retransmit-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][85],
        "tun-tcp-session-post-close-guard-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][86],
        "tun-tcp-unknown-session-reset-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][87],
        "tun-tcp-session-limit-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][88],
        "tun-tcp-session-idle-prune-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][89],
        "tun-tcp-session-close-marker-prune-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][90],
        "tun-tcp-session-close-marker-rst-clear-smoke"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][91],
        "machine-takeover-coverage"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][92],
        "default-core-promotion-verdict"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][93],
        "machine-takeover-smoke-mode"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][94],
        "default-core-release-gate"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][95],
        "default-core-release-gate-stability-evidence"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][96],
        "default-core-release-gate-stability-window"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][97],
        "default-core-release-gate-stability-traffic-floor"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][98],
        "default-core-release-gate-preset"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][99],
        "default-core-release-gate-preset-evidence"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][100],
        "default-core-release-gate-preset-minimums"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][101],
        "default-core-release-gate-stability-summary"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][102],
        "default-core-release-gate-preset-enforced"
    );
    assert_eq!(
        report["doctor"]["default_core_certification_capabilities"][103],
        "default-core-release-gate-preset-scope"
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
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][84],
        "packet-loop-drop-detail"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][85],
        "packet-loop-drop-history"
    );
    assert_eq!(
        report["doctor"]["tun_packet_pipeline_capabilities"][86],
        "packet-loop-dns-hijack-history"
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
            certification_include_system_proxy_smoke: false,
            certification_include_tun_runtime_smoke: false,
            certification_tun_runtime_smoke_min_duration: Duration::from_millis(50),
            certification_require_machine_takeover_ready: false,
            certification_required_stability_window: None,
            certification_required_stability_connections: None,
            certification_release_gate_preset: None,
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
    assert_eq!(
        certification["certification"]["system_proxy_smoke_included"],
        false
    );
    assert!(certification["certification"]["system_proxy_smoke_passed"].is_null());
    assert_eq!(
        certification["certification"]["machine_takeover_smokes_requested"],
        false
    );
    assert_eq!(certification["system_proxy_smoke"]["included"], false);
    assert_eq!(certification["system_proxy_smoke"]["status"], "not-run");
    assert_eq!(certification["takeover_coverage"]["status"], "not-run");
    assert_eq!(certification["takeover_coverage"]["complete"], false);
    assert_eq!(
        certification["takeover_coverage"]["machine_takeover_smokes_requested"],
        false
    );
    assert_eq!(
        certification["takeover_coverage"]["missing_evidence"][0],
        "system-proxy-smoke"
    );
    assert_eq!(
        certification["takeover_coverage"]["missing_evidence"][1],
        "tun-runtime-smoke"
    );
    assert_eq!(
        certification["takeover_coverage"]["failed_evidence_count"],
        0
    );
    let core_gates_ready = certification["ready_for_default_core"]
        .as_bool()
        .expect("ready_for_default_core boolean");
    assert_eq!(
        certification["default_core_promotion"]["core_gates_ready"],
        core_gates_ready
    );
    assert_eq!(
        certification["default_core_promotion"]["machine_takeover_ready"],
        false
    );
    assert_eq!(
        certification["default_core_promotion"]["machine_takeover_smokes_requested"],
        false
    );
    assert_eq!(
        certification["default_core_promotion"]["local_core_default_allowed"],
        core_gates_ready
    );
    assert_eq!(
        certification["default_core_promotion"]["machine_takeover_default_allowed"],
        false
    );
    assert_eq!(
        certification["default_core_promotion"]["missing_takeover_evidence"][0],
        "system-proxy-smoke"
    );
    assert_eq!(
        certification["default_core_promotion"]["missing_takeover_evidence"][1],
        "tun-runtime-smoke"
    );
    assert_eq!(certification["release_gate"]["status"], "not-required");
    assert_eq!(certification["release_gate"]["required_scope"], "none");
    assert_eq!(
        certification["release_gate"]["require_machine_takeover_ready"],
        false
    );
    assert_eq!(
        certification["release_gate"]["require_stability_window"],
        false
    );
    assert!(certification["release_gate"]["required_stability_window_ms"].is_null());
    assert_eq!(
        certification["release_gate"]["require_stability_connections"],
        false
    );
    assert!(certification["release_gate"]["required_stability_connections"].is_null());
    assert_eq!(certification["release_gate"]["passed"], true);
    assert_eq!(
        certification["release_gate"]["machine_takeover_smokes_requested"],
        false
    );
    assert_eq!(certification["release_gate"]["blocker_count"], 0);
    assert_eq!(
        certification["release_gate"]["stability"]["local_soak_min_duration_ms"],
        50
    );
    assert!(certification["release_gate"]["stability"]["required_window_ms"].is_null());
    assert_eq!(
        certification["release_gate"]["stability"]["required_window_met"],
        true
    );
    assert!(certification["release_gate"]["stability"]["required_connections"].is_null());
    assert!(certification["release_gate"]["stability"]["required_connections_met"].is_null());
    assert_eq!(
        certification["release_gate"]["stability"]["local_soak_connections"],
        2
    );
    assert_eq!(
        certification["release_gate"]["stability"]["local_soak_duration_required"],
        true
    );
    assert_eq!(
        certification["release_gate"]["stability"]["local_soak_complete"],
        true
    );
    assert!(certification["release_gate"]["stability"]["local_soak_required_window_met"].is_null());
    assert!(
        certification["release_gate"]["stability"]["tun_runtime_required_window_met"].is_null()
    );
    let promotion_next_actions = certification["default_core_promotion"]["next_actions"]
        .as_array()
        .expect("promotion next actions");
    assert!(promotion_next_actions
        .iter()
        .any(|action| action.as_str() == Some("run-with-include-system-proxy-smoke")));
    assert!(promotion_next_actions
        .iter()
        .any(|action| action.as_str() == Some("run-with-include-tun-runtime-smoke")));
    if core_gates_ready {
        assert_eq!(
            certification["default_core_promotion"]["status"],
            "core-ready"
        );
        assert_eq!(
            certification["default_core_promotion"]["safe_default_scope"],
            "local-core-only"
        );
        assert_eq!(
            certification["default_core_promotion"]["next_action_count"],
            2
        );
        assert_eq!(certification["default_core_promotion"]["blocker_count"], 0);
    } else {
        assert_eq!(certification["default_core_promotion"]["status"], "blocked");
        assert_eq!(
            certification["default_core_promotion"]["safe_default_scope"],
            "none"
        );
        assert_eq!(
            certification["default_core_promotion"]["next_actions"][0],
            "fix-readiness-blockers"
        );
        assert_eq!(
            certification["default_core_promotion"]["blockers"][0],
            "readiness-gates"
        );
        assert_eq!(
            certification["default_core_promotion"]["next_action_count"],
            3
        );
        assert_eq!(certification["default_core_promotion"]["blocker_count"], 1);
    }
    assert_eq!(
        certification["certification"]["route_rule_smoke_passed"],
        true
    );
    assert_eq!(certification["route_rule_smoke"]["status"], "passed");
    assert_eq!(certification["route_rule_smoke"]["case_count"], 3);
    assert_eq!(certification["route_rule_smoke"]["failed_case_count"], 0);
    assert_eq!(
        certification["readiness"]["route_rule_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["route_rule_smoke"]["case_count"],
        3
    );
    assert_eq!(
        certification["certification"]["dns_policy_smoke_passed"],
        true
    );
    assert_eq!(certification["dns_policy_smoke"]["status"], "passed");
    assert_eq!(certification["dns_policy_smoke"]["case_count"], 4);
    assert_eq!(certification["dns_policy_smoke"]["failed_case_count"], 0);
    assert_eq!(
        certification["readiness"]["dns_policy_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["dns_policy_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(certification["tcp_relay_smoke"]["status"], "passed");
    assert_eq!(certification["tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(certification["tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        certification["tcp_relay_smoke"]["selected_outbound"],
        "SS-TCP-SMOKE"
    );
    assert_eq!(
        certification["tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(certification["tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        certification["tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["socks5_tcp_outbound_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["socks5_tcp_outbound_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["socks5_tcp_outbound_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["socks5_tcp_outbound_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["socks5_tcp_outbound_relay_smoke"]["selected_outbound"],
        "SOCKS5-TCP-OUTBOUND-SMOKE"
    );
    assert_eq!(
        certification["socks5_tcp_outbound_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["socks5_tcp_outbound_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["socks5_tcp_outbound_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["socks5_tcp_outbound_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["socks5_tcp_outbound_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["socks5_tcp_outbound_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["socks5_tcp_outbound_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["http_connect_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["http_connect_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["http_connect_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["http_connect_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["http_connect_relay_smoke"]["selected_outbound"],
        "SS-HTTP-CONNECT-SMOKE"
    );
    assert_eq!(
        certification["http_connect_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["http_connect_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["http_connect_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["http_connect_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["http_connect_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["http_connect_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["http_connect_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["http_connect_outbound_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["http_connect_outbound_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["http_connect_outbound_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["http_connect_outbound_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["http_connect_outbound_relay_smoke"]["selected_outbound"],
        "HTTP-CONNECT-OUTBOUND-SMOKE"
    );
    assert_eq!(
        certification["http_connect_outbound_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["http_connect_outbound_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["http_connect_outbound_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["http_connect_outbound_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["http_connect_outbound_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["http_connect_outbound_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["http_connect_outbound_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["http_proxy_relay_smoke_passed"],
        true
    );
    assert_eq!(certification["http_proxy_relay_smoke"]["status"], "passed");
    assert_eq!(certification["http_proxy_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["http_proxy_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["http_proxy_relay_smoke"]["selected_outbound"],
        "SS-HTTP-PROXY-SMOKE"
    );
    assert_eq!(
        certification["http_proxy_relay_smoke"]["target"],
        "example.com:80"
    );
    assert_eq!(
        certification["http_proxy_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["http_proxy_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["http_proxy_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["http_proxy_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["http_proxy_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["http_proxy_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["trojan_tls_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["trojan_tls_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["trojan_tls_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["trojan_tls_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["trojan_tls_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-TLS-TCP-SMOKE"
    );
    assert_eq!(
        certification["trojan_tls_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["trojan_tls_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["trojan_tls_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["trojan_tls_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["trojan_tls_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["trojan_tls_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["trojan_tls_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["trojan_ws_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["trojan_ws_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["trojan_ws_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["trojan_ws_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["trojan_ws_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-WS-TCP-SMOKE"
    );
    assert_eq!(
        certification["trojan_ws_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["trojan_ws_tcp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        certification["trojan_ws_tcp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        certification["trojan_ws_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["trojan_ws_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["trojan_ws_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["trojan_ws_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["trojan_ws_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["trojan_ws_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["trojan_httpupgrade_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["trojan_httpupgrade_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["trojan_httpupgrade_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["trojan_httpupgrade_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["trojan_httpupgrade_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-HU-TCP-SMOKE"
    );
    assert_eq!(
        certification["trojan_httpupgrade_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["trojan_httpupgrade_tcp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        certification["trojan_httpupgrade_tcp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        certification["trojan_httpupgrade_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["trojan_httpupgrade_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["trojan_httpupgrade_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["trojan_httpupgrade_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["trojan_httpupgrade_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["trojan_httpupgrade_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["trojan_grpc_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["trojan_grpc_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["trojan_grpc_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["trojan_grpc_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["trojan_grpc_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-GRPC-TCP-SMOKE"
    );
    assert_eq!(
        certification["trojan_grpc_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["trojan_grpc_tcp_relay_smoke"]["request_payload_bytes"],
        22
    );
    assert_eq!(
        certification["trojan_grpc_tcp_relay_smoke"]["response_payload_bytes"],
        21
    );
    assert_eq!(
        certification["trojan_grpc_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["trojan_grpc_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["trojan_grpc_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["trojan_grpc_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["trojan_grpc_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["trojan_grpc_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["trojan_h2_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["trojan_h2_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["trojan_h2_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["trojan_h2_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["trojan_h2_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-H2-TCP-SMOKE"
    );
    assert_eq!(
        certification["trojan_h2_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["trojan_h2_tcp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        certification["trojan_h2_tcp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        certification["trojan_h2_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["trojan_h2_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["trojan_h2_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["trojan_h2_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["trojan_h2_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["trojan_h2_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["trojan_quic_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["trojan_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["trojan_quic_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["trojan_quic_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["trojan_quic_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-QUIC-TCP-SMOKE"
    );
    assert_eq!(
        certification["trojan_quic_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["trojan_quic_tcp_relay_smoke"]["request_payload_bytes"],
        22
    );
    assert_eq!(
        certification["trojan_quic_tcp_relay_smoke"]["response_payload_bytes"],
        21
    );
    assert_eq!(
        certification["trojan_quic_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["trojan_quic_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["trojan_quic_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["trojan_quic_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["trojan_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["trojan_quic_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_trojan_quic_udp_relay_smoke_certification(certification);
    assert_eq!(
        certification["certification"]["trojan_tls_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["trojan_tls_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["trojan_tls_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["trojan_tls_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["trojan_tls_udp_relay_smoke"]["selected_outbound"],
        "TROJAN-TLS-UDP-SMOKE"
    );
    assert_eq!(
        certification["trojan_tls_udp_relay_smoke"]["target"],
        "example.com:53"
    );
    assert_eq!(
        certification["trojan_tls_udp_relay_smoke"]["request_payload_bytes"],
        21
    );
    assert_eq!(
        certification["trojan_tls_udp_relay_smoke"]["response_payload_bytes"],
        20
    );
    assert_eq!(
        certification["trojan_tls_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["trojan_tls_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["trojan_tls_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["trojan_tls_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["trojan_tls_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["trojan_tls_udp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["anytls_tls_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["anytls_tls_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["anytls_tls_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["anytls_tls_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["anytls_tls_tcp_relay_smoke"]["selected_outbound"],
        "ANYTLS-TLS-TCP-SMOKE"
    );
    assert_eq!(
        certification["anytls_tls_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["anytls_tls_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["anytls_tls_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["anytls_tls_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["anytls_tls_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["anytls_tls_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["anytls_tls_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["anytls_tls_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["anytls_tls_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["anytls_tls_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["anytls_tls_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["anytls_tls_udp_relay_smoke"]["selected_outbound"],
        "ANYTLS-TLS-UDP-SMOKE"
    );
    assert_eq!(
        certification["anytls_tls_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["anytls_tls_udp_relay_smoke"]["request_payload_bytes"],
        21
    );
    assert_eq!(
        certification["anytls_tls_udp_relay_smoke"]["response_payload_bytes"],
        20
    );
    assert_eq!(
        certification["anytls_tls_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["anytls_tls_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["anytls_tls_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["anytls_tls_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["anytls_tls_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["anytls_tls_udp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["naive_h2_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["naive_h2_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["naive_h2_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["naive_h2_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["naive_h2_tcp_relay_smoke"]["selected_outbound"],
        "NAIVE-H2-TCP-SMOKE"
    );
    assert_eq!(
        certification["naive_h2_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["naive_h2_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["naive_h2_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["naive_h2_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["naive_h2_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["naive_h2_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["naive_h2_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["naive_h3_quic_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["naive_h3_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["naive_h3_quic_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["naive_h3_quic_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["naive_h3_quic_tcp_relay_smoke"]["selected_outbound"],
        "NAIVE-H3-QUIC-TCP-SMOKE"
    );
    assert_eq!(
        certification["naive_h3_quic_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["naive_h3_quic_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["naive_h3_quic_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["naive_h3_quic_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["naive_h3_quic_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["naive_h3_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["naive_h3_quic_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["hy2_quic_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["hy2_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["hy2_quic_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["hy2_quic_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["hy2_quic_tcp_relay_smoke"]["selected_outbound"],
        "HY2-QUIC-TCP-SMOKE"
    );
    assert_eq!(
        certification["hy2_quic_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["hy2_quic_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["hy2_quic_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["hy2_quic_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["hy2_quic_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["hy2_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["hy2_quic_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["tuic_quic_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["tuic_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["tuic_quic_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["tuic_quic_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["tuic_quic_tcp_relay_smoke"]["selected_outbound"],
        "TUIC-QUIC-TCP-SMOKE"
    );
    assert_eq!(
        certification["tuic_quic_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["tuic_quic_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["tuic_quic_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["tuic_quic_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["tuic_quic_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["tuic_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["tuic_quic_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["vless_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(certification["vless_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(certification["vless_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vless_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vless_tcp_relay_smoke"]["selected_outbound"],
        "VLESS-TCP-SMOKE"
    );
    assert_eq!(
        certification["vless_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["vless_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vless_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vless_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vless_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["vless_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vless_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["vless_ws_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vless_ws_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vless_ws_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vless_ws_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vless_ws_tcp_relay_smoke"]["selected_outbound"],
        "VLESS-WS-TCP-SMOKE"
    );
    assert_eq!(
        certification["vless_ws_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["vless_ws_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        certification["vless_ws_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        certification["vless_ws_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vless_ws_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vless_ws_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vless_ws_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["vless_ws_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vless_ws_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_vless_ws_udp_relay_smoke_certification(certification);
    assert_eq!(
        certification["certification"]["vless_httpupgrade_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vless_httpupgrade_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["vless_httpupgrade_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["vless_httpupgrade_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vless_httpupgrade_tcp_relay_smoke"]["selected_outbound"],
        "VLESS-HU-TCP-SMOKE"
    );
    assert_eq!(
        certification["vless_httpupgrade_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["vless_httpupgrade_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        certification["vless_httpupgrade_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        certification["vless_httpupgrade_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vless_httpupgrade_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vless_httpupgrade_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vless_httpupgrade_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["vless_httpupgrade_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vless_httpupgrade_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_vless_httpupgrade_udp_relay_smoke_certification(certification);
    assert_eq!(
        certification["certification"]["vless_grpc_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vless_grpc_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vless_grpc_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vless_grpc_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vless_grpc_tcp_relay_smoke"]["selected_outbound"],
        "VLESS-GRPC-TCP-SMOKE"
    );
    assert_eq!(
        certification["vless_grpc_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["vless_grpc_tcp_relay_smoke"]["request_payload_bytes"],
        21
    );
    assert_eq!(
        certification["vless_grpc_tcp_relay_smoke"]["response_payload_bytes"],
        20
    );
    assert_eq!(
        certification["vless_grpc_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vless_grpc_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vless_grpc_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vless_grpc_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["vless_grpc_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vless_grpc_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_vless_grpc_udp_relay_smoke_certification(certification);
    assert_eq!(
        certification["certification"]["vless_h2_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vless_h2_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vless_h2_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vless_h2_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vless_h2_tcp_relay_smoke"]["selected_outbound"],
        "VLESS-H2-TCP-SMOKE"
    );
    assert_eq!(
        certification["vless_h2_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["vless_h2_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        certification["vless_h2_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        certification["vless_h2_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vless_h2_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vless_h2_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vless_h2_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["vless_h2_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vless_h2_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_vless_h2_udp_relay_smoke_certification(certification);
    assert_vless_quic_tcp_relay_smoke_certification(certification);
    assert_vless_quic_udp_relay_smoke_certification(certification);
    assert_eq!(
        certification["certification"]["vless_tcp_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vless_tcp_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vless_tcp_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vless_tcp_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vless_tcp_udp_relay_smoke"]["selected_outbound"],
        "VLESS-TCP-UDP-SMOKE"
    );
    assert_eq!(
        certification["vless_tcp_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["vless_tcp_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["vless_tcp_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vless_tcp_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vless_tcp_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vless_tcp_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["vless_tcp_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vless_tcp_udp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["vmess_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(certification["vmess_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(certification["vmess_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vmess_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vmess_tcp_relay_smoke"]["selected_outbound"],
        "VMESS-TCP-SMOKE"
    );
    assert_eq!(
        certification["vmess_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["vmess_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vmess_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vmess_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vmess_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["vmess_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vmess_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["vmess_ws_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vmess_ws_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vmess_ws_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vmess_ws_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vmess_ws_tcp_relay_smoke"]["selected_outbound"],
        "VMESS-WS-TCP-SMOKE"
    );
    assert_eq!(
        certification["vmess_ws_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["vmess_ws_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vmess_ws_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vmess_ws_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vmess_ws_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["vmess_ws_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vmess_ws_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_vmess_ws_udp_relay_smoke_certification(certification);
    assert_eq!(
        certification["certification"]["vmess_httpupgrade_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vmess_httpupgrade_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["vmess_httpupgrade_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["vmess_httpupgrade_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vmess_httpupgrade_tcp_relay_smoke"]["selected_outbound"],
        "VMESS-HU-TCP-SMOKE"
    );
    assert_eq!(
        certification["vmess_httpupgrade_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["vmess_httpupgrade_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        certification["vmess_httpupgrade_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        certification["vmess_httpupgrade_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vmess_httpupgrade_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vmess_httpupgrade_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vmess_httpupgrade_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["vmess_httpupgrade_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vmess_httpupgrade_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_vmess_httpupgrade_udp_relay_smoke_certification(certification);
    assert_eq!(
        certification["certification"]["vmess_grpc_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vmess_grpc_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vmess_grpc_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vmess_grpc_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vmess_grpc_tcp_relay_smoke"]["selected_outbound"],
        "VMESS-GRPC-TCP-SMOKE"
    );
    assert_eq!(
        certification["vmess_grpc_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["vmess_grpc_tcp_relay_smoke"]["request_payload_bytes"],
        21
    );
    assert_eq!(
        certification["vmess_grpc_tcp_relay_smoke"]["response_payload_bytes"],
        20
    );
    assert_eq!(
        certification["vmess_grpc_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vmess_grpc_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vmess_grpc_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vmess_grpc_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["vmess_grpc_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vmess_grpc_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_vmess_grpc_udp_relay_smoke_certification(certification);
    assert_eq!(
        certification["certification"]["vmess_h2_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vmess_h2_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vmess_h2_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vmess_h2_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vmess_h2_tcp_relay_smoke"]["selected_outbound"],
        "VMESS-H2-TCP-SMOKE"
    );
    assert_eq!(
        certification["vmess_h2_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["vmess_h2_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        certification["vmess_h2_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        certification["vmess_h2_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vmess_h2_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vmess_h2_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vmess_h2_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["vmess_h2_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vmess_h2_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_vmess_h2_udp_relay_smoke_certification(certification);
    assert_vmess_quic_tcp_relay_smoke_certification(certification);
    assert_vmess_quic_udp_relay_smoke_certification(certification);
    assert_eq!(
        certification["certification"]["vmess_tcp_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vmess_tcp_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vmess_tcp_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vmess_tcp_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vmess_tcp_udp_relay_smoke"]["selected_outbound"],
        "VMESS-TCP-UDP-SMOKE"
    );
    assert_eq!(
        certification["vmess_tcp_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["vmess_tcp_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["vmess_tcp_udp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        certification["vmess_tcp_udp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        certification["vmess_tcp_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vmess_tcp_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vmess_tcp_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vmess_tcp_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["vmess_tcp_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vmess_tcp_udp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["mieru_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(certification["mieru_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(certification["mieru_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["mieru_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["mieru_tcp_relay_smoke"]["selected_outbound"],
        "MIERU-TCP-SMOKE"
    );
    assert_eq!(
        certification["mieru_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["mieru_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["mieru_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["mieru_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["mieru_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["mieru_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["mieru_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["mieru_tcp_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["mieru_tcp_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["mieru_tcp_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["mieru_tcp_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["mieru_tcp_udp_relay_smoke"]["selected_outbound"],
        "MIERU-TCP-UDP-SMOKE"
    );
    assert_eq!(
        certification["mieru_tcp_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["mieru_tcp_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["mieru_tcp_udp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        certification["mieru_tcp_udp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        certification["mieru_tcp_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["mieru_tcp_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["mieru_tcp_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["mieru_tcp_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["mieru_tcp_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["mieru_tcp_udp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["udp_relay_smoke_passed"],
        true
    );
    assert_eq!(certification["udp_relay_smoke"]["status"], "passed");
    assert_eq!(certification["udp_relay_smoke"]["case_count"], 4);
    assert_eq!(certification["udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        certification["udp_relay_smoke"]["selected_outbound"],
        "SS-UDP-SMOKE"
    );
    assert_eq!(certification["udp_relay_smoke"]["target"], "example.com:53");
    assert_eq!(
        certification["udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(certification["udp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        certification["udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["udp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["socks5_udp_outbound_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["socks5_udp_outbound_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["socks5_udp_outbound_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["socks5_udp_outbound_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["socks5_udp_outbound_relay_smoke"]["selected_outbound"],
        "SOCKS5-UDP-OUTBOUND-SMOKE"
    );
    assert_eq!(
        certification["socks5_udp_outbound_relay_smoke"]["target"],
        "example.com:53"
    );
    assert_eq!(
        certification["socks5_udp_outbound_relay_smoke"]["request_payload_bytes"],
        30
    );
    assert_eq!(
        certification["socks5_udp_outbound_relay_smoke"]["response_payload_bytes"],
        29
    );
    assert_eq!(
        certification["socks5_udp_outbound_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["socks5_udp_outbound_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["socks5_udp_outbound_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["socks5_udp_outbound_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["socks5_udp_outbound_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["socks5_udp_outbound_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["resource_limit_smoke_passed"],
        true
    );
    assert_eq!(certification["resource_limit_smoke"]["status"], "passed");
    assert_eq!(certification["resource_limit_smoke"]["case_count"], 5);
    assert_eq!(
        certification["resource_limit_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["resource_limit_smoke"]["worker_limit_enforced"],
        true
    );
    assert_eq!(
        certification["resource_limit_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["resource_limit_smoke"]["workers_drained"],
        true
    );
    assert_eq!(
        certification["readiness"]["resource_limit_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["resource_limit_smoke"]["case_count"],
        5
    );
    assert_eq!(
        certification["certification"]["panel_subscription_smoke_passed"],
        true
    );
    assert_eq!(
        certification["panel_subscription_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["panel_subscription_smoke"]["case_count"], 9);
    assert_eq!(
        certification["panel_subscription_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["panel_subscription_smoke"]["start_blocked"],
        true
    );
    assert_eq!(
        certification["panel_subscription_smoke"]["reload_blocked"],
        true
    );
    assert_eq!(
        certification["panel_subscription_smoke"]["runtime_preserved_while_restricted"],
        true
    );
    assert_eq!(
        certification["panel_subscription_smoke"]["clear_allowed_runtime"],
        true
    );
    assert_eq!(
        certification["readiness"]["panel_subscription_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["panel_subscription_smoke"]["case_count"],
        9
    );
    assert_eq!(
        certification["certification"]["subscription_reload_smoke_passed"],
        true
    );
    assert_eq!(
        certification["subscription_reload_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["subscription_reload_smoke"]["case_count"], 4);
    assert_eq!(
        certification["subscription_reload_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["subscription_reload_smoke"]["final_selected_outbound"],
        "SS-FALLBACK"
    );
    assert_eq!(
        certification["subscription_reload_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["subscription_reload_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["subscription_reload_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["runtime_recovery_smoke_passed"],
        true
    );
    assert_eq!(certification["runtime_recovery_smoke"]["status"], "passed");
    assert_eq!(certification["runtime_recovery_smoke"]["case_count"], 4);
    assert_eq!(
        certification["runtime_recovery_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["runtime_recovery_smoke"]["final_selected_outbound"],
        "SS-READY"
    );
    assert_eq!(
        certification["runtime_recovery_smoke"]["preserved_after_failures"],
        true
    );
    assert_eq!(
        certification["runtime_recovery_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["readiness"]["runtime_recovery_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["runtime_recovery_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["certification"]["tun_tcp_session_smoke_passed"],
        true
    );
    assert_eq!(
        certification["certification"]["tun_tcp_session_server_retransmit_smoke_passed"],
        true
    );
    assert_eq!(
        certification["certification"]["tun_tcp_session_server_fin_retransmit_smoke_passed"],
        true
    );
    assert_eq!(
        certification["certification"]["tun_tcp_session_post_close_guard_smoke_passed"],
        true
    );
    assert_eq!(
        certification["certification"]["tun_tcp_unknown_session_reset_smoke_passed"],
        true
    );
    assert_eq!(
        certification["certification"]["tun_tcp_session_limit_smoke_passed"],
        true
    );
    assert_eq!(
        certification["certification"]["tun_tcp_session_idle_prune_smoke_passed"],
        true
    );
    assert_eq!(
        certification["certification"]["tun_tcp_session_close_marker_prune_smoke_passed"],
        true
    );
    assert_eq!(
        certification["certification"]["tun_tcp_session_close_marker_rst_clear_smoke_passed"],
        true
    );
    assert_tun_tcp_session_smoke_json(&certification["tun_tcp_session_smoke"]);
    assert_tun_tcp_session_smoke_json(&certification["readiness"]["tun_tcp_session_smoke"]);
    assert_tun_tcp_session_server_retransmit_smoke_json(
        &certification["tun_tcp_session_server_retransmit_smoke"],
    );
    assert_tun_tcp_session_server_retransmit_smoke_json(
        &certification["readiness"]["tun_tcp_session_server_retransmit_smoke"],
    );
    assert_tun_tcp_session_server_fin_retransmit_smoke_json(
        &certification["tun_tcp_session_server_fin_retransmit_smoke"],
    );
    assert_tun_tcp_session_server_fin_retransmit_smoke_json(
        &certification["readiness"]["tun_tcp_session_server_fin_retransmit_smoke"],
    );
    assert_tun_tcp_session_post_close_guard_smoke_json(
        &certification["tun_tcp_session_post_close_guard_smoke"],
    );
    assert_tun_tcp_session_post_close_guard_smoke_json(
        &certification["readiness"]["tun_tcp_session_post_close_guard_smoke"],
    );
    assert_tun_tcp_unknown_session_reset_smoke_json(
        &certification["tun_tcp_unknown_session_reset_smoke"],
    );
    assert_tun_tcp_unknown_session_reset_smoke_json(
        &certification["readiness"]["tun_tcp_unknown_session_reset_smoke"],
    );
    assert_tun_tcp_session_limit_smoke_json(&certification["tun_tcp_session_limit_smoke"]);
    assert_tun_tcp_session_limit_smoke_json(
        &certification["readiness"]["tun_tcp_session_limit_smoke"],
    );
    assert_tun_tcp_session_idle_prune_smoke_json(
        &certification["tun_tcp_session_idle_prune_smoke"],
    );
    assert_tun_tcp_session_idle_prune_smoke_json(
        &certification["readiness"]["tun_tcp_session_idle_prune_smoke"],
    );
    assert_tun_tcp_session_close_marker_prune_smoke_json(
        &certification["tun_tcp_session_close_marker_prune_smoke"],
    );
    assert_tun_tcp_session_close_marker_prune_smoke_json(
        &certification["readiness"]["tun_tcp_session_close_marker_prune_smoke"],
    );
    assert_tun_tcp_session_close_marker_rst_clear_smoke_json(
        &certification["tun_tcp_session_close_marker_rst_clear_smoke"],
    );
    assert_tun_tcp_session_close_marker_rst_clear_smoke_json(
        &certification["readiness"]["tun_tcp_session_close_marker_rst_clear_smoke"],
    );
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
    assert!(certification["tun_runtime_smoke"]["route_takeover_cleanup_observed"].is_null());
    assert!(
        certification["tun_runtime_smoke"]["route_takeover_cleanup_expected_prefixes_absent"]
            .is_null()
    );
    assert!(
        certification["tun_runtime_smoke"]["route_takeover_cleanup_expected_prefixes"].is_null()
    );
    assert!(
        certification["tun_runtime_smoke"]["route_takeover_cleanup_observed_prefixes"].is_null()
    );
    assert!(
        certification["tun_runtime_smoke"]["route_takeover_cleanup_missing_prefixes"].is_null()
    );
    assert!(certification["tun_runtime_smoke"]["route_takeover_cleanup_error"].is_null());
    assert!(certification["tun_runtime_smoke"]["route_takeover_cleanup_snapshot"].is_null());
    assert!(certification["tun_runtime_smoke"]["interface_snapshot_attempted"].is_null());
    assert!(certification["tun_runtime_smoke"]["interface_snapshot_addresses_command"].is_null());
    assert!(
        certification["tun_runtime_smoke"]["interface_snapshot_addresses_exit_success"].is_null()
    );
    assert!(certification["tun_runtime_smoke"]["interface_snapshot_addresses_exit_code"].is_null());
    assert!(certification["tun_runtime_smoke"]["interface_snapshot_addresses_stdout"].is_null());
    assert!(certification["tun_runtime_smoke"]["interface_snapshot_addresses_stderr"].is_null());
    assert!(certification["tun_runtime_smoke"]["interface_snapshot_addresses_error"].is_null());
    assert!(certification["tun_runtime_smoke"]["interface_snapshot_interfaces_command"].is_null());
    assert!(
        certification["tun_runtime_smoke"]["interface_snapshot_interfaces_exit_success"].is_null()
    );
    assert!(
        certification["tun_runtime_smoke"]["interface_snapshot_interfaces_exit_code"].is_null()
    );
    assert!(certification["tun_runtime_smoke"]["interface_snapshot_interfaces_stdout"].is_null());
    assert!(certification["tun_runtime_smoke"]["interface_snapshot_interfaces_stderr"].is_null());
    assert!(certification["tun_runtime_smoke"]["interface_snapshot_interfaces_error"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_required"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_observed"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_packets_observed"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_drop_observed"].is_null());
    assert!(certification["tun_runtime_smoke"]["traffic_stimulus_drop_observed"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_required"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_observed"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_hijack_route_observed"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_attempted"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_source"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_target"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_query_name"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_query_type"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_query_id"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_query_bytes"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_response_received"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_response_source"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_response_bytes"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_response_id"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_response_id_matches"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_response_rcode"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_error_count"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_stimulus_errors"].is_null());
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
    assert!(certification["tun_runtime_smoke"]["dns_responses_written"].is_null());
    assert!(certification["tun_runtime_smoke"]["dns_hijacked_route_count"].is_null());
    assert!(certification["tun_runtime_smoke"]["recent_dropped_routes"].is_null());
    assert!(certification["tun_runtime_smoke"]["recent_dns_hijacked_routes"].is_null());
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

fn assert_trojan_quic_udp_relay_smoke_certification(certification: &Value) {
    assert_eq!(
        certification["certification"]["trojan_quic_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["trojan_quic_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["trojan_quic_udp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["trojan_quic_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["trojan_quic_udp_relay_smoke"]["selected_outbound"],
        "TROJAN-QUIC-UDP-SMOKE"
    );
    assert_eq!(
        certification["trojan_quic_udp_relay_smoke"]["target"],
        "example.com:53"
    );
    assert!(certification["trojan_quic_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        certification["trojan_quic_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["trojan_quic_udp_relay_smoke"]["request_payload_bytes"],
        26
    );
    assert_eq!(
        certification["trojan_quic_udp_relay_smoke"]["response_payload_bytes"],
        25
    );
    assert_eq!(
        certification["trojan_quic_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["trojan_quic_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["trojan_quic_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["trojan_quic_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        certification["trojan_quic_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        certification["trojan_quic_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["trojan_quic_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        certification["trojan_quic_udp_relay_smoke"]["stop_timed_out"],
        false
    );
    assert_eq!(
        certification["readiness"]["trojan_quic_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["trojan_quic_udp_relay_smoke"]["case_count"],
        4
    );
}

fn assert_vless_quic_tcp_relay_smoke_certification(certification: &Value) {
    assert_eq!(
        certification["certification"]["vless_quic_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vless_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vless_quic_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vless_quic_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vless_quic_tcp_relay_smoke"]["selected_outbound"],
        "VLESS-QUIC-TCP-SMOKE"
    );
    assert_eq!(
        certification["vless_quic_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["vless_quic_tcp_relay_smoke"]["request_payload_bytes"],
        21
    );
    assert_eq!(
        certification["vless_quic_tcp_relay_smoke"]["response_payload_bytes"],
        20
    );
    assert_eq!(
        certification["vless_quic_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vless_quic_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vless_quic_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vless_quic_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        certification["vless_quic_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        certification["vless_quic_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["vless_quic_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        certification["vless_quic_tcp_relay_smoke"]["stop_timed_out"],
        false
    );
    assert_eq!(
        certification["readiness"]["vless_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vless_quic_tcp_relay_smoke"]["case_count"],
        4
    );
}

fn assert_vless_grpc_udp_relay_smoke_certification(certification: &Value) {
    assert_eq!(
        certification["certification"]["vless_grpc_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vless_grpc_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vless_grpc_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vless_grpc_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vless_grpc_udp_relay_smoke"]["selected_outbound"],
        "VLESS-GRPC-UDP-SMOKE"
    );
    assert_eq!(
        certification["vless_grpc_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(
        certification["vless_grpc_udp_relay_smoke"]["relay_port"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert_eq!(
        certification["vless_grpc_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["vless_grpc_udp_relay_smoke"]["request_payload_bytes"],
        25
    );
    assert_eq!(
        certification["vless_grpc_udp_relay_smoke"]["response_payload_bytes"],
        24
    );
    assert_eq!(
        certification["vless_grpc_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vless_grpc_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vless_grpc_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vless_grpc_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        certification["vless_grpc_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        certification["vless_grpc_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["vless_grpc_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        certification["vless_grpc_udp_relay_smoke"]["stop_timed_out"],
        false
    );
    assert_eq!(
        certification["readiness"]["vless_grpc_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vless_grpc_udp_relay_smoke"]["case_count"],
        4
    );
}

fn assert_vless_h2_udp_relay_smoke_certification(certification: &Value) {
    assert_eq!(
        certification["certification"]["vless_h2_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vless_h2_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vless_h2_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vless_h2_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vless_h2_udp_relay_smoke"]["selected_outbound"],
        "VLESS-H2-UDP-SMOKE"
    );
    assert_eq!(
        certification["vless_h2_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(
        certification["vless_h2_udp_relay_smoke"]["relay_port"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert_eq!(
        certification["vless_h2_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["vless_h2_udp_relay_smoke"]["request_payload_bytes"],
        23
    );
    assert_eq!(
        certification["vless_h2_udp_relay_smoke"]["response_payload_bytes"],
        22
    );
    assert_eq!(
        certification["vless_h2_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vless_h2_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vless_h2_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vless_h2_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        certification["vless_h2_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        certification["vless_h2_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["vless_h2_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        certification["vless_h2_udp_relay_smoke"]["stop_timed_out"],
        false
    );
    assert_eq!(
        certification["readiness"]["vless_h2_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vless_h2_udp_relay_smoke"]["case_count"],
        4
    );
}

fn assert_vmess_grpc_udp_relay_smoke_certification(certification: &Value) {
    assert_eq!(
        certification["certification"]["vmess_grpc_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vmess_grpc_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vmess_grpc_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vmess_grpc_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vmess_grpc_udp_relay_smoke"]["selected_outbound"],
        "VMESS-GRPC-UDP-SMOKE"
    );
    assert_eq!(
        certification["vmess_grpc_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(
        certification["vmess_grpc_udp_relay_smoke"]["relay_port"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert_eq!(
        certification["vmess_grpc_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["vmess_grpc_udp_relay_smoke"]["request_payload_bytes"],
        25
    );
    assert_eq!(
        certification["vmess_grpc_udp_relay_smoke"]["response_payload_bytes"],
        24
    );
    assert_eq!(
        certification["vmess_grpc_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vmess_grpc_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vmess_grpc_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vmess_grpc_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        certification["vmess_grpc_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        certification["vmess_grpc_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["vmess_grpc_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        certification["vmess_grpc_udp_relay_smoke"]["stop_timed_out"],
        false
    );
    assert_eq!(
        certification["readiness"]["vmess_grpc_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vmess_grpc_udp_relay_smoke"]["case_count"],
        4
    );
}

fn assert_vless_ws_udp_relay_smoke_certification(certification: &Value) {
    assert_eq!(
        certification["certification"]["vless_ws_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vless_ws_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vless_ws_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vless_ws_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vless_ws_udp_relay_smoke"]["selected_outbound"],
        "VLESS-WS-UDP-SMOKE"
    );
    assert_eq!(
        certification["vless_ws_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(certification["vless_ws_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        certification["vless_ws_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["vless_ws_udp_relay_smoke"]["request_payload_bytes"],
        23
    );
    assert_eq!(
        certification["vless_ws_udp_relay_smoke"]["response_payload_bytes"],
        22
    );
    assert_eq!(
        certification["vless_ws_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vless_ws_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vless_ws_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vless_ws_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        certification["vless_ws_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        certification["vless_ws_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["vless_ws_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        certification["vless_ws_udp_relay_smoke"]["stop_timed_out"],
        false
    );
    assert_eq!(
        certification["readiness"]["vless_ws_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vless_ws_udp_relay_smoke"]["case_count"],
        4
    );
}

fn assert_vmess_ws_udp_relay_smoke_certification(certification: &Value) {
    assert_eq!(
        certification["certification"]["vmess_ws_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vmess_ws_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vmess_ws_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vmess_ws_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vmess_ws_udp_relay_smoke"]["selected_outbound"],
        "VMESS-WS-UDP-SMOKE"
    );
    assert_eq!(
        certification["vmess_ws_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(certification["vmess_ws_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        certification["vmess_ws_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["vmess_ws_udp_relay_smoke"]["request_payload_bytes"],
        23
    );
    assert_eq!(
        certification["vmess_ws_udp_relay_smoke"]["response_payload_bytes"],
        22
    );
    assert_eq!(
        certification["vmess_ws_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vmess_ws_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vmess_ws_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vmess_ws_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        certification["vmess_ws_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        certification["vmess_ws_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["vmess_ws_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        certification["vmess_ws_udp_relay_smoke"]["stop_timed_out"],
        false
    );
    assert_eq!(
        certification["readiness"]["vmess_ws_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vmess_ws_udp_relay_smoke"]["case_count"],
        4
    );
}

fn assert_vless_httpupgrade_udp_relay_smoke_certification(certification: &Value) {
    assert_eq!(
        certification["certification"]["vless_httpupgrade_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vless_httpupgrade_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["vless_httpupgrade_udp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["vless_httpupgrade_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vless_httpupgrade_udp_relay_smoke"]["selected_outbound"],
        "VLESS-HU-UDP-SMOKE"
    );
    assert_eq!(
        certification["vless_httpupgrade_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(certification["vless_httpupgrade_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        certification["vless_httpupgrade_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["vless_httpupgrade_udp_relay_smoke"]["request_payload_bytes"],
        23
    );
    assert_eq!(
        certification["vless_httpupgrade_udp_relay_smoke"]["response_payload_bytes"],
        22
    );
    assert_eq!(
        certification["vless_httpupgrade_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vless_httpupgrade_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vless_httpupgrade_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vless_httpupgrade_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        certification["vless_httpupgrade_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        certification["vless_httpupgrade_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["vless_httpupgrade_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        certification["vless_httpupgrade_udp_relay_smoke"]["stop_timed_out"],
        false
    );
    assert_eq!(
        certification["readiness"]["vless_httpupgrade_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vless_httpupgrade_udp_relay_smoke"]["case_count"],
        4
    );
}

fn assert_vless_quic_udp_relay_smoke_certification(certification: &Value) {
    assert_eq!(
        certification["certification"]["vless_quic_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vless_quic_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vless_quic_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vless_quic_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vless_quic_udp_relay_smoke"]["selected_outbound"],
        "VLESS-QUIC-UDP-SMOKE"
    );
    assert_eq!(
        certification["vless_quic_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(certification["vless_quic_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        certification["vless_quic_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["vless_quic_udp_relay_smoke"]["request_payload_bytes"],
        25
    );
    assert_eq!(
        certification["vless_quic_udp_relay_smoke"]["response_payload_bytes"],
        24
    );
    assert_eq!(
        certification["vless_quic_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vless_quic_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vless_quic_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vless_quic_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        certification["vless_quic_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        certification["vless_quic_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["vless_quic_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        certification["vless_quic_udp_relay_smoke"]["stop_timed_out"],
        false
    );
    assert_eq!(
        certification["readiness"]["vless_quic_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vless_quic_udp_relay_smoke"]["case_count"],
        4
    );
}

fn assert_vmess_h2_udp_relay_smoke_certification(certification: &Value) {
    assert_eq!(
        certification["certification"]["vmess_h2_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vmess_h2_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vmess_h2_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vmess_h2_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vmess_h2_udp_relay_smoke"]["selected_outbound"],
        "VMESS-H2-UDP-SMOKE"
    );
    assert_eq!(
        certification["vmess_h2_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(
        certification["vmess_h2_udp_relay_smoke"]["relay_port"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert_eq!(
        certification["vmess_h2_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["vmess_h2_udp_relay_smoke"]["request_payload_bytes"],
        23
    );
    assert_eq!(
        certification["vmess_h2_udp_relay_smoke"]["response_payload_bytes"],
        22
    );
    assert_eq!(
        certification["vmess_h2_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vmess_h2_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vmess_h2_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vmess_h2_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        certification["vmess_h2_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        certification["vmess_h2_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["vmess_h2_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        certification["vmess_h2_udp_relay_smoke"]["stop_timed_out"],
        false
    );
    assert_eq!(
        certification["readiness"]["vmess_h2_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vmess_h2_udp_relay_smoke"]["case_count"],
        4
    );
}

fn assert_vmess_quic_tcp_relay_smoke_certification(certification: &Value) {
    assert_eq!(
        certification["certification"]["vmess_quic_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vmess_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vmess_quic_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vmess_quic_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vmess_quic_tcp_relay_smoke"]["selected_outbound"],
        "VMESS-QUIC-TCP-SMOKE"
    );
    assert_eq!(
        certification["vmess_quic_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        certification["vmess_quic_tcp_relay_smoke"]["request_payload_bytes"],
        21
    );
    assert_eq!(
        certification["vmess_quic_tcp_relay_smoke"]["response_payload_bytes"],
        20
    );
    assert_eq!(
        certification["vmess_quic_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vmess_quic_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vmess_quic_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vmess_quic_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        certification["vmess_quic_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        certification["vmess_quic_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["vmess_quic_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        certification["vmess_quic_tcp_relay_smoke"]["stop_timed_out"],
        false
    );
    assert_eq!(
        certification["readiness"]["vmess_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vmess_quic_tcp_relay_smoke"]["case_count"],
        4
    );
}

fn assert_vmess_quic_udp_relay_smoke_certification(certification: &Value) {
    assert_eq!(
        certification["certification"]["vmess_quic_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vmess_quic_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(certification["vmess_quic_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        certification["vmess_quic_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vmess_quic_udp_relay_smoke"]["selected_outbound"],
        "VMESS-QUIC-UDP-SMOKE"
    );
    assert_eq!(
        certification["vmess_quic_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(certification["vmess_quic_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        certification["vmess_quic_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["vmess_quic_udp_relay_smoke"]["request_payload_bytes"],
        25
    );
    assert_eq!(
        certification["vmess_quic_udp_relay_smoke"]["response_payload_bytes"],
        24
    );
    assert_eq!(
        certification["vmess_quic_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vmess_quic_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vmess_quic_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vmess_quic_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        certification["vmess_quic_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        certification["vmess_quic_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["vmess_quic_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        certification["vmess_quic_udp_relay_smoke"]["stop_timed_out"],
        false
    );
    assert_eq!(
        certification["readiness"]["vmess_quic_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vmess_quic_udp_relay_smoke"]["case_count"],
        4
    );
}

fn assert_vmess_httpupgrade_udp_relay_smoke_certification(certification: &Value) {
    assert_eq!(
        certification["certification"]["vmess_httpupgrade_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        certification["vmess_httpupgrade_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["vmess_httpupgrade_udp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        certification["vmess_httpupgrade_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        certification["vmess_httpupgrade_udp_relay_smoke"]["selected_outbound"],
        "VMESS-HU-UDP-SMOKE"
    );
    assert_eq!(
        certification["vmess_httpupgrade_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(certification["vmess_httpupgrade_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        certification["vmess_httpupgrade_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        certification["vmess_httpupgrade_udp_relay_smoke"]["request_payload_bytes"],
        23
    );
    assert_eq!(
        certification["vmess_httpupgrade_udp_relay_smoke"]["response_payload_bytes"],
        22
    );
    assert_eq!(
        certification["vmess_httpupgrade_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        certification["vmess_httpupgrade_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        certification["vmess_httpupgrade_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        certification["vmess_httpupgrade_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        certification["vmess_httpupgrade_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        certification["vmess_httpupgrade_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        certification["vmess_httpupgrade_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        certification["vmess_httpupgrade_udp_relay_smoke"]["stop_timed_out"],
        false
    );
    assert_eq!(
        certification["readiness"]["vmess_httpupgrade_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        certification["readiness"]["vmess_httpupgrade_udp_relay_smoke"]["case_count"],
        4
    );
}

fn assert_tun_tcp_session_smoke_json(smoke: &Value) {
    assert_eq!(smoke["status"], "passed");
    assert_eq!(smoke["passed"], true);
    assert_eq!(smoke["selected_outbound"], "TUN-TCP-SESSION-SMOKE");
    assert!(smoke["target"]
        .as_str()
        .expect("TUN TCP session target")
        .starts_with("127.0.0.1:"));
    assert_eq!(smoke["request_payload_bytes"], 5);
    assert_eq!(smoke["response_payload_bytes"], 8);
    assert_eq!(smoke["response_payload_observed"], true);
    assert_eq!(smoke["server_received_payload"], true);
    assert_eq!(smoke["starts_observed"], 1);
    assert_eq!(smoke["opens_observed"], 1);
    assert_eq!(smoke["stops_observed"], 1);
    assert_eq!(smoke["tun_writes_observed"], 3);
    assert_eq!(smoke["processed_packets"], 4);
    assert_eq!(smoke["tcp_session_events"], 4);
    assert_eq!(smoke["tcp_session_packets_written"], 3);
    assert_eq!(smoke["tcp_sessions_peak"], 1);
    assert_eq!(smoke["tcp_sessions_open"], 0);
    assert_eq!(smoke["tcp_session_errors"], 0);
    assert_eq!(smoke["tcp_session_limit_rejections"], 0);
    assert_eq!(smoke["clean_stop_observed"], true);
    assert_eq!(smoke["residual_state_clean"], true);
    assert_eq!(smoke["case_count"], 4);
    assert_eq!(smoke["failed_case_count"], 0);
    let cases = smoke["cases"]
        .as_array()
        .expect("TUN TCP session smoke cases");
    let response = cases
        .iter()
        .find(|case| case["name"] == "write-tun-tcp-server-payload")
        .expect("TUN TCP session response case");
    assert_eq!(response["observed_response"], "HTTP/1.1");
    assert_eq!(response["passed"], true);
}

fn assert_tun_tcp_session_server_retransmit_smoke_json(smoke: &Value) {
    assert_eq!(smoke["status"], "passed");
    assert_eq!(smoke["passed"], true);
    assert_eq!(
        smoke["selected_outbound"],
        "TUN-TCP-SESSION-SERVER-RETRANSMIT-SMOKE"
    );
    assert!(smoke["target"]
        .as_str()
        .expect("TUN TCP server retransmit target")
        .starts_with("127.0.0.1:"));
    assert_eq!(smoke["request_payload_bytes"], 5);
    assert_eq!(smoke["follow_up_payload_bytes"], 4);
    assert_eq!(smoke["response_payload_bytes"], 8);
    assert_eq!(smoke["retransmit_response_payload_observed"], true);
    assert_eq!(smoke["ack_clear_response_payload_observed"], true);
    assert_eq!(smoke["retransmitted_payload_observed"], true);
    assert_eq!(smoke["no_retransmit_after_ack_clear"], true);
    assert_eq!(smoke["ack_clear_packet_observed"], true);
    assert_eq!(smoke["retransmit_server_received_payload"], true);
    assert_eq!(smoke["ack_clear_server_received_initial_payload"], true);
    assert_eq!(smoke["ack_clear_server_received_follow_up_payload"], true);
    assert_eq!(smoke["retransmit_processed_packets"], 4);
    assert_eq!(smoke["retransmit_tcp_session_events"], 4);
    assert_eq!(smoke["retransmit_tcp_session_packets_written"], 4);
    assert_eq!(smoke["retransmit_tun_writes_observed"], 4);
    assert_eq!(smoke["ack_clear_processed_packets"], 5);
    assert_eq!(smoke["ack_clear_tcp_session_events"], 5);
    assert!(
        smoke["ack_clear_tcp_session_packets_written"]
            .as_u64()
            .expect("ack-clear TCP packets written")
            >= 4
    );
    assert!(
        smoke["ack_clear_tun_writes_observed"]
            .as_u64()
            .expect("ack-clear TUN writes observed")
            >= 4
    );
    assert_eq!(smoke["tcp_session_errors"], 0);
    assert_eq!(smoke["case_count"], 4);
    assert_eq!(smoke["passed_case_count"], 4);
    assert_eq!(smoke["failed_case_count"], 0);
    let cases = smoke["cases"]
        .as_array()
        .expect("TUN TCP server retransmit smoke cases");
    let retransmit = cases
        .iter()
        .find(|case| case["name"] == "retransmit-server-payload-on-stale-ack")
        .expect("TUN TCP server payload retransmit case");
    assert_eq!(retransmit["observed_response_payload_count"], 2);
    assert_eq!(retransmit["observed_retransmitted_payload_count"], 1);
    assert_eq!(retransmit["passed"], true);
    let no_replay = cases
        .iter()
        .find(|case| case["name"] == "do-not-replay-server-payload-after-ack-clear")
        .expect("TUN TCP server payload ack-clear case");
    assert_eq!(no_replay["observed_response_payload_count"], 1);
    assert_eq!(no_replay["observed_no_retransmit_after_ack_clear"], true);
    assert_eq!(no_replay["passed"], true);
}

fn assert_tun_tcp_session_server_fin_retransmit_smoke_json(smoke: &Value) {
    assert_eq!(smoke["status"], "passed");
    assert_eq!(smoke["passed"], true);
    assert_eq!(
        smoke["selected_outbound"],
        "TUN-TCP-SESSION-SERVER-FIN-RETRANSMIT-SMOKE"
    );
    assert!(smoke["target"]
        .as_str()
        .expect("TUN TCP server FIN retransmit target")
        .starts_with("127.0.0.1:"));
    assert_eq!(smoke["request_payload_bytes"], 5);
    assert_eq!(smoke["server_received_payload"], true);
    assert_eq!(smoke["server_fin_observed"], true);
    assert_eq!(smoke["server_fin_retransmitted"], true);
    assert_eq!(smoke["final_ack_absorbed"], true);
    assert_eq!(smoke["no_reset_observed"], true);
    assert_eq!(smoke["first_fin_sequence_number"], 2);
    assert_eq!(smoke["first_fin_acknowledgment_number"], 16);
    assert_eq!(smoke["retransmitted_fin_sequence_number"], 2);
    assert_eq!(smoke["retransmitted_fin_acknowledgment_number"], 16);
    assert_eq!(smoke["starts_observed"], 1);
    assert_eq!(smoke["opens_observed"], 1);
    assert_eq!(smoke["stops_observed"], 1);
    assert_eq!(smoke["processed_packets"], 5);
    assert_eq!(smoke["tcp_session_events"], 5);
    assert_eq!(smoke["tcp_session_packets_written"], 4);
    assert_eq!(smoke["tun_writes_observed"], 4);
    assert_eq!(smoke["tcp_sessions_open"], 0);
    assert_eq!(smoke["tcp_server_close_markers_open"], 0);
    assert_eq!(smoke["tcp_post_close_markers_open"], 1);
    assert_eq!(smoke["tcp_session_errors"], 0);
    assert_eq!(smoke["post_close_marker_retained"], true);
    assert_eq!(smoke["clean_stop_observed"], true);
    assert_eq!(smoke["residual_state_clean"], true);
    assert_eq!(smoke["case_count"], 3);
    assert_eq!(smoke["failed_case_count"], 0);
    let cases = smoke["cases"]
        .as_array()
        .expect("TUN TCP server FIN retransmit smoke cases");
    let retransmit = cases
        .iter()
        .find(|case| case["name"] == "retransmit-server-fin-on-duplicate-ack")
        .expect("TUN TCP server FIN retransmit case");
    assert_eq!(retransmit["observed_fin_written"], true);
    assert_eq!(retransmit["observed_sequence_number"], 2);
    assert_eq!(retransmit["observed_acknowledgment_number"], 16);
    assert_eq!(retransmit["observed_reset_written"], false);
    assert_eq!(retransmit["passed"], true);
    let final_ack = cases
        .iter()
        .find(|case| case["name"] == "absorb-server-fin-final-ack-without-reset")
        .expect("TUN TCP server FIN final ACK case");
    assert_eq!(final_ack["expected_fin_written"], false);
    assert_eq!(final_ack["observed_fin_written"], false);
    assert_eq!(final_ack["expected_reset_written"], false);
    assert_eq!(final_ack["observed_reset_written"], false);
    assert_eq!(final_ack["passed"], true);
}

fn assert_tun_tcp_session_post_close_guard_smoke_json(smoke: &Value) {
    assert_eq!(smoke["status"], "passed");
    assert_eq!(smoke["passed"], true);
    assert_eq!(
        smoke["selected_outbound"],
        "TUN-TCP-SESSION-POST-CLOSE-GUARD-SMOKE"
    );
    assert!(smoke["target"]
        .as_str()
        .expect("TUN TCP post-close guard target")
        .starts_with("127.0.0.1:"));
    assert_eq!(smoke["request_payload_bytes"], 5);
    assert_eq!(smoke["late_client_fin_payload_bytes"], 4);
    assert_eq!(smoke["server_received_payload"], true);
    assert_eq!(smoke["server_fin_observed"], true);
    assert_eq!(smoke["final_ack_absorbed"], true);
    assert_eq!(smoke["duplicate_final_ack_absorbed"], true);
    assert_eq!(smoke["late_client_fin_payload_acknowledged"], true);
    assert_eq!(smoke["late_client_fin_acknowledged"], true);
    assert_eq!(smoke["no_reset_observed"], true);
    assert_eq!(smoke["late_client_fin_ack_sequence_number"], 3);
    assert_eq!(smoke["late_client_fin_ack_acknowledgment_number"], 21);
    assert_eq!(smoke["starts_observed"], 1);
    assert_eq!(smoke["opens_observed"], 1);
    assert_eq!(smoke["stops_observed"], 1);
    assert_eq!(smoke["processed_packets"], 7);
    assert_eq!(smoke["tcp_session_events"], 7);
    assert_eq!(smoke["tcp_session_packets_written"], 5);
    assert_eq!(smoke["tun_writes_observed"], 5);
    assert_eq!(smoke["tcp_sessions_open"], 0);
    assert_eq!(smoke["tcp_server_close_markers_open"], 0);
    assert_eq!(smoke["tcp_post_close_markers_open"], 1);
    assert_eq!(smoke["tcp_session_errors"], 0);
    assert_eq!(smoke["post_close_marker_retained"], true);
    assert_eq!(smoke["clean_stop_observed"], true);
    assert_eq!(smoke["residual_state_clean"], true);
    assert_eq!(smoke["case_count"], 4);
    assert_eq!(smoke["passed_case_count"], 4);
    assert_eq!(smoke["failed_case_count"], 0);
    let cases = smoke["cases"]
        .as_array()
        .expect("TUN TCP post-close guard smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "create-post-close-marker-after-server-fin-final-ack",
        "absorb-post-close-duplicate-final-ack-without-reset",
        "acknowledge-late-post-close-client-fin-payload-without-reset",
        "retain-bounded-post-close-marker-cleanly",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing TUN TCP post-close guard smoke case {expected}: {case_names:?}"
        );
    }
    let duplicate_ack = cases
        .iter()
        .find(|case| case["name"] == "absorb-post-close-duplicate-final-ack-without-reset")
        .expect("TUN TCP post-close duplicate final ACK case");
    assert_eq!(duplicate_ack["expected_packet_written"], false);
    assert_eq!(duplicate_ack["observed_packet_written"], false);
    assert_eq!(duplicate_ack["observed_reset_written"], false);
    assert_eq!(duplicate_ack["passed"], true);
    let late_fin = cases
        .iter()
        .find(|case| case["name"] == "acknowledge-late-post-close-client-fin-payload-without-reset")
        .expect("TUN TCP post-close late client FIN case");
    assert_eq!(late_fin["expected_packet_written"], true);
    assert_eq!(late_fin["observed_packet_written"], true);
    assert_eq!(late_fin["observed_sequence_number"], 3);
    assert_eq!(late_fin["observed_acknowledgment_number"], 21);
    assert_eq!(late_fin["observed_reset_written"], false);
    assert_eq!(late_fin["passed"], true);
}

fn assert_tun_tcp_unknown_session_reset_smoke_json(smoke: &Value) {
    assert_eq!(smoke["status"], "passed");
    assert_eq!(smoke["passed"], true);
    assert_eq!(
        smoke["selected_outbound"],
        "TUN-TCP-UNKNOWN-SESSION-RESET-SMOKE"
    );
    assert_eq!(smoke["target"], "93.184.216.34:443");
    assert_eq!(smoke["request_payload_bytes"], 5);
    assert_eq!(smoke["data_reset_observed"], true);
    assert_eq!(smoke["fin_reset_observed"], true);
    assert_eq!(smoke["stray_rst_absorbed"], true);
    assert_eq!(smoke["reset_loop_avoided"], true);
    assert_eq!(smoke["data_reset_sequence_number"], 1001);
    assert_eq!(smoke["data_reset_acknowledgment_number"], 16);
    assert_eq!(smoke["fin_reset_sequence_number"], 1001);
    assert_eq!(smoke["fin_reset_acknowledgment_number"], 17);
    assert_eq!(smoke["starts_observed"], 1);
    assert_eq!(smoke["opens_observed"], 1);
    assert_eq!(smoke["stops_observed"], 1);
    assert_eq!(smoke["processed_packets"], 3);
    assert_eq!(smoke["tcp_session_events"], 3);
    assert_eq!(smoke["tcp_session_packets_written"], 2);
    assert_eq!(smoke["tun_writes_observed"], 2);
    assert_eq!(smoke["tcp_sessions_open"], 0);
    assert_eq!(smoke["tcp_session_errors"], 0);
    assert_eq!(smoke["clean_stop_observed"], true);
    assert_eq!(smoke["residual_state_clean"], true);
    assert_eq!(smoke["case_count"], 3);
    assert_eq!(smoke["passed_case_count"], 3);
    assert_eq!(smoke["failed_case_count"], 0);
    let cases = smoke["cases"]
        .as_array()
        .expect("TUN TCP unknown-session reset smoke cases");
    let data = cases
        .iter()
        .find(|case| case["name"] == "reset-unknown-tun-tcp-data")
        .expect("TUN TCP unknown data reset case");
    assert_eq!(data["observed_reset_written"], true);
    assert_eq!(data["observed_sequence_number"], 1001);
    assert_eq!(data["observed_acknowledgment_number"], 16);
    assert_eq!(data["observed_rst_flag"], true);
    assert_eq!(data["observed_ack_flag"], true);
    assert_eq!(data["passed"], true);
    let stray_rst = cases
        .iter()
        .find(|case| case["name"] == "absorb-unknown-tun-tcp-rst-without-reset-loop")
        .expect("TUN TCP unknown RST absorb case");
    assert_eq!(stray_rst["expected_reset_written"], false);
    assert_eq!(stray_rst["observed_reset_written"], false);
    assert_eq!(stray_rst["passed"], true);
}

fn assert_tun_tcp_session_limit_smoke_json(smoke: &Value) {
    assert_eq!(smoke["status"], "passed");
    assert_eq!(smoke["passed"], true);
    assert_eq!(smoke["selected_outbound"], "TUN-TCP-SESSION-LIMIT-SMOKE");
    assert_eq!(smoke["target"], "93.184.216.34:443");
    assert_eq!(smoke["first_client"], "10.7.0.2:49152");
    assert_eq!(smoke["second_client"], "10.7.0.3:49153");
    assert_eq!(smoke["max_active_sessions"], 1);
    assert_eq!(smoke["limit_rejection_observed"], true);
    assert_eq!(smoke["session_error_observed"], true);
    assert!(smoke["last_error_kind"]
        .as_str()
        .expect("TUN TCP session limit error")
        .contains("TcpSessionLimitExceeded"));
    assert_eq!(smoke["starts_observed"], 1);
    assert_eq!(smoke["opens_observed"], 1);
    assert_eq!(smoke["stops_observed"], 1);
    assert_eq!(smoke["tun_writes_observed"], 1);
    assert_eq!(smoke["processed_packets"], 2);
    assert_eq!(smoke["tcp_session_events"], 1);
    assert_eq!(smoke["tcp_session_packets_written"], 1);
    assert_eq!(smoke["tcp_sessions_peak"], 1);
    assert_eq!(smoke["tcp_sessions_open"], 1);
    assert_eq!(smoke["tcp_session_errors"], 1);
    assert_eq!(smoke["tcp_session_limit_rejections"], 1);
    assert_eq!(smoke["tcp_max_active_sessions"], 1);
    assert_eq!(smoke["clean_stop_observed"], true);
    assert_eq!(smoke["active_session_retained"], true);
    assert_eq!(smoke["bounded_state_observed"], true);
    assert_eq!(smoke["case_count"], 4);
    assert_eq!(smoke["failed_case_count"], 0);
    let cases = smoke["cases"]
        .as_array()
        .expect("TUN TCP session limit smoke cases");
    let rejection = cases
        .iter()
        .find(|case| case["name"] == "reject-second-tun-tcp-session-over-limit")
        .expect("TUN TCP session limit rejection case");
    assert_eq!(rejection["expected_error_kind"], "TcpSessionLimitExceeded");
    assert!(rejection["observed_error_kind"]
        .as_str()
        .expect("observed TUN TCP session limit error")
        .contains("TcpSessionLimitExceeded"));
    assert_eq!(rejection["passed"], true);
}

fn assert_tun_tcp_session_idle_prune_smoke_json(smoke: &Value) {
    assert_eq!(smoke["status"], "passed");
    assert_eq!(smoke["passed"], true);
    assert_eq!(
        smoke["selected_outbound"],
        "TUN-TCP-SESSION-IDLE-PRUNE-SMOKE"
    );
    assert_eq!(smoke["target"], "93.184.216.34:443");
    assert_eq!(smoke["client"], "10.7.0.2:49152");
    assert_eq!(smoke["idle_timeout_ms"], 0);
    assert_eq!(smoke["prune_observed"], true);
    assert_eq!(smoke["prune_error_free"], true);
    assert!(smoke["last_error_kind"].is_null());
    assert_eq!(smoke["starts_observed"], 1);
    assert_eq!(smoke["opens_observed"], 1);
    assert_eq!(smoke["stops_observed"], 1);
    assert_eq!(smoke["tun_writes_observed"], 1);
    assert_eq!(smoke["processed_packets"], 1);
    assert_eq!(smoke["idle_events"], 1);
    assert_eq!(smoke["packet_limit_reached"], false);
    assert_eq!(smoke["tcp_session_events"], 1);
    assert_eq!(smoke["tcp_session_packets_written"], 1);
    assert_eq!(smoke["tcp_sessions_pruned"], 1);
    assert_eq!(smoke["tcp_sessions_peak"], 1);
    assert_eq!(smoke["tcp_sessions_open"], 0);
    assert_eq!(smoke["tcp_session_errors"], 0);
    assert_eq!(smoke["tcp_session_limit_rejections"], 0);
    assert_eq!(smoke["clean_stop_observed"], true);
    assert_eq!(smoke["residual_state_clean"], true);
    assert_eq!(smoke["case_count"], 4);
    assert_eq!(smoke["failed_case_count"], 0);
    let cases = smoke["cases"]
        .as_array()
        .expect("TUN TCP session idle prune smoke cases");
    let prune = cases
        .iter()
        .find(|case| case["name"] == "prune-idle-tun-tcp-session-before-next-read")
        .expect("TUN TCP session idle prune case");
    assert_eq!(prune["expected_pruned_sessions"], 1);
    assert_eq!(prune["observed_pruned_sessions"], 1);
    assert!(prune["observed_error_kind"].is_null());
    assert_eq!(prune["passed"], true);
}

fn assert_tun_tcp_session_close_marker_prune_smoke_json(smoke: &Value) {
    assert_eq!(smoke["status"], "passed");
    assert_eq!(smoke["passed"], true);
    assert_eq!(
        smoke["selected_outbound"],
        "TUN-TCP-SESSION-CLOSE-MARKER-PRUNE-SMOKE"
    );
    assert_eq!(smoke["target"], "93.184.216.34:443");
    assert_eq!(smoke["client"], "10.7.0.2:49152");
    assert_eq!(smoke["request_payload_bytes"], 5);
    assert_eq!(smoke["idle_timeout_ms"], 5000);
    assert_eq!(smoke["prune_after_ms"], 10000);
    assert_eq!(smoke["server_close_marker_observed"], true);
    assert_eq!(smoke["server_close_marker_pruned"], true);
    assert_eq!(smoke["server_close_reclose_avoided"], true);
    assert_eq!(smoke["server_close_markers_before_prune"], 1);
    assert_eq!(smoke["server_close_markers_after_prune"], 0);
    assert_eq!(smoke["server_close_closed_sessions_before_prune"], 1);
    assert_eq!(smoke["server_close_closed_sessions_after_prune"], 1);
    assert_eq!(smoke["server_close_pruned_server_closed_sessions"], 1);
    assert_eq!(smoke["server_close_pruned_post_closed_sessions"], 0);
    assert_eq!(smoke["server_close_close_errors"], 0);
    assert!(smoke["server_close_last_error_kind"].is_null());
    assert_eq!(smoke["post_close_marker_observed"], true);
    assert_eq!(smoke["post_close_marker_pruned"], true);
    assert_eq!(smoke["post_close_reclose_avoided"], true);
    assert_eq!(smoke["post_close_markers_before_prune"], 1);
    assert_eq!(smoke["post_close_markers_after_prune"], 0);
    assert_eq!(smoke["post_close_closed_sessions_before_prune"], 1);
    assert_eq!(smoke["post_close_closed_sessions_after_prune"], 1);
    assert_eq!(smoke["post_close_pruned_server_closed_sessions"], 0);
    assert_eq!(smoke["post_close_pruned_post_closed_sessions"], 1);
    assert_eq!(smoke["post_close_close_errors"], 0);
    assert!(smoke["post_close_last_error_kind"].is_null());
    assert_eq!(smoke["residual_state_clean"], true);
    assert_eq!(smoke["case_count"], 4);
    assert_eq!(smoke["failed_case_count"], 0);
    let cases = smoke["cases"]
        .as_array()
        .expect("TUN TCP close-marker prune smoke cases");
    let server_prune = cases
        .iter()
        .find(|case| case["name"] == "prune-server-close-marker-without-reclosing-relay")
        .expect("server-close prune case");
    assert_eq!(server_prune["marker_kind"], "server-close");
    assert_eq!(server_prune["observed_pruned_server_closed_sessions"], 1);
    assert_eq!(server_prune["closed_sessions_before_prune"], 1);
    assert_eq!(server_prune["closed_sessions_after_prune"], 1);
    assert_eq!(server_prune["passed"], true);
    let post_prune = cases
        .iter()
        .find(|case| case["name"] == "prune-post-close-marker-without-reclosing-relay")
        .expect("post-close prune case");
    assert_eq!(post_prune["marker_kind"], "post-close");
    assert_eq!(post_prune["observed_pruned_post_closed_sessions"], 1);
    assert_eq!(post_prune["closed_sessions_before_prune"], 1);
    assert_eq!(post_prune["closed_sessions_after_prune"], 1);
    assert_eq!(post_prune["passed"], true);
}

fn assert_tun_tcp_session_close_marker_rst_clear_smoke_json(smoke: &Value) {
    assert_eq!(smoke["status"], "passed");
    assert_eq!(smoke["passed"], true);
    assert_eq!(
        smoke["selected_outbound"],
        "TUN-TCP-SESSION-CLOSE-MARKER-RST-CLEAR-SMOKE"
    );
    assert_eq!(smoke["target"], "93.184.216.34:443");
    assert_eq!(smoke["client"], "10.7.0.2:49152");
    assert_eq!(smoke["request_payload_bytes"], 5);
    assert_eq!(smoke["server_close_marker_observed"], true);
    assert_eq!(smoke["server_close_marker_reset"], true);
    assert_eq!(smoke["server_close_reset_kind"], "server-close");
    assert_eq!(smoke["server_close_no_reset_response"], true);
    assert_eq!(smoke["server_close_reclose_avoided"], true);
    assert_eq!(smoke["server_close_markers_before_reset"], 1);
    assert_eq!(smoke["server_close_markers_after_reset"], 0);
    assert_eq!(smoke["server_close_response_packets"], 0);
    assert_eq!(smoke["server_close_closed_sessions_before_reset"], 1);
    assert_eq!(smoke["server_close_closed_sessions_after_reset"], 1);
    assert_eq!(
        smoke["server_close_pruned_server_closed_sessions_after_reset"],
        0
    );
    assert_eq!(
        smoke["server_close_pruned_post_closed_sessions_after_reset"],
        0
    );
    assert_eq!(smoke["server_close_close_errors_after_reset"], 0);
    assert!(smoke["server_close_last_error_kind"].is_null());
    assert_eq!(smoke["post_close_marker_observed"], true);
    assert_eq!(smoke["post_close_marker_reset"], true);
    assert_eq!(smoke["post_close_reset_kind"], "post-close");
    assert_eq!(smoke["post_close_no_reset_response"], true);
    assert_eq!(smoke["post_close_reclose_avoided"], true);
    assert_eq!(smoke["post_close_markers_before_reset"], 1);
    assert_eq!(smoke["post_close_markers_after_reset"], 0);
    assert_eq!(smoke["post_close_response_packets"], 0);
    assert_eq!(smoke["post_close_closed_sessions_before_reset"], 1);
    assert_eq!(smoke["post_close_closed_sessions_after_reset"], 1);
    assert_eq!(
        smoke["post_close_pruned_server_closed_sessions_after_reset"],
        0
    );
    assert_eq!(
        smoke["post_close_pruned_post_closed_sessions_after_reset"],
        0
    );
    assert_eq!(smoke["post_close_close_errors_after_reset"], 0);
    assert!(smoke["post_close_last_error_kind"].is_null());
    assert_eq!(smoke["residual_state_clean"], true);
    assert_eq!(smoke["case_count"], 4);
    assert_eq!(smoke["failed_case_count"], 0);
    let cases = smoke["cases"]
        .as_array()
        .expect("TUN TCP close-marker RST clear smoke cases");
    let server_reset = cases
        .iter()
        .find(|case| {
            case["name"] == "clear-server-close-marker-with-rst-without-reset-or-reclosing-relay"
        })
        .expect("server-close RST clear case");
    assert_eq!(server_reset["marker_kind"], "server-close");
    assert_eq!(server_reset["observed_reset_kind"], "server-close");
    assert_eq!(server_reset["response_packets"], 0);
    assert_eq!(server_reset["closed_sessions_before_reset"], 1);
    assert_eq!(server_reset["closed_sessions_after_reset"], 1);
    assert_eq!(server_reset["passed"], true);
    let post_reset = cases
        .iter()
        .find(|case| {
            case["name"] == "clear-post-close-marker-with-rst-without-reset-or-reclosing-relay"
        })
        .expect("post-close RST clear case");
    assert_eq!(post_reset["marker_kind"], "post-close");
    assert_eq!(post_reset["observed_reset_kind"], "post-close");
    assert_eq!(post_reset["response_packets"], 0);
    assert_eq!(post_reset["closed_sessions_before_reset"], 1);
    assert_eq!(post_reset["closed_sessions_after_reset"], 1);
    assert_eq!(post_reset["passed"], true);
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

#[test]
fn support_bundle_certification_records_stability_gate_failure() {
    let mut output = Vec::new();

    keli_cli::write_support_bundle_report_with_options(
        None,
        SupportBundleOptions {
            include_default_core_certification: true,
            certification_soak_connections: 1,
            certification_first_byte_timeout: Duration::from_secs(2),
            certification_max_connection_workers: 1,
            certification_soak_min_duration: Duration::from_millis(0),
            certification_include_system_proxy_smoke: false,
            certification_include_tun_runtime_smoke: false,
            certification_tun_runtime_smoke_min_duration: Duration::from_millis(50),
            certification_require_machine_takeover_ready: false,
            certification_required_stability_window: Some(Duration::from_millis(50)),
            certification_required_stability_connections: None,
            certification_release_gate_preset: None,
        },
        &mut output,
    )
    .expect("write support bundle with stability gate evidence");

    let report: Value = serde_json::from_slice(&output).expect("support bundle json");
    let certification = &report["default_core_certification"];

    assert_eq!(certification["release_gate"]["status"], "failed");
    assert_eq!(certification["release_gate"]["required_scope"], "stability");
    assert_eq!(
        certification["release_gate"]["require_stability_window"],
        true
    );
    assert_eq!(
        certification["release_gate"]["required_stability_window_ms"],
        50
    );
    assert_eq!(
        certification["release_gate"]["require_stability_connections"],
        false
    );
    assert!(certification["release_gate"]["required_stability_connections"].is_null());
    assert_eq!(certification["release_gate"]["passed"], false);
    assert_eq!(
        certification["release_gate"]["stability"]["required_window_ms"],
        50
    );
    assert_eq!(
        certification["release_gate"]["stability"]["required_window_met"],
        false
    );
    assert_eq!(
        certification["release_gate"]["stability"]["local_soak_required_window_met"],
        false
    );
    assert_eq!(
        certification["release_gate"]["blockers"][0],
        "local-soak-stability-window-too-short"
    );
}

#[test]
fn support_bundle_certification_records_stability_connection_gate_failure() {
    let mut output = Vec::new();

    keli_cli::write_support_bundle_report_with_options(
        None,
        SupportBundleOptions {
            include_default_core_certification: true,
            certification_soak_connections: 1,
            certification_first_byte_timeout: Duration::from_secs(2),
            certification_max_connection_workers: 1,
            certification_soak_min_duration: Duration::from_millis(0),
            certification_include_system_proxy_smoke: false,
            certification_include_tun_runtime_smoke: false,
            certification_tun_runtime_smoke_min_duration: Duration::from_millis(50),
            certification_require_machine_takeover_ready: false,
            certification_required_stability_window: None,
            certification_required_stability_connections: Some(2),
            certification_release_gate_preset: None,
        },
        &mut output,
    )
    .expect("write support bundle with stability connection gate evidence");

    let report: Value = serde_json::from_slice(&output).expect("support bundle json");
    let certification = &report["default_core_certification"];

    assert_eq!(certification["release_gate"]["status"], "failed");
    assert_eq!(certification["release_gate"]["required_scope"], "stability");
    assert_eq!(
        certification["release_gate"]["require_stability_connections"],
        true
    );
    assert_eq!(
        certification["release_gate"]["required_stability_connections"],
        2
    );
    assert_eq!(certification["release_gate"]["passed"], false);
    assert_eq!(
        certification["release_gate"]["stability"]["local_soak_connections"],
        1
    );
    assert_eq!(
        certification["release_gate"]["stability"]["required_connections"],
        2
    );
    assert_eq!(
        certification["release_gate"]["stability"]["required_connections_met"],
        false
    );
    assert_eq!(
        certification["release_gate"]["stability"]["summary"]["evidence_required"],
        true
    );
    assert_eq!(
        certification["release_gate"]["stability"]["summary"]["evidence_ready"],
        false
    );
    assert!(certification["release_gate"]["stability"]["summary"]["required_window_ms"].is_null());
    assert_eq!(
        certification["release_gate"]["stability"]["summary"]["required_connections"],
        2
    );
    assert_eq!(
        certification["release_gate"]["stability"]["summary"]["observed_local_soak_connections"],
        1
    );
    assert_eq!(
        certification["release_gate"]["stability"]["summary"]["local_soak_connections_met"],
        false
    );
    assert_eq!(
        certification["release_gate"]["blockers"][0],
        "local-soak-stability-connections-too-low"
    );
}

#[test]
fn support_bundle_certification_records_release_gate_preset_evidence() {
    let mut output = Vec::new();

    keli_cli::write_support_bundle_report_with_options(
        None,
        SupportBundleOptions {
            include_default_core_certification: true,
            certification_soak_connections: 2,
            certification_first_byte_timeout: Duration::from_secs(2),
            certification_max_connection_workers: 2,
            certification_soak_min_duration: Duration::from_millis(0),
            certification_include_system_proxy_smoke: false,
            certification_include_tun_runtime_smoke: false,
            certification_tun_runtime_smoke_min_duration: Duration::from_millis(50),
            certification_require_machine_takeover_ready: false,
            certification_required_stability_window: Some(Duration::from_millis(0)),
            certification_required_stability_connections: Some(2),
            certification_release_gate_preset: Some("default-core-release-gate"),
        },
        &mut output,
    )
    .expect("write support bundle with release gate preset evidence");

    let report: Value = serde_json::from_slice(&output).expect("support bundle json");
    let certification = &report["default_core_certification"];

    assert_eq!(
        certification["release_gate"]["preset"],
        "default-core-release-gate"
    );
    assert_eq!(certification["release_gate"]["status"], "failed");
    assert_eq!(certification["release_gate"]["passed"], false);
    assert_eq!(certification["release_gate"]["preset_requested"], true);
    assert_eq!(certification["release_gate"]["preset_applied"], false);
    assert_eq!(certification["release_gate"]["preset_minimums_met"], false);
    assert_eq!(
        certification["release_gate"]["preset_required_stability_window_ms"],
        60000
    );
    assert_eq!(
        certification["release_gate"]["preset_required_stability_connections"],
        25
    );
    let preset_blockers = certification["release_gate"]["preset_blockers"]
        .as_array()
        .expect("preset blockers");
    assert!(preset_blockers
        .iter()
        .any(|blocker| blocker.as_str() == Some("preset-machine-takeover-not-required")));
    assert!(preset_blockers
        .iter()
        .any(|blocker| blocker.as_str() == Some("preset-stability-window-below-default")));
    assert!(preset_blockers
        .iter()
        .any(|blocker| blocker.as_str() == Some("preset-stability-connections-below-default")));
    let release_gate_blockers = certification["release_gate"]["blockers"]
        .as_array()
        .expect("release gate blockers");
    assert!(release_gate_blockers
        .iter()
        .any(|blocker| blocker.as_str() == Some("preset-machine-takeover-not-required")));
    assert!(release_gate_blockers
        .iter()
        .any(|blocker| blocker.as_str() == Some("preset-stability-window-below-default")));
    assert!(release_gate_blockers
        .iter()
        .any(|blocker| blocker.as_str() == Some("preset-stability-connections-below-default")));
    assert_eq!(
        certification["release_gate"]["blocker_count"].as_u64(),
        Some(release_gate_blockers.len() as u64)
    );
    assert_eq!(
        certification["certification"]["release_gate_preset"],
        "default-core-release-gate"
    );
    assert_eq!(
        certification["certification"]["release_gate_preset_applied"],
        false
    );
}

#[test]
fn support_bundle_certification_treats_preset_request_as_release_gate_scope() {
    let mut output = Vec::new();

    keli_cli::write_support_bundle_report_with_options(
        None,
        SupportBundleOptions {
            include_default_core_certification: true,
            certification_soak_connections: 2,
            certification_first_byte_timeout: Duration::from_secs(2),
            certification_max_connection_workers: 2,
            certification_soak_min_duration: Duration::from_millis(0),
            certification_include_system_proxy_smoke: false,
            certification_include_tun_runtime_smoke: false,
            certification_tun_runtime_smoke_min_duration: Duration::from_millis(50),
            certification_require_machine_takeover_ready: false,
            certification_required_stability_window: None,
            certification_required_stability_connections: None,
            certification_release_gate_preset: Some("default-core-release-gate"),
        },
        &mut output,
    )
    .expect("write support bundle with preset-only release gate evidence");

    let report: Value = serde_json::from_slice(&output).expect("support bundle json");
    let certification = &report["default_core_certification"];

    assert_eq!(certification["release_gate"]["status"], "failed");
    assert_eq!(certification["release_gate"]["required_scope"], "preset");
    assert_eq!(certification["release_gate"]["passed"], false);
    assert_eq!(certification["release_gate"]["preset_requested"], true);
    assert_eq!(certification["release_gate"]["preset_applied"], false);
    let blockers = certification["release_gate"]["blockers"]
        .as_array()
        .expect("release gate blockers");
    assert!(blockers
        .iter()
        .any(|blocker| blocker.as_str() == Some("preset-machine-takeover-not-required")));
    assert!(blockers
        .iter()
        .any(|blocker| blocker.as_str() == Some("preset-stability-window-below-default")));
    assert!(blockers
        .iter()
        .any(|blocker| blocker.as_str() == Some("preset-stability-connections-below-default")));
}

#[test]
fn support_bundle_certification_records_machine_takeover_gate_failure() {
    let mut output = Vec::new();

    keli_cli::write_support_bundle_report_with_options(
        None,
        SupportBundleOptions {
            include_default_core_certification: true,
            certification_soak_connections: 1,
            certification_first_byte_timeout: Duration::from_secs(2),
            certification_max_connection_workers: 1,
            certification_soak_min_duration: Duration::from_millis(0),
            certification_include_system_proxy_smoke: false,
            certification_include_tun_runtime_smoke: false,
            certification_tun_runtime_smoke_min_duration: Duration::from_millis(50),
            certification_require_machine_takeover_ready: true,
            certification_required_stability_window: None,
            certification_required_stability_connections: None,
            certification_release_gate_preset: None,
        },
        &mut output,
    )
    .expect("write support bundle with machine takeover gate evidence");

    let report: Value = serde_json::from_slice(&output).expect("support bundle json");
    let certification = &report["default_core_certification"];

    assert_eq!(certification["release_gate"]["status"], "failed");
    assert_eq!(
        certification["release_gate"]["required_scope"],
        "machine-takeover"
    );
    assert_eq!(
        certification["release_gate"]["require_machine_takeover_ready"],
        true
    );
    assert_eq!(
        certification["release_gate"]["machine_takeover_smokes_requested"],
        false
    );
    assert_eq!(certification["release_gate"]["passed"], false);
    let blockers = certification["release_gate"]["blockers"]
        .as_array()
        .expect("release gate blockers");
    assert!(blockers
        .iter()
        .any(|blocker| { blocker.as_str() == Some("machine-takeover-smokes-not-requested") }));
}
