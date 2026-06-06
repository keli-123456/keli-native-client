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
    assert_eq!(report["summary"]["total_gate_count"], 27);
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
    assert_eq!(report["tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["tcp_relay_smoke"]["selected_outbound"],
        "SS-TCP-SMOKE"
    );
    assert_eq!(report["tcp_relay_smoke"]["target"], "example.com:443");
    assert_eq!(report["tcp_relay_smoke"]["request_payload_bytes"], 14);
    assert_eq!(report["tcp_relay_smoke"]["response_payload_bytes"], 13);
    assert_eq!(report["tcp_relay_smoke"]["round_trip_observed"], true);
    assert_eq!(report["tcp_relay_smoke"]["server_received_payload"], true);
    assert_eq!(report["tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(report["tcp_relay_smoke"]["metrics_inbound_count"], 1);
    assert_eq!(report["tcp_relay_smoke"]["metrics_outbound_route_count"], 1);
    assert_eq!(report["tcp_relay_smoke"]["clean_stop_observed"], true);
    assert_eq!(report["tcp_relay_smoke"]["stop_workers_remaining"], 0);
    assert_eq!(report["tcp_relay_smoke"]["stop_timed_out"], false);
    let tcp_cases = report["tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("TCP relay smoke cases");
    let tcp_case_names: Vec<_> = tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-tcp-relay-runtime",
        "socks5-tcp-shadowsocks-round-trip",
        "record-tcp-relay-metrics",
        "stop-tcp-relay-runtime",
    ] {
        assert!(
            tcp_case_names.contains(&expected),
            "missing TCP relay smoke case {expected}: {tcp_case_names:?}"
        );
    }
    let tcp_round_trip = tcp_cases
        .iter()
        .find(|case| case["name"] == "socks5-tcp-shadowsocks-round-trip")
        .expect("TCP relay round trip case");
    assert_eq!(tcp_round_trip["observed_response"], "keli-tcp-pong");
    assert_eq!(tcp_round_trip["round_trip_observed"], true);
    assert_eq!(tcp_round_trip["server_received_payload"], true);
    assert_eq!(report["http_connect_relay_smoke"]["status"], "passed");
    assert_eq!(report["http_connect_relay_smoke"]["passed"], true);
    assert_eq!(report["http_connect_relay_smoke"]["case_count"], 4);
    assert_eq!(report["http_connect_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["http_connect_relay_smoke"]["selected_outbound"],
        "SS-HTTP-CONNECT-SMOKE"
    );
    assert_eq!(
        report["http_connect_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["http_connect_relay_smoke"]["request_payload_bytes"],
        14
    );
    assert_eq!(
        report["http_connect_relay_smoke"]["response_payload_bytes"],
        13
    );
    assert_eq!(
        report["http_connect_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["http_connect_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["http_connect_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["http_connect_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["http_connect_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["http_connect_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["http_connect_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["http_connect_relay_smoke"]["stop_timed_out"], false);
    let http_connect_cases = report["http_connect_relay_smoke"]["cases"]
        .as_array()
        .expect("HTTP CONNECT relay smoke cases");
    let http_connect_case_names: Vec<_> = http_connect_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-http-connect-relay-runtime",
        "http-connect-shadowsocks-round-trip",
        "record-http-connect-relay-metrics",
        "stop-http-connect-relay-runtime",
    ] {
        assert!(
            http_connect_case_names.contains(&expected),
            "missing HTTP CONNECT relay smoke case {expected}: {http_connect_case_names:?}"
        );
    }
    let http_connect_round_trip = http_connect_cases
        .iter()
        .find(|case| case["name"] == "http-connect-shadowsocks-round-trip")
        .expect("HTTP CONNECT relay round trip case");
    assert_eq!(
        http_connect_round_trip["observed_response"],
        "keli-tcp-pong"
    );
    assert_eq!(http_connect_round_trip["round_trip_observed"], true);
    assert_eq!(http_connect_round_trip["server_received_payload"], true);
    assert_eq!(report["http_proxy_relay_smoke"]["status"], "passed");
    assert_eq!(report["http_proxy_relay_smoke"]["passed"], true);
    assert_eq!(report["http_proxy_relay_smoke"]["case_count"], 4);
    assert_eq!(report["http_proxy_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["http_proxy_relay_smoke"]["selected_outbound"],
        "SS-HTTP-PROXY-SMOKE"
    );
    assert_eq!(report["http_proxy_relay_smoke"]["target"], "example.com:80");
    assert_eq!(
        report["http_proxy_relay_smoke"]["request_payload_bytes"],
        85
    );
    assert_eq!(
        report["http_proxy_relay_smoke"]["response_payload_bytes"],
        78
    );
    assert_eq!(
        report["http_proxy_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["http_proxy_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["http_proxy_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(report["http_proxy_relay_smoke"]["metrics_inbound_count"], 1);
    assert_eq!(
        report["http_proxy_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["http_proxy_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["http_proxy_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["http_proxy_relay_smoke"]["stop_timed_out"], false);
    let http_proxy_cases = report["http_proxy_relay_smoke"]["cases"]
        .as_array()
        .expect("HTTP proxy relay smoke cases");
    let http_proxy_case_names: Vec<_> = http_proxy_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-http-proxy-relay-runtime",
        "http-proxy-shadowsocks-round-trip",
        "record-http-proxy-relay-metrics",
        "stop-http-proxy-relay-runtime",
    ] {
        assert!(
            http_proxy_case_names.contains(&expected),
            "missing HTTP proxy relay smoke case {expected}: {http_proxy_case_names:?}"
        );
    }
    let http_proxy_round_trip = http_proxy_cases
        .iter()
        .find(|case| case["name"] == "http-proxy-shadowsocks-round-trip")
        .expect("HTTP proxy relay round trip case");
    assert!(http_proxy_round_trip["observed_response"]
        .as_str()
        .expect("HTTP proxy observed response")
        .contains("keli-http-proxy-pong"));
    assert_eq!(http_proxy_round_trip["round_trip_observed"], true);
    assert_eq!(http_proxy_round_trip["server_received_payload"], true);
    assert_eq!(report["trojan_tls_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["trojan_tls_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["trojan_tls_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["trojan_tls_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-TLS-TCP-SMOKE"
    );
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["request_payload_bytes"],
        17
    );
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["response_payload_bytes"],
        16
    );
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["stop_timed_out"],
        false
    );
    let trojan_tls_tcp_cases = report["trojan_tls_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("Trojan TLS TCP relay smoke cases");
    let trojan_tls_tcp_case_names: Vec<_> = trojan_tls_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-trojan-tls-tcp-relay-runtime",
        "trojan-tls-tcp-protocol-round-trip",
        "record-trojan-tls-tcp-relay-metrics",
        "stop-trojan-tls-tcp-relay-runtime",
    ] {
        assert!(
            trojan_tls_tcp_case_names.contains(&expected),
            "missing Trojan TLS TCP relay smoke case {expected}: {trojan_tls_tcp_case_names:?}"
        );
    }
    let trojan_tls_tcp_round_trip = trojan_tls_tcp_cases
        .iter()
        .find(|case| case["name"] == "trojan-tls-tcp-protocol-round-trip")
        .expect("Trojan TLS TCP relay round trip case");
    assert_eq!(
        trojan_tls_tcp_round_trip["observed_response"],
        "keli-trojan-pong"
    );
    assert_eq!(trojan_tls_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(trojan_tls_tcp_round_trip["server_received_payload"], true);
    assert_eq!(report["anytls_tls_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["anytls_tls_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["anytls_tls_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["anytls_tls_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["selected_outbound"],
        "ANYTLS-TLS-TCP-SMOKE"
    );
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["request_payload_bytes"],
        17
    );
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["response_payload_bytes"],
        16
    );
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["stop_timed_out"],
        false
    );
    let anytls_tls_tcp_cases = report["anytls_tls_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("AnyTLS TLS TCP relay smoke cases");
    let anytls_tls_tcp_case_names: Vec<_> = anytls_tls_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-anytls-tls-tcp-relay-runtime",
        "anytls-tls-tcp-protocol-round-trip",
        "record-anytls-tls-tcp-relay-metrics",
        "stop-anytls-tls-tcp-relay-runtime",
    ] {
        assert!(
            anytls_tls_tcp_case_names.contains(&expected),
            "missing AnyTLS TLS TCP relay smoke case {expected}: {anytls_tls_tcp_case_names:?}"
        );
    }
    let anytls_tls_tcp_round_trip = anytls_tls_tcp_cases
        .iter()
        .find(|case| case["name"] == "anytls-tls-tcp-protocol-round-trip")
        .expect("AnyTLS TLS TCP relay round trip case");
    assert_eq!(
        anytls_tls_tcp_round_trip["observed_response"],
        "keli-anytls-pong"
    );
    assert_eq!(anytls_tls_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(anytls_tls_tcp_round_trip["server_received_payload"], true);
    assert_eq!(report["naive_h2_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["naive_h2_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["naive_h2_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["naive_h2_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["naive_h2_tcp_relay_smoke"]["selected_outbound"],
        "NAIVE-H2-TCP-SMOKE"
    );
    assert_eq!(
        report["naive_h2_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["naive_h2_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        report["naive_h2_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        report["naive_h2_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["naive_h2_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["naive_h2_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["naive_h2_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["naive_h2_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["naive_h2_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["naive_h2_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["naive_h2_tcp_relay_smoke"]["stop_timed_out"], false);
    let naive_h2_tcp_cases = report["naive_h2_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("Naive H2 TCP relay smoke cases");
    let naive_h2_tcp_case_names: Vec<_> = naive_h2_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-naive-h2-tcp-relay-runtime",
        "naive-h2-tcp-protocol-round-trip",
        "record-naive-h2-tcp-relay-metrics",
        "stop-naive-h2-tcp-relay-runtime",
    ] {
        assert!(
            naive_h2_tcp_case_names.contains(&expected),
            "missing Naive H2 TCP relay smoke case {expected}: {naive_h2_tcp_case_names:?}"
        );
    }
    let naive_h2_tcp_round_trip = naive_h2_tcp_cases
        .iter()
        .find(|case| case["name"] == "naive-h2-tcp-protocol-round-trip")
        .expect("Naive H2 TCP relay round trip case");
    assert_eq!(
        naive_h2_tcp_round_trip["observed_response"],
        "keli-naive-h2-pong"
    );
    assert_eq!(naive_h2_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(naive_h2_tcp_round_trip["server_received_payload"], true);
    assert_eq!(report["hy2_quic_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["hy2_quic_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["hy2_quic_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["hy2_quic_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["hy2_quic_tcp_relay_smoke"]["selected_outbound"],
        "HY2-QUIC-TCP-SMOKE"
    );
    assert_eq!(
        report["hy2_quic_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["hy2_quic_tcp_relay_smoke"]["request_payload_bytes"],
        14
    );
    assert_eq!(
        report["hy2_quic_tcp_relay_smoke"]["response_payload_bytes"],
        13
    );
    assert_eq!(
        report["hy2_quic_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["hy2_quic_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["hy2_quic_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["hy2_quic_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["hy2_quic_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["hy2_quic_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["hy2_quic_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["hy2_quic_tcp_relay_smoke"]["stop_timed_out"], false);
    let hy2_quic_tcp_cases = report["hy2_quic_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("HY2 QUIC TCP relay smoke cases");
    let hy2_quic_tcp_case_names: Vec<_> = hy2_quic_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-hy2-quic-tcp-relay-runtime",
        "hy2-quic-tcp-protocol-round-trip",
        "record-hy2-quic-tcp-relay-metrics",
        "stop-hy2-quic-tcp-relay-runtime",
    ] {
        assert!(
            hy2_quic_tcp_case_names.contains(&expected),
            "missing HY2 QUIC TCP relay smoke case {expected}: {hy2_quic_tcp_case_names:?}"
        );
    }
    let hy2_quic_tcp_round_trip = hy2_quic_tcp_cases
        .iter()
        .find(|case| case["name"] == "hy2-quic-tcp-protocol-round-trip")
        .expect("HY2 QUIC TCP relay round trip case");
    assert_eq!(
        hy2_quic_tcp_round_trip["observed_response"],
        "keli-hy2-pong"
    );
    assert_eq!(hy2_quic_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(hy2_quic_tcp_round_trip["server_received_payload"], true);
    assert_eq!(report["tuic_quic_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["tuic_quic_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["tuic_quic_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["tuic_quic_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["selected_outbound"],
        "TUIC-QUIC-TCP-SMOKE"
    );
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["request_payload_bytes"],
        15
    );
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["response_payload_bytes"],
        14
    );
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["tuic_quic_tcp_relay_smoke"]["stop_timed_out"], false);
    let tuic_quic_tcp_cases = report["tuic_quic_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("TUIC QUIC TCP relay smoke cases");
    let tuic_quic_tcp_case_names: Vec<_> = tuic_quic_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-tuic-quic-tcp-relay-runtime",
        "tuic-quic-tcp-protocol-round-trip",
        "record-tuic-quic-tcp-relay-metrics",
        "stop-tuic-quic-tcp-relay-runtime",
    ] {
        assert!(
            tuic_quic_tcp_case_names.contains(&expected),
            "missing TUIC QUIC TCP relay smoke case {expected}: {tuic_quic_tcp_case_names:?}"
        );
    }
    let tuic_quic_tcp_round_trip = tuic_quic_tcp_cases
        .iter()
        .find(|case| case["name"] == "tuic-quic-tcp-protocol-round-trip")
        .expect("TUIC QUIC TCP relay round trip case");
    assert_eq!(
        tuic_quic_tcp_round_trip["observed_response"],
        "keli-tuic-pong"
    );
    assert_eq!(tuic_quic_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(tuic_quic_tcp_round_trip["server_received_payload"], true);
    assert_eq!(report["vless_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vless_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["vless_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vless_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vless_tcp_relay_smoke"]["selected_outbound"],
        "VLESS-TCP-SMOKE"
    );
    assert_eq!(report["vless_tcp_relay_smoke"]["target"], "example.com:443");
    assert_eq!(report["vless_tcp_relay_smoke"]["request_payload_bytes"], 16);
    assert_eq!(
        report["vless_tcp_relay_smoke"]["response_payload_bytes"],
        15
    );
    assert_eq!(report["vless_tcp_relay_smoke"]["round_trip_observed"], true);
    assert_eq!(
        report["vless_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["vless_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(report["vless_tcp_relay_smoke"]["metrics_inbound_count"], 1);
    assert_eq!(
        report["vless_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(report["vless_tcp_relay_smoke"]["clean_stop_observed"], true);
    assert_eq!(report["vless_tcp_relay_smoke"]["stop_workers_remaining"], 0);
    assert_eq!(report["vless_tcp_relay_smoke"]["stop_timed_out"], false);
    let vless_tcp_cases = report["vless_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("VLESS TCP relay smoke cases");
    let vless_tcp_case_names: Vec<_> = vless_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vless-tcp-relay-runtime",
        "vless-tcp-protocol-round-trip",
        "record-vless-tcp-relay-metrics",
        "stop-vless-tcp-relay-runtime",
    ] {
        assert!(
            vless_tcp_case_names.contains(&expected),
            "missing VLESS TCP relay smoke case {expected}: {vless_tcp_case_names:?}"
        );
    }
    let vless_tcp_round_trip = vless_tcp_cases
        .iter()
        .find(|case| case["name"] == "vless-tcp-protocol-round-trip")
        .expect("VLESS TCP relay round trip case");
    assert_eq!(vless_tcp_round_trip["observed_response"], "keli-vless-pong");
    assert_eq!(vless_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(vless_tcp_round_trip["server_received_payload"], true);
    assert_eq!(report["vmess_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vmess_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["vmess_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vmess_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vmess_tcp_relay_smoke"]["selected_outbound"],
        "VMESS-TCP-SMOKE"
    );
    assert_eq!(report["vmess_tcp_relay_smoke"]["target"], "example.com:443");
    assert_eq!(report["vmess_tcp_relay_smoke"]["request_payload_bytes"], 16);
    assert_eq!(
        report["vmess_tcp_relay_smoke"]["response_payload_bytes"],
        15
    );
    assert_eq!(report["vmess_tcp_relay_smoke"]["round_trip_observed"], true);
    assert_eq!(
        report["vmess_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["vmess_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(report["vmess_tcp_relay_smoke"]["metrics_inbound_count"], 1);
    assert_eq!(
        report["vmess_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(report["vmess_tcp_relay_smoke"]["clean_stop_observed"], true);
    assert_eq!(report["vmess_tcp_relay_smoke"]["stop_workers_remaining"], 0);
    assert_eq!(report["vmess_tcp_relay_smoke"]["stop_timed_out"], false);
    let vmess_tcp_cases = report["vmess_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("VMess TCP relay smoke cases");
    let vmess_tcp_case_names: Vec<_> = vmess_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vmess-tcp-relay-runtime",
        "vmess-tcp-protocol-round-trip",
        "record-vmess-tcp-relay-metrics",
        "stop-vmess-tcp-relay-runtime",
    ] {
        assert!(
            vmess_tcp_case_names.contains(&expected),
            "missing VMess TCP relay smoke case {expected}: {vmess_tcp_case_names:?}"
        );
    }
    let vmess_tcp_round_trip = vmess_tcp_cases
        .iter()
        .find(|case| case["name"] == "vmess-tcp-protocol-round-trip")
        .expect("VMess TCP relay round trip case");
    assert_eq!(vmess_tcp_round_trip["observed_response"], "keli-vmess-pong");
    assert_eq!(vmess_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(vmess_tcp_round_trip["server_received_payload"], true);
    assert_eq!(report["mieru_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["mieru_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["mieru_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["mieru_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["mieru_tcp_relay_smoke"]["selected_outbound"],
        "MIERU-TCP-SMOKE"
    );
    assert_eq!(report["mieru_tcp_relay_smoke"]["target"], "example.com:443");
    assert_eq!(report["mieru_tcp_relay_smoke"]["request_payload_bytes"], 16);
    assert_eq!(
        report["mieru_tcp_relay_smoke"]["response_payload_bytes"],
        15
    );
    assert_eq!(report["mieru_tcp_relay_smoke"]["round_trip_observed"], true);
    assert_eq!(
        report["mieru_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["mieru_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(report["mieru_tcp_relay_smoke"]["metrics_inbound_count"], 1);
    assert_eq!(
        report["mieru_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(report["mieru_tcp_relay_smoke"]["clean_stop_observed"], true);
    assert_eq!(report["mieru_tcp_relay_smoke"]["stop_workers_remaining"], 0);
    assert_eq!(report["mieru_tcp_relay_smoke"]["stop_timed_out"], false);
    let mieru_tcp_cases = report["mieru_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("Mieru TCP relay smoke cases");
    let mieru_tcp_case_names: Vec<_> = mieru_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-mieru-tcp-relay-runtime",
        "mieru-tcp-protocol-round-trip",
        "record-mieru-tcp-relay-metrics",
        "stop-mieru-tcp-relay-runtime",
    ] {
        assert!(
            mieru_tcp_case_names.contains(&expected),
            "missing Mieru TCP relay smoke case {expected}: {mieru_tcp_case_names:?}"
        );
    }
    let mieru_tcp_round_trip = mieru_tcp_cases
        .iter()
        .find(|case| case["name"] == "mieru-tcp-protocol-round-trip")
        .expect("Mieru TCP relay round trip case");
    assert_eq!(mieru_tcp_round_trip["observed_response"], "keli-mieru-pong");
    assert_eq!(mieru_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(mieru_tcp_round_trip["server_received_payload"], true);
    assert_eq!(report["udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["udp_relay_smoke"]["passed"], true);
    assert_eq!(report["udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["udp_relay_smoke"]["selected_outbound"],
        "SS-UDP-SMOKE"
    );
    assert_eq!(report["udp_relay_smoke"]["target"], "example.com:53");
    assert!(report["udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(report["udp_relay_smoke"]["response_source"], "127.0.0.1:53");
    assert_eq!(report["udp_relay_smoke"]["request_payload_bytes"], 14);
    assert_eq!(report["udp_relay_smoke"]["response_payload_bytes"], 13);
    assert_eq!(report["udp_relay_smoke"]["round_trip_observed"], true);
    assert_eq!(report["udp_relay_smoke"]["server_received_payload"], true);
    assert_eq!(report["udp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(report["udp_relay_smoke"]["metrics_inbound_count"], 1);
    assert_eq!(report["udp_relay_smoke"]["metrics_outbound_route_count"], 1);
    assert_eq!(report["udp_relay_smoke"]["clean_stop_observed"], true);
    assert_eq!(report["udp_relay_smoke"]["stop_workers_remaining"], 0);
    assert_eq!(report["udp_relay_smoke"]["stop_timed_out"], false);
    let udp_cases = report["udp_relay_smoke"]["cases"]
        .as_array()
        .expect("UDP relay smoke cases");
    let udp_case_names: Vec<_> = udp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-udp-relay-runtime",
        "socks5-udp-shadowsocks-round-trip",
        "record-udp-relay-metrics",
        "stop-udp-relay-runtime",
    ] {
        assert!(
            udp_case_names.contains(&expected),
            "missing UDP relay smoke case {expected}: {udp_case_names:?}"
        );
    }
    let udp_round_trip = udp_cases
        .iter()
        .find(|case| case["name"] == "socks5-udp-shadowsocks-round-trip")
        .expect("UDP relay round trip case");
    assert_eq!(udp_round_trip["observed_response"], "keli-udp-pong");
    assert_eq!(udp_round_trip["round_trip_observed"], true);
    assert_eq!(udp_round_trip["server_received_payload"], true);
    assert_eq!(report["resource_limit_smoke"]["status"], "passed");
    assert_eq!(report["resource_limit_smoke"]["passed"], true);
    assert_eq!(report["resource_limit_smoke"]["case_count"], 5);
    assert_eq!(report["resource_limit_smoke"]["failed_case_count"], 0);
    assert_eq!(report["resource_limit_smoke"]["max_connection_workers"], 1);
    assert_eq!(report["resource_limit_smoke"]["busy_worker_count"], 1);
    assert_eq!(
        report["resource_limit_smoke"]["rejected_connection_count"],
        1
    );
    assert_eq!(
        report["resource_limit_smoke"]["connection_limit_error_count"],
        1
    );
    assert_eq!(
        report["resource_limit_smoke"]["worker_limit_enforced"],
        true
    );
    assert_eq!(report["resource_limit_smoke"]["metrics_recorded"], true);
    assert_eq!(report["resource_limit_smoke"]["workers_drained"], true);
    assert_eq!(report["resource_limit_smoke"]["clean_stop_observed"], true);
    assert_eq!(report["resource_limit_smoke"]["stop_workers_remaining"], 0);
    assert_eq!(report["resource_limit_smoke"]["stop_timed_out"], false);
    let resource_cases = report["resource_limit_smoke"]["cases"]
        .as_array()
        .expect("resource limit smoke cases");
    let resource_case_names: Vec<_> = resource_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-resource-limit-runtime",
        "occupy-worker-slot",
        "reject-over-worker-limit",
        "drain-worker-slot",
        "stop-resource-limit-runtime",
    ] {
        assert!(
            resource_case_names.contains(&expected),
            "missing resource limit smoke case {expected}: {resource_case_names:?}"
        );
    }
    let rejected = resource_cases
        .iter()
        .find(|case| case["name"] == "reject-over-worker-limit")
        .expect("resource limit reject case");
    assert_eq!(rejected["observed_error_kind"], "connection_limit_reached");
    assert_eq!(rejected["worker_limit_enforced"], true);
    assert_eq!(rejected["metrics_recorded"], true);
    assert_eq!(report["panel_subscription_smoke"]["status"], "passed");
    assert_eq!(report["panel_subscription_smoke"]["passed"], true);
    assert_eq!(report["panel_subscription_smoke"]["case_count"], 9);
    assert_eq!(report["panel_subscription_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["panel_subscription_smoke"]["restricted_account_state"],
        "limited"
    );
    assert_eq!(
        report["panel_subscription_smoke"]["restricted_risk_control"],
        "restricted"
    );
    assert_eq!(report["panel_subscription_smoke"]["start_blocked"], true);
    assert_eq!(report["panel_subscription_smoke"]["reload_blocked"], true);
    assert_eq!(report["panel_subscription_smoke"]["probe_blocked"], true);
    assert_eq!(report["panel_subscription_smoke"]["apply_blocked"], true);
    assert_eq!(
        report["panel_subscription_smoke"]["runtime_preserved_while_restricted"],
        true
    );
    assert_eq!(
        report["panel_subscription_smoke"]["clear_allowed_runtime"],
        true
    );
    assert_eq!(
        report["panel_subscription_smoke"]["final_selected_outbound"],
        "SS-READY"
    );
    assert_eq!(
        report["panel_subscription_smoke"]["clean_stop_observed"],
        true
    );
    let panel_cases = report["panel_subscription_smoke"]["cases"]
        .as_array()
        .expect("panel subscription smoke cases");
    let panel_case_names: Vec<_> = panel_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "record-restricted-panel-before-start",
        "block-start-while-restricted",
        "clear-and-start-runtime",
        "record-restricted-panel-during-runtime",
        "block-reload-while-restricted",
        "block-node-probe-while-restricted",
        "block-recommended-switch-while-restricted",
        "clear-restriction-allows-reload",
        "stop-runtime-after-panel-smoke",
    ] {
        assert!(
            panel_case_names.contains(&expected),
            "missing panel smoke case {expected}: {panel_case_names:?}"
        );
    }
    let reload_block = panel_cases
        .iter()
        .find(|case| case["name"] == "block-reload-while-restricted")
        .expect("panel reload block case");
    assert_eq!(
        reload_block["observed_error_kind"],
        "panel-traffic-restricted"
    );
    assert_eq!(reload_block["runtime_preserved"], true);
    let clear_reload = panel_cases
        .iter()
        .find(|case| case["name"] == "clear-restriction-allows-reload")
        .expect("panel clear reload case");
    assert_eq!(clear_reload["clear_allowed_runtime"], true);
    assert_eq!(clear_reload["panel_state_present"], false);
    assert_eq!(clear_reload["observed_generation"], 2);
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

    let resource_limits = gate(gates, "resource-limits");
    assert_eq!(resource_limits["category"], "stability");
    assert_eq!(resource_limits["status"], "passed");
    assert!(resource_limits["detail"]
        .as_str()
        .expect("resource limits detail")
        .contains("resource_limit_smoke=cases=5"));
    assert!(resource_limits["detail"]
        .as_str()
        .expect("resource limits detail")
        .contains("worker_limit_enforced=true"));

    let panel_state = gate(gates, "panel-subscription-state");
    assert_eq!(panel_state["category"], "managed-runtime");
    assert_eq!(panel_state["status"], "passed");
    assert!(panel_state["detail"]
        .as_str()
        .expect("panel state detail")
        .contains("panel_subscription_smoke=cases=9"));
    assert!(panel_state["detail"]
        .as_str()
        .expect("panel state detail")
        .contains("runtime_preserved=true"));

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
        "readiness status=not-ready schema_version={} gates=27",
        READINESS_CHECK_SCHEMA_VERSION
    )));
    assert!(output.contains("blockers="));
    assert!(output.contains("readiness gate=interop-matrix category=protocols status=passed"));
    assert!(output.contains("readiness gate=route-rule-smoke category=routing status=passed"));
    assert!(output.contains("readiness gate=dns-policy-smoke category=dns status=passed"));
    assert!(output.contains("readiness gate=tcp-relay-smoke category=protocols status=passed"));
    assert!(
        output.contains("readiness gate=http-connect-relay-smoke category=protocols status=passed")
    );
    assert!(
        output.contains("readiness gate=http-proxy-relay-smoke category=protocols status=passed")
    );
    assert!(output
        .contains("readiness gate=trojan-tls-tcp-relay-smoke category=protocols status=passed"));
    assert!(output
        .contains("readiness gate=anytls-tls-tcp-relay-smoke category=protocols status=passed"));
    assert!(
        output.contains("readiness gate=naive-h2-tcp-relay-smoke category=protocols status=passed")
    );
    assert!(
        output.contains("readiness gate=hy2-quic-tcp-relay-smoke category=protocols status=passed")
    );
    assert!(output
        .contains("readiness gate=tuic-quic-tcp-relay-smoke category=protocols status=passed"));
    assert!(
        output.contains("readiness gate=vless-tcp-relay-smoke category=protocols status=passed")
    );
    assert!(
        output.contains("readiness gate=vmess-tcp-relay-smoke category=protocols status=passed")
    );
    assert!(
        output.contains("readiness gate=mieru-tcp-relay-smoke category=protocols status=passed")
    );
    assert!(output.contains("readiness gate=udp-relay-smoke category=protocols status=passed"));
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
    assert!(output.contains("readiness tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness http_connect_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness http_proxy_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness trojan_tls_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness anytls_tls_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness naive_h2_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness hy2_quic_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness tuic_quic_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vless_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vmess_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness mieru_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness resource_limit_smoke status=passed cases=5"));
    assert!(output.contains("readiness panel_subscription_smoke status=passed cases=9"));
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
    assert_eq!(report["certification"]["tcp_relay_smoke_passed"], true);
    assert_eq!(report["tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(report["tcp_relay_smoke"]["round_trip_observed"], true);
    assert_eq!(report["tcp_relay_smoke"]["server_received_payload"], true);
    assert_eq!(report["tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(report["tcp_relay_smoke"]["clean_stop_observed"], true);
    assert_eq!(report["readiness"]["tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["readiness"]["tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["certification"]["http_connect_relay_smoke_passed"],
        true
    );
    assert_eq!(report["http_connect_relay_smoke"]["status"], "passed");
    assert_eq!(report["http_connect_relay_smoke"]["case_count"], 4);
    assert_eq!(report["http_connect_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["http_connect_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["http_connect_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["http_connect_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["http_connect_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["http_connect_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["http_connect_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["http_proxy_relay_smoke_passed"],
        true
    );
    assert_eq!(report["http_proxy_relay_smoke"]["status"], "passed");
    assert_eq!(report["http_proxy_relay_smoke"]["case_count"], 4);
    assert_eq!(report["http_proxy_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["http_proxy_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["http_proxy_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["http_proxy_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["http_proxy_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["http_proxy_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["http_proxy_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["trojan_tls_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["trojan_tls_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["trojan_tls_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["trojan_tls_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-TLS-TCP-SMOKE"
    );
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["trojan_tls_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["trojan_tls_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["trojan_tls_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["anytls_tls_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["anytls_tls_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["anytls_tls_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["anytls_tls_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["selected_outbound"],
        "ANYTLS-TLS-TCP-SMOKE"
    );
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["anytls_tls_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["anytls_tls_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["anytls_tls_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["naive_h2_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["naive_h2_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["naive_h2_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["naive_h2_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["naive_h2_tcp_relay_smoke"]["selected_outbound"],
        "NAIVE-H2-TCP-SMOKE"
    );
    assert_eq!(
        report["naive_h2_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["naive_h2_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["naive_h2_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["naive_h2_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["naive_h2_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["naive_h2_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["naive_h2_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["hy2_quic_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["hy2_quic_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["hy2_quic_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["hy2_quic_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["hy2_quic_tcp_relay_smoke"]["selected_outbound"],
        "HY2-QUIC-TCP-SMOKE"
    );
    assert_eq!(
        report["hy2_quic_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["hy2_quic_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["hy2_quic_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["hy2_quic_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["hy2_quic_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["hy2_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["hy2_quic_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["tuic_quic_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["tuic_quic_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["tuic_quic_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["tuic_quic_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["selected_outbound"],
        "TUIC-QUIC-TCP-SMOKE"
    );
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["tuic_quic_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["tuic_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["tuic_quic_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["vless_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["vless_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vless_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vless_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(report["vless_tcp_relay_smoke"]["round_trip_observed"], true);
    assert_eq!(
        report["vless_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["vless_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(report["vless_tcp_relay_smoke"]["clean_stop_observed"], true);
    assert_eq!(
        report["readiness"]["vless_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vless_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["vmess_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["vmess_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vmess_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vmess_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(report["vmess_tcp_relay_smoke"]["round_trip_observed"], true);
    assert_eq!(
        report["vmess_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["vmess_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(report["vmess_tcp_relay_smoke"]["clean_stop_observed"], true);
    assert_eq!(
        report["readiness"]["vmess_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vmess_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["mieru_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["mieru_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["mieru_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["mieru_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["mieru_tcp_relay_smoke"]["selected_outbound"],
        "MIERU-TCP-SMOKE"
    );
    assert_eq!(report["mieru_tcp_relay_smoke"]["target"], "example.com:443");
    assert_eq!(report["mieru_tcp_relay_smoke"]["round_trip_observed"], true);
    assert_eq!(
        report["mieru_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["mieru_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(report["mieru_tcp_relay_smoke"]["clean_stop_observed"], true);
    assert_eq!(
        report["readiness"]["mieru_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["mieru_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(report["certification"]["udp_relay_smoke_passed"], true);
    assert_eq!(report["udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(report["udp_relay_smoke"]["round_trip_observed"], true);
    assert_eq!(report["udp_relay_smoke"]["server_received_payload"], true);
    assert_eq!(report["udp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(report["udp_relay_smoke"]["clean_stop_observed"], true);
    assert_eq!(report["readiness"]["udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["readiness"]["udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["certification"]["resource_limit_smoke_passed"], true);
    assert_eq!(report["resource_limit_smoke"]["status"], "passed");
    assert_eq!(report["resource_limit_smoke"]["case_count"], 5);
    assert_eq!(report["resource_limit_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["resource_limit_smoke"]["worker_limit_enforced"],
        true
    );
    assert_eq!(report["resource_limit_smoke"]["metrics_recorded"], true);
    assert_eq!(report["resource_limit_smoke"]["workers_drained"], true);
    assert_eq!(
        report["readiness"]["resource_limit_smoke"]["status"],
        "passed"
    );
    assert_eq!(report["readiness"]["resource_limit_smoke"]["case_count"], 5);
    assert_eq!(
        report["certification"]["panel_subscription_smoke_passed"],
        true
    );
    assert_eq!(report["panel_subscription_smoke"]["status"], "passed");
    assert_eq!(report["panel_subscription_smoke"]["case_count"], 9);
    assert_eq!(report["panel_subscription_smoke"]["failed_case_count"], 0);
    assert_eq!(report["panel_subscription_smoke"]["start_blocked"], true);
    assert_eq!(report["panel_subscription_smoke"]["reload_blocked"], true);
    assert_eq!(report["panel_subscription_smoke"]["probe_blocked"], true);
    assert_eq!(report["panel_subscription_smoke"]["apply_blocked"], true);
    assert_eq!(
        report["panel_subscription_smoke"]["runtime_preserved_while_restricted"],
        true
    );
    assert_eq!(
        report["panel_subscription_smoke"]["clear_allowed_runtime"],
        true
    );
    assert_eq!(
        report["readiness"]["panel_subscription_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["panel_subscription_smoke"]["case_count"],
        9
    );
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
    assert_eq!(gate(gates, "tcp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "http-connect-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "http-proxy-relay-smoke")["status"], "passed");
    assert_eq!(
        gate(gates, "trojan-tls-tcp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "anytls-tls-tcp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(gate(gates, "hy2-quic-tcp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "tuic-quic-tcp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "vless-tcp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "vmess-tcp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "udp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "resource-limits")["status"], "passed");
    assert_eq!(gate(gates, "panel-subscription-state")["status"], "passed");
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
    assert!(output.contains("default_core_certification tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification http_connect_relay_smoke status=passed cases=4"));
    assert!(
        output.contains("default_core_certification http_proxy_relay_smoke status=passed cases=4")
    );
    assert!(output
        .contains("default_core_certification trojan_tls_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification anytls_tls_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification naive_h2_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification hy2_quic_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification tuic_quic_tcp_relay_smoke status=passed cases=4"));
    assert!(
        output.contains("default_core_certification vless_tcp_relay_smoke status=passed cases=4")
    );
    assert!(
        output.contains("default_core_certification vmess_tcp_relay_smoke status=passed cases=4")
    );
    assert!(
        output.contains("default_core_certification mieru_tcp_relay_smoke status=passed cases=4")
    );
    assert!(output.contains("default_core_certification udp_relay_smoke status=passed cases=4"));
    assert!(
        output.contains("default_core_certification resource_limit_smoke status=passed cases=5")
    );
    assert!(output
        .contains("default_core_certification panel_subscription_smoke status=passed cases=9"));
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
