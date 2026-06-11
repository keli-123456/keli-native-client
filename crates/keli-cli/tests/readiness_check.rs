use std::time::Duration;

use keli_cli::{
    write_default_core_certification_report,
    write_default_core_certification_report_with_release_gate_and_stability_options,
    write_default_core_certification_report_with_release_gate_and_stability_requirements,
    write_default_core_certification_report_with_release_gate_options,
    write_default_core_certification_report_with_release_gate_preset_and_stability_requirements,
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
    assert_eq!(report["summary"]["total_gate_count"], 71);
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
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(report["socks5_tcp_outbound_relay_smoke"]["passed"], true);
    assert_eq!(report["socks5_tcp_outbound_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["selected_outbound"],
        "SOCKS5-TCP-OUTBOUND-SMOKE"
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["request_payload_bytes"],
        26
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["response_payload_bytes"],
        25
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["stop_timed_out"],
        false
    );
    let socks5_tcp_outbound_cases = report["socks5_tcp_outbound_relay_smoke"]["cases"]
        .as_array()
        .expect("SOCKS5 TCP outbound relay smoke cases");
    let socks5_tcp_outbound_case_names: Vec<_> = socks5_tcp_outbound_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-socks5-tcp-outbound-relay-runtime",
        "socks5-tcp-outbound-protocol-round-trip",
        "record-socks5-tcp-outbound-relay-metrics",
        "stop-socks5-tcp-outbound-relay-runtime",
    ] {
        assert!(
            socks5_tcp_outbound_case_names.contains(&expected),
            "missing SOCKS5 TCP outbound relay smoke case {expected}: {socks5_tcp_outbound_case_names:?}"
        );
    }
    let socks5_tcp_outbound_round_trip = socks5_tcp_outbound_cases
        .iter()
        .find(|case| case["name"] == "socks5-tcp-outbound-protocol-round-trip")
        .expect("SOCKS5 TCP outbound relay round trip case");
    assert_eq!(
        socks5_tcp_outbound_round_trip["observed_response"],
        "keli-socks5-outbound-pong"
    );
    assert_eq!(socks5_tcp_outbound_round_trip["round_trip_observed"], true);
    assert_eq!(
        socks5_tcp_outbound_round_trip["server_received_payload"],
        true
    );
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
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(report["http_connect_outbound_relay_smoke"]["passed"], true);
    assert_eq!(report["http_connect_outbound_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["selected_outbound"],
        "HTTP-CONNECT-OUTBOUND-SMOKE"
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["request_payload_bytes"],
        24
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["response_payload_bytes"],
        23
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["stop_timed_out"],
        false
    );
    let http_connect_outbound_cases = report["http_connect_outbound_relay_smoke"]["cases"]
        .as_array()
        .expect("HTTP CONNECT outbound relay smoke cases");
    let http_connect_outbound_case_names: Vec<_> = http_connect_outbound_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-http-connect-outbound-relay-runtime",
        "http-connect-outbound-protocol-round-trip",
        "record-http-connect-outbound-relay-metrics",
        "stop-http-connect-outbound-relay-runtime",
    ] {
        assert!(
            http_connect_outbound_case_names.contains(&expected),
            "missing HTTP CONNECT outbound relay smoke case {expected}: {http_connect_outbound_case_names:?}"
        );
    }
    let http_connect_outbound_round_trip = http_connect_outbound_cases
        .iter()
        .find(|case| case["name"] == "http-connect-outbound-protocol-round-trip")
        .expect("HTTP CONNECT outbound relay round trip case");
    assert_eq!(
        http_connect_outbound_round_trip["observed_response"],
        "keli-http-outbound-pong"
    );
    assert_eq!(
        http_connect_outbound_round_trip["round_trip_observed"],
        true
    );
    assert_eq!(
        http_connect_outbound_round_trip["server_received_payload"],
        true
    );
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
    assert_eq!(report["trojan_ws_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["trojan_ws_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["trojan_ws_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["trojan_ws_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-WS-TCP-SMOKE"
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["trojan_ws_tcp_relay_smoke"]["stop_timed_out"], false);
    let trojan_ws_tcp_cases = report["trojan_ws_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("Trojan WS TCP relay smoke cases");
    let trojan_ws_tcp_case_names: Vec<_> = trojan_ws_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-trojan-ws-tcp-relay-runtime",
        "trojan-ws-tcp-protocol-round-trip",
        "record-trojan-ws-tcp-relay-metrics",
        "stop-trojan-ws-tcp-relay-runtime",
    ] {
        assert!(
            trojan_ws_tcp_case_names.contains(&expected),
            "missing Trojan WS TCP relay smoke case {expected}: {trojan_ws_tcp_case_names:?}"
        );
    }
    let trojan_ws_tcp_round_trip = trojan_ws_tcp_cases
        .iter()
        .find(|case| case["name"] == "trojan-ws-tcp-protocol-round-trip")
        .expect("Trojan WS TCP relay round trip case");
    assert_eq!(
        trojan_ws_tcp_round_trip["observed_response"],
        "keli-trojan-ws-pong"
    );
    assert_eq!(trojan_ws_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(trojan_ws_tcp_round_trip["server_received_payload"], true);
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(report["trojan_httpupgrade_tcp_relay_smoke"]["passed"], true);
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-HU-TCP-SMOKE"
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["stop_timed_out"],
        false
    );
    let trojan_httpupgrade_tcp_cases = report["trojan_httpupgrade_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("Trojan HTTPUpgrade TCP relay smoke cases");
    let trojan_httpupgrade_tcp_case_names: Vec<_> = trojan_httpupgrade_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-trojan-httpupgrade-tcp-relay-runtime",
        "trojan-httpupgrade-tcp-protocol-round-trip",
        "record-trojan-httpupgrade-tcp-relay-metrics",
        "stop-trojan-httpupgrade-tcp-relay-runtime",
    ] {
        assert!(
            trojan_httpupgrade_tcp_case_names.contains(&expected),
            "missing Trojan HTTPUpgrade TCP relay smoke case {expected}: {trojan_httpupgrade_tcp_case_names:?}"
        );
    }
    let trojan_httpupgrade_tcp_round_trip = trojan_httpupgrade_tcp_cases
        .iter()
        .find(|case| case["name"] == "trojan-httpupgrade-tcp-protocol-round-trip")
        .expect("Trojan HTTPUpgrade TCP relay round trip case");
    assert_eq!(
        trojan_httpupgrade_tcp_round_trip["observed_response"],
        "keli-trojan-hu-pong"
    );
    assert_eq!(
        trojan_httpupgrade_tcp_round_trip["round_trip_observed"],
        true
    );
    assert_eq!(
        trojan_httpupgrade_tcp_round_trip["server_received_payload"],
        true
    );
    assert_eq!(report["trojan_grpc_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["trojan_grpc_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["trojan_grpc_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-GRPC-TCP-SMOKE"
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["request_payload_bytes"],
        22
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["response_payload_bytes"],
        21
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["stop_timed_out"],
        false
    );
    let trojan_grpc_tcp_cases = report["trojan_grpc_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("Trojan gRPC TCP relay smoke cases");
    let trojan_grpc_tcp_case_names: Vec<_> = trojan_grpc_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-trojan-grpc-tcp-relay-runtime",
        "trojan-grpc-tcp-protocol-round-trip",
        "record-trojan-grpc-tcp-relay-metrics",
        "stop-trojan-grpc-tcp-relay-runtime",
    ] {
        assert!(
            trojan_grpc_tcp_case_names.contains(&expected),
            "missing Trojan gRPC TCP relay smoke case {expected}: {trojan_grpc_tcp_case_names:?}"
        );
    }
    let trojan_grpc_tcp_round_trip = trojan_grpc_tcp_cases
        .iter()
        .find(|case| case["name"] == "trojan-grpc-tcp-protocol-round-trip")
        .expect("Trojan gRPC TCP relay round trip case");
    assert_eq!(
        trojan_grpc_tcp_round_trip["observed_response"],
        "keli-trojan-grpc-pong"
    );
    assert_eq!(trojan_grpc_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(trojan_grpc_tcp_round_trip["server_received_payload"], true);
    assert_eq!(report["trojan_h2_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["trojan_h2_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["trojan_h2_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["trojan_h2_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-H2-TCP-SMOKE"
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["trojan_h2_tcp_relay_smoke"]["stop_timed_out"], false);
    let trojan_h2_tcp_cases = report["trojan_h2_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("Trojan H2 TCP relay smoke cases");
    let trojan_h2_tcp_case_names: Vec<_> = trojan_h2_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-trojan-h2-tcp-relay-runtime",
        "trojan-h2-tcp-protocol-round-trip",
        "record-trojan-h2-tcp-relay-metrics",
        "stop-trojan-h2-tcp-relay-runtime",
    ] {
        assert!(
            trojan_h2_tcp_case_names.contains(&expected),
            "missing Trojan H2 TCP relay smoke case {expected}: {trojan_h2_tcp_case_names:?}"
        );
    }
    let trojan_h2_tcp_round_trip = trojan_h2_tcp_cases
        .iter()
        .find(|case| case["name"] == "trojan-h2-tcp-protocol-round-trip")
        .expect("Trojan H2 TCP relay round trip case");
    assert_eq!(
        trojan_h2_tcp_round_trip["observed_response"],
        "keli-trojan-h2-pong"
    );
    assert_eq!(trojan_h2_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(trojan_h2_tcp_round_trip["server_received_payload"], true);
    assert_eq!(report["trojan_quic_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["trojan_quic_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["trojan_quic_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-QUIC-TCP-SMOKE"
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["request_payload_bytes"],
        22
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["response_payload_bytes"],
        21
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["stop_timed_out"],
        false
    );
    let trojan_quic_tcp_cases = report["trojan_quic_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("Trojan QUIC TCP relay smoke cases");
    let trojan_quic_tcp_case_names: Vec<_> = trojan_quic_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-trojan-quic-tcp-relay-runtime",
        "trojan-quic-tcp-protocol-round-trip",
        "record-trojan-quic-tcp-relay-metrics",
        "stop-trojan-quic-tcp-relay-runtime",
    ] {
        assert!(
            trojan_quic_tcp_case_names.contains(&expected),
            "missing Trojan QUIC TCP relay smoke case {expected}: {trojan_quic_tcp_case_names:?}"
        );
    }
    let trojan_quic_tcp_round_trip = trojan_quic_tcp_cases
        .iter()
        .find(|case| case["name"] == "trojan-quic-tcp-protocol-round-trip")
        .expect("Trojan QUIC TCP relay round trip case");
    assert_eq!(
        trojan_quic_tcp_round_trip["observed_response"],
        "keli-trojan-quic-pong"
    );
    assert_eq!(trojan_quic_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(trojan_quic_tcp_round_trip["server_received_payload"], true);
    assert_trojan_quic_udp_relay_smoke_json(&report);
    assert_eq!(report["trojan_tls_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["trojan_tls_udp_relay_smoke"]["passed"], true);
    assert_eq!(report["trojan_tls_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["trojan_tls_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["selected_outbound"],
        "TROJAN-TLS-UDP-SMOKE"
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["target"],
        "example.com:53"
    );
    assert!(report["trojan_tls_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["request_payload_bytes"],
        21
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["response_payload_bytes"],
        20
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["stop_timed_out"],
        false
    );
    let trojan_tls_udp_cases = report["trojan_tls_udp_relay_smoke"]["cases"]
        .as_array()
        .expect("Trojan TLS UDP relay smoke cases");
    let trojan_tls_udp_case_names: Vec<_> = trojan_tls_udp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-trojan-tls-udp-relay-runtime",
        "trojan-tls-udp-protocol-round-trip",
        "record-trojan-tls-udp-relay-metrics",
        "stop-trojan-tls-udp-relay-runtime",
    ] {
        assert!(
            trojan_tls_udp_case_names.contains(&expected),
            "missing Trojan TLS UDP relay smoke case {expected}: {trojan_tls_udp_case_names:?}"
        );
    }
    let trojan_tls_udp_round_trip = trojan_tls_udp_cases
        .iter()
        .find(|case| case["name"] == "trojan-tls-udp-protocol-round-trip")
        .expect("Trojan TLS UDP relay round trip case");
    assert_eq!(
        trojan_tls_udp_round_trip["observed_response"],
        "keli-trojan-udp-pong"
    );
    assert_eq!(trojan_tls_udp_round_trip["round_trip_observed"], true);
    assert_eq!(trojan_tls_udp_round_trip["server_received_payload"], true);
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
    assert_eq!(report["anytls_tls_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["anytls_tls_udp_relay_smoke"]["passed"], true);
    assert_eq!(report["anytls_tls_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["anytls_tls_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["selected_outbound"],
        "ANYTLS-TLS-UDP-SMOKE"
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(report["anytls_tls_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["request_payload_bytes"],
        21
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["response_payload_bytes"],
        20
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["stop_timed_out"],
        false
    );
    let anytls_tls_udp_cases = report["anytls_tls_udp_relay_smoke"]["cases"]
        .as_array()
        .expect("AnyTLS TLS UDP relay smoke cases");
    let anytls_tls_udp_case_names: Vec<_> = anytls_tls_udp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-anytls-tls-udp-relay-runtime",
        "anytls-tls-udp-uot-round-trip",
        "record-anytls-tls-udp-relay-metrics",
        "stop-anytls-tls-udp-relay-runtime",
    ] {
        assert!(
            anytls_tls_udp_case_names.contains(&expected),
            "missing AnyTLS TLS UDP relay smoke case {expected}: {anytls_tls_udp_case_names:?}"
        );
    }
    let anytls_tls_udp_round_trip = anytls_tls_udp_cases
        .iter()
        .find(|case| case["name"] == "anytls-tls-udp-uot-round-trip")
        .expect("AnyTLS TLS UDP relay round trip case");
    assert_eq!(
        anytls_tls_udp_round_trip["observed_response"],
        "keli-anytls-udp-pong"
    );
    assert_eq!(anytls_tls_udp_round_trip["round_trip_observed"], true);
    assert_eq!(anytls_tls_udp_round_trip["server_received_payload"], true);
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
    assert_eq!(report["naive_h3_quic_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["naive_h3_quic_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["naive_h3_quic_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["selected_outbound"],
        "NAIVE-H3-QUIC-TCP-SMOKE"
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["stop_timed_out"],
        false
    );
    let naive_h3_quic_tcp_cases = report["naive_h3_quic_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("Naive H3 QUIC TCP relay smoke cases");
    let naive_h3_quic_tcp_case_names: Vec<_> = naive_h3_quic_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-naive-h3-quic-tcp-relay-runtime",
        "naive-h3-quic-tcp-protocol-round-trip",
        "record-naive-h3-quic-tcp-relay-metrics",
        "stop-naive-h3-quic-tcp-relay-runtime",
    ] {
        assert!(
            naive_h3_quic_tcp_case_names.contains(&expected),
            "missing Naive H3 QUIC TCP relay smoke case {expected}: {naive_h3_quic_tcp_case_names:?}"
        );
    }
    let naive_h3_quic_tcp_round_trip = naive_h3_quic_tcp_cases
        .iter()
        .find(|case| case["name"] == "naive-h3-quic-tcp-protocol-round-trip")
        .expect("Naive H3 QUIC TCP relay round trip case");
    assert_eq!(
        naive_h3_quic_tcp_round_trip["observed_response"],
        "keli-naive-h3-pong"
    );
    assert_eq!(naive_h3_quic_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(
        naive_h3_quic_tcp_round_trip["server_received_payload"],
        true
    );
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
    assert_eq!(report["vless_ws_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vless_ws_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["vless_ws_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vless_ws_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["selected_outbound"],
        "VLESS-WS-TCP-SMOKE"
    );
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["vless_ws_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["vless_ws_tcp_relay_smoke"]["stop_timed_out"], false);
    let vless_ws_tcp_cases = report["vless_ws_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("VLESS WS TCP relay smoke cases");
    let vless_ws_tcp_case_names: Vec<_> = vless_ws_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vless-ws-tcp-relay-runtime",
        "vless-ws-tcp-protocol-round-trip",
        "record-vless-ws-tcp-relay-metrics",
        "stop-vless-ws-tcp-relay-runtime",
    ] {
        assert!(
            vless_ws_tcp_case_names.contains(&expected),
            "missing VLESS WS TCP relay smoke case {expected}: {vless_ws_tcp_case_names:?}"
        );
    }
    let vless_ws_tcp_round_trip = vless_ws_tcp_cases
        .iter()
        .find(|case| case["name"] == "vless-ws-tcp-protocol-round-trip")
        .expect("VLESS WS TCP relay round trip case");
    assert_eq!(
        vless_ws_tcp_round_trip["observed_response"],
        "keli-vless-ws-pong"
    );
    assert_eq!(vless_ws_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(vless_ws_tcp_round_trip["server_received_payload"], true);
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(report["vless_httpupgrade_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["vless_httpupgrade_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["selected_outbound"],
        "VLESS-HU-TCP-SMOKE"
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["stop_timed_out"],
        false
    );
    let vless_httpupgrade_tcp_cases = report["vless_httpupgrade_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("VLESS HTTPUpgrade TCP relay smoke cases");
    let vless_httpupgrade_tcp_case_names: Vec<_> = vless_httpupgrade_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vless-httpupgrade-tcp-relay-runtime",
        "vless-httpupgrade-tcp-protocol-round-trip",
        "record-vless-httpupgrade-tcp-relay-metrics",
        "stop-vless-httpupgrade-tcp-relay-runtime",
    ] {
        assert!(
            vless_httpupgrade_tcp_case_names.contains(&expected),
            "missing VLESS HTTPUpgrade TCP relay smoke case {expected}: {vless_httpupgrade_tcp_case_names:?}"
        );
    }
    let vless_httpupgrade_tcp_round_trip = vless_httpupgrade_tcp_cases
        .iter()
        .find(|case| case["name"] == "vless-httpupgrade-tcp-protocol-round-trip")
        .expect("VLESS HTTPUpgrade TCP relay round trip case");
    assert_eq!(
        vless_httpupgrade_tcp_round_trip["observed_response"],
        "keli-vless-hu-pong"
    );
    assert_eq!(
        vless_httpupgrade_tcp_round_trip["round_trip_observed"],
        true
    );
    assert_eq!(
        vless_httpupgrade_tcp_round_trip["server_received_payload"],
        true
    );
    assert_eq!(report["vless_grpc_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vless_grpc_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["vless_grpc_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vless_grpc_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["selected_outbound"],
        "VLESS-GRPC-TCP-SMOKE"
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["request_payload_bytes"],
        21
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["response_payload_bytes"],
        20
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["stop_timed_out"],
        false
    );
    let vless_grpc_tcp_cases = report["vless_grpc_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("VLESS gRPC TCP relay smoke cases");
    let vless_grpc_tcp_case_names: Vec<_> = vless_grpc_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vless-grpc-tcp-relay-runtime",
        "vless-grpc-tcp-protocol-round-trip",
        "record-vless-grpc-tcp-relay-metrics",
        "stop-vless-grpc-tcp-relay-runtime",
    ] {
        assert!(
            vless_grpc_tcp_case_names.contains(&expected),
            "missing VLESS gRPC TCP relay smoke case {expected}: {vless_grpc_tcp_case_names:?}"
        );
    }
    let vless_grpc_tcp_round_trip = vless_grpc_tcp_cases
        .iter()
        .find(|case| case["name"] == "vless-grpc-tcp-protocol-round-trip")
        .expect("VLESS gRPC TCP relay round trip case");
    assert_eq!(
        vless_grpc_tcp_round_trip["observed_response"],
        "keli-vless-grpc-pong"
    );
    assert_eq!(vless_grpc_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(vless_grpc_tcp_round_trip["server_received_payload"], true);
    assert_eq!(report["vless_h2_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vless_h2_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["vless_h2_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vless_h2_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["selected_outbound"],
        "VLESS-H2-TCP-SMOKE"
    );
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["vless_h2_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["vless_h2_tcp_relay_smoke"]["stop_timed_out"], false);
    let vless_h2_tcp_cases = report["vless_h2_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("VLESS H2 TCP relay smoke cases");
    let vless_h2_tcp_case_names: Vec<_> = vless_h2_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vless-h2-tcp-relay-runtime",
        "vless-h2-tcp-protocol-round-trip",
        "record-vless-h2-tcp-relay-metrics",
        "stop-vless-h2-tcp-relay-runtime",
    ] {
        assert!(
            vless_h2_tcp_case_names.contains(&expected),
            "missing VLESS H2 TCP relay smoke case {expected}: {vless_h2_tcp_case_names:?}"
        );
    }
    let vless_h2_tcp_round_trip = vless_h2_tcp_cases
        .iter()
        .find(|case| case["name"] == "vless-h2-tcp-protocol-round-trip")
        .expect("VLESS H2 TCP relay round trip case");
    assert_eq!(
        vless_h2_tcp_round_trip["observed_response"],
        "keli-vless-h2-pong"
    );
    assert_eq!(vless_h2_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(vless_h2_tcp_round_trip["server_received_payload"], true);
    assert_vless_h2_udp_relay_smoke_json(&report);
    assert_vless_ws_udp_relay_smoke_json(&report);
    assert_vless_grpc_udp_relay_smoke_json(&report);
    assert_vless_httpupgrade_udp_relay_smoke_json(&report);
    assert_vless_quic_tcp_relay_smoke_json(&report);
    assert_vless_quic_udp_relay_smoke_json(&report);
    assert_eq!(report["vless_tcp_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vless_tcp_udp_relay_smoke"]["passed"], true);
    assert_eq!(report["vless_tcp_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vless_tcp_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["selected_outbound"],
        "VLESS-TCP-UDP-SMOKE"
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(report["vless_tcp_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["vless_tcp_udp_relay_smoke"]["stop_timed_out"], false);
    let vless_tcp_udp_cases = report["vless_tcp_udp_relay_smoke"]["cases"]
        .as_array()
        .expect("VLESS TCP UDP relay smoke cases");
    let vless_tcp_udp_case_names: Vec<_> = vless_tcp_udp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vless-tcp-udp-relay-runtime",
        "vless-tcp-udp-protocol-round-trip",
        "record-vless-tcp-udp-relay-metrics",
        "stop-vless-tcp-udp-relay-runtime",
    ] {
        assert!(
            vless_tcp_udp_case_names.contains(&expected),
            "missing VLESS TCP UDP relay smoke case {expected}: {vless_tcp_udp_case_names:?}"
        );
    }
    let vless_tcp_udp_round_trip = vless_tcp_udp_cases
        .iter()
        .find(|case| case["name"] == "vless-tcp-udp-protocol-round-trip")
        .expect("VLESS TCP UDP relay round trip case");
    assert_eq!(
        vless_tcp_udp_round_trip["observed_response"],
        "keli-vless-udp-pong"
    );
    assert_eq!(vless_tcp_udp_round_trip["round_trip_observed"], true);
    assert_eq!(vless_tcp_udp_round_trip["server_received_payload"], true);
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
    assert_eq!(report["vmess_ws_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vmess_ws_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["vmess_ws_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vmess_ws_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["selected_outbound"],
        "VMESS-WS-TCP-SMOKE"
    );
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["vmess_ws_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["vmess_ws_tcp_relay_smoke"]["stop_timed_out"], false);
    let vmess_ws_tcp_cases = report["vmess_ws_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("VMess WS TCP relay smoke cases");
    let vmess_ws_tcp_case_names: Vec<_> = vmess_ws_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vmess-ws-tcp-relay-runtime",
        "vmess-ws-tcp-protocol-round-trip",
        "record-vmess-ws-tcp-relay-metrics",
        "stop-vmess-ws-tcp-relay-runtime",
    ] {
        assert!(
            vmess_ws_tcp_case_names.contains(&expected),
            "missing VMess WS TCP relay smoke case {expected}: {vmess_ws_tcp_case_names:?}"
        );
    }
    let vmess_ws_tcp_round_trip = vmess_ws_tcp_cases
        .iter()
        .find(|case| case["name"] == "vmess-ws-tcp-protocol-round-trip")
        .expect("VMess WS TCP relay round trip case");
    assert_eq!(
        vmess_ws_tcp_round_trip["observed_response"],
        "keli-vmess-ws-pong"
    );
    assert_eq!(vmess_ws_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(vmess_ws_tcp_round_trip["server_received_payload"], true);
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(report["vmess_httpupgrade_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["vmess_httpupgrade_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["selected_outbound"],
        "VMESS-HU-TCP-SMOKE"
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["stop_timed_out"],
        false
    );
    let vmess_httpupgrade_tcp_cases = report["vmess_httpupgrade_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("VMess HTTPUpgrade TCP relay smoke cases");
    let vmess_httpupgrade_tcp_case_names: Vec<_> = vmess_httpupgrade_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vmess-httpupgrade-tcp-relay-runtime",
        "vmess-httpupgrade-tcp-protocol-round-trip",
        "record-vmess-httpupgrade-tcp-relay-metrics",
        "stop-vmess-httpupgrade-tcp-relay-runtime",
    ] {
        assert!(
            vmess_httpupgrade_tcp_case_names.contains(&expected),
            "missing VMess HTTPUpgrade TCP relay smoke case {expected}: {vmess_httpupgrade_tcp_case_names:?}"
        );
    }
    let vmess_httpupgrade_tcp_round_trip = vmess_httpupgrade_tcp_cases
        .iter()
        .find(|case| case["name"] == "vmess-httpupgrade-tcp-protocol-round-trip")
        .expect("VMess HTTPUpgrade TCP relay round trip case");
    assert_eq!(
        vmess_httpupgrade_tcp_round_trip["observed_response"],
        "keli-vmess-hu-pong"
    );
    assert_eq!(
        vmess_httpupgrade_tcp_round_trip["round_trip_observed"],
        true
    );
    assert_eq!(
        vmess_httpupgrade_tcp_round_trip["server_received_payload"],
        true
    );
    assert_vmess_httpupgrade_udp_relay_smoke_json(&report);
    assert_eq!(report["vmess_grpc_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vmess_grpc_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["vmess_grpc_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vmess_grpc_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["selected_outbound"],
        "VMESS-GRPC-TCP-SMOKE"
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["request_payload_bytes"],
        21
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["response_payload_bytes"],
        20
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["stop_timed_out"],
        false
    );
    let vmess_grpc_tcp_cases = report["vmess_grpc_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("VMess gRPC TCP relay smoke cases");
    let vmess_grpc_tcp_case_names: Vec<_> = vmess_grpc_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vmess-grpc-tcp-relay-runtime",
        "vmess-grpc-tcp-protocol-round-trip",
        "record-vmess-grpc-tcp-relay-metrics",
        "stop-vmess-grpc-tcp-relay-runtime",
    ] {
        assert!(
            vmess_grpc_tcp_case_names.contains(&expected),
            "missing VMess gRPC TCP relay smoke case {expected}: {vmess_grpc_tcp_case_names:?}"
        );
    }
    let vmess_grpc_tcp_round_trip = vmess_grpc_tcp_cases
        .iter()
        .find(|case| case["name"] == "vmess-grpc-tcp-protocol-round-trip")
        .expect("VMess gRPC TCP relay round trip case");
    assert_eq!(
        vmess_grpc_tcp_round_trip["observed_response"],
        "keli-vmess-grpc-pong"
    );
    assert_eq!(vmess_grpc_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(vmess_grpc_tcp_round_trip["server_received_payload"], true);
    assert_vmess_grpc_udp_relay_smoke_json(&report);
    assert_eq!(report["vmess_h2_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vmess_h2_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["vmess_h2_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vmess_h2_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["selected_outbound"],
        "VMESS-H2-TCP-SMOKE"
    );
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["vmess_h2_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["vmess_h2_tcp_relay_smoke"]["stop_timed_out"], false);
    let vmess_h2_tcp_cases = report["vmess_h2_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("VMess H2 TCP relay smoke cases");
    let vmess_h2_tcp_case_names: Vec<_> = vmess_h2_tcp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vmess-h2-tcp-relay-runtime",
        "vmess-h2-tcp-protocol-round-trip",
        "record-vmess-h2-tcp-relay-metrics",
        "stop-vmess-h2-tcp-relay-runtime",
    ] {
        assert!(
            vmess_h2_tcp_case_names.contains(&expected),
            "missing VMess H2 TCP relay smoke case {expected}: {vmess_h2_tcp_case_names:?}"
        );
    }
    let vmess_h2_tcp_round_trip = vmess_h2_tcp_cases
        .iter()
        .find(|case| case["name"] == "vmess-h2-tcp-protocol-round-trip")
        .expect("VMess H2 TCP relay round trip case");
    assert_eq!(
        vmess_h2_tcp_round_trip["observed_response"],
        "keli-vmess-h2-pong"
    );
    assert_eq!(vmess_h2_tcp_round_trip["round_trip_observed"], true);
    assert_eq!(vmess_h2_tcp_round_trip["server_received_payload"], true);
    assert_vmess_h2_udp_relay_smoke_json(&report);
    assert_vmess_quic_tcp_relay_smoke_json(&report);
    assert_vmess_quic_udp_relay_smoke_json(&report);
    assert_eq!(report["vmess_tcp_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vmess_tcp_udp_relay_smoke"]["passed"], true);
    assert_eq!(report["vmess_tcp_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vmess_tcp_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["selected_outbound"],
        "VMESS-TCP-UDP-SMOKE"
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(report["vmess_tcp_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["vmess_tcp_udp_relay_smoke"]["stop_timed_out"], false);
    let vmess_tcp_udp_cases = report["vmess_tcp_udp_relay_smoke"]["cases"]
        .as_array()
        .expect("VMess TCP UDP relay smoke cases");
    let vmess_tcp_udp_case_names: Vec<_> = vmess_tcp_udp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vmess-tcp-udp-relay-runtime",
        "vmess-tcp-udp-protocol-round-trip",
        "record-vmess-tcp-udp-relay-metrics",
        "stop-vmess-tcp-udp-relay-runtime",
    ] {
        assert!(
            vmess_tcp_udp_case_names.contains(&expected),
            "missing VMess TCP UDP relay smoke case {expected}: {vmess_tcp_udp_case_names:?}"
        );
    }
    let vmess_tcp_udp_round_trip = vmess_tcp_udp_cases
        .iter()
        .find(|case| case["name"] == "vmess-tcp-udp-protocol-round-trip")
        .expect("VMess TCP UDP relay round trip case");
    assert_eq!(
        vmess_tcp_udp_round_trip["observed_response"],
        "keli-vmess-udp-pong"
    );
    assert_eq!(vmess_tcp_udp_round_trip["round_trip_observed"], true);
    assert_eq!(vmess_tcp_udp_round_trip["server_received_payload"], true);
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
    assert_eq!(report["mieru_tcp_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["mieru_tcp_udp_relay_smoke"]["passed"], true);
    assert_eq!(report["mieru_tcp_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["mieru_tcp_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["selected_outbound"],
        "MIERU-TCP-UDP-SMOKE"
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(report["mieru_tcp_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["mieru_tcp_udp_relay_smoke"]["stop_timed_out"], false);
    let mieru_tcp_udp_cases = report["mieru_tcp_udp_relay_smoke"]["cases"]
        .as_array()
        .expect("Mieru TCP UDP relay smoke cases");
    let mieru_tcp_udp_case_names: Vec<_> = mieru_tcp_udp_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-mieru-tcp-udp-relay-runtime",
        "mieru-tcp-udp-protocol-round-trip",
        "record-mieru-tcp-udp-relay-metrics",
        "stop-mieru-tcp-udp-relay-runtime",
    ] {
        assert!(
            mieru_tcp_udp_case_names.contains(&expected),
            "missing Mieru TCP UDP relay smoke case {expected}: {mieru_tcp_udp_case_names:?}"
        );
    }
    let mieru_tcp_udp_round_trip = mieru_tcp_udp_cases
        .iter()
        .find(|case| case["name"] == "mieru-tcp-udp-protocol-round-trip")
        .expect("Mieru TCP UDP relay round trip case");
    assert_eq!(
        mieru_tcp_udp_round_trip["observed_response"],
        "keli-mieru-udp-pong"
    );
    assert_eq!(mieru_tcp_udp_round_trip["response_source"], "127.0.0.1:53");
    assert_eq!(mieru_tcp_udp_round_trip["round_trip_observed"], true);
    assert_eq!(mieru_tcp_udp_round_trip["server_received_payload"], true);
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
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(report["socks5_udp_outbound_relay_smoke"]["passed"], true);
    assert_eq!(report["socks5_udp_outbound_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["selected_outbound"],
        "SOCKS5-UDP-OUTBOUND-SMOKE"
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["target"],
        "example.com:53"
    );
    assert!(report["socks5_udp_outbound_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["request_payload_bytes"],
        30
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["response_payload_bytes"],
        29
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["stop_timed_out"],
        false
    );
    let socks5_udp_outbound_cases = report["socks5_udp_outbound_relay_smoke"]["cases"]
        .as_array()
        .expect("SOCKS5 UDP outbound relay smoke cases");
    let socks5_udp_outbound_case_names: Vec<_> = socks5_udp_outbound_cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-socks5-udp-outbound-relay-runtime",
        "socks5-udp-outbound-protocol-round-trip",
        "record-socks5-udp-outbound-relay-metrics",
        "stop-socks5-udp-outbound-relay-runtime",
    ] {
        assert!(
            socks5_udp_outbound_case_names.contains(&expected),
            "missing SOCKS5 UDP outbound relay smoke case {expected}: {socks5_udp_outbound_case_names:?}"
        );
    }
    let socks5_udp_outbound_round_trip = socks5_udp_outbound_cases
        .iter()
        .find(|case| case["name"] == "socks5-udp-outbound-protocol-round-trip")
        .expect("SOCKS5 UDP outbound relay round trip case");
    assert_eq!(
        socks5_udp_outbound_round_trip["observed_response"],
        "keli-socks5-udp-outbound-pong"
    );
    assert_eq!(socks5_udp_outbound_round_trip["round_trip_observed"], true);
    assert_eq!(
        socks5_udp_outbound_round_trip["server_received_payload"],
        true
    );
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
    assert_tun_tcp_session_smoke_json(&report["tun_tcp_session_smoke"]);
    assert_tun_tcp_session_server_retransmit_smoke_json(
        &report["tun_tcp_session_server_retransmit_smoke"],
    );
    assert_tun_tcp_session_server_fin_retransmit_smoke_json(
        &report["tun_tcp_session_server_fin_retransmit_smoke"],
    );
    assert_tun_tcp_session_post_close_guard_smoke_json(
        &report["tun_tcp_session_post_close_guard_smoke"],
    );
    assert_tun_tcp_unknown_session_reset_smoke_json(&report["tun_tcp_unknown_session_reset_smoke"]);
    assert_tun_tcp_session_limit_smoke_json(&report["tun_tcp_session_limit_smoke"]);
    assert_tun_tcp_session_idle_prune_smoke_json(&report["tun_tcp_session_idle_prune_smoke"]);
    assert_tun_tcp_session_close_marker_prune_smoke_json(
        &report["tun_tcp_session_close_marker_prune_smoke"],
    );
    assert_tun_tcp_session_close_marker_rst_clear_smoke_json(
        &report["tun_tcp_session_close_marker_rst_clear_smoke"],
    );
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
        "readiness status=not-ready schema_version={} gates=71",
        READINESS_CHECK_SCHEMA_VERSION
    )));
    assert!(output.contains("blockers="));
    assert!(output.contains("readiness gate=interop-matrix category=protocols status=passed"));
    assert!(output.contains("readiness gate=route-rule-smoke category=routing status=passed"));
    assert!(output.contains("readiness gate=dns-policy-smoke category=dns status=passed"));
    assert!(output.contains("readiness gate=tcp-relay-smoke category=protocols status=passed"));
    assert!(output.contains(
        "readiness gate=socks5-tcp-outbound-relay-smoke category=protocols status=passed"
    ));
    assert!(
        output.contains("readiness gate=http-connect-relay-smoke category=protocols status=passed")
    );
    assert!(output.contains(
        "readiness gate=http-connect-outbound-relay-smoke category=protocols status=passed"
    ));
    assert!(
        output.contains("readiness gate=http-proxy-relay-smoke category=protocols status=passed")
    );
    assert!(output
        .contains("readiness gate=trojan-tls-tcp-relay-smoke category=protocols status=passed"));
    assert!(output
        .contains("readiness gate=trojan-ws-tcp-relay-smoke category=protocols status=passed"));
    assert!(output.contains(
        "readiness gate=trojan-httpupgrade-tcp-relay-smoke category=protocols status=passed"
    ));
    assert!(output
        .contains("readiness gate=trojan-grpc-tcp-relay-smoke category=protocols status=passed"));
    assert!(output
        .contains("readiness gate=trojan-h2-tcp-relay-smoke category=protocols status=passed"));
    assert!(output
        .contains("readiness gate=trojan-quic-tcp-relay-smoke category=protocols status=passed"));
    assert!(output
        .contains("readiness gate=trojan-quic-udp-relay-smoke category=protocols status=passed"));
    assert!(output
        .contains("readiness gate=trojan-tls-udp-relay-smoke category=protocols status=passed"));
    assert!(output
        .contains("readiness gate=anytls-tls-tcp-relay-smoke category=protocols status=passed"));
    assert!(output
        .contains("readiness gate=anytls-tls-udp-relay-smoke category=protocols status=passed"));
    assert!(
        output.contains("readiness gate=naive-h2-tcp-relay-smoke category=protocols status=passed")
    );
    assert!(output
        .contains("readiness gate=naive-h3-quic-tcp-relay-smoke category=protocols status=passed"));
    assert!(
        output.contains("readiness gate=hy2-quic-tcp-relay-smoke category=protocols status=passed")
    );
    assert!(output
        .contains("readiness gate=tuic-quic-tcp-relay-smoke category=protocols status=passed"));
    assert!(
        output.contains("readiness gate=vless-tcp-relay-smoke category=protocols status=passed")
    );
    assert!(
        output.contains("readiness gate=vless-ws-tcp-relay-smoke category=protocols status=passed")
    );
    assert!(
        output.contains("readiness gate=vless-ws-udp-relay-smoke category=protocols status=passed")
    );
    assert!(output.contains(
        "readiness gate=vless-httpupgrade-tcp-relay-smoke category=protocols status=passed"
    ));
    assert!(output.contains(
        "readiness gate=vless-httpupgrade-udp-relay-smoke category=protocols status=passed"
    ));
    assert!(output
        .contains("readiness gate=vless-grpc-tcp-relay-smoke category=protocols status=passed"));
    assert!(output
        .contains("readiness gate=vless-grpc-udp-relay-smoke category=protocols status=passed"));
    assert!(
        output.contains("readiness gate=vless-h2-tcp-relay-smoke category=protocols status=passed")
    );
    assert!(
        output.contains("readiness gate=vless-h2-udp-relay-smoke category=protocols status=passed")
    );
    assert!(output
        .contains("readiness gate=vless-quic-tcp-relay-smoke category=protocols status=passed"));
    assert!(output
        .contains("readiness gate=vless-quic-udp-relay-smoke category=protocols status=passed"));
    assert!(output
        .contains("readiness gate=vless-tcp-udp-relay-smoke category=protocols status=passed"));
    assert!(
        output.contains("readiness gate=vmess-tcp-relay-smoke category=protocols status=passed")
    );
    assert!(
        output.contains("readiness gate=vmess-ws-tcp-relay-smoke category=protocols status=passed")
    );
    assert!(output.contains(
        "readiness gate=vmess-httpupgrade-tcp-relay-smoke category=protocols status=passed"
    ));
    assert!(output.contains(
        "readiness gate=vmess-httpupgrade-udp-relay-smoke category=protocols status=passed"
    ));
    assert!(output
        .contains("readiness gate=vmess-grpc-tcp-relay-smoke category=protocols status=passed"));
    assert!(
        output.contains("readiness gate=vmess-h2-tcp-relay-smoke category=protocols status=passed")
    );
    assert!(
        output.contains("readiness gate=vmess-h2-udp-relay-smoke category=protocols status=passed")
    );
    assert!(output
        .contains("readiness gate=vmess-quic-tcp-relay-smoke category=protocols status=passed"));
    assert!(output
        .contains("readiness gate=vmess-quic-udp-relay-smoke category=protocols status=passed"));
    assert!(output
        .contains("readiness gate=vmess-tcp-udp-relay-smoke category=protocols status=passed"));
    assert!(
        output.contains("readiness gate=mieru-tcp-relay-smoke category=protocols status=passed")
    );
    assert!(output
        .contains("readiness gate=mieru-tcp-udp-relay-smoke category=protocols status=passed"));
    assert!(output.contains("readiness gate=udp-relay-smoke category=protocols status=passed"));
    assert!(output.contains(
        "readiness gate=socks5-udp-outbound-relay-smoke category=protocols status=passed"
    ));
    assert!(output.contains(
        "readiness gate=subscription-reload-smoke category=managed-runtime status=passed"
    ));
    assert!(
        output.contains("readiness gate=runtime-recovery-smoke category=stability status=passed")
    );
    assert!(output.contains("readiness gate=tun-tcp-session-smoke category=platform status=passed"));
    assert!(output.contains(
        "readiness gate=tun-tcp-session-server-retransmit-smoke category=platform status=passed"
    ));
    assert!(output.contains(
        "readiness gate=tun-tcp-session-server-fin-retransmit-smoke category=platform status=passed"
    ));
    assert!(output.contains(
        "readiness gate=tun-tcp-session-post-close-guard-smoke category=platform status=passed"
    ));
    assert!(output.contains(
        "readiness gate=tun-tcp-unknown-session-reset-smoke category=platform status=passed"
    ));
    assert!(output
        .contains("readiness gate=tun-tcp-session-limit-smoke category=platform status=passed"));
    assert!(output.contains(
        "readiness gate=tun-tcp-session-idle-prune-smoke category=platform status=passed"
    ));
    assert!(output.contains(
        "readiness gate=tun-tcp-session-close-marker-prune-smoke category=platform status=passed"
    ));
    assert!(output.contains(
        "readiness gate=tun-tcp-session-close-marker-rst-clear-smoke category=platform status=passed"
    ));
    assert!(output.contains("readiness gate=tun-backend category=platform status="));
    assert!(output.contains("readiness tun_preflight status="));
    assert!(output.contains("readiness route_rule_smoke status=passed cases=3"));
    assert!(output.contains("readiness dns_policy_smoke status=passed cases=4"));
    assert!(output.contains("readiness tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness socks5_tcp_outbound_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness http_connect_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness http_connect_outbound_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness http_proxy_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness trojan_tls_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness trojan_ws_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness trojan_httpupgrade_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness trojan_grpc_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness trojan_h2_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness trojan_quic_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness trojan_quic_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness trojan_tls_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness anytls_tls_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness anytls_tls_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness naive_h2_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness naive_h3_quic_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness hy2_quic_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness tuic_quic_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vless_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vless_ws_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vless_ws_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vless_httpupgrade_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vless_httpupgrade_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vless_grpc_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vless_grpc_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vless_h2_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vless_h2_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vless_quic_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vless_quic_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vless_tcp_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vmess_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vmess_ws_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vmess_ws_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vmess_httpupgrade_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vmess_httpupgrade_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vmess_grpc_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vmess_grpc_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vmess_h2_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vmess_h2_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vmess_quic_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vmess_quic_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness vmess_tcp_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness mieru_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness mieru_tcp_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness socks5_udp_outbound_relay_smoke status=passed cases=4"));
    assert!(output.contains("readiness resource_limit_smoke status=passed cases=5"));
    assert!(output.contains("readiness panel_subscription_smoke status=passed cases=9"));
    assert!(output.contains("readiness subscription_reload_smoke status=passed cases=4"));
    assert!(output.contains("readiness runtime_recovery_smoke status=passed cases=4"));
    assert!(output.contains("readiness tun_tcp_session_smoke status=passed cases=4"));
    assert!(
        output.contains("readiness tun_tcp_session_server_retransmit_smoke status=passed cases=4")
    );
    assert!(output
        .contains("readiness tun_tcp_session_server_fin_retransmit_smoke status=passed cases=3"));
    assert!(
        output.contains("readiness tun_tcp_session_post_close_guard_smoke status=passed cases=4")
    );
    assert!(output.contains("readiness tun_tcp_unknown_session_reset_smoke status=passed cases=3"));
    assert!(output.contains("readiness tun_tcp_session_limit_smoke status=passed cases=4"));
    assert!(output.contains("readiness tun_tcp_session_idle_prune_smoke status=passed cases=4"));
    assert!(
        output.contains("readiness tun_tcp_session_close_marker_prune_smoke status=passed cases=4")
    );
    assert!(output
        .contains("readiness tun_tcp_session_close_marker_rst_clear_smoke status=passed cases=4"));
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
    assert_eq!(
        report["certification"]["machine_takeover_smokes_requested"],
        false
    );
    assert_eq!(report["takeover_coverage"]["status"], "not-run");
    assert_eq!(report["takeover_coverage"]["complete"], false);
    assert_eq!(
        report["takeover_coverage"]["machine_takeover_smokes_requested"],
        false
    );
    assert_eq!(
        report["takeover_coverage"]["system_proxy_smoke_status"],
        "not-run"
    );
    assert_eq!(
        report["takeover_coverage"]["tun_runtime_smoke_status"],
        "not-run"
    );
    assert_eq!(
        report["takeover_coverage"]["missing_evidence"][0],
        "system-proxy-smoke"
    );
    assert_eq!(
        report["takeover_coverage"]["missing_evidence"][1],
        "tun-runtime-smoke"
    );
    assert_eq!(report["takeover_coverage"]["failed_evidence_count"], 0);
    let core_gates_ready = report["ready_for_default_core"]
        .as_bool()
        .expect("ready_for_default_core boolean");
    assert_eq!(
        report["default_core_promotion"]["core_gates_ready"],
        core_gates_ready
    );
    assert_eq!(
        report["default_core_promotion"]["machine_takeover_ready"],
        false
    );
    assert_eq!(
        report["default_core_promotion"]["machine_takeover_smokes_requested"],
        false
    );
    assert_eq!(
        report["default_core_promotion"]["local_core_default_allowed"],
        core_gates_ready
    );
    assert_eq!(
        report["default_core_promotion"]["machine_takeover_default_allowed"],
        false
    );
    assert_eq!(
        report["default_core_promotion"]["takeover_coverage_status"],
        "not-run"
    );
    assert_eq!(
        report["default_core_promotion"]["missing_takeover_evidence"][0],
        "system-proxy-smoke"
    );
    assert_eq!(
        report["default_core_promotion"]["missing_takeover_evidence"][1],
        "tun-runtime-smoke"
    );
    assert_eq!(report["release_gate"]["status"], "not-required");
    assert_eq!(report["release_gate"]["required_scope"], "none");
    assert_eq!(
        report["release_gate"]["require_machine_takeover_ready"],
        false
    );
    assert_eq!(report["release_gate"]["require_stability_window"], false);
    assert!(report["release_gate"]["required_stability_window_ms"].is_null());
    assert_eq!(
        report["release_gate"]["require_stability_connections"],
        false
    );
    assert!(report["release_gate"]["required_stability_connections"].is_null());
    assert_eq!(report["release_gate"]["passed"], true);
    assert_eq!(report["release_gate"]["machine_takeover_ready"], false);
    assert_eq!(
        report["release_gate"]["machine_takeover_smokes_requested"],
        false
    );
    assert_eq!(report["release_gate"]["blocker_count"], 0);
    assert_eq!(
        report["release_gate"]["stability"]["local_soak_min_duration_ms"],
        0
    );
    assert!(report["release_gate"]["stability"]["required_window_ms"].is_null());
    assert_eq!(
        report["release_gate"]["stability"]["required_window_met"],
        true
    );
    assert!(report["release_gate"]["stability"]["required_connections"].is_null());
    assert!(report["release_gate"]["stability"]["required_connections_met"].is_null());
    assert_eq!(
        report["release_gate"]["stability"]["local_soak_connections"],
        2
    );
    assert_eq!(
        report["release_gate"]["stability"]["local_soak_duration_required"],
        false
    );
    assert_eq!(
        report["release_gate"]["stability"]["local_soak_complete"],
        true
    );
    assert!(report["release_gate"]["stability"]["local_soak_required_window_met"].is_null());
    assert_eq!(
        report["release_gate"]["stability"]["local_soak_socks5_status"],
        "passed"
    );
    assert_eq!(
        report["release_gate"]["stability"]["local_soak_http_connect_status"],
        "passed"
    );
    assert_eq!(
        report["release_gate"]["stability"]["tun_runtime_smoke_min_duration_ms"],
        50
    );
    assert!(report["release_gate"]["stability"]["tun_runtime_duration_target_met"].is_null());
    assert!(report["release_gate"]["stability"]["tun_runtime_required_window_met"].is_null());
    let promotion_next_actions = report["default_core_promotion"]["next_actions"]
        .as_array()
        .expect("promotion next actions");
    assert!(promotion_next_actions
        .iter()
        .any(|action| action.as_str() == Some("run-with-include-system-proxy-smoke")));
    assert!(promotion_next_actions
        .iter()
        .any(|action| action.as_str() == Some("run-with-include-tun-runtime-smoke")));
    if core_gates_ready {
        assert_eq!(report["default_core_promotion"]["status"], "core-ready");
        assert_eq!(
            report["default_core_promotion"]["safe_default_scope"],
            "local-core-only"
        );
        assert_eq!(report["default_core_promotion"]["next_action_count"], 2);
        assert_eq!(report["default_core_promotion"]["blocker_count"], 0);
    } else {
        assert_eq!(report["default_core_promotion"]["status"], "blocked");
        assert_eq!(
            report["default_core_promotion"]["safe_default_scope"],
            "none"
        );
        assert_eq!(
            report["default_core_promotion"]["next_actions"][0],
            "fix-readiness-blockers"
        );
        assert_eq!(
            report["default_core_promotion"]["blockers"][0],
            "readiness-gates"
        );
        assert_eq!(report["default_core_promotion"]["next_action_count"], 3);
        assert_eq!(report["default_core_promotion"]["blocker_count"], 1);
    }
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
        report["certification"]["socks5_tcp_outbound_relay_smoke_passed"],
        true
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(report["socks5_tcp_outbound_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["selected_outbound"],
        "SOCKS5-TCP-OUTBOUND-SMOKE"
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["socks5_tcp_outbound_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["socks5_tcp_outbound_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["socks5_tcp_outbound_relay_smoke"]["case_count"],
        4
    );
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
        report["certification"]["http_connect_outbound_relay_smoke_passed"],
        true
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(report["http_connect_outbound_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["selected_outbound"],
        "HTTP-CONNECT-OUTBOUND-SMOKE"
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["http_connect_outbound_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["http_connect_outbound_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["http_connect_outbound_relay_smoke"]["case_count"],
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
        report["certification"]["trojan_ws_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["trojan_ws_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["trojan_ws_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["trojan_ws_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-WS-TCP-SMOKE"
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["trojan_ws_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["trojan_ws_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["trojan_ws_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["trojan_httpupgrade_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-HU-TCP-SMOKE"
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["trojan_httpupgrade_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["trojan_httpupgrade_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["trojan_httpupgrade_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["trojan_grpc_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["trojan_grpc_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["trojan_grpc_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-GRPC-TCP-SMOKE"
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["request_payload_bytes"],
        22
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["response_payload_bytes"],
        21
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["trojan_grpc_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["trojan_grpc_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["trojan_grpc_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["trojan_h2_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["trojan_h2_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["trojan_h2_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["trojan_h2_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-H2-TCP-SMOKE"
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["trojan_h2_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["trojan_h2_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["trojan_h2_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["trojan_quic_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["trojan_quic_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["trojan_quic_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["selected_outbound"],
        "TROJAN-QUIC-TCP-SMOKE"
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["request_payload_bytes"],
        22
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["response_payload_bytes"],
        21
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["trojan_quic_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["trojan_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["trojan_quic_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["trojan_quic_udp_relay_smoke_passed"],
        true
    );
    assert_trojan_quic_udp_relay_smoke_json(&report);
    assert_eq!(
        report["readiness"]["trojan_quic_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["trojan_quic_udp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["trojan_tls_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["trojan_tls_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["trojan_tls_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["trojan_tls_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["selected_outbound"],
        "TROJAN-TLS-UDP-SMOKE"
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["target"],
        "example.com:53"
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["request_payload_bytes"],
        21
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["response_payload_bytes"],
        20
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["trojan_tls_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["trojan_tls_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["trojan_tls_udp_relay_smoke"]["case_count"],
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
        report["certification"]["anytls_tls_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["anytls_tls_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["anytls_tls_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["anytls_tls_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["selected_outbound"],
        "ANYTLS-TLS-UDP-SMOKE"
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["request_payload_bytes"],
        21
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["response_payload_bytes"],
        20
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["anytls_tls_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["anytls_tls_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["anytls_tls_udp_relay_smoke"]["case_count"],
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
        report["certification"]["naive_h3_quic_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["naive_h3_quic_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["naive_h3_quic_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["selected_outbound"],
        "NAIVE-H3-QUIC-TCP-SMOKE"
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["naive_h3_quic_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["naive_h3_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["naive_h3_quic_tcp_relay_smoke"]["case_count"],
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
        report["certification"]["vless_ws_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["vless_ws_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vless_ws_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vless_ws_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["selected_outbound"],
        "VLESS-WS-TCP-SMOKE"
    );
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["vless_ws_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["vless_ws_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["vless_ws_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vless_ws_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["vless_httpupgrade_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(report["vless_httpupgrade_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["selected_outbound"],
        "VLESS-HU-TCP-SMOKE"
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vless_httpupgrade_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["vless_httpupgrade_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vless_httpupgrade_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["vless_httpupgrade_udp_relay_smoke_passed"],
        true
    );
    assert_vless_httpupgrade_udp_relay_smoke_json(&report);
    assert_eq!(
        report["readiness"]["vless_httpupgrade_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vless_httpupgrade_udp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["vless_grpc_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["vless_grpc_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vless_grpc_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vless_grpc_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["selected_outbound"],
        "VLESS-GRPC-TCP-SMOKE"
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["request_payload_bytes"],
        21
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["response_payload_bytes"],
        20
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vless_grpc_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["vless_grpc_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vless_grpc_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["vless_h2_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["vless_h2_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vless_h2_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vless_h2_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["selected_outbound"],
        "VLESS-H2-TCP-SMOKE"
    );
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["vless_h2_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vless_h2_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["readiness"]["vless_h2_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vless_h2_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_vless_h2_udp_relay_smoke_json(&report);
    assert_eq!(
        report["certification"]["vless_quic_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        report["certification"]["vless_ws_udp_relay_smoke_passed"],
        true
    );
    assert_vless_ws_udp_relay_smoke_json(&report);
    assert_vless_grpc_udp_relay_smoke_json(&report);
    assert_eq!(
        report["readiness"]["vless_ws_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vless_ws_udp_relay_smoke"]["case_count"],
        4
    );
    assert_vless_quic_tcp_relay_smoke_json(&report);
    assert_eq!(
        report["certification"]["vless_quic_udp_relay_smoke_passed"],
        true
    );
    assert_vless_quic_udp_relay_smoke_json(&report);
    assert_eq!(
        report["readiness"]["vless_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vless_quic_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["readiness"]["vless_quic_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vless_quic_udp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["vless_tcp_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["vless_tcp_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vless_tcp_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vless_tcp_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["selected_outbound"],
        "VLESS-TCP-UDP-SMOKE"
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vless_tcp_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["vless_tcp_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vless_tcp_udp_relay_smoke"]["case_count"],
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
        report["certification"]["vmess_ws_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["vmess_ws_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vmess_ws_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vmess_ws_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["selected_outbound"],
        "VMESS-WS-TCP-SMOKE"
    );
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["vmess_ws_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["vmess_ws_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["vmess_ws_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vmess_ws_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["vmess_ws_udp_relay_smoke_passed"],
        true
    );
    assert_vmess_ws_udp_relay_smoke_json(&report);
    assert_eq!(
        report["readiness"]["vmess_ws_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vmess_ws_udp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["vmess_httpupgrade_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(report["vmess_httpupgrade_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["selected_outbound"],
        "VMESS-HU-TCP-SMOKE"
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vmess_httpupgrade_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["vmess_httpupgrade_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vmess_httpupgrade_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["vmess_httpupgrade_udp_relay_smoke_passed"],
        true
    );
    assert_vmess_httpupgrade_udp_relay_smoke_json(&report);
    assert_eq!(
        report["readiness"]["vmess_httpupgrade_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vmess_httpupgrade_udp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["vmess_grpc_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["vmess_grpc_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vmess_grpc_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vmess_grpc_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["selected_outbound"],
        "VMESS-GRPC-TCP-SMOKE"
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["request_payload_bytes"],
        21
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["response_payload_bytes"],
        20
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vmess_grpc_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["vmess_grpc_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vmess_grpc_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_vmess_grpc_udp_relay_smoke_json(&report);
    assert_eq!(
        report["certification"]["vmess_h2_tcp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["vmess_h2_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vmess_h2_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vmess_h2_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["selected_outbound"],
        "VMESS-H2-TCP-SMOKE"
    );
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["request_payload_bytes"],
        19
    );
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["response_payload_bytes"],
        18
    );
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["vmess_h2_tcp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vmess_h2_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["readiness"]["vmess_h2_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vmess_h2_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["vmess_quic_tcp_relay_smoke_passed"],
        true
    );
    assert_vmess_h2_udp_relay_smoke_json(&report);
    assert_vmess_quic_tcp_relay_smoke_json(&report);
    assert_eq!(
        report["readiness"]["vmess_quic_tcp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vmess_quic_tcp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["vmess_quic_udp_relay_smoke_passed"],
        true
    );
    assert_vmess_quic_udp_relay_smoke_json(&report);
    assert_eq!(
        report["readiness"]["vmess_quic_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vmess_quic_udp_relay_smoke"]["case_count"],
        4
    );
    assert_eq!(
        report["certification"]["vmess_tcp_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["vmess_tcp_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vmess_tcp_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vmess_tcp_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["selected_outbound"],
        "VMESS-TCP-UDP-SMOKE"
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vmess_tcp_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["vmess_tcp_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["vmess_tcp_udp_relay_smoke"]["case_count"],
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
    assert_eq!(
        report["certification"]["mieru_tcp_udp_relay_smoke_passed"],
        true
    );
    assert_eq!(report["mieru_tcp_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["mieru_tcp_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["mieru_tcp_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["selected_outbound"],
        "MIERU-TCP-UDP-SMOKE"
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["request_payload_bytes"],
        20
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["response_payload_bytes"],
        19
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["mieru_tcp_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["mieru_tcp_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["mieru_tcp_udp_relay_smoke"]["case_count"],
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
    assert_eq!(
        report["certification"]["socks5_udp_outbound_relay_smoke_passed"],
        true
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(report["socks5_udp_outbound_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["selected_outbound"],
        "SOCKS5-UDP-OUTBOUND-SMOKE"
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["target"],
        "example.com:53"
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["socks5_udp_outbound_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["readiness"]["socks5_udp_outbound_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(
        report["readiness"]["socks5_udp_outbound_relay_smoke"]["case_count"],
        4
    );
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
        report["certification"]["tun_tcp_session_smoke_passed"],
        true
    );
    assert_eq!(
        report["certification"]["tun_tcp_session_server_retransmit_smoke_passed"],
        true
    );
    assert_eq!(
        report["certification"]["tun_tcp_session_server_fin_retransmit_smoke_passed"],
        true
    );
    assert_eq!(
        report["certification"]["tun_tcp_session_post_close_guard_smoke_passed"],
        true
    );
    assert_eq!(
        report["certification"]["tun_tcp_unknown_session_reset_smoke_passed"],
        true
    );
    assert_eq!(
        report["certification"]["tun_tcp_session_limit_smoke_passed"],
        true
    );
    assert_eq!(
        report["certification"]["tun_tcp_session_idle_prune_smoke_passed"],
        true
    );
    assert_eq!(
        report["certification"]["tun_tcp_session_close_marker_prune_smoke_passed"],
        true
    );
    assert_eq!(
        report["certification"]["tun_tcp_session_close_marker_rst_clear_smoke_passed"],
        true
    );
    assert_tun_tcp_session_smoke_json(&report["tun_tcp_session_smoke"]);
    assert_tun_tcp_session_smoke_json(&report["readiness"]["tun_tcp_session_smoke"]);
    assert_tun_tcp_session_server_retransmit_smoke_json(
        &report["tun_tcp_session_server_retransmit_smoke"],
    );
    assert_tun_tcp_session_server_retransmit_smoke_json(
        &report["readiness"]["tun_tcp_session_server_retransmit_smoke"],
    );
    assert_tun_tcp_session_server_fin_retransmit_smoke_json(
        &report["tun_tcp_session_server_fin_retransmit_smoke"],
    );
    assert_tun_tcp_session_server_fin_retransmit_smoke_json(
        &report["readiness"]["tun_tcp_session_server_fin_retransmit_smoke"],
    );
    assert_tun_tcp_session_post_close_guard_smoke_json(
        &report["tun_tcp_session_post_close_guard_smoke"],
    );
    assert_tun_tcp_session_post_close_guard_smoke_json(
        &report["readiness"]["tun_tcp_session_post_close_guard_smoke"],
    );
    assert_tun_tcp_unknown_session_reset_smoke_json(&report["tun_tcp_unknown_session_reset_smoke"]);
    assert_tun_tcp_unknown_session_reset_smoke_json(
        &report["readiness"]["tun_tcp_unknown_session_reset_smoke"],
    );
    assert_tun_tcp_session_limit_smoke_json(&report["tun_tcp_session_limit_smoke"]);
    assert_tun_tcp_session_limit_smoke_json(&report["readiness"]["tun_tcp_session_limit_smoke"]);
    assert_tun_tcp_session_idle_prune_smoke_json(&report["tun_tcp_session_idle_prune_smoke"]);
    assert_tun_tcp_session_idle_prune_smoke_json(
        &report["readiness"]["tun_tcp_session_idle_prune_smoke"],
    );
    assert_tun_tcp_session_close_marker_prune_smoke_json(
        &report["tun_tcp_session_close_marker_prune_smoke"],
    );
    assert_tun_tcp_session_close_marker_prune_smoke_json(
        &report["readiness"]["tun_tcp_session_close_marker_prune_smoke"],
    );
    assert_tun_tcp_session_close_marker_rst_clear_smoke_json(
        &report["tun_tcp_session_close_marker_rst_clear_smoke"],
    );
    assert_tun_tcp_session_close_marker_rst_clear_smoke_json(
        &report["readiness"]["tun_tcp_session_close_marker_rst_clear_smoke"],
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
    assert_eq!(
        gate(gates, "socks5-tcp-outbound-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(gate(gates, "http-connect-relay-smoke")["status"], "passed");
    assert_eq!(
        gate(gates, "http-connect-outbound-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(gate(gates, "http-proxy-relay-smoke")["status"], "passed");
    assert_eq!(
        gate(gates, "trojan-tls-tcp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(gate(gates, "trojan-ws-tcp-relay-smoke")["status"], "passed");
    assert_eq!(
        gate(gates, "trojan-httpupgrade-tcp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "trojan-grpc-tcp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(gate(gates, "trojan-h2-tcp-relay-smoke")["status"], "passed");
    assert_eq!(
        gate(gates, "trojan-quic-tcp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "trojan-quic-udp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "trojan-tls-udp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "anytls-tls-tcp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "anytls-tls-udp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(gate(gates, "naive-h2-tcp-relay-smoke")["status"], "passed");
    assert_eq!(
        gate(gates, "naive-h3-quic-tcp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(gate(gates, "hy2-quic-tcp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "tuic-quic-tcp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "vless-tcp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "vless-ws-tcp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "vless-ws-udp-relay-smoke")["status"], "passed");
    assert_eq!(
        gate(gates, "vless-httpupgrade-tcp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "vless-httpupgrade-udp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "vless-grpc-tcp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "vless-grpc-udp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(gate(gates, "vless-h2-tcp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "vless-h2-udp-relay-smoke")["status"], "passed");
    assert_eq!(
        gate(gates, "vless-quic-tcp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "vless-quic-udp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(gate(gates, "vless-tcp-udp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "vmess-tcp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "vmess-ws-tcp-relay-smoke")["status"], "passed");
    assert_eq!(
        gate(gates, "vmess-httpupgrade-tcp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "vmess-httpupgrade-udp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "vmess-grpc-tcp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "vmess-grpc-udp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(gate(gates, "vmess-h2-tcp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "vmess-h2-udp-relay-smoke")["status"], "passed");
    assert_eq!(
        gate(gates, "vmess-quic-tcp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "vmess-quic-udp-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(gate(gates, "vmess-tcp-udp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "mieru-tcp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "mieru-tcp-udp-relay-smoke")["status"], "passed");
    assert_eq!(gate(gates, "udp-relay-smoke")["status"], "passed");
    assert_eq!(
        gate(gates, "socks5-udp-outbound-relay-smoke")["status"],
        "passed"
    );
    assert_eq!(gate(gates, "resource-limits")["status"], "passed");
    assert_eq!(gate(gates, "panel-subscription-state")["status"], "passed");
    assert_eq!(gate(gates, "subscription-reload-smoke")["status"], "passed");
    assert_eq!(gate(gates, "runtime-recovery-smoke")["status"], "passed");
    assert_eq!(gate(gates, "tun-tcp-session-smoke")["status"], "passed");
    assert_eq!(
        gate(gates, "tun-tcp-session-server-retransmit-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "tun-tcp-session-server-fin-retransmit-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "tun-tcp-session-post-close-guard-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "tun-tcp-unknown-session-reset-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "tun-tcp-session-limit-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "tun-tcp-session-idle-prune-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "tun-tcp-session-close-marker-prune-smoke")["status"],
        "passed"
    );
    assert_eq!(
        gate(gates, "tun-tcp-session-close-marker-rst-clear-smoke")["status"],
        "passed"
    );
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
    assert!(output.contains("default_core_certification takeover_coverage status=not-run complete=false machine_takeover_smokes_requested=false system_proxy_included=false system_proxy_status=not-run tun_runtime_included=false tun_runtime_status=not-run missing=system-proxy-smoke,tun-runtime-smoke failed=-"));
    assert!(output.contains("default_core_certification promotion status="));
    assert!(output.contains("safe_default_scope="));
    assert!(output.contains("machine_takeover_ready=false"));
    assert!(output.contains("machine_takeover_default_allowed=false"));
    assert!(output.contains("run-with-include-system-proxy-smoke"));
    assert!(output.contains("run-with-include-tun-runtime-smoke"));
    assert!(output.contains("default_core_certification release_gate status=not-required"));
    assert!(output.contains("required_scope=none"));
    assert!(output.contains("require_machine_takeover_ready=false"));
    assert!(output.contains("rerun_args=-"));
    assert!(output.contains("default_core_certification tun_preflight status="));
    assert!(output.contains("default_core_certification route_rule_smoke status=passed cases=3"));
    assert!(output.contains("default_core_certification dns_policy_smoke status=passed cases=4"));
    assert!(output.contains("default_core_certification tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains(
        "default_core_certification socks5_tcp_outbound_relay_smoke status=passed cases=4"
    ));
    assert!(output
        .contains("default_core_certification http_connect_relay_smoke status=passed cases=4"));
    assert!(output.contains(
        "default_core_certification http_connect_outbound_relay_smoke status=passed cases=4"
    ));
    assert!(
        output.contains("default_core_certification http_proxy_relay_smoke status=passed cases=4")
    );
    assert!(output
        .contains("default_core_certification trojan_tls_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification trojan_ws_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains(
        "default_core_certification trojan_httpupgrade_tcp_relay_smoke status=passed cases=4"
    ));
    assert!(output
        .contains("default_core_certification trojan_grpc_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification trojan_h2_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification trojan_quic_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification trojan_quic_udp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification trojan_tls_udp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification anytls_tls_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification anytls_tls_udp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification naive_h2_tcp_relay_smoke status=passed cases=4"));
    assert!(output.contains(
        "default_core_certification naive_h3_quic_tcp_relay_smoke status=passed cases=4"
    ));
    assert!(output
        .contains("default_core_certification hy2_quic_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification tuic_quic_tcp_relay_smoke status=passed cases=4"));
    assert!(
        output.contains("default_core_certification vless_tcp_relay_smoke status=passed cases=4")
    );
    assert!(output
        .contains("default_core_certification vless_ws_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification vless_ws_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains(
        "default_core_certification vless_httpupgrade_tcp_relay_smoke status=passed cases=4"
    ));
    assert!(output.contains(
        "default_core_certification vless_httpupgrade_udp_relay_smoke status=passed cases=4"
    ));
    assert!(output
        .contains("default_core_certification vless_grpc_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification vless_grpc_udp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification vless_h2_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification vless_h2_udp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification vless_quic_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification vless_quic_udp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification vless_tcp_udp_relay_smoke status=passed cases=4"));
    assert!(
        output.contains("default_core_certification vmess_tcp_relay_smoke status=passed cases=4")
    );
    assert!(output
        .contains("default_core_certification vmess_ws_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification vmess_ws_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains(
        "default_core_certification vmess_httpupgrade_tcp_relay_smoke status=passed cases=4"
    ));
    assert!(output.contains(
        "default_core_certification vmess_httpupgrade_udp_relay_smoke status=passed cases=4"
    ));
    assert!(output
        .contains("default_core_certification vmess_grpc_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification vmess_grpc_udp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification vmess_h2_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification vmess_h2_udp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification vmess_quic_tcp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification vmess_quic_udp_relay_smoke status=passed cases=4"));
    assert!(output
        .contains("default_core_certification vmess_tcp_udp_relay_smoke status=passed cases=4"));
    assert!(
        output.contains("default_core_certification mieru_tcp_relay_smoke status=passed cases=4")
    );
    assert!(output
        .contains("default_core_certification mieru_tcp_udp_relay_smoke status=passed cases=4"));
    assert!(output.contains("default_core_certification udp_relay_smoke status=passed cases=4"));
    assert!(output.contains(
        "default_core_certification socks5_udp_outbound_relay_smoke status=passed cases=4"
    ));
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
    assert!(
        output.contains("default_core_certification tun_tcp_session_smoke status=passed cases=4")
    );
    assert!(output.contains(
        "default_core_certification tun_tcp_session_server_retransmit_smoke status=passed cases=4"
    ));
    assert!(output.contains(
        "default_core_certification tun_tcp_session_server_fin_retransmit_smoke status=passed cases=3"
    ));
    assert!(output.contains(
        "default_core_certification tun_tcp_session_post_close_guard_smoke status=passed cases=4"
    ));
    assert!(output.contains(
        "default_core_certification tun_tcp_unknown_session_reset_smoke status=passed cases=3"
    ));
    assert!(output
        .contains("default_core_certification tun_tcp_session_limit_smoke status=passed cases=4"));
    assert!(output.contains(
        "default_core_certification tun_tcp_session_idle_prune_smoke status=passed cases=4"
    ));
    assert!(output.contains(
        "default_core_certification tun_tcp_session_close_marker_prune_smoke status=passed cases=4"
    ));
    assert!(output.contains(
        "default_core_certification tun_tcp_session_close_marker_rst_clear_smoke status=passed cases=4"
    ));
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
fn default_core_certification_machine_takeover_release_gate_fails_without_takeover_evidence() {
    let mut output = Vec::new();

    let error = write_default_core_certification_report_with_release_gate_options(
        ProbeOutputFormat::Json,
        1,
        Duration::from_secs(2),
        1,
        Duration::from_millis(0),
        false,
        false,
        Duration::from_millis(50),
        true,
        &mut output,
    )
    .expect_err("release gate should fail without machine takeover evidence");

    assert!(error.contains("machine-takeover release gate failed"));
    assert!(error.contains("machine-takeover-smokes-not-requested"));
    assert!(error.contains("next_actions="));
    assert!(error.contains("run-with-include-system-proxy-smoke"));
    assert!(error.contains("run-with-include-tun-runtime-smoke"));
    assert!(error.contains("rerun_args="));
    assert!(error.contains("--include-system-proxy-smoke"));
    assert!(error.contains("--include-tun-runtime-smoke"));
    assert!(error.contains(
        "rerun_command=keli-cli default-core-certify --include-system-proxy-smoke --include-tun-runtime-smoke"
    ));

    let report: Value = serde_json::from_slice(&output).expect("certification JSON");
    assert_eq!(report["release_gate"]["status"], "failed");
    assert_eq!(report["release_gate"]["required_scope"], "machine-takeover");
    assert_eq!(
        report["release_gate"]["require_machine_takeover_ready"],
        true
    );
    assert_eq!(report["release_gate"]["require_stability_window"], false);
    assert!(report["release_gate"]["required_stability_window_ms"].is_null());
    assert_eq!(
        report["release_gate"]["require_stability_connections"],
        false
    );
    assert!(report["release_gate"]["required_stability_connections"].is_null());
    assert_eq!(report["release_gate"]["passed"], false);
    assert_eq!(report["release_gate"]["machine_takeover_ready"], false);
    assert_eq!(
        report["release_gate"]["machine_takeover_smokes_requested"],
        false
    );
    assert_eq!(
        report["release_gate"]["takeover_coverage_status"],
        "not-run"
    );
    assert_eq!(
        report["release_gate"]["missing_takeover_evidence"][0],
        "system-proxy-smoke"
    );
    assert_eq!(
        report["release_gate"]["missing_takeover_evidence"][1],
        "tun-runtime-smoke"
    );
    assert_eq!(report["release_gate"]["takeover"]["required"], true);
    assert_eq!(report["release_gate"]["takeover"]["ready"], false);
    assert_eq!(
        report["release_gate"]["takeover"]["coverage_status"],
        "not-run"
    );
    assert_eq!(
        report["release_gate"]["takeover"]["machine_takeover_smokes_requested"],
        false
    );
    assert_eq!(
        report["release_gate"]["takeover"]["system_proxy_smoke_included"],
        false
    );
    assert_eq!(
        report["release_gate"]["takeover"]["system_proxy_smoke_status"],
        "not-run"
    );
    assert!(report["release_gate"]["takeover"]["system_proxy_smoke_passed"].is_null());
    assert_eq!(
        report["release_gate"]["takeover"]["tun_runtime_smoke_included"],
        false
    );
    assert_eq!(
        report["release_gate"]["takeover"]["tun_runtime_smoke_status"],
        "not-run"
    );
    assert_eq!(
        report["release_gate"]["takeover"]["tun_runtime_smoke_min_duration_ms"],
        50
    );
    assert!(report["release_gate"]["takeover"]["tun_runtime_smoke_passed"].is_null());
    assert_eq!(
        report["release_gate"]["takeover"]["missing_evidence_count"],
        2
    );
    assert_eq!(
        report["release_gate"]["takeover"]["missing_evidence"][0],
        "system-proxy-smoke"
    );
    assert_eq!(
        report["release_gate"]["takeover"]["missing_evidence"][1],
        "tun-runtime-smoke"
    );
    assert_eq!(
        report["release_gate"]["takeover"]["failed_evidence_count"],
        0
    );
    let blockers = report["release_gate"]["blockers"]
        .as_array()
        .expect("release gate blockers");
    assert!(blockers
        .iter()
        .any(|blocker| blocker.as_str() == Some("machine-takeover-smokes-not-requested")));
    assert_eq!(
        report["release_gate"]["blocker_count"].as_u64(),
        Some(blockers.len() as u64)
    );
    let next_actions = report["release_gate"]["next_actions"]
        .as_array()
        .expect("release gate next actions");
    assert!(next_actions
        .iter()
        .any(|action| action.as_str() == Some("run-with-include-system-proxy-smoke")));
    assert!(next_actions
        .iter()
        .any(|action| action.as_str() == Some("run-with-include-tun-runtime-smoke")));
    assert_eq!(
        report["release_gate"]["next_action_count"].as_u64(),
        Some(next_actions.len() as u64)
    );
    let rerun_args = report["release_gate"]["rerun_args"]
        .as_array()
        .expect("release gate rerun args");
    assert!(rerun_args
        .iter()
        .any(|arg| arg.as_str() == Some("--include-system-proxy-smoke")));
    assert!(rerun_args
        .iter()
        .any(|arg| arg.as_str() == Some("--include-tun-runtime-smoke")));
    assert_eq!(
        report["release_gate"]["rerun_arg_count"].as_u64(),
        Some(rerun_args.len() as u64)
    );
    assert_eq!(
        report["release_gate"]["rerun_command"],
        "keli-cli default-core-certify --include-system-proxy-smoke --include-tun-runtime-smoke"
    );
}

#[test]
fn default_core_certification_stability_gate_fails_when_soak_window_is_too_short() {
    let mut output = Vec::new();

    let error = write_default_core_certification_report_with_release_gate_and_stability_options(
        ProbeOutputFormat::Json,
        1,
        Duration::from_secs(2),
        1,
        Duration::from_millis(0),
        false,
        false,
        Duration::from_millis(50),
        false,
        Some(Duration::from_millis(50)),
        &mut output,
    )
    .expect_err("stability gate should fail when local soak window is too short");

    assert!(error.contains("stability release gate failed"));
    assert!(error.contains("local-soak-stability-window-too-short"));

    let report: Value = serde_json::from_slice(&output).expect("certification JSON");
    assert_eq!(report["release_gate"]["status"], "failed");
    assert_eq!(report["release_gate"]["required_scope"], "stability");
    assert_eq!(report["release_gate"]["require_stability_window"], true);
    assert_eq!(report["release_gate"]["required_stability_window_ms"], 50);
    assert_eq!(
        report["release_gate"]["require_stability_connections"],
        false
    );
    assert!(report["release_gate"]["required_stability_connections"].is_null());
    assert_eq!(report["release_gate"]["passed"], false);
    assert_eq!(
        report["release_gate"]["stability"]["required_window_ms"],
        50
    );
    assert_eq!(
        report["release_gate"]["stability"]["required_window_met"],
        false
    );
    assert_eq!(
        report["release_gate"]["stability"]["local_soak_min_duration_ms"],
        0
    );
    assert_eq!(
        report["release_gate"]["stability"]["local_soak_required_window_met"],
        false
    );
    assert!(report["release_gate"]["stability"]["tun_runtime_required_window_met"].is_null());
    assert_eq!(
        report["release_gate"]["blockers"][0],
        "local-soak-stability-window-too-short"
    );
    let next_actions = report["release_gate"]["next_actions"]
        .as_array()
        .expect("release gate next actions");
    assert!(next_actions
        .iter()
        .any(|action| action.as_str() == Some("run-with-default-release-stability-window")));
    assert!(next_actions
        .iter()
        .any(|action| action.as_str() == Some("fix-local-soak-stability-window")));
    assert_eq!(
        report["release_gate"]["next_action_count"].as_u64(),
        Some(next_actions.len() as u64)
    );
}

#[test]
fn default_core_certification_stability_gate_fails_when_soak_connections_are_too_low() {
    let mut output = Vec::new();

    let error =
        write_default_core_certification_report_with_release_gate_and_stability_requirements(
            ProbeOutputFormat::Json,
            1,
            Duration::from_secs(2),
            1,
            Duration::from_millis(0),
            false,
            false,
            Duration::from_millis(50),
            false,
            None,
            Some(2),
            &mut output,
        )
        .expect_err("stability gate should fail when local soak connections are too low");

    assert!(error.contains("stability release gate failed"));
    assert!(error.contains("local-soak-stability-connections-too-low"));

    let report: Value = serde_json::from_slice(&output).expect("certification JSON");
    assert_eq!(report["release_gate"]["status"], "failed");
    assert_eq!(report["release_gate"]["required_scope"], "stability");
    assert_eq!(report["release_gate"]["require_stability_window"], false);
    assert!(report["release_gate"]["required_stability_window_ms"].is_null());
    assert_eq!(
        report["release_gate"]["require_stability_connections"],
        true
    );
    assert_eq!(report["release_gate"]["required_stability_connections"], 2);
    assert_eq!(report["release_gate"]["passed"], false);
    assert_eq!(
        report["release_gate"]["stability"]["local_soak_connections"],
        1
    );
    assert_eq!(
        report["release_gate"]["stability"]["required_connections"],
        2
    );
    assert_eq!(
        report["release_gate"]["stability"]["required_connections_met"],
        false
    );
    assert_eq!(
        report["release_gate"]["stability"]["summary"]["evidence_required"],
        true
    );
    assert_eq!(
        report["release_gate"]["stability"]["summary"]["evidence_ready"],
        false
    );
    assert!(report["release_gate"]["stability"]["summary"]["required_window_ms"].is_null());
    assert_eq!(
        report["release_gate"]["stability"]["summary"]["required_connections"],
        2
    );
    assert_eq!(
        report["release_gate"]["stability"]["summary"]["observed_local_soak_connections"],
        1
    );
    assert_eq!(
        report["release_gate"]["stability"]["summary"]["local_soak_connections_met"],
        false
    );
    assert_eq!(
        report["release_gate"]["blockers"][0],
        "local-soak-stability-connections-too-low"
    );
}

#[test]
fn default_core_certification_records_release_gate_preset_evidence() {
    let mut output = Vec::new();

    let error = write_default_core_certification_report_with_release_gate_preset_and_stability_requirements(
        ProbeOutputFormat::Json,
        2,
        Duration::from_secs(2),
        2,
        Duration::from_millis(0),
        false,
        false,
        Duration::from_millis(50),
        false,
        Some(Duration::from_millis(0)),
        Some(2),
        Some("default-core-release-gate"),
        &mut output,
    )
    .expect_err("preset evidence should fail when preset minimums are not met");
    assert!(error.contains("preset-machine-takeover-not-required"));
    assert!(error.contains("preset-stability-window-below-default"));
    assert!(error.contains("preset-stability-connections-below-default"));

    let report: Value = serde_json::from_slice(&output).expect("certification JSON");
    assert_eq!(report["release_gate"]["status"], "failed");
    assert_eq!(report["release_gate"]["passed"], false);
    assert_eq!(
        report["release_gate"]["preset"],
        "default-core-release-gate"
    );
    assert_eq!(report["release_gate"]["preset_requested"], true);
    assert_eq!(report["release_gate"]["preset_applied"], false);
    assert_eq!(report["release_gate"]["preset_minimums_met"], false);
    assert_eq!(
        report["release_gate"]["preset_required_stability_window_ms"],
        60000
    );
    assert_eq!(
        report["release_gate"]["preset_required_stability_connections"],
        25
    );
    let preset_blockers = report["release_gate"]["preset_blockers"]
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
    let release_gate_blockers = report["release_gate"]["blockers"]
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
        report["release_gate"]["blocker_count"].as_u64(),
        Some(release_gate_blockers.len() as u64)
    );
    let next_actions = report["release_gate"]["next_actions"]
        .as_array()
        .expect("release gate next actions");
    assert!(next_actions
        .iter()
        .any(|action| action.as_str() == Some("enable-machine-takeover-release-gate")));
    assert!(next_actions
        .iter()
        .any(|action| action.as_str() == Some("run-with-default-release-stability-window")));
    assert!(next_actions
        .iter()
        .any(|action| action.as_str() == Some("run-with-default-release-stability-connections")));
    assert_eq!(
        report["release_gate"]["next_action_count"].as_u64(),
        Some(next_actions.len() as u64)
    );
    let rerun_args = report["release_gate"]["rerun_args"]
        .as_array()
        .expect("release gate rerun args");
    assert_eq!(rerun_args.len(), 1);
    assert_eq!(rerun_args[0], "--default-core-release-gate");
    assert_eq!(report["release_gate"]["rerun_arg_count"].as_u64(), Some(1));
    assert_eq!(
        report["release_gate"]["rerun_command"],
        "keli-cli default-core-certify --default-core-release-gate"
    );
    assert_eq!(
        report["certification"]["release_gate_preset"],
        "default-core-release-gate"
    );
    assert_eq!(
        report["certification"]["release_gate_preset_applied"],
        false
    );
}

#[test]
fn default_core_certification_treats_preset_request_as_release_gate_scope() {
    let mut output = Vec::new();

    let error = write_default_core_certification_report_with_release_gate_preset_and_stability_requirements(
        ProbeOutputFormat::Json,
        2,
        Duration::from_secs(2),
        2,
        Duration::from_millis(0),
        false,
        false,
        Duration::from_millis(50),
        false,
        None,
        None,
        Some("default-core-release-gate"),
        &mut output,
    )
    .expect_err("preset request should be a release gate even without explicit gate options");

    assert!(error.contains("preset release gate failed"));
    assert!(error.contains("preset-machine-takeover-not-required"));
    assert!(error.contains("preset-stability-window-below-default"));
    assert!(error.contains("preset-stability-connections-below-default"));

    let report: Value = serde_json::from_slice(&output).expect("certification JSON");
    assert_eq!(report["release_gate"]["status"], "failed");
    assert_eq!(report["release_gate"]["required_scope"], "preset");
    assert_eq!(report["release_gate"]["passed"], false);
    assert_eq!(report["release_gate"]["preset_requested"], true);
    assert_eq!(report["release_gate"]["preset_applied"], false);
    let blockers = report["release_gate"]["blockers"]
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
    assert_eq!(
        report["release_gate"]["stability"]["local_soak_min_duration_ms"],
        50
    );
    assert_eq!(
        report["release_gate"]["stability"]["local_soak_duration_required"],
        true
    );
    assert_eq!(
        report["release_gate"]["stability"]["local_soak_complete"],
        true
    );
    let gates = report["readiness"]["gates"].as_array().expect("gates");
    assert!(gate(gates, "mixed-soak-socks5")["detail"]
        .as_str()
        .expect("socks5 detail")
        .contains("min_duration_ms=50"));
}

fn gate<'a>(gates: &'a [Value], name: &str) -> &'a Value {
    find_gate(gates, name).unwrap_or_else(|| panic!("missing gate {name}"))
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
    assert_eq!(smoke["tcp_server_close_markers_open"], 0);
    assert_eq!(smoke["tcp_post_close_markers_open"], 0);
    assert_eq!(smoke["tcp_session_errors"], 0);
    assert_eq!(smoke["tcp_session_limit_rejections"], 0);
    assert!(
        smoke["tcp_max_active_sessions"]
            .as_u64()
            .expect("TUN TCP max active sessions")
            > 0
    );
    assert_eq!(smoke["clean_stop_observed"], true);
    assert_eq!(smoke["residual_state_clean"], true);
    assert_eq!(smoke["case_count"], 4);
    assert_eq!(smoke["passed_case_count"], 4);
    assert_eq!(smoke["failed_case_count"], 0);
    let cases = smoke["cases"]
        .as_array()
        .expect("TUN TCP session smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-tun-tcp-session-relay",
        "relay-tun-tcp-client-payload",
        "write-tun-tcp-server-payload",
        "stop-tun-tcp-session-relay-cleanly",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing TUN TCP session smoke case {expected}: {case_names:?}"
        );
    }
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
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "write-server-payload-before-retransmit",
        "retransmit-server-payload-on-stale-ack",
        "clear-server-payload-retransmit-slot-on-latest-ack",
        "do-not-replay-server-payload-after-ack-clear",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing TUN TCP server retransmit smoke case {expected}: {case_names:?}"
        );
    }
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
    assert_eq!(no_replay["observed_ack_clear_packet"], true);
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
    assert_eq!(smoke["passed_case_count"], 3);
    assert_eq!(smoke["failed_case_count"], 0);
    let cases = smoke["cases"]
        .as_array()
        .expect("TUN TCP server FIN retransmit smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "write-server-fin-after-eof",
        "retransmit-server-fin-on-duplicate-ack",
        "absorb-server-fin-final-ack-without-reset",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing TUN TCP server FIN retransmit smoke case {expected}: {case_names:?}"
        );
    }
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
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "reset-unknown-tun-tcp-data",
        "reset-unknown-tun-tcp-fin",
        "absorb-unknown-tun-tcp-rst-without-reset-loop",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing TUN TCP unknown-session reset smoke case {expected}: {case_names:?}"
        );
    }
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
    let fin = cases
        .iter()
        .find(|case| case["name"] == "reset-unknown-tun-tcp-fin")
        .expect("TUN TCP unknown FIN reset case");
    assert_eq!(fin["observed_reset_written"], true);
    assert_eq!(fin["observed_sequence_number"], 1001);
    assert_eq!(fin["observed_acknowledgment_number"], 17);
    assert_eq!(fin["passed"], true);
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
    assert_eq!(smoke["passed_case_count"], 4);
    assert_eq!(smoke["failed_case_count"], 0);
    let cases = smoke["cases"]
        .as_array()
        .expect("TUN TCP session limit smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-tun-tcp-session-limit-smoke",
        "retain-first-tun-tcp-session",
        "reject-second-tun-tcp-session-over-limit",
        "stop-tun-tcp-session-limit-smoke-cleanly",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing TUN TCP session limit smoke case {expected}: {case_names:?}"
        );
    }
    let rejection = cases
        .iter()
        .find(|case| case["name"] == "reject-second-tun-tcp-session-over-limit")
        .expect("TUN TCP session limit rejection case");
    assert_eq!(rejection["expected_error_kind"], "TcpSessionLimitExceeded");
    assert!(rejection["observed_error_kind"]
        .as_str()
        .expect("observed session limit error")
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
    assert_eq!(smoke["tcp_server_closed_sessions_pruned"], 0);
    assert_eq!(smoke["tcp_post_closed_sessions_pruned"], 0);
    assert_eq!(smoke["tcp_sessions_peak"], 1);
    assert_eq!(smoke["tcp_sessions_open"], 0);
    assert_eq!(smoke["tcp_server_close_markers_open"], 0);
    assert_eq!(smoke["tcp_post_close_markers_open"], 0);
    assert_eq!(smoke["tcp_session_errors"], 0);
    assert_eq!(smoke["tcp_session_limit_rejections"], 0);
    assert!(
        smoke["tcp_max_active_sessions"]
            .as_u64()
            .expect("TUN TCP idle prune max active sessions")
            > 0
    );
    assert_eq!(smoke["clean_stop_observed"], true);
    assert_eq!(smoke["residual_state_clean"], true);
    assert_eq!(smoke["case_count"], 4);
    assert_eq!(smoke["passed_case_count"], 4);
    assert_eq!(smoke["failed_case_count"], 0);
    let cases = smoke["cases"]
        .as_array()
        .expect("TUN TCP session idle prune smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-tun-tcp-session-idle-prune-smoke",
        "create-prunable-tun-tcp-session",
        "prune-idle-tun-tcp-session-before-next-read",
        "stop-tun-tcp-session-idle-prune-cleanly",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing TUN TCP session idle prune smoke case {expected}: {case_names:?}"
        );
    }
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
    assert_eq!(smoke["server_close_active_sessions_after_marker"], 0);
    assert_eq!(smoke["server_close_markers_before_prune"], 1);
    assert_eq!(smoke["server_close_markers_after_prune"], 0);
    assert_eq!(smoke["server_close_closed_sessions_before_prune"], 1);
    assert_eq!(smoke["server_close_closed_sessions_after_prune"], 1);
    assert_eq!(smoke["server_close_pruned_sessions"], 0);
    assert_eq!(smoke["server_close_pruned_server_closed_sessions"], 1);
    assert_eq!(smoke["server_close_pruned_post_closed_sessions"], 0);
    assert_eq!(smoke["server_close_close_errors"], 0);
    assert!(smoke["server_close_last_error_kind"].is_null());
    assert_eq!(smoke["post_close_marker_observed"], true);
    assert_eq!(smoke["post_close_marker_pruned"], true);
    assert_eq!(smoke["post_close_reclose_avoided"], true);
    assert_eq!(smoke["post_close_active_sessions_after_marker"], 0);
    assert_eq!(smoke["post_close_markers_before_prune"], 1);
    assert_eq!(smoke["post_close_markers_after_prune"], 0);
    assert_eq!(smoke["post_close_closed_sessions_before_prune"], 1);
    assert_eq!(smoke["post_close_closed_sessions_after_prune"], 1);
    assert_eq!(smoke["post_close_pruned_sessions"], 0);
    assert_eq!(smoke["post_close_pruned_server_closed_sessions"], 0);
    assert_eq!(smoke["post_close_pruned_post_closed_sessions"], 1);
    assert_eq!(smoke["post_close_close_errors"], 0);
    assert!(smoke["post_close_last_error_kind"].is_null());
    assert_eq!(smoke["residual_state_clean"], true);
    assert_eq!(smoke["case_count"], 4);
    assert_eq!(smoke["passed_case_count"], 4);
    assert_eq!(smoke["failed_case_count"], 0);
    let cases = smoke["cases"]
        .as_array()
        .expect("TUN TCP close-marker prune smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "create-server-close-marker",
        "prune-server-close-marker-without-reclosing-relay",
        "create-post-close-marker",
        "prune-post-close-marker-without-reclosing-relay",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing TUN TCP close-marker prune smoke case {expected}: {case_names:?}"
        );
    }
    let server_prune = cases
        .iter()
        .find(|case| case["name"] == "prune-server-close-marker-without-reclosing-relay")
        .expect("server-close prune case");
    assert_eq!(server_prune["marker_kind"], "server-close");
    assert_eq!(server_prune["expected_pruned_server_closed_sessions"], 1);
    assert_eq!(server_prune["observed_pruned_server_closed_sessions"], 1);
    assert_eq!(server_prune["closed_sessions_before_prune"], 1);
    assert_eq!(server_prune["closed_sessions_after_prune"], 1);
    assert_eq!(server_prune["passed"], true);
    let post_prune = cases
        .iter()
        .find(|case| case["name"] == "prune-post-close-marker-without-reclosing-relay")
        .expect("post-close prune case");
    assert_eq!(post_prune["marker_kind"], "post-close");
    assert_eq!(post_prune["expected_pruned_post_closed_sessions"], 1);
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
    assert_eq!(smoke["server_close_active_sessions_before_reset"], 0);
    assert_eq!(smoke["server_close_markers_before_reset"], 1);
    assert_eq!(smoke["server_close_markers_after_reset"], 0);
    assert_eq!(smoke["server_close_response_packets"], 0);
    assert_eq!(smoke["server_close_closed_sessions_before_reset"], 1);
    assert_eq!(smoke["server_close_closed_sessions_after_reset"], 1);
    assert_eq!(smoke["server_close_pruned_sessions_after_reset"], 0);
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
    assert_eq!(smoke["post_close_active_sessions_before_reset"], 0);
    assert_eq!(smoke["post_close_markers_before_reset"], 1);
    assert_eq!(smoke["post_close_markers_after_reset"], 0);
    assert_eq!(smoke["post_close_response_packets"], 0);
    assert_eq!(smoke["post_close_closed_sessions_before_reset"], 1);
    assert_eq!(smoke["post_close_closed_sessions_after_reset"], 1);
    assert_eq!(smoke["post_close_pruned_sessions_after_reset"], 0);
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
    assert_eq!(smoke["passed_case_count"], 4);
    assert_eq!(smoke["failed_case_count"], 0);
    let cases = smoke["cases"]
        .as_array()
        .expect("TUN TCP close-marker RST clear smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "create-server-close-marker-before-rst",
        "clear-server-close-marker-with-rst-without-reset-or-reclosing-relay",
        "create-post-close-marker-before-rst",
        "clear-post-close-marker-with-rst-without-reset-or-reclosing-relay",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing TUN TCP close-marker RST clear smoke case {expected}: {case_names:?}"
        );
    }
    let server_reset = cases
        .iter()
        .find(|case| {
            case["name"] == "clear-server-close-marker-with-rst-without-reset-or-reclosing-relay"
        })
        .expect("server-close RST clear case");
    assert_eq!(server_reset["marker_kind"], "server-close");
    assert_eq!(server_reset["expected_reset_kind"], "server-close");
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
    assert_eq!(post_reset["expected_reset_kind"], "post-close");
    assert_eq!(post_reset["observed_reset_kind"], "post-close");
    assert_eq!(post_reset["response_packets"], 0);
    assert_eq!(post_reset["closed_sessions_before_reset"], 1);
    assert_eq!(post_reset["closed_sessions_after_reset"], 1);
    assert_eq!(post_reset["passed"], true);
}

fn assert_trojan_quic_udp_relay_smoke_json(report: &Value) {
    assert_eq!(report["trojan_quic_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["trojan_quic_udp_relay_smoke"]["passed"], true);
    assert_eq!(report["trojan_quic_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["trojan_quic_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["trojan_quic_udp_relay_smoke"]["selected_outbound"],
        "TROJAN-QUIC-UDP-SMOKE"
    );
    assert_eq!(
        report["trojan_quic_udp_relay_smoke"]["target"],
        "example.com:53"
    );
    assert!(report["trojan_quic_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        report["trojan_quic_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["trojan_quic_udp_relay_smoke"]["request_payload_bytes"],
        26
    );
    assert_eq!(
        report["trojan_quic_udp_relay_smoke"]["response_payload_bytes"],
        25
    );
    assert_eq!(
        report["trojan_quic_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["trojan_quic_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["trojan_quic_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["trojan_quic_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["trojan_quic_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["trojan_quic_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["trojan_quic_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["trojan_quic_udp_relay_smoke"]["stop_timed_out"],
        false
    );

    let cases = report["trojan_quic_udp_relay_smoke"]["cases"]
        .as_array()
        .expect("Trojan QUIC UDP relay smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-trojan-quic-udp-relay-runtime",
        "trojan-quic-udp-protocol-round-trip",
        "record-trojan-quic-udp-relay-metrics",
        "stop-trojan-quic-udp-relay-runtime",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing Trojan QUIC UDP relay smoke case {expected}: {case_names:?}"
        );
    }
    let round_trip = cases
        .iter()
        .find(|case| case["name"] == "trojan-quic-udp-protocol-round-trip")
        .expect("Trojan QUIC UDP relay round trip case");
    assert_eq!(round_trip["observed_response"], "keli-trojan-quic-udp-pong");
    assert_eq!(round_trip["response_source"], "127.0.0.1:53");
    assert_eq!(round_trip["round_trip_observed"], true);
    assert_eq!(round_trip["server_received_payload"], true);
}

fn assert_vless_quic_tcp_relay_smoke_json(report: &Value) {
    assert_eq!(report["vless_quic_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vless_quic_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["vless_quic_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vless_quic_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vless_quic_tcp_relay_smoke"]["selected_outbound"],
        "VLESS-QUIC-TCP-SMOKE"
    );
    assert_eq!(
        report["vless_quic_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vless_quic_tcp_relay_smoke"]["request_payload_bytes"],
        21
    );
    assert_eq!(
        report["vless_quic_tcp_relay_smoke"]["response_payload_bytes"],
        20
    );
    assert_eq!(
        report["vless_quic_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vless_quic_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vless_quic_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vless_quic_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vless_quic_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vless_quic_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vless_quic_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["vless_quic_tcp_relay_smoke"]["stop_timed_out"],
        false
    );

    let cases = report["vless_quic_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("VLESS QUIC TCP relay smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vless-quic-tcp-relay-runtime",
        "vless-quic-tcp-protocol-round-trip",
        "record-vless-quic-tcp-relay-metrics",
        "stop-vless-quic-tcp-relay-runtime",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing VLESS QUIC TCP relay smoke case {expected}: {case_names:?}"
        );
    }
    let round_trip = cases
        .iter()
        .find(|case| case["name"] == "vless-quic-tcp-protocol-round-trip")
        .expect("VLESS QUIC TCP relay round trip case");
    assert_eq!(round_trip["observed_response"], "keli-vless-quic-pong");
    assert_eq!(round_trip["round_trip_observed"], true);
    assert_eq!(round_trip["server_received_payload"], true);
}

fn assert_vless_grpc_udp_relay_smoke_json(report: &Value) {
    assert_eq!(report["vless_grpc_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vless_grpc_udp_relay_smoke"]["passed"], true);
    assert_eq!(report["vless_grpc_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vless_grpc_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vless_grpc_udp_relay_smoke"]["selected_outbound"],
        "VLESS-GRPC-UDP-SMOKE"
    );
    assert_eq!(
        report["vless_grpc_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(
        report["vless_grpc_udp_relay_smoke"]["relay_port"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert_eq!(
        report["vless_grpc_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["vless_grpc_udp_relay_smoke"]["request_payload_bytes"],
        25
    );
    assert_eq!(
        report["vless_grpc_udp_relay_smoke"]["response_payload_bytes"],
        24
    );
    assert_eq!(
        report["vless_grpc_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vless_grpc_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vless_grpc_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vless_grpc_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vless_grpc_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vless_grpc_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vless_grpc_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["vless_grpc_udp_relay_smoke"]["stop_timed_out"],
        false
    );
    let cases = report["vless_grpc_udp_relay_smoke"]["cases"]
        .as_array()
        .expect("VLESS gRPC UDP relay smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vless-grpc-udp-relay-runtime",
        "vless-grpc-udp-protocol-round-trip",
        "record-vless-grpc-udp-relay-metrics",
        "stop-vless-grpc-udp-relay-runtime",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing VLESS gRPC UDP relay smoke case {expected}: {case_names:?}"
        );
    }
    let round_trip = cases
        .iter()
        .find(|case| case["name"] == "vless-grpc-udp-protocol-round-trip")
        .expect("VLESS gRPC UDP relay round trip case");
    assert_eq!(round_trip["observed_response"], "keli-vless-grpc-udp-pong");
    assert_eq!(round_trip["response_source"], "127.0.0.1:53");
    assert_eq!(round_trip["round_trip_observed"], true);
    assert_eq!(round_trip["server_received_payload"], true);
    if let Some(certification) = report.get("certification") {
        assert_eq!(certification["vless_grpc_udp_relay_smoke_passed"], true);
    }
    if let Some(readiness) = report.get("readiness") {
        assert_eq!(readiness["vless_grpc_udp_relay_smoke"]["status"], "passed");
        assert_eq!(readiness["vless_grpc_udp_relay_smoke"]["case_count"], 4);
    }
}

fn assert_vmess_grpc_udp_relay_smoke_json(report: &Value) {
    assert_eq!(report["vmess_grpc_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vmess_grpc_udp_relay_smoke"]["passed"], true);
    assert_eq!(report["vmess_grpc_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vmess_grpc_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vmess_grpc_udp_relay_smoke"]["selected_outbound"],
        "VMESS-GRPC-UDP-SMOKE"
    );
    assert_eq!(
        report["vmess_grpc_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(
        report["vmess_grpc_udp_relay_smoke"]["relay_port"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert_eq!(
        report["vmess_grpc_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["vmess_grpc_udp_relay_smoke"]["request_payload_bytes"],
        25
    );
    assert_eq!(
        report["vmess_grpc_udp_relay_smoke"]["response_payload_bytes"],
        24
    );
    assert_eq!(
        report["vmess_grpc_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vmess_grpc_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vmess_grpc_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vmess_grpc_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vmess_grpc_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vmess_grpc_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vmess_grpc_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["vmess_grpc_udp_relay_smoke"]["stop_timed_out"],
        false
    );
    let cases = report["vmess_grpc_udp_relay_smoke"]["cases"]
        .as_array()
        .expect("VMess gRPC UDP relay smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vmess-grpc-udp-relay-runtime",
        "vmess-grpc-udp-protocol-round-trip",
        "record-vmess-grpc-udp-relay-metrics",
        "stop-vmess-grpc-udp-relay-runtime",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing VMess gRPC UDP relay smoke case {expected}: {case_names:?}"
        );
    }
    let round_trip = cases
        .iter()
        .find(|case| case["name"] == "vmess-grpc-udp-protocol-round-trip")
        .expect("VMess gRPC UDP relay round trip case");
    assert_eq!(round_trip["observed_response"], "keli-vmess-grpc-udp-pong");
    assert_eq!(round_trip["response_source"], "127.0.0.1:53");
    assert_eq!(round_trip["round_trip_observed"], true);
    assert_eq!(round_trip["server_received_payload"], true);
    if let Some(certification) = report.get("certification") {
        assert_eq!(certification["vmess_grpc_udp_relay_smoke_passed"], true);
    }
    if let Some(readiness) = report.get("readiness") {
        assert_eq!(readiness["vmess_grpc_udp_relay_smoke"]["status"], "passed");
        assert_eq!(readiness["vmess_grpc_udp_relay_smoke"]["case_count"], 4);
    }
}

fn assert_vless_h2_udp_relay_smoke_json(report: &Value) {
    assert_eq!(report["vless_h2_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vless_h2_udp_relay_smoke"]["passed"], true);
    assert_eq!(report["vless_h2_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vless_h2_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vless_h2_udp_relay_smoke"]["selected_outbound"],
        "VLESS-H2-UDP-SMOKE"
    );
    assert_eq!(report["vless_h2_udp_relay_smoke"]["target"], "127.0.0.1:53");
    assert!(
        report["vless_h2_udp_relay_smoke"]["relay_port"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert_eq!(
        report["vless_h2_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["vless_h2_udp_relay_smoke"]["request_payload_bytes"],
        23
    );
    assert_eq!(
        report["vless_h2_udp_relay_smoke"]["response_payload_bytes"],
        22
    );
    assert_eq!(
        report["vless_h2_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vless_h2_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["vless_h2_udp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["vless_h2_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vless_h2_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vless_h2_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vless_h2_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["vless_h2_udp_relay_smoke"]["stop_timed_out"], false);
    let cases = report["vless_h2_udp_relay_smoke"]["cases"]
        .as_array()
        .expect("VLESS H2 UDP relay smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vless-h2-udp-relay-runtime",
        "vless-h2-udp-protocol-round-trip",
        "record-vless-h2-udp-relay-metrics",
        "stop-vless-h2-udp-relay-runtime",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing VLESS H2 UDP relay smoke case {expected}: {case_names:?}"
        );
    }
    let round_trip = cases
        .iter()
        .find(|case| case["name"] == "vless-h2-udp-protocol-round-trip")
        .expect("VLESS H2 UDP relay round trip case");
    assert_eq!(round_trip["observed_response"], "keli-vless-h2-udp-pong");
    assert_eq!(round_trip["response_source"], "127.0.0.1:53");
    assert_eq!(round_trip["round_trip_observed"], true);
    assert_eq!(round_trip["server_received_payload"], true);
    if let Some(certification) = report.get("certification") {
        assert_eq!(certification["vless_h2_udp_relay_smoke_passed"], true);
    }
    if let Some(readiness) = report.get("readiness") {
        assert_eq!(readiness["vless_h2_udp_relay_smoke"]["status"], "passed");
        assert_eq!(readiness["vless_h2_udp_relay_smoke"]["case_count"], 4);
    }
}

fn assert_vless_ws_udp_relay_smoke_json(report: &Value) {
    assert_eq!(report["vless_ws_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vless_ws_udp_relay_smoke"]["passed"], true);
    assert_eq!(report["vless_ws_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vless_ws_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vless_ws_udp_relay_smoke"]["selected_outbound"],
        "VLESS-WS-UDP-SMOKE"
    );
    assert_eq!(report["vless_ws_udp_relay_smoke"]["target"], "127.0.0.1:53");
    assert!(report["vless_ws_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        report["vless_ws_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["vless_ws_udp_relay_smoke"]["request_payload_bytes"],
        23
    );
    assert_eq!(
        report["vless_ws_udp_relay_smoke"]["response_payload_bytes"],
        22
    );
    assert_eq!(
        report["vless_ws_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vless_ws_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["vless_ws_udp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["vless_ws_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vless_ws_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vless_ws_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vless_ws_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["vless_ws_udp_relay_smoke"]["stop_timed_out"], false);

    let cases = report["vless_ws_udp_relay_smoke"]["cases"]
        .as_array()
        .expect("VLESS WS UDP relay smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vless-ws-udp-relay-runtime",
        "vless-ws-udp-protocol-round-trip",
        "record-vless-ws-udp-relay-metrics",
        "stop-vless-ws-udp-relay-runtime",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing VLESS WS UDP relay smoke case {expected}: {case_names:?}"
        );
    }
    let round_trip = cases
        .iter()
        .find(|case| case["name"] == "vless-ws-udp-protocol-round-trip")
        .expect("VLESS WS UDP relay round trip case");
    assert_eq!(round_trip["observed_response"], "keli-vless-ws-udp-pong");
    assert_eq!(round_trip["response_source"], "127.0.0.1:53");
    assert_eq!(round_trip["round_trip_observed"], true);
    assert_eq!(round_trip["server_received_payload"], true);
}

fn assert_vmess_ws_udp_relay_smoke_json(report: &Value) {
    assert_eq!(report["vmess_ws_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vmess_ws_udp_relay_smoke"]["passed"], true);
    assert_eq!(report["vmess_ws_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vmess_ws_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vmess_ws_udp_relay_smoke"]["selected_outbound"],
        "VMESS-WS-UDP-SMOKE"
    );
    assert_eq!(report["vmess_ws_udp_relay_smoke"]["target"], "127.0.0.1:53");
    assert!(report["vmess_ws_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        report["vmess_ws_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["vmess_ws_udp_relay_smoke"]["request_payload_bytes"],
        23
    );
    assert_eq!(
        report["vmess_ws_udp_relay_smoke"]["response_payload_bytes"],
        22
    );
    assert_eq!(
        report["vmess_ws_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vmess_ws_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["vmess_ws_udp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["vmess_ws_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vmess_ws_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vmess_ws_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vmess_ws_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["vmess_ws_udp_relay_smoke"]["stop_timed_out"], false);

    let cases = report["vmess_ws_udp_relay_smoke"]["cases"]
        .as_array()
        .expect("VMess WS UDP relay smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vmess-ws-udp-relay-runtime",
        "vmess-ws-udp-protocol-round-trip",
        "record-vmess-ws-udp-relay-metrics",
        "stop-vmess-ws-udp-relay-runtime",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing VMess WS UDP relay smoke case {expected}: {case_names:?}"
        );
    }
    let round_trip = cases
        .iter()
        .find(|case| case["name"] == "vmess-ws-udp-protocol-round-trip")
        .expect("VMess WS UDP relay round trip case");
    assert_eq!(round_trip["observed_response"], "keli-vmess-ws-udp-pong");
    assert_eq!(round_trip["response_source"], "127.0.0.1:53");
    assert_eq!(round_trip["round_trip_observed"], true);
    assert_eq!(round_trip["server_received_payload"], true);
}

fn assert_vless_httpupgrade_udp_relay_smoke_json(report: &Value) {
    assert_eq!(
        report["vless_httpupgrade_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(report["vless_httpupgrade_udp_relay_smoke"]["passed"], true);
    assert_eq!(report["vless_httpupgrade_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["vless_httpupgrade_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["vless_httpupgrade_udp_relay_smoke"]["selected_outbound"],
        "VLESS-HU-UDP-SMOKE"
    );
    assert_eq!(
        report["vless_httpupgrade_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(report["vless_httpupgrade_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        report["vless_httpupgrade_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["vless_httpupgrade_udp_relay_smoke"]["request_payload_bytes"],
        23
    );
    assert_eq!(
        report["vless_httpupgrade_udp_relay_smoke"]["response_payload_bytes"],
        22
    );
    assert_eq!(
        report["vless_httpupgrade_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vless_httpupgrade_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vless_httpupgrade_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vless_httpupgrade_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vless_httpupgrade_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vless_httpupgrade_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vless_httpupgrade_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["vless_httpupgrade_udp_relay_smoke"]["stop_timed_out"],
        false
    );

    let cases = report["vless_httpupgrade_udp_relay_smoke"]["cases"]
        .as_array()
        .expect("VLESS HTTPUpgrade UDP relay smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vless-httpupgrade-udp-relay-runtime",
        "vless-httpupgrade-udp-protocol-round-trip",
        "record-vless-httpupgrade-udp-relay-metrics",
        "stop-vless-httpupgrade-udp-relay-runtime",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing VLESS HTTPUpgrade UDP relay smoke case {expected}: {case_names:?}"
        );
    }
    let round_trip = cases
        .iter()
        .find(|case| case["name"] == "vless-httpupgrade-udp-protocol-round-trip")
        .expect("VLESS HTTPUpgrade UDP relay round trip case");
    assert_eq!(round_trip["observed_response"], "keli-vless-hu-udp-pong");
    assert_eq!(round_trip["response_source"], "127.0.0.1:53");
    assert_eq!(round_trip["round_trip_observed"], true);
    assert_eq!(round_trip["server_received_payload"], true);
}

fn assert_vless_quic_udp_relay_smoke_json(report: &Value) {
    assert_eq!(report["vless_quic_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vless_quic_udp_relay_smoke"]["passed"], true);
    assert_eq!(report["vless_quic_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vless_quic_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vless_quic_udp_relay_smoke"]["selected_outbound"],
        "VLESS-QUIC-UDP-SMOKE"
    );
    assert_eq!(
        report["vless_quic_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(report["vless_quic_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        report["vless_quic_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["vless_quic_udp_relay_smoke"]["request_payload_bytes"],
        25
    );
    assert_eq!(
        report["vless_quic_udp_relay_smoke"]["response_payload_bytes"],
        24
    );
    assert_eq!(
        report["vless_quic_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vless_quic_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vless_quic_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vless_quic_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vless_quic_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vless_quic_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vless_quic_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["vless_quic_udp_relay_smoke"]["stop_timed_out"],
        false
    );

    let cases = report["vless_quic_udp_relay_smoke"]["cases"]
        .as_array()
        .expect("VLESS QUIC UDP relay smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vless-quic-udp-relay-runtime",
        "vless-quic-udp-protocol-round-trip",
        "record-vless-quic-udp-relay-metrics",
        "stop-vless-quic-udp-relay-runtime",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing VLESS QUIC UDP relay smoke case {expected}: {case_names:?}"
        );
    }
    let round_trip = cases
        .iter()
        .find(|case| case["name"] == "vless-quic-udp-protocol-round-trip")
        .expect("VLESS QUIC UDP relay round trip case");
    assert_eq!(round_trip["observed_response"], "keli-vless-quic-udp-pong");
    assert_eq!(round_trip["response_source"], "127.0.0.1:53");
    assert_eq!(round_trip["round_trip_observed"], true);
    assert_eq!(round_trip["server_received_payload"], true);
}

fn assert_vmess_h2_udp_relay_smoke_json(report: &Value) {
    assert_eq!(report["vmess_h2_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vmess_h2_udp_relay_smoke"]["passed"], true);
    assert_eq!(report["vmess_h2_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vmess_h2_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vmess_h2_udp_relay_smoke"]["selected_outbound"],
        "VMESS-H2-UDP-SMOKE"
    );
    assert_eq!(report["vmess_h2_udp_relay_smoke"]["target"], "127.0.0.1:53");
    assert!(
        report["vmess_h2_udp_relay_smoke"]["relay_port"]
            .as_u64()
            .unwrap_or_default()
            > 0
    );
    assert_eq!(
        report["vmess_h2_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["vmess_h2_udp_relay_smoke"]["request_payload_bytes"],
        23
    );
    assert_eq!(
        report["vmess_h2_udp_relay_smoke"]["response_payload_bytes"],
        22
    );
    assert_eq!(
        report["vmess_h2_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vmess_h2_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(report["vmess_h2_udp_relay_smoke"]["metrics_recorded"], true);
    assert_eq!(
        report["vmess_h2_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vmess_h2_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vmess_h2_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vmess_h2_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(report["vmess_h2_udp_relay_smoke"]["stop_timed_out"], false);
    let cases = report["vmess_h2_udp_relay_smoke"]["cases"]
        .as_array()
        .expect("VMess H2 UDP relay smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vmess-h2-udp-relay-runtime",
        "vmess-h2-udp-protocol-round-trip",
        "record-vmess-h2-udp-relay-metrics",
        "stop-vmess-h2-udp-relay-runtime",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing VMess H2 UDP relay smoke case {expected}: {case_names:?}"
        );
    }
    let round_trip = cases
        .iter()
        .find(|case| case["name"] == "vmess-h2-udp-protocol-round-trip")
        .expect("VMess H2 UDP relay round trip case");
    assert_eq!(round_trip["observed_response"], "keli-vmess-h2-udp-pong");
    assert_eq!(round_trip["response_source"], "127.0.0.1:53");
    assert_eq!(round_trip["round_trip_observed"], true);
    assert_eq!(round_trip["server_received_payload"], true);
    if let Some(certification) = report.get("certification") {
        assert_eq!(certification["vmess_h2_udp_relay_smoke_passed"], true);
    }
    if let Some(readiness) = report.get("readiness") {
        assert_eq!(readiness["vmess_h2_udp_relay_smoke"]["status"], "passed");
        assert_eq!(readiness["vmess_h2_udp_relay_smoke"]["case_count"], 4);
    }
}

fn assert_vmess_quic_tcp_relay_smoke_json(report: &Value) {
    assert_eq!(report["vmess_quic_tcp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vmess_quic_tcp_relay_smoke"]["passed"], true);
    assert_eq!(report["vmess_quic_tcp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vmess_quic_tcp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vmess_quic_tcp_relay_smoke"]["selected_outbound"],
        "VMESS-QUIC-TCP-SMOKE"
    );
    assert_eq!(
        report["vmess_quic_tcp_relay_smoke"]["target"],
        "example.com:443"
    );
    assert_eq!(
        report["vmess_quic_tcp_relay_smoke"]["request_payload_bytes"],
        21
    );
    assert_eq!(
        report["vmess_quic_tcp_relay_smoke"]["response_payload_bytes"],
        20
    );
    assert_eq!(
        report["vmess_quic_tcp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vmess_quic_tcp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vmess_quic_tcp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vmess_quic_tcp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vmess_quic_tcp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vmess_quic_tcp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vmess_quic_tcp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["vmess_quic_tcp_relay_smoke"]["stop_timed_out"],
        false
    );

    let cases = report["vmess_quic_tcp_relay_smoke"]["cases"]
        .as_array()
        .expect("VMess QUIC TCP relay smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vmess-quic-tcp-relay-runtime",
        "vmess-quic-tcp-protocol-round-trip",
        "record-vmess-quic-tcp-relay-metrics",
        "stop-vmess-quic-tcp-relay-runtime",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing VMess QUIC TCP relay smoke case {expected}: {case_names:?}"
        );
    }
    let round_trip = cases
        .iter()
        .find(|case| case["name"] == "vmess-quic-tcp-protocol-round-trip")
        .expect("VMess QUIC TCP relay round trip case");
    assert_eq!(round_trip["observed_response"], "keli-vmess-quic-pong");
    assert_eq!(round_trip["round_trip_observed"], true);
    assert_eq!(round_trip["server_received_payload"], true);
}

fn assert_vmess_quic_udp_relay_smoke_json(report: &Value) {
    assert_eq!(report["vmess_quic_udp_relay_smoke"]["status"], "passed");
    assert_eq!(report["vmess_quic_udp_relay_smoke"]["passed"], true);
    assert_eq!(report["vmess_quic_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(report["vmess_quic_udp_relay_smoke"]["failed_case_count"], 0);
    assert_eq!(
        report["vmess_quic_udp_relay_smoke"]["selected_outbound"],
        "VMESS-QUIC-UDP-SMOKE"
    );
    assert_eq!(
        report["vmess_quic_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(report["vmess_quic_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        report["vmess_quic_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["vmess_quic_udp_relay_smoke"]["request_payload_bytes"],
        25
    );
    assert_eq!(
        report["vmess_quic_udp_relay_smoke"]["response_payload_bytes"],
        24
    );
    assert_eq!(
        report["vmess_quic_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vmess_quic_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vmess_quic_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vmess_quic_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vmess_quic_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vmess_quic_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vmess_quic_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["vmess_quic_udp_relay_smoke"]["stop_timed_out"],
        false
    );

    let cases = report["vmess_quic_udp_relay_smoke"]["cases"]
        .as_array()
        .expect("VMess QUIC UDP relay smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vmess-quic-udp-relay-runtime",
        "vmess-quic-udp-protocol-round-trip",
        "record-vmess-quic-udp-relay-metrics",
        "stop-vmess-quic-udp-relay-runtime",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing VMess QUIC UDP relay smoke case {expected}: {case_names:?}"
        );
    }
    let round_trip = cases
        .iter()
        .find(|case| case["name"] == "vmess-quic-udp-protocol-round-trip")
        .expect("VMess QUIC UDP relay round trip case");
    assert_eq!(round_trip["observed_response"], "keli-vmess-quic-udp-pong");
    assert_eq!(round_trip["response_source"], "127.0.0.1:53");
    assert_eq!(round_trip["round_trip_observed"], true);
    assert_eq!(round_trip["server_received_payload"], true);
}

fn assert_vmess_httpupgrade_udp_relay_smoke_json(report: &Value) {
    assert_eq!(
        report["vmess_httpupgrade_udp_relay_smoke"]["status"],
        "passed"
    );
    assert_eq!(report["vmess_httpupgrade_udp_relay_smoke"]["passed"], true);
    assert_eq!(report["vmess_httpupgrade_udp_relay_smoke"]["case_count"], 4);
    assert_eq!(
        report["vmess_httpupgrade_udp_relay_smoke"]["failed_case_count"],
        0
    );
    assert_eq!(
        report["vmess_httpupgrade_udp_relay_smoke"]["selected_outbound"],
        "VMESS-HU-UDP-SMOKE"
    );
    assert_eq!(
        report["vmess_httpupgrade_udp_relay_smoke"]["target"],
        "127.0.0.1:53"
    );
    assert!(report["vmess_httpupgrade_udp_relay_smoke"]["relay_port"].is_number());
    assert_eq!(
        report["vmess_httpupgrade_udp_relay_smoke"]["response_source"],
        "127.0.0.1:53"
    );
    assert_eq!(
        report["vmess_httpupgrade_udp_relay_smoke"]["request_payload_bytes"],
        23
    );
    assert_eq!(
        report["vmess_httpupgrade_udp_relay_smoke"]["response_payload_bytes"],
        22
    );
    assert_eq!(
        report["vmess_httpupgrade_udp_relay_smoke"]["round_trip_observed"],
        true
    );
    assert_eq!(
        report["vmess_httpupgrade_udp_relay_smoke"]["server_received_payload"],
        true
    );
    assert_eq!(
        report["vmess_httpupgrade_udp_relay_smoke"]["metrics_recorded"],
        true
    );
    assert_eq!(
        report["vmess_httpupgrade_udp_relay_smoke"]["metrics_inbound_count"],
        1
    );
    assert_eq!(
        report["vmess_httpupgrade_udp_relay_smoke"]["metrics_outbound_route_count"],
        1
    );
    assert_eq!(
        report["vmess_httpupgrade_udp_relay_smoke"]["clean_stop_observed"],
        true
    );
    assert_eq!(
        report["vmess_httpupgrade_udp_relay_smoke"]["stop_workers_remaining"],
        0
    );
    assert_eq!(
        report["vmess_httpupgrade_udp_relay_smoke"]["stop_timed_out"],
        false
    );

    let cases = report["vmess_httpupgrade_udp_relay_smoke"]["cases"]
        .as_array()
        .expect("VMess HTTPUpgrade UDP relay smoke cases");
    let case_names: Vec<_> = cases
        .iter()
        .filter_map(|case| case["name"].as_str())
        .collect();
    for expected in [
        "start-vmess-httpupgrade-udp-relay-runtime",
        "vmess-httpupgrade-udp-protocol-round-trip",
        "record-vmess-httpupgrade-udp-relay-metrics",
        "stop-vmess-httpupgrade-udp-relay-runtime",
    ] {
        assert!(
            case_names.contains(&expected),
            "missing VMess HTTPUpgrade UDP relay smoke case {expected}: {case_names:?}"
        );
    }
    let round_trip = cases
        .iter()
        .find(|case| case["name"] == "vmess-httpupgrade-udp-protocol-round-trip")
        .expect("VMess HTTPUpgrade UDP relay round trip case");
    assert_eq!(round_trip["observed_response"], "keli-vmess-hu-udp-pong");
    assert_eq!(round_trip["response_source"], "127.0.0.1:53");
    assert_eq!(round_trip["round_trip_observed"], true);
    assert_eq!(round_trip["server_received_payload"], true);
}

fn find_gate<'a>(gates: &'a [Value], name: &str) -> Option<&'a Value> {
    gates.iter().find(|gate| gate["name"] == name)
}
