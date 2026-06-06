use std::time::Duration;

use keli_cli::{
    write_soak_mixed_report, write_soak_mixed_report_with_min_duration, ProbeOutputFormat,
    SmokeInboundKind,
};

#[test]
fn soak_mixed_json_reports_repeated_socks5_round_trips() {
    let mut output = Vec::new();

    write_soak_mixed_report(
        5,
        SmokeInboundKind::Socks5,
        Duration::from_secs(2),
        2,
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect("mixed SOCKS5 soak");

    let report: serde_json::Value = serde_json::from_slice(&output).expect("soak JSON");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["kind"], "keli_mixed_soak");
    assert_eq!(report["inbound"], "socks5");
    assert_eq!(report["requested_connections"], 5);
    assert_eq!(report["completed_connections"], 5);
    assert_eq!(report["failed_connections"], 0);
    assert_eq!(report["min_duration_ms"], 0);
    assert_eq!(report["duration_target_met"], true);
    assert_eq!(report["payload_bytes_per_connection"], 14);
    assert_eq!(report["connection_metrics"]["total_connection_count"], 5);
    assert_eq!(report["connection_metrics"]["success_count"], 5);
    assert_eq!(report["connection_metrics"]["failure_count"], 0);
    assert_eq!(report["connection_metrics"]["total_upload_bytes"], 70);
    assert_eq!(report["connection_metrics"]["total_download_bytes"], 70);
    assert_eq!(
        report["connection_metrics"]["route_action_counts"][0]["route_action"]["kind"],
        "direct"
    );
    assert_eq!(
        report["connection_metrics"]["inbound_counts"][0]["inbound"],
        "socks5"
    );
    assert_eq!(report["worker_gauge"]["max_connection_workers"], 2);
    assert!(
        report["worker_gauge"]["peak_connection_workers"]
            .as_u64()
            .expect("peak workers")
            >= 1
    );
    assert!(
        report["worker_gauge"]["peak_client_connections"]
            .as_u64()
            .expect("peak client connections")
            >= 1
    );
    assert_eq!(report["stop_drain"]["workers_remaining"], 0);
    assert_eq!(report["stop_drain"]["timed_out"], false);
}

#[test]
fn soak_mixed_text_reports_http_connect_success() {
    let mut output = Vec::new();

    write_soak_mixed_report(
        3,
        SmokeInboundKind::HttpConnect,
        Duration::from_secs(2),
        1,
        ProbeOutputFormat::Text,
        &mut output,
    )
    .expect("mixed HTTP CONNECT soak");

    let output = String::from_utf8(output).expect("soak text");
    assert!(output.contains("soak status=ok"));
    assert!(output.contains("inbound=http-connect"));
    assert!(output.contains("requested_connections=3"));
    assert!(output.contains("completed_connections=3"));
    assert!(output.contains("failed_connections=0"));
    assert!(output.contains("min_duration_ms=0"));
    assert!(output.contains("duration_target_met=true"));
    assert!(output.contains("total_connection_count=3"));
    assert!(output.contains("success_count=3"));
    assert!(output.contains("failure_count=0"));
    assert!(output.contains("stop_workers_remaining=0"));
    assert!(output.contains("stop_timed_out=false"));
}

#[test]
fn soak_mixed_json_can_hold_runtime_for_min_duration() {
    let mut output = Vec::new();

    write_soak_mixed_report_with_min_duration(
        1,
        SmokeInboundKind::Socks5,
        Duration::from_secs(2),
        1,
        Duration::from_millis(75),
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect("mixed SOCKS5 timed soak");

    let report: serde_json::Value = serde_json::from_slice(&output).expect("soak JSON");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["requested_connections"], 1);
    assert_eq!(report["completed_connections"], 1);
    assert_eq!(report["min_duration_ms"], 75);
    assert_eq!(report["duration_target_met"], true);
    assert!(report["elapsed_ms"].as_u64().expect("elapsed milliseconds") >= 75);
    assert_eq!(report["stop_drain"]["workers_remaining"], 0);
    assert_eq!(report["stop_drain"]["timed_out"], false);
}
