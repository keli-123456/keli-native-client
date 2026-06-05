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
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["doctor"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["doctor"]["platform"], "Windows");
    assert_eq!(report["doctor"]["route_rule_capabilities"][3], "ip-cidr");
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
