#[test]
fn doctor_report_lists_supported_outbounds() {
    let mut output = Vec::new();
    keli_cli::write_doctor_report(&mut output).expect("write doctor report");
    let output = String::from_utf8(output).expect("doctor utf8");

    assert!(output.contains("version="));
    assert!(output.contains("system_proxy_state="));
    assert!(output.contains("tun_device_supported="));
    assert!(output.contains("lifecycle_available="));
    assert!(output.contains("packet_io_available="));
    assert!(output.contains("dns_leak_prevention_policy_available=true"));
    assert!(output.contains("dns_address_family_policy_available=true"));
    assert!(output.contains("dns_default_local_resolution_policy=allow-system"));
    assert!(output.contains("dns_default_address_family_policy=dual-stack"));
    assert!(output.contains(
        "route_rule_capabilities=domain-suffix,domain-keyword,ip-exact,ip-cidr,port-exact,port-range"
    ));
    assert!(output.contains(
        "tun_packet_pipeline_capabilities=ipv4,ipv6,tcp,udp,udp-payload,icmp,route-decision,dns-hijack,dns-query-plan,dns-engine-response,packet-process-action,udp-response-packet,dns-response-packet,ipv4-fragment-guard,ipv6-extension-traversal,ipv6-extension-guard,packet-loop,packet-loop-summary,managed-packet-loop,direct-udp-relay,outbound-udp-relay,registry-udp-relay,managed-registry-udp-relay,listen-mixed-tun-runtime,concurrent-tun-runtime,background-runtime-report,tun-runtime-status-note,packet-io-readiness,tcp-segment-parse,tcp-response-packet,tcp-reset-response,tcp-syn-ack-response,tcp-syn-retransmit-guard,tcp-session-table,tcp-client-payload-ack,tcp-client-duplicate-ack,tcp-client-out-of-order-ack,tcp-client-overlap-ack,tcp-client-stale-server-ack,tcp-client-ack-keepalive,tcp-server-payload-packet,tcp-server-payload-retransmit,tcp-server-payload-ack-clear,tcp-server-mss-read-clamp,tcp-session-step-runner,tcp-session-device-loop,tcp-server-payload-poll,tcp-fin-close-ack,tcp-fin-payload-close,registry-tcp-fin-payload-close,tcp-client-fin-half-close,tcp-client-fin-stale-server-ack,tcp-client-fin-server-payload-retransmit,tcp-client-fin-server-payload-ack-clear,tcp-client-fin-duplicate-poll,tcp-client-fin-duplicate-payload-poll,tcp-client-fin-payload-duplicate-poll,tcp-client-fin-post-close-ack,tcp-close-sequence-guard,tcp-close-latest-ack-guard,tcp-unknown-session-reset,tcp-server-eof-fin-ack,tcp-server-fin-retransmit,tcp-server-fin-final-ack,tcp-server-fin-client-fin-ack,tcp-server-fin-post-close-guard,tcp-session-idle-cleanup,registry-tcp-session-relay,combined-tun-relay-loop,managed-registry-tcp-session-relay,tcp-relay-plan-summary,relay-plan"
    ));
    assert!(output.contains(
        "supported_outbounds=direct,socks5-tcp,http-connect,trojan-tcp,trojan-ws,trojan-httpupgrade,trojan-grpc,trojan-h2,trojan-quic,vless-tcp,vless-ws,vless-httpupgrade,vless-grpc,vless-h2,vless-quic,vmess-tcp,vmess-ws,vmess-httpupgrade,vmess-grpc,vmess-h2,vmess-quic,shadowsocks-tcp,anytls-tls-tcp,naive-h2-tcp,naive-h3-quic,mieru-tcp,hy2-quic,tuic-quic"
    ));
    assert!(output.contains(
        "supported_udp_outbounds=direct,socks5-udp,trojan-tcp-udp,trojan-tls-tcp-udp,trojan-ws-udp,trojan-tls-ws-udp,trojan-httpupgrade-udp,trojan-tls-httpupgrade-udp,trojan-grpc-udp,trojan-tls-grpc-udp,trojan-h2-udp,trojan-tls-h2-udp,trojan-quic-udp,vless-tcp-udp,vless-tls-tcp-udp,vless-ws-udp,vless-tls-ws-udp,vless-httpupgrade-udp,vless-tls-httpupgrade-udp,vless-grpc-udp,vless-tls-grpc-udp,vless-h2-udp,vless-tls-h2-udp,vless-quic-udp,vmess-tcp-aead-udp,vmess-tls-tcp-aead-udp,vmess-ws-aead-udp,vmess-tls-ws-aead-udp,vmess-httpupgrade-aead-udp,vmess-tls-httpupgrade-aead-udp,vmess-grpc-aead-udp,vmess-tls-grpc-aead-udp,vmess-h2-aead-udp,vmess-tls-h2-aead-udp,vmess-quic-aead-udp,shadowsocks-aead,anytls-tls-tcp-uot-udp,mieru-tcp-udp,hy2-quic,tuic-quic"
    ));
    assert!(output.contains(
        "protocol_capabilities=trojan=tcp,udp;vless=tcp,udp;vmess=tcp,udp;shadowsocks=tcp,udp;anytls=tcp,udp;naive=tcp;mieru=tcp,udp;hy2=tcp,udp;tuic=tcp,udp;socks=tcp,udp;http=tcp"
    ));
}

#[test]
fn doctor_json_report_is_machine_readable() {
    let mut output = Vec::new();
    keli_cli::write_doctor_report_with_format(&mut output, keli_cli::ProbeOutputFormat::Json)
        .expect("write doctor json report");
    let report: serde_json::Value = serde_json::from_slice(&output).expect("doctor json");

    assert_eq!(report["status"], "ok");
    assert_eq!(report["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["platform"], "Windows");
    assert_eq!(report["system_proxy"]["supported"], true);
    assert_eq!(report["tun"], true);
    assert_eq!(report["tun_device"]["supported"], true);
    assert_eq!(report["tun_device"]["lifecycle_available"], false);
    assert_eq!(report["tun_device"]["packet_io_available"], false);
    assert_eq!(report["tun_device"]["running"], false);
    assert!(report["tun_device"]["interface_name"].is_null());
    assert_eq!(report["inbound"]["kind"], "mixed");
    assert_eq!(report["inbound"]["port"], 7890);
    assert_eq!(report["route_rule_capabilities"][0], "domain-suffix");
    assert_eq!(report["route_rule_capabilities"][3], "ip-cidr");
    assert_eq!(report["tun_packet_pipeline_capabilities"][0], "ipv4");
    assert_eq!(report["tun_packet_pipeline_capabilities"][4], "udp-payload");
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][8],
        "dns-query-plan"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][9],
        "dns-engine-response"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][10],
        "packet-process-action"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][11],
        "udp-response-packet"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][12],
        "dns-response-packet"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][13],
        "ipv4-fragment-guard"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][14],
        "ipv6-extension-traversal"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][15],
        "ipv6-extension-guard"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][16],
        "packet-loop"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][17],
        "packet-loop-summary"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][18],
        "managed-packet-loop"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][19],
        "direct-udp-relay"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][20],
        "outbound-udp-relay"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][21],
        "registry-udp-relay"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][22],
        "managed-registry-udp-relay"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][23],
        "listen-mixed-tun-runtime"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][24],
        "concurrent-tun-runtime"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][25],
        "background-runtime-report"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][26],
        "tun-runtime-status-note"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][27],
        "packet-io-readiness"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][28],
        "tcp-segment-parse"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][29],
        "tcp-response-packet"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][30],
        "tcp-reset-response"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][31],
        "tcp-syn-ack-response"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][32],
        "tcp-syn-retransmit-guard"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][33],
        "tcp-session-table"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][34],
        "tcp-client-payload-ack"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][35],
        "tcp-client-duplicate-ack"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][36],
        "tcp-client-out-of-order-ack"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][37],
        "tcp-client-overlap-ack"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][38],
        "tcp-client-stale-server-ack"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][39],
        "tcp-client-ack-keepalive"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][40],
        "tcp-server-payload-packet"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][41],
        "tcp-server-payload-retransmit"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][42],
        "tcp-server-payload-ack-clear"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][43],
        "tcp-server-mss-read-clamp"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][44],
        "tcp-session-step-runner"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][45],
        "tcp-session-device-loop"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][46],
        "tcp-server-payload-poll"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][47],
        "tcp-fin-close-ack"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][48],
        "tcp-fin-payload-close"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][49],
        "registry-tcp-fin-payload-close"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][50],
        "tcp-client-fin-half-close"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][51],
        "tcp-client-fin-stale-server-ack"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][52],
        "tcp-client-fin-server-payload-retransmit"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][53],
        "tcp-client-fin-server-payload-ack-clear"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][54],
        "tcp-client-fin-duplicate-poll"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][55],
        "tcp-client-fin-duplicate-payload-poll"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][56],
        "tcp-client-fin-payload-duplicate-poll"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][57],
        "tcp-client-fin-post-close-ack"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][58],
        "tcp-close-sequence-guard"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][59],
        "tcp-close-latest-ack-guard"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][60],
        "tcp-unknown-session-reset"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][61],
        "tcp-server-eof-fin-ack"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][62],
        "tcp-server-fin-retransmit"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][63],
        "tcp-server-fin-final-ack"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][64],
        "tcp-server-fin-client-fin-ack"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][65],
        "tcp-server-fin-post-close-guard"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][66],
        "tcp-session-idle-cleanup"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][67],
        "registry-tcp-session-relay"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][68],
        "combined-tun-relay-loop"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][69],
        "managed-registry-tcp-session-relay"
    );
    assert_eq!(
        report["tun_packet_pipeline_capabilities"][70],
        "tcp-relay-plan-summary"
    );
    assert_eq!(report["tun_packet_pipeline_capabilities"][71], "relay-plan");
    assert_eq!(report["dns_engine"]["resolver"], "system_resolver");
    assert_eq!(report["dns_engine"]["cache_ttl_seconds"], 60);
    assert_eq!(
        report["dns_engine"]["leak_prevention_policy_available"],
        true
    );
    assert_eq!(
        report["dns_engine"]["address_family_policy_available"],
        true
    );
    assert_eq!(
        report["dns_engine"]["default_local_resolution_policy"],
        "allow-system"
    );
    assert_eq!(
        report["dns_engine"]["default_address_family_policy"],
        "dual-stack"
    );
    assert_eq!(report["supported_outbounds"][0], "direct");
    assert_eq!(report["supported_udp_outbounds"][0], "direct");
    assert_eq!(report["sample_profile_valid"], true);
    assert_eq!(report["initial_phase"], "Idle");
}
