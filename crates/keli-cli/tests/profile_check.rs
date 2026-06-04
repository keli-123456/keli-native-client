use keli_cli::ProbeOutputFormat;
use serde_json::Value;

#[test]
fn profile_check_json_reports_supported_and_skipped_profiles() {
    let config = r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
  - name: VMESS-OLD
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
  - name: NAIVE-TLS
    type: naive
    server: naive.example.com
    port: 443
    username: user
    password: pass
    tls: true
    sni: edge.example.com
    skip-cert-verify: true
  - name: MIERU-TCP
    type: mieru
    server: mieru.example.com
    port-range: 30000-30002
    username: user
    password: pass
    transport: TCP
    udp: true
"#;
    let mut output = Vec::new();

    keli_cli::write_profile_check_report_from_subscription_config_text(
        config,
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect("profile check");

    let report: serde_json::Value = serde_json::from_slice(&output).expect("json report");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["supported_count"], 4);
    assert_eq!(report["skipped_count"], 0);
    assert_eq!(report["default_outbound"], "SS-READY");
    assert_eq!(report["udp_supported_count"], 3);
    assert_eq!(report["supported_tags"][0], "SS-READY");
    assert_eq!(report["supported_tags"][1], "VMESS-OLD");
    assert_eq!(report["supported_tags"][2], "NAIVE-TLS");
    assert_eq!(report["supported_tags"][3], "MIERU-TCP");
    assert_eq!(report["udp_supported_tags"][0], "SS-READY");
    assert_eq!(report["udp_supported_tags"][1], "VMESS-OLD");
    assert_eq!(report["udp_supported_tags"][2], "MIERU-TCP");
    assert_eq!(report["supported"][0]["udp_supported"], true);
    assert_eq!(report["supported"][1]["udp_supported"], true);
    assert_eq!(report["supported"][2]["protocol"], "Naive");
    assert_eq!(report["supported"][2]["udp_supported"], false);
    assert_eq!(report["supported"][3]["protocol"], "Mieru");
    assert_eq!(report["supported"][3]["udp_supported"], true);
}

#[test]
fn profile_check_text_reports_protocol_capability_matrix() {
    let config = r#"
proxies:
  - name: NAIVE-TLS
    type: naive
    server: naive.example.com
    port: 443
    username: user
    password: pass
    tls: true
    sni: edge.example.com
  - name: MIERU-TCP
    type: mieru
    server: mieru.example.com
    port-range: 30000-30002
    username: user
    password: pass
    transport: TCP
    udp: true
"#;
    let mut output = Vec::new();

    keli_cli::write_profile_check_report_from_subscription_config_text(
        config,
        ProbeOutputFormat::Text,
        &mut output,
    )
    .expect("profile check");

    let output = String::from_utf8(output).expect("utf8 output");
    assert!(output.contains(
        "profile status=ok source_format=mihomo_yaml supported=2 skipped=0 default_outbound=NAIVE-TLS registry_error=- udp_supported=1 protocol_capabilities=2"
    ));
    assert!(output.contains(
        "profile capability protocol=Naive tcp_relay_supported=true udp_supported=false tags=NAIVE-TLS"
    ));
    assert!(output.contains(
        "profile capability protocol=Mieru tcp_relay_supported=true udp_supported=true tags=MIERU-TCP"
    ));
}

#[test]
fn profile_check_json_reports_share_link_source_format() {
    let links = "ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#ss-ready";
    let mut output = Vec::new();

    keli_cli::write_profile_check_report_from_subscription_config_text(
        links,
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect("profile check");

    let report: Value = serde_json::from_slice(&output).expect("json report");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["source_format"], "share_links");
    assert_eq!(report["supported_count"], 1);
    assert_eq!(report["protocol_capability_count"], 1);
    assert_eq!(
        protocol_capability(&report, "Shadowsocks")["udp_supported"],
        true
    );
}

#[test]
fn profile_check_json_groups_skipped_reasons() {
    let config = r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
  - name: WG-ONE
    type: wireguard
    server: wg1.example.com
    port: 51820
    password: ignored
  - name: WG-TWO
    type: wireguard
    server: wg2.example.com
    port: 51820
    password: ignored
"#;
    let mut output = Vec::new();

    keli_cli::write_profile_check_report_from_subscription_config_text(
        config,
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect("profile check");

    let report: Value = serde_json::from_slice(&output).expect("json report");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["supported_count"], 1);
    assert_eq!(report["skipped_count"], 2);
    assert_eq!(report["skipped_summary_count"], 1);
    assert_eq!(
        report["skipped_summary"][0]["reason"],
        "unsupported protocol: wireguard"
    );
    assert_eq!(report["skipped_summary"][0]["count"], 2);
    assert_eq!(report["skipped_summary"][0]["names"][0], "WG-ONE");
    assert_eq!(report["skipped_summary"][0]["names"][1], "WG-TWO");
}

#[test]
fn profile_check_text_groups_skipped_reasons() {
    let config = r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
  - name: WG-ONE
    type: wireguard
    server: wg1.example.com
    port: 51820
    password: ignored
  - name: WG-TWO
    type: wireguard
    server: wg2.example.com
    port: 51820
    password: ignored
"#;
    let mut output = Vec::new();

    keli_cli::write_profile_check_report_from_subscription_config_text(
        config,
        ProbeOutputFormat::Text,
        &mut output,
    )
    .expect("profile check");

    let output = String::from_utf8(output).expect("utf8 output");
    assert!(output.contains(
        "profile skipped_summary count=2 names=WG-ONE,WG-TWO reason=unsupported protocol: wireguard"
    ));
}

#[test]
fn profile_check_json_reports_protocol_capability_matrix() {
    let config = r#"
proxies:
  - name: TROJAN-WS
    type: trojan
    server: trojan.example.com
    port: 443
    password: password
    sni: sni.example.com
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /answer
  - name: VLESS-WS
    type: vless
    server: vless.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    tls: true
    servername: sni.example.com
    network: ws
    ws-opts:
      path: /vless
  - name: VMESS-TCP
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    alterId: 0
    cipher: none
  - name: SS-AEAD
    type: ss
    server: ss.example.com
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: secret
  - name: ANYTLS
    type: anytls
    server: anytls.example.com
    port: 443
    password: secret
    sni: sni.example.com
    skip-cert-verify: true
  - name: NAIVE-TLS
    type: naive
    server: naive.example.com
    port: 443
    username: user
    password: pass
    tls: true
    sni: edge.example.com
  - name: MIERU-TCP
    type: mieru
    server: mieru.example.com
    port-range: 30000-30002
    username: user
    password: pass
    transport: TCP
    udp: true
  - name: HY2
    type: hy2
    server: hy2.example.com
    port: 443
    password: secret
    sni: sni.example.com
    skip-cert-verify: true
  - name: TUIC
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    token: secret
  - name: SOCKS5
    type: socks5
    server: socks.example.com
    port: 1080
    username: user
    password: pass
  - name: HTTP
    type: http
    server: http.example.com
    port: 8080
    username: user
    password: pass
"#;
    let mut output = Vec::new();

    keli_cli::write_profile_check_report_from_subscription_config_text(
        config,
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect("profile check");

    let report: Value = serde_json::from_slice(&output).expect("json report");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["supported_count"], 11);
    assert_eq!(report["protocol_capability_count"], 11);
    assert_eq!(
        protocol_capability(&report, "Trojan")["tags"][0],
        "TROJAN-WS"
    );
    assert_eq!(
        protocol_capability(&report, "Trojan")["tcp_relay_supported"],
        true
    );
    assert_eq!(
        protocol_capability(&report, "Trojan")["udp_supported"],
        true
    );
    for protocol in [
        "Vless",
        "Vmess",
        "Shadowsocks",
        "AnyTls",
        "Mieru",
        "Hy2",
        "Tuic",
        "Socks",
    ] {
        assert_eq!(
            protocol_capability(&report, protocol)["udp_supported"],
            true
        );
    }
    assert_eq!(
        protocol_capability(&report, "Naive")["tcp_relay_supported"],
        true
    );
    assert_eq!(
        protocol_capability(&report, "Naive")["udp_supported"],
        false
    );
    assert_eq!(
        protocol_capability(&report, "Http")["tcp_relay_supported"],
        true
    );
    assert_eq!(protocol_capability(&report, "Http")["udp_supported"], false);
}

#[test]
fn profile_check_json_keeps_full_core_protocol_transport_matrix_supported() {
    let config = r#"
proxies:
  - name: TROJAN-TCP
    type: trojan
    server: trojan.example.com
    port: 443
    password: password
    sni: sni.example.com
  - name: TROJAN-WS
    type: trojan
    server: trojan.example.com
    port: 443
    password: password
    sni: sni.example.com
    network: ws
    ws-opts:
      path: /answer
      headers:
        Host: host.example.com
  - name: TROJAN-HTTPUPGRADE
    type: trojan
    server: trojan.example.com
    port: 443
    password: password
    sni: sni.example.com
    network: httpupgrade
    httpupgrade-opts:
      path: /upgrade
      host: host.example.com
  - name: TROJAN-GRPC
    type: trojan
    server: trojan.example.com
    port: 443
    password: password
    sni: sni.example.com
    network: grpc
    grpc-opts:
      grpc-service-name: GunService
  - name: TROJAN-H2
    type: trojan
    server: trojan.example.com
    port: 443
    password: password
    sni: sni.example.com
    network: h2
    h2-opts:
      path: /h2
      host:
        - host.example.com
  - name: TROJAN-QUIC
    type: trojan
    server: trojan.example.com
    port: 443
    password: password
    sni: sni.example.com
    network: quic
    quic-opts:
      security: aes-128-gcm
      key: secret
      header: none
  - name: VLESS-TCP
    type: vless
    server: vless.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    tls: true
    servername: sni.example.com
  - name: VLESS-WS
    type: vless
    server: vless.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    tls: true
    servername: sni.example.com
    network: ws
    ws-opts:
      path: /vless
      headers:
        Host: host.example.com
  - name: VLESS-HTTPUPGRADE
    type: vless
    server: vless.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    tls: true
    servername: sni.example.com
    network: httpupgrade
    httpupgrade-opts:
      path: /upgrade
      host: host.example.com
  - name: VLESS-GRPC
    type: vless
    server: vless.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    tls: true
    servername: sni.example.com
    network: grpc
    grpc-opts:
      grpc-service-name: GunService
  - name: VLESS-H2
    type: vless
    server: vless.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    tls: true
    servername: sni.example.com
    network: h2
    h2-opts:
      path: /h2
      host:
        - host.example.com
  - name: VLESS-QUIC
    type: vless
    server: vless.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    tls: true
    servername: sni.example.com
    network: quic
    quic-opts:
      security: aes-128-gcm
      key: secret
      header: none
  - name: VMESS-TCP
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    alterId: 0
    cipher: auto
  - name: VMESS-WS
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    alterId: 0
    cipher: auto
    tls: true
    servername: sni.example.com
    network: ws
    ws-opts:
      path: /vmess
      headers:
        Host: host.example.com
  - name: VMESS-HTTPUPGRADE
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    alterId: 0
    cipher: auto
    tls: true
    servername: sni.example.com
    network: httpupgrade
    httpupgrade-opts:
      path: /upgrade
      host: host.example.com
  - name: VMESS-GRPC
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    alterId: 0
    cipher: auto
    tls: true
    servername: sni.example.com
    network: grpc
    grpc-opts:
      grpc-service-name: GunService
  - name: VMESS-H2
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    alterId: 0
    cipher: auto
    tls: true
    servername: sni.example.com
    network: h2
    h2-opts:
      path: /h2
      host:
        - host.example.com
  - name: VMESS-QUIC
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    alterId: 0
    cipher: auto
    tls: true
    servername: sni.example.com
    network: quic
    quic-opts:
      security: aes-128-gcm
      key: secret
      header: none
  - name: SS-AEAD
    type: ss
    server: ss.example.com
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: secret
  - name: ANYTLS
    type: anytls
    server: anytls.example.com
    port: 443
    password: secret
    sni: sni.example.com
    skip-cert-verify: true
  - name: NAIVE-H2
    type: naive
    server: naive.example.com
    port: 443
    username: user
    password: pass
    tls: true
    sni: edge.example.com
  - name: MIERU-TCP
    type: mieru
    server: mieru.example.com
    port-range: 30000-30002
    username: user
    password: pass
    transport: TCP
    udp: true
  - name: HY2
    type: hy2
    server: hy2.example.com
    port: 443
    password: secret
    sni: sni.example.com
    skip-cert-verify: true
  - name: TUIC
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    token: secret
  - name: SOCKS5
    type: socks5
    server: socks.example.com
    port: 1080
    username: user
    password: pass
  - name: HTTP
    type: http
    server: http.example.com
    port: 8080
    username: user
    password: pass
"#;
    let mut output = Vec::new();

    keli_cli::write_profile_check_report_from_subscription_config_text(
        config,
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect("profile check");

    let report: Value = serde_json::from_slice(&output).expect("json report");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["source_format"], "mihomo_yaml");
    assert_eq!(report["supported_count"], 26);
    assert_eq!(report["skipped_count"], 0);
    assert_eq!(report["udp_supported_count"], 24);
    assert_eq!(report["protocol_capability_count"], 11);

    let supported_tags = report["supported_tags"]
        .as_array()
        .expect("supported tags")
        .iter()
        .map(|tag| tag.as_str().expect("supported tag string"))
        .collect::<Vec<_>>();
    for expected in [
        "TROJAN-TCP",
        "TROJAN-WS",
        "TROJAN-HTTPUPGRADE",
        "TROJAN-GRPC",
        "TROJAN-H2",
        "TROJAN-QUIC",
        "VLESS-TCP",
        "VLESS-WS",
        "VLESS-HTTPUPGRADE",
        "VLESS-GRPC",
        "VLESS-H2",
        "VLESS-QUIC",
        "VMESS-TCP",
        "VMESS-WS",
        "VMESS-HTTPUPGRADE",
        "VMESS-GRPC",
        "VMESS-H2",
        "VMESS-QUIC",
        "SS-AEAD",
        "ANYTLS",
        "NAIVE-H2",
        "MIERU-TCP",
        "HY2",
        "TUIC",
        "SOCKS5",
        "HTTP",
    ] {
        assert!(
            supported_tags.contains(&expected),
            "missing supported tag {expected}"
        );
    }

    for protocol in ["Trojan", "Vless", "Vmess"] {
        let capability = protocol_capability(&report, protocol);
        assert_eq!(capability["udp_supported"], true);
        assert_eq!(capability["tags"].as_array().expect("tags").len(), 6);
    }
    for protocol in ["Shadowsocks", "AnyTls", "Mieru", "Hy2", "Tuic", "Socks"] {
        assert_eq!(
            protocol_capability(&report, protocol)["udp_supported"],
            true
        );
    }
    for protocol in ["Naive", "Http"] {
        assert_eq!(
            protocol_capability(&report, protocol)["tcp_relay_supported"],
            true
        );
        assert_eq!(
            protocol_capability(&report, protocol)["udp_supported"],
            false
        );
    }
}

#[test]
fn profile_check_json_keeps_full_share_link_transport_matrix_supported() {
    let links = r#"
trojan://password@trojan.example.com:443?security=tls&sni=sni.example.com&type=tcp#TROJAN-TCP
trojan://password@trojan.example.com:443?security=tls&sni=sni.example.com&type=ws&host=host.example.com&path=%2Fanswer#TROJAN-WS
trojan://password@trojan.example.com:443?security=tls&sni=sni.example.com&type=httpupgrade&host=host.example.com&path=%2Fupgrade#TROJAN-HTTPUPGRADE
trojan://password@trojan.example.com:443?security=tls&sni=sni.example.com&type=grpc&serviceName=GunService#TROJAN-GRPC
trojan://password@trojan.example.com:443?security=tls&sni=sni.example.com&type=h2&host=host.example.com&path=%2Fh2#TROJAN-H2
trojan://password@trojan.example.com:443?security=tls&sni=sni.example.com&type=quic&quicSecurity=aes-128-gcm&key=secret&headerType=none#TROJAN-QUIC
vless://00112233-4455-6677-8899-aabbccddeeff@vless.example.com:443?security=tls&sni=sni.example.com&type=tcp#VLESS-TCP
vless://00112233-4455-6677-8899-aabbccddeeff@vless.example.com:443?security=tls&sni=sni.example.com&type=ws&host=host.example.com&path=%2Fvless#VLESS-WS
vless://00112233-4455-6677-8899-aabbccddeeff@vless.example.com:443?security=tls&sni=sni.example.com&type=httpupgrade&host=host.example.com&path=%2Fupgrade#VLESS-HTTPUPGRADE
vless://00112233-4455-6677-8899-aabbccddeeff@vless.example.com:443?security=tls&sni=sni.example.com&type=grpc&serviceName=GunService#VLESS-GRPC
vless://00112233-4455-6677-8899-aabbccddeeff@vless.example.com:443?security=tls&sni=sni.example.com&type=h2&host=host.example.com&path=%2Fh2#VLESS-H2
vless://00112233-4455-6677-8899-aabbccddeeff@vless.example.com:443?security=tls&sni=sni.example.com&type=quic&quicSecurity=aes-128-gcm&key=secret&headerType=none#VLESS-QUIC
vmess://00112233-4455-6677-8899-aabbccddeeff@vmess.example.com:443?security=none&type=tcp&cipher=auto#VMESS-TCP
vmess://00112233-4455-6677-8899-aabbccddeeff@vmess.example.com:443?security=tls&sni=sni.example.com&type=ws&host=host.example.com&path=%2Fvmess&cipher=auto#VMESS-WS
vmess://00112233-4455-6677-8899-aabbccddeeff@vmess.example.com:443?security=tls&sni=sni.example.com&type=httpupgrade&host=host.example.com&path=%2Fupgrade&cipher=auto#VMESS-HTTPUPGRADE
vmess://00112233-4455-6677-8899-aabbccddeeff@vmess.example.com:443?security=tls&sni=sni.example.com&type=grpc&serviceName=GunService&cipher=auto#VMESS-GRPC
vmess://00112233-4455-6677-8899-aabbccddeeff@vmess.example.com:443?security=tls&sni=sni.example.com&type=h2&host=host.example.com&path=%2Fh2&cipher=auto#VMESS-H2
vmess://00112233-4455-6677-8899-aabbccddeeff@vmess.example.com:443?security=tls&sni=sni.example.com&type=quic&quicSecurity=aes-128-gcm&key=secret&headerType=none&cipher=auto#VMESS-QUIC
ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#SS-AEAD
anytls://secret@anytls.example.com:443?sni=sni.example.com&allowInsecure=1#ANYTLS
naive://user:pass@naive.example.com:443?security=tls&sni=edge.example.com#NAIVE-H2
mierus://user:pass@mieru.example.com?profile=MIERU-TCP&multiplexing=MULTIPLEXING_LOW&port=30000-30002&protocol=TCP
hysteria2://secret@hy2.example.com:443/?insecure=1&sni=sni.example.com#HY2
tuic://00112233-4455-6677-8899-aabbccddeeff:secret@tuic.example.com:443#TUIC
socks://user:pass@socks.example.com:1080#SOCKS5
http://user:pass@http.example.com:8080#HTTP
"#;
    let mut output = Vec::new();

    keli_cli::write_profile_check_report_from_subscription_config_text(
        links,
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect("profile check");

    let report: Value = serde_json::from_slice(&output).expect("json report");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["source_format"], "share_links");
    assert_eq!(report["supported_count"], 26);
    assert_eq!(report["skipped_count"], 0);
    assert_eq!(report["udp_supported_count"], 24);
    assert_eq!(report["protocol_capability_count"], 11);

    for protocol in ["Trojan", "Vless", "Vmess"] {
        let capability = protocol_capability(&report, protocol);
        assert_eq!(capability["udp_supported"], true);
        assert_eq!(capability["tags"].as_array().expect("tags").len(), 6);
    }
    for protocol in ["Shadowsocks", "AnyTls", "Mieru", "Hy2", "Tuic", "Socks"] {
        assert_eq!(
            protocol_capability(&report, protocol)["udp_supported"],
            true
        );
    }
    for protocol in ["Naive", "Http"] {
        assert_eq!(
            protocol_capability(&report, protocol)["tcp_relay_supported"],
            true
        );
        assert_eq!(
            protocol_capability(&report, protocol)["udp_supported"],
            false
        );
    }
}

fn protocol_capability<'a>(report: &'a Value, protocol: &str) -> &'a Value {
    report["protocol_capabilities"]
        .as_array()
        .expect("protocol capabilities array")
        .iter()
        .find(|capability| capability["protocol"] == protocol)
        .expect("protocol capability")
}
