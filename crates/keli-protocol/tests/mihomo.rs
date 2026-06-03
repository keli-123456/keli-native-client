use keli_protocol::{
    parse_mihomo_outbound_profiles, Endpoint, ProxyProtocol, SecurityKind, TransportKind,
};

#[test]
fn parses_trojan_ws_tls_proxy_from_mihomo_yaml() {
    let yaml = r#"
proxies:
  - name: 美国-TROJAN-54
    type: trojan
    server: 123.dnscloudcloud.top
    port: 443
    password: 0b700559-6e2a-493a-acca-fdea6190ce07
    udp: true
    skip-cert-verify: false
    sni: 675441.123903.xyz
    network: ws
    ws-opts:
      path: /answer
      headers:
        Host: 675441.123903.xyz
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "美国-TROJAN-54");
    assert_eq!(profile.protocol, ProxyProtocol::Trojan);
    assert_eq!(
        profile.endpoint,
        Endpoint::new("123.dnscloudcloud.top", 443)
    );
    assert_eq!(
        profile.transport,
        TransportKind::WebSocket {
            path: "/answer".to_string(),
            host: Some("675441.123903.xyz".to_string()),
        }
    );
    assert_eq!(
        profile.security,
        SecurityKind::Tls {
            sni: Some("675441.123903.xyz".to_string()),
            skip_verify: false,
        }
    );
    assert_eq!(profile.credential, "0b700559-6e2a-493a-acca-fdea6190ce07");
    profile.validate().expect("valid profile");
}

#[test]
fn parses_vless_ws_tls_proxy_from_mihomo_yaml() {
    let yaml = r#"
proxies:
  - name: 德国-VLESS-21
    type: vless
    server: edge.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    tls: true
    servername: sni.example.com
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vless
      headers:
        host: host.example.com
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "德国-VLESS-21");
    assert_eq!(profile.protocol, ProxyProtocol::Vless);
    assert_eq!(profile.endpoint, Endpoint::new("edge.example.com", 443));
    assert_eq!(
        profile.transport,
        TransportKind::WebSocket {
            path: "/vless".to_string(),
            host: Some("host.example.com".to_string()),
        }
    );
    assert_eq!(
        profile.security,
        SecurityKind::Tls {
            sni: Some("sni.example.com".to_string()),
            skip_verify: true,
        }
    );
    assert_eq!(profile.credential, "00112233-4455-6677-8899-aabbccddeeff");
    assert_eq!(profile.flow, None);
    profile.validate().expect("valid profile");
}

#[test]
fn parses_vless_httpupgrade_tls_proxy_from_mihomo_yaml() {
    let yaml = r#"
proxies:
  - name: VLESS-HTTPUpgrade
    type: vless
    server: edge.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    tls: true
    servername: sni.example.com
    skip-cert-verify: true
    network: httpupgrade
    httpupgrade-opts:
      path: /upgrade
      host: host.example.com
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "VLESS-HTTPUpgrade");
    assert_eq!(profile.protocol, ProxyProtocol::Vless);
    assert_eq!(profile.endpoint, Endpoint::new("edge.example.com", 443));
    assert_eq!(
        profile.transport,
        TransportKind::HttpUpgrade {
            path: "/upgrade".to_string(),
            host: Some("host.example.com".to_string()),
        }
    );
    assert_eq!(
        profile.security,
        SecurityKind::Tls {
            sni: Some("sni.example.com".to_string()),
            skip_verify: true,
        }
    );
    assert_eq!(profile.credential, "00112233-4455-6677-8899-aabbccddeeff");
    profile.validate().expect("valid httpupgrade profile");
}

#[test]
fn parses_vless_grpc_tls_proxy_from_mihomo_yaml() {
    let yaml = r#"
proxies:
  - name: VLESS-gRPC
    type: vless
    server: edge.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    tls: true
    servername: sni.example.com
    skip-cert-verify: true
    network: grpc
    grpc-opts:
      grpc-service-name: GunService
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "VLESS-gRPC");
    assert_eq!(profile.protocol, ProxyProtocol::Vless);
    assert_eq!(profile.endpoint, Endpoint::new("edge.example.com", 443));
    assert_eq!(
        profile.transport,
        TransportKind::Grpc {
            service_name: Some("GunService".to_string()),
        }
    );
    assert_eq!(
        profile.security,
        SecurityKind::Tls {
            sni: Some("sni.example.com".to_string()),
            skip_verify: true,
        }
    );
    assert_eq!(profile.credential, "00112233-4455-6677-8899-aabbccddeeff");
    profile.validate().expect("valid grpc profile");
}

#[test]
fn parses_vless_h2_tls_proxy_from_mihomo_yaml() {
    let yaml = r#"
proxies:
  - name: VLESS-H2
    type: vless
    server: edge.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    tls: true
    servername: sni.example.com
    skip-cert-verify: true
    network: h2
    h2-opts:
      path: /h2
      host:
        - host.example.com
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "VLESS-H2");
    assert_eq!(profile.protocol, ProxyProtocol::Vless);
    assert_eq!(profile.endpoint, Endpoint::new("edge.example.com", 443));
    assert_eq!(
        profile.transport,
        TransportKind::Http2 {
            path: "/h2".to_string(),
            host: Some("host.example.com".to_string()),
        }
    );
    assert_eq!(
        profile.security,
        SecurityKind::Tls {
            sni: Some("sni.example.com".to_string()),
            skip_verify: true,
        }
    );
    assert_eq!(profile.credential, "00112233-4455-6677-8899-aabbccddeeff");
    profile.validate().expect("valid h2 profile");
}

#[test]
fn parses_trojan_grpc_tls_proxy_from_mihomo_yaml() {
    let yaml = r#"
proxies:
  - name: TROJAN-gRPC
    type: trojan
    server: trojan.example.com
    port: 443
    password: password
    sni: sni.example.com
    skip-cert-verify: true
    network: grpc
    grpc-opts:
      grpc-service-name: GunService
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "TROJAN-gRPC");
    assert_eq!(profile.protocol, ProxyProtocol::Trojan);
    assert_eq!(profile.endpoint, Endpoint::new("trojan.example.com", 443));
    assert_eq!(
        profile.transport,
        TransportKind::Grpc {
            service_name: Some("GunService".to_string()),
        }
    );
    assert_eq!(
        profile.security,
        SecurityKind::Tls {
            sni: Some("sni.example.com".to_string()),
            skip_verify: true,
        }
    );
    assert_eq!(profile.credential, "password");
    profile.validate().expect("valid trojan grpc profile");
}

#[test]
fn parses_vmess_grpc_tls_proxy_from_mihomo_yaml() {
    let yaml = r#"
proxies:
  - name: VMess-gRPC
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    cipher: none
    tls: true
    servername: sni.example.com
    skip-cert-verify: true
    network: grpc
    grpc-opts:
      serviceName: GunService
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "VMess-gRPC");
    assert_eq!(profile.protocol, ProxyProtocol::Vmess);
    assert_eq!(profile.endpoint, Endpoint::new("vmess.example.com", 443));
    assert_eq!(
        profile.transport,
        TransportKind::Grpc {
            service_name: Some("GunService".to_string()),
        }
    );
    assert_eq!(
        profile.security,
        SecurityKind::Tls {
            sni: Some("sni.example.com".to_string()),
            skip_verify: true,
        }
    );
    assert_eq!(profile.credential, "00112233-4455-6677-8899-aabbccddeeff");
    assert_eq!(profile.cipher, Some("none".to_string()));
    profile.validate().expect("valid vmess grpc profile");
}

#[test]
fn parses_vmess_tcp_proxy_from_mihomo_yaml() {
    let yaml = r#"
proxies:
  - name: VMess-TCP
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    alterId: 0
    cipher: none
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "VMess-TCP");
    assert_eq!(profile.protocol, ProxyProtocol::Vmess);
    assert_eq!(profile.endpoint, Endpoint::new("vmess.example.com", 443));
    assert_eq!(profile.transport, TransportKind::Tcp);
    assert_eq!(profile.security, SecurityKind::None);
    assert_eq!(profile.credential, "00112233-4455-6677-8899-aabbccddeeff");
    assert_eq!(profile.cipher, Some("none".to_string()));
    profile.validate().expect("valid profile");
}

#[test]
fn parses_vmess_ws_tls_proxy_from_mihomo_yaml() {
    let yaml = r#"
proxies:
  - name: VMess-WS
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    alterId: 0
    cipher: auto
    tls: true
    servername: edge.example.com
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vmess
      headers:
        Host: host.example.com
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "VMess-WS");
    assert_eq!(profile.protocol, ProxyProtocol::Vmess);
    assert_eq!(profile.endpoint, Endpoint::new("vmess.example.com", 443));
    assert_eq!(
        profile.transport,
        TransportKind::WebSocket {
            path: "/vmess".to_string(),
            host: Some("host.example.com".to_string()),
        }
    );
    assert_eq!(
        profile.security,
        SecurityKind::Tls {
            sni: Some("edge.example.com".to_string()),
            skip_verify: true,
        }
    );
    assert_eq!(profile.credential, "00112233-4455-6677-8899-aabbccddeeff");
    assert_eq!(profile.cipher, Some("auto".to_string()));
    profile.validate().expect("valid vmess ws tls profile");
}

#[test]
fn parses_naive_tcp_tls_proxy_from_mihomo_yaml() {
    let yaml = r#"
proxies:
  - name: Naive-TLS
    type: naive
    server: naive.example.com
    port: 443
    username: user
    password: pass
    tls: true
    sni: edge.example.com
    skip-cert-verify: true
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "Naive-TLS");
    assert_eq!(profile.protocol, ProxyProtocol::Naive);
    assert_eq!(profile.endpoint, Endpoint::new("naive.example.com", 443));
    assert_eq!(profile.transport, TransportKind::Tcp);
    assert_eq!(
        profile.security,
        SecurityKind::Tls {
            sni: Some("edge.example.com".to_string()),
            skip_verify: true,
        }
    );
    assert_eq!(profile.credential, "user:pass");
    profile.validate().expect("valid profile");
}

#[test]
fn parses_mieru_tcp_proxy_with_port_range_from_mihomo_yaml() {
    let yaml = r#"
proxies:
  - name: Mieru-TCP
    type: mieru
    server: mieru.example.com
    port-range: 30000-30002
    username: user
    password: pass
    transport: TCP
    udp: true
    multiplexing: MULTIPLEXING_LOW
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "Mieru-TCP");
    assert_eq!(profile.protocol, ProxyProtocol::Mieru);
    assert_eq!(profile.endpoint, Endpoint::new("mieru.example.com", 30000));
    assert_eq!(profile.transport, TransportKind::Tcp);
    assert_eq!(profile.security, SecurityKind::None);
    assert_eq!(profile.credential, "user:pass");
    profile.validate().expect("valid mieru profile");
}

#[test]
fn parses_vless_flow_from_mihomo_yaml() {
    let yaml = r#"
proxies:
  - name: VLESS-Vision
    type: vless
    server: edge.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    tls: true
    flow: xtls-rprx-vision
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    assert_eq!(
        parsed.profiles[0].flow,
        Some("xtls-rprx-vision".to_string())
    );
}

#[test]
fn parses_shadowsocks_tcp_proxy_from_mihomo_yaml() {
    let yaml = r#"
proxies:
  - name: SS-AEAD
    type: ss
    server: ss.example.com
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: secret
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "SS-AEAD");
    assert_eq!(profile.protocol, ProxyProtocol::Shadowsocks);
    assert_eq!(profile.endpoint, Endpoint::new("ss.example.com", 8388));
    assert_eq!(profile.transport, TransportKind::Tcp);
    assert_eq!(profile.security, SecurityKind::None);
    assert_eq!(profile.credential, "secret");
    assert_eq!(profile.cipher, Some("chacha20-ietf-poly1305".to_string()));
    profile.validate().expect("valid profile");
}

#[test]
fn parses_anytls_tcp_tls_proxy_from_mihomo_yaml() {
    let yaml = r#"
proxies:
  - name: AnyTLS
    type: anytls
    server: anytls.example.com
    port: 443
    password: secret
    sni: sni.example.com
    skip-cert-verify: true
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "AnyTLS");
    assert_eq!(profile.protocol, ProxyProtocol::AnyTls);
    assert_eq!(profile.endpoint, Endpoint::new("anytls.example.com", 443));
    assert_eq!(profile.transport, TransportKind::Tcp);
    assert_eq!(
        profile.security,
        SecurityKind::Tls {
            sni: Some("sni.example.com".to_string()),
            skip_verify: true,
        }
    );
    assert_eq!(profile.credential, "secret");
    profile.validate().expect("valid profile");
}

#[test]
fn parses_hy2_and_tuic_quic_proxies_without_dropping_supported_entries() {
    let yaml = r#"
proxies:
  - name: hy2-ready
    type: hy2
    server: hy2.example.com
    port: 443
    password: secret
    sni: sni.example.com
    skip-cert-verify: true
  - name: tuic-not-yet
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    token: secret
  - name: tcp-vless
    type: vless
    server: vless.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
"#;

    let parsed = parse_mihomo_outbound_profiles(yaml).expect("parse subscription");

    assert_eq!(parsed.profiles.len(), 3);
    let hy2 = &parsed.profiles[0];
    assert_eq!(hy2.tag, "hy2-ready");
    assert_eq!(hy2.protocol, ProxyProtocol::Hy2);
    assert_eq!(hy2.endpoint, Endpoint::new("hy2.example.com", 443));
    assert_eq!(hy2.transport, TransportKind::Quic);
    assert_eq!(
        hy2.security,
        SecurityKind::Tls {
            sni: Some("sni.example.com".to_string()),
            skip_verify: true,
        }
    );
    assert_eq!(hy2.credential, "secret");
    hy2.validate().expect("valid hy2 profile");
    let tuic = &parsed.profiles[1];
    assert_eq!(tuic.tag, "tuic-not-yet");
    assert_eq!(tuic.protocol, ProxyProtocol::Tuic);
    assert_eq!(tuic.endpoint, Endpoint::new("tuic.example.com", 443));
    assert_eq!(tuic.transport, TransportKind::Quic);
    assert_eq!(
        tuic.security,
        SecurityKind::Tls {
            sni: Some("tuic.example.com".to_string()),
            skip_verify: false,
        }
    );
    assert_eq!(
        tuic.credential,
        "00112233-4455-6677-8899-aabbccddeeff:secret"
    );
    tuic.validate().expect("valid tuic profile");
    assert_eq!(parsed.profiles[2].tag, "tcp-vless");
    assert!(parsed.skipped.is_empty());
}
