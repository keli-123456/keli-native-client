use keli_protocol::{
    parse_share_outbound_profiles, Endpoint, ProxyProtocol, SecurityKind, TransportKind,
};

#[test]
fn parses_vless_ws_tls_share_link() {
    let links = "vless://00112233-4455-6677-8899-aabbccddeeff@example.com:443?security=tls&sni=edge.example&type=ws&host=host.example&path=%2Fvless&flow=xtls-rprx-vision#vless-ws";

    let parsed = parse_share_outbound_profiles(links).expect("parse share links");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "vless-ws");
    assert_eq!(profile.protocol, ProxyProtocol::Vless);
    assert_eq!(profile.endpoint, Endpoint::new("example.com", 443));
    assert_eq!(
        profile.transport,
        TransportKind::WebSocket {
            path: "/vless".to_string(),
            host: Some("host.example".to_string()),
        }
    );
    assert_eq!(
        profile.security,
        SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: false,
        }
    );
    assert_eq!(profile.credential, "00112233-4455-6677-8899-aabbccddeeff");
    assert_eq!(profile.flow, Some("xtls-rprx-vision".to_string()));
}

#[test]
fn parses_base64_trojan_ws_tls_share_link() {
    let base64_links = "dHJvamFuOi8vcGFzc3dvcmRAZXhhbXBsZS5jb206NDQzP3NlY3VyaXR5PXRscyZzbmk9ZWRnZS5leGFtcGxlJnR5cGU9d3MmaG9zdD1lZGdlLmV4YW1wbGUmcGF0aD0lMkZhbnN3ZXImYWxsb3dJbnNlY3VyZT0xI3Ryb2phbi13cw==";

    let parsed = parse_share_outbound_profiles(base64_links).expect("parse share links");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "trojan-ws");
    assert_eq!(profile.protocol, ProxyProtocol::Trojan);
    assert_eq!(profile.endpoint, Endpoint::new("example.com", 443));
    assert_eq!(
        profile.transport,
        TransportKind::WebSocket {
            path: "/answer".to_string(),
            host: Some("edge.example".to_string()),
        }
    );
    assert_eq!(
        profile.security,
        SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: true,
        }
    );
    assert_eq!(profile.credential, "password");
    assert_eq!(profile.flow, None);
}

#[test]
fn parses_shadowsocks_share_link() {
    let links = "ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#ss-aead";

    let parsed = parse_share_outbound_profiles(links).expect("parse share links");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "ss-aead");
    assert_eq!(profile.protocol, ProxyProtocol::Shadowsocks);
    assert_eq!(profile.endpoint, Endpoint::new("ss.example.com", 8388));
    assert_eq!(profile.transport, TransportKind::Tcp);
    assert_eq!(profile.security, SecurityKind::None);
    assert_eq!(profile.credential, "secret");
    assert_eq!(profile.cipher, Some("aes-256-gcm".to_string()));
}

#[test]
fn parses_anytls_share_link() {
    let links = "anytls://secret@anytls.example.com:443?sni=sni.example.com&allowInsecure=1#anytls";

    let parsed = parse_share_outbound_profiles(links).expect("parse share links");

    assert!(parsed.skipped.is_empty());
    assert_eq!(parsed.profiles.len(), 1);
    let profile = &parsed.profiles[0];
    assert_eq!(profile.tag, "anytls");
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
    assert_eq!(profile.cipher, None);
}

#[test]
fn parses_hy2_and_tuic_share_links() {
    let links = "\
hysteria2://secret@hy2.example.com:443/?insecure=1&sni=sni.example.com#hy2
tuic://00112233-4455-6677-8899-aabbccddeeff:secret@tuic.example.com:443#tuic
vless://00112233-4455-6677-8899-aabbccddeeff@example.com:443?security=tls#vless";

    let parsed = parse_share_outbound_profiles(links).expect("parse share links");

    assert_eq!(parsed.profiles.len(), 3);
    let hy2 = &parsed.profiles[0];
    assert_eq!(hy2.tag, "hy2");
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
    assert_eq!(tuic.tag, "tuic");
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
    assert_eq!(parsed.profiles[2].tag, "vless");
    assert!(parsed.skipped.is_empty());
}
