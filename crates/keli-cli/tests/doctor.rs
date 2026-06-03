#[test]
fn doctor_report_lists_supported_outbounds() {
    let mut output = Vec::new();
    keli_cli::write_doctor_report(&mut output).expect("write doctor report");
    let output = String::from_utf8(output).expect("doctor utf8");

    assert!(output.contains("version="));
    assert!(output.contains(
        "supported_outbounds=direct,trojan-tcp,trojan-ws,trojan-httpupgrade,vless-tcp,vless-ws,vless-httpupgrade,vmess-tcp,vmess-ws,vmess-httpupgrade,shadowsocks-tcp,anytls-tls-tcp,naive-h2-tcp,mieru-tcp,hy2-quic,tuic-quic"
    ));
    assert!(output.contains("supported_udp_outbounds=direct,shadowsocks-aead,hy2-quic,tuic-quic"));
}
