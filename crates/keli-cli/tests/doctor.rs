#[test]
fn doctor_report_lists_supported_outbounds() {
    let mut output = Vec::new();
    keli_cli::write_doctor_report(&mut output).expect("write doctor report");
    let output = String::from_utf8(output).expect("doctor utf8");

    assert!(output.contains("version="));
    assert!(output.contains(
        "supported_outbounds=direct,trojan-tcp,trojan-ws,vless-tcp,vless-ws,shadowsocks-tcp,anytls-tls-tcp,hy2-quic,tuic-quic"
    ));
}
