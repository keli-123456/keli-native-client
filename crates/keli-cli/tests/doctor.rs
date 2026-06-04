#[test]
fn doctor_report_lists_supported_outbounds() {
    let mut output = Vec::new();
    keli_cli::write_doctor_report(&mut output).expect("write doctor report");
    let output = String::from_utf8(output).expect("doctor utf8");

    assert!(output.contains("version="));
    assert!(output.contains(
        "supported_outbounds=direct,socks5-tcp,http-connect,trojan-tcp,trojan-ws,trojan-httpupgrade,trojan-grpc,trojan-h2,trojan-quic,vless-tcp,vless-ws,vless-httpupgrade,vless-grpc,vless-h2,vless-quic,vmess-tcp,vmess-ws,vmess-httpupgrade,vmess-grpc,vmess-h2,vmess-quic,shadowsocks-tcp,anytls-tls-tcp,naive-h2-tcp,naive-h3-quic,mieru-tcp,hy2-quic,tuic-quic"
    ));
    assert!(output.contains(
        "supported_udp_outbounds=direct,socks5-udp,vmess-tcp-aead-udp,vmess-tls-tcp-aead-udp,vmess-ws-aead-udp,vmess-tls-ws-aead-udp,vmess-httpupgrade-aead-udp,vmess-tls-httpupgrade-aead-udp,vmess-grpc-aead-udp,vmess-tls-grpc-aead-udp,vmess-h2-aead-udp,vmess-tls-h2-aead-udp,vmess-quic-aead-udp,shadowsocks-aead,hy2-quic,tuic-quic"
    ));
}
