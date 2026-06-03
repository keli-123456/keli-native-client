use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use keli_cli::ProbeOutputFormat;
use keli_net_core::RouteAction;
use shadowsocks_crypto::kind::CipherKind;
use shadowsocks_crypto::v1::{openssl_bytes_to_key, Cipher};

#[test]
fn smoke_mixed_socks5_reports_selected_outbound_and_payload_round_trip() {
    let (ss_port, ss_thread) = spawn_shadowsocks_tcp_echo_server();
    let config = format!(
        r#"proxies:
  - name: SS-READY
    type: ss
    server: 127.0.0.1
    port: {ss_port}
    cipher: aes-256-gcm
    password: secret
"#
    );

    let report = keli_cli::smoke_mixed_socks5_connect_from_subscription_config_text(
        &config,
        Some("SS-READY".to_string()),
        "example.com:443",
        b"ping",
        b"pong",
        Duration::from_secs(2),
    )
    .expect("local mixed smoke");

    assert_eq!(report.inbound, "mixed-socks5-smoke");
    assert_eq!(report.target.host, "example.com");
    assert_eq!(report.target.port, 443);
    assert_eq!(
        report.route_action,
        RouteAction::Outbound("SS-READY".to_string())
    );
    assert_eq!(report.upload_bytes, 4);
    assert_eq!(report.download_bytes, 4);
    assert_eq!(report.error_kind, None);
    ss_thread.join().expect("ss thread");
}

#[test]
fn smoke_mixed_json_reports_machine_readable_success() {
    let (ss_port, ss_thread) = spawn_shadowsocks_tcp_echo_server();
    let config = format!(
        r#"proxies:
  - name: SS-READY
    type: ss
    server: 127.0.0.1
    port: {ss_port}
    cipher: aes-256-gcm
    password: secret
"#
    );
    let mut output = Vec::new();

    keli_cli::write_smoke_mixed_socks5_report_from_subscription_config_text(
        &config,
        Some("SS-READY".to_string()),
        "example.com:443",
        b"ping",
        b"pong",
        Duration::from_secs(2),
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect("local mixed smoke json");

    let report: serde_json::Value = serde_json::from_slice(&output).expect("json report");
    assert_eq!(report["status"], "ok");
    assert_eq!(report["inbound"], "mixed-socks5-smoke");
    assert_eq!(report["target"], "example.com:443");
    assert_eq!(report["route"], "outbound");
    assert_eq!(report["outbound_tag"], "SS-READY");
    assert_eq!(report["upload_bytes"], 4);
    assert_eq!(report["download_bytes"], 4);
    assert_eq!(report["error_kind"], serde_json::Value::Null);
    ss_thread.join().expect("ss thread");
}

fn spawn_shadowsocks_tcp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ss tcp server");
    let port = listener.local_addr().expect("ss tcp addr").port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept ss tcp server");
        let kind = CipherKind::from_str("aes-256-gcm").expect("cipher");
        let key = shadowsocks_key(kind, "secret");

        let mut client_salt = vec![0; kind.salt_len()];
        stream
            .read_exact(&mut client_salt)
            .expect("read client salt");
        let mut client_cipher = Cipher::new(kind, &key, &client_salt);
        let request_header = read_ss_chunk(&mut stream, &mut client_cipher);
        assert_eq!(request_header, b"\x03\x0bexample.com\x01\xbb");
        let payload = read_ss_chunk(&mut stream, &mut client_cipher);
        assert_eq!(&payload, b"ping");

        let server_salt = vec![7; kind.salt_len()];
        stream.write_all(&server_salt).expect("write server salt");
        let mut server_cipher = Cipher::new(kind, &key, &server_salt);
        write_ss_chunk(&mut stream, &mut server_cipher, b"pong");
    });
    (port, handle)
}

fn shadowsocks_key(kind: CipherKind, password: &str) -> Vec<u8> {
    let mut key = vec![0; kind.key_len()];
    openssl_bytes_to_key(password.as_bytes(), &mut key);
    key
}

fn read_ss_chunk(stream: &mut TcpStream, cipher: &mut Cipher) -> Vec<u8> {
    let mut encrypted_len = vec![0; 2 + cipher.tag_len()];
    stream
        .read_exact(&mut encrypted_len)
        .expect("read encrypted ss chunk length");
    assert!(cipher.decrypt_packet(&mut encrypted_len));
    encrypted_len.truncate(2);
    let len = u16::from_be_bytes([encrypted_len[0], encrypted_len[1]]) as usize;
    let mut encrypted_payload = vec![0; len + cipher.tag_len()];
    stream
        .read_exact(&mut encrypted_payload)
        .expect("read encrypted ss chunk payload");
    assert!(cipher.decrypt_packet(&mut encrypted_payload));
    encrypted_payload.truncate(len);
    encrypted_payload
}

fn write_ss_chunk(stream: &mut TcpStream, cipher: &mut Cipher, payload: &[u8]) {
    let tag_len = cipher.tag_len();
    let mut encrypted_len = vec![0; 2 + tag_len];
    encrypted_len[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    cipher.encrypt_packet(&mut encrypted_len);
    stream
        .write_all(&encrypted_len)
        .expect("write encrypted ss chunk length");
    let mut encrypted_payload = vec![0; payload.len() + tag_len];
    encrypted_payload[..payload.len()].copy_from_slice(payload);
    cipher.encrypt_packet(&mut encrypted_payload);
    stream
        .write_all(&encrypted_payload)
        .expect("write encrypted ss chunk payload");
}
