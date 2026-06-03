use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keli_cli::CliCommand;
use shadowsocks_crypto::kind::CipherKind;
use shadowsocks_crypto::v1::{openssl_bytes_to_key, Cipher};

#[test]
fn probe_outbound_reports_successful_payload_round_trip() {
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

    keli_cli::probe_outbound_from_subscription_config_text(
        &config,
        Some("SS-READY".to_string()),
        "example.com:443",
        b"ping",
        Some(b"pong"),
        Duration::from_secs(2),
        &mut output,
    )
    .expect("probe outbound");

    let output = String::from_utf8(output).expect("output utf8");
    assert!(output.contains("probe status=ok"));
    assert!(output.contains("target=example.com:443"));
    assert!(output.contains("route=Outbound(\"SS-READY\")"));
    assert!(output.contains("upload_bytes=4"));
    assert!(output.contains("download_bytes=4"));
    assert!(output.contains("error_kind=none"));
    ss_thread.join().expect("ss thread");
}

#[test]
fn run_probe_outbound_command_uses_profile_config_path() {
    let (ss_port, ss_thread) = spawn_shadowsocks_tcp_echo_server();
    let profile_path = write_temp_profile_config(ss_port);

    keli_cli::run(CliCommand::ProbeOutbound {
        profile_config: profile_path.clone(),
        outbound_tag: Some("SS-READY".to_string()),
        target: "example.com:443".to_string(),
        payload: Some("ping".to_string()),
        expect: Some("pong".to_string()),
        first_byte_timeout: Duration::from_secs(2),
    })
    .expect("run probe command");

    ss_thread.join().expect("ss thread");
    std::fs::remove_file(profile_path).ok();
}

fn write_temp_profile_config(ss_port: u16) -> String {
    let name = format!(
        "keli-native-client-probe-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: SS-READY
    type: ss
    server: 127.0.0.1
    port: {ss_port}
    cipher: aes-256-gcm
    password: secret
"#
    );
    std::fs::write(&path, content).expect("write profile config");
    path.to_string_lossy().into_owned()
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
