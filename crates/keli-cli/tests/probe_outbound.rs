use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keli_cli::{CliCommand, ProbeOutputFormat};
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
        false,
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
        udp: false,
        output: ProbeOutputFormat::Text,
        first_byte_timeout: Duration::from_secs(2),
    })
    .expect("run probe command");

    ss_thread.join().expect("ss thread");
    std::fs::remove_file(profile_path).ok();
}

#[test]
fn probe_outbound_json_reports_machine_readable_success() {
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

    keli_cli::probe_outbound_from_subscription_config_text_with_format(
        &config,
        Some("SS-READY".to_string()),
        "example.com:443",
        b"ping",
        Some(b"pong"),
        false,
        Duration::from_secs(2),
        ProbeOutputFormat::Json,
        &mut output,
    )
    .expect("probe outbound");

    let output: serde_json::Value = serde_json::from_slice(&output).expect("json output");
    assert_eq!(output["status"], "ok");
    assert_eq!(output["inbound"], "probe-outbound");
    assert_eq!(output["target"], "example.com:443");
    assert_eq!(output["route"], "outbound");
    assert_eq!(output["outbound_tag"], "SS-READY");
    assert_eq!(output["upload_bytes"], 4);
    assert_eq!(output["download_bytes"], 4);
    assert_eq!(output["error_kind"], serde_json::Value::Null);
    ss_thread.join().expect("ss thread");
}

#[test]
fn probe_udp_outbound_reports_successful_payload_round_trip() {
    let (ss_port, ss_thread) = spawn_shadowsocks_udp_echo_server();
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
        "example.com:53",
        b"ping",
        Some(b"pong"),
        true,
        Duration::from_secs(2),
        &mut output,
    )
    .expect("probe UDP outbound");

    let output = String::from_utf8(output).expect("output utf8");
    assert!(output.contains("probe status=ok"));
    assert!(output.contains("inbound=probe-udp"));
    assert!(output.contains("target=example.com:53"));
    assert!(output.contains("route=Outbound(\"SS-READY\")"));
    assert!(output.contains("upload_bytes=4"));
    assert!(output.contains("download_bytes=4"));
    assert!(output.contains("error_kind=none"));
    ss_thread.join().expect("ss thread");
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

fn spawn_shadowsocks_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ss udp server");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("ss udp timeout");
    let port = socket.local_addr().expect("ss udp addr").port();
    let handle = thread::spawn(move || {
        let kind = CipherKind::from_str("aes-256-gcm").expect("cipher");
        let key = shadowsocks_key(kind, "secret");
        let mut request = [0; 1500];
        let (size, from) = socket.recv_from(&mut request).expect("read ss udp request");
        let plaintext = decrypt_ss_udp_packet(kind, &key, &request[..size]);
        assert_eq!(plaintext, b"\x03\x0bexample.com\x005ping");

        let salt = vec![9; kind.salt_len()];
        let response = encrypt_ss_udp_packet(kind, &key, &salt, b"\x01\x7f\x00\x00\x01\x005pong");
        socket
            .send_to(&response, from)
            .expect("write ss udp response");
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

fn decrypt_ss_udp_packet(kind: CipherKind, key: &[u8], packet: &[u8]) -> Vec<u8> {
    let salt_len = kind.salt_len();
    let tag_len = kind.tag_len();
    let (salt, payload) = packet.split_at(salt_len);
    let mut payload = payload.to_vec();
    let mut cipher = Cipher::new(kind, key, salt);
    assert!(cipher.decrypt_packet(&mut payload));
    payload.truncate(payload.len() - tag_len);
    payload
}

fn encrypt_ss_udp_packet(kind: CipherKind, key: &[u8], salt: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let tag_len = kind.tag_len();
    let mut payload = vec![0; plaintext.len() + tag_len];
    payload[..plaintext.len()].copy_from_slice(plaintext);
    let mut cipher = Cipher::new(kind, key, salt);
    cipher.encrypt_packet(&mut payload);
    let mut packet = salt.to_vec();
    packet.extend_from_slice(&payload);
    packet
}
