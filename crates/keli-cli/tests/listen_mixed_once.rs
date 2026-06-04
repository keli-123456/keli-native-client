use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream, UdpSocket};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keli_cli::{run, CliCommand};
use keli_net_core::{encode_socks5_udp_datagram, parse_socks5_udp_datagram, Socks5Address};
use shadowsocks_crypto::kind::CipherKind;
use shadowsocks_crypto::v1::{openssl_bytes_to_key, Cipher};

#[test]
fn listen_mixed_once_uses_profile_config_for_socks5_connect() {
    let (ss_port, ss_thread) = spawn_shadowsocks_tcp_echo_server();
    let profile_path = write_temp_profile_config(ss_port);
    let listen = free_local_addr();
    let run_listen = listen.clone();
    let run_profile_path = profile_path.clone();
    let server_thread = thread::spawn(move || {
        run(CliCommand::ListenMixed {
            listen: run_listen,
            once: true,
            block_domains: Vec::new(),
            profile_config: Some(run_profile_path),
            outbound_tag: Some("SS-READY".to_string()),
            first_byte_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
        })
        .expect("run listen-mixed once");
    });

    let mut client = connect_with_retry(&listen);
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    client.write_all(&[0x05, 0x01, 0x00]).expect("write hello");
    let mut hello = [0; 2];
    client.read_exact(&mut hello).expect("read hello response");
    assert_eq!(hello, [0x05, 0x00]);

    client
        .write_all(&[
            0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
            b'o', b'm', 0x01, 0xbb,
        ])
        .expect("write socks5 connect");
    let mut connect_response = [0; 10];
    client
        .read_exact(&mut connect_response)
        .expect("read connect response");
    assert_eq!(connect_response, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

    client.write_all(b"ping").expect("write ping");
    let mut response = [0; 4];
    client.read_exact(&mut response).expect("read pong");
    assert_eq!(&response, b"pong");
    client.shutdown(Shutdown::Both).ok();

    server_thread.join().expect("listen thread");
    ss_thread.join().expect("ss thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_http_connect() {
    let (ss_port, ss_thread) = spawn_shadowsocks_tcp_echo_server();
    let profile_path = write_temp_profile_config(ss_port);
    let listen = free_local_addr();
    let run_listen = listen.clone();
    let run_profile_path = profile_path.clone();
    let server_thread = thread::spawn(move || {
        run(CliCommand::ListenMixed {
            listen: run_listen,
            once: true,
            block_domains: Vec::new(),
            profile_config: Some(run_profile_path),
            outbound_tag: Some("SS-READY".to_string()),
            first_byte_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
        })
        .expect("run listen-mixed once");
    });

    let mut client = connect_with_retry(&listen);
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .expect("write http connect");

    let mut connect_response = Vec::new();
    read_until_header_end(&mut client, &mut connect_response);
    assert_eq!(
        connect_response,
        b"HTTP/1.1 200 Connection Established\r\n\r\n"
    );

    client.write_all(b"ping").expect("write ping");
    let mut response = [0; 4];
    client.read_exact(&mut response).expect("read pong");
    assert_eq!(&response, b"pong");
    client.shutdown(Shutdown::Both).ok();

    server_thread.join().expect("listen thread");
    ss_thread.join().expect("ss thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_socks5_udp_associate() {
    let (ss_port, ss_thread) = spawn_shadowsocks_udp_echo_server();
    let profile_path = write_temp_profile_config(ss_port);
    let listen = free_local_addr();
    let run_listen = listen.clone();
    let run_profile_path = profile_path.clone();
    let server_thread = thread::spawn(move || {
        run(CliCommand::ListenMixed {
            listen: run_listen,
            once: true,
            block_domains: Vec::new(),
            profile_config: Some(run_profile_path),
            outbound_tag: Some("SS-READY".to_string()),
            first_byte_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
        })
        .expect("run listen-mixed once");
    });

    let mut client = connect_with_retry(&listen);
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    client.write_all(&[0x05, 0x01, 0x00]).expect("write hello");
    let mut hello = [0; 2];
    client.read_exact(&mut hello).expect("read hello response");
    assert_eq!(hello, [0x05, 0x00]);

    client
        .write_all(&[0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00])
        .expect("write udp associate request");
    let mut reply = [0; 10];
    client.read_exact(&mut reply).expect("read udp reply");
    assert_eq!(&reply[..4], &[0x05, 0x00, 0x00, 0x01]);
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    assert_ne!(relay_port, 0);

    let udp_client = UdpSocket::bind("127.0.0.1:0").expect("bind udp client");
    udp_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("udp timeout");
    let request = encode_socks5_udp_datagram(
        &Socks5Address::Domain("example.com".to_string()),
        53,
        b"ping",
    )
    .expect("encode socks5 udp");
    udp_client
        .send_to(&request, ("127.0.0.1", relay_port))
        .expect("send udp request");

    let mut response = [0; 1500];
    let (size, _) = udp_client
        .recv_from(&mut response)
        .expect("read udp response");
    let response = parse_socks5_udp_datagram(&response[..size]).expect("parse udp response");
    assert_eq!(response.address, Socks5Address::Ipv4(Ipv4Addr::LOCALHOST));
    assert_eq!(response.port, 53);
    assert_eq!(response.payload, b"pong");
    client.shutdown(Shutdown::Both).ok();

    server_thread.join().expect("listen thread");
    ss_thread.join().expect("ss thread");
    fs::remove_file(profile_path).ok();
}

fn read_until_header_end(stream: &mut TcpStream, output: &mut Vec<u8>) {
    let mut byte = [0; 1];
    while !output.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read response byte");
        output.push(byte[0]);
    }
}

fn free_local_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind free addr");
    listener.local_addr().expect("local addr").to_string()
}

fn connect_with_retry(addr: &str) -> TcpStream {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => return stream,
            Err(error) if std::time::Instant::now() < deadline => {
                let _ = error;
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("connect listen-mixed {addr}: {error}"),
        }
    }
}

fn write_temp_profile_config(ss_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-{}.yaml",
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
    fs::write(&path, content).expect("write profile config");
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
