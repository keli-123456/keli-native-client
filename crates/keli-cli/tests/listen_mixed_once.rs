use std::fs;
use std::future::{poll_fn, Future};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::str::FromStr;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod support;

use base64::Engine;
use bytes::Bytes;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use h2::RecvStream;
use hmac::{Hmac, Mac};
use http::{HeaderMap, Request, Response, StatusCode};
use keli_cli::{run, CliCommand};
use keli_net_core::{
    encode_socks5_udp_datagram, parse_socks5_udp_datagram, websocket_accept_for_key, Socks5Address,
};
use keli_protocol::Endpoint;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use shadowsocks_crypto::kind::CipherKind;
use shadowsocks_crypto::v1::{openssl_bytes_to_key, Cipher};
use support::vmess::{
    read_vmess_aead_request, read_vmess_aead_request_async, read_vmess_aes128_gcm_chunk_async,
    write_vmess_aead_response_header, write_vmess_aead_response_header_async,
    write_vmess_aes128_gcm_response_chunk_async,
};
use tokio::io::{AsyncRead, AsyncWrite};

const MIERU_NONCE_LEN: usize = 24;
const MIERU_METADATA_LEN: usize = 32;
const MIERU_TAG_LEN: usize = 16;
const MIERU_ENCRYPTED_METADATA_LEN: usize = MIERU_METADATA_LEN + MIERU_TAG_LEN;
const MIERU_KEY_WINDOW_SECS: i64 = 120;
const MIERU_OPEN_SESSION_REQUEST: u8 = 2;
const MIERU_OPEN_SESSION_RESPONSE: u8 = 3;
const MIERU_DATA_CLIENT_TO_SERVER: u8 = 6;
const MIERU_DATA_SERVER_TO_CLIENT: u8 = 7;
const MIERU_STATUS_OK: u8 = 0;
const MIERU_SOCKS_CONNECT_SUCCESS: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
const MIERU_UDP_MARKER_START: u8 = 0x00;
const MIERU_UDP_MARKER_END: u8 = 0xff;
const VMESS_OPTION_CHUNK_STREAM: u8 = 0x01;
const VMESS_OPTION_CHUNK_MASKING: u8 = 0x04;
const VMESS_SECURITY_AES_128_GCM: u8 = 0x03;
const VMESS_SECURITY_NONE: u8 = 0x05;

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
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            dns_options: Default::default(),
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
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            dns_options: Default::default(),
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
fn listen_mixed_once_uses_profile_config_for_anytls_http_connect() {
    let (anytls_port, anytls_thread) = spawn_anytls_tcp_echo_server();
    let profile_path = write_temp_anytls_profile_config(anytls_port);
    let listen = free_local_addr();
    let run_listen = listen.clone();
    let run_profile_path = profile_path.clone();
    let server_thread = thread::spawn(move || {
        run(CliCommand::ListenMixed {
            listen: run_listen,
            once: true,
            block_domains: Vec::new(),
            profile_config: Some(run_profile_path),
            outbound_tag: Some("ANYTLS-READY".to_string()),
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            dns_options: Default::default(),
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
    anytls_thread.join().expect("anytls thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_anytls_socks5_udp_associate() {
    let (anytls_port, anytls_thread) = spawn_anytls_udp_echo_server();
    let profile_path = write_temp_anytls_profile_config(anytls_port);

    run_profile_socks5_udp_associate_round_trip(&profile_path, "ANYTLS-READY");

    anytls_thread.join().expect("anytls udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_naive_http_connect() {
    let (naive_port, naive_thread) = spawn_naive_h2_echo_server();
    let profile_path = write_temp_naive_profile_config(naive_port);
    let listen = free_local_addr();
    let run_listen = listen.clone();
    let run_profile_path = profile_path.clone();
    let server_thread = thread::spawn(move || {
        run(CliCommand::ListenMixed {
            listen: run_listen,
            once: true,
            block_domains: Vec::new(),
            profile_config: Some(run_profile_path),
            outbound_tag: Some("NAIVE-READY".to_string()),
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_secs(3),
            idle_timeout: Duration::from_secs(3),
            dns_options: Default::default(),
        })
        .expect("run listen-mixed once");
    });

    let mut client = connect_with_retry(&listen);
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
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
    naive_thread.join().expect("naive thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_mieru_http_connect() {
    let (mieru_port, mieru_thread) = spawn_mieru_tcp_echo_server();
    let profile_path = write_temp_mieru_profile_config(mieru_port);

    run_profile_http_connect_round_trip(&profile_path, "MIERU-READY");

    mieru_thread.join().expect("mieru thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vmess_http_connect() {
    let (vmess_port, vmess_thread) = spawn_vmess_tcp_echo_server();
    let profile_path = write_temp_vmess_profile_config(vmess_port);

    run_profile_http_connect_round_trip(&profile_path, "VMESS-READY");

    vmess_thread.join().expect("vmess thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_trojan_ws_http_connect() {
    let (trojan_port, trojan_thread) = spawn_trojan_ws_echo_server();
    let profile_path = write_temp_trojan_ws_profile_config(trojan_port);

    run_profile_http_connect_round_trip(&profile_path, "TROJAN-WS-READY");

    trojan_thread.join().expect("trojan ws thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vless_ws_http_connect() {
    let (vless_port, vless_thread) = spawn_vless_ws_echo_server();
    let profile_path = write_temp_vless_ws_profile_config(vless_port);

    run_profile_http_connect_round_trip(&profile_path, "VLESS-WS-READY");

    vless_thread.join().expect("vless ws thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vmess_ws_http_connect() {
    let (vmess_port, vmess_thread) = spawn_vmess_ws_echo_server();
    let profile_path = write_temp_vmess_ws_profile_config(vmess_port);

    run_profile_http_connect_round_trip(&profile_path, "VMESS-WS-READY");

    vmess_thread.join().expect("vmess ws thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_trojan_ws_socks5_udp_associate() {
    let (trojan_port, trojan_thread) = spawn_trojan_ws_udp_echo_server();
    let profile_path = write_temp_trojan_ws_profile_config(trojan_port);

    run_profile_socks5_udp_associate_round_trip(&profile_path, "TROJAN-WS-READY");

    trojan_thread.join().expect("trojan ws udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vless_ws_socks5_udp_associate() {
    let (vless_port, vless_thread) = spawn_vless_ws_udp_echo_server();
    let profile_path = write_temp_vless_ws_profile_config(vless_port);

    run_profile_socks5_udp_associate_round_trip(&profile_path, "VLESS-WS-READY");

    vless_thread.join().expect("vless ws udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vmess_ws_socks5_udp_associate() {
    let (vmess_port, vmess_thread) = spawn_vmess_ws_udp_echo_server();
    let profile_path = write_temp_vmess_ws_profile_config(vmess_port);

    run_profile_socks5_udp_associate_round_trip(&profile_path, "VMESS-WS-READY");

    vmess_thread.join().expect("vmess ws udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_trojan_httpupgrade_http_connect() {
    let (trojan_port, trojan_thread) = spawn_trojan_httpupgrade_echo_server();
    let profile_path = write_temp_trojan_httpupgrade_profile_config(trojan_port);

    run_profile_http_connect_round_trip(&profile_path, "TROJAN-HU-READY");

    trojan_thread.join().expect("trojan httpupgrade thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vless_httpupgrade_http_connect() {
    let (vless_port, vless_thread) = spawn_vless_httpupgrade_echo_server();
    let profile_path = write_temp_vless_httpupgrade_profile_config(vless_port);

    run_profile_http_connect_round_trip(&profile_path, "VLESS-HU-READY");

    vless_thread.join().expect("vless httpupgrade thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vmess_httpupgrade_http_connect() {
    let (vmess_port, vmess_thread) = spawn_vmess_httpupgrade_echo_server();
    let profile_path = write_temp_vmess_httpupgrade_profile_config(vmess_port);

    run_profile_http_connect_round_trip(&profile_path, "VMESS-HU-READY");

    vmess_thread.join().expect("vmess httpupgrade thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_trojan_httpupgrade_socks5_udp_associate() {
    let (trojan_port, trojan_thread) = spawn_trojan_httpupgrade_udp_echo_server();
    let profile_path = write_temp_trojan_httpupgrade_profile_config(trojan_port);

    run_profile_socks5_udp_associate_round_trip(&profile_path, "TROJAN-HU-READY");

    trojan_thread.join().expect("trojan httpupgrade udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vless_httpupgrade_socks5_udp_associate() {
    let (vless_port, vless_thread) = spawn_vless_httpupgrade_udp_echo_server();
    let profile_path = write_temp_vless_httpupgrade_profile_config(vless_port);

    run_profile_socks5_udp_associate_round_trip(&profile_path, "VLESS-HU-READY");

    vless_thread.join().expect("vless httpupgrade udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vmess_httpupgrade_socks5_udp_associate() {
    let (vmess_port, vmess_thread) = spawn_vmess_httpupgrade_udp_echo_server();
    let profile_path = write_temp_vmess_httpupgrade_udp_profile_config(vmess_port);

    run_profile_socks5_udp_associate_round_trip(&profile_path, "VMESS-HU-READY");

    vmess_thread.join().expect("vmess httpupgrade udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_trojan_grpc_http_connect() {
    let (trojan_port, trojan_thread) = spawn_trojan_grpc_echo_server();
    let profile_path = write_temp_trojan_grpc_profile_config(trojan_port);

    run_profile_http_connect_round_trip(&profile_path, "TROJAN-GRPC-READY");

    trojan_thread.join().expect("trojan grpc thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vless_grpc_http_connect() {
    let (vless_port, vless_thread) = spawn_vless_grpc_echo_server();
    let profile_path = write_temp_vless_grpc_profile_config(vless_port);

    run_profile_http_connect_round_trip(&profile_path, "VLESS-GRPC-READY");

    vless_thread.join().expect("vless grpc thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vmess_grpc_http_connect() {
    let (vmess_port, vmess_thread) = spawn_vmess_grpc_echo_server();
    let profile_path = write_temp_vmess_grpc_profile_config(vmess_port);

    run_profile_http_connect_round_trip(&profile_path, "VMESS-GRPC-READY");

    vmess_thread.join().expect("vmess grpc thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_trojan_grpc_socks5_udp_associate() {
    let (trojan_port, trojan_thread) = spawn_trojan_grpc_udp_echo_server();
    let profile_path = write_temp_trojan_grpc_profile_config(trojan_port);

    run_profile_socks5_udp_associate_round_trip(&profile_path, "TROJAN-GRPC-READY");

    trojan_thread.join().expect("trojan grpc udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vless_grpc_socks5_udp_associate() {
    let (vless_port, vless_thread) = spawn_vless_grpc_udp_echo_server();
    let profile_path = write_temp_vless_grpc_profile_config(vless_port);

    run_profile_socks5_udp_associate_round_trip(&profile_path, "VLESS-GRPC-READY");

    vless_thread.join().expect("vless grpc udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vmess_grpc_socks5_udp_associate() {
    let (vmess_port, vmess_thread) = spawn_vmess_grpc_udp_echo_server();
    let profile_path = write_temp_vmess_grpc_profile_config(vmess_port);

    run_profile_socks5_udp_associate_round_trip(&profile_path, "VMESS-GRPC-READY");

    vmess_thread.join().expect("vmess grpc udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_trojan_h2_http_connect() {
    let (trojan_port, trojan_thread) = spawn_trojan_h2_echo_server();
    let profile_path = write_temp_trojan_h2_profile_config(trojan_port);

    run_profile_http_connect_round_trip(&profile_path, "TROJAN-H2-READY");

    trojan_thread.join().expect("trojan h2 thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vless_h2_http_connect() {
    let (vless_port, vless_thread) = spawn_vless_h2_echo_server();
    let profile_path = write_temp_vless_h2_profile_config(vless_port);

    run_profile_http_connect_round_trip(&profile_path, "VLESS-H2-READY");

    vless_thread.join().expect("vless h2 thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vmess_h2_http_connect() {
    let (vmess_port, vmess_thread) = spawn_vmess_h2_echo_server();
    let profile_path = write_temp_vmess_h2_profile_config(vmess_port);

    run_profile_http_connect_round_trip(&profile_path, "VMESS-H2-READY");

    vmess_thread.join().expect("vmess h2 thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_trojan_h2_socks5_udp_associate() {
    let (trojan_port, trojan_thread) = spawn_trojan_h2_udp_echo_server();
    let profile_path = write_temp_trojan_h2_profile_config(trojan_port);

    run_profile_socks5_udp_associate_round_trip(&profile_path, "TROJAN-H2-READY");

    trojan_thread.join().expect("trojan h2 udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vless_h2_socks5_udp_associate() {
    let (vless_port, vless_thread) = spawn_vless_h2_udp_echo_server();
    let profile_path = write_temp_vless_h2_profile_config(vless_port);

    run_profile_socks5_udp_associate_round_trip(&profile_path, "VLESS-H2-READY");

    vless_thread.join().expect("vless h2 udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vmess_h2_socks5_udp_associate() {
    let (vmess_port, vmess_thread) = spawn_vmess_h2_udp_echo_server();
    let profile_path = write_temp_vmess_h2_profile_config(vmess_port);

    run_profile_socks5_udp_associate_round_trip(&profile_path, "VMESS-H2-READY");

    vmess_thread.join().expect("vmess h2 udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_trojan_quic_http_connect() {
    let (trojan_port, trojan_thread) = spawn_trojan_quic_echo_server();
    let profile_path = write_temp_trojan_quic_profile_config(trojan_port);

    run_profile_http_connect_round_trip(&profile_path, "TROJAN-QUIC-READY");

    trojan_thread.join().expect("trojan quic thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vless_quic_http_connect() {
    let (vless_port, vless_thread) = spawn_vless_quic_echo_server();
    let profile_path = write_temp_vless_quic_profile_config(vless_port);

    run_profile_http_connect_round_trip(&profile_path, "VLESS-QUIC-READY");

    vless_thread.join().expect("vless quic thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vmess_quic_http_connect() {
    let (vmess_port, vmess_thread) = spawn_vmess_quic_echo_server();
    let profile_path = write_temp_vmess_quic_profile_config(vmess_port);

    run_profile_http_connect_round_trip(&profile_path, "VMESS-QUIC-READY");

    vmess_thread.join().expect("vmess quic thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_trojan_quic_socks5_udp_associate() {
    let (trojan_port, trojan_thread) = spawn_trojan_quic_udp_echo_server();
    let profile_path = write_temp_trojan_quic_profile_config(trojan_port);

    run_profile_socks5_udp_associate_round_trip(&profile_path, "TROJAN-QUIC-READY");

    trojan_thread.join().expect("trojan quic udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vless_quic_socks5_udp_associate() {
    let (vless_port, vless_thread) = spawn_vless_quic_udp_echo_server();
    let profile_path = write_temp_vless_quic_profile_config(vless_port);

    run_profile_socks5_udp_associate_round_trip(&profile_path, "VLESS-QUIC-READY");

    vless_thread.join().expect("vless quic udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vmess_quic_socks5_udp_associate() {
    let (vmess_port, vmess_thread) = spawn_vmess_quic_udp_echo_server();
    let profile_path = write_temp_vmess_quic_profile_config(vmess_port);

    run_profile_socks5_udp_associate_round_trip(&profile_path, "VMESS-QUIC-READY");

    vmess_thread.join().expect("vmess quic udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_hy2_http_connect() {
    let (hy2_addr, hy2_thread) = spawn_hy2_echo_server();
    let profile_path = write_temp_hy2_profile_config(hy2_addr.port());

    run_profile_http_connect_round_trip(&profile_path, "HY2-READY");

    hy2_thread.join().expect("hy2 thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_tuic_http_connect() {
    let (tuic_addr, tuic_thread) = spawn_tuic_echo_server();
    let profile_path = write_temp_tuic_profile_config(tuic_addr.port());

    run_profile_http_connect_round_trip(&profile_path, "TUIC-READY");

    tuic_thread.join().expect("tuic thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_hy2_socks5_udp_associate() {
    let (hy2_addr, hy2_thread) = spawn_hy2_udp_echo_server();
    let profile_path = write_temp_hy2_profile_config(hy2_addr.port());

    run_profile_socks5_udp_associate_round_trip_to(
        &profile_path,
        "HY2-READY",
        Socks5Address::Domain("example.com".to_string()),
    );

    hy2_thread.join().expect("hy2 udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_tuic_socks5_udp_associate() {
    let (tuic_addr, tuic_thread) = spawn_tuic_udp_echo_server();
    let profile_path = write_temp_tuic_profile_config(tuic_addr.port());

    run_profile_socks5_udp_associate_round_trip_to(
        &profile_path,
        "TUIC-READY",
        Socks5Address::Domain("example.com".to_string()),
    );

    tuic_thread.join().expect("tuic udp thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_remote_socks5_http_connect() {
    let (socks_port, socks_thread) = spawn_socks5_tcp_proxy_echo_server();
    let profile_path = write_temp_socks5_profile_config(socks_port);

    run_profile_http_connect_round_trip(&profile_path, "SOCKS5-READY");

    socks_thread.join().expect("socks5 proxy thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_remote_http_proxy_connect() {
    let (http_port, http_thread) = spawn_http_connect_proxy_echo_server();
    let profile_path = write_temp_http_proxy_profile_config(http_port);

    run_profile_http_connect_round_trip(&profile_path, "HTTP-READY");

    http_thread.join().expect("http proxy thread");
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
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            dns_options: Default::default(),
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

#[test]
fn listen_mixed_once_uses_profile_config_for_mieru_socks5_udp_associate() {
    let (mieru_port, mieru_thread) = spawn_mieru_udp_echo_server();
    let profile_path = write_temp_mieru_profile_config(mieru_port);
    let listen = free_local_addr();
    let run_listen = listen.clone();
    let run_profile_path = profile_path.clone();
    let server_thread = thread::spawn(move || {
        run(CliCommand::ListenMixed {
            listen: run_listen,
            once: true,
            block_domains: Vec::new(),
            profile_config: Some(run_profile_path),
            outbound_tag: Some("MIERU-READY".to_string()),
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            dns_options: Default::default(),
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
    mieru_thread.join().expect("mieru thread");
    fs::remove_file(profile_path).ok();
}

#[test]
fn listen_mixed_once_uses_profile_config_for_vmess_socks5_udp_associate() {
    let (vmess_port, vmess_thread) = spawn_vmess_udp_echo_server();
    let profile_path = write_temp_vmess_udp_profile_config(vmess_port);
    let listen = free_local_addr();
    let run_listen = listen.clone();
    let run_profile_path = profile_path.clone();
    let server_thread = thread::spawn(move || {
        run(CliCommand::ListenMixed {
            listen: run_listen,
            once: true,
            block_domains: Vec::new(),
            profile_config: Some(run_profile_path),
            outbound_tag: Some("VMESS-READY".to_string()),
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            dns_options: Default::default(),
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
    let request =
        encode_socks5_udp_datagram(&Socks5Address::Ipv4(Ipv4Addr::LOCALHOST), 53, b"ping")
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
    vmess_thread.join().expect("vmess thread");
    fs::remove_file(profile_path).ok();
}

fn read_until_header_end(stream: &mut TcpStream, output: &mut Vec<u8>) {
    let mut byte = [0; 1];
    while !output.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read response byte");
        output.push(byte[0]);
    }
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    read_until_header_end(stream, &mut request);
    String::from_utf8(request).expect("request utf8")
}

fn header_value(request: &str, header: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case(header)
            .then(|| value.trim().to_string())
    })
}

fn assert_httpupgrade_request(request: &str, path: &str, host: &str) {
    assert!(request.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
    assert_eq!(header_value(request, "Host").as_deref(), Some(host));
    assert_eq!(
        header_value(request, "Connection").as_deref(),
        Some("Upgrade")
    );
    assert_eq!(
        header_value(request, "Upgrade").as_deref(),
        Some("websocket")
    );
    assert!(
        header_value(request, "Sec-WebSocket-Key").is_none(),
        "HTTPUpgrade should not send a WebSocket frame key"
    );
}

fn httpupgrade_response() -> &'static str {
    "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
}

fn read_masked_client_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0; 2];
    stream.read_exact(&mut header).expect("read frame header");
    assert_eq!(header[0], 0x82);
    assert!(header[1] & 0x80 != 0);
    let payload_len = match header[1] & 0x7f {
        len @ 0..=125 => usize::from(len),
        126 => {
            let mut bytes = [0; 2];
            stream.read_exact(&mut bytes).expect("read extended len");
            usize::from(u16::from_be_bytes(bytes))
        }
        127 => panic!("test payload should not use 64-bit length"),
        _ => unreachable!(),
    };
    let mut mask = [0; 4];
    stream.read_exact(&mut mask).expect("read mask");
    let mut payload = vec![0; payload_len];
    stream.read_exact(&mut payload).expect("read payload");
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    payload
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

fn run_profile_http_connect_round_trip(profile_path: &str, outbound_tag: &str) {
    let listen = free_local_addr();
    let run_listen = listen.clone();
    let run_profile_path = profile_path.to_string();
    let run_outbound_tag = outbound_tag.to_string();
    let server_thread = thread::spawn(move || {
        run(CliCommand::ListenMixed {
            listen: run_listen,
            once: true,
            block_domains: Vec::new(),
            profile_config: Some(run_profile_path),
            outbound_tag: Some(run_outbound_tag),
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            dns_options: Default::default(),
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
}

fn run_profile_socks5_udp_associate_round_trip(profile_path: &str, outbound_tag: &str) {
    run_profile_socks5_udp_associate_round_trip_to(
        profile_path,
        outbound_tag,
        Socks5Address::Ipv4(Ipv4Addr::LOCALHOST),
    );
}

fn run_profile_socks5_udp_associate_round_trip_to(
    profile_path: &str,
    outbound_tag: &str,
    target_address: Socks5Address,
) {
    let listen = free_local_addr();
    let run_listen = listen.clone();
    let run_profile_path = profile_path.to_string();
    let run_outbound_tag = outbound_tag.to_string();
    let server_thread = thread::spawn(move || {
        run(CliCommand::ListenMixed {
            listen: run_listen,
            once: true,
            block_domains: Vec::new(),
            profile_config: Some(run_profile_path),
            outbound_tag: Some(run_outbound_tag),
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            tun_device: None,
            first_byte_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            dns_options: Default::default(),
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
    let request =
        encode_socks5_udp_datagram(&target_address, 53, b"ping").expect("encode socks5 udp");
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

fn write_temp_socks5_profile_config(socks_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-socks5-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: SOCKS5-READY
    type: socks5
    server: 127.0.0.1
    port: {socks_port}
"#
    );
    fs::write(&path, content).expect("write socks5 profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_http_proxy_profile_config(http_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-http-proxy-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: HTTP-READY
    type: http
    server: 127.0.0.1
    port: {http_port}
"#
    );
    fs::write(&path, content).expect("write http proxy profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_anytls_profile_config(anytls_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-anytls-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: ANYTLS-READY
    type: anytls
    server: 127.0.0.1
    port: {anytls_port}
    password: secret
    tls: true
    sni: edge.example
    skip-cert-verify: true
"#
    );
    fs::write(&path, content).expect("write anytls profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_naive_profile_config(naive_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-naive-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: NAIVE-READY
    type: naive
    server: 127.0.0.1
    port: {naive_port}
    username: user
    password: pass
    tls: true
    sni: edge.example
    skip-cert-verify: true
"#
    );
    fs::write(&path, content).expect("write naive profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_mieru_profile_config(mieru_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-mieru-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: MIERU-READY
    type: mieru
    server: 127.0.0.1
    port: {mieru_port}
    username: user
    password: pass
"#
    );
    fs::write(&path, content).expect("write mieru profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_vmess_profile_config(vmess_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-vmess-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: VMESS-READY
    type: vmess
    server: 127.0.0.1
    port: {vmess_port}
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    cipher: none
    network: tcp
"#
    );
    fs::write(&path, content).expect("write vmess profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_vmess_udp_profile_config(vmess_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-vmess-udp-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: VMESS-READY
    type: vmess
    server: 127.0.0.1
    port: {vmess_port}
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    cipher: auto
    network: tcp
"#
    );
    fs::write(&path, content).expect("write vmess udp profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_trojan_ws_profile_config(trojan_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-trojan-ws-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: TROJAN-WS-READY
    type: trojan
    server: 127.0.0.1
    port: {trojan_port}
    password: password
    tls: false
    network: ws
    ws-opts:
      path: /answer
      headers:
        Host: edge.example
"#
    );
    fs::write(&path, content).expect("write trojan ws profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_vless_ws_profile_config(vless_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-vless-ws-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: VLESS-WS-READY
    type: vless
    server: 127.0.0.1
    port: {vless_port}
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    network: ws
    ws-opts:
      path: /vless
      headers:
        Host: edge.example
"#
    );
    fs::write(&path, content).expect("write vless ws profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_vmess_ws_profile_config(vmess_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-vmess-ws-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: VMESS-WS-READY
    type: vmess
    server: 127.0.0.1
    port: {vmess_port}
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    cipher: auto
    network: ws
    ws-opts:
      path: /vmess
      headers:
        Host: edge.example
"#
    );
    fs::write(&path, content).expect("write vmess ws profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_trojan_httpupgrade_profile_config(trojan_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-trojan-httpupgrade-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: TROJAN-HU-READY
    type: trojan
    server: 127.0.0.1
    port: {trojan_port}
    password: password
    tls: false
    network: httpupgrade
    httpupgrade-opts:
      path: /trojan-upgrade
      host: edge.example
"#
    );
    fs::write(&path, content).expect("write trojan httpupgrade profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_vless_httpupgrade_profile_config(vless_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-vless-httpupgrade-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: VLESS-HU-READY
    type: vless
    server: 127.0.0.1
    port: {vless_port}
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    network: httpupgrade
    httpupgrade-opts:
      path: /vless-upgrade
      host: edge.example
"#
    );
    fs::write(&path, content).expect("write vless httpupgrade profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_vmess_httpupgrade_profile_config(vmess_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-vmess-httpupgrade-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: VMESS-HU-READY
    type: vmess
    server: 127.0.0.1
    port: {vmess_port}
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    cipher: none
    network: httpupgrade
    httpupgrade-opts:
      path: /vmess-upgrade
      host: edge.example
"#
    );
    fs::write(&path, content).expect("write vmess httpupgrade profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_vmess_httpupgrade_udp_profile_config(vmess_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-vmess-httpupgrade-udp-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: VMESS-HU-READY
    type: vmess
    server: 127.0.0.1
    port: {vmess_port}
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    cipher: auto
    network: httpupgrade
    httpupgrade-opts:
      path: /vmess-upgrade
      host: edge.example
"#
    );
    fs::write(&path, content).expect("write vmess httpupgrade udp profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_trojan_grpc_profile_config(trojan_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-trojan-grpc-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: TROJAN-GRPC-READY
    type: trojan
    server: 127.0.0.1
    port: {trojan_port}
    password: password
    tls: false
    network: grpc
    grpc-opts:
      grpc-service-name: GunService
"#
    );
    fs::write(&path, content).expect("write trojan grpc profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_vless_grpc_profile_config(vless_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-vless-grpc-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: VLESS-GRPC-READY
    type: vless
    server: 127.0.0.1
    port: {vless_port}
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    network: grpc
    grpc-opts:
      grpc-service-name: GunService
"#
    );
    fs::write(&path, content).expect("write vless grpc profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_vmess_grpc_profile_config(vmess_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-vmess-grpc-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: VMESS-GRPC-READY
    type: vmess
    server: 127.0.0.1
    port: {vmess_port}
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    cipher: aes-128-gcm
    network: grpc
    grpc-opts:
      grpc-service-name: GunService
"#
    );
    fs::write(&path, content).expect("write vmess grpc profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_trojan_h2_profile_config(trojan_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-trojan-h2-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: TROJAN-H2-READY
    type: trojan
    server: 127.0.0.1
    port: {trojan_port}
    password: password
    tls: false
    network: h2
    h2-opts:
      path: /trojan-h2
      host:
        - trojan-h2.example
"#
    );
    fs::write(&path, content).expect("write trojan h2 profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_vless_h2_profile_config(vless_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-vless-h2-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: VLESS-H2-READY
    type: vless
    server: 127.0.0.1
    port: {vless_port}
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    network: h2
    h2-opts:
      path: /h2
      host:
        - h2.example
"#
    );
    fs::write(&path, content).expect("write vless h2 profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_vmess_h2_profile_config(vmess_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-vmess-h2-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: VMESS-H2-READY
    type: vmess
    server: 127.0.0.1
    port: {vmess_port}
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    cipher: aes-128-gcm
    network: h2
    h2-opts:
      path: /vmess-h2
      host:
        - vmess-h2.example
"#
    );
    fs::write(&path, content).expect("write vmess h2 profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_trojan_quic_profile_config(trojan_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-trojan-quic-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: TROJAN-QUIC-READY
    type: trojan
    server: 127.0.0.1
    port: {trojan_port}
    password: password
    tls: true
    servername: localhost
    skip-cert-verify: true
    network: quic
"#
    );
    fs::write(&path, content).expect("write trojan quic profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_vless_quic_profile_config(vless_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-vless-quic-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: VLESS-QUIC-READY
    type: vless
    server: 127.0.0.1
    port: {vless_port}
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    tls: true
    servername: localhost
    skip-cert-verify: true
    network: quic
"#
    );
    fs::write(&path, content).expect("write vless quic profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_vmess_quic_profile_config(vmess_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-vmess-quic-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: VMESS-QUIC-READY
    type: vmess
    server: 127.0.0.1
    port: {vmess_port}
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    cipher: aes-128-gcm
    tls: true
    servername: localhost
    skip-cert-verify: true
    network: quic
"#
    );
    fs::write(&path, content).expect("write vmess quic profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_hy2_profile_config(hy2_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-hy2-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: HY2-READY
    type: hy2
    server: 127.0.0.1
    port: {hy2_port}
    password: secret
    sni: localhost
    skip-cert-verify: true
"#
    );
    fs::write(&path, content).expect("write hy2 profile config");
    path.to_string_lossy().into_owned()
}

fn write_temp_tuic_profile_config(tuic_port: u16) -> String {
    let name = format!(
        "keli-native-client-listen-mixed-tuic-{}.yaml",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(name);
    let content = format!(
        r#"proxies:
  - name: TUIC-READY
    type: tuic
    server: 127.0.0.1
    port: {tuic_port}
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    token: secret
    sni: localhost
    skip-cert-verify: true
"#
    );
    fs::write(&path, content).expect("write tuic profile config");
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

fn spawn_anytls_tcp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind anytls server");
    let port = listener.local_addr().expect("anytls addr").port();
    let server_config = tls_server_config();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept anytls tcp");
        let connection = rustls::ServerConnection::new(server_config).expect("server tls");
        let mut stream = rustls::StreamOwned::new(connection, stream);

        assert_anytls_auth(&mut stream, "secret");
        let (cmd, sid, settings) = read_anytls_frame(&mut stream);
        assert_eq!((cmd, sid), (4, 0));
        let settings = String::from_utf8(settings).expect("settings utf8");
        assert!(settings.contains("v=2"));
        assert!(settings.contains("client=keli-native-client/"));

        let (cmd, sid, data) = read_anytls_frame(&mut stream);
        assert_eq!((cmd, sid, data.len()), (1, 1, 0));

        let (cmd, sid, target) = read_anytls_frame(&mut stream);
        assert_eq!((cmd, sid), (2, 1));
        assert_eq!(&target, b"\x03\x0bexample.com\x01\xbb");

        let (cmd, sid, payload) = read_anytls_frame(&mut stream);
        assert_eq!((cmd, sid), (2, 1));
        assert_eq!(&payload, b"ping");

        write_anytls_frame(&mut stream, 10, 0, b"v=2");
        write_anytls_frame(&mut stream, 7, 1, b"");
        write_anytls_frame(&mut stream, 2, 1, b"pong");
    });
    (port, handle)
}

fn spawn_anytls_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind anytls udp server");
    let port = listener.local_addr().expect("anytls udp addr").port();
    let server_config = tls_server_config();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept anytls udp tcp");
        let connection = rustls::ServerConnection::new(server_config).expect("server tls");
        let mut stream = rustls::StreamOwned::new(connection, stream);

        assert_anytls_auth(&mut stream, "secret");
        let (cmd, sid, settings) = read_anytls_frame(&mut stream);
        assert_eq!((cmd, sid), (4, 0));
        let settings = String::from_utf8(settings).expect("settings utf8");
        assert!(settings.contains("v=2"));
        assert!(settings.contains("client=keli-native-client/"));

        let (cmd, sid, data) = read_anytls_frame(&mut stream);
        assert_eq!((cmd, sid, data.len()), (1, 1, 0));

        let (cmd, sid, target) = read_anytls_frame(&mut stream);
        assert_eq!((cmd, sid), (2, 1));
        assert_eq!(&target, b"\x03\x11udp-over-tcp.arpa\x00\x00");
        write_anytls_frame(&mut stream, 7, 1, b"");

        let (cmd, sid, packet) = read_anytls_frame(&mut stream);
        assert_eq!((cmd, sid), (2, 1));
        assert_eq!(&packet, b"\x01\x01\x7f\x00\x00\x01\x005\x00\x04ping");
        write_anytls_frame(&mut stream, 2, 1, b"\x00\x04pong");
    });
    (port, handle)
}

fn spawn_naive_h2_echo_server() -> (u16, thread::JoinHandle<()>) {
    let (port_tx, port_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build naive test runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind naive h2 server");
            port_tx
                .send(listener.local_addr().expect("naive addr").port())
                .expect("send naive port");
            let acceptor = tokio_rustls::TlsAcceptor::from(h2_tls_server_config());
            let (stream, _) = listener.accept().await.expect("accept naive h2 tcp");
            let stream = acceptor.accept(stream).await.expect("accept naive tls");
            let mut connection = h2::server::handshake(stream)
                .await
                .expect("server h2 handshake");
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let mut done_tx = Some(done_tx);
            let _connection_task = tokio::spawn(async move {
                while let Some(request) = connection.accept().await {
                    let (request, mut respond) = request.expect("valid h2 request");
                    let done_tx = done_tx.take();
                    tokio::spawn(async move {
                        assert_eq!(request.method(), http::Method::CONNECT);
                        assert_eq!(request.uri().to_string(), "example.com:443");
                        assert_eq!(
                            request.headers()["proxy-authorization"],
                            format!(
                                "Basic {}",
                                base64::engine::general_purpose::STANDARD.encode("user:pass")
                            )
                        );

                        let mut body = request.into_body();
                        let response = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .body(())
                            .expect("build h2 response");
                        let mut send = respond
                            .send_response(response, false)
                            .expect("send h2 response");
                        let payload = tokio::time::timeout(Duration::from_secs(3), body.data())
                            .await
                            .expect("timeout waiting for naive payload")
                            .expect("naive payload")
                            .expect("valid h2 data");
                        let _ = body.flow_control().release_capacity(payload.len());
                        assert_eq!(&payload[..], b"ping");
                        send.send_data(Bytes::from_static(b"pong"), true)
                            .expect("send h2 payload");
                        if let Some(done_tx) = done_tx {
                            let _ = done_tx.send(());
                        }
                    });
                }
            });
            tokio::time::timeout(Duration::from_secs(3), done_rx)
                .await
                .expect("timeout waiting for naive relay")
                .expect("naive relay done");
        });
    });
    (port_rx.recv().expect("receive naive port"), handle)
}

fn spawn_mieru_tcp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mieru server");
    let port = listener.local_addr().expect("mieru addr").port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept mieru server");
        let key = derive_mieru_key_for_test("user", "pass");
        let mut read_nonce = None;
        let open = read_mieru_segment_for_test(&mut stream, &key, &mut read_nonce);
        assert_eq!(open.protocol_type, MIERU_OPEN_SESSION_REQUEST);
        assert_eq!(open.payload, b"\x05\x01\x00\x03\x0bexample.com\x01\xbb");

        let mut writer =
            MieruTestWriter::new(stream.try_clone().expect("clone"), key, open.session_id);
        writer.write_segment(MIERU_OPEN_SESSION_RESPONSE, b"");
        writer.write_segment(MIERU_DATA_SERVER_TO_CLIENT, &MIERU_SOCKS_CONNECT_SUCCESS);

        let data = read_mieru_segment_for_test(&mut stream, &key, &mut read_nonce);
        assert_eq!(data.protocol_type, MIERU_DATA_CLIENT_TO_SERVER);
        assert_eq!(data.payload, b"ping");
        writer.write_segment(MIERU_DATA_SERVER_TO_CLIENT, b"pong");
    });
    (port, handle)
}

fn spawn_mieru_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mieru udp server");
    let port = listener.local_addr().expect("mieru udp addr").port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept mieru udp server");
        let key = derive_mieru_key_for_test("user", "pass");
        let mut read_nonce = None;
        let open = read_mieru_segment_for_test(&mut stream, &key, &mut read_nonce);
        assert_eq!(open.protocol_type, MIERU_OPEN_SESSION_REQUEST);
        assert_eq!(open.payload, b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00");

        let mut writer =
            MieruTestWriter::new(stream.try_clone().expect("clone"), key, open.session_id);
        writer.write_segment(MIERU_OPEN_SESSION_RESPONSE, b"");
        writer.write_segment(MIERU_DATA_SERVER_TO_CLIENT, &MIERU_SOCKS_CONNECT_SUCCESS);

        let data = read_mieru_segment_for_test(&mut stream, &key, &mut read_nonce);
        assert_eq!(data.protocol_type, MIERU_DATA_CLIENT_TO_SERVER);
        let packet = decode_mieru_udp_frame_for_test(&data.payload);
        let datagram = parse_socks5_udp_datagram(&packet).expect("parse mieru udp request");
        assert_eq!(
            datagram.address,
            Socks5Address::Domain("example.com".to_string())
        );
        assert_eq!(datagram.port, 53);
        assert_eq!(datagram.payload, b"ping");

        let response =
            encode_socks5_udp_datagram(&Socks5Address::Ipv4(Ipv4Addr::LOCALHOST), 53, b"pong")
                .expect("encode mieru udp response");
        writer.write_segment(
            MIERU_DATA_SERVER_TO_CLIENT,
            &encode_mieru_udp_frame_for_test(&response),
        );
    });
    (port, handle)
}

fn spawn_vmess_tcp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vmess tcp server");
    let port = listener.local_addr().expect("vmess tcp addr").port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vmess tcp server");
        let request = read_vmess_aead_request(&mut stream, uuid);
        assert_eq!(request.target_host, "example.com");
        assert_eq!(request.target_port, 443);
        assert_eq!(request.command, 0x01);
        assert_eq!(request.security, VMESS_SECURITY_NONE);

        write_vmess_aead_response_header(&mut stream, &request);
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).expect("read vmess payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write vmess response");
    });
    (port, handle)
}

fn spawn_vmess_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vmess udp server");
    let port = listener.local_addr().expect("vmess udp addr").port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vmess udp server");
        let request = read_vmess_aead_request(&mut stream, uuid);
        assert_eq!(request.target_host, "127.0.0.1");
        assert_eq!(request.target_port, 53);
        assert_eq!(request.command, 0x02);
        assert_eq!(
            request.option,
            VMESS_OPTION_CHUNK_STREAM | VMESS_OPTION_CHUNK_MASKING
        );
        assert_eq!(request.security, VMESS_SECURITY_AES_128_GCM);

        write_vmess_aead_response_header(&mut stream, &request);
        let payload = support::vmess::read_vmess_aes128_gcm_chunk(&mut stream, &request);
        assert_eq!(&payload, b"ping");
        support::vmess::write_vmess_aes128_gcm_response_chunk(&mut stream, &request, b"pong");
    });
    (port, handle)
}

fn spawn_trojan_ws_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan ws server");
    let port = listener.local_addr().expect("trojan ws addr").port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept trojan ws server");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /answer HTTP/1.1\r\n"));
        assert!(request.contains("Host: edge.example\r\n"));
        let key = header_value(&request, "Sec-WebSocket-Key").expect("client key");
        let accept = websocket_accept_for_key(&key);
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .expect("write ws response");

        let trojan_header = read_masked_client_frame(&mut stream);
        assert_eq!(
            &trojan_header[..],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x01\x03\x0bexample.com\x01\xbb\r\n"
        );
        let payload = read_masked_client_frame(&mut stream);
        assert_eq!(&payload, b"ping");
        stream.write_all(b"\x82\x04pong").expect("write pong frame");
    });
    (port, handle)
}

fn spawn_vless_ws_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vless ws server");
    let port = listener.local_addr().expect("vless ws addr").port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vless ws server");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /vless HTTP/1.1\r\n"));
        assert!(request.contains("Host: edge.example\r\n"));
        let key = header_value(&request, "Sec-WebSocket-Key").expect("client key");
        let accept = websocket_accept_for_key(&key);
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .expect("write ws response");

        let vless_header = read_masked_client_frame(&mut stream);
        assert_eq!(
            &vless_header[..],
            &[
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x01, 0x01, 0xbb, 0x02, 0x0b, b'e', b'x', b'a', b'm', b'p',
                b'l', b'e', b'.', b'c', b'o', b'm',
            ]
        );
        stream
            .write_all(b"\x82\x02\x00\x00")
            .expect("write vless response header");
        let payload = read_masked_client_frame(&mut stream);
        assert_eq!(&payload, b"ping");
        stream.write_all(b"\x82\x04pong").expect("write pong frame");
    });
    (port, handle)
}

fn spawn_vmess_ws_echo_server() -> (u16, thread::JoinHandle<()>) {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vmess ws server");
    let port = listener.local_addr().expect("vmess ws addr").port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vmess ws server");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /vmess HTTP/1.1\r\n"));
        assert!(request.contains("Host: edge.example\r\n"));
        let key = header_value(&request, "Sec-WebSocket-Key").expect("client key");
        let accept = websocket_accept_for_key(&key);
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .expect("write ws response");

        let request_header = read_masked_client_frame(&mut stream);
        let mut cursor = std::io::Cursor::new(request_header);
        let request = read_vmess_aead_request(&mut cursor, uuid);
        assert_eq!(request.target_host, "example.com");
        assert_eq!(request.target_port, 443);
        assert_eq!(request.command, 0x01);
        assert_eq!(request.security, VMESS_SECURITY_AES_128_GCM);

        let mut response_header = Vec::new();
        write_vmess_aead_response_header(&mut response_header, &request);
        write_server_binary_frame(&mut stream, &response_header);

        let mut request_chunk = read_masked_client_frame(&mut stream);
        if request_chunk.len() == 2 {
            request_chunk.extend(read_masked_client_frame(&mut stream));
        }
        let mut cursor = std::io::Cursor::new(request_chunk);
        let payload = support::vmess::read_vmess_aes128_gcm_chunk(&mut cursor, &request);
        assert_eq!(&payload, b"ping");

        let mut response_chunk = Vec::new();
        support::vmess::write_vmess_aes128_gcm_response_chunk(
            &mut response_chunk,
            &request,
            b"pong",
        );
        write_server_binary_frame(&mut stream, &response_chunk);
    });
    (port, handle)
}

fn spawn_trojan_ws_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan ws udp server");
    let port = listener.local_addr().expect("trojan ws udp addr").port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept trojan ws udp server");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /answer HTTP/1.1\r\n"));
        assert!(request.contains("Host: edge.example\r\n"));
        let key = header_value(&request, "Sec-WebSocket-Key").expect("client key");
        let accept = websocket_accept_for_key(&key);
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .expect("write ws response");

        let trojan_header = read_masked_client_frame(&mut stream);
        assert_eq!(
            &trojan_header,
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x03\x01\x7f\x00\x00\x01\x005\r\n"
        );
        let request_payload = read_masked_client_frame(&mut stream);
        assert_eq!(
            &request_payload,
            b"\x01\x7f\x00\x00\x01\x005\x00\x04\r\nping"
        );
        write_server_binary_frame(&mut stream, b"\x01\x7f\x00\x00\x01\x005\x00\x04\r\npong");
    });
    (port, handle)
}

fn spawn_vless_ws_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vless ws udp server");
    let port = listener.local_addr().expect("vless ws udp addr").port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vless ws udp server");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /vless HTTP/1.1\r\n"));
        assert!(request.contains("Host: edge.example\r\n"));
        let key = header_value(&request, "Sec-WebSocket-Key").expect("client key");
        let accept = websocket_accept_for_key(&key);
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .expect("write ws response");

        let vless_header = read_masked_client_frame(&mut stream);
        assert_eq!(
            &vless_header[..],
            &[
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x02, 0x00, 0x35, 0x01, 0x7f, 0x00, 0x00, 0x01,
            ]
        );
        write_server_binary_frame(&mut stream, b"\x00\x00");

        let mut request_payload = read_masked_client_frame(&mut stream);
        if request_payload.len() == 2 {
            request_payload.extend(read_masked_client_frame(&mut stream));
        }
        assert_eq!(&request_payload, b"\x00\x04ping");
        write_server_binary_frame(&mut stream, b"\x00\x04pong");
    });
    (port, handle)
}

fn spawn_vmess_ws_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vmess ws udp server");
    let port = listener.local_addr().expect("vmess ws udp addr").port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vmess ws udp server");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /vmess HTTP/1.1\r\n"));
        assert!(request.contains("Host: edge.example\r\n"));
        let key = header_value(&request, "Sec-WebSocket-Key").expect("client key");
        let accept = websocket_accept_for_key(&key);
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .expect("write ws response");

        let request_header = read_masked_client_frame(&mut stream);
        let mut cursor = std::io::Cursor::new(request_header);
        let request = read_vmess_aead_request(&mut cursor, uuid);
        assert_eq!(request.target_host, "127.0.0.1");
        assert_eq!(request.target_port, 53);
        assert_eq!(request.command, 0x02);
        assert_eq!(
            request.option,
            VMESS_OPTION_CHUNK_STREAM | VMESS_OPTION_CHUNK_MASKING
        );
        assert_eq!(request.security, VMESS_SECURITY_AES_128_GCM);

        let mut response_header = Vec::new();
        write_vmess_aead_response_header(&mut response_header, &request);
        write_server_binary_frame(&mut stream, &response_header);

        let mut request_chunk = read_masked_client_frame(&mut stream);
        if request_chunk.len() == 2 {
            request_chunk.extend(read_masked_client_frame(&mut stream));
        }
        let mut cursor = std::io::Cursor::new(request_chunk);
        let payload = support::vmess::read_vmess_aes128_gcm_chunk(&mut cursor, &request);
        assert_eq!(&payload, b"ping");

        let mut response_chunk = Vec::new();
        support::vmess::write_vmess_aes128_gcm_response_chunk(
            &mut response_chunk,
            &request,
            b"pong",
        );
        write_server_binary_frame(&mut stream, &response_chunk);
    });
    (port, handle)
}

fn spawn_trojan_httpupgrade_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan httpupgrade server");
    let port = listener
        .local_addr()
        .expect("trojan httpupgrade addr")
        .port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept trojan httpupgrade server");
        let request = read_http_request(&mut stream);
        assert_httpupgrade_request(&request, "/trojan-upgrade", "edge.example");
        stream
            .write_all(httpupgrade_response().as_bytes())
            .expect("write httpupgrade response");

        let mut trojan_header = [0; 76];
        stream
            .read_exact(&mut trojan_header)
            .expect("read trojan request header");
        assert_eq!(
            &trojan_header[..],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x01\x03\x0bexample.com\x01\xbb\r\n"
        );
        let mut payload = [0; 4];
        stream
            .read_exact(&mut payload)
            .expect("read trojan httpupgrade payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write trojan response");
    });
    (port, handle)
}

fn spawn_vless_httpupgrade_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vless httpupgrade server");
    let port = listener
        .local_addr()
        .expect("vless httpupgrade addr")
        .port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vless httpupgrade server");
        let request = read_http_request(&mut stream);
        assert_httpupgrade_request(&request, "/vless-upgrade", "edge.example");
        stream
            .write_all(httpupgrade_response().as_bytes())
            .expect("write httpupgrade response");

        let mut vless_header = [0; 34];
        stream
            .read_exact(&mut vless_header)
            .expect("read vless request header");
        assert_eq!(
            &vless_header[..],
            &[
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x01, 0x01, 0xbb, 0x02, 0x0b, b'e', b'x', b'a', b'm', b'p',
                b'l', b'e', b'.', b'c', b'o', b'm',
            ]
        );
        stream
            .write_all(&[0x00, 0x00])
            .expect("write vless response header");
        let mut payload = [0; 4];
        stream
            .read_exact(&mut payload)
            .expect("read vless httpupgrade payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write vless response");
    });
    (port, handle)
}

fn spawn_vmess_httpupgrade_echo_server() -> (u16, thread::JoinHandle<()>) {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vmess httpupgrade server");
    let port = listener
        .local_addr()
        .expect("vmess httpupgrade addr")
        .port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vmess httpupgrade server");
        let request = read_http_request(&mut stream);
        assert_httpupgrade_request(&request, "/vmess-upgrade", "edge.example");
        stream
            .write_all(httpupgrade_response().as_bytes())
            .expect("write httpupgrade response");

        let request = read_vmess_aead_request(&mut stream, uuid);
        assert_eq!(request.target_host, "example.com");
        assert_eq!(request.target_port, 443);
        assert_eq!(request.command, 0x01);
        assert_eq!(request.security, VMESS_SECURITY_NONE);

        write_vmess_aead_response_header(&mut stream, &request);
        let mut payload = [0; 4];
        stream
            .read_exact(&mut payload)
            .expect("read vmess httpupgrade payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write vmess response");
    });
    (port, handle)
}

fn spawn_trojan_httpupgrade_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan httpupgrade udp server");
    let port = listener
        .local_addr()
        .expect("trojan httpupgrade udp addr")
        .port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .expect("accept trojan httpupgrade udp server");
        let request = read_http_request(&mut stream);
        assert_httpupgrade_request(&request, "/trojan-upgrade", "edge.example");
        stream
            .write_all(httpupgrade_response().as_bytes())
            .expect("write httpupgrade response");

        let mut trojan_header = [0; 68];
        stream
            .read_exact(&mut trojan_header)
            .expect("read trojan udp associate header");
        assert_eq!(
            &trojan_header[..],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x03\x01\x7f\x00\x00\x01\x005\r\n"
        );
        let mut request_payload = [0; 15];
        stream
            .read_exact(&mut request_payload)
            .expect("read trojan udp packet");
        assert_eq!(
            &request_payload,
            b"\x01\x7f\x00\x00\x01\x005\x00\x04\r\nping"
        );
        stream
            .write_all(b"\x01\x7f\x00\x00\x01\x005\x00\x04\r\npong")
            .expect("write trojan udp response packet");
    });
    (port, handle)
}

fn spawn_vless_httpupgrade_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vless httpupgrade udp server");
    let port = listener
        .local_addr()
        .expect("vless httpupgrade udp addr")
        .port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .expect("accept vless httpupgrade udp server");
        let request = read_http_request(&mut stream);
        assert_httpupgrade_request(&request, "/vless-upgrade", "edge.example");
        stream
            .write_all(httpupgrade_response().as_bytes())
            .expect("write httpupgrade response");

        let mut vless_header = [0; 26];
        stream
            .read_exact(&mut vless_header)
            .expect("read vless udp request header");
        assert_eq!(
            vless_header,
            [
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x02, 0x00, 0x35, 0x01, 0x7f, 0x00, 0x00, 0x01,
            ]
        );
        stream
            .write_all(&[0x00, 0x00])
            .expect("write vless response header");
        let mut request_payload = [0; 6];
        stream
            .read_exact(&mut request_payload)
            .expect("read vless udp payload");
        assert_eq!(&request_payload, b"\x00\x04ping");
        stream
            .write_all(b"\x00\x04pong")
            .expect("write vless udp response payload");
    });
    (port, handle)
}

fn spawn_vmess_httpupgrade_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vmess httpupgrade udp server");
    let port = listener
        .local_addr()
        .expect("vmess httpupgrade udp addr")
        .port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .expect("accept vmess httpupgrade udp server");
        let request = read_http_request(&mut stream);
        assert_httpupgrade_request(&request, "/vmess-upgrade", "edge.example");
        stream
            .write_all(httpupgrade_response().as_bytes())
            .expect("write httpupgrade response");

        let request = read_vmess_aead_request(&mut stream, uuid);
        assert_eq!(request.target_host, "127.0.0.1");
        assert_eq!(request.target_port, 53);
        assert_eq!(request.command, 0x02);
        assert_eq!(
            request.option,
            VMESS_OPTION_CHUNK_STREAM | VMESS_OPTION_CHUNK_MASKING
        );
        assert_eq!(request.security, VMESS_SECURITY_AES_128_GCM);

        write_vmess_aead_response_header(&mut stream, &request);
        let payload = support::vmess::read_vmess_aes128_gcm_chunk(&mut stream, &request);
        assert_eq!(&payload, b"ping");
        support::vmess::write_vmess_aes128_gcm_response_chunk(&mut stream, &request, b"pong");
    });
    (port, handle)
}

fn spawn_trojan_grpc_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan grpc server");
    let port = listener.local_addr().expect("trojan grpc addr").port();
    let handle = spawn_grpc_server(listener, "/GunService/Tun", |mut stream| {
        let mut trojan_header = [0; 76];
        stream
            .read_exact(&mut trojan_header)
            .expect("read trojan grpc header");
        assert_eq!(
            &trojan_header[..],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x01\x03\x0bexample.com\x01\xbb\r\n"
        );
        let mut payload = [0; 4];
        stream
            .read_exact(&mut payload)
            .expect("read trojan grpc payload");
        assert_eq!(&payload, b"ping");
        stream
            .write_all(b"pong")
            .expect("write trojan grpc response");
    });
    (port, handle)
}

fn spawn_vless_grpc_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vless grpc server");
    let port = listener.local_addr().expect("vless grpc addr").port();
    let handle = spawn_grpc_server(listener, "/GunService/Tun", |mut stream| {
        let mut vless_header = [0; 34];
        stream
            .read_exact(&mut vless_header)
            .expect("read vless grpc header");
        assert_eq!(
            &vless_header[..],
            &[
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x01, 0x01, 0xbb, 0x02, 0x0b, b'e', b'x', b'a', b'm', b'p',
                b'l', b'e', b'.', b'c', b'o', b'm',
            ]
        );
        stream
            .write_all(&[0x00, 0x00])
            .expect("write vless grpc response header");
        let mut payload = [0; 4];
        stream
            .read_exact(&mut payload)
            .expect("read vless grpc payload");
        assert_eq!(&payload, b"ping");
        stream
            .write_all(b"pong")
            .expect("write vless grpc response");
    });
    (port, handle)
}

fn spawn_vmess_grpc_echo_server() -> (u16, thread::JoinHandle<()>) {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vmess grpc server");
    let port = listener.local_addr().expect("vmess grpc addr").port();
    let handle = spawn_grpc_server(listener, "/GunService/Tun", move |mut stream| {
        let request = read_vmess_aead_request(&mut stream, uuid);
        assert_eq!(request.target_host, "example.com");
        assert_eq!(request.target_port, 443);
        assert_eq!(request.command, 0x01);
        assert_eq!(request.security, VMESS_SECURITY_AES_128_GCM);

        write_vmess_aead_response_header(&mut stream, &request);
        let payload = support::vmess::read_vmess_aes128_gcm_chunk(&mut stream, &request);
        assert_eq!(&payload, b"ping");
        support::vmess::write_vmess_aes128_gcm_response_chunk(&mut stream, &request, b"pong");
    });
    (port, handle)
}

fn spawn_trojan_grpc_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan grpc udp server");
    let port = listener.local_addr().expect("trojan grpc udp addr").port();
    let handle = spawn_grpc_server(listener, "/GunService/Tun", |mut stream| {
        let mut trojan_header = [0; 68];
        stream
            .read_exact(&mut trojan_header)
            .expect("read trojan grpc udp associate header");
        assert_eq!(
            &trojan_header[..],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x03\x01\x7f\x00\x00\x01\x005\r\n"
        );
        let mut request_payload = [0; 15];
        stream
            .read_exact(&mut request_payload)
            .expect("read trojan grpc udp packet");
        assert_eq!(
            &request_payload,
            b"\x01\x7f\x00\x00\x01\x005\x00\x04\r\nping"
        );
        stream
            .write_all(b"\x01\x7f\x00\x00\x01\x005\x00\x04\r\npong")
            .expect("write trojan grpc udp response packet");
    });
    (port, handle)
}

fn spawn_vless_grpc_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vless grpc udp server");
    let port = listener.local_addr().expect("vless grpc udp addr").port();
    let handle = spawn_grpc_server(listener, "/GunService/Tun", |mut stream| {
        let mut vless_header = [0; 26];
        stream
            .read_exact(&mut vless_header)
            .expect("read vless grpc udp header");
        assert_eq!(
            vless_header,
            [
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x02, 0x00, 0x35, 0x01, 0x7f, 0x00, 0x00, 0x01,
            ]
        );
        stream
            .write_all(&[0x00, 0x00])
            .expect("write vless grpc udp response header");
        let mut request_payload = [0; 6];
        stream
            .read_exact(&mut request_payload)
            .expect("read vless grpc udp payload");
        assert_eq!(&request_payload, b"\x00\x04ping");
        stream
            .write_all(b"\x00\x04pong")
            .expect("write vless grpc udp response payload");
    });
    (port, handle)
}

fn spawn_vmess_grpc_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vmess grpc udp server");
    let port = listener.local_addr().expect("vmess grpc udp addr").port();
    let handle = spawn_grpc_server(listener, "/GunService/Tun", move |mut stream| {
        let request = read_vmess_aead_request(&mut stream, uuid);
        assert_eq!(request.target_host, "127.0.0.1");
        assert_eq!(request.target_port, 53);
        assert_eq!(request.command, 0x02);
        assert_eq!(request.security, VMESS_SECURITY_AES_128_GCM);

        write_vmess_aead_response_header(&mut stream, &request);
        let payload = support::vmess::read_vmess_aes128_gcm_chunk(&mut stream, &request);
        assert_eq!(&payload, b"ping");
        support::vmess::write_vmess_aes128_gcm_response_chunk(&mut stream, &request, b"pong");
    });
    (port, handle)
}

fn spawn_trojan_h2_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan h2 server");
    let port = listener.local_addr().expect("trojan h2 addr").port();
    let handle = spawn_h2_server(
        listener,
        "/trojan-h2",
        Some("trojan-h2.example"),
        |mut stream| {
            let mut trojan_header = [0; 76];
            stream
                .read_exact(&mut trojan_header)
                .expect("read trojan h2 header");
            assert_eq!(
                &trojan_header[..],
                b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x01\x03\x0bexample.com\x01\xbb\r\n"
            );
            let mut payload = [0; 4];
            stream
                .read_exact(&mut payload)
                .expect("read trojan h2 payload");
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").expect("write trojan h2 response");
        },
    );
    (port, handle)
}

fn spawn_vless_h2_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vless h2 server");
    let port = listener.local_addr().expect("vless h2 addr").port();
    let handle = spawn_h2_server(listener, "/h2", Some("h2.example"), |mut stream| {
        let mut vless_header = [0; 34];
        stream
            .read_exact(&mut vless_header)
            .expect("read vless h2 header");
        assert_eq!(
            &vless_header[..],
            &[
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x01, 0x01, 0xbb, 0x02, 0x0b, b'e', b'x', b'a', b'm', b'p',
                b'l', b'e', b'.', b'c', b'o', b'm',
            ]
        );
        stream
            .write_all(&[0x00, 0x00])
            .expect("write vless h2 response header");
        let mut payload = [0; 4];
        stream
            .read_exact(&mut payload)
            .expect("read vless h2 payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write vless h2 response");
    });
    (port, handle)
}

fn spawn_vmess_h2_echo_server() -> (u16, thread::JoinHandle<()>) {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vmess h2 server");
    let port = listener.local_addr().expect("vmess h2 addr").port();
    let handle = spawn_h2_server(
        listener,
        "/vmess-h2",
        Some("vmess-h2.example"),
        move |mut stream| {
            let request = read_vmess_aead_request(&mut stream, uuid);
            assert_eq!(request.target_host, "example.com");
            assert_eq!(request.target_port, 443);
            assert_eq!(request.command, 0x01);
            assert_eq!(request.security, VMESS_SECURITY_AES_128_GCM);

            write_vmess_aead_response_header(&mut stream, &request);
            let payload = support::vmess::read_vmess_aes128_gcm_chunk(&mut stream, &request);
            assert_eq!(&payload, b"ping");
            support::vmess::write_vmess_aes128_gcm_response_chunk(&mut stream, &request, b"pong");
        },
    );
    (port, handle)
}

fn spawn_trojan_h2_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind trojan h2 udp server");
    let port = listener.local_addr().expect("trojan h2 udp addr").port();
    let handle = spawn_h2_server(
        listener,
        "/trojan-h2",
        Some("trojan-h2.example"),
        |mut stream| {
            let mut trojan_header = [0; 68];
            stream
                .read_exact(&mut trojan_header)
                .expect("read trojan h2 udp associate header");
            assert_eq!(
                &trojan_header[..],
                b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x03\x01\x7f\x00\x00\x01\x005\r\n"
            );
            let mut request_payload = [0; 15];
            stream
                .read_exact(&mut request_payload)
                .expect("read trojan h2 udp packet");
            assert_eq!(
                &request_payload,
                b"\x01\x7f\x00\x00\x01\x005\x00\x04\r\nping"
            );
            stream
                .write_all(b"\x01\x7f\x00\x00\x01\x005\x00\x04\r\npong")
                .expect("write trojan h2 udp response packet");
        },
    );
    (port, handle)
}

fn spawn_vless_h2_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vless h2 udp server");
    let port = listener.local_addr().expect("vless h2 udp addr").port();
    let handle = spawn_h2_server(listener, "/h2", Some("h2.example"), |mut stream| {
        let mut vless_header = [0; 26];
        stream
            .read_exact(&mut vless_header)
            .expect("read vless h2 udp header");
        assert_eq!(
            vless_header,
            [
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x02, 0x00, 0x35, 0x01, 0x7f, 0x00, 0x00, 0x01,
            ]
        );
        stream
            .write_all(&[0x00, 0x00])
            .expect("write vless h2 udp response header");
        let mut request_payload = [0; 6];
        stream
            .read_exact(&mut request_payload)
            .expect("read vless h2 udp payload");
        assert_eq!(&request_payload, b"\x00\x04ping");
        stream
            .write_all(b"\x00\x04pong")
            .expect("write vless h2 udp response payload");
    });
    (port, handle)
}

fn spawn_vmess_h2_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let uuid = "00112233-4455-6677-8899-aabbccddeeff";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind vmess h2 udp server");
    let port = listener.local_addr().expect("vmess h2 udp addr").port();
    let handle = spawn_h2_server(
        listener,
        "/vmess-h2",
        Some("vmess-h2.example"),
        move |mut stream| {
            let request = read_vmess_aead_request(&mut stream, uuid);
            assert_eq!(request.target_host, "127.0.0.1");
            assert_eq!(request.target_port, 53);
            assert_eq!(request.command, 0x02);
            assert_eq!(request.security, VMESS_SECURITY_AES_128_GCM);

            write_vmess_aead_response_header(&mut stream, &request);
            let payload = support::vmess::read_vmess_aes128_gcm_chunk(&mut stream, &request);
            assert_eq!(&payload, b"ping");
            support::vmess::write_vmess_aes128_gcm_response_chunk(&mut stream, &request, b"pong");
        },
    );
    (port, handle)
}

fn spawn_trojan_quic_echo_server() -> (u16, thread::JoinHandle<()>) {
    spawn_legacy_quic_server(|mut send, mut recv| async move {
        let expected = keli_protocol::encode_trojan_tcp_request_header(
            "password",
            &Endpoint::new("example.com", 443),
        )
        .expect("expected trojan quic request");
        let mut request = vec![0; expected.len()];
        recv.read_exact(&mut request)
            .await
            .expect("read trojan quic request");
        assert_eq!(request, expected);
        let mut payload = [0; 4];
        recv.read_exact(&mut payload)
            .await
            .expect("read trojan quic payload");
        assert_eq!(&payload, b"ping");
        send.write_all(b"pong")
            .await
            .expect("write trojan quic response");
        send.finish().expect("finish trojan quic stream");
    })
}

fn spawn_vless_quic_echo_server() -> (u16, thread::JoinHandle<()>) {
    spawn_legacy_quic_server(|mut send, mut recv| async move {
        let expected = keli_protocol::encode_vless_tcp_request_header(
            "00112233-4455-6677-8899-aabbccddeeff",
            &Endpoint::new("example.com", 443),
            None,
        )
        .expect("expected vless quic request");
        let mut request = vec![0; expected.len()];
        recv.read_exact(&mut request)
            .await
            .expect("read vless quic request");
        assert_eq!(request, expected);
        send.write_all(&[0x00, 0x00])
            .await
            .expect("write vless quic response header");
        let mut payload = [0; 4];
        recv.read_exact(&mut payload)
            .await
            .expect("read vless quic payload");
        assert_eq!(&payload, b"ping");
        send.write_all(b"pong")
            .await
            .expect("write vless quic response");
        send.finish().expect("finish vless quic stream");
    })
}

fn spawn_vmess_quic_echo_server() -> (u16, thread::JoinHandle<()>) {
    spawn_legacy_quic_server(|mut send, mut recv| async move {
        let request =
            read_vmess_aead_request_async(&mut recv, "00112233-4455-6677-8899-aabbccddeeff").await;
        assert_eq!(request.target_host, "example.com");
        assert_eq!(request.target_port, 443);
        assert_eq!(request.command, 0x01);
        assert_eq!(request.security, VMESS_SECURITY_AES_128_GCM);

        write_vmess_aead_response_header_async(&mut send, &request).await;
        let payload = read_vmess_aes128_gcm_chunk_async(&mut recv, &request).await;
        assert_eq!(&payload, b"ping");
        write_vmess_aes128_gcm_response_chunk_async(&mut send, &request, b"pong").await;
        send.finish().expect("finish vmess quic stream");
    })
}

fn spawn_trojan_quic_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    spawn_legacy_quic_server(|mut send, mut recv| async move {
        let expected = keli_protocol::encode_trojan_udp_request_header(
            "password",
            &Endpoint::new("127.0.0.1", 53),
        )
        .expect("expected trojan quic udp request");
        let mut request = vec![0; expected.len()];
        recv.read_exact(&mut request)
            .await
            .expect("read trojan quic udp associate request");
        assert_eq!(request, expected);
        let mut request_payload = [0; 15];
        recv.read_exact(&mut request_payload)
            .await
            .expect("read trojan quic udp packet");
        assert_eq!(
            &request_payload,
            b"\x01\x7f\x00\x00\x01\x005\x00\x04\r\nping"
        );
        send.write_all(b"\x01\x7f\x00\x00\x01\x005\x00\x04\r\npong")
            .await
            .expect("write trojan quic udp response packet");
        send.finish().expect("finish trojan quic udp stream");
    })
}

fn spawn_vless_quic_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    spawn_legacy_quic_server(|mut send, mut recv| async move {
        let expected = keli_protocol::encode_vless_udp_request_header(
            "00112233-4455-6677-8899-aabbccddeeff",
            &Endpoint::new("127.0.0.1", 53),
        )
        .expect("expected vless quic udp request");
        let mut request = vec![0; expected.len()];
        recv.read_exact(&mut request)
            .await
            .expect("read vless quic udp request");
        assert_eq!(request, expected);
        send.write_all(&[0x00, 0x00])
            .await
            .expect("write vless quic udp response header");
        let mut request_payload = [0; 6];
        recv.read_exact(&mut request_payload)
            .await
            .expect("read vless quic udp payload");
        assert_eq!(&request_payload, b"\x00\x04ping");
        send.write_all(b"\x00\x04pong")
            .await
            .expect("write vless quic udp response payload");
        send.finish().expect("finish vless quic udp stream");
    })
}

fn spawn_vmess_quic_udp_echo_server() -> (u16, thread::JoinHandle<()>) {
    spawn_legacy_quic_server(|mut send, mut recv| async move {
        let request =
            read_vmess_aead_request_async(&mut recv, "00112233-4455-6677-8899-aabbccddeeff").await;
        assert_eq!(request.target_host, "127.0.0.1");
        assert_eq!(request.target_port, 53);
        assert_eq!(request.command, 0x02);
        assert_eq!(request.security, VMESS_SECURITY_AES_128_GCM);

        write_vmess_aead_response_header_async(&mut send, &request).await;
        let payload = read_vmess_aes128_gcm_chunk_async(&mut recv, &request).await;
        assert_eq!(&payload, b"ping");
        write_vmess_aes128_gcm_response_chunk_async(&mut send, &request, b"pong").await;
        send.finish().expect("finish vmess quic udp stream");
    })
}

fn spawn_legacy_quic_server<F, Fut>(handler: F) -> (u16, thread::JoinHandle<()>)
where
    F: FnOnce(quinn::SendStream, quinn::RecvStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (port_tx, port_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let server_endpoint = quinn::Endpoint::server(
                legacy_quic_test_server_config(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            )
            .expect("bind local legacy quic server");
            let server_addr = server_endpoint.local_addr().expect("legacy quic addr");
            port_tx
                .send(server_addr.port())
                .expect("send legacy quic port");
            let incoming = server_endpoint
                .accept()
                .await
                .expect("server accepts legacy quic connection");
            let connection = incoming.await.expect("server legacy quic connection");
            let (send, recv) = connection
                .accept_bi()
                .await
                .expect("accept legacy quic stream");
            handler(send, recv).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
    });
    let port = port_rx.recv().expect("receive legacy quic port");
    (port, handle)
}

fn legacy_quic_test_server_config() -> quinn::ServerConfig {
    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("server protocol versions")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .expect("server config");
    quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("legacy quic server config"),
    ))
}

fn spawn_h2_server(
    listener: TcpListener,
    expected_path: &'static str,
    expected_authority: Option<&'static str>,
    handler: impl FnOnce(H2TestStream) + Send + 'static,
) -> thread::JoinHandle<()> {
    listener
        .set_nonblocking(true)
        .expect("listener nonblocking");
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            let (stream, _) = listener.accept().await.expect("accept h2 tcp");
            serve_h2_connection(stream, expected_path, expected_authority, handler).await;
        });
    })
}

async fn serve_h2_connection<S>(
    stream: S,
    expected_path: &'static str,
    expected_authority: Option<&'static str>,
    handler: impl FnOnce(H2TestStream) + Send + 'static,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = h2::server::handshake(stream).await.expect("h2 handshake");
    let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let mut handler = Some(handler);
    loop {
        tokio::select! {
            request = connection.accept() => {
                let Some(request) = request else {
                    break;
                };
                let (request, respond) = request.expect("valid h2 request");
                let handler = handler.take().expect("single h2 request handler");
                let done_tx = done_tx.clone();
                tokio::spawn(async move {
                    serve_h2_request(request, respond, expected_path, expected_authority, handler).await;
                    let _ = done_tx.send(());
                });
            }
            _ = done_rx.recv() => break,
        }
    }
}

async fn serve_h2_request(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    expected_path: &str,
    expected_authority: Option<&str>,
    handler: impl FnOnce(H2TestStream) + Send + 'static,
) {
    assert_eq!(request.method(), http::Method::PUT);
    assert_eq!(request.uri().path(), expected_path);
    if let Some(authority) = expected_authority {
        assert_eq!(
            request.uri().authority().map(|value| value.as_str()),
            Some(authority)
        );
    }
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .expect("h2 response");
    let mut send = respond
        .send_response(response, false)
        .expect("send response");
    let (input_tx, input_rx) = mpsc::channel();
    let (output_tx, mut output_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let mut body = request.into_body();
    let read_task = tokio::spawn(async move {
        while let Some(chunk) = body.data().await {
            let chunk = chunk.expect("read h2 body");
            let len = chunk.len();
            let _ = body.flow_control().release_capacity(len);
            if input_tx.send(chunk.to_vec()).is_err() {
                return;
            }
        }
    });
    let write_task = tokio::spawn(async move {
        while let Some(payload) = output_rx.recv().await {
            send_h2_data(&mut send, Bytes::from(payload), false)
                .await
                .expect("write h2 body");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        send.send_data(Bytes::new(), true)
            .expect("finish h2 response");
    });
    tokio::task::spawn_blocking(move || handler(H2TestStream::new(input_rx, output_tx)))
        .await
        .expect("handler task");
    write_task.await.expect("write task");
    read_task.abort();
}

fn spawn_grpc_server(
    listener: TcpListener,
    expected_path: &'static str,
    handler: impl FnOnce(GrpcTestStream) + Send + 'static,
) -> thread::JoinHandle<()> {
    listener
        .set_nonblocking(true)
        .expect("listener nonblocking");
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            let (stream, _) = listener.accept().await.expect("accept grpc tcp");
            serve_grpc_h2_connection(stream, expected_path, handler).await;
        });
    })
}

async fn serve_grpc_h2_connection<S>(
    stream: S,
    expected_path: &'static str,
    handler: impl FnOnce(GrpcTestStream) + Send + 'static,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = h2::server::handshake(stream).await.expect("h2 handshake");
    let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let mut handler = Some(handler);
    loop {
        tokio::select! {
            request = connection.accept() => {
                let Some(request) = request else {
                    break;
                };
                let (request, respond) = request.expect("valid h2 request");
                let handler = handler.take().expect("single grpc request handler");
                let done_tx = done_tx.clone();
                tokio::spawn(async move {
                    serve_grpc_request(request, respond, expected_path, handler).await;
                    let _ = done_tx.send(());
                });
            }
            _ = done_rx.recv() => break,
        }
    }
}

async fn serve_grpc_request(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    expected_path: &str,
    handler: impl FnOnce(GrpcTestStream) + Send + 'static,
) {
    assert_eq!(request.method(), http::Method::POST);
    assert_eq!(request.uri().path(), expected_path);
    assert_eq!(
        request
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc")
    );
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .body(())
        .expect("grpc response");
    let mut send = respond
        .send_response(response, false)
        .expect("send response");
    let (input_tx, input_rx) = mpsc::channel();
    let (output_tx, mut output_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let mut body = request.into_body();
    let read_task = tokio::spawn(async move {
        let mut buffer = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.expect("read grpc body");
            let len = chunk.len();
            buffer.extend_from_slice(&chunk);
            let _ = body.flow_control().release_capacity(len);
            while let Some(payload) = take_grpc_payload(&mut buffer).expect("grpc payload") {
                if input_tx.send(payload).is_err() {
                    return;
                }
            }
        }
    });
    let write_task = tokio::spawn(async move {
        while let Some(payload) = output_rx.recv().await {
            send_h2_data(&mut send, Bytes::from(encode_grpc_hunk(&payload)), false)
                .await
                .expect("write grpc hunk");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().expect("grpc-status"));
        send.send_trailers(trailers).expect("write grpc trailers");
    });
    tokio::task::spawn_blocking(move || handler(GrpcTestStream::new(input_rx, output_tx)))
        .await
        .expect("handler task");
    write_task.await.expect("write task");
    read_task.abort();
}

struct GrpcTestStream {
    input_rx: mpsc::Receiver<Vec<u8>>,
    output_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    buffer: Vec<u8>,
}

impl GrpcTestStream {
    fn new(
        input_rx: mpsc::Receiver<Vec<u8>>,
        output_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        Self {
            input_rx,
            output_tx,
            buffer: Vec::new(),
        }
    }
}

impl Read for GrpcTestStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        while self.buffer.is_empty() {
            self.buffer = self
                .input_rx
                .recv()
                .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "grpc input closed"))?;
        }
        let len = output.len().min(self.buffer.len());
        output[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Ok(len)
    }
}

impl Write for GrpcTestStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.output_tx
            .send(input.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "grpc output closed"))?;
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct H2TestStream {
    input_rx: mpsc::Receiver<Vec<u8>>,
    output_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    buffer: Vec<u8>,
}

impl H2TestStream {
    fn new(
        input_rx: mpsc::Receiver<Vec<u8>>,
        output_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        Self {
            input_rx,
            output_tx,
            buffer: Vec::new(),
        }
    }
}

impl Read for H2TestStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        while self.buffer.is_empty() {
            self.buffer = self
                .input_rx
                .recv()
                .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "h2 input closed"))?;
        }
        let len = output.len().min(self.buffer.len());
        output[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Ok(len)
    }
}

impl Write for H2TestStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.output_tx
            .send(input.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "h2 output closed"))?;
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_grpc_hunk(payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(2 + payload.len());
    message.push(0x0a);
    encode_varint(payload.len() as u64, &mut message);
    message.extend_from_slice(payload);
    let mut output = Vec::with_capacity(5 + message.len());
    output.push(0);
    output.extend_from_slice(&(message.len() as u32).to_be_bytes());
    output.extend_from_slice(&message);
    output
}

async fn send_h2_data(
    send: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
    end_stream: bool,
) -> io::Result<()> {
    if data.is_empty() {
        return send
            .send_data(data, end_stream)
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()));
    }
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let capacity = loop {
            match poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(capacity)) if capacity > 0 => break capacity,
                Some(Ok(_)) => continue,
                Some(Err(error)) => {
                    return Err(io::Error::new(io::ErrorKind::Other, error.to_string()));
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "stream closed before capacity",
                    ));
                }
            }
        };
        let chunk_len = capacity.min(data.len());
        let chunk = data.split_to(chunk_len);
        let chunk_ends_stream = end_stream && data.is_empty();
        send.send_data(chunk, chunk_ends_stream)
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
    }
    Ok(())
}

fn take_grpc_payload(buffer: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    if buffer.len() < 5 {
        return Ok(None);
    }
    if buffer[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "compressed grpc messages are not supported",
        ));
    }
    let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
    if buffer.len() < 5 + len {
        return Ok(None);
    }
    let message = buffer[5..5 + len].to_vec();
    buffer.drain(..5 + len);
    decode_hunk_message(&message).map(Some)
}

fn decode_hunk_message(message: &[u8]) -> io::Result<Vec<u8>> {
    let mut cursor = 0usize;
    let mut data = None;
    while cursor < message.len() {
        let key = decode_varint(message, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (1, 2) => {
                let len = decode_varint(message, &mut cursor)? as usize;
                if cursor + len > message.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated hunk data",
                    ));
                }
                data = Some(message[cursor..cursor + len].to_vec());
                cursor += len;
            }
            (_, 0) => {
                let _ = decode_varint(message, &mut cursor)?;
            }
            (_, 2) => {
                let len = decode_varint(message, &mut cursor)? as usize;
                if cursor + len > message.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated hunk field",
                    ));
                }
                cursor += len;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported hunk wire type",
                ));
            }
        }
    }
    Ok(data.unwrap_or_default())
}

fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn decode_varint(input: &[u8], cursor: &mut usize) -> io::Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    while *cursor < input.len() && shift < 64 {
        let byte = input[*cursor];
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "invalid varint"))
}

fn write_server_binary_frame(stream: &mut impl Write, payload: &[u8]) {
    assert!(payload.len() <= 125);
    stream
        .write_all(&[0x82, payload.len() as u8])
        .expect("write frame header");
    stream.write_all(payload).expect("write frame payload");
}

fn spawn_hy2_echo_server() -> (SocketAddr, thread::JoinHandle<()>) {
    let (addr_tx, addr_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build HY2 test runtime");
        runtime.block_on(async move {
            let endpoint = quinn::Endpoint::server(
                hy2_h3_test_server_config(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            )
            .expect("bind HY2 test server");
            addr_tx
                .send(endpoint.local_addr().expect("HY2 test server addr"))
                .expect("send HY2 addr");
            let incoming = endpoint.accept().await.expect("accept HY2 connection");
            let connection = incoming.await.expect("HY2 QUIC connection");
            let mut h3_connection: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
                h3::server::builder()
                    .build(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .expect("HY2 H3 server connection");
            let resolver = h3_connection
                .accept()
                .await
                .expect("accept HY2 auth")
                .expect("HY2 auth request exists");
            let (request, mut auth_stream) =
                resolver.resolve_request().await.expect("resolve HY2 auth");
            assert_eq!(request.headers()["Hysteria-Auth"], "secret");
            auth_stream
                .send_response(http::Response::builder().status(233).body(()).unwrap())
                .await
                .expect("send HY2 auth OK");
            auth_stream.finish().await.expect("finish HY2 auth OK");
            let (mut send, mut recv) = connection.accept_bi().await.expect("accept HY2 TCP");
            let mut request = [0; 19];
            recv.read_exact(&mut request)
                .await
                .expect("read HY2 TCP request");
            assert_eq!(
                request,
                [
                    0x44, 0x01, 0x0f, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
                    b'm', b':', b'4', b'4', b'3', 0x00,
                ]
            );
            send.write_all(&[0x00, 0x00, 0x00])
                .await
                .expect("write HY2 TCP OK response");
            let mut payload = [0; 4];
            recv.read_exact(&mut payload)
                .await
                .expect("read HY2 payload");
            assert_eq!(&payload, b"ping");
            send.write_all(b"pong").await.expect("write HY2 response");
            send.finish().expect("finish HY2 response stream");
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
    });
    (addr_rx.recv().expect("receive HY2 addr"), handle)
}

fn spawn_tuic_echo_server() -> (SocketAddr, thread::JoinHandle<()>) {
    let (addr_tx, addr_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build TUIC test runtime");
        runtime.block_on(async move {
            let endpoint = quinn::Endpoint::server(
                hy2_h3_test_server_config(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            )
            .expect("bind TUIC test server");
            addr_tx
                .send(endpoint.local_addr().expect("TUIC test server addr"))
                .expect("send TUIC addr");
            let incoming = endpoint.accept().await.expect("accept TUIC connection");
            let connection = incoming.await.expect("TUIC QUIC connection");
            let mut auth_recv = connection.accept_uni().await.expect("accept TUIC auth");
            let auth = auth_recv
                .read_to_end(64)
                .await
                .expect("read TUIC auth command");
            let expected_auth = keli_net_core::tuic_authenticate_command(
                &connection,
                "00112233-4455-6677-8899-aabbccddeeff",
                "secret",
            )
            .expect("expected TUIC auth");
            assert_eq!(auth, expected_auth);
            let (mut send, mut recv) = connection.accept_bi().await.expect("accept TUIC TCP");
            let expected_connect =
                keli_protocol::encode_tuic_connect_command(&Endpoint::new("example.com", 443))
                    .expect("expected TUIC connect");
            let mut connect = vec![0; expected_connect.len()];
            recv.read_exact(&mut connect)
                .await
                .expect("read TUIC connect command");
            assert_eq!(connect, expected_connect);
            let mut payload = [0; 4];
            recv.read_exact(&mut payload)
                .await
                .expect("read TUIC payload");
            assert_eq!(&payload, b"ping");
            send.write_all(b"pong").await.expect("write TUIC response");
            send.finish().expect("finish TUIC response stream");
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
    });
    (addr_rx.recv().expect("receive TUIC addr"), handle)
}

fn spawn_hy2_udp_echo_server() -> (SocketAddr, thread::JoinHandle<()>) {
    let (addr_tx, addr_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build HY2 UDP test runtime");
        runtime.block_on(async move {
            let endpoint = quinn::Endpoint::server(
                hy2_h3_test_server_config(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            )
            .expect("bind HY2 UDP test server");
            addr_tx
                .send(endpoint.local_addr().expect("HY2 UDP test server addr"))
                .expect("send HY2 UDP addr");
            let incoming = endpoint.accept().await.expect("accept HY2 connection");
            let connection = incoming.await.expect("HY2 QUIC connection");
            let mut h3_connection: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
                h3::server::builder()
                    .build(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .expect("HY2 H3 server connection");
            let resolver = h3_connection
                .accept()
                .await
                .expect("accept HY2 auth")
                .expect("HY2 auth request exists");
            let (request, mut auth_stream) =
                resolver.resolve_request().await.expect("resolve HY2 auth");
            assert_eq!(request.headers()["Hysteria-Auth"], "secret");
            auth_stream
                .send_response(http::Response::builder().status(233).body(()).unwrap())
                .await
                .expect("send HY2 auth OK");
            auth_stream.finish().await.expect("finish HY2 auth OK");

            let message = keli_net_core::hy2_read_udp_datagram(&connection)
                .await
                .expect("read HY2 UDP request");
            assert_eq!(message.address, Endpoint::new("example.com", 53));
            assert_eq!(message.payload, b"ping");
            keli_net_core::hy2_send_udp_datagram(
                &connection,
                message.session_id,
                message.packet_id,
                message.fragment_id,
                message.fragment_count,
                &Endpoint::new("127.0.0.1", 53),
                b"pong",
            )
            .expect("send HY2 UDP response");
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
    });
    (addr_rx.recv().expect("receive HY2 UDP addr"), handle)
}

fn spawn_tuic_udp_echo_server() -> (SocketAddr, thread::JoinHandle<()>) {
    let (addr_tx, addr_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build TUIC UDP test runtime");
        runtime.block_on(async move {
            let endpoint = quinn::Endpoint::server(
                hy2_h3_test_server_config(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            )
            .expect("bind TUIC UDP test server");
            addr_tx
                .send(endpoint.local_addr().expect("TUIC UDP test server addr"))
                .expect("send TUIC UDP addr");
            let incoming = endpoint.accept().await.expect("accept TUIC connection");
            let connection = incoming.await.expect("TUIC QUIC connection");
            let mut auth_recv = connection.accept_uni().await.expect("accept TUIC auth");
            let auth = auth_recv
                .read_to_end(64)
                .await
                .expect("read TUIC auth command");
            let expected_auth = keli_net_core::tuic_authenticate_command(
                &connection,
                "00112233-4455-6677-8899-aabbccddeeff",
                "secret",
            )
            .expect("expected TUIC auth");
            assert_eq!(auth, expected_auth);

            let packet = keli_net_core::tuic_read_packet_datagram(&connection)
                .await
                .expect("read TUIC UDP request");
            assert_eq!(packet.source, Endpoint::new("example.com", 53));
            assert_eq!(packet.payload, b"ping");
            keli_net_core::tuic_send_packet_datagram(
                &connection,
                packet.associate_id,
                packet.packet_id,
                packet.fragment_total,
                packet.fragment_id,
                &Endpoint::new("127.0.0.1", 53),
                b"pong",
            )
            .expect("send TUIC UDP response");
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
    });
    (addr_rx.recv().expect("receive TUIC UDP addr"), handle)
}

fn spawn_socks5_tcp_proxy_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind socks5 proxy");
    let port = listener.local_addr().expect("socks5 proxy addr").port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept socks5 proxy");
        let mut hello = [0; 3];
        stream.read_exact(&mut hello).expect("read socks5 hello");
        assert_eq!(hello, [0x05, 0x01, 0x00]);
        stream
            .write_all(&[0x05, 0x00])
            .expect("write socks5 hello response");

        let mut request = [0; 18];
        stream
            .read_exact(&mut request)
            .expect("read socks5 connect request");
        assert_eq!(
            request,
            [
                0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
                b'o', b'm', 0x01, 0xbb,
            ]
        );
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .expect("write socks5 connect response");

        let mut payload = [0; 4];
        stream
            .read_exact(&mut payload)
            .expect("read socks5 payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write socks5 response");
    });
    (port, handle)
}

fn spawn_http_connect_proxy_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind http proxy");
    let port = listener.local_addr().expect("http proxy addr").port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept http proxy");
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(request.contains("Host: example.com:443\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .expect("write http proxy response");

        let mut payload = [0; 4];
        stream.read_exact(&mut payload).expect("read http payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write http response");
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

fn tls_server_config() -> Arc<rustls::ServerConfig> {
    let cert = generate_simple_self_signed(vec!["edge.example".to_string()]).expect("cert");
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    Arc::new(
        rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("server protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server config"),
    )
}

fn h2_tls_server_config() -> Arc<rustls::ServerConfig> {
    let mut config = Arc::unwrap_or_clone(tls_server_config());
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

fn hy2_h3_test_server_config() -> quinn::ServerConfig {
    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let mut tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("server protocol versions")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .expect("server config");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("quic server config"),
    ))
}

fn assert_anytls_auth(stream: &mut impl Read, password: &str) {
    let mut header = [0; 34];
    stream.read_exact(&mut header).expect("read anytls auth");
    let expected = Sha256::digest(password.as_bytes());
    assert_eq!(&header[..32], expected.as_slice());
    let padding_len = u16::from_be_bytes([header[32], header[33]]) as usize;
    assert_eq!(padding_len, 30);
    let mut padding = vec![0; padding_len];
    stream
        .read_exact(&mut padding)
        .expect("read anytls auth padding");
}

fn read_anytls_frame(stream: &mut impl Read) -> (u8, u32, Vec<u8>) {
    let mut header = [0; 7];
    stream
        .read_exact(&mut header)
        .expect("read anytls frame header");
    let cmd = header[0];
    let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0; len];
    stream
        .read_exact(&mut data)
        .expect("read anytls frame data");
    (cmd, sid, data)
}

fn write_anytls_frame(stream: &mut impl Write, cmd: u8, sid: u32, data: &[u8]) {
    let mut header = [0; 7];
    header[0] = cmd;
    header[1..5].copy_from_slice(&sid.to_be_bytes());
    header[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    stream.write_all(&header).expect("write anytls header");
    stream.write_all(data).expect("write anytls data");
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

#[derive(Debug)]
struct MieruTestSegment {
    protocol_type: u8,
    session_id: u32,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct MieruTestWriter {
    stream: TcpStream,
    key: [u8; 32],
    nonce: [u8; MIERU_NONCE_LEN],
    session_id: u32,
    sequence: u32,
    sent_nonce: bool,
}

impl MieruTestWriter {
    fn new(stream: TcpStream, key: [u8; 32], session_id: u32) -> Self {
        let mut nonce = [7u8; MIERU_NONCE_LEN];
        apply_mieru_nonce_user_hint_for_test(&mut nonce, "user");
        Self {
            stream,
            key,
            nonce,
            session_id,
            sequence: 0,
            sent_nonce: false,
        }
    }

    fn write_segment(&mut self, protocol_type: u8, payload: &[u8]) {
        let metadata =
            mieru_metadata_for_test(protocol_type, self.session_id, self.sequence, payload.len());
        self.sequence = self.sequence.saturating_add(1);
        let mut segment = Vec::new();
        if !self.sent_nonce {
            segment.extend_from_slice(&self.nonce);
            self.sent_nonce = true;
        }
        segment.extend(mieru_xchacha_seal_for_test(
            &self.key,
            &self.nonce,
            &metadata,
        ));
        increment_mieru_nonce_for_test(&mut self.nonce);
        if !payload.is_empty() {
            segment.extend(mieru_xchacha_seal_for_test(&self.key, &self.nonce, payload));
            increment_mieru_nonce_for_test(&mut self.nonce);
        }
        self.stream
            .write_all(&segment)
            .expect("write mieru segment");
    }
}

fn read_mieru_segment_for_test(
    stream: &mut TcpStream,
    key: &[u8; 32],
    nonce: &mut Option<[u8; MIERU_NONCE_LEN]>,
) -> MieruTestSegment {
    let mut buffer = Vec::new();
    loop {
        if let Some(segment) = try_read_mieru_segment_for_test(&buffer, key, nonce) {
            return segment;
        }
        let mut temp = [0; 4096];
        let read = stream.read(&mut temp).expect("read mieru segment");
        assert_ne!(read, 0, "mieru stream closed before segment");
        buffer.extend_from_slice(&temp[..read]);
    }
}

fn encode_mieru_udp_frame_for_test(packet: &[u8]) -> Vec<u8> {
    assert!(packet.len() <= u16::MAX as usize);
    let mut output = Vec::with_capacity(packet.len() + 4);
    output.push(MIERU_UDP_MARKER_START);
    output.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    output.extend_from_slice(packet);
    output.push(MIERU_UDP_MARKER_END);
    output
}

fn decode_mieru_udp_frame_for_test(input: &[u8]) -> Vec<u8> {
    assert!(input.len() >= 4);
    assert_eq!(input[0], MIERU_UDP_MARKER_START);
    let len = u16::from_be_bytes([input[1], input[2]]) as usize;
    assert_eq!(input.len(), len + 4);
    assert_eq!(input[input.len() - 1], MIERU_UDP_MARKER_END);
    input[3..3 + len].to_vec()
}

fn try_read_mieru_segment_for_test(
    buffer: &[u8],
    key: &[u8; 32],
    nonce_state: &mut Option<[u8; MIERU_NONCE_LEN]>,
) -> Option<MieruTestSegment> {
    let has_nonce = nonce_state.is_none();
    let metadata_offset = if has_nonce {
        if buffer.len() < MIERU_NONCE_LEN {
            return None;
        }
        let mut nonce = [0; MIERU_NONCE_LEN];
        nonce.copy_from_slice(&buffer[..MIERU_NONCE_LEN]);
        *nonce_state = Some(nonce);
        MIERU_NONCE_LEN
    } else {
        0
    };
    if buffer.len() < metadata_offset + MIERU_ENCRYPTED_METADATA_LEN {
        return None;
    }
    let nonce = nonce_state.as_mut().expect("nonce initialized");
    let metadata = mieru_xchacha_open_for_test(
        key,
        nonce,
        &buffer[metadata_offset..metadata_offset + MIERU_ENCRYPTED_METADATA_LEN],
    );
    let protocol_type = metadata[0];
    let session_id = u32::from_be_bytes([metadata[6], metadata[7], metadata[8], metadata[9]]);
    increment_mieru_nonce_for_test(nonce);
    let payload_len = if matches!(
        protocol_type,
        MIERU_OPEN_SESSION_REQUEST | MIERU_OPEN_SESSION_RESPONSE
    ) {
        u16::from_be_bytes([metadata[15], metadata[16]]) as usize
    } else {
        u16::from_be_bytes([metadata[22], metadata[23]]) as usize
    };
    let encrypted_payload_len = if payload_len == 0 {
        0
    } else {
        payload_len + MIERU_TAG_LEN
    };
    let payload_offset = metadata_offset + MIERU_ENCRYPTED_METADATA_LEN;
    if buffer.len() < payload_offset + encrypted_payload_len {
        return None;
    }
    let payload = if payload_len == 0 {
        Vec::new()
    } else {
        let payload = mieru_xchacha_open_for_test(
            key,
            nonce,
            &buffer[payload_offset..payload_offset + encrypted_payload_len],
        );
        increment_mieru_nonce_for_test(nonce);
        payload
    };
    Some(MieruTestSegment {
        protocol_type,
        session_id,
        payload,
    })
}

fn mieru_metadata_for_test(
    protocol_type: u8,
    session_id: u32,
    sequence: u32,
    payload_len: usize,
) -> [u8; MIERU_METADATA_LEN] {
    let mut output = [0; MIERU_METADATA_LEN];
    output[0] = protocol_type;
    output[2..6].copy_from_slice(&((now_unix_secs_for_mieru_test() / 60) as u32).to_be_bytes());
    output[6..10].copy_from_slice(&session_id.to_be_bytes());
    output[10..14].copy_from_slice(&sequence.to_be_bytes());
    if matches!(
        protocol_type,
        MIERU_OPEN_SESSION_REQUEST | MIERU_OPEN_SESSION_RESPONSE
    ) {
        output[14] = MIERU_STATUS_OK;
        output[15..17].copy_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        output[18..20].copy_from_slice(&(64u16).to_be_bytes());
        output[22..24].copy_from_slice(&(payload_len as u16).to_be_bytes());
    }
    output
}

fn derive_mieru_key_for_test(username: &str, password: &str) -> [u8; 32] {
    let mut password_hasher = Sha256::new();
    password_hasher.update(password.as_bytes());
    password_hasher.update([0]);
    password_hasher.update(username.as_bytes());
    let hashed_password = password_hasher.finalize();

    let mut time_hasher = Sha256::new();
    time_hasher.update(
        (rounded_unix_time_for_mieru_test(now_unix_secs_for_mieru_test()) as u64).to_be_bytes(),
    );
    let time_salt = time_hasher.finalize();

    let mut key = [0; 32];
    pbkdf2_hmac_sha256_for_mieru_test(&hashed_password, &time_salt, 64, &mut key);
    key
}

fn pbkdf2_hmac_sha256_for_mieru_test(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output: &mut [u8],
) {
    let mut block_index = 1u32;
    let mut offset = 0usize;
    while offset < output.len() {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(password).expect("hmac key");
        Mac::update(&mut mac, salt);
        Mac::update(&mut mac, &block_index.to_be_bytes());
        let mut u = mac.finalize().into_bytes().to_vec();
        let mut block = u.clone();
        for _ in 1..iterations {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(password).expect("hmac key");
            Mac::update(&mut mac, &u);
            u = mac.finalize().into_bytes().to_vec();
            for (left, right) in block.iter_mut().zip(&u) {
                *left ^= *right;
            }
        }
        let take = (output.len() - offset).min(block.len());
        output[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
        block_index = block_index.saturating_add(1);
    }
}

fn apply_mieru_nonce_user_hint_for_test(nonce: &mut [u8; MIERU_NONCE_LEN], username: &str) {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update(&nonce[..16]);
    let digest = hasher.finalize();
    nonce[20..24].copy_from_slice(&digest[..4]);
}

fn increment_mieru_nonce_for_test(nonce: &mut [u8; MIERU_NONCE_LEN]) {
    for byte in nonce.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
}

fn mieru_xchacha_seal_for_test(
    key: &[u8; 32],
    nonce: &[u8; MIERU_NONCE_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    XChaCha20Poly1305::new_from_slice(key)
        .expect("xchacha key")
        .encrypt(XNonce::from_slice(nonce), plaintext)
        .expect("seal mieru segment")
}

fn mieru_xchacha_open_for_test(
    key: &[u8; 32],
    nonce: &[u8; MIERU_NONCE_LEN],
    ciphertext: &[u8],
) -> Vec<u8> {
    XChaCha20Poly1305::new_from_slice(key)
        .expect("xchacha key")
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .expect("open mieru segment")
}

fn rounded_unix_time_for_mieru_test(unix_secs: i64) -> i64 {
    ((unix_secs + MIERU_KEY_WINDOW_SECS / 2) / MIERU_KEY_WINDOW_SECS) * MIERU_KEY_WINDOW_SECS
}

fn now_unix_secs_for_mieru_test() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
