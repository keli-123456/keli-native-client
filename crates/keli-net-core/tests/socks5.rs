use std::io::Cursor;

use keli_net_core::{
    parse_socks5_handshake, parse_socks5_request, socks5_no_auth_response, socks5_reply,
    Socks5Address, Socks5Command, Socks5ReplyCode,
};

#[test]
fn parses_socks5_no_auth_handshake() {
    let mut input = Cursor::new([0x05, 0x01, 0x00]);

    let handshake = parse_socks5_handshake(&mut input).expect("handshake should parse");

    assert_eq!(handshake.methods, vec![0x00]);
}

#[test]
fn parses_socks5_connect_domain_request() {
    let mut input = Cursor::new([
        0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
        b'm', 0x01, 0xbb,
    ]);

    let request = parse_socks5_request(&mut input).expect("request should parse");

    assert_eq!(request.command, Socks5Command::Connect);
    assert_eq!(
        request.address,
        Socks5Address::Domain("example.com".to_string())
    );
    assert_eq!(request.port, 443);
}

#[test]
fn rejects_unsupported_socks_version() {
    let mut input = Cursor::new([0x04, 0x01, 0x00]);

    let error = parse_socks5_handshake(&mut input).expect_err("version must be rejected");

    assert!(error.to_string().contains("unsupported SOCKS version"));
}

#[test]
fn builds_no_auth_handshake_response() {
    assert_eq!(socks5_no_auth_response(), [0x05, 0x00]);
}

#[test]
fn builds_command_not_supported_reply() {
    assert_eq!(
        socks5_reply(Socks5ReplyCode::CommandNotSupported),
        [0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
}
