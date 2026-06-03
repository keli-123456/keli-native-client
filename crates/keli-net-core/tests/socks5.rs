use std::io::Cursor;

use keli_net_core::{
    encode_socks5_udp_datagram, parse_socks5_handshake, parse_socks5_request,
    parse_socks5_udp_datagram, socks5_no_auth_response, socks5_reply, Socks5Address, Socks5Command,
    Socks5ReplyCode,
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

#[test]
fn parses_socks5_udp_domain_datagram() {
    let input = [
        0x00, 0x00, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
        b'm', 0x00, 0x35, b'p', b'i', b'n', b'g',
    ];

    let datagram = parse_socks5_udp_datagram(&input).expect("parse udp datagram");

    assert_eq!(
        datagram.address,
        Socks5Address::Domain("example.com".to_string())
    );
    assert_eq!(datagram.port, 53);
    assert_eq!(datagram.payload, b"ping");
}

#[test]
fn encodes_socks5_udp_ipv4_and_ipv6_datagrams() {
    let ipv4 =
        encode_socks5_udp_datagram(&Socks5Address::Ipv4("127.0.0.1".parse().unwrap()), 53, b"a")
            .expect("encode ipv4 datagram");
    assert_eq!(
        ipv4,
        [0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x35, b'a']
    );

    let ipv6 = encode_socks5_udp_datagram(&Socks5Address::Ipv6("::1".parse().unwrap()), 443, b"b")
        .expect("encode ipv6 datagram");
    assert_eq!(ipv6[0..4], [0x00, 0x00, 0x00, 0x04]);
    assert_eq!(&ipv6[4..20], &std::net::Ipv6Addr::LOCALHOST.octets());
    assert_eq!(ipv6[20..], [0x01, 0xbb, b'b']);
}

#[test]
fn rejects_fragmented_socks5_udp_datagram() {
    let input = [0x00, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0x00, 0x35];

    let error = parse_socks5_udp_datagram(&input).expect_err("fragmentation is unsupported");

    assert!(error.to_string().contains("fragmented"));
}
