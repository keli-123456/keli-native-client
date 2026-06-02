use std::io::Cursor;

use keli_net_core::{http_connect_success_response, parse_http_connect_request, HttpConnectError};

#[test]
fn parses_http_connect_domain_target() {
    let mut input = Cursor::new(
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: test\r\n\r\n",
    );

    let request = parse_http_connect_request(&mut input).expect("CONNECT should parse");

    assert_eq!(request.host, "example.com");
    assert_eq!(request.port, 443);
    assert_eq!(request.http_version, "HTTP/1.1");
}

#[test]
fn parses_http_connect_ipv6_target() {
    let mut input = Cursor::new(b"CONNECT [::1]:8443 HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n");

    let request = parse_http_connect_request(&mut input).expect("IPv6 CONNECT should parse");

    assert_eq!(request.host, "::1");
    assert_eq!(request.port, 8443);
}

#[test]
fn rejects_non_connect_method() {
    let mut input = Cursor::new(b"GET http://example.com/ HTTP/1.1\r\n\r\n");

    let error = parse_http_connect_request(&mut input).expect_err("GET should be rejected");

    assert_eq!(
        error,
        HttpConnectError::UnsupportedMethod("GET".to_string())
    );
}

#[test]
fn builds_http_connect_success_response() {
    assert_eq!(
        http_connect_success_response(),
        b"HTTP/1.1 200 Connection Established\r\n\r\n"
    );
}
