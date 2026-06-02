use std::io::Cursor;

use keli_net_core::{http_proxy_bad_request_response, parse_http_proxy_request, HttpProxyError};

#[test]
fn parses_absolute_form_http_get_and_rewrites_origin_form() {
    let mut input = Cursor::new(
        b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n",
    );

    let request = parse_http_proxy_request(&mut input).expect("HTTP proxy request should parse");

    assert_eq!(request.host, "example.com");
    assert_eq!(request.port, 80);
    assert_eq!(request.method, "GET");
    assert_eq!(request.path_and_query, "/path?q=1");
    assert_eq!(
        request.rewritten_header,
        b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
    );
}

#[test]
fn parses_absolute_form_with_explicit_port() {
    let mut input =
        Cursor::new(b"GET http://127.0.0.1:8080/health HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n");

    let request = parse_http_proxy_request(&mut input).expect("HTTP proxy request should parse");

    assert_eq!(request.host, "127.0.0.1");
    assert_eq!(request.port, 8080);
    assert_eq!(request.path_and_query, "/health");
}

#[test]
fn parses_origin_form_with_host_header() {
    let mut input = Cursor::new(b"GET /status HTTP/1.1\r\nHost: example.com:8080\r\n\r\n");

    let request = parse_http_proxy_request(&mut input).expect("origin-form request should parse");

    assert_eq!(request.host, "example.com");
    assert_eq!(request.port, 8080);
    assert_eq!(request.path_and_query, "/status");
}

#[test]
fn rejects_https_absolute_url_without_connect() {
    let mut input = Cursor::new(b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n");

    let error = parse_http_proxy_request(&mut input).expect_err("https URL must be rejected");

    assert_eq!(
        error,
        HttpProxyError::UnsupportedScheme("https".to_string())
    );
}

#[test]
fn builds_http_proxy_bad_request_response() {
    assert_eq!(
        http_proxy_bad_request_response(),
        b"HTTP/1.1 400 Bad Request\r\n\r\n"
    );
}
