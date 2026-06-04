use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use keli_cli::{handle_mixed_connection_with_routes, MixedDnsOptions, MixedProxyRuntime};
use keli_net_core::{
    DnsAddressFamilyPolicy, RouteAction, RouteEngine, RouteIpCidr, RouteMatcher, RouteRule,
};

#[test]
fn http_connect_block_rule_returns_forbidden_without_connecting_target() {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind target");
    let target_port = target.local_addr().expect("target addr").port();
    target
        .set_nonblocking(true)
        .expect("target nonblocking mode");

    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let runtime = block_localhost_runtime();
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_mixed_connection_with_routes(&mut stream, &runtime).expect("handle blocked request");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    write!(
        client,
        "CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
    )
    .expect("write CONNECT");

    let mut response = String::new();
    read_until_header_end(&mut client, &mut response);
    assert_eq!(response, "HTTP/1.1 403 Forbidden\r\n\r\n");

    inbound_thread.join().expect("inbound thread");
    assert!(
        target.accept().is_err(),
        "blocked route must not connect to the target"
    );
}

#[test]
fn socks5_block_rule_returns_connection_not_allowed() {
    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let runtime = block_localhost_runtime();
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_mixed_connection_with_routes(&mut stream, &runtime).expect("handle blocked request");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    client.write_all(&[0x05, 0x01, 0x00]).expect("write hello");
    let mut hello = [0; 2];
    client.read_exact(&mut hello).expect("read hello");
    assert_eq!(hello, [0x05, 0x00]);

    client
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb])
        .expect("write request");
    let mut reply = [0; 10];
    client.read_exact(&mut reply).expect("read reply");
    assert_eq!(reply, [0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

    inbound_thread.join().expect("inbound thread");
}

#[test]
fn direct_route_respects_ipv6_only_dns_policy_for_ipv4_literals() {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind target");
    let target_port = target.local_addr().expect("target addr").port();
    target
        .set_nonblocking(true)
        .expect("target nonblocking mode");

    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let mut runtime = MixedProxyRuntime::with_routes(RouteEngine::new(RouteAction::Direct));
    runtime.dns_options = MixedDnsOptions {
        address_family_policy: DnsAddressFamilyPolicy::Ipv6Only,
        ..MixedDnsOptions::default()
    };
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_mixed_connection_with_routes(&mut stream, &runtime)
            .expect_err("IPv6-only DNS policy should reject IPv4 literal");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    write!(
        client,
        "CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
    )
    .expect("write CONNECT");

    let mut response = String::new();
    read_until_header_end(&mut client, &mut response);
    assert_eq!(response, "HTTP/1.1 400 Bad Request\r\n\r\n");

    inbound_thread.join().expect("inbound thread");
    assert!(
        target.accept().is_err(),
        "DNS address-family policy must prevent connecting to the target"
    );
}

#[test]
fn http_connect_port_rule_blocks_without_connecting_target() {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind target");
    let target_port = target.local_addr().expect("target addr").port();
    target
        .set_nonblocking(true)
        .expect("target nonblocking mode");

    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let mut routes = RouteEngine::new(RouteAction::Direct);
    routes.add_rule(RouteRule {
        name: "block-selected-port".to_string(),
        matcher: RouteMatcher::PortExact(target_port),
        action: RouteAction::Block,
    });
    let runtime = MixedProxyRuntime::with_routes(routes);
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_mixed_connection_with_routes(&mut stream, &runtime).expect("handle blocked request");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    write!(
        client,
        "CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
    )
    .expect("write CONNECT");

    let mut response = String::new();
    read_until_header_end(&mut client, &mut response);
    assert_eq!(response, "HTTP/1.1 403 Forbidden\r\n\r\n");

    inbound_thread.join().expect("inbound thread");
    assert!(
        target.accept().is_err(),
        "port route must not connect to the target"
    );
}

#[test]
fn socks5_cidr_rule_blocks_without_connecting_target() {
    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let mut routes = RouteEngine::new(RouteAction::Direct);
    routes.add_rule(RouteRule {
        name: "block-loopback-cidr".to_string(),
        matcher: RouteMatcher::IpCidr(
            RouteIpCidr::new("127.42.0.1".parse().expect("valid IP"), 8).expect("valid CIDR"),
        ),
        action: RouteAction::Block,
    });
    let runtime = MixedProxyRuntime::with_routes(routes);
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_mixed_connection_with_routes(&mut stream, &runtime).expect("handle blocked request");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    client.write_all(&[0x05, 0x01, 0x00]).expect("write hello");
    let mut hello = [0; 2];
    client.read_exact(&mut hello).expect("read hello");
    assert_eq!(hello, [0x05, 0x00]);

    client
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb])
        .expect("write request");
    let mut reply = [0; 10];
    client.read_exact(&mut reply).expect("read reply");
    assert_eq!(reply, [0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

    inbound_thread.join().expect("inbound thread");
}

fn block_localhost_runtime() -> MixedProxyRuntime {
    let mut routes = RouteEngine::new(RouteAction::Direct);
    routes.add_rule(RouteRule {
        name: "block-localhost".to_string(),
        matcher: RouteMatcher::IpExact("127.0.0.1".parse().expect("valid IP")),
        action: RouteAction::Block,
    });
    MixedProxyRuntime::with_routes(routes)
}

fn read_until_header_end(stream: &mut TcpStream, output: &mut String) {
    let mut bytes = Vec::new();
    let mut byte = [0; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read response byte");
        bytes.push(byte[0]);
    }
    *output = String::from_utf8(bytes).expect("response utf8");
}
