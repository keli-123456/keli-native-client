use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use keli_cli::{handle_mixed_connection_with_routes, MixedProxyRuntime};
use keli_net_core::{OutboundRegistry, RouteAction, RouteEngine};

#[test]
fn http_connect_uses_registered_outbound_route() {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind target");
    let target_port = target.local_addr().expect("target addr").port();
    let target_thread = thread::spawn(move || {
        let (mut stream, _) = target.accept().expect("accept target");
        let mut request = [0; 4];
        stream.read_exact(&mut request).expect("read request");
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").expect("write response");
        stream.shutdown(Shutdown::Both).ok();
    });

    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let mut outbounds = OutboundRegistry::new();
    outbounds.add_direct("proxy");
    let runtime = MixedProxyRuntime::with_routes_and_outbounds(
        RouteEngine::new(RouteAction::Outbound("proxy".to_string())),
        outbounds,
    );
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_mixed_connection_with_routes(&mut stream, &runtime).expect("handle outbound route");
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

    inbound_thread.join().expect("inbound thread");
    target_thread.join().expect("target thread");
}

fn read_until_header_end(stream: &mut TcpStream, output: &mut Vec<u8>) {
    let mut byte = [0; 1];
    while !output.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read response byte");
        output.push(byte[0]);
    }
}
