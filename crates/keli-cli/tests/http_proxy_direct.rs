use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use keli_cli::handle_mixed_connection;

#[test]
fn http_proxy_get_relays_to_direct_tcp_target() {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind target");
    let target_port = target.local_addr().expect("target addr").port();
    let target_thread = thread::spawn(move || {
        let (mut stream, _) = target.accept().expect("accept target");
        let mut request = Vec::new();
        read_until_header_end(&mut stream, &mut request);
        let request = String::from_utf8(request).expect("request utf8");
        assert!(request.starts_with("GET /hello HTTP/1.1\r\n"));
        assert!(request.contains("Host: 127.0.0.1:"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong")
            .expect("write target response");
        stream.shutdown(Shutdown::Both).ok();
    });

    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_mixed_connection(&mut stream).expect("handle mixed HTTP proxy");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    write!(
        client,
        "GET http://127.0.0.1:{target_port}/hello HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
    )
    .expect("write HTTP request");

    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .expect("read HTTP response");
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("pong"));
    client.shutdown(Shutdown::Both).ok();

    inbound_thread.join().expect("inbound thread");
    target_thread.join().expect("target thread");
}

fn read_until_header_end(stream: &mut TcpStream, output: &mut Vec<u8>) {
    let mut byte = [0; 1];
    while !output.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read request byte");
        output.push(byte[0]);
    }
}
