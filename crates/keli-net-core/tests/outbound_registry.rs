use std::io::{Read, Write};
use std::time::Duration;

use keli_net_core::{OutboundRegistry, OutboundTarget, VlessTcpOutbound};
use keli_protocol::Endpoint;

#[test]
fn registered_direct_outbound_connects_to_target() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind target");
    let port = listener.local_addr().expect("target addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept target");
        let mut request = [0; 4];
        stream.read_exact(&mut request).expect("read request");
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").expect("write response");
    });
    let mut registry = OutboundRegistry::new();
    registry.add_direct("proxy");

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("127.0.0.1", port),
            Duration::from_secs(1),
        )
        .expect("registered direct outbound should connect");
    stream.write_all(b"ping").expect("write request");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read response");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn missing_outbound_tag_is_unsupported() {
    let registry = OutboundRegistry::new();

    let error = registry
        .connect(
            "missing",
            &OutboundTarget::new("127.0.0.1", 443),
            Duration::from_millis(10),
        )
        .expect_err("missing outbound should fail");

    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
}

#[test]
fn registered_vless_tcp_outbound_writes_header_and_relays_stream() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind vless server");
    let port = listener.local_addr().expect("vless addr").port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept vless server");
        let mut request_header = [0; 34];
        stream
            .read_exact(&mut request_header)
            .expect("read vless request header");
        assert_eq!(
            request_header,
            [
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x01, 0x01, 0xbb, 0x02, 0x0b, b'e', b'x', b'a', b'm', b'p',
                b'l', b'e', b'.', b'c', b'o', b'm',
            ]
        );
        stream
            .write_all(&[0x00, 0x00])
            .expect("write vless response header");
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).expect("read relay payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write relay payload");
    });
    let mut registry = OutboundRegistry::new();
    registry.add_vless_tcp(
        "proxy",
        VlessTcpOutbound::new(
            Endpoint::new("127.0.0.1", port),
            "00112233-4455-6677-8899-aabbccddeeff",
            None,
        ),
    );

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(1),
        )
        .expect("registered vless outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}
