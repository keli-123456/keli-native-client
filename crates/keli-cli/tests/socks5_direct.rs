use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use keli_cli::handle_socks5_connection;
use keli_net_core::{encode_socks5_udp_datagram, parse_socks5_udp_datagram, Socks5Address};

#[test]
fn socks5_connect_relays_to_direct_tcp_target() {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind target");
    let target_port = target.local_addr().expect("target addr").port();
    let target_thread = thread::spawn(move || {
        let (mut stream, _) = target.accept().expect("accept target");
        let mut request = [0; 4];
        stream
            .read_exact(&mut request)
            .expect("read target request");
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").expect("write target response");
        stream.shutdown(Shutdown::Both).ok();
    });

    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_socks5_connection(&mut stream).expect("handle socks5");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    client.write_all(&[0x05, 0x01, 0x00]).expect("write hello");
    let mut hello = [0; 2];
    client.read_exact(&mut hello).expect("read hello response");
    assert_eq!(hello, [0x05, 0x00]);

    let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    request.extend_from_slice(&target_port.to_be_bytes());
    client.write_all(&request).expect("write connect request");
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

    inbound_thread.join().expect("inbound thread");
    target_thread.join().expect("target thread");
}

#[test]
fn socks5_udp_associate_relays_direct_ipv4_datagram() {
    let target = UdpSocket::bind("127.0.0.1:0").expect("bind udp target");
    target
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("target timeout");
    let target_port = target.local_addr().expect("target addr").port();
    let target_thread = thread::spawn(move || {
        let mut request = [0; 1500];
        let (size, from) = target.recv_from(&mut request).expect("read udp target");
        assert_eq!(&request[..size], b"ping");
        target
            .send_to(b"pong", from)
            .expect("write udp target response");
    });

    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_socks5_connection(&mut stream).expect("handle socks5");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
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
    assert_eq!(&reply[4..8], &[127, 0, 0, 1]);
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    assert_ne!(relay_port, 0);

    let udp_client = UdpSocket::bind("127.0.0.1:0").expect("bind udp client");
    udp_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("udp client timeout");
    let request = encode_socks5_udp_datagram(
        &Socks5Address::Ipv4(Ipv4Addr::LOCALHOST),
        target_port,
        b"ping",
    )
    .expect("encode udp request");
    udp_client
        .send_to(&request, ("127.0.0.1", relay_port))
        .expect("send udp request");

    let mut response = [0; 1500];
    let (size, _) = udp_client
        .recv_from(&mut response)
        .expect("read udp response");
    let response = parse_socks5_udp_datagram(&response[..size]).expect("parse udp response");
    assert_eq!(response.address, Socks5Address::Ipv4(Ipv4Addr::LOCALHOST));
    assert_eq!(response.port, target_port);
    assert_eq!(response.payload, b"pong");

    client.shutdown(Shutdown::Both).ok();

    inbound_thread.join().expect("inbound thread");
    target_thread.join().expect("target thread");
}

#[test]
fn socks5_udp_associate_relays_multiple_direct_ipv4_datagrams() {
    let target = UdpSocket::bind("127.0.0.1:0").expect("bind udp target");
    target
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("target timeout");
    let target_port = target.local_addr().expect("target addr").port();
    let target_thread = thread::spawn(move || {
        let exchanges: [(&[u8], &[u8]); 2] = [(b"ping", b"pong"), (b"next", b"done")];
        for (expected, response) in exchanges {
            let mut request = [0; 1500];
            let (size, from) = target.recv_from(&mut request).expect("read udp target");
            assert_eq!(&request[..size], expected);
            target
                .send_to(response, from)
                .expect("write udp target response");
        }
    });

    let inbound = TcpListener::bind("127.0.0.1:0").expect("bind inbound");
    let inbound_port = inbound.local_addr().expect("inbound addr").port();
    let inbound_thread = thread::spawn(move || {
        let (mut stream, _) = inbound.accept().expect("accept inbound");
        handle_socks5_connection(&mut stream).expect("handle socks5");
    });

    let mut client = TcpStream::connect(("127.0.0.1", inbound_port)).expect("connect inbound");
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
        .expect("udp client timeout");
    for (payload, expected_response) in [(b"ping".as_slice(), b"pong"), (b"next", b"done")] {
        let request = encode_socks5_udp_datagram(
            &Socks5Address::Ipv4(Ipv4Addr::LOCALHOST),
            target_port,
            payload,
        )
        .expect("encode udp request");
        udp_client
            .send_to(&request, ("127.0.0.1", relay_port))
            .expect("send udp request");

        let mut response = [0; 1500];
        let (size, _) = udp_client
            .recv_from(&mut response)
            .expect("read udp response");
        let response = parse_socks5_udp_datagram(&response[..size]).expect("parse udp response");
        assert_eq!(response.address, Socks5Address::Ipv4(Ipv4Addr::LOCALHOST));
        assert_eq!(response.port, target_port);
        assert_eq!(response.payload, expected_response);
    }

    client.shutdown(Shutdown::Both).ok();

    inbound_thread.join().expect("inbound thread");
    target_thread.join().expect("target thread");
}
