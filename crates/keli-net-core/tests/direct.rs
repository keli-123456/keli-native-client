use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use keli_net_core::{
    relay_owned_bidirectional_with_options, relay_tcp_bidirectional,
    relay_tcp_bidirectional_with_options, ConnectionErrorKind, DirectTcpConnector, DnsCache,
    DnsEngine, DnsError, DnsResolver, OutboundTarget, OwnedRelayStream, RelayOptions,
    RouteDestination, RouteTarget, Socks5Address, Socks5Request,
};

#[test]
fn maps_socks5_domain_request_to_outbound_target() {
    let request = Socks5Request {
        command: keli_net_core::Socks5Command::Connect,
        address: Socks5Address::Domain("example.com".to_string()),
        port: 443,
    };

    let target = OutboundTarget::from_socks5_request(&request);

    assert_eq!(target.host, "example.com");
    assert_eq!(target.port, 443);
}

#[test]
fn maps_outbound_target_to_domain_route_target() {
    let target = OutboundTarget::new("example.com", 443);

    assert_eq!(
        target.route_target(),
        RouteTarget::Domain("example.com".to_string())
    );
}

#[test]
fn maps_outbound_target_to_ip_route_target() {
    let target = OutboundTarget::new("127.0.0.1", 443);

    assert_eq!(
        target.route_target(),
        RouteTarget::Ip("127.0.0.1".parse().expect("valid IP"))
    );
}

#[test]
fn maps_outbound_target_to_route_destination_with_port() {
    let target = OutboundTarget::new("example.com", 443);

    assert_eq!(
        target.route_destination(),
        RouteDestination::new(RouteTarget::Domain("example.com".to_string()), 443)
    );
}

#[test]
fn direct_connector_reaches_local_tcp_target() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local echo server");
    let port = listener.local_addr().expect("local addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept direct connection");
        let mut request = [0; 4];
        stream.read_exact(&mut request).expect("read ping");
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").expect("write pong");
    });

    let mut stream = DirectTcpConnector::connect(
        &OutboundTarget::new("127.0.0.1", port),
        Duration::from_secs(1),
    )
    .expect("direct connection should succeed");
    stream.write_all(b"ping").expect("write ping");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read pong");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn direct_connector_uses_injected_dns_engine_for_domains() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local server");
    let port = listener.local_addr().expect("local addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept direct connection");
        let mut request = [0; 4];
        stream.read_exact(&mut request).expect("read ping");
        stream.write_all(b"pong").expect("write pong");
    });
    let resolver = CountingResolver::new(vec!["127.0.0.1".parse().expect("valid IP")]);
    let mut dns = DnsEngine::new(resolver.clone(), DnsCache::new(Duration::from_secs(60)));

    let mut stream = DirectTcpConnector::connect_with_dns(
        &OutboundTarget::new("example.test", port),
        Duration::from_secs(1),
        &mut dns,
    )
    .expect("direct connection should use injected DNS");
    stream.write_all(b"ping").expect("write ping");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read pong");

    assert_eq!(&response, b"pong");
    assert_eq!(resolver.calls(), 1);
    server.join().expect("server thread");
}

#[test]
fn relay_copies_bytes_in_both_directions() {
    let (mut inbound_client, inbound_core) = tcp_pair();
    let (outbound_core, mut outbound_server) = tcp_pair();

    let relay = thread::spawn(move || relay_tcp_bidirectional(inbound_core, outbound_core));

    inbound_client.write_all(b"ping").expect("write inbound");
    let mut inbound_payload = [0; 4];
    outbound_server
        .read_exact(&mut inbound_payload)
        .expect("read outbound side");
    assert_eq!(&inbound_payload, b"ping");

    outbound_server.write_all(b"pong").expect("write outbound");
    let mut outbound_payload = [0; 4];
    inbound_client
        .read_exact(&mut outbound_payload)
        .expect("read inbound side");
    assert_eq!(&outbound_payload, b"pong");

    inbound_client.shutdown(Shutdown::Both).ok();
    outbound_server.shutdown(Shutdown::Both).ok();

    let stats = relay.join().expect("relay thread").expect("relay result");
    assert_eq!(stats.client_to_remote_bytes, 4);
    assert_eq!(stats.remote_to_client_bytes, 4);
    assert!(stats.remote_first_byte_after.is_some());
}

#[test]
fn relay_copies_bytes_with_non_clone_remote_stream() {
    let (mut inbound_client, inbound_core) = tcp_pair();
    let (outbound_core, mut outbound_server) = tcp_pair();

    let relay = thread::spawn(move || {
        relay_owned_bidirectional_with_options(
            inbound_core,
            NonCloneTcpStream(outbound_core),
            RelayOptions {
                first_byte_timeout: Some(Duration::from_secs(1)),
                idle_timeout: Some(Duration::from_secs(1)),
            },
        )
    });

    inbound_client.write_all(b"ping").expect("write inbound");
    let mut inbound_payload = [0; 4];
    outbound_server
        .read_exact(&mut inbound_payload)
        .expect("read outbound side");
    assert_eq!(&inbound_payload, b"ping");

    outbound_server.write_all(b"pong").expect("write outbound");
    let mut outbound_payload = [0; 4];
    inbound_client
        .read_exact(&mut outbound_payload)
        .expect("read inbound side");
    assert_eq!(&outbound_payload, b"pong");

    inbound_client.shutdown(Shutdown::Both).ok();
    outbound_server.shutdown(Shutdown::Both).ok();

    let stats = relay.join().expect("relay thread").expect("relay result");
    assert_eq!(stats.client_to_remote_bytes, 4);
    assert_eq!(stats.remote_to_client_bytes, 4);
    assert!(stats.remote_first_byte_after.is_some());
}

#[test]
fn owned_relay_treats_missing_tls_close_notify_as_remote_eof() {
    let (mut inbound_client, inbound_core) = tcp_pair();
    let relay = thread::spawn(move || {
        relay_owned_bidirectional_with_options(
            inbound_core,
            RemoteErrorAfterDataStream::missing_close_notify(b"pong"),
            RelayOptions {
                first_byte_timeout: Some(Duration::from_secs(1)),
                idle_timeout: Some(Duration::from_secs(1)),
            },
        )
    });

    inbound_client.shutdown(Shutdown::Write).ok();
    let mut outbound_payload = [0; 4];
    inbound_client
        .read_exact(&mut outbound_payload)
        .expect("read inbound side");
    assert_eq!(&outbound_payload, b"pong");
    inbound_client.shutdown(Shutdown::Both).ok();

    let stats = relay.join().expect("relay thread").expect("relay result");
    assert_eq!(stats.client_to_remote_bytes, 0);
    assert_eq!(stats.remote_to_client_bytes, 4);
    assert!(stats.remote_first_byte_after.is_some());
}

#[test]
fn owned_relay_treats_h2_no_error_stream_close_as_remote_eof() {
    let (mut inbound_client, inbound_core) = tcp_pair();
    let relay = thread::spawn(move || {
        relay_owned_bidirectional_with_options(
            inbound_core,
            RemoteErrorAfterDataStream::h2_no_error_close(b"pong"),
            RelayOptions {
                first_byte_timeout: Some(Duration::from_secs(1)),
                idle_timeout: Some(Duration::from_secs(1)),
            },
        )
    });

    inbound_client.shutdown(Shutdown::Write).ok();
    let mut outbound_payload = [0; 4];
    inbound_client
        .read_exact(&mut outbound_payload)
        .expect("read inbound side");
    assert_eq!(&outbound_payload, b"pong");
    inbound_client.shutdown(Shutdown::Both).ok();

    let stats = relay.join().expect("relay thread").expect("relay result");
    assert_eq!(stats.client_to_remote_bytes, 0);
    assert_eq!(stats.remote_to_client_bytes, 4);
    assert!(stats.remote_first_byte_after.is_some());
}

#[test]
fn relay_records_remote_first_byte_after_start() {
    let (mut inbound_client, inbound_core) = tcp_pair();
    let (outbound_core, mut outbound_server) = tcp_pair();

    let started = Instant::now();
    let relay = thread::spawn(move || relay_tcp_bidirectional(inbound_core, outbound_core));

    thread::sleep(Duration::from_millis(25));
    outbound_server.write_all(b"pong").expect("write outbound");
    let mut outbound_payload = [0; 4];
    inbound_client
        .read_exact(&mut outbound_payload)
        .expect("read inbound side");
    assert_eq!(&outbound_payload, b"pong");

    inbound_client.shutdown(Shutdown::Both).ok();
    outbound_server.shutdown(Shutdown::Both).ok();

    let stats = relay.join().expect("relay thread").expect("relay result");
    let first_byte_after = stats
        .remote_first_byte_after
        .expect("first byte duration should be recorded");
    assert!(first_byte_after >= Duration::from_millis(20));
    assert!(first_byte_after <= started.elapsed());
}

#[test]
fn relay_times_out_waiting_for_remote_first_byte() {
    let (mut inbound_client, inbound_core) = tcp_pair();
    let (outbound_core, _outbound_server) = tcp_pair();

    inbound_client.write_all(b"ping").expect("write inbound");
    let relay = thread::spawn(move || {
        relay_tcp_bidirectional_with_options(
            inbound_core,
            outbound_core,
            RelayOptions {
                first_byte_timeout: Some(Duration::from_millis(30)),
                idle_timeout: None,
            },
        )
    });

    let error = relay
        .join()
        .expect("relay thread")
        .expect_err("relay should time out");
    assert_eq!(error.kind, ConnectionErrorKind::FirstByteTimeout);

    inbound_client.shutdown(Shutdown::Both).ok();
}

#[test]
fn relay_times_out_after_remote_becomes_idle() {
    let (mut inbound_client, inbound_core) = tcp_pair();
    let (outbound_core, mut outbound_server) = tcp_pair();

    let relay = thread::spawn(move || {
        relay_tcp_bidirectional_with_options(
            inbound_core,
            outbound_core,
            RelayOptions {
                first_byte_timeout: Some(Duration::from_millis(100)),
                idle_timeout: Some(Duration::from_millis(30)),
            },
        )
    });

    outbound_server
        .write_all(b"pong")
        .expect("write first byte");
    let mut outbound_payload = [0; 4];
    inbound_client
        .read_exact(&mut outbound_payload)
        .expect("read first response");
    assert_eq!(&outbound_payload, b"pong");

    let error = relay
        .join()
        .expect("relay thread")
        .expect_err("relay should time out after idle");
    assert_eq!(error.kind, ConnectionErrorKind::IdleTimeout);

    inbound_client.shutdown(Shutdown::Both).ok();
    outbound_server.shutdown(Shutdown::Both).ok();
}

#[test]
fn owned_relay_times_out_waiting_for_remote_first_byte() {
    let (mut inbound_client, inbound_core) = tcp_pair();
    let (outbound_core, _outbound_server) = tcp_pair();

    inbound_client.write_all(b"ping").expect("write inbound");
    let relay = thread::spawn(move || {
        relay_owned_bidirectional_with_options(
            inbound_core,
            NonCloneTcpStream(outbound_core),
            RelayOptions {
                first_byte_timeout: Some(Duration::from_millis(30)),
                idle_timeout: None,
            },
        )
    });

    let error = relay
        .join()
        .expect("relay thread")
        .expect_err("relay should time out");
    assert_eq!(error.kind, ConnectionErrorKind::FirstByteTimeout);

    inbound_client.shutdown(Shutdown::Both).ok();
}

#[test]
fn owned_relay_times_out_after_remote_becomes_idle() {
    let (mut inbound_client, inbound_core) = tcp_pair();
    let (outbound_core, mut outbound_server) = tcp_pair();

    let relay = thread::spawn(move || {
        relay_owned_bidirectional_with_options(
            inbound_core,
            NonCloneTcpStream(outbound_core),
            RelayOptions {
                first_byte_timeout: Some(Duration::from_millis(100)),
                idle_timeout: Some(Duration::from_millis(30)),
            },
        )
    });

    outbound_server
        .write_all(b"pong")
        .expect("write first byte");
    let mut outbound_payload = [0; 4];
    inbound_client
        .read_exact(&mut outbound_payload)
        .expect("read first response");
    assert_eq!(&outbound_payload, b"pong");

    let error = relay
        .join()
        .expect("relay thread")
        .expect_err("relay should time out after idle");
    assert_eq!(error.kind, ConnectionErrorKind::IdleTimeout);

    inbound_client.shutdown(Shutdown::Both).ok();
    outbound_server.shutdown(Shutdown::Both).ok();
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp pair");
    let port = listener.local_addr().expect("pair local addr").port();
    let accept = thread::spawn(move || listener.accept().expect("accept pair").0);
    let client = TcpStream::connect(("127.0.0.1", port)).expect("connect pair");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    let server = accept.join().expect("accept thread");
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("server timeout");
    (client, server)
}

#[derive(Clone)]
struct CountingResolver {
    ips: Vec<IpAddr>,
    calls: Arc<Mutex<usize>>,
}

impl CountingResolver {
    fn new(ips: Vec<IpAddr>) -> Self {
        Self {
            ips,
            calls: Arc::new(Mutex::new(0)),
        }
    }

    fn calls(&self) -> usize {
        *self.calls.lock().expect("calls lock")
    }
}

impl DnsResolver for CountingResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        assert_eq!(host, "example.test");
        *self.calls.lock().expect("calls lock") += 1;
        Ok(self.ips.clone())
    }
}

struct NonCloneTcpStream(TcpStream);

impl Read for NonCloneTcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buffer)
    }
}

enum RemoteRead {
    Data(Vec<u8>),
    Error(io::ErrorKind, &'static str),
}

struct RemoteErrorAfterDataStream {
    reads: VecDeque<RemoteRead>,
}

impl RemoteErrorAfterDataStream {
    fn missing_close_notify(payload: &[u8]) -> Self {
        Self::new(
            payload,
            io::ErrorKind::UnexpectedEof,
            "peer closed connection without sending TLS close_notify",
        )
    }

    fn h2_no_error_close(payload: &[u8]) -> Self {
        Self::new(
            payload,
            io::ErrorKind::Other,
            "stream error received: not a result of an error",
        )
    }

    fn new(payload: &[u8], kind: io::ErrorKind, message: &'static str) -> Self {
        Self {
            reads: VecDeque::from([
                RemoteRead::Data(payload.to_vec()),
                RemoteRead::Error(kind, message),
            ]),
        }
    }
}

impl Read for RemoteErrorAfterDataStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self.reads.pop_front() {
            Some(RemoteRead::Data(data)) => {
                let bytes = data.len().min(buffer.len());
                buffer[..bytes].copy_from_slice(&data[..bytes]);
                if bytes < data.len() {
                    self.reads
                        .push_front(RemoteRead::Data(data[bytes..].to_vec()));
                }
                Ok(bytes)
            }
            Some(RemoteRead::Error(kind, message)) => Err(io::Error::new(kind, message)),
            None => Ok(0),
        }
    }
}

impl Write for RemoteErrorAfterDataStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl OwnedRelayStream for RemoteErrorAfterDataStream {
    fn set_nonblocking_mode(&mut self, _nonblocking: bool) -> io::Result<()> {
        Ok(())
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn shutdown_both(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for NonCloneTcpStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl OwnedRelayStream for NonCloneTcpStream {
    fn set_nonblocking_mode(&mut self, nonblocking: bool) -> std::io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    fn shutdown_write(&mut self) -> std::io::Result<()> {
        self.0.shutdown(Shutdown::Write)
    }

    fn shutdown_both(&mut self) -> std::io::Result<()> {
        self.0.shutdown(Shutdown::Both)
    }
}
