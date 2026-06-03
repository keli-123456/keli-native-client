mod support;

use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use h2::RecvStream;
use http::{Request, Response, StatusCode};
use keli_net_core::{OutboundRegistry, OutboundTarget};
use keli_protocol::{Endpoint, OutboundProfile, ProxyProtocol, SecurityKind, TransportKind};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use support::vmess::{
    read_vmess_aead_request, read_vmess_aes128_gcm_chunk, write_vmess_aead_response_header,
    write_vmess_aes128_gcm_response_chunk,
};
use tokio::io::{AsyncRead, AsyncWrite};

const VLESS_UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const VMESS_UUID: &str = "11111111-1111-1111-1111-111111111111";

#[test]
fn registry_from_vless_h2_profile_relays_over_http2_body() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind h2 server");
    let port = listener.local_addr().expect("h2 addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vless,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Http2 {
            path: "/h2".to_string(),
            host: Some("h2.example".to_string()),
        },
        security: SecurityKind::None,
        credential: VLESS_UUID.to_string(),
        cipher: None,
        flow: None,
    }])
    .expect("profile registry");
    let server = spawn_h2_server(listener, "/h2", Some("h2.example"), |mut stream| {
        let mut request_header = [0; 34];
        stream
            .read_exact(&mut request_header)
            .expect("read vless request header");
        assert_eq!(
            &request_header[..],
            &[
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

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(2),
        )
        .expect("registered vless h2 outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_trojan_h2_profile_relays_over_http2_body() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind h2 server");
    let port = listener.local_addr().expect("h2 addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Trojan,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Http2 {
            path: "/trojan-h2".to_string(),
            host: Some("trojan-h2.example".to_string()),
        },
        security: SecurityKind::None,
        credential: "password".to_string(),
        cipher: None,
        flow: None,
    }])
    .expect("profile registry");
    let server = spawn_h2_server(
        listener,
        "/trojan-h2",
        Some("trojan-h2.example"),
        |mut stream| {
            let mut request_header = [0; 76];
            stream
                .read_exact(&mut request_header)
                .expect("read trojan request header");
            assert_eq!(
                &request_header[..],
                b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x01\x03\x0bexample.com\x01\xbb\r\n"
            );
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).expect("read relay payload");
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").expect("write relay payload");
        },
    );

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(2),
        )
        .expect("registered trojan h2 outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vmess_h2_profile_relays_over_http2_body() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind h2 server");
    let port = listener.local_addr().expect("h2 addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vmess,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Http2 {
            path: "/vmess-h2".to_string(),
            host: Some("vmess-h2.example".to_string()),
        },
        security: SecurityKind::None,
        credential: VMESS_UUID.to_string(),
        cipher: Some("aes-128-gcm".to_string()),
        flow: None,
    }])
    .expect("profile registry");
    let server = spawn_h2_server(
        listener,
        "/vmess-h2",
        Some("vmess-h2.example"),
        |mut stream| {
            let request = read_vmess_aead_request(&mut stream, VMESS_UUID);
            assert_eq!(request.target_host, "example.com");
            assert_eq!(request.target_port, 443);
            assert_eq!(request.command, 0x01);
            assert_eq!(request.security, 0x03);
            write_vmess_aead_response_header(&mut stream, &request);
            let payload = read_vmess_aes128_gcm_chunk(&mut stream, &request);
            assert_eq!(&payload, b"ping");
            write_vmess_aes128_gcm_response_chunk(&mut stream, &request, b"pong");
        },
    );

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(2),
        )
        .expect("registered vmess h2 outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vless_tls_h2_profile_relays_over_tls_http2_body() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls h2 server");
    let port = listener.local_addr().expect("tls h2 addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vless,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Http2 {
            path: "/h2".to_string(),
            host: Some("h2.example".to_string()),
        },
        security: SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: true,
        },
        credential: VLESS_UUID.to_string(),
        cipher: None,
        flow: None,
    }])
    .expect("profile registry");
    let server = spawn_tls_h2_server(listener, "/h2", Some("h2.example"), |mut stream| {
        let mut request_header = [0; 34];
        stream
            .read_exact(&mut request_header)
            .expect("read vless request header");
        assert_eq!(&request_header[18..], b"\x01\x01\xbb\x02\x0bexample.com");
        stream
            .write_all(&[0x00, 0x00])
            .expect("write vless response header");
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).expect("read relay payload");
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").expect("write relay payload");
    });

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(2),
        )
        .expect("registered vless tls h2 outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_trojan_tls_h2_profile_relays_over_tls_http2_body() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls h2 server");
    let port = listener.local_addr().expect("tls h2 addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Trojan,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Http2 {
            path: "/trojan-h2".to_string(),
            host: Some("trojan-h2.example".to_string()),
        },
        security: SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: true,
        },
        credential: "password".to_string(),
        cipher: None,
        flow: None,
    }])
    .expect("profile registry");
    let server = spawn_tls_h2_server(
        listener,
        "/trojan-h2",
        Some("trojan-h2.example"),
        |mut stream| {
            let mut request_header = [0; 76];
            stream
                .read_exact(&mut request_header)
                .expect("read trojan request header");
            assert_eq!(
                &request_header[..],
                b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x01\x03\x0bexample.com\x01\xbb\r\n"
            );
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).expect("read relay payload");
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").expect("write relay payload");
        },
    );

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(2),
        )
        .expect("registered trojan tls h2 outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

#[test]
fn registry_from_vmess_tls_h2_profile_relays_over_tls_http2_body() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls h2 server");
    let port = listener.local_addr().expect("tls h2 addr").port();
    let registry = OutboundRegistry::from_profiles([OutboundProfile {
        tag: "proxy".to_string(),
        protocol: ProxyProtocol::Vmess,
        endpoint: Endpoint::new("127.0.0.1", port),
        transport: TransportKind::Http2 {
            path: "/vmess-h2".to_string(),
            host: Some("vmess-h2.example".to_string()),
        },
        security: SecurityKind::Tls {
            sni: Some("edge.example".to_string()),
            skip_verify: true,
        },
        credential: VMESS_UUID.to_string(),
        cipher: Some("aes-128-gcm".to_string()),
        flow: None,
    }])
    .expect("profile registry");
    let server = spawn_tls_h2_server(
        listener,
        "/vmess-h2",
        Some("vmess-h2.example"),
        |mut stream| {
            let request = read_vmess_aead_request(&mut stream, VMESS_UUID);
            assert_eq!(request.target_host, "example.com");
            assert_eq!(request.target_port, 443);
            write_vmess_aead_response_header(&mut stream, &request);
            let payload = read_vmess_aes128_gcm_chunk(&mut stream, &request);
            assert_eq!(&payload, b"ping");
            write_vmess_aes128_gcm_response_chunk(&mut stream, &request, b"pong");
        },
    );

    let mut stream = registry
        .connect(
            "proxy",
            &OutboundTarget::new("example.com", 443),
            Duration::from_secs(2),
        )
        .expect("registered vmess tls h2 outbound should connect");
    stream.write_all(b"ping").expect("write payload");
    let mut response = [0; 4];
    stream.read_exact(&mut response).expect("read payload");

    assert_eq!(&response, b"pong");
    server.join().expect("server thread");
}

fn spawn_h2_server(
    listener: TcpListener,
    expected_path: &'static str,
    expected_authority: Option<&'static str>,
    handler: impl FnOnce(H2TestStream) + Send + 'static,
) -> thread::JoinHandle<()> {
    listener
        .set_nonblocking(true)
        .expect("listener nonblocking");
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            let (stream, _) = listener.accept().await.expect("accept h2 tcp");
            serve_h2_connection(stream, expected_path, expected_authority, handler).await;
        });
    })
}

fn spawn_tls_h2_server(
    listener: TcpListener,
    expected_path: &'static str,
    expected_authority: Option<&'static str>,
    handler: impl FnOnce(H2TestStream) + Send + 'static,
) -> thread::JoinHandle<()> {
    listener
        .set_nonblocking(true)
        .expect("listener nonblocking");
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            let (stream, _) = listener.accept().await.expect("accept h2 tcp");
            let acceptor = tokio_rustls::TlsAcceptor::from(h2_tls_server_config());
            let stream = acceptor.accept(stream).await.expect("accept h2 tls");
            serve_h2_connection(stream, expected_path, expected_authority, handler).await;
        });
    })
}

async fn serve_h2_connection<S>(
    stream: S,
    expected_path: &'static str,
    expected_authority: Option<&'static str>,
    handler: impl FnOnce(H2TestStream) + Send + 'static,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = h2::server::handshake(stream).await.expect("h2 handshake");
    let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let mut handler = Some(handler);
    loop {
        tokio::select! {
            request = connection.accept() => {
                let Some(request) = request else {
                    break;
                };
                let (request, respond) = request.expect("valid h2 request");
                let handler = handler.take().expect("single h2 request handler");
                let done_tx = done_tx.clone();
                tokio::spawn(async move {
                    serve_h2_request(request, respond, expected_path, expected_authority, handler).await;
                    let _ = done_tx.send(());
                });
            }
            _ = done_rx.recv() => break,
        }
    }
}

async fn serve_h2_request(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    expected_path: &str,
    expected_authority: Option<&str>,
    handler: impl FnOnce(H2TestStream) + Send + 'static,
) {
    assert_eq!(request.method(), http::Method::PUT);
    assert_eq!(request.uri().path(), expected_path);
    if let Some(authority) = expected_authority {
        assert_eq!(
            request.uri().authority().map(|value| value.as_str()),
            Some(authority)
        );
    }
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .expect("h2 response");
    let mut send = respond
        .send_response(response, false)
        .expect("send response");
    let (input_tx, input_rx) = mpsc::channel();
    let (output_tx, mut output_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let mut body = request.into_body();
    let read_task = tokio::spawn(async move {
        while let Some(chunk) = body.data().await {
            let chunk = chunk.expect("read h2 body");
            let len = chunk.len();
            let _ = body.flow_control().release_capacity(len);
            if input_tx.send(chunk.to_vec()).is_err() {
                return;
            }
        }
    });
    let write_task = tokio::spawn(async move {
        while let Some(payload) = output_rx.recv().await {
            send_h2_data(&mut send, Bytes::from(payload), false)
                .await
                .expect("write h2 body");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        send.send_data(Bytes::new(), true)
            .expect("finish h2 response");
    });
    tokio::task::spawn_blocking(move || handler(H2TestStream::new(input_rx, output_tx)))
        .await
        .expect("handler task");
    write_task.await.expect("write task");
    read_task.abort();
}

struct H2TestStream {
    input_rx: mpsc::Receiver<Vec<u8>>,
    output_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    buffer: Vec<u8>,
}

impl H2TestStream {
    fn new(
        input_rx: mpsc::Receiver<Vec<u8>>,
        output_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        Self {
            input_rx,
            output_tx,
            buffer: Vec::new(),
        }
    }
}

impl Read for H2TestStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        while self.buffer.is_empty() {
            self.buffer = self
                .input_rx
                .recv()
                .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "h2 input closed"))?;
        }
        let len = output.len().min(self.buffer.len());
        output[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Ok(len)
    }
}

impl Write for H2TestStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.output_tx
            .send(input.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "h2 output closed"))?;
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn send_h2_data(
    send: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
    end_stream: bool,
) -> io::Result<()> {
    if data.is_empty() {
        return send
            .send_data(data, end_stream)
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()));
    }
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let capacity = loop {
            match poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(capacity)) if capacity > 0 => break capacity,
                Some(Ok(_)) => continue,
                Some(Err(error)) => {
                    return Err(io::Error::new(io::ErrorKind::Other, error.to_string()));
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "stream closed before capacity",
                    ));
                }
            }
        };
        let chunk_len = capacity.min(data.len());
        let chunk = data.split_to(chunk_len);
        let chunk_ends_stream = end_stream && data.is_empty();
        send.send_data(chunk, chunk_ends_stream)
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
    }
    Ok(())
}

fn h2_tls_server_config() -> Arc<rustls::ServerConfig> {
    let cert = generate_simple_self_signed(vec!["edge.example".to_string()]).expect("self cert");
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let mut config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .expect("tls versions")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key_der)
    .expect("server config");
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}
