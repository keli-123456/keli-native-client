use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use bytes::{Buf, Bytes};
use keli_protocol::Endpoint;
use tokio::sync::mpsc as tokio_mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use crate::{
    DirectTcpConnector, DnsCache, DnsEngine, OutboundConnection, OutboundTarget, OwnedRelayStream,
    SystemDnsResolver,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaiveH2TcpOutbound {
    pub server: Endpoint,
    pub credential: String,
    pub sni: String,
    pub skip_verify: bool,
}

impl NaiveH2TcpOutbound {
    pub fn new(
        server: Endpoint,
        credential: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
    ) -> Self {
        Self {
            server,
            credential: credential.into(),
            sni: sni.into(),
            skip_verify,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: std::time::Duration,
    ) -> io::Result<OutboundConnection> {
        let server = OutboundTarget::new(self.server.host.clone(), self.server.port);
        let stream = DirectTcpConnector::connect(&server, timeout)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let stream = NaiveH2TcpStream::connect(
            stream,
            &self.sni,
            self.skip_verify,
            &self.credential,
            &target,
        )?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaiveH3QuicOutbound {
    pub server: Endpoint,
    pub credential: String,
    pub sni: String,
    pub skip_verify: bool,
}

impl NaiveH3QuicOutbound {
    pub fn new(
        server: Endpoint,
        credential: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
    ) -> Self {
        Self {
            server,
            credential: credential.into(),
            sni: sni.into(),
            skip_verify,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let target = Endpoint::new(target.host.clone(), target.port);
        let mut last_error = None;
        for server_addr in self.resolve_server_addrs()? {
            let bind_addr = quic_bind_addr_for(server_addr);
            match NaiveH3QuicStream::connect(
                bind_addr,
                server_addr,
                &self.sni,
                self.skip_verify,
                &self.credential,
                &target,
                timeout,
            ) {
                Ok(stream) => return Ok(OutboundConnection::Owned(Box::new(stream))),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "no address resolved for {}:{}",
                    self.server.host, self.server.port
                ),
            )
        }))
    }

    fn resolve_server_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        let mut dns = DnsEngine::new(SystemDnsResolver, DnsCache::new(Duration::from_secs(60)));
        dns.resolve(&self.server.host, self.server.port)
            .map_err(|error| io::Error::new(io::ErrorKind::AddrNotAvailable, error))
            .map(|addresses| {
                addresses
                    .into_iter()
                    .map(|address| SocketAddr::new(address.ip, address.port))
                    .collect()
            })
    }
}

pub struct NaiveH2TcpStream {
    runtime: Arc<tokio::runtime::Runtime>,
    send: Arc<Mutex<h2::SendStream<Bytes>>>,
    read_rx: mpsc::Receiver<io::Result<Vec<u8>>>,
    read_buffer: Vec<u8>,
    read_offset: usize,
    connection_task: JoinHandle<()>,
    reader_task: JoinHandle<()>,
    nonblocking: bool,
    eof: bool,
}

impl NaiveH2TcpStream {
    pub fn connect(
        stream: TcpStream,
        server_name: &str,
        skip_verify: bool,
        credential: &str,
        target: &Endpoint,
    ) -> io::Result<Self> {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .thread_name("keli-naive-h2-runtime")
                .build()
                .map_err(io_other)?,
        );
        stream.set_nonblocking(true)?;
        runtime.block_on(Self::connect_async(
            runtime.clone(),
            stream,
            server_name,
            skip_verify,
            credential,
            target,
        ))
    }

    async fn connect_async(
        runtime: Arc<tokio::runtime::Runtime>,
        stream: TcpStream,
        server_name: &str,
        skip_verify: bool,
        credential: &str,
        target: &Endpoint,
    ) -> io::Result<Self> {
        let stream = tokio::net::TcpStream::from_std(stream)?;
        let config = crate::direct::tls_client_config_with_alpn(skip_verify, vec![b"h2".to_vec()])?;
        let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let stream = TlsConnector::from(config)
            .connect(server_name, stream)
            .await
            .map_err(io_other)?;
        let (mut client, connection) = h2::client::handshake(stream).await.map_err(io_other)?;
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let auth = base64::engine::general_purpose::STANDARD.encode(credential);
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://{}", connect_authority(target)))
            .header("proxy-authorization", format!("Basic {auth}"))
            .body(())
            .map_err(io_other)?;
        let (response, send) = client.send_request(request, false).map_err(io_other)?;
        let response = response.await.map_err(io_other)?;
        if response.status() != http::StatusCode::OK {
            connection_task.abort();
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("naive CONNECT failed with status {}", response.status()),
            ));
        }
        let mut body = response.into_body();
        let (read_tx, read_rx) = mpsc::channel();
        let reader_task = tokio::spawn(async move {
            while let Some(chunk) = body.data().await {
                match chunk {
                    Ok(bytes) => {
                        let _ = body.flow_control().release_capacity(bytes.len());
                        if read_tx.send(Ok(bytes.to_vec())).is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        let _ = read_tx.send(Err(io_other(error)));
                        return;
                    }
                }
            }
            let _ = read_tx.send(Ok(Vec::new()));
        });
        Ok(Self {
            runtime,
            send: Arc::new(Mutex::new(send)),
            read_rx,
            read_buffer: Vec::new(),
            read_offset: 0,
            connection_task,
            reader_task,
            nonblocking: false,
            eof: false,
        })
    }

    pub fn set_nonblocking_mode(&mut self, nonblocking: bool) {
        self.nonblocking = nonblocking;
    }

    pub fn shutdown_write(&mut self) -> io::Result<()> {
        let mut send = self
            .send
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Naive H2 send lock poisoned"))?;
        self.runtime.block_on(send_h2_data(&mut send, &[], true))
    }

    pub fn shutdown_both(&mut self) -> io::Result<()> {
        self.shutdown_write().ok();
        self.reader_task.abort();
        self.connection_task.abort();
        Ok(())
    }

    fn read_from_buffer(&mut self, buffer: &mut [u8]) -> Option<usize> {
        if self.read_offset >= self.read_buffer.len() {
            self.read_buffer.clear();
            self.read_offset = 0;
            return None;
        }
        let remaining = &self.read_buffer[self.read_offset..];
        let amount = remaining.len().min(buffer.len());
        buffer[..amount].copy_from_slice(&remaining[..amount]);
        self.read_offset += amount;
        if self.read_offset >= self.read_buffer.len() {
            self.read_buffer.clear();
            self.read_offset = 0;
        }
        Some(amount)
    }

    fn receive_next_read_chunk(&mut self) -> io::Result<bool> {
        if self.eof {
            return Ok(false);
        }
        let received = if self.nonblocking {
            match self.read_rx.try_recv() {
                Ok(received) => received,
                Err(mpsc::TryRecvError::Empty) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "Naive H2 stream has no data available",
                    ));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.eof = true;
                    return Ok(false);
                }
            }
        } else {
            match self.read_rx.recv() {
                Ok(received) => received,
                Err(_) => {
                    self.eof = true;
                    return Ok(false);
                }
            }
        }?;
        if received.is_empty() {
            self.eof = true;
            Ok(false)
        } else {
            self.read_buffer = received;
            self.read_offset = 0;
            Ok(true)
        }
    }
}

impl Read for NaiveH2TcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if let Some(bytes) = self.read_from_buffer(buffer) {
            return Ok(bytes);
        }
        if !self.receive_next_read_chunk()? {
            return Ok(0);
        }
        Ok(self.read_from_buffer(buffer).unwrap_or(0))
    }
}

impl Write for NaiveH2TcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut send = self
            .send
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Naive H2 send lock poisoned"))?;
        self.runtime
            .block_on(send_h2_data(&mut send, buffer, false))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl OwnedRelayStream for NaiveH2TcpStream {
    fn set_nonblocking_mode(&mut self, nonblocking: bool) -> io::Result<()> {
        self.set_nonblocking_mode(nonblocking);
        Ok(())
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.shutdown_write()
    }

    fn shutdown_both(&mut self) -> io::Result<()> {
        self.shutdown_both()
    }
}

impl Drop for NaiveH2TcpStream {
    fn drop(&mut self) {
        self.reader_task.abort();
        self.connection_task.abort();
    }
}

enum NaiveH3WriteCommand {
    Data(Vec<u8>, mpsc::Sender<io::Result<()>>),
    Finish(mpsc::Sender<io::Result<()>>),
}

pub struct NaiveH3QuicStream {
    _runtime: Arc<tokio::runtime::Runtime>,
    _endpoint: quinn::Endpoint,
    _connection: quinn::Connection,
    _send_request: crate::Hy2H3SendRequest,
    write_tx: tokio_mpsc::UnboundedSender<NaiveH3WriteCommand>,
    read_rx: mpsc::Receiver<io::Result<Vec<u8>>>,
    read_buffer: Vec<u8>,
    read_offset: usize,
    h3_driver: JoinHandle<h3::error::ConnectionError>,
    stream_task: JoinHandle<()>,
    nonblocking: bool,
    eof: bool,
}

impl NaiveH3QuicStream {
    pub fn connect(
        bind_addr: SocketAddr,
        server_addr: SocketAddr,
        server_name: &str,
        skip_verify: bool,
        credential: &str,
        target: &Endpoint,
        timeout: Duration,
    ) -> io::Result<Self> {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .thread_name("keli-naive-h3-runtime")
                .build()
                .map_err(io_other)?,
        );
        runtime.block_on(Self::connect_async(
            runtime.clone(),
            bind_addr,
            server_addr,
            server_name,
            skip_verify,
            credential,
            target,
            timeout,
        ))
    }

    async fn connect_async(
        runtime: Arc<tokio::runtime::Runtime>,
        bind_addr: SocketAddr,
        server_addr: SocketAddr,
        server_name: &str,
        skip_verify: bool,
        credential: &str,
        target: &Endpoint,
        timeout: Duration,
    ) -> io::Result<Self> {
        let endpoint = crate::h3_quic_client_endpoint(bind_addr, skip_verify)?;
        let connection = tokio::time::timeout(
            timeout,
            crate::h3_quic_connect(&endpoint, server_addr, server_name),
        )
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "Naive H3 QUIC handshake timed out")
        })??;
        let (mut h3_connection, mut send_request) =
            crate::h3_client_from_quinn_connection(connection.clone())
                .await
                .map_err(|error| {
                    io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}"))
                })?;
        let h3_driver =
            tokio::spawn(async move { poll_fn(|cx| h3_connection.poll_close(cx)).await });
        let auth = base64::engine::general_purpose::STANDARD.encode(credential);
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://{}", connect_authority(target)))
            .header("proxy-authorization", format!("Basic {auth}"))
            .body(())
            .map_err(io_other)?;
        let mut stream =
            match tokio::time::timeout(timeout, send_request.send_request(request)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    h3_driver.abort();
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("{error:?}"),
                    ));
                }
                Err(_) => {
                    h3_driver.abort();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Naive H3 CONNECT request timed out",
                    ));
                }
            };
        let response = match tokio::time::timeout(timeout, stream.recv_response()).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                h3_driver.abort();
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("{error:?}"),
                ));
            }
            Err(_) => {
                h3_driver.abort();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Naive H3 CONNECT response timed out",
                ));
            }
        };
        if response.status() != http::StatusCode::OK {
            h3_driver.abort();
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("naive CONNECT failed with status {}", response.status()),
            ));
        }
        let (mut send, mut recv) = stream.split();
        let (write_tx, mut write_rx) = tokio_mpsc::unbounded_channel();
        let (read_tx, read_rx) = mpsc::channel();
        let stream_task = tokio::spawn(async move {
            let mut write_closed = false;
            loop {
                if write_closed {
                    if !receive_h3_data(&mut recv, &read_tx).await {
                        break;
                    }
                    continue;
                }
                tokio::select! {
                    command = write_rx.recv() => {
                        match command {
                            Some(NaiveH3WriteCommand::Data(data, ack)) => {
                                let result = send
                                    .send_data(Bytes::from(data))
                                    .await
                                    .map_err(|error| io::Error::new(
                                        io::ErrorKind::ConnectionAborted,
                                        format!("{error:?}"),
                                    ));
                                let failed = result.is_err();
                                let _ = ack.send(result);
                                if failed {
                                    break;
                                }
                            }
                            Some(NaiveH3WriteCommand::Finish(ack)) => {
                                write_closed = true;
                                let result = send
                                    .finish()
                                    .await
                                    .map_err(|error| io::Error::new(
                                        io::ErrorKind::ConnectionAborted,
                                        format!("{error:?}"),
                                    ));
                                let failed = result.is_err();
                                let _ = ack.send(result);
                                if failed {
                                    break;
                                }
                            }
                            None => {
                                write_closed = true;
                                if send.finish().await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    received = recv.recv_data() => {
                        if !forward_h3_received_data(received, &read_tx) {
                            break;
                        }
                    }
                }
            }
        });
        Ok(Self {
            _runtime: runtime,
            _endpoint: endpoint,
            _connection: connection,
            _send_request: send_request,
            write_tx,
            read_rx,
            read_buffer: Vec::new(),
            read_offset: 0,
            h3_driver,
            stream_task,
            nonblocking: false,
            eof: false,
        })
    }

    pub fn set_nonblocking_mode(&mut self, nonblocking: bool) {
        self.nonblocking = nonblocking;
    }

    pub fn shutdown_write(&mut self) -> io::Result<()> {
        let (ack_tx, ack_rx) = mpsc::channel();
        self.write_tx
            .send(NaiveH3WriteCommand::Finish(ack_tx))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Naive H3 stream is closed"))?;
        recv_h3_write_ack(ack_rx)
    }

    pub fn shutdown_both(&mut self) -> io::Result<()> {
        self.shutdown_write().ok();
        self.stream_task.abort();
        self.h3_driver.abort();
        Ok(())
    }

    fn read_from_buffer(&mut self, buffer: &mut [u8]) -> Option<usize> {
        if self.read_offset >= self.read_buffer.len() {
            self.read_buffer.clear();
            self.read_offset = 0;
            return None;
        }
        let remaining = &self.read_buffer[self.read_offset..];
        let amount = remaining.len().min(buffer.len());
        buffer[..amount].copy_from_slice(&remaining[..amount]);
        self.read_offset += amount;
        if self.read_offset >= self.read_buffer.len() {
            self.read_buffer.clear();
            self.read_offset = 0;
        }
        Some(amount)
    }

    fn receive_next_read_chunk(&mut self) -> io::Result<bool> {
        if self.eof {
            return Ok(false);
        }
        let received = if self.nonblocking {
            match self.read_rx.try_recv() {
                Ok(received) => received,
                Err(mpsc::TryRecvError::Empty) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "Naive H3 stream has no data available",
                    ));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.eof = true;
                    return Ok(false);
                }
            }
        } else {
            match self.read_rx.recv() {
                Ok(received) => received,
                Err(_) => {
                    self.eof = true;
                    return Ok(false);
                }
            }
        }?;
        if received.is_empty() {
            self.eof = true;
            Ok(false)
        } else {
            self.read_buffer = received;
            self.read_offset = 0;
            Ok(true)
        }
    }
}

impl Read for NaiveH3QuicStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if let Some(bytes) = self.read_from_buffer(buffer) {
            return Ok(bytes);
        }
        if !self.receive_next_read_chunk()? {
            return Ok(0);
        }
        Ok(self.read_from_buffer(buffer).unwrap_or(0))
    }
}

impl Write for NaiveH3QuicStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let (ack_tx, ack_rx) = mpsc::channel();
        self.write_tx
            .send(NaiveH3WriteCommand::Data(buffer.to_vec(), ack_tx))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Naive H3 stream is closed"))?;
        recv_h3_write_ack(ack_rx)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl OwnedRelayStream for NaiveH3QuicStream {
    fn set_nonblocking_mode(&mut self, nonblocking: bool) -> io::Result<()> {
        self.set_nonblocking_mode(nonblocking);
        Ok(())
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.shutdown_write()
    }

    fn shutdown_both(&mut self) -> io::Result<()> {
        self.shutdown_both()
    }
}

impl Drop for NaiveH3QuicStream {
    fn drop(&mut self) {
        self.stream_task.abort();
        self.h3_driver.abort();
    }
}

async fn receive_h3_data(
    recv: &mut h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    read_tx: &mpsc::Sender<io::Result<Vec<u8>>>,
) -> bool {
    forward_h3_received_data(recv.recv_data().await, read_tx)
}

fn forward_h3_received_data(
    received: Result<Option<impl Buf>, h3::error::StreamError>,
    read_tx: &mpsc::Sender<io::Result<Vec<u8>>>,
) -> bool {
    match received {
        Ok(Some(mut bytes)) => {
            let bytes = bytes.copy_to_bytes(bytes.remaining());
            !bytes.is_empty() && read_tx.send(Ok(bytes.to_vec())).is_ok()
        }
        Ok(None) => {
            let _ = read_tx.send(Ok(Vec::new()));
            false
        }
        Err(error) => {
            let _ = read_tx.send(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("{error:?}"),
            )));
            false
        }
    }
}

fn recv_h3_write_ack(ack_rx: mpsc::Receiver<io::Result<()>>) -> io::Result<()> {
    ack_rx
        .recv()
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Naive H3 stream is closed"))?
}

async fn send_h2_data(
    send: &mut h2::SendStream<Bytes>,
    mut buffer: &[u8],
    end_stream: bool,
) -> io::Result<()> {
    if buffer.is_empty() {
        if end_stream {
            send.send_data(Bytes::new(), true).map_err(io_other)?;
        }
        return Ok(());
    }
    while !buffer.is_empty() {
        let amount = buffer.len().min(16 * 1024);
        let chunk = Bytes::copy_from_slice(&buffer[..amount]);
        buffer = &buffer[amount..];
        send.send_data(chunk, end_stream && buffer.is_empty())
            .map_err(io_other)?;
    }
    Ok(())
}

fn connect_authority(target: &Endpoint) -> String {
    match target.host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{}]:{}", target.host, target.port),
        _ => format!("{}:{}", target.host, target.port),
    }
}

fn quic_bind_addr_for(server_addr: SocketAddr) -> SocketAddr {
    if server_addr.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    }
}

fn io_other(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.to_string())
}
