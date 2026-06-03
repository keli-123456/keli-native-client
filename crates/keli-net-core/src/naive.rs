use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::{mpsc, Arc, Mutex};

use base64::Engine;
use bytes::Bytes;
use keli_protocol::Endpoint;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use crate::{DirectTcpConnector, OutboundConnection, OutboundTarget, OwnedRelayStream};

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

fn io_other(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.to_string())
}
