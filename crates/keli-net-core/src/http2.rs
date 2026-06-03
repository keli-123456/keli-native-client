use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, TcpStream};
use std::sync::{mpsc, Arc, Mutex};

use bytes::Bytes;
use h2::RecvStream;
use http::{Request, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use crate::direct::OwnedRelayStream;

const DEFAULT_H2_PATH: &str = "/";
const H2_METHOD: http::Method = http::Method::PUT;

pub struct Http2TcpStream {
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

impl Http2TcpStream {
    pub fn connect_plain(stream: TcpStream, host: &str, path: &str) -> io::Result<Self> {
        let runtime = http2_runtime()?;
        stream.set_nonblocking(true)?;
        runtime.block_on(async {
            let stream = tokio::net::TcpStream::from_std(stream)?;
            Self::connect_async(runtime.clone(), stream, false, host, path).await
        })
    }

    pub fn connect_tls(
        stream: TcpStream,
        server_name: &str,
        skip_verify: bool,
        host: &str,
        path: &str,
    ) -> io::Result<Self> {
        let runtime = http2_runtime()?;
        stream.set_nonblocking(true)?;
        runtime.block_on(async {
            let stream = tokio::net::TcpStream::from_std(stream)?;
            let config =
                crate::direct::tls_client_config_with_alpn(skip_verify, vec![b"h2".to_vec()])?;
            let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            let stream = TlsConnector::from(config)
                .connect(server_name, stream)
                .await
                .map_err(io_other)?;
            Self::connect_async(runtime.clone(), stream, true, host, path).await
        })
    }

    async fn connect_async<S>(
        runtime: Arc<tokio::runtime::Runtime>,
        stream: S,
        tls: bool,
        host: &str,
        path: &str,
    ) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut client, connection) = h2::client::handshake(stream).await.map_err(io_other)?;
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let uri = http2_request_uri(tls, host, &normalize_path(path));
        let request = Request::builder()
            .method(H2_METHOD)
            .uri(uri)
            .body(())
            .map_err(io_other)?;
        let (response, send) = client.send_request(request, false).map_err(io_other)?;
        let response = response.await.map_err(io_other)?;
        if response.status() != StatusCode::OK {
            connection_task.abort();
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("h2 outbound server returned {}", response.status()),
            ));
        }
        let (read_tx, read_rx) = mpsc::channel();
        let reader_task = tokio::spawn(read_h2_data(response.into_body(), read_tx));
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
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "h2 send lock poisoned"))?;
        self.runtime
            .block_on(send_h2_data(&mut send, Bytes::new(), true))
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
                        "h2 stream has no data available",
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

impl Read for Http2TcpStream {
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

impl Write for Http2TcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let mut send = self
            .send
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "h2 send lock poisoned"))?;
        self.runtime.block_on(send_h2_data(
            &mut send,
            Bytes::copy_from_slice(buffer),
            false,
        ))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl OwnedRelayStream for Http2TcpStream {
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

impl Drop for Http2TcpStream {
    fn drop(&mut self) {
        self.reader_task.abort();
        self.connection_task.abort();
    }
}

async fn read_h2_data(mut stream: RecvStream, tx: mpsc::Sender<io::Result<Vec<u8>>>) {
    while let Some(chunk) = stream.data().await {
        match chunk {
            Ok(bytes) => {
                let len = bytes.len();
                let _ = stream.flow_control().release_capacity(len);
                if tx.send(Ok(bytes.to_vec())).is_err() {
                    return;
                }
            }
            Err(error) => {
                let _ = tx.send(Err(io_other(error)));
                return;
            }
        }
    }
    let _ = tx.send(Ok(Vec::new()));
}

async fn send_h2_data(
    send: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
    end_stream: bool,
) -> io::Result<()> {
    if data.is_empty() {
        return send.send_data(data, end_stream).map_err(io_other);
    }

    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let capacity = loop {
            match poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(capacity)) if capacity > 0 => break capacity,
                Some(Ok(_)) => continue,
                Some(Err(error)) => return Err(io_other(error)),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "h2 stream closed before data capacity was assigned",
                    ));
                }
            }
        };
        let chunk_len = capacity.min(data.len());
        let chunk = data.split_to(chunk_len);
        let chunk_ends_stream = end_stream && data.is_empty();
        send.send_data(chunk, chunk_ends_stream).map_err(io_other)?;
    }

    Ok(())
}

fn http2_runtime() -> io::Result<Arc<tokio::runtime::Runtime>> {
    Ok(Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("keli-http2-runtime")
            .build()
            .map_err(io_other)?,
    ))
}

fn http2_request_uri(tls: bool, host: &str, path: &str) -> String {
    let scheme = if tls { "https" } else { "http" };
    let authority = http2_authority(host);
    format!("{scheme}://{authority}{path}")
}

fn http2_authority(host: &str) -> String {
    let host = host.trim().trim_matches(['[', ']']);
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn normalize_path(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() {
        DEFAULT_H2_PATH.to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn io_other(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{http2_request_uri, normalize_path};

    #[test]
    fn normalizes_xray_h2_path() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("h2"), "/h2");
        assert_eq!(normalize_path("/h2"), "/h2");
    }

    #[test]
    fn builds_h2_uri_with_ipv6_authority() {
        assert_eq!(http2_request_uri(true, "::1", "/h2"), "https://[::1]/h2");
    }
}
