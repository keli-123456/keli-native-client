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

const DEFAULT_SERVICE_NAME: &str = "GunService";
const MAX_GRPC_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

pub struct GrpcTcpStream {
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

impl GrpcTcpStream {
    pub fn connect_plain(
        stream: TcpStream,
        host: &str,
        service_name: Option<&str>,
    ) -> io::Result<Self> {
        let runtime = grpc_runtime()?;
        stream.set_nonblocking(true)?;
        runtime.block_on(async {
            let stream = tokio::net::TcpStream::from_std(stream)?;
            Self::connect_async(runtime.clone(), stream, false, host, service_name).await
        })
    }

    pub fn connect_tls(
        stream: TcpStream,
        server_name: &str,
        skip_verify: bool,
        host: &str,
        service_name: Option<&str>,
    ) -> io::Result<Self> {
        let runtime = grpc_runtime()?;
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
            Self::connect_async(runtime.clone(), stream, true, host, service_name).await
        })
    }

    async fn connect_async<S>(
        runtime: Arc<tokio::runtime::Runtime>,
        stream: S,
        tls: bool,
        host: &str,
        service_name: Option<&str>,
    ) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut client, connection) = h2::client::handshake(stream).await.map_err(io_other)?;
        let connection_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let path = grpc_tun_path(service_name.unwrap_or(DEFAULT_SERVICE_NAME));
        let uri = grpc_request_uri(tls, host, &path);
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .map_err(io_other)?;
        let (response, send) = client.send_request(request, false).map_err(io_other)?;
        let response = response.await.map_err(io_other)?;
        if response.status() != StatusCode::OK {
            connection_task.abort();
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("grpc outbound server returned {}", response.status()),
            ));
        }
        let (read_tx, read_rx) = mpsc::channel();
        let reader_task = tokio::spawn(read_grpc_hunks(response.into_body(), read_tx));
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
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "gRPC send lock poisoned"))?;
        self.runtime
            .block_on(send_grpc_data(&mut send, Bytes::new(), true))
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
                        "gRPC stream has no data available",
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

impl Read for GrpcTcpStream {
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

impl Write for GrpcTcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let mut send = self
            .send
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "gRPC send lock poisoned"))?;
        self.runtime.block_on(send_grpc_data(
            &mut send,
            Bytes::from(encode_grpc_hunk(buffer)),
            false,
        ))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl OwnedRelayStream for GrpcTcpStream {
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

impl Drop for GrpcTcpStream {
    fn drop(&mut self) {
        self.reader_task.abort();
        self.connection_task.abort();
    }
}

async fn read_grpc_hunks(mut stream: RecvStream, tx: mpsc::Sender<io::Result<Vec<u8>>>) {
    let mut buffer = Vec::new();
    while let Some(chunk) = stream.data().await {
        match chunk {
            Ok(bytes) => {
                let len = bytes.len();
                buffer.extend_from_slice(&bytes);
                let _ = stream.flow_control().release_capacity(len);
                loop {
                    match take_grpc_message(&mut buffer) {
                        Ok(Some(message)) => match decode_hunk_message(&message) {
                            Ok(data) => {
                                if tx.send(Ok(data)).is_err() {
                                    return;
                                }
                            }
                            Err(error) => {
                                let _ = tx.send(Err(error));
                                return;
                            }
                        },
                        Ok(None) => break,
                        Err(error) => {
                            let _ = tx.send(Err(error));
                            return;
                        }
                    }
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

async fn send_grpc_data(
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
                        "gRPC stream closed before data capacity was assigned",
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

fn grpc_runtime() -> io::Result<Arc<tokio::runtime::Runtime>> {
    Ok(Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("keli-grpc-runtime")
            .build()
            .map_err(io_other)?,
    ))
}

fn grpc_request_uri(tls: bool, host: &str, path: &str) -> String {
    let scheme = if tls { "https" } else { "http" };
    let authority = grpc_authority(host);
    format!("{scheme}://{authority}{path}")
}

fn grpc_authority(host: &str) -> String {
    let host = host.trim().trim_matches(['[', ']']);
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn grpc_tun_path(service_name: &str) -> String {
    let service_name = service_name.trim();
    if service_name.is_empty() {
        return format!("/{DEFAULT_SERVICE_NAME}/Tun");
    }
    if !service_name.starts_with('/') {
        return format!("/{service_name}/Tun");
    }

    let trimmed = service_name.trim_start_matches('/');
    let Some((prefix, ending)) = trimmed.rsplit_once('/') else {
        return format!("/{}/Tun", trimmed.trim_matches('/'));
    };
    let tun = ending.split('|').next().unwrap_or("Tun").trim();
    format!(
        "/{}/{}",
        prefix.trim_matches('/'),
        first_non_empty(tun, "Tun")
    )
}

fn first_non_empty<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.trim().is_empty() {
        fallback
    } else {
        value
    }
}

fn encode_grpc_hunk(payload: &[u8]) -> Vec<u8> {
    let message = encode_hunk_message(payload);
    let mut output = Vec::with_capacity(5 + message.len());
    output.push(0);
    output.extend_from_slice(&(message.len() as u32).to_be_bytes());
    output.extend_from_slice(&message);
    output
}

fn encode_hunk_message(payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(1 + varint_len(payload.len() as u64) + payload.len());
    output.push(0x0a);
    encode_varint(payload.len() as u64, &mut output);
    output.extend_from_slice(payload);
    output
}

fn take_grpc_message(buffer: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    if buffer.len() < 5 {
        return Ok(None);
    }
    if buffer[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "compressed gRPC hunk messages are not supported",
        ));
    }
    let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
    if len > MAX_GRPC_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gRPC hunk message is too large",
        ));
    }
    if buffer.len() < 5 + len {
        return Ok(None);
    }
    let message = buffer[5..5 + len].to_vec();
    buffer.drain(..5 + len);
    Ok(Some(message))
}

fn decode_hunk_message(message: &[u8]) -> io::Result<Vec<u8>> {
    let mut cursor = 0usize;
    let mut data = None;
    while cursor < message.len() {
        let key = decode_varint(message, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (1, 2) => {
                let len = decode_varint(message, &mut cursor)? as usize;
                if cursor + len > message.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated gRPC hunk data",
                    ));
                }
                data = Some(message[cursor..cursor + len].to_vec());
                cursor += len;
            }
            (_, 0) => {
                let _ = decode_varint(message, &mut cursor)?;
            }
            (_, 2) => {
                let len = decode_varint(message, &mut cursor)? as usize;
                if cursor + len > message.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated gRPC hunk field",
                    ));
                }
                cursor += len;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported gRPC hunk wire type",
                ));
            }
        }
    }
    Ok(data.unwrap_or_default())
}

fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn decode_varint(input: &[u8], cursor: &mut usize) -> io::Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    while *cursor < input.len() && shift < 64 {
        let byte = input[*cursor];
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid gRPC hunk varint",
    ))
}

fn varint_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        len += 1;
        value >>= 7;
    }
    len
}

fn io_other(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{decode_hunk_message, encode_grpc_hunk, grpc_tun_path, take_grpc_message};

    #[test]
    fn encodes_and_decodes_grpc_hunk_messages() {
        let mut encoded = encode_grpc_hunk(b"hello");
        let message = take_grpc_message(&mut encoded)
            .expect("frame")
            .expect("message");

        assert_eq!(decode_hunk_message(&message).expect("hunk"), b"hello");
        assert!(encoded.is_empty());
    }

    #[test]
    fn resolves_xray_grpc_tun_path() {
        assert_eq!(grpc_tun_path("GunService"), "/GunService/Tun");
        assert_eq!(grpc_tun_path("/my/sample/path1|path2"), "/my/sample/path1");
        assert_eq!(grpc_tun_path(""), "/GunService/Tun");
    }
}
