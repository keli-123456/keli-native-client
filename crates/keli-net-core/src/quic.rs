use std::fmt;
use std::future::poll_fn;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{mpsc, Arc, Mutex};
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use keli_protocol::{
    build_hy2_auth_request, decode_hy2_tcp_response, decode_hy2_udp_message,
    decode_tuic_packet_command, encode_hy2_tcp_request, encode_hy2_udp_message,
    encode_tuic_authenticate_command, encode_tuic_connect_command, encode_tuic_packet_command,
    is_hy2_auth_success_status, Endpoint, Hy2UdpMessage, ProtocolDecodingError, TuicPacketCommand,
};
use quinn::Runtime;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub type Hy2H3Connection = h3::client::Connection<h3_quinn::Connection, bytes::Bytes>;
pub type Hy2H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>;
pub const LEGACY_QUIC_INTERNAL_SERVER_NAME: &str = "quic.internal.v2fly.org";
const QUIC_SALT: &[u8] = b"v2ray-quic-salt";
const HY2_TCP_RESPONSE_PREFETCH_LIMIT: usize = 64 * 1024;

pub fn h3_rustls_client_config(skip_verify: bool) -> io::Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

    let mut config = if skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(QuicInsecureServerVerifier::new(provider))
            .with_no_client_auth()
    } else {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };
    config.alpn_protocols = vec![b"h3".to_vec()];
    config.enable_early_data = true;
    Ok(config)
}

pub fn h3_quic_client_config(skip_verify: bool) -> io::Result<quinn::ClientConfig> {
    let tls = h3_rustls_client_config(skip_verify)?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

pub fn h3_quic_client_endpoint(
    bind_addr: SocketAddr,
    skip_verify: bool,
) -> io::Result<quinn::Endpoint> {
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(h3_quic_client_config(skip_verify)?);
    Ok(endpoint)
}

pub async fn h3_quic_connect(
    endpoint: &quinn::Endpoint,
    server_addr: SocketAddr,
    server_name: &str,
) -> io::Result<quinn::Connection> {
    if server_name.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HY2 QUIC server name is empty",
        ));
    }
    endpoint
        .connect(server_addr, server_name)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyQuicTransportConfig {
    pub security: Option<String>,
    pub key: Option<String>,
    pub header_type: Option<String>,
}

impl LegacyQuicTransportConfig {
    pub fn new(security: Option<String>, key: Option<String>, header_type: Option<String>) -> Self {
        Self {
            security,
            key,
            header_type,
        }
    }

    fn validate(&self) -> io::Result<()> {
        let security = self.normalized_security();
        let key = self.normalized_key();
        if security.eq_ignore_ascii_case("none") && !key.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "legacy QUIC key is supported only with encrypted packet security",
            ));
        }
        let _ = QuicPacketSecurity::from_name_and_key(&security, &key)?;
        let header = self.normalized_header_type();
        if !header.eq_ignore_ascii_case("none") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("legacy QUIC packet header {header} is not supported yet"),
            ));
        }
        Ok(())
    }

    fn packet_security(&self) -> io::Result<Option<QuicPacketSecurity>> {
        QuicPacketSecurity::from_name_and_key(&self.normalized_security(), &self.normalized_key())
    }

    fn normalized_security(&self) -> String {
        self.security
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("none")
            .to_ascii_lowercase()
    }

    fn normalized_key(&self) -> String {
        self.key
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .to_string()
    }

    fn normalized_header_type(&self) -> String {
        self.header_type
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("none")
            .to_ascii_lowercase()
    }
}

pub fn legacy_quic_client_config(skip_verify: bool) -> io::Result<quinn::ClientConfig> {
    let tls = legacy_quic_rustls_client_config(skip_verify)?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

pub fn legacy_quic_rustls_client_config(skip_verify: bool) -> io::Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

    if skip_verify {
        Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(QuicInsecureServerVerifier::new(provider))
            .with_no_client_auth())
    } else {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Ok(builder
            .with_root_certificates(root_store)
            .with_no_client_auth())
    }
}

pub fn legacy_quic_client_endpoint(
    bind_addr: SocketAddr,
    skip_verify: bool,
    transport: &LegacyQuicTransportConfig,
) -> io::Result<quinn::Endpoint> {
    transport.validate()?;
    let mut endpoint = if let Some(security) = transport.packet_security()? {
        let socket = std::net::UdpSocket::bind(bind_addr)?;
        let runtime = Arc::new(quinn::TokioRuntime);
        let socket = runtime.wrap_udp_socket(socket)?;
        let socket = Arc::new(QuicPacketUdpSocket::new(socket, security));
        quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )?
    } else {
        quinn::Endpoint::client(bind_addr)?
    };
    endpoint.set_default_client_config(legacy_quic_client_config(skip_verify)?);
    Ok(endpoint)
}

pub async fn legacy_quic_connect(
    endpoint: &quinn::Endpoint,
    server_addr: SocketAddr,
    server_name: &str,
) -> io::Result<quinn::Connection> {
    if server_name.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "legacy QUIC server name is empty",
        ));
    }
    endpoint
        .connect(server_addr, server_name)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error))
}

struct QuicPacketUdpSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    security: QuicPacketSecurity,
}

impl QuicPacketUdpSocket {
    fn new(inner: Arc<dyn quinn::AsyncUdpSocket>, security: QuicPacketSecurity) -> Self {
        Self { inner, security }
    }
}

impl fmt::Debug for QuicPacketUdpSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuicPacketUdpSocket")
            .field("security", &self.security.name())
            .finish_non_exhaustive()
    }
}

impl quinn::AsyncUdpSocket for QuicPacketUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        if segment_size == 0 || segment_size >= transmit.contents.len() {
            let packet = self.security.seal_packet(transmit.contents)?;
            let wrapped = quinn::udp::Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: &packet,
                segment_size: None,
                src_ip: transmit.src_ip,
            };
            return self.inner.try_send(&wrapped);
        }

        let segment_count = transmit.contents.len().div_ceil(segment_size);
        let wrapped_segment_size = segment_size + self.security.packet_overhead();
        let mut packet = Vec::with_capacity(
            transmit.contents.len() + segment_count * self.security.packet_overhead(),
        );
        for chunk in transmit.contents.chunks(segment_size) {
            self.security.seal_packet_into(chunk, &mut packet)?;
        }
        let wrapped = quinn::udp::Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &packet,
            segment_size: Some(wrapped_segment_size),
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&wrapped)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(read)) => {
                for index in 0..read {
                    if !self.security.open_meta(&mut bufs[index], &mut meta[index]) {
                        meta[index].len = 0;
                        meta[index].stride = 0;
                    }
                }
                Poll::Ready(Ok(read))
            }
            other => other,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

enum QuicPacketSecurity {
    Aes128Gcm(Aes128Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl QuicPacketSecurity {
    fn from_name_and_key(security: &str, key: &str) -> io::Result<Option<Self>> {
        let security = security.trim().to_ascii_lowercase();
        if security.is_empty() || security == "none" {
            return Ok(None);
        }

        let digest = quic_packet_key(key);
        match security.as_str() {
            "aes-128-gcm" | "aes128-gcm" => {
                let cipher = Aes128Gcm::new_from_slice(&digest[..16]).map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
                })?;
                Ok(Some(Self::Aes128Gcm(cipher)))
            }
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => {
                let cipher = ChaCha20Poly1305::new_from_slice(&digest).map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
                })?;
                Ok(Some(Self::ChaCha20Poly1305(cipher)))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("legacy QUIC packet security {security} is not supported"),
            )),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Aes128Gcm(_) => "aes-128-gcm",
            Self::ChaCha20Poly1305(_) => "chacha20-poly1305",
        }
    }

    fn nonce_size(&self) -> usize {
        12
    }

    fn tag_size(&self) -> usize {
        16
    }

    fn packet_overhead(&self) -> usize {
        self.nonce_size() + self.tag_size()
    }

    fn seal_packet(&self, input: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(input.len() + self.packet_overhead());
        self.seal_packet_into(input, &mut output)?;
        Ok(output)
    }

    fn seal_packet_into(&self, input: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        output.extend_from_slice(&nonce);
        let encrypted = match self {
            Self::Aes128Gcm(cipher) => cipher
                .encrypt(AesNonce::from_slice(&nonce), input)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "legacy QUIC packet seal failed")
                })?,
            Self::ChaCha20Poly1305(cipher) => cipher
                .encrypt(ChaChaNonce::from_slice(&nonce), input)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "legacy QUIC packet seal failed")
                })?,
        };
        output.extend_from_slice(&encrypted);
        Ok(())
    }

    fn open_packet(&self, input: &[u8]) -> Option<Vec<u8>> {
        if input.len() <= self.packet_overhead() {
            return None;
        }
        let (nonce, payload) = input.split_at(self.nonce_size());
        match self {
            Self::Aes128Gcm(cipher) => cipher.decrypt(AesNonce::from_slice(nonce), payload).ok(),
            Self::ChaCha20Poly1305(cipher) => {
                cipher.decrypt(ChaChaNonce::from_slice(nonce), payload).ok()
            }
        }
    }

    fn open_meta(&self, buffer: &mut IoSliceMut<'_>, meta: &mut quinn::udp::RecvMeta) -> bool {
        let stride = if meta.stride == 0 {
            meta.len
        } else {
            meta.stride
        };
        if stride <= self.packet_overhead() {
            return false;
        }

        let mut input_offset = 0usize;
        let mut output_offset = 0usize;
        let mut output_stride = 0usize;
        let mut segment_count = 0usize;
        while input_offset < meta.len {
            let packet_len = stride.min(meta.len - input_offset);
            if packet_len <= self.packet_overhead() {
                return false;
            }

            let Some(plain) = self.open_packet(&buffer[input_offset..input_offset + packet_len])
            else {
                return false;
            };
            let plain_len = plain.len();
            buffer[output_offset..output_offset + plain_len].copy_from_slice(&plain);
            if segment_count == 0 {
                output_stride = plain_len;
            }
            segment_count += 1;
            input_offset += packet_len;
            output_offset += plain_len;
        }

        meta.len = output_offset;
        meta.stride = if segment_count <= 1 {
            output_offset
        } else {
            output_stride
        };
        true
    }
}

fn quic_packet_key(key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.update(QUIC_SALT);
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

pub fn tuic_export_token(
    connection: &quinn::Connection,
    uuid: &str,
    password: &str,
) -> io::Result<[u8; 32]> {
    if password.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUIC password is empty",
        ));
    }
    let zero_token = [0; 32];
    let auth = encode_tuic_authenticate_command(uuid, &zero_token)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let uuid_label = &auth[2..18];
    let mut token = [0; 32];
    connection
        .export_keying_material(&mut token, uuid_label, password.as_bytes())
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("TUIC keying material export failed: {error:?}"),
            )
        })?;
    Ok(token)
}

pub fn tuic_authenticate_command(
    connection: &quinn::Connection,
    uuid: &str,
    password: &str,
) -> io::Result<Vec<u8>> {
    let token = tuic_export_token(connection, uuid, password)?;
    encode_tuic_authenticate_command(uuid, &token)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

pub async fn tuic_authenticate(
    connection: &quinn::Connection,
    uuid: &str,
    password: &str,
) -> io::Result<()> {
    let command = tuic_authenticate_command(connection, uuid, password)?;
    let mut stream = connection
        .open_uni()
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))?;
    stream
        .write_all(&command)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))?;
    stream
        .finish()
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))
}

pub fn tuic_send_packet_datagram(
    connection: &quinn::Connection,
    associate_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    target: &Endpoint,
    payload: &[u8],
) -> io::Result<()> {
    let command = encode_tuic_packet_command(
        associate_id,
        packet_id,
        fragment_total,
        fragment_id,
        target,
        payload,
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    connection
        .send_datagram(bytes::Bytes::from(command))
        .map_err(tuic_datagram_send_error_to_io)
}

pub async fn tuic_read_packet_datagram(
    connection: &quinn::Connection,
) -> io::Result<TuicPacketCommand> {
    let datagram = connection
        .read_datagram()
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))?;
    decode_tuic_packet_command(&datagram)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn hy2_send_udp_datagram(
    connection: &quinn::Connection,
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    address: &Endpoint,
    payload: &[u8],
) -> io::Result<()> {
    let message = encode_hy2_udp_message(
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        address,
        payload,
    )
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    connection
        .send_datagram(bytes::Bytes::from(message))
        .map_err(hy2_datagram_send_error_to_io)
}

pub async fn hy2_read_udp_datagram(connection: &quinn::Connection) -> io::Result<Hy2UdpMessage> {
    let datagram = connection
        .read_datagram()
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))?;
    decode_hy2_udp_message(&datagram)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn tuic_datagram_send_error_to_io(error: quinn::SendDatagramError) -> io::Error {
    match error {
        quinn::SendDatagramError::UnsupportedByPeer => io::Error::new(
            io::ErrorKind::Unsupported,
            "TUIC QUIC datagrams are not supported by peer",
        ),
        quinn::SendDatagramError::Disabled => io::Error::new(
            io::ErrorKind::Unsupported,
            "TUIC QUIC datagrams are disabled locally",
        ),
        quinn::SendDatagramError::TooLarge => {
            io::Error::new(io::ErrorKind::InvalidInput, "TUIC datagram is too large")
        }
        quinn::SendDatagramError::ConnectionLost(error) => {
            io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}"))
        }
    }
}

fn hy2_datagram_send_error_to_io(error: quinn::SendDatagramError) -> io::Error {
    match error {
        quinn::SendDatagramError::UnsupportedByPeer => io::Error::new(
            io::ErrorKind::Unsupported,
            "HY2 QUIC datagrams are not supported by peer",
        ),
        quinn::SendDatagramError::Disabled => io::Error::new(
            io::ErrorKind::Unsupported,
            "HY2 QUIC datagrams are disabled locally",
        ),
        quinn::SendDatagramError::TooLarge => {
            io::Error::new(io::ErrorKind::InvalidInput, "HY2 datagram is too large")
        }
        quinn::SendDatagramError::ConnectionLost(error) => {
            io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}"))
        }
    }
}

pub fn hy2_auth_http_request(
    auth: &str,
    cc_rx: u64,
    padding: &str,
) -> io::Result<http::Request<()>> {
    let request = build_hy2_auth_request(auth, cc_rx, padding)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    http::Request::builder()
        .method(request.method)
        .uri("https://hysteria/auth")
        .header("Hysteria-Auth", request.auth)
        .header("Hysteria-CC-RX", request.cc_rx)
        .header("Hysteria-Padding", request.padding)
        .body(())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

pub async fn h3_client_from_quinn_connection(
    connection: quinn::Connection,
) -> Result<(Hy2H3Connection, Hy2H3SendRequest), h3::error::ConnectionError> {
    h3::client::new(h3_quinn::Connection::new(connection)).await
}

pub async fn hy2_authenticate_h3(
    send_request: &mut Hy2H3SendRequest,
    auth: &str,
    cc_rx: u64,
    padding: &str,
) -> io::Result<()> {
    let request = hy2_auth_http_request(auth, cc_rx, padding)?;
    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))?;
    stream
        .finish()
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))?;
    let response = stream
        .recv_response()
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))?;
    validate_hy2_auth_response(&response)
}

pub struct Hy2ClientSession {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    _send_request: Hy2H3SendRequest,
    h3_driver: tokio::task::JoinHandle<h3::error::ConnectionError>,
}

impl Hy2ClientSession {
    pub async fn connect(
        bind_addr: SocketAddr,
        server_addr: SocketAddr,
        server_name: &str,
        skip_verify: bool,
        auth: &str,
        cc_rx: u64,
        auth_padding: &str,
    ) -> io::Result<Self> {
        let endpoint = h3_quic_client_endpoint(bind_addr, skip_verify)?;
        let connection = h3_quic_connect(&endpoint, server_addr, server_name).await?;
        let (mut h3_connection, mut send_request) =
            h3_client_from_quinn_connection(connection.clone())
                .await
                .map_err(|error| {
                    io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}"))
                })?;
        let h3_driver =
            tokio::spawn(async move { poll_fn(|cx| h3_connection.poll_close(cx)).await });
        if let Err(error) = hy2_authenticate_h3(&mut send_request, auth, cc_rx, auth_padding).await
        {
            h3_driver.abort();
            return Err(error);
        }
        Ok(Self {
            endpoint,
            connection,
            _send_request: send_request,
            h3_driver,
        })
    }

    pub async fn open_tcp_stream(
        &self,
        target: &Endpoint,
        padding: &[u8],
    ) -> io::Result<Hy2QuicTcpStream> {
        hy2_open_tcp_stream(&self.connection, target, padding).await
    }

    pub async fn relay_udp_datagram(
        &self,
        session_id: u32,
        packet_id: u16,
        target: &Endpoint,
        payload: &[u8],
    ) -> io::Result<Hy2UdpMessage> {
        hy2_send_udp_datagram(
            &self.connection,
            session_id,
            packet_id,
            0,
            1,
            target,
            payload,
        )?;
        hy2_read_udp_datagram(&self.connection).await
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    pub fn h3_driver_finished(&self) -> bool {
        self.h3_driver.is_finished()
    }
}

impl Drop for Hy2ClientSession {
    fn drop(&mut self) {
        self.h3_driver.abort();
    }
}

pub struct Hy2QuicTcpStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    read_buffer: Vec<u8>,
    read_offset: usize,
}

pub struct TuicQuicTcpStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    read_buffer: Vec<u8>,
    read_offset: usize,
}

pub struct TuicClientSession {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

pub struct LegacyQuicTcpStream {
    runtime: Arc<tokio::runtime::Runtime>,
    _endpoint: quinn::Endpoint,
    _connection: quinn::Connection,
    send: Arc<Mutex<quinn::SendStream>>,
    read_rx: mpsc::Receiver<io::Result<Vec<u8>>>,
    read_buffer: Vec<u8>,
    read_offset: usize,
    reader: tokio::task::JoinHandle<()>,
    nonblocking: bool,
    eof: bool,
}

impl LegacyQuicTcpStream {
    pub fn connect(
        bind_addr: SocketAddr,
        server_addr: SocketAddr,
        server_name: &str,
        skip_verify: bool,
        transport: LegacyQuicTransportConfig,
        timeout: std::time::Duration,
    ) -> io::Result<Self> {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .thread_name("keli-legacy-quic-runtime")
                .build()
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?,
        );
        let (endpoint, connection, send, recv) = runtime.block_on(async {
            let endpoint = legacy_quic_client_endpoint(bind_addr, skip_verify, &transport)?;
            let connection = tokio::time::timeout(
                timeout,
                legacy_quic_connect(&endpoint, server_addr, server_name),
            )
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "legacy QUIC handshake timed out")
            })??;
            let (send, recv) = tokio::time::timeout(timeout, connection.open_bi())
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "legacy QUIC stream open timed out")
                })?
                .map_err(|error| {
                    io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}"))
                })?;
            Ok::<_, io::Error>((endpoint, connection, send, recv))
        })?;
        Ok(Self::from_stream(runtime, endpoint, connection, send, recv))
    }

    fn from_stream(
        runtime: Arc<tokio::runtime::Runtime>,
        endpoint: quinn::Endpoint,
        connection: quinn::Connection,
        send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) -> Self {
        let send = Arc::new(Mutex::new(send));
        let (read_tx, read_rx) = mpsc::channel();
        let reader = runtime.spawn(async move {
            let mut buffer = vec![0; 16 * 1024];
            loop {
                match recv.read(&mut buffer).await {
                    Ok(Some(bytes)) => {
                        if bytes == 0 {
                            continue;
                        }
                        if read_tx.send(Ok(buffer[..bytes].to_vec())).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        let _ = read_tx.send(Ok(Vec::new()));
                        break;
                    }
                    Err(error) => {
                        let _ = read_tx.send(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            format!("{error:?}"),
                        )));
                        break;
                    }
                }
            }
        });
        Self {
            runtime,
            _endpoint: endpoint,
            _connection: connection,
            send,
            read_rx,
            read_buffer: Vec::new(),
            read_offset: 0,
            reader,
            nonblocking: false,
            eof: false,
        }
    }

    pub fn set_nonblocking_mode(&mut self, nonblocking: bool) {
        self.nonblocking = nonblocking;
    }

    pub fn shutdown_write(&mut self) -> io::Result<()> {
        let mut send = self.send.lock().map_err(|_| {
            io::Error::new(
                io::ErrorKind::Other,
                "legacy QUIC send stream lock poisoned",
            )
        })?;
        send.finish()
            .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))
    }

    pub fn shutdown_both(&mut self) -> io::Result<()> {
        self.shutdown_write().ok();
        self.reader.abort();
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
                        "legacy QUIC stream has no data available",
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

impl std::io::Read for LegacyQuicTcpStream {
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

impl std::io::Write for LegacyQuicTcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut send = self.send.lock().map_err(|_| {
            io::Error::new(
                io::ErrorKind::Other,
                "legacy QUIC send stream lock poisoned",
            )
        })?;
        self.runtime
            .block_on(send.write_all(buffer))
            .map_err(|error| {
                io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}"))
            })?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for LegacyQuicTcpStream {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl TuicClientSession {
    pub async fn connect(
        bind_addr: SocketAddr,
        server_addr: SocketAddr,
        server_name: &str,
        skip_verify: bool,
        uuid: &str,
        password: &str,
    ) -> io::Result<Self> {
        let endpoint = h3_quic_client_endpoint(bind_addr, skip_verify)?;
        let connection = h3_quic_connect(&endpoint, server_addr, server_name).await?;
        tuic_authenticate(&connection, uuid, password).await?;
        Ok(Self {
            endpoint,
            connection,
        })
    }

    pub async fn open_tcp_stream(&self, target: &Endpoint) -> io::Result<TuicQuicTcpStream> {
        tuic_open_tcp_stream(&self.connection, target).await
    }

    pub async fn relay_udp_datagram(
        &self,
        associate_id: u16,
        packet_id: u16,
        target: &Endpoint,
        payload: &[u8],
    ) -> io::Result<TuicPacketCommand> {
        tuic_send_packet_datagram(
            &self.connection,
            associate_id,
            packet_id,
            1,
            0,
            target,
            payload,
        )?;
        tuic_read_packet_datagram(&self.connection).await
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }
}

pub struct TuicBlockingTcpStream {
    runtime: Arc<tokio::runtime::Runtime>,
    _session: TuicClientSession,
    send: Arc<Mutex<quinn::SendStream>>,
    read_rx: mpsc::Receiver<io::Result<Vec<u8>>>,
    read_buffer: Vec<u8>,
    read_offset: usize,
    reader: tokio::task::JoinHandle<()>,
    nonblocking: bool,
    eof: bool,
}

impl TuicBlockingTcpStream {
    pub fn connect(
        bind_addr: SocketAddr,
        server_addr: SocketAddr,
        server_name: &str,
        skip_verify: bool,
        uuid: &str,
        password: &str,
        target: &Endpoint,
    ) -> io::Result<Self> {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .thread_name("keli-tuic-runtime")
                .build()
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?,
        );
        let session = runtime.block_on(TuicClientSession::connect(
            bind_addr,
            server_addr,
            server_name,
            skip_verify,
            uuid,
            password,
        ))?;
        let stream = runtime.block_on(session.open_tcp_stream(target))?;
        Ok(Self::from_session_stream(runtime, session, stream))
    }

    fn from_session_stream(
        runtime: Arc<tokio::runtime::Runtime>,
        session: TuicClientSession,
        stream: TuicQuicTcpStream,
    ) -> Self {
        let TuicQuicTcpStream {
            send,
            mut recv,
            read_buffer,
            read_offset,
        } = stream;
        let send = Arc::new(Mutex::new(send));
        let (read_tx, read_rx) = mpsc::channel();
        let reader = runtime.spawn(async move {
            let mut buffer = vec![0; 16 * 1024];
            loop {
                match recv.read(&mut buffer).await {
                    Ok(Some(bytes)) => {
                        if bytes == 0 {
                            continue;
                        }
                        if read_tx.send(Ok(buffer[..bytes].to_vec())).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        let _ = read_tx.send(Ok(Vec::new()));
                        break;
                    }
                    Err(error) => {
                        let _ = read_tx.send(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            format!("{error:?}"),
                        )));
                        break;
                    }
                }
            }
        });
        Self {
            runtime,
            _session: session,
            send,
            read_rx,
            read_buffer,
            read_offset,
            reader,
            nonblocking: false,
            eof: false,
        }
    }

    pub fn set_nonblocking_mode(&mut self, nonblocking: bool) {
        self.nonblocking = nonblocking;
    }

    pub fn shutdown_write(&mut self) -> io::Result<()> {
        let mut send = self
            .send
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "TUIC send stream lock poisoned"))?;
        send.finish()
            .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))
    }

    pub fn shutdown_both(&mut self) -> io::Result<()> {
        self.shutdown_write().ok();
        self.reader.abort();
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
                        "TUIC stream has no data available",
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

impl std::io::Read for TuicBlockingTcpStream {
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

impl std::io::Write for TuicBlockingTcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut send = self
            .send
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "TUIC send stream lock poisoned"))?;
        self.runtime
            .block_on(send.write_all(buffer))
            .map_err(|error| {
                io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}"))
            })?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for TuicBlockingTcpStream {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

pub struct Hy2BlockingTcpStream {
    runtime: Arc<tokio::runtime::Runtime>,
    _session: Hy2ClientSession,
    send: Arc<Mutex<quinn::SendStream>>,
    read_rx: mpsc::Receiver<io::Result<Vec<u8>>>,
    read_buffer: Vec<u8>,
    read_offset: usize,
    reader: tokio::task::JoinHandle<()>,
    nonblocking: bool,
    eof: bool,
}

impl Hy2BlockingTcpStream {
    pub fn connect(
        bind_addr: SocketAddr,
        server_addr: SocketAddr,
        server_name: &str,
        skip_verify: bool,
        auth: &str,
        cc_rx: u64,
        auth_padding: &str,
        target: &Endpoint,
        tcp_padding: &[u8],
    ) -> io::Result<Self> {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .thread_name("keli-hy2-runtime")
                .build()
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?,
        );
        let session = runtime.block_on(Hy2ClientSession::connect(
            bind_addr,
            server_addr,
            server_name,
            skip_verify,
            auth,
            cc_rx,
            auth_padding,
        ))?;
        let stream = runtime.block_on(session.open_tcp_stream(target, tcp_padding))?;
        Ok(Self::from_session_stream(runtime, session, stream))
    }

    fn from_session_stream(
        runtime: Arc<tokio::runtime::Runtime>,
        session: Hy2ClientSession,
        stream: Hy2QuicTcpStream,
    ) -> Self {
        let Hy2QuicTcpStream {
            send,
            mut recv,
            read_buffer,
            read_offset,
        } = stream;
        let send = Arc::new(Mutex::new(send));
        let (read_tx, read_rx) = mpsc::channel();
        let reader = runtime.spawn(async move {
            let mut buffer = vec![0; 16 * 1024];
            loop {
                match recv.read(&mut buffer).await {
                    Ok(Some(bytes)) => {
                        if bytes == 0 {
                            continue;
                        }
                        if read_tx.send(Ok(buffer[..bytes].to_vec())).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        let _ = read_tx.send(Ok(Vec::new()));
                        break;
                    }
                    Err(error) => {
                        let _ = read_tx.send(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            format!("{error:?}"),
                        )));
                        break;
                    }
                }
            }
        });
        Self {
            runtime,
            _session: session,
            send,
            read_rx,
            read_buffer,
            read_offset,
            reader,
            nonblocking: false,
            eof: false,
        }
    }

    pub fn set_nonblocking_mode(&mut self, nonblocking: bool) {
        self.nonblocking = nonblocking;
    }

    pub fn shutdown_write(&mut self) -> io::Result<()> {
        let mut send = self
            .send
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "HY2 send stream lock poisoned"))?;
        send.finish()
            .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))
    }

    pub fn shutdown_both(&mut self) -> io::Result<()> {
        self.shutdown_write().ok();
        self.reader.abort();
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
                        "HY2 stream has no data available",
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

impl std::io::Read for Hy2BlockingTcpStream {
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

impl std::io::Write for Hy2BlockingTcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut send = self
            .send
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "HY2 send stream lock poisoned"))?;
        self.runtime
            .block_on(send.write_all(buffer))
            .map_err(|error| {
                io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}"))
            })?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Hy2BlockingTcpStream {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl Hy2QuicTcpStream {
    pub async fn write_all(&mut self, buffer: &[u8]) -> io::Result<()> {
        self.send
            .write_all(buffer)
            .await
            .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))
    }

    pub async fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.read_offset < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_offset..];
            let amount = remaining.len().min(buffer.len());
            buffer[..amount].copy_from_slice(&remaining[..amount]);
            self.read_offset += amount;
            if self.read_offset >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_offset = 0;
            }
            return Ok(amount);
        }
        self.recv
            .read(buffer)
            .await
            .map(|amount| amount.unwrap_or(0))
            .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))
    }

    pub async fn read_exact(&mut self, buffer: &mut [u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < buffer.len() {
            let amount = self.read(&mut buffer[offset..]).await?;
            if amount == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "HY2 TCP stream closed before enough data was read",
                ));
            }
            offset += amount;
        }
        Ok(())
    }

    pub fn finish(&mut self) -> io::Result<()> {
        self.send
            .finish()
            .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))
    }
}

impl TuicQuicTcpStream {
    pub async fn write_all(&mut self, buffer: &[u8]) -> io::Result<()> {
        self.send
            .write_all(buffer)
            .await
            .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))
    }

    pub async fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.read_offset < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_offset..];
            let amount = remaining.len().min(buffer.len());
            buffer[..amount].copy_from_slice(&remaining[..amount]);
            self.read_offset += amount;
            if self.read_offset >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_offset = 0;
            }
            return Ok(amount);
        }
        self.recv
            .read(buffer)
            .await
            .map(|amount| amount.unwrap_or(0))
            .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))
    }

    pub async fn read_exact(&mut self, buffer: &mut [u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < buffer.len() {
            let amount = self.read(&mut buffer[offset..]).await?;
            if amount == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TUIC TCP stream closed before enough data was read",
                ));
            }
            offset += amount;
        }
        Ok(())
    }

    pub fn finish(&mut self) -> io::Result<()> {
        self.send
            .finish()
            .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))
    }
}

pub async fn tuic_open_tcp_stream(
    connection: &quinn::Connection,
    target: &Endpoint,
) -> io::Result<TuicQuicTcpStream> {
    let request = encode_tuic_connect_command(target)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let (mut send, recv) = connection
        .open_bi()
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))?;
    send.write_all(&request)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))?;
    Ok(TuicQuicTcpStream {
        send,
        recv,
        read_buffer: Vec::new(),
        read_offset: 0,
    })
}

pub async fn hy2_open_tcp_stream(
    connection: &quinn::Connection,
    target: &Endpoint,
    padding: &[u8],
) -> io::Result<Hy2QuicTcpStream> {
    let request = encode_hy2_tcp_request(target, padding)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))?;
    send.write_all(&request)
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}")))?;
    let read_buffer = read_hy2_tcp_response_prefetch(&mut recv).await?;
    Ok(Hy2QuicTcpStream {
        send,
        recv,
        read_buffer,
        read_offset: 0,
    })
}

pub async fn hy2_open_authenticated_tcp_stream(
    connection: &quinn::Connection,
    send_request: &mut Hy2H3SendRequest,
    auth: &str,
    cc_rx: u64,
    auth_padding: &str,
    target: &Endpoint,
    tcp_padding: &[u8],
) -> io::Result<Hy2QuicTcpStream> {
    hy2_authenticate_h3(send_request, auth, cc_rx, auth_padding).await?;
    hy2_open_tcp_stream(connection, target, tcp_padding).await
}

pub fn validate_hy2_auth_response(response: &http::Response<()>) -> io::Result<()> {
    let status = response.status().as_u16();
    if is_hy2_auth_success_status(status) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("HY2 auth failed with HTTP/3 status {status}"),
        ))
    }
}

async fn read_hy2_tcp_response_prefetch(recv: &mut quinn::RecvStream) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut chunk = [0; 1024];
    loop {
        let Some(amount) = recv.read(&mut chunk).await.map_err(|error| {
            io::Error::new(io::ErrorKind::ConnectionAborted, format!("{error:?}"))
        })?
        else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HY2 TCP stream closed before response",
            ));
        };
        buffer.extend_from_slice(&chunk[..amount]);
        match decode_hy2_tcp_response(&buffer) {
            Ok((response, consumed)) => {
                if !response.ok {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("HY2 TCP connect failed: {}", response.message),
                    ));
                }
                return Ok(buffer[consumed..].to_vec());
            }
            Err(ProtocolDecodingError::UnexpectedEof)
                if buffer.len() <= HY2_TCP_RESPONSE_PREFETCH_LIMIT => {}
            Err(error) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, error));
            }
        }
    }
}

#[derive(Debug)]
struct QuicInsecureServerVerifier(Arc<rustls::crypto::CryptoProvider>);

impl QuicInsecureServerVerifier {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for QuicInsecureServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
