use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use keli_protocol::{
    build_hy2_auth_request, decode_hy2_tcp_response, encode_hy2_tcp_request,
    is_hy2_auth_success_status, Endpoint, ProtocolDecodingError,
};

pub type Hy2H3Connection = h3::client::Connection<h3_quinn::Connection, bytes::Bytes>;
pub type Hy2H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>;
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

pub struct Hy2QuicTcpStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    read_buffer: Vec<u8>,
    read_offset: usize,
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
