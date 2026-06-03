use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use keli_protocol::{build_hy2_auth_request, is_hy2_auth_success_status};

pub type Hy2H3Connection = h3::client::Connection<h3_quinn::Connection, bytes::Bytes>;
pub type Hy2H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>;

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
