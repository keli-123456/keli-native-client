use std::io;
use std::sync::Arc;

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
