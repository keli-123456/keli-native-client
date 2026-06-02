use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::{
    ConnectionErrorKind, DnsCache, DnsEngine, DnsResolver, RouteTarget, Socks5Address,
    Socks5Request, SystemDnsResolver,
};
use keli_protocol::{
    encode_trojan_tcp_request_header, encode_vless_tcp_request_header, Endpoint, OutboundProfile,
    ProtocolEncodingError, ProtocolValidationError, ProxyProtocol, SecurityKind, TransportKind,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundTarget {
    pub host: String,
    pub port: u16,
}

impl OutboundTarget {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    pub fn from_socks5_request(request: &Socks5Request) -> Self {
        let host = match &request.address {
            Socks5Address::Ipv4(ip) => ip.to_string(),
            Socks5Address::Domain(domain) => domain.clone(),
            Socks5Address::Ipv6(ip) => ip.to_string(),
        };
        Self::new(host, request.port)
    }

    pub fn route_target(&self) -> RouteTarget {
        match self.host.parse::<IpAddr>() {
            Ok(ip) => RouteTarget::Ip(ip),
            Err(_) => RouteTarget::Domain(self.host.clone()),
        }
    }
}

pub struct DirectTcpConnector;

impl DirectTcpConnector {
    pub fn connect(target: &OutboundTarget, timeout: Duration) -> io::Result<TcpStream> {
        let mut dns = DnsEngine::new(SystemDnsResolver, DnsCache::new(Duration::from_secs(60)));
        Self::connect_with_dns(target, timeout, &mut dns)
    }

    pub fn connect_with_dns<R: DnsResolver>(
        target: &OutboundTarget,
        timeout: Duration,
        dns: &mut DnsEngine<R>,
    ) -> io::Result<TcpStream> {
        let addresses = dns
            .resolve(&target.host, target.port)
            .map_err(|error| io::Error::new(io::ErrorKind::AddrNotAvailable, error))?
            .into_iter()
            .map(|address| SocketAddr::new(address.ip, address.port));
        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect_timeout(&address, timeout) {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    return Ok(stream);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no address resolved for {}:{}", target.host, target.port),
            )
        }))
    }
}

#[derive(Debug, Clone, Default)]
pub struct OutboundRegistry {
    direct_tags: HashSet<String>,
    trojan_tcp_tags: HashMap<String, TrojanTcpOutbound>,
    trojan_tls_tcp_tags: HashMap<String, TrojanTlsTcpOutbound>,
    trojan_ws_tags: HashMap<String, TrojanWsOutbound>,
    trojan_tls_ws_tags: HashMap<String, TrojanTlsWsOutbound>,
    vless_tcp_tags: HashMap<String, VlessTcpOutbound>,
    vless_tls_tcp_tags: HashMap<String, VlessTlsTcpOutbound>,
    vless_ws_tags: HashMap<String, VlessWsOutbound>,
    vless_tls_ws_tags: HashMap<String, VlessTlsWsOutbound>,
}

impl OutboundRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_profiles(
        profiles: impl IntoIterator<Item = OutboundProfile>,
    ) -> Result<Self, OutboundProfileError> {
        let mut registry = Self::new();
        for profile in profiles {
            registry.add_profile(profile)?;
        }
        Ok(registry)
    }

    pub fn add_profile(&mut self, profile: OutboundProfile) -> Result<(), OutboundProfileError> {
        profile
            .validate()
            .map_err(|source| OutboundProfileError::Validation {
                tag: profile.tag.clone(),
                source,
            })?;

        let OutboundProfile {
            tag,
            protocol,
            endpoint,
            transport,
            security,
            credential,
        } = profile;
        match (protocol, transport, security) {
            (ProxyProtocol::Trojan, TransportKind::Tcp, SecurityKind::None) => {
                self.add_trojan_tcp(tag, TrojanTcpOutbound::new(endpoint, credential));
                Ok(())
            }
            (ProxyProtocol::Trojan, TransportKind::Tcp, SecurityKind::Tls { sni, skip_verify }) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                self.add_trojan_tls_tcp(
                    tag,
                    TrojanTlsTcpOutbound::new(endpoint, credential, sni, skip_verify),
                );
                Ok(())
            }
            (
                ProxyProtocol::Trojan,
                TransportKind::WebSocket { path, host },
                SecurityKind::None,
            ) => {
                let host = host.unwrap_or_else(|| endpoint.host.clone());
                self.add_trojan_ws(tag, TrojanWsOutbound::new(endpoint, host, path, credential));
                Ok(())
            }
            (
                ProxyProtocol::Trojan,
                TransportKind::WebSocket { path, host },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let host = host.unwrap_or_else(|| endpoint.host.clone());
                let sni = sni.unwrap_or_else(|| host.clone());
                self.add_trojan_tls_ws(
                    tag,
                    TrojanTlsWsOutbound::new(endpoint, host, path, credential, sni, skip_verify),
                );
                Ok(())
            }
            (ProxyProtocol::Vless, TransportKind::Tcp, SecurityKind::None) => {
                self.add_vless_tcp(tag, VlessTcpOutbound::new(endpoint, credential, None));
                Ok(())
            }
            (ProxyProtocol::Vless, TransportKind::Tcp, SecurityKind::Tls { sni, skip_verify }) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                self.add_vless_tls_tcp(
                    tag,
                    VlessTlsTcpOutbound::new(endpoint, credential, None, sni, skip_verify),
                );
                Ok(())
            }
            (ProxyProtocol::Vless, TransportKind::WebSocket { path, host }, SecurityKind::None) => {
                let host = host.unwrap_or_else(|| endpoint.host.clone());
                self.add_vless_ws(
                    tag,
                    VlessWsOutbound::new(endpoint, host, path, credential, None),
                );
                Ok(())
            }
            (
                ProxyProtocol::Vless,
                TransportKind::WebSocket { path, host },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let host = host.unwrap_or_else(|| endpoint.host.clone());
                let sni = sni.unwrap_or_else(|| host.clone());
                self.add_vless_tls_ws(
                    tag,
                    VlessTlsWsOutbound::new(
                        endpoint,
                        host,
                        path,
                        credential,
                        None,
                        sni,
                        skip_verify,
                    ),
                );
                Ok(())
            }
            (protocol, transport, security) => Err(OutboundProfileError::UnsupportedTransport {
                tag,
                protocol,
                transport,
                security,
            }),
        }
    }

    pub fn add_direct(&mut self, tag: impl Into<String>) {
        self.direct_tags.insert(tag.into());
    }

    pub fn add_trojan_tcp(&mut self, tag: impl Into<String>, outbound: TrojanTcpOutbound) {
        self.trojan_tcp_tags.insert(tag.into(), outbound);
    }

    pub fn add_trojan_tls_tcp(&mut self, tag: impl Into<String>, outbound: TrojanTlsTcpOutbound) {
        self.trojan_tls_tcp_tags.insert(tag.into(), outbound);
    }

    pub fn add_trojan_ws(&mut self, tag: impl Into<String>, outbound: TrojanWsOutbound) {
        self.trojan_ws_tags.insert(tag.into(), outbound);
    }

    pub fn add_trojan_tls_ws(&mut self, tag: impl Into<String>, outbound: TrojanTlsWsOutbound) {
        self.trojan_tls_ws_tags.insert(tag.into(), outbound);
    }

    pub fn add_vless_tcp(&mut self, tag: impl Into<String>, outbound: VlessTcpOutbound) {
        self.vless_tcp_tags.insert(tag.into(), outbound);
    }

    pub fn add_vless_tls_tcp(&mut self, tag: impl Into<String>, outbound: VlessTlsTcpOutbound) {
        self.vless_tls_tcp_tags.insert(tag.into(), outbound);
    }

    pub fn add_vless_ws(&mut self, tag: impl Into<String>, outbound: VlessWsOutbound) {
        self.vless_ws_tags.insert(tag.into(), outbound);
    }

    pub fn add_vless_tls_ws(&mut self, tag: impl Into<String>, outbound: VlessTlsWsOutbound) {
        self.vless_tls_ws_tags.insert(tag.into(), outbound);
    }

    pub fn connect(
        &self,
        tag: &str,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        if self.direct_tags.contains(tag) {
            DirectTcpConnector::connect(target, timeout).map(OutboundConnection::Tcp)
        } else if let Some(outbound) = self.trojan_tcp_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.trojan_tls_tcp_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.trojan_ws_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.trojan_tls_ws_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_tcp_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_tls_tcp_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_ws_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_tls_ws_tags.get(tag) {
            outbound.connect(target, timeout)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound tag is not registered: {tag}"),
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundProfileError {
    Validation {
        tag: String,
        source: ProtocolValidationError,
    },
    UnsupportedSecurity {
        tag: String,
        security: SecurityKind,
    },
    UnsupportedTransport {
        tag: String,
        protocol: ProxyProtocol,
        transport: TransportKind,
        security: SecurityKind,
    },
}

impl std::fmt::Display for OutboundProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation { tag, source } => {
                write!(f, "outbound profile {tag} is invalid: {source}")
            }
            Self::UnsupportedSecurity { tag, security } => {
                write!(
                    f,
                    "outbound profile {tag} security is unsupported: {security:?}"
                )
            }
            Self::UnsupportedTransport {
                tag,
                protocol,
                transport,
                security,
            } => write!(
                f,
                "outbound profile {tag} transport is unsupported: {protocol:?}/{transport:?}/{security:?}"
            ),
        }
    }
}

impl std::error::Error for OutboundProfileError {}

pub enum OutboundConnection {
    Tcp(TcpStream),
    WebSocket(crate::WebSocketClientStream),
    Owned(Box<dyn OwnedRelayStream>),
}

impl std::fmt::Debug for OutboundConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(_) => f.write_str("OutboundConnection::Tcp"),
            Self::WebSocket(_) => f.write_str("OutboundConnection::WebSocket"),
            Self::Owned(_) => f.write_str("OutboundConnection::Owned"),
        }
    }
}

impl OutboundConnection {
    pub fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Tcp(stream) => stream.try_clone().map(Self::Tcp),
            Self::WebSocket(stream) => stream.try_clone().map(Self::WebSocket),
            Self::Owned(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "owned outbound connection cannot be cloned",
            )),
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_read_timeout(timeout),
            Self::WebSocket(stream) => stream.set_read_timeout(timeout),
            Self::Owned(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "owned outbound connection does not expose read timeout",
            )),
        }
    }

    pub fn shutdown_write(&self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.shutdown(Shutdown::Write),
            Self::WebSocket(stream) => stream.shutdown_write(),
            Self::Owned(_) => Ok(()),
        }
    }

    pub fn shutdown_both(&self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.shutdown(Shutdown::Both),
            Self::WebSocket(stream) => stream.shutdown_both(),
            Self::Owned(_) => Ok(()),
        }
    }
}

impl Read for OutboundConnection {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buffer),
            Self::WebSocket(stream) => stream.read(buffer),
            Self::Owned(stream) => stream.read(buffer),
        }
    }
}

impl Write for OutboundConnection {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buffer),
            Self::WebSocket(stream) => stream.write(buffer),
            Self::Owned(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            Self::WebSocket(stream) => stream.flush(),
            Self::Owned(stream) => stream.flush(),
        }
    }
}

#[derive(Debug)]
pub struct TlsTcpStream {
    inner: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
}

impl TlsTcpStream {
    pub fn connect(stream: TcpStream, server_name: &str, skip_verify: bool) -> io::Result<Self> {
        let config = tls_client_config(skip_verify)?;
        let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let connection = rustls::ClientConnection::new(config, server_name)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self {
            inner: rustls::StreamOwned::new(connection, stream),
        })
    }
}

impl Read for TlsTcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl Write for TlsTcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl OwnedRelayStream for TlsTcpStream {
    fn set_nonblocking_mode(&mut self, nonblocking: bool) -> io::Result<()> {
        self.inner.sock.set_nonblocking(nonblocking)
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.sock.shutdown(Shutdown::Write)
    }

    fn shutdown_both(&mut self) -> io::Result<()> {
        self.inner.sock.shutdown(Shutdown::Both)
    }
}

fn tls_client_config(skip_verify: bool) -> io::Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let config = if skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(InsecureServerVerifier::new(provider))
            .with_no_client_auth()
    } else {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct InsecureServerVerifier(Arc<rustls::crypto::CryptoProvider>);

impl InsecureServerVerifier {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for InsecureServerVerifier {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessWsOutbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub uuid: String,
    pub flow: Option<String>,
}

impl VlessWsOutbound {
    pub fn new(
        server: Endpoint,
        host: impl Into<String>,
        path: impl Into<String>,
        uuid: impl Into<String>,
        flow: Option<String>,
    ) -> Self {
        Self {
            server,
            host: host.into(),
            path: path.into(),
            uuid: uuid.into(),
            flow,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let server = OutboundTarget::new(self.server.host.clone(), self.server.port);
        let stream = DirectTcpConnector::connect(&server, timeout)?;
        let mut stream = crate::WebSocketClientStream::connect(stream, &self.host, &self.path)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_vless_tcp_request_header(&self.uuid, &target, self.flow.as_deref())
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        read_vless_response_header_from_stream(&mut stream)?;
        Ok(OutboundConnection::WebSocket(stream))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessTlsWsOutbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub uuid: String,
    pub flow: Option<String>,
    pub sni: String,
    pub skip_verify: bool,
}

impl VlessTlsWsOutbound {
    pub fn new(
        server: Endpoint,
        host: impl Into<String>,
        path: impl Into<String>,
        uuid: impl Into<String>,
        flow: Option<String>,
        sni: impl Into<String>,
        skip_verify: bool,
    ) -> Self {
        Self {
            server,
            host: host.into(),
            path: path.into(),
            uuid: uuid.into(),
            flow,
            sni: sni.into(),
            skip_verify,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let server = OutboundTarget::new(self.server.host.clone(), self.server.port);
        let stream = DirectTcpConnector::connect(&server, timeout)?;
        let stream = TlsTcpStream::connect(stream, &self.sni, self.skip_verify)?;
        let mut stream =
            crate::OwnedWebSocketClientStream::connect(stream, &self.host, &self.path)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_vless_tcp_request_header(&self.uuid, &target, self.flow.as_deref())
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        read_vless_response_header_from_stream(&mut stream)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanTcpOutbound {
    pub server: Endpoint,
    pub password: String,
}

impl TrojanTcpOutbound {
    pub fn new(server: Endpoint, password: impl Into<String>) -> Self {
        Self {
            server,
            password: password.into(),
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let server = OutboundTarget::new(self.server.host.clone(), self.server.port);
        let mut stream = DirectTcpConnector::connect(&server, timeout)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_trojan_tcp_request_header(&self.password, &target)
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        Ok(OutboundConnection::Tcp(stream))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanTlsTcpOutbound {
    pub server: Endpoint,
    pub password: String,
    pub sni: String,
    pub skip_verify: bool,
}

impl TrojanTlsTcpOutbound {
    pub fn new(
        server: Endpoint,
        password: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
    ) -> Self {
        Self {
            server,
            password: password.into(),
            sni: sni.into(),
            skip_verify,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let server = OutboundTarget::new(self.server.host.clone(), self.server.port);
        let stream = DirectTcpConnector::connect(&server, timeout)?;
        let mut stream = TlsTcpStream::connect(stream, &self.sni, self.skip_verify)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_trojan_tcp_request_header(&self.password, &target)
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanWsOutbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub password: String,
}

impl TrojanWsOutbound {
    pub fn new(
        server: Endpoint,
        host: impl Into<String>,
        path: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            server,
            host: host.into(),
            path: path.into(),
            password: password.into(),
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let server = OutboundTarget::new(self.server.host.clone(), self.server.port);
        let stream = DirectTcpConnector::connect(&server, timeout)?;
        let mut stream = crate::WebSocketClientStream::connect(stream, &self.host, &self.path)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_trojan_tcp_request_header(&self.password, &target)
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        Ok(OutboundConnection::WebSocket(stream))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanTlsWsOutbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub password: String,
    pub sni: String,
    pub skip_verify: bool,
}

impl TrojanTlsWsOutbound {
    pub fn new(
        server: Endpoint,
        host: impl Into<String>,
        path: impl Into<String>,
        password: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
    ) -> Self {
        Self {
            server,
            host: host.into(),
            path: path.into(),
            password: password.into(),
            sni: sni.into(),
            skip_verify,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let server = OutboundTarget::new(self.server.host.clone(), self.server.port);
        let stream = DirectTcpConnector::connect(&server, timeout)?;
        let stream = TlsTcpStream::connect(stream, &self.sni, self.skip_verify)?;
        let mut stream =
            crate::OwnedWebSocketClientStream::connect(stream, &self.host, &self.path)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_trojan_tcp_request_header(&self.password, &target)
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessTcpOutbound {
    pub server: Endpoint,
    pub uuid: String,
    pub flow: Option<String>,
}

impl VlessTcpOutbound {
    pub fn new(server: Endpoint, uuid: impl Into<String>, flow: Option<String>) -> Self {
        Self {
            server,
            uuid: uuid.into(),
            flow,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let server = OutboundTarget::new(self.server.host.clone(), self.server.port);
        let mut stream = DirectTcpConnector::connect(&server, timeout)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_vless_tcp_request_header(&self.uuid, &target, self.flow.as_deref())
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        read_vless_response_header_from_stream(&mut stream)?;
        Ok(OutboundConnection::Tcp(stream))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessTlsTcpOutbound {
    pub server: Endpoint,
    pub uuid: String,
    pub flow: Option<String>,
    pub sni: String,
    pub skip_verify: bool,
}

impl VlessTlsTcpOutbound {
    pub fn new(
        server: Endpoint,
        uuid: impl Into<String>,
        flow: Option<String>,
        sni: impl Into<String>,
        skip_verify: bool,
    ) -> Self {
        Self {
            server,
            uuid: uuid.into(),
            flow,
            sni: sni.into(),
            skip_verify,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let server = OutboundTarget::new(self.server.host.clone(), self.server.port);
        let stream = DirectTcpConnector::connect(&server, timeout)?;
        let mut stream = TlsTcpStream::connect(stream, &self.sni, self.skip_verify)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_vless_tcp_request_header(&self.uuid, &target, self.flow.as_deref())
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        read_vless_response_header_from_stream(&mut stream)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

fn read_vless_response_header_from_stream(stream: &mut impl Read) -> io::Result<()> {
    let mut header = [0; 2];
    stream.read_exact(&mut header)?;
    if header[0] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid VLESS response version",
        ));
    }
    if header[1] > 0 {
        let mut addon = vec![0; usize::from(header[1])];
        stream.read_exact(&mut addon)?;
    }
    Ok(())
}

fn protocol_encoding_to_io(error: ProtocolEncodingError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayStats {
    pub client_to_remote_bytes: u64,
    pub remote_to_client_bytes: u64,
    pub remote_first_byte_after: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelayOptions {
    pub first_byte_timeout: Option<Duration>,
    pub idle_timeout: Option<Duration>,
}

#[derive(Debug)]
pub struct RelayError {
    pub kind: ConnectionErrorKind,
    pub source: io::Error,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.source)
    }
}

impl std::error::Error for RelayError {}

impl From<io::Error> for RelayError {
    fn from(source: io::Error) -> Self {
        Self {
            kind: ConnectionErrorKind::from_io(&source),
            source,
        }
    }
}

pub trait OwnedRelayStream: Read + Write + Send {
    fn set_nonblocking_mode(&mut self, nonblocking: bool) -> io::Result<()>;
    fn shutdown_write(&mut self) -> io::Result<()>;
    fn shutdown_both(&mut self) -> io::Result<()>;
}

impl OwnedRelayStream for TcpStream {
    fn set_nonblocking_mode(&mut self, nonblocking: bool) -> io::Result<()> {
        self.set_nonblocking(nonblocking)
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }

    fn shutdown_both(&mut self) -> io::Result<()> {
        self.shutdown(Shutdown::Both)
    }
}

impl OwnedRelayStream for OutboundConnection {
    fn set_nonblocking_mode(&mut self, nonblocking: bool) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_nonblocking(nonblocking),
            Self::WebSocket(stream) => stream.set_nonblocking_mode(nonblocking),
            Self::Owned(stream) => stream.set_nonblocking_mode(nonblocking),
        }
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.shutdown(Shutdown::Write),
            Self::WebSocket(stream) => stream.shutdown_write(),
            Self::Owned(stream) => stream.shutdown_write(),
        }
    }

    fn shutdown_both(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.shutdown(Shutdown::Both),
            Self::WebSocket(stream) => stream.shutdown_both(),
            Self::Owned(stream) => stream.shutdown_both(),
        }
    }
}

impl<S: OwnedRelayStream> OwnedRelayStream for crate::OwnedWebSocketClientStream<S> {
    fn set_nonblocking_mode(&mut self, nonblocking: bool) -> io::Result<()> {
        self.inner_mut().set_nonblocking_mode(nonblocking)
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner_mut().shutdown_write()
    }

    fn shutdown_both(&mut self) -> io::Result<()> {
        self.inner_mut().shutdown_both()
    }
}

pub fn relay_tcp_bidirectional(
    client: TcpStream,
    remote: TcpStream,
) -> Result<RelayStats, RelayError> {
    relay_tcp_bidirectional_with_options(client, remote, RelayOptions::default())
}

pub fn relay_tcp_bidirectional_with_options(
    client: TcpStream,
    remote: TcpStream,
    options: RelayOptions,
) -> Result<RelayStats, RelayError> {
    relay_outbound_bidirectional_with_options(client, OutboundConnection::Tcp(remote), options)
}

pub fn relay_owned_bidirectional_with_options<R: OwnedRelayStream>(
    mut client: TcpStream,
    mut remote: R,
    options: RelayOptions,
) -> Result<RelayStats, RelayError> {
    client.set_nonblocking(true)?;
    remote.set_nonblocking_mode(true)?;

    let started = Instant::now();
    let mut upload = PendingWrite::new();
    let mut download = PendingWrite::new();
    let mut upload_buffer = [0; 16 * 1024];
    let mut download_buffer = [0; 16 * 1024];
    let mut client_eof = false;
    let mut remote_eof = false;
    let mut remote_write_shutdown = false;
    let mut client_to_remote_bytes = 0;
    let mut remote_to_client_bytes = 0;
    let mut remote_first_byte_after = None;
    let mut last_remote_byte_at = started;

    loop {
        let mut progressed = false;

        match pump_read(&mut client, &mut upload, &mut upload_buffer, client_eof)? {
            PumpRead::Bytes(bytes) => {
                client_to_remote_bytes += bytes as u64;
                progressed = true;
            }
            PumpRead::Eof => {
                client_eof = true;
                progressed = true;
            }
            PumpRead::NoProgress => {}
        }

        match pump_read(&mut remote, &mut download, &mut download_buffer, remote_eof)? {
            PumpRead::Bytes(bytes) => {
                if remote_first_byte_after.is_none() {
                    remote_first_byte_after = Some(started.elapsed());
                }
                remote_to_client_bytes += bytes as u64;
                last_remote_byte_at = Instant::now();
                progressed = true;
            }
            PumpRead::Eof => {
                remote_eof = true;
                progressed = true;
            }
            PumpRead::NoProgress => {}
        }

        if pump_write(&mut remote, &mut upload)? {
            progressed = true;
        }
        if pump_write(&mut client, &mut download)? {
            progressed = true;
        }

        if client_eof && upload.is_empty() && !remote_write_shutdown {
            remote.shutdown_write().ok();
            remote_write_shutdown = true;
        }
        if remote_eof && download.is_empty() {
            client.shutdown(Shutdown::Write).ok();
            break;
        }

        if remote_first_byte_after.is_none() {
            if let Some(timeout) = options.first_byte_timeout {
                if started.elapsed() >= timeout {
                    client.shutdown(Shutdown::Both).ok();
                    remote.shutdown_both().ok();
                    return Err(relay_timeout_error(
                        ConnectionErrorKind::FirstByteTimeout,
                        "timed out waiting for remote first byte",
                    ));
                }
            }
        } else if let Some(timeout) = options.idle_timeout {
            if last_remote_byte_at.elapsed() >= timeout {
                client.shutdown(Shutdown::Both).ok();
                remote.shutdown_both().ok();
                return Err(relay_timeout_error(
                    ConnectionErrorKind::IdleTimeout,
                    "remote stream became idle",
                ));
            }
        }

        if !progressed {
            thread::sleep(Duration::from_millis(1));
        }
    }

    remote.shutdown_both().ok();
    client.shutdown(Shutdown::Both).ok();

    Ok(RelayStats {
        client_to_remote_bytes,
        remote_to_client_bytes,
        remote_first_byte_after,
    })
}

pub fn relay_outbound_bidirectional_with_options(
    client: TcpStream,
    remote: OutboundConnection,
    options: RelayOptions,
) -> Result<RelayStats, RelayError> {
    let started = Instant::now();
    let unblock_client = client.try_clone()?;
    let unblock_remote = remote.try_clone()?;
    let mut client_reader = client.try_clone()?;
    let mut client_writer = client;
    let remote_reader = remote.try_clone()?;
    let mut remote_writer = remote;

    let upload = thread::spawn(move || {
        let result = io::copy(&mut client_reader, &mut remote_writer);
        remote_writer.shutdown_write().ok();
        result
    });
    let download = thread::spawn(move || {
        let result = copy_remote_with_timeouts(
            remote_reader,
            &mut client_writer,
            started,
            options.first_byte_timeout,
            options.idle_timeout,
        );
        client_writer.shutdown(Shutdown::Write).ok();
        result
    });

    let download_result = join_download(download);
    if download_result.is_err() {
        unblock_client.shutdown(Shutdown::Both).ok();
        unblock_remote.shutdown_both().ok();
    }
    let (remote_to_client_bytes, remote_first_byte_after) = download_result?;
    let client_to_remote_bytes = join_copy(upload)?;

    Ok(RelayStats {
        client_to_remote_bytes,
        remote_to_client_bytes,
        remote_first_byte_after,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PumpRead {
    Bytes(usize),
    Eof,
    NoProgress,
}

#[derive(Debug, Default)]
struct PendingWrite {
    bytes: Vec<u8>,
    offset: usize,
}

impl PendingWrite {
    fn new() -> Self {
        Self::default()
    }

    fn is_empty(&self) -> bool {
        self.offset >= self.bytes.len()
    }

    fn set(&mut self, bytes: &[u8]) {
        self.bytes.clear();
        self.bytes.extend_from_slice(bytes);
        self.offset = 0;
    }

    fn remaining(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }

    fn advance(&mut self, bytes: usize) {
        self.offset += bytes;
        if self.is_empty() {
            self.bytes.clear();
            self.offset = 0;
        }
    }
}

fn pump_read(
    reader: &mut impl Read,
    pending: &mut PendingWrite,
    buffer: &mut [u8],
    eof: bool,
) -> Result<PumpRead, RelayError> {
    if eof || !pending.is_empty() {
        return Ok(PumpRead::NoProgress);
    }

    match reader.read(buffer) {
        Ok(0) => Ok(PumpRead::Eof),
        Ok(bytes) => {
            pending.set(&buffer[..bytes]);
            Ok(PumpRead::Bytes(bytes))
        }
        Err(error) if is_nonblocking_pause(&error) => Ok(PumpRead::NoProgress),
        Err(error) => Err(RelayError::from(error)),
    }
}

fn pump_write(writer: &mut impl Write, pending: &mut PendingWrite) -> Result<bool, RelayError> {
    let mut progressed = false;
    while !pending.is_empty() {
        match writer.write(pending.remaining()) {
            Ok(0) => {
                return Err(RelayError::from(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "relay writer returned zero bytes",
                )));
            }
            Ok(bytes) => {
                pending.advance(bytes);
                progressed = true;
            }
            Err(error) if is_nonblocking_pause(&error) => return Ok(progressed),
            Err(error) => return Err(RelayError::from(error)),
        }
    }
    Ok(progressed)
}

fn is_nonblocking_pause(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
        || error.kind() == io::ErrorKind::TimedOut
        || error.kind() == io::ErrorKind::Interrupted
}

fn relay_timeout_error(kind: ConnectionErrorKind, message: &'static str) -> RelayError {
    RelayError {
        kind,
        source: io::Error::new(io::ErrorKind::TimedOut, message),
    }
}

fn join_copy(handle: thread::JoinHandle<io::Result<u64>>) -> io::Result<u64> {
    handle
        .join()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "relay worker panicked"))?
}

fn join_download(
    handle: thread::JoinHandle<Result<(u64, Option<Duration>), RelayError>>,
) -> Result<(u64, Option<Duration>), RelayError> {
    handle.join().map_err(|_| RelayError {
        kind: ConnectionErrorKind::RelayIo,
        source: io::Error::new(io::ErrorKind::Other, "relay worker panicked"),
    })?
}

fn copy_remote_with_timeouts(
    reader: OutboundConnection,
    writer: &mut impl Write,
    started: Instant,
    first_byte_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
) -> Result<(u64, Option<Duration>), RelayError> {
    reader.set_read_timeout(first_byte_timeout)?;
    let mut reader = reader;
    let mut buffer = [0; 16 * 1024];
    let mut total = 0;
    let mut first_byte_after = None;

    loop {
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(error) => {
                return Err(classify_download_timeout(
                    error,
                    first_byte_after.is_some(),
                    first_byte_timeout.is_some(),
                    idle_timeout.is_some(),
                ));
            }
        };
        if read == 0 {
            return Ok((total, first_byte_after));
        }
        if first_byte_after.is_none() {
            first_byte_after = Some(started.elapsed());
            reader.set_read_timeout(idle_timeout)?;
        }
        writer.write_all(&buffer[..read])?;
        total += read as u64;
    }
}

fn classify_download_timeout(
    source: io::Error,
    first_byte_seen: bool,
    first_byte_timeout_enabled: bool,
    idle_timeout_enabled: bool,
) -> RelayError {
    if !is_timeout_error(&source) {
        return RelayError::from(source);
    }

    if !first_byte_seen && first_byte_timeout_enabled {
        RelayError {
            kind: ConnectionErrorKind::FirstByteTimeout,
            source,
        }
    } else if first_byte_seen && idle_timeout_enabled {
        RelayError {
            kind: ConnectionErrorKind::IdleTimeout,
            source,
        }
    } else {
        RelayError::from(source)
    }
}

fn is_timeout_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock || error.kind() == io::ErrorKind::TimedOut
}
