use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use crate::{
    ConnectionErrorKind, DnsCache, DnsEngine, DnsResolver, RouteTarget, Socks5Address,
    Socks5Request, SystemDnsResolver,
};
use keli_protocol::{
    encode_trojan_tcp_request_header, encode_vless_tcp_request_header, Endpoint,
    ProtocolEncodingError,
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
    trojan_ws_tags: HashMap<String, TrojanWsOutbound>,
    vless_tcp_tags: HashMap<String, VlessTcpOutbound>,
    vless_ws_tags: HashMap<String, VlessWsOutbound>,
}

impl OutboundRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_direct(&mut self, tag: impl Into<String>) {
        self.direct_tags.insert(tag.into());
    }

    pub fn add_trojan_tcp(&mut self, tag: impl Into<String>, outbound: TrojanTcpOutbound) {
        self.trojan_tcp_tags.insert(tag.into(), outbound);
    }

    pub fn add_trojan_ws(&mut self, tag: impl Into<String>, outbound: TrojanWsOutbound) {
        self.trojan_ws_tags.insert(tag.into(), outbound);
    }

    pub fn add_vless_tcp(&mut self, tag: impl Into<String>, outbound: VlessTcpOutbound) {
        self.vless_tcp_tags.insert(tag.into(), outbound);
    }

    pub fn add_vless_ws(&mut self, tag: impl Into<String>, outbound: VlessWsOutbound) {
        self.vless_ws_tags.insert(tag.into(), outbound);
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
        } else if let Some(outbound) = self.trojan_ws_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_tcp_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_ws_tags.get(tag) {
            outbound.connect(target, timeout)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound tag is not registered: {tag}"),
            ))
        }
    }
}

#[derive(Debug)]
pub enum OutboundConnection {
    Tcp(TcpStream),
    WebSocket(crate::WebSocketClientStream),
}

impl OutboundConnection {
    pub fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Tcp(stream) => stream.try_clone().map(Self::Tcp),
            Self::WebSocket(stream) => stream.try_clone().map(Self::WebSocket),
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_read_timeout(timeout),
            Self::WebSocket(stream) => stream.set_read_timeout(timeout),
        }
    }

    pub fn shutdown_write(&self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.shutdown(Shutdown::Write),
            Self::WebSocket(stream) => stream.shutdown_write(),
        }
    }

    pub fn shutdown_both(&self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.shutdown(Shutdown::Both),
            Self::WebSocket(stream) => stream.shutdown_both(),
        }
    }
}

impl Read for OutboundConnection {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buffer),
            Self::WebSocket(stream) => stream.read(buffer),
        }
    }
}

impl Write for OutboundConnection {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buffer),
            Self::WebSocket(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            Self::WebSocket(stream) => stream.flush(),
        }
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
