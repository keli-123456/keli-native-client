use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use sha2::{Digest, Sha224};

const VLESS_VERSION: u8 = 0x00;
const VLESS_COMMAND_TCP: u8 = 0x01;
const VLESS_ATYP_IPV4: u8 = 0x01;
const VLESS_ATYP_DOMAIN: u8 = 0x02;
const VLESS_ATYP_IPV6: u8 = 0x03;
const TROJAN_COMMAND_CONNECT: u8 = 0x01;
const TROJAN_ATYP_IPV4: u8 = 0x01;
const TROJAN_ATYP_DOMAIN: u8 = 0x03;
const TROJAN_ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyProtocol {
    Trojan,
    Vless,
    Hy2,
    Shadowsocks,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportKind {
    Tcp,
    WebSocket { path: String, host: Option<String> },
    Quic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityKind {
    None,
    Tls {
        sni: Option<String>,
        skip_verify: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundProfile {
    pub tag: String,
    pub protocol: ProxyProtocol,
    pub endpoint: Endpoint,
    pub transport: TransportKind,
    pub security: SecurityKind,
    pub credential: String,
}

impl OutboundProfile {
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.tag.trim().is_empty() {
            return Err(ProtocolValidationError::MissingTag);
        }
        if self.endpoint.host.trim().is_empty() {
            return Err(ProtocolValidationError::MissingServer);
        }
        if self.credential.trim().is_empty() {
            return Err(ProtocolValidationError::MissingCredential {
                protocol: self.protocol.clone(),
            });
        }
        match (&self.protocol, &self.transport, &self.security) {
            (
                ProxyProtocol::Trojan,
                TransportKind::WebSocket { path, .. },
                SecurityKind::Tls { .. },
            ) if path.starts_with('/') => Ok(()),
            (ProxyProtocol::Trojan, TransportKind::WebSocket { .. }, SecurityKind::Tls { .. }) => {
                Err(ProtocolValidationError::InvalidWebSocketPath)
            }
            (ProxyProtocol::Trojan, _, SecurityKind::Tls { .. }) => Ok(()),
            (ProxyProtocol::Trojan, _, SecurityKind::None) => {
                Err(ProtocolValidationError::MissingTls)
            }
            (ProxyProtocol::Vless, _, _) if !looks_like_uuid(&self.credential) => {
                Err(ProtocolValidationError::InvalidUuid)
            }
            (ProxyProtocol::Vless, _, _) => Ok(()),
            (ProxyProtocol::Hy2, TransportKind::Quic, SecurityKind::Tls { .. }) => Ok(()),
            (ProxyProtocol::Hy2, _, _) => Err(ProtocolValidationError::InvalidHy2Transport),
            (ProxyProtocol::Shadowsocks, _, _) => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolValidationError {
    MissingTag,
    MissingServer,
    MissingCredential { protocol: ProxyProtocol },
    MissingTls,
    InvalidUuid,
    InvalidWebSocketPath,
    InvalidHy2Transport,
}

impl fmt::Display for ProtocolValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTag => write!(f, "outbound tag is empty"),
            Self::MissingServer => write!(f, "server host is empty"),
            Self::MissingCredential { protocol } => {
                write!(f, "{protocol:?} credential is empty")
            }
            Self::MissingTls => write!(f, "TLS is required for this profile"),
            Self::InvalidUuid => write!(f, "VLESS credential must be a UUID"),
            Self::InvalidWebSocketPath => write!(f, "WebSocket path must start with '/'"),
            Self::InvalidHy2Transport => write!(f, "HY2 requires QUIC transport with TLS"),
        }
    }
}

impl std::error::Error for ProtocolValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolEncodingError {
    InvalidUuid,
    InvalidPassword,
    InvalidTargetHost,
    FlowTooLong,
}

impl fmt::Display for ProtocolEncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUuid => write!(f, "VLESS credential must be a UUID"),
            Self::InvalidPassword => write!(f, "Trojan password is empty"),
            Self::InvalidTargetHost => write!(f, "VLESS target host is invalid"),
            Self::FlowTooLong => write!(f, "VLESS flow is too long"),
        }
    }
}

impl std::error::Error for ProtocolEncodingError {}

pub fn encode_vless_tcp_request_header(
    uuid: &str,
    target: &Endpoint,
    flow: Option<&str>,
) -> Result<Vec<u8>, ProtocolEncodingError> {
    let user_id = parse_uuid_bytes(uuid)?;
    let mut header = Vec::with_capacity(32 + target.host.len());
    header.push(VLESS_VERSION);
    header.extend_from_slice(&user_id);
    encode_vless_addon(&mut header, flow.unwrap_or(""))?;
    header.push(VLESS_COMMAND_TCP);
    encode_vless_target(&mut header, target)?;
    Ok(header)
}

pub fn encode_trojan_tcp_request_header(
    password: &str,
    target: &Endpoint,
) -> Result<Vec<u8>, ProtocolEncodingError> {
    if password.is_empty() {
        return Err(ProtocolEncodingError::InvalidPassword);
    }
    let mut header = Vec::with_capacity(80 + target.host.len());
    encode_trojan_password_hash(&mut header, password);
    header.extend_from_slice(b"\r\n");
    header.push(TROJAN_COMMAND_CONNECT);
    encode_trojan_target(&mut header, target)?;
    header.extend_from_slice(b"\r\n");
    Ok(header)
}

fn looks_like_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        match index {
            8 | 13 | 18 | 23 => {
                if *byte != b'-' {
                    return false;
                }
            }
            _ if !byte.is_ascii_hexdigit() => return false,
            _ => {}
        }
    }
    true
}

fn encode_trojan_password_hash(output: &mut Vec<u8>, password: &str) {
    let digest = Sha224::digest(password.as_bytes());
    for byte in digest {
        push_lower_hex(output, byte);
    }
}

fn push_lower_hex(output: &mut Vec<u8>, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.push(HEX[usize::from(byte >> 4)]);
    output.push(HEX[usize::from(byte & 0x0f)]);
}

fn parse_uuid_bytes(value: &str) -> Result<[u8; 16], ProtocolEncodingError> {
    if !looks_like_uuid(value) {
        return Err(ProtocolEncodingError::InvalidUuid);
    }
    let compact: Vec<u8> = value.bytes().filter(|byte| *byte != b'-').collect();
    let mut output = [0; 16];
    for (index, chunk) in compact.chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Ok(output)
}

fn encode_trojan_target(
    output: &mut Vec<u8>,
    target: &Endpoint,
) -> Result<(), ProtocolEncodingError> {
    let host = target.host.trim().trim_matches(['[', ']']);
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        output.push(TROJAN_ATYP_IPV4);
        output.extend_from_slice(&ip.octets());
        output.extend_from_slice(&target.port.to_be_bytes());
        return Ok(());
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        output.push(TROJAN_ATYP_IPV6);
        output.extend_from_slice(&ip.octets());
        output.extend_from_slice(&target.port.to_be_bytes());
        return Ok(());
    }
    if host.is_empty() || host.len() > u8::MAX as usize {
        return Err(ProtocolEncodingError::InvalidTargetHost);
    }
    output.push(TROJAN_ATYP_DOMAIN);
    output.push(host.len() as u8);
    output.extend_from_slice(host.as_bytes());
    output.extend_from_slice(&target.port.to_be_bytes());
    Ok(())
}

fn hex_nibble(byte: u8) -> Result<u8, ProtocolEncodingError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ProtocolEncodingError::InvalidUuid),
    }
}

fn encode_vless_addon(output: &mut Vec<u8>, flow: &str) -> Result<(), ProtocolEncodingError> {
    let flow = flow.trim();
    if flow.is_empty() {
        output.push(0);
        return Ok(());
    }
    if flow.len() > u8::MAX as usize - 2 {
        return Err(ProtocolEncodingError::FlowTooLong);
    }
    output.push((2 + flow.len()) as u8);
    output.push(0x0a);
    output.push(flow.len() as u8);
    output.extend_from_slice(flow.as_bytes());
    Ok(())
}

fn encode_vless_target(
    output: &mut Vec<u8>,
    target: &Endpoint,
) -> Result<(), ProtocolEncodingError> {
    output.extend_from_slice(&target.port.to_be_bytes());
    let host = target.host.trim().trim_matches(['[', ']']);
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        output.push(VLESS_ATYP_IPV4);
        output.extend_from_slice(&ip.octets());
        return Ok(());
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        output.push(VLESS_ATYP_IPV6);
        output.extend_from_slice(&ip.octets());
        return Ok(());
    }
    if host.is_empty() || host.len() > u8::MAX as usize {
        return Err(ProtocolEncodingError::InvalidTargetHost);
    }
    output.push(VLESS_ATYP_DOMAIN);
    output.push(host.len() as u8);
    output.extend_from_slice(host.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls() -> SecurityKind {
        SecurityKind::Tls {
            sni: Some("example.com".to_string()),
            skip_verify: false,
        }
    }

    #[test]
    fn trojan_ws_requires_absolute_path() {
        let profile = OutboundProfile {
            tag: "trojan".to_string(),
            protocol: ProxyProtocol::Trojan,
            endpoint: Endpoint::new("example.com", 443),
            transport: TransportKind::WebSocket {
                path: "answer".to_string(),
                host: None,
            },
            security: tls(),
            credential: "password".to_string(),
        };

        assert_eq!(
            profile.validate(),
            Err(ProtocolValidationError::InvalidWebSocketPath)
        );
    }

    #[test]
    fn vless_requires_uuid_credential() {
        let profile = OutboundProfile {
            tag: "vless".to_string(),
            protocol: ProxyProtocol::Vless,
            endpoint: Endpoint::new("example.com", 443),
            transport: TransportKind::Tcp,
            security: tls(),
            credential: "not-a-uuid".to_string(),
        };

        assert_eq!(
            profile.validate(),
            Err(ProtocolValidationError::InvalidUuid)
        );
    }

    #[test]
    fn hy2_requires_quic_transport() {
        let profile = OutboundProfile {
            tag: "hy2".to_string(),
            protocol: ProxyProtocol::Hy2,
            endpoint: Endpoint::new("example.com", 443),
            transport: TransportKind::Tcp,
            security: tls(),
            credential: "auth".to_string(),
        };

        assert_eq!(
            profile.validate(),
            Err(ProtocolValidationError::InvalidHy2Transport)
        );
    }

    #[test]
    fn encodes_vless_tcp_request_header_for_domain_target() {
        let header = encode_vless_tcp_request_header(
            "00112233-4455-6677-8899-aabbccddeeff",
            &Endpoint::new("example.com", 443),
            None,
        )
        .expect("vless header");

        assert_eq!(
            header,
            [
                0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                0xdd, 0xee, 0xff, 0x00, 0x01, 0x01, 0xbb, 0x02, 0x0b, b'e', b'x', b'a', b'm', b'p',
                b'l', b'e', b'.', b'c', b'o', b'm',
            ]
        );
    }

    #[test]
    fn encodes_vless_tcp_request_header_for_ipv4_target() {
        let header = encode_vless_tcp_request_header(
            "00112233-4455-6677-8899-aabbccddeeff",
            &Endpoint::new("1.2.3.4", 80),
            None,
        )
        .expect("vless header");

        assert_eq!(&header[18..], &[0x01, 0x00, 0x50, 0x01, 1, 2, 3, 4]);
    }

    #[test]
    fn encodes_vless_flow_as_addon() {
        let header = encode_vless_tcp_request_header(
            "00112233-4455-6677-8899-aabbccddeeff",
            &Endpoint::new("example.com", 443),
            Some("xtls-rprx-vision"),
        )
        .expect("vless header");

        assert_eq!(&header[17..37], b"\x12\x0a\x10xtls-rprx-vision\x01");
    }

    #[test]
    fn encodes_trojan_tcp_request_header_for_domain_target() {
        let header =
            encode_trojan_tcp_request_header("password", &Endpoint::new("example.com", 443))
                .expect("trojan header");

        assert_eq!(
            &header[..56],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
        assert_eq!(&header[56..], b"\r\n\x01\x03\x0bexample.com\x01\xbb\r\n");
    }

    #[test]
    fn encodes_trojan_tcp_request_header_for_ipv6_target() {
        let header = encode_trojan_tcp_request_header("password", &Endpoint::new("[::1]", 443))
            .expect("trojan header");

        assert_eq!(header[58], 0x01);
        assert_eq!(header[59], 0x04);
        assert_eq!(
            &header[60..76],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(&header[76..], b"\x01\xbb\r\n");
    }
}
