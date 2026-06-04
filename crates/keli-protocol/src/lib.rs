use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::Deserialize;
use sha2::{Digest, Sha224};
use url::Url;

const VLESS_VERSION: u8 = 0x00;
const VLESS_COMMAND_TCP: u8 = 0x01;
const VLESS_COMMAND_UDP: u8 = 0x02;
const VLESS_ATYP_IPV4: u8 = 0x01;
const VLESS_ATYP_DOMAIN: u8 = 0x02;
const VLESS_ATYP_IPV6: u8 = 0x03;
const TROJAN_COMMAND_CONNECT: u8 = 0x01;
const TROJAN_COMMAND_UDP_ASSOCIATE: u8 = 0x03;
const TROJAN_ATYP_IPV4: u8 = 0x01;
const TROJAN_ATYP_DOMAIN: u8 = 0x03;
const TROJAN_ATYP_IPV6: u8 = 0x04;
const SHADOWSOCKS_ATYP_IPV4: u8 = 0x01;
const SHADOWSOCKS_ATYP_DOMAIN: u8 = 0x03;
const SHADOWSOCKS_ATYP_IPV6: u8 = 0x04;
const TUIC_VERSION: u8 = 0x05;
const TUIC_COMMAND_AUTHENTICATE: u8 = 0x00;
const TUIC_COMMAND_CONNECT: u8 = 0x01;
const TUIC_COMMAND_PACKET: u8 = 0x02;
const TUIC_COMMAND_HEARTBEAT: u8 = 0x04;
const TUIC_ATYP_NONE: u8 = 0xff;
const TUIC_ATYP_DOMAIN: u8 = 0x00;
const TUIC_ATYP_IPV4: u8 = 0x01;
const TUIC_ATYP_IPV6: u8 = 0x02;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyProtocol {
    Trojan,
    Vmess,
    Vless,
    Naive,
    Mieru,
    Hy2,
    Shadowsocks,
    AnyTls,
    Tuic,
    Socks,
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportKind {
    Tcp,
    WebSocket {
        path: String,
        host: Option<String>,
    },
    HttpUpgrade {
        path: String,
        host: Option<String>,
    },
    Http2 {
        path: String,
        host: Option<String>,
    },
    Grpc {
        service_name: Option<String>,
    },
    Quic {
        security: Option<String>,
        key: Option<String>,
        header_type: Option<String>,
    },
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
    pub cipher: Option<String>,
    pub flow: Option<String>,
}

impl OutboundProfile {
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.tag.trim().is_empty() {
            return Err(ProtocolValidationError::MissingTag);
        }
        if self.endpoint.host.trim().is_empty() {
            return Err(ProtocolValidationError::MissingServer);
        }
        if self.credential.trim().is_empty()
            && !matches!(self.protocol, ProxyProtocol::Socks | ProxyProtocol::Http)
        {
            return Err(ProtocolValidationError::MissingCredential {
                protocol: self.protocol.clone(),
            });
        }
        match (&self.protocol, &self.transport, &self.security) {
            (
                ProxyProtocol::Trojan,
                TransportKind::WebSocket { path, .. },
                SecurityKind::None | SecurityKind::Tls { .. },
            ) if path.starts_with('/') => Ok(()),
            (ProxyProtocol::Trojan, TransportKind::WebSocket { .. }, _) => {
                Err(ProtocolValidationError::InvalidWebSocketPath)
            }
            (
                ProxyProtocol::Trojan,
                TransportKind::HttpUpgrade { path, .. },
                SecurityKind::None | SecurityKind::Tls { .. },
            ) if path.starts_with('/') => Ok(()),
            (ProxyProtocol::Trojan, TransportKind::HttpUpgrade { .. }, _) => {
                Err(ProtocolValidationError::InvalidHttpUpgradePath)
            }
            (
                ProxyProtocol::Trojan,
                TransportKind::Http2 { path, .. },
                SecurityKind::None | SecurityKind::Tls { .. },
            ) if path.starts_with('/') => Ok(()),
            (ProxyProtocol::Trojan, TransportKind::Http2 { .. }, _) => {
                Err(ProtocolValidationError::InvalidHttp2Path)
            }
            (
                ProxyProtocol::Trojan,
                TransportKind::Quic { .. },
                SecurityKind::None | SecurityKind::Tls { .. },
            ) => Ok(()),
            (
                ProxyProtocol::Trojan,
                TransportKind::Grpc { .. },
                SecurityKind::None | SecurityKind::Tls { .. },
            ) => Ok(()),
            (ProxyProtocol::Trojan, _, SecurityKind::Tls { .. }) => Ok(()),
            (ProxyProtocol::Trojan, _, SecurityKind::None) => {
                Err(ProtocolValidationError::MissingTls)
            }
            (ProxyProtocol::Vmess, _, _) if !looks_like_uuid(&self.credential) => {
                Err(ProtocolValidationError::InvalidUuid)
            }
            (ProxyProtocol::Vmess, TransportKind::Tcp, SecurityKind::None) => Ok(()),
            (ProxyProtocol::Vmess, TransportKind::Tcp, SecurityKind::Tls { .. }) => Ok(()),
            (
                ProxyProtocol::Vmess,
                TransportKind::WebSocket { path, .. },
                SecurityKind::None | SecurityKind::Tls { .. },
            ) if path.starts_with('/') => Ok(()),
            (
                ProxyProtocol::Vmess,
                TransportKind::WebSocket { .. },
                SecurityKind::None | SecurityKind::Tls { .. },
            ) => Err(ProtocolValidationError::InvalidWebSocketPath),
            (
                ProxyProtocol::Vmess,
                TransportKind::HttpUpgrade { path, .. },
                SecurityKind::None | SecurityKind::Tls { .. },
            ) if path.starts_with('/') => Ok(()),
            (
                ProxyProtocol::Vmess,
                TransportKind::HttpUpgrade { .. },
                SecurityKind::None | SecurityKind::Tls { .. },
            ) => Err(ProtocolValidationError::InvalidHttpUpgradePath),
            (
                ProxyProtocol::Vmess,
                TransportKind::Http2 { path, .. },
                SecurityKind::None | SecurityKind::Tls { .. },
            ) if path.starts_with('/') => Ok(()),
            (
                ProxyProtocol::Vmess,
                TransportKind::Http2 { .. },
                SecurityKind::None | SecurityKind::Tls { .. },
            ) => Err(ProtocolValidationError::InvalidHttp2Path),
            (
                ProxyProtocol::Vmess,
                TransportKind::Quic { .. },
                SecurityKind::None | SecurityKind::Tls { .. },
            ) => Ok(()),
            (
                ProxyProtocol::Vmess,
                TransportKind::Grpc { .. },
                SecurityKind::None | SecurityKind::Tls { .. },
            ) => Ok(()),
            (ProxyProtocol::Vless, _, _) if !looks_like_uuid(&self.credential) => {
                Err(ProtocolValidationError::InvalidUuid)
            }
            (ProxyProtocol::Vless, TransportKind::HttpUpgrade { path, .. }, _)
                if !path.starts_with('/') =>
            {
                Err(ProtocolValidationError::InvalidHttpUpgradePath)
            }
            (ProxyProtocol::Vless, TransportKind::Http2 { path, .. }, _)
                if !path.starts_with('/') =>
            {
                Err(ProtocolValidationError::InvalidHttp2Path)
            }
            (ProxyProtocol::Vless, TransportKind::Quic { .. }, _) => Ok(()),
            (ProxyProtocol::Vless, TransportKind::Grpc { .. }, _) => Ok(()),
            (ProxyProtocol::Vless, _, _) => Ok(()),
            (ProxyProtocol::Naive, _, _) if !is_user_password_credential(&self.credential) => {
                Err(ProtocolValidationError::InvalidNaiveCredential)
            }
            (
                ProxyProtocol::Naive,
                TransportKind::Tcp | TransportKind::Quic { .. },
                SecurityKind::Tls { .. },
            ) => Ok(()),
            (ProxyProtocol::Naive, _, SecurityKind::None) => {
                Err(ProtocolValidationError::MissingTls)
            }
            (ProxyProtocol::Naive, _, _) => Err(ProtocolValidationError::InvalidNaiveTransport),
            (ProxyProtocol::Mieru, _, _) if !is_user_password_credential(&self.credential) => {
                Err(ProtocolValidationError::InvalidMieruCredential)
            }
            (ProxyProtocol::Mieru, TransportKind::Tcp, SecurityKind::None) => Ok(()),
            (ProxyProtocol::Mieru, _, _) => Err(ProtocolValidationError::InvalidMieruTransport),
            (ProxyProtocol::Hy2, TransportKind::Quic { .. }, SecurityKind::Tls { .. }) => Ok(()),
            (ProxyProtocol::Hy2, _, _) => Err(ProtocolValidationError::InvalidHy2Transport),
            (ProxyProtocol::Tuic, TransportKind::Quic { .. }, SecurityKind::Tls { .. }) => {
                if is_tuic_credential(&self.credential) {
                    Ok(())
                } else {
                    Err(ProtocolValidationError::InvalidTuicCredential)
                }
            }
            (ProxyProtocol::Tuic, _, _) => Err(ProtocolValidationError::InvalidTuicTransport),
            (ProxyProtocol::Shadowsocks, TransportKind::Tcp, SecurityKind::None) => {
                let cipher = self
                    .cipher
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or(ProtocolValidationError::MissingShadowsocksCipher)?;
                if is_supported_shadowsocks_aead_cipher(cipher) {
                    Ok(())
                } else {
                    Err(ProtocolValidationError::InvalidShadowsocksCipher)
                }
            }
            (ProxyProtocol::Shadowsocks, _, _) => {
                Err(ProtocolValidationError::InvalidShadowsocksTransport)
            }
            (ProxyProtocol::AnyTls, TransportKind::Tcp, SecurityKind::Tls { .. }) => Ok(()),
            (ProxyProtocol::AnyTls, _, SecurityKind::None) => {
                Err(ProtocolValidationError::MissingTls)
            }
            (ProxyProtocol::AnyTls, _, _) => Err(ProtocolValidationError::InvalidAnyTlsTransport),
            (ProxyProtocol::Socks, TransportKind::Tcp, SecurityKind::None) => Ok(()),
            (ProxyProtocol::Socks, _, _) => Err(ProtocolValidationError::InvalidSocksTransport),
            (ProxyProtocol::Http, TransportKind::Tcp, SecurityKind::None) => Ok(()),
            (ProxyProtocol::Http, _, _) => Err(ProtocolValidationError::InvalidHttpTransport),
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
    InvalidVmessTransport,
    InvalidNaiveCredential,
    InvalidNaiveTransport,
    InvalidMieruCredential,
    InvalidMieruTransport,
    InvalidWebSocketPath,
    InvalidHttpUpgradePath,
    InvalidHttp2Path,
    InvalidHy2Transport,
    InvalidTuicCredential,
    InvalidTuicTransport,
    MissingShadowsocksCipher,
    InvalidShadowsocksCipher,
    InvalidShadowsocksTransport,
    InvalidAnyTlsTransport,
    InvalidSocksTransport,
    InvalidHttpTransport,
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
            Self::InvalidUuid => write!(f, "proxy credential must be a UUID"),
            Self::InvalidVmessTransport => {
                write!(f, "VMess currently supports TCP/WS with optional TLS")
            }
            Self::InvalidNaiveCredential => {
                write!(f, "Naive credential must be formatted as username:password")
            }
            Self::InvalidNaiveTransport => {
                write!(f, "Naive requires TCP or QUIC transport with TLS")
            }
            Self::InvalidMieruCredential => {
                write!(f, "Mieru credential must be formatted as username:password")
            }
            Self::InvalidMieruTransport => {
                write!(f, "Mieru currently supports TCP transport without TLS")
            }
            Self::InvalidWebSocketPath => write!(f, "WebSocket path must start with '/'"),
            Self::InvalidHttpUpgradePath => {
                write!(f, "HTTPUpgrade path must start with '/'")
            }
            Self::InvalidHttp2Path => write!(f, "HTTP/2 path must start with '/'"),
            Self::InvalidHy2Transport => write!(f, "HY2 requires QUIC transport with TLS"),
            Self::InvalidTuicCredential => {
                write!(f, "TUIC credential must be formatted as uuid:password")
            }
            Self::InvalidTuicTransport => write!(f, "TUIC requires QUIC transport with TLS"),
            Self::MissingShadowsocksCipher => write!(f, "Shadowsocks cipher is required"),
            Self::InvalidShadowsocksCipher => write!(f, "Shadowsocks cipher is unsupported"),
            Self::InvalidShadowsocksTransport => {
                write!(f, "Shadowsocks currently supports TCP without TLS")
            }
            Self::InvalidAnyTlsTransport => write!(f, "AnyTLS requires TCP transport with TLS"),
            Self::InvalidSocksTransport => {
                write!(f, "SOCKS outbound requires TCP transport without TLS")
            }
            Self::InvalidHttpTransport => {
                write!(f, "HTTP outbound requires TCP transport without TLS")
            }
        }
    }
}

impl std::error::Error for ProtocolValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedOutboundProfiles {
    pub profiles: Vec<OutboundProfile>,
    pub skipped: Vec<SkippedOutboundProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedOutboundProfile {
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionParseError {
    InvalidYaml(String),
    InvalidShare(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionInputFormat {
    MihomoYaml,
    ShareLinks,
}

impl SubscriptionInputFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MihomoYaml => "mihomo_yaml",
            Self::ShareLinks => "share_links",
        }
    }
}

impl fmt::Display for SubscriptionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidYaml(error) => write!(f, "invalid Mihomo YAML: {error}"),
            Self::InvalidShare(error) => write!(f, "invalid share links: {error}"),
        }
    }
}

impl std::error::Error for SubscriptionParseError {}

pub fn parse_mihomo_outbound_profiles(
    input: &str,
) -> Result<ParsedOutboundProfiles, SubscriptionParseError> {
    let config: MihomoConfig = serde_yaml::from_str(input)
        .map_err(|error| SubscriptionParseError::InvalidYaml(error.to_string()))?;
    let mut profiles = Vec::new();
    let mut skipped = Vec::new();

    for (index, proxy) in config.proxies.into_iter().enumerate() {
        match mihomo_proxy_to_profile(proxy, index) {
            Ok(profile) => profiles.push(profile),
            Err(skip) => skipped.push(skip),
        }
    }

    Ok(ParsedOutboundProfiles { profiles, skipped })
}

pub fn parse_subscription_outbound_profiles(
    input: &str,
) -> Result<ParsedOutboundProfiles, SubscriptionParseError> {
    match detect_subscription_input_format(input) {
        SubscriptionInputFormat::MihomoYaml => parse_mihomo_outbound_profiles(input),
        SubscriptionInputFormat::ShareLinks => parse_share_outbound_profiles(input),
    }
}

pub fn detect_subscription_input_format(input: &str) -> SubscriptionInputFormat {
    if looks_like_mihomo_yaml(input) {
        SubscriptionInputFormat::MihomoYaml
    } else {
        SubscriptionInputFormat::ShareLinks
    }
}

pub fn parse_share_outbound_profiles(
    input: &str,
) -> Result<ParsedOutboundProfiles, SubscriptionParseError> {
    let decoded = decode_share_subscription_text(input)?;
    let mut profiles = Vec::new();
    let mut skipped = Vec::new();
    for (index, line) in decoded
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        match share_link_to_profile(line, index) {
            Ok(profile) => profiles.push(profile),
            Err(skip) => skipped.push(skip),
        }
    }
    Ok(ParsedOutboundProfiles { profiles, skipped })
}

#[derive(Debug, Deserialize)]
struct MihomoConfig {
    #[serde(default)]
    proxies: Vec<MihomoProxy>,
}

fn looks_like_mihomo_yaml(input: &str) -> bool {
    input
        .lines()
        .map(str::trim_start)
        .any(|line| line.starts_with("proxies:"))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct MihomoProxy {
    name: Option<String>,
    #[serde(rename = "type")]
    protocol: Option<String>,
    server: Option<String>,
    port: Option<u16>,
    port_range: Option<String>,
    password: Option<String>,
    token: Option<String>,
    username: Option<String>,
    cipher: Option<String>,
    uuid: Option<String>,
    flow: Option<String>,
    tls: Option<bool>,
    sni: Option<String>,
    servername: Option<String>,
    skip_cert_verify: Option<bool>,
    network: Option<String>,
    transport: Option<String>,
    ws_opts: Option<MihomoWsOptions>,
    httpupgrade_opts: Option<MihomoHttpUpgradeOptions>,
    h2_opts: Option<MihomoH2Options>,
    quic_opts: Option<MihomoQuicOptions>,
    grpc_opts: Option<MihomoGrpcOptions>,
}

#[derive(Debug, Deserialize)]
struct MihomoWsOptions {
    path: Option<String>,
    headers: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct MihomoHttpUpgradeOptions {
    path: Option<String>,
    host: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MihomoH2Options {
    path: Option<String>,
    host: Option<StringList>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StringList {
    One(String),
    Many(Vec<String>),
}

impl StringList {
    fn first_non_empty(self) -> Option<String> {
        match self {
            Self::One(value) => non_empty(Some(value)),
            Self::Many(values) => values.into_iter().find_map(|value| non_empty(Some(value))),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct MihomoQuicOptions {
    security: Option<String>,
    key: Option<String>,
    #[serde(alias = "headerType", alias = "header_type")]
    header: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct MihomoGrpcOptions {
    #[serde(alias = "serviceName", alias = "service_name")]
    grpc_service_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VmessJsonShare {
    ps: Option<String>,
    add: Option<String>,
    port: Option<serde_json::Value>,
    id: Option<String>,
    net: Option<String>,
    host: Option<String>,
    path: Option<String>,
    #[serde(rename = "serviceName", alias = "service_name", alias = "service-name")]
    service_name: Option<String>,
    tls: Option<String>,
    sni: Option<String>,
    servername: Option<String>,
    scy: Option<String>,
    cipher: Option<String>,
    allow_insecure: Option<serde_json::Value>,
}

fn mihomo_proxy_to_profile(
    proxy: MihomoProxy,
    index: usize,
) -> Result<OutboundProfile, SkippedOutboundProfile> {
    let name = non_empty(proxy.name).unwrap_or_else(|| format!("proxy-{}", index + 1));
    let Some(protocol_name) = non_empty(proxy.protocol) else {
        return Err(skip(name, "missing protocol type"));
    };
    let Some(server) = non_empty(proxy.server) else {
        return Err(skip(name, "missing server"));
    };
    let protocol_name = protocol_name.to_ascii_lowercase();
    let protocol = match protocol_name.as_str() {
        "trojan" => ProxyProtocol::Trojan,
        "vmess" => ProxyProtocol::Vmess,
        "vless" => ProxyProtocol::Vless,
        "naive" => ProxyProtocol::Naive,
        "mieru" => ProxyProtocol::Mieru,
        "hy2" | "hysteria2" => ProxyProtocol::Hy2,
        "ss" | "shadowsocks" => ProxyProtocol::Shadowsocks,
        "anytls" | "any-tls" => ProxyProtocol::AnyTls,
        "tuic" => ProxyProtocol::Tuic,
        "socks" | "socks5" => ProxyProtocol::Socks,
        "http" => ProxyProtocol::Http,
        other => return Err(skip(name, format!("unsupported protocol: {other}"))),
    };
    let credential = match protocol {
        ProxyProtocol::Trojan => non_empty(proxy.password)
            .ok_or_else(|| skip(name.clone(), "missing trojan password"))?,
        ProxyProtocol::Vmess => {
            non_empty(proxy.uuid).ok_or_else(|| skip(name.clone(), "missing vmess uuid"))?
        }
        ProxyProtocol::Vless => {
            non_empty(proxy.uuid).ok_or_else(|| skip(name.clone(), "missing vless uuid"))?
        }
        ProxyProtocol::Naive => {
            let username = non_empty(proxy.username)
                .ok_or_else(|| skip(name.clone(), "missing naive username"))?;
            let password = non_empty(proxy.password)
                .ok_or_else(|| skip(name.clone(), "missing naive password"))?;
            format!("{username}:{password}")
        }
        ProxyProtocol::Mieru => {
            let username = non_empty(proxy.username)
                .ok_or_else(|| skip(name.clone(), "missing mieru username"))?;
            let password = non_empty(proxy.password)
                .ok_or_else(|| skip(name.clone(), "missing mieru password"))?;
            format!("{username}:{password}")
        }
        ProxyProtocol::Shadowsocks => non_empty(proxy.password)
            .ok_or_else(|| skip(name.clone(), "missing shadowsocks password"))?,
        ProxyProtocol::AnyTls => non_empty(proxy.password)
            .ok_or_else(|| skip(name.clone(), "missing anytls password"))?,
        ProxyProtocol::Hy2 => non_empty(proxy.password)
            .ok_or_else(|| skip(name.clone(), "missing hy2 auth password"))?,
        ProxyProtocol::Tuic => {
            let uuid =
                non_empty(proxy.uuid).ok_or_else(|| skip(name.clone(), "missing tuic uuid"))?;
            let password = non_empty(proxy.password)
                .or_else(|| non_empty(proxy.token))
                .ok_or_else(|| skip(name.clone(), "missing tuic password"))?;
            format!("{uuid}:{password}")
        }
        ProxyProtocol::Socks | ProxyProtocol::Http => {
            proxy_credential(proxy.username, proxy.password)
        }
    };
    let cipher = matches!(protocol, ProxyProtocol::Shadowsocks | ProxyProtocol::Vmess)
        .then(|| non_empty(proxy.cipher))
        .flatten();
    let flow = matches!(protocol, ProxyProtocol::Vless)
        .then(|| non_empty(proxy.flow))
        .flatten();
    let port = profile_port(proxy.port, proxy.port_range.as_deref())
        .ok_or_else(|| skip(name.clone(), "missing port"))?;
    let network = proxy.network.as_deref().or(proxy.transport.as_deref());
    let transport = mihomo_transport(
        &name,
        &server,
        &protocol,
        network,
        proxy.ws_opts,
        proxy.httpupgrade_opts,
        proxy.h2_opts,
        proxy.quic_opts,
        proxy.grpc_opts,
    )?;
    let security = mihomo_security(
        &protocol,
        &server,
        proxy.tls,
        proxy.sni,
        proxy.servername,
        proxy.skip_cert_verify,
    );
    let profile = OutboundProfile {
        tag: name.clone(),
        protocol,
        endpoint: Endpoint::new(server, port),
        transport,
        security,
        credential,
        cipher,
        flow,
    };

    profile
        .validate()
        .map_err(|error| skip(name, format!("invalid profile: {error}")))?;
    Ok(profile)
}

fn mihomo_transport(
    name: &str,
    server: &str,
    protocol: &ProxyProtocol,
    network: Option<&str>,
    ws_opts: Option<MihomoWsOptions>,
    httpupgrade_opts: Option<MihomoHttpUpgradeOptions>,
    h2_opts: Option<MihomoH2Options>,
    quic_opts: Option<MihomoQuicOptions>,
    grpc_opts: Option<MihomoGrpcOptions>,
) -> Result<TransportKind, SkippedOutboundProfile> {
    if matches!(protocol, ProxyProtocol::Hy2 | ProxyProtocol::Tuic) {
        return match network
            .map(|value| value.to_ascii_lowercase())
            .as_deref()
            .unwrap_or("")
        {
            "" | "quic" | "hy2" | "hysteria2" | "tuic" => Ok(default_quic_transport()),
            other => Err(skip(
                name.to_string(),
                format!("unsupported QUIC transport: {other}"),
            )),
        };
    }
    if matches!(protocol, ProxyProtocol::Mieru) {
        return match network
            .map(|value| value.to_ascii_lowercase())
            .as_deref()
            .unwrap_or("tcp")
        {
            "" | "tcp" => Ok(TransportKind::Tcp),
            other => Err(skip(
                name.to_string(),
                format!("unsupported Mieru transport: {other}"),
            )),
        };
    }
    match network.unwrap_or("tcp").to_ascii_lowercase().as_str() {
        "" | "tcp" => Ok(TransportKind::Tcp),
        "ws" | "websocket" => {
            let path = ws_opts
                .as_ref()
                .and_then(|opts| non_empty(opts.path.clone()))
                .unwrap_or_else(|| "/".to_string());
            let host = ws_opts
                .and_then(|opts| opts.headers)
                .and_then(|headers| header_value_case_insensitive(&headers, "host"))
                .or_else(|| Some(server.to_string()));
            Ok(TransportKind::WebSocket { path, host })
        }
        "httpupgrade" | "http-upgrade" => {
            let path = httpupgrade_opts
                .as_ref()
                .and_then(|opts| non_empty(opts.path.clone()))
                .unwrap_or_else(|| "/".to_string());
            let host = httpupgrade_opts
                .and_then(|opts| non_empty(opts.host))
                .or_else(|| Some(server.to_string()));
            Ok(TransportKind::HttpUpgrade { path, host })
        }
        "h2" | "http" | "http2" => {
            let path = h2_opts
                .as_ref()
                .and_then(|opts| non_empty(opts.path.clone()))
                .unwrap_or_else(|| "/".to_string());
            let host = h2_opts
                .and_then(|opts| opts.host)
                .and_then(StringList::first_non_empty)
                .or_else(|| Some(server.to_string()));
            Ok(TransportKind::Http2 { path, host })
        }
        "quic" => Ok(mihomo_quic_transport(quic_opts)),
        "grpc" => {
            let service_name = grpc_opts.and_then(|opts| non_empty(opts.grpc_service_name));
            Ok(TransportKind::Grpc { service_name })
        }
        other => Err(skip(
            name.to_string(),
            format!("unsupported transport: {other}"),
        )),
    }
}

fn mihomo_quic_transport(opts: Option<MihomoQuicOptions>) -> TransportKind {
    let (security, key, header_type) = opts
        .map(|opts| {
            (
                non_empty(opts.security),
                non_empty(opts.key),
                non_empty(opts.header),
            )
        })
        .unwrap_or((None, None, None));
    TransportKind::Quic {
        security,
        key,
        header_type,
    }
}

fn mihomo_security(
    protocol: &ProxyProtocol,
    server: &str,
    tls: Option<bool>,
    sni: Option<String>,
    servername: Option<String>,
    skip_cert_verify: Option<bool>,
) -> SecurityKind {
    let sni = non_empty(sni)
        .or_else(|| non_empty(servername))
        .or_else(|| Some(server.to_string()));
    let tls_enabled = tls.unwrap_or(matches!(
        protocol,
        ProxyProtocol::Trojan
            | ProxyProtocol::Hy2
            | ProxyProtocol::AnyTls
            | ProxyProtocol::Tuic
            | ProxyProtocol::Naive
    ));
    if tls_enabled {
        SecurityKind::Tls {
            sni,
            skip_verify: skip_cert_verify.unwrap_or(false),
        }
    } else {
        SecurityKind::None
    }
}

fn header_value_case_insensitive(headers: &HashMap<String, String>, name: &str) -> Option<String> {
    headers.iter().find_map(|(key, value)| {
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn proxy_credential(username: Option<String>, password: Option<String>) -> String {
    match (non_empty(username), non_empty(password)) {
        (Some(username), Some(password)) => format!("{username}:{password}"),
        (Some(username), None) => username,
        (None, Some(password)) => format!(":{password}"),
        (None, None) => String::new(),
    }
}

fn default_quic_transport() -> TransportKind {
    TransportKind::Quic {
        security: None,
        key: None,
        header_type: None,
    }
}

fn profile_port(port: Option<u16>, port_range: Option<&str>) -> Option<u16> {
    port.or_else(|| first_port_in_range(port_range?))
}

fn first_port_in_range(value: &str) -> Option<u16> {
    let first = value
        .split(',')
        .map(str::trim)
        .find(|part| !part.is_empty())?;
    let first = first
        .split_once('-')
        .map(|(start, _)| start)
        .unwrap_or(first);
    first.trim().parse::<u16>().ok()
}

fn is_supported_shadowsocks_aead_cipher(cipher: &str) -> bool {
    matches!(
        cipher.to_ascii_lowercase().as_str(),
        "aes-128-gcm" | "aes-256-gcm" | "chacha20-ietf-poly1305"
    )
}

fn skip(name: String, reason: impl Into<String>) -> SkippedOutboundProfile {
    SkippedOutboundProfile {
        name,
        reason: reason.into(),
    }
}

fn decode_share_subscription_text(input: &str) -> Result<String, SubscriptionParseError> {
    if input.contains("://") {
        return Ok(input.to_string());
    }
    let compact: String = input.chars().filter(|ch| !ch.is_whitespace()).collect();
    if compact.is_empty() {
        return Ok(String::new());
    }
    let bytes = decode_base64_flexible(&compact)
        .map_err(|error| SubscriptionParseError::InvalidShare(error.to_string()))?;
    String::from_utf8(bytes)
        .map_err(|error| SubscriptionParseError::InvalidShare(error.to_string()))
}

fn decode_base64_flexible(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD
        .decode(input.as_bytes())
        .or_else(|_| URL_SAFE_NO_PAD.decode(input.as_bytes()))
        .or_else(|_| URL_SAFE.decode(input.as_bytes()))
}

fn share_link_to_profile(
    link: &str,
    index: usize,
) -> Result<OutboundProfile, SkippedOutboundProfile> {
    if let Some(profile) = vmess_json_share_link_to_profile(link, index)? {
        return Ok(profile);
    }
    let url =
        Url::parse(link).map_err(|error| skip(format!("link-{}", index + 1), error.to_string()))?;
    if url.scheme() == "ss" {
        return shadowsocks_share_link_to_profile(&url, link, index);
    }
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    let tag = non_empty(url.fragment().map(ToString::to_string))
        .or_else(|| {
            query
                .get("profile")
                .cloned()
                .and_then(|profile| non_empty(Some(profile)))
        })
        .unwrap_or_else(|| format!("proxy-{}", index + 1));
    let Some(server) = url.host_str().map(ToString::to_string) else {
        return Err(skip(tag, "missing server"));
    };
    let protocol = match url.scheme() {
        "trojan" => ProxyProtocol::Trojan,
        "vmess" => ProxyProtocol::Vmess,
        "vless" => ProxyProtocol::Vless,
        "naive" => ProxyProtocol::Naive,
        "mieru" | "mierus" => ProxyProtocol::Mieru,
        "hy2" | "hysteria2" => ProxyProtocol::Hy2,
        "anytls" | "any-tls" => ProxyProtocol::AnyTls,
        "tuic" => ProxyProtocol::Tuic,
        "socks" | "socks5" => ProxyProtocol::Socks,
        "http" => ProxyProtocol::Http,
        other => return Err(skip(tag, format!("unsupported protocol: {other}"))),
    };
    let credential = match &protocol {
        ProxyProtocol::Tuic => {
            let uuid = non_empty(Some(url.username().to_string()))
                .ok_or_else(|| skip(tag.clone(), "missing tuic uuid"))?;
            let password = non_empty(url.password().map(ToString::to_string))
                .ok_or_else(|| skip(tag.clone(), "missing tuic password"))?;
            format!("{uuid}:{password}")
        }
        ProxyProtocol::Naive => {
            let username = non_empty(Some(url.username().to_string()))
                .ok_or_else(|| skip(tag.clone(), "missing naive username"))?;
            let password = non_empty(url.password().map(ToString::to_string))
                .ok_or_else(|| skip(tag.clone(), "missing naive password"))?;
            format!("{username}:{password}")
        }
        ProxyProtocol::Mieru => {
            let username = non_empty(Some(url.username().to_string()))
                .ok_or_else(|| skip(tag.clone(), "missing mieru username"))?;
            let password = non_empty(url.password().map(ToString::to_string))
                .ok_or_else(|| skip(tag.clone(), "missing mieru password"))?;
            format!("{username}:{password}")
        }
        ProxyProtocol::Socks | ProxyProtocol::Http => proxy_credential(
            Some(url.username().to_string()),
            url.password().map(ToString::to_string),
        ),
        _ => non_empty(Some(url.username().to_string()))
            .ok_or_else(|| skip(tag.clone(), "missing credential"))?,
    };
    let port = share_link_port(&protocol, &url, &query)
        .ok_or_else(|| skip(tag.clone(), "missing port"))?;
    let transport = share_link_transport(&tag, &server, &protocol, &query)?;
    let security = share_link_security(&protocol, &server, &query);
    let flow = matches!(protocol, ProxyProtocol::Vless)
        .then(|| {
            query
                .get("flow")
                .cloned()
                .and_then(|flow| non_empty(Some(flow)))
        })
        .flatten();
    let cipher = matches!(protocol, ProxyProtocol::Vmess)
        .then(|| {
            query
                .get("cipher")
                .cloned()
                .and_then(|cipher| non_empty(Some(cipher)))
        })
        .flatten();
    let profile = OutboundProfile {
        tag: tag.clone(),
        protocol,
        endpoint: Endpoint::new(server, port),
        transport,
        security,
        credential,
        cipher,
        flow,
    };
    profile
        .validate()
        .map_err(|error| skip(tag, format!("invalid profile: {error}")))?;
    Ok(profile)
}

fn vmess_json_share_link_to_profile(
    link: &str,
    index: usize,
) -> Result<Option<OutboundProfile>, SkippedOutboundProfile> {
    let Some(body) = link.strip_prefix("vmess://") else {
        return Ok(None);
    };
    if body.contains('@') {
        return Ok(None);
    }
    let body = body.split('#').next().unwrap_or(body);
    let body = body.split('?').next().unwrap_or(body);
    let bytes = decode_base64_flexible(body)
        .map_err(|error| skip(format!("proxy-{}", index + 1), error.to_string()))?;
    let config: VmessJsonShare = serde_json::from_slice(&bytes)
        .map_err(|error| skip(format!("proxy-{}", index + 1), error.to_string()))?;
    let tag = non_empty(config.ps).unwrap_or_else(|| format!("proxy-{}", index + 1));
    let server = non_empty(config.add).ok_or_else(|| skip(tag.clone(), "missing server"))?;
    let port = config
        .port
        .as_ref()
        .and_then(json_value_to_u16)
        .ok_or_else(|| skip(tag.clone(), "missing port"))?;
    let credential = non_empty(config.id).ok_or_else(|| skip(tag.clone(), "missing vmess uuid"))?;
    let network = non_empty(config.net).unwrap_or_else(|| "tcp".to_string());
    let transport = match network.to_ascii_lowercase().as_str() {
        "" | "tcp" => TransportKind::Tcp,
        "ws" | "websocket" => TransportKind::WebSocket {
            path: non_empty(config.path).unwrap_or_else(|| "/".to_string()),
            host: non_empty(config.host).or_else(|| Some(server.clone())),
        },
        "httpupgrade" | "http-upgrade" => TransportKind::HttpUpgrade {
            path: non_empty(config.path).unwrap_or_else(|| "/".to_string()),
            host: non_empty(config.host).or_else(|| Some(server.clone())),
        },
        "h2" | "http" | "http2" => TransportKind::Http2 {
            path: non_empty(config.path).unwrap_or_else(|| "/".to_string()),
            host: non_empty(config.host).or_else(|| Some(server.clone())),
        },
        "quic" => default_quic_transport(),
        "grpc" => TransportKind::Grpc {
            service_name: non_empty(config.service_name).or_else(|| non_empty(config.path)),
        },
        other => {
            return Err(skip(
                tag,
                format!("unsupported VMess JSON transport: {other}"),
            ))
        }
    };
    let tls_enabled = non_empty(config.tls)
        .map(|tls| matches!(tls.to_ascii_lowercase().as_str(), "tls" | "true" | "1"))
        .unwrap_or(false);
    let security = if tls_enabled {
        SecurityKind::Tls {
            sni: non_empty(config.sni)
                .or_else(|| non_empty(config.servername))
                .or_else(|| Some(server.clone())),
            skip_verify: config
                .allow_insecure
                .as_ref()
                .map(truthy_json_value)
                .unwrap_or(false),
        }
    } else {
        SecurityKind::None
    };
    let cipher = non_empty(config.scy)
        .or_else(|| non_empty(config.cipher))
        .or_else(|| Some("auto".to_string()));
    let profile = OutboundProfile {
        tag: tag.clone(),
        protocol: ProxyProtocol::Vmess,
        endpoint: Endpoint::new(server, port),
        transport,
        security,
        credential,
        cipher,
        flow: None,
    };
    profile
        .validate()
        .map_err(|error| skip(tag, format!("invalid profile: {error}")))?;
    Ok(Some(profile))
}

fn json_value_to_u16(value: &serde_json::Value) -> Option<u16> {
    match value {
        serde_json::Value::Number(number) => {
            number.as_u64().and_then(|port| u16::try_from(port).ok())
        }
        serde_json::Value::String(value) => value.trim().parse::<u16>().ok(),
        _ => None,
    }
}

fn truthy_json_value(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(number) => number.as_u64().unwrap_or(0) != 0,
        serde_json::Value::String(value) => {
            matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes")
        }
        _ => false,
    }
}

fn shadowsocks_share_link_to_profile(
    url: &Url,
    link: &str,
    index: usize,
) -> Result<OutboundProfile, SkippedOutboundProfile> {
    let tag = non_empty(url.fragment().map(ToString::to_string))
        .unwrap_or_else(|| format!("proxy-{}", index + 1));
    let (cipher, credential, server, port) =
        if let Some(server) = url.host_str().map(ToString::to_string) {
            let port = url.port().unwrap_or(8388);
            let (cipher, password) = shadowsocks_userinfo(url)
                .ok_or_else(|| skip(tag.clone(), "missing shadowsocks method/password"))?;
            (cipher, password, server, port)
        } else {
            decode_legacy_shadowsocks_share_body(link)
                .ok_or_else(|| skip(tag.clone(), "invalid shadowsocks share body"))?
        };

    let profile = OutboundProfile {
        tag: tag.clone(),
        protocol: ProxyProtocol::Shadowsocks,
        endpoint: Endpoint::new(server, port),
        transport: TransportKind::Tcp,
        security: SecurityKind::None,
        credential,
        cipher: Some(cipher),
        flow: None,
    };
    profile
        .validate()
        .map_err(|error| skip(tag, format!("invalid profile: {error}")))?;
    Ok(profile)
}

fn shadowsocks_userinfo(url: &Url) -> Option<(String, String)> {
    if !url.username().is_empty() {
        if let Some(password) = url.password() {
            return Some((url.username().to_string(), password.to_string()));
        }
        let decoded = decode_base64_flexible(url.username()).ok()?;
        let decoded = String::from_utf8(decoded).ok()?;
        let (cipher, password) = decoded.split_once(':')?;
        return Some((cipher.to_string(), password.to_string()));
    }
    None
}

fn decode_legacy_shadowsocks_share_body(link: &str) -> Option<(String, String, String, u16)> {
    let body = link.strip_prefix("ss://")?;
    let body = body.split('#').next().unwrap_or(body);
    let body = body.split('?').next().unwrap_or(body);
    let decoded = decode_base64_flexible(body).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (method_password, server_port) = decoded.rsplit_once('@')?;
    let (cipher, password) = method_password.split_once(':')?;
    let (server, port) = split_host_port(server_port, 8388)?;
    Some((cipher.to_string(), password.to_string(), server, port))
}

fn share_link_port(
    protocol: &ProxyProtocol,
    url: &Url,
    query: &HashMap<String, String>,
) -> Option<u16> {
    if matches!(protocol, ProxyProtocol::Mieru) {
        return url.port().or_else(|| {
            query
                .get("port")
                .and_then(|value| first_port_in_range(value))
        });
    }
    let default_port = match protocol {
        ProxyProtocol::Socks => 1080,
        ProxyProtocol::Http => 80,
        _ => 443,
    };
    Some(url.port().unwrap_or(default_port))
}

fn split_host_port(value: &str, default_port: u16) -> Option<(String, u16)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.starts_with('[') {
        let end = value.find(']')?;
        let host = value[1..end].to_string();
        let port = value[end + 1..]
            .strip_prefix(':')
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(default_port);
        return Some((host, port));
    }
    let colon_count = value
        .as_bytes()
        .iter()
        .filter(|byte| **byte == b':')
        .count();
    if colon_count == 1 {
        let (host, port) = value.rsplit_once(':')?;
        let port = port.parse::<u16>().ok().unwrap_or(default_port);
        return Some((host.to_string(), port));
    }
    Some((value.to_string(), default_port))
}

fn share_link_transport(
    tag: &str,
    server: &str,
    protocol: &ProxyProtocol,
    query: &HashMap<String, String>,
) -> Result<TransportKind, SkippedOutboundProfile> {
    if matches!(protocol, ProxyProtocol::Hy2 | ProxyProtocol::Tuic) {
        return match query
            .get("type")
            .or_else(|| query.get("network"))
            .map(|value| value.to_ascii_lowercase())
            .as_deref()
            .unwrap_or("")
        {
            "" | "quic" | "hy2" | "hysteria2" | "tuic" => Ok(default_quic_transport()),
            other => Err(skip(
                tag.to_string(),
                format!("unsupported QUIC transport: {other}"),
            )),
        };
    }
    if matches!(protocol, ProxyProtocol::Mieru) {
        return match query
            .get("protocol")
            .or_else(|| query.get("type"))
            .or_else(|| query.get("network"))
            .map(|value| value.to_ascii_lowercase())
            .as_deref()
            .unwrap_or("tcp")
        {
            "" | "tcp" => Ok(TransportKind::Tcp),
            other => Err(skip(
                tag.to_string(),
                format!("unsupported Mieru transport: {other}"),
            )),
        };
    }
    match query
        .get("type")
        .or_else(|| query.get("network"))
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
        .unwrap_or("tcp")
    {
        "" | "tcp" => Ok(TransportKind::Tcp),
        "ws" | "websocket" => Ok(TransportKind::WebSocket {
            path: query
                .get("path")
                .cloned()
                .and_then(|path| non_empty(Some(path)))
                .unwrap_or_else(|| "/".to_string()),
            host: query
                .get("host")
                .cloned()
                .and_then(|host| non_empty(Some(host)))
                .or_else(|| Some(server.to_string())),
        }),
        "httpupgrade" | "http-upgrade" => Ok(TransportKind::HttpUpgrade {
            path: query
                .get("path")
                .cloned()
                .and_then(|path| non_empty(Some(path)))
                .unwrap_or_else(|| "/".to_string()),
            host: query
                .get("host")
                .cloned()
                .and_then(|host| non_empty(Some(host)))
                .or_else(|| Some(server.to_string())),
        }),
        "h2" | "http" | "http2" => Ok(TransportKind::Http2 {
            path: query
                .get("path")
                .cloned()
                .and_then(|path| non_empty(Some(path)))
                .unwrap_or_else(|| "/".to_string()),
            host: query
                .get("host")
                .cloned()
                .and_then(|host| non_empty(Some(host)))
                .or_else(|| Some(server.to_string())),
        }),
        "quic" => Ok(share_link_quic_transport(query)),
        "grpc" => Ok(TransportKind::Grpc {
            service_name: query
                .get("serviceName")
                .or_else(|| query.get("service_name"))
                .or_else(|| query.get("service-name"))
                .or_else(|| query.get("path"))
                .cloned()
                .and_then(|service_name| non_empty(Some(service_name))),
        }),
        other => Err(skip(
            tag.to_string(),
            format!("unsupported transport: {other}"),
        )),
    }
}

fn share_link_quic_transport(query: &HashMap<String, String>) -> TransportKind {
    TransportKind::Quic {
        security: query_first_non_empty(
            query,
            &[
                "quicSecurity",
                "quic-security",
                "quic_security",
                "encryption",
            ],
        ),
        key: query_first_non_empty(query, &["quicKey", "quic-key", "quic_key", "key"]),
        header_type: query_first_non_empty(
            query,
            &[
                "headerType",
                "header-type",
                "header_type",
                "quicHeaderType",
                "quic-header-type",
                "quic_header_type",
                "header",
            ],
        ),
    }
}

fn query_first_non_empty(query: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| query.get(*key))
        .cloned()
        .and_then(|value| non_empty(Some(value)))
}

fn share_link_security(
    protocol: &ProxyProtocol,
    server: &str,
    query: &HashMap<String, String>,
) -> SecurityKind {
    let security = query
        .get("security")
        .or_else(|| query.get("tls"))
        .map(|value| value.to_ascii_lowercase());
    let tls_enabled = security
        .as_deref()
        .map(|value| matches!(value, "tls" | "true" | "1"))
        .unwrap_or(matches!(
            protocol,
            ProxyProtocol::Trojan
                | ProxyProtocol::Hy2
                | ProxyProtocol::AnyTls
                | ProxyProtocol::Tuic
                | ProxyProtocol::Naive
        ));
    if tls_enabled {
        SecurityKind::Tls {
            sni: query
                .get("sni")
                .or_else(|| query.get("servername"))
                .cloned()
                .and_then(|sni| non_empty(Some(sni)))
                .or_else(|| Some(server.to_string())),
            skip_verify: truthy_query(query, "allowInsecure")
                || truthy_query(query, "skip-cert-verify")
                || truthy_query(query, "insecure"),
        }
    } else {
        SecurityKind::None
    }
}

fn truthy_query(query: &HashMap<String, String>, key: &str) -> bool {
    query
        .get(key)
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolEncodingError {
    InvalidUuid,
    InvalidPassword,
    InvalidTargetHost,
    FlowTooLong,
    PacketTooLong,
}

impl fmt::Display for ProtocolEncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUuid => write!(f, "VLESS credential must be a UUID"),
            Self::InvalidPassword => write!(f, "Trojan password is empty"),
            Self::InvalidTargetHost => write!(f, "VLESS target host is invalid"),
            Self::FlowTooLong => write!(f, "VLESS flow is too long"),
            Self::PacketTooLong => write!(f, "UDP packet payload is too long"),
        }
    }
}

impl std::error::Error for ProtocolEncodingError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolDecodingError {
    UnexpectedEof,
    InvalidUtf8,
    InvalidHy2Status(u8),
    InvalidEndpoint,
    InvalidTuicVersion(u8),
    InvalidTuicCommand(u8),
    InvalidTuicAddressType(u8),
}

impl fmt::Display for ProtocolDecodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "protocol message is truncated"),
            Self::InvalidUtf8 => write!(f, "protocol message contains invalid UTF-8"),
            Self::InvalidHy2Status(status) => {
                write!(f, "HY2 TCP response status is invalid: {status}")
            }
            Self::InvalidEndpoint => write!(f, "proxy endpoint is invalid"),
            Self::InvalidTuicVersion(version) => {
                write!(f, "TUIC command version is invalid: {version}")
            }
            Self::InvalidTuicCommand(command) => {
                write!(f, "TUIC command type is invalid: {command}")
            }
            Self::InvalidTuicAddressType(address_type) => {
                write!(f, "TUIC address type is invalid: {address_type}")
            }
        }
    }
}

impl std::error::Error for ProtocolDecodingError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hy2TcpResponse {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hy2AuthRequest {
    pub method: &'static str,
    pub path: &'static str,
    pub host: &'static str,
    pub auth: String,
    pub cc_rx: String,
    pub padding: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hy2UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub address: Endpoint,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuicPacketCommand {
    pub associate_id: u16,
    pub packet_id: u16,
    pub fragment_total: u8,
    pub fragment_id: u8,
    pub source: Endpoint,
    pub payload: Vec<u8>,
}

pub fn build_hy2_auth_request(
    auth: &str,
    cc_rx: u64,
    padding: &str,
) -> Result<Hy2AuthRequest, ProtocolEncodingError> {
    if auth.trim().is_empty() {
        return Err(ProtocolEncodingError::InvalidPassword);
    }
    Ok(Hy2AuthRequest {
        method: "POST",
        path: "/auth",
        host: "hysteria",
        auth: auth.to_string(),
        cc_rx: cc_rx.to_string(),
        padding: padding.to_string(),
    })
}

pub fn is_hy2_auth_success_status(status: u16) -> bool {
    status == 233
}

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

pub fn encode_vless_udp_request_header(
    uuid: &str,
    target: &Endpoint,
) -> Result<Vec<u8>, ProtocolEncodingError> {
    let user_id = parse_uuid_bytes(uuid)?;
    let mut header = Vec::with_capacity(32 + target.host.len());
    header.push(VLESS_VERSION);
    header.extend_from_slice(&user_id);
    encode_vless_addon(&mut header, "")?;
    header.push(VLESS_COMMAND_UDP);
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

pub fn encode_trojan_udp_request_header(
    password: &str,
    target: &Endpoint,
) -> Result<Vec<u8>, ProtocolEncodingError> {
    if password.is_empty() {
        return Err(ProtocolEncodingError::InvalidPassword);
    }
    let mut header = Vec::with_capacity(80 + target.host.len());
    encode_trojan_password_hash(&mut header, password);
    header.extend_from_slice(b"\r\n");
    header.push(TROJAN_COMMAND_UDP_ASSOCIATE);
    encode_trojan_target(&mut header, target)?;
    header.extend_from_slice(b"\r\n");
    Ok(header)
}

pub fn encode_trojan_udp_packet(
    target: &Endpoint,
    payload: &[u8],
) -> Result<Vec<u8>, ProtocolEncodingError> {
    let payload_len =
        u16::try_from(payload.len()).map_err(|_| ProtocolEncodingError::PacketTooLong)?;
    let mut packet = Vec::with_capacity(8 + target.host.len() + payload.len());
    encode_trojan_target(&mut packet, target)?;
    packet.extend_from_slice(&payload_len.to_be_bytes());
    packet.extend_from_slice(b"\r\n");
    packet.extend_from_slice(payload);
    Ok(packet)
}

pub fn encode_shadowsocks_tcp_request_header(
    target: &Endpoint,
) -> Result<Vec<u8>, ProtocolEncodingError> {
    let mut header = Vec::with_capacity(4 + target.host.len());
    encode_shadowsocks_target(&mut header, target)?;
    Ok(header)
}

pub fn encode_hy2_tcp_request(
    target: &Endpoint,
    padding: &[u8],
) -> Result<Vec<u8>, ProtocolEncodingError> {
    if target.host.trim().is_empty() {
        return Err(ProtocolEncodingError::InvalidTargetHost);
    }
    let address = format!("{}:{}", target.host, target.port);
    let mut request = Vec::with_capacity(8 + address.len() + padding.len());
    encode_quic_varint(&mut request, 0x401);
    encode_quic_varint(&mut request, address.len() as u64);
    request.extend_from_slice(address.as_bytes());
    encode_quic_varint(&mut request, padding.len() as u64);
    request.extend_from_slice(padding);
    Ok(request)
}

pub fn encode_hy2_udp_message(
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    address: &Endpoint,
    payload: &[u8],
) -> Result<Vec<u8>, ProtocolEncodingError> {
    if address.host.trim().is_empty() {
        return Err(ProtocolEncodingError::InvalidTargetHost);
    }
    let address = format!("{}:{}", address.host.trim(), address.port);
    let mut message = Vec::with_capacity(12 + address.len() + payload.len());
    message.extend_from_slice(&session_id.to_be_bytes());
    message.extend_from_slice(&packet_id.to_be_bytes());
    message.push(fragment_id);
    message.push(fragment_count);
    encode_quic_varint(&mut message, address.len() as u64);
    message.extend_from_slice(address.as_bytes());
    message.extend_from_slice(payload);
    Ok(message)
}

pub fn encode_tuic_authenticate_command(
    uuid: &str,
    token: &[u8; 32],
) -> Result<Vec<u8>, ProtocolEncodingError> {
    let uuid = parse_uuid_bytes(uuid)?;
    let mut command = Vec::with_capacity(50);
    command.push(TUIC_VERSION);
    command.push(TUIC_COMMAND_AUTHENTICATE);
    command.extend_from_slice(&uuid);
    command.extend_from_slice(token);
    Ok(command)
}

pub fn encode_tuic_connect_command(target: &Endpoint) -> Result<Vec<u8>, ProtocolEncodingError> {
    let mut command = Vec::with_capacity(8 + target.host.len());
    command.push(TUIC_VERSION);
    command.push(TUIC_COMMAND_CONNECT);
    encode_tuic_target(&mut command, target)?;
    Ok(command)
}

pub fn encode_tuic_packet_command(
    associate_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    target: &Endpoint,
    payload: &[u8],
) -> Result<Vec<u8>, ProtocolEncodingError> {
    if payload.len() > u16::MAX as usize {
        return Err(ProtocolEncodingError::PacketTooLong);
    }
    let mut command = Vec::with_capacity(12 + target.host.len() + payload.len());
    command.push(TUIC_VERSION);
    command.push(TUIC_COMMAND_PACKET);
    command.extend_from_slice(&associate_id.to_be_bytes());
    command.extend_from_slice(&packet_id.to_be_bytes());
    command.push(fragment_total);
    command.push(fragment_id);
    command.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encode_tuic_target(&mut command, target)?;
    command.extend_from_slice(payload);
    Ok(command)
}

pub fn encode_tuic_heartbeat_command() -> [u8; 2] {
    [TUIC_VERSION, TUIC_COMMAND_HEARTBEAT]
}

pub fn decode_tuic_packet_command(
    input: &[u8],
) -> Result<TuicPacketCommand, ProtocolDecodingError> {
    let mut offset = 0;
    let version = read_u8(input, &mut offset)?;
    if version != TUIC_VERSION {
        return Err(ProtocolDecodingError::InvalidTuicVersion(version));
    }
    let command_type = read_u8(input, &mut offset)?;
    if command_type != TUIC_COMMAND_PACKET {
        return Err(ProtocolDecodingError::InvalidTuicCommand(command_type));
    }
    let associate_id = read_u16(input, &mut offset)?;
    let packet_id = read_u16(input, &mut offset)?;
    let fragment_total = read_u8(input, &mut offset)?;
    let fragment_id = read_u8(input, &mut offset)?;
    let size = read_u16(input, &mut offset)? as usize;
    let source = decode_tuic_target(input, &mut offset)?;
    let payload_end = offset
        .checked_add(size)
        .filter(|end| *end <= input.len())
        .ok_or(ProtocolDecodingError::UnexpectedEof)?;
    let payload = input[offset..payload_end].to_vec();
    Ok(TuicPacketCommand {
        associate_id,
        packet_id,
        fragment_total,
        fragment_id,
        source,
        payload,
    })
}

pub fn decode_hy2_udp_message(input: &[u8]) -> Result<Hy2UdpMessage, ProtocolDecodingError> {
    let mut offset = 0;
    let session_id = read_u32(input, &mut offset)?;
    let packet_id = read_u16(input, &mut offset)?;
    let fragment_id = read_u8(input, &mut offset)?;
    let fragment_count = read_u8(input, &mut offset)?;
    let (address_len, consumed) = decode_quic_varint(input, offset)?;
    offset += consumed;
    let address_len = address_len as usize;
    let address_bytes = read_bytes(input, &mut offset, address_len)?;
    let address = String::from_utf8(address_bytes.to_vec())
        .map_err(|_| ProtocolDecodingError::InvalidUtf8)?;
    let address = parse_host_port_endpoint(&address)?;
    let payload = input[offset..].to_vec();
    Ok(Hy2UdpMessage {
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        address,
        payload,
    })
}

pub fn decode_hy2_tcp_response(
    input: &[u8],
) -> Result<(Hy2TcpResponse, usize), ProtocolDecodingError> {
    let Some((&status, rest)) = input.split_first() else {
        return Err(ProtocolDecodingError::UnexpectedEof);
    };
    let ok = match status {
        0x00 => true,
        0x01 => false,
        other => return Err(ProtocolDecodingError::InvalidHy2Status(other)),
    };

    let mut offset = input.len() - rest.len();
    let (message_len, consumed) = decode_quic_varint(input, offset)?;
    offset += consumed;
    let message_len = message_len as usize;
    let message_end = offset
        .checked_add(message_len)
        .filter(|end| *end <= input.len())
        .ok_or(ProtocolDecodingError::UnexpectedEof)?;
    let message = String::from_utf8(input[offset..message_end].to_vec())
        .map_err(|_| ProtocolDecodingError::InvalidUtf8)?;
    offset = message_end;

    let (padding_len, consumed) = decode_quic_varint(input, offset)?;
    offset += consumed;
    let padding_len = padding_len as usize;
    offset = offset
        .checked_add(padding_len)
        .filter(|end| *end <= input.len())
        .ok_or(ProtocolDecodingError::UnexpectedEof)?;

    Ok((Hy2TcpResponse { ok, message }, offset))
}

fn encode_quic_varint(output: &mut Vec<u8>, value: u64) {
    match value {
        0..=63 => output.push(value as u8),
        64..=16_383 => output.extend_from_slice(&(0x4000 | value as u16).to_be_bytes()),
        16_384..=1_073_741_823 => {
            output.extend_from_slice(&(0x8000_0000 | value as u32).to_be_bytes());
        }
        _ => output.extend_from_slice(&(0xc000_0000_0000_0000 | value).to_be_bytes()),
    }
}

fn decode_quic_varint(input: &[u8], offset: usize) -> Result<(u64, usize), ProtocolDecodingError> {
    let Some(&first) = input.get(offset) else {
        return Err(ProtocolDecodingError::UnexpectedEof);
    };
    let length = 1usize << (first >> 6);
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= input.len())
        .ok_or(ProtocolDecodingError::UnexpectedEof)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &input[offset + 1..end] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, length))
}

fn read_u8(input: &[u8], offset: &mut usize) -> Result<u8, ProtocolDecodingError> {
    let byte = *input
        .get(*offset)
        .ok_or(ProtocolDecodingError::UnexpectedEof)?;
    *offset += 1;
    Ok(byte)
}

fn read_u16(input: &[u8], offset: &mut usize) -> Result<u16, ProtocolDecodingError> {
    let bytes = read_bytes(input, offset, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(input: &[u8], offset: &mut usize) -> Result<u32, ProtocolDecodingError> {
    let bytes = read_bytes(input, offset, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_bytes<'a>(
    input: &'a [u8],
    offset: &mut usize,
    amount: usize,
) -> Result<&'a [u8], ProtocolDecodingError> {
    let end = offset
        .checked_add(amount)
        .filter(|end| *end <= input.len())
        .ok_or(ProtocolDecodingError::UnexpectedEof)?;
    let bytes = &input[*offset..end];
    *offset = end;
    Ok(bytes)
}

fn parse_host_port_endpoint(value: &str) -> Result<Endpoint, ProtocolDecodingError> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or(ProtocolDecodingError::InvalidEndpoint)?;
    let host = host.trim().trim_matches(['[', ']']);
    if host.is_empty() {
        return Err(ProtocolDecodingError::InvalidEndpoint);
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| ProtocolDecodingError::InvalidEndpoint)?;
    Ok(Endpoint::new(host, port))
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

fn is_tuic_credential(value: &str) -> bool {
    let Some((uuid, password)) = value.split_once(':') else {
        return false;
    };
    looks_like_uuid(uuid.trim()) && !password.trim().is_empty()
}

fn is_user_password_credential(value: &str) -> bool {
    let Some((username, password)) = value.split_once(':') else {
        return false;
    };
    !username.trim().is_empty() && !password.trim().is_empty()
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

fn encode_shadowsocks_target(
    output: &mut Vec<u8>,
    target: &Endpoint,
) -> Result<(), ProtocolEncodingError> {
    let host = target.host.trim().trim_matches(['[', ']']);
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        output.push(SHADOWSOCKS_ATYP_IPV4);
        output.extend_from_slice(&ip.octets());
        output.extend_from_slice(&target.port.to_be_bytes());
        return Ok(());
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        output.push(SHADOWSOCKS_ATYP_IPV6);
        output.extend_from_slice(&ip.octets());
        output.extend_from_slice(&target.port.to_be_bytes());
        return Ok(());
    }
    if host.is_empty() || host.len() > u8::MAX as usize {
        return Err(ProtocolEncodingError::InvalidTargetHost);
    }
    output.push(SHADOWSOCKS_ATYP_DOMAIN);
    output.push(host.len() as u8);
    output.extend_from_slice(host.as_bytes());
    output.extend_from_slice(&target.port.to_be_bytes());
    Ok(())
}

fn encode_tuic_target(
    output: &mut Vec<u8>,
    target: &Endpoint,
) -> Result<(), ProtocolEncodingError> {
    let host = target.host.trim().trim_matches(['[', ']']);
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        output.push(TUIC_ATYP_IPV4);
        output.extend_from_slice(&ip.octets());
        output.extend_from_slice(&target.port.to_be_bytes());
        return Ok(());
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        output.push(TUIC_ATYP_IPV6);
        output.extend_from_slice(&ip.octets());
        output.extend_from_slice(&target.port.to_be_bytes());
        return Ok(());
    }
    if host.is_empty() || host.len() > u8::MAX as usize {
        return Err(ProtocolEncodingError::InvalidTargetHost);
    }
    output.push(TUIC_ATYP_DOMAIN);
    output.push(host.len() as u8);
    output.extend_from_slice(host.as_bytes());
    output.extend_from_slice(&target.port.to_be_bytes());
    Ok(())
}

fn decode_tuic_target(input: &[u8], offset: &mut usize) -> Result<Endpoint, ProtocolDecodingError> {
    match read_u8(input, offset)? {
        TUIC_ATYP_NONE => Ok(Endpoint::new("", 0)),
        TUIC_ATYP_DOMAIN => {
            let length = read_u8(input, offset)? as usize;
            let domain = read_bytes(input, offset, length)?;
            let host = String::from_utf8(domain.to_vec())
                .map_err(|_| ProtocolDecodingError::InvalidUtf8)?;
            let port = read_u16(input, offset)?;
            Ok(Endpoint::new(host, port))
        }
        TUIC_ATYP_IPV4 => {
            let bytes = read_bytes(input, offset, 4)?;
            let host = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string();
            let port = read_u16(input, offset)?;
            Ok(Endpoint::new(host, port))
        }
        TUIC_ATYP_IPV6 => {
            let bytes = read_bytes(input, offset, 16)?;
            let mut octets = [0; 16];
            octets.copy_from_slice(bytes);
            let host = Ipv6Addr::from(octets).to_string();
            let port = read_u16(input, offset)?;
            Ok(Endpoint::new(host, port))
        }
        other => Err(ProtocolDecodingError::InvalidTuicAddressType(other)),
    }
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
            cipher: None,
            flow: None,
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
            cipher: None,
            flow: None,
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
            cipher: None,
            flow: None,
        };

        assert_eq!(
            profile.validate(),
            Err(ProtocolValidationError::InvalidHy2Transport)
        );
    }

    #[test]
    fn encodes_tuic_authenticate_command() {
        let token = [0x11; 32];
        let command =
            encode_tuic_authenticate_command("00112233-4455-6677-8899-aabbccddeeff", &token)
                .expect("tuic authenticate command");

        assert_eq!(command.len(), 50);
        assert_eq!(command[0], 0x05);
        assert_eq!(command[1], 0x00);
        assert_eq!(
            &command[2..18],
            &[
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]
        );
        assert_eq!(&command[18..], token);
    }

    #[test]
    fn encodes_tuic_connect_command_for_domain_target() {
        let command = encode_tuic_connect_command(&Endpoint::new("example.com", 443))
            .expect("tuic connect command");

        assert_eq!(
            command,
            [
                0x05, 0x01, 0x00, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
                b'm', 0x01, 0xbb,
            ]
        );
    }

    #[test]
    fn encodes_tuic_connect_command_for_ip_targets() {
        let ipv4 = encode_tuic_connect_command(&Endpoint::new("127.0.0.1", 8080))
            .expect("tuic ipv4 command");
        assert_eq!(ipv4, [0x05, 0x01, 0x01, 127, 0, 0, 1, 0x1f, 0x90]);

        let ipv6 =
            encode_tuic_connect_command(&Endpoint::new("[::1]", 443)).expect("tuic ipv6 command");
        assert_eq!(ipv6[0..3], [0x05, 0x01, 0x02]);
        assert_eq!(&ipv6[3..19], &Ipv6Addr::LOCALHOST.octets());
        assert_eq!(ipv6[19..21], [0x01, 0xbb]);
    }

    #[test]
    fn encodes_tuic_heartbeat_command() {
        assert_eq!(encode_tuic_heartbeat_command(), [0x05, 0x04]);
    }

    #[test]
    fn encodes_tuic_packet_command_for_udp_payload() {
        let packet = encode_tuic_packet_command(
            0x1234,
            0x5678,
            1,
            0,
            &Endpoint::new("example.com", 53),
            b"ping",
        )
        .expect("tuic UDP packet command");

        assert_eq!(
            packet,
            [
                0x05, 0x02, 0x12, 0x34, 0x56, 0x78, 0x01, 0x00, 0x00, 0x04, 0x00, 0x0b, b'e', b'x',
                b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x00, 0x35, b'p', b'i', b'n',
                b'g',
            ]
        );
    }

    #[test]
    fn decodes_tuic_packet_command_for_udp_payload() {
        let packet = decode_tuic_packet_command(&[
            0x05, 0x02, 0xab, 0xcd, 0x00, 0x07, 0x01, 0x00, 0x00, 0x04, 0x01, 127, 0, 0, 1, 0x1f,
            0x90, b'p', b'o', b'n', b'g',
        ])
        .expect("decode tuic UDP packet");

        assert_eq!(packet.associate_id, 0xabcd);
        assert_eq!(packet.packet_id, 7);
        assert_eq!(packet.fragment_total, 1);
        assert_eq!(packet.fragment_id, 0);
        assert_eq!(packet.source, Endpoint::new("127.0.0.1", 8080));
        assert_eq!(packet.payload, b"pong");
    }

    #[test]
    fn encodes_hy2_udp_message_for_udp_payload() {
        let message = encode_hy2_udp_message(
            0x01020304,
            0x0506,
            0,
            1,
            &Endpoint::new("example.com", 53),
            b"ping",
        )
        .expect("encode HY2 UDP message");

        assert_eq!(
            message,
            [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x0e, b'e', b'x', b'a', b'm', b'p',
                b'l', b'e', b'.', b'c', b'o', b'm', b':', b'5', b'3', b'p', b'i', b'n', b'g',
            ]
        );
    }

    #[test]
    fn decodes_hy2_udp_message_for_udp_payload() {
        let message = decode_hy2_udp_message(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x0c, b'1', b'2', b'7', b'.', b'0',
            b'.', b'0', b'.', b'1', b':', b'5', b'3', b'p', b'o', b'n', b'g',
        ])
        .expect("decode HY2 UDP message");

        assert_eq!(message.session_id, 0x01020304);
        assert_eq!(message.packet_id, 0x0506);
        assert_eq!(message.fragment_id, 0);
        assert_eq!(message.fragment_count, 1);
        assert_eq!(message.address, Endpoint::new("127.0.0.1", 53));
        assert_eq!(message.payload, b"pong");
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

    #[test]
    fn encodes_trojan_udp_associate_request_header_for_domain_target() {
        let header =
            encode_trojan_udp_request_header("password", &Endpoint::new("example.com", 53))
                .expect("trojan udp header");

        assert_eq!(
            &header[..56],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
        assert_eq!(&header[56..], b"\r\n\x03\x03\x0bexample.com\x005\r\n");
    }

    #[test]
    fn encodes_trojan_udp_packet_for_ipv4_target() {
        let packet = encode_trojan_udp_packet(&Endpoint::new("1.2.3.4", 53), b"ping")
            .expect("trojan udp packet");

        assert_eq!(&packet, b"\x01\x01\x02\x03\x04\x005\x00\x04\r\nping");
    }

    #[test]
    fn rejects_trojan_udp_packet_payloads_larger_than_u16() {
        let payload = vec![0u8; usize::from(u16::MAX) + 1];

        assert_eq!(
            encode_trojan_udp_packet(&Endpoint::new("1.2.3.4", 53), &payload),
            Err(ProtocolEncodingError::PacketTooLong)
        );
    }

    #[test]
    fn encodes_shadowsocks_tcp_request_header_for_domain_target() {
        let header = encode_shadowsocks_tcp_request_header(&Endpoint::new("example.com", 443))
            .expect("ss header");

        assert_eq!(&header, b"\x03\x0bexample.com\x01\xbb");
    }

    #[test]
    fn encodes_hy2_tcp_request_for_domain_target() {
        let request =
            encode_hy2_tcp_request(&Endpoint::new("example.com", 443), b"pad").expect("hy2 tcp");

        assert_eq!(
            &request, b"\x44\x01\x0fexample.com:443\x03pad",
            "HY2 TCPRequest is QUIC varint id 0x401, address, and padding"
        );
    }

    #[test]
    fn rejects_hy2_tcp_request_with_empty_target_host() {
        let error = encode_hy2_tcp_request(&Endpoint::new("", 443), b"")
            .expect_err("empty HY2 target should fail");

        assert_eq!(error, ProtocolEncodingError::InvalidTargetHost);
    }

    #[test]
    fn decodes_hy2_tcp_ok_response_and_reports_consumed_bytes() {
        let input = b"\x00\x05ready\x03padnext-bytes";

        let (response, consumed) = decode_hy2_tcp_response(input).expect("hy2 tcp response");

        assert!(response.ok);
        assert_eq!(response.message, "ready");
        assert_eq!(consumed, 11);
    }

    #[test]
    fn decodes_hy2_tcp_error_response_message() {
        let input = b"\x01\x0econnect failed\x00";

        let (response, consumed) = decode_hy2_tcp_response(input).expect("hy2 tcp response");

        assert!(!response.ok);
        assert_eq!(response.message, "connect failed");
        assert_eq!(consumed, input.len());
    }

    #[test]
    fn rejects_truncated_hy2_tcp_response() {
        let error =
            decode_hy2_tcp_response(b"\x00\x05no").expect_err("truncated response should fail");

        assert_eq!(error, ProtocolDecodingError::UnexpectedEof);
    }

    #[test]
    fn builds_hy2_auth_request_headers() {
        let headers =
            build_hy2_auth_request("secret", 0, "padding").expect("hy2 auth request headers");

        assert_eq!(headers.method, "POST");
        assert_eq!(headers.path, "/auth");
        assert_eq!(headers.host, "hysteria");
        assert_eq!(headers.auth, "secret");
        assert_eq!(headers.cc_rx, "0");
        assert_eq!(headers.padding, "padding");
    }

    #[test]
    fn accepts_only_hy2_auth_status_233() {
        assert!(is_hy2_auth_success_status(233));
        assert!(!is_hy2_auth_success_status(200));
        assert!(!is_hy2_auth_success_status(401));
    }

    #[test]
    fn rejects_empty_hy2_auth() {
        let error = build_hy2_auth_request("", 0, "").expect_err("empty HY2 auth should fail");

        assert_eq!(error, ProtocolEncodingError::InvalidPassword);
    }
}
