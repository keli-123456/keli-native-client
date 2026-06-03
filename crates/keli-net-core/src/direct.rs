use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce as AesGcmNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChachaNonce};
use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake128Reader,
};
use shadowsocks_crypto::kind::{CipherCategory, CipherKind};
use shadowsocks_crypto::v1::{openssl_bytes_to_key, Cipher};

use crate::{
    ConnectionErrorKind, DnsCache, DnsEngine, DnsResolver, RouteTarget, Socks5Address,
    Socks5Request, SystemDnsResolver,
};
use keli_protocol::{
    encode_shadowsocks_tcp_request_header, encode_trojan_tcp_request_header,
    encode_vless_tcp_request_header, Endpoint, OutboundProfile, ProtocolEncodingError,
    ProtocolValidationError, ProxyProtocol, SecurityKind, TransportKind,
};

const VMESS_VERSION: u8 = 0x01;
const VMESS_COMMAND_TCP: u8 = 0x01;
const VMESS_ATYP_IPV4: u8 = 0x01;
const VMESS_ATYP_DOMAIN: u8 = 0x02;
const VMESS_ATYP_IPV6: u8 = 0x03;
const VMESS_OPTION_CHUNK_STREAM: u8 = 0x01;
const VMESS_OPTION_CHUNK_MASKING: u8 = 0x04;
const VMESS_SECURITY_AES_128_GCM: u8 = 0x03;
const VMESS_SECURITY_CHACHA20_POLY1305: u8 = 0x04;
const VMESS_SECURITY_NONE: u8 = 0x05;
const VMESS_WRITE_CHUNK_SIZE: usize = 15_000;
const VMESS_KDF_ROOT: &[u8] = b"VMess AEAD KDF";
const VMESS_AUTH_ID_KEY: &[u8] = b"AES Auth ID Encryption";
const VMESS_HEADER_LENGTH_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const VMESS_HEADER_LENGTH_NONCE: &[u8] = b"VMess Header AEAD Nonce_Length";
const VMESS_HEADER_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
const VMESS_HEADER_PAYLOAD_NONCE: &[u8] = b"VMess Header AEAD Nonce";
const VMESS_RESPONSE_HEADER_LENGTH_KEY: &[u8] = b"AEAD Resp Header Len Key";
const VMESS_RESPONSE_HEADER_LENGTH_IV: &[u8] = b"AEAD Resp Header Len IV";
const VMESS_RESPONSE_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const VMESS_RESPONSE_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";
const VMESS_CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const HTTPUPGRADE_HEADER_LIMIT: usize = 16 * 1024;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpRelayResponse {
    pub source: SocketAddr,
    pub payload: Vec<u8>,
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

pub struct DirectUdpConnector;

impl DirectUdpConnector {
    pub fn relay_datagram(
        target: &OutboundTarget,
        payload: &[u8],
        timeout: Duration,
    ) -> io::Result<UdpRelayResponse> {
        let mut dns = DnsEngine::new(SystemDnsResolver, DnsCache::new(Duration::from_secs(60)));
        Self::relay_datagram_with_dns(target, payload, timeout, &mut dns)
    }

    pub fn relay_datagram_with_dns<R: DnsResolver>(
        target: &OutboundTarget,
        payload: &[u8],
        timeout: Duration,
        dns: &mut DnsEngine<R>,
    ) -> io::Result<UdpRelayResponse> {
        let addresses = dns
            .resolve(&target.host, target.port)
            .map_err(|error| io::Error::new(io::ErrorKind::AddrNotAvailable, error))?
            .into_iter()
            .map(|address| SocketAddr::new(address.ip, address.port));
        let mut last_error = None;
        for address in addresses {
            let bind_addr = match address {
                SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            };
            let socket = match UdpSocket::bind(bind_addr) {
                Ok(socket) => socket,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            socket.set_read_timeout(Some(timeout))?;
            if let Err(error) = socket.send_to(payload, address) {
                last_error = Some(error);
                continue;
            }

            let mut response = vec![0; 65_535];
            match socket.recv_from(&mut response) {
                Ok((size, source)) => {
                    response.truncate(size);
                    return Ok(UdpRelayResponse {
                        source,
                        payload: response,
                    });
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
    trojan_httpupgrade_tags: HashMap<String, TrojanHttpUpgradeOutbound>,
    trojan_tls_httpupgrade_tags: HashMap<String, TrojanTlsHttpUpgradeOutbound>,
    trojan_grpc_tags: HashMap<String, TrojanGrpcOutbound>,
    trojan_tls_grpc_tags: HashMap<String, TrojanTlsGrpcOutbound>,
    trojan_h2_tags: HashMap<String, TrojanH2Outbound>,
    trojan_tls_h2_tags: HashMap<String, TrojanTlsH2Outbound>,
    trojan_quic_tags: HashMap<String, TrojanQuicOutbound>,
    vless_tcp_tags: HashMap<String, VlessTcpOutbound>,
    vless_tls_tcp_tags: HashMap<String, VlessTlsTcpOutbound>,
    vless_ws_tags: HashMap<String, VlessWsOutbound>,
    vless_tls_ws_tags: HashMap<String, VlessTlsWsOutbound>,
    vless_httpupgrade_tags: HashMap<String, VlessHttpUpgradeOutbound>,
    vless_tls_httpupgrade_tags: HashMap<String, VlessTlsHttpUpgradeOutbound>,
    vless_grpc_tags: HashMap<String, VlessGrpcOutbound>,
    vless_tls_grpc_tags: HashMap<String, VlessTlsGrpcOutbound>,
    vless_h2_tags: HashMap<String, VlessH2Outbound>,
    vless_tls_h2_tags: HashMap<String, VlessTlsH2Outbound>,
    vless_quic_tags: HashMap<String, VlessQuicOutbound>,
    vmess_tcp_tags: HashMap<String, VmessTcpOutbound>,
    vmess_tls_tcp_tags: HashMap<String, VmessTlsTcpOutbound>,
    vmess_ws_tags: HashMap<String, VmessWsOutbound>,
    vmess_tls_ws_tags: HashMap<String, VmessTlsWsOutbound>,
    vmess_httpupgrade_tags: HashMap<String, VmessHttpUpgradeOutbound>,
    vmess_tls_httpupgrade_tags: HashMap<String, VmessTlsHttpUpgradeOutbound>,
    vmess_grpc_tags: HashMap<String, VmessGrpcOutbound>,
    vmess_tls_grpc_tags: HashMap<String, VmessTlsGrpcOutbound>,
    vmess_h2_tags: HashMap<String, VmessH2Outbound>,
    vmess_tls_h2_tags: HashMap<String, VmessTlsH2Outbound>,
    vmess_quic_tags: HashMap<String, VmessQuicOutbound>,
    shadowsocks_tcp_tags: HashMap<String, ShadowsocksTcpOutbound>,
    anytls_tls_tcp_tags: HashMap<String, AnyTlsTlsTcpOutbound>,
    naive_h2_tcp_tags: HashMap<String, crate::NaiveH2TcpOutbound>,
    mieru_tcp_tags: HashMap<String, crate::MieruTcpOutbound>,
    hy2_tags: HashMap<String, Hy2Outbound>,
    tuic_tags: HashMap<String, TuicOutbound>,
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
            cipher,
            flow,
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
            (
                ProxyProtocol::Trojan,
                TransportKind::HttpUpgrade { path, host },
                SecurityKind::None,
            ) => {
                let host = host.unwrap_or_else(|| endpoint.host.clone());
                self.add_trojan_httpupgrade(
                    tag,
                    TrojanHttpUpgradeOutbound::new(endpoint, host, path, credential),
                );
                Ok(())
            }
            (
                ProxyProtocol::Trojan,
                TransportKind::HttpUpgrade { path, host },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let host = host.unwrap_or_else(|| endpoint.host.clone());
                let sni = sni.unwrap_or_else(|| host.clone());
                self.add_trojan_tls_httpupgrade(
                    tag,
                    TrojanTlsHttpUpgradeOutbound::new(
                        endpoint,
                        host,
                        path,
                        credential,
                        sni,
                        skip_verify,
                    ),
                );
                Ok(())
            }
            (ProxyProtocol::Trojan, TransportKind::Grpc { service_name }, SecurityKind::None) => {
                let host = endpoint.host.clone();
                self.add_trojan_grpc(
                    tag,
                    TrojanGrpcOutbound::new(endpoint, host, service_name, credential),
                );
                Ok(())
            }
            (
                ProxyProtocol::Trojan,
                TransportKind::Grpc { service_name },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                let host = sni.clone();
                self.add_trojan_tls_grpc(
                    tag,
                    TrojanTlsGrpcOutbound::new(
                        endpoint,
                        host,
                        service_name,
                        credential,
                        sni,
                        skip_verify,
                    ),
                );
                Ok(())
            }
            (ProxyProtocol::Trojan, TransportKind::Http2 { path, host }, SecurityKind::None) => {
                let host = host.unwrap_or_else(|| endpoint.host.clone());
                self.add_trojan_h2(tag, TrojanH2Outbound::new(endpoint, host, path, credential));
                Ok(())
            }
            (
                ProxyProtocol::Trojan,
                TransportKind::Http2 { path, host },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                let host = host.unwrap_or_else(|| sni.clone());
                self.add_trojan_tls_h2(
                    tag,
                    TrojanTlsH2Outbound::new(endpoint, host, path, credential, sni, skip_verify),
                );
                Ok(())
            }
            (
                ProxyProtocol::Trojan,
                TransportKind::Quic {
                    security: quic_security,
                    key,
                    header_type,
                },
                SecurityKind::None,
            ) => {
                self.add_trojan_quic(
                    tag,
                    TrojanQuicOutbound::new(
                        endpoint,
                        credential,
                        crate::LEGACY_QUIC_INTERNAL_SERVER_NAME,
                        true,
                        crate::LegacyQuicTransportConfig::new(quic_security, key, header_type),
                    ),
                );
                Ok(())
            }
            (
                ProxyProtocol::Trojan,
                TransportKind::Quic {
                    security: quic_security,
                    key,
                    header_type,
                },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                self.add_trojan_quic(
                    tag,
                    TrojanQuicOutbound::new(
                        endpoint,
                        credential,
                        sni,
                        skip_verify,
                        crate::LegacyQuicTransportConfig::new(quic_security, key, header_type),
                    ),
                );
                Ok(())
            }
            (ProxyProtocol::Vmess, TransportKind::Tcp, SecurityKind::None) => {
                let vmess_security = vmess_security_from_profile_cipher(&tag, cipher.as_deref())?;
                self.add_vmess_tcp(
                    tag,
                    VmessTcpOutbound::new_with_security(endpoint, credential, vmess_security),
                );
                Ok(())
            }
            (ProxyProtocol::Vmess, TransportKind::Tcp, SecurityKind::Tls { sni, skip_verify }) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                let vmess_security = vmess_security_from_profile_cipher(&tag, cipher.as_deref())?;
                self.add_vmess_tls_tcp(
                    tag,
                    VmessTlsTcpOutbound::new_with_security(
                        endpoint,
                        credential,
                        sni,
                        skip_verify,
                        vmess_security,
                    ),
                );
                Ok(())
            }
            (ProxyProtocol::Vmess, TransportKind::WebSocket { path, host }, SecurityKind::None) => {
                let host = host.unwrap_or_else(|| endpoint.host.clone());
                let vmess_security = vmess_security_from_profile_cipher(&tag, cipher.as_deref())?;
                self.add_vmess_ws(
                    tag,
                    VmessWsOutbound::new_with_security(
                        endpoint,
                        host,
                        path,
                        credential,
                        vmess_security,
                    ),
                );
                Ok(())
            }
            (
                ProxyProtocol::Vmess,
                TransportKind::WebSocket { path, host },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let host = host.unwrap_or_else(|| endpoint.host.clone());
                let sni = sni.unwrap_or_else(|| host.clone());
                let vmess_security = vmess_security_from_profile_cipher(&tag, cipher.as_deref())?;
                self.add_vmess_tls_ws(
                    tag,
                    VmessTlsWsOutbound::new_with_security(
                        endpoint,
                        host,
                        path,
                        credential,
                        sni,
                        skip_verify,
                        vmess_security,
                    ),
                );
                Ok(())
            }
            (
                ProxyProtocol::Vmess,
                TransportKind::HttpUpgrade { path, host },
                SecurityKind::None,
            ) => {
                let host = host.unwrap_or_else(|| endpoint.host.clone());
                let vmess_security = vmess_security_from_profile_cipher(&tag, cipher.as_deref())?;
                self.add_vmess_httpupgrade(
                    tag,
                    VmessHttpUpgradeOutbound::new_with_security(
                        endpoint,
                        host,
                        path,
                        credential,
                        vmess_security,
                    ),
                );
                Ok(())
            }
            (
                ProxyProtocol::Vmess,
                TransportKind::HttpUpgrade { path, host },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let host = host.unwrap_or_else(|| endpoint.host.clone());
                let sni = sni.unwrap_or_else(|| host.clone());
                let vmess_security = vmess_security_from_profile_cipher(&tag, cipher.as_deref())?;
                self.add_vmess_tls_httpupgrade(
                    tag,
                    VmessTlsHttpUpgradeOutbound::new_with_security(
                        endpoint,
                        host,
                        path,
                        credential,
                        sni,
                        skip_verify,
                        vmess_security,
                    ),
                );
                Ok(())
            }
            (ProxyProtocol::Vmess, TransportKind::Grpc { service_name }, SecurityKind::None) => {
                let host = endpoint.host.clone();
                let vmess_security = vmess_security_from_profile_cipher(&tag, cipher.as_deref())?;
                self.add_vmess_grpc(
                    tag,
                    VmessGrpcOutbound::new_with_security(
                        endpoint,
                        host,
                        service_name,
                        credential,
                        vmess_security,
                    ),
                );
                Ok(())
            }
            (
                ProxyProtocol::Vmess,
                TransportKind::Grpc { service_name },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                let host = sni.clone();
                let vmess_security = vmess_security_from_profile_cipher(&tag, cipher.as_deref())?;
                self.add_vmess_tls_grpc(
                    tag,
                    VmessTlsGrpcOutbound::new_with_security(
                        endpoint,
                        host,
                        service_name,
                        credential,
                        sni,
                        skip_verify,
                        vmess_security,
                    ),
                );
                Ok(())
            }
            (ProxyProtocol::Vmess, TransportKind::Http2 { path, host }, SecurityKind::None) => {
                let host = host.unwrap_or_else(|| endpoint.host.clone());
                let vmess_security = vmess_security_from_profile_cipher(&tag, cipher.as_deref())?;
                self.add_vmess_h2(
                    tag,
                    VmessH2Outbound::new_with_security(
                        endpoint,
                        host,
                        path,
                        credential,
                        vmess_security,
                    ),
                );
                Ok(())
            }
            (
                ProxyProtocol::Vmess,
                TransportKind::Http2 { path, host },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                let host = host.unwrap_or_else(|| sni.clone());
                let vmess_security = vmess_security_from_profile_cipher(&tag, cipher.as_deref())?;
                self.add_vmess_tls_h2(
                    tag,
                    VmessTlsH2Outbound::new_with_security(
                        endpoint,
                        host,
                        path,
                        credential,
                        sni,
                        skip_verify,
                        vmess_security,
                    ),
                );
                Ok(())
            }
            (
                ProxyProtocol::Vmess,
                TransportKind::Quic {
                    security: quic_security,
                    key,
                    header_type,
                },
                SecurityKind::None,
            ) => {
                let vmess_security = vmess_security_from_profile_cipher(&tag, cipher.as_deref())?;
                self.add_vmess_quic(
                    tag,
                    VmessQuicOutbound::new_with_security(
                        endpoint,
                        credential,
                        crate::LEGACY_QUIC_INTERNAL_SERVER_NAME,
                        true,
                        crate::LegacyQuicTransportConfig::new(quic_security, key, header_type),
                        vmess_security,
                    ),
                );
                Ok(())
            }
            (
                ProxyProtocol::Vmess,
                TransportKind::Quic {
                    security: quic_security,
                    key,
                    header_type,
                },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                let vmess_security = vmess_security_from_profile_cipher(&tag, cipher.as_deref())?;
                self.add_vmess_quic(
                    tag,
                    VmessQuicOutbound::new_with_security(
                        endpoint,
                        credential,
                        sni,
                        skip_verify,
                        crate::LegacyQuicTransportConfig::new(quic_security, key, header_type),
                        vmess_security,
                    ),
                );
                Ok(())
            }
            (ProxyProtocol::Vless, TransportKind::Tcp, SecurityKind::None) => {
                self.add_vless_tcp(tag, VlessTcpOutbound::new(endpoint, credential, flow));
                Ok(())
            }
            (ProxyProtocol::Vless, TransportKind::Tcp, SecurityKind::Tls { sni, skip_verify }) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                self.add_vless_tls_tcp(
                    tag,
                    VlessTlsTcpOutbound::new(endpoint, credential, flow, sni, skip_verify),
                );
                Ok(())
            }
            (ProxyProtocol::Vless, TransportKind::WebSocket { path, host }, SecurityKind::None) => {
                let host = host.unwrap_or_else(|| endpoint.host.clone());
                self.add_vless_ws(
                    tag,
                    VlessWsOutbound::new(endpoint, host, path, credential, flow),
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
                        flow,
                        sni,
                        skip_verify,
                    ),
                );
                Ok(())
            }
            (
                ProxyProtocol::Vless,
                TransportKind::HttpUpgrade { path, host },
                SecurityKind::None,
            ) => {
                let host = host.unwrap_or_else(|| endpoint.host.clone());
                self.add_vless_httpupgrade(
                    tag,
                    VlessHttpUpgradeOutbound::new(endpoint, host, path, credential, flow),
                );
                Ok(())
            }
            (
                ProxyProtocol::Vless,
                TransportKind::HttpUpgrade { path, host },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let host = host.unwrap_or_else(|| endpoint.host.clone());
                let sni = sni.unwrap_or_else(|| host.clone());
                self.add_vless_tls_httpupgrade(
                    tag,
                    VlessTlsHttpUpgradeOutbound::new(
                        endpoint,
                        host,
                        path,
                        credential,
                        flow,
                        sni,
                        skip_verify,
                    ),
                );
                Ok(())
            }
            (ProxyProtocol::Vless, TransportKind::Grpc { service_name }, SecurityKind::None) => {
                let host = endpoint.host.clone();
                self.add_vless_grpc(
                    tag,
                    VlessGrpcOutbound::new(endpoint, host, service_name, credential, flow),
                );
                Ok(())
            }
            (
                ProxyProtocol::Vless,
                TransportKind::Grpc { service_name },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                let host = sni.clone();
                self.add_vless_tls_grpc(
                    tag,
                    VlessTlsGrpcOutbound::new(
                        endpoint,
                        host,
                        service_name,
                        credential,
                        flow,
                        sni,
                        skip_verify,
                    ),
                );
                Ok(())
            }
            (ProxyProtocol::Vless, TransportKind::Http2 { path, host }, SecurityKind::None) => {
                let host = host.unwrap_or_else(|| endpoint.host.clone());
                self.add_vless_h2(
                    tag,
                    VlessH2Outbound::new(endpoint, host, path, credential, flow),
                );
                Ok(())
            }
            (
                ProxyProtocol::Vless,
                TransportKind::Http2 { path, host },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                let host = host.unwrap_or_else(|| sni.clone());
                self.add_vless_tls_h2(
                    tag,
                    VlessTlsH2Outbound::new(
                        endpoint,
                        host,
                        path,
                        credential,
                        flow,
                        sni,
                        skip_verify,
                    ),
                );
                Ok(())
            }
            (
                ProxyProtocol::Vless,
                TransportKind::Quic {
                    security: quic_security,
                    key,
                    header_type,
                },
                SecurityKind::None,
            ) => {
                self.add_vless_quic(
                    tag,
                    VlessQuicOutbound::new(
                        endpoint,
                        credential,
                        flow,
                        crate::LEGACY_QUIC_INTERNAL_SERVER_NAME,
                        true,
                        crate::LegacyQuicTransportConfig::new(quic_security, key, header_type),
                    ),
                );
                Ok(())
            }
            (
                ProxyProtocol::Vless,
                TransportKind::Quic {
                    security: quic_security,
                    key,
                    header_type,
                },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                self.add_vless_quic(
                    tag,
                    VlessQuicOutbound::new(
                        endpoint,
                        credential,
                        flow,
                        sni,
                        skip_verify,
                        crate::LegacyQuicTransportConfig::new(quic_security, key, header_type),
                    ),
                );
                Ok(())
            }
            (ProxyProtocol::Shadowsocks, TransportKind::Tcp, SecurityKind::None) => {
                let cipher = cipher.ok_or_else(|| {
                    OutboundProfileError::MissingShadowsocksCipher { tag: tag.clone() }
                })?;
                self.add_shadowsocks_tcp(
                    tag,
                    ShadowsocksTcpOutbound::new(endpoint, cipher, credential),
                );
                Ok(())
            }
            (ProxyProtocol::AnyTls, TransportKind::Tcp, SecurityKind::Tls { sni, skip_verify }) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                self.add_anytls_tls_tcp(
                    tag,
                    AnyTlsTlsTcpOutbound::new(endpoint, credential, sni, skip_verify),
                );
                Ok(())
            }
            (ProxyProtocol::Naive, TransportKind::Tcp, SecurityKind::Tls { sni, skip_verify }) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                self.add_naive_h2_tcp(
                    tag,
                    crate::NaiveH2TcpOutbound::new(endpoint, credential, sni, skip_verify),
                );
                Ok(())
            }
            (ProxyProtocol::Mieru, TransportKind::Tcp, SecurityKind::None) => {
                let (username, password) =
                    credential
                        .split_once(':')
                        .ok_or_else(|| OutboundProfileError::Validation {
                            tag: tag.clone(),
                            source: ProtocolValidationError::InvalidMieruCredential,
                        })?;
                self.add_mieru_tcp(
                    tag,
                    crate::MieruTcpOutbound::new(endpoint, username, password),
                );
                Ok(())
            }
            (
                ProxyProtocol::Hy2,
                TransportKind::Quic { .. },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                self.add_hy2(
                    tag,
                    Hy2Outbound::new(endpoint, credential, sni, skip_verify),
                );
                Ok(())
            }
            (
                ProxyProtocol::Tuic,
                TransportKind::Quic { .. },
                SecurityKind::Tls { sni, skip_verify },
            ) => {
                let sni = sni.unwrap_or_else(|| endpoint.host.clone());
                let (uuid, password) = split_tuic_credential(&credential).ok_or_else(|| {
                    OutboundProfileError::Validation {
                        tag: tag.clone(),
                        source: ProtocolValidationError::InvalidTuicCredential,
                    }
                })?;
                self.add_tuic(
                    tag,
                    TuicOutbound::new(endpoint, uuid, password, sni, skip_verify),
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

    pub fn add_trojan_httpupgrade(
        &mut self,
        tag: impl Into<String>,
        outbound: TrojanHttpUpgradeOutbound,
    ) {
        self.trojan_httpupgrade_tags.insert(tag.into(), outbound);
    }

    pub fn add_trojan_tls_httpupgrade(
        &mut self,
        tag: impl Into<String>,
        outbound: TrojanTlsHttpUpgradeOutbound,
    ) {
        self.trojan_tls_httpupgrade_tags
            .insert(tag.into(), outbound);
    }

    pub fn add_trojan_grpc(&mut self, tag: impl Into<String>, outbound: TrojanGrpcOutbound) {
        self.trojan_grpc_tags.insert(tag.into(), outbound);
    }

    pub fn add_trojan_tls_grpc(&mut self, tag: impl Into<String>, outbound: TrojanTlsGrpcOutbound) {
        self.trojan_tls_grpc_tags.insert(tag.into(), outbound);
    }

    pub fn add_trojan_h2(&mut self, tag: impl Into<String>, outbound: TrojanH2Outbound) {
        self.trojan_h2_tags.insert(tag.into(), outbound);
    }

    pub fn add_trojan_tls_h2(&mut self, tag: impl Into<String>, outbound: TrojanTlsH2Outbound) {
        self.trojan_tls_h2_tags.insert(tag.into(), outbound);
    }

    pub fn add_trojan_quic(&mut self, tag: impl Into<String>, outbound: TrojanQuicOutbound) {
        self.trojan_quic_tags.insert(tag.into(), outbound);
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

    pub fn add_vless_httpupgrade(
        &mut self,
        tag: impl Into<String>,
        outbound: VlessHttpUpgradeOutbound,
    ) {
        self.vless_httpupgrade_tags.insert(tag.into(), outbound);
    }

    pub fn add_vless_tls_httpupgrade(
        &mut self,
        tag: impl Into<String>,
        outbound: VlessTlsHttpUpgradeOutbound,
    ) {
        self.vless_tls_httpupgrade_tags.insert(tag.into(), outbound);
    }

    pub fn add_vless_grpc(&mut self, tag: impl Into<String>, outbound: VlessGrpcOutbound) {
        self.vless_grpc_tags.insert(tag.into(), outbound);
    }

    pub fn add_vless_tls_grpc(&mut self, tag: impl Into<String>, outbound: VlessTlsGrpcOutbound) {
        self.vless_tls_grpc_tags.insert(tag.into(), outbound);
    }

    pub fn add_vless_h2(&mut self, tag: impl Into<String>, outbound: VlessH2Outbound) {
        self.vless_h2_tags.insert(tag.into(), outbound);
    }

    pub fn add_vless_tls_h2(&mut self, tag: impl Into<String>, outbound: VlessTlsH2Outbound) {
        self.vless_tls_h2_tags.insert(tag.into(), outbound);
    }

    pub fn add_vless_quic(&mut self, tag: impl Into<String>, outbound: VlessQuicOutbound) {
        self.vless_quic_tags.insert(tag.into(), outbound);
    }

    pub fn add_vmess_tcp(&mut self, tag: impl Into<String>, outbound: VmessTcpOutbound) {
        self.vmess_tcp_tags.insert(tag.into(), outbound);
    }

    pub fn add_vmess_tls_tcp(&mut self, tag: impl Into<String>, outbound: VmessTlsTcpOutbound) {
        self.vmess_tls_tcp_tags.insert(tag.into(), outbound);
    }

    pub fn add_vmess_ws(&mut self, tag: impl Into<String>, outbound: VmessWsOutbound) {
        self.vmess_ws_tags.insert(tag.into(), outbound);
    }

    pub fn add_vmess_tls_ws(&mut self, tag: impl Into<String>, outbound: VmessTlsWsOutbound) {
        self.vmess_tls_ws_tags.insert(tag.into(), outbound);
    }

    pub fn add_vmess_httpupgrade(
        &mut self,
        tag: impl Into<String>,
        outbound: VmessHttpUpgradeOutbound,
    ) {
        self.vmess_httpupgrade_tags.insert(tag.into(), outbound);
    }

    pub fn add_vmess_tls_httpupgrade(
        &mut self,
        tag: impl Into<String>,
        outbound: VmessTlsHttpUpgradeOutbound,
    ) {
        self.vmess_tls_httpupgrade_tags.insert(tag.into(), outbound);
    }

    pub fn add_vmess_grpc(&mut self, tag: impl Into<String>, outbound: VmessGrpcOutbound) {
        self.vmess_grpc_tags.insert(tag.into(), outbound);
    }

    pub fn add_vmess_tls_grpc(&mut self, tag: impl Into<String>, outbound: VmessTlsGrpcOutbound) {
        self.vmess_tls_grpc_tags.insert(tag.into(), outbound);
    }

    pub fn add_vmess_h2(&mut self, tag: impl Into<String>, outbound: VmessH2Outbound) {
        self.vmess_h2_tags.insert(tag.into(), outbound);
    }

    pub fn add_vmess_tls_h2(&mut self, tag: impl Into<String>, outbound: VmessTlsH2Outbound) {
        self.vmess_tls_h2_tags.insert(tag.into(), outbound);
    }

    pub fn add_vmess_quic(&mut self, tag: impl Into<String>, outbound: VmessQuicOutbound) {
        self.vmess_quic_tags.insert(tag.into(), outbound);
    }

    pub fn add_shadowsocks_tcp(
        &mut self,
        tag: impl Into<String>,
        outbound: ShadowsocksTcpOutbound,
    ) {
        self.shadowsocks_tcp_tags.insert(tag.into(), outbound);
    }

    pub fn add_anytls_tls_tcp(&mut self, tag: impl Into<String>, outbound: AnyTlsTlsTcpOutbound) {
        self.anytls_tls_tcp_tags.insert(tag.into(), outbound);
    }

    pub fn add_naive_h2_tcp(
        &mut self,
        tag: impl Into<String>,
        outbound: crate::NaiveH2TcpOutbound,
    ) {
        self.naive_h2_tcp_tags.insert(tag.into(), outbound);
    }

    pub fn add_mieru_tcp(&mut self, tag: impl Into<String>, outbound: crate::MieruTcpOutbound) {
        self.mieru_tcp_tags.insert(tag.into(), outbound);
    }

    pub fn add_hy2(&mut self, tag: impl Into<String>, outbound: Hy2Outbound) {
        self.hy2_tags.insert(tag.into(), outbound);
    }

    pub fn add_tuic(&mut self, tag: impl Into<String>, outbound: TuicOutbound) {
        self.tuic_tags.insert(tag.into(), outbound);
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
        } else if let Some(outbound) = self.trojan_httpupgrade_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.trojan_tls_httpupgrade_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.trojan_grpc_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.trojan_tls_grpc_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.trojan_h2_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.trojan_tls_h2_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.trojan_quic_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_tcp_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_tls_tcp_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_ws_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_tls_ws_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_httpupgrade_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_tls_httpupgrade_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_grpc_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_tls_grpc_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_h2_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_tls_h2_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vless_quic_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vmess_tcp_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vmess_tls_tcp_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vmess_ws_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vmess_tls_ws_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vmess_httpupgrade_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vmess_tls_httpupgrade_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vmess_grpc_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vmess_tls_grpc_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vmess_h2_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vmess_tls_h2_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.vmess_quic_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.shadowsocks_tcp_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.anytls_tls_tcp_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.naive_h2_tcp_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.mieru_tcp_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.hy2_tags.get(tag) {
            outbound.connect(target, timeout)
        } else if let Some(outbound) = self.tuic_tags.get(tag) {
            outbound.connect(target, timeout)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound tag is not registered: {tag}"),
            ))
        }
    }

    pub fn relay_udp_datagram(
        &self,
        tag: &str,
        target: &OutboundTarget,
        payload: &[u8],
        timeout: Duration,
    ) -> io::Result<UdpRelayResponse> {
        if self.direct_tags.contains(tag) {
            DirectUdpConnector::relay_datagram(target, payload, timeout)
        } else if let Some(outbound) = self.shadowsocks_tcp_tags.get(tag) {
            outbound.relay_udp_datagram(target, payload, timeout)
        } else if let Some(outbound) = self.hy2_tags.get(tag) {
            outbound.relay_udp_datagram(target, payload, timeout)
        } else if let Some(outbound) = self.tuic_tags.get(tag) {
            outbound.relay_udp_datagram(target, payload, timeout)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound tag does not support UDP relay yet: {tag}"),
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
    MissingShadowsocksCipher {
        tag: String,
    },
    UnsupportedVmessCipher {
        tag: String,
        cipher: String,
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
            Self::MissingShadowsocksCipher { tag } => {
                write!(f, "outbound profile {tag} shadowsocks cipher is missing")
            }
            Self::UnsupportedVmessCipher { tag, cipher } => {
                write!(f, "outbound profile {tag} vmess cipher is unsupported: {cipher}")
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

fn connect_httpupgrade_client<S: Read + Write>(
    mut stream: S,
    host: &str,
    path: &str,
) -> io::Result<S> {
    let path = path.trim();
    let path = if path.is_empty() { "/" } else { path };
    let host = host.trim();
    if host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTPUpgrade host is required",
        ));
    }
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let response = read_httpupgrade_response(&mut stream)?;
    validate_httpupgrade_response(&response)?;
    Ok(stream)
}

fn read_httpupgrade_response(stream: &mut impl Read) -> io::Result<String> {
    let mut bytes = Vec::new();
    let mut byte = [0; 1];
    while bytes.len() < HTTPUPGRADE_HEADER_LIMIT {
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTPUpgrade response header is too large",
    ))
}

fn validate_httpupgrade_response(response: &str) -> io::Result<()> {
    let mut lines = response.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if !status.contains(" 101 ") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTPUpgrade server did not switch protocols",
        ));
    }
    let mut saw_upgrade = false;
    let mut saw_connection = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("Upgrade") && value.eq_ignore_ascii_case("websocket") {
            saw_upgrade = true;
        } else if name.eq_ignore_ascii_case("Connection")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
        {
            saw_connection = true;
        }
    }
    if saw_upgrade && saw_connection {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTPUpgrade response is invalid",
        ))
    }
}

fn tls_client_config(skip_verify: bool) -> io::Result<Arc<rustls::ClientConfig>> {
    tls_client_config_with_alpn(skip_verify, Vec::new())
}

pub(crate) fn tls_client_config_with_alpn(
    skip_verify: bool,
    alpn_protocols: Vec<Vec<u8>>,
) -> io::Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut config = if skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(InsecureServerVerifier::new(provider))
            .with_no_client_auth()
    } else {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = alpn_protocols;
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
pub struct VlessHttpUpgradeOutbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub uuid: String,
    pub flow: Option<String>,
}

impl VlessHttpUpgradeOutbound {
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
        let mut stream = connect_httpupgrade_client(stream, &self.host, &self.path)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_vless_tcp_request_header(&self.uuid, &target, self.flow.as_deref())
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        read_vless_response_header_from_stream(&mut stream)?;
        Ok(OutboundConnection::Tcp(stream))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessTlsHttpUpgradeOutbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub uuid: String,
    pub flow: Option<String>,
    pub sni: String,
    pub skip_verify: bool,
}

impl VlessTlsHttpUpgradeOutbound {
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
        let mut stream = connect_httpupgrade_client(stream, &self.host, &self.path)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_vless_tcp_request_header(&self.uuid, &target, self.flow.as_deref())
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        read_vless_response_header_from_stream(&mut stream)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessGrpcOutbound {
    pub server: Endpoint,
    pub host: String,
    pub service_name: Option<String>,
    pub uuid: String,
    pub flow: Option<String>,
}

impl VlessGrpcOutbound {
    pub fn new(
        server: Endpoint,
        host: impl Into<String>,
        service_name: Option<String>,
        uuid: impl Into<String>,
        flow: Option<String>,
    ) -> Self {
        Self {
            server,
            host: host.into(),
            service_name,
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
        let mut stream =
            crate::GrpcTcpStream::connect_plain(stream, &self.host, self.service_name.as_deref())?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_vless_tcp_request_header(&self.uuid, &target, self.flow.as_deref())
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        read_vless_response_header_from_stream(&mut stream)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessTlsGrpcOutbound {
    pub server: Endpoint,
    pub host: String,
    pub service_name: Option<String>,
    pub uuid: String,
    pub flow: Option<String>,
    pub sni: String,
    pub skip_verify: bool,
}

impl VlessTlsGrpcOutbound {
    pub fn new(
        server: Endpoint,
        host: impl Into<String>,
        service_name: Option<String>,
        uuid: impl Into<String>,
        flow: Option<String>,
        sni: impl Into<String>,
        skip_verify: bool,
    ) -> Self {
        Self {
            server,
            host: host.into(),
            service_name,
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
        let mut stream = crate::GrpcTcpStream::connect_tls(
            stream,
            &self.sni,
            self.skip_verify,
            &self.host,
            self.service_name.as_deref(),
        )?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_vless_tcp_request_header(&self.uuid, &target, self.flow.as_deref())
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        read_vless_response_header_from_stream(&mut stream)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessH2Outbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub uuid: String,
    pub flow: Option<String>,
}

impl VlessH2Outbound {
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
        let mut stream = crate::Http2TcpStream::connect_plain(stream, &self.host, &self.path)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_vless_tcp_request_header(&self.uuid, &target, self.flow.as_deref())
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        read_vless_response_header_from_stream(&mut stream)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessTlsH2Outbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub uuid: String,
    pub flow: Option<String>,
    pub sni: String,
    pub skip_verify: bool,
}

impl VlessTlsH2Outbound {
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
        let mut stream = crate::Http2TcpStream::connect_tls(
            stream,
            &self.sni,
            self.skip_verify,
            &self.host,
            &self.path,
        )?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_vless_tcp_request_header(&self.uuid, &target, self.flow.as_deref())
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        read_vless_response_header_from_stream(&mut stream)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessQuicOutbound {
    pub server: Endpoint,
    pub uuid: String,
    pub flow: Option<String>,
    pub sni: String,
    pub skip_verify: bool,
    pub transport: crate::LegacyQuicTransportConfig,
}

impl VlessQuicOutbound {
    pub fn new(
        server: Endpoint,
        uuid: impl Into<String>,
        flow: Option<String>,
        sni: impl Into<String>,
        skip_verify: bool,
        transport: crate::LegacyQuicTransportConfig,
    ) -> Self {
        Self {
            server,
            uuid: uuid.into(),
            flow,
            sni: sni.into(),
            skip_verify,
            transport,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let mut stream = connect_legacy_quic_stream(
            &self.server,
            &self.sni,
            self.skip_verify,
            &self.transport,
            timeout,
        )?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_vless_tcp_request_header(&self.uuid, &target, self.flow.as_deref())
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        read_vless_response_header_from_stream(&mut stream)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowsocksTcpOutbound {
    pub server: Endpoint,
    pub cipher: String,
    pub password: String,
}

impl ShadowsocksTcpOutbound {
    pub fn new(server: Endpoint, cipher: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            server,
            cipher: cipher.into(),
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
        let cipher_kind = shadowsocks_cipher_kind(&self.cipher)?;
        let key = shadowsocks_key(cipher_kind, &self.password);
        let mut salt = vec![0; cipher_kind.salt_len()];
        rand::thread_rng().fill_bytes(&mut salt);
        stream.write_all(&salt)?;
        let encrypt_cipher = Cipher::new(cipher_kind, &key, &salt);
        let mut stream = ShadowsocksTcpStream {
            inner: stream,
            cipher_kind,
            key,
            encrypt_cipher,
            decrypt_cipher: None,
            read_buffer: Vec::new(),
            read_offset: 0,
        };
        let target = Endpoint::new(target.host.clone(), target.port);
        let header =
            encode_shadowsocks_tcp_request_header(&target).map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }

    pub fn relay_udp_datagram(
        &self,
        target: &OutboundTarget,
        payload: &[u8],
        timeout: Duration,
    ) -> io::Result<UdpRelayResponse> {
        let cipher_kind = shadowsocks_cipher_kind(&self.cipher)?;
        let key = shadowsocks_key(cipher_kind, &self.password);
        let target = Endpoint::new(target.host.clone(), target.port);
        let packet = shadowsocks_encrypt_udp_packet(cipher_kind, &key, &target, payload)?;
        let server = OutboundTarget::new(self.server.host.clone(), self.server.port);
        let mut dns = DnsEngine::new(SystemDnsResolver, DnsCache::new(Duration::from_secs(60)));
        let addresses = dns
            .resolve(&server.host, server.port)
            .map_err(|error| io::Error::new(io::ErrorKind::AddrNotAvailable, error))?
            .into_iter()
            .map(|address| SocketAddr::new(address.ip, address.port));
        let mut last_error = None;
        for address in addresses {
            let bind_addr = hy2_bind_addr_for(address);
            let socket = match UdpSocket::bind(bind_addr) {
                Ok(socket) => socket,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            socket.set_read_timeout(Some(timeout))?;
            if let Err(error) = socket.send_to(&packet, address) {
                last_error = Some(error);
                continue;
            }

            let mut response = vec![0; 65_535];
            match socket.recv_from(&mut response) {
                Ok((size, _)) => {
                    response.truncate(size);
                    let (source, payload) =
                        shadowsocks_decrypt_udp_packet(cipher_kind, &key, &response)?;
                    return Ok(UdpRelayResponse {
                        source: endpoint_to_socket_addr(&source)?,
                        payload,
                    });
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "no address resolved for {}:{}",
                    self.server.host, self.server.port
                ),
            )
        }))
    }
}

pub struct ShadowsocksTcpStream {
    inner: TcpStream,
    cipher_kind: CipherKind,
    key: Vec<u8>,
    encrypt_cipher: Cipher,
    decrypt_cipher: Option<Cipher>,
    read_buffer: Vec<u8>,
    read_offset: usize,
}

impl ShadowsocksTcpStream {
    fn read_next_chunk(&mut self) -> io::Result<bool> {
        if self.decrypt_cipher.is_none() {
            let mut salt = vec![0; self.cipher_kind.salt_len()];
            if !read_exact_or_clean_eof(&mut self.inner, &mut salt)? {
                return Ok(false);
            }
            self.decrypt_cipher = Some(Cipher::new(self.cipher_kind, &self.key, &salt));
        }

        let cipher = self.decrypt_cipher.as_mut().expect("decrypt cipher");
        let tag_len = cipher.tag_len();
        let mut encrypted_len = vec![0; 2 + tag_len];
        if !read_exact_or_clean_eof(&mut self.inner, &mut encrypted_len)? {
            return Ok(false);
        }
        if !cipher.decrypt_packet(&mut encrypted_len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid shadowsocks chunk length tag",
            ));
        }
        let payload_len = u16::from_be_bytes([encrypted_len[0], encrypted_len[1]]) as usize;

        let mut encrypted_payload = vec![0; payload_len + tag_len];
        read_exact_or_clean_eof(&mut self.inner, &mut encrypted_payload)?
            .then_some(())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing shadowsocks chunk payload",
                )
            })?;
        if !cipher.decrypt_packet(&mut encrypted_payload) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid shadowsocks chunk payload tag",
            ));
        }
        encrypted_payload.truncate(payload_len);
        self.read_buffer = encrypted_payload;
        self.read_offset = 0;
        Ok(true)
    }

    fn write_chunk(&mut self, payload: &[u8]) -> io::Result<()> {
        let tag_len = self.encrypt_cipher.tag_len();
        let mut encrypted_len = vec![0; 2 + tag_len];
        encrypted_len[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        self.encrypt_cipher.encrypt_packet(&mut encrypted_len);
        self.inner.write_all(&encrypted_len)?;

        let mut encrypted_payload = vec![0; payload.len() + tag_len];
        encrypted_payload[..payload.len()].copy_from_slice(payload);
        self.encrypt_cipher.encrypt_packet(&mut encrypted_payload);
        self.inner.write_all(&encrypted_payload)
    }
}

impl Read for ShadowsocksTcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.read_offset >= self.read_buffer.len() && !self.read_next_chunk()? {
            return Ok(0);
        }
        let remaining = &self.read_buffer[self.read_offset..];
        let amount = remaining.len().min(buffer.len());
        buffer[..amount].copy_from_slice(&remaining[..amount]);
        self.read_offset += amount;
        if self.read_offset >= self.read_buffer.len() {
            self.read_buffer.clear();
            self.read_offset = 0;
        }
        Ok(amount)
    }
}

impl Write for ShadowsocksTcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        for chunk in buffer.chunks(u16::MAX as usize) {
            self.write_chunk(chunk)?;
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl OwnedRelayStream for ShadowsocksTcpStream {
    fn set_nonblocking_mode(&mut self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown(Shutdown::Write)
    }

    fn shutdown_both(&mut self) -> io::Result<()> {
        self.inner.shutdown(Shutdown::Both)
    }
}

fn shadowsocks_cipher_kind(cipher: &str) -> io::Result<CipherKind> {
    let kind = cipher.trim().parse::<CipherKind>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported shadowsocks cipher {cipher}: {error}"),
        )
    })?;
    if kind.category() != CipherCategory::Aead {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported shadowsocks cipher category: {kind}"),
        ));
    }
    Ok(kind)
}

fn shadowsocks_key(kind: CipherKind, password: &str) -> Vec<u8> {
    let mut key = vec![0; kind.key_len()];
    openssl_bytes_to_key(password.as_bytes(), &mut key);
    key
}

fn shadowsocks_encrypt_udp_packet(
    cipher_kind: CipherKind,
    key: &[u8],
    target: &Endpoint,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut salt = vec![0; cipher_kind.salt_len()];
    rand::thread_rng().fill_bytes(&mut salt);
    let header = encode_shadowsocks_tcp_request_header(target).map_err(protocol_encoding_to_io)?;
    let tag_len = cipher_kind.tag_len();
    let mut encrypted = vec![0; header.len() + payload.len() + tag_len];
    encrypted[..header.len()].copy_from_slice(&header);
    encrypted[header.len()..header.len() + payload.len()].copy_from_slice(payload);
    let mut cipher = Cipher::new(cipher_kind, key, &salt);
    cipher.encrypt_packet(&mut encrypted);
    let mut packet = salt;
    packet.extend_from_slice(&encrypted);
    Ok(packet)
}

fn shadowsocks_decrypt_udp_packet(
    cipher_kind: CipherKind,
    key: &[u8],
    packet: &[u8],
) -> io::Result<(Endpoint, Vec<u8>)> {
    let salt_len = cipher_kind.salt_len();
    let tag_len = cipher_kind.tag_len();
    if packet.len() < salt_len + tag_len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "missing shadowsocks UDP salt or tag",
        ));
    }
    let (salt, encrypted) = packet.split_at(salt_len);
    let mut payload = encrypted.to_vec();
    let mut cipher = Cipher::new(cipher_kind, key, salt);
    if !cipher.decrypt_packet(&mut payload) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid shadowsocks UDP packet tag",
        ));
    }
    payload.truncate(payload.len() - tag_len);
    let (source, consumed) = decode_shadowsocks_udp_address(&payload)?;
    Ok((source, payload[consumed..].to_vec()))
}

fn decode_shadowsocks_udp_address(payload: &[u8]) -> io::Result<(Endpoint, usize)> {
    let atyp = payload.first().copied().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "missing shadowsocks UDP address type",
        )
    })?;
    match atyp {
        0x01 => {
            if payload.len() < 7 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing shadowsocks UDP IPv4 address",
                ));
            }
            let ip = Ipv4Addr::new(payload[1], payload[2], payload[3], payload[4]);
            let port = u16::from_be_bytes([payload[5], payload[6]]);
            Ok((Endpoint::new(ip.to_string(), port), 7))
        }
        0x03 => {
            let len = payload.get(1).copied().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing shadowsocks UDP domain length",
                )
            })? as usize;
            let required = 2 + len + 2;
            if payload.len() < required {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing shadowsocks UDP domain address",
                ));
            }
            let host = std::str::from_utf8(&payload[2..2 + len])
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let port = u16::from_be_bytes([payload[2 + len], payload[2 + len + 1]]);
            Ok((Endpoint::new(host, port), required))
        }
        0x04 => {
            if payload.len() < 19 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing shadowsocks UDP IPv6 address",
                ));
            }
            let mut octets = [0; 16];
            octets.copy_from_slice(&payload[1..17]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([payload[17], payload[18]]);
            Ok((Endpoint::new(ip.to_string(), port), 19))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported shadowsocks UDP address type: {atyp}"),
        )),
    }
}

fn read_exact_or_clean_eof(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<bool> {
    let mut read = 0;
    while read < buffer.len() {
        match reader.read(&mut buffer[read..]) {
            Ok(0) if read == 0 => return Ok(false),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stream ended mid-frame",
                ))
            }
            Ok(bytes) => read += bytes,
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

const ANYTLS_CMD_WASTE: u8 = 0;
const ANYTLS_CMD_SYN: u8 = 1;
const ANYTLS_CMD_PSH: u8 = 2;
const ANYTLS_CMD_FIN: u8 = 3;
const ANYTLS_CMD_SETTINGS: u8 = 4;
const ANYTLS_CMD_ALERT: u8 = 5;
const ANYTLS_CMD_UPDATE_PADDING_SCHEME: u8 = 6;
const ANYTLS_CMD_SYNACK: u8 = 7;
const ANYTLS_CMD_HEART_REQUEST: u8 = 8;
const ANYTLS_CMD_HEART_RESPONSE: u8 = 9;
const ANYTLS_CMD_SERVER_SETTINGS: u8 = 10;
const ANYTLS_STREAM_ID: u32 = 1;
const ANYTLS_AUTH_PADDING_LEN: usize = 30;
const ANYTLS_DEFAULT_PADDING_MD5: &str = "75cff2ad89aadf5e257059ee571ebe11";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnyTlsTlsTcpOutbound {
    pub server: Endpoint,
    pub password: String,
    pub sni: String,
    pub skip_verify: bool,
}

impl AnyTlsTlsTcpOutbound {
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
        write_anytls_auth(&mut stream, &self.password)?;
        let mut anytls = AnyTlsTcpStream {
            inner: stream,
            read_buffer: Vec::new(),
            read_offset: 0,
            stream_closed: false,
            fin_sent: false,
        };
        let target = Endpoint::new(target.host.clone(), target.port);
        let target_header =
            encode_shadowsocks_tcp_request_header(&target).map_err(protocol_encoding_to_io)?;
        anytls.write_startup_frames(&target_header)?;
        Ok(OutboundConnection::Owned(Box::new(anytls)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hy2Outbound {
    server: Endpoint,
    auth: String,
    sni: String,
    skip_verify: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuicOutbound {
    server: Endpoint,
    uuid: String,
    password: String,
    sni: String,
    skip_verify: bool,
}

impl TuicOutbound {
    pub fn new(
        server: Endpoint,
        uuid: impl Into<String>,
        password: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
    ) -> Self {
        Self {
            server,
            uuid: uuid.into(),
            password: password.into(),
            sni: sni.into(),
            skip_verify,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        _timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let target = Endpoint::new(target.host.clone(), target.port);
        let mut last_error = None;
        for server_addr in self.resolve_server_addrs()? {
            let bind_addr = hy2_bind_addr_for(server_addr);
            match crate::TuicBlockingTcpStream::connect(
                bind_addr,
                server_addr,
                &self.sni,
                self.skip_verify,
                &self.uuid,
                &self.password,
                &target,
            ) {
                Ok(stream) => return Ok(OutboundConnection::Owned(Box::new(stream))),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "no address resolved for {}:{}",
                    self.server.host, self.server.port
                ),
            )
        }))
    }

    pub fn relay_udp_datagram(
        &self,
        target: &OutboundTarget,
        payload: &[u8],
        timeout: Duration,
    ) -> io::Result<UdpRelayResponse> {
        let target = Endpoint::new(target.host.clone(), target.port);
        let associate_id = random_nonzero_u16();
        let packet_id = random_nonzero_u16();
        let mut last_error = None;
        for server_addr in self.resolve_server_addrs()? {
            let bind_addr = hy2_bind_addr_for(server_addr);
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .thread_name("keli-tuic-udp-runtime")
                .build()
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
            let result = runtime.block_on(async {
                tokio::time::timeout(timeout, async {
                    let session = crate::TuicClientSession::connect(
                        bind_addr,
                        server_addr,
                        &self.sni,
                        self.skip_verify,
                        &self.uuid,
                        &self.password,
                    )
                    .await?;
                    session
                        .relay_udp_datagram(associate_id, packet_id, &target, payload)
                        .await
                })
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "TUIC UDP response timed out")
                })?
            });
            match result {
                Ok(packet) => {
                    let source = endpoint_to_socket_addr(&packet.source)?;
                    return Ok(UdpRelayResponse {
                        source,
                        payload: packet.payload,
                    });
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "no address resolved for {}:{}",
                    self.server.host, self.server.port
                ),
            )
        }))
    }

    fn resolve_server_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        let mut dns = DnsEngine::new(SystemDnsResolver, DnsCache::new(Duration::from_secs(60)));
        dns.resolve(&self.server.host, self.server.port)
            .map_err(|error| io::Error::new(io::ErrorKind::AddrNotAvailable, error))
            .map(|addresses| {
                addresses
                    .into_iter()
                    .map(|address| SocketAddr::new(address.ip, address.port))
                    .collect()
            })
    }
}

impl Hy2Outbound {
    pub fn new(
        server: Endpoint,
        auth: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
    ) -> Self {
        Self {
            server,
            auth: auth.into(),
            sni: sni.into(),
            skip_verify,
        }
    }

    pub fn from_profile(profile: OutboundProfile) -> Result<Self, OutboundProfileError> {
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
            ..
        } = profile;
        match (protocol, transport, security) {
            (
                ProxyProtocol::Hy2,
                TransportKind::Quic { .. },
                SecurityKind::Tls { sni, skip_verify },
            ) => Ok(Self {
                sni: sni.unwrap_or_else(|| endpoint.host.clone()),
                server: endpoint,
                auth: credential,
                skip_verify,
            }),
            (protocol, transport, security) => Err(OutboundProfileError::UnsupportedTransport {
                tag,
                protocol,
                transport,
                security,
            }),
        }
    }

    pub fn server(&self) -> &Endpoint {
        &self.server
    }

    pub fn auth(&self) -> &str {
        &self.auth
    }

    pub fn sni(&self) -> &str {
        &self.sni
    }

    pub fn skip_verify(&self) -> bool {
        self.skip_verify
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        _timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let target = Endpoint::new(target.host.clone(), target.port);
        let mut last_error = None;
        for server_addr in self.resolve_server_addrs()? {
            let bind_addr = hy2_bind_addr_for(server_addr);
            match crate::Hy2BlockingTcpStream::connect(
                bind_addr,
                server_addr,
                &self.sni,
                self.skip_verify,
                &self.auth,
                0,
                "",
                &target,
                b"",
            ) {
                Ok(stream) => return Ok(OutboundConnection::Owned(Box::new(stream))),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "no address resolved for {}:{}",
                    self.server.host, self.server.port
                ),
            )
        }))
    }

    pub fn relay_udp_datagram(
        &self,
        target: &OutboundTarget,
        payload: &[u8],
        timeout: Duration,
    ) -> io::Result<UdpRelayResponse> {
        let target = Endpoint::new(target.host.clone(), target.port);
        let session_id = random_nonzero_u32();
        let packet_id = random_nonzero_u16();
        let mut last_error = None;
        for server_addr in self.resolve_server_addrs()? {
            let bind_addr = hy2_bind_addr_for(server_addr);
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .thread_name("keli-hy2-udp-runtime")
                .build()
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
            let result = runtime.block_on(async {
                tokio::time::timeout(timeout, async {
                    let session = crate::Hy2ClientSession::connect(
                        bind_addr,
                        server_addr,
                        &self.sni,
                        self.skip_verify,
                        &self.auth,
                        0,
                        "",
                    )
                    .await?;
                    session
                        .relay_udp_datagram(session_id, packet_id, &target, payload)
                        .await
                })
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "HY2 UDP response timed out")
                })?
            });
            match result {
                Ok(message) => {
                    let source = endpoint_to_socket_addr(&message.address)?;
                    return Ok(UdpRelayResponse {
                        source,
                        payload: message.payload,
                    });
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "no address resolved for {}:{}",
                    self.server.host, self.server.port
                ),
            )
        }))
    }

    fn resolve_server_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        let mut dns = DnsEngine::new(SystemDnsResolver, DnsCache::new(Duration::from_secs(60)));
        dns.resolve(&self.server.host, self.server.port)
            .map_err(|error| io::Error::new(io::ErrorKind::AddrNotAvailable, error))
            .map(|addresses| {
                addresses
                    .into_iter()
                    .map(|address| SocketAddr::new(address.ip, address.port))
                    .collect()
            })
    }
}

fn hy2_bind_addr_for(server_addr: SocketAddr) -> SocketAddr {
    if server_addr.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    }
}

fn endpoint_to_socket_addr(endpoint: &Endpoint) -> io::Result<SocketAddr> {
    let host = endpoint.host.trim().trim_matches(['[', ']']);
    let ip = host
        .parse::<IpAddr>()
        .map_err(|error| io::Error::new(io::ErrorKind::AddrNotAvailable, error))?;
    Ok(SocketAddr::new(ip, endpoint.port))
}

fn random_nonzero_u16() -> u16 {
    let value = (rand::thread_rng().next_u32() & 0xffff) as u16;
    if value == 0 {
        1
    } else {
        value
    }
}

fn random_nonzero_u32() -> u32 {
    let value = rand::thread_rng().next_u32();
    if value == 0 {
        1
    } else {
        value
    }
}

fn split_tuic_credential(credential: &str) -> Option<(String, String)> {
    let (uuid, password) = credential.split_once(':')?;
    let uuid = uuid.trim();
    let password = password.trim();
    if uuid.is_empty() || password.is_empty() {
        return None;
    }
    Some((uuid.to_string(), password.to_string()))
}

pub struct AnyTlsTcpStream {
    inner: TlsTcpStream,
    read_buffer: Vec<u8>,
    read_offset: usize,
    stream_closed: bool,
    fin_sent: bool,
}

impl AnyTlsTcpStream {
    fn write_startup_frames(&mut self, target_header: &[u8]) -> io::Result<()> {
        let settings = format!(
            "v=2\nclient=keli-native-client/{}\npadding-md5={ANYTLS_DEFAULT_PADDING_MD5}",
            env!("CARGO_PKG_VERSION")
        );
        self.write_frame(ANYTLS_CMD_SETTINGS, 0, settings.as_bytes())?;
        self.write_frame(ANYTLS_CMD_SYN, ANYTLS_STREAM_ID, &[])?;
        self.write_frame(ANYTLS_CMD_PSH, ANYTLS_STREAM_ID, target_header)
    }

    fn write_frame(&mut self, cmd: u8, sid: u32, data: &[u8]) -> io::Result<()> {
        if data.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AnyTLS frame payload is too large",
            ));
        }
        let mut header = [0; 7];
        header[0] = cmd;
        header[1..5].copy_from_slice(&sid.to_be_bytes());
        header[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
        self.inner.write_all(&header)?;
        self.inner.write_all(data)
    }

    fn read_next_data_frame(&mut self) -> io::Result<bool> {
        if self.stream_closed {
            return Ok(false);
        }
        loop {
            let Some((cmd, sid, data)) = self.read_frame()? else {
                return Ok(false);
            };
            match cmd {
                ANYTLS_CMD_PSH if sid == ANYTLS_STREAM_ID => {
                    self.read_buffer = data;
                    self.read_offset = 0;
                    return Ok(true);
                }
                ANYTLS_CMD_FIN if sid == ANYTLS_STREAM_ID => {
                    self.stream_closed = true;
                    return Ok(false);
                }
                ANYTLS_CMD_ALERT => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("AnyTLS alert: {}", String::from_utf8_lossy(&data)),
                    ));
                }
                ANYTLS_CMD_HEART_REQUEST => {
                    self.write_frame(ANYTLS_CMD_HEART_RESPONSE, sid, &[])?;
                }
                ANYTLS_CMD_WASTE
                | ANYTLS_CMD_SYNACK
                | ANYTLS_CMD_UPDATE_PADDING_SCHEME
                | ANYTLS_CMD_SERVER_SETTINGS
                | ANYTLS_CMD_HEART_RESPONSE => {}
                _ => {}
            }
        }
    }

    fn read_frame(&mut self) -> io::Result<Option<(u8, u32, Vec<u8>)>> {
        let mut header = [0; 7];
        if !read_exact_or_clean_eof(&mut self.inner, &mut header)? {
            return Ok(None);
        }
        let cmd = header[0];
        let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let len = u16::from_be_bytes([header[5], header[6]]) as usize;
        let mut data = vec![0; len];
        read_exact_or_clean_eof(&mut self.inner, &mut data)?
            .then_some(())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "missing AnyTLS frame payload")
            })?;
        Ok(Some((cmd, sid, data)))
    }
}

impl Read for AnyTlsTcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.read_offset >= self.read_buffer.len() && !self.read_next_data_frame()? {
            return Ok(0);
        }
        let remaining = &self.read_buffer[self.read_offset..];
        let amount = remaining.len().min(buffer.len());
        buffer[..amount].copy_from_slice(&remaining[..amount]);
        self.read_offset += amount;
        if self.read_offset >= self.read_buffer.len() {
            self.read_buffer.clear();
            self.read_offset = 0;
        }
        Ok(amount)
    }
}

impl Write for AnyTlsTcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        for chunk in buffer.chunks(u16::MAX as usize) {
            self.write_frame(ANYTLS_CMD_PSH, ANYTLS_STREAM_ID, chunk)?;
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl OwnedRelayStream for AnyTlsTcpStream {
    fn set_nonblocking_mode(&mut self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking_mode(nonblocking)
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        if !self.fin_sent {
            self.write_frame(ANYTLS_CMD_FIN, ANYTLS_STREAM_ID, &[])?;
            self.fin_sent = true;
        }
        Ok(())
    }

    fn shutdown_both(&mut self) -> io::Result<()> {
        self.shutdown_write().ok();
        self.inner.shutdown_both()
    }
}

fn write_anytls_auth(stream: &mut impl Write, password: &str) -> io::Result<()> {
    let digest = Sha256::digest(password.as_bytes());
    stream.write_all(&digest)?;
    stream.write_all(&(ANYTLS_AUTH_PADDING_LEN as u16).to_be_bytes())?;
    let mut padding = vec![0; ANYTLS_AUTH_PADDING_LEN];
    rand::thread_rng().fill_bytes(&mut padding);
    stream.write_all(&padding)
}

fn connect_legacy_quic_stream(
    server: &Endpoint,
    sni: &str,
    skip_verify: bool,
    transport: &crate::LegacyQuicTransportConfig,
    timeout: Duration,
) -> io::Result<crate::LegacyQuicTcpStream> {
    let mut last_error = None;
    for server_addr in resolve_endpoint_socket_addrs(server)? {
        let bind_addr = hy2_bind_addr_for(server_addr);
        match crate::LegacyQuicTcpStream::connect(
            bind_addr,
            server_addr,
            sni,
            skip_verify,
            transport.clone(),
            timeout,
        ) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no address resolved for {}:{}", server.host, server.port),
        )
    }))
}

fn resolve_endpoint_socket_addrs(endpoint: &Endpoint) -> io::Result<Vec<SocketAddr>> {
    let mut dns = DnsEngine::new(SystemDnsResolver, DnsCache::new(Duration::from_secs(60)));
    dns.resolve(&endpoint.host, endpoint.port)
        .map_err(|error| io::Error::new(io::ErrorKind::AddrNotAvailable, error))
        .map(|addresses| {
            addresses
                .into_iter()
                .map(|address| SocketAddr::new(address.ip, address.port))
                .collect()
        })
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
pub struct TrojanHttpUpgradeOutbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub password: String,
}

impl TrojanHttpUpgradeOutbound {
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
        let mut stream = connect_httpupgrade_client(stream, &self.host, &self.path)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_trojan_tcp_request_header(&self.password, &target)
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        Ok(OutboundConnection::Tcp(stream))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanTlsHttpUpgradeOutbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub password: String,
    pub sni: String,
    pub skip_verify: bool,
}

impl TrojanTlsHttpUpgradeOutbound {
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
        let mut stream = connect_httpupgrade_client(stream, &self.host, &self.path)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_trojan_tcp_request_header(&self.password, &target)
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanGrpcOutbound {
    pub server: Endpoint,
    pub host: String,
    pub service_name: Option<String>,
    pub password: String,
}

impl TrojanGrpcOutbound {
    pub fn new(
        server: Endpoint,
        host: impl Into<String>,
        service_name: Option<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            server,
            host: host.into(),
            service_name,
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
        let mut stream =
            crate::GrpcTcpStream::connect_plain(stream, &self.host, self.service_name.as_deref())?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_trojan_tcp_request_header(&self.password, &target)
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanTlsGrpcOutbound {
    pub server: Endpoint,
    pub host: String,
    pub service_name: Option<String>,
    pub password: String,
    pub sni: String,
    pub skip_verify: bool,
}

impl TrojanTlsGrpcOutbound {
    pub fn new(
        server: Endpoint,
        host: impl Into<String>,
        service_name: Option<String>,
        password: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
    ) -> Self {
        Self {
            server,
            host: host.into(),
            service_name,
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
        let mut stream = crate::GrpcTcpStream::connect_tls(
            stream,
            &self.sni,
            self.skip_verify,
            &self.host,
            self.service_name.as_deref(),
        )?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_trojan_tcp_request_header(&self.password, &target)
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanH2Outbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub password: String,
}

impl TrojanH2Outbound {
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
        let mut stream = crate::Http2TcpStream::connect_plain(stream, &self.host, &self.path)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_trojan_tcp_request_header(&self.password, &target)
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanTlsH2Outbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub password: String,
    pub sni: String,
    pub skip_verify: bool,
}

impl TrojanTlsH2Outbound {
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
        let mut stream = crate::Http2TcpStream::connect_tls(
            stream,
            &self.sni,
            self.skip_verify,
            &self.host,
            &self.path,
        )?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let header = encode_trojan_tcp_request_header(&self.password, &target)
            .map_err(protocol_encoding_to_io)?;
        stream.write_all(&header)?;
        Ok(OutboundConnection::Owned(Box::new(stream)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanQuicOutbound {
    pub server: Endpoint,
    pub password: String,
    pub sni: String,
    pub skip_verify: bool,
    pub transport: crate::LegacyQuicTransportConfig,
}

impl TrojanQuicOutbound {
    pub fn new(
        server: Endpoint,
        password: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
        transport: crate::LegacyQuicTransportConfig,
    ) -> Self {
        Self {
            server,
            password: password.into(),
            sni: sni.into(),
            skip_verify,
            transport,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let mut stream = connect_legacy_quic_stream(
            &self.server,
            &self.sni,
            self.skip_verify,
            &self.transport,
            timeout,
        )?;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessBodySecurity {
    None,
    Aes128Gcm,
    Chacha20Poly1305,
}

fn vmess_security_from_profile_cipher(
    tag: &str,
    cipher: Option<&str>,
) -> Result<VmessBodySecurity, OutboundProfileError> {
    let cipher = cipher.unwrap_or("auto").trim().to_ascii_lowercase();
    match cipher.as_str() {
        "" | "auto" | "aes-128-gcm" => Ok(VmessBodySecurity::Aes128Gcm),
        "chacha20-poly1305" => Ok(VmessBodySecurity::Chacha20Poly1305),
        "none" | "zero" => Ok(VmessBodySecurity::None),
        _ => Err(OutboundProfileError::UnsupportedVmessCipher {
            tag: tag.to_string(),
            cipher,
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmessTcpOutbound {
    pub server: Endpoint,
    pub uuid: String,
    pub security: VmessBodySecurity,
}

impl VmessTcpOutbound {
    pub fn new(server: Endpoint, uuid: impl Into<String>) -> Self {
        Self::new_with_security(server, uuid, VmessBodySecurity::None)
    }

    pub fn new_with_security(
        server: Endpoint,
        uuid: impl Into<String>,
        security: VmessBodySecurity,
    ) -> Self {
        Self {
            server,
            uuid: uuid.into(),
            security,
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
        let request =
            write_vmess_tcp_request_header(&mut stream, &self.uuid, &target, self.security)?;
        read_vmess_response_header_from_stream(&mut stream, &request)?;
        match self.security {
            VmessBodySecurity::None => Ok(OutboundConnection::Tcp(stream)),
            _ => Ok(OutboundConnection::Owned(Box::new(VmessAeadStream::new(
                stream,
                request,
                self.security,
            )))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmessTlsTcpOutbound {
    pub server: Endpoint,
    pub uuid: String,
    pub sni: String,
    pub skip_verify: bool,
    pub security: VmessBodySecurity,
}

impl VmessTlsTcpOutbound {
    pub fn new(
        server: Endpoint,
        uuid: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
    ) -> Self {
        Self::new_with_security(server, uuid, sni, skip_verify, VmessBodySecurity::None)
    }

    pub fn new_with_security(
        server: Endpoint,
        uuid: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
        security: VmessBodySecurity,
    ) -> Self {
        Self {
            server,
            uuid: uuid.into(),
            sni: sni.into(),
            skip_verify,
            security,
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
        let request =
            write_vmess_tcp_request_header(&mut stream, &self.uuid, &target, self.security)?;
        read_vmess_response_header_from_stream(&mut stream, &request)?;
        vmess_connection_from_stream(stream, request, self.security)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmessWsOutbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub uuid: String,
    pub security: VmessBodySecurity,
}

impl VmessWsOutbound {
    pub fn new(
        server: Endpoint,
        host: impl Into<String>,
        path: impl Into<String>,
        uuid: impl Into<String>,
    ) -> Self {
        Self::new_with_security(server, host, path, uuid, VmessBodySecurity::None)
    }

    pub fn new_with_security(
        server: Endpoint,
        host: impl Into<String>,
        path: impl Into<String>,
        uuid: impl Into<String>,
        security: VmessBodySecurity,
    ) -> Self {
        Self {
            server,
            host: host.into(),
            path: path.into(),
            uuid: uuid.into(),
            security,
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
        let request =
            write_vmess_tcp_request_header(&mut stream, &self.uuid, &target, self.security)?;
        read_vmess_response_header_from_stream(&mut stream, &request)?;
        match self.security {
            VmessBodySecurity::None => Ok(OutboundConnection::WebSocket(stream)),
            _ => Ok(OutboundConnection::Owned(Box::new(VmessAeadStream::new(
                stream,
                request,
                self.security,
            )))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmessTlsWsOutbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub uuid: String,
    pub sni: String,
    pub skip_verify: bool,
    pub security: VmessBodySecurity,
}

impl VmessTlsWsOutbound {
    pub fn new(
        server: Endpoint,
        host: impl Into<String>,
        path: impl Into<String>,
        uuid: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
    ) -> Self {
        Self::new_with_security(
            server,
            host,
            path,
            uuid,
            sni,
            skip_verify,
            VmessBodySecurity::None,
        )
    }

    pub fn new_with_security(
        server: Endpoint,
        host: impl Into<String>,
        path: impl Into<String>,
        uuid: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
        security: VmessBodySecurity,
    ) -> Self {
        Self {
            server,
            host: host.into(),
            path: path.into(),
            uuid: uuid.into(),
            sni: sni.into(),
            skip_verify,
            security,
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
        let request =
            write_vmess_tcp_request_header(&mut stream, &self.uuid, &target, self.security)?;
        read_vmess_response_header_from_stream(&mut stream, &request)?;
        vmess_connection_from_stream(stream, request, self.security)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmessHttpUpgradeOutbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub uuid: String,
    pub security: VmessBodySecurity,
}

impl VmessHttpUpgradeOutbound {
    pub fn new(
        server: Endpoint,
        host: impl Into<String>,
        path: impl Into<String>,
        uuid: impl Into<String>,
    ) -> Self {
        Self::new_with_security(server, host, path, uuid, VmessBodySecurity::None)
    }

    pub fn new_with_security(
        server: Endpoint,
        host: impl Into<String>,
        path: impl Into<String>,
        uuid: impl Into<String>,
        security: VmessBodySecurity,
    ) -> Self {
        Self {
            server,
            host: host.into(),
            path: path.into(),
            uuid: uuid.into(),
            security,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let server = OutboundTarget::new(self.server.host.clone(), self.server.port);
        let stream = DirectTcpConnector::connect(&server, timeout)?;
        let mut stream = connect_httpupgrade_client(stream, &self.host, &self.path)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let request =
            write_vmess_tcp_request_header(&mut stream, &self.uuid, &target, self.security)?;
        read_vmess_response_header_from_stream(&mut stream, &request)?;
        match self.security {
            VmessBodySecurity::None => Ok(OutboundConnection::Tcp(stream)),
            _ => Ok(OutboundConnection::Owned(Box::new(VmessAeadStream::new(
                stream,
                request,
                self.security,
            )))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmessTlsHttpUpgradeOutbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub uuid: String,
    pub sni: String,
    pub skip_verify: bool,
    pub security: VmessBodySecurity,
}

impl VmessTlsHttpUpgradeOutbound {
    pub fn new(
        server: Endpoint,
        host: impl Into<String>,
        path: impl Into<String>,
        uuid: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
    ) -> Self {
        Self::new_with_security(
            server,
            host,
            path,
            uuid,
            sni,
            skip_verify,
            VmessBodySecurity::None,
        )
    }

    pub fn new_with_security(
        server: Endpoint,
        host: impl Into<String>,
        path: impl Into<String>,
        uuid: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
        security: VmessBodySecurity,
    ) -> Self {
        Self {
            server,
            host: host.into(),
            path: path.into(),
            uuid: uuid.into(),
            sni: sni.into(),
            skip_verify,
            security,
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
        let mut stream = connect_httpupgrade_client(stream, &self.host, &self.path)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let request =
            write_vmess_tcp_request_header(&mut stream, &self.uuid, &target, self.security)?;
        read_vmess_response_header_from_stream(&mut stream, &request)?;
        vmess_connection_from_stream(stream, request, self.security)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmessGrpcOutbound {
    pub server: Endpoint,
    pub host: String,
    pub service_name: Option<String>,
    pub uuid: String,
    pub security: VmessBodySecurity,
}

impl VmessGrpcOutbound {
    pub fn new(
        server: Endpoint,
        host: impl Into<String>,
        service_name: Option<String>,
        uuid: impl Into<String>,
    ) -> Self {
        Self::new_with_security(server, host, service_name, uuid, VmessBodySecurity::None)
    }

    pub fn new_with_security(
        server: Endpoint,
        host: impl Into<String>,
        service_name: Option<String>,
        uuid: impl Into<String>,
        security: VmessBodySecurity,
    ) -> Self {
        Self {
            server,
            host: host.into(),
            service_name,
            uuid: uuid.into(),
            security,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let server = OutboundTarget::new(self.server.host.clone(), self.server.port);
        let stream = DirectTcpConnector::connect(&server, timeout)?;
        let mut stream =
            crate::GrpcTcpStream::connect_plain(stream, &self.host, self.service_name.as_deref())?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let request =
            write_vmess_tcp_request_header(&mut stream, &self.uuid, &target, self.security)?;
        read_vmess_response_header_from_stream(&mut stream, &request)?;
        vmess_connection_from_stream(stream, request, self.security)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmessTlsGrpcOutbound {
    pub server: Endpoint,
    pub host: String,
    pub service_name: Option<String>,
    pub uuid: String,
    pub sni: String,
    pub skip_verify: bool,
    pub security: VmessBodySecurity,
}

impl VmessTlsGrpcOutbound {
    pub fn new(
        server: Endpoint,
        host: impl Into<String>,
        service_name: Option<String>,
        uuid: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
    ) -> Self {
        Self::new_with_security(
            server,
            host,
            service_name,
            uuid,
            sni,
            skip_verify,
            VmessBodySecurity::None,
        )
    }

    pub fn new_with_security(
        server: Endpoint,
        host: impl Into<String>,
        service_name: Option<String>,
        uuid: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
        security: VmessBodySecurity,
    ) -> Self {
        Self {
            server,
            host: host.into(),
            service_name,
            uuid: uuid.into(),
            sni: sni.into(),
            skip_verify,
            security,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let server = OutboundTarget::new(self.server.host.clone(), self.server.port);
        let stream = DirectTcpConnector::connect(&server, timeout)?;
        let mut stream = crate::GrpcTcpStream::connect_tls(
            stream,
            &self.sni,
            self.skip_verify,
            &self.host,
            self.service_name.as_deref(),
        )?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let request =
            write_vmess_tcp_request_header(&mut stream, &self.uuid, &target, self.security)?;
        read_vmess_response_header_from_stream(&mut stream, &request)?;
        vmess_connection_from_stream(stream, request, self.security)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmessH2Outbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub uuid: String,
    pub security: VmessBodySecurity,
}

impl VmessH2Outbound {
    pub fn new(
        server: Endpoint,
        host: impl Into<String>,
        path: impl Into<String>,
        uuid: impl Into<String>,
    ) -> Self {
        Self::new_with_security(server, host, path, uuid, VmessBodySecurity::None)
    }

    pub fn new_with_security(
        server: Endpoint,
        host: impl Into<String>,
        path: impl Into<String>,
        uuid: impl Into<String>,
        security: VmessBodySecurity,
    ) -> Self {
        Self {
            server,
            host: host.into(),
            path: path.into(),
            uuid: uuid.into(),
            security,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let server = OutboundTarget::new(self.server.host.clone(), self.server.port);
        let stream = DirectTcpConnector::connect(&server, timeout)?;
        let mut stream = crate::Http2TcpStream::connect_plain(stream, &self.host, &self.path)?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let request =
            write_vmess_tcp_request_header(&mut stream, &self.uuid, &target, self.security)?;
        read_vmess_response_header_from_stream(&mut stream, &request)?;
        vmess_connection_from_stream(stream, request, self.security)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmessTlsH2Outbound {
    pub server: Endpoint,
    pub host: String,
    pub path: String,
    pub uuid: String,
    pub sni: String,
    pub skip_verify: bool,
    pub security: VmessBodySecurity,
}

impl VmessTlsH2Outbound {
    pub fn new(
        server: Endpoint,
        host: impl Into<String>,
        path: impl Into<String>,
        uuid: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
    ) -> Self {
        Self::new_with_security(
            server,
            host,
            path,
            uuid,
            sni,
            skip_verify,
            VmessBodySecurity::None,
        )
    }

    pub fn new_with_security(
        server: Endpoint,
        host: impl Into<String>,
        path: impl Into<String>,
        uuid: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
        security: VmessBodySecurity,
    ) -> Self {
        Self {
            server,
            host: host.into(),
            path: path.into(),
            uuid: uuid.into(),
            sni: sni.into(),
            skip_verify,
            security,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let server = OutboundTarget::new(self.server.host.clone(), self.server.port);
        let stream = DirectTcpConnector::connect(&server, timeout)?;
        let mut stream = crate::Http2TcpStream::connect_tls(
            stream,
            &self.sni,
            self.skip_verify,
            &self.host,
            &self.path,
        )?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let request =
            write_vmess_tcp_request_header(&mut stream, &self.uuid, &target, self.security)?;
        read_vmess_response_header_from_stream(&mut stream, &request)?;
        vmess_connection_from_stream(stream, request, self.security)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmessQuicOutbound {
    pub server: Endpoint,
    pub uuid: String,
    pub sni: String,
    pub skip_verify: bool,
    pub transport: crate::LegacyQuicTransportConfig,
    pub security: VmessBodySecurity,
}

impl VmessQuicOutbound {
    pub fn new(
        server: Endpoint,
        uuid: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
        transport: crate::LegacyQuicTransportConfig,
    ) -> Self {
        Self::new_with_security(
            server,
            uuid,
            sni,
            skip_verify,
            transport,
            VmessBodySecurity::None,
        )
    }

    pub fn new_with_security(
        server: Endpoint,
        uuid: impl Into<String>,
        sni: impl Into<String>,
        skip_verify: bool,
        transport: crate::LegacyQuicTransportConfig,
        security: VmessBodySecurity,
    ) -> Self {
        Self {
            server,
            uuid: uuid.into(),
            sni: sni.into(),
            skip_verify,
            transport,
            security,
        }
    }

    pub fn connect(
        &self,
        target: &OutboundTarget,
        timeout: Duration,
    ) -> io::Result<OutboundConnection> {
        let mut stream = connect_legacy_quic_stream(
            &self.server,
            &self.sni,
            self.skip_verify,
            &self.transport,
            timeout,
        )?;
        let target = Endpoint::new(target.host.clone(), target.port);
        let request =
            write_vmess_tcp_request_header(&mut stream, &self.uuid, &target, self.security)?;
        read_vmess_response_header_from_stream(&mut stream, &request)?;
        vmess_connection_from_stream(stream, request, self.security)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VmessClientRequest {
    request_body_key: [u8; 16],
    request_body_iv: [u8; 16],
    response_body_key: [u8; 16],
    response_body_iv: [u8; 16],
    response_header: u8,
}

fn write_vmess_tcp_request_header(
    stream: &mut impl Write,
    uuid: &str,
    target: &Endpoint,
    security: VmessBodySecurity,
) -> io::Result<VmessClientRequest> {
    let uuid = parse_vmess_uuid_bytes(uuid)?;
    let cmd_key = vmess_cmd_key(&uuid);
    let request_body_key = random_array::<16>();
    let request_body_iv = random_array::<16>();
    let response_header = random_array::<1>()[0];
    let mut header = Vec::new();
    header.push(VMESS_VERSION);
    header.extend_from_slice(&request_body_iv);
    header.extend_from_slice(&request_body_key);
    header.push(response_header);
    header.push(vmess_request_option(security));
    header.push(vmess_request_security(security));
    header.push(0x00);
    header.push(VMESS_COMMAND_TCP);
    write_vmess_target_header(&mut header, target)?;
    let checksum = fnv1a(&header);
    header.extend_from_slice(&checksum.to_be_bytes());

    let auth_id = create_vmess_auth_id(&cmd_key);
    let nonce = random_array::<8>();
    stream.write_all(&seal_vmess_request_header(
        &cmd_key, &auth_id, &nonce, &header,
    )?)?;

    Ok(VmessClientRequest {
        request_body_key,
        request_body_iv,
        response_body_key: first_16_sha256(&request_body_key),
        response_body_iv: first_16_sha256(&request_body_iv),
        response_header,
    })
}

fn vmess_request_option(security: VmessBodySecurity) -> u8 {
    match security {
        VmessBodySecurity::None => 0x00,
        VmessBodySecurity::Aes128Gcm | VmessBodySecurity::Chacha20Poly1305 => {
            VMESS_OPTION_CHUNK_STREAM | VMESS_OPTION_CHUNK_MASKING
        }
    }
}

fn vmess_request_security(security: VmessBodySecurity) -> u8 {
    match security {
        VmessBodySecurity::None => VMESS_SECURITY_NONE,
        VmessBodySecurity::Aes128Gcm => VMESS_SECURITY_AES_128_GCM,
        VmessBodySecurity::Chacha20Poly1305 => VMESS_SECURITY_CHACHA20_POLY1305,
    }
}

fn vmess_connection_from_stream<S>(
    stream: S,
    request: VmessClientRequest,
    security: VmessBodySecurity,
) -> io::Result<OutboundConnection>
where
    S: OwnedRelayStream + 'static,
{
    match security {
        VmessBodySecurity::None => Ok(OutboundConnection::Owned(Box::new(stream))),
        _ => Ok(OutboundConnection::Owned(Box::new(VmessAeadStream::new(
            stream, request, security,
        )))),
    }
}

struct VmessAeadStream<S> {
    inner: S,
    security: VmessBodySecurity,
    read_key: [u8; 16],
    read_iv: [u8; 16],
    read_counter: u16,
    read_mask: Shake128Reader,
    read_buffer: Vec<u8>,
    read_offset: usize,
    write_key: [u8; 16],
    write_iv: [u8; 16],
    write_counter: u16,
    write_mask: Shake128Reader,
}

impl<S> VmessAeadStream<S> {
    fn new(inner: S, request: VmessClientRequest, security: VmessBodySecurity) -> Self {
        Self {
            inner,
            security,
            read_key: request.response_body_key,
            read_iv: request.response_body_iv,
            read_counter: 0,
            read_mask: vmess_chunk_mask_reader(&request.response_body_iv),
            read_buffer: Vec::new(),
            read_offset: 0,
            write_key: request.request_body_key,
            write_iv: request.request_body_iv,
            write_counter: 0,
            write_mask: vmess_chunk_mask_reader(&request.request_body_iv),
        }
    }
}

impl<S: Read> Read for VmessAeadStream<S> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.read_offset >= self.read_buffer.len() && !self.read_next_chunk()? {
            return Ok(0);
        }
        let available = &self.read_buffer[self.read_offset..];
        let size = available.len().min(buffer.len());
        buffer[..size].copy_from_slice(&available[..size]);
        self.read_offset += size;
        Ok(size)
    }
}

impl<S: Read> VmessAeadStream<S> {
    fn read_next_chunk(&mut self) -> io::Result<bool> {
        let mut length_bytes = [0; 2];
        if !read_exact_or_clean_eof(&mut self.inner, &mut length_bytes)? {
            return Ok(false);
        }
        let encrypted_len =
            u16::from_be_bytes(length_bytes) ^ vmess_next_chunk_mask(&mut self.read_mask);
        let mut encrypted_payload = vec![0; usize::from(encrypted_len)];
        self.inner.read_exact(&mut encrypted_payload)?;
        let nonce = vmess_body_nonce(&self.read_iv, self.read_counter);
        self.read_counter = self.read_counter.wrapping_add(1);
        self.read_buffer =
            vmess_body_open(self.security, &self.read_key, &nonce, &encrypted_payload)?;
        self.read_offset = 0;
        Ok(!self.read_buffer.is_empty())
    }
}

impl<S: Write> Write for VmessAeadStream<S> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        for chunk in buffer.chunks(VMESS_WRITE_CHUNK_SIZE) {
            let nonce = vmess_body_nonce(&self.write_iv, self.write_counter);
            self.write_counter = self.write_counter.wrapping_add(1);
            let encrypted_payload = vmess_body_seal(self.security, &self.write_key, &nonce, chunk)?;
            let encrypted_len = u16::try_from(encrypted_payload.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "vmess chunk is too large")
            })?;
            let masked_len = encrypted_len ^ vmess_next_chunk_mask(&mut self.write_mask);
            self.inner.write_all(&masked_len.to_be_bytes())?;
            self.inner.write_all(&encrypted_payload)?;
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<S: OwnedRelayStream> OwnedRelayStream for VmessAeadStream<S> {
    fn set_nonblocking_mode(&mut self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking_mode(nonblocking)
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown_write()
    }

    fn shutdown_both(&mut self) -> io::Result<()> {
        self.inner.shutdown_both()
    }
}

fn vmess_chunk_mask_reader(nonce: &[u8; 16]) -> Shake128Reader {
    let mut shake = Shake128::default();
    Update::update(&mut shake, nonce);
    shake.finalize_xof()
}

fn vmess_next_chunk_mask(reader: &mut Shake128Reader) -> u16 {
    let mut mask = [0; 2];
    XofReader::read(reader, &mut mask);
    u16::from_be_bytes(mask)
}

fn vmess_body_nonce(base: &[u8; 16], counter: u16) -> [u8; 12] {
    let mut nonce: [u8; 12] = base[..12].try_into().expect("vmess body nonce");
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn write_vmess_target_header(output: &mut Vec<u8>, target: &Endpoint) -> io::Result<()> {
    output.extend_from_slice(&target.port.to_be_bytes());
    if let Ok(ip) = target.host.parse::<Ipv4Addr>() {
        output.push(VMESS_ATYP_IPV4);
        output.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = target.host.parse::<Ipv6Addr>() {
        output.push(VMESS_ATYP_IPV6);
        output.extend_from_slice(&ip.octets());
    } else {
        let host = target.host.trim().trim_matches(['[', ']']);
        if host.is_empty() || host.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vmess target host is invalid",
            ));
        }
        output.push(VMESS_ATYP_DOMAIN);
        output.push(host.len() as u8);
        output.extend_from_slice(host.as_bytes());
    }
    Ok(())
}

fn seal_vmess_request_header(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    nonce: &[u8; 8],
    header: &[u8],
) -> io::Result<Vec<u8>> {
    let len_key = vmess_kdf16(
        cmd_key,
        &[VMESS_HEADER_LENGTH_KEY, auth_id, nonce.as_slice()],
    );
    let len_nonce = first_12(&vmess_kdf(
        cmd_key,
        &[VMESS_HEADER_LENGTH_NONCE, auth_id, nonce.as_slice()],
    ));
    let payload_key = vmess_kdf16(
        cmd_key,
        &[VMESS_HEADER_PAYLOAD_KEY, auth_id, nonce.as_slice()],
    );
    let payload_nonce = first_12(&vmess_kdf(
        cmd_key,
        &[VMESS_HEADER_PAYLOAD_NONCE, auth_id, nonce.as_slice()],
    ));
    let mut output = Vec::with_capacity(42 + header.len());
    output.extend_from_slice(auth_id);
    output.extend_from_slice(&vmess_aes_gcm_seal(
        &len_key,
        &len_nonce,
        &(header.len() as u16).to_be_bytes(),
        auth_id,
    )?);
    output.extend_from_slice(nonce);
    output.extend_from_slice(&vmess_aes_gcm_seal(
        &payload_key,
        &payload_nonce,
        header,
        auth_id,
    )?);
    Ok(output)
}

fn read_vmess_response_header_from_stream(
    stream: &mut impl Read,
    request: &VmessClientRequest,
) -> io::Result<()> {
    let mut len_cipher = [0; 18];
    stream.read_exact(&mut len_cipher)?;
    let len_key = vmess_kdf16(
        &request.response_body_key,
        &[VMESS_RESPONSE_HEADER_LENGTH_KEY],
    );
    let len_nonce = first_12(&vmess_kdf(
        &request.response_body_iv,
        &[VMESS_RESPONSE_HEADER_LENGTH_IV],
    ));
    let len = vmess_aes_gcm_open(&len_key, &len_nonce, &len_cipher, &[])?;
    if len.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid vmess response header length",
        ));
    }
    let len = u16::from_be_bytes([len[0], len[1]]) as usize;
    let mut payload_cipher = vec![0; len + 16];
    stream.read_exact(&mut payload_cipher)?;
    let payload_key = vmess_kdf16(
        &request.response_body_key,
        &[VMESS_RESPONSE_HEADER_PAYLOAD_KEY],
    );
    let payload_nonce = first_12(&vmess_kdf(
        &request.response_body_iv,
        &[VMESS_RESPONSE_HEADER_PAYLOAD_IV],
    ));
    let payload = vmess_aes_gcm_open(&payload_key, &payload_nonce, &payload_cipher, &[])?;
    if payload.len() < 4 || payload[0] != request.response_header {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid vmess response header",
        ));
    }
    Ok(())
}

fn create_vmess_auth_id(cmd_key: &[u8; 16]) -> [u8; 16] {
    let mut plain = [0; 16];
    plain[..8].copy_from_slice(&unix_timestamp().to_be_bytes());
    plain[8..12].copy_from_slice(&random_array::<4>());
    let crc = crc32fast::hash(&plain[..12]);
    plain[12..16].copy_from_slice(&crc.to_be_bytes());
    let key = vmess_kdf16(cmd_key, &[VMESS_AUTH_ID_KEY]);
    let cipher = aes::Aes128::new_from_slice(&key).expect("aes accepts 128-bit vmess auth key");
    let mut block = aes::cipher::Block::<aes::Aes128>::clone_from_slice(&plain);
    cipher.encrypt_block(&mut block);
    block.into()
}

fn parse_vmess_uuid_bytes(value: &str) -> io::Result<[u8; 16]> {
    let compact: String = value
        .trim()
        .chars()
        .filter(|character| *character != '-')
        .collect();
    if compact.len() != 32 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vmess uuid is invalid",
        ));
    }
    let mut output = [0; 16];
    for (index, chunk) in compact.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        output[index] = u8::from_str_radix(hex, 16)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    }
    Ok(output)
}

fn vmess_cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, uuid);
    Md5Digest::update(&mut hasher, VMESS_CMD_KEY_SALT);
    hasher.finalize().into()
}

fn vmess_kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    vmess_kdf(key, path)[..16].try_into().expect("kdf16")
}

fn vmess_kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    if path.is_empty() {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(VMESS_KDF_ROOT).expect("hmac key");
        Mac::update(&mut mac, key);
        return mac.finalize().into_bytes().into();
    }
    let tail = path[path.len() - 1];
    vmess_hmac_with_hash(|input| vmess_kdf(input, &path[..path.len() - 1]), tail, key)
}

fn vmess_hmac_with_hash<H>(hash: H, key: &[u8], message: &[u8]) -> [u8; 32]
where
    H: Fn(&[u8]) -> [u8; 32],
{
    let mut normalized_key = if key.len() > 64 {
        hash(key).to_vec()
    } else {
        key.to_vec()
    };
    normalized_key.resize(64, 0);
    let mut inner = [0x36; 64];
    let mut outer = [0x5c; 64];
    for (index, key_byte) in normalized_key.iter().enumerate() {
        inner[index] ^= key_byte;
        outer[index] ^= key_byte;
    }
    let mut inner_input = Vec::with_capacity(64 + message.len());
    inner_input.extend_from_slice(&inner);
    inner_input.extend_from_slice(message);
    let inner_hash = hash(&inner_input);
    let mut outer_input = Vec::with_capacity(64 + inner_hash.len());
    outer_input.extend_from_slice(&outer);
    outer_input.extend_from_slice(&inner_hash);
    hash(&outer_input)
}

fn vmess_aes_gcm_seal(
    key: &[u8; 16],
    nonce: &[u8; 12],
    input: &[u8],
    aad: &[u8],
) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid vmess aes-gcm key"))?;
    cipher
        .encrypt(AesGcmNonce::from_slice(nonce), Payload { msg: input, aad })
        .map_err(|_| io::Error::other("vmess aes-gcm seal failed"))
}

fn vmess_aes_gcm_open(
    key: &[u8; 16],
    nonce: &[u8; 12],
    input: &[u8],
    aad: &[u8],
) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid vmess aes-gcm key"))?;
    cipher
        .decrypt(AesGcmNonce::from_slice(nonce), Payload { msg: input, aad })
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "vmess aes-gcm open failed"))
}

fn vmess_body_seal(
    security: VmessBodySecurity,
    key: &[u8; 16],
    nonce: &[u8; 12],
    input: &[u8],
) -> io::Result<Vec<u8>> {
    match security {
        VmessBodySecurity::Aes128Gcm => vmess_aes_gcm_seal(key, nonce, input, &[]),
        VmessBodySecurity::Chacha20Poly1305 => {
            let key = vmess_chacha20_poly1305_key(key);
            vmess_chacha20_poly1305_seal(&key, nonce, input)
        }
        VmessBodySecurity::None => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vmess none security does not use AEAD body chunks",
        )),
    }
}

fn vmess_body_open(
    security: VmessBodySecurity,
    key: &[u8; 16],
    nonce: &[u8; 12],
    input: &[u8],
) -> io::Result<Vec<u8>> {
    match security {
        VmessBodySecurity::Aes128Gcm => vmess_aes_gcm_open(key, nonce, input, &[]),
        VmessBodySecurity::Chacha20Poly1305 => {
            let key = vmess_chacha20_poly1305_key(key);
            vmess_chacha20_poly1305_open(&key, nonce, input)
        }
        VmessBodySecurity::None => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vmess none security does not use AEAD body chunks",
        )),
    }
}

fn vmess_chacha20_poly1305_key(input: &[u8; 16]) -> [u8; 32] {
    let mut output = [0; 32];
    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, input);
    let first = hasher.finalize();
    output[..16].copy_from_slice(&first);

    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, &output[..16]);
    let second = hasher.finalize();
    output[16..].copy_from_slice(&second);
    output
}

fn vmess_chacha20_poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    input: &[u8],
) -> io::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid vmess chacha20-poly1305 key",
        )
    })?;
    cipher
        .encrypt(
            ChachaNonce::from_slice(nonce),
            Payload {
                msg: input,
                aad: &[],
            },
        )
        .map_err(|_| io::Error::other("vmess chacha20-poly1305 seal failed"))
}

fn vmess_chacha20_poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    input: &[u8],
) -> io::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid vmess chacha20-poly1305 key",
        )
    })?;
    cipher
        .decrypt(
            ChachaNonce::from_slice(nonce),
            Payload {
                msg: input,
                aad: &[],
            },
        )
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "vmess chacha20-poly1305 open failed",
            )
        })
}

fn first_16_sha256(input: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, input);
    let digest = hasher.finalize();
    digest[..16].try_into().expect("sha256 first 16")
}

fn first_12(input: &[u8; 32]) -> [u8; 12] {
    input[..12].try_into().expect("first 12")
}

fn random_array<const N: usize>() -> [u8; N] {
    let mut output = [0; N];
    rand::thread_rng().fill_bytes(&mut output);
    output
}

fn fnv1a(input: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for byte in input {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
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

impl OwnedRelayStream for crate::WebSocketClientStream {
    fn set_nonblocking_mode(&mut self, nonblocking: bool) -> io::Result<()> {
        crate::WebSocketClientStream::set_nonblocking_mode(self, nonblocking)
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        crate::WebSocketClientStream::shutdown_write(self)
    }

    fn shutdown_both(&mut self) -> io::Result<()> {
        crate::WebSocketClientStream::shutdown_both(self)
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

impl OwnedRelayStream for crate::LegacyQuicTcpStream {
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

impl OwnedRelayStream for crate::Hy2BlockingTcpStream {
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

impl OwnedRelayStream for crate::TuicBlockingTcpStream {
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
