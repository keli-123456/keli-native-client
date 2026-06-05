use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{error::Error, fmt};

mod direct;
mod dns;
mod grpc;
mod http2;
mod http_connect;
mod http_proxy;
mod metrics;
mod mieru;
mod naive;
mod quic;
mod socks5;
mod tun;
mod websocket;

pub use direct::{
    relay_outbound_bidirectional_with_options, relay_owned_bidirectional_with_options,
    relay_tcp_bidirectional, relay_tcp_bidirectional_with_options, AnyTlsTlsTcpOutbound,
    DirectTcpConnector, DirectUdpConnector, HttpConnectOutbound, Hy2Outbound, OutboundConnection,
    OutboundProfileError, OutboundRegistry, OutboundTarget, OwnedRelayStream, RelayError,
    RelayOptions, RelayStats, ShadowsocksTcpOutbound, Socks5TcpOutbound, TlsTcpStream,
    TrojanGrpcOutbound, TrojanH2Outbound, TrojanHttpUpgradeOutbound, TrojanQuicOutbound,
    TrojanTcpOutbound, TrojanTlsGrpcOutbound, TrojanTlsH2Outbound, TrojanTlsHttpUpgradeOutbound,
    TrojanTlsTcpOutbound, TrojanTlsWsOutbound, TrojanWsOutbound, TuicOutbound, UdpRelayResponse,
    VlessGrpcOutbound, VlessH2Outbound, VlessHttpUpgradeOutbound, VlessQuicOutbound,
    VlessTcpOutbound, VlessTlsGrpcOutbound, VlessTlsH2Outbound, VlessTlsHttpUpgradeOutbound,
    VlessTlsTcpOutbound, VlessTlsWsOutbound, VlessWsOutbound, VmessBodySecurity, VmessGrpcOutbound,
    VmessH2Outbound, VmessHttpUpgradeOutbound, VmessQuicOutbound, VmessTcpOutbound,
    VmessTlsGrpcOutbound, VmessTlsH2Outbound, VmessTlsHttpUpgradeOutbound, VmessTlsTcpOutbound,
    VmessTlsWsOutbound, VmessWsOutbound,
};
pub use dns::{
    build_dns_error_response, build_dns_response, parse_dns_query, DnsAddressFamilyPolicy,
    DnsCache, DnsEngine, DnsError, DnsLocalResolutionPolicy, DnsQuestionType, DnsResolver,
    DnsWireError, DnsWireQuestion, ResolvedAddress, SystemDnsResolver,
};
pub use grpc::GrpcTcpStream;
pub use http2::Http2TcpStream;
pub use http_connect::{
    http_connect_bad_request_response, http_connect_success_response, parse_http_connect_request,
    HttpConnectError, HttpConnectRequest,
};
pub use http_proxy::{
    http_proxy_bad_request_response, parse_http_proxy_request, HttpProxyError, HttpProxyRequest,
};
pub use metrics::{ConnectionErrorKind, ConnectionReport};
pub use mieru::{MieruTcpOutbound, MieruTcpStream};
pub use naive::{NaiveH2TcpOutbound, NaiveH2TcpStream, NaiveH3QuicOutbound, NaiveH3QuicStream};
pub use quic::{
    h3_client_from_quinn_connection, h3_quic_client_config, h3_quic_client_endpoint,
    h3_quic_connect, h3_rustls_client_config, hy2_auth_http_request, hy2_authenticate_h3,
    hy2_open_authenticated_tcp_stream, hy2_open_tcp_stream, hy2_read_udp_datagram,
    hy2_send_udp_datagram, legacy_quic_client_config, legacy_quic_client_endpoint,
    legacy_quic_connect, legacy_quic_rustls_client_config, tuic_authenticate,
    tuic_authenticate_command, tuic_export_token, tuic_open_tcp_stream, tuic_read_packet_datagram,
    tuic_send_packet_datagram, validate_hy2_auth_response, Hy2BlockingTcpStream, Hy2ClientSession,
    Hy2H3Connection, Hy2H3SendRequest, Hy2QuicTcpStream, LegacyQuicTcpStream,
    LegacyQuicTransportConfig, TuicBlockingTcpStream, TuicClientSession, TuicQuicTcpStream,
    LEGACY_QUIC_INTERNAL_SERVER_NAME,
};
pub use socks5::{
    encode_socks5_udp_datagram, parse_socks5_handshake, parse_socks5_request,
    parse_socks5_udp_datagram, socks5_no_auth_response, socks5_reply, Socks5Address, Socks5Command,
    Socks5Error, Socks5Handshake, Socks5ReplyCode, Socks5Request, Socks5UdpDatagram,
};
pub use tun::{
    build_tun_dns_hijack_response, build_tun_dns_response_packet,
    build_tun_tcp_ack_response_packet, build_tun_tcp_fin_ack_response_packet,
    build_tun_tcp_payload_response_packet, build_tun_tcp_reset_response_packet,
    build_tun_tcp_response_packet, build_tun_tcp_syn_ack_response_packet,
    build_tun_udp_response_packet, decide_tun_packet_route, parse_tun_packet_flow,
    parse_tun_tcp_segment, parse_tun_udp_payload, plan_tun_dns_hijack, plan_tun_packet_relay,
    process_tun_device_packet, process_tun_device_packet_with_relays,
    process_tun_device_packet_with_tcp_session_relay, process_tun_device_packet_with_udp_relay,
    process_tun_packet, process_tun_tcp_session_segment, relay_tun_direct_udp_packet,
    relay_tun_udp_packet, run_tun_packet_loop, run_tun_packet_loop_summary,
    run_tun_packet_loop_with_relays_summary, run_tun_packet_loop_with_tcp_session_relay_summary,
    run_tun_packet_loop_with_udp_relay_summary, RegistryTunTcpSessionRelay, RegistryTunUdpRelay,
    TunDnsHijackPlan, TunDnsHijackResponse, TunIpVersion, TunPacketDevice, TunPacketError,
    TunPacketFlow, TunPacketLoopError, TunPacketLoopEvent, TunPacketLoopSummary,
    TunPacketProcessAction, TunPacketRelayAction, TunPacketRelayPlan, TunPacketRouteDecision,
    TunTcpClientPayloadFrame, TunTcpCloseFrame, TunTcpFlags, TunTcpResetResponse, TunTcpSegment,
    TunTcpServerCloseFrame, TunTcpServerPayloadFrame, TunTcpServerRead, TunTcpSessionError,
    TunTcpSessionKey, TunTcpSessionPhase, TunTcpSessionRecord, TunTcpSessionRelay,
    TunTcpSessionStep, TunTcpSessionTable, TunTcpSynAckResponse, TunTransportProtocol,
    TunUdpPayload, TunUdpRelay, TunUdpRelayError, TunUdpRelayResponse,
};
pub use websocket::{websocket_accept_for_key, OwnedWebSocketClientStream, WebSocketClientStream};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalInbound {
    Mixed { listen: String, port: u16 },
    Socks { listen: String, port: u16 },
    Http { listen: String, port: u16 },
    Tun { interface_name: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteTarget {
    Domain(String),
    Ip(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDestination {
    pub target: RouteTarget,
    pub port: u16,
}

impl RouteDestination {
    pub fn new(target: RouteTarget, port: u16) -> Self {
        Self { target, port }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteIpCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl RouteIpCidr {
    pub fn new(network: IpAddr, prefix_len: u8) -> Result<Self, RouteCidrError> {
        let max_prefix_len = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix_len {
            return Err(RouteCidrError::InvalidPrefixLength {
                network,
                prefix_len,
            });
        }
        Ok(Self {
            network: mask_ip(network, prefix_len),
            prefix_len,
        })
    }

    pub fn network(&self) -> IpAddr {
        self.network
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn matches(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = ipv4_prefix_mask(self.prefix_len);
                u32::from(network) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = ipv6_prefix_mask(self.prefix_len);
                u128::from(network) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteCidrError {
    InvalidPrefixLength { network: IpAddr, prefix_len: u8 },
}

impl fmt::Display for RouteCidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefixLength {
                network,
                prefix_len,
            } => write!(f, "invalid CIDR prefix length {prefix_len} for {network}"),
        }
    }
}

impl Error for RouteCidrError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteAction {
    Direct,
    Block,
    Outbound(String),
    HijackDns,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteMatcher {
    DomainExact(String),
    DomainKeyword(String),
    DomainSuffix(String),
    IpExact(IpAddr),
    IpCidr(RouteIpCidr),
    PortExact(u16),
    PortRange { start: u16, end: u16 },
}

impl RouteMatcher {
    fn matches(&self, destination: &RouteDestination) -> bool {
        match (self, &destination.target) {
            (Self::DomainExact(expected), RouteTarget::Domain(actual)) => {
                expected.eq_ignore_ascii_case(actual)
            }
            (Self::DomainKeyword(expected), RouteTarget::Domain(actual)) => actual
                .to_ascii_lowercase()
                .contains(&expected.to_ascii_lowercase()),
            (Self::DomainSuffix(expected), RouteTarget::Domain(actual)) => {
                let expected = expected.trim_start_matches('.');
                actual.eq_ignore_ascii_case(expected)
                    || actual
                        .to_ascii_lowercase()
                        .ends_with(&format!(".{}", expected.to_ascii_lowercase()))
            }
            (Self::IpExact(expected), RouteTarget::Ip(actual)) => expected == actual,
            (Self::IpCidr(cidr), RouteTarget::Ip(actual)) => cidr.matches(*actual),
            (Self::PortExact(expected), _) => destination.port == *expected,
            (Self::PortRange { start, end }, _) => {
                *start <= destination.port && destination.port <= *end
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRule {
    pub name: String,
    pub matcher: RouteMatcher,
    pub action: RouteAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    pub action: RouteAction,
    pub matched_rule: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEngine {
    rules: Vec<RouteRule>,
    default_action: RouteAction,
}

impl RouteEngine {
    pub fn new(default_action: RouteAction) -> Self {
        Self {
            rules: Vec::new(),
            default_action,
        }
    }

    pub fn add_rule(&mut self, rule: RouteRule) {
        self.rules.push(rule);
    }

    pub fn decide(&self, target: &RouteTarget) -> RouteDecision {
        self.decide_destination(&RouteDestination::new(target.clone(), 0))
    }

    pub fn decide_destination(&self, destination: &RouteDestination) -> RouteDecision {
        for rule in &self.rules {
            if rule.matcher.matches(destination) {
                return RouteDecision {
                    action: rule.action.clone(),
                    matched_rule: Some(rule.name.clone()),
                };
            }
        }
        RouteDecision {
            action: self.default_action.clone(),
            matched_rule: None,
        }
    }
}

fn mask_ip(ip: IpAddr, prefix_len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(u32::from(ip) & ipv4_prefix_mask(prefix_len))),
        IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(
            u128::from(ip) & ipv6_prefix_mask(prefix_len),
        )),
    }
}

fn ipv4_prefix_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn ipv6_prefix_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_domain_rule_wins() {
        let mut engine = RouteEngine::new(RouteAction::Outbound("proxy".to_string()));
        engine.add_rule(RouteRule {
            name: "block-example".to_string(),
            matcher: RouteMatcher::DomainExact("blocked.example".to_string()),
            action: RouteAction::Block,
        });

        let decision = engine.decide(&RouteTarget::Domain("blocked.example".to_string()));

        assert_eq!(decision.action, RouteAction::Block);
        assert_eq!(decision.matched_rule, Some("block-example".to_string()));
    }

    #[test]
    fn suffix_domain_rule_matches_subdomain() {
        let mut engine = RouteEngine::new(RouteAction::Outbound("proxy".to_string()));
        engine.add_rule(RouteRule {
            name: "direct-lan".to_string(),
            matcher: RouteMatcher::DomainSuffix("lan.example".to_string()),
            action: RouteAction::Direct,
        });

        let decision = engine.decide(&RouteTarget::Domain("router.lan.example".to_string()));

        assert_eq!(decision.action, RouteAction::Direct);
        assert_eq!(decision.matched_rule, Some("direct-lan".to_string()));
    }

    #[test]
    fn keyword_domain_rule_matches_case_insensitive() {
        let mut engine = RouteEngine::new(RouteAction::Outbound("proxy".to_string()));
        engine.add_rule(RouteRule {
            name: "direct-video".to_string(),
            matcher: RouteMatcher::DomainKeyword("Video".to_string()),
            action: RouteAction::Direct,
        });

        let decision = engine.decide(&RouteTarget::Domain("cdn.video.example".to_string()));

        assert_eq!(decision.action, RouteAction::Direct);
        assert_eq!(decision.matched_rule, Some("direct-video".to_string()));
    }

    #[test]
    fn cidr_rule_matches_ip_subnet() {
        let mut engine = RouteEngine::new(RouteAction::Outbound("proxy".to_string()));
        let cidr =
            RouteIpCidr::new("192.168.1.42".parse().expect("valid IP"), 24).expect("valid CIDR");
        engine.add_rule(RouteRule {
            name: "direct-lan-cidr".to_string(),
            matcher: RouteMatcher::IpCidr(cidr.clone()),
            action: RouteAction::Direct,
        });

        assert_eq!(
            cidr.network(),
            "192.168.1.0".parse::<IpAddr>().expect("valid IP")
        );
        let decision = engine.decide(&RouteTarget::Ip("192.168.1.99".parse().expect("valid IP")));

        assert_eq!(decision.action, RouteAction::Direct);
        assert_eq!(decision.matched_rule, Some("direct-lan-cidr".to_string()));
    }

    #[test]
    fn port_rule_matches_route_destination() {
        let mut engine = RouteEngine::new(RouteAction::Outbound("proxy".to_string()));
        engine.add_rule(RouteRule {
            name: "block-smtp".to_string(),
            matcher: RouteMatcher::PortRange { start: 25, end: 25 },
            action: RouteAction::Block,
        });

        let decision = engine.decide_destination(&RouteDestination::new(
            RouteTarget::Domain("mail.example".to_string()),
            25,
        ));

        assert_eq!(decision.action, RouteAction::Block);
        assert_eq!(decision.matched_rule, Some("block-smtp".to_string()));
    }

    #[test]
    fn invalid_cidr_prefix_is_rejected() {
        let error = RouteIpCidr::new("127.0.0.1".parse().expect("valid IP"), 33)
            .expect_err("invalid IPv4 prefix should fail");

        assert!(error.to_string().contains("invalid CIDR prefix length"));
    }

    #[test]
    fn unmatched_target_uses_default_action() {
        let engine = RouteEngine::new(RouteAction::Outbound("proxy".to_string()));

        let decision = engine.decide(&RouteTarget::Domain("youtube.com".to_string()));

        assert_eq!(decision.action, RouteAction::Outbound("proxy".to_string()));
        assert_eq!(decision.matched_rule, None);
    }
}
