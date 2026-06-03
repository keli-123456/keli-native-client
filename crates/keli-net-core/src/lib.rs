use std::net::IpAddr;

mod direct;
mod dns;
mod http_connect;
mod http_proxy;
mod metrics;
mod mieru;
mod naive;
mod quic;
mod socks5;
mod websocket;

pub use direct::{
    relay_outbound_bidirectional_with_options, relay_owned_bidirectional_with_options,
    relay_tcp_bidirectional, relay_tcp_bidirectional_with_options, AnyTlsTlsTcpOutbound,
    DirectTcpConnector, DirectUdpConnector, Hy2Outbound, OutboundConnection, OutboundProfileError,
    OutboundRegistry, OutboundTarget, OwnedRelayStream, RelayError, RelayOptions, RelayStats,
    ShadowsocksTcpOutbound, TlsTcpStream, TrojanTcpOutbound, TrojanTlsTcpOutbound,
    TrojanTlsWsOutbound, TrojanWsOutbound, UdpRelayResponse, VlessTcpOutbound, VlessTlsTcpOutbound,
    VlessTlsWsOutbound, VlessWsOutbound, VmessBodySecurity, VmessTcpOutbound, VmessTlsTcpOutbound,
    VmessTlsWsOutbound, VmessWsOutbound,
};
pub use dns::{DnsCache, DnsEngine, DnsError, DnsResolver, ResolvedAddress, SystemDnsResolver};
pub use http_connect::{
    http_connect_bad_request_response, http_connect_success_response, parse_http_connect_request,
    HttpConnectError, HttpConnectRequest,
};
pub use http_proxy::{
    http_proxy_bad_request_response, parse_http_proxy_request, HttpProxyError, HttpProxyRequest,
};
pub use metrics::{ConnectionErrorKind, ConnectionReport};
pub use mieru::{MieruTcpOutbound, MieruTcpStream};
pub use naive::{NaiveH2TcpOutbound, NaiveH2TcpStream};
pub use quic::{
    h3_client_from_quinn_connection, h3_quic_client_config, h3_quic_client_endpoint,
    h3_quic_connect, h3_rustls_client_config, hy2_auth_http_request, hy2_authenticate_h3,
    hy2_open_authenticated_tcp_stream, hy2_open_tcp_stream, hy2_read_udp_datagram,
    hy2_send_udp_datagram, tuic_authenticate, tuic_authenticate_command, tuic_export_token,
    tuic_open_tcp_stream, tuic_read_packet_datagram, tuic_send_packet_datagram,
    validate_hy2_auth_response, Hy2BlockingTcpStream, Hy2ClientSession, Hy2H3Connection,
    Hy2H3SendRequest, Hy2QuicTcpStream, TuicBlockingTcpStream, TuicClientSession,
    TuicQuicTcpStream,
};
pub use socks5::{
    encode_socks5_udp_datagram, parse_socks5_handshake, parse_socks5_request,
    parse_socks5_udp_datagram, socks5_no_auth_response, socks5_reply, Socks5Address, Socks5Command,
    Socks5Error, Socks5Handshake, Socks5ReplyCode, Socks5Request, Socks5UdpDatagram,
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
pub enum RouteAction {
    Direct,
    Block,
    Outbound(String),
    HijackDns,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteMatcher {
    DomainExact(String),
    DomainSuffix(String),
    IpExact(IpAddr),
}

impl RouteMatcher {
    fn matches(&self, target: &RouteTarget) -> bool {
        match (self, target) {
            (Self::DomainExact(expected), RouteTarget::Domain(actual)) => {
                expected.eq_ignore_ascii_case(actual)
            }
            (Self::DomainSuffix(expected), RouteTarget::Domain(actual)) => {
                let expected = expected.trim_start_matches('.');
                actual.eq_ignore_ascii_case(expected)
                    || actual
                        .to_ascii_lowercase()
                        .ends_with(&format!(".{}", expected.to_ascii_lowercase()))
            }
            (Self::IpExact(expected), RouteTarget::Ip(actual)) => expected == actual,
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
        for rule in &self.rules {
            if rule.matcher.matches(target) {
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
    fn unmatched_target_uses_default_action() {
        let engine = RouteEngine::new(RouteAction::Outbound("proxy".to_string()));

        let decision = engine.decide(&RouteTarget::Domain("youtube.com".to_string()));

        assert_eq!(decision.action, RouteAction::Outbound("proxy".to_string()));
        assert_eq!(decision.matched_rule, None);
    }
}
