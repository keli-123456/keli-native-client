use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::{error::Error, fmt};

use crate::dns::{
    build_dns_error_response, build_dns_response, parse_dns_query, DnsEngine, DnsError,
    DnsQuestionType, DnsResolver, DnsWireError, DnsWireQuestion,
};
use crate::{
    OutboundTarget, RouteAction, RouteDestination, RouteEngine, RouteTarget, UdpRelayResponse,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunIpVersion {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunTransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other(u8),
}

impl TunTransportProtocol {
    pub fn from_ip_protocol_number(value: u8) -> Self {
        match value {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            58 => Self::Icmpv6,
            other => Self::Other(other),
        }
    }

    pub fn ip_protocol_number(self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmpv6 => 58,
            Self::Other(value) => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunPacketFlow {
    pub ip_version: TunIpVersion,
    pub protocol: TunTransportProtocol,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunPacketRouteDecision {
    pub flow: TunPacketFlow,
    pub action: RouteAction,
    pub matched_rule: Option<String>,
    pub dns_hijacked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunPacketRelayAction {
    Drop,
    HijackDns,
    DirectTcp { target: OutboundTarget },
    DirectUdp { target: OutboundTarget },
    OutboundTcp { tag: String, target: OutboundTarget },
    OutboundUdp { tag: String, target: OutboundTarget },
    UnsupportedTransport { protocol: TunTransportProtocol },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunPacketRelayPlan {
    pub route: TunPacketRouteDecision,
    pub relay_action: TunPacketRelayAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunUdpPayload<'a> {
    pub flow: TunPacketFlow,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunDnsHijackPlan {
    pub flow: TunPacketFlow,
    pub question: DnsWireQuestion,
    pub response_source: SocketAddr,
    pub response_destination: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunDnsHijackResponse {
    pub plan: TunDnsHijackPlan,
    pub dns_payload: Vec<u8>,
    pub packet: Vec<u8>,
    pub rcode: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunUdpRelayResponse {
    pub plan: TunPacketRelayPlan,
    pub relay_source: SocketAddr,
    pub relay_payload: Vec<u8>,
    pub packet: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunPacketProcessAction {
    WritePacket { response: TunDnsHijackResponse },
    Relay(TunPacketRelayPlan),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunPacketLoopEvent {
    NoPacket,
    WrotePacket { response: TunDnsHijackResponse },
    WroteUdpRelayPacket { response: TunUdpRelayResponse },
    Relay(TunPacketRelayPlan),
    Drop(TunPacketRelayPlan),
    Unsupported(TunPacketRelayPlan),
    PacketError(TunPacketError),
    UdpRelayError(TunUdpRelayError),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunPacketLoopSummary {
    pub idle_events: usize,
    pub dns_responses_written: usize,
    pub udp_relay_responses_written: usize,
    pub relay_packets: usize,
    pub dropped_packets: usize,
    pub unsupported_packets: usize,
    pub packet_errors: usize,
    pub last_packet_error: Option<TunPacketError>,
    pub udp_relay_errors: usize,
    pub last_udp_relay_error: Option<TunUdpRelayError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunUdpRelayError {
    UnsupportedRelayAction(TunPacketRelayAction),
    Packet(TunPacketError),
    ResponsePacket(TunPacketError),
    PlanFlowMismatch {
        packet_flow: TunPacketFlow,
        plan_flow: TunPacketFlow,
    },
    Relay(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunPacketLoopError {
    Read(String),
    Write(String),
}

impl fmt::Display for TunPacketLoopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(f, "TUN packet read failed: {error}"),
            Self::Write(error) => write!(f, "TUN packet write failed: {error}"),
        }
    }
}

impl Error for TunPacketLoopError {}

pub trait TunPacketDevice {
    fn read_packet(&mut self) -> Result<Option<Vec<u8>>, String>;
    fn write_packet(&mut self, packet: &[u8]) -> Result<(), String>;
}

pub trait TunUdpRelay {
    fn relay_udp_datagram(
        &mut self,
        target: &OutboundTarget,
        payload: &[u8],
    ) -> Result<UdpRelayResponse, String>;

    fn relay_outbound_udp_datagram(
        &mut self,
        tag: &str,
        target: &OutboundTarget,
        payload: &[u8],
    ) -> Result<UdpRelayResponse, String> {
        let _ = (target, payload);
        Err(format!("outbound UDP relay is unsupported for tag: {tag}"))
    }
}

impl fmt::Display for TunUdpRelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedRelayAction(action) => {
                write!(f, "unsupported TUN UDP relay action: {action:?}")
            }
            Self::Packet(error) => write!(f, "failed to parse TUN UDP relay packet: {error}"),
            Self::ResponsePacket(error) => {
                write!(f, "failed to build TUN UDP relay response packet: {error}")
            }
            Self::PlanFlowMismatch {
                packet_flow,
                plan_flow,
            } => write!(
                f,
                "TUN UDP relay plan flow mismatch: packet={packet_flow:?} plan={plan_flow:?}"
            ),
            Self::Relay(error) => write!(f, "TUN UDP relay failed: {error}"),
        }
    }
}

impl Error for TunUdpRelayError {}

impl TunPacketLoopSummary {
    pub fn from_events(events: &[TunPacketLoopEvent]) -> Self {
        let mut summary = Self::default();
        for event in events {
            summary.record_event(event);
        }
        summary
    }

    pub fn record_event(&mut self, event: &TunPacketLoopEvent) {
        match event {
            TunPacketLoopEvent::NoPacket => {
                self.idle_events += 1;
            }
            TunPacketLoopEvent::WrotePacket { .. } => {
                self.dns_responses_written += 1;
            }
            TunPacketLoopEvent::WroteUdpRelayPacket { .. } => {
                self.udp_relay_responses_written += 1;
            }
            TunPacketLoopEvent::Relay(_) => {
                self.relay_packets += 1;
            }
            TunPacketLoopEvent::Drop(_) => {
                self.dropped_packets += 1;
            }
            TunPacketLoopEvent::Unsupported(_) => {
                self.unsupported_packets += 1;
            }
            TunPacketLoopEvent::PacketError(error) => {
                self.packet_errors += 1;
                self.last_packet_error = Some(error.clone());
            }
            TunPacketLoopEvent::UdpRelayError(error) => {
                self.udp_relay_errors += 1;
                self.last_udp_relay_error = Some(error.clone());
            }
        }
    }

    pub fn processed_packets(&self) -> usize {
        self.dns_responses_written
            + self.udp_relay_responses_written
            + self.relay_packets
            + self.dropped_packets
            + self.unsupported_packets
            + self.packet_errors
            + self.udp_relay_errors
    }
}

impl TunPacketFlow {
    pub fn route_destination(&self) -> RouteDestination {
        RouteDestination::new(
            RouteTarget::Ip(self.destination_ip),
            self.destination_port.unwrap_or(0),
        )
    }

    pub fn source_socket_addr(&self) -> Option<SocketAddr> {
        self.source_port
            .map(|port| SocketAddr::new(self.source_ip, port))
    }

    pub fn destination_socket_addr(&self) -> Option<SocketAddr> {
        self.destination_port
            .map(|port| SocketAddr::new(self.destination_ip, port))
    }

    pub fn destination_outbound_target(&self) -> Option<OutboundTarget> {
        self.destination_port
            .map(|port| OutboundTarget::new(self.destination_ip.to_string(), port))
    }

    pub fn is_dns_hijack_candidate(&self) -> bool {
        self.protocol == TunTransportProtocol::Udp && self.destination_port == Some(53)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunPacketError {
    PacketTooShort,
    UnsupportedIpVersion(u8),
    Ipv4HeaderTooShort {
        header_len: usize,
        packet_len: usize,
    },
    Ipv4TotalLengthTooShort {
        total_length: usize,
        header_len: usize,
    },
    Ipv4PacketTruncated {
        total_length: usize,
        packet_len: usize,
    },
    Ipv4FragmentedPacket {
        fragment_offset: u16,
        more_fragments: bool,
    },
    Ipv6PacketTruncated {
        total_length: usize,
        packet_len: usize,
    },
    Ipv6ExtensionHeaderUnsupported {
        next_header: u8,
    },
    TransportHeaderTooShort {
        protocol: TunTransportProtocol,
        required_len: usize,
        available_len: usize,
    },
    ExpectedUdpPayload {
        protocol: TunTransportProtocol,
    },
    UdpLengthTooShort {
        udp_length: usize,
    },
    UdpPacketTruncated {
        udp_length: usize,
        available_len: usize,
    },
    NotDnsHijackCandidate {
        destination_port: Option<u16>,
    },
    MissingUdpSocketAddress,
    IpVersionAddressMismatch {
        ip_version: TunIpVersion,
        source_ip: IpAddr,
        destination_ip: IpAddr,
    },
    UdpResponsePayloadTooLarge {
        ip_version: TunIpVersion,
        payload_len: usize,
        max_payload_len: usize,
    },
    DnsResolve(DnsError),
    DnsWire(DnsWireError),
}

impl fmt::Display for TunPacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort => write!(f, "TUN packet is too short"),
            Self::UnsupportedIpVersion(version) => {
                write!(f, "unsupported TUN packet IP version: {version}")
            }
            Self::Ipv4HeaderTooShort {
                header_len,
                packet_len,
            } => write!(
                f,
                "IPv4 header length {header_len} exceeds packet length {packet_len}"
            ),
            Self::Ipv4TotalLengthTooShort {
                total_length,
                header_len,
            } => write!(
                f,
                "IPv4 total length {total_length} is smaller than header length {header_len}"
            ),
            Self::Ipv4PacketTruncated {
                total_length,
                packet_len,
            } => write!(
                f,
                "IPv4 packet length {packet_len} is smaller than total length {total_length}"
            ),
            Self::Ipv4FragmentedPacket {
                fragment_offset,
                more_fragments,
            } => write!(
                f,
                "fragmented IPv4 TUN packets are unsupported: offset={fragment_offset}, more_fragments={more_fragments}"
            ),
            Self::Ipv6PacketTruncated {
                total_length,
                packet_len,
            } => write!(
                f,
                "IPv6 packet length {packet_len} is smaller than total length {total_length}"
            ),
            Self::Ipv6ExtensionHeaderUnsupported { next_header } => write!(
                f,
                "IPv6 extension header {next_header} is unsupported in TUN packets"
            ),
            Self::TransportHeaderTooShort {
                protocol,
                required_len,
                available_len,
            } => write!(
                f,
                "transport header for {:?} is too short: required {required_len}, available {available_len}",
                protocol
            ),
            Self::ExpectedUdpPayload { protocol } => {
                write!(f, "expected UDP TUN payload, got {:?}", protocol)
            }
            Self::UdpLengthTooShort { udp_length } => {
                write!(f, "UDP length {udp_length} is smaller than header length 8")
            }
            Self::UdpPacketTruncated {
                udp_length,
                available_len,
            } => write!(
                f,
                "UDP payload length {udp_length} exceeds available transport bytes {available_len}"
            ),
            Self::NotDnsHijackCandidate { destination_port } => write!(
                f,
                "TUN UDP packet is not a DNS hijack candidate: destination_port={}",
                destination_port
                    .map(|port| port.to_string())
                    .unwrap_or_else(|| "-".to_string())
            ),
            Self::MissingUdpSocketAddress => write!(f, "TUN UDP flow is missing a socket address"),
            Self::IpVersionAddressMismatch {
                ip_version,
                source_ip,
                destination_ip,
            } => write!(
                f,
                "TUN {ip_version:?} flow has mismatched addresses: source={source_ip}, destination={destination_ip}"
            ),
            Self::UdpResponsePayloadTooLarge {
                ip_version,
                payload_len,
                max_payload_len,
            } => write!(
                f,
                "TUN {ip_version:?} UDP response payload length {payload_len} exceeds max {max_payload_len}"
            ),
            Self::DnsResolve(error) => write!(f, "failed to resolve TUN DNS query: {error}"),
            Self::DnsWire(error) => write!(f, "failed to parse TUN DNS query: {error}"),
        }
    }
}

impl Error for TunPacketError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::DnsResolve(error) => Some(error),
            Self::DnsWire(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TunPacketParts<'a> {
    flow: TunPacketFlow,
    transport_payload: &'a [u8],
}

pub fn parse_tun_packet_flow(packet: &[u8]) -> Result<TunPacketFlow, TunPacketError> {
    Ok(parse_tun_packet_parts(packet)?.flow)
}

pub fn parse_tun_udp_payload(packet: &[u8]) -> Result<TunUdpPayload<'_>, TunPacketError> {
    let parts = parse_tun_packet_parts(packet)?;
    if parts.flow.protocol != TunTransportProtocol::Udp {
        return Err(TunPacketError::ExpectedUdpPayload {
            protocol: parts.flow.protocol,
        });
    }
    if parts.transport_payload.len() < 8 {
        return Err(TunPacketError::TransportHeaderTooShort {
            protocol: TunTransportProtocol::Udp,
            required_len: 8,
            available_len: parts.transport_payload.len(),
        });
    }
    let udp_length = usize::from(u16::from_be_bytes([
        parts.transport_payload[4],
        parts.transport_payload[5],
    ]));
    if udp_length < 8 {
        return Err(TunPacketError::UdpLengthTooShort { udp_length });
    }
    if udp_length > parts.transport_payload.len() {
        return Err(TunPacketError::UdpPacketTruncated {
            udp_length,
            available_len: parts.transport_payload.len(),
        });
    }
    Ok(TunUdpPayload {
        flow: parts.flow,
        payload: &parts.transport_payload[8..udp_length],
    })
}

pub fn plan_tun_dns_hijack(packet: &[u8]) -> Result<TunDnsHijackPlan, TunPacketError> {
    let udp = parse_tun_udp_payload(packet)?;
    if !udp.flow.is_dns_hijack_candidate() {
        return Err(TunPacketError::NotDnsHijackCandidate {
            destination_port: udp.flow.destination_port,
        });
    }
    let question = parse_dns_query(udp.payload).map_err(TunPacketError::DnsWire)?;
    let response_source = udp
        .flow
        .destination_socket_addr()
        .ok_or(TunPacketError::MissingUdpSocketAddress)?;
    let response_destination = udp
        .flow
        .source_socket_addr()
        .ok_or(TunPacketError::MissingUdpSocketAddress)?;
    Ok(TunDnsHijackPlan {
        flow: udp.flow,
        question,
        response_source,
        response_destination,
    })
}

pub fn build_tun_dns_response_packet(
    plan: &TunDnsHijackPlan,
    payload: &[u8],
) -> Result<Vec<u8>, TunPacketError> {
    build_tun_udp_response_packet(&plan.flow, payload)
}

pub fn build_tun_dns_hijack_response<R: DnsResolver>(
    packet: &[u8],
    dns: &mut DnsEngine<R>,
    ttl_seconds: u32,
) -> Result<TunDnsHijackResponse, TunPacketError> {
    let plan = plan_tun_dns_hijack(packet)?;
    let (dns_payload, rcode) = build_tun_dns_hijack_payload(&plan, dns, ttl_seconds)?;
    let packet = build_tun_dns_response_packet(&plan, &dns_payload)?;
    Ok(TunDnsHijackResponse {
        plan,
        dns_payload,
        packet,
        rcode,
    })
}

pub fn process_tun_packet<R: DnsResolver>(
    packet: &[u8],
    routes: &RouteEngine,
    dns_hijack_enabled: bool,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
) -> Result<TunPacketProcessAction, TunPacketError> {
    let relay_plan = plan_tun_packet_relay(packet, routes, dns_hijack_enabled)?;
    if relay_plan.relay_action == TunPacketRelayAction::HijackDns {
        return Ok(TunPacketProcessAction::WritePacket {
            response: build_tun_dns_hijack_response(packet, dns, dns_ttl_seconds)?,
        });
    }
    Ok(TunPacketProcessAction::Relay(relay_plan))
}

pub fn process_tun_device_packet<D: TunPacketDevice, R: DnsResolver>(
    device: &mut D,
    routes: &RouteEngine,
    dns_hijack_enabled: bool,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
) -> Result<TunPacketLoopEvent, TunPacketLoopError> {
    let Some(packet) = device.read_packet().map_err(TunPacketLoopError::Read)? else {
        return Ok(TunPacketLoopEvent::NoPacket);
    };

    let action = match process_tun_packet(&packet, routes, dns_hijack_enabled, dns, dns_ttl_seconds)
    {
        Ok(action) => action,
        Err(error) => return Ok(TunPacketLoopEvent::PacketError(error)),
    };

    match action {
        TunPacketProcessAction::WritePacket { response } => {
            device
                .write_packet(&response.packet)
                .map_err(TunPacketLoopError::Write)?;
            Ok(TunPacketLoopEvent::WrotePacket { response })
        }
        TunPacketProcessAction::Relay(plan) => Ok(loop_event_for_relay_plan(plan)),
    }
}

pub fn process_tun_device_packet_with_udp_relay<D, R, U>(
    device: &mut D,
    routes: &RouteEngine,
    dns_hijack_enabled: bool,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
    udp_relay: &mut U,
) -> Result<TunPacketLoopEvent, TunPacketLoopError>
where
    D: TunPacketDevice,
    R: DnsResolver,
    U: TunUdpRelay,
{
    let Some(packet) = device.read_packet().map_err(TunPacketLoopError::Read)? else {
        return Ok(TunPacketLoopEvent::NoPacket);
    };

    let action = match process_tun_packet(&packet, routes, dns_hijack_enabled, dns, dns_ttl_seconds)
    {
        Ok(action) => action,
        Err(error) => return Ok(TunPacketLoopEvent::PacketError(error)),
    };

    match action {
        TunPacketProcessAction::WritePacket { response } => {
            device
                .write_packet(&response.packet)
                .map_err(TunPacketLoopError::Write)?;
            Ok(TunPacketLoopEvent::WrotePacket { response })
        }
        TunPacketProcessAction::Relay(plan) => {
            if matches!(
                plan.relay_action,
                TunPacketRelayAction::DirectUdp { .. } | TunPacketRelayAction::OutboundUdp { .. }
            ) {
                let response = match relay_tun_udp_packet(&packet, plan, udp_relay) {
                    Ok(response) => response,
                    Err(error) => return Ok(TunPacketLoopEvent::UdpRelayError(error)),
                };
                device
                    .write_packet(&response.packet)
                    .map_err(TunPacketLoopError::Write)?;
                return Ok(TunPacketLoopEvent::WroteUdpRelayPacket { response });
            }
            Ok(loop_event_for_relay_plan(plan))
        }
    }
}

pub fn run_tun_packet_loop<D: TunPacketDevice, R: DnsResolver>(
    device: &mut D,
    routes: &RouteEngine,
    dns_hijack_enabled: bool,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
    max_packets: usize,
) -> Result<Vec<TunPacketLoopEvent>, TunPacketLoopError> {
    let mut events = Vec::new();
    for _ in 0..max_packets {
        let event =
            process_tun_device_packet(device, routes, dns_hijack_enabled, dns, dns_ttl_seconds)?;
        let should_stop = event == TunPacketLoopEvent::NoPacket;
        events.push(event);
        if should_stop {
            break;
        }
    }
    Ok(events)
}

pub fn run_tun_packet_loop_summary<D: TunPacketDevice, R: DnsResolver>(
    device: &mut D,
    routes: &RouteEngine,
    dns_hijack_enabled: bool,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
    max_packets: usize,
) -> Result<TunPacketLoopSummary, TunPacketLoopError> {
    let mut summary = TunPacketLoopSummary::default();
    for _ in 0..max_packets {
        let event =
            process_tun_device_packet(device, routes, dns_hijack_enabled, dns, dns_ttl_seconds)?;
        let should_stop = event == TunPacketLoopEvent::NoPacket;
        summary.record_event(&event);
        if should_stop {
            break;
        }
    }
    Ok(summary)
}

pub fn run_tun_packet_loop_with_udp_relay_summary<D, R, U>(
    device: &mut D,
    routes: &RouteEngine,
    dns_hijack_enabled: bool,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
    max_packets: usize,
    udp_relay: &mut U,
) -> Result<TunPacketLoopSummary, TunPacketLoopError>
where
    D: TunPacketDevice,
    R: DnsResolver,
    U: TunUdpRelay,
{
    let mut summary = TunPacketLoopSummary::default();
    for _ in 0..max_packets {
        let event = process_tun_device_packet_with_udp_relay(
            device,
            routes,
            dns_hijack_enabled,
            dns,
            dns_ttl_seconds,
            udp_relay,
        )?;
        let should_stop = event == TunPacketLoopEvent::NoPacket;
        summary.record_event(&event);
        if should_stop {
            break;
        }
    }
    Ok(summary)
}

pub fn relay_tun_direct_udp_packet<U: TunUdpRelay>(
    packet: &[u8],
    plan: TunPacketRelayPlan,
    udp_relay: &mut U,
) -> Result<TunUdpRelayResponse, TunUdpRelayError> {
    if !matches!(plan.relay_action, TunPacketRelayAction::DirectUdp { .. }) {
        return Err(TunUdpRelayError::UnsupportedRelayAction(
            plan.relay_action.clone(),
        ));
    }
    relay_tun_udp_packet(packet, plan, udp_relay)
}

pub fn relay_tun_udp_packet<U: TunUdpRelay>(
    packet: &[u8],
    plan: TunPacketRelayPlan,
    udp_relay: &mut U,
) -> Result<TunUdpRelayResponse, TunUdpRelayError> {
    let udp = parse_tun_udp_payload(packet).map_err(TunUdpRelayError::Packet)?;
    if udp.flow != plan.route.flow {
        return Err(TunUdpRelayError::PlanFlowMismatch {
            packet_flow: udp.flow,
            plan_flow: plan.route.flow,
        });
    }
    let relay_response = match &plan.relay_action {
        TunPacketRelayAction::DirectUdp { target } => {
            udp_relay.relay_udp_datagram(target, udp.payload)
        }
        TunPacketRelayAction::OutboundUdp { tag, target } => {
            udp_relay.relay_outbound_udp_datagram(tag, target, udp.payload)
        }
        action => {
            return Err(TunUdpRelayError::UnsupportedRelayAction(action.clone()));
        }
    }
    .map_err(TunUdpRelayError::Relay)?;
    let packet = build_tun_udp_response_packet(&udp.flow, &relay_response.payload)
        .map_err(TunUdpRelayError::ResponsePacket)?;
    Ok(TunUdpRelayResponse {
        plan,
        relay_source: relay_response.source,
        relay_payload: relay_response.payload,
        packet,
    })
}

pub fn build_tun_udp_response_packet(
    flow: &TunPacketFlow,
    payload: &[u8],
) -> Result<Vec<u8>, TunPacketError> {
    if flow.protocol != TunTransportProtocol::Udp {
        return Err(TunPacketError::ExpectedUdpPayload {
            protocol: flow.protocol,
        });
    }
    let source_port = flow
        .destination_port
        .ok_or(TunPacketError::MissingUdpSocketAddress)?;
    let destination_port = flow
        .source_port
        .ok_or(TunPacketError::MissingUdpSocketAddress)?;

    match (flow.ip_version, flow.destination_ip, flow.source_ip) {
        (TunIpVersion::Ipv4, IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
            let max_payload_len = u16::MAX as usize - 20 - 8;
            if payload.len() > max_payload_len {
                return Err(TunPacketError::UdpResponsePayloadTooLarge {
                    ip_version: flow.ip_version,
                    payload_len: payload.len(),
                    max_payload_len,
                });
            }
            Ok(build_ipv4_udp_response_packet(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                payload,
            ))
        }
        (TunIpVersion::Ipv6, IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
            let max_payload_len = u16::MAX as usize - 8;
            if payload.len() > max_payload_len {
                return Err(TunPacketError::UdpResponsePayloadTooLarge {
                    ip_version: flow.ip_version,
                    payload_len: payload.len(),
                    max_payload_len,
                });
            }
            Ok(build_ipv6_udp_response_packet(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                payload,
            ))
        }
        _ => Err(TunPacketError::IpVersionAddressMismatch {
            ip_version: flow.ip_version,
            source_ip: flow.source_ip,
            destination_ip: flow.destination_ip,
        }),
    }
}

fn loop_event_for_relay_plan(plan: TunPacketRelayPlan) -> TunPacketLoopEvent {
    match &plan.relay_action {
        TunPacketRelayAction::Drop => TunPacketLoopEvent::Drop(plan),
        TunPacketRelayAction::UnsupportedTransport { .. } => TunPacketLoopEvent::Unsupported(plan),
        _ => TunPacketLoopEvent::Relay(plan),
    }
}

fn build_tun_dns_hijack_payload<R: DnsResolver>(
    plan: &TunDnsHijackPlan,
    dns: &mut DnsEngine<R>,
    ttl_seconds: u32,
) -> Result<(Vec<u8>, u8), TunPacketError> {
    if matches!(plan.question.question_type, DnsQuestionType::Unsupported(_)) {
        return Ok((build_dns_error_response(&plan.question, 4), 4));
    }
    match dns.resolve(&plan.question.name, 0) {
        Ok(addresses) => {
            let ips = addresses
                .into_iter()
                .map(|address| address.ip)
                .collect::<Vec<_>>();
            Ok((build_dns_response(&plan.question, &ips, ttl_seconds), 0))
        }
        Err(DnsError::LocalResolutionBlocked { .. })
        | Err(DnsError::AddressFamilyFiltered { .. })
        | Err(DnsError::NoRecords(_)) => Ok((build_dns_error_response(&plan.question, 3), 3)),
        Err(error) => Err(TunPacketError::DnsResolve(error)),
    }
}

fn parse_tun_packet_parts(packet: &[u8]) -> Result<TunPacketParts<'_>, TunPacketError> {
    let first = *packet.first().ok_or(TunPacketError::PacketTooShort)?;
    match first >> 4 {
        4 => parse_ipv4_packet_parts(packet),
        6 => parse_ipv6_packet_parts(packet),
        version => Err(TunPacketError::UnsupportedIpVersion(version)),
    }
}

pub fn decide_tun_packet_route(
    packet: &[u8],
    routes: &RouteEngine,
    dns_hijack_enabled: bool,
) -> Result<TunPacketRouteDecision, TunPacketError> {
    let flow = parse_tun_packet_flow(packet)?;
    if dns_hijack_enabled && flow.is_dns_hijack_candidate() {
        return Ok(TunPacketRouteDecision {
            flow,
            action: RouteAction::HijackDns,
            matched_rule: None,
            dns_hijacked: true,
        });
    }
    let decision = routes.decide_destination(&flow.route_destination());
    Ok(TunPacketRouteDecision {
        flow,
        action: decision.action,
        matched_rule: decision.matched_rule,
        dns_hijacked: false,
    })
}

pub fn plan_tun_packet_relay(
    packet: &[u8],
    routes: &RouteEngine,
    dns_hijack_enabled: bool,
) -> Result<TunPacketRelayPlan, TunPacketError> {
    let route = decide_tun_packet_route(packet, routes, dns_hijack_enabled)?;
    let relay_action = match route.action.clone() {
        RouteAction::Block => TunPacketRelayAction::Drop,
        RouteAction::HijackDns => TunPacketRelayAction::HijackDns,
        RouteAction::Direct => tun_relay_action_for_transport(&route.flow, None),
        RouteAction::Outbound(tag) => tun_relay_action_for_transport(&route.flow, Some(tag)),
    };
    Ok(TunPacketRelayPlan {
        route,
        relay_action,
    })
}

fn tun_relay_action_for_transport(
    flow: &TunPacketFlow,
    outbound_tag: Option<String>,
) -> TunPacketRelayAction {
    let Some(target) = flow.destination_outbound_target() else {
        return TunPacketRelayAction::UnsupportedTransport {
            protocol: flow.protocol,
        };
    };
    match (flow.protocol, outbound_tag) {
        (TunTransportProtocol::Tcp, Some(tag)) => TunPacketRelayAction::OutboundTcp { tag, target },
        (TunTransportProtocol::Udp, Some(tag)) => TunPacketRelayAction::OutboundUdp { tag, target },
        (TunTransportProtocol::Tcp, None) => TunPacketRelayAction::DirectTcp { target },
        (TunTransportProtocol::Udp, None) => TunPacketRelayAction::DirectUdp { target },
        (protocol, _) => TunPacketRelayAction::UnsupportedTransport { protocol },
    }
}

fn parse_ipv4_packet_parts(packet: &[u8]) -> Result<TunPacketParts<'_>, TunPacketError> {
    if packet.len() < 20 {
        return Err(TunPacketError::PacketTooShort);
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || header_len > packet.len() {
        return Err(TunPacketError::Ipv4HeaderTooShort {
            header_len,
            packet_len: packet.len(),
        });
    }
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_length < header_len {
        return Err(TunPacketError::Ipv4TotalLengthTooShort {
            total_length,
            header_len,
        });
    }
    if total_length > packet.len() {
        return Err(TunPacketError::Ipv4PacketTruncated {
            total_length,
            packet_len: packet.len(),
        });
    }
    let fragment_control = u16::from_be_bytes([packet[6], packet[7]]);
    let more_fragments = fragment_control & 0x2000 != 0;
    let fragment_offset = fragment_control & 0x1fff;
    if more_fragments || fragment_offset != 0 {
        return Err(TunPacketError::Ipv4FragmentedPacket {
            fragment_offset,
            more_fragments,
        });
    }
    let protocol = TunTransportProtocol::from_ip_protocol_number(packet[9]);
    let source_ip = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let destination_ip = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    let transport_payload = &packet[header_len..total_length];
    let (source_port, destination_port) = parse_transport_ports(protocol, transport_payload)?;

    Ok(TunPacketParts {
        flow: TunPacketFlow {
            ip_version: TunIpVersion::Ipv4,
            protocol,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
        },
        transport_payload,
    })
}

fn parse_ipv6_packet_parts(packet: &[u8]) -> Result<TunPacketParts<'_>, TunPacketError> {
    if packet.len() < 40 {
        return Err(TunPacketError::PacketTooShort);
    }
    let payload_length = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_length = 40 + payload_length;
    if total_length > packet.len() {
        return Err(TunPacketError::Ipv6PacketTruncated {
            total_length,
            packet_len: packet.len(),
        });
    }
    let next_header = packet[6];
    if is_ipv6_extension_header(next_header) {
        return Err(TunPacketError::Ipv6ExtensionHeaderUnsupported { next_header });
    }
    let protocol = TunTransportProtocol::from_ip_protocol_number(next_header);
    let source_ip = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[8..24]).expect("IPv6 source slice length"),
    ));
    let destination_ip = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[24..40]).expect("IPv6 destination slice length"),
    ));
    let transport_payload = &packet[40..total_length];
    let (source_port, destination_port) = parse_transport_ports(protocol, transport_payload)?;

    Ok(TunPacketParts {
        flow: TunPacketFlow {
            ip_version: TunIpVersion::Ipv6,
            protocol,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
        },
        transport_payload,
    })
}

fn parse_transport_ports(
    protocol: TunTransportProtocol,
    payload: &[u8],
) -> Result<(Option<u16>, Option<u16>), TunPacketError> {
    match protocol {
        TunTransportProtocol::Tcp | TunTransportProtocol::Udp => {
            if payload.len() < 4 {
                return Err(TunPacketError::TransportHeaderTooShort {
                    protocol,
                    required_len: 4,
                    available_len: payload.len(),
                });
            }
            Ok((
                Some(u16::from_be_bytes([payload[0], payload[1]])),
                Some(u16::from_be_bytes([payload[2], payload[3]])),
            ))
        }
        _ => Ok((None, None)),
    }
}

fn is_ipv6_extension_header(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 44 | 50 | 51 | 60)
}

fn build_ipv4_udp_response_packet(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_length = 8 + payload.len();
    let total_length = 20 + udp_length;
    let mut packet = vec![0; total_length];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = TunTransportProtocol::Udp.ip_protocol_number();
    packet[12..16].copy_from_slice(&source_ip.octets());
    packet[16..20].copy_from_slice(&destination_ip.octets());
    write_udp_datagram(&mut packet[20..], source_port, destination_port, payload);
    let udp_checksum = udp_checksum_ipv4(source_ip, destination_ip, &packet[20..]);
    packet[26..28].copy_from_slice(&udp_checksum.to_be_bytes());
    let header_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    packet
}

fn build_ipv6_udp_response_packet(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_length = 8 + payload.len();
    let mut packet = vec![0; 40 + udp_length];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(udp_length as u16).to_be_bytes());
    packet[6] = TunTransportProtocol::Udp.ip_protocol_number();
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());
    write_udp_datagram(&mut packet[40..], source_port, destination_port, payload);
    let udp_checksum = udp_checksum_ipv6(source_ip, destination_ip, &packet[40..]);
    packet[46..48].copy_from_slice(&udp_checksum.to_be_bytes());
    packet
}

fn write_udp_datagram(
    datagram: &mut [u8],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) {
    let udp_length = 8 + payload.len();
    datagram[0..2].copy_from_slice(&source_port.to_be_bytes());
    datagram[2..4].copy_from_slice(&destination_port.to_be_bytes());
    datagram[4..6].copy_from_slice(&(udp_length as u16).to_be_bytes());
    datagram[6..8].copy_from_slice(&0u16.to_be_bytes());
    datagram[8..].copy_from_slice(payload);
}

fn udp_checksum_ipv4(source_ip: Ipv4Addr, destination_ip: Ipv4Addr, udp_datagram: &[u8]) -> u16 {
    let mut sum = 0;
    add_checksum_bytes(&mut sum, &source_ip.octets());
    add_checksum_bytes(&mut sum, &destination_ip.octets());
    add_checksum_bytes(
        &mut sum,
        &[0, TunTransportProtocol::Udp.ip_protocol_number()],
    );
    add_checksum_bytes(&mut sum, &(udp_datagram.len() as u16).to_be_bytes());
    add_checksum_bytes(&mut sum, udp_datagram);
    nonzero_checksum(sum)
}

fn udp_checksum_ipv6(source_ip: Ipv6Addr, destination_ip: Ipv6Addr, udp_datagram: &[u8]) -> u16 {
    let mut sum = 0;
    add_checksum_bytes(&mut sum, &source_ip.octets());
    add_checksum_bytes(&mut sum, &destination_ip.octets());
    add_checksum_bytes(&mut sum, &(udp_datagram.len() as u32).to_be_bytes());
    add_checksum_bytes(
        &mut sum,
        &[0, 0, 0, TunTransportProtocol::Udp.ip_protocol_number()],
    );
    add_checksum_bytes(&mut sum, udp_datagram);
    nonzero_checksum(sum)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0;
    add_checksum_bytes(&mut sum, bytes);
    finish_checksum(sum)
}

fn nonzero_checksum(sum: u32) -> u16 {
    match finish_checksum(sum) {
        0 => u16::MAX,
        checksum => checksum,
    }
}

fn add_checksum_bytes(sum: &mut u32, bytes: &[u8]) {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in chunks.by_ref() {
        *sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let [last] = chunks.remainder() {
        *sum += u32::from(*last) << 8;
    }
}

fn finish_checksum(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
