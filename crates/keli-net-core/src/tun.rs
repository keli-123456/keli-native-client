use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use std::{error::Error, fmt};

use crate::dns::{
    build_dns_error_response, build_dns_response, parse_dns_query, DnsEngine, DnsError,
    DnsQuestionType, DnsResolver, DnsWireError, DnsWireQuestion,
};
use crate::{
    DirectTcpConnector, DirectUdpConnector, OutboundConnection, OutboundRegistry, OutboundTarget,
    OwnedRelayStream, RouteAction, RouteDestination, RouteEngine, RouteTarget, UdpRelayResponse,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunTcpFlags {
    bits: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunTcpSegment<'a> {
    pub flow: TunPacketFlow,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub header_len: usize,
    pub flags: TunTcpFlags,
    pub window_size: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TunTcpSessionKey {
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunTcpSessionPhase {
    SynReceived,
    Established,
    ClientFinReceived,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunTcpServerUnackedPayload {
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunTcpSessionRecord {
    pub key: TunTcpSessionKey,
    pub flow: TunPacketFlow,
    pub client_initial_sequence_number: u32,
    pub client_next_sequence_number: u32,
    pub server_initial_sequence_number: u32,
    pub server_next_sequence_number: u32,
    pub server_unacked_payload: Option<TunTcpServerUnackedPayload>,
    pub window_size: u16,
    pub phase: TunTcpSessionPhase,
    pub last_activity_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunTcpClientPayloadFrame {
    pub session: TunTcpSessionRecord,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub payload: Vec<u8>,
    pub ack_packet: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunTcpDuplicateClientPayloadAck {
    pub session: TunTcpSessionRecord,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub payload: Vec<u8>,
    pub ack_packet: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunTcpOutOfOrderClientPayloadAck {
    pub session: TunTcpSessionRecord,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub payload: Vec<u8>,
    pub ack_packet: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunTcpServerPayloadFrame {
    pub session: TunTcpSessionRecord,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub payload: Vec<u8>,
    pub packet: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunTcpServerCloseFrame {
    pub session: TunTcpSessionRecord,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub packet: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TunTcpServerClosedSession {
    response: TunTcpServerCloseFrame,
    last_activity_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TunTcpPostCloseSession {
    session: TunTcpSessionRecord,
    server_next_sequence_number: u32,
    client_next_sequence_number: u32,
    client_fin_sequence_number: Option<u32>,
    client_fin_ack_packet: Option<Vec<u8>>,
    last_activity_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunTcpCloseFrame {
    pub session: TunTcpSessionRecord,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub packet: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunTcpSynAckResponse {
    pub session: TunTcpSessionRecord,
    pub packet: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunTcpSessionResetFrame {
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub packet: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunTcpSessionPruneReport {
    pub pruned_sessions: usize,
    pub pruned_server_closed_sessions: usize,
    pub pruned_post_closed_sessions: usize,
    pub close_errors: usize,
    pub last_close_error: Option<TunTcpSessionError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunTcpSessionStep {
    Noop,
    SynAck {
        response: TunTcpSynAckResponse,
    },
    Reset {
        response: TunTcpSessionResetFrame,
    },
    Established {
        session: TunTcpSessionRecord,
    },
    ClientAck {
        session: TunTcpSessionRecord,
    },
    ClientPayload {
        frame: TunTcpClientPayloadFrame,
        server_response: Option<TunTcpServerPayloadFrame>,
        server_close: Option<TunTcpServerCloseFrame>,
    },
    ClientPayloadClosed {
        frame: TunTcpClientPayloadFrame,
        response: TunTcpCloseFrame,
        server_response: Option<TunTcpServerPayloadFrame>,
        server_close: Option<TunTcpServerCloseFrame>,
    },
    ClientFinAck {
        response: TunTcpCloseFrame,
        server_response: Option<TunTcpServerPayloadFrame>,
        server_close: Option<TunTcpServerCloseFrame>,
    },
    OverlappingClientPayload {
        frame: TunTcpClientPayloadFrame,
        server_response: Option<TunTcpServerPayloadFrame>,
        server_close: Option<TunTcpServerCloseFrame>,
    },
    DuplicateClientPayload {
        ack: TunTcpDuplicateClientPayloadAck,
    },
    OutOfOrderClientPayload {
        ack: TunTcpOutOfOrderClientPayloadAck,
    },
    ServerPayload {
        response: TunTcpServerPayloadFrame,
    },
    ServerPayloadRetransmission {
        response: TunTcpServerPayloadFrame,
    },
    ServerClosed {
        response: TunTcpServerCloseFrame,
    },
    ServerCloseRetransmission {
        response: TunTcpServerCloseFrame,
    },
    ServerCloseAcknowledged {
        session: TunTcpSessionRecord,
    },
    CloseMarkerReset {
        session: TunTcpSessionRecord,
        kind: TunTcpCloseMarkerResetKind,
    },
    ServerCloseClientFinAck {
        response: TunTcpCloseFrame,
    },
    ClientFinDuplicateAck {
        response: TunTcpCloseFrame,
        server_response: Option<TunTcpServerPayloadFrame>,
        server_close: Option<TunTcpServerCloseFrame>,
    },
    Closed {
        session: TunTcpSessionRecord,
        response: Option<TunTcpCloseFrame>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunTcpCloseMarkerResetKind {
    ServerClose,
    PostClose,
}

#[derive(Debug, Clone, Default)]
pub struct TunTcpSessionTable {
    sessions: HashMap<TunTcpSessionKey, TunTcpSessionRecord>,
    server_closed_sessions: HashMap<TunTcpSessionKey, TunTcpServerClosedSession>,
    post_closed_sessions: HashMap<TunTcpSessionKey, TunTcpPostCloseSession>,
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
pub struct TunTcpResetResponse {
    pub plan: TunPacketRelayPlan,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub packet: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunPacketProcessAction {
    WritePacket { response: TunDnsHijackResponse },
    WriteTcpReset { response: TunTcpResetResponse },
    Relay(TunPacketRelayPlan),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunPacketLoopEvent {
    NoPacket,
    WrotePacket {
        response: TunDnsHijackResponse,
    },
    WroteUdpRelayPacket {
        response: TunUdpRelayResponse,
    },
    WroteTcpResetPacket {
        response: TunTcpResetResponse,
    },
    TcpSession {
        plan: TunPacketRelayPlan,
        step: TunTcpSessionStep,
        packets_written: usize,
    },
    Relay(TunPacketRelayPlan),
    Drop(TunPacketRelayPlan),
    Unsupported(TunPacketRelayPlan),
    PacketError(TunPacketError),
    UdpRelayError(TunUdpRelayError),
    TcpSessionError(TunTcpSessionError),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunPacketLoopSummary {
    pub idle_events: usize,
    pub dns_responses_written: usize,
    pub udp_relay_responses_written: usize,
    pub tcp_resets_written: usize,
    pub relay_packets: usize,
    pub tcp_relay_plans: usize,
    pub udp_relay_plans: usize,
    pub dropped_packets: usize,
    pub unsupported_packets: usize,
    pub packet_errors: usize,
    pub last_packet_error: Option<TunPacketError>,
    pub udp_relay_errors: usize,
    pub last_udp_relay_error: Option<TunUdpRelayError>,
    pub tcp_session_events: usize,
    pub tcp_session_packets_written: usize,
    pub tcp_sessions_pruned: usize,
    pub tcp_server_closed_sessions_pruned: usize,
    pub tcp_post_closed_sessions_pruned: usize,
    pub tcp_server_close_marker_resets: usize,
    pub tcp_post_close_marker_resets: usize,
    pub tcp_session_errors: usize,
    pub last_tcp_session_error: Option<TunTcpSessionError>,
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
pub enum TunTcpSessionError {
    Packet(TunPacketError),
    Relay(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunTcpServerRead {
    NoPayload,
    Payload(Vec<u8>),
    Closed,
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

pub trait TunTcpSessionRelay {
    fn establish_session(&mut self, _session: &TunTcpSessionRecord) -> Result<(), String> {
        Ok(())
    }

    fn establish_session_with_plan(
        &mut self,
        session: &TunTcpSessionRecord,
        _plan: &TunPacketRelayPlan,
    ) -> Result<(), String> {
        self.establish_session(session)
    }

    fn write_client_payload(&mut self, _frame: &TunTcpClientPayloadFrame) -> Result<(), String> {
        Ok(())
    }

    fn shutdown_client_write(&mut self, session: &TunTcpSessionRecord) -> Result<(), String> {
        self.close_session(session)
    }

    fn read_server_payload(
        &mut self,
        _session: &TunTcpSessionRecord,
    ) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }

    fn read_server_event(
        &mut self,
        session: &TunTcpSessionRecord,
    ) -> Result<TunTcpServerRead, String> {
        match self.read_server_payload(session)? {
            Some(payload) => Ok(TunTcpServerRead::Payload(payload)),
            None => Ok(TunTcpServerRead::NoPayload),
        }
    }

    fn poll_server_payload(
        &mut self,
        session: &TunTcpSessionRecord,
    ) -> Result<Option<Vec<u8>>, String> {
        self.read_server_payload(session)
    }

    fn poll_server_event(
        &mut self,
        session: &TunTcpSessionRecord,
    ) -> Result<TunTcpServerRead, String> {
        match self.poll_server_payload(session)? {
            Some(payload) => Ok(TunTcpServerRead::Payload(payload)),
            None => Ok(TunTcpServerRead::NoPayload),
        }
    }

    fn close_session(&mut self, _session: &TunTcpSessionRecord) -> Result<(), String> {
        Ok(())
    }
}

const DEFAULT_TUN_PACKET_MTU: usize = 1500;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
const DEFAULT_TUN_TCP_RELAY_READ_BUFFER_SIZE: usize = 16 * 1024;
const TUN_TCP_RELAY_READ_POLL_INTERVAL: Duration = Duration::from_millis(1);
pub const DEFAULT_TUN_TCP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

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

pub struct RegistryTunTcpSessionRelay<'a, R: DnsResolver> {
    outbounds: &'a OutboundRegistry,
    dns: &'a mut DnsEngine<R>,
    timeout: Duration,
    sessions: HashMap<TunTcpSessionKey, OutboundConnection>,
    read_buffer_size: usize,
}

impl<'a, R: DnsResolver> RegistryTunTcpSessionRelay<'a, R> {
    pub fn new(
        outbounds: &'a OutboundRegistry,
        dns: &'a mut DnsEngine<R>,
        timeout: Duration,
    ) -> Self {
        Self {
            outbounds,
            dns,
            timeout,
            sessions: HashMap::new(),
            read_buffer_size: DEFAULT_TUN_TCP_RELAY_READ_BUFFER_SIZE,
        }
    }

    pub fn with_read_buffer_size(mut self, read_buffer_size: usize) -> Self {
        self.read_buffer_size = read_buffer_size.max(1);
        self
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    fn connect_for_plan(
        &mut self,
        plan: &TunPacketRelayPlan,
    ) -> Result<OutboundConnection, String> {
        let mut connection = match &plan.relay_action {
            TunPacketRelayAction::DirectTcp { target } => {
                DirectTcpConnector::connect_with_dns(target, self.timeout, &mut *self.dns)
                    .map(OutboundConnection::Tcp)
            }
            TunPacketRelayAction::OutboundTcp { tag, target } => {
                self.outbounds
                    .connect_with_dns(tag, target, self.timeout, &mut *self.dns)
            }
            action => {
                return Err(format!("unsupported TUN TCP relay action: {action:?}"));
            }
        }
        .map_err(|error| error.to_string())?;
        connection
            .set_nonblocking_mode(true)
            .map_err(|error| error.to_string())?;
        Ok(connection)
    }

    fn close_key(&mut self, key: &TunTcpSessionKey) {
        if let Some(connection) = self.sessions.remove(key) {
            let _ = connection.shutdown_both();
        }
    }
}

impl<R: DnsResolver> TunTcpSessionRelay for RegistryTunTcpSessionRelay<'_, R> {
    fn establish_session(&mut self, _session: &TunTcpSessionRecord) -> Result<(), String> {
        Err("registry TUN TCP relay requires a relay plan to establish sessions".to_string())
    }

    fn establish_session_with_plan(
        &mut self,
        session: &TunTcpSessionRecord,
        plan: &TunPacketRelayPlan,
    ) -> Result<(), String> {
        self.close_key(&session.key);
        let connection = self.connect_for_plan(plan)?;
        self.sessions.insert(session.key.clone(), connection);
        Ok(())
    }

    fn write_client_payload(&mut self, frame: &TunTcpClientPayloadFrame) -> Result<(), String> {
        let connection = self
            .sessions
            .get_mut(&frame.session.key)
            .ok_or_else(|| format!("TUN TCP session is not connected: {:?}", frame.session.key))?;
        connection
            .write_all(&frame.payload)
            .and_then(|_| connection.flush())
            .map_err(|error| error.to_string())
    }

    fn read_server_payload(
        &mut self,
        session: &TunTcpSessionRecord,
    ) -> Result<Option<Vec<u8>>, String> {
        match self.read_server_event(session)? {
            TunTcpServerRead::Payload(payload) => Ok(Some(payload)),
            TunTcpServerRead::NoPayload | TunTcpServerRead::Closed => Ok(None),
        }
    }

    fn poll_server_payload(
        &mut self,
        session: &TunTcpSessionRecord,
    ) -> Result<Option<Vec<u8>>, String> {
        match self.poll_server_event(session)? {
            TunTcpServerRead::Payload(payload) => Ok(Some(payload)),
            TunTcpServerRead::NoPayload | TunTcpServerRead::Closed => Ok(None),
        }
    }

    fn read_server_event(
        &mut self,
        session: &TunTcpSessionRecord,
    ) -> Result<TunTcpServerRead, String> {
        self.read_server_event_until(session, Some(Instant::now() + self.timeout))
    }

    fn poll_server_event(
        &mut self,
        session: &TunTcpSessionRecord,
    ) -> Result<TunTcpServerRead, String> {
        self.read_server_event_until(session, None)
    }

    fn close_session(&mut self, session: &TunTcpSessionRecord) -> Result<(), String> {
        self.close_key(&session.key);
        Ok(())
    }

    fn shutdown_client_write(&mut self, session: &TunTcpSessionRecord) -> Result<(), String> {
        let connection = self
            .sessions
            .get(&session.key)
            .ok_or_else(|| format!("TUN TCP session is not connected: {:?}", session.key))?;
        connection
            .shutdown_write()
            .map_err(|error| error.to_string())
    }
}

impl<'a, R: DnsResolver> RegistryTunTcpSessionRelay<'a, R> {
    fn read_server_event_until(
        &mut self,
        session: &TunTcpSessionRecord,
        deadline: Option<Instant>,
    ) -> Result<TunTcpServerRead, String> {
        let read_buffer_size =
            tun_tcp_relay_read_buffer_size_for_flow(&session.flow, self.read_buffer_size);
        let mut buffer = vec![0; read_buffer_size];
        loop {
            let read_result = match self.sessions.get_mut(&session.key) {
                Some(connection) => connection.read(&mut buffer),
                None => return Ok(TunTcpServerRead::Closed),
            };
            match read_result {
                Ok(0) => {
                    self.close_key(&session.key);
                    return Ok(TunTcpServerRead::Closed);
                }
                Ok(size) => {
                    buffer.truncate(size);
                    return Ok(TunTcpServerRead::Payload(buffer));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::TimedOut =>
                {
                    let Some(deadline) = deadline else {
                        return Ok(TunTcpServerRead::NoPayload);
                    };
                    let now = Instant::now();
                    if now >= deadline {
                        return Ok(TunTcpServerRead::NoPayload);
                    }
                    std::thread::sleep(
                        deadline
                            .saturating_duration_since(now)
                            .min(TUN_TCP_RELAY_READ_POLL_INTERVAL),
                    );
                }
                Err(error) => return Err(error.to_string()),
            }
        }
    }
}

fn tun_tcp_relay_read_buffer_size_for_flow(flow: &TunPacketFlow, configured_size: usize) -> usize {
    let max_payload_len = match flow.ip_version {
        TunIpVersion::Ipv4 => DEFAULT_TUN_PACKET_MTU - IPV4_HEADER_LEN - TCP_HEADER_LEN,
        TunIpVersion::Ipv6 => DEFAULT_TUN_PACKET_MTU - IPV6_HEADER_LEN - TCP_HEADER_LEN,
    };
    configured_size.max(1).min(max_payload_len)
}

pub struct RegistryTunUdpRelay<'a, R: DnsResolver> {
    outbounds: &'a OutboundRegistry,
    dns: &'a mut DnsEngine<R>,
    timeout: Duration,
}

impl<'a, R: DnsResolver> RegistryTunUdpRelay<'a, R> {
    pub fn new(
        outbounds: &'a OutboundRegistry,
        dns: &'a mut DnsEngine<R>,
        timeout: Duration,
    ) -> Self {
        Self {
            outbounds,
            dns,
            timeout,
        }
    }
}

impl<R: DnsResolver> TunUdpRelay for RegistryTunUdpRelay<'_, R> {
    fn relay_udp_datagram(
        &mut self,
        target: &OutboundTarget,
        payload: &[u8],
    ) -> Result<UdpRelayResponse, String> {
        DirectUdpConnector::relay_datagram_with_dns(target, payload, self.timeout, &mut *self.dns)
            .map_err(|error| error.to_string())
    }

    fn relay_outbound_udp_datagram(
        &mut self,
        tag: &str,
        target: &OutboundTarget,
        payload: &[u8],
    ) -> Result<UdpRelayResponse, String> {
        self.outbounds
            .relay_udp_datagram_with_dns(tag, target, payload, self.timeout, &mut *self.dns)
            .map_err(|error| error.to_string())
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

impl fmt::Display for TunTcpSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(error) => write!(f, "failed to process TUN TCP session packet: {error}"),
            Self::Relay(error) => write!(f, "TUN TCP session relay failed: {error}"),
        }
    }
}

impl Error for TunTcpSessionError {}

impl From<TunPacketError> for TunTcpSessionError {
    fn from(error: TunPacketError) -> Self {
        Self::Packet(error)
    }
}

impl TunTcpSessionStep {
    pub fn response_packets(&self) -> Vec<&[u8]> {
        match self {
            Self::SynAck { response } => vec![response.packet.as_slice()],
            Self::Reset { response } => vec![response.packet.as_slice()],
            Self::ClientPayload {
                frame,
                server_response,
                server_close,
            }
            | Self::OverlappingClientPayload {
                frame,
                server_response,
                server_close,
            } => {
                let mut packets = vec![frame.ack_packet.as_slice()];
                if let Some(server_response) = server_response {
                    packets.push(server_response.packet.as_slice());
                }
                if let Some(server_close) = server_close {
                    packets.push(server_close.packet.as_slice());
                }
                packets
            }
            Self::DuplicateClientPayload { ack } => vec![ack.ack_packet.as_slice()],
            Self::OutOfOrderClientPayload { ack } => vec![ack.ack_packet.as_slice()],
            Self::ClientPayloadClosed {
                response,
                server_response,
                server_close,
                ..
            }
            | Self::ClientFinAck {
                response,
                server_response,
                server_close,
            } => {
                let mut packets = vec![response.packet.as_slice()];
                if let Some(server_response) = server_response {
                    packets.push(server_response.packet.as_slice());
                }
                if let Some(server_close) = server_close {
                    packets.push(server_close.packet.as_slice());
                }
                packets
            }
            Self::ServerPayload { response } | Self::ServerPayloadRetransmission { response } => {
                vec![response.packet.as_slice()]
            }
            Self::ServerClosed { response } | Self::ServerCloseRetransmission { response } => {
                vec![response.packet.as_slice()]
            }
            Self::ServerCloseClientFinAck { response } => vec![response.packet.as_slice()],
            Self::ClientFinDuplicateAck {
                response,
                server_response,
                server_close,
            } => {
                let mut packets = vec![response.packet.as_slice()];
                if let Some(server_response) = server_response {
                    packets.push(server_response.packet.as_slice());
                }
                if let Some(server_close) = server_close {
                    packets.push(server_close.packet.as_slice());
                }
                packets
            }
            Self::Closed {
                response: Some(response),
                ..
            } => vec![response.packet.as_slice()],
            _ => Vec::new(),
        }
    }
}

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
            TunPacketLoopEvent::WroteTcpResetPacket { .. } => {
                self.tcp_resets_written += 1;
            }
            TunPacketLoopEvent::TcpSession {
                step,
                packets_written,
                ..
            } => {
                self.tcp_session_events += 1;
                self.tcp_session_packets_written += packets_written;
                if let TunTcpSessionStep::CloseMarkerReset { kind, .. } = step {
                    match kind {
                        TunTcpCloseMarkerResetKind::ServerClose => {
                            self.tcp_server_close_marker_resets += 1;
                        }
                        TunTcpCloseMarkerResetKind::PostClose => {
                            self.tcp_post_close_marker_resets += 1;
                        }
                    }
                }
            }
            TunPacketLoopEvent::Relay(plan) => {
                self.relay_packets += 1;
                match plan.relay_action {
                    TunPacketRelayAction::DirectTcp { .. }
                    | TunPacketRelayAction::OutboundTcp { .. } => {
                        self.tcp_relay_plans += 1;
                    }
                    TunPacketRelayAction::DirectUdp { .. }
                    | TunPacketRelayAction::OutboundUdp { .. } => {
                        self.udp_relay_plans += 1;
                    }
                    _ => {}
                }
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
            TunPacketLoopEvent::TcpSessionError(error) => {
                self.tcp_session_errors += 1;
                self.last_tcp_session_error = Some(error.clone());
            }
        }
    }

    pub fn record_tcp_session_prune_report(&mut self, report: &TunTcpSessionPruneReport) {
        self.tcp_sessions_pruned += report.pruned_sessions;
        self.tcp_server_closed_sessions_pruned += report.pruned_server_closed_sessions;
        self.tcp_post_closed_sessions_pruned += report.pruned_post_closed_sessions;
        self.tcp_session_errors += report.close_errors;
        if let Some(error) = &report.last_close_error {
            self.last_tcp_session_error = Some(error.clone());
        }
    }

    pub fn processed_packets(&self) -> usize {
        self.dns_responses_written
            + self.udp_relay_responses_written
            + self.tcp_resets_written
            + self.tcp_session_events
            + self.relay_packets
            + self.dropped_packets
            + self.unsupported_packets
            + self.packet_errors
            + self.udp_relay_errors
            + self.tcp_session_errors
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
    Ipv6ExtensionHeaderTruncated {
        next_header: u8,
        required_len: usize,
        available_len: usize,
    },
    TransportHeaderTooShort {
        protocol: TunTransportProtocol,
        required_len: usize,
        available_len: usize,
    },
    ExpectedUdpPayload {
        protocol: TunTransportProtocol,
    },
    ExpectedTcpSegment {
        protocol: TunTransportProtocol,
    },
    ExpectedTcpSynSegment {
        flags: TunTcpFlags,
    },
    TcpDataOffsetTooSmall {
        data_offset: usize,
    },
    TcpSegmentTruncated {
        header_len: usize,
        available_len: usize,
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
    MissingTcpSocketAddress,
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
    TcpResponsePayloadTooLarge {
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
            Self::Ipv6ExtensionHeaderTruncated {
                next_header,
                required_len,
                available_len,
            } => write!(
                f,
                "IPv6 extension header {next_header} is truncated: required {required_len}, available {available_len}"
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
            Self::ExpectedTcpSegment { protocol } => {
                write!(f, "expected TCP TUN segment, got {:?}", protocol)
            }
            Self::ExpectedTcpSynSegment { flags } => write!(
                f,
                "expected initial TCP SYN segment, got flags=0x{:03x}",
                flags.bits()
            ),
            Self::TcpDataOffsetTooSmall { data_offset } => write!(
                f,
                "TCP data offset {data_offset} is smaller than minimum header length 20"
            ),
            Self::TcpSegmentTruncated {
                header_len,
                available_len,
            } => write!(
                f,
                "TCP header length {header_len} exceeds available transport bytes {available_len}"
            ),
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
            Self::MissingTcpSocketAddress => write!(f, "TUN TCP flow is missing a socket address"),
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
            Self::TcpResponsePayloadTooLarge {
                ip_version,
                payload_len,
                max_payload_len,
            } => write!(
                f,
                "TUN {ip_version:?} TCP response payload length {payload_len} exceeds max {max_payload_len}"
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

impl TunTcpFlags {
    pub fn from_bits(bits: u16) -> Self {
        Self {
            bits: bits & 0x01ff,
        }
    }

    pub fn bits(self) -> u16 {
        self.bits
    }

    pub fn ns(self) -> bool {
        self.bits & 0x0100 != 0
    }

    pub fn cwr(self) -> bool {
        self.bits & 0x0080 != 0
    }

    pub fn ece(self) -> bool {
        self.bits & 0x0040 != 0
    }

    pub fn urg(self) -> bool {
        self.bits & 0x0020 != 0
    }

    pub fn ack(self) -> bool {
        self.bits & 0x0010 != 0
    }

    pub fn psh(self) -> bool {
        self.bits & 0x0008 != 0
    }

    pub fn rst(self) -> bool {
        self.bits & 0x0004 != 0
    }

    pub fn syn(self) -> bool {
        self.bits & 0x0002 != 0
    }

    pub fn fin(self) -> bool {
        self.bits & 0x0001 != 0
    }
}

impl TunTcpSessionKey {
    pub fn from_flow(flow: &TunPacketFlow) -> Result<Self, TunPacketError> {
        if flow.protocol != TunTransportProtocol::Tcp {
            return Err(TunPacketError::ExpectedTcpSegment {
                protocol: flow.protocol,
            });
        }
        Ok(Self {
            source_ip: flow.source_ip,
            source_port: flow
                .source_port
                .ok_or(TunPacketError::MissingTcpSocketAddress)?,
            destination_ip: flow.destination_ip,
            destination_port: flow
                .destination_port
                .ok_or(TunPacketError::MissingTcpSocketAddress)?,
        })
    }
}

impl TunTcpSessionTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn get(&self, key: &TunTcpSessionKey) -> Option<&TunTcpSessionRecord> {
        self.sessions.get(key)
    }

    pub fn get_flow(
        &self,
        flow: &TunPacketFlow,
    ) -> Result<Option<&TunTcpSessionRecord>, TunPacketError> {
        Ok(self.sessions.get(&TunTcpSessionKey::from_flow(flow)?))
    }

    pub fn start_from_syn(
        &mut self,
        segment: &TunTcpSegment<'_>,
        server_initial_sequence_number: u32,
        window_size: u16,
    ) -> Result<TunTcpSynAckResponse, TunPacketError> {
        if !is_initial_tcp_syn_segment(segment) {
            return Err(TunPacketError::ExpectedTcpSynSegment {
                flags: segment.flags,
            });
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let session = TunTcpSessionRecord {
            key: key.clone(),
            flow: segment.flow.clone(),
            client_initial_sequence_number: segment.sequence_number,
            client_next_sequence_number: tcp_segment_next_sequence_number(segment),
            server_initial_sequence_number,
            server_next_sequence_number: server_initial_sequence_number.wrapping_add(1),
            server_unacked_payload: None,
            window_size,
            phase: TunTcpSessionPhase::SynReceived,
            last_activity_at: Instant::now(),
        };
        let packet = build_tun_tcp_syn_ack_response_packet(
            segment,
            server_initial_sequence_number,
            window_size,
        )?;
        self.server_closed_sessions.remove(&key);
        self.post_closed_sessions.remove(&key);
        self.sessions.insert(key, session.clone());
        Ok(TunTcpSynAckResponse { session, packet })
    }

    pub fn acknowledge_retransmitted_syn(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpSynAckResponse>, TunPacketError> {
        if !is_initial_tcp_syn_segment(segment) {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(session) = self.sessions.get_mut(&key) else {
            return Ok(None);
        };
        if session.phase != TunTcpSessionPhase::SynReceived
            || segment.sequence_number != session.client_initial_sequence_number
        {
            return Ok(None);
        }
        session.last_activity_at = Instant::now();
        let packet = build_tun_tcp_syn_ack_response_packet(
            segment,
            session.server_initial_sequence_number,
            session.window_size,
        )?;
        Ok(Some(TunTcpSynAckResponse {
            session: session.clone(),
            packet,
        }))
    }

    pub fn apply_ack(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpSessionRecord>, TunPacketError> {
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(session) = self.sessions.get_mut(&key) else {
            return Ok(None);
        };
        if session.phase == TunTcpSessionPhase::SynReceived
            && segment.flags.ack()
            && !segment.flags.syn()
            && !segment.flags.rst()
            && segment.sequence_number == session.client_next_sequence_number
            && segment.acknowledgment_number == session.server_next_sequence_number
        {
            session.phase = TunTcpSessionPhase::Established;
            session.last_activity_at = Instant::now();
            return Ok(Some(session.clone()));
        }
        Ok(None)
    }

    pub fn accept_client_payload(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpClientPayloadFrame>, TunPacketError> {
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(session) = self.sessions.get_mut(&key) else {
            return Ok(None);
        };
        if session.phase != TunTcpSessionPhase::Established
            || segment.payload.is_empty()
            || !segment.flags.ack()
            || segment.flags.syn()
            || segment.flags.rst()
            || segment.sequence_number != session.client_next_sequence_number
            || !tcp_segment_acknowledges_known_server_sequence(segment, session)
        {
            return Ok(None);
        }

        clear_server_unacked_payload_if_latest_acknowledged(segment, session);
        session.client_next_sequence_number = tcp_segment_next_sequence_number(segment);
        session.last_activity_at = Instant::now();
        let ack_packet = build_tun_tcp_ack_response_packet(
            &session.flow,
            session.server_next_sequence_number,
            session.client_next_sequence_number,
            session.window_size,
        )?;
        Ok(Some(TunTcpClientPayloadFrame {
            session: session.clone(),
            sequence_number: segment.sequence_number,
            acknowledgment_number: session.client_next_sequence_number,
            payload: segment.payload.to_vec(),
            ack_packet,
        }))
    }

    pub fn accept_overlapping_client_payload(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpClientPayloadFrame>, TunPacketError> {
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(session) = self.sessions.get_mut(&key) else {
            return Ok(None);
        };
        let segment_next_sequence_number = tcp_segment_next_sequence_number(segment);
        if session.phase != TunTcpSessionPhase::Established
            || segment.payload.is_empty()
            || !segment.flags.ack()
            || segment.flags.syn()
            || segment.flags.rst()
            || segment.flags.fin()
            || segment.sequence_number >= session.client_next_sequence_number
            || segment_next_sequence_number <= session.client_next_sequence_number
            || !tcp_segment_acknowledges_known_server_sequence(segment, session)
        {
            return Ok(None);
        }

        let payload_offset =
            (session.client_next_sequence_number - segment.sequence_number) as usize;
        let Some(payload) = segment.payload.get(payload_offset..) else {
            return Ok(None);
        };
        clear_server_unacked_payload_if_latest_acknowledged(segment, session);
        let sequence_number = session.client_next_sequence_number;
        session.client_next_sequence_number = segment_next_sequence_number;
        session.last_activity_at = Instant::now();
        let ack_packet = build_tun_tcp_ack_response_packet(
            &session.flow,
            session.server_next_sequence_number,
            session.client_next_sequence_number,
            session.window_size,
        )?;
        Ok(Some(TunTcpClientPayloadFrame {
            session: session.clone(),
            sequence_number,
            acknowledgment_number: session.client_next_sequence_number,
            payload: payload.to_vec(),
            ack_packet,
        }))
    }

    pub fn acknowledge_duplicate_client_payload(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpDuplicateClientPayloadAck>, TunPacketError> {
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(session) = self.sessions.get_mut(&key) else {
            return Ok(None);
        };
        let segment_next_sequence_number = tcp_segment_next_sequence_number(segment);
        if session.phase != TunTcpSessionPhase::Established
            || segment.payload.is_empty()
            || !segment.flags.ack()
            || segment.flags.syn()
            || segment.flags.rst()
            || segment.flags.fin()
            || segment.sequence_number >= session.client_next_sequence_number
            || segment_next_sequence_number > session.client_next_sequence_number
            || !tcp_segment_acknowledges_known_server_sequence(segment, session)
        {
            return Ok(None);
        }

        clear_server_unacked_payload_if_latest_acknowledged(segment, session);
        session.last_activity_at = Instant::now();
        let ack_packet = build_tun_tcp_ack_response_packet(
            &session.flow,
            session.server_next_sequence_number,
            session.client_next_sequence_number,
            session.window_size,
        )?;
        Ok(Some(TunTcpDuplicateClientPayloadAck {
            session: session.clone(),
            sequence_number: segment.sequence_number,
            acknowledgment_number: session.client_next_sequence_number,
            payload: segment.payload.to_vec(),
            ack_packet,
        }))
    }

    pub fn acknowledge_out_of_order_client_payload(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpOutOfOrderClientPayloadAck>, TunPacketError> {
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(session) = self.sessions.get_mut(&key) else {
            return Ok(None);
        };
        if session.phase != TunTcpSessionPhase::Established
            || segment.payload.is_empty()
            || !segment.flags.ack()
            || segment.flags.syn()
            || segment.flags.rst()
            || segment.flags.fin()
            || segment.sequence_number <= session.client_next_sequence_number
            || !tcp_segment_acknowledges_known_server_sequence(segment, session)
        {
            return Ok(None);
        }

        clear_server_unacked_payload_if_latest_acknowledged(segment, session);
        session.last_activity_at = Instant::now();
        let ack_packet = build_tun_tcp_ack_response_packet(
            &session.flow,
            session.server_next_sequence_number,
            session.client_next_sequence_number,
            session.window_size,
        )?;
        Ok(Some(TunTcpOutOfOrderClientPayloadAck {
            session: session.clone(),
            sequence_number: segment.sequence_number,
            acknowledgment_number: session.client_next_sequence_number,
            payload: segment.payload.to_vec(),
            ack_packet,
        }))
    }

    pub fn send_server_payload(
        &mut self,
        flow: &TunPacketFlow,
        payload: &[u8],
    ) -> Result<Option<TunTcpServerPayloadFrame>, TunPacketError> {
        let key = TunTcpSessionKey::from_flow(flow)?;
        let Some(session) = self.sessions.get_mut(&key) else {
            return Ok(None);
        };
        if !tun_tcp_phase_accepts_server_response(session.phase) || payload.is_empty() {
            return Ok(None);
        }

        let sequence_number = session.server_next_sequence_number;
        let acknowledgment_number = session.client_next_sequence_number;
        let payload = payload.to_vec();
        let packet = build_tun_tcp_payload_response_packet(
            &session.flow,
            sequence_number,
            acknowledgment_number,
            session.window_size,
            &payload,
        )?;
        session.server_next_sequence_number = session
            .server_next_sequence_number
            .wrapping_add(payload.len() as u32);
        session.server_unacked_payload = Some(TunTcpServerUnackedPayload {
            sequence_number,
            acknowledgment_number,
            payload: payload.clone(),
        });
        session.last_activity_at = Instant::now();
        Ok(Some(TunTcpServerPayloadFrame {
            session: session.clone(),
            sequence_number,
            acknowledgment_number,
            payload,
            packet,
        }))
    }

    pub fn retransmit_server_payload(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpServerPayloadFrame>, TunPacketError> {
        if !segment.flags.ack()
            || segment.flags.syn()
            || segment.flags.rst()
            || segment.flags.fin()
            || !segment.payload.is_empty()
        {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(session) = self.sessions.get_mut(&key) else {
            return Ok(None);
        };
        let Some(unacked) = session.server_unacked_payload.clone() else {
            return Ok(None);
        };
        if !tun_tcp_phase_accepts_server_response(session.phase)
            || segment.sequence_number != session.client_next_sequence_number
            || segment.acknowledgment_number != unacked.sequence_number
        {
            return Ok(None);
        }
        let acknowledgment_number = session.client_next_sequence_number;
        let packet = build_tun_tcp_payload_response_packet(
            &session.flow,
            unacked.sequence_number,
            acknowledgment_number,
            session.window_size,
            &unacked.payload,
        )?;
        session.last_activity_at = Instant::now();
        Ok(Some(TunTcpServerPayloadFrame {
            session: session.clone(),
            sequence_number: unacked.sequence_number,
            acknowledgment_number,
            payload: unacked.payload,
            packet,
        }))
    }

    pub fn retransmit_server_payload_for_duplicate_client_fin(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpServerPayloadFrame>, TunPacketError> {
        if !segment.flags.ack()
            || !segment.flags.fin()
            || segment.flags.syn()
            || segment.flags.rst()
        {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(session) = self.sessions.get_mut(&key) else {
            return Ok(None);
        };
        let Some(unacked) = session.server_unacked_payload.clone() else {
            return Ok(None);
        };
        if session.phase != TunTcpSessionPhase::ClientFinReceived
            || tcp_segment_next_sequence_number(segment) != session.client_next_sequence_number
            || segment.acknowledgment_number != unacked.sequence_number
        {
            return Ok(None);
        }
        let acknowledgment_number = session.client_next_sequence_number;
        let packet = build_tun_tcp_payload_response_packet(
            &session.flow,
            unacked.sequence_number,
            acknowledgment_number,
            session.window_size,
            &unacked.payload,
        )?;
        session.last_activity_at = Instant::now();
        Ok(Some(TunTcpServerPayloadFrame {
            session: session.clone(),
            sequence_number: unacked.sequence_number,
            acknowledgment_number,
            payload: unacked.payload,
            packet,
        }))
    }

    pub fn close_server_side(
        &mut self,
        key: &TunTcpSessionKey,
    ) -> Result<Option<TunTcpServerCloseFrame>, TunPacketError> {
        let Some(session) = self.sessions.remove(key) else {
            return Ok(None);
        };
        if !tun_tcp_phase_accepts_server_response(session.phase) {
            return Ok(None);
        }
        let sequence_number = session.server_next_sequence_number;
        let acknowledgment_number = session.client_next_sequence_number;
        let packet = build_tun_tcp_fin_ack_response_packet(
            &session.flow,
            sequence_number,
            acknowledgment_number,
            session.window_size,
        )?;
        let response = TunTcpServerCloseFrame {
            session,
            sequence_number,
            acknowledgment_number,
            packet,
        };
        self.server_closed_sessions.insert(
            key.clone(),
            TunTcpServerClosedSession {
                response: response.clone(),
                last_activity_at: Instant::now(),
            },
        );
        Ok(Some(response))
    }

    pub fn retransmit_server_close(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpServerCloseFrame>, TunPacketError> {
        if !segment.flags.ack()
            || segment.flags.syn()
            || segment.flags.rst()
            || segment.flags.fin()
            || !segment.payload.is_empty()
        {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(closed) = self.server_closed_sessions.get_mut(&key) else {
            return Ok(None);
        };
        if segment.sequence_number != closed.response.acknowledgment_number
            || segment.acknowledgment_number != closed.response.sequence_number
        {
            return Ok(None);
        }
        closed.last_activity_at = Instant::now();
        Ok(Some(closed.response.clone()))
    }

    pub fn retransmit_server_close_for_duplicate_client_fin(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpServerCloseFrame>, TunPacketError> {
        if !segment.flags.ack()
            || !segment.flags.fin()
            || segment.flags.syn()
            || segment.flags.rst()
        {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(closed) = self.server_closed_sessions.get_mut(&key) else {
            return Ok(None);
        };
        if tcp_segment_next_sequence_number(segment) != closed.response.acknowledgment_number
            || segment.acknowledgment_number != closed.response.sequence_number
        {
            return Ok(None);
        }
        closed.last_activity_at = Instant::now();
        Ok(Some(closed.response.clone()))
    }

    pub fn acknowledge_server_close(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpSessionRecord>, TunPacketError> {
        if !segment.flags.ack()
            || segment.flags.syn()
            || segment.flags.rst()
            || segment.flags.fin()
            || !segment.payload.is_empty()
        {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(closed) = self.server_closed_sessions.get(&key) else {
            return Ok(None);
        };
        if segment.sequence_number != closed.response.acknowledgment_number
            || segment.acknowledgment_number != server_close_next_sequence_number(&closed.response)
        {
            return Ok(None);
        }
        let Some(closed) = self.server_closed_sessions.remove(&key) else {
            return Ok(None);
        };
        let server_next_sequence_number = server_close_next_sequence_number(&closed.response);
        let session = closed.response.session;
        self.post_closed_sessions.insert(
            key,
            TunTcpPostCloseSession {
                session: session.clone(),
                server_next_sequence_number,
                client_next_sequence_number: closed.response.acknowledgment_number,
                client_fin_sequence_number: None,
                client_fin_ack_packet: None,
                last_activity_at: Instant::now(),
            },
        );
        Ok(Some(session))
    }

    pub fn acknowledge_server_close_with_client_fin(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpCloseFrame>, TunPacketError> {
        if !segment.flags.ack()
            || !segment.flags.fin()
            || segment.flags.syn()
            || segment.flags.rst()
            || !segment.payload.is_empty()
        {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(closed) = self.server_closed_sessions.get(&key) else {
            return Ok(None);
        };
        if segment.sequence_number != closed.response.acknowledgment_number
            || segment.acknowledgment_number != server_close_next_sequence_number(&closed.response)
        {
            return Ok(None);
        }
        let Some(closed) = self.server_closed_sessions.remove(&key) else {
            return Ok(None);
        };
        let sequence_number = server_close_next_sequence_number(&closed.response);
        let acknowledgment_number = tcp_segment_next_sequence_number(segment);
        let packet = build_tun_tcp_ack_response_packet(
            &closed.response.session.flow,
            sequence_number,
            acknowledgment_number,
            closed.response.session.window_size,
        )?;
        let response = TunTcpCloseFrame {
            session: closed.response.session.clone(),
            sequence_number,
            acknowledgment_number,
            packet: packet.clone(),
        };
        self.post_closed_sessions.insert(
            key,
            TunTcpPostCloseSession {
                session: closed.response.session,
                server_next_sequence_number: sequence_number,
                client_next_sequence_number: acknowledgment_number,
                client_fin_sequence_number: Some(segment.sequence_number),
                client_fin_ack_packet: Some(packet),
                last_activity_at: Instant::now(),
            },
        );
        Ok(Some(response))
    }

    pub fn acknowledge_post_close_ack(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpSessionRecord>, TunPacketError> {
        if !segment.flags.ack()
            || segment.flags.syn()
            || segment.flags.rst()
            || segment.flags.fin()
            || !segment.payload.is_empty()
        {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(post_close) = self.post_closed_sessions.get_mut(&key) else {
            return Ok(None);
        };
        let matches_client_sequence = segment.sequence_number
            == post_close.client_next_sequence_number
            || post_close.client_fin_sequence_number == Some(segment.sequence_number);
        if !matches_client_sequence
            || segment.acknowledgment_number != post_close.server_next_sequence_number
        {
            return Ok(None);
        }
        post_close.last_activity_at = Instant::now();
        Ok(Some(post_close.session.clone()))
    }

    pub fn acknowledge_post_close_client_fin(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpCloseFrame>, TunPacketError> {
        if !segment.flags.ack()
            || !segment.flags.fin()
            || segment.flags.syn()
            || segment.flags.rst()
        {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(post_close) = self.post_closed_sessions.get_mut(&key) else {
            return Ok(None);
        };
        if segment.acknowledgment_number != post_close.server_next_sequence_number {
            return Ok(None);
        }
        if let Some(client_fin_sequence_number) = post_close.client_fin_sequence_number {
            if segment.sequence_number != client_fin_sequence_number
                || tcp_segment_next_sequence_number(segment)
                    != post_close.client_next_sequence_number
            {
                return Ok(None);
            }
            let Some(packet) = post_close.client_fin_ack_packet.clone() else {
                return Ok(None);
            };
            post_close.last_activity_at = Instant::now();
            return Ok(Some(TunTcpCloseFrame {
                session: post_close.session.clone(),
                sequence_number: post_close.server_next_sequence_number,
                acknowledgment_number: post_close.client_next_sequence_number,
                packet,
            }));
        }
        if segment.sequence_number != post_close.client_next_sequence_number {
            return Ok(None);
        }
        let sequence_number = post_close.server_next_sequence_number;
        let acknowledgment_number = tcp_segment_next_sequence_number(segment);
        let packet = build_tun_tcp_ack_response_packet(
            &post_close.session.flow,
            sequence_number,
            acknowledgment_number,
            post_close.session.window_size,
        )?;
        post_close.client_next_sequence_number = acknowledgment_number;
        post_close.client_fin_sequence_number = Some(segment.sequence_number);
        post_close.client_fin_ack_packet = Some(packet.clone());
        post_close.last_activity_at = Instant::now();
        Ok(Some(TunTcpCloseFrame {
            session: post_close.session.clone(),
            sequence_number,
            acknowledgment_number,
            packet,
        }))
    }

    pub fn remove_server_close_on_rst(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpSessionRecord>, TunPacketError> {
        if !segment.flags.rst() || segment.flags.syn() || segment.flags.fin() {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(closed) = self.server_closed_sessions.get(&key) else {
            return Ok(None);
        };
        if segment.sequence_number != closed.response.acknowledgment_number {
            return Ok(None);
        }
        if segment.flags.ack() {
            let server_fin_sequence_number = closed.response.sequence_number;
            let server_next_sequence_number = server_close_next_sequence_number(&closed.response);
            if segment.acknowledgment_number != server_fin_sequence_number
                && segment.acknowledgment_number != server_next_sequence_number
            {
                return Ok(None);
            }
        }
        let Some(closed) = self.server_closed_sessions.remove(&key) else {
            return Ok(None);
        };
        Ok(Some(closed.response.session))
    }

    pub fn remove_post_close_on_rst(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpSessionRecord>, TunPacketError> {
        if !segment.flags.rst() || segment.flags.syn() || segment.flags.fin() {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(post_close) = self.post_closed_sessions.get(&key) else {
            return Ok(None);
        };
        let matches_client_sequence = segment.sequence_number
            == post_close.client_next_sequence_number
            || post_close.client_fin_sequence_number == Some(segment.sequence_number);
        if !matches_client_sequence {
            return Ok(None);
        }
        if segment.flags.ack()
            && segment.acknowledgment_number != post_close.server_next_sequence_number
        {
            return Ok(None);
        }
        let Some(post_close) = self.post_closed_sessions.remove(&key) else {
            return Ok(None);
        };
        Ok(Some(post_close.session))
    }

    pub fn accept_client_fin_with_payload(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<(TunTcpClientPayloadFrame, TunTcpCloseFrame)>, TunPacketError> {
        if !segment.flags.ack()
            || !segment.flags.fin()
            || segment.flags.syn()
            || segment.flags.rst()
            || segment.payload.is_empty()
        {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(session) = self.sessions.get_mut(&key) else {
            return Ok(None);
        };
        if session.phase != TunTcpSessionPhase::Established
            || segment.sequence_number != session.client_next_sequence_number
            || !tcp_segment_acknowledges_known_server_sequence(segment, session)
        {
            return Ok(None);
        }
        clear_server_unacked_payload_if_latest_acknowledged(segment, session);
        let sequence_number = session.server_next_sequence_number;
        let acknowledgment_number = tcp_segment_next_sequence_number(segment);
        let packet = build_tun_tcp_ack_response_packet(
            &session.flow,
            sequence_number,
            acknowledgment_number,
            session.window_size,
        )?;
        let now = Instant::now();
        session.client_next_sequence_number = acknowledgment_number;
        session.phase = TunTcpSessionPhase::ClientFinReceived;
        session.last_activity_at = now;
        let frame = TunTcpClientPayloadFrame {
            session: session.clone(),
            sequence_number: segment.sequence_number,
            acknowledgment_number,
            payload: segment.payload.to_vec(),
            ack_packet: packet.clone(),
        };
        let response = TunTcpCloseFrame {
            session: session.clone(),
            sequence_number,
            acknowledgment_number,
            packet: packet.clone(),
        };
        Ok(Some((frame, response)))
    }

    pub fn acknowledge_client_fin(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpCloseFrame>, TunPacketError> {
        if !segment.flags.ack()
            || !segment.flags.fin()
            || segment.flags.syn()
            || segment.flags.rst()
            || !segment.payload.is_empty()
        {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(session) = self.sessions.get_mut(&key) else {
            return Ok(None);
        };
        if session.phase != TunTcpSessionPhase::Established
            || segment.sequence_number != session.client_next_sequence_number
            || !tcp_segment_acknowledges_known_server_sequence(segment, session)
        {
            return Ok(None);
        }
        clear_server_unacked_payload_if_latest_acknowledged(segment, session);
        let sequence_number = session.server_next_sequence_number;
        let acknowledgment_number = tcp_segment_next_sequence_number(segment);
        let packet = build_tun_tcp_ack_response_packet(
            &session.flow,
            sequence_number,
            acknowledgment_number,
            session.window_size,
        )?;
        session.client_next_sequence_number = acknowledgment_number;
        session.phase = TunTcpSessionPhase::ClientFinReceived;
        session.last_activity_at = Instant::now();
        Ok(Some(TunTcpCloseFrame {
            session: session.clone(),
            sequence_number,
            acknowledgment_number,
            packet,
        }))
    }

    pub fn acknowledge_duplicate_client_fin(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpCloseFrame>, TunPacketError> {
        if !segment.flags.ack()
            || !segment.flags.fin()
            || segment.flags.syn()
            || segment.flags.rst()
        {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(session) = self.sessions.get_mut(&key) else {
            return Ok(None);
        };
        if session.phase != TunTcpSessionPhase::ClientFinReceived
            || tcp_segment_next_sequence_number(segment) != session.client_next_sequence_number
            || !tcp_segment_acknowledges_known_server_sequence(segment, session)
        {
            return Ok(None);
        }
        let sequence_number = session.server_next_sequence_number;
        let acknowledgment_number = session.client_next_sequence_number;
        let packet = build_tun_tcp_ack_response_packet(
            &session.flow,
            sequence_number,
            acknowledgment_number,
            session.window_size,
        )?;
        clear_server_unacked_payload_if_latest_acknowledged(segment, session);
        session.last_activity_at = Instant::now();
        Ok(Some(TunTcpCloseFrame {
            session: session.clone(),
            sequence_number,
            acknowledgment_number,
            packet,
        }))
    }

    pub fn server_payload_poll_session(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpSessionRecord>, TunPacketError> {
        if !segment.flags.ack()
            || segment.flags.syn()
            || segment.flags.rst()
            || segment.flags.fin()
            || !segment.payload.is_empty()
        {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(session) = self.sessions.get_mut(&key) else {
            return Ok(None);
        };
        if tun_tcp_phase_accepts_server_response(session.phase)
            && segment.sequence_number == session.client_next_sequence_number
            && segment.acknowledgment_number == session.server_next_sequence_number
        {
            clear_server_unacked_payload_if_latest_acknowledged(segment, session);
            session.last_activity_at = Instant::now();
            return Ok(Some(session.clone()));
        }
        Ok(None)
    }

    pub fn acknowledge_client_ack(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<TunTcpSessionRecord>, TunPacketError> {
        if !segment.flags.ack()
            || segment.flags.syn()
            || segment.flags.rst()
            || segment.flags.fin()
            || !segment.payload.is_empty()
        {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(session) = self.sessions.get_mut(&key) else {
            return Ok(None);
        };
        if tun_tcp_phase_accepts_server_response(session.phase)
            && segment.sequence_number == session.client_next_sequence_number
            && tcp_segment_acknowledges_known_server_sequence(segment, session)
        {
            clear_server_unacked_payload_if_latest_acknowledged(segment, session);
            session.last_activity_at = Instant::now();
            return Ok(Some(session.clone()));
        }
        Ok(None)
    }

    pub fn prune_idle(&mut self, now: Instant, idle_timeout: Duration) -> Vec<TunTcpSessionRecord> {
        let expired_keys = self
            .sessions
            .iter()
            .filter(|(_, session)| {
                now.saturating_duration_since(session.last_activity_at) >= idle_timeout
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let pruned_sessions = expired_keys
            .into_iter()
            .filter_map(|key| self.sessions.remove(&key))
            .collect::<Vec<_>>();
        let expired_server_closed_keys = self
            .server_closed_sessions
            .iter()
            .filter(|(_, closed)| {
                now.saturating_duration_since(closed.last_activity_at) >= idle_timeout
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in expired_server_closed_keys {
            self.server_closed_sessions.remove(&key);
        }
        let expired_post_closed_keys = self
            .post_closed_sessions
            .iter()
            .filter(|(_, post_close)| {
                now.saturating_duration_since(post_close.last_activity_at) >= idle_timeout
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in expired_post_closed_keys {
            self.post_closed_sessions.remove(&key);
        }
        pruned_sessions
    }

    pub fn remove_on_close(
        &mut self,
        segment: &TunTcpSegment<'_>,
    ) -> Result<Option<(TunTcpSessionRecord, Option<TunTcpCloseFrame>)>, TunPacketError> {
        if !(segment.flags.rst() || segment.flags.fin()) {
            return Ok(None);
        }
        let key = TunTcpSessionKey::from_flow(&segment.flow)?;
        let Some(session) = self.sessions.get(&key) else {
            return Ok(None);
        };
        if !tcp_close_segment_matches_session(segment, session) {
            return Ok(None);
        }
        let Some(session) = self.sessions.remove(&key) else {
            return Ok(None);
        };
        let response = if segment.flags.fin() && !segment.flags.rst() {
            let sequence_number = session.server_next_sequence_number;
            let acknowledgment_number = tcp_segment_next_sequence_number(segment);
            let packet = build_tun_tcp_ack_response_packet(
                &session.flow,
                sequence_number,
                acknowledgment_number,
                session.window_size,
            )?;
            Some(TunTcpCloseFrame {
                session: session.clone(),
                sequence_number,
                acknowledgment_number,
                packet,
            })
        } else {
            None
        };
        if let Some(response) = &response {
            self.post_closed_sessions.insert(
                key,
                TunTcpPostCloseSession {
                    session: response.session.clone(),
                    server_next_sequence_number: response.sequence_number,
                    client_next_sequence_number: response.acknowledgment_number,
                    client_fin_sequence_number: Some(segment.sequence_number),
                    client_fin_ack_packet: Some(response.packet.clone()),
                    last_activity_at: Instant::now(),
                },
            );
        }
        Ok(Some((session, response)))
    }
}

fn tcp_close_segment_matches_session(
    segment: &TunTcpSegment<'_>,
    session: &TunTcpSessionRecord,
) -> bool {
    match session.phase {
        TunTcpSessionPhase::SynReceived => true,
        TunTcpSessionPhase::Established => {
            segment.flags.ack()
                && segment.sequence_number == session.client_next_sequence_number
                && segment.acknowledgment_number == session.server_next_sequence_number
        }
        TunTcpSessionPhase::ClientFinReceived => {
            segment.flags.rst()
                && segment.flags.ack()
                && !segment.flags.fin()
                && segment.sequence_number == session.client_next_sequence_number
                && tcp_segment_acknowledges_known_server_sequence(segment, session)
        }
    }
}

fn tun_tcp_phase_accepts_server_response(phase: TunTcpSessionPhase) -> bool {
    matches!(
        phase,
        TunTcpSessionPhase::Established | TunTcpSessionPhase::ClientFinReceived
    )
}

pub fn parse_tun_packet_flow(packet: &[u8]) -> Result<TunPacketFlow, TunPacketError> {
    Ok(parse_tun_packet_parts(packet)?.flow)
}

pub fn parse_tun_tcp_segment(packet: &[u8]) -> Result<TunTcpSegment<'_>, TunPacketError> {
    let parts = parse_tun_packet_parts(packet)?;
    if parts.flow.protocol != TunTransportProtocol::Tcp {
        return Err(TunPacketError::ExpectedTcpSegment {
            protocol: parts.flow.protocol,
        });
    }
    if parts.transport_payload.len() < 20 {
        return Err(TunPacketError::TransportHeaderTooShort {
            protocol: TunTransportProtocol::Tcp,
            required_len: 20,
            available_len: parts.transport_payload.len(),
        });
    }
    let header_len = usize::from(parts.transport_payload[12] >> 4) * 4;
    if header_len < 20 {
        return Err(TunPacketError::TcpDataOffsetTooSmall {
            data_offset: header_len,
        });
    }
    if header_len > parts.transport_payload.len() {
        return Err(TunPacketError::TcpSegmentTruncated {
            header_len,
            available_len: parts.transport_payload.len(),
        });
    }
    let flags = (u16::from(parts.transport_payload[12] & 0x01) << 8)
        | u16::from(parts.transport_payload[13]);
    Ok(TunTcpSegment {
        flow: parts.flow,
        sequence_number: u32::from_be_bytes([
            parts.transport_payload[4],
            parts.transport_payload[5],
            parts.transport_payload[6],
            parts.transport_payload[7],
        ]),
        acknowledgment_number: u32::from_be_bytes([
            parts.transport_payload[8],
            parts.transport_payload[9],
            parts.transport_payload[10],
            parts.transport_payload[11],
        ]),
        header_len,
        flags: TunTcpFlags::from_bits(flags),
        window_size: u16::from_be_bytes([parts.transport_payload[14], parts.transport_payload[15]]),
        payload: &parts.transport_payload[header_len..],
    })
}

pub fn process_tun_tcp_session_segment<R: TunTcpSessionRelay>(
    sessions: &mut TunTcpSessionTable,
    segment: &TunTcpSegment<'_>,
    relay: &mut R,
    server_initial_sequence_number: u32,
    window_size: u16,
) -> Result<TunTcpSessionStep, TunTcpSessionError> {
    process_tun_tcp_session_segment_with_relay_plan(
        sessions,
        segment,
        relay,
        None,
        server_initial_sequence_number,
        window_size,
    )
}

pub fn prune_idle_tun_tcp_sessions<R: TunTcpSessionRelay>(
    sessions: &mut TunTcpSessionTable,
    tcp_relay: &mut R,
    now: Instant,
    idle_timeout: Duration,
) -> TunTcpSessionPruneReport {
    let server_closed_sessions_before = sessions.server_closed_sessions.len();
    let post_closed_sessions_before = sessions.post_closed_sessions.len();
    let pruned_sessions = sessions.prune_idle(now, idle_timeout);
    let mut report = TunTcpSessionPruneReport {
        pruned_sessions: pruned_sessions.len(),
        pruned_server_closed_sessions: server_closed_sessions_before
            .saturating_sub(sessions.server_closed_sessions.len()),
        pruned_post_closed_sessions: post_closed_sessions_before
            .saturating_sub(sessions.post_closed_sessions.len()),
        ..TunTcpSessionPruneReport::default()
    };
    for session in pruned_sessions {
        if let Err(error) = tcp_relay.close_session(&session) {
            report.close_errors += 1;
            report.last_close_error = Some(TunTcpSessionError::Relay(error));
        }
    }
    report
}

fn close_tun_tcp_session_from_server<R: TunTcpSessionRelay>(
    sessions: &mut TunTcpSessionTable,
    relay: &mut R,
    session: &TunTcpSessionRecord,
) -> Result<Option<TunTcpServerCloseFrame>, TunTcpSessionError> {
    let response = sessions.close_server_side(&session.key)?;
    if let Some(response) = &response {
        relay
            .close_session(&response.session)
            .map_err(TunTcpSessionError::Relay)?;
    }
    Ok(response)
}

fn build_tun_tcp_session_reset_frame(
    segment: &TunTcpSegment<'_>,
) -> Result<TunTcpSessionResetFrame, TunPacketError> {
    let sequence_number = tcp_reset_sequence_number(segment);
    let acknowledgment_number = tcp_reset_acknowledgment_number(segment);
    let packet = build_tun_tcp_reset_response_packet(segment)?;
    Ok(TunTcpSessionResetFrame {
        sequence_number,
        acknowledgment_number,
        packet,
    })
}

fn should_reset_unknown_tun_tcp_session_segment(segment: &TunTcpSegment<'_>) -> bool {
    !segment.flags.rst()
        && (segment.flags.syn()
            || segment.flags.fin()
            || segment.flags.ack()
            || !segment.payload.is_empty())
}

fn read_tun_tcp_server_event_after_client_payload<R: TunTcpSessionRelay>(
    sessions: &mut TunTcpSessionTable,
    relay: &mut R,
    frame: &TunTcpClientPayloadFrame,
) -> Result<
    (
        Option<TunTcpServerPayloadFrame>,
        Option<TunTcpServerCloseFrame>,
    ),
    TunTcpSessionError,
> {
    match relay
        .read_server_event(&frame.session)
        .map_err(TunTcpSessionError::Relay)?
    {
        TunTcpServerRead::Payload(payload) => Ok((
            sessions.send_server_payload(&frame.session.flow, &payload)?,
            None,
        )),
        TunTcpServerRead::Closed => Ok((
            None,
            close_tun_tcp_session_from_server(sessions, relay, &frame.session)?,
        )),
        TunTcpServerRead::NoPayload => Ok((None, None)),
    }
}

fn process_tun_tcp_session_segment_with_relay_plan<R: TunTcpSessionRelay>(
    sessions: &mut TunTcpSessionTable,
    segment: &TunTcpSegment<'_>,
    relay: &mut R,
    relay_plan: Option<&TunPacketRelayPlan>,
    server_initial_sequence_number: u32,
    window_size: u16,
) -> Result<TunTcpSessionStep, TunTcpSessionError> {
    if segment.flags.rst() || segment.flags.fin() {
        if segment.flags.fin() && !segment.flags.rst() && !segment.payload.is_empty() {
            if let Some(response) =
                sessions.retransmit_server_payload_for_duplicate_client_fin(segment)?
            {
                return Ok(TunTcpSessionStep::ServerPayloadRetransmission { response });
            }
            if let Some(response) = sessions.acknowledge_duplicate_client_fin(segment)? {
                let (server_response, server_close) =
                    read_tun_tcp_server_event_after_client_fin(sessions, relay, &response.session)?;
                if server_response.is_some() || server_close.is_some() {
                    return Ok(TunTcpSessionStep::ClientFinDuplicateAck {
                        response,
                        server_response,
                        server_close,
                    });
                }
                return Ok(TunTcpSessionStep::ServerCloseClientFinAck { response });
            }
            if let Some((frame, response)) = sessions.accept_client_fin_with_payload(segment)? {
                relay
                    .write_client_payload(&frame)
                    .map_err(TunTcpSessionError::Relay)?;
                relay
                    .shutdown_client_write(&response.session)
                    .map_err(TunTcpSessionError::Relay)?;
                let (server_response, server_close) =
                    read_tun_tcp_server_event_after_client_payload(sessions, relay, &frame)?;
                return Ok(TunTcpSessionStep::ClientPayloadClosed {
                    frame,
                    response,
                    server_response,
                    server_close,
                });
            }
        }
        if segment.flags.fin() && !segment.flags.rst() && segment.payload.is_empty() {
            if let Some(response) =
                sessions.retransmit_server_payload_for_duplicate_client_fin(segment)?
            {
                return Ok(TunTcpSessionStep::ServerPayloadRetransmission { response });
            }
            if let Some(response) = sessions.acknowledge_duplicate_client_fin(segment)? {
                let (server_response, server_close) =
                    read_tun_tcp_server_event_after_client_fin(sessions, relay, &response.session)?;
                if server_response.is_some() || server_close.is_some() {
                    return Ok(TunTcpSessionStep::ClientFinDuplicateAck {
                        response,
                        server_response,
                        server_close,
                    });
                }
                return Ok(TunTcpSessionStep::ServerCloseClientFinAck { response });
            }
            if let Some(response) = sessions.acknowledge_client_fin(segment)? {
                relay
                    .shutdown_client_write(&response.session)
                    .map_err(TunTcpSessionError::Relay)?;
                let (server_response, server_close) =
                    read_tun_tcp_server_event_after_client_fin(sessions, relay, &response.session)?;
                return Ok(TunTcpSessionStep::ClientFinAck {
                    response,
                    server_response,
                    server_close,
                });
            }
        }
        if let Some((session, response)) = sessions.remove_on_close(segment)? {
            relay
                .close_session(&session)
                .map_err(TunTcpSessionError::Relay)?;
            return Ok(TunTcpSessionStep::Closed { session, response });
        }
        if segment.flags.fin() && !segment.flags.rst() {
            if let Some(response) = sessions.acknowledge_server_close_with_client_fin(segment)? {
                return Ok(TunTcpSessionStep::ServerCloseClientFinAck { response });
            }
            if let Some(response) =
                sessions.retransmit_server_close_for_duplicate_client_fin(segment)?
            {
                return Ok(TunTcpSessionStep::ServerCloseRetransmission { response });
            }
            if let Some(response) = sessions.acknowledge_post_close_client_fin(segment)? {
                return Ok(TunTcpSessionStep::ServerCloseClientFinAck { response });
            }
        }
        if segment.flags.fin()
            && !segment.flags.rst()
            && sessions.get_flow(&segment.flow)?.is_none()
        {
            let response = build_tun_tcp_session_reset_frame(segment)?;
            return Ok(TunTcpSessionStep::Reset { response });
        }
        if segment.flags.rst() {
            if let Some(session) = sessions.remove_server_close_on_rst(segment)? {
                return Ok(TunTcpSessionStep::CloseMarkerReset {
                    session,
                    kind: TunTcpCloseMarkerResetKind::ServerClose,
                });
            }
            if let Some(session) = sessions.remove_post_close_on_rst(segment)? {
                return Ok(TunTcpSessionStep::CloseMarkerReset {
                    session,
                    kind: TunTcpCloseMarkerResetKind::PostClose,
                });
            }
        }
        return Ok(TunTcpSessionStep::Noop);
    }

    if is_initial_tcp_syn_segment(segment) {
        if let Some(response) = sessions.acknowledge_retransmitted_syn(segment)? {
            return Ok(TunTcpSessionStep::SynAck { response });
        }
        if matches!(
            sessions.get_flow(&segment.flow)?,
            Some(session) if tun_tcp_phase_accepts_server_response(session.phase)
        ) {
            return Ok(TunTcpSessionStep::Noop);
        }
        let response =
            sessions.start_from_syn(segment, server_initial_sequence_number, window_size)?;
        return Ok(TunTcpSessionStep::SynAck { response });
    }

    let established = if segment.flags.ack() && !segment.flags.syn() {
        let established = sessions.apply_ack(segment)?;
        if let Some(session) = &established {
            match relay_plan {
                Some(plan) => relay.establish_session_with_plan(session, plan),
                None => relay.establish_session(session),
            }
            .map_err(TunTcpSessionError::Relay)?;
        }
        established
    } else {
        None
    };

    if let Some(frame) = sessions.accept_client_payload(segment)? {
        relay
            .write_client_payload(&frame)
            .map_err(TunTcpSessionError::Relay)?;
        let (server_response, server_close) =
            read_tun_tcp_server_event_after_client_payload(sessions, relay, &frame)?;
        return Ok(TunTcpSessionStep::ClientPayload {
            frame,
            server_response,
            server_close,
        });
    }

    if let Some(frame) = sessions.accept_overlapping_client_payload(segment)? {
        relay
            .write_client_payload(&frame)
            .map_err(TunTcpSessionError::Relay)?;
        let (server_response, server_close) =
            read_tun_tcp_server_event_after_client_payload(sessions, relay, &frame)?;
        return Ok(TunTcpSessionStep::OverlappingClientPayload {
            frame,
            server_response,
            server_close,
        });
    }

    if let Some(ack) = sessions.acknowledge_duplicate_client_payload(segment)? {
        return Ok(TunTcpSessionStep::DuplicateClientPayload { ack });
    }

    if let Some(ack) = sessions.acknowledge_out_of_order_client_payload(segment)? {
        return Ok(TunTcpSessionStep::OutOfOrderClientPayload { ack });
    }

    if established.is_none() {
        if let Some(response) = sessions.retransmit_server_payload(segment)? {
            return Ok(TunTcpSessionStep::ServerPayloadRetransmission { response });
        }

        if let Some(session) = sessions.server_payload_poll_session(segment)? {
            match relay
                .poll_server_event(&session)
                .map_err(TunTcpSessionError::Relay)?
            {
                TunTcpServerRead::Payload(payload) => {
                    if let Some(response) = sessions.send_server_payload(&session.flow, &payload)? {
                        return Ok(TunTcpSessionStep::ServerPayload { response });
                    }
                }
                TunTcpServerRead::Closed => {
                    if let Some(response) =
                        close_tun_tcp_session_from_server(sessions, relay, &session)?
                    {
                        return Ok(TunTcpSessionStep::ServerClosed { response });
                    }
                }
                TunTcpServerRead::NoPayload => {
                    return Ok(TunTcpSessionStep::ClientAck { session });
                }
            }
        }

        if let Some(session) = sessions.acknowledge_client_ack(segment)? {
            return Ok(TunTcpSessionStep::ClientAck { session });
        }

        if let Some(response) = sessions.retransmit_server_close(segment)? {
            return Ok(TunTcpSessionStep::ServerCloseRetransmission { response });
        }

        if let Some(session) = sessions.acknowledge_server_close(segment)? {
            return Ok(TunTcpSessionStep::ServerCloseAcknowledged { session });
        }

        if let Some(session) = sessions.acknowledge_post_close_ack(segment)? {
            return Ok(TunTcpSessionStep::ServerCloseAcknowledged { session });
        }
    }

    if let Some(session) = established {
        return Ok(TunTcpSessionStep::Established { session });
    }

    if should_reset_unknown_tun_tcp_session_segment(segment)
        && sessions.get_flow(&segment.flow)?.is_none()
    {
        let response = build_tun_tcp_session_reset_frame(segment)?;
        return Ok(TunTcpSessionStep::Reset { response });
    }

    Ok(TunTcpSessionStep::Noop)
}

fn read_tun_tcp_server_event_after_client_fin<R: TunTcpSessionRelay>(
    sessions: &mut TunTcpSessionTable,
    relay: &mut R,
    session: &TunTcpSessionRecord,
) -> Result<
    (
        Option<TunTcpServerPayloadFrame>,
        Option<TunTcpServerCloseFrame>,
    ),
    TunTcpSessionError,
> {
    match relay
        .read_server_event(session)
        .map_err(TunTcpSessionError::Relay)?
    {
        TunTcpServerRead::Payload(payload) => {
            Ok((sessions.send_server_payload(&session.flow, &payload)?, None))
        }
        TunTcpServerRead::Closed => Ok((
            None,
            close_tun_tcp_session_from_server(sessions, relay, session)?,
        )),
        TunTcpServerRead::NoPayload => Ok((None, None)),
    }
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
    if relay_plan.relay_action == TunPacketRelayAction::Drop
        && relay_plan.route.flow.protocol == TunTransportProtocol::Tcp
    {
        let segment = parse_tun_tcp_segment(packet)?;
        if !segment.flags.rst() {
            return Ok(TunPacketProcessAction::WriteTcpReset {
                response: build_tun_tcp_reset_response(relay_plan, &segment)?,
            });
        }
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
        TunPacketProcessAction::WriteTcpReset { response } => {
            device
                .write_packet(&response.packet)
                .map_err(TunPacketLoopError::Write)?;
            Ok(TunPacketLoopEvent::WroteTcpResetPacket { response })
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
        TunPacketProcessAction::WriteTcpReset { response } => {
            device
                .write_packet(&response.packet)
                .map_err(TunPacketLoopError::Write)?;
            Ok(TunPacketLoopEvent::WroteTcpResetPacket { response })
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

pub fn process_tun_device_packet_with_tcp_session_relay<D, R, T>(
    device: &mut D,
    routes: &RouteEngine,
    dns_hijack_enabled: bool,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
    sessions: &mut TunTcpSessionTable,
    tcp_relay: &mut T,
    server_initial_sequence_number: u32,
    window_size: u16,
) -> Result<TunPacketLoopEvent, TunPacketLoopError>
where
    D: TunPacketDevice,
    R: DnsResolver,
    T: TunTcpSessionRelay,
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
        TunPacketProcessAction::WriteTcpReset { response } => {
            device
                .write_packet(&response.packet)
                .map_err(TunPacketLoopError::Write)?;
            Ok(TunPacketLoopEvent::WroteTcpResetPacket { response })
        }
        TunPacketProcessAction::Relay(plan) => {
            if !matches!(
                plan.relay_action,
                TunPacketRelayAction::DirectTcp { .. } | TunPacketRelayAction::OutboundTcp { .. }
            ) {
                return Ok(loop_event_for_relay_plan(plan));
            }
            let segment = match parse_tun_tcp_segment(&packet) {
                Ok(segment) => segment,
                Err(error) => return Ok(TunPacketLoopEvent::PacketError(error)),
            };
            let step = match process_tun_tcp_session_segment_with_relay_plan(
                sessions,
                &segment,
                tcp_relay,
                Some(&plan),
                server_initial_sequence_number,
                window_size,
            ) {
                Ok(step) => step,
                Err(error) => return Ok(TunPacketLoopEvent::TcpSessionError(error)),
            };
            let packets_written = {
                let packets = step.response_packets();
                let packets_written = packets.len();
                for packet in packets {
                    device
                        .write_packet(packet)
                        .map_err(TunPacketLoopError::Write)?;
                }
                packets_written
            };
            Ok(TunPacketLoopEvent::TcpSession {
                plan,
                step,
                packets_written,
            })
        }
    }
}

pub fn process_tun_device_packet_with_relays<D, R, U, T>(
    device: &mut D,
    routes: &RouteEngine,
    dns_hijack_enabled: bool,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
    udp_relay: &mut U,
    sessions: &mut TunTcpSessionTable,
    tcp_relay: &mut T,
    server_initial_sequence_number: u32,
    window_size: u16,
) -> Result<TunPacketLoopEvent, TunPacketLoopError>
where
    D: TunPacketDevice,
    R: DnsResolver,
    U: TunUdpRelay,
    T: TunTcpSessionRelay,
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
        TunPacketProcessAction::WriteTcpReset { response } => {
            device
                .write_packet(&response.packet)
                .map_err(TunPacketLoopError::Write)?;
            Ok(TunPacketLoopEvent::WroteTcpResetPacket { response })
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

            if matches!(
                plan.relay_action,
                TunPacketRelayAction::DirectTcp { .. } | TunPacketRelayAction::OutboundTcp { .. }
            ) {
                let segment = match parse_tun_tcp_segment(&packet) {
                    Ok(segment) => segment,
                    Err(error) => return Ok(TunPacketLoopEvent::PacketError(error)),
                };
                let step = match process_tun_tcp_session_segment_with_relay_plan(
                    sessions,
                    &segment,
                    tcp_relay,
                    Some(&plan),
                    server_initial_sequence_number,
                    window_size,
                ) {
                    Ok(step) => step,
                    Err(error) => return Ok(TunPacketLoopEvent::TcpSessionError(error)),
                };
                let packets_written = {
                    let packets = step.response_packets();
                    let packets_written = packets.len();
                    for packet in packets {
                        device
                            .write_packet(packet)
                            .map_err(TunPacketLoopError::Write)?;
                    }
                    packets_written
                };
                return Ok(TunPacketLoopEvent::TcpSession {
                    plan,
                    step,
                    packets_written,
                });
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

pub fn run_tun_packet_loop_with_tcp_session_relay_summary<D, R, T>(
    device: &mut D,
    routes: &RouteEngine,
    dns_hijack_enabled: bool,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
    max_packets: usize,
    sessions: &mut TunTcpSessionTable,
    tcp_relay: &mut T,
    server_initial_sequence_number: u32,
    window_size: u16,
) -> Result<TunPacketLoopSummary, TunPacketLoopError>
where
    D: TunPacketDevice,
    R: DnsResolver,
    T: TunTcpSessionRelay,
{
    run_tun_packet_loop_with_tcp_session_relay_summary_with_idle_timeout(
        device,
        routes,
        dns_hijack_enabled,
        dns,
        dns_ttl_seconds,
        max_packets,
        sessions,
        tcp_relay,
        server_initial_sequence_number,
        window_size,
        DEFAULT_TUN_TCP_SESSION_IDLE_TIMEOUT,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn run_tun_packet_loop_with_tcp_session_relay_summary_with_idle_timeout<D, R, T>(
    device: &mut D,
    routes: &RouteEngine,
    dns_hijack_enabled: bool,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
    max_packets: usize,
    sessions: &mut TunTcpSessionTable,
    tcp_relay: &mut T,
    server_initial_sequence_number: u32,
    window_size: u16,
    session_idle_timeout: Duration,
) -> Result<TunPacketLoopSummary, TunPacketLoopError>
where
    D: TunPacketDevice,
    R: DnsResolver,
    T: TunTcpSessionRelay,
{
    let mut summary = TunPacketLoopSummary::default();
    for _ in 0..max_packets {
        let prune_report =
            prune_idle_tun_tcp_sessions(sessions, tcp_relay, Instant::now(), session_idle_timeout);
        summary.record_tcp_session_prune_report(&prune_report);
        let event = process_tun_device_packet_with_tcp_session_relay(
            device,
            routes,
            dns_hijack_enabled,
            dns,
            dns_ttl_seconds,
            sessions,
            tcp_relay,
            server_initial_sequence_number,
            window_size,
        )?;
        let should_stop = event == TunPacketLoopEvent::NoPacket;
        summary.record_event(&event);
        if should_stop {
            break;
        }
    }
    Ok(summary)
}

pub fn run_tun_packet_loop_with_relays_summary<D, R, U, T>(
    device: &mut D,
    routes: &RouteEngine,
    dns_hijack_enabled: bool,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
    max_packets: usize,
    udp_relay: &mut U,
    sessions: &mut TunTcpSessionTable,
    tcp_relay: &mut T,
    server_initial_sequence_number: u32,
    window_size: u16,
) -> Result<TunPacketLoopSummary, TunPacketLoopError>
where
    D: TunPacketDevice,
    R: DnsResolver,
    U: TunUdpRelay,
    T: TunTcpSessionRelay,
{
    run_tun_packet_loop_with_relays_summary_with_idle_timeout(
        device,
        routes,
        dns_hijack_enabled,
        dns,
        dns_ttl_seconds,
        max_packets,
        udp_relay,
        sessions,
        tcp_relay,
        server_initial_sequence_number,
        window_size,
        DEFAULT_TUN_TCP_SESSION_IDLE_TIMEOUT,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn run_tun_packet_loop_with_relays_summary_with_idle_timeout<D, R, U, T>(
    device: &mut D,
    routes: &RouteEngine,
    dns_hijack_enabled: bool,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
    max_packets: usize,
    udp_relay: &mut U,
    sessions: &mut TunTcpSessionTable,
    tcp_relay: &mut T,
    server_initial_sequence_number: u32,
    window_size: u16,
    session_idle_timeout: Duration,
) -> Result<TunPacketLoopSummary, TunPacketLoopError>
where
    D: TunPacketDevice,
    R: DnsResolver,
    U: TunUdpRelay,
    T: TunTcpSessionRelay,
{
    let mut summary = TunPacketLoopSummary::default();
    for _ in 0..max_packets {
        let prune_report =
            prune_idle_tun_tcp_sessions(sessions, tcp_relay, Instant::now(), session_idle_timeout);
        summary.record_tcp_session_prune_report(&prune_report);
        let event = process_tun_device_packet_with_relays(
            device,
            routes,
            dns_hijack_enabled,
            dns,
            dns_ttl_seconds,
            udp_relay,
            sessions,
            tcp_relay,
            server_initial_sequence_number,
            window_size,
        )?;
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

pub fn build_tun_tcp_reset_response_packet(
    segment: &TunTcpSegment<'_>,
) -> Result<Vec<u8>, TunPacketError> {
    build_tun_tcp_response_packet(
        &segment.flow,
        tcp_reset_sequence_number(segment),
        tcp_reset_acknowledgment_number(segment),
        TunTcpFlags::from_bits(0x0014),
        0,
        b"",
    )
}

fn build_tun_tcp_reset_response(
    plan: TunPacketRelayPlan,
    segment: &TunTcpSegment<'_>,
) -> Result<TunTcpResetResponse, TunPacketError> {
    let sequence_number = tcp_reset_sequence_number(segment);
    let acknowledgment_number = tcp_reset_acknowledgment_number(segment);
    let packet = build_tun_tcp_response_packet(
        &segment.flow,
        sequence_number,
        acknowledgment_number,
        TunTcpFlags::from_bits(0x0014),
        0,
        b"",
    )?;
    Ok(TunTcpResetResponse {
        plan,
        sequence_number,
        acknowledgment_number,
        packet,
    })
}

pub fn build_tun_tcp_syn_ack_response_packet(
    segment: &TunTcpSegment<'_>,
    server_initial_sequence_number: u32,
    window_size: u16,
) -> Result<Vec<u8>, TunPacketError> {
    if !is_initial_tcp_syn_segment(segment) {
        return Err(TunPacketError::ExpectedTcpSynSegment {
            flags: segment.flags,
        });
    }
    build_tun_tcp_response_packet(
        &segment.flow,
        server_initial_sequence_number,
        tcp_segment_next_sequence_number(segment),
        TunTcpFlags::from_bits(0x0012),
        window_size,
        b"",
    )
}

pub fn build_tun_tcp_ack_response_packet(
    flow: &TunPacketFlow,
    sequence_number: u32,
    acknowledgment_number: u32,
    window_size: u16,
) -> Result<Vec<u8>, TunPacketError> {
    build_tun_tcp_response_packet(
        flow,
        sequence_number,
        acknowledgment_number,
        TunTcpFlags::from_bits(0x0010),
        window_size,
        b"",
    )
}

pub fn build_tun_tcp_payload_response_packet(
    flow: &TunPacketFlow,
    sequence_number: u32,
    acknowledgment_number: u32,
    window_size: u16,
    payload: &[u8],
) -> Result<Vec<u8>, TunPacketError> {
    build_tun_tcp_response_packet(
        flow,
        sequence_number,
        acknowledgment_number,
        TunTcpFlags::from_bits(0x0018),
        window_size,
        payload,
    )
}

pub fn build_tun_tcp_fin_ack_response_packet(
    flow: &TunPacketFlow,
    sequence_number: u32,
    acknowledgment_number: u32,
    window_size: u16,
) -> Result<Vec<u8>, TunPacketError> {
    build_tun_tcp_response_packet(
        flow,
        sequence_number,
        acknowledgment_number,
        TunTcpFlags::from_bits(0x0011),
        window_size,
        b"",
    )
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

pub fn build_tun_tcp_response_packet(
    flow: &TunPacketFlow,
    sequence_number: u32,
    acknowledgment_number: u32,
    flags: TunTcpFlags,
    window_size: u16,
    payload: &[u8],
) -> Result<Vec<u8>, TunPacketError> {
    if flow.protocol != TunTransportProtocol::Tcp {
        return Err(TunPacketError::ExpectedTcpSegment {
            protocol: flow.protocol,
        });
    }
    let source_port = flow
        .destination_port
        .ok_or(TunPacketError::MissingTcpSocketAddress)?;
    let destination_port = flow
        .source_port
        .ok_or(TunPacketError::MissingTcpSocketAddress)?;

    match (flow.ip_version, flow.destination_ip, flow.source_ip) {
        (TunIpVersion::Ipv4, IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
            let max_payload_len = u16::MAX as usize - 20 - 20;
            if payload.len() > max_payload_len {
                return Err(TunPacketError::TcpResponsePayloadTooLarge {
                    ip_version: flow.ip_version,
                    payload_len: payload.len(),
                    max_payload_len,
                });
            }
            Ok(build_ipv4_tcp_response_packet(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                sequence_number,
                acknowledgment_number,
                flags,
                window_size,
                payload,
            ))
        }
        (TunIpVersion::Ipv6, IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
            let max_payload_len = u16::MAX as usize - 20;
            if payload.len() > max_payload_len {
                return Err(TunPacketError::TcpResponsePayloadTooLarge {
                    ip_version: flow.ip_version,
                    payload_len: payload.len(),
                    max_payload_len,
                });
            }
            Ok(build_ipv6_tcp_response_packet(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                sequence_number,
                acknowledgment_number,
                flags,
                window_size,
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

fn tcp_reset_sequence_number(segment: &TunTcpSegment<'_>) -> u32 {
    if segment.flags.ack() {
        segment.acknowledgment_number
    } else {
        0
    }
}

fn tcp_reset_acknowledgment_number(segment: &TunTcpSegment<'_>) -> u32 {
    tcp_segment_next_sequence_number(segment)
}

fn tcp_segment_acknowledges_known_server_sequence(
    segment: &TunTcpSegment<'_>,
    session: &TunTcpSessionRecord,
) -> bool {
    let acknowledged_syn = session.server_initial_sequence_number.wrapping_add(1);
    if acknowledged_syn <= session.server_next_sequence_number {
        segment.acknowledgment_number >= acknowledged_syn
            && segment.acknowledgment_number <= session.server_next_sequence_number
    } else {
        segment.acknowledgment_number >= acknowledged_syn
            || segment.acknowledgment_number <= session.server_next_sequence_number
    }
}

fn clear_server_unacked_payload_if_latest_acknowledged(
    segment: &TunTcpSegment<'_>,
    session: &mut TunTcpSessionRecord,
) {
    if segment.acknowledgment_number == session.server_next_sequence_number {
        session.server_unacked_payload = None;
    }
}

fn server_close_next_sequence_number(response: &TunTcpServerCloseFrame) -> u32 {
    response.sequence_number.wrapping_add(1)
}

fn tcp_segment_next_sequence_number(segment: &TunTcpSegment<'_>) -> u32 {
    segment
        .sequence_number
        .wrapping_add(tcp_segment_sequence_len(segment))
}

fn tcp_segment_sequence_len(segment: &TunTcpSegment<'_>) -> u32 {
    let mut sequence_len = segment.payload.len() as u32;
    if segment.flags.syn() {
        sequence_len = sequence_len.wrapping_add(1);
    }
    if segment.flags.fin() {
        sequence_len = sequence_len.wrapping_add(1);
    }
    sequence_len
}

fn is_initial_tcp_syn_segment(segment: &TunTcpSegment<'_>) -> bool {
    segment.flags.syn() && !segment.flags.ack() && !segment.flags.rst()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_flow(ip_version: TunIpVersion) -> TunPacketFlow {
        let (source_ip, destination_ip) = match ip_version {
            TunIpVersion::Ipv4 => (
                IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            ),
            TunIpVersion::Ipv6 => (
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ),
        };
        TunPacketFlow {
            ip_version,
            protocol: TunTransportProtocol::Tcp,
            source_ip,
            destination_ip,
            source_port: Some(49152),
            destination_port: Some(443),
        }
    }

    #[test]
    fn tun_tcp_relay_read_buffer_size_uses_default_mtu_payload_limit() {
        assert_eq!(
            tun_tcp_relay_read_buffer_size_for_flow(&tcp_flow(TunIpVersion::Ipv4), 16 * 1024),
            1460
        );
        assert_eq!(
            tun_tcp_relay_read_buffer_size_for_flow(&tcp_flow(TunIpVersion::Ipv6), 16 * 1024),
            1440
        );
    }

    #[test]
    fn tun_tcp_relay_read_buffer_size_keeps_smaller_configured_limit() {
        assert_eq!(
            tun_tcp_relay_read_buffer_size_for_flow(&tcp_flow(TunIpVersion::Ipv4), 512),
            512
        );
        assert_eq!(
            tun_tcp_relay_read_buffer_size_for_flow(&tcp_flow(TunIpVersion::Ipv4), 0),
            1
        );
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
    let (next_header, transport_offset) =
        parse_ipv6_transport_header(packet, total_length, packet[6])?;
    let protocol = TunTransportProtocol::from_ip_protocol_number(next_header);
    let source_ip = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[8..24]).expect("IPv6 source slice length"),
    ));
    let destination_ip = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[24..40]).expect("IPv6 destination slice length"),
    ));
    let transport_payload = &packet[transport_offset..total_length];
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

fn parse_ipv6_transport_header(
    packet: &[u8],
    total_length: usize,
    mut next_header: u8,
) -> Result<(u8, usize), TunPacketError> {
    let mut offset = 40;
    while is_ipv6_skippable_extension_header(next_header) {
        let available_len = total_length - offset;
        if available_len < 2 {
            return Err(TunPacketError::Ipv6ExtensionHeaderTruncated {
                next_header,
                required_len: 2,
                available_len,
            });
        }
        let extension_len = (usize::from(packet[offset + 1]) + 1) * 8;
        if available_len < extension_len {
            return Err(TunPacketError::Ipv6ExtensionHeaderTruncated {
                next_header,
                required_len: extension_len,
                available_len,
            });
        }
        next_header = packet[offset];
        offset += extension_len;
    }
    if is_ipv6_extension_header(next_header) {
        return Err(TunPacketError::Ipv6ExtensionHeaderUnsupported { next_header });
    }
    Ok((next_header, offset))
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

fn is_ipv6_skippable_extension_header(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 60)
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

fn build_ipv4_tcp_response_packet(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    flags: TunTcpFlags,
    window_size: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_length = 20 + payload.len();
    let total_length = 20 + tcp_length;
    let mut packet = vec![0; total_length];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = TunTransportProtocol::Tcp.ip_protocol_number();
    packet[12..16].copy_from_slice(&source_ip.octets());
    packet[16..20].copy_from_slice(&destination_ip.octets());
    write_tcp_segment(
        &mut packet[20..],
        source_port,
        destination_port,
        sequence_number,
        acknowledgment_number,
        flags,
        window_size,
        payload,
    );
    let tcp_checksum = tcp_checksum_ipv4(source_ip, destination_ip, &packet[20..]);
    packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
    let header_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    packet
}

fn build_ipv6_tcp_response_packet(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    flags: TunTcpFlags,
    window_size: u16,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_length = 20 + payload.len();
    let mut packet = vec![0; 40 + tcp_length];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(tcp_length as u16).to_be_bytes());
    packet[6] = TunTransportProtocol::Tcp.ip_protocol_number();
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());
    write_tcp_segment(
        &mut packet[40..],
        source_port,
        destination_port,
        sequence_number,
        acknowledgment_number,
        flags,
        window_size,
        payload,
    );
    let tcp_checksum = tcp_checksum_ipv6(source_ip, destination_ip, &packet[40..]);
    packet[56..58].copy_from_slice(&tcp_checksum.to_be_bytes());
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

fn write_tcp_segment(
    segment: &mut [u8],
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    flags: TunTcpFlags,
    window_size: u16,
    payload: &[u8],
) {
    segment[0..2].copy_from_slice(&source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
    segment[4..8].copy_from_slice(&sequence_number.to_be_bytes());
    segment[8..12].copy_from_slice(&acknowledgment_number.to_be_bytes());
    segment[12] = (5 << 4) | (((flags.bits() >> 8) & 0x01) as u8);
    segment[13] = flags.bits() as u8;
    segment[14..16].copy_from_slice(&window_size.to_be_bytes());
    segment[16..18].copy_from_slice(&0u16.to_be_bytes());
    segment[18..20].copy_from_slice(&0u16.to_be_bytes());
    segment[20..].copy_from_slice(payload);
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

fn tcp_checksum_ipv4(source_ip: Ipv4Addr, destination_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum = 0;
    add_checksum_bytes(&mut sum, &source_ip.octets());
    add_checksum_bytes(&mut sum, &destination_ip.octets());
    add_checksum_bytes(
        &mut sum,
        &[0, TunTransportProtocol::Tcp.ip_protocol_number()],
    );
    add_checksum_bytes(&mut sum, &(tcp_segment.len() as u16).to_be_bytes());
    add_checksum_bytes(&mut sum, tcp_segment);
    finish_checksum(sum)
}

fn tcp_checksum_ipv6(source_ip: Ipv6Addr, destination_ip: Ipv6Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum = 0;
    add_checksum_bytes(&mut sum, &source_ip.octets());
    add_checksum_bytes(&mut sum, &destination_ip.octets());
    add_checksum_bytes(&mut sum, &(tcp_segment.len() as u32).to_be_bytes());
    add_checksum_bytes(
        &mut sum,
        &[0, 0, 0, TunTransportProtocol::Tcp.ip_protocol_number()],
    );
    add_checksum_bytes(&mut sum, tcp_segment);
    finish_checksum(sum)
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
