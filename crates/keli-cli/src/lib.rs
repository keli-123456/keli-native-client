use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
    UdpSocket,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use keli_client_core::{
    build_connection_plan, ClientErrorKind, ClientRuntime, ConnectionPhase, ConnectionPlan,
    PanelState, RuntimeConfig, RuntimeEvent, RuntimeStatus, SkippedProfileSummary,
    SubscriptionNodeCapability,
};
use keli_net_core::{
    build_dns_error_response, build_dns_response, encode_socks5_udp_datagram,
    http_connect_bad_request_response, http_connect_success_response,
    http_proxy_bad_request_response, parse_dns_query, parse_http_connect_request,
    parse_http_proxy_request, parse_socks5_handshake, parse_socks5_request,
    parse_socks5_udp_datagram, relay_owned_bidirectional_with_options, socks5_no_auth_response,
    socks5_reply, ConnectionErrorKind, ConnectionReport, DirectTcpConnector, DirectUdpConnector,
    DnsAddressFamilyPolicy, DnsCache, DnsEngine, DnsError, DnsLocalResolutionPolicy,
    DnsQuestionType, LocalInbound, OutboundConnection, OutboundRegistry, OutboundTarget,
    RelayOptions, RouteAction, RouteEngine, RouteIpCidr, RouteMatcher, RouteRule, Socks5Address,
    Socks5Command, Socks5ReplyCode, SystemDnsResolver,
};
use keli_platform::{
    NativeSystemProxyController, NativeTunDeviceController, PlatformCapabilities,
    SystemProxyConfig, SystemProxyController, SystemProxySnapshot, SystemProxyStatus,
    TunDeviceConfig, TunDeviceController, TunDevicePreflight, TunDeviceReadiness,
    TunDeviceSnapshot, TunDeviceStatus,
};
use keli_protocol::{
    detect_subscription_input_format, parse_mihomo_outbound_profiles,
    parse_subscription_outbound_profiles, Endpoint, OutboundProfile, ParsedOutboundProfiles,
    ProxyProtocol, SecurityKind, SkippedOutboundProfile, TransportKind,
};

const DEFAULT_FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_TUN_INTERFACE_NAME: &str = "keli-tun0";
const DEFAULT_TUN_ADDRESS_CIDR: &str = "10.7.0.1/24";
const DEFAULT_TUN_MTU: u16 = 1500;
const BLOCK_CIDR_RULE_PREFIX: &str = "cidr:";
const BLOCK_PORT_RULE_PREFIX: &str = "port:";
const UDP_RELAY_POLL_INTERVAL: Duration = Duration::from_millis(200);
const MANAGED_ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const SUPPORTED_OUTBOUNDS: &str =
    "direct,socks5-tcp,http-connect,trojan-tcp,trojan-ws,trojan-httpupgrade,trojan-grpc,trojan-h2,trojan-quic,vless-tcp,vless-ws,vless-httpupgrade,vless-grpc,vless-h2,vless-quic,vmess-tcp,vmess-ws,vmess-httpupgrade,vmess-grpc,vmess-h2,vmess-quic,shadowsocks-tcp,anytls-tls-tcp,naive-h2-tcp,naive-h3-quic,mieru-tcp,hy2-quic,tuic-quic";
const SUPPORTED_UDP_OUTBOUNDS: &str =
    "direct,socks5-udp,trojan-tcp-udp,trojan-tls-tcp-udp,trojan-ws-udp,trojan-tls-ws-udp,trojan-httpupgrade-udp,trojan-tls-httpupgrade-udp,trojan-grpc-udp,trojan-tls-grpc-udp,trojan-h2-udp,trojan-tls-h2-udp,trojan-quic-udp,vless-tcp-udp,vless-tls-tcp-udp,vless-ws-udp,vless-tls-ws-udp,vless-httpupgrade-udp,vless-tls-httpupgrade-udp,vless-grpc-udp,vless-tls-grpc-udp,vless-h2-udp,vless-tls-h2-udp,vless-quic-udp,vmess-tcp-aead-udp,vmess-tls-tcp-aead-udp,vmess-ws-aead-udp,vmess-tls-ws-aead-udp,vmess-httpupgrade-aead-udp,vmess-tls-httpupgrade-aead-udp,vmess-grpc-aead-udp,vmess-tls-grpc-aead-udp,vmess-h2-aead-udp,vmess-tls-h2-aead-udp,vmess-quic-aead-udp,shadowsocks-aead,anytls-tls-tcp-uot-udp,mieru-tcp-udp,hy2-quic,tuic-quic";
const SUPPORTED_PROTOCOL_CAPABILITIES: &str =
    "trojan=tcp,udp;vless=tcp,udp;vmess=tcp,udp;shadowsocks=tcp,udp;anytls=tcp,udp;naive=tcp;mieru=tcp,udp;hy2=tcp,udp;tuic=tcp,udp;socks=tcp,udp;http=tcp";
const ROUTE_RULE_CAPABILITIES: &str =
    "domain-suffix,domain-keyword,ip-exact,ip-cidr,port-exact,port-range";
const TUN_PACKET_PIPELINE_CAPABILITIES: &str =
    "ipv4,ipv6,tcp,udp,udp-payload,icmp,route-decision,dns-hijack,dns-query-plan,dns-engine-response,udp-response-packet,dns-response-packet,relay-plan";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    Doctor {
        output: ProbeOutputFormat,
    },
    TunPreflight {
        config: TunDeviceConfig,
        output: ProbeOutputFormat,
    },
    Version,
    ListenMixed {
        listen: String,
        once: bool,
        block_domains: Vec<String>,
        profile_config: Option<String>,
        outbound_tag: Option<String>,
        system_proxy: bool,
        system_proxy_bypass: Vec<String>,
        tun_device: Option<TunDeviceConfig>,
        first_byte_timeout: Duration,
        idle_timeout: Duration,
        dns_options: MixedDnsOptions,
    },
    ProbeOutbound {
        profile_config: String,
        outbound_tag: Option<String>,
        target: String,
        payload: Option<String>,
        expect: Option<String>,
        udp: bool,
        output: ProbeOutputFormat,
        first_byte_timeout: Duration,
    },
    SmokeMixed {
        profile_config: String,
        outbound_tag: Option<String>,
        target: String,
        payload: Option<String>,
        expect: Option<String>,
        inbound: SmokeInboundKind,
        output: ProbeOutputFormat,
        first_byte_timeout: Duration,
    },
    ProfileCheck {
        profile_config: String,
        output: ProbeOutputFormat,
    },
    SupportBundle {
        profile_config: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmokeInboundKind {
    Socks5,
    HttpConnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CliPortRange {
    start: u16,
    end: u16,
}

impl CliPortRange {
    fn label(self) -> String {
        if self.start == self.end {
            self.start.to_string()
        } else {
            format!("{}-{}", self.start, self.end)
        }
    }
}

impl SmokeInboundKind {
    fn label(self) -> &'static str {
        match self {
            Self::Socks5 => "mixed-socks5-smoke",
            Self::HttpConnect => "mixed-http-connect-smoke",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MixedDnsOptions {
    pub local_resolution_policy: DnsLocalResolutionPolicy,
    pub address_family_policy: DnsAddressFamilyPolicy,
    pub cache_ttl: Duration,
}

impl Default for MixedDnsOptions {
    fn default() -> Self {
        Self {
            local_resolution_policy: DnsLocalResolutionPolicy::AllowSystem,
            address_family_policy: DnsAddressFamilyPolicy::DualStack,
            cache_ttl: Duration::from_secs(60),
        }
    }
}

impl MixedDnsOptions {
    fn engine(self) -> DnsEngine<SystemDnsResolver> {
        DnsEngine::with_policies(
            SystemDnsResolver,
            DnsCache::new(self.cache_ttl),
            self.local_resolution_policy,
            self.address_family_policy,
        )
    }

    fn local_resolution_label(self) -> &'static str {
        match self.local_resolution_policy {
            DnsLocalResolutionPolicy::AllowSystem => "allow-system",
            DnsLocalResolutionPolicy::PreventPublicLeak => "prevent-public-leak",
        }
    }

    fn address_family_label(self) -> &'static str {
        match self.address_family_policy {
            DnsAddressFamilyPolicy::DualStack => "dual-stack",
            DnsAddressFamilyPolicy::Ipv4Only => "ipv4-only",
            DnsAddressFamilyPolicy::Ipv6Only => "ipv6-only",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MixedProxyRuntime {
    pub routes: RouteEngine,
    pub relay_options: RelayOptions,
    pub outbounds: OutboundRegistry,
    pub dns_options: MixedDnsOptions,
}

impl MixedProxyRuntime {
    pub fn with_routes(routes: RouteEngine) -> Self {
        Self {
            routes,
            relay_options: default_relay_options(),
            outbounds: OutboundRegistry::new(),
            dns_options: MixedDnsOptions::default(),
        }
    }

    pub fn with_routes_and_outbounds(routes: RouteEngine, outbounds: OutboundRegistry) -> Self {
        Self {
            routes,
            relay_options: default_relay_options(),
            outbounds,
            dns_options: MixedDnsOptions::default(),
        }
    }
}

impl Default for MixedProxyRuntime {
    fn default() -> Self {
        Self::with_routes(RouteEngine::new(RouteAction::Direct))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedMixedOptions {
    pub listen: String,
    pub block_domains: Vec<String>,
    pub outbound_tag: Option<String>,
    pub relay_options: RelayOptions,
    pub system_proxy: bool,
    pub system_proxy_bypass: Vec<String>,
    pub dns_options: MixedDnsOptions,
}

impl Default for ManagedMixedOptions {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7890".to_string(),
            block_domains: Vec::new(),
            outbound_tag: None,
            relay_options: default_relay_options(),
            system_proxy: false,
            system_proxy_bypass: Vec::new(),
            dns_options: MixedDnsOptions::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedNodeProbeOptions {
    pub outbound_tag: String,
    pub target: String,
    pub payload: Vec<u8>,
    pub expect: Vec<u8>,
    pub inbound: SmokeInboundKind,
    pub first_byte_timeout: Duration,
    pub udp_available: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedNodeProbeSweepOptions {
    pub target: String,
    pub payload: Vec<u8>,
    pub expect: Vec<u8>,
    pub inbound: SmokeInboundKind,
    pub first_byte_timeout: Duration,
    pub udp_available: Option<bool>,
}

#[derive(Debug)]
pub struct ManagedSystemProxyGuard<'a, C: SystemProxyController + ?Sized> {
    controller: &'a C,
    snapshot: Option<SystemProxySnapshot>,
    config: SystemProxyConfig,
}

impl<'a, C: SystemProxyController + ?Sized> ManagedSystemProxyGuard<'a, C> {
    pub fn config(&self) -> &SystemProxyConfig {
        &self.config
    }

    pub fn restore(mut self) -> Result<(), String> {
        let Some(snapshot) = self.snapshot.take() else {
            return Ok(());
        };
        self.controller
            .restore(&snapshot)
            .map_err(|error| format!("restore system proxy: {error}"))
    }
}

#[derive(Debug)]
pub struct ManagedTunDeviceGuard<'a, C: TunDeviceController + ?Sized> {
    controller: &'a C,
    config: TunDeviceConfig,
    snapshot: TunDeviceSnapshot,
    owns_device: bool,
}

impl<'a, C: TunDeviceController + ?Sized> ManagedTunDeviceGuard<'a, C> {
    pub fn config(&self) -> &TunDeviceConfig {
        &self.config
    }

    pub fn snapshot(&self) -> &TunDeviceSnapshot {
        &self.snapshot
    }

    pub fn owns_device(&self) -> bool {
        self.owns_device
    }

    pub fn stop(self) -> Result<TunDeviceSnapshot, String> {
        if !self.owns_device {
            return Ok(self.snapshot);
        }
        self.controller
            .stop()
            .map_err(|error| format!("stop TUN device: {error}"))
    }
}

pub fn apply_tun_device_for_config<'a, C: TunDeviceController + ?Sized>(
    controller: &'a C,
    config: TunDeviceConfig,
) -> Result<ManagedTunDeviceGuard<'a, C>, String> {
    let preflight = TunDevicePreflight::check(controller, config.clone());
    if !preflight.ready {
        return Err(format!(
            "TUN preflight failed: status={} reason={}",
            preflight.readiness.label(),
            preflight.reason.as_deref().unwrap_or("-")
        ));
    }

    match preflight.readiness {
        TunDeviceReadiness::AlreadyRunning => {
            return Ok(ManagedTunDeviceGuard {
                controller,
                config,
                snapshot: TunDeviceSnapshot {
                    supported: preflight.status.supported,
                    lifecycle_available: preflight.status.lifecycle_available,
                    running: preflight.status.running,
                    interface_name: preflight.status.interface_name,
                    address_cidr: preflight.status.address_cidr,
                    mtu: preflight.status.mtu,
                    dns_hijack: preflight.status.dns_hijack,
                },
                owns_device: false,
            });
        }
        TunDeviceReadiness::Ready => {}
        _ => {
            return Err(format!(
                "TUN preflight failed: status={} reason={}",
                preflight.readiness.label(),
                preflight.reason.as_deref().unwrap_or("-")
            ));
        }
    }

    let snapshot = controller
        .start(&config)
        .map_err(|error| format!("start TUN device: {error}"))?;
    if !snapshot.running {
        return Err("start TUN device did not report a running device".to_string());
    }
    if !managed_tun_snapshot_matches_config(&snapshot, &config) {
        return Err("start TUN device returned a different running config".to_string());
    }

    Ok(ManagedTunDeviceGuard {
        controller,
        config,
        snapshot,
        owns_device: true,
    })
}

fn managed_tun_snapshot_matches_config(
    snapshot: &TunDeviceSnapshot,
    config: &TunDeviceConfig,
) -> bool {
    snapshot.interface_name.as_deref() == Some(config.interface_name.as_str())
        && snapshot.address_cidr.as_deref() == Some(config.address_cidr.as_str())
        && snapshot.mtu == Some(config.mtu)
        && snapshot.dns_hijack == Some(config.dns_hijack)
}

pub fn run_with_optional_tun_device<C, F>(
    controller: &C,
    config: Option<TunDeviceConfig>,
    run: F,
) -> Result<(), String>
where
    C: TunDeviceController + ?Sized,
    F: FnOnce() -> Result<(), String>,
{
    let guard = config
        .map(|config| apply_tun_device_for_config(controller, config))
        .transpose()?;
    let run_result = run();
    let stop_result = guard
        .map(|guard| guard.stop().map(|_| ()))
        .unwrap_or(Ok(()));

    match (run_result, stop_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(run_error), Ok(())) => Err(run_error),
        (Ok(()), Err(stop_error)) => Err(stop_error),
        (Err(run_error), Err(stop_error)) => Err(format!("{run_error}; {stop_error}")),
    }
}

#[derive(Debug)]
pub struct ManagedMixedSession<'a, C: SystemProxyController + ?Sized> {
    state: ClientRuntime,
    listener: Option<TcpListener>,
    listen_addr: SocketAddr,
    runtime: MixedProxyRuntime,
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    dns_options: MixedDnsOptions,
    system_proxy_guard: Option<ManagedSystemProxyGuard<'a, C>>,
}

#[derive(Debug)]
pub struct ManagedMixedHandle<'a, C: SystemProxyController + ?Sized> {
    state: ClientRuntime,
    listen_addr: SocketAddr,
    selected_outbound: Option<String>,
    runtime: Arc<RwLock<MixedProxyRuntime>>,
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    dns_options: MixedDnsOptions,
    node_health: HashMap<String, ManagedNodeHealthStatus>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<io::Result<()>>>,
    system_proxy_guard: Option<ManagedSystemProxyGuard<'a, C>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedMixedStatusSnapshot {
    pub status: RuntimeStatus,
    pub listen_addr: Option<SocketAddr>,
    pub selected_outbound: Option<String>,
    pub generation: u64,
    pub event_count: usize,
    pub recent_events: Vec<RuntimeEvent>,
    pub last_error: Option<ClientErrorKind>,
    pub system_proxy: Option<SystemProxyConfig>,
    pub subscription: Option<ManagedSubscriptionStatus>,
    pub dns_options: MixedDnsOptions,
    pub panel_state: Option<PanelState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSubscriptionStatus {
    pub usable: bool,
    pub supported_tags: Vec<String>,
    pub supported: Vec<SubscriptionNodeCapability>,
    pub skipped: Vec<SkippedProfileSummary>,
    pub default_outbound: Option<String>,
    pub selected_outbound: String,
    pub recommended_outbound: String,
    pub health_summary: ManagedSubscriptionHealthSummary,
    pub node_health: Vec<ManagedNodeHealthStatus>,
}

impl ManagedSubscriptionStatus {
    fn from_plan(
        plan: &ConnectionPlan,
        node_health: &HashMap<String, ManagedNodeHealthStatus>,
    ) -> Self {
        let preflight = plan.preflight();
        let supported_tags = preflight.supported_tags().to_vec();
        let supported = preflight.supported().to_vec();
        let node_health = supported_tags
            .iter()
            .map(|tag| {
                node_health
                    .get(tag)
                    .cloned()
                    .unwrap_or_else(|| ManagedNodeHealthStatus::unknown(tag.clone()))
            })
            .collect::<Vec<_>>();
        let selected_outbound = plan.selected_outbound().to_string();
        let recommended_outbound =
            recommend_managed_outbound_from_health(&node_health, &selected_outbound);
        let health_summary = ManagedSubscriptionHealthSummary::from_node_health(
            &node_health,
            &selected_outbound,
            &recommended_outbound,
        );
        Self {
            usable: preflight.is_usable(),
            supported_tags,
            supported,
            skipped: preflight.skipped().to_vec(),
            default_outbound: preflight.default_outbound().map(str::to_string),
            selected_outbound,
            recommended_outbound,
            health_summary,
            node_health,
        }
    }

    pub fn supported_count(&self) -> usize {
        self.supported.len()
    }

    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }

    pub fn health_for(&self, tag: &str) -> Option<&ManagedNodeHealthStatus> {
        self.node_health.iter().find(|health| health.tag == tag)
    }

    pub fn capability_for(&self, tag: &str) -> Option<&SubscriptionNodeCapability> {
        self.supported
            .iter()
            .find(|capability| capability.tag == tag)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSubscriptionHealthSummary {
    pub healthy_count: usize,
    pub unhealthy_count: usize,
    pub unknown_count: usize,
    pub checked_count: usize,
    pub last_checked_at: Option<SystemTime>,
    pub selected_state: Option<ManagedNodeHealthState>,
    pub recommended_state: Option<ManagedNodeHealthState>,
    pub recommended_is_selected: bool,
    pub switch_recommended: bool,
    pub fully_checked: bool,
}

impl ManagedSubscriptionHealthSummary {
    fn from_node_health(
        node_health: &[ManagedNodeHealthStatus],
        selected_outbound: &str,
        recommended_outbound: &str,
    ) -> Self {
        let mut healthy_count = 0;
        let mut unhealthy_count = 0;
        let mut unknown_count = 0;
        let mut checked_count = 0;
        let mut last_checked_at = None;

        for health in node_health {
            match health.state {
                ManagedNodeHealthState::Healthy => healthy_count += 1,
                ManagedNodeHealthState::Unhealthy => unhealthy_count += 1,
                ManagedNodeHealthState::Unknown => unknown_count += 1,
            }
            if let Some(checked_at) = health.checked_at {
                checked_count += 1;
                last_checked_at = Some(
                    last_checked_at.map_or(checked_at, |latest: SystemTime| latest.max(checked_at)),
                );
            }
        }
        let selected_state = node_health
            .iter()
            .find(|health| health.tag == selected_outbound)
            .map(|health| health.state.clone());
        let recommended_state = node_health
            .iter()
            .find(|health| health.tag == recommended_outbound)
            .map(|health| health.state.clone());
        let recommended_is_selected = selected_outbound == recommended_outbound;

        Self {
            healthy_count,
            unhealthy_count,
            unknown_count,
            checked_count,
            last_checked_at,
            selected_state,
            recommended_state,
            recommended_is_selected,
            switch_recommended: !recommended_is_selected,
            fully_checked: checked_count == node_health.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedNodeHealthState {
    Unknown,
    Healthy,
    Unhealthy,
}

impl ManagedNodeHealthState {
    fn label(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedNodeHealthStatus {
    pub tag: String,
    pub state: ManagedNodeHealthState,
    pub tcp_available: Option<bool>,
    pub udp_available: Option<bool>,
    pub latency_ms: Option<u128>,
    pub error_kind: Option<ConnectionErrorKind>,
    pub error_detail: Option<String>,
    pub checked_at: Option<SystemTime>,
}

impl ManagedNodeHealthStatus {
    pub fn unknown(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            state: ManagedNodeHealthState::Unknown,
            tcp_available: None,
            udp_available: None,
            latency_ms: None,
            error_kind: None,
            error_detail: None,
            checked_at: None,
        }
    }

    pub fn healthy(
        tag: impl Into<String>,
        latency_ms: Option<u128>,
        tcp_available: bool,
        udp_available: bool,
    ) -> Self {
        Self {
            tag: tag.into(),
            state: ManagedNodeHealthState::Healthy,
            tcp_available: Some(tcp_available),
            udp_available: Some(udp_available),
            latency_ms,
            error_kind: None,
            error_detail: None,
            checked_at: Some(SystemTime::now()),
        }
    }

    pub fn unhealthy(
        tag: impl Into<String>,
        error_kind: ConnectionErrorKind,
        error_detail: Option<String>,
    ) -> Self {
        Self {
            tag: tag.into(),
            state: ManagedNodeHealthState::Unhealthy,
            tcp_available: Some(false),
            udp_available: Some(false),
            latency_ms: None,
            error_kind: Some(error_kind),
            error_detail,
            checked_at: Some(SystemTime::now()),
        }
    }
}

fn recommend_managed_outbound_from_health(
    node_health: &[ManagedNodeHealthStatus],
    selected_outbound: &str,
) -> String {
    node_health
        .iter()
        .filter(|health| {
            health.state == ManagedNodeHealthState::Healthy && health.tcp_available != Some(false)
        })
        .min_by_key(|health| {
            (
                health.latency_ms.is_none(),
                health.latency_ms.unwrap_or(u128::MAX),
            )
        })
        .map(|health| health.tag.clone())
        .unwrap_or_else(|| selected_outbound.to_string())
}

impl ManagedMixedStatusSnapshot {
    fn stopped(panel_state: Option<PanelState>) -> Self {
        Self {
            status: RuntimeStatus::Stopped,
            listen_addr: None,
            selected_outbound: None,
            generation: 0,
            event_count: 0,
            recent_events: Vec::new(),
            last_error: None,
            system_proxy: None,
            subscription: None,
            dns_options: MixedDnsOptions::default(),
            panel_state,
        }
    }

    pub fn system_proxy_enabled(&self) -> bool {
        self.system_proxy.is_some()
    }
}

#[derive(Debug)]
pub struct ManagedMixedController<'a, C: SystemProxyController + ?Sized> {
    controller: &'a C,
    handle: Option<ManagedMixedHandle<'a, C>>,
    panel_state: Option<PanelState>,
}

impl<'a, C: SystemProxyController + ?Sized> ManagedMixedController<'a, C> {
    pub fn new(controller: &'a C) -> Self {
        Self {
            controller,
            handle: None,
            panel_state: None,
        }
    }

    pub fn is_running(&self) -> bool {
        self.handle.is_some()
    }

    pub fn status(&self) -> ManagedMixedStatusSnapshot {
        self.handle
            .as_ref()
            .map(|handle| ManagedMixedStatusSnapshot::from_handle(handle, self.panel_state.clone()))
            .unwrap_or_else(|| ManagedMixedStatusSnapshot::stopped(self.panel_state.clone()))
    }

    pub fn start_from_subscription_config_text(
        &mut self,
        config_text: &str,
        options: ManagedMixedOptions,
    ) -> Result<ManagedMixedStatusSnapshot, String> {
        if self.handle.is_some() {
            return Err("managed mixed core is already running".to_string());
        }
        self.ensure_panel_allows_traffic()?;

        let session = ManagedMixedSession::start_from_subscription_config_text(
            config_text,
            options,
            self.controller,
        )?;
        self.handle = Some(session.spawn_background()?);
        Ok(self.status())
    }

    pub fn reload_from_subscription_config_text(
        &mut self,
        config_text: &str,
        outbound_tag: Option<String>,
    ) -> Result<ManagedMixedStatusSnapshot, String> {
        self.ensure_panel_allows_traffic()?;
        {
            let handle = self
                .handle
                .as_mut()
                .ok_or_else(|| "managed mixed core is not running".to_string())?;
            handle.reload_from_subscription_config_text(config_text, outbound_tag)?;
        }
        Ok(self.status())
    }

    pub fn record_node_health(
        &mut self,
        health: ManagedNodeHealthStatus,
    ) -> Result<ManagedMixedStatusSnapshot, String> {
        {
            let handle = self
                .handle
                .as_mut()
                .ok_or_else(|| "managed mixed core is not running".to_string())?;
            handle.record_node_health(health)?;
        }
        Ok(self.status())
    }

    pub fn probe_node_health(
        &mut self,
        options: ManagedNodeProbeOptions,
    ) -> Result<ManagedMixedStatusSnapshot, String> {
        self.ensure_panel_allows_traffic()?;
        {
            let handle = self
                .handle
                .as_mut()
                .ok_or_else(|| "managed mixed core is not running".to_string())?;
            handle.probe_node_health(options)?;
        }
        Ok(self.status())
    }

    pub fn probe_all_node_health(
        &mut self,
        options: ManagedNodeProbeSweepOptions,
    ) -> Result<ManagedMixedStatusSnapshot, String> {
        self.ensure_panel_allows_traffic()?;
        {
            let handle = self
                .handle
                .as_mut()
                .ok_or_else(|| "managed mixed core is not running".to_string())?;
            handle.probe_all_node_health(options)?;
        }
        Ok(self.status())
    }

    pub fn probe_all_node_health_and_apply_recommended(
        &mut self,
        options: ManagedNodeProbeSweepOptions,
    ) -> Result<ManagedMixedStatusSnapshot, String> {
        self.ensure_panel_allows_traffic()?;
        {
            let handle = self
                .handle
                .as_mut()
                .ok_or_else(|| "managed mixed core is not running".to_string())?;
            handle.probe_all_node_health(options)?;
            handle.apply_recommended_outbound()?;
        }
        Ok(self.status())
    }

    pub fn apply_recommended_outbound(&mut self) -> Result<ManagedMixedStatusSnapshot, String> {
        self.ensure_panel_allows_traffic()?;
        {
            let handle = self
                .handle
                .as_mut()
                .ok_or_else(|| "managed mixed core is not running".to_string())?;
            handle.apply_recommended_outbound()?;
        }
        Ok(self.status())
    }

    pub fn record_panel_state(&mut self, panel_state: PanelState) -> ManagedMixedStatusSnapshot {
        if let Some(handle) = self.handle.as_mut() {
            handle.record_panel_state(&panel_state);
        }
        self.panel_state = Some(panel_state);
        self.status()
    }

    pub fn clear_panel_state(&mut self) -> ManagedMixedStatusSnapshot {
        if let Some(handle) = self.handle.as_mut() {
            handle.record_panel_state_cleared();
        }
        self.panel_state = None;
        self.status()
    }

    fn ensure_panel_allows_traffic(&mut self) -> Result<(), String> {
        let Some(error) = self
            .panel_state
            .as_ref()
            .and_then(PanelState::traffic_restriction_error)
        else {
            return Ok(());
        };
        if let Some(handle) = self.handle.as_mut() {
            handle.record_panel_traffic_restricted(error.clone());
        }
        Err(format!(
            "managed mixed core traffic restricted by panel: {error:?}"
        ))
    }

    pub fn stop(&mut self) -> Result<ClientRuntime, String> {
        let handle = self
            .handle
            .take()
            .ok_or_else(|| "managed mixed core is not running".to_string())?;
        handle.stop()
    }
}

impl ManagedMixedStatusSnapshot {
    fn from_handle<C: SystemProxyController + ?Sized>(
        handle: &ManagedMixedHandle<'_, C>,
        panel_state: Option<PanelState>,
    ) -> Self {
        let recent_events: Vec<RuntimeEvent> =
            handle.events().iter().rev().take(5).cloned().collect();
        let last_error = handle
            .events()
            .iter()
            .rev()
            .find_map(|event| match &event.status {
                RuntimeStatus::Failed(error) => Some(error.clone()),
                _ => None,
            });
        Self {
            status: handle.status().clone(),
            listen_addr: Some(handle.listen_addr()),
            selected_outbound: handle.selected_outbound().map(str::to_string),
            generation: handle.generation(),
            event_count: handle.events().len(),
            recent_events,
            last_error,
            system_proxy: handle.system_proxy_config().cloned(),
            subscription: handle.subscription_status(),
            dns_options: handle.dns_options,
            panel_state,
        }
    }
}

impl<'a, C: SystemProxyController + ?Sized> ManagedMixedHandle<'a, C> {
    pub fn status(&self) -> &RuntimeStatus {
        self.state.status()
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn selected_outbound(&self) -> Option<&str> {
        self.selected_outbound.as_deref()
    }

    pub fn generation(&self) -> u64 {
        self.state.generation()
    }

    pub fn events(&self) -> &[RuntimeEvent] {
        self.state.events()
    }

    pub fn system_proxy_config(&self) -> Option<&SystemProxyConfig> {
        self.system_proxy_guard
            .as_ref()
            .map(ManagedSystemProxyGuard::config)
    }

    pub fn subscription_status(&self) -> Option<ManagedSubscriptionStatus> {
        self.state
            .active_plan()
            .map(|plan| ManagedSubscriptionStatus::from_plan(plan, &self.node_health))
    }

    fn record_panel_state(&mut self, panel_state: &PanelState) {
        self.state.record_status_note(format!(
            "panel state recorded: account={} risk={} restrict_traffic={}",
            panel_state.user.account_state.label(),
            panel_state.risk_control.label(),
            panel_state.should_restrict_traffic()
        ));
    }

    fn record_panel_state_cleared(&mut self) {
        self.state.record_status_note("panel state cleared");
    }

    fn record_panel_traffic_restricted(&mut self, error: ClientErrorKind) {
        self.state
            .record_control_rejected(error, "panel traffic restricted");
    }

    pub fn record_node_health(&mut self, health: ManagedNodeHealthStatus) -> Result<(), String> {
        self.ensure_active_subscription_tag(&health.tag)?;
        self.set_node_health(health);
        Ok(())
    }

    pub fn probe_node_health(&mut self, options: ManagedNodeProbeOptions) -> Result<(), String> {
        self.ensure_active_subscription_tag(&options.outbound_tag)?;
        let config_text = self
            .state
            .active_config()
            .ok_or_else(|| "managed mixed core has no active subscription".to_string())?
            .config_text()
            .to_string();
        let result = smoke_mixed_connect_from_subscription_config_text(
            &config_text,
            Some(options.outbound_tag.clone()),
            &options.target,
            &options.payload,
            &options.expect,
            options.inbound,
            options.first_byte_timeout,
        );

        match result {
            Ok(report) => {
                self.set_node_health(ManagedNodeHealthStatus {
                    tag: options.outbound_tag,
                    state: ManagedNodeHealthState::Healthy,
                    tcp_available: Some(true),
                    udp_available: options.udp_available,
                    latency_ms: report.first_byte_ms.or(report.connect_ms),
                    error_kind: None,
                    error_detail: None,
                    checked_at: Some(SystemTime::now()),
                });
                Ok(())
            }
            Err(error) => {
                self.set_node_health(ManagedNodeHealthStatus {
                    tag: options.outbound_tag,
                    state: ManagedNodeHealthState::Unhealthy,
                    tcp_available: Some(false),
                    udp_available: None,
                    latency_ms: None,
                    error_kind: Some(classify_managed_probe_error(&error)),
                    error_detail: Some(error.clone()),
                    checked_at: Some(SystemTime::now()),
                });
                Err(error)
            }
        }
    }

    fn set_node_health(&mut self, health: ManagedNodeHealthStatus) {
        let note = format!(
            "node health recorded: {}={}",
            health.tag,
            health.state.label()
        );
        self.node_health.insert(health.tag.clone(), health);
        self.state.record_status_note(note);
    }

    pub fn probe_all_node_health(
        &mut self,
        options: ManagedNodeProbeSweepOptions,
    ) -> Result<(), String> {
        let tags = self
            .state
            .active_plan()
            .ok_or_else(|| "managed mixed core has no active subscription".to_string())?
            .preflight()
            .supported_tags()
            .to_vec();
        if tags.is_empty() {
            return Err("managed mixed core has no supported subscription nodes".to_string());
        }
        for outbound_tag in tags {
            let _ = self.probe_node_health(ManagedNodeProbeOptions {
                outbound_tag,
                target: options.target.clone(),
                payload: options.payload.clone(),
                expect: options.expect.clone(),
                inbound: options.inbound,
                first_byte_timeout: options.first_byte_timeout,
                udp_available: options.udp_available,
            });
        }
        Ok(())
    }

    pub fn probe_all_node_health_and_apply_recommended(
        &mut self,
        options: ManagedNodeProbeSweepOptions,
    ) -> Result<(), String> {
        self.probe_all_node_health(options)?;
        self.apply_recommended_outbound()
    }

    pub fn apply_recommended_outbound(&mut self) -> Result<(), String> {
        let (selected_outbound, recommended_outbound) = {
            let plan = self
                .state
                .active_plan()
                .ok_or_else(|| "managed mixed core has no active subscription".to_string())?;
            let status = ManagedSubscriptionStatus::from_plan(plan, &self.node_health);
            (
                plan.selected_outbound().to_string(),
                status.recommended_outbound,
            )
        };
        if recommended_outbound == selected_outbound {
            return Ok(());
        }
        let config_text = self
            .state
            .active_config()
            .ok_or_else(|| "managed mixed core has no active subscription".to_string())?
            .config_text()
            .to_string();
        self.reload_from_subscription_config_text(&config_text, Some(recommended_outbound))
    }

    fn ensure_active_subscription_tag(&self, tag: &str) -> Result<(), String> {
        let Some(plan) = self.state.active_plan() else {
            return Err("managed mixed core has no active subscription".to_string());
        };
        if plan
            .preflight()
            .supported_tags()
            .iter()
            .any(|supported| supported == tag)
        {
            return Ok(());
        }
        Err(format!(
            "node health tag is not in active subscription: {tag}"
        ))
    }

    pub fn reload_from_subscription_config_text(
        &mut self,
        config_text: &str,
        outbound_tag: Option<String>,
    ) -> Result<(), String> {
        let listen = self.listen_addr.to_string();
        let config = RuntimeConfig::new(config_text, outbound_tag.clone(), listen.clone());
        let plan = match build_connection_plan(config_text, outbound_tag.as_deref(), listen.clone())
        {
            Ok(plan) => plan,
            Err(error) => {
                let _ = self.state.reload(config);
                return Err(format!("runtime reload failed: {error:?}"));
            }
        };
        let selected_outbound = plan.selected_outbound().to_string();
        let next_runtime = match mixed_runtime_from_subscription_config_text_with_dns_options(
            config_text,
            self.block_domains.clone(),
            self.relay_options,
            Some(selected_outbound.clone()),
            self.dns_options,
        ) {
            Ok(runtime) => runtime,
            Err(error) => {
                self.state
                    .record_reload_rejected(ClientErrorKind::ConfigInvalid(error.clone()));
                return Err(format!("runtime reload failed: {error}"));
            }
        };

        {
            let mut runtime = self
                .runtime
                .write()
                .map_err(|_| "managed mixed runtime lock poisoned".to_string())?;
            *runtime = next_runtime;
        }

        self.state
            .reload(config)
            .map_err(|error| format!("runtime reload failed: {error:?}"))?;
        self.selected_outbound = Some(selected_outbound);
        self.prune_node_health_to_active_plan();
        Ok(())
    }

    fn prune_node_health_to_active_plan(&mut self) {
        let Some(plan) = self.state.active_plan() else {
            self.node_health.clear();
            return;
        };
        self.node_health.retain(|tag, _| {
            plan.preflight()
                .supported_tags()
                .iter()
                .any(|supported| supported == tag)
        });
    }

    pub fn stop(mut self) -> Result<ClientRuntime, String> {
        self.stop.store(true, Ordering::SeqCst);
        let serve_result = self
            .thread
            .take()
            .map(|thread| {
                thread
                    .join()
                    .map_err(|_| "managed mixed listener thread panicked".to_string())
                    .and_then(|result| {
                        result.map_err(|error| format!("managed mixed listener failed: {error}"))
                    })
            })
            .unwrap_or(Ok(()));
        let restore_result = self
            .system_proxy_guard
            .take()
            .map(ManagedSystemProxyGuard::restore)
            .unwrap_or(Ok(()));
        self.state.stop();

        match (serve_result, restore_result) {
            (Ok(()), Ok(())) => Ok(self.state),
            (Err(serve_error), Ok(())) => Err(serve_error),
            (Ok(()), Err(restore_error)) => Err(restore_error),
            (Err(serve_error), Err(restore_error)) => {
                Err(format!("{serve_error}; {restore_error}"))
            }
        }
    }
}

fn classify_managed_probe_error(error: &str) -> ConnectionErrorKind {
    let error = error.to_ascii_lowercase();
    if error.contains("refused") {
        ConnectionErrorKind::TcpConnectionRefused
    } else if error.contains("timeout") || error.contains("timed out") {
        if error.contains("connect") {
            ConnectionErrorKind::TcpConnectTimeout
        } else {
            ConnectionErrorKind::FirstByteTimeout
        }
    } else if error.contains("unsupported") || error.contains("outboundnotfound") {
        ConnectionErrorKind::UnsupportedOutbound
    } else if error.contains("dns") || error.contains("resolve") {
        ConnectionErrorKind::DnsResolveFailed
    } else if error.contains("mismatch") || error.contains("invalid") {
        ConnectionErrorKind::ProtocolError
    } else {
        ConnectionErrorKind::RelayIo
    }
}

impl<'a, C: SystemProxyController + ?Sized> ManagedMixedSession<'a, C> {
    pub fn start_from_subscription_config_text(
        config_text: &str,
        options: ManagedMixedOptions,
        controller: &'a C,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind(&options.listen)
            .map_err(|error| format!("listen-mixed bind failed on {}: {error}", options.listen))?;
        let listen_addr = listener
            .local_addr()
            .map_err(|error| format!("read mixed listener address: {error}"))?;
        let listen = listen_addr.to_string();
        let block_domains = options.block_domains;
        let relay_options = options.relay_options;
        let dns_options = options.dns_options;
        let mut state = ClientRuntime::default();
        let selected_outbound = match state.start(RuntimeConfig::new(
            config_text,
            options.outbound_tag.clone(),
            listen,
        )) {
            Ok(plan) => plan.selected_outbound().to_string(),
            Err(error) => return Err(format!("runtime start failed: {error:?}")),
        };
        let runtime = match mixed_runtime_from_subscription_config_text_with_dns_options(
            config_text,
            block_domains.clone(),
            relay_options,
            Some(selected_outbound),
            dns_options,
        ) {
            Ok(runtime) => runtime,
            Err(error) => {
                state.record_failure(ClientErrorKind::ConfigInvalid(error.clone()));
                return Err(error);
            }
        };
        let system_proxy_guard = if options.system_proxy {
            match apply_system_proxy_for_listener(
                controller,
                &listener,
                options.system_proxy_bypass,
            ) {
                Ok(guard) => Some(guard),
                Err(error) => {
                    state.record_failure(ClientErrorKind::SystemProxyLoop);
                    return Err(error);
                }
            }
        } else {
            None
        };

        println!("mixed inbound listening on {listen_addr}");
        Ok(Self {
            state,
            listener: Some(listener),
            listen_addr,
            runtime,
            block_domains,
            relay_options,
            dns_options,
            system_proxy_guard,
        })
    }

    pub fn status(&self) -> &RuntimeStatus {
        self.state.status()
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn selected_outbound(&self) -> Option<&str> {
        match self.state.status() {
            RuntimeStatus::Running {
                selected_outbound, ..
            } => Some(selected_outbound.as_str()),
            _ => None,
        }
    }

    pub fn serve(mut self, once: bool) -> Result<ClientRuntime, String> {
        let listener = self
            .listener
            .take()
            .expect("managed mixed listener is present");
        let serve_result = serve_mixed_listener(listener, once, &self.runtime);
        let stop_result = self.stop();

        match (serve_result, stop_result) {
            (Ok(()), Ok(state)) => Ok(state),
            (Err(serve_error), Ok(_)) => Err(format!("listen-mixed failed: {serve_error}")),
            (Ok(()), Err(restore_error)) => Err(restore_error),
            (Err(serve_error), Err(restore_error)) => Err(format!(
                "listen-mixed failed: {serve_error}; {restore_error}"
            )),
        }
    }

    pub fn spawn_background(mut self) -> Result<ManagedMixedHandle<'a, C>, String> {
        let listener = self
            .listener
            .take()
            .expect("managed mixed listener is present");
        let selected_outbound = self.selected_outbound().map(str::to_string);
        let runtime = Arc::new(RwLock::new(self.runtime));
        let thread_runtime = Arc::clone(&runtime);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            serve_mixed_listener_until(listener, thread_runtime, thread_stop)
        });

        Ok(ManagedMixedHandle {
            state: self.state,
            listen_addr: self.listen_addr,
            selected_outbound,
            runtime,
            block_domains: self.block_domains,
            relay_options: self.relay_options,
            dns_options: self.dns_options,
            node_health: HashMap::new(),
            stop,
            thread: Some(thread),
            system_proxy_guard: self.system_proxy_guard,
        })
    }

    pub fn stop(mut self) -> Result<ClientRuntime, String> {
        let restore_result = self
            .system_proxy_guard
            .take()
            .map(ManagedSystemProxyGuard::restore)
            .unwrap_or(Ok(()));
        self.state.stop();
        restore_result.map(|_| self.state)
    }
}

pub fn parse_cli_command(
    args: impl IntoIterator<Item = impl Into<String>>,
) -> Result<CliCommand, String> {
    let mut args = args.into_iter().map(Into::into);
    match args.next().as_deref() {
        None => Ok(CliCommand::Doctor {
            output: ProbeOutputFormat::Text,
        }),
        Some("doctor") => parse_doctor(args),
        Some("tun-preflight") => parse_tun_preflight(args),
        Some("version") => Ok(CliCommand::Version),
        Some("listen-mixed") => parse_listen_mixed(args),
        Some("probe-outbound") => parse_probe_outbound(args),
        Some("smoke-mixed") => parse_smoke_mixed(args),
        Some("profile-check") => parse_profile_check(args),
        Some("support-bundle") => parse_support_bundle(args),
        Some(other) => Err(format!("unknown command: {other}")),
    }
}

pub fn run(command: CliCommand) -> Result<(), String> {
    match command {
        CliCommand::Doctor { output } => {
            print_doctor(output);
            Ok(())
        }
        CliCommand::TunPreflight { config, output } => {
            let controller = NativeTunDeviceController::new();
            let mut stdout = io::stdout();
            write_tun_preflight_report_with_controller(&mut stdout, output, config, &controller)
                .map_err(|error| format!("write TUN preflight report: {error}"))
        }
        CliCommand::Version => {
            println!("keli-cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        CliCommand::ListenMixed {
            listen,
            once,
            block_domains,
            profile_config,
            outbound_tag,
            system_proxy,
            system_proxy_bypass,
            tun_device,
            first_byte_timeout,
            idle_timeout,
            dns_options,
        } => {
            let relay_options = RelayOptions {
                first_byte_timeout: Some(first_byte_timeout),
                idle_timeout: Some(idle_timeout),
            };
            let controller = NativeSystemProxyController::new();
            let tun_controller = NativeTunDeviceController::new();

            run_with_optional_tun_device(&tun_controller, tun_device, || {
                if let Some(path) = profile_config {
                    let config_text = fs::read_to_string(&path)
                        .map_err(|error| format!("read profile config {path}: {error}"))?;
                    let session = ManagedMixedSession::start_from_subscription_config_text(
                        &config_text,
                        ManagedMixedOptions {
                            listen,
                            block_domains,
                            outbound_tag,
                            relay_options,
                            system_proxy,
                            system_proxy_bypass,
                            dns_options,
                        },
                        &controller,
                    )?;
                    return session.serve(once).map(|_| ());
                }

                let runtime = mixed_runtime_from_cli(block_domains, relay_options, dns_options);
                if system_proxy {
                    listen_mixed_with_system_proxy_controller(
                        &listen,
                        once,
                        &runtime,
                        &controller,
                        system_proxy_bypass,
                    )
                } else {
                    listen_mixed(&listen, once, &runtime)
                        .map_err(|error| format!("listen-mixed failed on {listen}: {error}"))
                }
            })
        }
        CliCommand::ProbeOutbound {
            profile_config,
            outbound_tag,
            target,
            payload,
            expect,
            udp,
            output,
            first_byte_timeout,
        } => {
            let config_text = fs::read_to_string(&profile_config)
                .map_err(|error| format!("read profile config {profile_config}: {error}"))?;
            let mut stdout = io::stdout();
            probe_outbound_from_subscription_config_text_with_format(
                &config_text,
                outbound_tag,
                &target,
                payload.as_deref().unwrap_or("").as_bytes(),
                expect.as_deref().map(str::as_bytes),
                udp,
                first_byte_timeout,
                output,
                &mut stdout,
            )
        }
        CliCommand::SmokeMixed {
            profile_config,
            outbound_tag,
            target,
            payload,
            expect,
            inbound,
            output,
            first_byte_timeout,
        } => {
            let config_text = fs::read_to_string(&profile_config)
                .map_err(|error| format!("read profile config {profile_config}: {error}"))?;
            let mut stdout = io::stdout();
            write_smoke_mixed_report_from_subscription_config_text(
                &config_text,
                outbound_tag,
                &target,
                payload.as_deref().unwrap_or("").as_bytes(),
                expect.as_deref().unwrap_or("").as_bytes(),
                inbound,
                first_byte_timeout,
                output,
                &mut stdout,
            )
        }
        CliCommand::ProfileCheck {
            profile_config,
            output,
        } => {
            let config_text = fs::read_to_string(&profile_config)
                .map_err(|error| format!("read profile config {profile_config}: {error}"))?;
            let mut stdout = io::stdout();
            write_profile_check_report_from_subscription_config_text(
                &config_text,
                output,
                &mut stdout,
            )
        }
        CliCommand::SupportBundle { profile_config } => {
            let config_text = profile_config
                .as_deref()
                .map(|path| {
                    fs::read_to_string(path)
                        .map_err(|error| format!("read profile config {path}: {error}"))
                })
                .transpose()?;
            let mut stdout = io::stdout();
            write_support_bundle_report(config_text.as_deref(), &mut stdout)
        }
    }
}

pub fn print_usage(mut writer: impl Write) -> io::Result<()> {
    writeln!(
        writer,
        "usage: keli-cli [doctor|tun-preflight|version|listen-mixed|probe-outbound|smoke-mixed|profile-check|support-bundle]"
    )?;
    writeln!(writer, "       keli-cli doctor [--format text|json]")?;
    writeln!(
        writer,
        "       keli-cli tun-preflight [--interface keli-tun0] [--address 10.7.0.1/24] [--mtu 1500] [--dns-hijack] [--format text|json]"
    )?;
    writeln!(
        writer,
        "       keli-cli listen-mixed [--listen 127.0.0.1:7890] [--once] [--profile-config subscription.yaml] [--outbound-tag proxy] [--block-domain example.com] [--block-cidr 10.0.0.0/8] [--block-port 25|1000-2000] [--first-byte-timeout-ms 30000] [--idle-timeout-ms 300000] [--dns-local-policy allow-system|prevent-public-leak] [--dns-address-family dual-stack|ipv4-only|ipv6-only] [--tun] [--tun-interface keli-tun0] [--tun-address 10.7.0.1/24] [--tun-mtu 1500] [--tun-dns-hijack]"
    )?;
    writeln!(
        writer,
        "       keli-cli listen-mixed --system-proxy [--system-proxy-bypass localhost] [--system-proxy-bypass <local>]"
    )?;
    writeln!(
        writer,
        "       keli-cli probe-outbound --profile-config subscription.yaml [--outbound-tag proxy] --target example.com:443 [--payload ping] [--expect pong] [--udp] [--format text|json] [--first-byte-timeout-ms 30000]"
    )?;
    writeln!(
        writer,
        "       keli-cli smoke-mixed --profile-config subscription.yaml [--outbound-tag proxy] --target example.com:443 [--inbound socks5|http-connect] [--payload ping] [--expect pong] [--format text|json] [--first-byte-timeout-ms 30000]"
    )?;
    writeln!(
        writer,
        "       keli-cli profile-check --profile-config subscription.yaml [--format text|json]"
    )?;
    writeln!(
        writer,
        "       keli-cli support-bundle [--profile-config subscription.yaml]"
    )
}

fn parse_doctor(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut output = ProbeOutputFormat::Text;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--format" => {
                output = parse_probe_output_format(
                    args.next()
                        .ok_or_else(|| "--format requires text or json".to_string())?,
                )?;
            }
            other => return Err(format!("unknown doctor option: {other}")),
        }
    }

    Ok(CliCommand::Doctor { output })
}

fn parse_tun_preflight(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut interface_name = DEFAULT_TUN_INTERFACE_NAME.to_string();
    let mut address_cidr = DEFAULT_TUN_ADDRESS_CIDR.to_string();
    let mut mtu = DEFAULT_TUN_MTU;
    let mut dns_hijack = false;
    let mut output = ProbeOutputFormat::Text;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--interface" | "--interface-name" => {
                interface_name = args
                    .next()
                    .ok_or_else(|| "--interface requires a TUN interface name".to_string())?;
            }
            "--address" | "--address-cidr" => {
                address_cidr = args
                    .next()
                    .ok_or_else(|| "--address requires an IP CIDR".to_string())?;
            }
            "--mtu" => {
                mtu = args
                    .next()
                    .ok_or_else(|| "--mtu requires a value".to_string())?
                    .parse::<u16>()
                    .map_err(|_| "--mtu must be a non-zero u16 value".to_string())?;
            }
            "--dns-hijack" => dns_hijack = true,
            "--format" => {
                output = parse_probe_output_format(
                    args.next()
                        .ok_or_else(|| "--format requires text or json".to_string())?,
                )?;
            }
            other => return Err(format!("unknown tun-preflight option: {other}")),
        }
    }

    let config = TunDeviceConfig::new(interface_name, address_cidr, mtu)
        .map_err(|error| format!("invalid TUN preflight config: {error}"))?
        .with_dns_hijack(dns_hijack);
    Ok(CliCommand::TunPreflight { config, output })
}

fn parse_support_bundle(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut profile_config = None;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile-config" => {
                profile_config = Some(
                    args.next()
                        .ok_or_else(|| "--profile-config requires a path".to_string())?,
                );
            }
            other => return Err(format!("unknown support-bundle option: {other}")),
        }
    }

    Ok(CliCommand::SupportBundle { profile_config })
}

fn parse_listen_mixed(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut listen = "127.0.0.1:7890".to_string();
    let mut once = false;
    let mut block_domains = Vec::new();
    let mut profile_config = None;
    let mut outbound_tag = None;
    let mut system_proxy = false;
    let mut system_proxy_bypass = Vec::new();
    let mut tun_enabled = false;
    let mut tun_interface_name = DEFAULT_TUN_INTERFACE_NAME.to_string();
    let mut tun_address_cidr = DEFAULT_TUN_ADDRESS_CIDR.to_string();
    let mut tun_mtu = DEFAULT_TUN_MTU;
    let mut tun_dns_hijack = false;
    let mut first_byte_timeout = DEFAULT_FIRST_BYTE_TIMEOUT;
    let mut idle_timeout = DEFAULT_IDLE_TIMEOUT;
    let mut dns_options = MixedDnsOptions::default();
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                listen = args
                    .next()
                    .ok_or_else(|| "--listen requires an address".to_string())?;
            }
            "--once" => once = true,
            "--first-byte-timeout-ms" => {
                first_byte_timeout = parse_duration_ms(
                    args.next()
                        .ok_or_else(|| "--first-byte-timeout-ms requires a value".to_string())?,
                    "--first-byte-timeout-ms",
                )?;
            }
            "--idle-timeout-ms" => {
                idle_timeout = parse_duration_ms(
                    args.next()
                        .ok_or_else(|| "--idle-timeout-ms requires a value".to_string())?,
                    "--idle-timeout-ms",
                )?;
            }
            "--block-domain" => {
                block_domains.push(
                    args.next()
                        .ok_or_else(|| "--block-domain requires a domain".to_string())?,
                );
            }
            "--block-cidr" | "--block-ip-cidr" => {
                let cidr = parse_cli_block_cidr(
                    &args
                        .next()
                        .ok_or_else(|| "--block-cidr requires an IP CIDR".to_string())?,
                )?;
                block_domains.push(block_cidr_rule_value(&cidr));
            }
            "--block-port" => {
                let range = parse_cli_block_port(
                    &args
                        .next()
                        .ok_or_else(|| "--block-port requires a port or range".to_string())?,
                )?;
                block_domains.push(block_port_rule_value(range));
            }
            "--profile-config" => {
                profile_config = Some(
                    args.next()
                        .ok_or_else(|| "--profile-config requires a path".to_string())?,
                );
            }
            "--outbound-tag" => {
                outbound_tag = Some(
                    args.next()
                        .ok_or_else(|| "--outbound-tag requires a profile name".to_string())?,
                );
            }
            "--system-proxy" => system_proxy = true,
            "--system-proxy-bypass" => {
                system_proxy_bypass.push(
                    args.next()
                        .ok_or_else(|| "--system-proxy-bypass requires a value".to_string())?,
                );
            }
            "--tun" => tun_enabled = true,
            "--tun-interface" | "--tun-interface-name" => {
                tun_enabled = true;
                tun_interface_name = args
                    .next()
                    .ok_or_else(|| "--tun-interface requires a TUN interface name".to_string())?;
            }
            "--tun-address" | "--tun-address-cidr" => {
                tun_enabled = true;
                tun_address_cidr = args
                    .next()
                    .ok_or_else(|| "--tun-address requires an IP CIDR".to_string())?;
            }
            "--tun-mtu" => {
                tun_enabled = true;
                tun_mtu = args
                    .next()
                    .ok_or_else(|| "--tun-mtu requires a value".to_string())?
                    .parse::<u16>()
                    .map_err(|_| "--tun-mtu must be a non-zero u16 value".to_string())?;
            }
            "--tun-dns-hijack" => {
                tun_enabled = true;
                tun_dns_hijack = true;
            }
            "--dns-local-policy" => {
                dns_options.local_resolution_policy = parse_dns_local_resolution_policy(
                    &args
                        .next()
                        .ok_or_else(|| "--dns-local-policy requires a value".to_string())?,
                )?;
            }
            "--dns-address-family" => {
                dns_options.address_family_policy = parse_dns_address_family_policy(
                    &args
                        .next()
                        .ok_or_else(|| "--dns-address-family requires a value".to_string())?,
                )?;
            }
            other => return Err(format!("unknown listen-mixed option: {other}")),
        }
    }

    let tun_device = if tun_enabled {
        Some(
            TunDeviceConfig::new(tun_interface_name, tun_address_cidr, tun_mtu)
                .map_err(|error| format!("invalid listen-mixed TUN config: {error}"))?
                .with_dns_hijack(tun_dns_hijack),
        )
    } else {
        None
    };

    Ok(CliCommand::ListenMixed {
        listen,
        once,
        block_domains,
        profile_config,
        outbound_tag,
        system_proxy,
        system_proxy_bypass,
        tun_device,
        first_byte_timeout,
        idle_timeout,
        dns_options,
    })
}

fn parse_dns_local_resolution_policy(input: &str) -> Result<DnsLocalResolutionPolicy, String> {
    match input {
        "allow-system" => Ok(DnsLocalResolutionPolicy::AllowSystem),
        "prevent-public-leak" => Ok(DnsLocalResolutionPolicy::PreventPublicLeak),
        other => Err(format!(
            "invalid --dns-local-policy value: {other}; expected allow-system|prevent-public-leak"
        )),
    }
}

fn parse_dns_address_family_policy(input: &str) -> Result<DnsAddressFamilyPolicy, String> {
    match input {
        "dual-stack" => Ok(DnsAddressFamilyPolicy::DualStack),
        "ipv4-only" => Ok(DnsAddressFamilyPolicy::Ipv4Only),
        "ipv6-only" => Ok(DnsAddressFamilyPolicy::Ipv6Only),
        other => Err(format!(
            "invalid --dns-address-family value: {other}; expected dual-stack|ipv4-only|ipv6-only"
        )),
    }
}

fn parse_cli_block_cidr(input: &str) -> Result<RouteIpCidr, String> {
    let Some((network, prefix_len)) = input.split_once('/') else {
        return Err(format!(
            "invalid --block-cidr value: {input}; expected ip/prefix"
        ));
    };
    let network = network
        .parse::<IpAddr>()
        .map_err(|_| format!("invalid --block-cidr IP address: {input}"))?;
    let prefix_len = prefix_len
        .parse::<u8>()
        .map_err(|_| format!("invalid --block-cidr prefix length: {input}"))?;
    RouteIpCidr::new(network, prefix_len)
        .map_err(|error| format!("invalid --block-cidr value: {error}"))
}

fn parse_cli_block_port(input: &str) -> Result<CliPortRange, String> {
    let parse_port = |value: &str| -> Result<u16, String> {
        let port = value
            .parse::<u16>()
            .map_err(|_| format!("invalid --block-port value: {input}"))?;
        if port == 0 {
            return Err("--block-port must be between 1 and 65535".to_string());
        }
        Ok(port)
    };
    if let Some((start, end)) = input.split_once('-') {
        let start = parse_port(start)?;
        let end = parse_port(end)?;
        if start > end {
            return Err(format!("invalid --block-port range: {input}"));
        }
        return Ok(CliPortRange { start, end });
    }
    let port = parse_port(input)?;
    Ok(CliPortRange {
        start: port,
        end: port,
    })
}

fn block_cidr_rule_value(cidr: &RouteIpCidr) -> String {
    format!(
        "{BLOCK_CIDR_RULE_PREFIX}{}/{}",
        cidr.network(),
        cidr.prefix_len()
    )
}

fn block_port_rule_value(range: CliPortRange) -> String {
    format!("{BLOCK_PORT_RULE_PREFIX}{}", range.label())
}

fn parse_probe_outbound(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut profile_config = None;
    let mut outbound_tag = None;
    let mut target = None;
    let mut payload = None;
    let mut expect = None;
    let mut udp = false;
    let mut output = ProbeOutputFormat::Text;
    let mut first_byte_timeout = DEFAULT_FIRST_BYTE_TIMEOUT;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile-config" => {
                profile_config = Some(
                    args.next()
                        .ok_or_else(|| "--profile-config requires a path".to_string())?,
                );
            }
            "--outbound-tag" => {
                outbound_tag = Some(
                    args.next()
                        .ok_or_else(|| "--outbound-tag requires a profile name".to_string())?,
                );
            }
            "--target" => {
                target = Some(
                    args.next()
                        .ok_or_else(|| "--target requires host:port".to_string())?,
                );
            }
            "--payload" => {
                payload = Some(
                    args.next()
                        .ok_or_else(|| "--payload requires a value".to_string())?,
                );
            }
            "--expect" => {
                expect = Some(
                    args.next()
                        .ok_or_else(|| "--expect requires a value".to_string())?,
                );
            }
            "--udp" => udp = true,
            "--format" => {
                output = parse_probe_output_format(
                    args.next()
                        .ok_or_else(|| "--format requires text or json".to_string())?,
                )?;
            }
            "--first-byte-timeout-ms" => {
                first_byte_timeout = parse_duration_ms(
                    args.next()
                        .ok_or_else(|| "--first-byte-timeout-ms requires a value".to_string())?,
                    "--first-byte-timeout-ms",
                )?;
            }
            other => return Err(format!("unknown probe-outbound option: {other}")),
        }
    }

    Ok(CliCommand::ProbeOutbound {
        profile_config: profile_config
            .ok_or_else(|| "probe-outbound requires --profile-config".to_string())?,
        outbound_tag,
        target: target.ok_or_else(|| "probe-outbound requires --target".to_string())?,
        payload,
        expect,
        udp,
        output,
        first_byte_timeout,
    })
}

fn parse_smoke_mixed(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut profile_config = None;
    let mut outbound_tag = None;
    let mut target = None;
    let mut payload = None;
    let mut expect = None;
    let mut inbound = SmokeInboundKind::Socks5;
    let mut output = ProbeOutputFormat::Text;
    let mut first_byte_timeout = DEFAULT_FIRST_BYTE_TIMEOUT;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile-config" => {
                profile_config = Some(
                    args.next()
                        .ok_or_else(|| "--profile-config requires a path".to_string())?,
                );
            }
            "--outbound-tag" => {
                outbound_tag = Some(
                    args.next()
                        .ok_or_else(|| "--outbound-tag requires a profile name".to_string())?,
                );
            }
            "--target" => {
                target = Some(
                    args.next()
                        .ok_or_else(|| "--target requires host:port".to_string())?,
                );
            }
            "--payload" => {
                payload = Some(
                    args.next()
                        .ok_or_else(|| "--payload requires a value".to_string())?,
                );
            }
            "--expect" => {
                expect = Some(
                    args.next()
                        .ok_or_else(|| "--expect requires a value".to_string())?,
                );
            }
            "--inbound" => {
                inbound = parse_smoke_inbound_kind(
                    args.next()
                        .ok_or_else(|| "--inbound requires socks5 or http-connect".to_string())?,
                )?;
            }
            "--format" => {
                output = parse_probe_output_format(
                    args.next()
                        .ok_or_else(|| "--format requires text or json".to_string())?,
                )?;
            }
            "--first-byte-timeout-ms" => {
                first_byte_timeout = parse_duration_ms(
                    args.next()
                        .ok_or_else(|| "--first-byte-timeout-ms requires a value".to_string())?,
                    "--first-byte-timeout-ms",
                )?;
            }
            other => return Err(format!("unknown smoke-mixed option: {other}")),
        }
    }

    Ok(CliCommand::SmokeMixed {
        profile_config: profile_config
            .ok_or_else(|| "smoke-mixed requires --profile-config".to_string())?,
        outbound_tag,
        target: target.ok_or_else(|| "smoke-mixed requires --target".to_string())?,
        payload,
        expect,
        inbound,
        output,
        first_byte_timeout,
    })
}

fn parse_smoke_inbound_kind(value: String) -> Result<SmokeInboundKind, String> {
    match value.as_str() {
        "socks5" => Ok(SmokeInboundKind::Socks5),
        "http-connect" => Ok(SmokeInboundKind::HttpConnect),
        other => Err(format!("unknown smoke-mixed inbound: {other}")),
    }
}

fn parse_probe_output_format(value: String) -> Result<ProbeOutputFormat, String> {
    match value.as_str() {
        "text" => Ok(ProbeOutputFormat::Text),
        "json" => Ok(ProbeOutputFormat::Json),
        other => Err(format!("unknown probe-outbound format: {other}")),
    }
}

fn parse_profile_check(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut profile_config = None;
    let mut output = ProbeOutputFormat::Text;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile-config" => {
                profile_config = Some(
                    args.next()
                        .ok_or_else(|| "--profile-config requires a path".to_string())?,
                );
            }
            "--format" => {
                output = parse_probe_output_format(
                    args.next()
                        .ok_or_else(|| "--format requires text or json".to_string())?,
                )?;
            }
            other => return Err(format!("unknown profile-check option: {other}")),
        }
    }

    Ok(CliCommand::ProfileCheck {
        profile_config: profile_config
            .ok_or_else(|| "profile-check requires --profile-config".to_string())?,
        output,
    })
}

#[derive(Debug, Clone)]
struct DoctorReport {
    version: &'static str,
    platform: String,
    system_proxy_supported: bool,
    system_proxy_state: String,
    system_proxy_server: Option<String>,
    system_proxy_error: Option<String>,
    tun: bool,
    tun_device: TunDeviceStatus,
    secure_storage: bool,
    inbound_debug: String,
    inbound_kind: &'static str,
    inbound_listen: &'static str,
    inbound_port: u16,
    route_default_debug: String,
    route_rule_capabilities: Vec<&'static str>,
    dns_resolver: &'static str,
    dns_cache_ttl_seconds: u64,
    dns_leak_prevention_policy_available: bool,
    dns_address_family_policy_available: bool,
    dns_default_local_resolution_policy: &'static str,
    dns_default_address_family_policy: &'static str,
    supported_outbounds: Vec<&'static str>,
    supported_udp_outbounds: Vec<&'static str>,
    protocol_capabilities: &'static str,
    tun_packet_pipeline_capabilities: Vec<&'static str>,
    sample_profile_valid: bool,
    initial_phase: String,
}

fn print_doctor(output: ProbeOutputFormat) {
    let mut stdout = io::stdout();
    write_doctor_report_with_format(&mut stdout, output).expect("write doctor report");
}

pub fn write_doctor_report(writer: impl Write) -> io::Result<()> {
    write_doctor_report_with_format(writer, ProbeOutputFormat::Text)
}

pub fn write_doctor_report_with_format(
    mut writer: impl Write,
    output: ProbeOutputFormat,
) -> io::Result<()> {
    let report = collect_doctor_report();
    match output {
        ProbeOutputFormat::Text => write_doctor_text_report(&mut writer, &report),
        ProbeOutputFormat::Json => write_doctor_json_report(&mut writer, &report),
    }
}

fn collect_doctor_report() -> DoctorReport {
    let capabilities = PlatformCapabilities::detect();
    let system_proxy_status = SystemProxyStatus::detect();
    let tun_device = TunDeviceStatus::detect();
    let default_dns_options = MixedDnsOptions::default();
    let inbound = LocalInbound::Mixed {
        listen: "127.0.0.1".to_string(),
        port: 7890,
    };
    let route_engine = RouteEngine::new(RouteAction::Outbound("proxy".to_string()));
    let profile = OutboundProfile {
        tag: "trojan-ws".to_string(),
        protocol: ProxyProtocol::Trojan,
        endpoint: Endpoint::new("example.com", 443),
        transport: TransportKind::WebSocket {
            path: "/answer".to_string(),
            host: Some("example.com".to_string()),
        },
        security: SecurityKind::Tls {
            sni: Some("example.com".to_string()),
            skip_verify: false,
        },
        credential: "password".to_string(),
        cipher: None,
        flow: None,
    };

    DoctorReport {
        version: env!("CARGO_PKG_VERSION"),
        platform: format!("{:?}", capabilities.platform),
        system_proxy_supported: capabilities.system_proxy,
        system_proxy_state: system_proxy_status
            .enabled
            .map(|enabled| if enabled { "enabled" } else { "disabled" })
            .unwrap_or(if system_proxy_status.supported {
                "unknown"
            } else {
                "unsupported"
            })
            .to_string(),
        system_proxy_server: system_proxy_status.server,
        system_proxy_error: system_proxy_status.error,
        tun: capabilities.tun,
        tun_device,
        secure_storage: capabilities.secure_storage,
        inbound_debug: format!("{inbound:?}"),
        inbound_kind: "mixed",
        inbound_listen: "127.0.0.1",
        inbound_port: 7890,
        route_default_debug: format!("{route_engine:?}"),
        route_rule_capabilities: ROUTE_RULE_CAPABILITIES.split(',').collect(),
        dns_resolver: "system_resolver",
        dns_cache_ttl_seconds: 60,
        dns_leak_prevention_policy_available: true,
        dns_address_family_policy_available: true,
        dns_default_local_resolution_policy: default_dns_options.local_resolution_label(),
        dns_default_address_family_policy: default_dns_options.address_family_label(),
        supported_outbounds: SUPPORTED_OUTBOUNDS.split(',').collect(),
        supported_udp_outbounds: SUPPORTED_UDP_OUTBOUNDS.split(',').collect(),
        protocol_capabilities: SUPPORTED_PROTOCOL_CAPABILITIES,
        tun_packet_pipeline_capabilities: TUN_PACKET_PIPELINE_CAPABILITIES.split(',').collect(),
        sample_profile_valid: profile.validate().is_ok(),
        initial_phase: format!("{:?}", ConnectionPhase::Idle),
    }
}

fn write_doctor_text_report(mut writer: impl Write, report: &DoctorReport) -> io::Result<()> {
    writeln!(writer, "keli-native-client doctor")?;
    writeln!(writer, "version={}", report.version)?;
    writeln!(writer, "platform={}", report.platform)?;
    writeln!(writer, "system_proxy={}", report.system_proxy_supported)?;
    writeln!(
        writer,
        "system_proxy_state={} server={} error={}",
        report.system_proxy_state,
        report.system_proxy_server.as_deref().unwrap_or("-"),
        report.system_proxy_error.as_deref().unwrap_or("-")
    )?;
    writeln!(writer, "tun={}", report.tun)?;
    writeln!(
        writer,
        "tun_device_supported={} lifecycle_available={} state={} interface={} address={} mtu={} dns_hijack={} error={}",
        report.tun_device.supported,
        report.tun_device.lifecycle_available,
        tun_device_state(&report.tun_device),
        report.tun_device.interface_name.as_deref().unwrap_or("-"),
        report.tun_device.address_cidr.as_deref().unwrap_or("-"),
        report
            .tun_device
            .mtu
            .map(|mtu| mtu.to_string())
            .as_deref()
            .unwrap_or("-"),
        report
            .tun_device
            .dns_hijack
            .map(|dns_hijack| dns_hijack.to_string())
            .as_deref()
            .unwrap_or("-"),
        report.tun_device.error.as_deref().unwrap_or("-")
    )?;
    writeln!(writer, "secure_storage={}", report.secure_storage)?;
    writeln!(writer, "inbound={}", report.inbound_debug)?;
    writeln!(writer, "route_default={}", report.route_default_debug)?;
    writeln!(
        writer,
        "route_rule_capabilities={}",
        report.route_rule_capabilities.join(",")
    )?;
    writeln!(
        writer,
        "dns_engine={} cache_ttl={}s",
        report.dns_resolver, report.dns_cache_ttl_seconds
    )?;
    writeln!(
        writer,
        "dns_leak_prevention_policy_available={}",
        report.dns_leak_prevention_policy_available
    )?;
    writeln!(
        writer,
        "dns_address_family_policy_available={}",
        report.dns_address_family_policy_available
    )?;
    writeln!(
        writer,
        "dns_default_local_resolution_policy={}",
        report.dns_default_local_resolution_policy
    )?;
    writeln!(
        writer,
        "dns_default_address_family_policy={}",
        report.dns_default_address_family_policy
    )?;
    writeln!(
        writer,
        "supported_outbounds={}",
        report.supported_outbounds.join(",")
    )?;
    writeln!(
        writer,
        "supported_udp_outbounds={}",
        report.supported_udp_outbounds.join(",")
    )?;
    writeln!(
        writer,
        "protocol_capabilities={}",
        report.protocol_capabilities
    )?;
    writeln!(
        writer,
        "tun_packet_pipeline_capabilities={}",
        report.tun_packet_pipeline_capabilities.join(",")
    )?;
    writeln!(
        writer,
        "sample_profile_valid={}",
        report.sample_profile_valid
    )?;
    writeln!(writer, "initial_phase={}", report.initial_phase)?;
    Ok(())
}

fn write_doctor_json_report(mut writer: impl Write, report: &DoctorReport) -> io::Result<()> {
    let value = doctor_report_json_value(report);
    serde_json::to_writer_pretty(&mut writer, &value).map_err(io::Error::other)?;
    writeln!(writer)?;
    Ok(())
}

fn doctor_report_json_value(report: &DoctorReport) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "version": report.version,
        "platform": &report.platform,
        "system_proxy": {
            "supported": report.system_proxy_supported,
            "state": &report.system_proxy_state,
            "server": report.system_proxy_server.as_deref(),
            "error": report.system_proxy_error.as_deref(),
        },
        "tun": report.tun,
        "tun_device": {
            "supported": report.tun_device.supported,
            "lifecycle_available": report.tun_device.lifecycle_available,
            "running": report.tun_device.running,
            "interface_name": report.tun_device.interface_name.as_deref(),
            "address_cidr": report.tun_device.address_cidr.as_deref(),
            "mtu": report.tun_device.mtu,
            "dns_hijack": report.tun_device.dns_hijack,
            "error": report.tun_device.error.as_deref(),
        },
        "secure_storage": report.secure_storage,
        "inbound": {
            "kind": report.inbound_kind,
            "listen": report.inbound_listen,
            "port": report.inbound_port,
        },
        "route_default": &report.route_default_debug,
        "route_rule_capabilities": &report.route_rule_capabilities,
        "dns_engine": {
            "resolver": report.dns_resolver,
            "cache_ttl_seconds": report.dns_cache_ttl_seconds,
            "leak_prevention_policy_available": report.dns_leak_prevention_policy_available,
            "address_family_policy_available": report.dns_address_family_policy_available,
            "default_local_resolution_policy": report.dns_default_local_resolution_policy,
            "default_address_family_policy": report.dns_default_address_family_policy,
        },
        "supported_outbounds": &report.supported_outbounds,
        "supported_udp_outbounds": &report.supported_udp_outbounds,
        "protocol_capabilities": report.protocol_capabilities,
        "tun_packet_pipeline_capabilities": &report.tun_packet_pipeline_capabilities,
        "sample_profile_valid": report.sample_profile_valid,
        "initial_phase": &report.initial_phase,
    })
}

pub fn write_tun_preflight_report_with_controller<C: TunDeviceController + ?Sized>(
    mut writer: impl Write,
    output: ProbeOutputFormat,
    config: TunDeviceConfig,
    controller: &C,
) -> io::Result<()> {
    let preflight = TunDevicePreflight::check(controller, config);
    match output {
        ProbeOutputFormat::Text => write_tun_preflight_text_report(&mut writer, &preflight),
        ProbeOutputFormat::Json => write_tun_preflight_json_report(&mut writer, &preflight),
    }
}

fn write_tun_preflight_text_report(
    mut writer: impl Write,
    preflight: &TunDevicePreflight,
) -> io::Result<()> {
    writeln!(writer, "keli-native-client tun-preflight")?;
    writeln!(writer, "status={}", preflight.readiness.label())?;
    writeln!(writer, "ready={}", preflight.ready)?;
    writeln!(
        writer,
        "reason={}",
        preflight.reason.as_deref().unwrap_or("-")
    )?;
    writeln!(
        writer,
        "config interface={} address={} mtu={} dns_hijack={}",
        preflight.config.interface_name,
        preflight.config.address_cidr,
        preflight.config.mtu,
        preflight.config.dns_hijack
    )?;
    writeln!(
        writer,
        "device supported={} lifecycle_available={} state={} interface={} address={} mtu={} dns_hijack={} error={}",
        preflight.status.supported,
        preflight.status.lifecycle_available,
        tun_device_state(&preflight.status),
        preflight.status.interface_name.as_deref().unwrap_or("-"),
        preflight.status.address_cidr.as_deref().unwrap_or("-"),
        preflight
            .status
            .mtu
            .map(|mtu| mtu.to_string())
            .as_deref()
            .unwrap_or("-"),
        preflight
            .status
            .dns_hijack
            .map(|dns_hijack| dns_hijack.to_string())
            .as_deref()
            .unwrap_or("-"),
        preflight.status.error.as_deref().unwrap_or("-")
    )?;
    Ok(())
}

fn write_tun_preflight_json_report(
    mut writer: impl Write,
    preflight: &TunDevicePreflight,
) -> io::Result<()> {
    let value = tun_preflight_json_value(preflight);
    serde_json::to_writer_pretty(&mut writer, &value).map_err(io::Error::other)?;
    writeln!(writer)?;
    Ok(())
}

fn tun_preflight_json_value(preflight: &TunDevicePreflight) -> serde_json::Value {
    serde_json::json!({
        "status": preflight.readiness.label(),
        "ready": preflight.ready,
        "reason": preflight.reason.as_deref(),
        "config": {
            "interface_name": &preflight.config.interface_name,
            "address_cidr": &preflight.config.address_cidr,
            "mtu": preflight.config.mtu,
            "dns_hijack": preflight.config.dns_hijack,
        },
        "device": {
            "supported": preflight.status.supported,
            "lifecycle_available": preflight.status.lifecycle_available,
            "running": preflight.status.running,
            "state": tun_device_state(&preflight.status),
            "interface_name": preflight.status.interface_name.as_deref(),
            "address_cidr": preflight.status.address_cidr.as_deref(),
            "mtu": preflight.status.mtu,
            "dns_hijack": preflight.status.dns_hijack,
            "error": preflight.status.error.as_deref(),
        },
    })
}

fn collect_default_tun_preflight() -> TunDevicePreflight {
    let controller = NativeTunDeviceController::new();
    TunDevicePreflight::check(&controller, default_tun_device_config())
}

fn default_tun_device_config() -> TunDeviceConfig {
    TunDeviceConfig::new(
        DEFAULT_TUN_INTERFACE_NAME,
        DEFAULT_TUN_ADDRESS_CIDR,
        DEFAULT_TUN_MTU,
    )
    .expect("default TUN config is valid")
}

fn tun_device_state(status: &TunDeviceStatus) -> &'static str {
    if status.running {
        "running"
    } else if status.supported {
        "stopped"
    } else {
        "unsupported"
    }
}

pub fn write_support_bundle_report(
    profile_config_text: Option<&str>,
    mut writer: impl Write,
) -> Result<(), String> {
    let generated_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let value = serde_json::json!({
        "status": "ok",
        "kind": "keli_support_bundle",
        "schema_version": 1,
        "generated_at_unix_ms": generated_at_unix_ms,
        "doctor": doctor_report_json_value(&collect_doctor_report()),
        "tun_preflight": tun_preflight_json_value(&collect_default_tun_preflight()),
        "profile": support_bundle_profile_value(profile_config_text),
        "redaction": {
            "profile_config_text": "omitted",
            "credentials": "omitted",
            "server_endpoints": "omitted",
        },
    });
    serde_json::to_writer_pretty(&mut writer, &value).map_err(|error| error.to_string())?;
    writeln!(writer).map_err(|error| error.to_string())
}

fn support_bundle_profile_value(profile_config_text: Option<&str>) -> serde_json::Value {
    let Some(config_text) = profile_config_text else {
        return serde_json::Value::Null;
    };

    let source_format = detect_subscription_input_format(config_text);
    let parsed = match parse_subscription_outbound_profiles(config_text) {
        Ok(parsed) => profiles_with_registry_supported_outbounds(parsed),
        Err(error) => {
            return serde_json::json!({
                "status": "error",
                "source_format": source_format.as_str(),
                "error": format!("profile config parse failed: {error}"),
            });
        }
    };
    let supported_tags: Vec<&str> = parsed
        .profiles
        .iter()
        .map(|profile| profile.tag.as_str())
        .collect();
    let supported: Vec<_> = parsed
        .profiles
        .iter()
        .map(redacted_supported_profile_value)
        .collect();
    let udp_supported_tags = udp_supported_tags(&parsed.profiles);
    let skipped_summary = skipped_summary_reports(&parsed.skipped);
    let skipped_summary_json: Vec<_> = skipped_summary
        .iter()
        .map(|summary| {
            serde_json::json!({
                "reason": &summary.reason,
                "count": summary.names.len(),
                "names": &summary.names,
            })
        })
        .collect();
    let skipped: Vec<_> = parsed
        .skipped
        .iter()
        .map(|skipped| {
            serde_json::json!({
                "name": skipped.name.as_str(),
                "reason": skipped.reason.as_str(),
            })
        })
        .collect();
    let protocol_capabilities = protocol_capability_reports(&parsed.profiles);
    let protocol_capabilities_json: Vec<_> = protocol_capabilities
        .iter()
        .map(|capability| {
            serde_json::json!({
                "protocol": &capability.protocol,
                "tcp_relay_supported": capability.tcp_relay_supported,
                "udp_supported": capability.udp_supported,
                "tags": &capability.tags,
            })
        })
        .collect();

    serde_json::json!({
        "status": if parsed.profiles.is_empty() { "error" } else { "ok" },
        "source_format": source_format.as_str(),
        "supported_count": parsed.profiles.len(),
        "skipped_count": parsed.skipped.len(),
        "skipped_summary_count": skipped_summary.len(),
        "default_outbound": parsed.profiles.first().map(|profile| profile.tag.as_str()),
        "supported_tags": supported_tags,
        "supported": supported,
        "udp_supported_count": udp_supported_tags.len(),
        "udp_supported_tags": udp_supported_tags,
        "protocol_capability_count": protocol_capabilities.len(),
        "protocol_capabilities": protocol_capabilities_json,
        "skipped_summary": skipped_summary_json,
        "skipped": skipped,
    })
}

fn listen_mixed(listen: &str, once: bool, runtime: &MixedProxyRuntime) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    println!("mixed inbound listening on {}", listener.local_addr()?);

    serve_mixed_listener(listener, once, runtime)
}

fn serve_mixed_listener(
    listener: TcpListener,
    once: bool,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    for stream in listener.incoming() {
        let mut stream = stream?;
        if let Err(error) = handle_mixed_connection_with_routes(&mut stream, runtime) {
            eprintln!("mixed inbound failed: {error}");
        }
        if once {
            break;
        }
    }

    Ok(())
}

fn serve_mixed_listener_until(
    listener: TcpListener,
    runtime: Arc<RwLock<MixedProxyRuntime>>,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let runtime = runtime
                    .read()
                    .map_err(|_| io::Error::other("mixed runtime lock poisoned"))?
                    .clone();
                if let Err(error) = handle_mixed_connection_with_routes(&mut stream, &runtime) {
                    eprintln!("mixed inbound failed: {error}");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(MANAGED_ACCEPT_POLL_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub fn listen_mixed_with_system_proxy_controller<C: SystemProxyController + ?Sized>(
    listen: &str,
    once: bool,
    runtime: &MixedProxyRuntime,
    controller: &C,
    bypass: Vec<String>,
) -> Result<(), String> {
    let listener = TcpListener::bind(listen)
        .map_err(|error| format!("listen-mixed bind failed on {listen}: {error}"))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|error| format!("read mixed listener address: {error}"))?;
    println!("mixed inbound listening on {listen_addr}");
    let guard = apply_system_proxy_for_listener(controller, &listener, bypass)?;
    let serve_result = serve_mixed_listener(listener, once, runtime);
    let restore_result = guard.restore();

    match (serve_result, restore_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(serve_error), Ok(())) => Err(format!("listen-mixed failed: {serve_error}")),
        (Ok(()), Err(restore_error)) => Err(restore_error),
        (Err(serve_error), Err(restore_error)) => Err(format!(
            "listen-mixed failed: {serve_error}; {restore_error}"
        )),
    }
}

pub fn apply_system_proxy_for_listener<'a, C: SystemProxyController + ?Sized>(
    controller: &'a C,
    listener: &TcpListener,
    bypass: Vec<String>,
) -> Result<ManagedSystemProxyGuard<'a, C>, String> {
    let local_addr = listener
        .local_addr()
        .map_err(|error| format!("read mixed listener address: {error}"))?;
    let server = system_proxy_server_for_listener(local_addr);
    let config = SystemProxyConfig::new(server)
        .map_err(|error| format!("build system proxy config: {error}"))?
        .with_bypass(bypass);
    let snapshot = controller
        .apply(&config)
        .map_err(|error| format!("apply system proxy: {error}"))?;
    Ok(ManagedSystemProxyGuard {
        controller,
        snapshot: Some(snapshot),
        config,
    })
}

fn system_proxy_server_for_listener(addr: SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port()).to_string()
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port()).to_string()
        }
        _ => addr.to_string(),
    }
}

pub fn handle_socks5_connection(stream: &mut TcpStream) -> io::Result<()> {
    handle_socks5_connection_with_routes(stream, &MixedProxyRuntime::default())
}

pub fn handle_socks5_connection_with_routes(
    stream: &mut TcpStream,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    let handshake = parse_socks5_handshake(stream).map_err(to_io_error)?;
    if !handshake.methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xff])?;
        return Ok(());
    }

    stream.write_all(&socks5_no_auth_response())?;
    let request = parse_socks5_request(stream).map_err(to_io_error)?;
    println!(
        "socks5 request command={:?} address={:?} port={}",
        request.command, request.address, request.port
    );

    match request.command {
        Socks5Command::Connect => {}
        Socks5Command::UdpAssociate => {
            return handle_socks5_udp_associate(stream, runtime);
        }
        Socks5Command::Bind => {
            stream.write_all(&socks5_reply(Socks5ReplyCode::CommandNotSupported))?;
            return Ok(());
        }
    }

    let target = OutboundTarget::from_socks5_request(&request);
    let mut report = ConnectionReport::new("socks5", target.clone(), RouteAction::Direct);
    let remote = match connect_by_route(&target, runtime) {
        Ok(RouteConnect::Direct {
            stream: remote,
            route_action,
            connect_duration,
        }) => {
            report.route_action = route_action;
            report.record_connect_duration(connect_duration);
            remote
        }
        Ok(RouteConnect::Blocked { route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::RouteBlocked);
            println!("{}", report.summary_line());
            stream.write_all(&socks5_reply(Socks5ReplyCode::ConnectionNotAllowed))?;
            return Ok(());
        }
        Ok(RouteConnect::UnsupportedOutbound { tag, route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::UnsupportedOutbound);
            println!("{}", report.summary_line());
            stream.write_all(&socks5_reply(Socks5ReplyCode::CommandNotSupported))?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound route is not implemented: {tag}"),
            ));
        }
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            println!("{}", report.summary_line());
            stream.write_all(&socks5_reply(Socks5ReplyCode::HostUnreachable))?;
            return Err(error);
        }
    };

    stream.write_all(&socks5_reply(Socks5ReplyCode::Succeeded))?;
    let client = stream.try_clone()?;
    relay_with_report(client, remote, &mut report, runtime.relay_options)
}

fn handle_socks5_udp_associate(
    stream: &mut TcpStream,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    let relay = UdpSocket::bind("127.0.0.1:0")?;
    let first_byte_timeout = runtime
        .relay_options
        .first_byte_timeout
        .unwrap_or(DEFAULT_FIRST_BYTE_TIMEOUT);
    let idle_timeout = runtime
        .relay_options
        .idle_timeout
        .unwrap_or(DEFAULT_IDLE_TIMEOUT);
    relay.set_read_timeout(Some(UDP_RELAY_POLL_INTERVAL))?;
    let outbound = UdpSocket::bind("0.0.0.0:0")?;
    outbound.set_read_timeout(Some(first_byte_timeout))?;

    let bound_addr = relay.local_addr()?;
    stream.write_all(&socks5_success_reply_for_bound_addr(bound_addr))?;
    stream.set_nonblocking(true)?;
    let session_result = relay_socks5_udp_session(
        stream,
        runtime,
        &relay,
        &outbound,
        first_byte_timeout,
        idle_timeout,
    );
    stream.set_nonblocking(false).ok();
    session_result
}

fn relay_socks5_udp_session(
    stream: &TcpStream,
    runtime: &MixedProxyRuntime,
    relay: &UdpSocket,
    outbound: &UdpSocket,
    first_byte_timeout: Duration,
    idle_timeout: Duration,
) -> io::Result<()> {
    let mut request_buffer = [0; 65_535];
    let started = Instant::now();
    let mut last_activity = started;
    let mut received_datagram = false;

    loop {
        if socks5_udp_control_is_closed(stream)? {
            return Ok(());
        }

        match relay.recv_from(&mut request_buffer) {
            Ok((request_size, client_udp_addr)) => {
                received_datagram = true;
                relay_socks5_udp_datagram(
                    runtime,
                    relay,
                    outbound,
                    &request_buffer[..request_size],
                    client_udp_addr,
                    first_byte_timeout,
                )?;
                last_activity = Instant::now();
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                if socks5_udp_control_is_closed(stream)? {
                    return Ok(());
                }
                let timeout = if received_datagram {
                    idle_timeout
                } else {
                    first_byte_timeout
                };
                let reference = if received_datagram {
                    last_activity
                } else {
                    started
                };
                if reference.elapsed() >= timeout {
                    return Ok(());
                }
            }
            Err(error) => return Err(error),
        }
    }
}

fn relay_socks5_udp_datagram(
    runtime: &MixedProxyRuntime,
    relay: &UdpSocket,
    outbound: &UdpSocket,
    request: &[u8],
    client_udp_addr: SocketAddr,
    response_timeout: Duration,
) -> io::Result<()> {
    let datagram = parse_socks5_udp_datagram(request).map_err(to_io_error)?;
    let target = outbound_target_from_socks5_udp(&datagram.address, datagram.port);
    let mut report = ConnectionReport::new("socks5-udp", target.clone(), RouteAction::Direct);

    match runtime
        .routes
        .decide_destination(&target.route_destination())
        .action
    {
        RouteAction::Direct => {}
        RouteAction::Block => {
            report.route_action = RouteAction::Block;
            report.record_error(ConnectionErrorKind::RouteBlocked);
            println!("{}", report.summary_line());
            return Ok(());
        }
        RouteAction::Outbound(tag) => {
            report.route_action = RouteAction::Outbound(tag.clone());
            let started = Instant::now();
            let response = match runtime.outbounds.relay_udp_datagram(
                &tag,
                &target,
                &datagram.payload,
                response_timeout,
            ) {
                Ok(response) => response,
                Err(error) => {
                    report.record_error(ConnectionErrorKind::from_io(&error));
                    println!("{}", report.summary_line());
                    return Ok(());
                }
            };
            report.upload_bytes = datagram.payload.len() as u64;
            report.record_first_byte_duration(started.elapsed());
            report.download_bytes = response.payload.len() as u64;
            send_socks5_udp_response(relay, client_udp_addr, response.source, &response.payload)?;
            println!("{}", report.summary_line());
            return Ok(());
        }
        RouteAction::HijackDns => {
            report.route_action = RouteAction::HijackDns;
            let started = Instant::now();
            let mut dns = runtime.dns_options.engine();
            let response = match build_hijacked_dns_response(&datagram.payload, &mut dns) {
                Ok(response) => response,
                Err(error) => {
                    report.record_error_detail(
                        ConnectionErrorKind::from_io(&error),
                        error.to_string(),
                    );
                    println!("{}", report.summary_line());
                    return Ok(());
                }
            };
            report.upload_bytes = datagram.payload.len() as u64;
            report.record_first_byte_duration(started.elapsed());
            report.download_bytes = response.len() as u64;
            send_socks5_udp_response(
                relay,
                client_udp_addr,
                socks5_udp_response_source_for_target(&target),
                &response,
            )?;
            println!("{}", report.summary_line());
            return Ok(());
        }
    }

    let remote_addr = match resolve_udp_socket_addr(&target) {
        Ok(remote_addr) => remote_addr,
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            println!("{}", report.summary_line());
            return Ok(());
        }
    };
    let started = Instant::now();
    if let Err(error) = outbound.send_to(&datagram.payload, remote_addr) {
        report.record_error(ConnectionErrorKind::from_io(&error));
        println!("{}", report.summary_line());
        return Ok(());
    }
    report.upload_bytes = datagram.payload.len() as u64;

    let mut response_buffer = [0; 65_535];
    let (response_size, response_from) = match outbound.recv_from(&mut response_buffer) {
        Ok(response) => response,
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            println!("{}", report.summary_line());
            return Ok(());
        }
    };
    report.record_first_byte_duration(started.elapsed());
    report.download_bytes = response_size as u64;

    send_socks5_udp_response(
        relay,
        client_udp_addr,
        response_from,
        &response_buffer[..response_size],
    )?;
    println!("{}", report.summary_line());
    Ok(())
}

fn build_hijacked_dns_response(
    payload: &[u8],
    dns: &mut DnsEngine<SystemDnsResolver>,
) -> io::Result<Vec<u8>> {
    let question = parse_dns_query(payload)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if matches!(question.question_type, DnsQuestionType::Unsupported(_)) {
        return Ok(build_dns_error_response(&question, 4));
    }
    match dns.resolve(&question.name, 0) {
        Ok(addresses) => {
            let ips = addresses
                .into_iter()
                .map(|address| address.ip)
                .collect::<Vec<_>>();
            Ok(build_dns_response(&question, &ips, 60))
        }
        Err(DnsError::LocalResolutionBlocked { .. })
        | Err(DnsError::AddressFamilyFiltered { .. })
        | Err(DnsError::NoRecords(_)) => Ok(build_dns_error_response(&question, 3)),
        Err(error) => Err(io::Error::new(io::ErrorKind::NotFound, error)),
    }
}

fn socks5_udp_response_source_for_target(target: &OutboundTarget) -> SocketAddr {
    target.host.parse::<IpAddr>().map_or_else(
        |_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), target.port),
        |ip| SocketAddr::new(ip, target.port),
    )
}

fn send_socks5_udp_response(
    relay: &UdpSocket,
    client_udp_addr: SocketAddr,
    response_from: SocketAddr,
    payload: &[u8],
) -> io::Result<()> {
    let response_address = socks5_address_from_ip(response_from.ip());
    let response = encode_socks5_udp_datagram(&response_address, response_from.port(), payload)
        .map_err(to_io_error)?;
    relay.send_to(&response, client_udp_addr)?;
    Ok(())
}

fn socks5_udp_control_is_closed(stream: &TcpStream) -> io::Result<bool> {
    let mut buffer = [0; 1];
    match stream.peek(&mut buffer) {
        Ok(0) => Ok(true),
        Ok(_) => Ok(false),
        Err(error)
            if error.kind() == io::ErrorKind::WouldBlock
                || error.kind() == io::ErrorKind::TimedOut =>
        {
            Ok(false)
        }
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => Ok(true),
        Err(error) => Err(error),
    }
}

fn socks5_success_reply_for_bound_addr(bound_addr: SocketAddr) -> Vec<u8> {
    let mut reply = Vec::with_capacity(22);
    reply.extend_from_slice(&[0x05, 0x00, 0x00]);
    match bound_addr.ip() {
        IpAddr::V4(ip) => {
            reply.push(0x01);
            reply.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            reply.push(0x04);
            reply.extend_from_slice(&ip.octets());
        }
    }
    reply.extend_from_slice(&bound_addr.port().to_be_bytes());
    reply
}

fn outbound_target_from_socks5_udp(address: &Socks5Address, port: u16) -> OutboundTarget {
    let host = match address {
        Socks5Address::Ipv4(ip) => ip.to_string(),
        Socks5Address::Domain(domain) => domain.clone(),
        Socks5Address::Ipv6(ip) => ip.to_string(),
    };
    OutboundTarget::new(host, port)
}

fn resolve_udp_socket_addr(target: &OutboundTarget) -> io::Result<SocketAddr> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, target.port));
    }

    (target.host.as_str(), target.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no address resolved for {}:{}", target.host, target.port),
            )
        })
}

fn socks5_address_from_ip(ip: IpAddr) -> Socks5Address {
    match ip {
        IpAddr::V4(ip) => Socks5Address::Ipv4(ip),
        IpAddr::V6(ip) => Socks5Address::Ipv6(ip),
    }
}

pub fn handle_mixed_connection(stream: &mut TcpStream) -> io::Result<()> {
    handle_mixed_connection_with_routes(stream, &MixedProxyRuntime::default())
}

pub fn handle_mixed_connection_with_routes(
    stream: &mut TcpStream,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    let mut first = [0; 1];
    stream.peek(&mut first)?;
    match first[0] {
        0x05 => handle_socks5_connection_with_routes(stream, runtime),
        b'C' | b'c' => handle_http_connect_connection(stream, runtime),
        b'D' | b'd' | b'G' | b'g' | b'H' | b'h' | b'O' | b'o' | b'P' | b'p' | b'T' | b't' => {
            handle_http_proxy_connection(stream, runtime)
        }
        _ => {
            stream.write_all(http_connect_bad_request_response())?;
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mixed inbound received an unsupported protocol",
            ))
        }
    }
}

fn handle_http_connect_connection(
    stream: &mut TcpStream,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    let request = match parse_http_connect_request(stream) {
        Ok(remote) => remote,
        Err(error) => {
            stream.write_all(http_connect_bad_request_response())?;
            return Err(to_io_error(error));
        }
    };
    println!(
        "http connect request address={} port={}",
        request.host, request.port
    );

    let target = OutboundTarget::new(request.host, request.port);
    let mut report = ConnectionReport::new("http-connect", target.clone(), RouteAction::Direct);
    let remote = match connect_by_route(&target, runtime) {
        Ok(RouteConnect::Direct {
            stream: remote,
            route_action,
            connect_duration,
        }) => {
            report.route_action = route_action;
            report.record_connect_duration(connect_duration);
            remote
        }
        Ok(RouteConnect::Blocked { route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::RouteBlocked);
            println!("{}", report.summary_line());
            stream.write_all(http_forbidden_response())?;
            return Ok(());
        }
        Ok(RouteConnect::UnsupportedOutbound { tag, route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::UnsupportedOutbound);
            println!("{}", report.summary_line());
            stream.write_all(http_connect_bad_request_response())?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound route is not implemented: {tag}"),
            ));
        }
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            println!("{}", report.summary_line());
            stream.write_all(http_connect_bad_request_response())?;
            return Err(error);
        }
    };

    stream.write_all(http_connect_success_response())?;
    let client = stream.try_clone()?;
    relay_with_report(client, remote, &mut report, runtime.relay_options)
}

fn handle_http_proxy_connection(
    stream: &mut TcpStream,
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    let request = match parse_http_proxy_request(stream) {
        Ok(request) => request,
        Err(error) => {
            stream.write_all(http_proxy_bad_request_response())?;
            return Err(to_io_error(error));
        }
    };
    println!(
        "http proxy request method={} address={} port={} path={}",
        request.method, request.host, request.port, request.path_and_query
    );

    let target = OutboundTarget::new(request.host, request.port);
    let mut report = ConnectionReport::new("http-proxy", target.clone(), RouteAction::Direct);
    let mut remote = match connect_by_route(&target, runtime) {
        Ok(RouteConnect::Direct {
            stream: remote,
            route_action,
            connect_duration,
        }) => {
            report.route_action = route_action;
            report.record_connect_duration(connect_duration);
            remote
        }
        Ok(RouteConnect::Blocked { route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::RouteBlocked);
            println!("{}", report.summary_line());
            stream.write_all(http_forbidden_response())?;
            return Ok(());
        }
        Ok(RouteConnect::UnsupportedOutbound { tag, route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::UnsupportedOutbound);
            println!("{}", report.summary_line());
            stream.write_all(http_proxy_bad_request_response())?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound route is not implemented: {tag}"),
            ));
        }
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            println!("{}", report.summary_line());
            stream.write_all(http_proxy_bad_request_response())?;
            return Err(error);
        }
    };

    remote.write_all(&request.rewritten_header)?;
    let client = stream.try_clone()?;
    relay_with_report(client, remote, &mut report, runtime.relay_options)
}

enum RouteConnect {
    Direct {
        stream: OutboundConnection,
        route_action: RouteAction,
        connect_duration: Duration,
    },
    Blocked {
        route_action: RouteAction,
    },
    UnsupportedOutbound {
        tag: String,
        route_action: RouteAction,
    },
}

fn connect_by_route(
    target: &OutboundTarget,
    runtime: &MixedProxyRuntime,
) -> io::Result<RouteConnect> {
    let decision = runtime
        .routes
        .decide_destination(&target.route_destination());
    match decision.action {
        RouteAction::Direct => {
            let started = Instant::now();
            let mut dns = runtime.dns_options.engine();
            DirectTcpConnector::connect_with_dns(target, Duration::from_secs(10), &mut dns).map(
                |stream| RouteConnect::Direct {
                    stream: OutboundConnection::Tcp(stream),
                    route_action: RouteAction::Direct,
                    connect_duration: started.elapsed(),
                },
            )
        }
        RouteAction::Block => Ok(RouteConnect::Blocked {
            route_action: RouteAction::Block,
        }),
        RouteAction::Outbound(tag) => {
            let started = Instant::now();
            let mut dns = runtime.dns_options.engine();
            match runtime.outbounds.connect_with_dns(
                &tag,
                target,
                Duration::from_secs(10),
                &mut dns,
            ) {
                Ok(stream) => Ok(RouteConnect::Direct {
                    stream,
                    route_action: RouteAction::Outbound(tag),
                    connect_duration: started.elapsed(),
                }),
                Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                    Ok(RouteConnect::UnsupportedOutbound {
                        route_action: RouteAction::Outbound(tag.clone()),
                        tag,
                    })
                }
                Err(error) => Err(error),
            }
        }
        RouteAction::HijackDns => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "hijack-dns route action is not valid for TCP proxy relay",
        )),
    }
}

pub fn mixed_runtime_from_mihomo_config_text(
    config_text: &str,
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    outbound_tag: Option<String>,
) -> Result<MixedProxyRuntime, String> {
    mixed_runtime_from_mihomo_config_text_with_dns_options(
        config_text,
        block_domains,
        relay_options,
        outbound_tag,
        MixedDnsOptions::default(),
    )
}

pub fn mixed_runtime_from_mihomo_config_text_with_dns_options(
    config_text: &str,
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    outbound_tag: Option<String>,
    dns_options: MixedDnsOptions,
) -> Result<MixedProxyRuntime, String> {
    let parsed = parse_mihomo_outbound_profiles(config_text)
        .map_err(|error| format!("profile config parse failed: {error}"))?;
    mixed_runtime_from_parsed_profiles(
        parsed,
        block_domains,
        relay_options,
        outbound_tag,
        dns_options,
    )
}

pub fn mixed_runtime_from_subscription_config_text(
    config_text: &str,
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    outbound_tag: Option<String>,
) -> Result<MixedProxyRuntime, String> {
    mixed_runtime_from_subscription_config_text_with_dns_options(
        config_text,
        block_domains,
        relay_options,
        outbound_tag,
        MixedDnsOptions::default(),
    )
}

pub fn mixed_runtime_from_subscription_config_text_with_dns_options(
    config_text: &str,
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    outbound_tag: Option<String>,
    dns_options: MixedDnsOptions,
) -> Result<MixedProxyRuntime, String> {
    let parsed = parse_subscription_outbound_profiles(config_text)
        .map_err(|error| format!("profile config parse failed: {error}"))?;
    mixed_runtime_from_parsed_profiles(
        parsed,
        block_domains,
        relay_options,
        outbound_tag,
        dns_options,
    )
}

pub fn probe_outbound_from_subscription_config_text(
    config_text: &str,
    outbound_tag: Option<String>,
    target: &str,
    payload: &[u8],
    expect: Option<&[u8]>,
    udp: bool,
    first_byte_timeout: Duration,
    mut writer: impl Write,
) -> Result<(), String> {
    probe_outbound_from_subscription_config_text_with_format(
        config_text,
        outbound_tag,
        target,
        payload,
        expect,
        udp,
        first_byte_timeout,
        ProbeOutputFormat::Text,
        &mut writer,
    )
}

pub fn smoke_mixed_socks5_connect_from_subscription_config_text(
    config_text: &str,
    outbound_tag: Option<String>,
    target: &str,
    payload: &[u8],
    expect: &[u8],
    first_byte_timeout: Duration,
) -> Result<ConnectionReport, String> {
    smoke_mixed_connect_from_subscription_config_text(
        config_text,
        outbound_tag,
        target,
        payload,
        expect,
        SmokeInboundKind::Socks5,
        first_byte_timeout,
    )
}

pub fn smoke_mixed_http_connect_from_subscription_config_text(
    config_text: &str,
    outbound_tag: Option<String>,
    target: &str,
    payload: &[u8],
    expect: &[u8],
    first_byte_timeout: Duration,
) -> Result<ConnectionReport, String> {
    smoke_mixed_connect_from_subscription_config_text(
        config_text,
        outbound_tag,
        target,
        payload,
        expect,
        SmokeInboundKind::HttpConnect,
        first_byte_timeout,
    )
}

pub fn smoke_mixed_connect_from_subscription_config_text(
    config_text: &str,
    outbound_tag: Option<String>,
    target: &str,
    payload: &[u8],
    expect: &[u8],
    inbound: SmokeInboundKind,
    first_byte_timeout: Duration,
) -> Result<ConnectionReport, String> {
    let target = parse_probe_target(target)?;
    let plan = build_connection_plan(config_text, outbound_tag.as_deref(), "127.0.0.1:0")
        .map_err(|error| format!("connection plan failed: {error:?}"))?;
    let selected_outbound = plan.selected_outbound().to_string();
    let relay_options = RelayOptions {
        first_byte_timeout: Some(first_byte_timeout),
        idle_timeout: Some(first_byte_timeout),
    };
    let runtime = mixed_runtime_from_subscription_config_text(
        config_text,
        Vec::new(),
        relay_options,
        Some(selected_outbound.clone()),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("bind smoke listener: {error}"))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|error| format!("read smoke listener addr: {error}"))?;
    let server = thread::spawn(move || -> io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        handle_mixed_connection_with_routes(&mut stream, &runtime)
    });

    let mut client = TcpStream::connect(listen_addr)
        .map_err(|error| format!("connect smoke listener {listen_addr}: {error}"))?;
    client
        .set_read_timeout(Some(first_byte_timeout))
        .map_err(|error| format!("set smoke read timeout: {error}"))?;
    client
        .set_write_timeout(Some(first_byte_timeout))
        .map_err(|error| format!("set smoke write timeout: {error}"))?;

    write_smoke_connect(&mut client, &target, inbound)?;
    let started = Instant::now();
    if !payload.is_empty() {
        client
            .write_all(payload)
            .map_err(|error| format!("write smoke payload: {error}"))?;
    }
    if !expect.is_empty() {
        let mut received = vec![0; expect.len()];
        client
            .read_exact(&mut received)
            .map_err(|error| format!("read smoke response: {error}"))?;
        if received != expect {
            client.shutdown(Shutdown::Both).ok();
            return Err(format!(
                "smoke response mismatch: expected {:?}, got {:?}",
                String::from_utf8_lossy(expect),
                String::from_utf8_lossy(&received)
            ));
        }
    }
    client.shutdown(Shutdown::Both).ok();
    server
        .join()
        .map_err(|_| "mixed smoke worker panicked".to_string())?
        .map_err(|error| format!("mixed smoke relay failed: {error}"))?;

    let mut report = ConnectionReport::new(
        inbound.label(),
        target,
        RouteAction::Outbound(selected_outbound),
    );
    if !expect.is_empty() {
        report.record_first_byte_duration(started.elapsed());
    }
    report.upload_bytes = payload.len() as u64;
    report.download_bytes = expect.len() as u64;
    Ok(report)
}

pub fn write_smoke_mixed_report_from_subscription_config_text(
    config_text: &str,
    outbound_tag: Option<String>,
    target: &str,
    payload: &[u8],
    expect: &[u8],
    inbound: SmokeInboundKind,
    first_byte_timeout: Duration,
    output: ProbeOutputFormat,
    mut writer: impl Write,
) -> Result<(), String> {
    let report = smoke_mixed_connect_from_subscription_config_text(
        config_text,
        outbound_tag,
        target,
        payload,
        expect,
        inbound,
        first_byte_timeout,
    )?;
    write_smoke_result(&mut writer, "ok", &report, output)
}

pub fn write_smoke_mixed_socks5_report_from_subscription_config_text(
    config_text: &str,
    outbound_tag: Option<String>,
    target: &str,
    payload: &[u8],
    expect: &[u8],
    first_byte_timeout: Duration,
    output: ProbeOutputFormat,
    mut writer: impl Write,
) -> Result<(), String> {
    let report = smoke_mixed_connect_from_subscription_config_text(
        config_text,
        outbound_tag,
        target,
        payload,
        expect,
        SmokeInboundKind::Socks5,
        first_byte_timeout,
    )?;
    write_smoke_result(&mut writer, "ok", &report, output)
}

pub fn probe_outbound_from_subscription_config_text_with_format(
    config_text: &str,
    outbound_tag: Option<String>,
    target: &str,
    payload: &[u8],
    expect: Option<&[u8]>,
    udp: bool,
    first_byte_timeout: Duration,
    output: ProbeOutputFormat,
    mut writer: impl Write,
) -> Result<(), String> {
    let relay_options = RelayOptions {
        first_byte_timeout: Some(first_byte_timeout),
        idle_timeout: Some(first_byte_timeout),
    };
    let runtime = mixed_runtime_from_subscription_config_text(
        config_text,
        Vec::new(),
        relay_options,
        outbound_tag,
    )?;
    let target = parse_probe_target(target)?;
    if udp {
        return probe_udp_outbound(
            &runtime,
            target,
            payload,
            expect,
            first_byte_timeout,
            output,
            writer,
        );
    }
    let mut report = ConnectionReport::new("probe-outbound", target.clone(), RouteAction::Direct);
    let mut remote = match connect_by_route(&target, &runtime) {
        Ok(RouteConnect::Direct {
            stream,
            route_action,
            connect_duration,
        }) => {
            report.route_action = route_action;
            report.record_connect_duration(connect_duration);
            stream
        }
        Ok(RouteConnect::Blocked { route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::RouteBlocked);
            write_probe_result(&mut writer, "error", &report, output)?;
            return Err("probe route blocked".to_string());
        }
        Ok(RouteConnect::UnsupportedOutbound { tag, route_action }) => {
            report.route_action = route_action;
            let detail = format!("outbound route is not implemented: {tag}");
            report.record_error_detail(ConnectionErrorKind::UnsupportedOutbound, detail.clone());
            write_probe_result(&mut writer, "error", &report, output)?;
            return Err(detail);
        }
        Err(error) => {
            report.record_error_detail(ConnectionErrorKind::from_io(&error), error.to_string());
            write_probe_result(&mut writer, "error", &report, output)?;
            return Err(format!("probe connect failed: {error}"));
        }
    };

    if !payload.is_empty() {
        remote
            .write_all(payload)
            .map_err(|error| probe_io_error(error, &mut report, &mut writer, output))?;
        report.upload_bytes = payload.len() as u64;
    }

    if let Some(expected) = expect {
        let started = Instant::now();
        let mut received = vec![0; expected.len()];
        remote
            .read_exact(&mut received)
            .map_err(|error| probe_io_error(error, &mut report, &mut writer, output))?;
        report.record_first_byte_duration(started.elapsed());
        report.download_bytes = received.len() as u64;
        if received != expected {
            report.record_error(ConnectionErrorKind::ProtocolError);
            write_probe_result(&mut writer, "error", &report, output)?;
            return Err(format!(
                "probe response mismatch: expected {:?}, got {:?}",
                String::from_utf8_lossy(expected),
                String::from_utf8_lossy(&received)
            ));
        }
    }

    write_probe_result(&mut writer, "ok", &report, output)
}

fn write_smoke_connect(
    client: &mut TcpStream,
    target: &OutboundTarget,
    inbound: SmokeInboundKind,
) -> Result<(), String> {
    match inbound {
        SmokeInboundKind::Socks5 => write_socks5_smoke_connect(client, target),
        SmokeInboundKind::HttpConnect => write_http_connect_smoke_connect(client, target),
    }
}

fn write_socks5_smoke_connect(
    client: &mut TcpStream,
    target: &OutboundTarget,
) -> Result<(), String> {
    client
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|error| format!("write smoke socks5 hello: {error}"))?;
    let mut hello = [0; 2];
    client
        .read_exact(&mut hello)
        .map_err(|error| format!("read smoke socks5 hello response: {error}"))?;
    if hello != [0x05, 0x00] {
        return Err(format!("unexpected smoke socks5 hello response: {hello:?}"));
    }

    let mut request = vec![0x05, 0x01, 0x00];
    match target.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let host = target.host.as_bytes();
            if host.len() > u8::MAX as usize {
                return Err(format!("smoke target host is too long: {}", target.host));
            }
            request.push(0x03);
            request.push(host.len() as u8);
            request.extend_from_slice(host);
        }
    }
    request.extend_from_slice(&target.port.to_be_bytes());
    client
        .write_all(&request)
        .map_err(|error| format!("write smoke socks5 connect: {error}"))?;
    let mut response = [0; 10];
    client
        .read_exact(&mut response)
        .map_err(|error| format!("read smoke socks5 connect response: {error}"))?;
    if response[1] != 0x00 {
        return Err(format!("smoke socks5 connect failed: {response:?}"));
    }
    Ok(())
}

fn write_http_connect_smoke_connect(
    client: &mut TcpStream,
    target: &OutboundTarget,
) -> Result<(), String> {
    let authority = format!("{}:{}", target.host, target.port);
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    client
        .write_all(request.as_bytes())
        .map_err(|error| format!("write smoke http connect: {error}"))?;

    let mut response = Vec::new();
    let mut byte = [0; 1];
    while response.len() < 1024 {
        client
            .read_exact(&mut byte)
            .map_err(|error| format!("read smoke http connect response: {error}"))?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !response.ends_with(b"\r\n\r\n") {
        return Err("smoke http connect response header is too large".to_string());
    }
    if !response.starts_with(b"HTTP/1.1 200 ") {
        return Err(format!(
            "smoke http connect failed: {}",
            String::from_utf8_lossy(&response)
        ));
    }
    Ok(())
}

fn parse_probe_target(target: &str) -> Result<OutboundTarget, String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("probe target is empty".to_string());
    }
    if let Some(rest) = target.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| format!("invalid probe target: {target}"))?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| format!("invalid probe target: {target}"))?
            .parse::<u16>()
            .map_err(|_| format!("invalid probe target port: {target}"))?;
        return Ok(OutboundTarget::new(host, port));
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| format!("probe target requires host:port: {target}"))?;
    if host.is_empty() {
        return Err(format!("probe target host is empty: {target}"));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("invalid probe target port: {target}"))?;
    Ok(OutboundTarget::new(host, port))
}

fn probe_udp_outbound(
    runtime: &MixedProxyRuntime,
    target: OutboundTarget,
    payload: &[u8],
    expect: Option<&[u8]>,
    timeout: Duration,
    output: ProbeOutputFormat,
    mut writer: impl Write,
) -> Result<(), String> {
    let mut report = ConnectionReport::new("probe-udp", target.clone(), RouteAction::Direct);
    let started = Instant::now();
    let response = match runtime
        .routes
        .decide_destination(&target.route_destination())
        .action
    {
        RouteAction::Direct => {
            let mut dns = runtime.dns_options.engine();
            DirectUdpConnector::relay_datagram_with_dns(&target, payload, timeout, &mut dns)
        }
        RouteAction::Block => {
            report.route_action = RouteAction::Block;
            report.record_error(ConnectionErrorKind::RouteBlocked);
            write_probe_result(&mut writer, "error", &report, output)?;
            return Err("probe route blocked".to_string());
        }
        RouteAction::Outbound(tag) => {
            report.route_action = RouteAction::Outbound(tag.clone());
            let mut dns = runtime.dns_options.engine();
            runtime
                .outbounds
                .relay_udp_datagram_with_dns(&tag, &target, payload, timeout, &mut dns)
        }
        RouteAction::HijackDns => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "hijack-dns route action is not valid for UDP probe",
        )),
    };

    let response = match response {
        Ok(response) => response,
        Err(error) => {
            report.record_error_detail(ConnectionErrorKind::from_io(&error), error.to_string());
            write_probe_result(&mut writer, "error", &report, output)?;
            return Err(format!("probe UDP relay failed: {error}"));
        }
    };
    report.record_first_byte_duration(started.elapsed());
    report.upload_bytes = payload.len() as u64;
    report.download_bytes = response.payload.len() as u64;

    if let Some(expected) = expect {
        if response.payload != expected {
            report.record_error(ConnectionErrorKind::ProtocolError);
            write_probe_result(&mut writer, "error", &report, output)?;
            return Err(format!(
                "probe UDP response mismatch: expected {:?}, got {:?}",
                String::from_utf8_lossy(expected),
                String::from_utf8_lossy(&response.payload)
            ));
        }
    }

    write_probe_result(&mut writer, "ok", &report, output)
}

fn probe_io_error(
    error: io::Error,
    report: &mut ConnectionReport,
    writer: &mut impl Write,
    output: ProbeOutputFormat,
) -> String {
    report.record_error_detail(ConnectionErrorKind::from_io(&error), error.to_string());
    let _ = write_probe_result(writer, "error", report, output);
    format!("probe relay failed: {error}")
}

fn write_probe_result(
    writer: &mut impl Write,
    status: &str,
    report: &ConnectionReport,
    output: ProbeOutputFormat,
) -> Result<(), String> {
    match output {
        ProbeOutputFormat::Text => {
            writeln!(writer, "probe status={status} {}", report.summary_line())
                .map_err(|error| error.to_string())
        }
        ProbeOutputFormat::Json => {
            let (route, outbound_tag) = probe_route_fields(&report.route_action);
            let value = serde_json::json!({
                "status": status,
                "inbound": report.inbound.as_str(),
                "target": format!("{}:{}", report.target.host, report.target.port),
                "target_host": report.target.host.as_str(),
                "target_port": report.target.port,
                "route": route,
                "outbound_tag": outbound_tag,
                "connect_ms": report.connect_ms,
                "first_byte_ms": report.first_byte_ms,
                "upload_bytes": report.upload_bytes,
                "download_bytes": report.download_bytes,
                "error_kind": report.error_kind.map(ConnectionErrorKind::as_str),
                "error_detail": report.error_detail.as_deref(),
            });
            writeln!(writer, "{value}").map_err(|error| error.to_string())
        }
    }
}

fn write_smoke_result(
    writer: &mut impl Write,
    status: &str,
    report: &ConnectionReport,
    output: ProbeOutputFormat,
) -> Result<(), String> {
    match output {
        ProbeOutputFormat::Text => {
            writeln!(writer, "smoke status={status} {}", report.summary_line())
                .map_err(|error| error.to_string())
        }
        ProbeOutputFormat::Json => {
            let (route, outbound_tag) = probe_route_fields(&report.route_action);
            let value = serde_json::json!({
                "status": status,
                "inbound": report.inbound.as_str(),
                "target": format!("{}:{}", report.target.host, report.target.port),
                "target_host": report.target.host.as_str(),
                "target_port": report.target.port,
                "route": route,
                "outbound_tag": outbound_tag,
                "connect_ms": report.connect_ms,
                "first_byte_ms": report.first_byte_ms,
                "upload_bytes": report.upload_bytes,
                "download_bytes": report.download_bytes,
                "error_kind": report.error_kind.map(ConnectionErrorKind::as_str),
                "error_detail": report.error_detail.as_deref(),
            });
            writeln!(writer, "{value}").map_err(|error| error.to_string())
        }
    }
}

fn probe_route_fields(route_action: &RouteAction) -> (&'static str, Option<&str>) {
    match route_action {
        RouteAction::Direct => ("direct", None),
        RouteAction::Block => ("block", None),
        RouteAction::HijackDns => ("hijack_dns", None),
        RouteAction::Outbound(tag) => ("outbound", Some(tag.as_str())),
    }
}

pub fn write_profile_check_report_from_subscription_config_text(
    config_text: &str,
    output: ProbeOutputFormat,
    mut writer: impl Write,
) -> Result<(), String> {
    let source_format = detect_subscription_input_format(config_text);
    let parsed = parse_subscription_outbound_profiles(config_text)
        .map_err(|error| format!("profile config parse failed: {error}"))?;
    let parsed = profiles_with_registry_supported_outbounds(parsed);
    let default_outbound = parsed.profiles.first().map(|profile| profile.tag.as_str());
    let status = if parsed.profiles.is_empty() {
        "error"
    } else {
        "ok"
    };

    write_profile_check_report(
        &mut writer,
        status,
        source_format.as_str(),
        &parsed,
        default_outbound,
        None,
        output,
    )?;

    if parsed.profiles.is_empty() {
        return Err("profile config did not contain supported outbounds".to_string());
    }
    Ok(())
}

fn profiles_with_registry_supported_outbounds(
    parsed: ParsedOutboundProfiles,
) -> ParsedOutboundProfiles {
    let mut profiles = Vec::new();
    let mut skipped = parsed.skipped;
    for profile in parsed.profiles {
        match OutboundRegistry::from_profiles([profile.clone()]) {
            Ok(_) => profiles.push(profile),
            Err(error) => skipped.push(SkippedOutboundProfile {
                name: profile.tag,
                reason: format!("registry unsupported: {error}"),
            }),
        }
    }
    ParsedOutboundProfiles { profiles, skipped }
}

fn write_profile_check_report(
    writer: &mut impl Write,
    status: &str,
    source_format: &str,
    parsed: &keli_protocol::ParsedOutboundProfiles,
    default_outbound: Option<&str>,
    registry_error: Option<&str>,
    output: ProbeOutputFormat,
) -> Result<(), String> {
    match output {
        ProbeOutputFormat::Text => {
            let udp_supported_tags = udp_supported_tags(&parsed.profiles);
            let protocol_capabilities = protocol_capability_reports(&parsed.profiles);
            let skipped_summary = skipped_summary_reports(&parsed.skipped);
            writeln!(
                writer,
                "profile status={status} source_format={source_format} supported={} skipped={} default_outbound={} registry_error={} udp_supported={} protocol_capabilities={}",
                parsed.profiles.len(),
                parsed.skipped.len(),
                default_outbound.unwrap_or("-"),
                registry_error.unwrap_or("-"),
                udp_supported_tags.len(),
                protocol_capabilities.len()
            )
            .map_err(|error| error.to_string())?;
            for capability in &protocol_capabilities {
                writeln!(
                    writer,
                    "profile capability protocol={} tcp_relay_supported={} udp_supported={} tags={}",
                    capability.protocol,
                    capability.tcp_relay_supported,
                    capability.udp_supported,
                    capability.tags.join(",")
                )
                .map_err(|error| error.to_string())?;
            }
            for summary in &skipped_summary {
                writeln!(
                    writer,
                    "profile skipped_summary count={} names={} reason={}",
                    summary.names.len(),
                    summary.names.join(","),
                    summary.reason
                )
                .map_err(|error| error.to_string())?;
            }
            for skipped in &parsed.skipped {
                writeln!(
                    writer,
                    "profile skipped name={} reason={}",
                    skipped.name, skipped.reason
                )
                .map_err(|error| error.to_string())?;
            }
            Ok(())
        }
        ProbeOutputFormat::Json => {
            let supported_tags: Vec<&str> = parsed
                .profiles
                .iter()
                .map(|profile| profile.tag.as_str())
                .collect();
            let udp_supported_tags = udp_supported_tags(&parsed.profiles);
            let supported: Vec<_> = parsed
                .profiles
                .iter()
                .map(redacted_supported_profile_value)
                .collect();
            let skipped: Vec<_> = parsed
                .skipped
                .iter()
                .map(|skipped| {
                    serde_json::json!({
                        "name": skipped.name.as_str(),
                        "reason": skipped.reason.as_str(),
                    })
                })
                .collect();
            let skipped_summary = skipped_summary_reports(&parsed.skipped);
            let skipped_summary_json: Vec<_> = skipped_summary
                .iter()
                .map(|summary| {
                    serde_json::json!({
                        "reason": summary.reason,
                        "count": summary.names.len(),
                        "names": summary.names,
                    })
                })
                .collect();
            let protocol_capabilities = protocol_capability_reports(&parsed.profiles);
            let protocol_capabilities_json: Vec<_> = protocol_capabilities
                .iter()
                .map(|capability| {
                    serde_json::json!({
                        "protocol": capability.protocol,
                        "tcp_relay_supported": capability.tcp_relay_supported,
                        "udp_supported": capability.udp_supported,
                        "tags": capability.tags,
                    })
                })
                .collect();
            let value = serde_json::json!({
                "status": status,
                "source_format": source_format,
                "supported_count": parsed.profiles.len(),
                "skipped_count": parsed.skipped.len(),
                "skipped_summary_count": skipped_summary.len(),
                "skipped_summary": skipped_summary_json,
                "default_outbound": default_outbound,
                "registry_error": registry_error,
                "supported_tags": supported_tags,
                "udp_supported_count": udp_supported_tags.len(),
                "udp_supported_tags": udp_supported_tags,
                "protocol_capability_count": protocol_capabilities.len(),
                "protocol_capabilities": protocol_capabilities_json,
                "supported": supported,
                "skipped": skipped,
            });
            writeln!(writer, "{value}").map_err(|error| error.to_string())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProtocolCapabilityReport {
    protocol: String,
    tcp_relay_supported: bool,
    udp_supported: bool,
    tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SkippedSummaryReport {
    reason: String,
    names: Vec<String>,
}

fn skipped_summary_reports(skipped: &[SkippedOutboundProfile]) -> Vec<SkippedSummaryReport> {
    let mut summaries = Vec::<SkippedSummaryReport>::new();
    for skipped in skipped {
        if let Some(summary) = summaries
            .iter_mut()
            .find(|summary| summary.reason == skipped.reason)
        {
            summary.names.push(skipped.name.clone());
            continue;
        }
        summaries.push(SkippedSummaryReport {
            reason: skipped.reason.clone(),
            names: vec![skipped.name.clone()],
        });
    }
    summaries
}

fn udp_supported_tags(profiles: &[OutboundProfile]) -> Vec<&str> {
    profiles
        .iter()
        .filter(|profile| profile_supports_udp(profile))
        .map(|profile| profile.tag.as_str())
        .collect()
}

fn profile_supports_udp(profile: &OutboundProfile) -> bool {
    !matches!(profile.protocol, ProxyProtocol::Http | ProxyProtocol::Naive)
}

fn redacted_supported_profile_value(profile: &OutboundProfile) -> serde_json::Value {
    serde_json::json!({
        "tag": profile.tag.as_str(),
        "protocol": format!("{:?}", profile.protocol),
        "transport": redacted_transport_label(&profile.transport),
        "security": redacted_security_label(&profile.security),
        "tls_skip_verify": redacted_tls_skip_verify(&profile.security),
        "udp_supported": profile_supports_udp(profile),
    })
}

fn redacted_transport_label(transport: &TransportKind) -> &'static str {
    match transport {
        TransportKind::Tcp => "tcp",
        TransportKind::WebSocket { .. } => "ws",
        TransportKind::HttpUpgrade { .. } => "httpupgrade",
        TransportKind::Http2 { .. } => "h2",
        TransportKind::Grpc { .. } => "grpc",
        TransportKind::Quic { .. } => "quic",
    }
}

fn redacted_security_label(security: &SecurityKind) -> &'static str {
    match security {
        SecurityKind::None => "none",
        SecurityKind::Tls { .. } => "tls",
    }
}

fn redacted_tls_skip_verify(security: &SecurityKind) -> Option<bool> {
    match security {
        SecurityKind::None => None,
        SecurityKind::Tls { skip_verify, .. } => Some(*skip_verify),
    }
}

fn protocol_capability_reports(profiles: &[OutboundProfile]) -> Vec<ProtocolCapabilityReport> {
    let mut capabilities = Vec::<ProtocolCapabilityReport>::new();
    for profile in profiles {
        let protocol = format!("{:?}", profile.protocol);
        if let Some(capability) = capabilities
            .iter_mut()
            .find(|capability| capability.protocol == protocol)
        {
            capability.tags.push(profile.tag.clone());
            capability.udp_supported |= profile_supports_udp(profile);
            continue;
        }
        capabilities.push(ProtocolCapabilityReport {
            protocol,
            tcp_relay_supported: true,
            udp_supported: profile_supports_udp(profile),
            tags: vec![profile.tag.clone()],
        });
    }
    capabilities
}

fn mixed_runtime_from_parsed_profiles(
    parsed: keli_protocol::ParsedOutboundProfiles,
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    outbound_tag: Option<String>,
    dns_options: MixedDnsOptions,
) -> Result<MixedProxyRuntime, String> {
    let available_tags: Vec<String> = parsed
        .profiles
        .iter()
        .map(|profile| profile.tag.clone())
        .collect();
    let selected_tag = match outbound_tag {
        Some(tag) => tag,
        None => available_tags
            .first()
            .cloned()
            .ok_or_else(|| "profile config did not contain supported outbounds".to_string())?,
    };
    if !available_tags.iter().any(|tag| tag == &selected_tag) {
        return Err(format!(
            "outbound tag not found: {selected_tag}; available: {}",
            available_tags.join(", ")
        ));
    }
    let outbounds = OutboundRegistry::from_profiles(parsed.profiles)
        .map_err(|error| format!("profile config contains unsupported outbound: {error}"))?;
    Ok(MixedProxyRuntime {
        routes: routes_from_cli(block_domains, RouteAction::Outbound(selected_tag)),
        relay_options,
        outbounds,
        dns_options,
    })
}

fn mixed_runtime_from_cli(
    block_domains: Vec<String>,
    relay_options: RelayOptions,
    dns_options: MixedDnsOptions,
) -> MixedProxyRuntime {
    MixedProxyRuntime {
        routes: routes_from_cli(block_domains, RouteAction::Direct),
        relay_options,
        outbounds: OutboundRegistry::new(),
        dns_options,
    }
}

fn routes_from_cli(block_domains: Vec<String>, default_action: RouteAction) -> RouteEngine {
    let mut routes = RouteEngine::new(default_action);
    for rule in block_domains {
        if let Some(cidr) = rule.strip_prefix(BLOCK_CIDR_RULE_PREFIX) {
            if let Ok(cidr) = parse_cli_block_cidr(cidr) {
                routes.add_rule(RouteRule {
                    name: format!("block-cidr:{}/{}", cidr.network(), cidr.prefix_len()),
                    matcher: RouteMatcher::IpCidr(cidr),
                    action: RouteAction::Block,
                });
                continue;
            }
        }
        if let Some(port) = rule.strip_prefix(BLOCK_PORT_RULE_PREFIX) {
            if let Ok(range) = parse_cli_block_port(port) {
                let matcher = if range.start == range.end {
                    RouteMatcher::PortExact(range.start)
                } else {
                    RouteMatcher::PortRange {
                        start: range.start,
                        end: range.end,
                    }
                };
                routes.add_rule(RouteRule {
                    name: format!("block-port:{}", range.label()),
                    matcher,
                    action: RouteAction::Block,
                });
                continue;
            }
        }
        routes.add_rule(RouteRule {
            name: format!("block-domain:{rule}"),
            matcher: RouteMatcher::DomainSuffix(rule),
            action: RouteAction::Block,
        });
    }
    routes
}

fn http_forbidden_response() -> &'static [u8] {
    b"HTTP/1.1 403 Forbidden\r\n\r\n"
}

fn relay_with_report(
    client: TcpStream,
    remote: OutboundConnection,
    report: &mut ConnectionReport,
    relay_options: RelayOptions,
) -> io::Result<()> {
    match relay_owned_bidirectional_with_options(client, remote, relay_options) {
        Ok(stats) => {
            report.record_relay_stats(stats);
            println!("{}", report.summary_line());
            Ok(())
        }
        Err(error) => {
            report.record_error(error.kind);
            println!("{}", report.summary_line());
            Err(io::Error::new(io::ErrorKind::Other, error))
        }
    }
}

fn default_relay_options() -> RelayOptions {
    RelayOptions {
        first_byte_timeout: Some(DEFAULT_FIRST_BYTE_TIMEOUT),
        idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
    }
}

fn parse_duration_ms(value: String, option: &str) -> Result<Duration, String> {
    let milliseconds = value
        .parse::<u64>()
        .map_err(|_| format!("{option} requires a positive integer value"))?;
    if milliseconds == 0 {
        return Err(format!("{option} must be greater than 0"));
    }
    Ok(Duration::from_millis(milliseconds))
}

fn to_io_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
