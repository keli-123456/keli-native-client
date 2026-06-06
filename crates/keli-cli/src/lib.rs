use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
    UdpSocket,
};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex, RwLock,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use keli_client_core::{
    build_connection_plan, plan_subscription_update, ClientErrorKind, ClientRuntime,
    ConnectionPhase, ConnectionPlan, PanelState, RuntimeConfig, RuntimeDiagnostic, RuntimeEvent,
    RuntimeManagedMixedStopDrainDiagnostic, RuntimeManagedNodeProbeSweepDiagnostic, RuntimeStatus,
    RuntimeTunPacketLoopDiagnostic, SkippedProfileSummary, SubscriptionNodeCapability,
    SubscriptionUpdateReport, DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT,
};
use keli_net_core::{
    build_dns_error_response, build_dns_response, encode_socks5_udp_datagram,
    http_connect_bad_request_response, http_connect_success_response,
    http_proxy_bad_request_response, parse_dns_query, parse_http_connect_request,
    parse_http_proxy_request, parse_socks5_handshake, parse_socks5_request,
    parse_socks5_udp_datagram, process_tun_device_packet_with_relays, prune_idle_tun_tcp_sessions,
    relay_owned_bidirectional_with_options, run_tun_packet_loop_summary,
    run_tun_packet_loop_with_relays_summary_with_idle_timeout,
    run_tun_packet_loop_with_udp_relay_summary, socks5_no_auth_response, socks5_reply,
    ConnectionErrorKind, ConnectionReport, DirectTcpConnector, DirectUdpConnector,
    DnsAddressFamilyPolicy, DnsCache, DnsEngine, DnsError, DnsLocalResolutionPolicy,
    DnsQuestionType, DnsResolver, LocalInbound, OutboundConnection, OutboundRegistry,
    OutboundTarget, RegistryTunTcpSessionRelay, RegistryTunUdpRelay, RelayOptions, RouteAction,
    RouteEngine, RouteIpCidr, RouteMatcher, RouteRule, Socks5Address, Socks5Command,
    Socks5ReplyCode, SystemDnsResolver, TunPacketDevice, TunPacketLoopEvent, TunPacketLoopSummary,
    TunTcpSessionTable, TunUdpRelay, DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
};
use keli_platform::{
    install_wintun_library, NativeSystemProxyController, NativeTunDeviceController,
    PlatformCapabilities, SystemProxyConfig, SystemProxyController, SystemProxySnapshot,
    SystemProxyStatus, TunBackendStatus, TunDeviceConfig, TunDeviceController, TunDevicePreflight,
    TunDeviceReadiness, TunDeviceSnapshot, TunDeviceStatus, TunPacketIo, TunPacketIoController,
    WintunInstallReport,
};
use keli_protocol::{
    detect_subscription_input_format, parse_mihomo_outbound_profiles,
    parse_subscription_outbound_profiles, Endpoint, OutboundProfile, ParsedOutboundProfiles,
    ProxyProtocol, SecurityKind, SkippedOutboundProfile, TransportKind,
};

const DEFAULT_FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const DEFAULT_SUBSCRIPTION_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_SUBSCRIPTION_FETCH_MAX_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_TUN_INTERFACE_NAME: &str = "keli-tun0";
const DEFAULT_TUN_ADDRESS_CIDR: &str = "10.7.0.1/24";
const DEFAULT_TUN_MTU: u16 = 1500;
const BLOCK_CIDR_RULE_PREFIX: &str = "cidr:";
const BLOCK_PORT_RULE_PREFIX: &str = "port:";
const UDP_RELAY_POLL_INTERVAL: Duration = Duration::from_millis(200);
const MANAGED_ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MANAGED_CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);
const MANAGED_TUN_IDLE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const DEFAULT_TUN_DNS_TTL_SECONDS: u32 = 30;
const DEFAULT_TUN_PACKET_LOOP_MAX_PACKETS: usize = usize::MAX;
const DEFAULT_TUN_TCP_SERVER_INITIAL_SEQUENCE_NUMBER: u32 = 1;
const DEFAULT_TUN_TCP_WINDOW_SIZE: u16 = 0x4000;
const DEFAULT_MIXED_SOAK_CONNECTIONS: usize = 25;
const DEFAULT_MIXED_SOAK_MIN_DURATION: Duration = Duration::from_millis(0);
const DEFAULT_READINESS_SOAK_CONNECTIONS: usize = 3;
const MIXED_SOAK_PAYLOAD: &[u8] = b"keli-soak-ping";
pub const MANAGED_MIXED_RECENT_EVENT_LIMIT: usize = 5;
pub const MANAGED_CONNECTION_REPORT_HISTORY_LIMIT: usize = 64;
pub const DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS: usize = 1024;
pub const DOCTOR_REPORT_SCHEMA_VERSION: u32 = 11;
pub const SUPPORT_BUNDLE_SCHEMA_VERSION: u32 = 3;
pub const INTEROP_MATRIX_SCHEMA_VERSION: u32 = 1;
pub const READINESS_CHECK_SCHEMA_VERSION: u32 = 3;
pub const DEFAULT_CORE_CERTIFICATION_SCHEMA_VERSION: u32 = 3;
pub const MANAGED_MIXED_STATUS_SCHEMA_VERSION: u32 = 2;
const SUPPORTED_OUTBOUNDS: &str =
    "direct,socks5-tcp,http-connect,trojan-tcp,trojan-ws,trojan-httpupgrade,trojan-grpc,trojan-h2,trojan-quic,vless-tcp,vless-ws,vless-httpupgrade,vless-grpc,vless-h2,vless-quic,vmess-tcp,vmess-ws,vmess-httpupgrade,vmess-grpc,vmess-h2,vmess-quic,shadowsocks-tcp,anytls-tls-tcp,naive-h2-tcp,naive-h3-quic,mieru-tcp,hy2-quic,tuic-quic";
const SUPPORTED_UDP_OUTBOUNDS: &str =
    "direct,socks5-udp,trojan-tcp-udp,trojan-tls-tcp-udp,trojan-ws-udp,trojan-tls-ws-udp,trojan-httpupgrade-udp,trojan-tls-httpupgrade-udp,trojan-grpc-udp,trojan-tls-grpc-udp,trojan-h2-udp,trojan-tls-h2-udp,trojan-quic-udp,vless-tcp-udp,vless-tls-tcp-udp,vless-ws-udp,vless-tls-ws-udp,vless-httpupgrade-udp,vless-tls-httpupgrade-udp,vless-grpc-udp,vless-tls-grpc-udp,vless-h2-udp,vless-tls-h2-udp,vless-quic-udp,vmess-tcp-aead-udp,vmess-tls-tcp-aead-udp,vmess-ws-aead-udp,vmess-tls-ws-aead-udp,vmess-httpupgrade-aead-udp,vmess-tls-httpupgrade-aead-udp,vmess-grpc-aead-udp,vmess-tls-grpc-aead-udp,vmess-h2-aead-udp,vmess-tls-h2-aead-udp,vmess-quic-aead-udp,shadowsocks-aead,anytls-tls-tcp-uot-udp,mieru-tcp-udp,hy2-quic,tuic-quic";
const SUPPORTED_PROTOCOL_CAPABILITIES: &str =
    "trojan=tcp,udp;vless=tcp,udp;vmess=tcp,udp;shadowsocks=tcp,udp;anytls=tcp,udp;naive=tcp;mieru=tcp,udp;hy2=tcp,udp;tuic=tcp,udp;socks=tcp,udp;http=tcp";
const ROUTE_RULE_CAPABILITIES: &str =
    "domain-suffix,domain-keyword,ip-exact,ip-cidr,port-exact,port-range";
const MANAGED_CONNECTION_METRIC_CAPABILITIES: &str =
    "total-connection-count,success-count,failure-count,connection-limit-rejection-count,error-kind-counts,route-action-counts,inbound-counts,total-upload-bytes,total-download-bytes,total-connect-ms,timed-connect-count,average-connect-ms,total-first-byte-ms,timed-first-byte-count,average-first-byte-ms,last-connection-timestamp,last-success-timestamp,last-failure-timestamp,recent-connection-reports,history-limit";
const MANAGED_STATUS_SCHEMA_CAPABILITIES: &str =
    "schema-version,runtime-status,listen-address,selected-outbound,generation,start-time,uptime,connection-metrics,event-count,event-retention,recent-events,runtime-event-diagnostics,last-error,system-proxy,subscription-status,node-health,node-health-coverage,node-health-switch-readiness,node-health-switch-reason,node-health-sweep-diagnostic,node-health-udp-probe,node-health-udp-aware-recommendation,dns-options,tun-tcp-session-limit,connection-worker-counts,panel-state,subscription-url-update-status";
const SUBSCRIPTION_FETCH_CAPABILITIES: &str =
    "http,https,timeout,max-bytes,redacted-source,profile-check-summary";
const SUBSCRIPTION_UPDATE_CAPABILITIES: &str =
    "current-config,new-config,current-outbound,tag-diff,selected-preservation,default-fallback,redacted-profile-summary,managed-reload-plan,managed-url-reload,managed-url-update-status";
const TUN_PACKET_PIPELINE_CAPABILITIES: &str =
    "ipv4,ipv6,tcp,udp,udp-payload,icmp,route-decision,dns-hijack,dns-query-plan,dns-engine-response,packet-process-action,udp-response-packet,dns-response-packet,ipv4-fragment-guard,ipv6-extension-traversal,ipv6-extension-guard,packet-loop,packet-loop-summary,managed-packet-loop,direct-udp-relay,outbound-udp-relay,registry-udp-relay,managed-registry-udp-relay,listen-mixed-tun-runtime,concurrent-tun-runtime,background-runtime-report,tun-runtime-status-note,packet-io-readiness,tcp-segment-parse,tcp-response-packet,tcp-reset-response,tcp-syn-ack-response,tcp-syn-retransmit-guard,tcp-session-table,tcp-client-payload-ack,tcp-client-duplicate-ack,tcp-client-out-of-order-ack,tcp-client-overlap-ack,tcp-client-stale-server-ack,tcp-client-ack-keepalive,tcp-server-payload-packet,tcp-server-payload-retransmit,tcp-server-payload-ack-clear,tcp-server-mss-read-clamp,tcp-session-step-runner,tcp-session-device-loop,tcp-server-payload-poll,tcp-fin-close-ack,tcp-fin-payload-close,registry-tcp-fin-payload-close,tcp-client-fin-half-close,tcp-client-fin-stale-server-ack,tcp-client-fin-server-payload-retransmit,tcp-client-fin-server-payload-ack-clear,tcp-client-fin-duplicate-poll,tcp-client-fin-duplicate-payload-poll,tcp-client-fin-payload-duplicate-poll,tcp-client-fin-post-close-ack,tcp-client-fin-post-close-payload-ack,tcp-close-sequence-guard,tcp-close-latest-ack-guard,tcp-unknown-session-reset,tcp-server-eof-fin-ack,tcp-server-fin-retransmit,tcp-server-fin-final-ack,tcp-server-fin-client-fin-ack,tcp-server-fin-post-close-guard,tcp-session-idle-cleanup,tcp-close-marker-prune-summary,registry-tcp-session-relay,combined-tun-relay-loop,managed-registry-tcp-session-relay,tcp-relay-plan-summary,relay-plan,tun-runtime-last-error-note,tcp-close-marker-rst-clear,tcp-close-marker-rst-summary,tcp-session-state-summary,tcp-session-state-peak,tcp-session-limit,tcp-session-limit-config,tun-runtime-exit-reason,tun-runtime-exit-reason-label,tun-runtime-structured-diagnostic";
const STABILITY_DIAGNOSTIC_CAPABILITIES: &str =
    "local-mixed-soak,loopback-echo,managed-metrics,worker-drain,socks5,http-connect,min-duration";
const INTEROP_MATRIX_CAPABILITIES: &str =
    "protocol-summary,transport-coverage,tcp-relay,udp-relay,profile-source,profile-validation,registry-validation,support-bundle-export";
const READINESS_CHECK_CAPABILITIES: &str =
    "doctor-schema,interop-matrix,local-mixed-soak,resource-limits,tun-preflight,system-proxy,panel-subscription-state,support-diagnostics,json-gates,blocker-summary,soak-min-duration";
const TUN_BACKEND_CHECK_CAPABILITIES: &str =
    "backend-kind,driver-library-detection,driver-api-load,install-required,lifecycle-wiring,packet-io-wiring,route-takeover-wiring,searched-paths,readiness-blocker-detail,validated-runtime-install";
const DEFAULT_CORE_CERTIFICATION_CAPABILITIES: &str =
    "schema-version,readiness-embed,tun-backend-evidence,non-skipped-soak,soak-parameters,soak-min-duration,promotion-decision,promotion-blockers,json-artifact,text-summary,support-bundle-export";
const INTEROP_SAMPLE_UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    Doctor {
        output: ProbeOutputFormat,
    },
    InteropMatrix {
        output: ProbeOutputFormat,
    },
    ReadinessCheck {
        output: ProbeOutputFormat,
        soak_connections: usize,
        first_byte_timeout: Duration,
        max_connection_workers: usize,
        soak_min_duration: Duration,
        skip_soak: bool,
    },
    DefaultCoreCertify {
        output: ProbeOutputFormat,
        soak_connections: usize,
        first_byte_timeout: Duration,
        max_connection_workers: usize,
        soak_min_duration: Duration,
    },
    TunPreflight {
        config: TunDeviceConfig,
        output: ProbeOutputFormat,
    },
    TunBackendCheck {
        output: ProbeOutputFormat,
    },
    TunBackendInstall {
        source: PathBuf,
        target_dir: Option<PathBuf>,
        output: ProbeOutputFormat,
    },
    Version,
    SubscriptionFetch {
        url: String,
        output: ProbeOutputFormat,
        timeout: Duration,
        max_bytes: usize,
    },
    SubscriptionUpdate {
        current_config: Option<String>,
        new_config: String,
        current_outbound: Option<String>,
        output: ProbeOutputFormat,
    },
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
        tun_tcp_max_active_sessions: usize,
        max_connection_workers: usize,
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
    SoakMixed {
        connections: usize,
        inbound: SmokeInboundKind,
        output: ProbeOutputFormat,
        first_byte_timeout: Duration,
        max_connection_workers: usize,
        min_duration: Duration,
    },
    ProfileCheck {
        profile_config: String,
        output: ProbeOutputFormat,
    },
    SupportBundle {
        profile_config: Option<String>,
        include_default_core_certification: bool,
        certification_soak_connections: usize,
        certification_first_byte_timeout: Duration,
        certification_max_connection_workers: usize,
        certification_soak_min_duration: Duration,
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

    fn cli_value(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::HttpConnect => "http-connect",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MixedSoakReport {
    pub requested_connections: usize,
    pub completed_connections: usize,
    pub failed_connections: usize,
    pub inbound: SmokeInboundKind,
    pub listen_addr: SocketAddr,
    pub target_addr: SocketAddr,
    pub elapsed: Duration,
    pub min_duration: Duration,
    pub duration_target_met: bool,
    pub payload_bytes_per_connection: usize,
    pub connection_metrics: ConnectionMetricsSnapshot,
    pub max_connection_workers: usize,
    pub active_connection_workers: usize,
    pub peak_connection_workers: usize,
    pub active_client_connections: usize,
    pub peak_client_connections: usize,
    pub available_connection_worker_slots: usize,
    pub stop_drain: RuntimeManagedMixedStopDrainDiagnostic,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionMetricsSnapshot {
    pub total_connection_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub connection_limit_rejection_count: u64,
    pub error_kind_counts: Vec<ConnectionErrorKindCount>,
    pub route_action_counts: Vec<ConnectionRouteActionCount>,
    pub inbound_counts: Vec<ConnectionInboundCount>,
    pub total_upload_bytes: u64,
    pub total_download_bytes: u64,
    pub total_connect_ms: u128,
    pub timed_connect_count: u64,
    pub total_first_byte_ms: u128,
    pub timed_first_byte_count: u64,
    pub last_connection_at: Option<SystemTime>,
    pub last_success_at: Option<SystemTime>,
    pub last_failure_at: Option<SystemTime>,
    pub retained_connection_count: usize,
    pub connection_history_limit: usize,
    pub recent_connections: Vec<ConnectionReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionErrorKindCount {
    pub error_kind: ConnectionErrorKind,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRouteActionCount {
    pub route_action: RouteAction,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionInboundCount {
    pub inbound: String,
    pub count: u64,
}

impl Default for ConnectionMetricsSnapshot {
    fn default() -> Self {
        Self {
            total_connection_count: 0,
            success_count: 0,
            failure_count: 0,
            connection_limit_rejection_count: 0,
            error_kind_counts: Vec::new(),
            route_action_counts: Vec::new(),
            inbound_counts: Vec::new(),
            total_upload_bytes: 0,
            total_download_bytes: 0,
            total_connect_ms: 0,
            timed_connect_count: 0,
            total_first_byte_ms: 0,
            timed_first_byte_count: 0,
            last_connection_at: None,
            last_success_at: None,
            last_failure_at: None,
            retained_connection_count: 0,
            connection_history_limit: MANAGED_CONNECTION_REPORT_HISTORY_LIMIT,
            recent_connections: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
struct ConnectionMetricsState {
    total_connection_count: u64,
    success_count: u64,
    failure_count: u64,
    connection_limit_rejection_count: u64,
    error_kind_counts: Vec<ConnectionErrorKindCount>,
    route_action_counts: Vec<ConnectionRouteActionCount>,
    inbound_counts: Vec<ConnectionInboundCount>,
    total_upload_bytes: u64,
    total_download_bytes: u64,
    total_connect_ms: u128,
    timed_connect_count: u64,
    total_first_byte_ms: u128,
    timed_first_byte_count: u64,
    last_connection_at: Option<SystemTime>,
    last_success_at: Option<SystemTime>,
    last_failure_at: Option<SystemTime>,
    recent_connections: Vec<ConnectionReport>,
}

#[derive(Debug, Clone)]
pub struct ConnectionMetrics {
    inner: Arc<Mutex<ConnectionMetricsState>>,
    history_limit: usize,
}

impl ConnectionMetrics {
    pub fn new(history_limit: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ConnectionMetricsState::default())),
            history_limit: history_limit.max(1),
        }
    }

    pub fn record(&self, report: &ConnectionReport) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        let recorded_at = SystemTime::now();
        state.last_connection_at = Some(recorded_at);
        state.total_connection_count = state.total_connection_count.saturating_add(1);
        if let Some(entry) = state
            .inbound_counts
            .iter_mut()
            .find(|entry| entry.inbound == report.inbound)
        {
            entry.count = entry.count.saturating_add(1);
        } else {
            state.inbound_counts.push(ConnectionInboundCount {
                inbound: report.inbound.clone(),
                count: 1,
            });
        }
        if let Some(entry) = state
            .route_action_counts
            .iter_mut()
            .find(|entry| entry.route_action == report.route_action)
        {
            entry.count = entry.count.saturating_add(1);
        } else {
            state.route_action_counts.push(ConnectionRouteActionCount {
                route_action: report.route_action.clone(),
                count: 1,
            });
        }
        state.total_upload_bytes = state.total_upload_bytes.saturating_add(report.upload_bytes);
        state.total_download_bytes = state
            .total_download_bytes
            .saturating_add(report.download_bytes);
        if let Some(connect_ms) = report.connect_ms {
            state.total_connect_ms = state.total_connect_ms.saturating_add(connect_ms);
            state.timed_connect_count = state.timed_connect_count.saturating_add(1);
        }
        if let Some(first_byte_ms) = report.first_byte_ms {
            state.total_first_byte_ms = state.total_first_byte_ms.saturating_add(first_byte_ms);
            state.timed_first_byte_count = state.timed_first_byte_count.saturating_add(1);
        }
        if let Some(error_kind) = report.error_kind {
            state.failure_count = state.failure_count.saturating_add(1);
            state.last_failure_at = Some(recorded_at);
            if let Some(entry) = state
                .error_kind_counts
                .iter_mut()
                .find(|entry| entry.error_kind == error_kind)
            {
                entry.count = entry.count.saturating_add(1);
            } else {
                state.error_kind_counts.push(ConnectionErrorKindCount {
                    error_kind,
                    count: 1,
                });
            }
            if error_kind == ConnectionErrorKind::ConnectionLimitReached {
                state.connection_limit_rejection_count =
                    state.connection_limit_rejection_count.saturating_add(1);
            }
        } else {
            state.success_count = state.success_count.saturating_add(1);
            state.last_success_at = Some(recorded_at);
        }
        state.recent_connections.push(report.clone());
        if state.recent_connections.len() > self.history_limit {
            let overflow = state.recent_connections.len() - self.history_limit;
            state.recent_connections.drain(0..overflow);
        }
    }

    pub fn snapshot(&self) -> ConnectionMetricsSnapshot {
        let Ok(state) = self.inner.lock() else {
            return ConnectionMetricsSnapshot {
                connection_history_limit: self.history_limit,
                ..ConnectionMetricsSnapshot::default()
            };
        };
        let recent_connections = state
            .recent_connections
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>();
        let mut error_kind_counts = state.error_kind_counts.clone();
        error_kind_counts.sort_by_key(|entry| entry.error_kind.as_str());
        let mut route_action_counts = state.route_action_counts.clone();
        route_action_counts.sort_by_key(|entry| route_action_sort_key(&entry.route_action));
        let mut inbound_counts = state.inbound_counts.clone();
        inbound_counts.sort_by(|left, right| left.inbound.cmp(&right.inbound));
        ConnectionMetricsSnapshot {
            total_connection_count: state.total_connection_count,
            success_count: state.success_count,
            failure_count: state.failure_count,
            connection_limit_rejection_count: state.connection_limit_rejection_count,
            error_kind_counts,
            route_action_counts,
            inbound_counts,
            total_upload_bytes: state.total_upload_bytes,
            total_download_bytes: state.total_download_bytes,
            total_connect_ms: state.total_connect_ms,
            timed_connect_count: state.timed_connect_count,
            total_first_byte_ms: state.total_first_byte_ms,
            timed_first_byte_count: state.timed_first_byte_count,
            last_connection_at: state.last_connection_at,
            last_success_at: state.last_success_at,
            last_failure_at: state.last_failure_at,
            retained_connection_count: recent_connections.len(),
            connection_history_limit: self.history_limit,
            recent_connections,
        }
    }
}

impl Default for ConnectionMetrics {
    fn default() -> Self {
        Self::new(MANAGED_CONNECTION_REPORT_HISTORY_LIMIT)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionWorkerGauge {
    inner: Arc<ConnectionWorkerGaugeInner>,
}

#[derive(Debug, Default)]
struct ConnectionWorkerGaugeInner {
    active: AtomicUsize,
    peak: AtomicUsize,
}

impl ConnectionWorkerGauge {
    pub fn active(&self) -> usize {
        self.inner.active.load(Ordering::SeqCst)
    }

    pub fn peak(&self) -> usize {
        self.inner.peak.load(Ordering::SeqCst)
    }

    fn start_worker(&self) -> ConnectionWorkerLease {
        let active = self.inner.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.record_peak(active);
        ConnectionWorkerLease {
            gauge: self.clone(),
        }
    }

    fn record_peak(&self, active_count: usize) {
        let _ = self
            .inner
            .peak
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |peak| {
                (active_count > peak).then_some(active_count)
            });
    }

    fn finish_worker(&self) {
        let _ = self
            .inner
            .active
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |active| {
                Some(active.saturating_sub(1))
            });
    }
}

struct ConnectionWorkerLease {
    gauge: ConnectionWorkerGauge,
}

impl Drop for ConnectionWorkerLease {
    fn drop(&mut self) {
        self.gauge.finish_worker();
    }
}

#[derive(Debug, Clone, Default)]
pub struct ActiveConnectionRegistry {
    inner: Arc<ActiveConnectionRegistryInner>,
}

#[derive(Debug, Default)]
struct ActiveConnectionRegistryInner {
    next_id: AtomicUsize,
    peak: AtomicUsize,
    streams: Mutex<HashMap<usize, TcpStream>>,
}

impl ActiveConnectionRegistry {
    fn register(&self, stream: &TcpStream) -> io::Result<ActiveConnectionLease> {
        let shutdown_stream = stream.try_clone()?;
        let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
        let mut streams = self
            .inner
            .streams
            .lock()
            .map_err(|_| io::Error::other("active connection registry lock poisoned"))?;
        streams.insert(id, shutdown_stream);
        self.record_peak(streams.len());
        Ok(ActiveConnectionLease {
            registry: self.clone(),
            id,
        })
    }

    fn record_peak(&self, active_count: usize) {
        let _ = self
            .inner
            .peak
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |peak| {
                (active_count > peak).then_some(active_count)
            });
    }

    fn shutdown_all(&self) -> usize {
        let Ok(mut streams) = self.inner.streams.lock() else {
            return 0;
        };
        let shutdown_streams = std::mem::take(&mut *streams);
        let shutdown_count = shutdown_streams.len();
        for stream in shutdown_streams.values() {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(10)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(10)));
            let _ = stream.shutdown(Shutdown::Both);
        }
        shutdown_count
    }

    fn active_count(&self) -> usize {
        self.inner
            .streams
            .lock()
            .map(|streams| streams.len())
            .unwrap_or(0)
    }

    fn peak_count(&self) -> usize {
        self.inner.peak.load(Ordering::SeqCst)
    }

    fn unregister(&self, id: usize) {
        if let Ok(mut streams) = self.inner.streams.lock() {
            streams.remove(&id);
        }
    }
}

struct ActiveConnectionLease {
    registry: ActiveConnectionRegistry,
    id: usize,
}

impl Drop for ActiveConnectionLease {
    fn drop(&mut self) {
        self.registry.unregister(self.id);
    }
}

#[derive(Debug, Clone)]
pub struct MixedProxyRuntime {
    pub routes: RouteEngine,
    pub relay_options: RelayOptions,
    pub outbounds: OutboundRegistry,
    pub dns_options: MixedDnsOptions,
    pub tun_tcp_max_active_sessions: usize,
    pub connection_metrics: ConnectionMetrics,
    pub max_connection_workers: usize,
    pub connection_worker_gauge: ConnectionWorkerGauge,
    pub active_connection_registry: ActiveConnectionRegistry,
}

impl MixedProxyRuntime {
    pub fn with_routes(routes: RouteEngine) -> Self {
        Self {
            routes,
            relay_options: default_relay_options(),
            outbounds: OutboundRegistry::new(),
            dns_options: MixedDnsOptions::default(),
            tun_tcp_max_active_sessions: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
            connection_metrics: ConnectionMetrics::default(),
            max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
            connection_worker_gauge: ConnectionWorkerGauge::default(),
            active_connection_registry: ActiveConnectionRegistry::default(),
        }
    }

    pub fn with_routes_and_outbounds(routes: RouteEngine, outbounds: OutboundRegistry) -> Self {
        Self {
            routes,
            relay_options: default_relay_options(),
            outbounds,
            dns_options: MixedDnsOptions::default(),
            tun_tcp_max_active_sessions: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
            connection_metrics: ConnectionMetrics::default(),
            max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
            connection_worker_gauge: ConnectionWorkerGauge::default(),
            active_connection_registry: ActiveConnectionRegistry::default(),
        }
    }

    pub fn record_connection_report(&self, report: &ConnectionReport) {
        self.connection_metrics.record(report);
    }

    pub fn connection_metrics_snapshot(&self) -> ConnectionMetricsSnapshot {
        self.connection_metrics.snapshot()
    }

    pub fn active_connection_workers(&self) -> usize {
        self.connection_worker_gauge.active()
    }

    pub fn peak_connection_workers(&self) -> usize {
        self.connection_worker_gauge.peak()
    }

    pub fn active_client_connections(&self) -> usize {
        self.active_connection_registry.active_count()
    }

    pub fn peak_client_connections(&self) -> usize {
        self.active_connection_registry.peak_count()
    }

    pub fn available_connection_worker_slots(&self) -> usize {
        self.max_connection_workers
            .max(1)
            .saturating_sub(self.active_connection_workers())
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
    pub tun_tcp_max_active_sessions: usize,
    pub max_connection_workers: usize,
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
            tun_tcp_max_active_sessions: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
            max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
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
    pub udp_probe: Option<ManagedNodeUdpProbeOptions>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedNodeProbeSweepOptions {
    pub target: String,
    pub payload: Vec<u8>,
    pub expect: Vec<u8>,
    pub inbound: SmokeInboundKind,
    pub first_byte_timeout: Duration,
    pub udp_available: Option<bool>,
    pub udp_probe: Option<ManagedNodeUdpProbeOptions>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedNodeUdpProbeOptions {
    pub target: String,
    pub payload: Vec<u8>,
    pub expect: Vec<u8>,
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

#[derive(Debug)]
pub struct PlatformTunPacketDevice<I: TunPacketIo> {
    io: I,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedTunPacketLoopReport {
    pub config: TunDeviceConfig,
    pub start_snapshot: TunDeviceSnapshot,
    pub stop_snapshot: TunDeviceSnapshot,
    pub owns_device: bool,
    pub summary: TunPacketLoopSummary,
}

pub fn managed_tun_runtime_report_note(report: &ManagedTunPacketLoopReport) -> String {
    let last_packet_error = tun_runtime_note_error_value(report.summary.last_packet_error.as_ref());
    let last_udp_relay_error =
        tun_runtime_note_error_value(report.summary.last_udp_relay_error.as_ref());
    let last_tcp_session_error =
        tun_runtime_note_error_value(report.summary.last_tcp_session_error.as_ref());
    format!(
        "managed TUN runtime stopped interface={} owns_device={} processed={} idle={} exit_reason={} stop_requested={} packet_limit_reached={} dns_responses={} udp_responses={} tcp_resets={} tcp_session_events={} tcp_session_writes={} tcp_max_active_sessions={} tcp_session_limit_rejections={} tcp_sessions_pruned={} tcp_server_closed_pruned={} tcp_post_closed_pruned={} tcp_server_close_rst_cleared={} tcp_post_close_rst_cleared={} tcp_sessions_open={} tcp_server_close_markers_open={} tcp_post_close_markers_open={} tcp_sessions_peak={} tcp_server_close_markers_peak={} tcp_post_close_markers_peak={} relay_plans={} tcp_relay_plans={} udp_relay_plans={} drops={} unsupported={} packet_errors={} udp_relay_errors={} tcp_session_errors={} last_packet_error={} last_udp_relay_error={} last_tcp_session_error={}",
        report.config.interface_name,
        report.owns_device,
        report.summary.processed_packets(),
        report.summary.idle_events,
        report.summary.exit_reason_label(),
        report.summary.stop_requested,
        report.summary.packet_limit_reached,
        report.summary.dns_responses_written,
        report.summary.udp_relay_responses_written,
        report.summary.tcp_resets_written,
        report.summary.tcp_session_events,
        report.summary.tcp_session_packets_written,
        report.summary.tcp_max_active_sessions,
        report.summary.tcp_session_limit_rejections,
        report.summary.tcp_sessions_pruned,
        report.summary.tcp_server_closed_sessions_pruned,
        report.summary.tcp_post_closed_sessions_pruned,
        report.summary.tcp_server_close_marker_resets,
        report.summary.tcp_post_close_marker_resets,
        report.summary.tcp_sessions_open,
        report.summary.tcp_server_close_markers_open,
        report.summary.tcp_post_close_markers_open,
        report.summary.tcp_sessions_peak,
        report.summary.tcp_server_close_markers_peak,
        report.summary.tcp_post_close_markers_peak,
        report.summary.relay_packets,
        report.summary.tcp_relay_plans,
        report.summary.udp_relay_plans,
        report.summary.dropped_packets,
        report.summary.unsupported_packets,
        report.summary.packet_errors,
        report.summary.udp_relay_errors,
        report.summary.tcp_session_errors,
        last_packet_error,
        last_udp_relay_error,
        last_tcp_session_error,
    )
}

pub fn managed_tun_runtime_report_diagnostic(
    report: &ManagedTunPacketLoopReport,
) -> RuntimeDiagnostic {
    RuntimeDiagnostic::TunPacketLoop(RuntimeTunPacketLoopDiagnostic {
        interface_name: report.config.interface_name.clone(),
        owns_device: report.owns_device,
        processed_packets: report.summary.processed_packets(),
        idle_events: report.summary.idle_events,
        exit_reason: report.summary.exit_reason_label().to_string(),
        stop_requested: report.summary.stop_requested,
        packet_limit_reached: report.summary.packet_limit_reached,
        dns_responses_written: report.summary.dns_responses_written,
        udp_relay_responses_written: report.summary.udp_relay_responses_written,
        tcp_resets_written: report.summary.tcp_resets_written,
        tcp_session_events: report.summary.tcp_session_events,
        tcp_session_packets_written: report.summary.tcp_session_packets_written,
        tcp_max_active_sessions: report.summary.tcp_max_active_sessions,
        tcp_session_limit_rejections: report.summary.tcp_session_limit_rejections,
        tcp_sessions_pruned: report.summary.tcp_sessions_pruned,
        tcp_server_closed_sessions_pruned: report.summary.tcp_server_closed_sessions_pruned,
        tcp_post_closed_sessions_pruned: report.summary.tcp_post_closed_sessions_pruned,
        tcp_server_close_marker_resets: report.summary.tcp_server_close_marker_resets,
        tcp_post_close_marker_resets: report.summary.tcp_post_close_marker_resets,
        tcp_sessions_open: report.summary.tcp_sessions_open,
        tcp_server_close_markers_open: report.summary.tcp_server_close_markers_open,
        tcp_post_close_markers_open: report.summary.tcp_post_close_markers_open,
        tcp_sessions_peak: report.summary.tcp_sessions_peak,
        tcp_server_close_markers_peak: report.summary.tcp_server_close_markers_peak,
        tcp_post_close_markers_peak: report.summary.tcp_post_close_markers_peak,
        relay_packets: report.summary.relay_packets,
        tcp_relay_plans: report.summary.tcp_relay_plans,
        udp_relay_plans: report.summary.udp_relay_plans,
        dropped_packets: report.summary.dropped_packets,
        unsupported_packets: report.summary.unsupported_packets,
        packet_errors: report.summary.packet_errors,
        udp_relay_errors: report.summary.udp_relay_errors,
        tcp_session_errors: report.summary.tcp_session_errors,
        last_packet_error: report
            .summary
            .last_packet_error
            .as_ref()
            .map(|error| sanitize_runtime_note_value(&error.to_string())),
        last_udp_relay_error: report
            .summary
            .last_udp_relay_error
            .as_ref()
            .map(|error| sanitize_runtime_note_value(&error.to_string())),
        last_tcp_session_error: report
            .summary
            .last_tcp_session_error
            .as_ref()
            .map(|error| sanitize_runtime_note_value(&error.to_string())),
    })
}

pub fn managed_mixed_stop_drain_note(
    diagnostic: &RuntimeManagedMixedStopDrainDiagnostic,
) -> String {
    format!(
        "managed mixed stop drain active_connections_shutdown={} workers_before_shutdown={} workers_drained={} workers_remaining={} drain_elapsed_ms={} drain_timeout_ms={} timed_out={}",
        diagnostic.active_connections_shutdown,
        diagnostic.workers_before_shutdown,
        diagnostic.workers_drained,
        diagnostic.workers_remaining,
        diagnostic.drain_elapsed_ms,
        diagnostic.drain_timeout_ms,
        diagnostic.timed_out,
    )
}

pub fn managed_mixed_stop_drain_diagnostic(
    diagnostic: RuntimeManagedMixedStopDrainDiagnostic,
) -> RuntimeDiagnostic {
    RuntimeDiagnostic::ManagedMixedStopDrain(diagnostic)
}

fn tun_runtime_note_error_value<E: std::fmt::Display>(error: Option<&E>) -> String {
    error
        .map(|error| sanitize_runtime_note_value(&error.to_string()))
        .unwrap_or_else(|| "none".to_string())
}

fn sanitize_runtime_note_value(value: &str) -> String {
    const MAX_RUNTIME_NOTE_VALUE_LEN: usize = 240;

    let mut sanitized = String::new();
    for character in value.chars().take(MAX_RUNTIME_NOTE_VALUE_LEN) {
        if character.is_ascii_alphanumeric()
            || matches!(
                character,
                '-' | '_' | '.' | ':' | '=' | '/' | ',' | '(' | ')'
            )
        {
            sanitized.push(character);
        } else {
            sanitized.push('_');
        }
    }
    sanitized
}

impl<I: TunPacketIo> PlatformTunPacketDevice<I> {
    pub fn new(io: I) -> Self {
        Self { io }
    }

    pub fn into_inner(self) -> I {
        self.io
    }
}

impl<I: TunPacketIo> TunPacketDevice for PlatformTunPacketDevice<I> {
    fn read_packet(&mut self) -> Result<Option<Vec<u8>>, String> {
        self.io.read_packet().map_err(|error| error.to_string())
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        self.io
            .write_packet(packet)
            .map_err(|error| error.to_string())
    }
}

pub fn run_managed_tun_packet_loop<C, R>(
    controller: &C,
    config: TunDeviceConfig,
    routes: &RouteEngine,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
    max_packets: usize,
) -> Result<ManagedTunPacketLoopReport, String>
where
    C: TunPacketIoController + ?Sized,
    R: DnsResolver,
{
    let guard = apply_tun_device_for_config(controller, config)?;
    let config = guard.config().clone();
    let start_snapshot = guard.snapshot().clone();
    let owns_device = guard.owns_device();
    let summary_result = run_managed_tun_packet_loop_inner(
        controller,
        &config,
        routes,
        dns,
        dns_ttl_seconds,
        max_packets,
    );
    let stop_result = guard.stop();

    match (summary_result, stop_result) {
        (Ok(summary), Ok(stop_snapshot)) => Ok(ManagedTunPacketLoopReport {
            config,
            start_snapshot,
            stop_snapshot,
            owns_device,
            summary,
        }),
        (Ok(_), Err(stop_error)) => Err(stop_error),
        (Err(loop_error), Ok(_)) => Err(loop_error),
        (Err(loop_error), Err(stop_error)) => Err(format!("{loop_error}; {stop_error}")),
    }
}

pub fn run_managed_tun_packet_loop_with_udp_relay<C, R, U>(
    controller: &C,
    config: TunDeviceConfig,
    routes: &RouteEngine,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
    max_packets: usize,
    udp_relay: &mut U,
) -> Result<ManagedTunPacketLoopReport, String>
where
    C: TunPacketIoController + ?Sized,
    R: DnsResolver,
    U: TunUdpRelay,
{
    let guard = apply_tun_device_for_config(controller, config)?;
    let config = guard.config().clone();
    let start_snapshot = guard.snapshot().clone();
    let owns_device = guard.owns_device();
    let summary_result = run_managed_tun_packet_loop_inner_with_udp_relay(
        controller,
        &config,
        routes,
        dns,
        dns_ttl_seconds,
        max_packets,
        udp_relay,
    );
    let stop_result = guard.stop();

    match (summary_result, stop_result) {
        (Ok(summary), Ok(stop_snapshot)) => Ok(ManagedTunPacketLoopReport {
            config,
            start_snapshot,
            stop_snapshot,
            owns_device,
            summary,
        }),
        (Ok(_), Err(stop_error)) => Err(stop_error),
        (Err(loop_error), Ok(_)) => Err(loop_error),
        (Err(loop_error), Err(stop_error)) => Err(format!("{loop_error}; {stop_error}")),
    }
}

pub fn run_managed_tun_packet_loop_with_runtime<C>(
    controller: &C,
    config: TunDeviceConfig,
    runtime: &MixedProxyRuntime,
    dns_ttl_seconds: u32,
    max_packets: usize,
) -> Result<ManagedTunPacketLoopReport, String>
where
    C: TunPacketIoController + ?Sized,
{
    let guard = apply_tun_device_for_config(controller, config)?;
    let config = guard.config().clone();
    let start_snapshot = guard.snapshot().clone();
    let owns_device = guard.owns_device();
    let summary_result = run_managed_tun_packet_loop_inner_with_runtime_summary(
        controller,
        &config,
        runtime,
        dns_ttl_seconds,
        max_packets,
    );
    let stop_result = guard.stop();

    match (summary_result, stop_result) {
        (Ok(summary), Ok(stop_snapshot)) => Ok(ManagedTunPacketLoopReport {
            config,
            start_snapshot,
            stop_snapshot,
            owns_device,
            summary,
        }),
        (Ok(_), Err(stop_error)) => Err(stop_error),
        (Err(loop_error), Ok(_)) => Err(loop_error),
        (Err(loop_error), Err(stop_error)) => Err(format!("{loop_error}; {stop_error}")),
    }
}

pub fn run_with_optional_tun_runtime<C, F, T>(
    controller: &C,
    config: Option<TunDeviceConfig>,
    runtime: &MixedProxyRuntime,
    dns_ttl_seconds: u32,
    max_packets: usize,
    run: F,
) -> Result<T, String>
where
    C: TunPacketIoController + ?Sized,
    F: FnOnce() -> Result<T, String>,
{
    let guard = config
        .map(|config| apply_tun_device_for_config(controller, config))
        .transpose()?;
    let tun_result = if let Some(guard) = guard.as_ref() {
        run_managed_tun_packet_loop_inner_with_runtime_summary(
            controller,
            guard.config(),
            runtime,
            dns_ttl_seconds,
            max_packets,
        )
        .map(|_| ())
    } else {
        Ok(())
    };
    let run_result = match tun_result {
        Ok(()) => run(),
        Err(error) => Err(error),
    };
    let stop_result = guard
        .map(|guard| guard.stop().map(|_| ()))
        .unwrap_or(Ok(()));

    match (run_result, stop_result) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(run_error), Ok(())) => Err(run_error),
        (Ok(_), Err(stop_error)) => Err(stop_error),
        (Err(run_error), Err(stop_error)) => Err(format!("{run_error}; {stop_error}")),
    }
}

pub fn run_with_optional_tun_runtime_background<C, F, T>(
    controller: &C,
    config: Option<TunDeviceConfig>,
    runtime: &MixedProxyRuntime,
    dns_ttl_seconds: u32,
    max_packets: usize,
    run: F,
) -> Result<T, String>
where
    C: TunPacketIoController + ?Sized,
    C::PacketIo: Send + 'static,
    F: FnOnce() -> Result<T, String>,
{
    run_with_optional_tun_runtime_background_report(
        controller,
        config,
        runtime,
        dns_ttl_seconds,
        max_packets,
        run,
    )
    .map(|(output, _)| output)
}

pub fn run_with_optional_tun_runtime_background_report<C, F, T>(
    controller: &C,
    config: Option<TunDeviceConfig>,
    runtime: &MixedProxyRuntime,
    dns_ttl_seconds: u32,
    max_packets: usize,
    run: F,
) -> Result<(T, Option<ManagedTunPacketLoopReport>), String>
where
    C: TunPacketIoController + ?Sized,
    C::PacketIo: Send + 'static,
    F: FnOnce() -> Result<T, String>,
{
    let guard = config
        .map(|config| apply_tun_device_for_config(controller, config))
        .transpose()?;
    let tun_metadata = guard.as_ref().map(|guard| {
        (
            guard.config().clone(),
            guard.snapshot().clone(),
            guard.owns_device(),
        )
    });
    let tun_thread = if let Some(guard) = guard.as_ref() {
        let io = match controller.open_packet_io(guard.config()) {
            Ok(io) => io,
            Err(error) => {
                let open_error = format!("open TUN packet I/O: {error}");
                let stop_result = if guard.owns_device() {
                    controller
                        .stop()
                        .map(|_| ())
                        .map_err(|error| format!("stop TUN device: {error}"))
                } else {
                    Ok(())
                };
                return match stop_result {
                    Ok(()) => Err(open_error),
                    Err(stop_error) => Err(format!("{open_error}; {stop_error}")),
                };
            }
        };
        let config = guard.config().clone();
        let runtime = runtime.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            run_managed_tun_packet_loop_io_until_stop(
                io,
                config,
                runtime,
                dns_ttl_seconds,
                max_packets,
                thread_stop,
            )
        });
        Some((stop, thread))
    } else {
        None
    };

    let run_result = run();
    let tun_summary_result = tun_thread
        .map(|(stop, thread)| {
            stop.store(true, Ordering::SeqCst);
            thread
                .join()
                .map_err(|_| "TUN packet loop thread panicked".to_string())
                .and_then(|result| result.map(Some))
        })
        .unwrap_or(Ok(None));
    let stop_result = guard
        .map(|guard| guard.stop().map(Some))
        .unwrap_or(Ok(None));

    let mut errors = Vec::new();
    let output = match run_result {
        Ok(output) => Some(output),
        Err(error) => {
            errors.push(error);
            None
        }
    };
    let tun_summary = match tun_summary_result {
        Ok(summary) => summary,
        Err(error) => {
            errors.push(error);
            None
        }
    };
    let stop_snapshot = match stop_result {
        Ok(snapshot) => snapshot,
        Err(error) => {
            errors.push(error);
            None
        }
    };

    if !errors.is_empty() {
        return Err(errors.join("; "));
    }

    let report = match (tun_metadata, tun_summary, stop_snapshot) {
        (Some((config, start_snapshot, owns_device)), Some(summary), Some(stop_snapshot)) => {
            Some(ManagedTunPacketLoopReport {
                config,
                start_snapshot,
                stop_snapshot,
                owns_device,
                summary,
            })
        }
        _ => None,
    };
    let Some(output) = output else {
        return Err("managed TUN runtime finished without run output".to_string());
    };
    Ok((output, report))
}

fn run_managed_tun_packet_loop_inner<C, R>(
    controller: &C,
    config: &TunDeviceConfig,
    routes: &RouteEngine,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
    max_packets: usize,
) -> Result<TunPacketLoopSummary, String>
where
    C: TunPacketIoController + ?Sized,
    R: DnsResolver,
{
    let io = controller
        .open_packet_io(config)
        .map_err(|error| format!("open TUN packet I/O: {error}"))?;
    let mut device = PlatformTunPacketDevice::new(io);
    run_tun_packet_loop_summary(
        &mut device,
        routes,
        config.dns_hijack,
        dns,
        dns_ttl_seconds,
        max_packets,
    )
    .map_err(|error| format!("run TUN packet loop: {error}"))
}

fn run_managed_tun_packet_loop_io_until_stop<I>(
    io: I,
    config: TunDeviceConfig,
    runtime: MixedProxyRuntime,
    dns_ttl_seconds: u32,
    max_packets: usize,
    stop: Arc<AtomicBool>,
) -> Result<TunPacketLoopSummary, String>
where
    I: TunPacketIo,
{
    let mut device = PlatformTunPacketDevice::new(io);
    let mut dns = runtime.dns_options.engine();
    let mut udp_relay_dns = runtime.dns_options.engine();
    let mut tcp_relay_dns = runtime.dns_options.engine();
    let timeout = runtime
        .relay_options
        .first_byte_timeout
        .unwrap_or(DEFAULT_FIRST_BYTE_TIMEOUT);
    let session_idle_timeout = runtime
        .relay_options
        .idle_timeout
        .unwrap_or(DEFAULT_IDLE_TIMEOUT);
    let mut udp_relay = RegistryTunUdpRelay::new(&runtime.outbounds, &mut udp_relay_dns, timeout);
    let mut tcp_relay =
        RegistryTunTcpSessionRelay::new(&runtime.outbounds, &mut tcp_relay_dns, timeout);
    let mut sessions =
        TunTcpSessionTable::with_max_active_sessions(runtime.tun_tcp_max_active_sessions);
    let mut summary = TunPacketLoopSummary::default();
    let mut packet_limit_reached = true;
    for _ in 0..max_packets {
        if stop.load(Ordering::SeqCst) {
            summary.record_stop_requested();
            packet_limit_reached = false;
            break;
        }
        let prune_report = prune_idle_tun_tcp_sessions(
            &mut sessions,
            &mut tcp_relay,
            Instant::now(),
            session_idle_timeout,
        );
        summary.record_tcp_session_prune_report(&prune_report);
        let event = process_tun_device_packet_with_relays(
            &mut device,
            &runtime.routes,
            config.dns_hijack,
            &mut dns,
            dns_ttl_seconds,
            &mut udp_relay,
            &mut sessions,
            &mut tcp_relay,
            DEFAULT_TUN_TCP_SERVER_INITIAL_SEQUENCE_NUMBER,
            DEFAULT_TUN_TCP_WINDOW_SIZE,
        )
        .map_err(|error| format!("run TUN packet loop: {error}"))?;
        let should_pause = event == TunPacketLoopEvent::NoPacket;
        summary.record_event(&event);
        summary.record_tcp_session_table_state(&sessions);
        if should_pause {
            thread::sleep(MANAGED_TUN_IDLE_POLL_INTERVAL);
        }
    }
    if packet_limit_reached {
        summary.record_packet_limit_reached();
    }
    summary.record_tcp_session_table_state(&sessions);
    Ok(summary)
}

fn run_managed_tun_packet_loop_inner_with_runtime_summary<C>(
    controller: &C,
    config: &TunDeviceConfig,
    runtime: &MixedProxyRuntime,
    dns_ttl_seconds: u32,
    max_packets: usize,
) -> Result<TunPacketLoopSummary, String>
where
    C: TunPacketIoController + ?Sized,
{
    let mut dns = runtime.dns_options.engine();
    let mut udp_relay_dns = runtime.dns_options.engine();
    let mut tcp_relay_dns = runtime.dns_options.engine();
    let timeout = runtime
        .relay_options
        .first_byte_timeout
        .unwrap_or(DEFAULT_FIRST_BYTE_TIMEOUT);
    let session_idle_timeout = runtime
        .relay_options
        .idle_timeout
        .unwrap_or(DEFAULT_IDLE_TIMEOUT);
    let mut udp_relay = RegistryTunUdpRelay::new(&runtime.outbounds, &mut udp_relay_dns, timeout);
    let mut tcp_relay =
        RegistryTunTcpSessionRelay::new(&runtime.outbounds, &mut tcp_relay_dns, timeout);
    let mut sessions =
        TunTcpSessionTable::with_max_active_sessions(runtime.tun_tcp_max_active_sessions);
    run_managed_tun_packet_loop_inner_with_relays(
        controller,
        config,
        &runtime.routes,
        &mut dns,
        dns_ttl_seconds,
        max_packets,
        &mut udp_relay,
        &mut sessions,
        &mut tcp_relay,
        session_idle_timeout,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_managed_tun_packet_loop_inner_with_relays<C, R, U, T>(
    controller: &C,
    config: &TunDeviceConfig,
    routes: &RouteEngine,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
    max_packets: usize,
    udp_relay: &mut U,
    sessions: &mut TunTcpSessionTable,
    tcp_relay: &mut T,
    session_idle_timeout: Duration,
) -> Result<TunPacketLoopSummary, String>
where
    C: TunPacketIoController + ?Sized,
    R: DnsResolver,
    U: TunUdpRelay,
    T: keli_net_core::TunTcpSessionRelay,
{
    let io = controller
        .open_packet_io(config)
        .map_err(|error| format!("open TUN packet I/O: {error}"))?;
    let mut device = PlatformTunPacketDevice::new(io);
    run_tun_packet_loop_with_relays_summary_with_idle_timeout(
        &mut device,
        routes,
        config.dns_hijack,
        dns,
        dns_ttl_seconds,
        max_packets,
        udp_relay,
        sessions,
        tcp_relay,
        DEFAULT_TUN_TCP_SERVER_INITIAL_SEQUENCE_NUMBER,
        DEFAULT_TUN_TCP_WINDOW_SIZE,
        session_idle_timeout,
    )
    .map_err(|error| format!("run TUN packet loop: {error}"))
}

fn run_managed_tun_packet_loop_inner_with_udp_relay<C, R, U>(
    controller: &C,
    config: &TunDeviceConfig,
    routes: &RouteEngine,
    dns: &mut DnsEngine<R>,
    dns_ttl_seconds: u32,
    max_packets: usize,
    udp_relay: &mut U,
) -> Result<TunPacketLoopSummary, String>
where
    C: TunPacketIoController + ?Sized,
    R: DnsResolver,
    U: TunUdpRelay,
{
    let io = controller
        .open_packet_io(config)
        .map_err(|error| format!("open TUN packet I/O: {error}"))?;
    let mut device = PlatformTunPacketDevice::new(io);
    run_tun_packet_loop_with_udp_relay_summary(
        &mut device,
        routes,
        config.dns_hijack,
        dns,
        dns_ttl_seconds,
        max_packets,
        udp_relay,
    )
    .map_err(|error| format!("run TUN packet loop: {error}"))
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
                    packet_io_available: preflight.status.packet_io_available,
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
    tun_tcp_max_active_sessions: usize,
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
    tun_tcp_max_active_sessions: usize,
    node_health: HashMap<String, ManagedNodeHealthStatus>,
    last_subscription_url_update: Option<ManagedSubscriptionUrlUpdateStatus>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<io::Result<RuntimeManagedMixedStopDrainDiagnostic>>>,
    system_proxy_guard: Option<ManagedSystemProxyGuard<'a, C>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedMixedStatusSnapshot {
    pub status: RuntimeStatus,
    pub listen_addr: Option<SocketAddr>,
    pub selected_outbound: Option<String>,
    pub generation: u64,
    pub started_at: Option<SystemTime>,
    pub uptime: Option<Duration>,
    pub connection_metrics: ConnectionMetricsSnapshot,
    pub event_count: usize,
    pub retained_event_count: usize,
    pub event_history_limit: usize,
    pub recent_event_limit: usize,
    pub recent_events: Vec<RuntimeEvent>,
    pub last_error: Option<ClientErrorKind>,
    pub system_proxy: Option<SystemProxyConfig>,
    pub subscription: Option<ManagedSubscriptionStatus>,
    pub last_subscription_url_update: Option<ManagedSubscriptionUrlUpdateStatus>,
    pub dns_options: MixedDnsOptions,
    pub tun_tcp_max_active_sessions: usize,
    pub max_connection_workers: usize,
    pub active_connection_workers: usize,
    pub peak_connection_workers: usize,
    pub active_client_connections: usize,
    pub peak_client_connections: usize,
    pub available_connection_worker_slots: usize,
    pub panel_state: Option<PanelState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSubscriptionUpdateOutcome {
    pub report: SubscriptionUpdateReport,
    pub status: ManagedMixedStatusSnapshot,
    pub applied: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSubscriptionUrlUpdateOutcome {
    pub fetch: ManagedSubscriptionUrlFetchOutcome,
    pub update: Option<SubscriptionUpdateReport>,
    pub status: ManagedMixedStatusSnapshot,
    pub applied: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSubscriptionUrlUpdateStatus {
    pub at: SystemTime,
    pub fetch: ManagedSubscriptionUrlFetchOutcome,
    pub update: Option<SubscriptionUpdateReport>,
    pub applied: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSubscriptionUrlFetchOutcome {
    pub ok: bool,
    pub source: Option<ManagedSubscriptionUrlSource>,
    pub http_status: Option<u16>,
    pub body_bytes: Option<usize>,
    pub elapsed: Option<Duration>,
    pub error_kind: Option<String>,
    pub error_detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSubscriptionUrlSource {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub default_port: bool,
    pub path_present: bool,
    pub query_present: bool,
}

impl ManagedSubscriptionUrlUpdateStatus {
    fn new(
        fetch: ManagedSubscriptionUrlFetchOutcome,
        update: Option<SubscriptionUpdateReport>,
        applied: bool,
        error: Option<String>,
    ) -> Self {
        Self {
            at: SystemTime::now(),
            fetch,
            update,
            applied,
            error,
        }
    }
}

impl ManagedSubscriptionUrlFetchOutcome {
    fn from_response(response: &SubscriptionFetchResponse) -> Self {
        Self {
            ok: true,
            source: Some(ManagedSubscriptionUrlSource::from_fetch_source(
                &response.source,
            )),
            http_status: Some(response.status_code),
            body_bytes: Some(response.body_bytes),
            elapsed: Some(response.elapsed),
            error_kind: None,
            error_detail: None,
        }
    }

    fn from_error(error: &SubscriptionFetchError) -> Self {
        Self {
            ok: false,
            source: error
                .source
                .as_ref()
                .map(ManagedSubscriptionUrlSource::from_fetch_source),
            http_status: None,
            body_bytes: None,
            elapsed: None,
            error_kind: Some(error.kind.label().to_string()),
            error_detail: Some(error.detail.clone()),
        }
    }
}

impl ManagedSubscriptionUrlSource {
    fn from_fetch_source(source: &SubscriptionFetchSource) -> Self {
        Self {
            scheme: source.scheme.clone(),
            host: source.host.clone(),
            port: source.port,
            default_port: source.default_port,
            path_present: source.path_present,
            query_present: source.query_present,
        }
    }

    fn label(&self) -> String {
        format!(
            "{}://{}:{} default_port={} path_present={} query_present={}",
            self.scheme,
            self.host,
            self.port,
            self.default_port,
            self.path_present,
            self.query_present
        )
    }
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
    pub node_count: usize,
    pub healthy_count: usize,
    pub unhealthy_count: usize,
    pub unknown_count: usize,
    pub checked_count: usize,
    pub unchecked_count: usize,
    pub udp_available_count: usize,
    pub udp_unavailable_count: usize,
    pub udp_unknown_count: usize,
    pub last_checked_at: Option<SystemTime>,
    pub selected_state: Option<ManagedNodeHealthState>,
    pub recommended_state: Option<ManagedNodeHealthState>,
    pub selected_udp_available: Option<bool>,
    pub recommended_udp_available: Option<bool>,
    pub recommended_is_selected: bool,
    pub switch_recommended: bool,
    pub selected_outbound_healthy: bool,
    pub recommended_outbound_healthy: bool,
    pub recommended_switch_ready: bool,
    pub recommended_switch_reason: ManagedRecommendedSwitchReason,
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
        let mut udp_available_count = 0;
        let mut udp_unavailable_count = 0;
        let mut udp_unknown_count = 0;
        let mut last_checked_at = None;
        let node_count = node_health.len();

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
            match health.udp_available {
                Some(true) => udp_available_count += 1,
                Some(false) => udp_unavailable_count += 1,
                None => udp_unknown_count += 1,
            }
        }
        let selected_health = node_health
            .iter()
            .find(|health| health.tag == selected_outbound);
        let recommended_health = node_health
            .iter()
            .find(|health| health.tag == recommended_outbound);
        let selected_state = selected_health.map(|health| health.state.clone());
        let recommended_state = recommended_health.map(|health| health.state.clone());
        let selected_udp_available = selected_health.and_then(|health| health.udp_available);
        let recommended_udp_available = recommended_health.and_then(|health| health.udp_available);
        let recommended_is_selected = selected_outbound == recommended_outbound;
        let selected_outbound_healthy = matches!(
            selected_state.as_ref(),
            Some(ManagedNodeHealthState::Healthy)
        );
        let recommended_outbound_healthy = matches!(
            recommended_state.as_ref(),
            Some(ManagedNodeHealthState::Healthy)
        );
        let recommended_switch_ready = !recommended_is_selected && recommended_outbound_healthy;
        let recommended_switch_reason = if recommended_switch_ready {
            ManagedRecommendedSwitchReason::Ready
        } else if recommended_is_selected && selected_outbound_healthy {
            ManagedRecommendedSwitchReason::AlreadySelected
        } else if recommended_is_selected {
            ManagedRecommendedSwitchReason::NoReadyAlternative
        } else {
            ManagedRecommendedSwitchReason::RecommendedNotHealthy
        };
        let unchecked_count = node_count.saturating_sub(checked_count);

        Self {
            node_count,
            healthy_count,
            unhealthy_count,
            unknown_count,
            checked_count,
            unchecked_count,
            udp_available_count,
            udp_unavailable_count,
            udp_unknown_count,
            last_checked_at,
            selected_state,
            recommended_state,
            selected_udp_available,
            recommended_udp_available,
            recommended_is_selected,
            switch_recommended: !recommended_is_selected,
            selected_outbound_healthy,
            recommended_outbound_healthy,
            recommended_switch_ready,
            recommended_switch_reason,
            fully_checked: unchecked_count == 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedRecommendedSwitchReason {
    Ready,
    AlreadySelected,
    NoReadyAlternative,
    RecommendedNotHealthy,
}

impl ManagedRecommendedSwitchReason {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::AlreadySelected => "already-selected",
            Self::NoReadyAlternative => "no-ready-alternative",
            Self::RecommendedNotHealthy => "recommended-not-healthy",
        }
    }
}

#[cfg(test)]
mod managed_subscription_health_summary_tests {
    use super::*;

    #[test]
    fn recommended_switch_reason_blocks_unhealthy_recommendation() {
        let health = vec![
            ManagedNodeHealthStatus::healthy("SS-READY", Some(50), true, true),
            ManagedNodeHealthStatus::unhealthy(
                "SS-BAD",
                ConnectionErrorKind::TcpConnectTimeout,
                Some("timeout".to_string()),
            ),
        ];

        let summary =
            ManagedSubscriptionHealthSummary::from_node_health(&health, "SS-READY", "SS-BAD");

        assert!(!summary.recommended_is_selected);
        assert!(!summary.recommended_outbound_healthy);
        assert!(!summary.recommended_switch_ready);
        assert_eq!(
            summary.recommended_switch_reason,
            ManagedRecommendedSwitchReason::RecommendedNotHealthy
        );
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
                managed_node_udp_recommendation_rank(health.udp_available),
                health.latency_ms.is_none(),
                health.latency_ms.unwrap_or(u128::MAX),
            )
        })
        .map(|health| health.tag.clone())
        .unwrap_or_else(|| selected_outbound.to_string())
}

fn managed_node_udp_recommendation_rank(udp_available: Option<bool>) -> u8 {
    match udp_available {
        Some(true) => 0,
        None => 1,
        Some(false) => 2,
    }
}

impl ManagedMixedStatusSnapshot {
    fn stopped(panel_state: Option<PanelState>) -> Self {
        Self {
            status: RuntimeStatus::Stopped,
            listen_addr: None,
            selected_outbound: None,
            generation: 0,
            started_at: None,
            uptime: None,
            connection_metrics: ConnectionMetricsSnapshot::default(),
            event_count: 0,
            retained_event_count: 0,
            event_history_limit: DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT,
            recent_event_limit: MANAGED_MIXED_RECENT_EVENT_LIMIT,
            recent_events: Vec::new(),
            last_error: None,
            system_proxy: None,
            subscription: None,
            last_subscription_url_update: None,
            dns_options: MixedDnsOptions::default(),
            tun_tcp_max_active_sessions: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
            max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
            active_connection_workers: 0,
            peak_connection_workers: 0,
            active_client_connections: 0,
            peak_client_connections: 0,
            available_connection_worker_slots: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
            panel_state,
        }
    }

    fn from_stopped_runtime(
        state: &ClientRuntime,
        previous: &ManagedMixedStatusSnapshot,
        panel_state: Option<PanelState>,
    ) -> Self {
        let recent_events: Vec<RuntimeEvent> = state
            .events()
            .iter()
            .rev()
            .take(MANAGED_MIXED_RECENT_EVENT_LIMIT)
            .cloned()
            .collect();
        Self {
            status: state.status().clone(),
            listen_addr: None,
            selected_outbound: None,
            generation: state.generation(),
            started_at: state.started_at(),
            uptime: state.uptime(),
            connection_metrics: previous.connection_metrics.clone(),
            event_count: state.event_count(),
            retained_event_count: state.events().len(),
            event_history_limit: DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT,
            recent_event_limit: MANAGED_MIXED_RECENT_EVENT_LIMIT,
            recent_events,
            last_error: state.last_error().cloned(),
            system_proxy: None,
            subscription: None,
            last_subscription_url_update: previous.last_subscription_url_update.clone(),
            dns_options: previous.dns_options,
            tun_tcp_max_active_sessions: previous.tun_tcp_max_active_sessions,
            max_connection_workers: previous.max_connection_workers,
            active_connection_workers: 0,
            peak_connection_workers: previous.peak_connection_workers,
            active_client_connections: 0,
            peak_client_connections: previous.peak_client_connections,
            available_connection_worker_slots: previous.max_connection_workers,
            panel_state,
        }
    }

    fn with_panel_state(mut self, panel_state: Option<PanelState>) -> Self {
        self.panel_state = panel_state;
        self
    }

    pub fn system_proxy_enabled(&self) -> bool {
        self.system_proxy.is_some()
    }
}

pub fn managed_mixed_status_json_value(status: &ManagedMixedStatusSnapshot) -> serde_json::Value {
    serde_json::json!({
        "schema_version": MANAGED_MIXED_STATUS_SCHEMA_VERSION,
        "status": runtime_status_json_value(&status.status),
        "listen_addr": status.listen_addr.map(|addr| addr.to_string()),
        "selected_outbound": status.selected_outbound.as_deref(),
        "generation": status.generation,
        "started_at_unix_ms": status.started_at.map(system_time_unix_ms),
        "uptime_ms": status.uptime.map(duration_millis),
        "connection_metrics": connection_metrics_json_value(&status.connection_metrics),
        "event_count": status.event_count,
        "retained_event_count": status.retained_event_count,
        "event_history_limit": status.event_history_limit,
        "recent_event_limit": status.recent_event_limit,
        "recent_events": status
            .recent_events
            .iter()
            .map(runtime_event_json_value)
            .collect::<Vec<_>>(),
        "last_error": status.last_error.as_ref().map(client_error_json_value),
        "system_proxy": status.system_proxy.as_ref().map(system_proxy_config_json_value),
        "subscription": status.subscription.as_ref().map(managed_subscription_status_json_value),
        "last_subscription_url_update": status
            .last_subscription_url_update
            .as_ref()
            .map(managed_subscription_url_update_status_json_value),
        "dns_options": mixed_dns_options_json_value(status.dns_options),
        "tun_tcp_max_active_sessions": status.tun_tcp_max_active_sessions,
        "max_connection_workers": status.max_connection_workers,
        "active_connection_workers": status.active_connection_workers,
        "peak_connection_workers": status.peak_connection_workers,
        "active_client_connections": status.active_client_connections,
        "peak_client_connections": status.peak_client_connections,
        "available_connection_worker_slots": status.available_connection_worker_slots,
        "panel_state": status.panel_state.as_ref().map(panel_state_json_value),
    })
}

pub fn managed_subscription_url_update_outcome_json_value(
    outcome: &ManagedSubscriptionUrlUpdateOutcome,
) -> serde_json::Value {
    serde_json::json!({
        "status": if outcome.applied { "ok" } else { "error" },
        "kind": "keli_managed_subscription_url_update",
        "applied": outcome.applied,
        "error": outcome.error.as_deref(),
        "fetch": managed_subscription_url_fetch_outcome_json_value(&outcome.fetch),
        "update": outcome.update.as_ref().map(subscription_update_json_value),
        "runtime_status": managed_mixed_status_json_value(&outcome.status),
        "redaction": {
            "source_url": "scheme-host-port-flags-only",
            "profile_config_text": "omitted",
            "credentials": "omitted",
            "server_endpoints": "omitted",
        },
    })
}

fn managed_subscription_url_update_status_json_value(
    status: &ManagedSubscriptionUrlUpdateStatus,
) -> serde_json::Value {
    serde_json::json!({
        "status": if status.applied { "ok" } else { "error" },
        "at_unix_ms": system_time_unix_ms(status.at),
        "applied": status.applied,
        "error": status.error.as_deref(),
        "fetch": managed_subscription_url_fetch_outcome_json_value(&status.fetch),
        "update": status.update.as_ref().map(subscription_update_json_value),
        "redaction": {
            "source_url": "scheme-host-port-flags-only",
            "profile_config_text": "omitted",
            "credentials": "omitted",
            "server_endpoints": "omitted",
        },
    })
}

fn managed_subscription_url_fetch_outcome_json_value(
    fetch: &ManagedSubscriptionUrlFetchOutcome,
) -> serde_json::Value {
    serde_json::json!({
        "status": if fetch.ok { "ok" } else { "error" },
        "source": fetch
            .source
            .as_ref()
            .map(managed_subscription_url_source_json_value),
        "http_status": fetch.http_status,
        "body_bytes": fetch.body_bytes,
        "elapsed_ms": fetch.elapsed.map(duration_millis),
        "error_kind": fetch.error_kind.as_deref(),
        "error_detail": fetch.error_detail.as_deref(),
    })
}

fn managed_subscription_url_source_json_value(
    source: &ManagedSubscriptionUrlSource,
) -> serde_json::Value {
    serde_json::json!({
        "scheme": &source.scheme,
        "host": &source.host,
        "port": source.port,
        "default_port": source.default_port,
        "path_present": source.path_present,
        "query_present": source.query_present,
    })
}

pub fn write_managed_mixed_status_json_report(
    status: &ManagedMixedStatusSnapshot,
    mut writer: impl Write,
) -> io::Result<()> {
    let value = managed_mixed_status_json_value(status);
    serde_json::to_writer_pretty(&mut writer, &value).map_err(io::Error::other)?;
    writeln!(writer)
}

fn runtime_status_json_value(status: &RuntimeStatus) -> serde_json::Value {
    match status {
        RuntimeStatus::Stopped => serde_json::json!({
            "state": "stopped",
        }),
        RuntimeStatus::Starting => serde_json::json!({
            "state": "starting",
        }),
        RuntimeStatus::Running {
            generation,
            selected_outbound,
            listen,
        } => serde_json::json!({
            "state": "running",
            "generation": generation,
            "selected_outbound": selected_outbound,
            "listen": listen,
        }),
        RuntimeStatus::Reloading { generation } => serde_json::json!({
            "state": "reloading",
            "generation": generation,
        }),
        RuntimeStatus::Stopping { generation } => serde_json::json!({
            "state": "stopping",
            "generation": generation,
        }),
        RuntimeStatus::Failed(error) => serde_json::json!({
            "state": "failed",
            "error": client_error_json_value(error),
        }),
    }
}

fn runtime_event_json_value(event: &RuntimeEvent) -> serde_json::Value {
    serde_json::json!({
        "status": runtime_status_json_value(&event.status),
        "note": event.note.as_deref(),
        "diagnostic": event.diagnostic.as_ref().map(runtime_diagnostic_json_value),
        "at_unix_ms": system_time_unix_ms(event.at),
    })
}

fn runtime_diagnostic_json_value(diagnostic: &RuntimeDiagnostic) -> serde_json::Value {
    match diagnostic {
        RuntimeDiagnostic::TunPacketLoop(diagnostic) => serde_json::json!({
            "kind": "tun-packet-loop",
            "interface_name": &diagnostic.interface_name,
            "owns_device": diagnostic.owns_device,
            "processed_packets": diagnostic.processed_packets,
            "idle_events": diagnostic.idle_events,
            "exit_reason": &diagnostic.exit_reason,
            "stop_requested": diagnostic.stop_requested,
            "packet_limit_reached": diagnostic.packet_limit_reached,
            "dns_responses_written": diagnostic.dns_responses_written,
            "udp_relay_responses_written": diagnostic.udp_relay_responses_written,
            "tcp_resets_written": diagnostic.tcp_resets_written,
            "tcp_session_events": diagnostic.tcp_session_events,
            "tcp_session_packets_written": diagnostic.tcp_session_packets_written,
            "tcp_max_active_sessions": diagnostic.tcp_max_active_sessions,
            "tcp_session_limit_rejections": diagnostic.tcp_session_limit_rejections,
            "tcp_sessions_pruned": diagnostic.tcp_sessions_pruned,
            "tcp_server_closed_sessions_pruned": diagnostic.tcp_server_closed_sessions_pruned,
            "tcp_post_closed_sessions_pruned": diagnostic.tcp_post_closed_sessions_pruned,
            "tcp_server_close_marker_resets": diagnostic.tcp_server_close_marker_resets,
            "tcp_post_close_marker_resets": diagnostic.tcp_post_close_marker_resets,
            "tcp_sessions_open": diagnostic.tcp_sessions_open,
            "tcp_server_close_markers_open": diagnostic.tcp_server_close_markers_open,
            "tcp_post_close_markers_open": diagnostic.tcp_post_close_markers_open,
            "tcp_sessions_peak": diagnostic.tcp_sessions_peak,
            "tcp_server_close_markers_peak": diagnostic.tcp_server_close_markers_peak,
            "tcp_post_close_markers_peak": diagnostic.tcp_post_close_markers_peak,
            "relay_packets": diagnostic.relay_packets,
            "tcp_relay_plans": diagnostic.tcp_relay_plans,
            "udp_relay_plans": diagnostic.udp_relay_plans,
            "dropped_packets": diagnostic.dropped_packets,
            "unsupported_packets": diagnostic.unsupported_packets,
            "packet_errors": diagnostic.packet_errors,
            "udp_relay_errors": diagnostic.udp_relay_errors,
            "tcp_session_errors": diagnostic.tcp_session_errors,
            "last_packet_error": diagnostic.last_packet_error.as_deref(),
            "last_udp_relay_error": diagnostic.last_udp_relay_error.as_deref(),
            "last_tcp_session_error": diagnostic.last_tcp_session_error.as_deref(),
        }),
        RuntimeDiagnostic::ManagedMixedStopDrain(diagnostic) => serde_json::json!({
            "kind": "managed-mixed-stop-drain",
            "active_connections_shutdown": diagnostic.active_connections_shutdown,
            "workers_before_shutdown": diagnostic.workers_before_shutdown,
            "workers_drained": diagnostic.workers_drained,
            "workers_remaining": diagnostic.workers_remaining,
            "drain_elapsed_ms": diagnostic.drain_elapsed_ms,
            "drain_timeout_ms": diagnostic.drain_timeout_ms,
            "timed_out": diagnostic.timed_out,
        }),
        RuntimeDiagnostic::ManagedNodeProbeSweep(diagnostic) => serde_json::json!({
            "kind": "managed-node-probe-sweep",
            "target": &diagnostic.target,
            "inbound": &diagnostic.inbound,
            "elapsed_ms": diagnostic.elapsed_ms,
            "attempted_nodes": diagnostic.attempted_nodes,
            "successful_probes": diagnostic.successful_probes,
            "failed_probes": diagnostic.failed_probes,
            "node_count": diagnostic.node_count,
            "healthy_count": diagnostic.healthy_count,
            "unhealthy_count": diagnostic.unhealthy_count,
            "unknown_count": diagnostic.unknown_count,
            "checked_count": diagnostic.checked_count,
            "unchecked_count": diagnostic.unchecked_count,
            "selected_outbound": &diagnostic.selected_outbound,
            "recommended_outbound": &diagnostic.recommended_outbound,
            "recommended_switch_ready": diagnostic.recommended_switch_ready,
            "recommended_switch_reason": &diagnostic.recommended_switch_reason,
        }),
    }
}

fn client_error_json_value(error: &ClientErrorKind) -> serde_json::Value {
    match error {
        ClientErrorKind::CoreNotStarted => serde_json::json!({
            "kind": "core-not-started",
        }),
        ClientErrorKind::DnsTimeout => serde_json::json!({
            "kind": "dns-timeout",
        }),
        ClientErrorKind::TcpConnectTimeout => serde_json::json!({
            "kind": "tcp-connect-timeout",
        }),
        ClientErrorKind::TlsHandshakeFailed => serde_json::json!({
            "kind": "tls-handshake-failed",
        }),
        ClientErrorKind::WebSocketUpgradeFailed => serde_json::json!({
            "kind": "websocket-upgrade-failed",
        }),
        ClientErrorKind::ProxyAuthFailed => serde_json::json!({
            "kind": "proxy-auth-failed",
        }),
        ClientErrorKind::RelayStalled => serde_json::json!({
            "kind": "relay-stalled",
        }),
        ClientErrorKind::TunPermissionMissing => serde_json::json!({
            "kind": "tun-permission-missing",
        }),
        ClientErrorKind::SystemProxyLoop => serde_json::json!({
            "kind": "system-proxy-loop",
        }),
        ClientErrorKind::RouteNoOutbound => serde_json::json!({
            "kind": "route-no-outbound",
        }),
        ClientErrorKind::NoSupportedOutbounds => serde_json::json!({
            "kind": "no-supported-outbounds",
        }),
        ClientErrorKind::OutboundNotFound(tag) => serde_json::json!({
            "kind": "outbound-not-found",
            "tag": tag,
        }),
        ClientErrorKind::PanelTrafficRestricted {
            account_state,
            risk_control,
        } => serde_json::json!({
            "kind": "panel-traffic-restricted",
            "account_state": account_state,
            "risk_control": risk_control,
        }),
        ClientErrorKind::ConfigInvalid(detail) => serde_json::json!({
            "kind": "config-invalid",
            "detail": detail,
        }),
    }
}

fn system_proxy_config_json_value(config: &SystemProxyConfig) -> serde_json::Value {
    serde_json::json!({
        "server": &config.server,
        "bypass": &config.bypass,
    })
}

fn managed_subscription_status_json_value(status: &ManagedSubscriptionStatus) -> serde_json::Value {
    serde_json::json!({
        "usable": status.usable,
        "supported_count": status.supported_count(),
        "skipped_count": status.skipped_count(),
        "supported_tags": &status.supported_tags,
        "supported": status
            .supported
            .iter()
            .map(subscription_node_capability_json_value)
            .collect::<Vec<_>>(),
        "skipped": status
            .skipped
            .iter()
            .map(skipped_profile_summary_json_value)
            .collect::<Vec<_>>(),
        "default_outbound": status.default_outbound.as_deref(),
        "selected_outbound": &status.selected_outbound,
        "recommended_outbound": &status.recommended_outbound,
        "health_summary": managed_subscription_health_summary_json_value(&status.health_summary),
        "node_health": status
            .node_health
            .iter()
            .map(managed_node_health_status_json_value)
            .collect::<Vec<_>>(),
    })
}

fn subscription_node_capability_json_value(
    capability: &SubscriptionNodeCapability,
) -> serde_json::Value {
    serde_json::json!({
        "tag": &capability.tag,
        "protocol": &capability.protocol,
        "transport": &capability.transport,
        "security": &capability.security,
        "tls_skip_verify": capability.tls_skip_verify,
        "udp_supported": capability.udp_supported,
    })
}

fn skipped_profile_summary_json_value(summary: &SkippedProfileSummary) -> serde_json::Value {
    serde_json::json!({
        "name": &summary.name,
        "reason": &summary.reason,
    })
}

fn managed_subscription_health_summary_json_value(
    summary: &ManagedSubscriptionHealthSummary,
) -> serde_json::Value {
    serde_json::json!({
        "node_count": summary.node_count,
        "healthy_count": summary.healthy_count,
        "unhealthy_count": summary.unhealthy_count,
        "unknown_count": summary.unknown_count,
        "checked_count": summary.checked_count,
        "unchecked_count": summary.unchecked_count,
        "udp_available_count": summary.udp_available_count,
        "udp_unavailable_count": summary.udp_unavailable_count,
        "udp_unknown_count": summary.udp_unknown_count,
        "last_checked_at_unix_ms": summary.last_checked_at.map(system_time_unix_ms),
        "selected_state": summary.selected_state.as_ref().map(ManagedNodeHealthState::label),
        "recommended_state": summary.recommended_state.as_ref().map(ManagedNodeHealthState::label),
        "selected_udp_available": summary.selected_udp_available,
        "recommended_udp_available": summary.recommended_udp_available,
        "recommended_is_selected": summary.recommended_is_selected,
        "switch_recommended": summary.switch_recommended,
        "selected_outbound_healthy": summary.selected_outbound_healthy,
        "recommended_outbound_healthy": summary.recommended_outbound_healthy,
        "recommended_switch_ready": summary.recommended_switch_ready,
        "recommended_switch_reason": summary.recommended_switch_reason.label(),
        "fully_checked": summary.fully_checked,
    })
}

fn managed_node_health_status_json_value(health: &ManagedNodeHealthStatus) -> serde_json::Value {
    serde_json::json!({
        "tag": &health.tag,
        "state": health.state.label(),
        "tcp_available": health.tcp_available,
        "udp_available": health.udp_available,
        "latency_ms": health.latency_ms.map(saturating_u128_to_u64),
        "error_kind": health.error_kind.as_ref().map(|kind| format!("{kind:?}")),
        "error_detail": health.error_detail.as_deref(),
        "checked_at_unix_ms": health.checked_at.map(system_time_unix_ms),
    })
}

fn connection_metrics_json_value(metrics: &ConnectionMetricsSnapshot) -> serde_json::Value {
    let error_kind_counts = metrics
        .error_kind_counts
        .iter()
        .map(|entry| {
            (
                entry.error_kind.as_str().to_string(),
                serde_json::json!(entry.count),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let route_action_counts = metrics
        .route_action_counts
        .iter()
        .map(|entry| {
            serde_json::json!({
                "route_action": route_action_json_value(&entry.route_action),
                "count": entry.count,
            })
        })
        .collect::<Vec<_>>();
    let inbound_counts = metrics
        .inbound_counts
        .iter()
        .map(|entry| {
            serde_json::json!({
                "inbound": &entry.inbound,
                "count": entry.count,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "total_connection_count": metrics.total_connection_count,
        "success_count": metrics.success_count,
        "failure_count": metrics.failure_count,
        "connection_limit_rejection_count": metrics.connection_limit_rejection_count,
        "error_kind_counts": error_kind_counts,
        "route_action_counts": route_action_counts,
        "inbound_counts": inbound_counts,
        "total_upload_bytes": metrics.total_upload_bytes,
        "total_download_bytes": metrics.total_download_bytes,
        "total_connect_ms": saturating_u128_to_u64(metrics.total_connect_ms),
        "timed_connect_count": metrics.timed_connect_count,
        "average_connect_ms": average_duration_ms(
            metrics.total_connect_ms,
            metrics.timed_connect_count
        ),
        "total_first_byte_ms": saturating_u128_to_u64(metrics.total_first_byte_ms),
        "timed_first_byte_count": metrics.timed_first_byte_count,
        "average_first_byte_ms": average_duration_ms(
            metrics.total_first_byte_ms,
            metrics.timed_first_byte_count
        ),
        "last_connection_at_unix_ms": metrics.last_connection_at.map(system_time_unix_ms),
        "last_success_at_unix_ms": metrics.last_success_at.map(system_time_unix_ms),
        "last_failure_at_unix_ms": metrics.last_failure_at.map(system_time_unix_ms),
        "retained_connection_count": metrics.retained_connection_count,
        "connection_history_limit": metrics.connection_history_limit,
        "recent_connections": metrics
            .recent_connections
            .iter()
            .map(connection_report_json_value)
            .collect::<Vec<_>>(),
    })
}

fn route_action_sort_key(action: &RouteAction) -> String {
    match action {
        RouteAction::Direct => "0:direct".to_string(),
        RouteAction::Block => "1:block".to_string(),
        RouteAction::HijackDns => "2:hijack-dns".to_string(),
        RouteAction::Outbound(tag) => format!("3:outbound:{tag}"),
    }
}

fn average_duration_ms(total_ms: u128, count: u64) -> Option<u64> {
    if count == 0 {
        None
    } else {
        Some(saturating_u128_to_u64(total_ms / u128::from(count)))
    }
}

fn connection_report_json_value(report: &ConnectionReport) -> serde_json::Value {
    serde_json::json!({
        "inbound": &report.inbound,
        "target": {
            "host": &report.target.host,
            "port": report.target.port,
        },
        "route_action": route_action_json_value(&report.route_action),
        "connect_ms": report.connect_ms.map(saturating_u128_to_u64),
        "first_byte_ms": report.first_byte_ms.map(saturating_u128_to_u64),
        "upload_bytes": report.upload_bytes,
        "download_bytes": report.download_bytes,
        "error_kind": report.error_kind.map(ConnectionErrorKind::as_str),
        "error_detail": report.error_detail.as_deref(),
    })
}

fn route_action_json_value(action: &RouteAction) -> serde_json::Value {
    match action {
        RouteAction::Direct => serde_json::json!({
            "kind": "direct",
        }),
        RouteAction::Block => serde_json::json!({
            "kind": "block",
        }),
        RouteAction::Outbound(tag) => serde_json::json!({
            "kind": "outbound",
            "tag": tag,
        }),
        RouteAction::HijackDns => serde_json::json!({
            "kind": "hijack-dns",
        }),
    }
}

fn mixed_dns_options_json_value(options: MixedDnsOptions) -> serde_json::Value {
    serde_json::json!({
        "local_resolution_policy": options.local_resolution_label(),
        "address_family_policy": options.address_family_label(),
        "cache_ttl_ms": saturating_u128_to_u64(options.cache_ttl.as_millis()),
    })
}

fn panel_state_json_value(panel_state: &PanelState) -> serde_json::Value {
    serde_json::json!({
        "account_state": panel_state.user.account_state.label(),
        "used_bytes": panel_state.user.used_bytes,
        "total_bytes": panel_state.user.total_bytes,
        "traffic_used_per_mille": panel_state.user.traffic_used_per_mille(),
        "quota_exhausted": panel_state.user.quota_exhausted(),
        "expires_at_unix_ms": panel_state.user.expires_at.map(system_time_unix_ms),
        "risk_control": panel_state.risk_control.label(),
        "updated_at_unix_ms": system_time_unix_ms(panel_state.updated_at),
        "support_note": panel_state.support_note.as_deref(),
        "restrict_traffic": panel_state.should_restrict_traffic(),
    })
}

fn system_time_unix_ms(at: SystemTime) -> u64 {
    let millis = at
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    saturating_u128_to_u64(millis)
}

fn duration_millis(duration: Duration) -> u64 {
    saturating_u128_to_u64(duration.as_millis())
}

fn saturating_u128_to_u64(value: u128) -> u64 {
    value.min(u128::from(u64::MAX)) as u64
}

#[derive(Debug)]
pub struct ManagedMixedController<'a, C: SystemProxyController + ?Sized> {
    controller: &'a C,
    handle: Option<ManagedMixedHandle<'a, C>>,
    last_stopped_status: Option<ManagedMixedStatusSnapshot>,
    panel_state: Option<PanelState>,
}

impl<'a, C: SystemProxyController + ?Sized> ManagedMixedController<'a, C> {
    pub fn new(controller: &'a C) -> Self {
        Self {
            controller,
            handle: None,
            last_stopped_status: None,
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
            .or_else(|| {
                self.last_stopped_status
                    .as_ref()
                    .map(|status| status.clone().with_panel_state(self.panel_state.clone()))
            })
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
        self.last_stopped_status = None;
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

    pub fn reload_from_subscription_config_text_with_update_plan(
        &mut self,
        config_text: &str,
    ) -> Result<ManagedSubscriptionUpdateOutcome, String> {
        self.ensure_panel_allows_traffic()?;
        let (report, applied, error) = {
            let handle = self
                .handle
                .as_mut()
                .ok_or_else(|| "managed mixed core is not running".to_string())?;
            handle.reload_from_subscription_config_text_with_update_plan(config_text)?
        };
        Ok(ManagedSubscriptionUpdateOutcome {
            report,
            status: self.status(),
            applied,
            error,
        })
    }

    pub fn reload_from_subscription_url_with_update_plan(
        &mut self,
        url: &str,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<ManagedSubscriptionUrlUpdateOutcome, String> {
        self.ensure_panel_allows_traffic()?;
        if self.handle.is_none() {
            return Err("managed mixed core is not running".to_string());
        }

        let fetch_result =
            fetch_subscription_config_text(&subscription_fetch_options(url, timeout, max_bytes));
        match fetch_result {
            Ok(response) => {
                let fetch = ManagedSubscriptionUrlFetchOutcome::from_response(&response);
                match self.reload_from_subscription_config_text_with_update_plan(&response.body) {
                    Ok(update) => {
                        let url_update_status = ManagedSubscriptionUrlUpdateStatus::new(
                            fetch.clone(),
                            Some(update.report.clone()),
                            update.applied,
                            update.error.clone(),
                        );
                        if let Some(handle) = self.handle.as_mut() {
                            handle.record_subscription_url_update_status(url_update_status);
                        }
                        Ok(ManagedSubscriptionUrlUpdateOutcome {
                            fetch,
                            update: Some(update.report),
                            status: self.status(),
                            applied: update.applied,
                            error: update.error,
                        })
                    }
                    Err(error) => {
                        let url_update_status = ManagedSubscriptionUrlUpdateStatus::new(
                            fetch.clone(),
                            None,
                            false,
                            Some(error.clone()),
                        );
                        if let Some(handle) = self.handle.as_mut() {
                            handle.record_subscription_url_update_status(url_update_status);
                        }
                        Ok(ManagedSubscriptionUrlUpdateOutcome {
                            fetch,
                            update: None,
                            status: self.status(),
                            applied: false,
                            error: Some(error),
                        })
                    }
                }
            }
            Err(error) => {
                let fetch = ManagedSubscriptionUrlFetchOutcome::from_error(&error);
                let error_message = format!(
                    "subscription URL fetch failed: {}",
                    fetch.error_kind.as_deref().unwrap_or("unknown")
                );
                let url_update_status = ManagedSubscriptionUrlUpdateStatus::new(
                    fetch.clone(),
                    None,
                    false,
                    Some(error_message.clone()),
                );
                if let Some(handle) = self.handle.as_mut() {
                    handle
                        .record_subscription_url_fetch_rejected(&url_update_status, &error_message);
                }
                Ok(ManagedSubscriptionUrlUpdateOutcome {
                    fetch,
                    update: None,
                    status: self.status(),
                    applied: false,
                    error: Some(error_message),
                })
            }
        }
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
        let pre_stop_status =
            ManagedMixedStatusSnapshot::from_handle(&handle, self.panel_state.clone());
        let state = handle.stop()?;
        self.last_stopped_status = Some(ManagedMixedStatusSnapshot::from_stopped_runtime(
            &state,
            &pre_stop_status,
            self.panel_state.clone(),
        ));
        Ok(state)
    }
}

impl ManagedMixedStatusSnapshot {
    fn from_handle<C: SystemProxyController + ?Sized>(
        handle: &ManagedMixedHandle<'_, C>,
        panel_state: Option<PanelState>,
    ) -> Self {
        let recent_events: Vec<RuntimeEvent> = handle
            .events()
            .iter()
            .rev()
            .take(MANAGED_MIXED_RECENT_EVENT_LIMIT)
            .cloned()
            .collect();
        Self {
            status: handle.status().clone(),
            listen_addr: Some(handle.listen_addr()),
            selected_outbound: handle.selected_outbound().map(str::to_string),
            generation: handle.generation(),
            started_at: handle.started_at(),
            uptime: handle.uptime(),
            connection_metrics: handle.connection_metrics_snapshot(),
            event_count: handle.event_count(),
            retained_event_count: handle.events().len(),
            event_history_limit: DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT,
            recent_event_limit: MANAGED_MIXED_RECENT_EVENT_LIMIT,
            recent_events,
            last_error: handle.last_error().cloned(),
            system_proxy: handle.system_proxy_config().cloned(),
            subscription: handle.subscription_status(),
            last_subscription_url_update: handle.last_subscription_url_update.clone(),
            dns_options: handle.dns_options,
            tun_tcp_max_active_sessions: handle.tun_tcp_max_active_sessions,
            max_connection_workers: handle.max_connection_workers(),
            active_connection_workers: handle.active_connection_workers(),
            peak_connection_workers: handle.peak_connection_workers(),
            active_client_connections: handle.active_client_connections(),
            peak_client_connections: handle.peak_client_connections(),
            available_connection_worker_slots: handle.available_connection_worker_slots(),
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

    pub fn started_at(&self) -> Option<SystemTime> {
        self.state.started_at()
    }

    pub fn uptime(&self) -> Option<Duration> {
        self.state.uptime()
    }

    pub fn connection_metrics_snapshot(&self) -> ConnectionMetricsSnapshot {
        self.runtime
            .read()
            .map(|runtime| runtime.connection_metrics_snapshot())
            .unwrap_or_default()
    }

    pub fn max_connection_workers(&self) -> usize {
        self.runtime
            .read()
            .map(|runtime| runtime.max_connection_workers)
            .unwrap_or(DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS)
    }

    pub fn active_connection_workers(&self) -> usize {
        self.runtime
            .read()
            .map(|runtime| runtime.active_connection_workers())
            .unwrap_or(0)
    }

    pub fn peak_connection_workers(&self) -> usize {
        self.runtime
            .read()
            .map(|runtime| runtime.peak_connection_workers())
            .unwrap_or(0)
    }

    pub fn active_client_connections(&self) -> usize {
        self.runtime
            .read()
            .map(|runtime| runtime.active_client_connections())
            .unwrap_or(0)
    }

    pub fn peak_client_connections(&self) -> usize {
        self.runtime
            .read()
            .map(|runtime| runtime.peak_client_connections())
            .unwrap_or(0)
    }

    pub fn available_connection_worker_slots(&self) -> usize {
        self.runtime
            .read()
            .map(|runtime| runtime.available_connection_worker_slots())
            .unwrap_or(DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS)
    }

    pub fn event_count(&self) -> usize {
        self.state.event_count()
    }

    pub fn last_error(&self) -> Option<&ClientErrorKind> {
        self.state.last_error()
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

    fn record_subscription_url_fetch_rejected(
        &mut self,
        status: &ManagedSubscriptionUrlUpdateStatus,
        error_message: &str,
    ) {
        self.state
            .record_reload_rejected(ClientErrorKind::ConfigInvalid(error_message.to_string()));
        self.state.record_status_note(format!(
            "subscription URL update rejected: fetch_status=error error_kind={} source={}",
            status.fetch.error_kind.as_deref().unwrap_or("unknown"),
            status
                .fetch
                .source
                .as_ref()
                .map(ManagedSubscriptionUrlSource::label)
                .unwrap_or_else(|| "-".to_string())
        ));
        self.last_subscription_url_update = Some(status.clone());
    }

    fn record_subscription_url_update_status(
        &mut self,
        status: ManagedSubscriptionUrlUpdateStatus,
    ) {
        let fetch_status = if status.fetch.ok { "ok" } else { "error" };
        let update_reason = status
            .update
            .as_ref()
            .map(|report| report.reason.label())
            .unwrap_or("-");
        self.state.record_status_note(format!(
            "subscription URL update status recorded: fetch_status={} applied={} update_reason={} source={}",
            fetch_status,
            status.applied,
            update_reason,
            status
                .fetch
                .source
                .as_ref()
                .map(ManagedSubscriptionUrlSource::label)
                .unwrap_or_else(|| "-".to_string())
        ));
        self.last_subscription_url_update = Some(status);
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
                let udp_available = if let Some(udp_probe) = options.udp_probe {
                    let mut udp_output = Vec::new();
                    Some(
                        probe_outbound_from_subscription_config_text_with_format(
                            &config_text,
                            Some(options.outbound_tag.clone()),
                            &udp_probe.target,
                            &udp_probe.payload,
                            Some(&udp_probe.expect),
                            true,
                            options.first_byte_timeout,
                            ProbeOutputFormat::Json,
                            &mut udp_output,
                        )
                        .is_ok(),
                    )
                } else {
                    options.udp_available
                };
                self.set_node_health(ManagedNodeHealthStatus {
                    tag: options.outbound_tag,
                    state: ManagedNodeHealthState::Healthy,
                    tcp_available: Some(true),
                    udp_available,
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
        let sweep_started = Instant::now();
        let target = options.target.clone();
        let inbound = options.inbound.label().to_string();
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
        let attempted_nodes = tags.len();
        let mut successful_probes = 0;
        let mut failed_probes = 0;
        for outbound_tag in tags {
            match self.probe_node_health(ManagedNodeProbeOptions {
                outbound_tag,
                target: options.target.clone(),
                payload: options.payload.clone(),
                expect: options.expect.clone(),
                inbound: options.inbound,
                first_byte_timeout: options.first_byte_timeout,
                udp_available: options.udp_available,
                udp_probe: options.udp_probe.clone(),
            }) {
                Ok(()) => successful_probes += 1,
                Err(_) => failed_probes += 1,
            }
        }
        if let Some(status) = self.subscription_status() {
            let summary = &status.health_summary;
            self.state.record_status_diagnostic(
                format!(
                    "node health sweep completed: target={} inbound={} attempted={} success={} failure={} healthy={} unhealthy={} unknown={} recommended={} switch_ready={} reason={}",
                    target,
                    inbound,
                    attempted_nodes,
                    successful_probes,
                    failed_probes,
                    summary.healthy_count,
                    summary.unhealthy_count,
                    summary.unknown_count,
                    status.recommended_outbound,
                    summary.recommended_switch_ready,
                    summary.recommended_switch_reason.label()
                ),
                RuntimeDiagnostic::ManagedNodeProbeSweep(RuntimeManagedNodeProbeSweepDiagnostic {
                    target,
                    inbound,
                    elapsed_ms: duration_millis(sweep_started.elapsed()),
                    attempted_nodes,
                    successful_probes,
                    failed_probes,
                    node_count: summary.node_count,
                    healthy_count: summary.healthy_count,
                    unhealthy_count: summary.unhealthy_count,
                    unknown_count: summary.unknown_count,
                    checked_count: summary.checked_count,
                    unchecked_count: summary.unchecked_count,
                    selected_outbound: status.selected_outbound,
                    recommended_outbound: status.recommended_outbound,
                    recommended_switch_ready: summary.recommended_switch_ready,
                    recommended_switch_reason: summary.recommended_switch_reason.label().to_string(),
                }),
            );
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
        let (
            selected_outbound,
            recommended_outbound,
            recommended_switch_ready,
            recommended_switch_reason,
        ) = {
            let plan = self
                .state
                .active_plan()
                .ok_or_else(|| "managed mixed core has no active subscription".to_string())?;
            let status = ManagedSubscriptionStatus::from_plan(plan, &self.node_health);
            (
                plan.selected_outbound().to_string(),
                status.recommended_outbound.clone(),
                status.health_summary.recommended_switch_ready,
                status.health_summary.recommended_switch_reason.label(),
            )
        };
        if !recommended_switch_ready {
            self.state.record_status_note(format!(
                "recommended outbound switch skipped: reason={} selected={} recommended={}",
                recommended_switch_reason, selected_outbound, recommended_outbound
            ));
            return Ok(());
        }
        self.state.record_status_note(format!(
            "recommended outbound switch applying: reason={} selected={} recommended={}",
            recommended_switch_reason, selected_outbound, recommended_outbound
        ));
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

    pub fn subscription_update_report_from_config_text(
        &self,
        config_text: &str,
    ) -> Result<SubscriptionUpdateReport, String> {
        let current_config_text = self
            .state
            .active_config()
            .ok_or_else(|| "managed mixed core has no active subscription".to_string())?
            .config_text()
            .to_string();
        let current_selected_outbound = self
            .state
            .active_plan()
            .map(|plan| plan.selected_outbound().to_string());
        plan_subscription_update(
            Some(&current_config_text),
            config_text,
            current_selected_outbound.as_deref(),
        )
        .map_err(|error| format!("subscription update plan failed: {error:?}"))
    }

    pub fn reload_from_subscription_config_text_with_update_plan(
        &mut self,
        config_text: &str,
    ) -> Result<(SubscriptionUpdateReport, bool, Option<String>), String> {
        let report = match self.subscription_update_report_from_config_text(config_text) {
            Ok(report) => report,
            Err(error) => {
                self.state
                    .record_reload_rejected(ClientErrorKind::ConfigInvalid(error.clone()));
                return Err(error);
            }
        };

        let Some(planned_selected_outbound) = report.planned_selected_outbound.clone() else {
            let error = "subscription update rejected: no supported outbounds".to_string();
            self.state
                .record_reload_rejected(ClientErrorKind::NoSupportedOutbounds);
            self.state.record_status_note(format!(
                "{error} reason={} new_supported={} new_skipped={}",
                report.reason.label(),
                report.new_supported_count,
                report.new_skipped_count
            ));
            return Ok((report, false, Some(error)));
        };

        self.reload_from_subscription_config_text(config_text, Some(planned_selected_outbound))?;
        self.state.record_status_note(format!(
            "subscription update applied: reason={} preserved={} changed={} added={} removed={} retained={}",
            report.reason.label(),
            report.selected_outbound_preserved,
            report.selected_outbound_changed,
            report.added_tags.len(),
            report.removed_tags.len(),
            report.retained_tags.len()
        ));
        Ok((report, true, None))
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
        let mut next_runtime = match mixed_runtime_from_subscription_config_text_with_dns_options(
            config_text,
            self.block_domains.clone(),
            self.relay_options,
            Some(selected_outbound.clone()),
            self.dns_options,
        ) {
            Ok(mut runtime) => {
                runtime.tun_tcp_max_active_sessions = self.tun_tcp_max_active_sessions;
                runtime
            }
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
            next_runtime.connection_metrics = runtime.connection_metrics.clone();
            next_runtime.max_connection_workers = runtime.max_connection_workers;
            next_runtime.connection_worker_gauge = runtime.connection_worker_gauge.clone();
            next_runtime.active_connection_registry = runtime.active_connection_registry.clone();
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
                        result
                            .map(Some)
                            .map_err(|error| format!("managed mixed listener failed: {error}"))
                    })
            })
            .unwrap_or(Ok(None));
        let restore_result = self
            .system_proxy_guard
            .take()
            .map(ManagedSystemProxyGuard::restore)
            .unwrap_or(Ok(()));
        if let Ok(Some(diagnostic)) = &serve_result {
            self.state.record_status_diagnostic(
                managed_mixed_stop_drain_note(diagnostic),
                managed_mixed_stop_drain_diagnostic(diagnostic.clone()),
            );
        }
        self.state.stop();

        match (serve_result, restore_result) {
            (Ok(_), Ok(())) => Ok(self.state),
            (Err(serve_error), Ok(())) => Err(serve_error),
            (Ok(_), Err(restore_error)) => Err(restore_error),
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
        let tun_tcp_max_active_sessions = options.tun_tcp_max_active_sessions;
        let max_connection_workers = options.max_connection_workers.max(1);
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
            Ok(mut runtime) => {
                runtime.tun_tcp_max_active_sessions = tun_tcp_max_active_sessions;
                runtime.max_connection_workers = max_connection_workers;
                runtime
            }
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
            tun_tcp_max_active_sessions,
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

    pub fn serve_with_optional_tun_controller<T>(
        self,
        once: bool,
        tun_controller: &T,
        tun_device: Option<TunDeviceConfig>,
    ) -> Result<ClientRuntime, String>
    where
        T: TunPacketIoController + ?Sized,
        T::PacketIo: Send + 'static,
    {
        self.serve_with_optional_tun_controller_report(once, tun_controller, tun_device)
            .map(|(state, _)| state)
    }

    pub fn serve_with_optional_tun_controller_report<T>(
        mut self,
        once: bool,
        tun_controller: &T,
        tun_device: Option<TunDeviceConfig>,
    ) -> Result<(ClientRuntime, Option<ManagedTunPacketLoopReport>), String>
    where
        T: TunPacketIoController + ?Sized,
        T::PacketIo: Send + 'static,
    {
        let listener = self
            .listener
            .take()
            .expect("managed mixed listener is present");
        let runtime = self.runtime.clone();
        let serve_result = run_with_optional_tun_runtime_background_report(
            tun_controller,
            tun_device,
            &runtime,
            DEFAULT_TUN_DNS_TTL_SECONDS,
            DEFAULT_TUN_PACKET_LOOP_MAX_PACKETS,
            || {
                serve_mixed_listener(listener, once, &runtime)
                    .map_err(|error| format!("listen-mixed failed: {error}"))
            },
        );
        let stop_result = self.stop();

        match (serve_result, stop_result) {
            (Ok(((), tun_report)), Ok(mut state)) => {
                if let Some(report) = tun_report.as_ref() {
                    state.record_status_diagnostic(
                        managed_tun_runtime_report_note(report),
                        managed_tun_runtime_report_diagnostic(report),
                    );
                }
                Ok((state, tun_report))
            }
            (Err(serve_error), Ok(_)) => Err(serve_error),
            (Ok(((), _)), Err(restore_error)) => Err(restore_error),
            (Err(serve_error), Err(restore_error)) => {
                Err(format!("{serve_error}; {restore_error}"))
            }
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
            tun_tcp_max_active_sessions: self.tun_tcp_max_active_sessions,
            node_health: HashMap::new(),
            last_subscription_url_update: None,
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
        Some("interop-matrix") => parse_interop_matrix(args),
        Some("readiness-check") => parse_readiness_check(args),
        Some("default-core-certify") => parse_default_core_certify(args),
        Some("tun-preflight") => parse_tun_preflight(args),
        Some("tun-backend-check") => parse_tun_backend_check(args),
        Some("tun-backend-install") => parse_tun_backend_install(args),
        Some("version") => Ok(CliCommand::Version),
        Some("subscription-fetch") => parse_subscription_fetch(args),
        Some("subscription-update") => parse_subscription_update(args),
        Some("listen-mixed") => parse_listen_mixed(args),
        Some("probe-outbound") => parse_probe_outbound(args),
        Some("smoke-mixed") => parse_smoke_mixed(args),
        Some("soak-mixed") => parse_soak_mixed(args),
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
        CliCommand::InteropMatrix { output } => {
            let mut stdout = io::stdout();
            write_interop_matrix_report(output, &mut stdout)
        }
        CliCommand::ReadinessCheck {
            output,
            soak_connections,
            first_byte_timeout,
            max_connection_workers,
            soak_min_duration,
            skip_soak,
        } => {
            let mut stdout = io::stdout();
            write_readiness_check_report_with_soak_min_duration(
                output,
                soak_connections,
                first_byte_timeout,
                max_connection_workers,
                soak_min_duration,
                skip_soak,
                &mut stdout,
            )
        }
        CliCommand::DefaultCoreCertify {
            output,
            soak_connections,
            first_byte_timeout,
            max_connection_workers,
            soak_min_duration,
        } => {
            let mut stdout = io::stdout();
            write_default_core_certification_report_with_soak_min_duration(
                output,
                soak_connections,
                first_byte_timeout,
                max_connection_workers,
                soak_min_duration,
                &mut stdout,
            )
        }
        CliCommand::TunPreflight { config, output } => {
            let controller = NativeTunDeviceController::new();
            let mut stdout = io::stdout();
            write_tun_preflight_report_with_controller(&mut stdout, output, config, &controller)
                .map_err(|error| format!("write TUN preflight report: {error}"))
        }
        CliCommand::TunBackendCheck { output } => {
            let mut stdout = io::stdout();
            write_tun_backend_check_report(output, &mut stdout)
        }
        CliCommand::TunBackendInstall {
            source,
            target_dir,
            output,
        } => {
            let mut stdout = io::stdout();
            write_tun_backend_install_report(source, target_dir, output, &mut stdout)
        }
        CliCommand::Version => {
            println!("keli-cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        CliCommand::SubscriptionFetch {
            url,
            output,
            timeout,
            max_bytes,
        } => {
            let mut stdout = io::stdout();
            write_subscription_fetch_report_from_url(&url, output, timeout, max_bytes, &mut stdout)
        }
        CliCommand::SubscriptionUpdate {
            current_config,
            new_config,
            current_outbound,
            output,
        } => {
            let current_config_text = match current_config.as_deref() {
                Some(path) => Some(
                    fs::read_to_string(path)
                        .map_err(|error| format!("read current profile config {path}: {error}"))?,
                ),
                None => None,
            };
            let new_config_text = fs::read_to_string(&new_config)
                .map_err(|error| format!("read new profile config {new_config}: {error}"))?;
            let mut stdout = io::stdout();
            write_subscription_update_report_from_config_text(
                current_config_text.as_deref(),
                &new_config_text,
                current_outbound.as_deref(),
                output,
                &mut stdout,
            )
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
            tun_tcp_max_active_sessions,
            max_connection_workers,
            dns_options,
        } => {
            let relay_options = RelayOptions {
                first_byte_timeout: Some(first_byte_timeout),
                idle_timeout: Some(idle_timeout),
            };
            let controller = NativeSystemProxyController::new();
            let tun_controller = NativeTunDeviceController::new();
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
                        tun_tcp_max_active_sessions,
                        max_connection_workers,
                    },
                    &controller,
                )?;
                let (_, tun_report) = session.serve_with_optional_tun_controller_report(
                    once,
                    &tun_controller,
                    tun_device,
                )?;
                if let Some(report) = tun_report.as_ref() {
                    println!("{}", managed_tun_runtime_report_note(report));
                }
                return Ok(());
            }

            let mut runtime = mixed_runtime_from_cli(block_domains, relay_options, dns_options);
            runtime.tun_tcp_max_active_sessions = tun_tcp_max_active_sessions;
            runtime.max_connection_workers = max_connection_workers;
            let tun_report = listen_mixed_with_optional_tun_controller_report(
                &listen,
                once,
                &runtime,
                &controller,
                system_proxy,
                system_proxy_bypass,
                &tun_controller,
                tun_device,
            )?;
            if let Some(report) = tun_report.as_ref() {
                println!("{}", managed_tun_runtime_report_note(report));
            }
            Ok(())
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
        CliCommand::SoakMixed {
            connections,
            inbound,
            output,
            first_byte_timeout,
            max_connection_workers,
            min_duration,
        } => {
            let mut stdout = io::stdout();
            write_soak_mixed_report_with_min_duration(
                connections,
                inbound,
                first_byte_timeout,
                max_connection_workers,
                min_duration,
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
        CliCommand::SupportBundle {
            profile_config,
            include_default_core_certification,
            certification_soak_connections,
            certification_first_byte_timeout,
            certification_max_connection_workers,
            certification_soak_min_duration,
        } => {
            let config_text = profile_config
                .as_deref()
                .map(|path| {
                    fs::read_to_string(path)
                        .map_err(|error| format!("read profile config {path}: {error}"))
                })
                .transpose()?;
            let mut stdout = io::stdout();
            write_support_bundle_report_with_options(
                config_text.as_deref(),
                SupportBundleOptions {
                    include_default_core_certification,
                    certification_soak_connections,
                    certification_first_byte_timeout,
                    certification_max_connection_workers,
                    certification_soak_min_duration,
                },
                &mut stdout,
            )
        }
    }
}

pub fn print_usage(mut writer: impl Write) -> io::Result<()> {
    writeln!(
        writer,
        "usage: keli-cli [doctor|interop-matrix|readiness-check|default-core-certify|tun-preflight|tun-backend-check|tun-backend-install|version|subscription-fetch|subscription-update|listen-mixed|probe-outbound|smoke-mixed|soak-mixed|profile-check|support-bundle]"
    )?;
    writeln!(writer, "       keli-cli doctor [--format text|json]")?;
    writeln!(
        writer,
        "       keli-cli interop-matrix [--format text|json]"
    )?;
    writeln!(
        writer,
        "       keli-cli readiness-check [--format text|json] [--soak-connections 3] [--first-byte-timeout-ms 30000] [--max-connection-workers 1024] [--soak-min-duration-ms 1] [--skip-soak]"
    )?;
    writeln!(
        writer,
        "       keli-cli default-core-certify [--format text|json] [--soak-connections 3] [--first-byte-timeout-ms 30000] [--max-connection-workers 1024] [--soak-min-duration-ms 1]"
    )?;
    writeln!(
        writer,
        "       keli-cli tun-preflight [--interface keli-tun0] [--address 10.7.0.1/24] [--mtu 1500] [--dns-hijack] [--format text|json]"
    )?;
    writeln!(
        writer,
        "       keli-cli tun-backend-check [--format text|json]"
    )?;
    writeln!(
        writer,
        "       keli-cli tun-backend-install --source path\\to\\wintun.dll [--target-dir path\\to\\runtime-dir] [--format text|json]"
    )?;
    writeln!(
        writer,
        "       keli-cli subscription-fetch --url https://panel.example/subscription [--format text|json] [--timeout-ms 30000] [--max-bytes 2097152]"
    )?;
    writeln!(
        writer,
        "       keli-cli subscription-update --new-config subscription.yaml [--current-config active.yaml] [--current-outbound proxy] [--format text|json]"
    )?;
    writeln!(
        writer,
        "       keli-cli listen-mixed [--listen 127.0.0.1:7890] [--once] [--profile-config subscription.yaml] [--outbound-tag proxy] [--block-domain example.com] [--block-cidr 10.0.0.0/8] [--block-port 25|1000-2000] [--first-byte-timeout-ms 30000] [--idle-timeout-ms 300000] [--max-connection-workers 1024] [--dns-local-policy allow-system|prevent-public-leak] [--dns-address-family dual-stack|ipv4-only|ipv6-only] [--tun] [--tun-interface keli-tun0] [--tun-address 10.7.0.1/24] [--tun-mtu 1500] [--tun-dns-hijack] [--tun-tcp-max-active-sessions 4096]"
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
        "       keli-cli soak-mixed [--connections 25] [--inbound socks5|http-connect] [--format text|json] [--first-byte-timeout-ms 30000] [--max-connection-workers 1024] [--min-duration-ms 1]"
    )?;
    writeln!(
        writer,
        "       keli-cli profile-check --profile-config subscription.yaml [--format text|json]"
    )?;
    writeln!(
        writer,
        "       keli-cli support-bundle [--profile-config subscription.yaml] [--include-certification] [--certification-soak-connections 3] [--certification-first-byte-timeout-ms 30000] [--certification-max-connection-workers 1024] [--certification-soak-min-duration-ms 1]"
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

fn parse_interop_matrix(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
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
            other => return Err(format!("unknown interop-matrix option: {other}")),
        }
    }

    Ok(CliCommand::InteropMatrix { output })
}

fn parse_readiness_check(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut output = ProbeOutputFormat::Text;
    let mut soak_connections = DEFAULT_READINESS_SOAK_CONNECTIONS;
    let mut first_byte_timeout = DEFAULT_FIRST_BYTE_TIMEOUT;
    let mut max_connection_workers = DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS;
    let mut soak_min_duration = DEFAULT_MIXED_SOAK_MIN_DURATION;
    let mut skip_soak = false;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--format" => {
                output = parse_probe_output_format(
                    args.next()
                        .ok_or_else(|| "--format requires text or json".to_string())?,
                )?;
            }
            "--soak-connections" => {
                soak_connections = parse_positive_usize(
                    args.next()
                        .ok_or_else(|| "--soak-connections requires a value".to_string())?,
                    "--soak-connections",
                )?;
            }
            "--first-byte-timeout-ms" => {
                first_byte_timeout = parse_duration_ms(
                    args.next()
                        .ok_or_else(|| "--first-byte-timeout-ms requires a value".to_string())?,
                    "--first-byte-timeout-ms",
                )?;
            }
            "--max-connection-workers" => {
                max_connection_workers = parse_positive_usize(
                    args.next()
                        .ok_or_else(|| "--max-connection-workers requires a value".to_string())?,
                    "--max-connection-workers",
                )?;
            }
            "--soak-min-duration-ms" => {
                soak_min_duration = parse_duration_ms(
                    args.next()
                        .ok_or_else(|| "--soak-min-duration-ms requires a value".to_string())?,
                    "--soak-min-duration-ms",
                )?;
            }
            "--skip-soak" => skip_soak = true,
            other => return Err(format!("unknown readiness-check option: {other}")),
        }
    }

    Ok(CliCommand::ReadinessCheck {
        output,
        soak_connections,
        first_byte_timeout,
        max_connection_workers,
        soak_min_duration,
        skip_soak,
    })
}

fn parse_default_core_certify(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut output = ProbeOutputFormat::Text;
    let mut soak_connections = DEFAULT_READINESS_SOAK_CONNECTIONS;
    let mut first_byte_timeout = DEFAULT_FIRST_BYTE_TIMEOUT;
    let mut max_connection_workers = DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS;
    let mut soak_min_duration = DEFAULT_MIXED_SOAK_MIN_DURATION;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--format" => {
                output = parse_probe_output_format(
                    args.next()
                        .ok_or_else(|| "--format requires text or json".to_string())?,
                )?;
            }
            "--soak-connections" => {
                soak_connections = parse_positive_usize(
                    args.next()
                        .ok_or_else(|| "--soak-connections requires a value".to_string())?,
                    "--soak-connections",
                )?;
            }
            "--first-byte-timeout-ms" => {
                first_byte_timeout = parse_duration_ms(
                    args.next()
                        .ok_or_else(|| "--first-byte-timeout-ms requires a value".to_string())?,
                    "--first-byte-timeout-ms",
                )?;
            }
            "--max-connection-workers" => {
                max_connection_workers = parse_positive_usize(
                    args.next()
                        .ok_or_else(|| "--max-connection-workers requires a value".to_string())?,
                    "--max-connection-workers",
                )?;
            }
            "--soak-min-duration-ms" => {
                soak_min_duration = parse_duration_ms(
                    args.next()
                        .ok_or_else(|| "--soak-min-duration-ms requires a value".to_string())?,
                    "--soak-min-duration-ms",
                )?;
            }
            other => return Err(format!("unknown default-core-certify option: {other}")),
        }
    }

    Ok(CliCommand::DefaultCoreCertify {
        output,
        soak_connections,
        first_byte_timeout,
        max_connection_workers,
        soak_min_duration,
    })
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

fn parse_tun_backend_check(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
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
            other => return Err(format!("unknown tun-backend-check option: {other}")),
        }
    }

    Ok(CliCommand::TunBackendCheck { output })
}

fn parse_tun_backend_install(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut source = None;
    let mut target_dir = None;
    let mut output = ProbeOutputFormat::Text;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--source" => {
                source = Some(PathBuf::from(args.next().ok_or_else(|| {
                    "--source requires a path to an extracted wintun.dll".to_string()
                })?));
            }
            "--target-dir" => {
                target_dir =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        "--target-dir requires a directory path".to_string()
                    })?));
            }
            "--format" => {
                output = parse_probe_output_format(
                    args.next()
                        .ok_or_else(|| "--format requires text or json".to_string())?,
                )?;
            }
            other => return Err(format!("unknown tun-backend-install option: {other}")),
        }
    }

    Ok(CliCommand::TunBackendInstall {
        source: source.ok_or_else(|| "--source is required".to_string())?,
        target_dir,
        output,
    })
}

fn parse_subscription_fetch(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut url = None;
    let mut output = ProbeOutputFormat::Text;
    let mut timeout = DEFAULT_SUBSCRIPTION_FETCH_TIMEOUT;
    let mut max_bytes = DEFAULT_SUBSCRIPTION_FETCH_MAX_BYTES;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--url" => {
                url = Some(
                    args.next()
                        .ok_or_else(|| "--url requires a subscription URL".to_string())?,
                );
            }
            "--format" => {
                output = parse_probe_output_format(
                    args.next()
                        .ok_or_else(|| "--format requires text or json".to_string())?,
                )?;
            }
            "--timeout-ms" => {
                timeout = parse_duration_ms(
                    args.next()
                        .ok_or_else(|| "--timeout-ms requires a value".to_string())?,
                    "--timeout-ms",
                )?;
            }
            "--max-bytes" => {
                max_bytes = parse_positive_usize(
                    args.next()
                        .ok_or_else(|| "--max-bytes requires a value".to_string())?,
                    "--max-bytes",
                )?;
            }
            other => return Err(format!("unknown subscription-fetch option: {other}")),
        }
    }

    Ok(CliCommand::SubscriptionFetch {
        url: url.ok_or_else(|| "subscription-fetch requires --url".to_string())?,
        output,
        timeout,
        max_bytes,
    })
}

fn parse_subscription_update(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut current_config = None;
    let mut new_config = None;
    let mut current_outbound = None;
    let mut output = ProbeOutputFormat::Text;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--current-config" => {
                current_config = Some(
                    args.next()
                        .ok_or_else(|| "--current-config requires a path".to_string())?,
                );
            }
            "--new-config" => {
                new_config = Some(
                    args.next()
                        .ok_or_else(|| "--new-config requires a path".to_string())?,
                );
            }
            "--current-outbound" | "--current-outbound-tag" => {
                current_outbound = Some(
                    args.next()
                        .ok_or_else(|| "--current-outbound requires a tag".to_string())?,
                );
            }
            "--format" => {
                output = parse_probe_output_format(
                    args.next()
                        .ok_or_else(|| "--format requires text or json".to_string())?,
                )?;
            }
            other => return Err(format!("unknown subscription-update option: {other}")),
        }
    }

    Ok(CliCommand::SubscriptionUpdate {
        current_config,
        new_config: new_config
            .ok_or_else(|| "subscription-update requires --new-config".to_string())?,
        current_outbound,
        output,
    })
}

fn parse_support_bundle(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut profile_config = None;
    let mut include_default_core_certification = false;
    let mut certification_soak_connections = DEFAULT_READINESS_SOAK_CONNECTIONS;
    let mut certification_first_byte_timeout = DEFAULT_FIRST_BYTE_TIMEOUT;
    let mut certification_max_connection_workers = DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS;
    let mut certification_soak_min_duration = DEFAULT_MIXED_SOAK_MIN_DURATION;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile-config" => {
                profile_config = Some(
                    args.next()
                        .ok_or_else(|| "--profile-config requires a path".to_string())?,
                );
            }
            "--include-certification" | "--include-default-core-certification" => {
                include_default_core_certification = true;
            }
            "--certification-soak-connections" => {
                include_default_core_certification = true;
                certification_soak_connections = parse_positive_usize(
                    args.next().ok_or_else(|| {
                        "--certification-soak-connections requires a value".to_string()
                    })?,
                    "--certification-soak-connections",
                )?;
            }
            "--certification-first-byte-timeout-ms" => {
                include_default_core_certification = true;
                certification_first_byte_timeout = parse_duration_ms(
                    args.next().ok_or_else(|| {
                        "--certification-first-byte-timeout-ms requires a value".to_string()
                    })?,
                    "--certification-first-byte-timeout-ms",
                )?;
            }
            "--certification-max-connection-workers" => {
                include_default_core_certification = true;
                certification_max_connection_workers = parse_positive_usize(
                    args.next().ok_or_else(|| {
                        "--certification-max-connection-workers requires a value".to_string()
                    })?,
                    "--certification-max-connection-workers",
                )?;
            }
            "--certification-soak-min-duration-ms" => {
                include_default_core_certification = true;
                certification_soak_min_duration = parse_duration_ms(
                    args.next().ok_or_else(|| {
                        "--certification-soak-min-duration-ms requires a value".to_string()
                    })?,
                    "--certification-soak-min-duration-ms",
                )?;
            }
            other => return Err(format!("unknown support-bundle option: {other}")),
        }
    }

    Ok(CliCommand::SupportBundle {
        profile_config,
        include_default_core_certification,
        certification_soak_connections,
        certification_first_byte_timeout,
        certification_max_connection_workers,
        certification_soak_min_duration,
    })
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
    let mut tun_tcp_max_active_sessions = DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS;
    let mut max_connection_workers = DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS;
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
            "--tun-tcp-max-active-sessions" => {
                tun_enabled = true;
                tun_tcp_max_active_sessions = parse_positive_usize(
                    args.next().ok_or_else(|| {
                        "--tun-tcp-max-active-sessions requires a value".to_string()
                    })?,
                    "--tun-tcp-max-active-sessions",
                )?;
            }
            "--max-connection-workers" => {
                max_connection_workers = parse_positive_usize(
                    args.next()
                        .ok_or_else(|| "--max-connection-workers requires a value".to_string())?,
                    "--max-connection-workers",
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
        tun_tcp_max_active_sessions,
        max_connection_workers,
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
                inbound = parse_mixed_inbound_kind(
                    args.next()
                        .ok_or_else(|| "--inbound requires socks5 or http-connect".to_string())?,
                    "smoke-mixed",
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

fn parse_soak_mixed(args: impl Iterator<Item = String>) -> Result<CliCommand, String> {
    let mut connections = DEFAULT_MIXED_SOAK_CONNECTIONS;
    let mut inbound = SmokeInboundKind::Socks5;
    let mut output = ProbeOutputFormat::Text;
    let mut first_byte_timeout = DEFAULT_FIRST_BYTE_TIMEOUT;
    let mut max_connection_workers = DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS;
    let mut min_duration = DEFAULT_MIXED_SOAK_MIN_DURATION;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--connections" => {
                connections = parse_positive_usize(
                    args.next()
                        .ok_or_else(|| "--connections requires a value".to_string())?,
                    "--connections",
                )?;
            }
            "--inbound" => {
                inbound = parse_mixed_inbound_kind(
                    args.next()
                        .ok_or_else(|| "--inbound requires socks5 or http-connect".to_string())?,
                    "soak-mixed",
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
            "--max-connection-workers" => {
                max_connection_workers = parse_positive_usize(
                    args.next()
                        .ok_or_else(|| "--max-connection-workers requires a value".to_string())?,
                    "--max-connection-workers",
                )?;
            }
            "--min-duration-ms" => {
                min_duration = parse_duration_ms(
                    args.next()
                        .ok_or_else(|| "--min-duration-ms requires a value".to_string())?,
                    "--min-duration-ms",
                )?;
            }
            other => return Err(format!("unknown soak-mixed option: {other}")),
        }
    }

    Ok(CliCommand::SoakMixed {
        connections,
        inbound,
        output,
        first_byte_timeout,
        max_connection_workers,
        min_duration,
    })
}

fn parse_mixed_inbound_kind(value: String, command: &str) -> Result<SmokeInboundKind, String> {
    match value.as_str() {
        "socks5" => Ok(SmokeInboundKind::Socks5),
        "http-connect" => Ok(SmokeInboundKind::HttpConnect),
        other => Err(format!("unknown {command} inbound: {other}")),
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
    doctor_report_schema_version: u32,
    support_bundle_schema_version: u32,
    interop_matrix_schema_version: u32,
    readiness_check_schema_version: u32,
    default_core_certification_schema_version: u32,
    managed_mixed_status_schema_version: u32,
    version: &'static str,
    platform: String,
    system_proxy_supported: bool,
    system_proxy_state: String,
    system_proxy_server: Option<String>,
    system_proxy_error: Option<String>,
    tun: bool,
    tun_device: TunDeviceStatus,
    tun_backend: TunBackendStatus,
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
    subscription_fetch_capabilities: Vec<&'static str>,
    subscription_update_capabilities: Vec<&'static str>,
    managed_connection_metric_capabilities: Vec<&'static str>,
    managed_status_schema_capabilities: Vec<&'static str>,
    tun_packet_pipeline_capabilities: Vec<&'static str>,
    stability_diagnostic_capabilities: Vec<&'static str>,
    interop_matrix_capabilities: Vec<&'static str>,
    readiness_check_capabilities: Vec<&'static str>,
    tun_backend_check_capabilities: Vec<&'static str>,
    default_core_certification_capabilities: Vec<&'static str>,
    runtime_event_history_limit: usize,
    managed_status_recent_event_limit: usize,
    managed_connection_report_history_limit: usize,
    managed_connection_worker_limit: usize,
    tun_tcp_max_active_sessions_default: usize,
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
    let tun_backend = TunBackendStatus::detect();
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
        doctor_report_schema_version: DOCTOR_REPORT_SCHEMA_VERSION,
        support_bundle_schema_version: SUPPORT_BUNDLE_SCHEMA_VERSION,
        interop_matrix_schema_version: INTEROP_MATRIX_SCHEMA_VERSION,
        readiness_check_schema_version: READINESS_CHECK_SCHEMA_VERSION,
        default_core_certification_schema_version: DEFAULT_CORE_CERTIFICATION_SCHEMA_VERSION,
        managed_mixed_status_schema_version: MANAGED_MIXED_STATUS_SCHEMA_VERSION,
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
        tun_backend,
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
        subscription_fetch_capabilities: SUBSCRIPTION_FETCH_CAPABILITIES.split(',').collect(),
        subscription_update_capabilities: SUBSCRIPTION_UPDATE_CAPABILITIES.split(',').collect(),
        managed_connection_metric_capabilities: MANAGED_CONNECTION_METRIC_CAPABILITIES
            .split(',')
            .collect(),
        managed_status_schema_capabilities: MANAGED_STATUS_SCHEMA_CAPABILITIES.split(',').collect(),
        tun_packet_pipeline_capabilities: TUN_PACKET_PIPELINE_CAPABILITIES.split(',').collect(),
        stability_diagnostic_capabilities: STABILITY_DIAGNOSTIC_CAPABILITIES.split(',').collect(),
        interop_matrix_capabilities: INTEROP_MATRIX_CAPABILITIES.split(',').collect(),
        readiness_check_capabilities: READINESS_CHECK_CAPABILITIES.split(',').collect(),
        tun_backend_check_capabilities: TUN_BACKEND_CHECK_CAPABILITIES.split(',').collect(),
        default_core_certification_capabilities: DEFAULT_CORE_CERTIFICATION_CAPABILITIES
            .split(',')
            .collect(),
        runtime_event_history_limit: DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT,
        managed_status_recent_event_limit: MANAGED_MIXED_RECENT_EVENT_LIMIT,
        managed_connection_report_history_limit: MANAGED_CONNECTION_REPORT_HISTORY_LIMIT,
        managed_connection_worker_limit: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
        tun_tcp_max_active_sessions_default: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
        sample_profile_valid: profile.validate().is_ok(),
        initial_phase: format!("{:?}", ConnectionPhase::Idle),
    }
}

fn write_doctor_text_report(mut writer: impl Write, report: &DoctorReport) -> io::Result<()> {
    writeln!(writer, "keli-native-client doctor")?;
    writeln!(writer, "version={}", report.version)?;
    writeln!(
        writer,
        "schema_versions doctor_report={} support_bundle={} interop_matrix={} readiness_check={} default_core_certification={} managed_mixed_status={}",
        report.doctor_report_schema_version,
        report.support_bundle_schema_version,
        report.interop_matrix_schema_version,
        report.readiness_check_schema_version,
        report.default_core_certification_schema_version,
        report.managed_mixed_status_schema_version
    )?;
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
        "tun_device_supported={} lifecycle_available={} packet_io_available={} state={} interface={} address={} mtu={} dns_hijack={} error={}",
        report.tun_device.supported,
        report.tun_device.lifecycle_available,
        report.tun_device.packet_io_available,
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
    writeln!(
        writer,
        "tun_backend platform={} backend={} supported={} driver_library_present={} driver_api_available={} install_required={} lifecycle_wired={} packet_io_wired={} route_takeover_wired={} driver_library_path={} driver_api_error={} reason={}",
        format!("{:?}", report.tun_backend.platform),
        report.tun_backend.backend_label(),
        report.tun_backend.supported,
        report.tun_backend.driver_library_present,
        report.tun_backend.driver_api_available,
        report.tun_backend.install_required,
        report.tun_backend.lifecycle_wired,
        report.tun_backend.packet_io_wired,
        report.tun_backend.route_takeover_wired,
        report.tun_backend.driver_library_path.as_deref().unwrap_or("-"),
        report.tun_backend.driver_api_error.as_deref().unwrap_or("-"),
        report.tun_backend.reason.as_deref().unwrap_or("-")
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
        "subscription_fetch_capabilities={}",
        report.subscription_fetch_capabilities.join(",")
    )?;
    writeln!(
        writer,
        "subscription_update_capabilities={}",
        report.subscription_update_capabilities.join(",")
    )?;
    writeln!(
        writer,
        "managed_connection_metric_capabilities={}",
        report.managed_connection_metric_capabilities.join(",")
    )?;
    writeln!(
        writer,
        "managed_status_schema_capabilities={}",
        report.managed_status_schema_capabilities.join(",")
    )?;
    writeln!(
        writer,
        "tun_packet_pipeline_capabilities={}",
        report.tun_packet_pipeline_capabilities.join(",")
    )?;
    writeln!(
        writer,
        "stability_diagnostic_capabilities={}",
        report.stability_diagnostic_capabilities.join(",")
    )?;
    writeln!(
        writer,
        "interop_matrix_capabilities={}",
        report.interop_matrix_capabilities.join(",")
    )?;
    writeln!(
        writer,
        "readiness_check_capabilities={}",
        report.readiness_check_capabilities.join(",")
    )?;
    writeln!(
        writer,
        "tun_backend_check_capabilities={}",
        report.tun_backend_check_capabilities.join(",")
    )?;
    writeln!(
        writer,
        "default_core_certification_capabilities={}",
        report.default_core_certification_capabilities.join(",")
    )?;
    writeln!(
        writer,
        "resource_limits runtime_event_history={} managed_status_recent_events={} managed_connection_report_history={} managed_connection_workers={} tun_tcp_max_active_sessions={}",
        report.runtime_event_history_limit,
        report.managed_status_recent_event_limit,
        report.managed_connection_report_history_limit,
        report.managed_connection_worker_limit,
        report.tun_tcp_max_active_sessions_default
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
        "schema_version": report.doctor_report_schema_version,
        "schema_versions": {
            "doctor_report": report.doctor_report_schema_version,
            "support_bundle": report.support_bundle_schema_version,
            "interop_matrix": report.interop_matrix_schema_version,
            "readiness_check": report.readiness_check_schema_version,
            "default_core_certification": report.default_core_certification_schema_version,
            "managed_mixed_status": report.managed_mixed_status_schema_version,
        },
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
            "packet_io_available": report.tun_device.packet_io_available,
            "running": report.tun_device.running,
            "interface_name": report.tun_device.interface_name.as_deref(),
            "address_cidr": report.tun_device.address_cidr.as_deref(),
            "mtu": report.tun_device.mtu,
            "dns_hijack": report.tun_device.dns_hijack,
            "error": report.tun_device.error.as_deref(),
        },
        "tun_backend": tun_backend_json_value(&report.tun_backend),
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
        "subscription_fetch_capabilities": &report.subscription_fetch_capabilities,
        "subscription_update_capabilities": &report.subscription_update_capabilities,
        "managed_connection_metric_capabilities": &report.managed_connection_metric_capabilities,
        "managed_status_schema_capabilities": &report.managed_status_schema_capabilities,
        "tun_packet_pipeline_capabilities": &report.tun_packet_pipeline_capabilities,
        "stability_diagnostic_capabilities": &report.stability_diagnostic_capabilities,
        "interop_matrix_capabilities": &report.interop_matrix_capabilities,
        "readiness_check_capabilities": &report.readiness_check_capabilities,
        "tun_backend_check_capabilities": &report.tun_backend_check_capabilities,
        "default_core_certification_capabilities": &report.default_core_certification_capabilities,
        "resource_limits": {
            "runtime_event_history": report.runtime_event_history_limit,
            "managed_status_recent_events": report.managed_status_recent_event_limit,
            "managed_connection_report_history": report.managed_connection_report_history_limit,
            "managed_connection_workers": report.managed_connection_worker_limit,
            "tun_tcp_max_active_sessions": report.tun_tcp_max_active_sessions_default,
        },
        "sample_profile_valid": report.sample_profile_valid,
        "initial_phase": &report.initial_phase,
    })
}

pub fn write_tun_backend_check_report(
    output: ProbeOutputFormat,
    mut writer: impl Write,
) -> Result<(), String> {
    let status = TunBackendStatus::detect();
    match output {
        ProbeOutputFormat::Text => write_tun_backend_check_text_report(&mut writer, &status),
        ProbeOutputFormat::Json => write_tun_backend_check_json_report(&mut writer, &status),
    }
}

fn write_tun_backend_check_text_report(
    writer: &mut impl Write,
    status: &TunBackendStatus,
) -> Result<(), String> {
    writeln!(
        writer,
        "tun_backend status={} platform={:?} backend={} supported={} driver_library_present={} driver_api_available={} install_required={} lifecycle_wired={} packet_io_wired={} route_takeover_wired={} driver_library_path={} driver_api_error={} reason={}",
        if status.is_ready() {
            "ready"
        } else {
            "not-ready"
        },
        status.platform,
        status.backend_label(),
        status.supported,
        status.driver_library_present,
        status.driver_api_available,
        status.install_required,
        status.lifecycle_wired,
        status.packet_io_wired,
        status.route_takeover_wired,
        status.driver_library_path.as_deref().unwrap_or("-"),
        status.driver_api_error.as_deref().unwrap_or("-"),
        status.reason.as_deref().unwrap_or("-")
    )
    .map_err(|error| error.to_string())?;
    for path in &status.searched_paths {
        writeln!(writer, "tun_backend searched_path={path}").map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn write_tun_backend_check_json_report(
    writer: &mut impl Write,
    status: &TunBackendStatus,
) -> Result<(), String> {
    let value = serde_json::json!({
        "status": if status.is_ready() { "ready" } else { "not-ready" },
        "kind": "keli_tun_backend_check",
        "backend": tun_backend_json_value(status),
    });
    serde_json::to_writer_pretty(&mut *writer, &value).map_err(|error| error.to_string())?;
    writeln!(writer).map_err(|error| error.to_string())
}

fn tun_backend_json_value(status: &TunBackendStatus) -> serde_json::Value {
    serde_json::json!({
        "platform": format!("{:?}", status.platform),
        "backend": status.backend_label(),
        "supported": status.supported,
        "lifecycle_wired": status.lifecycle_wired,
        "packet_io_wired": status.packet_io_wired,
        "route_takeover_wired": status.route_takeover_wired,
        "driver_library_present": status.driver_library_present,
        "driver_api_available": status.driver_api_available,
        "driver_library_path": status.driver_library_path.as_deref(),
        "driver_api_error": status.driver_api_error.as_deref(),
        "install_required": status.install_required,
        "searched_paths": &status.searched_paths,
        "reason": status.reason.as_deref(),
    })
}

pub fn write_tun_backend_install_report(
    source: PathBuf,
    target_dir: Option<PathBuf>,
    output: ProbeOutputFormat,
    mut writer: impl Write,
) -> Result<(), String> {
    let report = install_wintun_library(&source, target_dir.as_deref())
        .map_err(|error| format!("install Wintun backend: {error}"))?;
    match output {
        ProbeOutputFormat::Text => write_tun_backend_install_text_report(&mut writer, &report),
        ProbeOutputFormat::Json => write_tun_backend_install_json_report(&mut writer, &report),
    }
}

fn write_tun_backend_install_text_report(
    writer: &mut impl Write,
    report: &WintunInstallReport,
) -> Result<(), String> {
    writeln!(
        writer,
        "tun_backend_install status={} source={} target={} copied_bytes={} previous_target_present={} driver_api_available={} ready_after_install={}",
        if report.ready_after_install { "ready" } else { "not-ready" },
        report.source_path,
        report.target_path,
        report.copied_bytes,
        report.previous_target_present,
        report.driver_api_available,
        report.ready_after_install
    )
    .map_err(|error| error.to_string())
}

fn write_tun_backend_install_json_report(
    writer: &mut impl Write,
    report: &WintunInstallReport,
) -> Result<(), String> {
    let value = serde_json::json!({
        "status": if report.ready_after_install { "ready" } else { "not-ready" },
        "kind": "keli_tun_backend_install",
        "source_path": &report.source_path,
        "target_path": &report.target_path,
        "copied_bytes": report.copied_bytes,
        "previous_target_present": report.previous_target_present,
        "driver_api_available": report.driver_api_available,
        "ready_after_install": report.ready_after_install,
    });
    serde_json::to_writer_pretty(&mut *writer, &value).map_err(|error| error.to_string())?;
    writeln!(writer).map_err(|error| error.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteropMatrixReport {
    pub schema_version: u32,
    pub version: &'static str,
    pub summary: InteropMatrixSummary,
    pub entries: Vec<InteropMatrixEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteropMatrixSummary {
    pub protocol_count: usize,
    pub tcp_relay_supported_count: usize,
    pub udp_relay_supported_count: usize,
    pub profile_source_supported_count: usize,
    pub validation_supported_count: usize,
    pub registry_supported_count: usize,
    pub sample_profile_count: usize,
    pub registry_profile_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteropMatrixEntry {
    pub protocol: &'static str,
    pub tcp_relay_supported: bool,
    pub udp_relay_supported: bool,
    pub covered_transports: Vec<&'static str>,
    pub profile_sources: Vec<&'static str>,
    pub sample_profile_count: usize,
    pub validation_supported: bool,
    pub validated_profile_count: usize,
    pub validation_error: Option<String>,
    pub registry_supported: bool,
    pub registry_profile_count: usize,
    pub registry_error: Option<String>,
}

struct InteropMatrixSpec {
    protocol: &'static str,
    tcp_relay_supported: bool,
    udp_relay_supported: bool,
    covered_transports: Vec<&'static str>,
    profile_sources: Vec<&'static str>,
    sample_profiles: Vec<OutboundProfile>,
}

pub fn write_interop_matrix_report(
    output: ProbeOutputFormat,
    mut writer: impl Write,
) -> Result<(), String> {
    let report = collect_interop_matrix_report();
    match output {
        ProbeOutputFormat::Text => write_interop_matrix_text_report(&mut writer, &report),
        ProbeOutputFormat::Json => write_interop_matrix_json_report(&mut writer, &report),
    }
}

fn collect_interop_matrix_report() -> InteropMatrixReport {
    let entries: Vec<_> = interop_matrix_specs()
        .into_iter()
        .map(interop_matrix_entry_from_spec)
        .collect();
    let summary = InteropMatrixSummary {
        protocol_count: entries.len(),
        tcp_relay_supported_count: entries
            .iter()
            .filter(|entry| entry.tcp_relay_supported)
            .count(),
        udp_relay_supported_count: entries
            .iter()
            .filter(|entry| entry.udp_relay_supported)
            .count(),
        profile_source_supported_count: entries
            .iter()
            .filter(|entry| {
                entry
                    .profile_sources
                    .iter()
                    .any(|source| matches!(*source, "mihomo-yaml" | "share-link"))
            })
            .count(),
        validation_supported_count: entries
            .iter()
            .filter(|entry| entry.validation_supported)
            .count(),
        registry_supported_count: entries
            .iter()
            .filter(|entry| entry.registry_supported)
            .count(),
        sample_profile_count: entries.iter().map(|entry| entry.sample_profile_count).sum(),
        registry_profile_count: entries
            .iter()
            .map(|entry| entry.registry_profile_count)
            .sum(),
    };

    InteropMatrixReport {
        schema_version: INTEROP_MATRIX_SCHEMA_VERSION,
        version: env!("CARGO_PKG_VERSION"),
        summary,
        entries,
    }
}

fn write_interop_matrix_text_report(
    writer: &mut impl Write,
    report: &InteropMatrixReport,
) -> Result<(), String> {
    writeln!(
        writer,
        "interop status=ok schema_version={} protocols={} tcp_relay_supported={} udp_relay_supported={} profile_source_supported={} validation_supported={} registry_supported={} sample_profiles={} registry_profiles={}",
        report.schema_version,
        report.summary.protocol_count,
        report.summary.tcp_relay_supported_count,
        report.summary.udp_relay_supported_count,
        report.summary.profile_source_supported_count,
        report.summary.validation_supported_count,
        report.summary.registry_supported_count,
        report.summary.sample_profile_count,
        report.summary.registry_profile_count
    )
    .map_err(|error| error.to_string())?;
    for entry in &report.entries {
        writeln!(
            writer,
            "interop protocol={} tcp_relay_supported={} udp_relay_supported={} transports={} profile_sources={} sample_profiles={} validation_supported={} validated_profiles={} validation_error={} registry_supported={} registry_profiles={} registry_error={}",
            entry.protocol,
            entry.tcp_relay_supported,
            entry.udp_relay_supported,
            entry.covered_transports.join(","),
            entry.profile_sources.join(","),
            entry.sample_profile_count,
            entry.validation_supported,
            entry.validated_profile_count,
            entry.validation_error.as_deref().unwrap_or("-"),
            entry.registry_supported,
            entry.registry_profile_count,
            entry.registry_error.as_deref().unwrap_or("-")
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn write_interop_matrix_json_report(
    writer: &mut impl Write,
    report: &InteropMatrixReport,
) -> Result<(), String> {
    let value = interop_matrix_json_value(report);
    serde_json::to_writer_pretty(&mut *writer, &value).map_err(|error| error.to_string())?;
    writeln!(writer).map_err(|error| error.to_string())
}

fn interop_matrix_json_value(report: &InteropMatrixReport) -> serde_json::Value {
    let entries: Vec<_> = report
        .entries
        .iter()
        .map(|entry| {
            serde_json::json!({
                "protocol": entry.protocol,
                "tcp_relay_supported": entry.tcp_relay_supported,
                "udp_relay_supported": entry.udp_relay_supported,
                "covered_transports": &entry.covered_transports,
                "profile_sources": &entry.profile_sources,
                "sample_profile_count": entry.sample_profile_count,
                "validation_supported": entry.validation_supported,
                "validated_profile_count": entry.validated_profile_count,
                "validation_error": entry.validation_error.as_deref(),
                "registry_supported": entry.registry_supported,
                "registry_profile_count": entry.registry_profile_count,
                "registry_error": entry.registry_error.as_deref(),
            })
        })
        .collect();

    serde_json::json!({
        "status": "ok",
        "kind": "keli_interop_matrix",
        "schema_version": report.schema_version,
        "version": report.version,
        "summary": {
            "protocol_count": report.summary.protocol_count,
            "tcp_relay_supported_count": report.summary.tcp_relay_supported_count,
            "udp_relay_supported_count": report.summary.udp_relay_supported_count,
            "profile_source_supported_count": report.summary.profile_source_supported_count,
            "validation_supported_count": report.summary.validation_supported_count,
            "registry_supported_count": report.summary.registry_supported_count,
            "sample_profile_count": report.summary.sample_profile_count,
            "registry_profile_count": report.summary.registry_profile_count,
        },
        "entries": entries,
    })
}

fn interop_matrix_entry_from_spec(spec: InteropMatrixSpec) -> InteropMatrixEntry {
    let sample_profile_count = spec.sample_profiles.len();
    let mut validated_profile_count = 0;
    let mut validation_error = None;
    for profile in &spec.sample_profiles {
        match profile.validate() {
            Ok(()) => validated_profile_count += 1,
            Err(error) if validation_error.is_none() => {
                validation_error = Some(format!("{}: {error}", profile.tag));
            }
            Err(_) => {}
        }
    }
    let validation_supported = validated_profile_count == sample_profile_count;

    let mut registry_profile_count = 0;
    let mut registry_error = None;
    for profile in &spec.sample_profiles {
        match OutboundRegistry::from_profiles([profile.clone()]) {
            Ok(_) => registry_profile_count += 1,
            Err(error) if registry_error.is_none() => {
                registry_error = Some(format!("{}: {error}", profile.tag));
            }
            Err(_) => {}
        }
    }
    let registry_supported = registry_profile_count == sample_profile_count;

    InteropMatrixEntry {
        protocol: spec.protocol,
        tcp_relay_supported: spec.tcp_relay_supported,
        udp_relay_supported: spec.udp_relay_supported,
        covered_transports: spec.covered_transports,
        profile_sources: spec.profile_sources,
        sample_profile_count,
        validation_supported,
        validated_profile_count,
        validation_error,
        registry_supported,
        registry_profile_count,
        registry_error,
    }
}

fn interop_matrix_specs() -> Vec<InteropMatrixSpec> {
    vec![
        InteropMatrixSpec {
            protocol: "direct",
            tcp_relay_supported: true,
            udp_relay_supported: true,
            covered_transports: vec!["tcp", "udp"],
            profile_sources: vec!["built-in"],
            sample_profiles: Vec::new(),
        },
        InteropMatrixSpec {
            protocol: "trojan",
            tcp_relay_supported: true,
            udp_relay_supported: true,
            covered_transports: vec!["tcp", "ws", "httpupgrade", "grpc", "h2", "quic"],
            profile_sources: interop_profile_sources(),
            sample_profiles: vec![
                interop_profile(
                    "interop-trojan-tcp",
                    ProxyProtocol::Trojan,
                    TransportKind::Tcp,
                    interop_tls_security(),
                    "password",
                ),
                interop_profile(
                    "interop-trojan-ws",
                    ProxyProtocol::Trojan,
                    interop_ws_transport(),
                    SecurityKind::None,
                    "password",
                ),
                interop_profile(
                    "interop-trojan-httpupgrade",
                    ProxyProtocol::Trojan,
                    interop_httpupgrade_transport(),
                    SecurityKind::None,
                    "password",
                ),
                interop_profile(
                    "interop-trojan-grpc",
                    ProxyProtocol::Trojan,
                    interop_grpc_transport(),
                    SecurityKind::None,
                    "password",
                ),
                interop_profile(
                    "interop-trojan-h2",
                    ProxyProtocol::Trojan,
                    interop_h2_transport(),
                    SecurityKind::None,
                    "password",
                ),
                interop_profile(
                    "interop-trojan-quic",
                    ProxyProtocol::Trojan,
                    interop_quic_transport(),
                    SecurityKind::None,
                    "password",
                ),
            ],
        },
        InteropMatrixSpec {
            protocol: "vless",
            tcp_relay_supported: true,
            udp_relay_supported: true,
            covered_transports: vec!["tcp", "ws", "httpupgrade", "grpc", "h2", "quic"],
            profile_sources: interop_profile_sources(),
            sample_profiles: vec![
                interop_uuid_profile(
                    "interop-vless-tcp",
                    ProxyProtocol::Vless,
                    TransportKind::Tcp,
                ),
                interop_uuid_profile(
                    "interop-vless-ws",
                    ProxyProtocol::Vless,
                    interop_ws_transport(),
                ),
                interop_uuid_profile(
                    "interop-vless-httpupgrade",
                    ProxyProtocol::Vless,
                    interop_httpupgrade_transport(),
                ),
                interop_uuid_profile(
                    "interop-vless-grpc",
                    ProxyProtocol::Vless,
                    interop_grpc_transport(),
                ),
                interop_uuid_profile(
                    "interop-vless-h2",
                    ProxyProtocol::Vless,
                    interop_h2_transport(),
                ),
                interop_uuid_profile(
                    "interop-vless-quic",
                    ProxyProtocol::Vless,
                    interop_quic_transport(),
                ),
            ],
        },
        InteropMatrixSpec {
            protocol: "vmess",
            tcp_relay_supported: true,
            udp_relay_supported: true,
            covered_transports: vec!["tcp", "ws", "httpupgrade", "grpc", "h2", "quic"],
            profile_sources: interop_profile_sources(),
            sample_profiles: vec![
                interop_vmess_profile("interop-vmess-tcp", TransportKind::Tcp),
                interop_vmess_profile("interop-vmess-ws", interop_ws_transport()),
                interop_vmess_profile("interop-vmess-httpupgrade", interop_httpupgrade_transport()),
                interop_vmess_profile("interop-vmess-grpc", interop_grpc_transport()),
                interop_vmess_profile("interop-vmess-h2", interop_h2_transport()),
                interop_vmess_profile("interop-vmess-quic", interop_quic_transport()),
            ],
        },
        InteropMatrixSpec {
            protocol: "shadowsocks",
            tcp_relay_supported: true,
            udp_relay_supported: true,
            covered_transports: vec!["tcp"],
            profile_sources: interop_profile_sources(),
            sample_profiles: vec![interop_shadowsocks_profile()],
        },
        InteropMatrixSpec {
            protocol: "anytls",
            tcp_relay_supported: true,
            udp_relay_supported: true,
            covered_transports: vec!["tls-tcp"],
            profile_sources: interop_profile_sources(),
            sample_profiles: vec![interop_profile(
                "interop-anytls",
                ProxyProtocol::AnyTls,
                TransportKind::Tcp,
                interop_tls_security(),
                "password",
            )],
        },
        InteropMatrixSpec {
            protocol: "naive",
            tcp_relay_supported: true,
            udp_relay_supported: false,
            covered_transports: vec!["h2", "h3"],
            profile_sources: interop_profile_sources(),
            sample_profiles: vec![
                interop_profile(
                    "interop-naive-h2",
                    ProxyProtocol::Naive,
                    TransportKind::Tcp,
                    interop_tls_security(),
                    "user:password",
                ),
                interop_profile(
                    "interop-naive-h3",
                    ProxyProtocol::Naive,
                    interop_quic_transport(),
                    interop_tls_security(),
                    "user:password",
                ),
            ],
        },
        InteropMatrixSpec {
            protocol: "mieru",
            tcp_relay_supported: true,
            udp_relay_supported: true,
            covered_transports: vec!["tcp"],
            profile_sources: interop_profile_sources(),
            sample_profiles: vec![interop_profile(
                "interop-mieru",
                ProxyProtocol::Mieru,
                TransportKind::Tcp,
                SecurityKind::None,
                "user:password",
            )],
        },
        InteropMatrixSpec {
            protocol: "hy2",
            tcp_relay_supported: true,
            udp_relay_supported: true,
            covered_transports: vec!["quic"],
            profile_sources: interop_profile_sources(),
            sample_profiles: vec![interop_profile(
                "interop-hy2",
                ProxyProtocol::Hy2,
                interop_quic_transport(),
                interop_tls_security(),
                "password",
            )],
        },
        InteropMatrixSpec {
            protocol: "tuic",
            tcp_relay_supported: true,
            udp_relay_supported: true,
            covered_transports: vec!["quic"],
            profile_sources: interop_profile_sources(),
            sample_profiles: vec![interop_profile(
                "interop-tuic",
                ProxyProtocol::Tuic,
                interop_quic_transport(),
                interop_tls_security(),
                &format!("{INTEROP_SAMPLE_UUID}:password"),
            )],
        },
        InteropMatrixSpec {
            protocol: "socks5",
            tcp_relay_supported: true,
            udp_relay_supported: true,
            covered_transports: vec!["tcp", "udp-associate"],
            profile_sources: interop_profile_sources(),
            sample_profiles: vec![interop_profile(
                "interop-socks5",
                ProxyProtocol::Socks,
                TransportKind::Tcp,
                SecurityKind::None,
                "",
            )],
        },
        InteropMatrixSpec {
            protocol: "http",
            tcp_relay_supported: true,
            udp_relay_supported: false,
            covered_transports: vec!["connect"],
            profile_sources: interop_profile_sources(),
            sample_profiles: vec![interop_profile(
                "interop-http",
                ProxyProtocol::Http,
                TransportKind::Tcp,
                SecurityKind::None,
                "",
            )],
        },
    ]
}

fn interop_profile_sources() -> Vec<&'static str> {
    vec!["mihomo-yaml", "share-link"]
}

fn interop_uuid_profile(
    tag: &'static str,
    protocol: ProxyProtocol,
    transport: TransportKind,
) -> OutboundProfile {
    interop_profile(
        tag,
        protocol,
        transport,
        SecurityKind::None,
        INTEROP_SAMPLE_UUID,
    )
}

fn interop_vmess_profile(tag: &'static str, transport: TransportKind) -> OutboundProfile {
    OutboundProfile {
        cipher: Some("auto".to_string()),
        ..interop_uuid_profile(tag, ProxyProtocol::Vmess, transport)
    }
}

fn interop_shadowsocks_profile() -> OutboundProfile {
    OutboundProfile {
        cipher: Some("aes-256-gcm".to_string()),
        ..interop_profile(
            "interop-shadowsocks",
            ProxyProtocol::Shadowsocks,
            TransportKind::Tcp,
            SecurityKind::None,
            "password",
        )
    }
}

fn interop_profile(
    tag: &'static str,
    protocol: ProxyProtocol,
    transport: TransportKind,
    security: SecurityKind,
    credential: impl Into<String>,
) -> OutboundProfile {
    OutboundProfile {
        tag: tag.to_string(),
        protocol,
        endpoint: Endpoint::new("interop.example.com", 443),
        transport,
        security,
        credential: credential.into(),
        cipher: None,
        flow: None,
    }
}

fn interop_tls_security() -> SecurityKind {
    SecurityKind::Tls {
        sni: Some("interop.example.com".to_string()),
        skip_verify: true,
    }
}

fn interop_ws_transport() -> TransportKind {
    TransportKind::WebSocket {
        path: "/interop".to_string(),
        host: Some("interop.example.com".to_string()),
    }
}

fn interop_httpupgrade_transport() -> TransportKind {
    TransportKind::HttpUpgrade {
        path: "/interop".to_string(),
        host: Some("interop.example.com".to_string()),
    }
}

fn interop_h2_transport() -> TransportKind {
    TransportKind::Http2 {
        path: "/interop".to_string(),
        host: Some("interop.example.com".to_string()),
    }
}

fn interop_grpc_transport() -> TransportKind {
    TransportKind::Grpc {
        service_name: Some("interop".to_string()),
    }
}

fn interop_quic_transport() -> TransportKind {
    TransportKind::Quic {
        security: None,
        key: None,
        header_type: None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultCoreReadinessReport {
    pub schema_version: u32,
    pub version: &'static str,
    pub ready_for_default_core: bool,
    pub soak_min_duration: Duration,
    pub gates: Vec<ReadinessGateReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultCoreCertificationReport {
    pub schema_version: u32,
    pub version: &'static str,
    pub ready_for_default_core: bool,
    pub readiness: DefaultCoreReadinessReport,
    pub tun_backend: TunBackendStatus,
    pub soak_connections: usize,
    pub first_byte_timeout: Duration,
    pub max_connection_workers: usize,
    pub soak_min_duration: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessGateReport {
    pub name: &'static str,
    pub category: &'static str,
    pub status: ReadinessGateStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessGateStatus {
    Passed,
    Failed,
    Warning,
    Skipped,
}

impl ReadinessGateStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Warning => "warning",
            Self::Skipped => "skipped",
        }
    }
}

pub fn write_readiness_check_report(
    output: ProbeOutputFormat,
    soak_connections: usize,
    first_byte_timeout: Duration,
    max_connection_workers: usize,
    skip_soak: bool,
    mut writer: impl Write,
) -> Result<(), String> {
    write_readiness_check_report_with_soak_min_duration(
        output,
        soak_connections,
        first_byte_timeout,
        max_connection_workers,
        DEFAULT_MIXED_SOAK_MIN_DURATION,
        skip_soak,
        &mut writer,
    )
}

pub fn write_readiness_check_report_with_soak_min_duration(
    output: ProbeOutputFormat,
    soak_connections: usize,
    first_byte_timeout: Duration,
    max_connection_workers: usize,
    soak_min_duration: Duration,
    skip_soak: bool,
    mut writer: impl Write,
) -> Result<(), String> {
    let report = collect_readiness_check_report(
        soak_connections,
        first_byte_timeout,
        max_connection_workers,
        soak_min_duration,
        skip_soak,
    )?;
    match output {
        ProbeOutputFormat::Text => write_readiness_check_text_report(&mut writer, &report),
        ProbeOutputFormat::Json => write_readiness_check_json_report(&mut writer, &report),
    }
}

pub fn write_default_core_certification_report(
    output: ProbeOutputFormat,
    soak_connections: usize,
    first_byte_timeout: Duration,
    max_connection_workers: usize,
    mut writer: impl Write,
) -> Result<(), String> {
    write_default_core_certification_report_with_soak_min_duration(
        output,
        soak_connections,
        first_byte_timeout,
        max_connection_workers,
        DEFAULT_MIXED_SOAK_MIN_DURATION,
        &mut writer,
    )
}

pub fn write_default_core_certification_report_with_soak_min_duration(
    output: ProbeOutputFormat,
    soak_connections: usize,
    first_byte_timeout: Duration,
    max_connection_workers: usize,
    soak_min_duration: Duration,
    mut writer: impl Write,
) -> Result<(), String> {
    let report = collect_default_core_certification_report(
        soak_connections,
        first_byte_timeout,
        max_connection_workers,
        soak_min_duration,
    )?;
    match output {
        ProbeOutputFormat::Text => {
            write_default_core_certification_text_report(&mut writer, &report)
        }
        ProbeOutputFormat::Json => {
            write_default_core_certification_json_report(&mut writer, &report)
        }
    }
}

fn collect_default_core_certification_report(
    soak_connections: usize,
    first_byte_timeout: Duration,
    max_connection_workers: usize,
    soak_min_duration: Duration,
) -> Result<DefaultCoreCertificationReport, String> {
    if soak_connections == 0 {
        return Err("default-core-certify soak connections must be greater than 0".to_string());
    }
    if max_connection_workers == 0 {
        return Err(
            "default-core-certify max connection workers must be greater than 0".to_string(),
        );
    }

    let readiness = collect_readiness_check_report(
        soak_connections,
        first_byte_timeout,
        max_connection_workers,
        soak_min_duration,
        false,
    )?;
    let tun_backend = TunBackendStatus::detect();
    let ready_for_default_core = readiness.ready_for_default_core && tun_backend.is_ready();

    Ok(DefaultCoreCertificationReport {
        schema_version: DEFAULT_CORE_CERTIFICATION_SCHEMA_VERSION,
        version: env!("CARGO_PKG_VERSION"),
        ready_for_default_core,
        readiness,
        tun_backend,
        soak_connections,
        first_byte_timeout,
        max_connection_workers,
        soak_min_duration,
    })
}

fn collect_readiness_check_report(
    soak_connections: usize,
    first_byte_timeout: Duration,
    max_connection_workers: usize,
    soak_min_duration: Duration,
    skip_soak: bool,
) -> Result<DefaultCoreReadinessReport, String> {
    if soak_connections == 0 {
        return Err("readiness-check soak connections must be greater than 0".to_string());
    }
    if max_connection_workers == 0 {
        return Err("readiness-check max connection workers must be greater than 0".to_string());
    }

    let doctor = collect_doctor_report();
    let interop = collect_interop_matrix_report();
    let tun_preflight = collect_default_tun_preflight();
    let mut gates = vec![
        readiness_gate(
            "doctor-schema",
            "diagnostics",
            doctor.doctor_report_schema_version == DOCTOR_REPORT_SCHEMA_VERSION
                && doctor.readiness_check_schema_version == READINESS_CHECK_SCHEMA_VERSION
                && doctor.default_core_certification_schema_version
                    == DEFAULT_CORE_CERTIFICATION_SCHEMA_VERSION,
            format!(
                "doctor_schema={} readiness_schema={} default_core_certification_schema={} support_bundle_schema={} managed_status_schema={}",
                doctor.doctor_report_schema_version,
                doctor.readiness_check_schema_version,
                doctor.default_core_certification_schema_version,
                doctor.support_bundle_schema_version,
                doctor.managed_mixed_status_schema_version
            ),
        ),
        readiness_gate(
            "interop-matrix",
            "protocols",
            interop.summary.validation_supported_count == interop.summary.protocol_count
                && interop.summary.registry_supported_count == interop.summary.protocol_count
                && interop.summary.registry_profile_count == interop.summary.sample_profile_count,
            format!(
                "protocols={} validation_supported={} registry_supported={} registry_profiles={}/{}",
                interop.summary.protocol_count,
                interop.summary.validation_supported_count,
                interop.summary.registry_supported_count,
                interop.summary.registry_profile_count,
                interop.summary.sample_profile_count
            ),
        ),
        readiness_gate(
            "udp-coverage",
            "protocols",
            interop.summary.udp_relay_supported_count >= 10,
            format!(
                "udp_supported_protocols={} protocol_count={}",
                interop.summary.udp_relay_supported_count, interop.summary.protocol_count
            ),
        ),
        readiness_gate(
            "resource-limits",
            "stability",
            doctor.runtime_event_history_limit > 0
                && doctor.managed_status_recent_event_limit > 0
                && doctor.managed_connection_report_history_limit > 0
                && doctor.managed_connection_worker_limit > 0
                && doctor.tun_tcp_max_active_sessions_default > 0,
            format!(
                "runtime_events={} recent_events={} connection_history={} workers={} tun_tcp_sessions={}",
                doctor.runtime_event_history_limit,
                doctor.managed_status_recent_event_limit,
                doctor.managed_connection_report_history_limit,
                doctor.managed_connection_worker_limit,
                doctor.tun_tcp_max_active_sessions_default
            ),
        ),
        readiness_gate(
            "panel-subscription-state",
            "managed-runtime",
            doctor
                .managed_status_schema_capabilities
                .contains(&"panel-state")
                && doctor
                    .managed_status_schema_capabilities
                    .contains(&"subscription-url-update-status")
                && doctor
                    .managed_status_schema_capabilities
                    .contains(&"node-health-udp-aware-recommendation"),
            "panel-state subscription-url-update-status node-health-udp-aware-recommendation".to_string(),
        ),
        readiness_gate(
            "support-diagnostics",
            "diagnostics",
            doctor
                .stability_diagnostic_capabilities
                .contains(&"local-mixed-soak")
                && doctor
                    .interop_matrix_capabilities
                    .contains(&"support-bundle-export")
                && doctor
                    .readiness_check_capabilities
                    .contains(&"json-gates"),
            "support bundle exports doctor and interop matrix; readiness exposes json gates".to_string(),
        ),
        readiness_gate(
            "system-proxy-platform",
            "platform",
            doctor.system_proxy_supported,
            format!(
                "supported={} state={}",
                doctor.system_proxy_supported, doctor.system_proxy_state
            ),
        ),
        readiness_gate(
            "tun-backend",
            "platform",
            doctor.tun_backend.is_ready(),
            format!(
                "platform={:?} backend={} supported={} driver_library_present={} driver_api_available={} install_required={} lifecycle_wired={} packet_io_wired={} route_takeover_wired={} driver_api_error={} reason={}",
                doctor.tun_backend.platform,
                doctor.tun_backend.backend_label(),
                doctor.tun_backend.supported,
                doctor.tun_backend.driver_library_present,
                doctor.tun_backend.driver_api_available,
                doctor.tun_backend.install_required,
                doctor.tun_backend.lifecycle_wired,
                doctor.tun_backend.packet_io_wired,
                doctor.tun_backend.route_takeover_wired,
                doctor.tun_backend.driver_api_error.as_deref().unwrap_or("-"),
                doctor.tun_backend.reason.as_deref().unwrap_or("-")
            ),
        ),
        readiness_gate(
            "tun-preflight",
            "platform",
            tun_preflight.ready,
            format!(
                "status={} interface={} address={} mtu={} reason={}",
                tun_preflight.readiness.label(),
                tun_preflight.config.interface_name,
                tun_preflight.config.address_cidr,
                tun_preflight.config.mtu,
                tun_preflight.reason.as_deref().unwrap_or("-")
            ),
        ),
    ];

    if skip_soak {
        gates.push(ReadinessGateReport {
            name: "mixed-soak-socks5",
            category: "stability",
            status: ReadinessGateStatus::Skipped,
            detail: format!(
                "skipped by --skip-soak; planned_connections={soak_connections} planned_min_duration_ms={}",
                duration_millis_for_report(soak_min_duration)
            ),
        });
        gates.push(ReadinessGateReport {
            name: "mixed-soak-http-connect",
            category: "stability",
            status: ReadinessGateStatus::Skipped,
            detail: format!(
                "skipped by --skip-soak; planned_connections={soak_connections} planned_min_duration_ms={}",
                duration_millis_for_report(soak_min_duration)
            ),
        });
    } else {
        gates.push(readiness_soak_gate(
            "mixed-soak-socks5",
            SmokeInboundKind::Socks5,
            soak_connections,
            first_byte_timeout,
            max_connection_workers,
            soak_min_duration,
        ));
        gates.push(readiness_soak_gate(
            "mixed-soak-http-connect",
            SmokeInboundKind::HttpConnect,
            soak_connections,
            first_byte_timeout,
            max_connection_workers,
            soak_min_duration,
        ));
    }

    let ready_for_default_core = gates
        .iter()
        .all(|gate| gate.status == ReadinessGateStatus::Passed);

    Ok(DefaultCoreReadinessReport {
        schema_version: READINESS_CHECK_SCHEMA_VERSION,
        version: env!("CARGO_PKG_VERSION"),
        ready_for_default_core,
        soak_min_duration,
        gates,
    })
}

fn readiness_gate(
    name: &'static str,
    category: &'static str,
    passed: bool,
    detail: String,
) -> ReadinessGateReport {
    ReadinessGateReport {
        name,
        category,
        status: if passed {
            ReadinessGateStatus::Passed
        } else {
            ReadinessGateStatus::Failed
        },
        detail,
    }
}

fn readiness_soak_gate(
    name: &'static str,
    inbound: SmokeInboundKind,
    soak_connections: usize,
    first_byte_timeout: Duration,
    max_connection_workers: usize,
    soak_min_duration: Duration,
) -> ReadinessGateReport {
    match run_soak_mixed_with_min_duration(
        soak_connections,
        inbound,
        first_byte_timeout,
        max_connection_workers,
        soak_min_duration,
    ) {
        Ok(report) => readiness_gate(
            name,
            "stability",
            report.completed_connections == report.requested_connections
                && report.failed_connections == 0
                && report.connection_metrics.failure_count == 0
                && report.duration_target_met
                && !report.stop_drain.timed_out
                && report.stop_drain.workers_remaining == 0,
            format!(
                "inbound={} completed={}/{} failures={} elapsed_ms={} min_duration_ms={} duration_target_met={} stop_workers_remaining={} stop_timed_out={}",
                inbound.cli_value(),
                report.completed_connections,
                report.requested_connections,
                report.failed_connections,
                duration_millis_for_report(report.elapsed),
                duration_millis_for_report(report.min_duration),
                report.duration_target_met,
                report.stop_drain.workers_remaining,
                report.stop_drain.timed_out
            ),
        ),
        Err(error) => ReadinessGateReport {
            name,
            category: "stability",
            status: ReadinessGateStatus::Failed,
            detail: error,
        },
    }
}

fn write_readiness_check_text_report(
    writer: &mut impl Write,
    report: &DefaultCoreReadinessReport,
) -> Result<(), String> {
    let summary = readiness_summary_counts(&report.gates);
    writeln!(
        writer,
        "readiness status={} schema_version={} gates={} passed={} failed={} warning={} skipped={} blockers={}",
        if report.ready_for_default_core {
            "ready"
        } else {
            "not-ready"
        },
        report.schema_version,
        summary.total,
        summary.passed,
        summary.failed,
        summary.warning,
        summary.skipped,
        summary.blocking
    )
    .map_err(|error| error.to_string())?;
    for gate in &report.gates {
        writeln!(
            writer,
            "readiness gate={} category={} status={} detail={}",
            gate.name,
            gate.category,
            gate.status.label(),
            gate.detail
        )
        .map_err(|error| error.to_string())?;
    }
    writeln!(
        writer,
        "readiness parameters soak_min_duration_ms={}",
        duration_millis_for_report(report.soak_min_duration)
    )
    .map_err(|error| error.to_string())?;
    for gate in readiness_blocking_gates(&report.gates) {
        writeln!(
            writer,
            "readiness blocker={} category={} status={} detail={}",
            gate.name,
            gate.category,
            gate.status.label(),
            gate.detail
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn write_readiness_check_json_report(
    writer: &mut impl Write,
    report: &DefaultCoreReadinessReport,
) -> Result<(), String> {
    let value = readiness_check_json_value(report);
    serde_json::to_writer_pretty(&mut *writer, &value).map_err(|error| error.to_string())?;
    writeln!(writer).map_err(|error| error.to_string())
}

fn readiness_check_json_value(report: &DefaultCoreReadinessReport) -> serde_json::Value {
    let summary = readiness_summary_counts(&report.gates);
    let gates: Vec<_> = report.gates.iter().map(readiness_gate_json_value).collect();
    let blocking_gates: Vec<_> = readiness_blocking_gates(&report.gates)
        .into_iter()
        .map(readiness_gate_json_value)
        .collect();
    serde_json::json!({
        "status": if report.ready_for_default_core { "ready" } else { "not-ready" },
        "kind": "keli_default_core_readiness",
        "schema_version": report.schema_version,
        "version": report.version,
        "ready_for_default_core": report.ready_for_default_core,
        "soak_min_duration_ms": duration_millis_for_report(report.soak_min_duration),
        "summary": {
            "total_gate_count": summary.total,
            "passed_gate_count": summary.passed,
            "failed_gate_count": summary.failed,
            "warning_gate_count": summary.warning,
            "skipped_gate_count": summary.skipped,
            "blocking_gate_count": summary.blocking,
        },
        "gates": gates,
        "blocking_gates": blocking_gates,
    })
}

fn readiness_gate_json_value(gate: &ReadinessGateReport) -> serde_json::Value {
    serde_json::json!({
        "name": gate.name,
        "category": gate.category,
        "status": gate.status.label(),
        "detail": gate.detail,
    })
}

fn readiness_blocking_gates(gates: &[ReadinessGateReport]) -> Vec<&ReadinessGateReport> {
    gates
        .iter()
        .filter(|gate| gate.status != ReadinessGateStatus::Passed)
        .collect()
}

fn write_default_core_certification_text_report(
    writer: &mut impl Write,
    report: &DefaultCoreCertificationReport,
) -> Result<(), String> {
    let summary = readiness_summary_counts(&report.readiness.gates);
    writeln!(
        writer,
        "default_core_certification status={} schema_version={} version={} ready_for_default_core={} gates={} passed={} failed={} warning={} skipped={} blockers={} tun_backend_status={} install_required={} driver_library_present={} driver_api_available={} driver_library_path={}",
        if report.ready_for_default_core {
            "ready"
        } else {
            "not-ready"
        },
        report.schema_version,
        report.version,
        report.ready_for_default_core,
        summary.total,
        summary.passed,
        summary.failed,
        summary.warning,
        summary.skipped,
        summary.blocking,
        if report.tun_backend.is_ready() {
            "ready"
        } else {
            "not-ready"
        },
        report.tun_backend.install_required,
        report.tun_backend.driver_library_present,
        report.tun_backend.driver_api_available,
        report
            .tun_backend
            .driver_library_path
            .as_deref()
            .unwrap_or("-")
    )
    .map_err(|error| error.to_string())?;
    writeln!(
        writer,
        "default_core_certification parameters soak_connections={} first_byte_timeout_ms={} max_connection_workers={} soak_min_duration_ms={}",
        report.soak_connections,
        duration_millis_for_report(report.first_byte_timeout),
        report.max_connection_workers,
        duration_millis_for_report(report.soak_min_duration)
    )
    .map_err(|error| error.to_string())?;
    for gate in readiness_blocking_gates(&report.readiness.gates) {
        writeln!(
            writer,
            "default_core_certification promotion_blocker={} category={} status={} detail={}",
            gate.name,
            gate.category,
            gate.status.label(),
            gate.detail
        )
        .map_err(|error| error.to_string())?;
    }
    for gate in &report.readiness.gates {
        writeln!(
            writer,
            "default_core_certification readiness_gate={} category={} status={} detail={}",
            gate.name,
            gate.category,
            gate.status.label(),
            gate.detail
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn write_default_core_certification_json_report(
    writer: &mut impl Write,
    report: &DefaultCoreCertificationReport,
) -> Result<(), String> {
    let value = default_core_certification_json_value(report);
    serde_json::to_writer_pretty(&mut *writer, &value).map_err(|error| error.to_string())?;
    writeln!(writer).map_err(|error| error.to_string())
}

fn default_core_certification_json_value(
    report: &DefaultCoreCertificationReport,
) -> serde_json::Value {
    let summary = readiness_summary_counts(&report.readiness.gates);
    let promotion_blockers: Vec<_> = readiness_blocking_gates(&report.readiness.gates)
        .into_iter()
        .map(readiness_gate_json_value)
        .collect();
    serde_json::json!({
        "status": if report.ready_for_default_core { "ready" } else { "not-ready" },
        "kind": "keli_default_core_certification",
        "schema_version": report.schema_version,
        "version": report.version,
        "ready_for_default_core": report.ready_for_default_core,
        "certification": {
            "ready_for_default_core": report.ready_for_default_core,
            "soak_connections": report.soak_connections,
            "first_byte_timeout_ms": duration_millis_for_report(report.first_byte_timeout),
            "max_connection_workers": report.max_connection_workers,
            "soak_min_duration_ms": duration_millis_for_report(report.soak_min_duration),
            "failed_gate_count": summary.failed,
            "warning_gate_count": summary.warning,
            "skipped_gate_count": summary.skipped,
            "blocking_gate_count": summary.blocking,
            "tun_backend_ready": report.tun_backend.is_ready(),
        },
        "readiness": readiness_check_json_value(&report.readiness),
        "promotion_blockers": promotion_blockers,
        "tun_backend_status": if report.tun_backend.is_ready() { "ready" } else { "not-ready" },
        "tun_backend": tun_backend_json_value(&report.tun_backend),
    })
}

fn duration_millis_for_report(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadinessSummaryCounts {
    total: usize,
    passed: usize,
    failed: usize,
    warning: usize,
    skipped: usize,
    blocking: usize,
}

fn readiness_summary_counts(gates: &[ReadinessGateReport]) -> ReadinessSummaryCounts {
    let mut summary = ReadinessSummaryCounts {
        total: gates.len(),
        passed: 0,
        failed: 0,
        warning: 0,
        skipped: 0,
        blocking: 0,
    };
    for gate in gates {
        match gate.status {
            ReadinessGateStatus::Passed => summary.passed += 1,
            ReadinessGateStatus::Failed => summary.failed += 1,
            ReadinessGateStatus::Warning => summary.warning += 1,
            ReadinessGateStatus::Skipped => summary.skipped += 1,
        }
        if gate.status != ReadinessGateStatus::Passed {
            summary.blocking += 1;
        }
    }
    summary
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
        "device supported={} lifecycle_available={} packet_io_available={} state={} interface={} address={} mtu={} dns_hijack={} error={}",
        preflight.status.supported,
        preflight.status.lifecycle_available,
        preflight.status.packet_io_available,
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
            "packet_io_available": preflight.status.packet_io_available,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SubscriptionFetchOptions {
    url: String,
    timeout: Duration,
    max_bytes: usize,
    user_agent: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SubscriptionFetchSource {
    scheme: String,
    host: String,
    port: u16,
    default_port: bool,
    path_present: bool,
    query_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SubscriptionFetchResponse {
    source: SubscriptionFetchSource,
    status_code: u16,
    body: String,
    body_bytes: usize,
    elapsed: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubscriptionFetchErrorKind {
    InvalidUrl,
    UnsupportedScheme,
    MissingHost,
    Resolve,
    Connect,
    Tls,
    Write,
    Read,
    ResponseTooLarge,
    InvalidResponse,
    HttpStatus,
    Utf8,
}

impl SubscriptionFetchErrorKind {
    fn label(self) -> &'static str {
        match self {
            Self::InvalidUrl => "invalid-url",
            Self::UnsupportedScheme => "unsupported-scheme",
            Self::MissingHost => "missing-host",
            Self::Resolve => "resolve",
            Self::Connect => "connect",
            Self::Tls => "tls",
            Self::Write => "write",
            Self::Read => "read",
            Self::ResponseTooLarge => "response-too-large",
            Self::InvalidResponse => "invalid-response",
            Self::HttpStatus => "http-status",
            Self::Utf8 => "utf8",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SubscriptionFetchError {
    kind: SubscriptionFetchErrorKind,
    detail: String,
    source: Option<SubscriptionFetchSource>,
}

impl SubscriptionFetchError {
    fn new(
        kind: SubscriptionFetchErrorKind,
        detail: impl Into<String>,
        source: Option<SubscriptionFetchSource>,
    ) -> Self {
        Self {
            kind,
            detail: detail.into(),
            source,
        }
    }
}

pub fn write_subscription_fetch_report_from_url(
    url: &str,
    output: ProbeOutputFormat,
    timeout: Duration,
    max_bytes: usize,
    mut writer: impl Write,
) -> Result<(), String> {
    let options = subscription_fetch_options(url, timeout, max_bytes);
    let report = subscription_fetch_report_value(fetch_subscription_config_text(&options));

    match output {
        ProbeOutputFormat::Text => write_subscription_fetch_text_report(&mut writer, &report),
        ProbeOutputFormat::Json => {
            serde_json::to_writer_pretty(&mut writer, &report)
                .map_err(|error| error.to_string())?;
            writeln!(writer).map_err(|error| error.to_string())
        }
    }
}

fn subscription_fetch_options(
    url: &str,
    timeout: Duration,
    max_bytes: usize,
) -> SubscriptionFetchOptions {
    SubscriptionFetchOptions {
        url: url.to_string(),
        timeout,
        max_bytes,
        user_agent: format!("keli-native-client/{}", env!("CARGO_PKG_VERSION")),
    }
}

fn write_subscription_fetch_text_report(
    writer: &mut impl Write,
    report: &serde_json::Value,
) -> Result<(), String> {
    let fetch = &report["fetch"];
    let source = &fetch["source"];
    let profile = &report["profile"];
    let status = report["status"].as_str().unwrap_or("error");
    let fetch_status = fetch["status"].as_str().unwrap_or("error");
    let scheme = source["scheme"].as_str().unwrap_or("-");
    let host = source["host"].as_str().unwrap_or("-");
    let port = source["port"]
        .as_u64()
        .map(|port| port.to_string())
        .unwrap_or_else(|| "-".to_string());

    if fetch_status == "ok" {
        writeln!(
            writer,
            "subscription-fetch status={} fetch_status=ok scheme={} host={} port={} http_status={} bytes={} elapsed_ms={} source_format={} supported={} skipped={} default_outbound={}",
            status,
            scheme,
            host,
            port,
            fetch["http_status"].as_u64().unwrap_or(0),
            fetch["body_bytes"].as_u64().unwrap_or(0),
            fetch["elapsed_ms"].as_u64().unwrap_or(0),
            profile["source_format"].as_str().unwrap_or("-"),
            profile["supported_count"].as_u64().unwrap_or(0),
            profile["skipped_count"].as_u64().unwrap_or(0),
            profile["default_outbound"].as_str().unwrap_or("-"),
        )
        .map_err(|error| error.to_string())
    } else {
        writeln!(
            writer,
            "subscription-fetch status=error fetch_status=error scheme={} host={} port={} error_kind={} error_detail={}",
            scheme,
            host,
            port,
            fetch["error_kind"].as_str().unwrap_or("unknown"),
            fetch["error_detail"].as_str().unwrap_or("-"),
        )
        .map_err(|error| error.to_string())
    }
}

fn subscription_fetch_report_value(
    result: Result<SubscriptionFetchResponse, SubscriptionFetchError>,
) -> serde_json::Value {
    match result {
        Ok(response) => {
            let profile = support_bundle_profile_value(Some(&response.body));
            let profile_status = profile["status"].as_str().unwrap_or("error");
            serde_json::json!({
                "status": if profile_status == "ok" { "ok" } else { "error" },
                "kind": "keli_subscription_fetch",
                "fetch": {
                    "status": "ok",
                    "source": subscription_fetch_source_json_value(&response.source),
                    "http_status": response.status_code,
                    "body_bytes": response.body_bytes,
                    "elapsed_ms": duration_millis(response.elapsed),
                },
                "profile": profile,
                "redaction": {
                    "source_url": "scheme-host-port-flags-only",
                    "profile_config_text": "omitted",
                    "credentials": "omitted",
                    "server_endpoints": "omitted",
                },
            })
        }
        Err(error) => serde_json::json!({
            "status": "error",
            "kind": "keli_subscription_fetch",
            "fetch": {
                "status": "error",
                "source": error.source.as_ref().map(subscription_fetch_source_json_value),
                "error_kind": error.kind.label(),
                "error_detail": error.detail,
            },
            "profile": serde_json::Value::Null,
            "redaction": {
                "source_url": "scheme-host-port-flags-only",
                "profile_config_text": "omitted",
                "credentials": "omitted",
                "server_endpoints": "omitted",
            },
        }),
    }
}

pub fn write_subscription_update_report_from_config_text(
    current_config_text: Option<&str>,
    new_config_text: &str,
    current_outbound: Option<&str>,
    output: ProbeOutputFormat,
    mut writer: impl Write,
) -> Result<(), String> {
    let result = plan_subscription_update(current_config_text, new_config_text, current_outbound);
    let report = subscription_update_report_value(result, current_config_text, new_config_text);

    match output {
        ProbeOutputFormat::Text => write_subscription_update_text_report(&mut writer, &report),
        ProbeOutputFormat::Json => {
            serde_json::to_writer_pretty(&mut writer, &report)
                .map_err(|error| error.to_string())?;
            writeln!(writer).map_err(|error| error.to_string())
        }
    }
}

fn write_subscription_update_text_report(
    writer: &mut impl Write,
    report: &serde_json::Value,
) -> Result<(), String> {
    let update = &report["update"];
    if report["status"].as_str().unwrap_or("error") == "ok" {
        writeln!(
            writer,
            "subscription-update status=ok usable={} reason={} current_supported={} new_supported={} new_skipped={} current_selected={} planned_selected={} preserved={} changed={} added={} removed={} retained={}",
            update["usable"].as_bool().unwrap_or(false),
            update["reason"].as_str().unwrap_or("-"),
            update["current_supported_count"].as_u64().unwrap_or(0),
            update["new_supported_count"].as_u64().unwrap_or(0),
            update["new_skipped_count"].as_u64().unwrap_or(0),
            update["current_selected_outbound"].as_str().unwrap_or("-"),
            update["planned_selected_outbound"].as_str().unwrap_or("-"),
            update["selected_outbound_preserved"].as_bool().unwrap_or(false),
            update["selected_outbound_changed"].as_bool().unwrap_or(false),
            json_string_array_csv(&update["added_tags"]),
            json_string_array_csv(&update["removed_tags"]),
            json_string_array_csv(&update["retained_tags"]),
        )
        .map_err(|error| error.to_string())
    } else {
        writeln!(
            writer,
            "subscription-update status=error error_kind={} error_detail={}",
            update["error"]["kind"].as_str().unwrap_or("unknown"),
            update["error"]["detail"].as_str().unwrap_or("-"),
        )
        .map_err(|error| error.to_string())
    }
}

fn subscription_update_report_value(
    result: Result<SubscriptionUpdateReport, ClientErrorKind>,
    current_config_text: Option<&str>,
    new_config_text: &str,
) -> serde_json::Value {
    match result {
        Ok(report) => serde_json::json!({
            "status": "ok",
            "kind": "keli_subscription_update",
            "update": subscription_update_json_value(&report),
            "current_profile": support_bundle_profile_value(current_config_text),
            "new_profile": support_bundle_profile_value(Some(new_config_text)),
            "redaction": {
                "profile_config_text": "omitted",
                "credentials": "omitted",
                "server_endpoints": "omitted",
            },
        }),
        Err(error) => serde_json::json!({
            "status": "error",
            "kind": "keli_subscription_update",
            "update": {
                "status": "error",
                "error": client_error_json_value(&error),
            },
            "current_profile": support_bundle_profile_value(current_config_text),
            "new_profile": support_bundle_profile_value(Some(new_config_text)),
            "redaction": {
                "profile_config_text": "omitted",
                "credentials": "omitted",
                "server_endpoints": "omitted",
            },
        }),
    }
}

fn subscription_update_json_value(report: &SubscriptionUpdateReport) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "usable": report.usable,
        "reason": report.reason.label(),
        "current_supported_count": report.current_supported_count,
        "new_supported_count": report.new_supported_count,
        "new_skipped_count": report.new_skipped_count,
        "current_default_outbound": report.current_default_outbound.as_deref(),
        "new_default_outbound": report.new_default_outbound.as_deref(),
        "current_selected_outbound": report.current_selected_outbound.as_deref(),
        "planned_selected_outbound": report.planned_selected_outbound.as_deref(),
        "selected_outbound_preserved": report.selected_outbound_preserved,
        "selected_outbound_changed": report.selected_outbound_changed,
        "added_tags": &report.added_tags,
        "removed_tags": &report.removed_tags,
        "retained_tags": &report.retained_tags,
    })
}

fn json_string_array_csv(value: &serde_json::Value) -> String {
    let joined = value
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    if joined.is_empty() {
        "-".to_string()
    } else {
        joined
    }
}

fn fetch_subscription_config_text(
    options: &SubscriptionFetchOptions,
) -> Result<SubscriptionFetchResponse, SubscriptionFetchError> {
    let started = Instant::now();
    let url = url::Url::parse(&options.url).map_err(|error| {
        SubscriptionFetchError::new(
            SubscriptionFetchErrorKind::InvalidUrl,
            format!("invalid subscription URL: {error}"),
            None,
        )
    })?;
    let source = subscription_fetch_source_from_url(&url)?;

    match url.scheme() {
        "http" => fetch_subscription_over_http(&url, &source, options, started),
        "https" => fetch_subscription_over_https(&url, &source, options, started),
        scheme => Err(SubscriptionFetchError::new(
            SubscriptionFetchErrorKind::UnsupportedScheme,
            format!("unsupported subscription URL scheme: {scheme}"),
            Some(source),
        )),
    }
}

fn fetch_subscription_over_http(
    url: &url::Url,
    source: &SubscriptionFetchSource,
    options: &SubscriptionFetchOptions,
    started: Instant,
) -> Result<SubscriptionFetchResponse, SubscriptionFetchError> {
    let mut stream = connect_subscription_fetch_socket(source, options.timeout)?;
    write_subscription_fetch_request(&mut stream, url, source, &options.user_agent).map_err(
        |error| subscription_fetch_io_error(SubscriptionFetchErrorKind::Write, error, source),
    )?;
    let response = read_subscription_fetch_response(&mut stream, options.max_bytes, source)?;
    parse_subscription_fetch_response(response, source.clone(), started, options.max_bytes)
}

fn fetch_subscription_over_https(
    url: &url::Url,
    source: &SubscriptionFetchSource,
    options: &SubscriptionFetchOptions,
    started: Instant,
) -> Result<SubscriptionFetchResponse, SubscriptionFetchError> {
    let stream = connect_subscription_fetch_socket(source, options.timeout)?;
    let server_name =
        rustls::pki_types::ServerName::try_from(source.host.clone()).map_err(|error| {
            SubscriptionFetchError::new(
                SubscriptionFetchErrorKind::Tls,
                format!("invalid TLS server name: {error}"),
                Some(source.clone()),
            )
        })?;
    let tls_config = subscription_fetch_tls_config()?;
    let connection = rustls::ClientConnection::new(tls_config, server_name).map_err(|error| {
        SubscriptionFetchError::new(
            SubscriptionFetchErrorKind::Tls,
            format!("create TLS connection: {error}"),
            Some(source.clone()),
        )
    })?;
    let mut stream = rustls::StreamOwned::new(connection, stream);
    write_subscription_fetch_request(&mut stream, url, source, &options.user_agent).map_err(
        |error| subscription_fetch_io_error(SubscriptionFetchErrorKind::Write, error, source),
    )?;
    let response = read_subscription_fetch_response(&mut stream, options.max_bytes, source)?;
    parse_subscription_fetch_response(response, source.clone(), started, options.max_bytes)
}

fn subscription_fetch_tls_config() -> Result<Arc<rustls::ClientConfig>, SubscriptionFetchError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| {
            SubscriptionFetchError::new(
                SubscriptionFetchErrorKind::Tls,
                format!("build TLS protocol versions: {error}"),
                None,
            )
        })?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn subscription_fetch_source_from_url(
    url: &url::Url,
) -> Result<SubscriptionFetchSource, SubscriptionFetchError> {
    let host = url.host_str().ok_or_else(|| {
        SubscriptionFetchError::new(
            SubscriptionFetchErrorKind::MissingHost,
            "subscription URL must include a host",
            None,
        )
    })?;
    let port = url.port_or_known_default().ok_or_else(|| {
        SubscriptionFetchError::new(
            SubscriptionFetchErrorKind::UnsupportedScheme,
            format!("unsupported subscription URL scheme: {}", url.scheme()),
            None,
        )
    })?;
    let path_present = !url.path().is_empty() && url.path() != "/";
    Ok(SubscriptionFetchSource {
        scheme: url.scheme().to_string(),
        host: host.to_string(),
        port,
        default_port: url.port().is_none(),
        path_present,
        query_present: url.query().is_some(),
    })
}

fn subscription_fetch_source_json_value(source: &SubscriptionFetchSource) -> serde_json::Value {
    serde_json::json!({
        "scheme": &source.scheme,
        "host": &source.host,
        "port": source.port,
        "default_port": source.default_port,
        "path_present": source.path_present,
        "query_present": source.query_present,
    })
}

fn connect_subscription_fetch_socket(
    source: &SubscriptionFetchSource,
    timeout: Duration,
) -> Result<TcpStream, SubscriptionFetchError> {
    let addresses = (source.host.as_str(), source.port)
        .to_socket_addrs()
        .map_err(|error| {
            subscription_fetch_io_error(SubscriptionFetchErrorKind::Resolve, error, source)
        })?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(SubscriptionFetchError::new(
            SubscriptionFetchErrorKind::Resolve,
            "subscription host did not resolve to any socket address",
            Some(source.clone()),
        ));
    }

    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                stream.set_read_timeout(Some(timeout)).map_err(|error| {
                    subscription_fetch_io_error(SubscriptionFetchErrorKind::Read, error, source)
                })?;
                stream.set_write_timeout(Some(timeout)).map_err(|error| {
                    subscription_fetch_io_error(SubscriptionFetchErrorKind::Write, error, source)
                })?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(subscription_fetch_io_error(
        SubscriptionFetchErrorKind::Connect,
        last_error.unwrap_or_else(|| io::Error::other("connect failed")),
        source,
    ))
}

fn write_subscription_fetch_request(
    writer: &mut impl Write,
    url: &url::Url,
    source: &SubscriptionFetchSource,
    user_agent: &str,
) -> io::Result<()> {
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let request_target = if let Some(query) = url.query() {
        format!("{path}?{query}")
    } else {
        path.to_string()
    };
    let host_header = subscription_fetch_host_header(source);
    write!(
        writer,
        "GET {request_target} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {user_agent}\r\nAccept: text/plain, application/yaml, application/octet-stream, */*\r\nConnection: close\r\n\r\n"
    )?;
    writer.flush()
}

fn subscription_fetch_host_header(source: &SubscriptionFetchSource) -> String {
    let host = if source.host.contains(':') && !source.host.starts_with('[') {
        format!("[{}]", source.host)
    } else {
        source.host.clone()
    };
    if source.default_port {
        host
    } else {
        format!("{host}:{}", source.port)
    }
}

fn read_subscription_fetch_response(
    reader: &mut impl Read,
    max_bytes: usize,
    source: &SubscriptionFetchSource,
) -> Result<Vec<u8>, SubscriptionFetchError> {
    let mut response = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let bytes = reader.read(&mut buffer).map_err(|error| {
            subscription_fetch_io_error(SubscriptionFetchErrorKind::Read, error, source)
        })?;
        if bytes == 0 {
            break;
        }
        if response.len().saturating_add(bytes) > max_bytes {
            return Err(SubscriptionFetchError::new(
                SubscriptionFetchErrorKind::ResponseTooLarge,
                format!("subscription response exceeded max-bytes limit: {max_bytes}"),
                Some(source.clone()),
            ));
        }
        response.extend_from_slice(&buffer[..bytes]);
    }
    Ok(response)
}

fn parse_subscription_fetch_response(
    response: Vec<u8>,
    source: SubscriptionFetchSource,
    started: Instant,
    max_bytes: usize,
) -> Result<SubscriptionFetchResponse, SubscriptionFetchError> {
    let Some(header_end) = find_http_header_end(&response) else {
        return Err(SubscriptionFetchError::new(
            SubscriptionFetchErrorKind::InvalidResponse,
            "subscription fetch response is missing HTTP headers",
            Some(source),
        ));
    };
    let headers = String::from_utf8_lossy(&response[..header_end]);
    let mut lines = headers.lines();
    let status_line = lines.next().unwrap_or_default();
    let status_code = parse_http_status_code(status_line).ok_or_else(|| {
        SubscriptionFetchError::new(
            SubscriptionFetchErrorKind::InvalidResponse,
            "subscription fetch response has an invalid HTTP status line",
            Some(source.clone()),
        )
    })?;
    if !(200..300).contains(&status_code) {
        return Err(SubscriptionFetchError::new(
            SubscriptionFetchErrorKind::HttpStatus,
            format!("subscription fetch returned HTTP status {status_code}"),
            Some(source),
        ));
    }

    let transfer_encoding =
        lines
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("transfer-encoding")
                    .then(|| value.trim().to_ascii_lowercase())
            });
    let body = &response[header_end + 4..];
    let body = if transfer_encoding
        .as_deref()
        .is_some_and(|encoding| encoding.contains("chunked"))
    {
        decode_chunked_subscription_body(body, max_bytes, &source)?
    } else {
        body.to_vec()
    };
    let body_bytes = body.len();
    let body = String::from_utf8(body).map_err(|error| {
        SubscriptionFetchError::new(
            SubscriptionFetchErrorKind::Utf8,
            format!("subscription body is not UTF-8: {error}"),
            Some(source.clone()),
        )
    })?;

    Ok(SubscriptionFetchResponse {
        source,
        status_code,
        body,
        body_bytes,
        elapsed: started.elapsed(),
    })
}

fn find_http_header_end(response: &[u8]) -> Option<usize> {
    response.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_http_status_code(status_line: &str) -> Option<u16> {
    let mut parts = status_line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

fn decode_chunked_subscription_body(
    body: &[u8],
    max_bytes: usize,
    source: &SubscriptionFetchSource,
) -> Result<Vec<u8>, SubscriptionFetchError> {
    let mut decoded = Vec::new();
    let mut offset = 0;
    loop {
        let Some(line_end) = body[offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|index| offset + index)
        else {
            return Err(SubscriptionFetchError::new(
                SubscriptionFetchErrorKind::InvalidResponse,
                "chunked subscription response is missing a chunk length",
                Some(source.clone()),
            ));
        };
        let length_line = String::from_utf8_lossy(&body[offset..line_end]);
        let length_hex = length_line.split(';').next().unwrap_or_default().trim();
        let length = usize::from_str_radix(length_hex, 16).map_err(|_| {
            SubscriptionFetchError::new(
                SubscriptionFetchErrorKind::InvalidResponse,
                "chunked subscription response has an invalid chunk length",
                Some(source.clone()),
            )
        })?;
        offset = line_end + 2;
        if length == 0 {
            return Ok(decoded);
        }
        let chunk_end = offset.checked_add(length).ok_or_else(|| {
            SubscriptionFetchError::new(
                SubscriptionFetchErrorKind::InvalidResponse,
                "chunked subscription response length overflowed",
                Some(source.clone()),
            )
        })?;
        if chunk_end + 2 > body.len() || &body[chunk_end..chunk_end + 2] != b"\r\n" {
            return Err(SubscriptionFetchError::new(
                SubscriptionFetchErrorKind::InvalidResponse,
                "chunked subscription response is truncated",
                Some(source.clone()),
            ));
        }
        if decoded.len().saturating_add(length) > max_bytes {
            return Err(SubscriptionFetchError::new(
                SubscriptionFetchErrorKind::ResponseTooLarge,
                format!("decoded subscription body exceeded max-bytes limit: {max_bytes}"),
                Some(source.clone()),
            ));
        }
        decoded.extend_from_slice(&body[offset..chunk_end]);
        offset = chunk_end + 2;
    }
}

fn subscription_fetch_io_error(
    kind: SubscriptionFetchErrorKind,
    error: io::Error,
    source: &SubscriptionFetchSource,
) -> SubscriptionFetchError {
    SubscriptionFetchError::new(kind, error.to_string(), Some(source.clone()))
}

pub fn write_support_bundle_report(
    profile_config_text: Option<&str>,
    mut writer: impl Write,
) -> Result<(), String> {
    write_support_bundle_report_with_options(
        profile_config_text,
        SupportBundleOptions::default(),
        &mut writer,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupportBundleOptions {
    pub include_default_core_certification: bool,
    pub certification_soak_connections: usize,
    pub certification_first_byte_timeout: Duration,
    pub certification_max_connection_workers: usize,
    pub certification_soak_min_duration: Duration,
}

impl Default for SupportBundleOptions {
    fn default() -> Self {
        Self {
            include_default_core_certification: false,
            certification_soak_connections: DEFAULT_READINESS_SOAK_CONNECTIONS,
            certification_first_byte_timeout: DEFAULT_FIRST_BYTE_TIMEOUT,
            certification_max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
            certification_soak_min_duration: DEFAULT_MIXED_SOAK_MIN_DURATION,
        }
    }
}

pub fn write_support_bundle_report_with_options(
    profile_config_text: Option<&str>,
    options: SupportBundleOptions,
    mut writer: impl Write,
) -> Result<(), String> {
    let generated_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let default_core_certification = if options.include_default_core_certification {
        default_core_certification_json_value(&collect_default_core_certification_report(
            options.certification_soak_connections,
            options.certification_first_byte_timeout,
            options.certification_max_connection_workers,
            options.certification_soak_min_duration,
        )?)
    } else {
        serde_json::Value::Null
    };
    let value = serde_json::json!({
        "status": "ok",
        "kind": "keli_support_bundle",
        "schema_version": SUPPORT_BUNDLE_SCHEMA_VERSION,
        "generated_at_unix_ms": generated_at_unix_ms,
        "doctor": doctor_report_json_value(&collect_doctor_report()),
        "interop_matrix": interop_matrix_json_value(&collect_interop_matrix_report()),
        "tun_preflight": tun_preflight_json_value(&collect_default_tun_preflight()),
        "default_core_certification": default_core_certification,
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
) -> io::Result<RuntimeManagedMixedStopDrainDiagnostic> {
    let mut workers = Vec::new();
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::SeqCst) {
        reap_finished_mixed_connection_workers(&mut workers);
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false)?;
                let runtime = runtime
                    .read()
                    .map_err(|_| io::Error::other("mixed runtime lock poisoned"))?
                    .clone();
                if workers.len() >= runtime.max_connection_workers.max(1) {
                    record_mixed_connection_worker_limit_rejection(stream, &runtime);
                    continue;
                }
                let connection_lease = runtime.active_connection_registry.register(&stream)?;
                let worker_lease = runtime.connection_worker_gauge.start_worker();
                workers.push(thread::spawn(move || {
                    let _connection_lease = connection_lease;
                    let _worker_lease = worker_lease;
                    if let Err(error) = handle_mixed_connection_with_routes(&mut stream, &runtime) {
                        eprintln!("mixed inbound failed: {error}");
                    }
                }));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(MANAGED_ACCEPT_POLL_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
    let workers_before_shutdown = workers.len();
    let active_connections_shutdown = shutdown_active_mixed_connections(&runtime)?;
    reap_finished_mixed_connection_workers(&mut workers);
    let (workers_remaining, drain_elapsed) =
        drain_mixed_connection_workers(&mut workers, MANAGED_CONNECTION_DRAIN_TIMEOUT);
    let workers_drained = workers_before_shutdown.saturating_sub(workers_remaining);
    Ok(RuntimeManagedMixedStopDrainDiagnostic {
        active_connections_shutdown,
        workers_before_shutdown,
        workers_drained,
        workers_remaining,
        drain_elapsed_ms: duration_millis(drain_elapsed),
        drain_timeout_ms: duration_millis(MANAGED_CONNECTION_DRAIN_TIMEOUT),
        timed_out: workers_remaining > 0,
    })
}

fn shutdown_active_mixed_connections(
    runtime: &Arc<RwLock<MixedProxyRuntime>>,
) -> io::Result<usize> {
    let runtime = runtime
        .read()
        .map_err(|_| io::Error::other("mixed runtime lock poisoned"))?;
    Ok(runtime.active_connection_registry.shutdown_all())
}

fn record_mixed_connection_worker_limit_rejection(stream: TcpStream, runtime: &MixedProxyRuntime) {
    let mut report = ConnectionReport::new(
        "mixed",
        OutboundTarget::new("connection-worker-limit", 0),
        RouteAction::Direct,
    );
    report.record_error_detail(
        ConnectionErrorKind::ConnectionLimitReached,
        "managed mixed connection worker limit reached",
    );
    emit_connection_report(runtime, &report);
    let _ = stream.shutdown(Shutdown::Both);
}

fn reap_finished_mixed_connection_workers(workers: &mut Vec<thread::JoinHandle<()>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            if worker.join().is_err() {
                eprintln!("mixed inbound worker panicked");
            }
        } else {
            index += 1;
        }
    }
}

fn drain_mixed_connection_workers(
    workers: &mut Vec<thread::JoinHandle<()>>,
    timeout: Duration,
) -> (usize, Duration) {
    let started = Instant::now();
    while !workers.is_empty() && started.elapsed() < timeout {
        reap_finished_mixed_connection_workers(workers);
        if !workers.is_empty() {
            thread::sleep(MANAGED_ACCEPT_POLL_INTERVAL);
        }
    }
    if !workers.is_empty() {
        eprintln!(
            "mixed inbound stop timed out waiting for {} active worker(s)",
            workers.len()
        );
    }
    (workers.len(), started.elapsed())
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

pub fn listen_mixed_with_optional_tun_controller<C, T>(
    listen: &str,
    once: bool,
    runtime: &MixedProxyRuntime,
    system_proxy_controller: &C,
    system_proxy: bool,
    bypass: Vec<String>,
    tun_controller: &T,
    tun_device: Option<TunDeviceConfig>,
) -> Result<(), String>
where
    C: SystemProxyController + ?Sized,
    T: TunPacketIoController + ?Sized,
    T::PacketIo: Send + 'static,
{
    listen_mixed_with_optional_tun_controller_report(
        listen,
        once,
        runtime,
        system_proxy_controller,
        system_proxy,
        bypass,
        tun_controller,
        tun_device,
    )
    .map(|_| ())
}

pub fn listen_mixed_with_optional_tun_controller_report<C, T>(
    listen: &str,
    once: bool,
    runtime: &MixedProxyRuntime,
    system_proxy_controller: &C,
    system_proxy: bool,
    bypass: Vec<String>,
    tun_controller: &T,
    tun_device: Option<TunDeviceConfig>,
) -> Result<Option<ManagedTunPacketLoopReport>, String>
where
    C: SystemProxyController + ?Sized,
    T: TunPacketIoController + ?Sized,
    T::PacketIo: Send + 'static,
{
    run_with_optional_tun_runtime_background_report(
        tun_controller,
        tun_device,
        runtime,
        DEFAULT_TUN_DNS_TTL_SECONDS,
        DEFAULT_TUN_PACKET_LOOP_MAX_PACKETS,
        || {
            if system_proxy {
                listen_mixed_with_system_proxy_controller(
                    listen,
                    once,
                    runtime,
                    system_proxy_controller,
                    bypass,
                )
            } else {
                listen_mixed(listen, once, runtime)
                    .map_err(|error| format!("listen-mixed failed on {listen}: {error}"))
            }
        },
    )
    .map(|(_, report)| report)
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
    eprintln!(
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
            emit_connection_report(runtime, &report);
            stream.write_all(&socks5_reply(Socks5ReplyCode::ConnectionNotAllowed))?;
            return Ok(());
        }
        Ok(RouteConnect::UnsupportedOutbound { tag, route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::UnsupportedOutbound);
            emit_connection_report(runtime, &report);
            stream.write_all(&socks5_reply(Socks5ReplyCode::CommandNotSupported))?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound route is not implemented: {tag}"),
            ));
        }
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            emit_connection_report(runtime, &report);
            stream.write_all(&socks5_reply(Socks5ReplyCode::HostUnreachable))?;
            return Err(error);
        }
    };

    stream.write_all(&socks5_reply(Socks5ReplyCode::Succeeded))?;
    let client = stream.try_clone()?;
    relay_with_report(client, remote, &mut report, runtime)
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
            emit_connection_report(runtime, &report);
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
                    emit_connection_report(runtime, &report);
                    return Ok(());
                }
            };
            report.upload_bytes = datagram.payload.len() as u64;
            report.record_first_byte_duration(started.elapsed());
            report.download_bytes = response.payload.len() as u64;
            send_socks5_udp_response(relay, client_udp_addr, response.source, &response.payload)?;
            emit_connection_report(runtime, &report);
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
                    emit_connection_report(runtime, &report);
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
            emit_connection_report(runtime, &report);
            return Ok(());
        }
    }

    let remote_addr = match resolve_udp_socket_addr(&target) {
        Ok(remote_addr) => remote_addr,
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            emit_connection_report(runtime, &report);
            return Ok(());
        }
    };
    let started = Instant::now();
    if let Err(error) = outbound.send_to(&datagram.payload, remote_addr) {
        report.record_error(ConnectionErrorKind::from_io(&error));
        emit_connection_report(runtime, &report);
        return Ok(());
    }
    report.upload_bytes = datagram.payload.len() as u64;

    let mut response_buffer = [0; 65_535];
    let (response_size, response_from) = match outbound.recv_from(&mut response_buffer) {
        Ok(response) => response,
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            emit_connection_report(runtime, &report);
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
    emit_connection_report(runtime, &report);
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
    eprintln!(
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
            emit_connection_report(runtime, &report);
            stream.write_all(http_forbidden_response())?;
            return Ok(());
        }
        Ok(RouteConnect::UnsupportedOutbound { tag, route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::UnsupportedOutbound);
            emit_connection_report(runtime, &report);
            stream.write_all(http_connect_bad_request_response())?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound route is not implemented: {tag}"),
            ));
        }
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            emit_connection_report(runtime, &report);
            stream.write_all(http_connect_bad_request_response())?;
            return Err(error);
        }
    };

    stream.write_all(http_connect_success_response())?;
    let client = stream.try_clone()?;
    relay_with_report(client, remote, &mut report, runtime)
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
    eprintln!(
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
            emit_connection_report(runtime, &report);
            stream.write_all(http_forbidden_response())?;
            return Ok(());
        }
        Ok(RouteConnect::UnsupportedOutbound { tag, route_action }) => {
            report.route_action = route_action;
            report.record_error(ConnectionErrorKind::UnsupportedOutbound);
            emit_connection_report(runtime, &report);
            stream.write_all(http_proxy_bad_request_response())?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound route is not implemented: {tag}"),
            ));
        }
        Err(error) => {
            report.record_error(ConnectionErrorKind::from_io(&error));
            emit_connection_report(runtime, &report);
            stream.write_all(http_proxy_bad_request_response())?;
            return Err(error);
        }
    };

    remote.write_all(&request.rewritten_header)?;
    let client = stream.try_clone()?;
    relay_with_report(client, remote, &mut report, runtime)
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

pub fn write_soak_mixed_report(
    connections: usize,
    inbound: SmokeInboundKind,
    first_byte_timeout: Duration,
    max_connection_workers: usize,
    output: ProbeOutputFormat,
    mut writer: impl Write,
) -> Result<(), String> {
    write_soak_mixed_report_with_min_duration(
        connections,
        inbound,
        first_byte_timeout,
        max_connection_workers,
        DEFAULT_MIXED_SOAK_MIN_DURATION,
        output,
        &mut writer,
    )
}

pub fn write_soak_mixed_report_with_min_duration(
    connections: usize,
    inbound: SmokeInboundKind,
    first_byte_timeout: Duration,
    max_connection_workers: usize,
    min_duration: Duration,
    output: ProbeOutputFormat,
    mut writer: impl Write,
) -> Result<(), String> {
    let report = run_soak_mixed_with_min_duration(
        connections,
        inbound,
        first_byte_timeout,
        max_connection_workers,
        min_duration,
    )?;
    write_soak_mixed_result(&mut writer, &report, output)
}

pub fn run_soak_mixed(
    connections: usize,
    inbound: SmokeInboundKind,
    first_byte_timeout: Duration,
    max_connection_workers: usize,
) -> Result<MixedSoakReport, String> {
    run_soak_mixed_with_min_duration(
        connections,
        inbound,
        first_byte_timeout,
        max_connection_workers,
        DEFAULT_MIXED_SOAK_MIN_DURATION,
    )
}

pub fn run_soak_mixed_with_min_duration(
    connections: usize,
    inbound: SmokeInboundKind,
    first_byte_timeout: Duration,
    max_connection_workers: usize,
    min_duration: Duration,
) -> Result<MixedSoakReport, String> {
    if connections == 0 {
        return Err("soak-mixed connections must be greater than 0".to_string());
    }
    if max_connection_workers == 0 {
        return Err("soak-mixed max connection workers must be greater than 0".to_string());
    }

    let echo_stop = Arc::new(AtomicBool::new(false));
    let (target_addr, echo_thread) = spawn_mixed_soak_echo_server(
        connections,
        MIXED_SOAK_PAYLOAD.len(),
        first_byte_timeout,
        Arc::clone(&echo_stop),
    )?;
    let relay_options = RelayOptions {
        first_byte_timeout: Some(first_byte_timeout),
        idle_timeout: Some(first_byte_timeout),
    };
    let mut runtime = mixed_runtime_from_cli(Vec::new(), relay_options, MixedDnsOptions::default());
    runtime.max_connection_workers = max_connection_workers;
    let runtime = Arc::new(RwLock::new(runtime));
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("bind soak mixed listener: {error}"))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|error| format!("read soak mixed listener addr: {error}"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let server_runtime = Arc::clone(&runtime);
    let server_stop = Arc::clone(&stop);
    let server =
        thread::spawn(move || serve_mixed_listener_until(listener, server_runtime, server_stop));
    let target = OutboundTarget::new(target_addr.ip().to_string(), target_addr.port());
    let started = Instant::now();
    let mut completed_connections = 0;
    let mut first_error = None;

    for index in 0..connections {
        match run_mixed_soak_iteration(listen_addr, &target, inbound, first_byte_timeout) {
            Ok(()) => completed_connections += 1,
            Err(error) => {
                first_error = Some(format!("soak connection {} failed: {error}", index + 1));
                break;
            }
        }
    }

    if first_error.is_none() {
        while started.elapsed() < min_duration {
            let remaining = min_duration.saturating_sub(started.elapsed());
            thread::sleep(remaining.min(Duration::from_millis(25)));
        }
    }
    let elapsed = started.elapsed();
    echo_stop.store(true, Ordering::SeqCst);
    stop.store(true, Ordering::SeqCst);
    let stop_drain = server
        .join()
        .map_err(|_| "soak mixed listener thread panicked".to_string())?
        .map_err(|error| format!("soak mixed listener failed: {error}"))?;
    let echo_connections = echo_thread
        .join()
        .map_err(|_| "soak echo server thread panicked".to_string())??;
    let runtime_snapshot = runtime
        .read()
        .map_err(|_| "soak mixed runtime lock poisoned".to_string())?;
    let connection_metrics = runtime_snapshot.connection_metrics_snapshot();
    let max_connection_workers = runtime_snapshot.max_connection_workers;
    let active_connection_workers = runtime_snapshot.active_connection_workers();
    let peak_connection_workers = runtime_snapshot.peak_connection_workers();
    let active_client_connections = runtime_snapshot.active_client_connections();
    let peak_client_connections = runtime_snapshot.peak_client_connections();
    let available_connection_worker_slots = runtime_snapshot.available_connection_worker_slots();
    drop(runtime_snapshot);
    let failed_connections = connections.saturating_sub(completed_connections);

    if let Some(error) = first_error {
        return Err(error);
    }
    if echo_connections != connections {
        return Err(format!(
            "soak echo server handled {echo_connections} of {connections} connections"
        ));
    }

    Ok(MixedSoakReport {
        requested_connections: connections,
        completed_connections,
        failed_connections,
        inbound,
        listen_addr,
        target_addr,
        elapsed,
        min_duration,
        duration_target_met: elapsed >= min_duration,
        payload_bytes_per_connection: MIXED_SOAK_PAYLOAD.len(),
        connection_metrics,
        max_connection_workers,
        active_connection_workers,
        peak_connection_workers,
        active_client_connections,
        peak_client_connections,
        available_connection_worker_slots,
        stop_drain,
    })
}

fn spawn_mixed_soak_echo_server(
    expected_connections: usize,
    payload_len: usize,
    timeout: Duration,
    stop: Arc<AtomicBool>,
) -> Result<(SocketAddr, thread::JoinHandle<Result<usize, String>>), String> {
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|error| format!("bind soak echo: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("set soak echo nonblocking: {error}"))?;
    let addr = listener
        .local_addr()
        .map_err(|error| format!("read soak echo addr: {error}"))?;
    let handle = thread::spawn(move || -> Result<usize, String> {
        let mut accepted = 0;
        while accepted < expected_connections && !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .map_err(|error| format!("set soak echo blocking: {error}"))?;
                    stream
                        .set_read_timeout(Some(timeout))
                        .map_err(|error| format!("set soak echo read timeout: {error}"))?;
                    stream
                        .set_write_timeout(Some(timeout))
                        .map_err(|error| format!("set soak echo write timeout: {error}"))?;
                    let mut payload = vec![0; payload_len];
                    stream
                        .read_exact(&mut payload)
                        .map_err(|error| format!("read soak echo payload: {error}"))?;
                    stream
                        .write_all(&payload)
                        .map_err(|error| format!("write soak echo payload: {error}"))?;
                    accepted += 1;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(MANAGED_ACCEPT_POLL_INTERVAL);
                }
                Err(error) => return Err(format!("accept soak echo connection: {error}")),
            }
        }
        Ok(accepted)
    });
    Ok((addr, handle))
}

fn run_mixed_soak_iteration(
    listen_addr: SocketAddr,
    target: &OutboundTarget,
    inbound: SmokeInboundKind,
    timeout: Duration,
) -> Result<(), String> {
    let mut client = TcpStream::connect(listen_addr)
        .map_err(|error| format!("connect soak mixed listener {listen_addr}: {error}"))?;
    client
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("set soak read timeout: {error}"))?;
    client
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("set soak write timeout: {error}"))?;
    write_smoke_connect(&mut client, target, inbound)?;
    client
        .write_all(MIXED_SOAK_PAYLOAD)
        .map_err(|error| format!("write soak payload: {error}"))?;
    let mut received = vec![0; MIXED_SOAK_PAYLOAD.len()];
    client
        .read_exact(&mut received)
        .map_err(|error| format!("read soak response: {error}"))?;
    if received != MIXED_SOAK_PAYLOAD {
        return Err(format!(
            "soak response mismatch: expected {:?}, got {:?}",
            String::from_utf8_lossy(MIXED_SOAK_PAYLOAD),
            String::from_utf8_lossy(&received)
        ));
    }
    client.shutdown(Shutdown::Both).ok();
    Ok(())
}

fn write_soak_mixed_result(
    writer: &mut impl Write,
    report: &MixedSoakReport,
    output: ProbeOutputFormat,
) -> Result<(), String> {
    match output {
        ProbeOutputFormat::Text => {
            writeln!(
                writer,
                "soak status=ok inbound={} requested_connections={} completed_connections={} failed_connections={} elapsed_ms={} min_duration_ms={} duration_target_met={} total_connection_count={} success_count={} failure_count={} peak_connection_workers={} peak_client_connections={} stop_workers_remaining={} stop_timed_out={}",
                report.inbound.cli_value(),
                report.requested_connections,
                report.completed_connections,
                report.failed_connections,
                duration_millis(report.elapsed),
                duration_millis(report.min_duration),
                report.duration_target_met,
                report.connection_metrics.total_connection_count,
                report.connection_metrics.success_count,
                report.connection_metrics.failure_count,
                report.peak_connection_workers,
                report.peak_client_connections,
                report.stop_drain.workers_remaining,
                report.stop_drain.timed_out
            )
            .map_err(|error| error.to_string())
        }
        ProbeOutputFormat::Json => {
            let value = serde_json::json!({
                "status": "ok",
                "kind": "keli_mixed_soak",
                "inbound": report.inbound.cli_value(),
                "requested_connections": report.requested_connections,
                "completed_connections": report.completed_connections,
                "failed_connections": report.failed_connections,
                "listen_addr": report.listen_addr.to_string(),
                "target_addr": report.target_addr.to_string(),
                "elapsed_ms": duration_millis(report.elapsed),
                "min_duration_ms": duration_millis(report.min_duration),
                "duration_target_met": report.duration_target_met,
                "payload_bytes_per_connection": report.payload_bytes_per_connection,
                "connection_metrics": connection_metrics_json_value(&report.connection_metrics),
                "worker_gauge": {
                    "max_connection_workers": report.max_connection_workers,
                    "active_connection_workers": report.active_connection_workers,
                    "peak_connection_workers": report.peak_connection_workers,
                    "active_client_connections": report.active_client_connections,
                    "peak_client_connections": report.peak_client_connections,
                    "available_connection_worker_slots": report.available_connection_worker_slots,
                },
                "stop_drain": {
                    "active_connections_shutdown": report.stop_drain.active_connections_shutdown,
                    "workers_before_shutdown": report.stop_drain.workers_before_shutdown,
                    "workers_drained": report.stop_drain.workers_drained,
                    "workers_remaining": report.stop_drain.workers_remaining,
                    "drain_elapsed_ms": report.stop_drain.drain_elapsed_ms,
                    "drain_timeout_ms": report.stop_drain.drain_timeout_ms,
                    "timed_out": report.stop_drain.timed_out,
                },
            });
            writeln!(writer, "{value}").map_err(|error| error.to_string())
        }
    }
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
        tun_tcp_max_active_sessions: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
        connection_metrics: ConnectionMetrics::default(),
        max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
        connection_worker_gauge: ConnectionWorkerGauge::default(),
        active_connection_registry: ActiveConnectionRegistry::default(),
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
        tun_tcp_max_active_sessions: DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
        connection_metrics: ConnectionMetrics::default(),
        max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
        connection_worker_gauge: ConnectionWorkerGauge::default(),
        active_connection_registry: ActiveConnectionRegistry::default(),
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
    runtime: &MixedProxyRuntime,
) -> io::Result<()> {
    match relay_owned_bidirectional_with_options(client, remote, runtime.relay_options) {
        Ok(stats) => {
            report.record_relay_stats(stats);
            emit_connection_report(runtime, report);
            Ok(())
        }
        Err(error) => {
            report.record_error(error.kind);
            emit_connection_report(runtime, report);
            Err(io::Error::new(io::ErrorKind::Other, error))
        }
    }
}

fn emit_connection_report(runtime: &MixedProxyRuntime, report: &ConnectionReport) {
    runtime.record_connection_report(report);
    eprintln!("{}", report.summary_line());
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

fn parse_positive_usize(value: String, option: &str) -> Result<usize, String> {
    let number = value
        .parse::<usize>()
        .map_err(|_| format!("{option} requires a positive integer value"))?;
    if number == 0 {
        return Err(format!("{option} must be greater than 0"));
    }
    Ok(number)
}

fn to_io_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
