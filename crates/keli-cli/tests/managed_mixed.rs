use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use keli_cli::{
    apply_system_proxy_for_listener, managed_mixed_status_json_value,
    managed_subscription_url_update_outcome_json_value, write_managed_mixed_status_json_report,
    ConnectionErrorKindCount, ConnectionInboundCount, ConnectionMetrics, ConnectionMetricsSnapshot,
    ConnectionRouteActionCount, ManagedMixedController, ManagedMixedOptions, ManagedMixedSession,
    ManagedMixedStatusSnapshot, ManagedNodeHealthState, ManagedNodeHealthStatus,
    ManagedNodeProbeOptions, ManagedNodeProbeSweepOptions, ManagedNodeUdpProbeOptions,
    ManagedRecommendedSwitchReason, MixedDnsOptions, SmokeInboundKind,
    DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS, MANAGED_CONNECTION_REPORT_HISTORY_LIMIT,
    MANAGED_MIXED_RECENT_EVENT_LIMIT, MANAGED_MIXED_STATUS_SCHEMA_VERSION,
};
use keli_client_core::{
    ClientErrorKind, PanelAccountState, PanelRiskControlState, PanelState, PanelUserState,
    RuntimeDiagnostic, RuntimeEvent, RuntimeManagedMixedStopDrainDiagnostic, RuntimeStatus,
    RuntimeTunPacketDroppedRouteDiagnostic, RuntimeTunPacketLoopDiagnostic,
    SubscriptionUpdateReason, DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT,
};
use keli_net_core::{
    ConnectionErrorKind, ConnectionReport, DnsAddressFamilyPolicy, DnsLocalResolutionPolicy,
    OutboundTarget, RouteAction, DEFAULT_TUN_TCP_MAX_ACTIVE_SESSIONS,
};
use keli_platform::{
    SystemProxyConfig, SystemProxyController, SystemProxyError, SystemProxySnapshot,
};
use serde_json::Value;
use shadowsocks_crypto::kind::CipherKind;
use shadowsocks_crypto::v1::{openssl_bytes_to_key, Cipher};

fn ss_config() -> &'static str {
    r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#
}

fn ss_config_with_tag(tag: &str) -> String {
    format!(
        r#"
proxies:
  - name: {tag}
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#
    )
}

fn ss_config_with_tags(tags: &[&str]) -> String {
    let mut config = String::from("proxies:\n");
    for tag in tags {
        config.push_str(&format!(
            r#"  - name: {tag}
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#
        ));
    }
    config
}

fn ss_config_for_port(port: u16) -> String {
    format!(
        r#"
proxies:
  - name: SS-READY
    type: ss
    server: 127.0.0.1
    port: {port}
    cipher: aes-256-gcm
    password: secret
"#
    )
}

fn mixed_subscription_for_ports(ready_port: u16, next_port: u16) -> String {
    format!(
        r#"
proxies:
  - name: SS-READY
    type: ss
    server: 127.0.0.1
    port: {ready_port}
    cipher: aes-256-gcm
    password: secret
  - name: SS-NEXT
    type: ss
    server: 127.0.0.1
    port: {next_port}
    cipher: aes-256-gcm
    password: secret
"#
    )
}

fn mixed_subscription_with_skipped_proxy() -> &'static str {
    r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
  - name: SS-NEXT
    type: ss
    server: next.example.com
    port: 8389
    cipher: aes-256-gcm
    password: secret
  - name: WG-SKIPPED
    type: wireguard
    server: wg.example.com
    port: 51820
    password: ignored
"#
}

fn mixed_subscription_with_capability_variants() -> &'static str {
    r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
  - name: VLESS-EDGE
    type: vless
    server: vless.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
    network: ws
    tls: true
    skip-cert-verify: true
    servername: private-sni.example.com
    ws-opts:
      path: /private-vless-path
      headers:
        Host: private-host.example.com
  - name: WG-SKIPPED
    type: wireguard
    server: wg.example.com
    port: 51820
    password: ignored
"#
}

fn request_blocked_socks5_domain(listen_addr: SocketAddr, host: &str, port: u16) {
    let mut client = open_socks5_handshake(listen_addr);

    let host_len = u8::try_from(host.len()).expect("SOCKS5 host length");
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host_len];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    client.write_all(&request).expect("write blocked request");

    let mut reply = [0; 10];
    client.read_exact(&mut reply).expect("read blocked reply");
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x02);
}

fn open_socks5_handshake(listen_addr: SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(listen_addr).expect("connect managed mixed listener");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    client
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("set write timeout");
    client.write_all(&[0x05, 0x01, 0x00]).expect("write hello");
    let mut hello = [0; 2];
    client.read_exact(&mut hello).expect("read hello");
    assert_eq!(hello, [0x05, 0x00]);
    client
}

fn attempt_rejected_socks5_hello(listen_addr: SocketAddr) {
    let mut client = TcpStream::connect(listen_addr).expect("connect managed mixed listener");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    client
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("set write timeout");
    if client.write_all(&[0x05, 0x01, 0x00]).is_ok() {
        let mut hello = [0; 2];
        assert!(client.read_exact(&mut hello).is_err());
    }
}

fn wait_for_connection_count<C: SystemProxyController + ?Sized>(
    core: &ManagedMixedController<'_, C>,
    expected_count: u64,
) -> ManagedMixedStatusSnapshot {
    for _ in 0..40 {
        let status = core.status();
        if status.connection_metrics.total_connection_count >= expected_count {
            return status;
        }
        thread::sleep(Duration::from_millis(25));
    }
    core.status()
}

fn wait_for_active_connection_workers<C: SystemProxyController + ?Sized>(
    core: &ManagedMixedController<'_, C>,
    expected_count: usize,
) -> ManagedMixedStatusSnapshot {
    for _ in 0..80 {
        let status = core.status();
        if status.active_connection_workers == expected_count {
            return status;
        }
        thread::sleep(Duration::from_millis(25));
    }
    core.status()
}

fn spawn_subscription_http_server(
    status_code: u16,
    reason: &str,
    body: String,
) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind subscription HTTP server");
    let port = listener
        .local_addr()
        .expect("subscription server addr")
        .port();
    let url = format!("http://127.0.0.1:{port}/panel/private/sub?token=super-secret-token");
    let reason = reason.to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept subscription fetch");
        let mut request = Vec::new();
        let mut byte = [0; 1];
        while stream.read(&mut byte).expect("read subscription request") != 0 {
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).expect("subscription request utf8");
        let response = format!(
            "HTTP/1.1 {status_code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write subscription response");
        request.lines().next().unwrap_or_default().to_string()
    });
    (url, handle)
}

#[test]
fn connection_metrics_summarize_totals_after_recent_history_trims() {
    let metrics = ConnectionMetrics::new(1);
    let mut success = ConnectionReport::new(
        "socks5",
        OutboundTarget::new("example.com", 443),
        RouteAction::Direct,
    );
    success.connect_ms = Some(10);
    success.first_byte_ms = Some(30);
    success.upload_bytes = 7;
    success.download_bytes = 11;
    metrics.record(&success);

    let mut outbound = ConnectionReport::new(
        "http-connect",
        OutboundTarget::new("proxy.example.com", 443),
        RouteAction::Outbound("SS-READY".to_string()),
    );
    outbound.connect_ms = Some(30);
    outbound.first_byte_ms = Some(50);
    outbound.upload_bytes = 5;
    outbound.download_bytes = 9;
    metrics.record(&outbound);

    let mut failure = ConnectionReport::new(
        "http-connect",
        OutboundTarget::new("blocked.example.com", 443),
        RouteAction::Block,
    );
    failure.connect_ms = Some(20);
    failure.upload_bytes = 13;
    failure.download_bytes = 17;
    failure.record_error(ConnectionErrorKind::RouteBlocked);
    metrics.record(&failure);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.total_connection_count, 3);
    assert_eq!(snapshot.success_count, 2);
    assert_eq!(snapshot.failure_count, 1);
    assert_eq!(
        snapshot.inbound_counts,
        vec![
            ConnectionInboundCount {
                inbound: "http-connect".to_string(),
                count: 2,
            },
            ConnectionInboundCount {
                inbound: "socks5".to_string(),
                count: 1,
            },
        ]
    );
    assert_eq!(
        snapshot.route_action_counts,
        vec![
            ConnectionRouteActionCount {
                route_action: RouteAction::Direct,
                count: 1,
            },
            ConnectionRouteActionCount {
                route_action: RouteAction::Block,
                count: 1,
            },
            ConnectionRouteActionCount {
                route_action: RouteAction::Outbound("SS-READY".to_string()),
                count: 1,
            },
        ]
    );
    assert_eq!(snapshot.total_upload_bytes, 25);
    assert_eq!(snapshot.total_download_bytes, 37);
    assert_eq!(snapshot.total_connect_ms, 60);
    assert_eq!(snapshot.timed_connect_count, 3);
    assert_eq!(snapshot.total_first_byte_ms, 80);
    assert_eq!(snapshot.timed_first_byte_count, 2);
    assert_eq!(snapshot.retained_connection_count, 1);
    assert_eq!(
        snapshot.recent_connections[0].target.host,
        "blocked.example.com"
    );
    assert!(snapshot.last_connection_at.is_some());
    assert!(snapshot.last_success_at.is_some());
    assert_eq!(snapshot.last_failure_at, snapshot.last_connection_at);

    let status = ManagedMixedStatusSnapshot {
        status: RuntimeStatus::Stopped,
        listen_addr: None,
        selected_outbound: None,
        generation: 0,
        started_at: None,
        uptime: None,
        connection_metrics: snapshot,
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
        panel_state: None,
    };
    let value = managed_mixed_status_json_value(&status);
    assert_eq!(
        value["connection_metrics"]["inbound_counts"][0]["inbound"],
        "http-connect"
    );
    assert_eq!(value["connection_metrics"]["inbound_counts"][0]["count"], 2);
    assert_eq!(
        value["connection_metrics"]["inbound_counts"][1]["inbound"],
        "socks5"
    );
    assert_eq!(value["connection_metrics"]["inbound_counts"][1]["count"], 1);
    assert_eq!(
        value["connection_metrics"]["route_action_counts"][0]["route_action"]["kind"],
        "direct"
    );
    assert_eq!(
        value["connection_metrics"]["route_action_counts"][0]["count"],
        1
    );
    assert_eq!(
        value["connection_metrics"]["route_action_counts"][1]["route_action"]["kind"],
        "block"
    );
    assert_eq!(
        value["connection_metrics"]["route_action_counts"][1]["count"],
        1
    );
    assert_eq!(
        value["connection_metrics"]["route_action_counts"][2]["route_action"]["kind"],
        "outbound"
    );
    assert_eq!(
        value["connection_metrics"]["route_action_counts"][2]["route_action"]["tag"],
        "SS-READY"
    );
    assert_eq!(
        value["connection_metrics"]["route_action_counts"][2]["count"],
        1
    );
    assert_eq!(value["connection_metrics"]["total_upload_bytes"], 25);
    assert_eq!(value["connection_metrics"]["total_download_bytes"], 37);
    assert_eq!(value["connection_metrics"]["total_connect_ms"], 60);
    assert_eq!(value["connection_metrics"]["timed_connect_count"], 3);
    assert_eq!(value["connection_metrics"]["average_connect_ms"], 20);
    assert_eq!(value["connection_metrics"]["total_first_byte_ms"], 80);
    assert_eq!(value["connection_metrics"]["timed_first_byte_count"], 2);
    assert_eq!(value["connection_metrics"]["average_first_byte_ms"], 40);
}

#[derive(Debug)]
struct FakeSystemProxyController {
    snapshot: SystemProxySnapshot,
    applied: RefCell<Vec<SystemProxyConfig>>,
    restored: RefCell<Vec<SystemProxySnapshot>>,
}

impl FakeSystemProxyController {
    fn new(snapshot: SystemProxySnapshot) -> Self {
        Self {
            snapshot,
            applied: RefCell::new(Vec::new()),
            restored: RefCell::new(Vec::new()),
        }
    }
}

impl SystemProxyController for FakeSystemProxyController {
    fn snapshot(&self) -> Result<SystemProxySnapshot, SystemProxyError> {
        Ok(self.snapshot.clone())
    }

    fn apply(&self, config: &SystemProxyConfig) -> Result<SystemProxySnapshot, SystemProxyError> {
        self.applied.borrow_mut().push(config.clone());
        Ok(self.snapshot.clone())
    }

    fn restore(&self, snapshot: &SystemProxySnapshot) -> Result<(), SystemProxyError> {
        self.restored.borrow_mut().push(snapshot.clone());
        Ok(())
    }
}

#[test]
fn managed_system_proxy_uses_listener_port_and_restores_snapshot() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local listener");
    let port = listener.local_addr().expect("local addr").port();
    let snapshot = SystemProxySnapshot {
        proxy_enable: Some(0),
        proxy_server: Some("old.proxy:8080".to_string()),
        proxy_override: Some("<local>".to_string()),
    };
    let controller = FakeSystemProxyController::new(snapshot.clone());

    let guard = apply_system_proxy_for_listener(
        &controller,
        &listener,
        vec!["localhost".to_string(), "<local>".to_string()],
    )
    .expect("apply managed proxy");

    assert_eq!(guard.config().server, format!("127.0.0.1:{port}"));
    assert_eq!(
        guard.config().bypass,
        vec!["localhost".to_string(), "<local>".to_string()]
    );
    assert_eq!(controller.applied.borrow().len(), 1);

    guard.restore().expect("restore proxy");

    assert_eq!(controller.restored.borrow().as_slice(), &[snapshot]);
}

#[test]
fn managed_system_proxy_normalizes_wildcard_listener_to_loopback() {
    let listener = TcpListener::bind("0.0.0.0:0").expect("bind wildcard listener");
    let port = listener.local_addr().expect("local addr").port();
    let controller = FakeSystemProxyController::new(SystemProxySnapshot::default());

    let guard = apply_system_proxy_for_listener(&controller, &listener, Vec::<String>::new())
        .expect("apply managed proxy");

    assert_eq!(guard.config().server, format!("127.0.0.1:{port}"));
    guard.restore().expect("restore proxy");
}

#[test]
fn managed_mixed_session_starts_core_applies_proxy_and_restores_on_stop() {
    let snapshot = SystemProxySnapshot {
        proxy_enable: Some(0),
        proxy_server: Some("old.proxy:8080".to_string()),
        proxy_override: None,
    };
    let controller = FakeSystemProxyController::new(snapshot.clone());

    let session = ManagedMixedSession::start_from_subscription_config_text(
        ss_config(),
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-READY".to_string()),
            system_proxy: true,
            system_proxy_bypass: vec!["localhost".to_string()],
            ..ManagedMixedOptions::default()
        },
        &controller,
    )
    .expect("start managed mixed session");

    let port = session.listen_addr().port();
    assert_eq!(session.selected_outbound(), Some("SS-READY"));
    assert!(matches!(session.status(), RuntimeStatus::Running { .. }));
    assert_eq!(
        controller.applied.borrow()[0].server,
        format!("127.0.0.1:{port}")
    );
    assert_eq!(
        controller.applied.borrow()[0].bypass,
        vec!["localhost".to_string()]
    );

    let state = session.stop().expect("stop managed mixed session");

    assert_eq!(state.status(), &RuntimeStatus::Stopped);
    assert_eq!(controller.restored.borrow().as_slice(), &[snapshot]);
}

#[test]
fn managed_mixed_background_handle_stops_listener_and_restores_proxy() {
    let snapshot = SystemProxySnapshot {
        proxy_enable: Some(1),
        proxy_server: Some("existing.proxy:7890".to_string()),
        proxy_override: Some("localhost;<local>".to_string()),
    };
    let controller = FakeSystemProxyController::new(snapshot.clone());

    let session = ManagedMixedSession::start_from_subscription_config_text(
        ss_config(),
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-READY".to_string()),
            system_proxy: true,
            ..ManagedMixedOptions::default()
        },
        &controller,
    )
    .expect("start managed mixed session");

    let handle = session
        .spawn_background()
        .expect("spawn managed mixed background listener");
    let port = handle.listen_addr().port();

    assert_eq!(handle.selected_outbound(), Some("SS-READY"));
    assert!(matches!(handle.status(), RuntimeStatus::Running { .. }));
    assert_eq!(
        controller.applied.borrow()[0].server,
        format!("127.0.0.1:{port}")
    );

    let state = handle
        .stop()
        .expect("stop managed mixed background listener");

    assert_eq!(state.status(), &RuntimeStatus::Stopped);
    assert_eq!(controller.restored.borrow().as_slice(), &[snapshot]);
}

#[test]
fn managed_mixed_background_handle_reloads_to_new_subscription() {
    let controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let session = ManagedMixedSession::start_from_subscription_config_text(
        ss_config(),
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-READY".to_string()),
            system_proxy: false,
            ..ManagedMixedOptions::default()
        },
        &controller,
    )
    .expect("start managed mixed session");
    let mut handle = session
        .spawn_background()
        .expect("spawn managed mixed background listener");
    let initial_generation = handle.generation();

    handle
        .reload_from_subscription_config_text(
            &ss_config_with_tag("SS-NEXT"),
            Some("SS-NEXT".to_string()),
        )
        .expect("reload managed mixed background listener");

    assert_eq!(handle.selected_outbound(), Some("SS-NEXT"));
    assert_eq!(handle.generation(), initial_generation + 1);
    assert!(matches!(
        handle.status(),
        RuntimeStatus::Running {
            selected_outbound,
            ..
        } if selected_outbound == "SS-NEXT"
    ));
    assert!(handle.events().iter().any(|event| {
        event
            .note
            .as_deref()
            .is_some_and(|note| note == "runtime reload applied")
    }));

    let state = handle
        .stop()
        .expect("stop managed mixed background listener");
    assert_eq!(state.status(), &RuntimeStatus::Stopped);
}

#[test]
fn managed_mixed_background_reload_failure_preserves_active_runtime() {
    let controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let session = ManagedMixedSession::start_from_subscription_config_text(
        ss_config(),
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-READY".to_string()),
            system_proxy: false,
            ..ManagedMixedOptions::default()
        },
        &controller,
    )
    .expect("start managed mixed session");
    let mut handle = session
        .spawn_background()
        .expect("spawn managed mixed background listener");
    let initial_generation = handle.generation();

    let error = handle
        .reload_from_subscription_config_text(ss_config(), Some("MISSING".to_string()))
        .expect_err("reload should reject unknown outbound");

    assert!(error.contains("OutboundNotFound"));
    assert_eq!(handle.selected_outbound(), Some("SS-READY"));
    assert_eq!(handle.generation(), initial_generation);
    assert!(matches!(
        handle.status(),
        RuntimeStatus::Running {
            selected_outbound,
            ..
        } if selected_outbound == "SS-READY"
    ));
    assert!(handle
        .events()
        .last()
        .is_some_and(|event| matches!(event.status, RuntimeStatus::Failed(_))));

    let state = handle
        .stop()
        .expect("stop managed mixed background listener");
    assert_eq!(state.status(), &RuntimeStatus::Stopped);
}

#[test]
fn managed_mixed_controller_start_status_reload_and_stop() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);

    assert!(!core.is_running());
    assert_eq!(core.status().status, RuntimeStatus::Stopped);

    let started = core
        .start_from_subscription_config_text(
            ss_config(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                system_proxy: true,
                system_proxy_bypass: vec!["localhost".to_string()],
                tun_tcp_max_active_sessions: 17,
                dns_options: MixedDnsOptions {
                    local_resolution_policy: DnsLocalResolutionPolicy::PreventPublicLeak,
                    address_family_policy: DnsAddressFamilyPolicy::Ipv6Only,
                    ..MixedDnsOptions::default()
                },
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");

    assert!(core.is_running());
    assert_eq!(started.selected_outbound.as_deref(), Some("SS-READY"));
    assert!(started.listen_addr.is_some());
    assert_eq!(started.generation, 1);
    assert!(started.started_at.is_some());
    assert!(started.uptime.is_some());
    assert_eq!(started.connection_metrics.total_connection_count, 0);
    assert_eq!(
        started.connection_metrics.connection_history_limit,
        MANAGED_CONNECTION_REPORT_HISTORY_LIMIT
    );
    assert!(matches!(started.status, RuntimeStatus::Running { .. }));
    assert!(started.system_proxy_enabled());
    assert_eq!(
        started.dns_options.local_resolution_policy,
        DnsLocalResolutionPolicy::PreventPublicLeak
    );
    assert_eq!(
        started.dns_options.address_family_policy,
        DnsAddressFamilyPolicy::Ipv6Only
    );
    assert_eq!(started.tun_tcp_max_active_sessions, 17);
    assert_eq!(
        started.max_connection_workers,
        DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS
    );
    assert_eq!(started.active_connection_workers, 0);
    assert_eq!(started.peak_connection_workers, 0);
    assert_eq!(started.active_client_connections, 0);
    assert_eq!(started.peak_client_connections, 0);
    assert_eq!(
        started.available_connection_worker_slots,
        DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS
    );
    assert_eq!(
        started.system_proxy.as_ref().map(|config| &config.bypass),
        Some(&vec!["localhost".to_string()])
    );
    assert_eq!(started.last_error, None);
    assert!(!started.recent_events.is_empty());

    let duplicate_start = core
        .start_from_subscription_config_text(
            ss_config(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                ..ManagedMixedOptions::default()
            },
        )
        .expect_err("controller should reject duplicate start");
    assert!(duplicate_start.contains("already running"));

    let reloaded = core
        .reload_from_subscription_config_text(
            &ss_config_with_tag("SS-NEXT"),
            Some("SS-NEXT".to_string()),
        )
        .expect("reload managed mixed controller");

    assert_eq!(reloaded.selected_outbound.as_deref(), Some("SS-NEXT"));
    assert_eq!(reloaded.generation, 2);
    assert_eq!(reloaded.started_at, started.started_at);
    assert!(reloaded.uptime.is_some());
    assert_eq!(
        reloaded.dns_options.address_family_policy,
        DnsAddressFamilyPolicy::Ipv6Only
    );
    assert_eq!(reloaded.tun_tcp_max_active_sessions, 17);
    assert_eq!(
        reloaded.max_connection_workers,
        DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS
    );
    assert_eq!(reloaded.active_connection_workers, 0);
    assert_eq!(reloaded.peak_connection_workers, 0);
    assert_eq!(reloaded.active_client_connections, 0);
    assert_eq!(reloaded.peak_client_connections, 0);
    assert_eq!(
        reloaded.available_connection_worker_slots,
        DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS
    );
    assert!(reloaded.event_count >= started.event_count);
    assert!(reloaded.recent_events.len() <= MANAGED_MIXED_RECENT_EVENT_LIMIT);
    assert!(matches!(
        reloaded.status,
        RuntimeStatus::Running {
            selected_outbound,
            ..
        } if selected_outbound == "SS-NEXT"
    ));

    let stop_started = Instant::now();
    let stopped = core.stop().expect("stop managed mixed controller");
    assert!(stop_started.elapsed() < Duration::from_secs(5));

    assert_eq!(stopped.status(), &RuntimeStatus::Stopped);
    assert!(!core.is_running());
    assert_eq!(core.status().status, RuntimeStatus::Stopped);
    assert!(core.status().started_at.is_none());
    assert!(core.status().uptime.is_none());
    assert_eq!(core.status().active_connection_workers, 0);
    assert_eq!(core.status().peak_connection_workers, 0);
    assert_eq!(core.status().active_client_connections, 0);
    assert_eq!(core.status().peak_client_connections, 0);
    assert!(!core.status().system_proxy_enabled());
    assert!(!platform_controller.restored.borrow().is_empty());
}

#[test]
fn managed_mixed_controller_update_plan_reload_preserves_selected_outbound() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    core.start_from_subscription_config_text(
        &ss_config_with_tags(&["SS-OLD", "SS-STAY"]),
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-STAY".to_string()),
            ..ManagedMixedOptions::default()
        },
    )
    .expect("start managed mixed controller");
    core.record_node_health(ManagedNodeHealthStatus::healthy(
        "SS-OLD",
        Some(80),
        true,
        true,
    ))
    .expect("record old health");

    let outcome = core
        .reload_from_subscription_config_text_with_update_plan(&ss_config_with_tags(&[
            "SS-STAY", "SS-NEW",
        ]))
        .expect("planned subscription update");

    assert!(outcome.applied);
    assert_eq!(outcome.error, None);
    assert_eq!(
        outcome.report.reason,
        SubscriptionUpdateReason::SelectedOutboundPreserved
    );
    assert_eq!(
        outcome.report.current_selected_outbound.as_deref(),
        Some("SS-STAY")
    );
    assert_eq!(
        outcome.report.planned_selected_outbound.as_deref(),
        Some("SS-STAY")
    );
    assert!(outcome.report.selected_outbound_preserved);
    assert!(!outcome.report.selected_outbound_changed);
    assert_eq!(outcome.report.added_tags, vec!["SS-NEW".to_string()]);
    assert_eq!(outcome.report.removed_tags, vec!["SS-OLD".to_string()]);
    assert_eq!(outcome.report.retained_tags, vec!["SS-STAY".to_string()]);
    assert_eq!(outcome.status.selected_outbound.as_deref(), Some("SS-STAY"));
    assert_eq!(outcome.status.generation, 2);
    let subscription = outcome.status.subscription.as_ref().expect("subscription");
    assert!(subscription.health_for("SS-OLD").is_none());
    assert!(subscription.health_for("SS-STAY").is_some());
    assert!(subscription.health_for("SS-NEW").is_some());
    assert!(outcome.status.recent_events.iter().any(|event| {
        event.note.as_deref().is_some_and(|note| {
            note.starts_with("subscription update applied: reason=selected-outbound-preserved")
        })
    }));

    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_update_plan_reload_falls_back_to_new_default() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    core.start_from_subscription_config_text(
        &ss_config_with_tags(&["SS-A", "SS-B"]),
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-B".to_string()),
            ..ManagedMixedOptions::default()
        },
    )
    .expect("start managed mixed controller");

    let outcome = core
        .reload_from_subscription_config_text_with_update_plan(&ss_config_with_tags(&[
            "SS-C", "SS-D",
        ]))
        .expect("planned subscription update");

    assert!(outcome.applied);
    assert_eq!(
        outcome.report.reason,
        SubscriptionUpdateReason::SelectedOutboundMissingUseDefault
    );
    assert_eq!(
        outcome.report.current_selected_outbound.as_deref(),
        Some("SS-B")
    );
    assert_eq!(
        outcome.report.planned_selected_outbound.as_deref(),
        Some("SS-C")
    );
    assert!(!outcome.report.selected_outbound_preserved);
    assert!(outcome.report.selected_outbound_changed);
    assert_eq!(outcome.status.selected_outbound.as_deref(), Some("SS-C"));
    assert!(matches!(
        outcome.status.status,
        RuntimeStatus::Running {
            selected_outbound,
            ..
        } if selected_outbound == "SS-C"
    ));

    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_update_plan_rejects_unusable_new_subscription() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    let started = core
        .start_from_subscription_config_text(
            ss_config(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");
    let unusable = r#"
proxies:
  - name: WG-SKIPPED
    type: wireguard
    server: wg.example.com
    port: 51820
    password: ignored
"#;

    let outcome = core
        .reload_from_subscription_config_text_with_update_plan(unusable)
        .expect("planned unusable subscription update");

    assert!(!outcome.applied);
    assert_eq!(
        outcome.error.as_deref(),
        Some("subscription update rejected: no supported outbounds")
    );
    assert_eq!(
        outcome.report.reason,
        SubscriptionUpdateReason::NoSupportedOutbounds
    );
    assert!(!outcome.report.usable);
    assert_eq!(outcome.report.new_supported_count, 0);
    assert_eq!(outcome.report.new_skipped_count, 1);
    assert_eq!(outcome.report.planned_selected_outbound, None);
    assert_eq!(outcome.status.generation, started.generation);
    assert_eq!(
        outcome.status.selected_outbound.as_deref(),
        Some("SS-READY")
    );
    assert_eq!(
        outcome.status.last_error,
        Some(ClientErrorKind::NoSupportedOutbounds)
    );
    assert!(matches!(
        outcome.status.status,
        RuntimeStatus::Running {
            ref selected_outbound,
            ..
        } if selected_outbound == "SS-READY"
    ));
    assert!(outcome.status.recent_events.iter().any(|event| {
        event.note.as_deref().is_some_and(|note| {
            note.starts_with("subscription update rejected: no supported outbounds")
        })
    }));

    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_updates_from_subscription_url_and_redacts_source() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    core.start_from_subscription_config_text(
        &ss_config_with_tags(&["SS-OLD", "SS-STAY"]),
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-STAY".to_string()),
            ..ManagedMixedOptions::default()
        },
    )
    .expect("start managed mixed controller");
    let (url, request_thread) =
        spawn_subscription_http_server(200, "OK", ss_config_with_tags(&["SS-STAY", "SS-NEW"]));

    let outcome = core
        .reload_from_subscription_url_with_update_plan(&url, Duration::from_secs(2), 4096)
        .expect("subscription URL update");
    let request_line = request_thread.join().expect("subscription request");

    assert_eq!(
        request_line,
        "GET /panel/private/sub?token=super-secret-token HTTP/1.1"
    );
    assert!(outcome.applied);
    assert_eq!(outcome.error, None);
    assert!(outcome.fetch.ok);
    assert_eq!(outcome.fetch.http_status, Some(200));
    assert!(outcome.fetch.body_bytes.is_some_and(|bytes| bytes > 0));
    let source = outcome.fetch.source.as_ref().expect("fetch source");
    assert_eq!(source.scheme, "http");
    assert_eq!(source.host, "127.0.0.1");
    assert!(source.path_present);
    assert!(source.query_present);
    let update = outcome.update.as_ref().expect("update report");
    assert_eq!(
        update.reason,
        SubscriptionUpdateReason::SelectedOutboundPreserved
    );
    assert_eq!(update.planned_selected_outbound.as_deref(), Some("SS-STAY"));
    assert_eq!(outcome.status.selected_outbound.as_deref(), Some("SS-STAY"));
    assert_eq!(outcome.status.generation, 2);
    let last_update = outcome
        .status
        .last_subscription_url_update
        .as_ref()
        .expect("last subscription URL update status");
    assert!(last_update.applied);
    assert_eq!(last_update.error, None);
    assert!(last_update.fetch.ok);
    assert_eq!(last_update.fetch.http_status, Some(200));
    assert_eq!(
        last_update
            .update
            .as_ref()
            .expect("last update report")
            .reason,
        SubscriptionUpdateReason::SelectedOutboundPreserved
    );

    let value = managed_subscription_url_update_outcome_json_value(&outcome);
    assert_eq!(value["status"], "ok");
    assert_eq!(value["fetch"]["status"], "ok");
    assert_eq!(value["fetch"]["source"]["path_present"], true);
    assert_eq!(value["fetch"]["source"]["query_present"], true);
    assert_eq!(value["update"]["reason"], "selected-outbound-preserved");
    assert_eq!(
        value["runtime_status"]["subscription"]["selected_outbound"],
        "SS-STAY"
    );
    assert_eq!(
        value["runtime_status"]["last_subscription_url_update"]["status"],
        "ok"
    );
    assert_eq!(
        value["runtime_status"]["last_subscription_url_update"]["fetch"]["source"]["path_present"],
        true
    );
    let status_value = managed_mixed_status_json_value(&outcome.status);
    assert_eq!(status_value["last_subscription_url_update"]["status"], "ok");
    assert_eq!(
        status_value["last_subscription_url_update"]["update"]["reason"],
        "selected-outbound-preserved"
    );
    let serialized = value.to_string();
    assert!(!serialized.contains("/panel/private/sub"));
    assert!(!serialized.contains("super-secret-token"));
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("ss.example.com"));

    core.stop().expect("stop managed mixed controller");
    let stopped_status = core.status();
    assert!(stopped_status
        .last_subscription_url_update
        .as_ref()
        .is_some_and(|update| update.applied));
}

#[test]
fn managed_mixed_controller_subscription_url_fetch_failure_keeps_runtime() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    let started = core
        .start_from_subscription_config_text(
            ss_config(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");
    let (url, request_thread) =
        spawn_subscription_http_server(500, "Panel Error", "panel failed".to_string());

    let outcome = core
        .reload_from_subscription_url_with_update_plan(&url, Duration::from_secs(2), 4096)
        .expect("subscription URL update failure outcome");
    let request_line = request_thread.join().expect("subscription request");

    assert_eq!(
        request_line,
        "GET /panel/private/sub?token=super-secret-token HTTP/1.1"
    );
    assert!(!outcome.applied);
    assert!(outcome.update.is_none());
    assert!(!outcome.fetch.ok);
    assert_eq!(outcome.fetch.error_kind.as_deref(), Some("http-status"));
    assert_eq!(
        outcome.error.as_deref(),
        Some("subscription URL fetch failed: http-status")
    );
    assert_eq!(outcome.status.generation, started.generation);
    assert_eq!(
        outcome.status.selected_outbound.as_deref(),
        Some("SS-READY")
    );
    assert!(matches!(
        outcome.status.status,
        RuntimeStatus::Running {
            ref selected_outbound,
            ..
        } if selected_outbound == "SS-READY"
    ));
    assert!(outcome.status.last_error.as_ref().is_some_and(|error| {
        matches!(error, ClientErrorKind::ConfigInvalid(detail) if detail == "subscription URL fetch failed: http-status")
    }));
    let last_update = outcome
        .status
        .last_subscription_url_update
        .as_ref()
        .expect("last subscription URL update status");
    assert!(!last_update.applied);
    assert_eq!(last_update.update, None);
    assert!(!last_update.fetch.ok);
    assert_eq!(last_update.fetch.error_kind.as_deref(), Some("http-status"));
    assert_eq!(
        last_update.error.as_deref(),
        Some("subscription URL fetch failed: http-status")
    );
    let value = managed_subscription_url_update_outcome_json_value(&outcome);
    assert_eq!(value["status"], "error");
    assert_eq!(value["fetch"]["error_kind"], "http-status");
    assert_eq!(
        value["runtime_status"]["last_subscription_url_update"]["status"],
        "error"
    );
    assert_eq!(
        value["runtime_status"]["last_subscription_url_update"]["fetch"]["error_kind"],
        "http-status"
    );
    let serialized = value.to_string();
    assert!(!serialized.contains("/panel/private/sub"));
    assert!(!serialized.contains("super-secret-token"));

    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_subscription_url_unusable_update_keeps_runtime() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    let started = core
        .start_from_subscription_config_text(
            ss_config(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");
    let unusable = r#"
proxies:
  - name: WG-SKIPPED
    type: wireguard
    server: wg.example.com
    port: 51820
    password: ignored
"#;
    let (url, request_thread) = spawn_subscription_http_server(200, "OK", unusable.to_string());

    let outcome = core
        .reload_from_subscription_url_with_update_plan(&url, Duration::from_secs(2), 4096)
        .expect("subscription URL unusable update outcome");
    request_thread.join().expect("subscription request");

    assert!(!outcome.applied);
    assert!(outcome.fetch.ok);
    assert_eq!(outcome.fetch.http_status, Some(200));
    assert_eq!(
        outcome.error.as_deref(),
        Some("subscription update rejected: no supported outbounds")
    );
    let update = outcome.update.as_ref().expect("update report");
    assert_eq!(
        update.reason,
        SubscriptionUpdateReason::NoSupportedOutbounds
    );
    assert_eq!(update.new_supported_count, 0);
    assert_eq!(update.new_skipped_count, 1);
    assert_eq!(outcome.status.generation, started.generation);
    assert_eq!(
        outcome.status.selected_outbound.as_deref(),
        Some("SS-READY")
    );
    assert_eq!(
        outcome.status.last_error,
        Some(ClientErrorKind::NoSupportedOutbounds)
    );
    let last_update = outcome
        .status
        .last_subscription_url_update
        .as_ref()
        .expect("last subscription URL update status");
    assert!(!last_update.applied);
    assert!(last_update.fetch.ok);
    assert_eq!(
        last_update
            .update
            .as_ref()
            .expect("last update report")
            .reason,
        SubscriptionUpdateReason::NoSupportedOutbounds
    );
    assert_eq!(
        last_update.error.as_deref(),
        Some("subscription update rejected: no supported outbounds")
    );
    let value = managed_mixed_status_json_value(&outcome.status);
    assert_eq!(value["last_subscription_url_update"]["status"], "error");
    assert_eq!(
        value["last_subscription_url_update"]["update"]["reason"],
        "no-supported-outbounds"
    );

    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_subscription_url_invalid_update_keeps_runtime() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    let started = core
        .start_from_subscription_config_text(
            ss_config(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");
    let (url, request_thread) = spawn_subscription_http_server(
        200,
        "OK",
        "proxies:\n  - name: BROKEN\n    type: ss\n    port: nope\n".to_string(),
    );

    let outcome = core
        .reload_from_subscription_url_with_update_plan(&url, Duration::from_secs(2), 4096)
        .expect("subscription URL invalid update outcome");
    request_thread.join().expect("subscription request");

    assert!(!outcome.applied);
    assert!(outcome.fetch.ok);
    assert_eq!(outcome.fetch.http_status, Some(200));
    assert!(outcome.update.is_none());
    assert!(outcome
        .error
        .as_deref()
        .is_some_and(|error| error.contains("subscription update plan failed")));
    assert_eq!(outcome.status.generation, started.generation);
    assert_eq!(
        outcome.status.selected_outbound.as_deref(),
        Some("SS-READY")
    );
    assert!(outcome.status.last_error.as_ref().is_some_and(|error| {
        matches!(error, ClientErrorKind::ConfigInvalid(detail) if detail.contains("subscription update plan failed"))
    }));
    let last_update = outcome
        .status
        .last_subscription_url_update
        .as_ref()
        .expect("last subscription URL update status");
    assert!(!last_update.applied);
    assert!(last_update.fetch.ok);
    assert_eq!(last_update.update, None);
    assert!(last_update
        .error
        .as_deref()
        .is_some_and(|error| error.contains("subscription update plan failed")));
    let value = managed_subscription_url_update_outcome_json_value(&outcome);
    assert_eq!(value["status"], "error");
    assert_eq!(value["fetch"]["status"], "ok");
    assert!(value["update"].is_null());
    assert_eq!(
        value["runtime_status"]["last_subscription_url_update"]["status"],
        "error"
    );
    let serialized = value.to_string();
    assert!(!serialized.contains("/panel/private/sub"));
    assert!(!serialized.contains("super-secret-token"));

    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_status_records_recent_connection_metrics_across_reload() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    let started = core
        .start_from_subscription_config_text(
            ss_config(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                block_domains: vec!["blocked.example.com".to_string()],
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");
    let listen_addr = started.listen_addr.expect("managed listener addr");

    request_blocked_socks5_domain(listen_addr, "blocked.example.com", 443);

    let status = core.status();
    assert_eq!(status.connection_metrics.total_connection_count, 1);
    assert_eq!(status.connection_metrics.success_count, 0);
    assert_eq!(status.connection_metrics.failure_count, 1);
    assert_eq!(
        status.connection_metrics.connection_limit_rejection_count,
        0
    );
    assert_eq!(
        status.connection_metrics.error_kind_counts,
        vec![ConnectionErrorKindCount {
            error_kind: ConnectionErrorKind::RouteBlocked,
            count: 1,
        }]
    );
    assert_eq!(
        status.connection_metrics.route_action_counts,
        vec![ConnectionRouteActionCount {
            route_action: RouteAction::Block,
            count: 1,
        }]
    );
    assert_eq!(
        status.connection_metrics.inbound_counts,
        vec![ConnectionInboundCount {
            inbound: "socks5".to_string(),
            count: 1,
        }]
    );
    assert!(status.connection_metrics.last_connection_at.is_some());
    assert!(status.connection_metrics.last_success_at.is_none());
    assert_eq!(
        status.connection_metrics.last_failure_at,
        status.connection_metrics.last_connection_at
    );
    assert_eq!(status.connection_metrics.retained_connection_count, 1);
    assert_eq!(
        status.connection_metrics.connection_history_limit,
        MANAGED_CONNECTION_REPORT_HISTORY_LIMIT
    );
    let report = status
        .connection_metrics
        .recent_connections
        .first()
        .expect("recent connection report");
    assert_eq!(report.inbound, "socks5");
    assert_eq!(report.target.host, "blocked.example.com");
    assert_eq!(report.target.port, 443);
    assert_eq!(report.route_action, keli_net_core::RouteAction::Block);
    assert_eq!(report.error_kind, Some(ConnectionErrorKind::RouteBlocked));

    let value = managed_mixed_status_json_value(&status);
    assert_eq!(value["connection_metrics"]["total_connection_count"], 1);
    assert_eq!(value["connection_metrics"]["failure_count"], 1);
    assert_eq!(
        value["connection_metrics"]["connection_limit_rejection_count"],
        0
    );
    assert_eq!(
        value["connection_metrics"]["error_kind_counts"]["route_blocked"],
        1
    );
    assert_eq!(
        value["connection_metrics"]["route_action_counts"][0]["route_action"]["kind"],
        "block"
    );
    assert_eq!(
        value["connection_metrics"]["route_action_counts"][0]["count"],
        1
    );
    assert_eq!(
        value["connection_metrics"]["inbound_counts"][0]["inbound"],
        "socks5"
    );
    assert_eq!(value["connection_metrics"]["inbound_counts"][0]["count"], 1);
    assert!(value["connection_metrics"]["last_connection_at_unix_ms"]
        .as_u64()
        .is_some());
    assert_eq!(
        value["connection_metrics"]["last_success_at_unix_ms"],
        Value::Null
    );
    assert_eq!(
        value["connection_metrics"]["last_failure_at_unix_ms"],
        value["connection_metrics"]["last_connection_at_unix_ms"]
    );
    assert_eq!(
        value["connection_metrics"]["recent_connections"][0]["target"]["host"],
        "blocked.example.com"
    );
    assert_eq!(
        value["connection_metrics"]["recent_connections"][0]["route_action"]["kind"],
        "block"
    );
    assert_eq!(
        value["connection_metrics"]["recent_connections"][0]["error_kind"],
        "route_blocked"
    );

    let reloaded = core
        .reload_from_subscription_config_text(
            &ss_config_with_tag("SS-NEXT"),
            Some("SS-NEXT".to_string()),
        )
        .expect("reload managed mixed controller");
    assert_eq!(reloaded.connection_metrics.total_connection_count, 1);
    assert_eq!(reloaded.connection_metrics.failure_count, 1);
    assert_eq!(
        reloaded.connection_metrics.connection_limit_rejection_count,
        0
    );
    assert_eq!(
        reloaded.connection_metrics.error_kind_counts,
        vec![ConnectionErrorKindCount {
            error_kind: ConnectionErrorKind::RouteBlocked,
            count: 1,
        }]
    );
    assert_eq!(
        reloaded.connection_metrics.route_action_counts,
        status.connection_metrics.route_action_counts
    );
    assert_eq!(
        reloaded.connection_metrics.inbound_counts,
        status.connection_metrics.inbound_counts
    );
    assert_eq!(
        reloaded.connection_metrics.last_failure_at,
        status.connection_metrics.last_failure_at
    );
    assert_eq!(reloaded.connection_metrics.retained_connection_count, 1);

    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_background_listener_handles_next_connection_while_one_waits() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    let started = core
        .start_from_subscription_config_text(
            ss_config(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                block_domains: vec!["blocked.example.com".to_string()],
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");
    let listen_addr = started.listen_addr.expect("managed listener addr");

    let stalled_client = open_socks5_handshake(listen_addr);
    let busy = wait_for_active_connection_workers(&core, 1);
    assert_eq!(busy.active_connection_workers, 1);
    assert_eq!(busy.peak_connection_workers, 1);
    assert_eq!(busy.active_client_connections, 1);
    assert_eq!(busy.peak_client_connections, 1);
    assert_eq!(
        busy.available_connection_worker_slots,
        DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS - 1
    );

    request_blocked_socks5_domain(listen_addr, "blocked.example.com", 443);

    let status = core.status();
    assert_eq!(status.peak_connection_workers, 2);
    assert_eq!(status.peak_client_connections, 2);
    assert_eq!(status.connection_metrics.total_connection_count, 1);
    assert_eq!(status.connection_metrics.failure_count, 1);
    assert_eq!(
        status
            .connection_metrics
            .recent_connections
            .first()
            .map(|report| report.error_kind),
        Some(Some(ConnectionErrorKind::RouteBlocked))
    );

    drop(stalled_client);
    let drained = wait_for_active_connection_workers(&core, 0);
    assert_eq!(drained.active_connection_workers, 0);
    assert_eq!(drained.peak_connection_workers, 2);
    assert_eq!(drained.active_client_connections, 0);
    assert_eq!(drained.peak_client_connections, 2);
    assert_eq!(
        drained.available_connection_worker_slots,
        DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS
    );
    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_background_stop_closes_active_connections() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    let started = core
        .start_from_subscription_config_text(
            ss_config(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");
    let listen_addr = started.listen_addr.expect("managed listener addr");

    let mut stalled_client = open_socks5_handshake(listen_addr);
    let busy = wait_for_active_connection_workers(&core, 1);
    assert_eq!(busy.active_connection_workers, 1);
    assert_eq!(busy.peak_connection_workers, 1);
    assert_eq!(busy.active_client_connections, 1);
    assert_eq!(busy.peak_client_connections, 1);

    let stop_started = Instant::now();
    let stopped = core.stop().expect("stop managed mixed controller");
    assert!(stop_started.elapsed() < Duration::from_secs(5));
    assert_eq!(stopped.status(), &RuntimeStatus::Stopped);
    assert!(!core.is_running());

    let drain_event = stopped
        .events()
        .iter()
        .find(|event| {
            matches!(
                event.diagnostic,
                Some(RuntimeDiagnostic::ManagedMixedStopDrain(_))
            )
        })
        .expect("managed mixed stop drain diagnostic event");
    assert!(matches!(
        &drain_event.status,
        RuntimeStatus::Running {
            selected_outbound,
            ..
        } if selected_outbound == "SS-READY"
    ));
    let drain_note = drain_event.note.as_deref().expect("stop drain note");
    assert!(drain_note.starts_with(
        "managed mixed stop drain active_connections_shutdown=1 workers_before_shutdown=1"
    ));
    assert!(drain_note.contains("drain_elapsed_ms="));
    assert!(drain_note.contains("drain_timeout_ms=500"));
    let RuntimeDiagnostic::ManagedMixedStopDrain(diagnostic) = drain_event
        .diagnostic
        .as_ref()
        .expect("stop drain diagnostic")
    else {
        panic!("expected managed mixed stop drain diagnostic");
    };
    assert_eq!(diagnostic.active_connections_shutdown, 1);
    assert_eq!(diagnostic.workers_before_shutdown, 1);
    assert_eq!(
        diagnostic.workers_drained + diagnostic.workers_remaining,
        diagnostic.workers_before_shutdown
    );
    assert!(diagnostic.workers_remaining <= diagnostic.workers_before_shutdown);
    assert!(diagnostic.drain_elapsed_ms <= stop_started.elapsed().as_millis() as u64);
    assert!(diagnostic.drain_elapsed_ms <= diagnostic.drain_timeout_ms + 1000);
    assert_eq!(diagnostic.drain_timeout_ms, 500);
    assert_eq!(diagnostic.timed_out, diagnostic.workers_remaining > 0);

    let post_stop_status = core.status();
    assert_eq!(post_stop_status.status, RuntimeStatus::Stopped);
    assert_eq!(post_stop_status.event_count, stopped.event_count());
    assert_eq!(
        post_stop_status.retained_event_count,
        stopped.events().len()
    );
    assert!(post_stop_status.started_at.is_none());
    assert!(post_stop_status.uptime.is_none());
    assert_eq!(post_stop_status.active_connection_workers, 0);
    assert_eq!(post_stop_status.peak_connection_workers, 1);
    assert_eq!(post_stop_status.active_client_connections, 0);
    assert_eq!(post_stop_status.peak_client_connections, 1);
    assert!(post_stop_status.recent_events.iter().any(|event| {
        matches!(
            event.diagnostic,
            Some(RuntimeDiagnostic::ManagedMixedStopDrain(_))
        )
    }));
    let post_stop_value = managed_mixed_status_json_value(&post_stop_status);
    assert_eq!(post_stop_value["status"]["state"], "stopped");
    assert!(post_stop_value["recent_events"]
        .as_array()
        .is_some_and(|events| {
            events.iter().any(|event| {
                event["diagnostic"]["kind"].as_str() == Some("managed-mixed-stop-drain")
            })
        }));

    let mut byte = [0; 1];
    assert!(stalled_client.read_exact(&mut byte).is_err());
}

#[test]
fn managed_mixed_background_listener_rejects_connections_above_worker_limit() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    let started = core
        .start_from_subscription_config_text(
            ss_config(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                max_connection_workers: 1,
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");
    let listen_addr = started.listen_addr.expect("managed listener addr");

    let stalled_client = open_socks5_handshake(listen_addr);
    let busy = wait_for_active_connection_workers(&core, 1);
    assert_eq!(busy.max_connection_workers, 1);
    assert_eq!(busy.active_connection_workers, 1);
    assert_eq!(busy.peak_connection_workers, 1);
    assert_eq!(busy.active_client_connections, 1);
    assert_eq!(busy.peak_client_connections, 1);
    assert_eq!(busy.available_connection_worker_slots, 0);
    attempt_rejected_socks5_hello(listen_addr);

    let status = wait_for_connection_count(&core, 1);
    assert_eq!(status.max_connection_workers, 1);
    assert_eq!(status.active_connection_workers, 1);
    assert_eq!(status.peak_connection_workers, 1);
    assert_eq!(status.active_client_connections, 1);
    assert_eq!(status.peak_client_connections, 1);
    assert_eq!(status.available_connection_worker_slots, 0);
    assert_eq!(status.connection_metrics.total_connection_count, 1);
    assert_eq!(status.connection_metrics.failure_count, 1);
    assert_eq!(
        status.connection_metrics.connection_limit_rejection_count,
        1
    );
    assert_eq!(
        status.connection_metrics.error_kind_counts,
        vec![ConnectionErrorKindCount {
            error_kind: ConnectionErrorKind::ConnectionLimitReached,
            count: 1,
        }]
    );
    assert!(status.connection_metrics.last_connection_at.is_some());
    assert!(status.connection_metrics.last_success_at.is_none());
    assert_eq!(
        status.connection_metrics.last_failure_at,
        status.connection_metrics.last_connection_at
    );
    let report = status
        .connection_metrics
        .recent_connections
        .first()
        .expect("connection limit report");
    assert_eq!(report.inbound, "mixed");
    assert_eq!(report.target.host, "connection-worker-limit");
    assert_eq!(
        report.error_kind,
        Some(ConnectionErrorKind::ConnectionLimitReached)
    );

    let value = managed_mixed_status_json_value(&status);
    assert_eq!(value["max_connection_workers"], 1);
    assert_eq!(value["active_connection_workers"], 1);
    assert_eq!(value["peak_connection_workers"], 1);
    assert_eq!(value["active_client_connections"], 1);
    assert_eq!(value["peak_client_connections"], 1);
    assert_eq!(value["available_connection_worker_slots"], 0);
    assert_eq!(
        value["connection_metrics"]["connection_limit_rejection_count"],
        1
    );
    assert_eq!(
        value["connection_metrics"]["error_kind_counts"]["connection_limit_reached"],
        1
    );
    assert!(value["connection_metrics"]["last_failure_at_unix_ms"]
        .as_u64()
        .is_some());
    assert_eq!(
        value["connection_metrics"]["recent_connections"][0]["error_kind"],
        "connection_limit_reached"
    );

    drop(stalled_client);
    let drained = wait_for_active_connection_workers(&core, 0);
    assert_eq!(drained.active_connection_workers, 0);
    assert_eq!(drained.peak_connection_workers, 1);
    assert_eq!(drained.active_client_connections, 0);
    assert_eq!(drained.peak_client_connections, 1);
    assert_eq!(drained.available_connection_worker_slots, 1);
    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_status_json_reports_ui_snapshot_without_secrets() {
    let snapshot = SystemProxySnapshot {
        proxy_enable: Some(0),
        proxy_server: Some("old.proxy:8080".to_string()),
        proxy_override: None,
    };
    let platform_controller = FakeSystemProxyController::new(snapshot);
    let mut core = ManagedMixedController::new(&platform_controller);
    core.record_panel_state(
        PanelState::new(
            PanelUserState {
                account_state: PanelAccountState::Active,
                used_bytes: Some(256),
                total_bytes: Some(1024),
                expires_at: None,
            },
            PanelRiskControlState::Clear,
        )
        .with_support_note("panel account active"),
    );
    let started = core
        .start_from_subscription_config_text(
            mixed_subscription_with_capability_variants(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                system_proxy: true,
                system_proxy_bypass: vec!["localhost".to_string(), "<local>".to_string()],
                tun_tcp_max_active_sessions: 17,
                dns_options: MixedDnsOptions {
                    local_resolution_policy: DnsLocalResolutionPolicy::PreventPublicLeak,
                    address_family_policy: DnsAddressFamilyPolicy::Ipv4Only,
                    ..MixedDnsOptions::default()
                },
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");
    let status = core
        .record_node_health(ManagedNodeHealthStatus::healthy(
            "SS-READY",
            Some(42),
            true,
            true,
        ))
        .expect("record node health");

    let value = managed_mixed_status_json_value(&status);
    assert_eq!(value["schema_version"], MANAGED_MIXED_STATUS_SCHEMA_VERSION);
    assert_eq!(value["status"]["state"], "running");
    assert_eq!(value["status"]["generation"], started.generation);
    assert_eq!(value["selected_outbound"], "SS-READY");
    assert_eq!(value["generation"], started.generation);
    assert!(value["started_at_unix_ms"].as_u64().is_some());
    assert!(value["uptime_ms"].as_u64().is_some());
    assert_eq!(value["connection_metrics"]["total_connection_count"], 0);
    assert_eq!(value["connection_metrics"]["success_count"], 0);
    assert_eq!(value["connection_metrics"]["failure_count"], 0);
    assert_eq!(
        value["connection_metrics"]["connection_limit_rejection_count"],
        0
    );
    assert!(value["connection_metrics"]["error_kind_counts"]
        .as_object()
        .is_some_and(|counts| counts.is_empty()));
    assert!(value["connection_metrics"]["route_action_counts"]
        .as_array()
        .is_some_and(|counts| counts.is_empty()));
    assert!(value["connection_metrics"]["inbound_counts"]
        .as_array()
        .is_some_and(|counts| counts.is_empty()));
    assert_eq!(value["connection_metrics"]["total_upload_bytes"], 0);
    assert_eq!(value["connection_metrics"]["total_download_bytes"], 0);
    assert_eq!(value["connection_metrics"]["total_connect_ms"], 0);
    assert_eq!(value["connection_metrics"]["timed_connect_count"], 0);
    assert_eq!(
        value["connection_metrics"]["average_connect_ms"],
        Value::Null
    );
    assert_eq!(value["connection_metrics"]["total_first_byte_ms"], 0);
    assert_eq!(value["connection_metrics"]["timed_first_byte_count"], 0);
    assert_eq!(
        value["connection_metrics"]["average_first_byte_ms"],
        Value::Null
    );
    assert_eq!(
        value["connection_metrics"]["last_connection_at_unix_ms"],
        Value::Null
    );
    assert_eq!(
        value["connection_metrics"]["last_success_at_unix_ms"],
        Value::Null
    );
    assert_eq!(
        value["connection_metrics"]["last_failure_at_unix_ms"],
        Value::Null
    );
    assert_eq!(
        value["connection_metrics"]["connection_history_limit"],
        MANAGED_CONNECTION_REPORT_HISTORY_LIMIT
    );
    assert!(value["listen_addr"].as_str().is_some());
    assert!(value["event_count"]
        .as_u64()
        .is_some_and(|count| count >= 3));
    assert!(value["retained_event_count"]
        .as_u64()
        .is_some_and(|count| count >= 3 && count <= DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT as u64));
    assert_eq!(
        value["event_history_limit"].as_u64(),
        Some(DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT as u64)
    );
    assert_eq!(
        value["recent_event_limit"].as_u64(),
        Some(MANAGED_MIXED_RECENT_EVENT_LIMIT as u64)
    );
    assert!(value["recent_events"].as_array().is_some_and(|events| {
        !events.is_empty() && events.len() <= MANAGED_MIXED_RECENT_EVENT_LIMIT
    }));
    assert_eq!(
        value["dns_options"]["local_resolution_policy"],
        "prevent-public-leak"
    );
    assert_eq!(value["dns_options"]["address_family_policy"], "ipv4-only");
    assert_eq!(value["tun_tcp_max_active_sessions"], 17);
    assert_eq!(
        value["max_connection_workers"],
        DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS
    );
    assert_eq!(value["active_connection_workers"], 0);
    assert_eq!(value["peak_connection_workers"], 0);
    assert_eq!(value["active_client_connections"], 0);
    assert_eq!(value["peak_client_connections"], 0);
    assert_eq!(
        value["available_connection_worker_slots"],
        DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS
    );
    assert_eq!(value["system_proxy"]["bypass"][0], "localhost");
    assert_eq!(value["panel_state"]["account_state"], "active");
    assert_eq!(value["panel_state"]["traffic_used_per_mille"], 250);
    assert_eq!(value["panel_state"]["restrict_traffic"], false);
    assert_eq!(value["subscription"]["selected_outbound"], "SS-READY");
    assert_eq!(value["subscription"]["recommended_outbound"], "SS-READY");
    assert_eq!(value["subscription"]["supported_count"], 2);
    assert_eq!(value["subscription"]["supported"][1]["tag"], "VLESS-EDGE");
    assert_eq!(value["subscription"]["supported"][1]["transport"], "ws");
    assert_eq!(value["subscription"]["node_health"][0]["state"], "healthy");
    assert_eq!(value["subscription"]["node_health"][0]["latency_ms"], 42);
    assert_eq!(value["subscription"]["health_summary"]["node_count"], 2);
    assert_eq!(value["subscription"]["health_summary"]["healthy_count"], 1);
    assert_eq!(value["subscription"]["health_summary"]["checked_count"], 1);
    assert_eq!(
        value["subscription"]["health_summary"]["unchecked_count"],
        1
    );
    assert_eq!(
        value["subscription"]["health_summary"]["udp_available_count"],
        1
    );
    assert_eq!(
        value["subscription"]["health_summary"]["udp_unavailable_count"],
        0
    );
    assert_eq!(
        value["subscription"]["health_summary"]["udp_unknown_count"],
        1
    );
    assert_eq!(
        value["subscription"]["health_summary"]["selected_udp_available"],
        true
    );
    assert_eq!(
        value["subscription"]["health_summary"]["recommended_udp_available"],
        true
    );
    assert_eq!(
        value["subscription"]["health_summary"]["selected_outbound_healthy"],
        true
    );
    assert_eq!(
        value["subscription"]["health_summary"]["recommended_outbound_healthy"],
        true
    );
    assert_eq!(
        value["subscription"]["health_summary"]["recommended_switch_ready"],
        false
    );
    assert_eq!(
        value["subscription"]["health_summary"]["recommended_switch_reason"],
        "already-selected"
    );

    let serialized = value.to_string();
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("00112233-4455-6677-8899-aabbccddeeff"));
    assert!(!serialized.contains("ss.example.com"));
    assert!(!serialized.contains("vless.example.com"));
    assert!(!serialized.contains("private-sni.example.com"));
    assert!(!serialized.contains("private-host.example.com"));
    assert!(!serialized.contains("/private-vless-path"));

    let mut output = Vec::new();
    write_managed_mixed_status_json_report(&status, &mut output)
        .expect("write managed status json");
    let report: Value = serde_json::from_slice(&output).expect("parse managed status json");
    assert_eq!(report["status"]["state"], "running");
    assert_eq!(report["subscription"]["supported"][1]["transport"], "ws");

    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_status_reports_total_event_count_after_history_is_bounded() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    let started = core
        .start_from_subscription_config_text(
            ss_config(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");
    core.reload_from_subscription_config_text(ss_config(), Some("MISSING".to_string()))
        .expect_err("reload should reject missing outbound");
    let expected_last_error = ClientErrorKind::OutboundNotFound("MISSING".to_string());
    let failed_status = core.status();
    assert_eq!(failed_status.last_error, Some(expected_last_error.clone()));

    let panel_state = PanelState::new(
        PanelUserState {
            account_state: PanelAccountState::Active,
            used_bytes: Some(128),
            total_bytes: Some(1024),
            expires_at: None,
        },
        PanelRiskControlState::Clear,
    );
    let mut status = failed_status.clone();

    for _ in 0..(DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT + 7) {
        status = core.record_panel_state(panel_state.clone());
    }

    assert!(status.event_count > started.event_count + DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT);
    assert!(status.event_count > status.recent_events.len());
    assert_eq!(
        status.retained_event_count,
        DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT
    );
    assert_eq!(
        status.event_history_limit,
        DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT
    );
    assert_eq!(status.recent_event_limit, MANAGED_MIXED_RECENT_EVENT_LIMIT);
    assert_eq!(status.last_error, Some(expected_last_error));
    assert!(!status
        .recent_events
        .iter()
        .any(|event| matches!(event.status, RuntimeStatus::Failed(_))));
    assert_eq!(status.recent_events.len(), MANAGED_MIXED_RECENT_EVENT_LIMIT);
    assert!(status.recent_events.iter().all(|event| {
        event
            .note
            .as_deref()
            .is_some_and(|note| note.starts_with("panel state recorded:"))
    }));

    let value = managed_mixed_status_json_value(&status);
    assert_eq!(
        value["event_count"].as_u64(),
        Some(status.event_count as u64)
    );
    assert_eq!(
        value["retained_event_count"].as_u64(),
        Some(DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT as u64)
    );
    assert_eq!(
        value["event_history_limit"].as_u64(),
        Some(DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT as u64)
    );
    assert_eq!(
        value["recent_event_limit"].as_u64(),
        Some(MANAGED_MIXED_RECENT_EVENT_LIMIT as u64)
    );
    assert!(value["recent_events"]
        .as_array()
        .is_some_and(|events| events.len() <= MANAGED_MIXED_RECENT_EVENT_LIMIT));

    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_status_json_includes_tun_runtime_diagnostic() {
    let diagnostic = RuntimeDiagnostic::TunPacketLoop(RuntimeTunPacketLoopDiagnostic {
        interface_name: "keli-tun0".to_string(),
        owns_device: true,
        processed_packets: 3,
        idle_events: 1,
        exit_reason: "stop-requested".to_string(),
        stop_requested: true,
        packet_limit_reached: false,
        dns_responses_written: 0,
        udp_relay_responses_written: 1,
        tcp_resets_written: 0,
        tcp_session_events: 2,
        tcp_session_packets_written: 2,
        tcp_max_active_sessions: 17,
        tcp_session_limit_rejections: 0,
        tcp_sessions_pruned: 0,
        tcp_server_closed_sessions_pruned: 0,
        tcp_post_closed_sessions_pruned: 0,
        tcp_server_close_marker_resets: 0,
        tcp_post_close_marker_resets: 0,
        tcp_sessions_open: 0,
        tcp_server_close_markers_open: 0,
        tcp_post_close_markers_open: 0,
        tcp_sessions_peak: 1,
        tcp_server_close_markers_peak: 0,
        tcp_post_close_markers_peak: 0,
        relay_packets: 3,
        tcp_relay_plans: 2,
        udp_relay_plans: 1,
        last_relay_route_action: Some("outbound:SS-READY".to_string()),
        last_relay_matched_rule: Some("proxy-udp".to_string()),
        dropped_packets: 1,
        recent_dropped_routes: vec![RuntimeTunPacketDroppedRouteDiagnostic {
            flow: "10.7.0.2:54321->198.18.0.1:9/17".to_string(),
            route_action: "block".to_string(),
            matched_rule: Some("tun-runtime-smoke-traffic-stimulus".to_string()),
            dns_hijacked: false,
        }],
        recent_dns_hijacked_routes: vec![RuntimeTunPacketDroppedRouteDiagnostic {
            flow: "10.7.0.2:54322->198.18.0.1:53/17".to_string(),
            route_action: "hijack-dns".to_string(),
            matched_rule: None,
            dns_hijacked: true,
        }],
        last_dropped_flow: Some("10.7.0.2:54321->198.18.0.1:9/17".to_string()),
        last_dropped_route_action: Some("block".to_string()),
        last_dropped_matched_rule: Some("tun-runtime-smoke-traffic-stimulus".to_string()),
        unsupported_packets: 0,
        packet_errors: 1,
        udp_relay_errors: 0,
        tcp_session_errors: 0,
        last_packet_error: Some("unsupported_TUN_packet_IP_version:_0".to_string()),
        last_udp_relay_error: None,
        last_tcp_session_error: None,
    });
    let snapshot = ManagedMixedStatusSnapshot {
        status: RuntimeStatus::Running {
            generation: 7,
            selected_outbound: "SS-READY".to_string(),
            listen: "127.0.0.1:7890".to_string(),
        },
        listen_addr: Some("127.0.0.1:7890".parse().expect("listen addr")),
        selected_outbound: Some("SS-READY".to_string()),
        generation: 7,
        started_at: Some(SystemTime::UNIX_EPOCH),
        uptime: Some(Duration::from_secs(2)),
        connection_metrics: ConnectionMetricsSnapshot::default(),
        event_count: 1,
        retained_event_count: 1,
        event_history_limit: DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT,
        recent_event_limit: MANAGED_MIXED_RECENT_EVENT_LIMIT,
        recent_events: vec![RuntimeEvent::with_diagnostic(
            RuntimeStatus::Running {
                generation: 7,
                selected_outbound: "SS-READY".to_string(),
                listen: "127.0.0.1:7890".to_string(),
            },
            Some("managed TUN runtime stopped"),
            diagnostic,
        )],
        last_error: None,
        system_proxy: None,
        subscription: None,
        last_subscription_url_update: None,
        dns_options: MixedDnsOptions::default(),
        tun_tcp_max_active_sessions: 17,
        max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
        active_connection_workers: 0,
        peak_connection_workers: 0,
        active_client_connections: 0,
        peak_client_connections: 0,
        available_connection_worker_slots: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
        panel_state: None,
    };

    let value = managed_mixed_status_json_value(&snapshot);
    let diagnostic = &value["recent_events"][0]["diagnostic"];
    assert_eq!(diagnostic["kind"], "tun-packet-loop");
    assert_eq!(diagnostic["interface_name"], "keli-tun0");
    assert_eq!(diagnostic["exit_reason"], "stop-requested");
    assert_eq!(diagnostic["processed_packets"], 3);
    assert_eq!(diagnostic["udp_relay_responses_written"], 1);
    assert_eq!(diagnostic["tcp_session_events"], 2);
    assert_eq!(diagnostic["tcp_max_active_sessions"], 17);
    assert_eq!(diagnostic["last_relay_route_action"], "outbound:SS-READY");
    assert_eq!(diagnostic["last_relay_matched_rule"], "proxy-udp");
    assert_eq!(diagnostic["dropped_packets"], 1);
    assert_eq!(
        diagnostic["recent_dropped_routes"][0]["flow"],
        "10.7.0.2:54321->198.18.0.1:9/17"
    );
    assert_eq!(
        diagnostic["recent_dropped_routes"][0]["route_action"],
        "block"
    );
    assert_eq!(
        diagnostic["recent_dropped_routes"][0]["matched_rule"],
        "tun-runtime-smoke-traffic-stimulus"
    );
    assert_eq!(
        diagnostic["recent_dropped_routes"][0]["dns_hijacked"],
        false
    );
    assert_eq!(
        diagnostic["recent_dns_hijacked_routes"][0]["flow"],
        "10.7.0.2:54322->198.18.0.1:53/17"
    );
    assert_eq!(
        diagnostic["recent_dns_hijacked_routes"][0]["route_action"],
        "hijack-dns"
    );
    assert_eq!(
        diagnostic["recent_dns_hijacked_routes"][0]["matched_rule"],
        Value::Null
    );
    assert_eq!(
        diagnostic["recent_dns_hijacked_routes"][0]["dns_hijacked"],
        true
    );
    assert_eq!(
        diagnostic["last_dropped_flow"],
        "10.7.0.2:54321->198.18.0.1:9/17"
    );
    assert_eq!(diagnostic["last_dropped_route_action"], "block");
    assert_eq!(
        diagnostic["last_dropped_matched_rule"],
        "tun-runtime-smoke-traffic-stimulus"
    );
    assert_eq!(
        diagnostic["last_packet_error"],
        "unsupported_TUN_packet_IP_version:_0"
    );
    assert_eq!(value["status"]["state"], "running");
    assert_eq!(value["status"]["generation"], 7);
    assert_eq!(value["started_at_unix_ms"], 0);
    assert_eq!(value["uptime_ms"], 2000);
}

#[test]
fn managed_mixed_status_json_includes_stop_drain_diagnostic() {
    let diagnostic =
        RuntimeDiagnostic::ManagedMixedStopDrain(RuntimeManagedMixedStopDrainDiagnostic {
            active_connections_shutdown: 2,
            workers_before_shutdown: 3,
            workers_drained: 2,
            workers_remaining: 1,
            drain_elapsed_ms: 47,
            drain_timeout_ms: 500,
            timed_out: true,
        });
    let snapshot = ManagedMixedStatusSnapshot {
        status: RuntimeStatus::Running {
            generation: 3,
            selected_outbound: "SS-READY".to_string(),
            listen: "127.0.0.1:7890".to_string(),
        },
        listen_addr: Some("127.0.0.1:7890".parse().expect("listen addr")),
        selected_outbound: Some("SS-READY".to_string()),
        generation: 3,
        started_at: Some(SystemTime::UNIX_EPOCH),
        uptime: Some(Duration::from_secs(1)),
        connection_metrics: ConnectionMetricsSnapshot::default(),
        event_count: 1,
        retained_event_count: 1,
        event_history_limit: DEFAULT_RUNTIME_EVENT_HISTORY_LIMIT,
        recent_event_limit: MANAGED_MIXED_RECENT_EVENT_LIMIT,
        recent_events: vec![RuntimeEvent::with_diagnostic(
            RuntimeStatus::Running {
                generation: 3,
                selected_outbound: "SS-READY".to_string(),
                listen: "127.0.0.1:7890".to_string(),
            },
            Some("managed mixed stop drain"),
            diagnostic,
        )],
        last_error: None,
        system_proxy: None,
        subscription: None,
        last_subscription_url_update: None,
        dns_options: MixedDnsOptions::default(),
        tun_tcp_max_active_sessions: 17,
        max_connection_workers: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
        active_connection_workers: 0,
        peak_connection_workers: 0,
        active_client_connections: 0,
        peak_client_connections: 0,
        available_connection_worker_slots: DEFAULT_MANAGED_MIXED_MAX_CONNECTION_WORKERS,
        panel_state: None,
    };

    let value = managed_mixed_status_json_value(&snapshot);
    let diagnostic = &value["recent_events"][0]["diagnostic"];
    assert_eq!(diagnostic["kind"], "managed-mixed-stop-drain");
    assert_eq!(diagnostic["active_connections_shutdown"], 2);
    assert_eq!(diagnostic["workers_before_shutdown"], 3);
    assert_eq!(diagnostic["workers_drained"], 2);
    assert_eq!(diagnostic["workers_remaining"], 1);
    assert_eq!(diagnostic["drain_elapsed_ms"], 47);
    assert_eq!(diagnostic["drain_timeout_ms"], 500);
    assert_eq!(diagnostic["timed_out"], true);
}

#[test]
fn managed_mixed_controller_records_panel_state_across_runtime() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);

    let healthy_panel = PanelState::new(
        PanelUserState {
            account_state: PanelAccountState::Active,
            used_bytes: Some(128),
            total_bytes: Some(1024),
            expires_at: None,
        },
        PanelRiskControlState::Clear,
    )
    .with_support_note("panel account active");
    let stopped = core.record_panel_state(healthy_panel.clone());

    assert_eq!(stopped.status, RuntimeStatus::Stopped);
    assert_eq!(stopped.panel_state, Some(healthy_panel.clone()));
    assert!(!stopped
        .panel_state
        .as_ref()
        .expect("panel state")
        .should_restrict_traffic());
    assert_eq!(
        stopped
            .panel_state
            .as_ref()
            .expect("panel state")
            .user
            .traffic_used_per_mille(),
        Some(125)
    );

    let started = core
        .start_from_subscription_config_text(
            ss_config(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");
    assert_eq!(started.panel_state, Some(healthy_panel));

    let restricted_panel = PanelState::new(
        PanelUserState {
            account_state: PanelAccountState::Limited,
            used_bytes: Some(1024),
            total_bytes: Some(1024),
            expires_at: None,
        },
        PanelRiskControlState::Restricted,
    )
    .with_support_note("panel risk-control restricted traffic");
    let restricted = core.record_panel_state(restricted_panel.clone());

    assert!(restricted
        .panel_state
        .as_ref()
        .expect("restricted panel state")
        .should_restrict_traffic());
    assert!(restricted.recent_events.iter().any(|event| {
        event.note.as_deref()
            == Some("panel state recorded: account=limited risk=restricted restrict_traffic=true")
    }));

    core.stop().expect("stop managed mixed controller");
    let stopped_after_runtime = core.status();
    assert_eq!(stopped_after_runtime.status, RuntimeStatus::Stopped);
    assert_eq!(stopped_after_runtime.panel_state, Some(restricted_panel));

    let cleared = core.clear_panel_state();
    assert_eq!(cleared.status, RuntimeStatus::Stopped);
    assert_eq!(cleared.panel_state, None);
}

#[test]
fn managed_mixed_controller_blocks_traffic_actions_when_panel_restricted() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    let restricted_panel = PanelState::new(
        PanelUserState {
            account_state: PanelAccountState::Limited,
            used_bytes: Some(1024),
            total_bytes: Some(1024),
            expires_at: None,
        },
        PanelRiskControlState::Restricted,
    );

    core.record_panel_state(restricted_panel.clone());
    let start_error = core
        .start_from_subscription_config_text(
            ss_config(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                ..ManagedMixedOptions::default()
            },
        )
        .expect_err("restricted panel should block start");
    assert!(start_error.contains("PanelTrafficRestricted"));
    assert!(!core.is_running());
    assert_eq!(core.status().panel_state, Some(restricted_panel.clone()));

    core.clear_panel_state();
    core.start_from_subscription_config_text(
        ss_config(),
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-READY".to_string()),
            ..ManagedMixedOptions::default()
        },
    )
    .expect("start managed mixed controller");
    core.record_panel_state(restricted_panel);

    let reload_error = core
        .reload_from_subscription_config_text(ss_config(), Some("SS-READY".to_string()))
        .expect_err("restricted panel should block reload");
    assert!(reload_error.contains("PanelTrafficRestricted"));
    let status = core.status();
    assert_eq!(
        status.last_error,
        Some(ClientErrorKind::PanelTrafficRestricted {
            account_state: "limited".to_string(),
            risk_control: "restricted".to_string()
        })
    );
    assert!(matches!(status.status, RuntimeStatus::Running { .. }));
    assert!(status
        .recent_events
        .iter()
        .any(|event| { event.note.as_deref() == Some("panel traffic restricted") }));

    let probe_error = core
        .probe_node_health(ManagedNodeProbeOptions {
            outbound_tag: "SS-READY".to_string(),
            target: "127.0.0.1:1".to_string(),
            payload: Vec::new(),
            expect: Vec::new(),
            inbound: SmokeInboundKind::Socks5,
            first_byte_timeout: Duration::from_millis(20),
            udp_available: None,
            udp_probe: None,
        })
        .expect_err("restricted panel should block probe");
    assert!(probe_error.contains("PanelTrafficRestricted"));
    assert!(core
        .probe_all_node_health(ManagedNodeProbeSweepOptions {
            target: "127.0.0.1:1".to_string(),
            payload: Vec::new(),
            expect: Vec::new(),
            inbound: SmokeInboundKind::Socks5,
            first_byte_timeout: Duration::from_millis(20),
            udp_available: None,
            udp_probe: None,
        })
        .expect_err("restricted panel should block probe all")
        .contains("PanelTrafficRestricted"));
    assert!(core
        .probe_all_node_health_and_apply_recommended(ManagedNodeProbeSweepOptions {
            target: "127.0.0.1:1".to_string(),
            payload: Vec::new(),
            expect: Vec::new(),
            inbound: SmokeInboundKind::Socks5,
            first_byte_timeout: Duration::from_millis(20),
            udp_available: None,
            udp_probe: None,
        })
        .expect_err("restricted panel should block probe all and apply")
        .contains("PanelTrafficRestricted"));
    assert!(core
        .apply_recommended_outbound()
        .expect_err("restricted panel should block apply recommended")
        .contains("PanelTrafficRestricted"));

    core.clear_panel_state();
    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_rejects_reload_and_stop_before_start() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);

    let reload_error = core
        .reload_from_subscription_config_text(ss_config(), Some("SS-READY".to_string()))
        .expect_err("reload should require running core");
    let stop_error = core.stop().expect_err("stop should require running core");

    assert!(reload_error.contains("not running"));
    assert!(stop_error.contains("not running"));
    assert_eq!(core.status().status, RuntimeStatus::Stopped);
}

#[test]
fn managed_mixed_controller_status_reports_reload_failure_detail() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    core.start_from_subscription_config_text(
        ss_config(),
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-READY".to_string()),
            ..ManagedMixedOptions::default()
        },
    )
    .expect("start managed mixed controller");

    let error = core
        .reload_from_subscription_config_text(ss_config(), Some("MISSING".to_string()))
        .expect_err("reload should reject unknown outbound");
    let status = core.status();

    assert!(error.contains("OutboundNotFound"));
    assert_eq!(status.selected_outbound.as_deref(), Some("SS-READY"));
    assert_eq!(status.generation, 1);
    assert_eq!(
        status.last_error,
        Some(keli_client_core::ClientErrorKind::OutboundNotFound(
            "MISSING".to_string()
        ))
    );
    assert!(status
        .recent_events
        .iter()
        .any(|event| matches!(event.status, RuntimeStatus::Failed(_))));

    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_status_reports_redacted_node_capabilities() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);

    let started = core
        .start_from_subscription_config_text(
            mixed_subscription_with_capability_variants(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");
    let subscription = started.subscription.as_ref().expect("subscription status");

    assert_eq!(subscription.supported_count(), 2);
    assert_eq!(
        subscription.supported_tags,
        vec!["SS-READY".to_string(), "VLESS-EDGE".to_string()]
    );
    let ss = subscription
        .capability_for("SS-READY")
        .expect("SS-READY capability");
    assert_eq!(ss.protocol, "Shadowsocks");
    assert_eq!(ss.transport, "tcp");
    assert_eq!(ss.security, "none");
    assert_eq!(ss.tls_skip_verify, None);
    assert!(ss.udp_supported);

    let vless = subscription
        .capability_for("VLESS-EDGE")
        .expect("VLESS-EDGE capability");
    assert_eq!(vless.protocol, "Vless");
    assert_eq!(vless.transport, "ws");
    assert_eq!(vless.security, "tls");
    assert_eq!(vless.tls_skip_verify, Some(true));
    assert!(vless.udp_supported);
    assert!(subscription.capability_for("WG-SKIPPED").is_none());

    let debug = format!("{subscription:?}");
    assert!(!debug.contains("secret"));
    assert!(!debug.contains("00112233-4455-6677-8899-aabbccddeeff"));
    assert!(!debug.contains("ss.example.com"));
    assert!(!debug.contains("vless.example.com"));
    assert!(!debug.contains("wg.example.com"));
    assert!(!debug.contains("private-sni.example.com"));
    assert!(!debug.contains("private-host.example.com"));
    assert!(!debug.contains("/private-vless-path"));

    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_status_reports_subscription_nodes() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);

    let started = core
        .start_from_subscription_config_text(
            mixed_subscription_with_skipped_proxy(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-NEXT".to_string()),
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");
    let subscription = started.subscription.as_ref().expect("subscription status");

    assert!(subscription.usable);
    assert_eq!(subscription.supported_count(), 2);
    assert_eq!(subscription.skipped_count(), 1);
    assert_eq!(
        subscription.supported_tags,
        vec!["SS-READY".to_string(), "SS-NEXT".to_string()]
    );
    assert_eq!(subscription.default_outbound.as_deref(), Some("SS-READY"));
    assert_eq!(subscription.selected_outbound, "SS-NEXT");
    assert_eq!(subscription.recommended_outbound, "SS-NEXT");
    assert_eq!(subscription.health_summary.node_count, 2);
    assert_eq!(subscription.health_summary.healthy_count, 0);
    assert_eq!(subscription.health_summary.unhealthy_count, 0);
    assert_eq!(subscription.health_summary.unknown_count, 2);
    assert_eq!(subscription.health_summary.checked_count, 0);
    assert_eq!(subscription.health_summary.unchecked_count, 2);
    assert_eq!(subscription.health_summary.last_checked_at, None);
    assert_eq!(
        subscription.health_summary.selected_state,
        Some(ManagedNodeHealthState::Unknown)
    );
    assert_eq!(
        subscription.health_summary.recommended_state,
        Some(ManagedNodeHealthState::Unknown)
    );
    assert!(subscription.health_summary.recommended_is_selected);
    assert!(!subscription.health_summary.switch_recommended);
    assert!(!subscription.health_summary.selected_outbound_healthy);
    assert!(!subscription.health_summary.recommended_outbound_healthy);
    assert!(!subscription.health_summary.recommended_switch_ready);
    assert_eq!(
        subscription.health_summary.recommended_switch_reason,
        ManagedRecommendedSwitchReason::NoReadyAlternative
    );
    assert!(!subscription.health_summary.fully_checked);
    assert_eq!(subscription.skipped[0].name, "WG-SKIPPED");
    assert_eq!(
        subscription.skipped[0].reason,
        "unsupported protocol: wireguard"
    );

    let reloaded = core
        .reload_from_subscription_config_text(ss_config(), Some("SS-READY".to_string()))
        .expect("reload managed mixed controller");
    let subscription = reloaded
        .subscription
        .as_ref()
        .expect("reloaded subscription status");

    assert_eq!(subscription.supported_count(), 1);
    assert_eq!(subscription.skipped_count(), 0);
    assert_eq!(subscription.selected_outbound, "SS-READY");
    assert_eq!(subscription.default_outbound.as_deref(), Some("SS-READY"));
    assert_eq!(subscription.recommended_outbound, "SS-READY");
    assert_eq!(subscription.health_summary.node_count, 1);
    assert_eq!(subscription.health_summary.unknown_count, 1);
    assert_eq!(subscription.health_summary.checked_count, 0);
    assert_eq!(subscription.health_summary.unchecked_count, 1);
    assert_eq!(
        subscription.health_summary.selected_state,
        Some(ManagedNodeHealthState::Unknown)
    );
    assert_eq!(
        subscription.health_summary.recommended_state,
        Some(ManagedNodeHealthState::Unknown)
    );
    assert!(subscription.health_summary.recommended_is_selected);
    assert!(!subscription.health_summary.switch_recommended);
    assert!(!subscription.health_summary.selected_outbound_healthy);
    assert!(!subscription.health_summary.recommended_outbound_healthy);
    assert!(!subscription.health_summary.recommended_switch_ready);
    assert_eq!(
        subscription.health_summary.recommended_switch_reason,
        ManagedRecommendedSwitchReason::NoReadyAlternative
    );
    assert!(!subscription.health_summary.fully_checked);

    core.stop().expect("stop managed mixed controller");
    assert!(core.status().subscription.is_none());
}

#[test]
fn managed_mixed_controller_records_node_health_and_prunes_on_reload() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);

    let started = core
        .start_from_subscription_config_text(
            mixed_subscription_with_skipped_proxy(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");
    let subscription = started.subscription.as_ref().expect("subscription status");

    let ready = subscription
        .health_for("SS-READY")
        .expect("SS-READY health");
    let next = subscription.health_for("SS-NEXT").expect("SS-NEXT health");
    assert_eq!(ready.state, ManagedNodeHealthState::Unknown);
    assert_eq!(ready.checked_at, None);
    assert_eq!(next.state, ManagedNodeHealthState::Unknown);
    assert_eq!(next.checked_at, None);
    assert_eq!(subscription.health_summary.node_count, 2);
    assert_eq!(subscription.health_summary.unknown_count, 2);
    assert_eq!(subscription.health_summary.checked_count, 0);
    assert_eq!(subscription.health_summary.unchecked_count, 2);
    assert_eq!(subscription.health_summary.udp_available_count, 0);
    assert_eq!(subscription.health_summary.udp_unavailable_count, 0);
    assert_eq!(subscription.health_summary.udp_unknown_count, 2);
    assert_eq!(
        subscription.health_summary.selected_state,
        Some(ManagedNodeHealthState::Unknown)
    );
    assert_eq!(subscription.health_summary.selected_udp_available, None);
    assert_eq!(subscription.health_summary.recommended_udp_available, None);
    assert!(!subscription.health_summary.selected_outbound_healthy);
    assert!(!subscription.health_summary.recommended_outbound_healthy);
    assert!(!subscription.health_summary.recommended_switch_ready);
    assert_eq!(
        subscription.health_summary.recommended_switch_reason,
        ManagedRecommendedSwitchReason::NoReadyAlternative
    );
    assert!(!subscription.health_summary.fully_checked);

    core.record_node_health(ManagedNodeHealthStatus::healthy(
        "SS-READY",
        Some(42),
        true,
        true,
    ))
    .expect("record healthy node");
    let status = core
        .record_node_health(ManagedNodeHealthStatus::unhealthy(
            "SS-NEXT",
            ConnectionErrorKind::TcpConnectTimeout,
            Some("timeout to example target".to_string()),
        ))
        .expect("record unhealthy node");
    let subscription = status.subscription.as_ref().expect("subscription status");
    let ready = subscription
        .health_for("SS-READY")
        .expect("SS-READY health");
    let next = subscription.health_for("SS-NEXT").expect("SS-NEXT health");

    assert_eq!(ready.state, ManagedNodeHealthState::Healthy);
    assert_eq!(ready.latency_ms, Some(42));
    assert_eq!(ready.tcp_available, Some(true));
    assert_eq!(ready.udp_available, Some(true));
    assert!(ready.checked_at.is_some());
    assert_eq!(next.state, ManagedNodeHealthState::Unhealthy);
    assert!(next.checked_at.is_some());
    assert_eq!(subscription.recommended_outbound, "SS-READY");
    assert_eq!(subscription.health_summary.healthy_count, 1);
    assert_eq!(subscription.health_summary.unhealthy_count, 1);
    assert_eq!(subscription.health_summary.unknown_count, 0);
    assert_eq!(subscription.health_summary.checked_count, 2);
    assert_eq!(subscription.health_summary.unchecked_count, 0);
    assert_eq!(subscription.health_summary.udp_available_count, 1);
    assert_eq!(subscription.health_summary.udp_unavailable_count, 1);
    assert_eq!(subscription.health_summary.udp_unknown_count, 0);
    assert!(subscription.health_summary.last_checked_at.is_some());
    assert_eq!(
        subscription.health_summary.selected_state,
        Some(ManagedNodeHealthState::Healthy)
    );
    assert_eq!(
        subscription.health_summary.recommended_state,
        Some(ManagedNodeHealthState::Healthy)
    );
    assert_eq!(
        subscription.health_summary.selected_udp_available,
        Some(true)
    );
    assert_eq!(
        subscription.health_summary.recommended_udp_available,
        Some(true)
    );
    assert!(subscription.health_summary.recommended_is_selected);
    assert!(!subscription.health_summary.switch_recommended);
    assert!(subscription.health_summary.selected_outbound_healthy);
    assert!(subscription.health_summary.recommended_outbound_healthy);
    assert!(!subscription.health_summary.recommended_switch_ready);
    assert_eq!(
        subscription.health_summary.recommended_switch_reason,
        ManagedRecommendedSwitchReason::AlreadySelected
    );
    assert!(subscription.health_summary.fully_checked);
    assert_eq!(
        next.error_kind,
        Some(ConnectionErrorKind::TcpConnectTimeout)
    );
    assert_eq!(
        next.error_detail.as_deref(),
        Some("timeout to example target")
    );
    assert_eq!(
        status
            .recent_events
            .first()
            .and_then(|event| event.note.as_deref()),
        Some("node health recorded: SS-NEXT=unhealthy")
    );

    let unsupported = core
        .record_node_health(ManagedNodeHealthStatus::healthy(
            "WG-SKIPPED",
            Some(1),
            true,
            false,
        ))
        .expect_err("skipped node should not accept health");
    assert!(unsupported.contains("not in active subscription"));

    let reloaded = core
        .reload_from_subscription_config_text(ss_config(), Some("SS-READY".to_string()))
        .expect("reload managed mixed controller");
    let subscription = reloaded
        .subscription
        .as_ref()
        .expect("subscription after reload");

    assert_eq!(subscription.supported_tags, vec!["SS-READY".to_string()]);
    assert!(subscription.health_for("SS-NEXT").is_none());
    assert_eq!(
        subscription
            .health_for("SS-READY")
            .expect("SS-READY health")
            .state,
        ManagedNodeHealthState::Healthy
    );
    assert_eq!(subscription.recommended_outbound, "SS-READY");
    assert_eq!(subscription.health_summary.udp_available_count, 1);
    assert_eq!(subscription.health_summary.udp_unavailable_count, 0);
    assert_eq!(subscription.health_summary.udp_unknown_count, 0);
    assert_eq!(
        subscription.health_summary.selected_state,
        Some(ManagedNodeHealthState::Healthy)
    );
    assert_eq!(
        subscription.health_summary.recommended_state,
        Some(ManagedNodeHealthState::Healthy)
    );
    assert!(subscription.health_summary.fully_checked);

    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_recommends_fastest_healthy_node() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);

    let started = core
        .start_from_subscription_config_text(
            mixed_subscription_with_skipped_proxy(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");
    let subscription = started.subscription.as_ref().expect("subscription status");

    assert_eq!(subscription.selected_outbound, "SS-READY");
    assert_eq!(subscription.recommended_outbound, "SS-READY");

    core.record_node_health(ManagedNodeHealthStatus::healthy(
        "SS-READY",
        Some(120),
        true,
        true,
    ))
    .expect("record selected health");
    let status = core
        .record_node_health(ManagedNodeHealthStatus::healthy(
            "SS-NEXT",
            Some(30),
            true,
            true,
        ))
        .expect("record faster health");
    let subscription = status.subscription.as_ref().expect("subscription status");

    assert_eq!(subscription.selected_outbound, "SS-READY");
    assert_eq!(subscription.recommended_outbound, "SS-NEXT");
    assert_eq!(subscription.health_summary.healthy_count, 2);
    assert_eq!(subscription.health_summary.unhealthy_count, 0);
    assert_eq!(subscription.health_summary.checked_count, 2);
    assert_eq!(
        subscription.health_summary.selected_state,
        Some(ManagedNodeHealthState::Healthy)
    );
    assert_eq!(
        subscription.health_summary.recommended_state,
        Some(ManagedNodeHealthState::Healthy)
    );
    assert!(!subscription.health_summary.recommended_is_selected);
    assert!(subscription.health_summary.switch_recommended);
    assert!(subscription.health_summary.selected_outbound_healthy);
    assert!(subscription.health_summary.recommended_outbound_healthy);
    assert!(subscription.health_summary.recommended_switch_ready);
    assert_eq!(
        subscription.health_summary.recommended_switch_reason,
        ManagedRecommendedSwitchReason::Ready
    );
    assert!(subscription.health_summary.fully_checked);

    let status = core
        .record_node_health(ManagedNodeHealthStatus::unhealthy(
            "SS-NEXT",
            ConnectionErrorKind::RelayIo,
            Some("relay failed".to_string()),
        ))
        .expect("record faster node failure");
    let subscription = status.subscription.as_ref().expect("subscription status");

    assert_eq!(subscription.recommended_outbound, "SS-READY");
    assert_eq!(subscription.health_summary.healthy_count, 1);
    assert_eq!(subscription.health_summary.unhealthy_count, 1);
    assert_eq!(
        subscription.health_summary.selected_state,
        Some(ManagedNodeHealthState::Healthy)
    );
    assert_eq!(
        subscription.health_summary.recommended_state,
        Some(ManagedNodeHealthState::Healthy)
    );
    assert!(subscription.health_summary.recommended_is_selected);
    assert!(!subscription.health_summary.switch_recommended);
    assert!(subscription.health_summary.selected_outbound_healthy);
    assert!(subscription.health_summary.recommended_outbound_healthy);
    assert!(!subscription.health_summary.recommended_switch_ready);
    assert_eq!(
        subscription.health_summary.recommended_switch_reason,
        ManagedRecommendedSwitchReason::AlreadySelected
    );
    assert!(subscription.health_summary.fully_checked);

    let status = core
        .record_node_health(ManagedNodeHealthStatus::unhealthy(
            "SS-READY",
            ConnectionErrorKind::FirstByteTimeout,
            Some("selected node timeout".to_string()),
        ))
        .expect("record selected node failure");
    let subscription = status.subscription.as_ref().expect("subscription status");

    assert_eq!(subscription.recommended_outbound, "SS-READY");
    assert_eq!(subscription.health_summary.healthy_count, 0);
    assert_eq!(subscription.health_summary.unhealthy_count, 2);
    assert_eq!(
        subscription.health_summary.selected_state,
        Some(ManagedNodeHealthState::Unhealthy)
    );
    assert_eq!(
        subscription.health_summary.recommended_state,
        Some(ManagedNodeHealthState::Unhealthy)
    );
    assert!(subscription.health_summary.recommended_is_selected);
    assert!(!subscription.health_summary.switch_recommended);
    assert!(!subscription.health_summary.selected_outbound_healthy);
    assert!(!subscription.health_summary.recommended_outbound_healthy);
    assert!(!subscription.health_summary.recommended_switch_ready);
    assert_eq!(
        subscription.health_summary.recommended_switch_reason,
        ManagedRecommendedSwitchReason::NoReadyAlternative
    );
    assert!(subscription.health_summary.fully_checked);

    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_prefers_udp_available_recommendation() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);

    core.start_from_subscription_config_text(
        mixed_subscription_with_skipped_proxy(),
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-READY".to_string()),
            ..ManagedMixedOptions::default()
        },
    )
    .expect("start managed mixed controller");

    core.record_node_health(ManagedNodeHealthStatus::healthy(
        "SS-READY",
        Some(20),
        true,
        false,
    ))
    .expect("record selected TCP-only health");
    let status = core
        .record_node_health(ManagedNodeHealthStatus::healthy(
            "SS-NEXT",
            Some(200),
            true,
            true,
        ))
        .expect("record UDP-capable health");
    let subscription = status.subscription.as_ref().expect("subscription status");

    assert_eq!(subscription.selected_outbound, "SS-READY");
    assert_eq!(subscription.recommended_outbound, "SS-NEXT");
    assert_eq!(subscription.health_summary.udp_available_count, 1);
    assert_eq!(subscription.health_summary.udp_unavailable_count, 1);
    assert_eq!(subscription.health_summary.udp_unknown_count, 0);
    assert_eq!(
        subscription.health_summary.selected_udp_available,
        Some(false)
    );
    assert_eq!(
        subscription.health_summary.recommended_udp_available,
        Some(true)
    );
    assert!(!subscription.health_summary.recommended_is_selected);
    assert!(subscription.health_summary.recommended_switch_ready);
    assert_eq!(
        subscription.health_summary.recommended_switch_reason,
        ManagedRecommendedSwitchReason::Ready
    );

    let json = managed_mixed_status_json_value(&status);
    assert_eq!(
        json["subscription"]["health_summary"]["selected_udp_available"],
        false
    );
    assert_eq!(
        json["subscription"]["health_summary"]["recommended_udp_available"],
        true
    );

    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_applies_recommended_outbound() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);

    let started = core
        .start_from_subscription_config_text(
            mixed_subscription_with_skipped_proxy(),
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-READY".to_string()),
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");
    let initial_generation = started.generation;

    core.record_node_health(ManagedNodeHealthStatus::healthy(
        "SS-READY",
        Some(120),
        true,
        true,
    ))
    .expect("record selected health");
    let status = core
        .record_node_health(ManagedNodeHealthStatus::healthy(
            "SS-NEXT",
            Some(25),
            true,
            true,
        ))
        .expect("record recommended health");
    let subscription = status.subscription.as_ref().expect("subscription status");

    assert_eq!(subscription.selected_outbound, "SS-READY");
    assert_eq!(subscription.recommended_outbound, "SS-NEXT");
    assert!(!subscription.health_summary.recommended_is_selected);
    assert!(subscription.health_summary.switch_recommended);
    assert!(subscription.health_summary.recommended_switch_ready);
    assert_eq!(
        subscription.health_summary.recommended_switch_reason,
        ManagedRecommendedSwitchReason::Ready
    );
    assert!(subscription.health_summary.fully_checked);

    let switched = core
        .apply_recommended_outbound()
        .expect("apply recommended outbound");
    let subscription = switched.subscription.as_ref().expect("subscription status");

    assert_eq!(switched.selected_outbound.as_deref(), Some("SS-NEXT"));
    assert_eq!(switched.generation, initial_generation + 1);
    assert_eq!(subscription.selected_outbound, "SS-NEXT");
    assert_eq!(subscription.recommended_outbound, "SS-NEXT");
    assert!(switched.recent_events.iter().any(|event| {
        event.note.as_deref()
            == Some(
                "recommended outbound switch applying: reason=ready selected=SS-READY recommended=SS-NEXT",
            )
    }));
    assert!(subscription.health_summary.recommended_is_selected);
    assert_eq!(
        subscription.health_summary.selected_state,
        Some(ManagedNodeHealthState::Healthy)
    );
    assert_eq!(
        subscription.health_summary.recommended_state,
        Some(ManagedNodeHealthState::Healthy)
    );
    assert!(!subscription.health_summary.switch_recommended);
    assert!(subscription.health_summary.selected_outbound_healthy);
    assert!(subscription.health_summary.recommended_outbound_healthy);
    assert!(!subscription.health_summary.recommended_switch_ready);
    assert_eq!(
        subscription.health_summary.recommended_switch_reason,
        ManagedRecommendedSwitchReason::AlreadySelected
    );
    assert!(subscription.health_summary.fully_checked);
    assert_eq!(
        subscription
            .health_for("SS-READY")
            .expect("SS-READY health")
            .latency_ms,
        Some(120)
    );
    assert_eq!(
        subscription
            .health_for("SS-NEXT")
            .expect("SS-NEXT health")
            .latency_ms,
        Some(25)
    );

    let no_op = core
        .apply_recommended_outbound()
        .expect("recommended outbound already selected");

    assert_eq!(no_op.selected_outbound.as_deref(), Some("SS-NEXT"));
    assert_eq!(no_op.generation, switched.generation);
    assert!(no_op.recent_events.iter().any(|event| {
        event.note.as_deref()
            == Some(
                "recommended outbound switch skipped: reason=already-selected selected=SS-NEXT recommended=SS-NEXT",
            )
    }));

    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_probe_all_node_health_records_each_supported_node() {
    let (ready_port, ss_thread) = spawn_shadowsocks_tcp_echo_server();
    let closed_port = unused_tcp_port();
    let config = mixed_subscription_for_ports(ready_port, closed_port);
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    core.start_from_subscription_config_text(
        &config,
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-NEXT".to_string()),
            ..ManagedMixedOptions::default()
        },
    )
    .expect("start managed mixed controller");

    let status = core
        .probe_all_node_health(ManagedNodeProbeSweepOptions {
            target: "example.com:443".to_string(),
            payload: b"ping".to_vec(),
            expect: b"pong".to_vec(),
            inbound: SmokeInboundKind::HttpConnect,
            first_byte_timeout: Duration::from_secs(2),
            udp_available: None,
            udp_probe: None,
        })
        .expect("probe all node health");
    let subscription = status.subscription.as_ref().expect("subscription status");
    let ready = subscription
        .health_for("SS-READY")
        .expect("SS-READY health");
    let next = subscription.health_for("SS-NEXT").expect("SS-NEXT health");

    assert_eq!(subscription.selected_outbound, "SS-NEXT");
    assert_eq!(subscription.recommended_outbound, "SS-READY");
    assert_eq!(ready.state, ManagedNodeHealthState::Healthy);
    assert_eq!(ready.tcp_available, Some(true));
    assert!(ready.latency_ms.is_some());
    assert!(ready.checked_at.is_some());
    assert_eq!(next.state, ManagedNodeHealthState::Unhealthy);
    assert_eq!(next.tcp_available, Some(false));
    assert!(next.checked_at.is_some());
    assert_eq!(subscription.health_summary.healthy_count, 1);
    assert_eq!(subscription.health_summary.unhealthy_count, 1);
    assert_eq!(subscription.health_summary.unknown_count, 0);
    assert_eq!(subscription.health_summary.checked_count, 2);
    assert!(subscription.health_summary.last_checked_at.is_some());
    let sweep_diagnostic = status
        .recent_events
        .iter()
        .rev()
        .find_map(|event| {
            if let Some(RuntimeDiagnostic::ManagedNodeProbeSweep(diagnostic)) = &event.diagnostic {
                Some(diagnostic)
            } else {
                None
            }
        })
        .expect("node probe sweep diagnostic");
    assert_eq!(sweep_diagnostic.target, "example.com:443");
    assert_eq!(sweep_diagnostic.inbound, "mixed-http-connect-smoke");
    assert_eq!(sweep_diagnostic.attempted_nodes, 2);
    assert_eq!(sweep_diagnostic.successful_probes, 1);
    assert_eq!(sweep_diagnostic.failed_probes, 1);
    assert_eq!(sweep_diagnostic.node_count, 2);
    assert_eq!(sweep_diagnostic.healthy_count, 1);
    assert_eq!(sweep_diagnostic.unhealthy_count, 1);
    assert_eq!(sweep_diagnostic.unknown_count, 0);
    assert_eq!(sweep_diagnostic.checked_count, 2);
    assert_eq!(sweep_diagnostic.unchecked_count, 0);
    assert_eq!(sweep_diagnostic.selected_outbound, "SS-NEXT");
    assert_eq!(sweep_diagnostic.recommended_outbound, "SS-READY");
    assert!(sweep_diagnostic.recommended_switch_ready);
    assert_eq!(sweep_diagnostic.recommended_switch_reason, "ready");
    assert!(status.recent_events.iter().any(|event| {
        event.note.as_deref().is_some_and(|note| {
            note.contains("node health sweep completed")
                && note.contains("attempted=2")
                && note.contains("failure=1")
        })
    }));
    let status_json = managed_mixed_status_json_value(&status);
    let json_diagnostic = status_json["recent_events"]
        .as_array()
        .expect("recent events")
        .iter()
        .find_map(|event| {
            let diagnostic = &event["diagnostic"];
            (diagnostic["kind"] == "managed-node-probe-sweep").then_some(diagnostic)
        })
        .expect("node probe sweep JSON diagnostic");
    assert_eq!(json_diagnostic["attempted_nodes"], 2);
    assert_eq!(json_diagnostic["successful_probes"], 1);
    assert_eq!(json_diagnostic["failed_probes"], 1);
    assert_eq!(json_diagnostic["recommended_switch_ready"], true);
    assert_eq!(json_diagnostic["recommended_switch_reason"], "ready");
    assert!(!subscription.health_summary.recommended_is_selected);
    assert!(!subscription.health_summary.selected_outbound_healthy);
    assert!(subscription.health_summary.recommended_outbound_healthy);
    assert!(subscription.health_summary.recommended_switch_ready);
    assert_eq!(
        subscription.health_summary.recommended_switch_reason,
        ManagedRecommendedSwitchReason::Ready
    );
    assert!(next.error_kind.is_some());
    assert!(next.error_detail.is_some());

    ss_thread.join().expect("ss tcp echo server");
    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_probe_all_node_health_can_apply_recommended_outbound() {
    let (ready_port, ss_thread) = spawn_shadowsocks_tcp_echo_server();
    let closed_port = unused_tcp_port();
    let config = mixed_subscription_for_ports(ready_port, closed_port);
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    let started = core
        .start_from_subscription_config_text(
            &config,
            ManagedMixedOptions {
                listen: "127.0.0.1:0".to_string(),
                outbound_tag: Some("SS-NEXT".to_string()),
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");

    let switched = core
        .probe_all_node_health_and_apply_recommended(ManagedNodeProbeSweepOptions {
            target: "example.com:443".to_string(),
            payload: b"ping".to_vec(),
            expect: b"pong".to_vec(),
            inbound: SmokeInboundKind::HttpConnect,
            first_byte_timeout: Duration::from_secs(2),
            udp_available: None,
            udp_probe: None,
        })
        .expect("probe all node health and apply recommendation");
    let subscription = switched.subscription.as_ref().expect("subscription status");
    let ready = subscription
        .health_for("SS-READY")
        .expect("SS-READY health");
    let next = subscription.health_for("SS-NEXT").expect("SS-NEXT health");

    assert_eq!(switched.selected_outbound.as_deref(), Some("SS-READY"));
    assert_eq!(switched.generation, started.generation + 1);
    assert_eq!(subscription.selected_outbound, "SS-READY");
    assert_eq!(subscription.recommended_outbound, "SS-READY");
    assert_eq!(ready.state, ManagedNodeHealthState::Healthy);
    assert!(ready.checked_at.is_some());
    assert_eq!(next.state, ManagedNodeHealthState::Unhealthy);
    assert!(next.checked_at.is_some());
    assert_eq!(subscription.health_summary.healthy_count, 1);
    assert_eq!(subscription.health_summary.unhealthy_count, 1);
    assert_eq!(subscription.health_summary.checked_count, 2);
    assert!(subscription.health_summary.recommended_is_selected);
    assert!(subscription.health_summary.selected_outbound_healthy);
    assert!(subscription.health_summary.recommended_outbound_healthy);
    assert!(!subscription.health_summary.recommended_switch_ready);
    assert_eq!(
        subscription.health_summary.recommended_switch_reason,
        ManagedRecommendedSwitchReason::AlreadySelected
    );

    ss_thread.join().expect("ss tcp echo server");
    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_probe_node_health_records_success() {
    let (ss_port, ss_thread) = spawn_shadowsocks_tcp_echo_server();
    let config = ss_config_for_port(ss_port);
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    core.start_from_subscription_config_text(
        &config,
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-READY".to_string()),
            ..ManagedMixedOptions::default()
        },
    )
    .expect("start managed mixed controller");

    let status = core
        .probe_node_health(ManagedNodeProbeOptions {
            outbound_tag: "SS-READY".to_string(),
            target: "example.com:443".to_string(),
            payload: b"ping".to_vec(),
            expect: b"pong".to_vec(),
            inbound: SmokeInboundKind::HttpConnect,
            first_byte_timeout: Duration::from_secs(2),
            udp_available: None,
            udp_probe: None,
        })
        .expect("probe node health");
    let health = status
        .subscription
        .as_ref()
        .expect("subscription status")
        .health_for("SS-READY")
        .expect("SS-READY health");

    assert_eq!(health.state, ManagedNodeHealthState::Healthy);
    assert_eq!(health.tcp_available, Some(true));
    assert_eq!(health.udp_available, None);
    assert!(health.latency_ms.is_some());
    assert_eq!(health.error_kind, None);
    assert_eq!(health.error_detail, None);
    assert!(health.checked_at.is_some());
    assert_eq!(
        status
            .recent_events
            .first()
            .and_then(|event| event.note.as_deref()),
        Some("node health recorded: SS-READY=healthy")
    );

    ss_thread.join().expect("ss tcp echo server");
    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_probe_node_health_records_udp_probe_success() {
    let (ss_port, tcp_thread, udp_thread) = spawn_shadowsocks_tcp_udp_echo_server();
    let config = ss_config_for_port(ss_port);
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    core.start_from_subscription_config_text(
        &config,
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-READY".to_string()),
            ..ManagedMixedOptions::default()
        },
    )
    .expect("start managed mixed controller");

    let status = core
        .probe_node_health(ManagedNodeProbeOptions {
            outbound_tag: "SS-READY".to_string(),
            target: "example.com:443".to_string(),
            payload: b"ping".to_vec(),
            expect: b"pong".to_vec(),
            inbound: SmokeInboundKind::HttpConnect,
            first_byte_timeout: Duration::from_secs(2),
            udp_available: None,
            udp_probe: Some(ManagedNodeUdpProbeOptions {
                target: "example.com:53".to_string(),
                payload: b"ping".to_vec(),
                expect: b"pong".to_vec(),
            }),
        })
        .expect("probe node health with UDP");
    let health = status
        .subscription
        .as_ref()
        .expect("subscription status")
        .health_for("SS-READY")
        .expect("SS-READY health");

    assert_eq!(health.state, ManagedNodeHealthState::Healthy);
    assert_eq!(health.tcp_available, Some(true));
    assert_eq!(health.udp_available, Some(true));
    assert_eq!(health.error_kind, None);
    assert_eq!(health.error_detail, None);

    tcp_thread.join().expect("ss tcp echo server");
    udp_thread.join().expect("ss udp echo server");
    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_probe_node_health_records_udp_probe_failure_without_failing_tcp() {
    let (ss_port, ss_thread) = spawn_shadowsocks_tcp_echo_server();
    let config = ss_config_for_port(ss_port);
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    core.start_from_subscription_config_text(
        &config,
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-READY".to_string()),
            ..ManagedMixedOptions::default()
        },
    )
    .expect("start managed mixed controller");

    let status = core
        .probe_node_health(ManagedNodeProbeOptions {
            outbound_tag: "SS-READY".to_string(),
            target: "example.com:443".to_string(),
            payload: b"ping".to_vec(),
            expect: b"pong".to_vec(),
            inbound: SmokeInboundKind::HttpConnect,
            first_byte_timeout: Duration::from_millis(50),
            udp_available: None,
            udp_probe: Some(ManagedNodeUdpProbeOptions {
                target: "example.com:53".to_string(),
                payload: b"ping".to_vec(),
                expect: b"pong".to_vec(),
            }),
        })
        .expect("TCP health should survive UDP failure");
    let health = status
        .subscription
        .as_ref()
        .expect("subscription status")
        .health_for("SS-READY")
        .expect("SS-READY health");

    assert_eq!(health.state, ManagedNodeHealthState::Healthy);
    assert_eq!(health.tcp_available, Some(true));
    assert_eq!(health.udp_available, Some(false));
    assert_eq!(health.error_kind, None);
    assert_eq!(health.error_detail, None);

    ss_thread.join().expect("ss tcp echo server");
    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_probe_node_health_records_failure() {
    let (ss_port, ss_thread) = spawn_shadowsocks_tcp_echo_server();
    let config = ss_config_for_port(ss_port);
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    core.start_from_subscription_config_text(
        &config,
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-READY".to_string()),
            ..ManagedMixedOptions::default()
        },
    )
    .expect("start managed mixed controller");

    let error = core
        .probe_node_health(ManagedNodeProbeOptions {
            outbound_tag: "SS-READY".to_string(),
            target: "example.com:443".to_string(),
            payload: b"ping".to_vec(),
            expect: b"nope".to_vec(),
            inbound: SmokeInboundKind::HttpConnect,
            first_byte_timeout: Duration::from_secs(2),
            udp_available: Some(false),
            udp_probe: None,
        })
        .expect_err("probe should fail on mismatched response");
    let status = core.status();
    let health = status
        .subscription
        .as_ref()
        .expect("subscription status")
        .health_for("SS-READY")
        .expect("SS-READY health");

    assert!(error.contains("smoke response mismatch"));
    assert_eq!(health.state, ManagedNodeHealthState::Unhealthy);
    assert_eq!(health.tcp_available, Some(false));
    assert_eq!(health.udp_available, None);
    assert_eq!(health.latency_ms, None);
    assert_eq!(health.error_kind, Some(ConnectionErrorKind::ProtocolError));
    assert!(health.checked_at.is_some());
    assert!(health
        .error_detail
        .as_deref()
        .is_some_and(|detail| detail.contains("smoke response mismatch")));
    assert_eq!(
        status
            .recent_events
            .first()
            .and_then(|event| event.note.as_deref()),
        Some("node health recorded: SS-READY=unhealthy")
    );

    ss_thread.join().expect("ss tcp echo server");
    core.stop().expect("stop managed mixed controller");
}

#[test]
fn managed_mixed_controller_rejects_node_health_before_start() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);

    let error = core
        .record_node_health(ManagedNodeHealthStatus::healthy(
            "SS-READY",
            Some(10),
            true,
            true,
        ))
        .expect_err("recording health should require running core");

    assert!(error.contains("not running"));

    let probe_error = core
        .probe_node_health(ManagedNodeProbeOptions {
            outbound_tag: "SS-READY".to_string(),
            target: "example.com:443".to_string(),
            payload: b"ping".to_vec(),
            expect: b"pong".to_vec(),
            inbound: SmokeInboundKind::HttpConnect,
            first_byte_timeout: Duration::from_secs(1),
            udp_available: None,
            udp_probe: None,
        })
        .expect_err("probing health should require running core");

    assert!(probe_error.contains("not running"));

    let probe_all_error = core
        .probe_all_node_health(ManagedNodeProbeSweepOptions {
            target: "example.com:443".to_string(),
            payload: b"ping".to_vec(),
            expect: b"pong".to_vec(),
            inbound: SmokeInboundKind::HttpConnect,
            first_byte_timeout: Duration::from_secs(1),
            udp_available: None,
            udp_probe: None,
        })
        .expect_err("probing all health should require running core");

    assert!(probe_all_error.contains("not running"));

    let probe_all_apply_error = core
        .probe_all_node_health_and_apply_recommended(ManagedNodeProbeSweepOptions {
            target: "example.com:443".to_string(),
            payload: b"ping".to_vec(),
            expect: b"pong".to_vec(),
            inbound: SmokeInboundKind::HttpConnect,
            first_byte_timeout: Duration::from_secs(1),
            udp_available: None,
            udp_probe: None,
        })
        .expect_err("probing all health and applying recommendation should require running core");

    assert!(probe_all_apply_error.contains("not running"));

    let apply_error = core
        .apply_recommended_outbound()
        .expect_err("applying recommendation should require running core");

    assert!(apply_error.contains("not running"));
}

#[test]
fn managed_mixed_session_can_run_without_system_proxy() {
    let controller = FakeSystemProxyController::new(SystemProxySnapshot::default());

    let session = ManagedMixedSession::start_from_subscription_config_text(
        ss_config(),
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-READY".to_string()),
            system_proxy: false,
            ..ManagedMixedOptions::default()
        },
        &controller,
    )
    .expect("start managed mixed session");

    assert_eq!(session.selected_outbound(), Some("SS-READY"));

    let state = session.stop().expect("stop managed mixed session");

    assert_eq!(state.status(), &RuntimeStatus::Stopped);
    assert!(controller.applied.borrow().is_empty());
    assert!(controller.restored.borrow().is_empty());
}

fn spawn_shadowsocks_tcp_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ss tcp server");
    let port = listener.local_addr().expect("ss tcp addr").port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept ss tcp server");
        let kind = CipherKind::from_str("aes-256-gcm").expect("cipher");
        let key = shadowsocks_key(kind, "secret");

        let mut client_salt = vec![0; kind.salt_len()];
        stream
            .read_exact(&mut client_salt)
            .expect("read client salt");
        let mut client_cipher = Cipher::new(kind, &key, &client_salt);
        let request_header = read_ss_chunk(&mut stream, &mut client_cipher);
        assert_eq!(request_header, b"\x03\x0bexample.com\x01\xbb");
        let payload = read_ss_chunk(&mut stream, &mut client_cipher);
        assert_eq!(&payload, b"ping");

        let server_salt = vec![7; kind.salt_len()];
        stream.write_all(&server_salt).expect("write server salt");
        let mut server_cipher = Cipher::new(kind, &key, &server_salt);
        write_ss_chunk(&mut stream, &mut server_cipher, b"pong");
    });
    (port, handle)
}

fn spawn_shadowsocks_tcp_udp_echo_server() -> (u16, thread::JoinHandle<()>, thread::JoinHandle<()>)
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ss tcp server");
    let port = listener.local_addr().expect("ss tcp addr").port();
    let socket = UdpSocket::bind(("127.0.0.1", port)).expect("bind ss udp server");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("ss udp timeout");

    let tcp_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept ss tcp server");
        let kind = CipherKind::from_str("aes-256-gcm").expect("cipher");
        let key = shadowsocks_key(kind, "secret");

        let mut client_salt = vec![0; kind.salt_len()];
        stream
            .read_exact(&mut client_salt)
            .expect("read client salt");
        let mut client_cipher = Cipher::new(kind, &key, &client_salt);
        let request_header = read_ss_chunk(&mut stream, &mut client_cipher);
        assert_eq!(request_header, b"\x03\x0bexample.com\x01\xbb");
        let payload = read_ss_chunk(&mut stream, &mut client_cipher);
        assert_eq!(&payload, b"ping");

        let server_salt = vec![7; kind.salt_len()];
        stream.write_all(&server_salt).expect("write server salt");
        let mut server_cipher = Cipher::new(kind, &key, &server_salt);
        write_ss_chunk(&mut stream, &mut server_cipher, b"pong");
    });

    let udp_handle = thread::spawn(move || {
        let kind = CipherKind::from_str("aes-256-gcm").expect("cipher");
        let key = shadowsocks_key(kind, "secret");
        let mut request = [0; 1500];
        let (size, from) = socket.recv_from(&mut request).expect("read ss udp request");
        let plaintext = decrypt_ss_udp_packet(kind, &key, &request[..size]);
        assert_eq!(plaintext, b"\x03\x0bexample.com\x005ping");

        let salt = vec![9; kind.salt_len()];
        let response = encrypt_ss_udp_packet(kind, &key, &salt, b"\x01\x7f\x00\x00\x01\x005pong");
        socket
            .send_to(&response, from)
            .expect("write ss udp response");
    });

    (port, tcp_handle, udp_handle)
}

fn unused_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused tcp port");
    listener.local_addr().expect("unused tcp addr").port()
}

fn shadowsocks_key(kind: CipherKind, password: &str) -> Vec<u8> {
    let mut key = vec![0; kind.key_len()];
    openssl_bytes_to_key(password.as_bytes(), &mut key);
    key
}

fn read_ss_chunk(stream: &mut TcpStream, cipher: &mut Cipher) -> Vec<u8> {
    let mut encrypted_len = vec![0; 2 + cipher.tag_len()];
    stream
        .read_exact(&mut encrypted_len)
        .expect("read encrypted ss chunk length");
    assert!(cipher.decrypt_packet(&mut encrypted_len));
    encrypted_len.truncate(2);
    let len = u16::from_be_bytes([encrypted_len[0], encrypted_len[1]]) as usize;
    let mut encrypted_payload = vec![0; len + cipher.tag_len()];
    stream
        .read_exact(&mut encrypted_payload)
        .expect("read encrypted ss chunk payload");
    assert!(cipher.decrypt_packet(&mut encrypted_payload));
    encrypted_payload.truncate(len);
    encrypted_payload
}

fn write_ss_chunk(stream: &mut TcpStream, cipher: &mut Cipher, payload: &[u8]) {
    let tag_len = cipher.tag_len();
    let mut encrypted_len = vec![0; 2 + tag_len];
    encrypted_len[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    cipher.encrypt_packet(&mut encrypted_len);
    stream
        .write_all(&encrypted_len)
        .expect("write encrypted ss chunk length");
    let mut encrypted_payload = vec![0; payload.len() + tag_len];
    encrypted_payload[..payload.len()].copy_from_slice(payload);
    cipher.encrypt_packet(&mut encrypted_payload);
    stream
        .write_all(&encrypted_payload)
        .expect("write encrypted ss chunk payload");
}

fn decrypt_ss_udp_packet(kind: CipherKind, key: &[u8], packet: &[u8]) -> Vec<u8> {
    let salt_len = kind.salt_len();
    let tag_len = kind.tag_len();
    let (salt, payload) = packet.split_at(salt_len);
    let mut payload = payload.to_vec();
    let mut cipher = Cipher::new(kind, key, salt);
    assert!(cipher.decrypt_packet(&mut payload));
    payload.truncate(payload.len() - tag_len);
    payload
}

fn encrypt_ss_udp_packet(kind: CipherKind, key: &[u8], salt: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let tag_len = kind.tag_len();
    let mut payload = vec![0; plaintext.len() + tag_len];
    payload[..plaintext.len()].copy_from_slice(plaintext);
    let mut cipher = Cipher::new(kind, key, salt);
    cipher.encrypt_packet(&mut payload);
    let mut packet = salt.to_vec();
    packet.extend_from_slice(&payload);
    packet
}
