use std::cell::RefCell;
use std::net::TcpListener;

use keli_cli::{
    apply_system_proxy_for_listener, ManagedMixedController, ManagedMixedOptions,
    ManagedMixedSession, ManagedNodeHealthState, ManagedNodeHealthStatus,
};
use keli_client_core::RuntimeStatus;
use keli_net_core::ConnectionErrorKind;
use keli_platform::{
    SystemProxyConfig, SystemProxyController, SystemProxyError, SystemProxySnapshot,
};

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
                ..ManagedMixedOptions::default()
            },
        )
        .expect("start managed mixed controller");

    assert!(core.is_running());
    assert_eq!(started.selected_outbound.as_deref(), Some("SS-READY"));
    assert!(started.listen_addr.is_some());
    assert_eq!(started.generation, 1);
    assert!(matches!(started.status, RuntimeStatus::Running { .. }));
    assert!(started.system_proxy_enabled());
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
    assert!(reloaded.event_count >= started.event_count);
    assert!(reloaded.recent_events.len() <= 5);
    assert!(matches!(
        reloaded.status,
        RuntimeStatus::Running {
            selected_outbound,
            ..
        } if selected_outbound == "SS-NEXT"
    ));

    let stopped = core.stop().expect("stop managed mixed controller");

    assert_eq!(stopped.status(), &RuntimeStatus::Stopped);
    assert!(!core.is_running());
    assert_eq!(core.status().status, RuntimeStatus::Stopped);
    assert!(!core.status().system_proxy_enabled());
    assert!(!platform_controller.restored.borrow().is_empty());
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

    assert_eq!(
        subscription
            .health_for("SS-READY")
            .expect("SS-READY health")
            .state,
        ManagedNodeHealthState::Unknown
    );
    assert_eq!(
        subscription
            .health_for("SS-NEXT")
            .expect("SS-NEXT health")
            .state,
        ManagedNodeHealthState::Unknown
    );

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
    assert_eq!(next.state, ManagedNodeHealthState::Unhealthy);
    assert_eq!(
        next.error_kind,
        Some(ConnectionErrorKind::TcpConnectTimeout)
    );
    assert_eq!(
        next.error_detail.as_deref(),
        Some("timeout to example target")
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
