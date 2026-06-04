use std::cell::RefCell;
use std::net::TcpListener;

use keli_cli::{apply_system_proxy_for_listener, ManagedMixedOptions, ManagedMixedSession};
use keli_client_core::RuntimeStatus;
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
