use keli_cli::ManagedMixedStatusSnapshot;
use keli_client_core::{ClientErrorKind, ClientRuntime, RuntimeStatus};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesktopRunState {
    Stopped,
    Starting,
    Running,
    Reloading,
    Stopping,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesktopTrafficMode {
    SystemProxy,
    Tun,
    MixedInboundOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopStatusSnapshot {
    pub run_state: DesktopRunState,
    pub traffic_mode: DesktopTrafficMode,
    pub selected_outbound: Option<String>,
    pub listen: Option<String>,
    pub generation: u64,
    pub event_count: usize,
    pub last_error: Option<String>,
}

impl DesktopStatusSnapshot {
    pub fn from_client_runtime(runtime: &ClientRuntime, traffic_mode: DesktopTrafficMode) -> Self {
        let (selected_outbound, listen) = match runtime.status() {
            RuntimeStatus::Running {
                selected_outbound,
                listen,
                ..
            } => (Some(selected_outbound.clone()), Some(listen.clone())),
            _ => (None, None),
        };
        Self {
            run_state: run_state(runtime.status()),
            traffic_mode,
            selected_outbound,
            listen,
            generation: runtime.generation(),
            event_count: runtime.event_count(),
            last_error: runtime.last_error().map(error_label),
        }
    }

    pub fn from_managed_mixed_status(
        status: &ManagedMixedStatusSnapshot,
        traffic_mode: DesktopTrafficMode,
    ) -> Self {
        Self {
            run_state: run_state(&status.status),
            traffic_mode,
            selected_outbound: status.selected_outbound.clone(),
            listen: status.listen_addr.map(|addr| addr.to_string()),
            generation: status.generation,
            event_count: status.event_count,
            last_error: status.last_error.as_ref().map(error_label),
        }
    }
}

fn error_label(error: &ClientErrorKind) -> String {
    format!("{error:?}")
}

fn run_state(status: &RuntimeStatus) -> DesktopRunState {
    match status {
        RuntimeStatus::Stopped => DesktopRunState::Stopped,
        RuntimeStatus::Starting => DesktopRunState::Starting,
        RuntimeStatus::Running { .. } => DesktopRunState::Running,
        RuntimeStatus::Reloading { .. } => DesktopRunState::Reloading,
        RuntimeStatus::Stopping { .. } => DesktopRunState::Stopping,
        RuntimeStatus::Failed(_) => DesktopRunState::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    use keli_cli::ManagedMixedController;
    use keli_client_core::RuntimeConfig;
    use keli_platform::{
        SystemProxyConfig, SystemProxyController, SystemProxyError, SystemProxySnapshot,
    };

    fn ss_config(tag: &str) -> String {
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

    #[test]
    fn stopped_runtime_maps_to_stopped_desktop_status() {
        let runtime = ClientRuntime::default();

        let status =
            DesktopStatusSnapshot::from_client_runtime(&runtime, DesktopTrafficMode::SystemProxy);

        assert_eq!(status.run_state, DesktopRunState::Stopped);
        assert_eq!(status.traffic_mode, DesktopTrafficMode::SystemProxy);
        assert_eq!(status.selected_outbound, None);
        assert_eq!(status.listen, None);
        assert_eq!(status.generation, 0);
        assert_eq!(status.last_error, None);
    }

    #[test]
    fn running_runtime_exposes_selected_outbound_and_listen_address() {
        let mut runtime = ClientRuntime::default();
        runtime
            .start(RuntimeConfig::new(
                ss_config("SS-READY"),
                Some("SS-READY"),
                "127.0.0.1:7890",
            ))
            .expect("start runtime");

        let status = DesktopStatusSnapshot::from_client_runtime(&runtime, DesktopTrafficMode::Tun);

        assert_eq!(status.run_state, DesktopRunState::Running);
        assert_eq!(status.traffic_mode, DesktopTrafficMode::Tun);
        assert_eq!(status.selected_outbound.as_deref(), Some("SS-READY"));
        assert_eq!(status.listen.as_deref(), Some("127.0.0.1:7890"));
        assert_eq!(status.generation, 1);
        assert!(status.event_count >= 2);
    }

    #[derive(Debug)]
    struct FakeSystemProxyController {
        snapshot: SystemProxySnapshot,
        applied: RefCell<Vec<SystemProxyConfig>>,
        restored: RefCell<Vec<SystemProxySnapshot>>,
    }

    impl FakeSystemProxyController {
        fn new() -> Self {
            Self {
                snapshot: SystemProxySnapshot::default(),
                applied: RefCell::new(Vec::new()),
                restored: RefCell::new(Vec::new()),
            }
        }
    }

    impl SystemProxyController for FakeSystemProxyController {
        fn snapshot(&self) -> Result<SystemProxySnapshot, SystemProxyError> {
            Ok(self.snapshot.clone())
        }

        fn apply(
            &self,
            config: &SystemProxyConfig,
        ) -> Result<SystemProxySnapshot, SystemProxyError> {
            self.applied.borrow_mut().push(config.clone());
            Ok(self.snapshot.clone())
        }

        fn restore(&self, snapshot: &SystemProxySnapshot) -> Result<(), SystemProxyError> {
            self.restored.borrow_mut().push(snapshot.clone());
            Ok(())
        }
    }

    #[test]
    fn managed_mixed_status_maps_to_stopped_desktop_status() {
        let platform_controller = FakeSystemProxyController::new();
        let core = ManagedMixedController::new(&platform_controller);

        let status = DesktopStatusSnapshot::from_managed_mixed_status(
            &core.status(),
            DesktopTrafficMode::MixedInboundOnly,
        );

        assert_eq!(status.run_state, DesktopRunState::Stopped);
        assert_eq!(status.traffic_mode, DesktopTrafficMode::MixedInboundOnly);
        assert_eq!(status.selected_outbound, None);
        assert_eq!(status.listen, None);
        assert_eq!(status.generation, 0);
        assert_eq!(status.event_count, 0);
        assert_eq!(status.last_error, None);
    }
}
