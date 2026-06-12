use keli_cli::{
    ConnectionMetricsSnapshot, ManagedMixedStatusSnapshot, ManagedNodeHealthState,
    ManagedSubscriptionHealthSummary,
};
use keli_client_core::{ClientErrorKind, ClientRuntime, RuntimeEvent, RuntimeStatus};
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
pub struct DesktopConnectionMetricsSummary {
    pub total: u64,
    pub success: u64,
    pub failure: u64,
    pub average_connect_ms: Option<u64>,
    pub average_first_byte_ms: Option<u64>,
}

impl Default for DesktopConnectionMetricsSummary {
    fn default() -> Self {
        Self {
            total: 0,
            success: 0,
            failure: 0,
            average_connect_ms: None,
            average_first_byte_ms: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopNodeHealthSummary {
    pub node_count: usize,
    pub healthy_count: usize,
    pub unhealthy_count: usize,
    pub unknown_count: usize,
    pub checked_count: usize,
    pub unchecked_count: usize,
    pub udp_available_count: usize,
    pub selected_state: Option<String>,
    pub recommended_state: Option<String>,
    pub selected_outbound_healthy: bool,
    pub recommended_switch_ready: bool,
}

impl Default for DesktopNodeHealthSummary {
    fn default() -> Self {
        Self {
            node_count: 0,
            healthy_count: 0,
            unhealthy_count: 0,
            unknown_count: 0,
            checked_count: 0,
            unchecked_count: 0,
            udp_available_count: 0,
            selected_state: None,
            recommended_state: None,
            selected_outbound_healthy: false,
            recommended_switch_ready: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopRecentRuntimeEvent {
    pub status: DesktopRunState,
    pub note: Option<String>,
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
    pub connection_metrics: DesktopConnectionMetricsSummary,
    pub node_health: DesktopNodeHealthSummary,
    pub recent_events: Vec<DesktopRecentRuntimeEvent>,
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
            connection_metrics: DesktopConnectionMetricsSummary::default(),
            node_health: DesktopNodeHealthSummary::default(),
            recent_events: Vec::new(),
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
            connection_metrics: DesktopConnectionMetricsSummary::from_metrics(
                &status.connection_metrics,
            ),
            node_health: status
                .subscription
                .as_ref()
                .map(|subscription| {
                    DesktopNodeHealthSummary::from_health_summary(&subscription.health_summary)
                })
                .unwrap_or_default(),
            recent_events: status
                .recent_events
                .iter()
                .map(DesktopRecentRuntimeEvent::from_runtime_event)
                .collect(),
        }
    }
}

impl DesktopConnectionMetricsSummary {
    fn from_metrics(metrics: &ConnectionMetricsSnapshot) -> Self {
        Self {
            total: metrics.total_connection_count,
            success: metrics.success_count,
            failure: metrics.failure_count,
            average_connect_ms: average_duration_ms(
                metrics.total_connect_ms,
                metrics.timed_connect_count,
            ),
            average_first_byte_ms: average_duration_ms(
                metrics.total_first_byte_ms,
                metrics.timed_first_byte_count,
            ),
        }
    }
}

impl DesktopNodeHealthSummary {
    fn from_health_summary(summary: &ManagedSubscriptionHealthSummary) -> Self {
        Self {
            node_count: summary.node_count,
            healthy_count: summary.healthy_count,
            unhealthy_count: summary.unhealthy_count,
            unknown_count: summary.unknown_count,
            checked_count: summary.checked_count,
            unchecked_count: summary.unchecked_count,
            udp_available_count: summary.udp_available_count,
            selected_state: summary.selected_state.as_ref().map(node_health_state_label),
            recommended_state: summary
                .recommended_state
                .as_ref()
                .map(node_health_state_label),
            selected_outbound_healthy: summary.selected_outbound_healthy,
            recommended_switch_ready: summary.recommended_switch_ready,
        }
    }
}

impl DesktopRecentRuntimeEvent {
    fn from_runtime_event(event: &RuntimeEvent) -> Self {
        Self {
            status: run_state(&event.status),
            note: event.note.clone(),
        }
    }
}

fn error_label(error: &ClientErrorKind) -> String {
    format!("{error:?}")
}

fn average_duration_ms(total_ms: u128, count: u64) -> Option<u64> {
    if count == 0 {
        None
    } else {
        Some((total_ms / u128::from(count)).min(u128::from(u64::MAX)) as u64)
    }
}

fn node_health_state_label(state: &ManagedNodeHealthState) -> String {
    match state {
        ManagedNodeHealthState::Unknown => "unknown",
        ManagedNodeHealthState::Healthy => "healthy",
        ManagedNodeHealthState::Unhealthy => "unhealthy",
    }
    .to_string()
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

    fn managed_options() -> keli_cli::ManagedMixedOptions {
        keli_cli::ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            ..keli_cli::ManagedMixedOptions::default()
        }
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

    #[test]
    fn managed_mixed_status_exposes_runtime_evidence_summary() {
        let platform_controller = FakeSystemProxyController::new();
        let mut core = ManagedMixedController::new(&platform_controller);
        let status = core
            .start_from_subscription_config_text(
                &ss_config("SS-READY"),
                managed_options(),
            )
            .expect("start managed core");

        let status = DesktopStatusSnapshot::from_managed_mixed_status(
            &status,
            DesktopTrafficMode::MixedInboundOnly,
        );

        assert_eq!(status.connection_metrics.total, 0);
        assert_eq!(status.connection_metrics.success, 0);
        assert_eq!(status.connection_metrics.failure, 0);
        assert_eq!(status.connection_metrics.average_connect_ms, None);
        assert_eq!(status.node_health.node_count, 1);
        assert_eq!(status.node_health.unknown_count, 1);
        assert_eq!(status.node_health.checked_count, 0);
        assert_eq!(status.node_health.selected_state.as_deref(), Some("unknown"));
        assert_eq!(
            status.node_health.recommended_state.as_deref(),
            Some("unknown")
        );
        assert!(!status.node_health.recommended_switch_ready);
        assert!(!status.recent_events.is_empty());
        assert!(status
            .recent_events
            .iter()
            .any(|event| event.status == DesktopRunState::Running));
        assert!(status
            .recent_events
            .iter()
            .any(|event| event.note.as_deref() == Some("runtime running")));
    }

    #[test]
    fn managed_mixed_status_exposes_recorded_node_health_summary() {
        let platform_controller = FakeSystemProxyController::new();
        let mut core = ManagedMixedController::new(&platform_controller);
        core.start_from_subscription_config_text(
            &ss_config("SS-READY"),
            managed_options(),
        )
        .expect("start managed core");

        let status = core
            .record_node_health(keli_cli::ManagedNodeHealthStatus::healthy(
                "SS-READY",
                Some(42),
                true,
                true,
            ))
            .expect("record node health");

        let status = DesktopStatusSnapshot::from_managed_mixed_status(
            &status,
            DesktopTrafficMode::MixedInboundOnly,
        );

        assert_eq!(status.node_health.node_count, 1);
        assert_eq!(status.node_health.healthy_count, 1);
        assert_eq!(status.node_health.checked_count, 1);
        assert_eq!(status.node_health.udp_available_count, 1);
        assert_eq!(status.node_health.selected_state.as_deref(), Some("healthy"));
        assert_eq!(
            status.node_health.recommended_state.as_deref(),
            Some("healthy")
        );
        assert!(status.node_health.selected_outbound_healthy);
    }
}
