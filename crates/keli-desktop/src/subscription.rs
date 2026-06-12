use keli_cli::{
    ManagedNodeHealthState, ManagedNodeHealthStatus, ManagedSubscriptionStatus,
    ManagedSubscriptionUrlFetchOutcome, ManagedSubscriptionUrlUpdateOutcome,
};
use keli_client_core::{SubscriptionPreflightReport, SubscriptionUpdateReport};
use serde::{Deserialize, Serialize};

use crate::status::{DesktopStatusSnapshot, DesktopTrafficMode};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopNodeSummary {
    pub tag: String,
    pub protocol: String,
    pub transport: String,
    pub security: String,
    pub udp_supported: bool,
    pub selected: bool,
    pub recommended: bool,
    pub health_state: Option<String>,
    pub tcp_available: Option<bool>,
    pub udp_available: Option<bool>,
    pub latency_ms: Option<u64>,
    pub health_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopSubscriptionSummary {
    pub usable: bool,
    pub supported_count: usize,
    pub skipped_count: usize,
    pub default_outbound: Option<String>,
    pub selected_outbound: Option<String>,
    pub recommended_outbound: Option<String>,
    pub nodes: Vec<DesktopNodeSummary>,
    pub skipped: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopSubscriptionUpdateSummary {
    pub applied: bool,
    pub error: Option<String>,
    pub reason: String,
    pub current_supported_count: usize,
    pub new_supported_count: usize,
    pub new_skipped_count: usize,
    pub current_selected_outbound: Option<String>,
    pub planned_selected_outbound: Option<String>,
    pub selected_outbound_preserved: bool,
    pub selected_outbound_changed: bool,
    pub added_tags: Vec<String>,
    pub removed_tags: Vec<String>,
    pub retained_tags: Vec<String>,
    pub subscription: DesktopSubscriptionSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopSubscriptionUrlFetchSummary {
    pub ok: bool,
    pub scheme: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub default_port: Option<bool>,
    pub path_present: Option<bool>,
    pub query_present: Option<bool>,
    pub http_status: Option<u16>,
    pub body_bytes: Option<usize>,
    pub elapsed_ms: Option<u64>,
    pub error_kind: Option<String>,
    pub error_detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopSubscriptionUrlImportSummary {
    pub fetch: DesktopSubscriptionUrlFetchSummary,
    pub subscription: Option<DesktopSubscriptionSummary>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopSubscriptionUrlUpdateSummary {
    pub applied: bool,
    pub error: Option<String>,
    pub fetch: DesktopSubscriptionUrlFetchSummary,
    pub update: Option<DesktopSubscriptionUpdateSummary>,
    pub runtime_status: DesktopStatusSnapshot,
}

impl DesktopSubscriptionUrlFetchSummary {
    pub fn from_managed(fetch: &ManagedSubscriptionUrlFetchOutcome) -> Self {
        let source = fetch.source.as_ref();
        Self {
            ok: fetch.ok,
            scheme: source.map(|source| source.scheme.clone()),
            host: source.map(|source| source.host.clone()),
            port: source.map(|source| source.port),
            default_port: source.map(|source| source.default_port),
            path_present: source.map(|source| source.path_present),
            query_present: source.map(|source| source.query_present),
            http_status: fetch.http_status,
            body_bytes: fetch.body_bytes,
            elapsed_ms: fetch
                .elapsed
                .map(|elapsed| elapsed.as_millis().min(u128::from(u64::MAX)) as u64),
            error_kind: fetch.error_kind.clone(),
            error_detail: fetch.error_detail.clone(),
        }
    }
}

impl DesktopSubscriptionUrlImportSummary {
    pub fn fetch_error(fetch: DesktopSubscriptionUrlFetchSummary) -> Self {
        let error = Some(format!(
            "subscription URL fetch failed: {}",
            fetch.error_kind.as_deref().unwrap_or("unknown")
        ));
        Self {
            fetch,
            subscription: None,
            error,
        }
    }
}

impl DesktopSubscriptionUrlUpdateSummary {
    pub fn from_managed(
        outcome: &ManagedSubscriptionUrlUpdateOutcome,
        update: Option<DesktopSubscriptionUpdateSummary>,
        traffic_mode: DesktopTrafficMode,
    ) -> Self {
        Self {
            applied: outcome.applied,
            error: outcome.error.clone(),
            fetch: DesktopSubscriptionUrlFetchSummary::from_managed(&outcome.fetch),
            update,
            runtime_status: DesktopStatusSnapshot::from_managed_mixed_status(
                &outcome.status,
                traffic_mode,
            ),
        }
    }
}

impl DesktopSubscriptionUpdateSummary {
    pub fn from_report(
        report: &SubscriptionUpdateReport,
        applied: bool,
        error: Option<String>,
        subscription: DesktopSubscriptionSummary,
    ) -> Self {
        Self {
            applied,
            error,
            reason: report.reason.label().to_string(),
            current_supported_count: report.current_supported_count,
            new_supported_count: report.new_supported_count,
            new_skipped_count: report.new_skipped_count,
            current_selected_outbound: report.current_selected_outbound.clone(),
            planned_selected_outbound: report.planned_selected_outbound.clone(),
            selected_outbound_preserved: report.selected_outbound_preserved,
            selected_outbound_changed: report.selected_outbound_changed,
            added_tags: report.added_tags.clone(),
            removed_tags: report.removed_tags.clone(),
            retained_tags: report.retained_tags.clone(),
            subscription,
        }
    }
}

impl DesktopSubscriptionSummary {
    pub fn from_preflight(
        report: &SubscriptionPreflightReport,
        selected_outbound: Option<&str>,
        recommended_outbound: Option<&str>,
    ) -> Self {
        let selected_outbound = selected_outbound
            .map(str::to_string)
            .or_else(|| report.default_outbound().map(str::to_string));
        let recommended_outbound = recommended_outbound
            .map(str::to_string)
            .or_else(|| selected_outbound.clone());
        let nodes = report
            .supported()
            .iter()
            .map(|node| DesktopNodeSummary {
                tag: node.tag.clone(),
                protocol: node.protocol.clone(),
                transport: node.transport.clone(),
                security: node.security.clone(),
                udp_supported: node.udp_supported,
                selected: selected_outbound.as_deref() == Some(node.tag.as_str()),
                recommended: recommended_outbound.as_deref() == Some(node.tag.as_str()),
                health_state: Some("unknown".to_string()),
                tcp_available: None,
                udp_available: None,
                latency_ms: None,
                health_error: None,
            })
            .collect();
        Self {
            usable: report.is_usable(),
            supported_count: report.supported_count(),
            skipped_count: report.skipped_count(),
            default_outbound: report.default_outbound().map(str::to_string),
            selected_outbound,
            recommended_outbound,
            nodes,
            skipped: report
                .skipped()
                .iter()
                .map(|skipped| format!("{}: {}", skipped.name, skipped.reason))
                .collect(),
        }
    }

    pub fn from_managed(status: &ManagedSubscriptionStatus) -> Self {
        let nodes = status
            .supported
            .iter()
            .map(|node| {
                let health = status.health_for(&node.tag);
                let node_health = health
                    .map(desktop_node_health_summary)
                    .unwrap_or_else(unknown_node_health_summary);
                DesktopNodeSummary {
                    tag: node.tag.clone(),
                    protocol: node.protocol.clone(),
                    transport: node.transport.clone(),
                    security: node.security.clone(),
                    udp_supported: node.udp_supported,
                    selected: status.selected_outbound == node.tag,
                    recommended: status.recommended_outbound == node.tag,
                    health_state: node_health.health_state,
                    tcp_available: node_health.tcp_available,
                    udp_available: node_health.udp_available,
                    latency_ms: node_health.latency_ms,
                    health_error: node_health.health_error,
                }
            })
            .collect();

        Self {
            usable: status.usable,
            supported_count: status.supported_count(),
            skipped_count: status.skipped_count(),
            default_outbound: status.default_outbound.clone(),
            selected_outbound: Some(status.selected_outbound.clone()),
            recommended_outbound: Some(status.recommended_outbound.clone()),
            nodes,
            skipped: status
                .skipped
                .iter()
                .map(|skipped| format!("{}: {}", skipped.name, skipped.reason))
                .collect(),
        }
    }
}

struct DesktopNodeHealthFields {
    health_state: Option<String>,
    tcp_available: Option<bool>,
    udp_available: Option<bool>,
    latency_ms: Option<u64>,
    health_error: Option<String>,
}

fn unknown_node_health_summary() -> DesktopNodeHealthFields {
    DesktopNodeHealthFields {
        health_state: Some("unknown".to_string()),
        tcp_available: None,
        udp_available: None,
        latency_ms: None,
        health_error: None,
    }
}

fn desktop_node_health_summary(health: &ManagedNodeHealthStatus) -> DesktopNodeHealthFields {
    DesktopNodeHealthFields {
        health_state: Some(node_health_state_label(&health.state).to_string()),
        tcp_available: health.tcp_available,
        udp_available: health.udp_available,
        latency_ms: health.latency_ms.map(saturating_u128_to_u64),
        health_error: health.error_detail.clone().or_else(|| {
            health
                .error_kind
                .as_ref()
                .map(|error_kind| format!("{error_kind:?}"))
        }),
    }
}

fn node_health_state_label(state: &ManagedNodeHealthState) -> &'static str {
    match state {
        ManagedNodeHealthState::Unknown => "unknown",
        ManagedNodeHealthState::Healthy => "healthy",
        ManagedNodeHealthState::Unhealthy => "unhealthy",
    }
}

fn saturating_u128_to_u64(value: u128) -> u64 {
    value.min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    use keli_cli::ManagedMixedController;
    use keli_client_core::preflight_subscription_config;
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
    fn subscription_summary_marks_selected_and_recommended_nodes() {
        let config = r#"
proxies:
  - name: SS-A
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
  - name: VMESS-B
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
"#;
        let report = preflight_subscription_config(config).expect("preflight");

        let summary =
            DesktopSubscriptionSummary::from_preflight(&report, Some("VMESS-B"), Some("SS-A"));

        assert!(summary.usable);
        assert_eq!(summary.supported_count, 2);
        assert_eq!(summary.skipped_count, 0);
        assert_eq!(summary.default_outbound.as_deref(), Some("SS-A"));
        assert_eq!(summary.selected_outbound.as_deref(), Some("VMESS-B"));
        assert_eq!(summary.recommended_outbound.as_deref(), Some("SS-A"));
        assert!(summary
            .nodes
            .iter()
            .any(|node| node.tag == "VMESS-B" && node.selected));
        assert!(summary
            .nodes
            .iter()
            .any(|node| node.tag == "SS-A" && node.recommended));
    }

    #[test]
    fn subscription_summary_from_preflight_marks_node_health_unknown() {
        let report = preflight_subscription_config(&ss_config("SS-A")).expect("preflight");

        let summary =
            DesktopSubscriptionSummary::from_preflight(&report, Some("SS-A"), Some("SS-A"));
        let node = summary
            .nodes
            .iter()
            .find(|node| node.tag == "SS-A")
            .expect("SS-A");

        assert_eq!(node.health_state.as_deref(), Some("unknown"));
        assert_eq!(node.tcp_available, None);
        assert_eq!(node.udp_available, None);
        assert_eq!(node.latency_ms, None);
        assert_eq!(node.health_error, None);
    }

    #[test]
    fn subscription_summary_from_managed_maps_node_health() {
        let platform_controller = FakeSystemProxyController::new();
        let mut core = ManagedMixedController::new(&platform_controller);
        core.start_from_subscription_config_text(&ss_config("SS-A"), managed_options())
            .expect("start core");
        let status = core
            .record_node_health(keli_cli::ManagedNodeHealthStatus::healthy(
                "SS-A",
                Some(42),
                true,
                true,
            ))
            .expect("record health");
        let managed = status.subscription.as_ref().expect("managed subscription");

        let summary = DesktopSubscriptionSummary::from_managed(managed);
        let node = summary
            .nodes
            .iter()
            .find(|node| node.tag == "SS-A")
            .expect("SS-A");

        assert_eq!(node.health_state.as_deref(), Some("healthy"));
        assert_eq!(node.tcp_available, Some(true));
        assert_eq!(node.udp_available, Some(true));
        assert_eq!(node.latency_ms, Some(42));
        assert_eq!(node.health_error, None);
    }
}
