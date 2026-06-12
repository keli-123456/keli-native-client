use keli_cli::{ManagedSubscriptionUrlFetchOutcome, ManagedSubscriptionUrlUpdateOutcome};
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use keli_client_core::preflight_subscription_config;

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
}
