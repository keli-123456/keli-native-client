use keli_client_core::SubscriptionPreflightReport;
use serde::{Deserialize, Serialize};

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
