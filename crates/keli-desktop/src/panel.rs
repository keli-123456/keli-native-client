use keli_client_core::panel::{PanelBootstrapPayload, PanelNode};
use serde::{Deserialize, Serialize};

use crate::subscription::DesktopSubscriptionSummary;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopPanelSnapshot {
    pub endpoint: DesktopPanelEndpointSummary,
    pub account: DesktopPanelAccountSummary,
    pub subscription: DesktopPanelSubscriptionSummary,
    pub nodes: Vec<DesktopPanelNodeSummary>,
    pub notices: Vec<DesktopPanelNoticeSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopPanelEndpointSummary {
    pub panel_host: String,
    pub api_base_redacted: String,
    pub api_prefix: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopPanelAccountSummary {
    pub email_redacted: String,
    pub plan_id: Option<i64>,
    pub balance_cents: Option<i64>,
    pub expired_at: Option<i64>,
    pub blocked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopPanelSubscriptionSummary {
    pub plan_name: Option<String>,
    pub used_bytes: Option<i64>,
    pub total_bytes: Option<i64>,
    pub device_limit: Option<i64>,
    pub speed_limit: Option<i64>,
    pub reset_day: Option<i64>,
    pub has_subscribe_url: bool,
    pub has_accelerated_subscribe_url: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopPanelNodeSummary {
    pub id: i64,
    pub name: String,
    pub protocol: Option<String>,
    pub tags: Vec<String>,
    pub online: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopPanelNoticeSummary {
    pub id: String,
    pub title: String,
    pub show: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopPanelConfigImportSummary {
    pub server_id: i64,
    pub server_name: String,
    pub selected_outbound: Option<String>,
    pub usable: bool,
    pub subscription: DesktopSubscriptionSummary,
}

impl DesktopPanelConfigImportSummary {
    pub fn from_subscription(
        server_id: i64,
        server_name: impl Into<String>,
        subscription: DesktopSubscriptionSummary,
    ) -> Self {
        Self {
            server_id,
            server_name: server_name.into(),
            selected_outbound: subscription.selected_outbound.clone(),
            usable: subscription.usable,
            subscription,
        }
    }
}

impl DesktopPanelSnapshot {
    pub fn from_bootstrap(
        endpoint: DesktopPanelEndpointSummary,
        payload: &PanelBootstrapPayload,
    ) -> Self {
        Self {
            endpoint,
            account: DesktopPanelAccountSummary {
                email_redacted: redact_email(&payload.account.email),
                plan_id: payload.account.plan_id,
                balance_cents: payload.account.balance_cents,
                expired_at: payload.account.expired_at,
                blocked: payload.account.banned,
            },
            subscription: DesktopPanelSubscriptionSummary {
                plan_name: payload.subscription.plan_name.clone(),
                used_bytes: payload.subscription.used_bytes,
                total_bytes: payload.subscription.total_bytes,
                device_limit: payload.subscription.device_limit,
                speed_limit: payload.subscription.speed_limit,
                reset_day: payload.subscription.reset_day,
                has_subscribe_url: payload.subscription.subscribe_url.is_some(),
                has_accelerated_subscribe_url: payload
                    .subscription
                    .accelerated_subscribe_url
                    .is_some(),
            },
            nodes: payload
                .nodes
                .iter()
                .map(DesktopPanelNodeSummary::from_panel)
                .collect(),
            notices: Vec::new(),
        }
    }

    pub fn fixture_ready() -> Self {
        Self {
            endpoint: DesktopPanelEndpointSummary {
                panel_host: "panel.example.com".to_string(),
                api_base_redacted: "https://panel.example.com".to_string(),
                api_prefix: "/api/v1".to_string(),
                source: "fixture".to_string(),
            },
            account: DesktopPanelAccountSummary {
                email_redacted: "u***@example.com".to_string(),
                plan_id: Some(1),
                balance_cents: Some(1234),
                expired_at: Some(1_810_000_000),
                blocked: false,
            },
            subscription: DesktopPanelSubscriptionSummary {
                plan_name: Some("Pro".to_string()),
                used_bytes: Some(4_294_967_296),
                total_bytes: Some(10_737_418_240),
                device_limit: Some(3),
                speed_limit: Some(100),
                reset_day: Some(5),
                has_subscribe_url: true,
                has_accelerated_subscribe_url: true,
            },
            nodes: vec![DesktopPanelNodeSummary {
                id: 51,
                name: "JP Tokyo 01".to_string(),
                protocol: Some("hysteria".to_string()),
                tags: vec!["jp".to_string(), "streaming".to_string()],
                online: Some(true),
            }],
            notices: vec![DesktopPanelNoticeSummary {
                id: "notice-1".to_string(),
                title: "欢迎使用 Keli".to_string(),
                show: true,
            }],
        }
    }
}

impl DesktopPanelNodeSummary {
    fn from_panel(node: &PanelNode) -> Self {
        Self {
            id: node.id,
            name: node.name.clone(),
            protocol: node.protocol.clone(),
            tags: node.tags.clone(),
            online: node.online,
        }
    }
}

fn redact_email(email: &str) -> String {
    let Some((name, domain)) = email.split_once('@') else {
        return "***".to_string();
    };
    let first = name.chars().next().unwrap_or('*');
    format!("{first}***@{domain}")
}
