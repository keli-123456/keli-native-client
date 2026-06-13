use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PanelAppInfo {
    pub name: Option<String>,
    pub url: Option<String>,
    pub logo: Option<String>,
    pub tos_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelAccount {
    pub email: String,
    pub plan_id: Option<i64>,
    pub balance_cents: Option<i64>,
    pub expired_at: Option<i64>,
    pub banned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PanelSubscription {
    pub plan_id: Option<i64>,
    pub plan_name: Option<String>,
    pub subscribe_url: Option<String>,
    pub accelerated_subscribe_url: Option<String>,
    pub used_bytes: Option<i64>,
    pub total_bytes: Option<i64>,
    pub device_limit: Option<i64>,
    pub speed_limit: Option<i64>,
    pub reset_day: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelNode {
    pub id: i64,
    pub name: String,
    pub protocol: Option<String>,
    pub transport: Option<String>,
    pub tags: Vec<String>,
    pub online: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelBootstrapPayload {
    pub app: PanelAppInfo,
    pub account: PanelAccount,
    pub subscription: PanelSubscription,
    pub nodes: Vec<PanelNode>,
}
