use serde_json::Value;

use crate::panel::models::{
    PanelAccount, PanelAppInfo, PanelBootstrapPayload, PanelNode, PanelSubscription,
};

pub fn parse_bootstrap_payload(value: &Value) -> Option<PanelBootstrapPayload> {
    let data = data_value(value).as_object()?;
    Some(PanelBootstrapPayload {
        app: parse_app(data.get("app")),
        account: parse_account(data.get("user")?)?,
        subscription: parse_subscription(data.get("subscribe")),
        nodes: parse_nodes(
            data.get("servers")
                .or_else(|| data.get("nodes"))
                .unwrap_or(&Value::Null),
        )
        .unwrap_or_default(),
    })
}

pub fn parse_legacy_bootstrap_payload(
    info: &Value,
    subscribe: &Value,
    servers: &Value,
) -> Option<PanelBootstrapPayload> {
    Some(PanelBootstrapPayload {
        app: PanelAppInfo::default(),
        account: parse_account(data_value(info))?,
        subscription: parse_subscription(Some(data_value(subscribe))),
        nodes: parse_nodes(servers).unwrap_or_default(),
    })
}

pub fn parse_nodes(value: &Value) -> Option<Vec<PanelNode>> {
    match data_value(value) {
        Value::Array(items) => Some(items.iter().filter_map(parse_node).collect()),
        Value::Null => Some(Vec::new()),
        _ => None,
    }
}

fn parse_app(value: Option<&Value>) -> PanelAppInfo {
    let Some(value) = value else {
        return PanelAppInfo::default();
    };
    PanelAppInfo {
        name: string_value(value, "name"),
        url: string_value(value, "url"),
        logo: string_value(value, "logo"),
        tos_url: string_value(value, "tos_url"),
    }
}

fn parse_account(value: &Value) -> Option<PanelAccount> {
    Some(PanelAccount {
        email: string_value(value, "email")?,
        plan_id: int_value(value, "plan_id"),
        balance_cents: int_value(value, "balance"),
        expired_at: int_value(value, "expired_at"),
        banned: bool_value(value, "banned").unwrap_or(false),
    })
}

fn parse_subscription(value: Option<&Value>) -> PanelSubscription {
    let Some(value) = value else {
        return PanelSubscription::default();
    };
    let uploaded = int_value(value, "u").unwrap_or(0);
    let downloaded = int_value(value, "d").unwrap_or(0);
    PanelSubscription {
        plan_id: int_value(value, "plan_id"),
        plan_name: value
            .get("plan")
            .and_then(|plan| string_value(plan, "name")),
        subscribe_url: string_value(value, "subscribe_url"),
        accelerated_subscribe_url: string_value(value, "accelerated_subscribe_url"),
        used_bytes: Some(uploaded.saturating_add(downloaded)),
        total_bytes: int_value(value, "transfer_enable"),
        device_limit: int_value(value, "device_limit"),
        speed_limit: int_value(value, "speed_limit"),
        reset_day: int_value(value, "reset_day"),
    }
}

fn parse_node(value: &Value) -> Option<PanelNode> {
    Some(PanelNode {
        id: int_value(value, "id")?,
        name: string_value(value, "name")?,
        protocol: string_value(value, "protocol").or_else(|| string_value(value, "type")),
        transport: string_value(value, "transport"),
        tags: value
            .get("tags")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        online: bool_value(value, "is_online").or_else(|| bool_value(value, "online")),
    })
}

fn data_value(value: &Value) -> &Value {
    value.get("data").unwrap_or(value)
}

fn string_value(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
}

fn int_value(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(|item| {
        item.as_i64()
            .or_else(|| item.as_str()?.trim().parse::<i64>().ok())
    })
}

fn bool_value(value: &Value, key: &str) -> Option<bool> {
    match value.get(key)? {
        Value::Bool(value) => Some(*value),
        Value::Number(value) => Some(value.as_i64().unwrap_or(0) != 0),
        Value::String(value) => Some(matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes"
        )),
        _ => None,
    }
}
