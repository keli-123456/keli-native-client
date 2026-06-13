use keli_client_core::panel::{
    parse_bootstrap_payload, parse_legacy_bootstrap_payload, parse_nodes,
};
use serde_json::json;

#[test]
fn parses_app_bootstrap_profile_subscription_and_nodes() {
    let value = json!({
        "data": {
            "app": {"name": "Keli", "url": "https://panel.example.com"},
            "user": {
                "email": "user@example.com",
                "balance": 1234,
                "plan_id": 1,
                "expired_at": 1810000000,
                "banned": 0
            },
            "subscribe": {
                "plan_id": 1,
                "subscribe_url": "https://panel.example.com/s/token",
                "accelerated_subscribe_url": "https://sub.example.com/s/token",
                "u": 3221225472i64,
                "d": 1073741824i64,
                "transfer_enable": 10737418240i64,
                "device_limit": 3,
                "speed_limit": 100,
                "reset_day": 5,
                "plan": {"id": 1, "name": "Pro"}
            },
            "servers": [
                {
                    "id": 51,
                    "name": "JP Tokyo 01",
                    "type": "hysteria",
                    "tags": ["jp", "streaming"],
                    "is_online": true
                }
            ]
        }
    });

    let payload = parse_bootstrap_payload(&value).expect("bootstrap payload");
    let node = payload.nodes.first().expect("node");

    assert_eq!(payload.app.name.as_deref(), Some("Keli"));
    assert_eq!(payload.account.email, "user@example.com");
    assert_eq!(payload.account.plan_id, Some(1));
    assert_eq!(payload.subscription.plan_name.as_deref(), Some("Pro"));
    assert_eq!(payload.subscription.used_bytes, Some(4_294_967_296));
    assert_eq!(payload.subscription.total_bytes, Some(10_737_418_240));
    assert_eq!(payload.subscription.device_limit, Some(3));
    assert_eq!(node.id, 51);
    assert_eq!(node.name, "JP Tokyo 01");
    assert_eq!(node.protocol.as_deref(), Some("hysteria"));
    assert_eq!(node.tags, vec!["jp".to_string(), "streaming".to_string()]);
    assert!(node.online.unwrap_or(false));
}

#[test]
fn parses_legacy_bootstrap_from_info_subscribe_and_servers() {
    let info = json!({
        "data": {
            "email": "user@example.com",
            "plan_id": 7,
            "balance": 500
        }
    });
    let subscribe = json!({
        "data": {
            "subscribe_url": "https://panel.example.com/s/token",
            "u": 100,
            "d": 50,
            "transfer_enable": 1000,
            "plan": {"id": 7, "name": "Basic"}
        }
    });
    let servers = json!({
        "data": [
            {"id": 1, "name": "HK 01", "type": "shadowsocks"}
        ]
    });

    let payload =
        parse_legacy_bootstrap_payload(&info, &subscribe, &servers).expect("legacy bootstrap");
    let node = payload.nodes.first().expect("node");

    assert_eq!(payload.account.email, "user@example.com");
    assert_eq!(payload.subscription.plan_name.as_deref(), Some("Basic"));
    assert_eq!(node.name, "HK 01");
}

#[test]
fn parse_nodes_accepts_data_wrapper_or_plain_array() {
    let wrapped = json!({"data": [{"id": 2, "name": "US 01", "protocol": "vless"}]});
    let plain = json!([{"id": 3, "name": "SG 01", "type": "trojan"}]);

    assert_eq!(parse_nodes(&wrapped).expect("wrapped")[0].id, 2);
    assert_eq!(
        parse_nodes(&plain).expect("plain")[0].protocol.as_deref(),
        Some("trojan")
    );
}
