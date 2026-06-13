use std::time::{Duration, SystemTime};

use keli_client_core::panel::{normalize_api_prefix, normalize_base_url, PanelEndpointConfig};
use serde_json::json;

#[test]
fn normalizes_manual_panel_url_and_api_prefix() {
    assert_eq!(
        normalize_base_url("panel.example.com/").expect("base URL"),
        "https://panel.example.com"
    );
    assert_eq!(
        normalize_base_url("https://panel.example.com/root/").expect("base URL"),
        "https://panel.example.com/root"
    );
    assert_eq!(normalize_api_prefix("api/v1"), "/api/v1");
    assert_eq!(normalize_api_prefix("/api/v1/"), "/api/v1");
    assert_eq!(normalize_api_prefix(""), "/api/v1");
}

#[test]
fn parses_well_known_discovery_payload_with_ttl_and_backups() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    let value = json!({
        "api_base": "https://api.example.com/",
        "api_prefix": "api/v1/",
        "backup_api_bases": ["https://backup.example.com/", "backup2.example.com"],
        "bootstrap_urls": ["https://panel.example.com/bootstrap/keli-client.json"],
        "panel_host": "PANEL.EXAMPLE.COM",
        "source": "well-known",
        "ttl": 3600,
        "updated_at": "2026-06-13T00:00:00Z",
        "signature": "ed25519:test"
    });

    let config = PanelEndpointConfig::from_discovery_json(&value, now).expect("discovery config");

    assert_eq!(config.api_base, "https://api.example.com");
    assert_eq!(config.api_prefix, "/api/v1");
    assert_eq!(
        config.backup_api_bases,
        vec![
            "https://backup.example.com".to_string(),
            "https://backup2.example.com".to_string()
        ]
    );
    assert_eq!(
        config.bootstrap_urls,
        vec!["https://panel.example.com/bootstrap/keli-client.json".to_string()]
    );
    assert_eq!(config.panel_host.as_deref(), Some("panel.example.com"));
    assert_eq!(config.source, "well-known");
    assert_eq!(config.signature.as_deref(), Some("ed25519:test"));
    assert!(!config.is_expired(now + Duration::from_secs(3599)));
    assert!(config.is_expired(now + Duration::from_secs(3601)));
}

#[test]
fn rejects_empty_or_non_http_base_urls() {
    assert!(normalize_base_url("").is_none());
    assert!(normalize_base_url("file:///tmp/panel").is_none());
}
