use keli_client_core::panel::{parse_login_session, PanelSession};
use serde_json::json;

#[test]
fn parses_login_response_auth_data_into_bearer_session() {
    let value = json!({
        "data": {
            "auth_data": "token-secret",
            "token": "legacy-token",
            "user": {"email": "user@example.com"}
        }
    });

    let session = parse_login_session(&value, "https://api.example.com", "/api/v1")
        .expect("login session");

    assert_eq!(session.api_base, "https://api.example.com");
    assert_eq!(session.api_prefix, "/api/v1");
    assert_eq!(session.email.as_deref(), Some("user@example.com"));
    assert_eq!(session.authorization_header(), "Bearer token-secret");
}

#[test]
fn falls_back_to_token_when_auth_data_is_absent() {
    let value = json!({"data": {"token": "legacy-token"}});

    let session = parse_login_session(&value, "https://api.example.com", "/api/v1")
        .expect("login session");

    assert_eq!(session.authorization_header(), "Bearer legacy-token");
}

#[test]
fn redacts_token_from_debug_output() {
    let session = PanelSession::new(
        "https://api.example.com",
        "/api/v1",
        "token-secret",
        Some("user@example.com".to_string()),
    );

    let debug = format!("{session:?}");

    assert!(debug.contains("token_redacted"));
    assert!(!debug.contains("token-secret"));
}
