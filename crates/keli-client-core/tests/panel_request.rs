use keli_client_core::panel::{PanelHttpMethod, PanelRequest};
use serde_json::json;

#[test]
fn login_request_targets_v2_passport_login_without_auth() {
    let request = PanelRequest::login("user@example.com", "secret");

    assert_eq!(request.method, PanelHttpMethod::Post);
    assert_eq!(request.api_prefix, "/api/v2");
    assert_eq!(request.path, "/passport/auth/login");
    assert!(!request.authenticated);
    assert_eq!(
        request.body,
        Some(json!({"email": "user@example.com", "password": "secret"}))
    );
}

#[test]
fn bootstrap_and_legacy_requests_use_v1_user_session() {
    assert_eq!(PanelRequest::bootstrap().path, "/app/bootstrap");
    assert_eq!(PanelRequest::user_info().path, "/user/info");
    assert_eq!(PanelRequest::user_subscribe().path, "/user/getSubscribe");
    assert_eq!(PanelRequest::servers().path, "/user/server/fetch");

    for request in [
        PanelRequest::bootstrap(),
        PanelRequest::user_info(),
        PanelRequest::user_subscribe(),
        PanelRequest::servers(),
    ] {
        assert_eq!(request.api_prefix, "/api/v1");
        assert!(request.authenticated);
    }
}

#[test]
fn config_request_builds_sing_box_windows_query() {
    let request = PanelRequest::sing_box_config_for_server(51, "windows", Some("1.13.11"));

    assert_eq!(request.method, PanelHttpMethod::Get);
    assert_eq!(request.path, "/app/config");
    assert_eq!(
        request.query,
        vec![
            ("core".to_string(), "sing-box".to_string()),
            ("platform".to_string(), "windows".to_string()),
            ("server_id".to_string(), "51".to_string()),
            ("core_version".to_string(), "1.13.11".to_string())
        ]
    );
}

#[test]
fn batch_config_request_omits_server_id_for_all_nodes() {
    let request = PanelRequest::sing_box_batch_config("windows", Some("1.13.11"));

    assert_eq!(request.method, PanelHttpMethod::Get);
    assert_eq!(request.path, "/app/config");
    assert_eq!(
        request.query,
        vec![
            ("core".to_string(), "sing-box".to_string()),
            ("platform".to_string(), "windows".to_string()),
            ("core_version".to_string(), "1.13.11".to_string())
        ]
    );
    assert!(request.authenticated);
}

#[test]
fn store_and_notice_requests_match_keliboard_routes() {
    assert_eq!(PanelRequest::plans().path, "/user/plan/fetch");
    assert_eq!(
        PanelRequest::payment_methods().path,
        "/user/order/getPaymentMethod"
    );
    assert_eq!(PanelRequest::orders().path, "/user/order/fetch");
    assert_eq!(
        PanelRequest::announcements(2, 50).path,
        "/user/notice/fetch"
    );
    assert_eq!(
        PanelRequest::announcements(2, 50).query,
        vec![
            ("current".to_string(), "2".to_string()),
            ("pageSize".to_string(), "50".to_string())
        ]
    );
}
