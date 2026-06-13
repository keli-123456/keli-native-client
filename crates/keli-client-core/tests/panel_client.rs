use std::cell::RefCell;

use keli_client_core::panel::{
    PanelApiClient, PanelApiError, PanelApiRequest, PanelApiResponse, PanelApiTransport,
    PanelHttpMethod, PanelSession,
};
use serde_json::json;

#[derive(Default)]
struct FakeTransport {
    responses: RefCell<Vec<PanelApiResponse>>,
    requests: RefCell<Vec<PanelApiRequest>>,
}

impl FakeTransport {
    fn with_responses(responses: Vec<PanelApiResponse>) -> Self {
        Self {
            responses: RefCell::new(responses),
            requests: RefCell::new(Vec::new()),
        }
    }
}

impl PanelApiTransport for FakeTransport {
    fn send(&self, request: PanelApiRequest) -> Result<PanelApiResponse, PanelApiError> {
        self.requests.borrow_mut().push(request);
        Ok(self.responses.borrow_mut().remove(0))
    }
}

#[test]
fn login_then_bootstrap_sends_expected_requests_and_auth_header() {
    let transport = FakeTransport::with_responses(vec![
        PanelApiResponse::json(200, json!({"data": {"auth_data": "token-secret"}})),
        PanelApiResponse::json(
            200,
            json!({
                "data": {
                    "app": {"name": "Keli"},
                    "user": {"email": "user@example.com", "plan_id": 7},
                    "subscribe": {
                        "plan": {"name": "Pro"},
                        "u": 1,
                        "d": 2,
                        "transfer_enable": 10
                    },
                    "servers": [{"id": 51, "name": "JP Tokyo 01", "type": "hysteria"}]
                }
            }),
        ),
    ]);
    let client = PanelApiClient::new("https://api.example.com", &transport).expect("client");

    let session = client.login("user@example.com", "secret").expect("login");
    let bootstrap = client.bootstrap(&session).expect("bootstrap");

    let requests = transport.requests.borrow();
    assert_eq!(requests[0].method, PanelHttpMethod::Post);
    assert_eq!(
        requests[0].url,
        "https://api.example.com/api/v2/passport/auth/login"
    );
    assert!(requests[0].authorization.is_none());
    assert_eq!(
        requests[1].url,
        "https://api.example.com/api/v1/app/bootstrap"
    );
    assert_eq!(
        requests[1].authorization.as_deref(),
        Some("Bearer token-secret")
    );
    assert_eq!(bootstrap.account.email, "user@example.com");
    assert_eq!(bootstrap.nodes[0].id, 51);
}

#[test]
fn bootstrap_uses_legacy_fallback_when_app_bootstrap_is_missing() {
    let transport = FakeTransport::with_responses(vec![
        PanelApiResponse::json(404, json!({"message": "missing"})),
        PanelApiResponse::json(200, json!({"data": {"email": "user@example.com"}})),
        PanelApiResponse::json(
            200,
            json!({"data": {"plan": {"name": "Pro"}, "u": 1, "d": 2, "transfer_enable": 10}}),
        ),
        PanelApiResponse::json(
            200,
            json!({"data": [{"id": 51, "name": "JP Tokyo 01", "type": "hysteria"}]}),
        ),
    ]);
    let client = PanelApiClient::new("https://api.example.com", &transport).expect("client");
    let session = PanelSession::new(
        "https://api.example.com",
        "/api/v1",
        "token-secret",
        Some("user@example.com".to_string()),
    );

    let bootstrap = client.bootstrap(&session).expect("bootstrap fallback");

    let urls = transport
        .requests
        .borrow()
        .iter()
        .map(|request| request.url.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        urls,
        vec![
            "https://api.example.com/api/v1/app/bootstrap",
            "https://api.example.com/api/v1/user/info",
            "https://api.example.com/api/v1/user/getSubscribe",
            "https://api.example.com/api/v1/user/server/fetch",
        ]
    );
    assert_eq!(bootstrap.subscription.plan_name.as_deref(), Some("Pro"));
}

#[test]
fn fetch_sing_box_config_returns_text_without_logging_token() {
    let transport = FakeTransport::with_responses(vec![PanelApiResponse::text(
        200,
        "proxies:\n  - name: JP Tokyo 01\n    type: ss\n    server: ss.example.com\n    port: 8388\n    cipher: aes-128-gcm\n    password: pass\n",
    )]);
    let client = PanelApiClient::new("https://api.example.com", &transport).expect("client");
    let session = PanelSession::new(
        "https://api.example.com",
        "/api/v1",
        "token-secret",
        Some("user@example.com".to_string()),
    );

    let config = client
        .sing_box_config_for_server(&session, 51, "windows", Some("1.13.11"))
        .expect("config");

    let request = &transport.requests.borrow()[0];
    assert_eq!(
        request.url,
        "https://api.example.com/api/v1/app/config?core=sing-box&platform=windows&server_id=51&core_version=1.13.11"
    );
    assert_eq!(request.authorization.as_deref(), Some("Bearer token-secret"));
    assert!(config.contains("JP Tokyo 01"));
    assert!(!format!("{request:?}").contains("token-secret"));
}
