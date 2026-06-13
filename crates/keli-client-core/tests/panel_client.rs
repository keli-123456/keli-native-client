use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use keli_client_core::panel::{
    PanelApiClient, PanelApiError, PanelApiRequest, PanelApiResponse, PanelApiTransport,
    PanelHttpMethod, PanelHttpTransport, PanelSession,
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
    assert_eq!(
        request.authorization.as_deref(),
        Some("Bearer token-secret")
    );
    assert!(config.contains("JP Tokyo 01"));
    assert!(!format!("{request:?}").contains("token-secret"));
}

#[test]
fn fetch_sing_box_batch_config_requests_all_panel_nodes() {
    let transport = FakeTransport::with_responses(vec![PanelApiResponse::text(
        200,
        "proxies:\n  - name: JP Tokyo 01\n    type: ss\n    server: ss.example.com\n    port: 8388\n    cipher: aes-128-gcm\n    password: pass\n  - name: SG 02\n    type: ss\n    server: sg.example.com\n    port: 8388\n    cipher: aes-128-gcm\n    password: pass\n",
    )]);
    let client = PanelApiClient::new("https://api.example.com", &transport).expect("client");
    let session = PanelSession::new(
        "https://api.example.com",
        "/api/v1",
        "token-secret",
        Some("user@example.com".to_string()),
    );

    let config = client
        .sing_box_batch_config(&session, "windows", Some("1.13.11"))
        .expect("batch config");

    let request = &transport.requests.borrow()[0];
    assert_eq!(
        request.url,
        "https://api.example.com/api/v1/app/config?core=sing-box&platform=windows&core_version=1.13.11"
    );
    assert_eq!(
        request.authorization.as_deref(),
        Some("Bearer token-secret")
    );
    assert!(config.contains("JP Tokyo 01"));
    assert!(config.contains("SG 02"));
}

#[test]
fn http_transport_posts_login_json_to_panel() {
    let (base_url, request_thread) =
        spawn_panel_http_server(200, r#"{"data":{"auth_data":"token-secret"}}"#);
    let transport = PanelHttpTransport::default().with_timeout(Duration::from_secs(2));
    let client = PanelApiClient::new(&base_url, &transport).expect("client");

    let session = client.login("user@example.com", "secret").expect("login");
    let request = request_thread.join().expect("panel request");

    assert_eq!(session.authorization_header(), "Bearer token-secret");
    assert!(request.starts_with("POST /api/v2/passport/auth/login HTTP/1.1"));
    assert!(request.contains("Host: 127.0.0.1:"));
    assert!(request.contains("Content-Type: application/json"));
    assert!(request.contains(r#""email":"user@example.com""#));
    assert!(request.contains(r#""password":"secret""#));
    assert!(!request.contains("Authorization:"));
}

#[test]
fn http_transport_sends_authorization_for_config_requests() {
    let (base_url, request_thread) = spawn_panel_http_server(
        200,
        "proxies:\n  - name: JP Tokyo 01\n    type: ss\n    server: ss.example.com\n    port: 8388\n    cipher: aes-128-gcm\n    password: pass\n",
    );
    let transport = PanelHttpTransport::default().with_timeout(Duration::from_secs(2));
    let client = PanelApiClient::new(&base_url, &transport).expect("client");
    let session = PanelSession::new(
        &base_url,
        "/api/v1",
        "token-secret",
        Some("user@example.com".to_string()),
    );

    let config = client
        .sing_box_config_for_server(&session, 51, "windows", Some("1.13.11"))
        .expect("config");
    let request = request_thread.join().expect("panel request");

    assert!(config.contains("JP Tokyo 01"));
    assert!(request.starts_with(
        "GET /api/v1/app/config?core=sing-box&platform=windows&server_id=51&core_version=1.13.11 HTTP/1.1"
    ));
    assert!(request.contains("Authorization: Bearer token-secret"));
}

fn spawn_panel_http_server(
    status: u16,
    body: &'static str,
) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind panel HTTP server");
    let port = listener.local_addr().expect("panel HTTP addr").port();
    let base_url = format!("http://127.0.0.1:{port}");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept panel request");
        let request = read_http_request(&mut stream);
        let response = format!(
            "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write panel response");
        request
    });
    (base_url, handle)
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 512];
    let mut header_end = None;
    while header_end.is_none() {
        let read = stream.read(&mut buffer).expect("read request header");
        assert!(read > 0, "connection closed before request header");
        bytes.extend_from_slice(&buffer[..read]);
        header_end = find_header_end(&bytes);
    }
    let header_end = header_end.expect("header end");
    let header = String::from_utf8_lossy(&bytes[..header_end]).to_string();
    let content_length = header
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let body_start = header_end + 4;
    while bytes.len().saturating_sub(body_start) < content_length {
        let read = stream.read(&mut buffer).expect("read request body");
        assert!(read > 0, "connection closed before request body");
        bytes.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(bytes).expect("request UTF-8")
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}
