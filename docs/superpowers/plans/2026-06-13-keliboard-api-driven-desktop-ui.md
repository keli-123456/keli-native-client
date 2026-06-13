# Keliboard API Driven Desktop UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first keliboard-aware desktop UI foundation by adding typed panel API contracts, composing panel state into the desktop shell snapshot, and rendering compact Chinese account/subscription/node/store/support surfaces without page-level scrolling.

**Architecture:** `keli-client-core` owns panel endpoint normalization, API request contracts, and response parsing. `keli-desktop` composes parsed panel state with existing local core status into `DesktopShellState`. `keli-desktop-shell` stays a rendering/event layer and does not know raw Laravel route details.

**Tech Stack:** Rust 2021, Cargo workspace, `serde`, `serde_json`, `url`, existing `keli-client-core`, `keli-desktop`, and `keli-desktop-shell` tests.

---

## File Structure

- Modify: `Cargo.toml`
  Adds shared `serde`, `serde_json`, and `url` usage to `keli-client-core`.
- Modify: `crates/keli-client-core/Cargo.toml`
  Enables panel model serialization and URL normalization dependencies.
- Modify: `crates/keli-client-core/src/lib.rs`
  Exports the new `panel` module.
- Create: `crates/keli-client-core/src/panel/mod.rs`
  Module exports for endpoint, request, models, and parsing helpers.
- Create: `crates/keli-client-core/src/panel/endpoint.rs`
  Discovery payload parsing, base URL normalization, API prefix normalization, cache expiration logic.
- Create: `crates/keli-client-core/src/panel/request.rs`
  Typed route/request builders for login, bootstrap, fallback endpoints, config, store, notices, and support.
- Create: `crates/keli-client-core/src/panel/models.rs`
  Account, subscription, node, plan, order, payment method, announcement, and bootstrap models.
- Create: `crates/keli-client-core/src/panel/parse.rs`
  Tolerant parsers for keliboard/Xboard-shaped JSON responses.
- Create: `crates/keli-client-core/tests/panel_endpoint.rs`
  Discovery and endpoint contract tests.
- Create: `crates/keli-client-core/tests/panel_request.rs`
  Request path/query/body contract tests.
- Create: `crates/keli-client-core/tests/panel_parse.rs`
  Bootstrap, fallback, node, store, and notice parsing tests.
- Create: `crates/keli-desktop/src/panel.rs`
  Desktop-facing panel DTOs and redaction helpers.
- Modify: `crates/keli-desktop/src/lib.rs`
  Exports desktop panel DTOs.
- Modify: `crates/keli-desktop/src/shell.rs`
  Adds `panel: Option<DesktopPanelSnapshot>` to `DesktopShellState` and keeps `panel = None` behavior unchanged.
- Modify: `crates/keli-desktop/src/app.rs`
  Adds fixture/test helpers for refreshing panel snapshots through the controller boundary.
- Modify: `crates/keli-desktop-shell/src/html.rs`
  Adds compact Chinese panel-aware views and tests for no page-level scroll.

---

### Task 1: Add Panel Module Skeleton And Endpoint Contracts

**Files:**
- Modify: `crates/keli-client-core/Cargo.toml`
- Modify: `crates/keli-client-core/src/lib.rs`
- Create: `crates/keli-client-core/src/panel/mod.rs`
- Create: `crates/keli-client-core/src/panel/endpoint.rs`
- Create: `crates/keli-client-core/tests/panel_endpoint.rs`

- [ ] **Step 1: Write the failing endpoint tests**

Create `crates/keli-client-core/tests/panel_endpoint.rs`:

```rust
use std::time::{Duration, SystemTime};

use keli_client_core::panel::{
    normalize_api_prefix, normalize_base_url, PanelEndpointConfig,
};
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

    let config = PanelEndpointConfig::from_discovery_json(&value, now)
        .expect("discovery config");

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
```

- [ ] **Step 2: Run the failing endpoint tests**

Run: `cargo test -p keli-client-core --test panel_endpoint -- --test-threads=1`

Expected: FAIL because `panel` exports and endpoint types do not exist.

- [ ] **Step 3: Add dependencies and panel exports**

Modify `crates/keli-client-core/Cargo.toml`:

```toml
[dependencies]
keli-protocol.workspace = true
serde.workspace = true
serde_json.workspace = true
url.workspace = true
```

Modify `crates/keli-client-core/src/lib.rs` near the top:

```rust
pub mod panel;
```

Create `crates/keli-client-core/src/panel/mod.rs`:

```rust
pub mod endpoint;

pub use endpoint::{
    normalize_api_prefix, normalize_base_url, PanelEndpointCandidate, PanelEndpointConfig,
};
```

- [ ] **Step 4: Implement endpoint parsing**

Create `crates/keli-client-core/src/panel/endpoint.rs`:

```rust
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelEndpointCandidate {
    pub base_url: String,
    pub api_prefix: String,
    pub source: String,
}

impl PanelEndpointCandidate {
    pub fn key(&self) -> String {
        format!("{}|{}", self.base_url.to_lowercase(), self.api_prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelEndpointConfig {
    pub api_base: String,
    pub api_prefix: String,
    pub backup_api_bases: Vec<String>,
    pub bootstrap_urls: Vec<String>,
    pub panel_host: Option<String>,
    pub source: String,
    pub updated_at: SystemTime,
    pub ttl: Duration,
    pub signature: Option<String>,
}

impl PanelEndpointConfig {
    pub fn from_discovery_json(value: &Value, now: SystemTime) -> Option<Self> {
        let api_base = normalize_base_url(string_value(value, "api_base")?)?;
        let api_prefix = normalize_api_prefix(string_value(value, "api_prefix").unwrap_or("/api/v1"));
        let backup_api_bases = string_list(value.get("backup_api_bases"))
            .into_iter()
            .filter_map(|item| normalize_base_url(&item))
            .collect();
        let bootstrap_urls = string_list(value.get("bootstrap_urls"))
            .into_iter()
            .filter(|item| Url::parse(item).is_ok())
            .collect();
        let panel_host = string_value(value, "panel_host")
            .map(str::to_lowercase)
            .filter(|item| !item.is_empty());
        let source = string_value(value, "source").unwrap_or("well-known").to_string();
        let ttl_seconds = value
            .get("ttl")
            .and_then(Value::as_u64)
            .unwrap_or(3600)
            .max(60);
        let signature = string_value(value, "signature")
            .map(str::to_string)
            .filter(|item| !item.is_empty());

        Some(Self {
            api_base,
            api_prefix,
            backup_api_bases,
            bootstrap_urls,
            panel_host,
            source,
            updated_at: now,
            ttl: Duration::from_secs(ttl_seconds),
            signature,
        })
    }

    pub fn primary_candidate(&self) -> PanelEndpointCandidate {
        PanelEndpointCandidate {
            base_url: self.api_base.clone(),
            api_prefix: self.api_prefix.clone(),
            source: self.source.clone(),
        }
    }

    pub fn backup_candidates(&self) -> Vec<PanelEndpointCandidate> {
        self.backup_api_bases
            .iter()
            .map(|base_url| PanelEndpointCandidate {
                base_url: base_url.clone(),
                api_prefix: self.api_prefix.clone(),
                source: format!("{} backup", self.source),
            })
            .collect()
    }

    pub fn is_expired(&self, now: SystemTime) -> bool {
        match self.updated_at.checked_add(self.ttl) {
            Some(expires_at) => now >= expires_at,
            None => true,
        }
    }
}

pub fn normalize_base_url(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else if trimmed.contains("://") {
        return None;
    } else {
        format!("https://{trimmed}")
    };
    let parsed = Url::parse(&with_scheme).ok()?;
    match parsed.scheme() {
        "http" | "https" => Some(with_scheme),
        _ => None,
    }
}

pub fn normalize_api_prefix(value: &str) -> String {
    let trimmed = value.trim().trim_matches('/');
    if trimmed.is_empty() {
        "/api/v1".to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn string_value<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str).map(str::trim).filter(|item| !item.is_empty())
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect(),
        Some(Value::String(items)) => items
            .split(|ch: char| ch == ',' || ch.is_whitespace())
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}
```

- [ ] **Step 5: Run endpoint tests**

Run: `cargo test -p keli-client-core --test panel_endpoint -- --test-threads=1`

Expected: PASS.

- [ ] **Step 6: Commit Task 1**

```bash
git add Cargo.toml crates/keli-client-core/Cargo.toml crates/keli-client-core/src/lib.rs crates/keli-client-core/src/panel/mod.rs crates/keli-client-core/src/panel/endpoint.rs crates/keli-client-core/tests/panel_endpoint.rs
git commit -m "feat: add keliboard endpoint contracts"
```

---

### Task 2: Add Typed Panel Request Contracts

**Files:**
- Modify: `crates/keli-client-core/src/panel/mod.rs`
- Create: `crates/keli-client-core/src/panel/request.rs`
- Create: `crates/keli-client-core/tests/panel_request.rs`

- [ ] **Step 1: Write failing request contract tests**

Create `crates/keli-client-core/tests/panel_request.rs`:

```rust
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
fn store_and_notice_requests_match_keliboard_routes() {
    assert_eq!(PanelRequest::plans().path, "/user/plan/fetch");
    assert_eq!(PanelRequest::payment_methods().path, "/user/order/getPaymentMethod");
    assert_eq!(PanelRequest::orders().path, "/user/order/fetch");
    assert_eq!(PanelRequest::announcements(2, 50).path, "/user/notice/fetch");
    assert_eq!(
        PanelRequest::announcements(2, 50).query,
        vec![
            ("current".to_string(), "2".to_string()),
            ("pageSize".to_string(), "50".to_string())
        ]
    );
}
```

- [ ] **Step 2: Run failing request tests**

Run: `cargo test -p keli-client-core --test panel_request -- --test-threads=1`

Expected: FAIL because `PanelRequest` does not exist.

- [ ] **Step 3: Export request module**

Modify `crates/keli-client-core/src/panel/mod.rs`:

```rust
pub mod endpoint;
pub mod request;

pub use endpoint::{
    normalize_api_prefix, normalize_base_url, PanelEndpointCandidate, PanelEndpointConfig,
};
pub use request::{PanelHttpMethod, PanelRequest};
```

- [ ] **Step 4: Implement request contracts**

Create `crates/keli-client-core/src/panel/request.rs`:

```rust
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PanelHttpMethod {
    Get,
    Post,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PanelRequest {
    pub method: PanelHttpMethod,
    pub api_prefix: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Option<Value>,
    pub authenticated: bool,
}

impl PanelRequest {
    pub fn login(email: &str, password: &str) -> Self {
        Self::post(
            "/api/v2",
            "/passport/auth/login",
            false,
            Some(json!({"email": email.trim(), "password": password})),
        )
    }

    pub fn bootstrap() -> Self {
        Self::get("/api/v1", "/app/bootstrap", true, Vec::new())
    }

    pub fn user_info() -> Self {
        Self::get("/api/v1", "/user/info", true, Vec::new())
    }

    pub fn user_subscribe() -> Self {
        Self::get("/api/v1", "/user/getSubscribe", true, Vec::new())
    }

    pub fn servers() -> Self {
        Self::get("/api/v1", "/user/server/fetch", true, Vec::new())
    }

    pub fn sing_box_config_for_server(
        server_id: i64,
        platform: &str,
        core_version: Option<&str>,
    ) -> Self {
        let mut query = vec![
            ("core".to_string(), "sing-box".to_string()),
            ("platform".to_string(), platform.to_string()),
            ("server_id".to_string(), server_id.to_string()),
        ];
        if let Some(core_version) = core_version.filter(|item| !item.trim().is_empty()) {
            query.push(("core_version".to_string(), core_version.trim().to_string()));
        }
        Self::get("/api/v1", "/app/config", true, query)
    }

    pub fn sing_box_batch_config(platform: &str, core_version: Option<&str>) -> Self {
        let mut query = vec![
            ("core".to_string(), "sing-box".to_string()),
            ("platform".to_string(), platform.to_string()),
        ];
        if let Some(core_version) = core_version.filter(|item| !item.trim().is_empty()) {
            query.push(("core_version".to_string(), core_version.trim().to_string()));
        }
        Self::get("/api/v1", "/app/config", true, query)
    }

    pub fn plans() -> Self {
        Self::get("/api/v1", "/user/plan/fetch", true, Vec::new())
    }

    pub fn payment_methods() -> Self {
        Self::get("/api/v1", "/user/order/getPaymentMethod", true, Vec::new())
    }

    pub fn orders() -> Self {
        Self::get("/api/v1", "/user/order/fetch", true, Vec::new())
    }

    pub fn announcements(current: usize, page_size: usize) -> Self {
        Self::get(
            "/api/v1",
            "/user/notice/fetch",
            true,
            vec![
                ("current".to_string(), current.to_string()),
                ("pageSize".to_string(), page_size.to_string()),
            ],
        )
    }

    fn get(
        api_prefix: &str,
        path: &str,
        authenticated: bool,
        query: Vec<(String, String)>,
    ) -> Self {
        Self {
            method: PanelHttpMethod::Get,
            api_prefix: api_prefix.to_string(),
            path: path.to_string(),
            query,
            body: None,
            authenticated,
        }
    }

    fn post(api_prefix: &str, path: &str, authenticated: bool, body: Option<Value>) -> Self {
        Self {
            method: PanelHttpMethod::Post,
            api_prefix: api_prefix.to_string(),
            path: path.to_string(),
            query: Vec::new(),
            body,
            authenticated,
        }
    }
}
```

- [ ] **Step 5: Run request tests**

Run: `cargo test -p keli-client-core --test panel_request -- --test-threads=1`

Expected: PASS.

- [ ] **Step 6: Commit Task 2**

```bash
git add crates/keli-client-core/src/panel/mod.rs crates/keli-client-core/src/panel/request.rs crates/keli-client-core/tests/panel_request.rs
git commit -m "feat: add keliboard request contracts"
```

---

### Task 3: Add Panel Models And Parsers

**Files:**
- Modify: `crates/keli-client-core/src/panel/mod.rs`
- Create: `crates/keli-client-core/src/panel/models.rs`
- Create: `crates/keli-client-core/src/panel/parse.rs`
- Create: `crates/keli-client-core/tests/panel_parse.rs`

- [ ] **Step 1: Write failing parser tests**

Create `crates/keli-client-core/tests/panel_parse.rs`:

```rust
use keli_client_core::panel::{
    parse_bootstrap_payload, parse_legacy_bootstrap_payload, parse_nodes, PanelBootstrapPayload,
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

    assert_eq!(payload.app.name.as_deref(), Some("Keli"));
    assert_eq!(payload.account.email, "user@example.com");
    assert_eq!(payload.account.plan_id, Some(1));
    assert_eq!(payload.subscription.plan_name.as_deref(), Some("Pro"));
    assert_eq!(payload.subscription.used_bytes, Some(4_294_967_296));
    assert_eq!(payload.subscription.total_bytes, Some(10_737_418_240));
    assert_eq!(payload.subscription.device_limit, Some(3));
    assert_eq!(payload.nodes.single().id, 51);
    assert_eq!(payload.nodes.single().name, "JP Tokyo 01");
    assert_eq!(payload.nodes.single().protocol.as_deref(), Some("hysteria"));
    assert!(payload.nodes.single().online.unwrap_or(false));
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

    let payload = parse_legacy_bootstrap_payload(&info, &subscribe, &servers)
        .expect("legacy bootstrap");

    assert_eq!(payload.account.email, "user@example.com");
    assert_eq!(payload.subscription.plan_name.as_deref(), Some("Basic"));
    assert_eq!(payload.nodes.single().name, "HK 01");
}

#[test]
fn parse_nodes_accepts_data_wrapper_or_plain_array() {
    let wrapped = json!({"data": [{"id": 2, "name": "US 01", "protocol": "vless"}]});
    let plain = json!([{"id": 3, "name": "SG 01", "type": "trojan"}]);

    assert_eq!(parse_nodes(&wrapped).expect("wrapped").single().id, 2);
    assert_eq!(
        parse_nodes(&plain).expect("plain").single().protocol.as_deref(),
        Some("trojan")
    );
}
```

- [ ] **Step 2: Run failing parser tests**

Run: `cargo test -p keli-client-core --test panel_parse -- --test-threads=1`

Expected: FAIL because parser types do not exist.

- [ ] **Step 3: Export model and parser modules**

Modify `crates/keli-client-core/src/panel/mod.rs`:

```rust
pub mod endpoint;
pub mod models;
pub mod parse;
pub mod request;

pub use endpoint::{
    normalize_api_prefix, normalize_base_url, PanelEndpointCandidate, PanelEndpointConfig,
};
pub use models::{
    PanelAccount, PanelAppInfo, PanelBootstrapPayload, PanelNode, PanelSubscription,
};
pub use parse::{parse_bootstrap_payload, parse_legacy_bootstrap_payload, parse_nodes};
pub use request::{PanelHttpMethod, PanelRequest};
```

- [ ] **Step 4: Implement panel models**

Create `crates/keli-client-core/src/panel/models.rs`:

```rust
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
```

- [ ] **Step 5: Implement parser helpers**

Create `crates/keli-client-core/src/panel/parse.rs`:

```rust
use serde_json::Value;

use crate::panel::models::{
    PanelAccount, PanelAppInfo, PanelBootstrapPayload, PanelNode, PanelSubscription,
};

pub fn parse_bootstrap_payload(value: &Value) -> Option<PanelBootstrapPayload> {
    let data = data_object(value)?;
    Some(PanelBootstrapPayload {
        app: parse_app(data.get("app")),
        account: parse_account(data.get("user")?)?,
        subscription: parse_subscription(data.get("subscribe")),
        nodes: parse_nodes(data.get("servers").or_else(|| data.get("nodes")).unwrap_or(&Value::Null))
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
        account: parse_account(data_object(info)?)?,
        subscription: parse_subscription(Some(data_object(subscribe)?)),
        nodes: parse_nodes(servers).unwrap_or_default(),
    })
}

pub fn parse_nodes(value: &Value) -> Option<Vec<PanelNode>> {
    let items = match value {
        Value::Array(items) => items,
        Value::Object(_) => data_object(value)?.as_array()?,
        _ => return Some(Vec::new()),
    };
    Some(items.iter().filter_map(parse_node).collect())
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

fn data_object(value: &Value) -> Option<&Value> {
    value.get("data").unwrap_or(value).as_object().map(|_| value.get("data").unwrap_or(value))
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
    value
        .get(key)
        .and_then(|item| item.as_i64().or_else(|| item.as_str()?.parse::<i64>().ok()))
}

fn bool_value(value: &Value, key: &str) -> Option<bool> {
    match value.get(key)? {
        Value::Bool(value) => Some(*value),
        Value::Number(value) => Some(value.as_i64().unwrap_or(0) != 0),
        Value::String(value) => Some(matches!(value.as_str(), "1" | "true" | "yes")),
        _ => None,
    }
}
```

- [ ] **Step 6: Run parser tests**

Run: `cargo test -p keli-client-core --test panel_parse -- --test-threads=1`

Expected: PASS.

- [ ] **Step 7: Commit Task 3**

```bash
git add crates/keli-client-core/src/panel/mod.rs crates/keli-client-core/src/panel/models.rs crates/keli-client-core/src/panel/parse.rs crates/keli-client-core/tests/panel_parse.rs
git commit -m "feat: parse keliboard panel payloads"
```

---

### Task 4: Add Desktop Panel Snapshot DTOs

**Files:**
- Create: `crates/keli-desktop/src/panel.rs`
- Modify: `crates/keli-desktop/src/lib.rs`
- Modify: `crates/keli-desktop/src/shell.rs`

- [ ] **Step 1: Write failing desktop panel DTO tests**

Add this test module to `crates/keli-desktop/src/shell.rs` under the existing tests:

```rust
#[test]
fn shell_state_can_include_panel_snapshot_without_breaking_local_only_mode() {
    let mut shell = DesktopShellState::new(status(DesktopRunState::Stopped), ready_dependencies());
    assert!(shell.panel.is_none());
    assert!(!shell.can_start);

    shell.refresh_panel(Some(crate::panel::DesktopPanelSnapshot::fixture_ready()));

    assert!(shell.panel.is_some());
    assert!(!shell.can_start);
    assert_eq!(
        shell.panel.as_ref().unwrap().account.email_redacted,
        "u***@example.com"
    );
}
```

- [ ] **Step 2: Run failing desktop shell test**

Run: `cargo test -p keli-desktop shell_state_can_include_panel_snapshot_without_breaking_local_only_mode -- --test-threads=1`

Expected: FAIL because `DesktopPanelSnapshot` and `DesktopShellState.panel` do not exist.

- [ ] **Step 3: Implement desktop panel DTOs**

Create `crates/keli-desktop/src/panel.rs`:

```rust
use keli_client_core::panel::{PanelBootstrapPayload, PanelNode};
use serde::{Deserialize, Serialize};

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
                has_accelerated_subscribe_url: payload.subscription.accelerated_subscribe_url.is_some(),
            },
            nodes: payload.nodes.iter().map(DesktopPanelNodeSummary::from_panel).collect(),
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
                expired_at: Some(1810000000),
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
```

- [ ] **Step 4: Export desktop panel DTOs**

Modify `crates/keli-desktop/src/lib.rs`:

```rust
pub mod panel;
pub use panel::{
    DesktopPanelAccountSummary, DesktopPanelEndpointSummary, DesktopPanelNodeSummary,
    DesktopPanelNoticeSummary, DesktopPanelSnapshot, DesktopPanelSubscriptionSummary,
};
```

- [ ] **Step 5: Extend shell state with panel snapshot**

Modify `crates/keli-desktop/src/shell.rs` imports:

```rust
use crate::panel::DesktopPanelSnapshot;
```

Add field to `DesktopShellState`:

```rust
pub panel: Option<DesktopPanelSnapshot>,
```

Initialize it in `DesktopShellState::new`:

```rust
panel: None,
```

Add method:

```rust
pub fn refresh_panel(&mut self, panel: Option<DesktopPanelSnapshot>) {
    self.panel = panel;
    self.rebuild_derived();
}
```

- [ ] **Step 6: Run desktop shell test**

Run: `cargo test -p keli-desktop shell_state_can_include_panel_snapshot_without_breaking_local_only_mode -- --test-threads=1`

Expected: PASS.

- [ ] **Step 7: Commit Task 4**

```bash
git add crates/keli-desktop/src/panel.rs crates/keli-desktop/src/lib.rs crates/keli-desktop/src/shell.rs
git commit -m "feat: add desktop panel snapshot"
```

---

### Task 5: Render Panel-Aware Compact Chinese UI

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Write failing shell HTML tests**

Add tests to `crates/keli-desktop-shell/src/html.rs`:

```rust
#[test]
fn panel_ui_baseline_includes_account_subscription_store_and_support_views() {
    let mut snapshot = fixture_snapshot();
    snapshot.panel = Some(keli_desktop::DesktopPanelSnapshot::fixture_ready());

    let html = render_shell_html(&snapshot);

    assert!(html.contains("data-view-target=\"subscription-view\""));
    assert!(html.contains("data-view-target=\"store-view\""));
    assert!(html.contains("data-view-target=\"support-view\""));
    assert!(html.contains(">订阅</button>"));
    assert!(html.contains(">商店</button>"));
    assert!(html.contains(">支持</button>"));
    assert!(html.contains("id=\"dashboard-panel-account\""));
    assert!(html.contains("u***@example.com"));
    assert!(!html.contains("token"));
}

#[test]
fn panel_ui_keeps_page_level_scrolling_disabled() {
    let html = render_shell_html(&fixture_snapshot());

    assert!(html.contains("body {{"));
    assert!(html.contains("overflow: hidden;"));
    assert!(html.contains(".bounded-list"));
}
```

- [ ] **Step 2: Run failing HTML tests**

Run: `cargo test -p keli-desktop-shell panel_ui -- --test-threads=1`

Expected: FAIL because the new views and panel fields are not rendered.

- [ ] **Step 3: Add panel summary variables**

In `render_shell_html`, add after existing snapshot-derived variables:

```rust
let panel_account = panel_account_summary(snapshot);
let panel_subscription = panel_subscription_summary(snapshot);
let panel_nodes = panel_nodes_summary(snapshot);
let panel_notice = panel_notice_summary(snapshot);
```

Add format args near the bottom of `format!`:

```rust
panel_account = escape_html(&panel_account),
panel_subscription = escape_html(&panel_subscription),
panel_nodes = panel_nodes,
panel_notice = escape_html(&panel_notice),
```

- [ ] **Step 4: Add compact CSS for bounded panel regions**

In `crates/keli-desktop-shell/src/html.rs`, add CSS inside the existing `<style>`:

```css
    .panel-grid {
      min-height: 0;
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(280px, 0.9fr);
      gap: 12px;
      overflow: hidden;
    }
    .bounded-list {
      min-height: 0;
      max-height: 320px;
      overflow: auto;
    }
    .panel-kpi-row {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }
    .panel-kpi {
      min-width: 0;
      padding: 10px;
      border: 1px solid #d9dee5;
      border-radius: 8px;
      background: #ffffff;
    }
```

- [ ] **Step 5: Add navigation buttons**

Add these buttons after the existing `节点` button:

```html
        <button class="nav-item" data-view-target="subscription-view" onclick="postViewTarget('subscription-view')">订阅</button>
        <button class="nav-item" data-view-target="store-view" onclick="postViewTarget('store-view')">商店</button>
        <button class="nav-item" data-view-target="support-view" onclick="postViewTarget('support-view')">支持</button>
```

- [ ] **Step 6: Add dashboard panel account section**

Inside `dashboard-view`, add a compact section before the existing dashboard row:

```html
    <section id="dashboard-panel-account">
      <h2>账号</h2>
      <div class="panel-kpi-row">
        <div class="panel-kpi"><div class="metric-label">账号</div><strong>{panel_account}</strong></div>
        <div class="panel-kpi"><div class="metric-label">订阅</div><strong>{panel_subscription}</strong></div>
        <div class="panel-kpi"><div class="metric-label">公告</div><strong>{panel_notice}</strong></div>
      </div>
    </section>
```

- [ ] **Step 7: Add subscription/store/support views**

Add views before `diagnostics-view`:

```html
    <div class="app-view subscription-view" id="subscription-view" data-app-view hidden>
      <div class="panel-grid">
        <section>
          <h2>订阅</h2>
          <div class="value">{panel_subscription}</div>
          <p class="muted">账号模式优先；订阅 URL 导入保留为兼容入口。</p>
        </section>
        <section>
          <h2>面板节点</h2>
          <div class="bounded-list">{panel_nodes}</div>
        </section>
      </div>
    </div>
    <div class="app-view store-view" id="store-view" data-app-view hidden>
      <section>
        <h2>商店</h2>
        <div class="value">套餐、订单、支付接口已进入客户端契约。</div>
        <p class="muted">下一步接入套餐和订单快照。</p>
      </section>
    </div>
    <div class="app-view support-view" id="support-view" data-app-view hidden>
      <section>
        <h2>支持</h2>
        <div class="value">{panel_notice}</div>
        <p class="muted">公告先接入；知识库和工单动作单独规划。</p>
      </section>
    </div>
```

- [ ] **Step 8: Add Rust helper renderers**

Add helper functions near existing HTML helper functions:

```rust
fn panel_account_summary(snapshot: &DesktopShellState) -> String {
    snapshot
        .panel
        .as_ref()
        .map(|panel| panel.account.email_redacted.clone())
        .unwrap_or_else(|| "未登录面板".to_string())
}

fn panel_subscription_summary(snapshot: &DesktopShellState) -> String {
    let Some(panel) = snapshot.panel.as_ref() else {
        return "未加载订阅".to_string();
    };
    let plan = panel
        .subscription
        .plan_name
        .as_deref()
        .unwrap_or("未命名套餐");
    let used = panel.subscription.used_bytes.unwrap_or(0);
    let total = panel.subscription.total_bytes.unwrap_or(0);
    format!("{plan}，已用 {} / {}", bytes_label(used), bytes_label(total))
}

fn panel_notice_summary(snapshot: &DesktopShellState) -> String {
    snapshot
        .panel
        .as_ref()
        .and_then(|panel| panel.notices.iter().find(|notice| notice.show))
        .map(|notice| notice.title.clone())
        .unwrap_or_else(|| "暂无公告".to_string())
}

fn panel_nodes_summary(snapshot: &DesktopShellState) -> String {
    let Some(panel) = snapshot.panel.as_ref() else {
        return r#"<div class="muted">未加载面板节点</div>"#.to_string();
    };
    if panel.nodes.is_empty() {
        return r#"<div class="muted">没有可用节点</div>"#.to_string();
    }
    panel
        .nodes
        .iter()
        .map(|node| {
            let protocol = node.protocol.as_deref().unwrap_or("未知协议");
            format!(
                r#"<div class="status-row"><strong>{}</strong><span>{}</span></div>"#,
                escape_html(&node.name),
                escape_html(protocol)
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn bytes_label(bytes: i64) -> String {
    let gb = bytes as f64 / 1024.0 / 1024.0 / 1024.0;
    format!("{gb:.1} GB")
}
```

- [ ] **Step 9: Run HTML tests**

Run: `cargo test -p keli-desktop-shell panel_ui -- --test-threads=1`

Expected: PASS.

- [ ] **Step 10: Commit Task 5**

```bash
git add crates/keli-desktop-shell/src/html.rs
git commit -m "feat: render keliboard-aware desktop views"
```

---

### Task 6: Wire Controller Fixture Panel Refresh

**Files:**
- Modify: `crates/keli-desktop/src/app.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Write failing controller refresh test**

Add to `crates/keli-desktop/src/app.rs` tests:

```rust
#[test]
fn controller_refresh_panel_snapshot_updates_shell_without_touching_subscription_url() {
    let host = FakeDesktopShellCommandHost::default();
    let mut controller = DesktopShellController::new(host);

    let snapshot = controller.refresh_panel_snapshot(Some(crate::panel::DesktopPanelSnapshot::fixture_ready()));

    assert!(snapshot.panel.is_some());
    assert!(snapshot.subscription.is_none());
    assert_eq!(
        snapshot.panel.as_ref().unwrap().nodes.single().name,
        "JP Tokyo 01"
    );
}
```

- [ ] **Step 2: Run failing controller test**

Run: `cargo test -p keli-desktop controller_refresh_panel_snapshot_updates_shell_without_touching_subscription_url -- --test-threads=1`

Expected: FAIL because the controller method does not exist.

- [ ] **Step 3: Add controller refresh method**

In `impl<H: DesktopShellCommandHost> DesktopShellController<H>`, add:

```rust
pub fn refresh_panel_snapshot(
    &mut self,
    panel: Option<crate::panel::DesktopPanelSnapshot>,
) -> DesktopShellState {
    self.shell.refresh_panel(panel);
    self.shell.clone()
}
```

- [ ] **Step 4: Add shell event for fixture preview**

In `crates/keli-desktop-shell/src/main.rs`, add a UI event variant:

```rust
LoadPanelFixture,
```

Map IPC message `"load-panel-fixture"` to it, and handle it with:

```rust
DesktopShellUiEvent::LoadPanelFixture => {
    Ok(controller.refresh_panel_snapshot(Some(keli_desktop::DesktopPanelSnapshot::fixture_ready())))
}
```

Add operation success message:

```rust
DesktopShellUiEvent::LoadPanelFixture => Some("已加载面板示例数据".to_string()),
```

- [ ] **Step 5: Add a hidden development button in settings**

In `crates/keli-desktop-shell/src/html.rs`, add a settings action button:

```html
            <button id="settings-load-panel-fixture-button" onclick="window.ipc.postMessage('load-panel-fixture')">加载面板示例</button>
```

- [ ] **Step 6: Run controller and shell event tests**

Run: `cargo test -p keli-desktop controller_refresh_panel_snapshot_updates_shell_without_touching_subscription_url -- --test-threads=1`

Expected: PASS.

Run: `cargo test -p keli-desktop-shell load_panel_fixture -- --test-threads=1`

Expected: PASS after adding or updating the shell event parsing tests.

- [ ] **Step 7: Commit Task 6**

```bash
git add crates/keli-desktop/src/app.rs crates/keli-desktop-shell/src/main.rs crates/keli-desktop-shell/src/html.rs
git commit -m "feat: add panel fixture preview path"
```

---

### Task 7: Verification And Smoke

**Files:**
- No source files expected.

- [ ] **Step 1: Run client core panel tests**

Run: `cargo test -p keli-client-core panel -- --test-threads=1`

Expected: PASS.

- [ ] **Step 2: Run desktop tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 3: Run desktop shell tests**

Run: `cargo test -p keli-desktop-shell -- --test-threads=1`

Expected: PASS.

- [ ] **Step 4: Run desktop shell smoke**

Run: `cargo run -q -p keli-desktop-shell -- --smoke`

Expected: PASS with a smoke JSON/status result and no panic.

- [ ] **Step 5: Check formatting**

Run: `cargo fmt`

Expected: no errors.

- [ ] **Step 6: Check diff cleanliness**

Run: `git diff --check`

Expected: no output.

- [ ] **Step 7: Commit verification-only fixes if formatting changed files**

If `cargo fmt` changed tracked Rust files, commit them:

```bash
git add crates/keli-client-core crates/keli-desktop crates/keli-desktop-shell
git commit -m "style: format keliboard panel foundation"
```

If `cargo fmt` did not change files, do not create a verification-only commit.

---

## Self-Review

Spec coverage:

- Discovery/API endpoint map is covered by Task 1 and Task 2.
- Bootstrap, fallback, node parsing, and store/support request contracts are covered by Task 2 and Task 3.
- Desktop panel state and redaction are covered by Task 4.
- Default viewport UI and Chinese panel views are covered by Task 5.
- Development preview path is covered by Task 6.
- Existing behavior and smoke verification are covered by Task 7.

Placeholder scan:

- The plan contains no unfinished-marker words.
- Each implementation task includes concrete files, test commands, and expected results.

Type consistency:

- `PanelEndpointConfig`, `PanelRequest`, `PanelBootstrapPayload`, and `DesktopPanelSnapshot` are introduced before dependent tasks use them.
- `DesktopShellState.panel` is added before shell HTML reads panel summaries.
