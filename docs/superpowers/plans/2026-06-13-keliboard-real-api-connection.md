# Keliboard Real API Connection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first real keliboard API connection loop: login, load bootstrap, fetch a sing-box Windows config for a selected panel node, validate/import that config into the existing desktop runtime, and expose the flow through Chinese desktop shell actions.

**Architecture:** `keli-client-core::panel` owns auth/session models, request execution planning, transport abstraction, and the high-level login/bootstrap/config workflow. `keli-desktop` owns desktop composition and imports fetched config through the existing subscription config preflight path. `keli-desktop-shell` remains an IPC/rendering layer and never embeds raw keliboard route details beyond typed UI event names.

**Tech Stack:** Rust 2021, Cargo workspace, `serde`, `serde_json`, `url`, existing std/TCP style tests, existing desktop controller and shell event tests.

---

## File Structure

- Modify: `crates/keli-client-core/src/panel/mod.rs`
  Exports auth/session/client workflow types.
- Create: `crates/keli-client-core/src/panel/auth.rs`
  Owns `PanelSession`, auth header construction, token redaction, and login response parsing.
- Create: `crates/keli-client-core/src/panel/client.rs`
  Owns `PanelApiTransport`, `PanelApiClient`, request URL construction, login/bootstrap/fallback/config workflow, and test transport helpers.
- Create: `crates/keli-client-core/tests/panel_auth.rs`
  Covers login response parsing, auth header shape, and no-token debug output.
- Create: `crates/keli-client-core/tests/panel_client.rs`
  Covers request execution order, auth header injection, bootstrap fallback, config fetch, and sensitive data redaction.
- Modify: `crates/keli-desktop/src/panel.rs`
  Adds desktop result DTOs for panel connect/config import status.
- Modify: `crates/keli-desktop/src/service.rs`
  Adds a method that imports a panel-fetched config through existing config preflight and runtime update logic.
- Modify: `crates/keli-desktop/src/commands.rs`
  Exposes panel config import on command service.
- Modify: `crates/keli-desktop/src/app.rs`
  Adds controller methods to apply a loaded panel snapshot and import fetched panel config without touching subscription URL compatibility.
- Modify: `crates/keli-desktop-shell/src/actions.rs`
  Adds JSON IPC events for panel login fixture and panel config import.
- Modify: `crates/keli-desktop-shell/src/main.rs`
  Dispatches new events and reports Chinese operation status.
- Modify: `crates/keli-desktop-shell/src/html.rs`
  Adds compact Chinese form/buttons for panel endpoint/login and pulling config from selected panel node.

---

## Task 1: Add Panel Auth And Session Contracts

**Files:**
- Modify: `crates/keli-client-core/src/panel/mod.rs`
- Create: `crates/keli-client-core/src/panel/auth.rs`
- Create: `crates/keli-client-core/tests/panel_auth.rs`

- [ ] **Step 1: Write the failing auth tests**

Create `crates/keli-client-core/tests/panel_auth.rs`:

```rust
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
```

- [ ] **Step 2: Run the failing auth tests**

Run: `cargo test -p keli-client-core --test panel_auth -- --test-threads=1`

Expected: FAIL because `panel::auth`, `PanelSession`, and `parse_login_session` do not exist.

- [ ] **Step 3: Implement auth/session**

Create `crates/keli-client-core/src/panel/auth.rs`:

```rust
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::panel::{normalize_api_prefix, normalize_base_url};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelSession {
    pub api_base: String,
    pub api_prefix: String,
    token: String,
    pub email: Option<String>,
}

impl fmt::Debug for PanelSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PanelSession")
            .field("api_base", &self.api_base)
            .field("api_prefix", &self.api_prefix)
            .field("token_redacted", &true)
            .field("email", &self.email)
            .finish()
    }
}

impl PanelSession {
    pub fn new(
        api_base: impl AsRef<str>,
        api_prefix: impl AsRef<str>,
        token: impl Into<String>,
        email: Option<String>,
    ) -> Self {
        Self {
            api_base: normalize_base_url(api_base.as_ref()).unwrap_or_else(|| api_base.as_ref().trim().trim_end_matches('/').to_string()),
            api_prefix: normalize_api_prefix(api_prefix.as_ref()),
            token: token.into(),
            email,
        }
    }

    pub fn authorization_header(&self) -> String {
        format!("Bearer {}", self.token)
    }

    pub fn token_is_empty(&self) -> bool {
        self.token.trim().is_empty()
    }
}

pub fn parse_login_session(
    value: &Value,
    api_base: &str,
    api_prefix: &str,
) -> Option<PanelSession> {
    let data = value.get("data").unwrap_or(value);
    let token = string_value(data, "auth_data")
        .or_else(|| string_value(data, "token"))?;
    let email = data
        .get("user")
        .and_then(|user| string_value(user, "email"))
        .or_else(|| string_value(data, "email"));
    Some(PanelSession::new(api_base, api_prefix, token, email))
}

fn string_value(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
}
```

Modify `crates/keli-client-core/src/panel/mod.rs`:

```rust
pub mod auth;
pub mod endpoint;
pub mod models;
pub mod parse;
pub mod request;

pub use auth::{parse_login_session, PanelSession};
```

- [ ] **Step 4: Run the auth tests**

Run: `cargo test -p keli-client-core --test panel_auth -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Commit Task 1**

Run:

```bash
git add crates/keli-client-core/src/panel/mod.rs crates/keli-client-core/src/panel/auth.rs crates/keli-client-core/tests/panel_auth.rs
git commit -m "feat: add keliboard session contracts"
```

---

## Task 2: Add Panel API Client Workflow With Test Transport

**Files:**
- Modify: `crates/keli-client-core/src/panel/mod.rs`
- Create: `crates/keli-client-core/src/panel/client.rs`
- Create: `crates/keli-client-core/tests/panel_client.rs`

- [ ] **Step 1: Write failing client workflow tests**

Create `crates/keli-client-core/tests/panel_client.rs` with tests that use a fake transport and assert:

```rust
use std::cell::RefCell;

use keli_client_core::panel::{
    PanelApiClient, PanelApiError, PanelApiRequest, PanelApiResponse, PanelApiTransport,
    PanelHttpMethod,
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
        PanelApiResponse::json(200, json!({
            "data": {
                "app": {"name": "Keli"},
                "user": {"email": "user@example.com", "plan_id": 7},
                "subscribe": {"plan": {"name": "Pro"}, "u": 1, "d": 2, "transfer_enable": 10},
                "servers": [{"id": 51, "name": "JP Tokyo 01", "type": "hysteria"}]
            }
        })),
    ]);
    let client = PanelApiClient::new("https://api.example.com", &transport).expect("client");

    let session = client.login("user@example.com", "secret").expect("login");
    let bootstrap = client.bootstrap(&session).expect("bootstrap");

    let requests = transport.requests.borrow();
    assert_eq!(requests[0].method, PanelHttpMethod::Post);
    assert_eq!(requests[0].url, "https://api.example.com/api/v2/passport/auth/login");
    assert!(requests[0].authorization.is_none());
    assert_eq!(requests[1].url, "https://api.example.com/api/v1/app/bootstrap");
    assert_eq!(requests[1].authorization.as_deref(), Some("Bearer token-secret"));
    assert_eq!(bootstrap.account.email, "user@example.com");
    assert_eq!(bootstrap.nodes[0].id, 51);
}

#[test]
fn bootstrap_uses_legacy_fallback_when_app_bootstrap_is_missing() {
    let transport = FakeTransport::with_responses(vec![
        PanelApiResponse::json(404, json!({"message": "missing"})),
        PanelApiResponse::json(200, json!({"data": {"email": "user@example.com"}})),
        PanelApiResponse::json(200, json!({"data": {"plan": {"name": "Pro"}, "u": 1, "d": 2, "transfer_enable": 10}})),
        PanelApiResponse::json(200, json!({"data": [{"id": 51, "name": "JP Tokyo 01", "type": "hysteria"}]})),
    ]);
    let client = PanelApiClient::new("https://api.example.com", &transport).expect("client");
    let session = keli_client_core::panel::PanelSession::new(
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
    let session = keli_client_core::panel::PanelSession::new(
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
```

- [ ] **Step 2: Run failing client tests**

Run: `cargo test -p keli-client-core --test panel_client -- --test-threads=1`

Expected: FAIL because client/transport types do not exist.

- [ ] **Step 3: Implement client workflow**

Create `crates/keli-client-core/src/panel/client.rs` with:

- `PanelApiRequest { method, url, body, authorization }` with custom `Debug` redacting `authorization`.
- `PanelApiResponse { status, body }` plus `json` and `text` constructors for tests.
- `PanelApiTransport` trait with `send`.
- `PanelApiError { kind, message }`.
- `PanelApiClient<T>` that builds URLs from `PanelRequest`, calls transport, parses login/bootstrap, uses legacy fallback on non-2xx or unparsable bootstrap, and returns config text for `/app/config`.

Modify `crates/keli-client-core/src/panel/mod.rs`:

```rust
pub mod client;

pub use client::{
    PanelApiClient, PanelApiError, PanelApiRequest, PanelApiResponse, PanelApiTransport,
};
```

- [ ] **Step 4: Run client tests**

Run: `cargo test -p keli-client-core --test panel_client -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Commit Task 2**

Run:

```bash
git add crates/keli-client-core/src/panel/mod.rs crates/keli-client-core/src/panel/client.rs crates/keli-client-core/tests/panel_client.rs
git commit -m "feat: add keliboard api client workflow"
```

---

## Task 3: Import Panel Config Through Desktop Runtime

**Files:**
- Modify: `crates/keli-desktop/src/panel.rs`
- Modify: `crates/keli-desktop/src/service.rs`
- Modify: `crates/keli-desktop/src/commands.rs`
- Modify: `crates/keli-desktop/src/app.rs`

- [ ] **Step 1: Write failing desktop tests**

Add tests that assert:

- `DesktopRuntimeService::import_panel_config` imports fetched config with existing preflight and selects the panel node name when possible.
- `DesktopShellController::import_panel_config` updates `shell.subscription`, preserves `shell.panel`, and does not write subscription URL persistence.

Use existing `ss_config("JP Tokyo 01")` helpers in `service.rs` and `app.rs`.

- [ ] **Step 2: Run failing desktop tests**

Run:

```bash
cargo test -p keli-desktop import_panel_config -- --test-threads=1
```

Expected: FAIL because methods do not exist.

- [ ] **Step 3: Implement desktop panel config import**

Add `DesktopPanelConfigImportSummary` in `crates/keli-desktop/src/panel.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopPanelConfigImportSummary {
    pub server_id: i64,
    pub server_name: String,
    pub selected_outbound: Option<String>,
    pub usable: bool,
}
```

Add service/command/controller methods that call existing `import_subscription_config(config_text)` and return the updated shell snapshot plus summary.

- [ ] **Step 4: Run desktop tests**

Run:

```bash
cargo test -p keli-desktop import_panel_config -- --test-threads=1
```

Expected: PASS.

- [ ] **Step 5: Commit Task 3**

Run:

```bash
git add crates/keli-desktop/src/panel.rs crates/keli-desktop/src/service.rs crates/keli-desktop/src/commands.rs crates/keli-desktop/src/app.rs
git commit -m "feat: import panel config into desktop runtime"
```

---

## Task 4: Add Shell IPC And Compact Chinese Controls

**Files:**
- Modify: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Write failing shell tests**

Add tests that assert:

- JSON `{"type":"panel-import-config","serverId":51,"serverName":"JP Tokyo 01","configText":"..."}` maps to `DesktopShellUiEvent::PanelImportConfig`.
- `render_shell_html` contains Chinese panel controls: `面板地址`, `账号`, `密码`, `登录面板`, `拉取当前节点配置`.
- Rendered HTML does not include `auth_data`, `token-secret`, or a raw subscribe token.
- Operation success message for panel config import is Chinese.

- [ ] **Step 2: Run failing shell tests**

Run:

```bash
cargo test -p keli-desktop-shell panel_import -- --test-threads=1
```

Expected: FAIL because event/control does not exist.

- [ ] **Step 3: Implement shell events and HTML controls**

Add `PanelImportConfig { server_id: i64, server_name: String, config_text: String }` to `DesktopShellUiEvent`.

Extend `IpcCommand` with `server_id`, `server_name`, and `config_text`.

Dispatch the event through `controller.import_panel_config(server_id, server_name, config_text)` and sync shell snapshot.

Add compact controls in settings or account section using Chinese labels. Keep controls inside existing bounded regions and keep `body { overflow: hidden; }` unchanged.

- [ ] **Step 4: Run shell tests**

Run:

```bash
cargo test -p keli-desktop-shell panel_import -- --test-threads=1
```

Expected: PASS.

- [ ] **Step 5: Commit Task 4**

Run:

```bash
git add crates/keli-desktop-shell/src/actions.rs crates/keli-desktop-shell/src/main.rs crates/keli-desktop-shell/src/html.rs
git commit -m "feat: add panel config shell actions"
```

---

## Task 5: Verification And Push

**Files:**
- No source files expected unless formatting changes tracked Rust files.

- [ ] **Step 1: Run client-core panel tests**

Run:

```bash
cargo test -p keli-client-core -- --test-threads=1
```

Expected: PASS.

- [ ] **Step 2: Run desktop tests**

Run:

```bash
cargo test -p keli-desktop -- --test-threads=1
```

Expected: PASS.

- [ ] **Step 3: Run desktop shell tests**

Run:

```bash
cargo test -p keli-desktop-shell -- --test-threads=1
```

Expected: PASS.

- [ ] **Step 4: Run smoke**

Run:

```bash
cargo run -q -p keli-desktop-shell -- --smoke
```

Expected: PASS JSON with `"status": "passed"`.

- [ ] **Step 5: Format and whitespace check**

Run:

```bash
cargo fmt
git diff --check
```

Expected: no formatting error and no whitespace output.

- [ ] **Step 6: Commit formatting if needed and push**

If `cargo fmt` changes files, commit with:

```bash
git add crates/keli-client-core crates/keli-desktop crates/keli-desktop-shell
git commit -m "style: format keliboard api connection"
```

Then push:

```bash
git push origin main
```

---

## Self-Review

Spec coverage:

- Login/session is covered by Task 1 and Task 2.
- Bootstrap and legacy fallback are covered by Task 2.
- `/api/v1/app/config` Windows sing-box config fetch is covered by Task 2.
- Existing runtime preflight/import is preserved by Task 3.
- Shell IPC and Chinese compact controls are covered by Task 4.
- Store/payment/ticket workflows are intentionally outside this phase because the main connection loop must become stable first.

Placeholder scan:

- The plan has no "TBD" or deferred code-path markers.
- Every task includes concrete files, commands, expected results, and commit messages.

Type consistency:

- `PanelSession` is introduced before `PanelApiClient` uses it.
- `DesktopPanelConfigImportSummary` is introduced before command/controller/shell events reference it.
- Shell events refer to config text already fetched or pasted by UI/dev flow; raw keliboard HTTP route details remain in `keli-client-core::panel`.
