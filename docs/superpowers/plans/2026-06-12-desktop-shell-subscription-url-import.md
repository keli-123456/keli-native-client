# Desktop Shell Subscription URL Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let users import a subscription URL from the desktop shell UI, fetch it through the existing native backend, update the node list, and show a redacted fetch/import status in the window.

**Architecture:** Reuse the existing `DesktopNativeCommandService::import_subscription_url` backend path. Add a typed controller method, an IPC event, a URL input/button/status area in the shell HTML, and a small WebView status script for `DesktopSubscriptionUrlImportSummary`. Keep the existing config-text import path intact.

**Tech Stack:** Rust 2021, existing `keli-desktop` and `keli-desktop-shell` crates, `serde_json`, Wry IPC.

---

## Scope Check

This slice implements stopped-core subscription URL import from the UI. It does not implement running-core URL update, scheduler refresh, credential storage, or a provider login flow. Running-core URL update is already available in the backend and should get its own UI slice after this import path lands.

## File Structure

- Modify: `crates/keli-desktop/src/app.rs`
  - Extend `DesktopShellCommandHost` and `DesktopShellController` with `import_subscription_url`.
  - Add controller tests proving the shell calls the host and refreshes subscription state.
- Modify: `crates/keli-desktop-shell/src/actions.rs`
  - Add `DesktopShellUiEvent::ImportSubscriptionUrl(String)` and JSON IPC parsing for `{"type":"import-subscription-url","subscriptionUrl":"..."}`.
- Modify: `crates/keli-desktop-shell/src/html.rs`
  - Add URL input/button/status UI and `subscription_url_import_status_script`.
- Modify: `crates/keli-desktop-shell/src/main.rs`
  - Handle `ImportSubscriptionUrl` as a special event that calls the controller, updates the URL status element, then syncs the shell snapshot.

## Task 1: Desktop Controller URL Import

**Files:**
- Modify: `crates/keli-desktop/src/app.rs`

- [ ] **Step 1: Write the failing controller test**

Add these imports in the test module:

```rust
use crate::subscription::{
    DesktopSubscriptionUrlFetchSummary, DesktopSubscriptionUrlImportSummary,
};
```

Add a `url_imports: Vec<String>` field to `FakeHostState`, initialize it to `Vec::new()`, and add this observer method to `impl FakeHost`:

```rust
fn url_imports(&self) -> Vec<String> {
    self.inner.borrow().url_imports.clone()
}
```

Add this method to the fake host implementation:

```rust
fn import_subscription_url(
    &mut self,
    url: String,
    _timeout: std::time::Duration,
    _max_bytes: usize,
) -> Result<DesktopSubscriptionUrlImportSummary, DesktopCommandError> {
    let mut inner = self.inner.borrow_mut();
    inner.url_imports.push(url);
    inner.subscription = subscription("URL-READY");
    inner.status.selected_outbound = Some("URL-READY".to_string());
    Ok(DesktopSubscriptionUrlImportSummary {
        fetch: DesktopSubscriptionUrlFetchSummary {
            ok: true,
            scheme: Some("https".to_string()),
            host: Some("sub.example.com".to_string()),
            port: None,
            default_port: Some(true),
            path_present: Some(true),
            query_present: Some(true),
            http_status: Some(200),
            body_bytes: Some(128),
            elapsed_ms: Some(9),
            error_kind: None,
            error_detail: None,
        },
        subscription: Some(inner.subscription.clone()),
        error: None,
    })
}
```

Add the test:

```rust
#[test]
fn shell_subscription_url_import_calls_host_and_updates_shell_snapshot() {
    let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
    let observed = host.clone();
    let mut controller = DesktopShellController::new(host);

    let imported = controller
        .import_subscription_url("https://sub.example.com/panel?token=secret")
        .expect("import subscription URL");

    assert_eq!(
        observed.url_imports(),
        vec!["https://sub.example.com/panel?token=secret".to_string()]
    );
    assert!(imported.fetch.ok);
    assert_eq!(imported.fetch.host.as_deref(), Some("sub.example.com"));
    assert_eq!(
        controller
            .snapshot()
            .subscription
            .as_ref()
            .and_then(|subscription| subscription.selected_outbound.as_deref()),
        Some("URL-READY")
    );
    assert_eq!(
        controller.snapshot().status.selected_outbound.as_deref(),
        Some("URL-READY")
    );
}
```

- [ ] **Step 2: Run the focused controller test to verify it fails**

Run:

```powershell
cargo test -p keli-desktop shell_subscription_url_import -- --test-threads=1
```

Expected: FAIL because `DesktopShellCommandHost::import_subscription_url` and `DesktopShellController::import_subscription_url` do not exist.

- [ ] **Step 3: Implement controller URL import**

In `crates/keli-desktop/src/app.rs`, add:

```rust
use std::time::Duration;
```

Extend the existing subscription import:

```rust
use crate::subscription::{
    DesktopSubscriptionSummary, DesktopSubscriptionUrlImportSummary,
};
```

Add constants near the trait:

```rust
const DEFAULT_SUBSCRIPTION_URL_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_SUBSCRIPTION_URL_MAX_BYTES: usize = 4 * 1024 * 1024;
```

Add this trait method:

```rust
fn import_subscription_url(
    &mut self,
    url: String,
    timeout: Duration,
    max_bytes: usize,
) -> Result<DesktopSubscriptionUrlImportSummary, DesktopCommandError>;
```

Implement it for `DesktopNativeCommandService`:

```rust
fn import_subscription_url(
    &mut self,
    url: String,
    timeout: Duration,
    max_bytes: usize,
) -> Result<DesktopSubscriptionUrlImportSummary, DesktopCommandError> {
    self.import_subscription_url(&url, timeout, max_bytes)
}
```

Add this controller method:

```rust
pub fn import_subscription_url(
    &mut self,
    url: impl Into<String>,
) -> Result<DesktopSubscriptionUrlImportSummary, DesktopShellControllerError> {
    let imported = self.host.import_subscription_url(
        url.into(),
        DEFAULT_SUBSCRIPTION_URL_TIMEOUT,
        DEFAULT_SUBSCRIPTION_URL_MAX_BYTES,
    )?;
    if let Some(subscription) = imported.subscription.clone() {
        self.shell.refresh_subscription(Some(subscription));
        self.shell.refresh_status(self.host.status());
    }
    Ok(imported)
}
```

- [ ] **Step 4: Run the focused controller test**

Run:

```powershell
cargo test -p keli-desktop shell_subscription_url_import -- --test-threads=1
```

Expected: PASS.

## Task 2: Shell IPC URL Import Event

**Files:**
- Modify: `crates/keli-desktop-shell/src/actions.rs`

- [ ] **Step 1: Write the failing IPC test**

Add this enum variant:

```rust
ImportSubscriptionUrl(String),
```

Add this field to `IpcCommand`:

```rust
subscription_url: Option<String>,
```

Add the test:

```rust
#[test]
fn subscription_ipc_import_url_json_maps_to_import_url_event() {
    assert_eq!(
        ipc_event_for_message(
            r#"{"type":"import-subscription-url","subscriptionUrl":"https://sub.example.com/panel?token=secret"}"#,
            &shell(DesktopRunState::Stopped, true),
        ),
        Some(DesktopShellUiEvent::ImportSubscriptionUrl(
            "https://sub.example.com/panel?token=secret".to_string()
        ))
    );
}
```

- [ ] **Step 2: Run the IPC test to verify it fails**

Run:

```powershell
cargo test -p keli-desktop-shell subscription_ipc_import_url -- --test-threads=1
```

Expected: FAIL because `json_ipc_event` does not map `import-subscription-url`.

- [ ] **Step 3: Implement IPC mapping**

Add this match arm in `json_ipc_event`:

```rust
"import-subscription-url" => command
    .subscription_url
    .map(DesktopShellUiEvent::ImportSubscriptionUrl),
```

- [ ] **Step 4: Run the IPC test**

Run:

```powershell
cargo test -p keli-desktop-shell subscription_ipc_import_url -- --test-threads=1
```

Expected: PASS.

## Task 3: Shell HTML URL Import Controls

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Write the failing HTML tests**

Add `DesktopSubscriptionUrlImportSummary` and `DesktopSubscriptionUrlFetchSummary` to the `use keli_desktop::{...}` import in the test module.

Add tests:

```rust
#[test]
fn subscription_url_html_includes_url_import_controls() {
    let html = render_shell_html(&snapshot());

    assert!(html.contains("id=\"subscription-url\""));
    assert!(html.contains("import-subscription-url"));
    assert!(html.contains("id=\"subscription-url-status\""));
    assert!(html.contains("window.keliSetSubscriptionUrlImport"));
}

#[test]
fn subscription_url_status_script_updates_redacted_fetch_status() {
    let summary = DesktopSubscriptionUrlImportSummary {
        fetch: DesktopSubscriptionUrlFetchSummary {
            ok: true,
            scheme: Some("https".to_string()),
            host: Some("sub.example.com".to_string()),
            port: None,
            default_port: Some(true),
            path_present: Some(true),
            query_present: Some(true),
            http_status: Some(200),
            body_bytes: Some(128),
            elapsed_ms: Some(9),
            error_kind: None,
            error_detail: None,
        },
        subscription: Some(subscription("URL-READY")),
        error: None,
    };

    let script =
        subscription_url_import_status_script(&summary).expect("subscription URL import script");

    assert!(script.contains("window.keliSetSubscriptionUrlImport"));
    assert!(script.contains("sub.example.com"));
    assert!(!script.contains("token=secret"));
}
```

- [ ] **Step 2: Run the HTML tests to verify they fail**

Run:

```powershell
cargo test -p keli-desktop-shell subscription_url -- --test-threads=1
```

Expected: FAIL because the controls and `subscription_url_import_status_script` do not exist.

- [ ] **Step 3: Implement HTML controls and status script**

At the top of `html.rs`, change the `keli_desktop` import to include:

```rust
DesktopSubscriptionUrlImportSummary,
```

In the Subscription section, add this before the config textarea:

```html
        <input id="subscription-url" type="url" placeholder="https://example.com/subscription" />
        <div class="actions">
          <button id="import-subscription-url-button" class="primary" onclick="postImportSubscriptionUrl()">Import URL</button>
        </div>
        <div class="muted" id="subscription-url-status">No subscription URL imported</div>
```

Add CSS for `input` alongside `textarea`:

```css
    input {{
      width: 100%;
      min-height: 34px;
      border: 1px solid #b7c0ca;
      border-radius: 6px;
      padding: 8px 10px;
      background: #ffffff;
      color: #171a1f;
      font: inherit;
      font-size: 13px;
    }}
```

Add this JavaScript function:

```javascript
    function postImportSubscriptionUrl() {{
      postJson({{
        type: "import-subscription-url",
        subscriptionUrl: document.getElementById("subscription-url").value
      }});
    }}
```

Add this JavaScript status setter:

```javascript
    window.keliSetSubscriptionUrlImport = (summary) => {{
      const fetch = summary.fetch || {{}};
      const source = fetch.host
        ? `${{fetch.scheme || "url"}}://${{fetch.host}}`
        : "subscription URL";
      const label = summary.error
        ? `Import failed from ${{source}}: ${{summary.error}}`
        : `Imported ${{summary.subscription ? summary.subscription.supported_count : 0}} nodes from ${{source}}`;
      document.getElementById("subscription-url-status").textContent = label;
    }};
```

Add this Rust helper after `support_export_status_script`:

```rust
pub fn subscription_url_import_status_script(
    summary: &DesktopSubscriptionUrlImportSummary,
) -> serde_json::Result<String> {
    let summary_json = serde_json::to_string(summary)?;
    Ok(format!(
        "window.keliSetSubscriptionUrlImport && window.keliSetSubscriptionUrlImport({summary_json});"
    ))
}
```

- [ ] **Step 4: Run the HTML tests**

Run:

```powershell
cargo test -p keli-desktop-shell subscription_url -- --test-threads=1
```

Expected: PASS.

## Task 4: Shell Main URL Import Dispatch

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Wire the event into main dispatch**

Import the status script:

```rust
use html::{
    render_shell_html, shell_snapshot_script, subscription_url_import_status_script,
    support_export_status_script,
};
```

In `handle_ui_event`, add a special event branch before support export:

```rust
if let DesktopShellUiEvent::ImportSubscriptionUrl(url) = event {
    match import_subscription_url(controller, url, webview) {
        Ok(shell) => {
            window.set_visible(shell.window.main_visible);
            sync_webview(webview, &shell);
            if shell.quit_requested {
                *control_flow = ControlFlow::Exit;
            }
        }
        Err(message) => {
            eprintln!("desktop shell subscription URL import failed: {message}");
            sync_webview(webview, controller.snapshot());
        }
    }
    return;
}
```

Add an exhaustive fallback arm in `dispatch_ui_event`:

```rust
DesktopShellUiEvent::ImportSubscriptionUrl(_) => Ok(controller.refresh()),
```

Add this helper near `export_support_bundle`:

```rust
fn import_subscription_url(
    controller: &mut DesktopShellController<keli_desktop::DesktopNativeCommandService>,
    url: String,
    webview: &WebView,
) -> Result<DesktopShellState, String> {
    let imported = controller
        .import_subscription_url(url)
        .map_err(|error| format!("{} {} {}", error.operation, error.kind, error.message))?;
    let script = subscription_url_import_status_script(&imported)
        .map_err(|error| format!("subscription URL import status serialization failed: {error}"))?;
    webview
        .evaluate_script(&script)
        .map_err(|error| format!("subscription URL import status sync failed: {error}"))?;
    Ok(controller.refresh())
}
```

- [ ] **Step 2: Run the shell crate tests**

Run:

```powershell
cargo test -p keli-desktop-shell
```

Expected: PASS.

## Task 5: Full Verification

**Files:**
- No source changes expected unless verification finds a defect.

- [ ] **Step 1: Format and diff checks**

Run:

```powershell
cargo fmt --check
git diff --check
```

Expected: PASS.

- [ ] **Step 2: Focused desktop and shell tests**

Run:

```powershell
cargo test -p keli-desktop shell_subscription_url_import -- --test-threads=1
cargo test -p keli-desktop-shell subscription_url -- --test-threads=1
cargo test -p keli-desktop-shell subscription_ipc_import_url -- --test-threads=1
```

Expected: all PASS.

- [ ] **Step 3: Full desktop MVP gate**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS. It must still run desktop tests, shell tests, release build, portable package, and install smoke.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add crates\keli-desktop\src\app.rs crates\keli-desktop-shell\src\actions.rs crates\keli-desktop-shell\src\html.rs crates\keli-desktop-shell\src\main.rs
git commit -m "Add desktop shell subscription URL import"
git push origin main
```

## Self-Review Checklist

- Spec coverage: this plan advances the user-facing subscription setup workflow by allowing a normal user to paste a subscription URL and import it from the desktop window without command-line use.
- Placeholder scan: every file, command, expected failure, and expected pass output is concrete.
- Type and command consistency: controller, IPC, HTML, and main-loop code all use `ImportSubscriptionUrl` and `DesktopSubscriptionUrlImportSummary`.
