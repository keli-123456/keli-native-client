# Desktop Subscription Config Import Status Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show local pasted subscription config import success and failure in the desktop UI so users can fix bad YAML or unusable configs without checking logs.

**Architecture:** Keep subscription parsing and controller behavior unchanged. Add a local config status line in the Subscription section, add success and failure status scripts, and route `ImportSubscriptionConfig` through a dedicated shell handler so both success and errors update the webview before the shell snapshot refreshes.

**Tech Stack:** Rust 2021, existing `keli-desktop-shell` webview glue, existing `DesktopSubscriptionSummary`, existing `DesktopShellController::import_subscription_config`.

---

## Scope Check

This slice covers:

- `#subscription-config-status` for local pasted config imports.
- A success script that shows imported supported/skipped node counts.
- A failure script that shows the controller error message.
- Dedicated shell handling for `ImportSubscriptionConfig`.
- Focused shell tests and desktop MVP/public release gates.

This slice does not cover:

- Changing subscription parsing.
- URL subscription import/update behavior.
- Adding a file picker.
- Persisting subscriptions to disk.

## File Structure

- Modify: `crates/keli-desktop-shell/src/html.rs`
  - Add the local config status element and JavaScript hook.
  - Add success/failure script helpers and tests.
- Modify: `crates/keli-desktop-shell/src/main.rs`
  - Handle local config import separately from generic dispatch.
  - Evaluate success or failure status scripts.

## Task 1: RED Status Script And HTML Tests

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add HTML and script tests**

Add to `html.rs` tests:

```rust
#[test]
fn subscription_config_import_html_includes_local_status_target() {
    let html = render_shell_html(&snapshot());

    assert!(html.contains("id=\"subscription-config-status\""));
    assert!(html.contains("window.keliSetSubscriptionConfigImport"));
}

#[test]
fn subscription_config_import_status_script_reports_success_counts() {
    let script = subscription_config_import_status_script(&subscription("SS-READY"))
        .expect("subscription config import status script");

    assert!(script.contains("window.keliSetSubscriptionConfigImport"));
    assert!(script.contains("\"status\":\"imported\""));
    assert!(script.contains("\"supported_count\":1"));
}

#[test]
fn subscription_config_import_failure_status_script_reports_error() {
    let script = subscription_config_import_failure_status_script(
        "import-subscription client InvalidSubscription",
    )
    .expect("subscription config import failure script");

    assert!(script.contains("window.keliSetSubscriptionConfigImport"));
    assert!(script.contains("\"status\":\"failed\""));
    assert!(script.contains("InvalidSubscription"));
}
```

- [ ] **Step 2: Add main serialization test**

Add to `main.rs` tests:

```rust
#[test]
fn subscription_config_import_failure_script_preserves_error() {
    let script = subscription_config_import_failure_status_script(
        "import-subscription client InvalidSubscription",
    )
    .expect("failure script");

    assert!(script.contains("InvalidSubscription"));
}
```

- [ ] **Step 3: Run RED tests**

Run:

```powershell
cargo test -p keli-desktop-shell subscription_config_import -- --nocapture
```

Expected: FAIL because the new status target and script helpers do not exist.

## Task 2: Implement Status Scripts And HTML

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add status element**

Add below the textarea:

```html
<div class="muted" id="subscription-config-status">No local subscription config imported</div>
```

- [ ] **Step 2: Add JavaScript hook**

Add:

```javascript
window.keliSetSubscriptionConfigImport = (summary) => {
  const label = summary.error
    ? `Import failed: ${summary.error}`
    : `Imported ${summary.supported_count || 0} nodes, skipped ${summary.skipped_count || 0}`;
  document.getElementById("subscription-config-status").textContent = label;
};
```

- [ ] **Step 3: Add script helper DTOs**

Add:

```rust
#[derive(serde::Serialize)]
struct SubscriptionConfigImportStatus<'a> {
    status: &'static str,
    supported_count: usize,
    skipped_count: usize,
    default_outbound: Option<&'a str>,
    selected_outbound: Option<&'a str>,
}

#[derive(serde::Serialize)]
struct SubscriptionConfigImportFailureStatus<'a> {
    status: &'static str,
    error: &'a str,
}
```

Add:

```rust
pub fn subscription_config_import_status_script(
    summary: &DesktopSubscriptionSummary,
) -> serde_json::Result<String> {
    let status = SubscriptionConfigImportStatus {
        status: "imported",
        supported_count: summary.supported_count,
        skipped_count: summary.skipped_count,
        default_outbound: summary.default_outbound.as_deref(),
        selected_outbound: summary.selected_outbound.as_deref(),
    };
    let status_json = serde_json::to_string(&status)?;
    Ok(format!(
        "window.keliSetSubscriptionConfigImport && window.keliSetSubscriptionConfigImport({status_json});"
    ))
}

pub fn subscription_config_import_failure_status_script(
    error: &str,
) -> serde_json::Result<String> {
    let status = SubscriptionConfigImportFailureStatus {
        status: "failed",
        error,
    };
    let status_json = serde_json::to_string(&status)?;
    Ok(format!(
        "window.keliSetSubscriptionConfigImport && window.keliSetSubscriptionConfigImport({status_json});"
    ))
}
```

## Task 3: Wire Shell Handler

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Import status helpers**

Add:

```rust
subscription_config_import_failure_status_script,
subscription_config_import_status_script,
```

- [ ] **Step 2: Add import handler branch**

Before URL import handling in `handle_ui_event`, add:

```rust
if let DesktopShellUiEvent::ImportSubscriptionConfig(config_text) = &event {
    match import_subscription_config(controller, config_text.clone(), webview) {
        Ok(shell) => {
            window.set_visible(shell.window.main_visible);
            sync_webview(webview, &shell);
            if shell.quit_requested {
                *control_flow = ControlFlow::Exit;
            }
        }
        Err(message) => {
            eprintln!("desktop shell subscription config import failed: {message}");
            sync_subscription_config_import_failure(webview, &message);
            sync_webview(webview, controller.snapshot());
        }
    }
    return;
}
```

- [ ] **Step 3: Add helper functions**

Add:

```rust
fn import_subscription_config(
    controller: &mut DesktopShellController<keli_desktop::DesktopNativeCommandService>,
    config_text: String,
    webview: &WebView,
) -> Result<DesktopShellState, String> {
    let shell = controller
        .import_subscription_config(config_text)
        .map_err(|error| format!("{} {} {}", error.operation, error.kind, error.message))?;
    if let Some(subscription) = shell.subscription.as_ref() {
        let script = subscription_config_import_status_script(subscription)
            .map_err(|error| format!("subscription config import status serialization failed: {error}"))?;
        webview
            .evaluate_script(&script)
            .map_err(|error| format!("subscription config import status sync failed: {error}"))?;
    }
    Ok(shell)
}

fn sync_subscription_config_import_failure(webview: &WebView, message: &str) {
    match subscription_config_import_failure_status_script(message) {
        Ok(script) => {
            if let Err(error) = webview.evaluate_script(&script) {
                eprintln!("subscription config import failure status sync failed: {error}");
            }
        }
        Err(error) => {
            eprintln!("subscription config import failure status serialization failed: {error}");
        }
    }
}
```

## Task 4: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-subscription-config-import-status.md`
- `crates/keli-desktop-shell/src/html.rs`
- `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Focused tests**

Run:

```powershell
cargo test -p keli-desktop-shell subscription_config_import -- --nocapture
```

Expected: PASS.

- [ ] **Step 2: Full shell tests**

Run:

```powershell
cargo test -p keli-desktop-shell
```

Expected: PASS.

- [ ] **Step 3: Desktop gates**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1
```

Expected: MVP gate PASS. Public release gate blocks only on signing.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-subscription-config-import-status.md
git commit -m "Plan desktop subscription config import status"
git push origin main
git add crates/keli-desktop-shell/src/html.rs crates/keli-desktop-shell/src/main.rs
git commit -m "Show desktop subscription config import status"
git push origin main
```

## Self-Review Checklist

- Spec coverage: local subscription config import gives visible success and failure feedback.
- Placeholder scan: event names, script helper names, and expected commands are concrete.
- Scope: subscription parsing and runtime update semantics are unchanged.
- Secret safety: failure messages do not introduce new token exposure beyond existing controller errors.
