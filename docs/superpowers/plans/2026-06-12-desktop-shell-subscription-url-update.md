# Desktop Shell Subscription URL Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the Windows desktop shell update a running subscription URL through the same native command host that already imports subscription URLs.

**Architecture:** Keep `DesktopNativeCommandService` as the only backend command boundary. Add an update-subscription-url IPC event, expose it through `DesktopShellController`, and render a small shell control plus status script so the webview can display whether a running update was applied while preserving runtime state.

**Tech Stack:** Rust 2021, serde DTOs, existing `DesktopSubscriptionUrlUpdateSummary`, wry IPC, existing desktop shell HTML tests.

---

## Scope Check

This plan covers:

- JSON IPC for `{"type":"update-subscription-url","subscriptionUrl":"..."}`.
- `DesktopShellCommandHost::update_subscription_url` and `DesktopShellController::update_subscription_url`.
- Webview status script `window.keliSetSubscriptionUrlUpdate`.
- HTML controls for import while stopped and update while running.
- Tests in `actions.rs`, `app.rs`, and `html.rs`.

This plan does not cover:

- Background scheduled subscription refresh.
- Persisting the subscription URL.
- New installer behavior or real network panel integration beyond the existing runtime service.

## File Structure

- Modify: `crates/keli-desktop-shell/src/actions.rs`
  - Add `DesktopShellUiEvent::UpdateSubscriptionUrl(String)` and JSON command mapping.
- Modify: `crates/keli-desktop/src/app.rs`
  - Add update URL command-host method and controller method.
- Modify: `crates/keli-desktop-shell/src/html.rs`
  - Add update button, status script, and JS status formatter.
- Modify: `crates/keli-desktop-shell/src/main.rs`
  - Route `UpdateSubscriptionUrl` to the controller and sync the status script.

## Task 1: RED Tests

**Files:**
- Modify: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop/src/app.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add failing IPC test**

Add `subscription_ipc_update_url_json_maps_to_update_url_event` expecting:

```rust
assert_eq!(
    ipc_event_for_message(
        r#"{"type":"update-subscription-url","subscriptionUrl":"https://sub.example.com/panel?token=secret"}"#,
        &shell(DesktopRunState::Running, true),
    ),
    Some(DesktopShellUiEvent::UpdateSubscriptionUrl(
        "https://sub.example.com/panel?token=secret".to_string()
    ))
);
```

- [ ] **Step 2: Add failing controller test**

Add `shell_subscription_url_update_calls_host_and_updates_shell_snapshot` expecting:

```rust
let updated = controller
    .update_subscription_url("https://sub.example.com/panel?token=secret")
    .expect("update subscription URL");
assert!(updated.applied);
assert_eq!(controller.snapshot().status.selected_outbound.as_deref(), Some("URL-STAY"));
assert_eq!(
    controller
        .snapshot()
        .subscription
        .as_ref()
        .and_then(|subscription| subscription.selected_outbound.as_deref()),
    Some("URL-STAY")
);
```

- [ ] **Step 3: Add failing shell HTML tests**

Add tests expecting:

```rust
assert!(html.contains("id=\"update-subscription-url-button\""));
assert!(html.contains("update-subscription-url"));
assert!(html.contains("window.keliSetSubscriptionUrlUpdate"));
```

and:

```rust
let script = subscription_url_update_status_script(&summary)
    .expect("subscription URL update script");
assert!(script.contains("window.keliSetSubscriptionUrlUpdate"));
assert!(script.contains("selected-outbound-preserved"));
assert!(!script.contains("token=secret"));
```

- [ ] **Step 4: Run RED tests**

Run: `cargo test -p keli-desktop-shell subscription_url -- --test-threads=1`

Expected: FAIL because the update IPC event, controller method, and status script do not exist.

## Task 2: Implement URL Update Path

**Files:**
- Modify: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop/src/app.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add IPC event**

Add:

```rust
UpdateSubscriptionUrl(String),
```

and map:

```rust
"update-subscription-url" => command
    .subscription_url
    .map(DesktopShellUiEvent::UpdateSubscriptionUrl),
```

- [ ] **Step 2: Add command host and controller method**

Extend `DesktopShellCommandHost` with:

```rust
fn update_subscription_url(
    &mut self,
    url: String,
    timeout: Duration,
    max_bytes: usize,
) -> Result<DesktopSubscriptionUrlUpdateSummary, DesktopCommandError>;
```

Add `DesktopShellController::update_subscription_url` that calls the host, refreshes the shell status from `runtime_status`, and refreshes subscription only when the update was applied.

- [ ] **Step 3: Add HTML control and script**

Add `postUpdateSubscriptionUrl()`, `window.keliSetSubscriptionUrlUpdate`, `subscription_url_update_status_script`, and an `Update URL` button with id `update-subscription-url-button`.

- [ ] **Step 4: Route main event**

Handle `DesktopShellUiEvent::UpdateSubscriptionUrl(url)` in `main.rs` by calling the controller, evaluating `subscription_url_update_status_script`, syncing the webview, and preserving the current quit/window behavior.

- [ ] **Step 5: Run GREEN tests**

Run: `cargo test -p keli-desktop-shell subscription_url -- --test-threads=1`

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `crates/keli-desktop-shell/src/actions.rs`
- `crates/keli-desktop-shell/src/html.rs`
- `crates/keli-desktop-shell/src/main.rs`
- `crates/keli-desktop/src/app.rs`
- `docs/superpowers/plans/2026-06-12-desktop-shell-subscription-url-update.md`

- [ ] **Step 1: Format**

Run: `cargo fmt --check`

Expected: PASS.

- [ ] **Step 2: Whitespace**

Run: `git diff --check`

Expected: PASS.

- [ ] **Step 3: Focused tests**

Run:

```powershell
cargo test -p keli-desktop-shell subscription_url -- --test-threads=1
cargo test -p keli-desktop app::tests::shell_subscription_url_update_calls_host_and_updates_shell_snapshot -- --test-threads=1
```

Expected: PASS.

- [ ] **Step 4: Package gate**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1`

Expected: PASS.

- [ ] **Step 5: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-shell-subscription-url-update.md
git commit -m "Plan desktop shell subscription URL update"
git push origin main
git add crates/keli-desktop-shell/src/actions.rs crates/keli-desktop-shell/src/html.rs crates/keli-desktop-shell/src/main.rs crates/keli-desktop/src/app.rs
git commit -m "Add desktop shell subscription URL update"
git push origin main
```

## Self-Review Checklist

- Spec coverage: advances the MVP by letting the GUI update a running subscription URL without dropping users to CLI.
- Runtime ownership: the shell uses the existing native command host and does not duplicate subscription update logic.
- UI behavior: import and update share the same URL input but report separate import/update outcomes through one visible status line.
- Scope: no scheduler, persistence, or installer behavior is added in this slice.
