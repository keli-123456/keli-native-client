# Desktop Operation Status Unification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one visible desktop operation status line that summarizes the most recent user-facing action across subscription, dependency, support export, and primary shell controls.

**Architecture:** Keep existing per-section status lines. Add a top-level operation status element and a generic `window.keliSetOperationStatus` hook, then have existing section status setters mirror their result to the unified line. Add a Rust helper for generic action success/failure messages used by shell actions that do not already have a dedicated section status setter.

**Tech Stack:** Rust 2021, existing `keli-desktop-shell` WebView HTML/JavaScript, existing Wry script evaluation flow, `serde_json`.

---

## Scope Check

This slice covers:

- Top-level `#operation-status` in the desktop window.
- JavaScript `window.keliSetOperationStatus` hook with success/error/info tones.
- Existing subscription, Wintun, and support status setters mirroring their label to the unified line.
- Generic Rust `operation_status_script` helper for primary, refresh, node selection, traffic mode, dependency action, and error paths.
- Focused shell tests plus desktop MVP/public release gate verification.

This slice does not cover:

- Changing core runtime behavior.
- Persisting operation history.
- Adding toast notifications.
- Signing certificates or public release signing.

## File Structure

- Modify: `crates/keli-desktop-shell/src/html.rs`
  - Add the operation status element, CSS tone styles, JS hook, script helper, and tests.
- Modify: `crates/keli-desktop-shell/src/main.rs`
  - Sync generic operation success/failure messages for actions that do not already use a dedicated status setter.

## Task 1: RED Operation Status Tests

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add HTML tests**

Add tests asserting:

```rust
#[test]
fn operation_status_html_includes_unified_target_and_setter() {
    let html = render_shell_html(&snapshot());

    assert!(html.contains("id=\"operation-status\""));
    assert!(html.contains("window.keliSetOperationStatus"));
    assert!(html.contains("data-kind=\"info\""));
}

#[test]
fn existing_status_setters_mirror_to_operation_status() {
    let html = render_shell_html(&snapshot());

    assert!(html.contains("window.keliSetOperationStatus({ kind:"));
    assert!(html.contains("document.getElementById(\"operation-status\")"));
}
```

- [ ] **Step 2: Add script helper test**

Add:

```rust
#[test]
fn operation_status_script_reports_kind_and_message() {
    let script = operation_status_script("error", "Start failed")
        .expect("operation status script");

    assert!(script.contains("window.keliSetOperationStatus"));
    assert!(script.contains("\"kind\":\"error\""));
    assert!(script.contains("Start failed"));
}
```

- [ ] **Step 3: Run RED tests**

Run:

```powershell
cargo test -p keli-desktop-shell operation_status -- --nocapture
```

Expected: FAIL because the unified status target and helper do not exist.

## Task 2: Implement HTML And Script Helper

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add operation status markup**

Add below the header:

```html
<div class="operation-status" id="operation-status" data-kind="info">Ready</div>
```

- [ ] **Step 2: Add CSS tones**

Add `.operation-status`, `.operation-status[data-kind="success"]`, and `.operation-status[data-kind="error"]` styles using the existing restrained desktop palette.

- [ ] **Step 3: Add JavaScript setter**

Add:

```javascript
window.keliSetOperationStatus = (summary) => {
  const status = document.getElementById("operation-status");
  const kind = summary.kind || "info";
  status.dataset.kind = kind;
  status.textContent = summary.message || "Ready";
};
```

- [ ] **Step 4: Mirror dedicated status setters**

Inside existing setters, after computing each label, call:

```javascript
window.keliSetOperationStatus({ kind: "success", message: label });
```

Use `kind: "error"` for error branches.

- [ ] **Step 5: Add Rust helper**

Add:

```rust
#[derive(serde::Serialize)]
struct OperationStatus<'a> {
    kind: &'a str,
    message: &'a str,
}

pub fn operation_status_script(kind: &str, message: &str) -> serde_json::Result<String> {
    let status = OperationStatus { kind, message };
    let status_json = serde_json::to_string(&status)?;
    Ok(format!(
        "window.keliSetOperationStatus && window.keliSetOperationStatus({status_json});"
    ))
}
```

- [ ] **Step 6: Run focused tests**

Run:

```powershell
cargo test -p keli-desktop-shell operation_status -- --nocapture
```

Expected: PASS.

## Task 3: Sync Generic Shell Action Status

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Import the helper**

Import `operation_status_script` from `html`.

- [ ] **Step 2: Add sync helper**

Add:

```rust
fn sync_operation_status(webview: &WebView, kind: &str, message: &str) {
    match operation_status_script(kind, message) {
        Ok(script) => {
            if let Err(error) = webview.evaluate_script(&script) {
                eprintln!("operation status sync failed: {error}");
            }
        }
        Err(error) => {
            eprintln!("operation status serialization failed: {error}");
        }
    }
}
```

- [ ] **Step 3: Add action label helper**

Add a helper that maps:

- `Refresh` to `Status refreshed`.
- `Action(RequestStart)` to `Start requested`.
- `Action(RequestStop)` to `Stop requested`.
- `SelectNode(tag)` to `Selected node {tag}`.
- `SetTrafficMode(mode)` to `Traffic mode set`.
- `DependencyAction(action)` to `Dependency action opened: {action}`.

- [ ] **Step 4: Call the helper on success and failure**

In `handle_ui_event`, call `sync_operation_status(webview, "success", ...)` after generic successful dispatches and dependency action success. On generic errors and dedicated-handler errors that only log today, call `sync_operation_status(webview, "error", &message)`.

- [ ] **Step 5: Run focused tests**

Run:

```powershell
cargo test -p keli-desktop-shell operation_status -- --nocapture
```

Expected: PASS.

## Task 4: Verify, Commit, Push

**Files:**
- `crates/keli-desktop-shell/src/html.rs`
- `crates/keli-desktop-shell/src/main.rs`
- `docs/superpowers/plans/2026-06-12-desktop-operation-status-unification.md`

- [ ] **Step 1: Format and shell tests**

Run:

```powershell
cargo fmt
cargo test -p keli-desktop-shell
```

Expected: PASS.

- [ ] **Step 2: Desktop MVP and public release gates**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
```

Expected: MVP gate PASS. Public release gate remains blocked only by `artifact-signature-missing` and `signing-certificate-missing`; readiness reports `machine_takeover_status` as `ready`.

- [ ] **Step 3: Commit and push**

Run:

```powershell
git add crates\keli-desktop-shell\src\html.rs crates\keli-desktop-shell\src\main.rs docs\superpowers\plans\2026-06-12-desktop-operation-status-unification.md
git commit -m "Unify desktop operation status"
git push origin main
```

## Self-Review

- Spec coverage: covers the user-facing unification request without touching core runtime behavior.
- Placeholder scan: no TBD/TODO/fill-in items.
- Type consistency: helper names match `operation_status_script` and `window.keliSetOperationStatus`.
