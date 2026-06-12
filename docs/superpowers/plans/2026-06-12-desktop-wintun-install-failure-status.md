# Desktop Wintun Install Failure Status Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show Wintun local install failures in the desktop UI so users can correct the local path or DLL problem without reading process logs.

**Architecture:** Keep the successful `DesktopWintunInstallSummary` path unchanged. Add a small shell-local serialized status object for failed install attempts and a helper that evaluates the same `window.keliSetWintunInstall(...)` hook used by success. Update the JavaScript label to display `error` when `status` is `failed`.

**Tech Stack:** Rust 2021, existing `keli-desktop-shell` Wry webview glue, existing `window.keliSetWintunInstall` status hook.

---

## Scope Check

This slice covers:

- A shell-local status script for failed Wintun install attempts.
- A Wintun install failure path that updates `#wintun-install-status`.
- JavaScript status rendering that shows the failure message when `summary.error` exists.
- Focused shell tests and desktop MVP/public release gates.

This slice does not cover:

- Changing backend Wintun install validation.
- Adding file picker integration.
- Automatic Wintun downloads.
- Retrying or elevating failed installs.

## File Structure

- Modify: `crates/keli-desktop-shell/src/html.rs`
  - Add `wintun_install_failure_status_script(source_path, error)`.
  - Update `window.keliSetWintunInstall` label logic to render failures.
  - Add tests for failure script content.
- Modify: `crates/keli-desktop-shell/src/main.rs`
  - Evaluate failure script when `install_wintun_path` returns an error.
  - Add a unit test for failure status serialization.

## Task 1: RED Failure Status Tests

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add HTML status-script test**

Add to `html.rs` tests:

```rust
#[test]
fn wintun_install_failure_status_script_updates_install_status() {
    let script = wintun_install_failure_status_script(
        "C:\\Downloads\\missing-wintun.dll",
        "install-wintun dependency Platform(\"Wintun source DLL was not found\")",
    )
    .expect("Wintun install failure script");

    assert!(script.contains("window.keliSetWintunInstall"));
    assert!(script.contains("\"status\":\"failed\""));
    assert!(script.contains("missing-wintun.dll"));
    assert!(script.contains("Wintun source DLL was not found"));
}
```

- [ ] **Step 2: Add main failure serialization test**

Add to `main.rs` tests:

```rust
#[test]
fn wintun_install_failure_script_preserves_source_path_and_error() {
    let script = wintun_install_failure_status_script(
        "C:\\Downloads\\missing-wintun.dll",
        "install-wintun dependency Platform(\"Wintun source DLL was not found\")",
    )
    .expect("failure script");

    assert!(script.contains("missing-wintun.dll"));
    assert!(script.contains("Wintun source DLL was not found"));
}
```

- [ ] **Step 3: Run RED tests**

Run:

```powershell
cargo test -p keli-desktop-shell wintun_install_failure -- --nocapture
```

Expected: FAIL because `wintun_install_failure_status_script` does not exist.

## Task 2: Implement Failure Status Script

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add shell-local failure DTO**

Add:

```rust
#[derive(serde::Serialize)]
struct WintunInstallFailureStatus<'a> {
    status: &'static str,
    source_path: &'a str,
    error: &'a str,
}
```

- [ ] **Step 2: Add failure script function**

Add:

```rust
pub fn wintun_install_failure_status_script(
    source_path: &str,
    error: &str,
) -> serde_json::Result<String> {
    let status = WintunInstallFailureStatus {
        status: "failed",
        source_path,
        error,
    };
    let status_json = serde_json::to_string(&status)?;
    Ok(format!(
        "window.keliSetWintunInstall && window.keliSetWintunInstall({status_json});"
    ))
}
```

- [ ] **Step 3: Update JS status label**

Change `window.keliSetWintunInstall` to:

```javascript
window.keliSetWintunInstall = (summary) => {
  const label = summary.error
    ? `${summary.status}: ${summary.error}`
    : `${summary.status}: ${summary.target_path || ""} (${summary.copied_bytes || 0} bytes)`;
  document.getElementById("wintun-install-status").textContent = label;
};
```

## Task 3: Wire Failure Path

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Import failure script**

Extend the existing html import:

```rust
wintun_install_failure_status_script, wintun_install_status_script,
```

- [ ] **Step 2: Add helper to evaluate failure status**

Add:

```rust
fn sync_wintun_install_failure(webview: &WebView, source_path: &str, message: &str) {
    match wintun_install_failure_status_script(source_path, message) {
        Ok(script) => {
            if let Err(error) = webview.evaluate_script(&script) {
                eprintln!("Wintun install failure status sync failed: {error}");
            }
        }
        Err(error) => {
            eprintln!("Wintun install failure status serialization failed: {error}");
        }
    }
}
```

- [ ] **Step 3: Evaluate failure script on install errors**

Change the Wintun install error branch in `handle_ui_event` to:

```rust
Err(message) => {
    eprintln!("desktop shell Wintun install failed: {message}");
    sync_wintun_install_failure(webview, path, &message);
    sync_webview(webview, controller.snapshot());
}
```

## Task 4: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-wintun-install-failure-status.md`
- `crates/keli-desktop-shell/src/html.rs`
- `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Focused tests**

Run:

```powershell
cargo test -p keli-desktop-shell wintun_install_failure -- --nocapture
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
git add docs/superpowers/plans/2026-06-12-desktop-wintun-install-failure-status.md
git commit -m "Plan desktop Wintun install failure status"
git push origin main
git add crates/keli-desktop-shell/src/html.rs crates/keli-desktop-shell/src/main.rs
git commit -m "Show desktop Wintun install failures"
git push origin main
```

## Self-Review Checklist

- Spec coverage: Wintun dependency handling gives visible feedback for failed setup attempts.
- Placeholder scan: functions, paths, test commands, and status JSON fields are concrete.
- Scope: no backend install behavior changes.
- Safety: the UI shows the error message but does not print secrets or mutate additional system state.
