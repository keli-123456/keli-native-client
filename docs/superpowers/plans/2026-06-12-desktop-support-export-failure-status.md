# Desktop Support Export Failure Status Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show support bundle export failures in the diagnostics support-export status area, not only in the global operation status.

**Architecture:** Reuse the existing `window.keliSetSupportExport(summary)` renderer by adding a failure status script that emits `{ status: "failed", error: ... }`. The WebView event error path will call this script before syncing the shell snapshot and global operation error, matching the existing URL and Wintun failure feedback pattern.

**Tech Stack:** Rust desktop shell (`keli-desktop-shell`), serde JSON script generation, existing WebView IPC flow.

---

### Task 1: Failure Script

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Write the failing test**

Add this test in the `html.rs` test module near `support_export_status_script_updates_export_status`:

```rust
#[test]
fn support_export_failure_status_script_reports_error() {
    let script = support_export_failure_status_script("write support bundle failed: access denied")
        .expect("support export failure script");

    assert!(script.contains("window.keliSetSupportExport"));
    assert!(script.contains("\"status\":\"failed\""));
    assert!(script.contains("access denied"));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_failure_status_script_reports_error -- --nocapture
```

Expected: FAIL because `support_export_failure_status_script` is not defined.

- [ ] **Step 3: Implement the failure script**

Add this serializable status next to `SupportBundleSaveSummary` script helpers:

```rust
#[derive(serde::Serialize)]
struct SupportExportFailureStatus<'a> {
    status: &'static str,
    error: &'a str,
}
```

Add this helper:

```rust
pub fn support_export_failure_status_script(error: &str) -> serde_json::Result<String> {
    let status = SupportExportFailureStatus {
        status: "failed",
        error,
    };
    let status_json = serde_json::to_string(&status)?;
    Ok(format!(
        "window.keliSetSupportExport && window.keliSetSupportExport({status_json});"
    ))
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_failure_status_script_reports_error -- --nocapture
```

Expected: PASS.

### Task 2: WebView Error Path

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Wire the failure script**

Import `support_export_failure_status_script` from `html`.

Add:

```rust
fn sync_support_export_failure(webview: &WebView, message: &str) {
    match support_export_failure_status_script(message) {
        Ok(script) => {
            if let Err(error) = webview.evaluate_script(&script) {
                eprintln!("support export failure status sync failed: {error}");
            }
        }
        Err(error) => {
            eprintln!("support export failure status serialization failed: {error}");
        }
    }
}
```

In the `DesktopShellUiEvent::ExportSupportBundle` error branch, call:

```rust
sync_support_export_failure(webview, &message);
```

before `sync_webview`.

- [ ] **Step 2: Run shell tests**

Run:

```powershell
cargo test -p keli-desktop-shell -- --nocapture
```

Expected: PASS.

### Task 3: Gate Verification

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Format and gate**

Run:

```powershell
cargo fmt
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: MVP gate PASS.

- [ ] **Step 2: Check release readiness**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
```

Expected: `machine_takeover_status = "ready"` and public release blockers remain only `artifact-signature-missing` and `signing-certificate-missing`.

### Task 4: Commit

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Commit implementation**

Run:

```powershell
git add crates/keli-desktop-shell/src/html.rs crates/keli-desktop-shell/src/main.rs
git commit -m "Show desktop support export failure status"
git push
```

Expected: commit pushed to `origin/main`.
