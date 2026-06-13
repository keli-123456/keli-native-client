# Support Export Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show support export directory usage in the desktop shell and add a safe cleanup action for Keli-generated support export artifacts.

**Architecture:** Keep filesystem scanning and deletion in `support.rs`, add a dedicated shell IPC event in `actions.rs`, expose small script helpers in `html.rs`, and orchestrate startup/export/cleanup sync from `main.rs`. Cleanup is allowlisted to `keli-support-*` files and `last-support-export.json` only.

**Tech Stack:** Rust 2021, `serde`, `serde_json`, existing Wry WebView bridge, existing `keli-desktop-shell` unit and smoke tests.

---

## File Structure

- Modify `crates/keli-desktop-shell/src/support.rs`
  - Add `SupportExportStorageSummary` and `SupportExportCleanupSummary`.
  - Add artifact discovery, directory summary, and cleanup helpers.
  - Test allowlist behavior and missing-directory handling.
- Modify `crates/keli-desktop-shell/src/actions.rs`
  - Add `DesktopShellUiEvent::ClearSupportExports`.
  - Map IPC message `clear-support-exports`.
- Modify `crates/keli-desktop-shell/src/html.rs`
  - Add support storage status lines and cleanup buttons in legacy and diagnostics support panels.
  - Add `window.keliSetSupportStorage`, `window.keliSetSupportCleanup`, and `postClearSupportExports`.
  - Add script serialization helpers and tests.
- Modify `crates/keli-desktop-shell/src/main.rs`
  - Sync storage summary on startup, after export, and after cleanup.
  - Handle cleanup event with UI success/error feedback.
  - Extend smoke workflow entrypoints to include `clear-support-exports`.

## Task 1: Support Directory Summary And Cleanup

**Files:**
- Modify: `crates/keli-desktop-shell/src/support.rs`

- [ ] **Step 1: Write failing summary test**

Add this test near existing support tests:

```rust
#[test]
fn support_export_directory_summary_counts_only_keli_artifacts() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("keli-support-cleanup-summary-test-{unique}"));
    fs::create_dir_all(&dir).expect("create dir");
    fs::write(dir.join("keli-support-a.json"), b"12345").expect("write bundle");
    fs::write(support_export_record_path(&dir), b"{}").expect("write record");
    fs::write(dir.join("notes.txt"), b"keep").expect("write unrelated");

    let summary = summarize_support_export_directory(&dir).expect("summarize support dir");

    assert_eq!(summary.status, "ready");
    assert_eq!(summary.directory, dir.to_string_lossy());
    assert_eq!(summary.file_count, 2);
    assert_eq!(summary.byte_count, 7);

    let _ = fs::remove_dir_all(dir);
}
```

- [ ] **Step 2: Run summary test to verify red**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_directory_summary_counts_only_keli_artifacts -- --test-threads=1
```

Expected: FAIL because `summarize_support_export_directory` is not defined.

- [ ] **Step 3: Implement summary types and helpers**

Add after `SupportBundleSaveSummary`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupportExportStorageSummary {
    pub status: String,
    pub directory: String,
    pub file_count: usize,
    pub byte_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupportExportCleanupSummary {
    pub status: String,
    pub directory: String,
    pub deleted_count: usize,
    pub reclaimed_bytes: u64,
    pub remaining_count: usize,
    pub remaining_bytes: u64,
}
```

Add helpers before `support_bundle_file_name`:

```rust
pub fn summarize_support_export_directory(
    directory: impl AsRef<Path>,
) -> io::Result<SupportExportStorageSummary> {
    let directory = directory.as_ref();
    let artifacts = support_export_artifacts(directory)?;
    Ok(SupportExportStorageSummary {
        status: "ready".to_string(),
        directory: directory.to_string_lossy().into_owned(),
        file_count: artifacts.len(),
        byte_count: artifacts.iter().map(|artifact| artifact.byte_count).sum(),
    })
}

fn support_export_artifacts(directory: &Path) -> io::Result<Vec<SupportExportArtifact>> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut artifacts = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || !is_support_export_artifact(&path) {
            continue;
        }
        let byte_count = entry.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        artifacts.push(SupportExportArtifact { path, byte_count });
    }
    Ok(artifacts)
}

fn is_support_export_artifact(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name == "last-support-export.json" || name.starts_with("keli-support-")
}

struct SupportExportArtifact {
    path: PathBuf,
    byte_count: u64,
}
```

- [ ] **Step 4: Run summary test to verify green**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_directory_summary_counts_only_keli_artifacts -- --test-threads=1
```

Expected: PASS.

- [ ] **Step 5: Write failing cleanup and missing-directory tests**

Add:

```rust
#[test]
fn support_export_directory_summary_handles_missing_directory() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("keli-support-cleanup-missing-test-{unique}"));

    let summary = summarize_support_export_directory(&dir).expect("summarize missing support dir");

    assert_eq!(summary.file_count, 0);
    assert_eq!(summary.byte_count, 0);
}

#[test]
fn support_export_cleanup_deletes_only_keli_artifacts() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("keli-support-cleanup-delete-test-{unique}"));
    fs::create_dir_all(&dir).expect("create dir");
    let bundle = dir.join("keli-support-a.json");
    let unrelated = dir.join("notes.txt");
    fs::write(&bundle, b"12345").expect("write bundle");
    fs::write(support_export_record_path(&dir), b"{}").expect("write record");
    fs::write(&unrelated, b"keep").expect("write unrelated");

    let summary = clear_support_export_directory(&dir).expect("clear support dir");

    assert_eq!(summary.status, "cleared");
    assert_eq!(summary.deleted_count, 2);
    assert_eq!(summary.reclaimed_bytes, 7);
    assert_eq!(summary.remaining_count, 0);
    assert_eq!(summary.remaining_bytes, 0);
    assert!(!bundle.exists());
    assert!(unrelated.exists());
    assert!(!support_export_record_path(&dir).exists());

    let _ = fs::remove_dir_all(dir);
}
```

- [ ] **Step 6: Run cleanup test to verify red**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_cleanup_deletes_only_keli_artifacts -- --test-threads=1
```

Expected: FAIL because `clear_support_export_directory` is not defined.

- [ ] **Step 7: Implement cleanup**

Add:

```rust
pub fn clear_support_export_directory(
    directory: impl AsRef<Path>,
) -> io::Result<SupportExportCleanupSummary> {
    let directory = directory.as_ref();
    let artifacts = support_export_artifacts(directory)?;
    let mut deleted_count = 0;
    let mut reclaimed_bytes = 0;
    for artifact in artifacts {
        fs::remove_file(&artifact.path)?;
        deleted_count += 1;
        reclaimed_bytes += artifact.byte_count;
    }
    let remaining = summarize_support_export_directory(directory)?;
    Ok(SupportExportCleanupSummary {
        status: "cleared".to_string(),
        directory: directory.to_string_lossy().into_owned(),
        deleted_count,
        reclaimed_bytes,
        remaining_count: remaining.file_count,
        remaining_bytes: remaining.byte_count,
    })
}
```

- [ ] **Step 8: Run support cleanup tests**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_directory -- --test-threads=1
cargo test -p keli-desktop-shell support_export_cleanup -- --test-threads=1
```

Expected: PASS.

- [ ] **Step 9: Commit support cleanup layer**

Run:

```powershell
git add crates/keli-desktop-shell/src/support.rs
git commit -m "feat: summarize and clean support exports"
```

## Task 2: IPC And UI Contract

**Files:**
- Modify: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add failing IPC test**

Add after `support_export_open_directory_ipc_maps_to_open_event`:

```rust
#[test]
fn support_export_cleanup_ipc_maps_to_cleanup_event() {
    assert_eq!(
        ipc_event_for_message(
            "clear-support-exports",
            &shell(DesktopRunState::Stopped, true)
        ),
        Some(DesktopShellUiEvent::ClearSupportExports)
    );
}
```

- [ ] **Step 2: Run IPC test to verify red**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_cleanup_ipc_maps_to_cleanup_event -- --test-threads=1
```

Expected: FAIL because `ClearSupportExports` is not defined.

- [ ] **Step 3: Implement IPC event**

Add enum variant:

```rust
ClearSupportExports,
```

Add match arm:

```rust
"clear-support-exports" => Some(DesktopShellUiEvent::ClearSupportExports),
```

- [ ] **Step 4: Run IPC test to verify green**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_cleanup_ipc_maps_to_cleanup_event -- --test-threads=1
```

Expected: PASS.

- [ ] **Step 5: Add failing HTML tests**

In `diagnostics_baseline_includes_support_settings_and_live_sync`, add:

```rust
assert!(html.contains("id=\"diagnostics-support-storage\""));
assert!(html.contains("id=\"diagnostics-clear-support-button\""));
assert!(html.contains("window.keliSetSupportStorage"));
assert!(html.contains("window.keliSetSupportCleanup"));
```

In `support_export_html_includes_export_button_and_status`, add:

```rust
assert!(html.contains("clear-support-exports"));
assert!(html.contains("id=\"support-export-storage\""));
assert!(html.contains("id=\"clear-support-button\""));
assert!(html.contains("function postClearSupportExports()"));
```

Add script tests:

```rust
#[test]
fn support_export_storage_status_script_updates_storage_status() {
    let summary = crate::support::SupportExportStorageSummary {
        status: "ready".to_string(),
        directory: "C:\\Users\\Administrator\\Documents\\Keli\\Support".to_string(),
        file_count: 2,
        byte_count: 128,
    };

    let script = support_export_storage_status_script(&summary).expect("storage script");

    assert!(script.contains("window.keliSetSupportStorage"));
    assert!(script.contains("\"file_count\":2"));
    assert!(script.contains("\"byte_count\":128"));
}

#[test]
fn support_export_cleanup_status_script_updates_cleanup_status() {
    let summary = crate::support::SupportExportCleanupSummary {
        status: "cleared".to_string(),
        directory: "C:\\Users\\Administrator\\Documents\\Keli\\Support".to_string(),
        deleted_count: 2,
        reclaimed_bytes: 128,
        remaining_count: 0,
        remaining_bytes: 0,
    };

    let script = support_export_cleanup_status_script(&summary).expect("cleanup script");

    assert!(script.contains("window.keliSetSupportCleanup"));
    assert!(script.contains("\"deleted_count\":2"));
    assert!(script.contains("\"reclaimed_bytes\":128"));
}
```

- [ ] **Step 6: Run HTML tests to verify red**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_html_includes_export_button_and_status -- --test-threads=1
cargo test -p keli-desktop-shell support_export_storage_status_script_updates_storage_status -- --test-threads=1
```

Expected: FAIL because UI elements and script helpers are not defined.

- [ ] **Step 7: Implement HTML UI and scripts**

In support panels, add storage lines:

```html
<div class="muted" id="support-export-storage">支持包目录：尚未统计</div>
<div class="muted" id="support-export-cleanup-status">尚未清理支持包</div>
```

and diagnostics equivalents:

```html
<div class="muted" id="diagnostics-support-storage">支持包目录：尚未统计</div>
<div class="muted" id="diagnostics-support-cleanup-status">尚未清理支持包</div>
```

Add buttons:

```html
<button id="clear-support-button" onclick="postClearSupportExports()">清理旧支持包</button>
<button id="diagnostics-clear-support-button" onclick="postClearSupportExports()">清理旧支持包</button>
```

Add JavaScript helpers:

```js
function supportBytesLabel(value) {
  const bytes = Number(value || 0);
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}
function supportStorageLabel(summary) {
  return `支持包目录：${summary.file_count || 0} 个文件，${supportBytesLabel(summary.byte_count)}`;
}
function setSupportCleanupStatus(label) {
  setText("support-export-cleanup-status", label);
  setText("diagnostics-support-cleanup-status", label);
}
function postClearSupportExports() {
  window.ipc.postMessage("clear-support-exports");
  window.keliSetOperationStatus({ kind: "info", message: "正在清理旧支持包" });
}
window.keliSetSupportStorage = (summary) => {
  const label = supportStorageLabel(summary || {});
  setText("support-export-storage", label);
  setText("diagnostics-support-storage", label);
};
window.keliSetSupportCleanup = (summary) => {
  const label = `已清理 ${summary.deleted_count || 0} 个文件，释放 ${supportBytesLabel(summary.reclaimed_bytes)}`;
  setSupportCleanupStatus(label);
  if ((summary.deleted_count || 0) > 0) {
    lastSupportExportDirectory = "";
    setSupportExportLocation("尚未生成", "尚未生成");
    setSupportExportDirectoryEnabled(false);
    setText("support-export-status", "已清理支持包目录");
    setText("diagnostics-support-status", "已清理支持包目录");
  }
  window.keliSetSupportStorage({
    status: "ready",
    directory: summary.directory || "",
    file_count: summary.remaining_count || 0,
    byte_count: summary.remaining_bytes || 0,
  });
  window.keliSetOperationStatus({ kind: "success", message: label });
};
```

Add Rust script helpers:

```rust
pub fn support_export_storage_status_script(
    summary: &crate::support::SupportExportStorageSummary,
) -> serde_json::Result<String> {
    let summary_json = serde_json::to_string(summary)?;
    Ok(format!(
        "window.keliSetSupportStorage && window.keliSetSupportStorage({summary_json});"
    ))
}

pub fn support_export_cleanup_status_script(
    summary: &crate::support::SupportExportCleanupSummary,
) -> serde_json::Result<String> {
    let summary_json = serde_json::to_string(summary)?;
    Ok(format!(
        "window.keliSetSupportCleanup && window.keliSetSupportCleanup({summary_json});"
    ))
}
```

- [ ] **Step 8: Run IPC and HTML tests**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_cleanup_ipc_maps_to_cleanup_event -- --test-threads=1
cargo test -p keli-desktop-shell support_export_html_includes_export_button_and_status -- --test-threads=1
cargo test -p keli-desktop-shell support_export_storage_status_script_updates_storage_status -- --test-threads=1
cargo test -p keli-desktop-shell support_export_cleanup_status_script_updates_cleanup_status -- --test-threads=1
```

Expected: PASS.

- [ ] **Step 9: Commit UI contract**

Run:

```powershell
git add crates/keli-desktop-shell/src/actions.rs crates/keli-desktop-shell/src/html.rs
git commit -m "feat: add support export cleanup controls"
```

## Task 3: Main Process Wiring

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add failing smoke entrypoint assertion**

In `smoke_report_confirms_shell_rendering_contract`, add `"clear-support-exports"` to the expected workflow list after `"export-support-bundle"`.

- [ ] **Step 2: Run smoke report test to verify red**

Run:

```powershell
cargo test -p keli-desktop-shell smoke_report_confirms_shell_rendering_contract -- --test-threads=1
```

Expected: FAIL because `smoke_workflow_entrypoints` does not report `clear-support-exports`.

- [ ] **Step 3: Wire cleanup in main process**

Import new helpers:

```rust
use html::{
    operation_status_script, render_shell_html, shell_snapshot_script,
    subscription_config_import_failure_status_script, subscription_config_import_status_script,
    subscription_url_import_failure_status_script, subscription_url_import_status_script,
    subscription_url_update_failure_status_script, subscription_url_update_status_script,
    support_export_cleanup_status_script, support_export_failure_status_script,
    support_export_status_script, support_export_storage_status_script,
    wintun_install_failure_status_script, wintun_install_status_script,
};
use support::{
    clear_support_export_directory, default_support_export_dir, read_last_support_bundle_export,
    summarize_support_export_directory, write_support_bundle_export,
};
```

Add event handling after open directory:

```rust
if matches!(event, DesktopShellUiEvent::ClearSupportExports) {
    let operation_status = match clear_support_exports(webview) {
        Ok(()) => ("success", "已清理旧支持包".to_string()),
        Err(message) => {
            eprintln!("desktop shell support cleanup failed: {message}");
            ("error", message)
        }
    };
    let shell = controller.refresh();
    window.set_visible(shell.window.main_visible);
    sync_webview(webview, &shell);
    sync_operation_status(webview, operation_status.0, &operation_status.1);
    if shell.quit_requested {
        *control_flow = ControlFlow::Exit;
    }
    return;
}
```

Add dispatch fallback:

```rust
DesktopShellUiEvent::ClearSupportExports => Ok(controller.refresh()),
```

Add sync helpers:

```rust
fn sync_support_export_storage(webview: &WebView) {
    match summarize_support_export_directory(default_support_export_dir()) {
        Ok(summary) => match support_export_storage_status_script(&summary) {
            Ok(script) => {
                if let Err(error) = webview.evaluate_script(&script) {
                    eprintln!("support export storage sync failed: {error}");
                }
            }
            Err(error) => eprintln!("support export storage serialization failed: {error}"),
        },
        Err(error) => eprintln!("support export storage summary failed: {error}"),
    }
}

fn clear_support_exports(webview: &WebView) -> Result<(), String> {
    let summary = clear_support_export_directory(default_support_export_dir())
        .map_err(|error| format!("clear support exports failed: {error}"))?;
    let script = support_export_cleanup_status_script(&summary)
        .map_err(|error| format!("support cleanup status serialization failed: {error}"))?;
    webview
        .evaluate_script(&script)
        .map_err(|error| format!("support cleanup status sync failed: {error}"))
}
```

Call `sync_support_export_storage(&webview)` after `sync_last_support_export(&webview)`.

Call `sync_support_export_storage(webview)` after successful export status script evaluation.

Add smoke entrypoint detection:

```rust
if html.contains("clear-support-exports") && html.contains("id=\"diagnostics-clear-support-button\"") {
    entrypoints.push("clear-support-exports".to_string());
}
```

- [ ] **Step 4: Run smoke report test**

Run:

```powershell
cargo test -p keli-desktop-shell smoke_report_confirms_shell_rendering_contract -- --test-threads=1
```

Expected: PASS.

- [ ] **Step 5: Run support export smoke**

Run:

```powershell
cargo run -q -p keli-desktop-shell -- --support-export-smoke target\desktop-support-export-smoke
```

Expected: PASS.

- [ ] **Step 6: Commit main wiring**

Run:

```powershell
git add crates/keli-desktop-shell/src/main.rs
git commit -m "feat: wire support export cleanup"
```

## Task 4: Full Verification

**Files:**
- Verify full final state.

- [ ] **Step 1: Format**

Run:

```powershell
cargo fmt
```

Expected: exit 0.

- [ ] **Step 2: Desktop shell tests**

Run:

```powershell
cargo test -p keli-desktop-shell -- --test-threads=1
```

Expected: all tests pass.

- [ ] **Step 3: Desktop smoke**

Run:

```powershell
cargo run -q -p keli-desktop-shell -- --smoke
```

Expected: `status` is `passed` and workflow entrypoints include `clear-support-exports`.

- [ ] **Step 4: Support export smoke**

Run:

```powershell
cargo run -q -p keli-desktop-shell -- --support-export-smoke target\desktop-support-export-smoke
```

Expected: `status` is `passed` and `last_record_matches` is `true`.

- [ ] **Step 5: Diff and push**

Run:

```powershell
git diff --check
git status --short
git push origin main
```

Expected: no whitespace errors, clean worktree after commits, push succeeds.

## Self-Review

- Spec coverage: summary, safe cleanup, UI controls, IPC, main process sync, and smoke evidence are covered.
- Placeholder scan: no placeholder markers or vague test instructions remain.
- Type consistency: `SupportExportStorageSummary`, `SupportExportCleanupSummary`, `ClearSupportExports`, and `clear-support-exports` are used consistently across files.
