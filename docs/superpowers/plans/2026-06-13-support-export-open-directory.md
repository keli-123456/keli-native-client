# Support Export Open Directory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show the exported support bundle file and directory in the desktop UI, and add a safe "open directory" action after export succeeds.

**Architecture:** Extend `SupportBundleSaveSummary` with a `directory` field, keep the browser-side UI state disabled until a saved summary arrives, and add a new shell IPC event that opens the application-owned default support export directory from Rust. The webview does not send arbitrary filesystem paths.

**Tech Stack:** Rust, serde, embedded JavaScript in `keli-desktop-shell`, shell unit tests, desktop shell smoke tests.

---

## File Structure

- Modify: `crates/keli-desktop-shell/src/support.rs`
  - Add `directory` to `SupportBundleSaveSummary`.
  - Populate it from the export directory.
  - Extend support writer tests.
- Modify: `crates/keli-desktop-shell/src/actions.rs`
  - Add `OpenSupportExportDirectory` event.
  - Map `open-support-export-dir` IPC message to the event.
  - Add event mapping test.
- Modify: `crates/keli-desktop-shell/src/main.rs`
  - Handle `OpenSupportExportDirectory` by creating and opening `default_support_export_dir()`.
  - Add platform-specific directory launch helper.
  - Update support export smoke test fixture summaries.
- Modify: `crates/keli-desktop-shell/src/html.rs`
  - Render file/directory fields and disabled open-directory buttons.
  - Enable the buttons after successful export.
  - Reset fields and buttons on failure.
  - Add HTML and status-script tests.

No desktop core support bundle JSON code should change.

---

### Task 1: Add Failing Save Summary Directory Test

**Files:**
- Modify: `crates/keli-desktop-shell/src/support.rs`
- Test: `crates/keli-desktop-shell/src/support.rs`

- [ ] **Step 1: Add directory assertion**

In `support_export_writer_creates_json_file_and_reports_path`, after:

```rust
assert!(summary.path.ends_with(".json"));
```

add:

```rust
assert_eq!(summary.directory, dir.to_string_lossy());
```

- [ ] **Step 2: Run focused test and verify it fails**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_writer_creates_json_file_and_reports_path -- --test-threads=1
```

Expected: FAIL because `SupportBundleSaveSummary` has no `directory` field.

- [ ] **Step 3: Add `directory` to `SupportBundleSaveSummary`**

Change the struct to:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupportBundleSaveSummary {
    pub status: String,
    pub path: String,
    pub directory: String,
    pub byte_count: usize,
}
```

In `write_support_bundle_export`, change the returned summary to:

```rust
Ok(SupportBundleSaveSummary {
    status: "saved".to_string(),
    path: path.to_string_lossy().into_owned(),
    directory: directory.to_string_lossy().into_owned(),
    byte_count: export.bytes.len(),
})
```

- [ ] **Step 4: Update existing test fixtures that construct summaries**

Add `directory` to every `SupportBundleSaveSummary` literal:

```rust
directory: "C:\\Temp\\KeliSupport".to_string(),
```

or:

```rust
directory: "C:\\Users\\Administrator\\Documents\\Keli\\Support".to_string(),
```

matching the path fixture around it.

- [ ] **Step 5: Run focused test and verify it passes**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_writer_creates_json_file_and_reports_path -- --test-threads=1
```

Expected: PASS.

---

### Task 2: Add Failing IPC Event Test

**Files:**
- Modify: `crates/keli-desktop-shell/src/actions.rs`
- Test: `crates/keli-desktop-shell/src/actions.rs`

- [ ] **Step 1: Add IPC mapping test**

After `support_export_ipc_maps_to_export_event`, add:

```rust
#[test]
fn support_export_open_directory_ipc_maps_to_open_event() {
    assert_eq!(
        ipc_event_for_message(
            "open-support-export-dir",
            &shell(DesktopRunState::Stopped, true)
        ),
        Some(DesktopShellUiEvent::OpenSupportExportDirectory)
    );
}
```

- [ ] **Step 2: Run focused test and verify it fails**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_open_directory_ipc_maps_to_open_event -- --test-threads=1
```

Expected: FAIL because `OpenSupportExportDirectory` does not exist.

- [ ] **Step 3: Add the event variant**

In `DesktopShellUiEvent`, after `ExportSupportBundle`, add:

```rust
OpenSupportExportDirectory,
```

- [ ] **Step 4: Map the string IPC event**

In `ipc_event_for_message`, after:

```rust
"export-support-bundle" => Some(DesktopShellUiEvent::ExportSupportBundle),
```

add:

```rust
"open-support-export-dir" => Some(DesktopShellUiEvent::OpenSupportExportDirectory),
```

- [ ] **Step 5: Run focused test and verify it passes**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_open_directory_ipc_maps_to_open_event -- --test-threads=1
```

Expected: PASS.

---

### Task 3: Add Failing HTML And Status Script Tests

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Test: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Extend support export HTML test**

In `support_export_html_includes_export_button_and_status`, after the support export status assertion, add:

```rust
assert!(html.contains("id=\"support-export-file\""));
assert!(html.contains("id=\"support-export-directory\""));
assert!(html.contains("id=\"open-support-directory-button\""));
assert!(html.contains("postOpenSupportExportDirectory()"));
assert!(html.contains("打开目录"));
```

- [ ] **Step 2: Extend diagnostics support panel test**

In `diagnostics_baseline_includes_support_settings_and_live_sync`, after the diagnostics support status assertion, add:

```rust
assert!(html.contains("id=\"diagnostics-support-file\""));
assert!(html.contains("id=\"diagnostics-support-directory\""));
assert!(html.contains("id=\"diagnostics-open-support-directory-button\""));
```

- [ ] **Step 3: Extend support export status script test**

Change the summary fixture in `support_export_status_script_updates_export_status` to include:

```rust
directory: "C:\\Users\\Administrator\\Documents\\Keli\\Support".to_string(),
```

Add assertions:

```rust
assert!(script.contains("lastSupportExportDirectory"));
assert!(script.contains("support-export-file"));
assert!(script.contains("diagnostics-support-directory"));
assert!(script.contains("Keli\\\\Support"));
```

- [ ] **Step 4: Extend failure status script test**

In `support_export_failure_status_script_reports_error`, add:

```rust
assert!(script.contains("window.keliSetSupportExport"));
assert!(script.contains("\"status\":\"failed\""));
```

This existing test should continue to pass after the JavaScript reset behavior is added.

- [ ] **Step 5: Run focused tests and verify at least one fails**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_html_includes_export_button_and_status -- --test-threads=1
cargo test -p keli-desktop-shell diagnostics_baseline_includes_support_settings_and_live_sync -- --test-threads=1
cargo test -p keli-desktop-shell support_export_status_script_updates_export_status -- --test-threads=1
```

Expected: at least one FAILS because file/directory fields, open-directory buttons, and JavaScript state are not implemented.

---

### Task 4: Implement HTML State And Directory Button

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Test: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add legacy support file and directory fields**

After:

```html
<div class="muted" id="support-export-status">尚未导出支持包</div>
```

add:

```html
<div class="muted" id="support-export-file">文件：尚未生成</div>
<div class="muted" id="support-export-directory">目录：尚未生成</div>
```

- [ ] **Step 2: Add legacy open directory button**

In the same legacy support actions block, after the export button, add:

```html
<button id="open-support-directory-button" onclick="postOpenSupportExportDirectory()" disabled>打开目录</button>
```

- [ ] **Step 3: Add diagnostics support file and directory fields**

After:

```html
<div class="muted" id="diagnostics-support-status">尚未导出支持包</div>
```

add:

```html
<div class="muted" id="diagnostics-support-file">文件：尚未生成</div>
<div class="muted" id="diagnostics-support-directory">目录：尚未生成</div>
```

- [ ] **Step 4: Add diagnostics open directory button**

In `diagnostics-support-panel`, after the diagnostics export button, add:

```html
<button id="diagnostics-open-support-directory-button" onclick="postOpenSupportExportDirectory()" disabled>打开目录</button>
```

- [ ] **Step 5: Add JavaScript state helpers**

Before `window.keliSetSupportExport = (summary) => {`, add:

```javascript
    let lastSupportExportDirectory = "";
    function setSupportExportLocation(file, directory) {
      setText("support-export-file", `文件：${file}`);
      setText("support-export-directory", `目录：${directory}`);
      setText("diagnostics-support-file", `文件：${file}`);
      setText("diagnostics-support-directory", `目录：${directory}`);
    }
    function setSupportExportDirectoryEnabled(enabled) {
      for (const id of ["open-support-directory-button", "diagnostics-open-support-directory-button"]) {
        const button = document.getElementById(id);
        if (button) button.disabled = !enabled;
      }
    }
    function postOpenSupportExportDirectory() {
      if (!lastSupportExportDirectory) {
        window.keliSetOperationStatus({ kind: "error", message: "请先导出支持包" });
        return;
      }
      window.ipc.postMessage("open-support-export-dir");
      window.keliSetOperationStatus({ kind: "info", message: "正在打开支持包目录" });
    }
```

- [ ] **Step 6: Update support export status setter**

Replace `window.keliSetSupportExport = (summary) => { ... }` with:

```javascript
    window.keliSetSupportExport = (summary) => {
      const saved = summary.status === "saved";
      const label = saved
        ? `已保存 ${summary.byte_count} 字节到 ${summary.path}`
        : `${summary.status}: ${summary.error || summary.path || ""}`;
      const kind = saved ? "success" : "error";
      lastSupportExportDirectory = saved ? (summary.directory || "") : "";
      setSupportExportLocation(
        saved ? (summary.path || "未返回文件路径") : "尚未生成",
        saved ? (summary.directory || "未返回目录") : "尚未生成"
      );
      setSupportExportDirectoryEnabled(Boolean(lastSupportExportDirectory));
      document.getElementById("support-export-status").textContent = label;
      setText("diagnostics-support-status", label);
      window.keliSetOperationStatus({ kind: kind, message: label });
    };
```

- [ ] **Step 7: Run focused HTML tests**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_html_includes_export_button_and_status -- --test-threads=1
cargo test -p keli-desktop-shell diagnostics_baseline_includes_support_settings_and_live_sync -- --test-threads=1
cargo test -p keli-desktop-shell support_export_status_script_updates_export_status -- --test-threads=1
```

Expected: PASS.

---

### Task 5: Handle Open Directory Event In Rust

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`
- Test: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Import `Path`**

Change:

```rust
use std::fs;
```

to:

```rust
use std::fs;
use std::path::Path;
```

- [ ] **Step 2: Handle the event before dependency actions**

In `handle_ui_event`, before the `DependencyAction` branch, add:

```rust
    if matches!(event, DesktopShellUiEvent::OpenSupportExportDirectory) {
        let operation_status = match open_support_export_directory() {
            Ok(()) => ("success", "已打开支持包目录".to_string()),
            Err(message) => {
                eprintln!("desktop shell open support export directory failed: {message}");
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

- [ ] **Step 3: Add dispatch fallback**

In `dispatch_ui_event`, after:

```rust
DesktopShellUiEvent::ExportSupportBundle => Ok(controller.refresh()),
```

add:

```rust
DesktopShellUiEvent::OpenSupportExportDirectory => Ok(controller.refresh()),
```

- [ ] **Step 4: Add open directory helpers**

After `open_dependency_action`, add:

```rust
fn open_support_export_directory() -> Result<(), String> {
    let directory = default_support_export_dir();
    fs::create_dir_all(&directory)
        .map_err(|error| format!("create support export dir {}: {error}", directory.display()))?;
    open_directory_target(&directory)
        .map_err(|error| format!("open support export dir {}: {error}", directory.display()))
}

fn open_directory_target(directory: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer.exe")
            .arg(directory)
            .spawn()?;
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(directory).spawn()?;
        return Ok(());
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open").arg(directory).spawn()?;
        return Ok(());
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", unix)))]
    {
        let _ = directory;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "opening support export directory is unsupported on this platform",
        ))
    }
}
```

- [ ] **Step 5: Update smoke fixture summary literals**

Add `directory` to `SupportBundleSaveSummary` literals in `main.rs` tests:

```rust
directory: "C:\\Temp\\KeliSupport".to_string(),
```

- [ ] **Step 6: Run focused action and main tests**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_open_directory_ipc_maps_to_open_event -- --test-threads=1
cargo test -p keli-desktop-shell support_export_smoke_report_confirms_bundle_shape -- --test-threads=1
```

Expected: PASS.

---

### Task 6: Verify, Commit, And Push

**Files:**
- Modify: `crates/keli-desktop-shell/src/support.rs`
- Modify: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Format Rust code**

Run:

```powershell
cargo fmt
```

Expected: exit code 0.

- [ ] **Step 2: Run full shell tests**

Run:

```powershell
cargo test -p keli-desktop-shell -- --test-threads=1
```

Expected: all tests pass.

- [ ] **Step 3: Run desktop shell smoke**

Run:

```powershell
cargo run -q -p keli-desktop-shell -- --smoke
```

Expected: JSON output contains `"status": "passed"`.

- [ ] **Step 4: Run support export smoke**

Run:

```powershell
cargo run -q -p keli-desktop-shell -- --support-export-smoke target\desktop-support-export-smoke
```

Expected: JSON output contains `"status": "passed"`.

- [ ] **Step 5: Run whitespace check**

Run:

```powershell
git diff --check
```

Expected: exit code 0.

- [ ] **Step 6: Inspect changed files**

Run:

```powershell
git status --short
git diff --stat
```

Expected: implementation changes are limited to `crates/keli-desktop-shell/src/support.rs`, `crates/keli-desktop-shell/src/actions.rs`, `crates/keli-desktop-shell/src/main.rs`, and `crates/keli-desktop-shell/src/html.rs`.

- [ ] **Step 7: Commit implementation**

Run:

```powershell
git add crates/keli-desktop-shell/src/support.rs crates/keli-desktop-shell/src/actions.rs crates/keli-desktop-shell/src/main.rs crates/keli-desktop-shell/src/html.rs
git commit -m "feat: open support export directory from shell"
```

Expected: one implementation commit.

- [ ] **Step 8: Push `main`**

Run:

```powershell
git push origin main
```

Expected: remote `main` advances successfully.
