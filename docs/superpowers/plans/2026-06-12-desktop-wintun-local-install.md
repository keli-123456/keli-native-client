# Desktop Wintun Local Install Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a Windows desktop user install Wintun from a downloaded local `wintun.dll` file or extracted Wintun directory through the Keli shell, without running CLI commands.

**Architecture:** Reuse the existing `keli-desktop` dependency wrappers around `keli_platform::install_wintun_library*`. Add a narrow desktop command-host method, controller method, shell IPC event, and UI path input. The shell reports the install summary back into the webview and refreshes dependency state after the attempted install.

**Tech Stack:** Rust 2021, existing `keli-desktop` command/controller boundary, existing `keli-desktop-shell` Wry/Tao webview UI, existing Wintun install DTOs.

---

## Scope Check

This slice covers:

- A typed backend command: install Wintun from a local file or directory path.
- A shell controller method that calls the host and refreshes dependency/status snapshots.
- HTML controls for a local Wintun source path and install button.
- IPC parsing for `{ "type": "install-wintun-path", "sourcePath": "..." }`.
- Webview status script for `DesktopWintunInstallSummary`.
- Shell smoke evidence that the Wintun local install controls exist.
- Focused backend and shell tests.

This slice does not cover:

- Automatic download of Wintun.
- File picker integration.
- Driver elevation prompts.
- Bypassing Wintun DLL API validation.
- Installing unsigned or third-party DLLs.

## File Structure

- Modify: `crates/keli-desktop/src/commands.rs`
  - Add command-service method to install Wintun from file or directory.
  - Map dependency install failures to `DesktopCommandError`.
- Modify: `crates/keli-desktop/src/app.rs`
  - Add host trait method and controller method.
  - Extend fake host tests for path forwarding and dependency refresh.
- Modify: `crates/keli-desktop-shell/src/actions.rs`
  - Add `InstallWintunPath(String)` UI event and JSON IPC parsing.
- Modify: `crates/keli-desktop-shell/src/html.rs`
  - Add Wintun source path input, install button, status label, and status script.
- Modify: `crates/keli-desktop-shell/src/main.rs`
  - Handle Wintun install event, evaluate status script, refresh shell snapshot, and include controls in smoke readiness.

## Task 1: RED Backend Tests

**Files:**
- Modify: `crates/keli-desktop/src/app.rs`
- Modify: `crates/keli-desktop/src/commands.rs`

- [ ] **Step 1: Add controller path install test**

Add to `FakeHostState`:

```rust
wintun_installs: Vec<String>,
```

Initialize it with:

```rust
wintun_installs: Vec::new(),
```

Add helper:

```rust
fn wintun_installs(&self) -> Vec<String> {
    self.inner.borrow().wintun_installs.clone()
}
```

Add trait implementation method:

```rust
fn install_wintun_from_path(
    &mut self,
    source_path: String,
) -> Result<crate::dependencies::DesktopWintunInstallSummary, DesktopCommandError> {
    let mut inner = self.inner.borrow_mut();
    inner.wintun_installs.push(source_path.clone());
    inner.dependencies.first_run.tun_ready = true;
    inner.dependencies.first_run.can_start_tun_mode = true;
    inner.dependencies.first_run.blockers.clear();
    inner.dependencies.tun_backend.state = "ready".to_string();
    inner.dependencies.tun_backend.driver_library_present = true;
    inner.dependencies.tun_backend.driver_api_available = true;
    inner.dependencies.tun_backend.install_required = false;
    inner.dependencies.tun_backend.action = None;
    Ok(crate::dependencies::DesktopWintunInstallSummary {
        status: "ready".to_string(),
        source_kind: "directory".to_string(),
        source_path,
        source_candidates: Vec::new(),
        target_path: "C:\\Program Files\\Keli\\wintun.dll".to_string(),
        copied_bytes: 12345,
        previous_target_present: false,
        driver_api_available: true,
        ready_after_install: true,
    })
}
```

Add test:

```rust
#[test]
fn shell_controller_install_wintun_path_calls_host_and_refreshes_dependencies() {
    let host = FakeHost::new(status(DesktopRunState::Stopped), blocked_dependencies());
    let observed = host.clone();
    let mut controller = DesktopShellController::new(host);

    let summary = controller
        .install_wintun_from_path("C:\\Downloads\\wintun")
        .expect("install Wintun");

    assert_eq!(observed.wintun_installs(), vec!["C:\\Downloads\\wintun".to_string()]);
    assert_eq!(summary.status, "ready");
    assert!(controller.snapshot().dependencies.first_run.tun_ready);
    assert_eq!(controller.snapshot().dependencies.tun_backend.state, "ready");
}
```

- [ ] **Step 2: Add command error mapping test**

Add to `crates/keli-desktop/src/commands.rs` tests:

```rust
#[test]
fn native_command_service_maps_missing_wintun_source_to_install_error() {
    let mut commands = DesktopNativeCommandService::new();

    let error = commands
        .install_wintun_from_path("C:\\definitely-missing-keli-wintun.dll")
        .expect_err("missing Wintun source should fail");

    assert_eq!(error.operation, "install-wintun");
    assert_eq!(error.kind, "dependency");
    assert!(error.message.contains("Wintun source DLL was not found"));
}
```

- [ ] **Step 3: Run RED backend tests**

Run:

```powershell
cargo test -p keli-desktop install_wintun -- --nocapture
```

Expected: FAIL because the host trait, controller method, and native command method do not exist.

## Task 2: Implement Backend Install Command

**Files:**
- Modify: `crates/keli-desktop/src/commands.rs`
- Modify: `crates/keli-desktop/src/app.rs`

- [ ] **Step 1: Add dependency error mapper**

In `DesktopCommandError`, add:

```rust
fn dependency(operation: &'static str, error: crate::dependencies::DesktopDependencyError) -> Self {
    Self {
        operation: operation.to_string(),
        kind: "dependency".to_string(),
        message: format!("{error:?}"),
    }
}
```

- [ ] **Step 2: Add native command method**

Import:

```rust
use std::path::Path;
use crate::dependencies::{install_wintun_from_directory, install_wintun_from_file, DesktopWintunInstallSummary};
```

Add to `DesktopNativeCommandService`:

```rust
pub fn install_wintun_from_path(
    &mut self,
    source_path: impl AsRef<Path>,
) -> Result<DesktopWintunInstallSummary, DesktopCommandError> {
    let source_path = source_path.as_ref();
    if source_path.is_dir() {
        install_wintun_from_directory(source_path, None)
    } else {
        install_wintun_from_file(source_path, None)
    }
    .map_err(|error| DesktopCommandError::dependency("install-wintun", error))
}
```

- [ ] **Step 3: Add controller host method**

In `DesktopShellCommandHost`, add:

```rust
fn install_wintun_from_path(
    &mut self,
    source_path: String,
) -> Result<DesktopWintunInstallSummary, DesktopCommandError>;
```

Implement for `DesktopNativeCommandService` by calling `self.install_wintun_from_path(source_path)`.

Add controller method:

```rust
pub fn install_wintun_from_path(
    &mut self,
    source_path: impl Into<String>,
) -> Result<DesktopWintunInstallSummary, DesktopShellControllerError> {
    let summary = self.host.install_wintun_from_path(source_path.into())?;
    self.shell.refresh_status(self.host.status());
    self.shell.refresh_dependencies(self.host.dependency_report());
    Ok(summary)
}
```

## Task 3: RED Shell UI And IPC Tests

**Files:**
- Modify: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add IPC test**

Add to `actions.rs` tests:

```rust
#[test]
fn install_wintun_path_ipc_maps_to_install_event() {
    assert_eq!(
        ipc_event_for_message(
            r#"{"type":"install-wintun-path","sourcePath":"C:\\Downloads\\wintun"}"#,
            &shell(DesktopRunState::Stopped, true),
        ),
        Some(DesktopShellUiEvent::InstallWintunPath(
            "C:\\Downloads\\wintun".to_string()
        ))
    );
}
```

- [ ] **Step 2: Add HTML and status-script tests**

Add to `html.rs` tests:

```rust
#[test]
fn wintun_install_html_includes_local_path_controls() {
    let html = render_shell_html(&snapshot());

    assert!(html.contains("id=\"wintun-source-path\""));
    assert!(html.contains("install-wintun-path"));
    assert!(html.contains("id=\"wintun-install-status\""));
    assert!(html.contains("window.keliSetWintunInstall"));
}
```

Add:

```rust
#[test]
fn wintun_install_status_script_updates_install_status() {
    let summary = keli_desktop::DesktopWintunInstallSummary {
        status: "ready".to_string(),
        source_kind: "directory".to_string(),
        source_path: "C:\\Downloads\\wintun".to_string(),
        source_candidates: Vec::new(),
        target_path: "C:\\Program Files\\Keli\\wintun.dll".to_string(),
        copied_bytes: 12345,
        previous_target_present: false,
        driver_api_available: true,
        ready_after_install: true,
    };

    let script = wintun_install_status_script(&summary).expect("Wintun install script");

    assert!(script.contains("window.keliSetWintunInstall"));
    assert!(script.contains("ready"));
    assert!(script.contains("wintun.dll"));
}
```

- [ ] **Step 3: Add smoke expectation**

Extend `smoke_report_confirms_shell_rendering_contract`:

```rust
assert!(html.contains("id=\"wintun-source-path\""));
```

Add a failure test similar to the dependency actions smoke test:

```rust
#[test]
fn smoke_report_requires_wintun_install_controls() {
    let snapshot = smoke_snapshot();
    let html = render_shell_html(&snapshot)
        .replace("id=\"wintun-source-path\"", "id=\"missing-wintun-source-path\"");
    let script = shell_snapshot_script(&snapshot).expect("snapshot script");

    let report = build_smoke_report(&snapshot, &html, &script);

    assert_eq!(report.status, "failed");
    assert!(!report.html_ready);
}
```

- [ ] **Step 4: Run RED shell tests**

Run:

```powershell
cargo test -p keli-desktop-shell install_wintun -- --nocapture
cargo test -p keli-desktop-shell smoke_report_requires_wintun_install_controls -- --nocapture
```

Expected: FAIL because the IPC event, status script, and smoke condition are missing.

## Task 4: Implement Shell UI And Event Handling

**Files:**
- Modify: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add IPC event**

Add:

```rust
InstallWintunPath(String),
```

Add `source_path: Option<String>` to `IpcCommand`.

Add parsing:

```rust
"install-wintun-path" => command.source_path.map(DesktopShellUiEvent::InstallWintunPath),
```

- [ ] **Step 2: Add HTML controls**

In the dependency section, add:

```html
<input id="wintun-source-path" type="text" placeholder="C:\Downloads\wintun or C:\Downloads\wintun.dll" />
<div class="actions">
  <button id="install-wintun-path-button" onclick="postInstallWintunPath()">Install Wintun from path</button>
</div>
<div class="muted" id="wintun-install-status">No local Wintun install attempted</div>
```

Add JS:

```javascript
function postInstallWintunPath() {
  postJson({
    type: "install-wintun-path",
    sourcePath: document.getElementById("wintun-source-path").value
  });
}
window.keliSetWintunInstall = (summary) => {
  const label = `${summary.status}: ${summary.target_path || ""} (${summary.copied_bytes || 0} bytes)`;
  document.getElementById("wintun-install-status").textContent = label;
};
```

Add Rust status script:

```rust
pub fn wintun_install_status_script(
    summary: &DesktopWintunInstallSummary,
) -> serde_json::Result<String> {
    let summary_json = serde_json::to_string(summary)?;
    Ok(format!(
        "window.keliSetWintunInstall && window.keliSetWintunInstall({summary_json});"
    ))
}
```

- [ ] **Step 3: Handle install event in shell main**

Import `wintun_install_status_script`.

Add to `handle_ui_event`:

```rust
if let DesktopShellUiEvent::InstallWintunPath(path) = &event {
    match install_wintun_path(controller, path.clone(), webview) {
        Ok(shell) => {
            window.set_visible(shell.window.main_visible);
            sync_webview(webview, &shell);
            if shell.quit_requested {
                *control_flow = ControlFlow::Exit;
            }
        }
        Err(message) => {
            eprintln!("desktop shell Wintun install failed: {message}");
            sync_webview(webview, controller.snapshot());
        }
    }
    return;
}
```

Add helper:

```rust
fn install_wintun_path(
    controller: &mut DesktopShellController<keli_desktop::DesktopNativeCommandService>,
    source_path: String,
    webview: &WebView,
) -> Result<DesktopShellState, String> {
    let installed = controller
        .install_wintun_from_path(source_path)
        .map_err(|error| format!("{} {} {}", error.operation, error.kind, error.message))?;
    let script = wintun_install_status_script(&installed)
        .map_err(|error| format!("Wintun install status serialization failed: {error}"))?;
    webview
        .evaluate_script(&script)
        .map_err(|error| format!("Wintun install status sync failed: {error}"))?;
    Ok(controller.refresh())
}
```

In `dispatch_ui_event`, add:

```rust
DesktopShellUiEvent::InstallWintunPath(_) => Ok(controller.refresh()),
```

Add `id="wintun-source-path"` to `build_smoke_report` HTML readiness.

## Task 5: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-wintun-local-install.md`
- `crates/keli-desktop/src/commands.rs`
- `crates/keli-desktop/src/app.rs`
- `crates/keli-desktop-shell/src/actions.rs`
- `crates/keli-desktop-shell/src/html.rs`
- `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Focused tests**

Run:

```powershell
cargo test -p keli-desktop install_wintun -- --nocapture
cargo test -p keli-desktop-shell install_wintun -- --nocapture
cargo test -p keli-desktop-shell smoke_report_requires_wintun_install_controls -- --nocapture
```

Expected: PASS.

- [ ] **Step 2: Full affected crate tests**

Run:

```powershell
cargo test -p keli-desktop -- --test-threads=1
cargo test -p keli-desktop-shell
```

Expected: PASS.

- [ ] **Step 3: Desktop gate**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1
```

Expected: MVP gate PASS. Public release gate should continue to block only on signing until a code-signing certificate is configured.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-wintun-local-install.md
git commit -m "Plan desktop Wintun local install"
git push origin main
git add crates/keli-desktop/src/commands.rs crates/keli-desktop/src/app.rs crates/keli-desktop-shell/src/actions.rs crates/keli-desktop-shell/src/html.rs crates/keli-desktop-shell/src/main.rs
git commit -m "Add desktop Wintun local install"
git push origin main
```

## Self-Review Checklist

- Spec coverage: Wintun dependency handling moves from external instructions to an in-app install attempt.
- Placeholder scan: paths, event names, method names, and commands are concrete.
- Safety: existing Wintun API validation remains mandatory.
- Scope: no automatic download, no elevation, and no settings mutation are introduced.
