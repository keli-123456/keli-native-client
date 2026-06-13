# Desktop Settings Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist desktop Settings view preferences, restore them on launch, and apply the saved default traffic mode to the existing desktop controller.

**Architecture:** Keep shell-only preferences in a new `keli-desktop-shell/src/settings.rs` module, stored as JSON beside existing `%APPDATA%\Keli` desktop persistence. Route a single `save-desktop-settings` IPC command through `actions.rs`, let `main.rs` load/apply/sync settings, and keep `html.rs` responsible for collecting form values and updating the UI.

**Tech Stack:** Rust 2021, `serde`, `serde_json`, existing Wry/Tao desktop shell, existing `keli_desktop::DesktopTrafficMode`.

---

## File Structure

- Create: `crates/keli-desktop-shell/src/settings.rs`
  - Owns `DesktopShellSettings`, JSON read/write helpers, default path, and save summary.
- Modify: `crates/keli-desktop-shell/src/actions.rs`
  - Adds `SaveDesktopSettings` event and JSON mapping.
- Modify: `crates/keli-desktop-shell/src/html.rs`
  - Adds Settings save UI, JS collection/posting, and `window.keliSetDesktopSettings`.
- Modify: `crates/keli-desktop-shell/src/main.rs`
  - Loads settings on startup, applies traffic mode, handles save IPC, syncs WebView, and adds smoke evidence.
- Add docs: `docs/superpowers/specs/2026-06-13-desktop-settings-persistence-design.md`
  - Captures scope and non-goals for this slice.
- Add plan: `docs/superpowers/plans/2026-06-13-desktop-settings-persistence.md`
  - Tracks this implementation.

## Task 1: Settings Persistence Module

**Files:**
- Create: `crates/keli-desktop-shell/src/settings.rs`

- [ ] **Step 1: Write failing persistence tests**

Add tests at the bottom of `settings.rs`:

```rust
#[test]
fn desktop_settings_round_trip_persists_form_values() {
    let dir = test_dir("round-trip");
    let path = dir.join("desktop-settings.json");
    let settings = DesktopShellSettings {
        traffic_mode: DesktopTrafficMode::Tun,
        start_with_windows: true,
        launch_minimized: false,
        auto_start_core: true,
        mixed_port: 17890,
        socks_port: 17891,
        http_port: 17892,
        dns_mode: "redir-host".to_string(),
        tun_stack: "gvisor".to_string(),
    };

    let summary = write_desktop_shell_settings(&path, &settings).expect("write settings");
    let restored = read_desktop_shell_settings(&path).expect("read settings");

    assert_eq!(summary.status, "saved");
    assert_eq!(summary.path, path.to_string_lossy());
    assert_eq!(summary.settings, settings);
    assert_eq!(restored, settings);

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn desktop_settings_reader_uses_default_for_missing_or_invalid_json() {
    let dir = test_dir("invalid");
    let missing = dir.join("missing.json");
    let invalid = dir.join("invalid.json");
    std::fs::create_dir_all(&dir).expect("create dir");
    std::fs::write(&invalid, b"{not-json").expect("write invalid");

    assert_eq!(
        read_desktop_shell_settings(&missing).expect("read missing"),
        DesktopShellSettings::default()
    );
    assert_eq!(
        read_desktop_shell_settings(&invalid).expect("read invalid"),
        DesktopShellSettings::default()
    );

    let _ = std::fs::remove_dir_all(dir);
}
```

- [ ] **Step 2: Run tests and confirm the module is missing**

Run: `cargo test -p keli-desktop-shell desktop_settings_ -- --test-threads=1`

Expected: FAIL because `settings.rs` is not wired or the types do not exist yet.

- [ ] **Step 3: Implement the module**

Create `settings.rs` with:

```rust
use std::io;
use std::path::{Path, PathBuf};

use keli_desktop::DesktopTrafficMode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopShellSettings {
    pub traffic_mode: DesktopTrafficMode,
    pub start_with_windows: bool,
    pub launch_minimized: bool,
    pub auto_start_core: bool,
    pub mixed_port: u16,
    pub socks_port: u16,
    pub http_port: u16,
    pub dns_mode: String,
    pub tun_stack: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopShellSettingsSaveSummary {
    pub status: String,
    pub path: String,
    pub settings: DesktopShellSettings,
}

impl Default for DesktopShellSettings {
    fn default() -> Self {
        Self {
            traffic_mode: DesktopTrafficMode::MixedInboundOnly,
            start_with_windows: false,
            launch_minimized: true,
            auto_start_core: false,
            mixed_port: 7890,
            socks_port: 7891,
            http_port: 7892,
            dns_mode: "fake-ip".to_string(),
            tun_stack: "system".to_string(),
        }
    }
}

pub fn default_desktop_shell_settings_path() -> PathBuf {
    if let Some(app_data) = std::env::var_os("APPDATA") {
        return PathBuf::from(app_data)
            .join("Keli")
            .join("desktop-settings.json");
    }
    std::env::temp_dir()
        .join("keli")
        .join("desktop-settings.json")
}

pub fn read_desktop_shell_settings(path: impl AsRef<Path>) -> io::Result<DesktopShellSettings> {
    match std::fs::read(&path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).unwrap_or_default()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(DesktopShellSettings::default()),
        Err(error) => Err(error),
    }
}

pub fn write_desktop_shell_settings(
    path: impl AsRef<Path>,
    settings: &DesktopShellSettings,
) -> io::Result<DesktopShellSettingsSaveSummary> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(settings)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    std::fs::write(path, bytes)?;
    Ok(DesktopShellSettingsSaveSummary {
        status: "saved".to_string(),
        path: path.to_string_lossy().into_owned(),
        settings: settings.clone(),
    })
}
```

- [ ] **Step 4: Run module tests**

Run: `cargo test -p keli-desktop-shell desktop_settings_ -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Commit module**

```bash
git add crates/keli-desktop-shell/src/settings.rs
git commit -m "feat: persist desktop shell settings"
```

## Task 2: IPC and HTML Contract

**Files:**
- Modify: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add failing IPC and HTML assertions**

In `actions.rs`, add a test that sends:

```rust
r#"{"type":"save-desktop-settings","settings":{"traffic_mode":"tun","start_with_windows":true,"launch_minimized":false,"auto_start_core":true,"mixed_port":17890,"socks_port":17891,"http_port":17892,"dns_mode":"redir-host","tun_stack":"gvisor"}}"#
```

Expected event:

```rust
Some(DesktopShellUiEvent::SaveDesktopSettings(DesktopShellSettings {
    traffic_mode: DesktopTrafficMode::Tun,
    start_with_windows: true,
    launch_minimized: false,
    auto_start_core: true,
    mixed_port: 17890,
    socks_port: 17891,
    http_port: 17892,
    dns_mode: "redir-host".to_string(),
    tun_stack: "gvisor".to_string(),
}))
```

In `html.rs`, extend the settings baseline test to require:

```rust
assert!(html.contains("id=\"settings-save-button\""));
assert!(html.contains("id=\"settings-save-status\""));
assert!(html.contains("postSaveDesktopSettings()"));
assert!(html.contains("save-desktop-settings"));
assert!(html.contains("window.keliSetDesktopSettings"));
assert!(html.contains("collectDesktopSettings()"));
```

- [ ] **Step 2: Run focused tests and confirm failures**

Run: `cargo test -p keli-desktop-shell settings_baseline subscription_ipc_save -- --test-threads=1`

Expected: FAIL because IPC/UI save contract does not exist.

- [ ] **Step 3: Implement IPC mapping**

In `actions.rs`:

```rust
use crate::settings::DesktopShellSettings;

pub enum DesktopShellUiEvent {
    ...
    SaveDesktopSettings(DesktopShellSettings),
}

struct IpcCommand {
    ...
    settings: Option<DesktopShellSettings>,
}

"save-desktop-settings" => command.settings.map(DesktopShellUiEvent::SaveDesktopSettings),
```

- [ ] **Step 4: Implement HTML controls and JS**

Add a save button/status inside the Settings network panel actions:

```html
<div class="actions">
  <button id="settings-save-button" class="primary" onclick="postSaveDesktopSettings()">保存设置</button>
  <span class="muted" id="settings-save-status">设置尚未保存</span>
</div>
```

Add JS:

```js
function numberFieldValue(id, fallback) {
  const value = Number(document.getElementById(id)?.value || fallback);
  return Number.isFinite(value) && value > 0 ? Math.min(65535, Math.trunc(value)) : fallback;
}

function checkedFieldValue(id) {
  return Boolean(document.getElementById(id)?.checked);
}

function collectDesktopSettings() {
  const pressed = document.querySelector("[data-settings-traffic-mode][aria-pressed='true']");
  return {
    traffic_mode: pressed ? pressed.dataset.settingsTrafficMode : "mixed-inbound-only",
    start_with_windows: checkedFieldValue("settings-start-with-windows"),
    launch_minimized: checkedFieldValue("settings-launch-minimized"),
    auto_start_core: checkedFieldValue("settings-auto-start-core"),
    mixed_port: numberFieldValue("settings-mixed-port", 7890),
    socks_port: numberFieldValue("settings-socks-port", 7891),
    http_port: numberFieldValue("settings-http-port", 7892),
    dns_mode: document.getElementById("settings-dns-mode")?.value || "fake-ip",
    tun_stack: document.getElementById("settings-tun-stack")?.value || "system"
  };
}

function postSaveDesktopSettings() {
  postJson({ type: "save-desktop-settings", settings: collectDesktopSettings() }, "正在保存设置");
}

window.keliSetDesktopSettings = (summary) => {
  const settings = summary.settings || summary;
  if (!settings) return;
  syncTrafficModeButtons(settings.traffic_mode);
  document.getElementById("settings-start-with-windows").checked = Boolean(settings.start_with_windows);
  document.getElementById("settings-launch-minimized").checked = Boolean(settings.launch_minimized);
  document.getElementById("settings-auto-start-core").checked = Boolean(settings.auto_start_core);
  document.getElementById("settings-mixed-port").value = settings.mixed_port || 7890;
  document.getElementById("settings-socks-port").value = settings.socks_port || 7891;
  document.getElementById("settings-http-port").value = settings.http_port || 7892;
  document.getElementById("settings-dns-mode").value = settings.dns_mode || "fake-ip";
  document.getElementById("settings-tun-stack").value = settings.tun_stack || "system";
  setText("settings-save-status", summary.status === "saved" ? "设置已保存" : "设置已恢复");
};
```

- [ ] **Step 5: Run focused tests**

Run: `cargo test -p keli-desktop-shell settings_baseline subscription_ipc_save -- --test-threads=1`

Expected: PASS.

- [ ] **Step 6: Commit IPC/UI contract**

```bash
git add crates/keli-desktop-shell/src/actions.rs crates/keli-desktop-shell/src/html.rs
git commit -m "feat: add desktop settings save IPC"
```

## Task 3: Startup Restore, Save Handling, and Smoke Evidence

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add failing smoke evidence tests**

Extend `smoke_report_confirms_shell_rendering_contract` expected entrypoints with:

```rust
"save-desktop-settings",
```

Add `settings_persistence_ready: bool` to `DesktopShellSmokeReport` and assert it is true when HTML contains `save-desktop-settings` and `window.keliSetDesktopSettings`.

- [ ] **Step 2: Run smoke report test and confirm failure**

Run: `cargo test -p keli-desktop-shell smoke_report_confirms_shell_rendering_contract -- --test-threads=1`

Expected: FAIL until smoke detection is updated.

- [ ] **Step 3: Implement startup restore and save handling**

In `main.rs`:

```rust
mod settings;

use settings::{
    default_desktop_shell_settings_path, read_desktop_shell_settings,
    write_desktop_shell_settings, DesktopShellSettings,
};
```

Before rendering:

```rust
let settings = read_desktop_shell_settings(default_desktop_shell_settings_path())
    .unwrap_or_default();
let mut controller = DesktopShellController::new_native();
controller.set_traffic_mode(settings.traffic_mode);
let initial_html = render_shell_html(controller.snapshot());
```

After WebView creation:

```rust
sync_desktop_settings(&webview, &settings);
```

When handling IPC:

```rust
if let DesktopShellUiEvent::SaveDesktopSettings(settings) = &event {
    match save_desktop_settings(controller, settings.clone(), webview) {
        Ok(shell) => sync_shell(webview, &shell),
        Err(message) => { eprintln!("desktop settings save failed: {message}"); }
    }
    return;
}
```

Add helper:

```rust
fn save_desktop_settings(
    controller: &mut DesktopShellController<keli_desktop::DesktopNativeCommandService>,
    settings: DesktopShellSettings,
    webview: &WebView,
) -> Result<DesktopShellState, String> {
    let summary = write_desktop_shell_settings(default_desktop_shell_settings_path(), &settings)
        .map_err(|error| format!("write desktop settings failed: {error}"))?;
    let script = desktop_settings_status_script(&summary)
        .map_err(|error| format!("desktop settings status serialization failed: {error}"))?;
    webview
        .evaluate_script(&script)
        .map_err(|error| format!("desktop settings status sync failed: {error}"))?;
    Ok(controller.set_traffic_mode(settings.traffic_mode))
}
```

Add `desktop_settings_status_script` in `html.rs`:

```rust
pub fn desktop_settings_status_script(
    summary: &DesktopShellSettingsSaveSummary,
) -> Result<String, serde_json::Error> {
    Ok(format!(
        "window.keliSetDesktopSettings({});",
        serde_json::to_string(summary)?
    ))
}
```

- [ ] **Step 4: Add smoke workflow detection**

`expected_smoke_workflows()` returns eight workflows, and `smoke_workflow_entrypoints()` adds `save-desktop-settings` when the HTML has the save button, command string, and settings sync function.

- [ ] **Step 5: Run focused tests**

Run: `cargo test -p keli-desktop-shell desktop_settings_ settings_baseline subscription_ipc_save smoke_report_confirms_shell_rendering_contract -- --test-threads=1`

Expected: PASS.

- [ ] **Step 6: Commit restore and smoke**

```bash
git add crates/keli-desktop-shell/src/main.rs crates/keli-desktop-shell/src/html.rs
git commit -m "feat: restore desktop shell settings on launch"
```

## Task 4: Final Verification

**Files:**
- All touched files.

- [ ] **Step 1: Format**

Run: `cargo fmt`

Expected: no formatting errors.

- [ ] **Step 2: Run shell tests**

Run: `cargo test -p keli-desktop-shell -- --test-threads=1`

Expected: all tests pass.

- [ ] **Step 3: Run smoke**

Run: `cargo run -q -p keli-desktop-shell -- --smoke`

Expected JSON includes:

```json
{
  "status": "passed",
  "settings_persistence_ready": true,
  "ui_workflow_entrypoints": [
    "save-desktop-settings"
  ]
}
```

- [ ] **Step 4: Check whitespace**

Run: `git diff --check`

Expected: no output and exit code 0.

- [ ] **Step 5: Commit docs if not already committed**

```bash
git add docs/superpowers/specs/2026-06-13-desktop-settings-persistence-design.md docs/superpowers/plans/2026-06-13-desktop-settings-persistence.md
git commit -m "docs: plan desktop settings persistence"
```

## Self Review

- Spec coverage: settings model, default path, missing/invalid fallback, IPC save, UI save/sync, startup restore, traffic mode application, and smoke evidence are covered.
- Placeholder scan: no TBD/TODO/implement-later placeholders remain.
- Type consistency: `DesktopShellSettings`, `DesktopShellSettingsSaveSummary`, `save-desktop-settings`, and `desktop_settings_status_script` are consistently named across tasks.
