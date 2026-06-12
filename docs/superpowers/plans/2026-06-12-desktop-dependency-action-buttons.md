# Desktop Dependency Action Buttons Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn desktop dependency blockers into clickable setup actions so a Windows user can handle Wintun and system proxy readiness from the shell instead of copying action codes into a command line.

**Architecture:** Keep dependency detection in `keli-desktop` unchanged. Extend the desktop shell HTML to render stable action buttons from existing dependency `action` fields, extend IPC parsing with a `dependency-action` event, and map known action IDs to fixed safe launch targets in the shell process. Unknown action IDs remain ignored.

**Tech Stack:** Rust 2021, existing `keli-desktop-shell` Wry/Tao shell, existing `keli-desktop` dependency DTOs, Windows `ms-settings:` URI, Wintun official site `https://www.wintun.net/`.

---

## Scope Check

This slice covers:

- Dependency action buttons in the shell dependency section.
- IPC parsing for `{ "type": "dependency-action", "action": "..." }`.
- Fixed launch targets for:
  - `check-system-proxy` -> `ms-settings:network-proxy`
  - `install-wintun` -> `https://www.wintun.net/`
  - `check-tun` -> `https://www.wintun.net/`
- Shell smoke evidence that the dependency action container exists.
- Focused Rust tests and desktop shell package tests.

This slice does not cover:

- File picker based Wintun DLL import.
- Copying `wintun.dll` into the app directory.
- Downloading binaries automatically.
- Elevation, driver install prompts, or mutating Windows settings.

## File Structure

- Modify: `crates/keli-desktop-shell/src/html.rs`
  - Render dependency action buttons and update them after shell snapshots.
  - Add tests for blocked Wintun and system proxy action buttons.
- Modify: `crates/keli-desktop-shell/src/actions.rs`
  - Add `DesktopShellUiEvent::DependencyAction(String)`.
  - Parse `dependency-action` JSON IPC.
- Modify: `crates/keli-desktop-shell/src/main.rs`
  - Handle dependency action events by launching fixed safe targets and refreshing shell state.
  - Add tests for launch target mapping and smoke report contract.

## Task 1: RED Shell UI And IPC Tests

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Modify: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add HTML expectations**

In `dependency_html_renders_missing_wintun_action`, add:

```rust
assert!(html.contains("id=\"dependency-actions\""));
assert!(html.contains("dependency-action"));
assert!(html.contains("Open Wintun download"));
```

Add a new test:

```rust
#[test]
fn dependency_html_renders_system_proxy_action_button() {
    let mut snapshot = snapshot();
    snapshot.dependencies.first_run.system_proxy_ready = false;
    snapshot.dependencies.first_run.can_start_system_proxy_mode = false;
    snapshot.dependencies.first_run.blockers = vec![keli_desktop::DesktopBlocker {
        code: "system-proxy-unavailable".to_string(),
        message: "System proxy control is unavailable".to_string(),
        action: Some("check-system-proxy".to_string()),
    }];
    snapshot.dependencies.system_proxy.state = "unavailable".to_string();
    snapshot.dependencies.system_proxy.ready = false;
    snapshot.dependencies.system_proxy.supported = false;
    snapshot.dependencies.system_proxy.error =
        Some("System proxy control is unavailable".to_string());
    snapshot.dependencies.system_proxy.action = Some("check-system-proxy".to_string());

    let html = render_shell_html(&snapshot);

    assert!(html.contains("id=\"dependency-actions\""));
    assert!(html.contains("check-system-proxy"));
    assert!(html.contains("Open proxy settings"));
}
```

- [ ] **Step 2: Add IPC expectation**

Add to `crates/keli-desktop-shell/src/actions.rs` tests:

```rust
#[test]
fn dependency_action_ipc_maps_to_dependency_action_event() {
    assert_eq!(
        ipc_event_for_message(
            r#"{"type":"dependency-action","action":"install-wintun"}"#,
            &shell(DesktopRunState::Stopped, true),
        ),
        Some(DesktopShellUiEvent::DependencyAction(
            "install-wintun".to_string()
        ))
    );
}
```

- [ ] **Step 3: Add launch target and smoke expectations**

Add to `crates/keli-desktop-shell/src/main.rs` tests:

```rust
#[test]
fn dependency_action_launch_targets_are_fixed_and_safe() {
    assert_eq!(
        dependency_action_launch_target("check-system-proxy").map(|target| target.target),
        Some("ms-settings:network-proxy")
    );
    assert_eq!(
        dependency_action_launch_target("install-wintun").map(|target| target.target),
        Some("https://www.wintun.net/")
    );
    assert_eq!(
        dependency_action_launch_target("check-tun").map(|target| target.target),
        Some("https://www.wintun.net/")
    );
    assert!(dependency_action_launch_target("unknown").is_none());
}
```

Extend `smoke_report_confirms_shell_rendering_contract`:

```rust
assert!(html.contains("id=\"dependency-actions\""));
```

- [ ] **Step 4: Run RED test**

Run:

```powershell
cargo test -p keli-desktop-shell dependency_action -- --nocapture
cargo test -p keli-desktop-shell dependency_html_renders_missing_wintun_action -- --nocapture
```

Expected: FAIL because dependency action IPC, launch target mapping, and dependency action buttons are not implemented.

## Task 2: Implement Dependency Action Buttons

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add initial dependency action HTML**

Compute:

```rust
let dependency_actions = dependency_action_buttons(snapshot);
```

Render:

```html
<div class="actions" id="dependency-actions">{dependency_actions}</div>
```

- [ ] **Step 2: Add JavaScript action rendering**

Add:

```javascript
const dependencyActionLabels = {
  "check-system-proxy": "Open proxy settings",
  "install-wintun": "Open Wintun download",
  "check-tun": "Open TUN help"
};
function postDependencyAction(action) {
  postJson({
    type: "dependency-action",
    action
  });
}
function collectDependencyActions(snapshot) {
  const actions = [];
  const add = (action) => {
    if (action && !actions.includes(action)) actions.push(action);
  };
  add(snapshot.dependencies.system_proxy.action);
  add(snapshot.dependencies.tun_backend.action);
  for (const blocker of snapshot.dependencies.first_run.blockers || []) {
    add(blocker.action);
  }
  return actions;
}
function renderDependencyActions(snapshot) {
  const container = document.getElementById("dependency-actions");
  container.replaceChildren();
  for (const action of collectDependencyActions(snapshot)) {
    const button = document.createElement("button");
    button.dataset.dependencyAction = action;
    button.textContent = dependencyActionLabels[action] || action;
    button.onclick = () => postDependencyAction(action);
    container.appendChild(button);
  }
}
```

Call `renderDependencyActions(snapshot);` inside `window.keliSetShell`.

- [ ] **Step 3: Add Rust helper rendering**

Add:

```rust
fn dependency_action_buttons(snapshot: &DesktopShellState) -> String {
    let mut actions = Vec::new();
    add_dependency_action(&mut actions, snapshot.dependencies.system_proxy.action.as_deref());
    add_dependency_action(&mut actions, snapshot.dependencies.tun_backend.action.as_deref());
    for blocker in &snapshot.dependencies.first_run.blockers {
        add_dependency_action(&mut actions, blocker.action.as_deref());
    }
    actions
        .iter()
        .map(|action| {
            let action_value = escape_html(action);
            let label = escape_html(dependency_action_label(action));
            format!(
                r#"<button data-dependency-action="{action_value}" onclick="postDependencyAction(this.dataset.dependencyAction)">{label}</button>"#
            )
        })
        .collect::<Vec<_>>()
        .join("")
}
```

Add:

```rust
fn add_dependency_action(actions: &mut Vec<String>, action: Option<&str>) {
    let Some(action) = action else {
        return;
    };
    if action.trim().is_empty() || actions.iter().any(|existing| existing == action) {
        return;
    }
    actions.push(action.to_string());
}

fn dependency_action_label(action: &str) -> &str {
    match action {
        "check-system-proxy" => "Open proxy settings",
        "install-wintun" => "Open Wintun download",
        "check-tun" => "Open TUN help",
        _ => action,
    }
}
```

## Task 3: Implement IPC And Launch Target Handling

**Files:**
- Modify: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add IPC field and event**

In `DesktopShellUiEvent`, add:

```rust
DependencyAction(String),
```

In `IpcCommand`, add:

```rust
action: Option<String>,
```

In `json_ipc_event`, add:

```rust
"dependency-action" => command.action.map(DesktopShellUiEvent::DependencyAction),
```

- [ ] **Step 2: Add shell event handling**

In `handle_ui_event`, add before dispatch:

```rust
if let DesktopShellUiEvent::DependencyAction(action) = &event {
    if let Err(message) = open_dependency_action(action) {
        eprintln!("desktop shell dependency action failed: {message}");
    }
    let shell = controller.refresh();
    window.set_visible(shell.window.main_visible);
    sync_webview(webview, &shell);
    return;
}
```

In `dispatch_ui_event`, add:

```rust
DesktopShellUiEvent::DependencyAction(_) => Ok(controller.refresh()),
```

- [ ] **Step 3: Add fixed launch target mapping**

Add:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DependencyActionLaunchTarget {
    target: &'static str,
}

fn dependency_action_launch_target(action: &str) -> Option<DependencyActionLaunchTarget> {
    match action {
        "check-system-proxy" => Some(DependencyActionLaunchTarget {
            target: "ms-settings:network-proxy",
        }),
        "install-wintun" | "check-tun" => Some(DependencyActionLaunchTarget {
            target: "https://www.wintun.net/",
        }),
        _ => None,
    }
}
```

Add:

```rust
fn open_dependency_action(action: &str) -> Result<(), String> {
    let target = dependency_action_launch_target(action)
        .ok_or_else(|| format!("unknown dependency action: {action}"))?;
    open_launch_target(target.target)
        .map_err(|error| format!("open {}: {error}", target.target))
}

fn open_launch_target(target: &str) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", target])
            .spawn()?;
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(target).spawn()?;
        return Ok(());
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open").arg(target).spawn()?;
        return Ok(());
    }
}
```

## Task 4: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-dependency-action-buttons.md`
- `crates/keli-desktop-shell/src/html.rs`
- `crates/keli-desktop-shell/src/actions.rs`
- `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Focused tests**

Run:

```powershell
cargo test -p keli-desktop-shell dependency_action -- --nocapture
cargo test -p keli-desktop-shell dependency_html_renders_missing_wintun_action -- --nocapture
cargo test -p keli-desktop-shell dependency_html_renders_system_proxy_action_button -- --nocapture
cargo test -p keli-desktop-shell smoke_report_confirms_shell_rendering_contract -- --nocapture
```

Expected: PASS.

- [ ] **Step 2: Full shell crate tests**

Run:

```powershell
cargo test -p keli-desktop-shell
```

Expected: PASS.

- [ ] **Step 3: Desktop smoke gate**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS for MVP gate, or fail only for an existing machine/environment blocker that is reported explicitly.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-dependency-action-buttons.md
git commit -m "Plan desktop dependency action buttons"
git push origin main
git add crates/keli-desktop-shell/src/html.rs crates/keli-desktop-shell/src/actions.rs crates/keli-desktop-shell/src/main.rs
git commit -m "Add desktop dependency action buttons"
git push origin main
```

## Self-Review Checklist

- Spec coverage: first-run dependency blockers are visible as actionable setup buttons.
- Placeholder scan: all action IDs, labels, and launch targets are concrete.
- Secret safety: launch targets contain no subscription or certificate data.
- Scope: no automatic driver download, elevation, or Windows setting mutation is introduced.
