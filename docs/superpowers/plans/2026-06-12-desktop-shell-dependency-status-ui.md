# Desktop Shell Dependency Status UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show Wintun/TUN and Windows system proxy readiness directly in the desktop shell, including blocker text and action labels, so users can understand dependency problems without reading raw JSON.

**Architecture:** Reuse the existing `DesktopShellState.dependencies` DTO. Add a visible Dependencies section to `crates/keli-desktop-shell/src/html.rs`, render the initial status server-side, and update the same DOM nodes inside `window.keliSetShell` whenever the shell snapshot refreshes.

**Tech Stack:** Rust 2021, existing `keli-desktop-shell` HTML renderer, `serde_json` snapshot updates.

---

## Scope Check

This slice is display-only. It does not install Wintun, open a file picker, mutate Windows proxy settings, or run real TUN/system-proxy smoke. The goal is to make already-detected dependency evidence visible and actionable in the MVP shell.

## File Structure

- Modify: `crates/keli-desktop-shell/src/html.rs`
  - Add HTML for dependency summary, system proxy status, Wintun/TUN status, and blockers.
  - Add Rust helper functions that render initial dependency strings and blocker markup.
  - Add JavaScript helpers to update dependency UI on every shell snapshot refresh.
  - Add tests for ready dependencies, missing Wintun/action rendering, and updater script coverage.

## Task 1: RED Tests For Dependency UI

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Write failing tests**

Add these tests to the existing `html.rs` test module:

```rust
#[test]
fn dependency_html_includes_readiness_targets() {
    let html = render_shell_html(&snapshot());

    assert!(html.contains("id=\"dependency-summary\""));
    assert!(html.contains("id=\"system-proxy-dependency\""));
    assert!(html.contains("id=\"tun-dependency\""));
    assert!(html.contains("id=\"dependency-blockers\""));
    assert!(html.contains("System proxy ready"));
    assert!(html.contains("TUN ready"));
}

#[test]
fn dependency_html_renders_missing_wintun_action() {
    let mut snapshot = snapshot();
    snapshot.dependencies.first_run.tun_ready = false;
    snapshot.dependencies.first_run.can_start_tun_mode = false;
    snapshot.dependencies.first_run.blockers = vec![keli_desktop::DesktopBlocker {
        code: "wintun-missing".to_string(),
        message: "Wintun library was not found".to_string(),
        action: Some("install-wintun".to_string()),
    }];
    snapshot.dependencies.tun_backend.state = "install-required".to_string();
    snapshot.dependencies.tun_backend.driver_library_present = false;
    snapshot.dependencies.tun_backend.driver_api_available = false;
    snapshot.dependencies.tun_backend.install_required = true;
    snapshot.dependencies.tun_backend.reason = Some("Wintun library was not found".to_string());
    snapshot.dependencies.tun_backend.action = Some("install-wintun".to_string());

    let html = render_shell_html(&snapshot);

    assert!(html.contains("Wintun install-required"));
    assert!(html.contains("Wintun library was not found"));
    assert!(html.contains("install-wintun"));
    assert!(html.contains("System proxy ready"));
}

#[test]
fn shell_snapshot_script_carries_dependency_updates() {
    let script = shell_snapshot_script(&snapshot()).expect("snapshot script");

    assert!(script.contains("dependencies"));
    assert!(script.contains("window.keliSetShell"));
}
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```powershell
cargo test -p keli-desktop-shell dependency_html -- --test-threads=1
```

Expected: FAIL because the dependency DOM ids and rendered labels do not exist.

## Task 2: Implement Dependency Rendering

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add initial dependency values**

Inside `render_shell_html`, after `node_buttons`, add:

```rust
let dependency_summary = dependency_summary(snapshot);
let system_proxy_dependency = system_proxy_dependency(snapshot);
let tun_dependency = tun_dependency(snapshot);
let dependency_blockers = dependency_blockers(snapshot);
```

Add a new wide section before the Subscription section:

```html
      <section class="wide">
        <h2>Dependencies</h2>
        <div class="value" id="dependency-summary">{dependency_summary}</div>
        <div class="muted" id="system-proxy-dependency">{system_proxy_dependency}</div>
        <div class="muted" id="tun-dependency">{tun_dependency}</div>
        <div class="muted" id="dependency-blockers">{dependency_blockers}</div>
      </section>
```

Pass the escaped values into `format!`:

```rust
dependency_summary = escape_html(&dependency_summary),
system_proxy_dependency = escape_html(&system_proxy_dependency),
tun_dependency = escape_html(&tun_dependency),
dependency_blockers = dependency_blockers,
```

- [ ] **Step 2: Add Rust helper functions**

Add these helpers near `subscription_summary`:

```rust
fn dependency_summary(snapshot: &DesktopShellState) -> String {
    let system = if snapshot.dependencies.first_run.system_proxy_ready {
        "System proxy ready"
    } else {
        "System proxy blocked"
    };
    let tun = if snapshot.dependencies.first_run.tun_ready {
        "TUN ready"
    } else {
        "TUN blocked"
    };
    format!("{system}, {tun}")
}

fn system_proxy_dependency(snapshot: &DesktopShellState) -> String {
    let proxy = &snapshot.dependencies.system_proxy;
    let mut parts = vec![format!("System proxy {}", proxy.state)];
    if let Some(enabled) = proxy.enabled {
        parts.push(format!("enabled={enabled}"));
    }
    if let Some(server) = proxy.server.as_deref() {
        parts.push(format!("server={server}"));
    }
    if let Some(error) = proxy.error.as_deref() {
        parts.push(error.to_string());
    }
    if let Some(action) = proxy.action.as_deref() {
        parts.push(format!("action={action}"));
    }
    parts.join(", ")
}

fn tun_dependency(snapshot: &DesktopShellState) -> String {
    let tun = &snapshot.dependencies.tun_backend;
    let mut parts = vec![format!("Wintun {}", tun.state)];
    parts.push(format!("driver_present={}", tun.driver_library_present));
    parts.push(format!("api_available={}", tun.driver_api_available));
    if let Some(path) = tun.driver_library_path.as_deref() {
        parts.push(format!("path={path}"));
    }
    if let Some(reason) = tun.reason.as_deref() {
        parts.push(reason.to_string());
    }
    if let Some(action) = tun.action.as_deref() {
        parts.push(format!("action={action}"));
    }
    parts.join(", ")
}

fn dependency_blockers(snapshot: &DesktopShellState) -> String {
    if snapshot.dependencies.first_run.blockers.is_empty() {
        return "No dependency blockers".to_string();
    }
    snapshot
        .dependencies
        .first_run
        .blockers
        .iter()
        .map(|blocker| {
            let action = blocker
                .action
                .as_deref()
                .map(|action| format!(" action={}", escape_html(action)))
                .unwrap_or_default();
            format!(
                "{}: {}{}",
                escape_html(&blocker.code),
                escape_html(&blocker.message),
                action
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}
```

## Task 3: Update Dependencies On Snapshot Refresh

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add JavaScript helpers**

Add these functions before `window.keliSetShell`:

```javascript
    function dependencySummary(snapshot) {{
      const firstRun = snapshot.dependencies.first_run;
      const system = firstRun.system_proxy_ready ? "System proxy ready" : "System proxy blocked";
      const tun = firstRun.tun_ready ? "TUN ready" : "TUN blocked";
      return `${{system}}, ${{tun}}`;
    }}
    function systemProxyDependency(snapshot) {{
      const proxy = snapshot.dependencies.system_proxy;
      const parts = [`System proxy ${{proxy.state}}`];
      if (proxy.enabled !== null && proxy.enabled !== undefined) parts.push(`enabled=${{proxy.enabled}}`);
      if (proxy.server) parts.push(`server=${{proxy.server}}`);
      if (proxy.error) parts.push(proxy.error);
      if (proxy.action) parts.push(`action=${{proxy.action}}`);
      return parts.join(", ");
    }}
    function tunDependency(snapshot) {{
      const tun = snapshot.dependencies.tun_backend;
      const parts = [
        `Wintun ${{tun.state}}`,
        `driver_present=${{tun.driver_library_present}}`,
        `api_available=${{tun.driver_api_available}}`
      ];
      if (tun.driver_library_path) parts.push(`path=${{tun.driver_library_path}}`);
      if (tun.reason) parts.push(tun.reason);
      if (tun.action) parts.push(`action=${{tun.action}}`);
      return parts.join(", ");
    }}
    function dependencyBlockers(snapshot) {{
      const blockers = snapshot.dependencies.first_run.blockers || [];
      if (!blockers.length) return "No dependency blockers";
      return blockers.map((blocker) => {{
        const action = blocker.action ? ` action=${{blocker.action}}` : "";
        return `${{blocker.code}}: ${{blocker.message}}${{action}}`;
      }}).join("; ");
    }}
```

In `window.keliSetShell`, after updating `window-visible`, add:

```javascript
      document.getElementById("dependency-summary").textContent = dependencySummary(snapshot);
      document.getElementById("system-proxy-dependency").textContent = systemProxyDependency(snapshot);
      document.getElementById("tun-dependency").textContent = tunDependency(snapshot);
      document.getElementById("dependency-blockers").textContent = dependencyBlockers(snapshot);
```

- [ ] **Step 2: Run focused tests**

Run:

```powershell
cargo test -p keli-desktop-shell dependency_html -- --test-threads=1
```

Expected: PASS.

## Task 4: Full Verification

**Files:**
- No source changes expected unless verification finds a defect.

- [ ] **Step 1: Format and focused tests**

Run:

```powershell
cargo fmt --check
git diff --check
cargo test -p keli-desktop-shell dependency_html -- --test-threads=1
cargo test -p keli-desktop-shell
```

Expected: PASS.

- [ ] **Step 2: Full desktop MVP gate**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS.

- [ ] **Step 3: Commit and push**

Run:

```powershell
git add crates\keli-desktop-shell\src\html.rs
git commit -m "Show desktop shell dependency status"
git push origin main
```

## Self-Review Checklist

- Spec coverage: this plan advances the Wintun/system proxy dependency handling requirement by surfacing current readiness, blockers, and action labels in the desktop UI.
- Placeholder scan: every file, helper, command, expected failure, and expected pass result is concrete.
- Type consistency: all rendering reads existing `DesktopShellState.dependencies` fields and does not introduce new backend DTOs.
