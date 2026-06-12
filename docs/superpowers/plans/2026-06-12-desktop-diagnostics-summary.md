# Desktop Diagnostics Summary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show a concise diagnostics health summary in the Windows desktop shell so users can inspect core status, event counters, last error, system proxy state, TUN/Wintun state, and default-core evidence before exporting a support bundle.

**Architecture:** Reuse the existing `DesktopShellState` snapshot already serialized to the WebView. Add diagnostics text helpers to `keli-desktop-shell/src/html.rs` for initial HTML rendering and mirrored JavaScript helpers for live `window.keliSetShell` updates. Keep support bundle export behavior unchanged.

**Tech Stack:** Rust 2021, existing desktop shell HTML renderer, DOM APIs, existing `DesktopStatusSnapshot` and dependency DTOs.

---

## Scope Check

This slice covers:

- Diagnostics panel lines for core status, runtime events, last error, system proxy, TUN/Wintun, and default native core.
- Initial server-rendered HTML diagnostics content.
- Live diagnostics updates when `window.keliSetShell` receives a new snapshot.
- Focused shell tests and full desktop gate verification.

This slice does not cover:

- New backend diagnostics probes.
- A separate diagnostics window.
- Support bundle schema changes.
- Traffic latency or active node health probes.

## File Structure

- Modify: `crates/keli-desktop-shell/src/html.rs`
  - Add diagnostics helper strings.
  - Add diagnostics DOM elements in the Diagnostics section.
  - Add JavaScript diagnostic summary functions and update calls.
  - Add focused tests.

## Task 1: RED Diagnostics Tests

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add initial render test**

Add:

```rust
#[test]
fn diagnostics_html_includes_health_summary() {
    let mut snapshot = snapshot();
    snapshot.status.last_error = Some("Managed(\"bind failed\")".to_string());

    let html = render_shell_html(&snapshot);

    assert!(html.contains("id=\"diagnostics-core-status\""));
    assert!(html.contains("Core stopped via System proxy"));
    assert!(html.contains("id=\"diagnostics-runtime-events\""));
    assert!(html.contains("Generation 3, events 5"));
    assert!(html.contains("Last error: Managed(&quot;bind failed&quot;)"));
    assert!(html.contains("id=\"diagnostics-system-proxy\""));
    assert!(html.contains("id=\"diagnostics-tun\""));
    assert!(html.contains("Native core default"));
}
```

- [ ] **Step 2: Add live-render test**

Add:

```rust
#[test]
fn diagnostics_live_renderer_updates_health_summary() {
    let html = render_shell_html(&snapshot());

    assert!(html.contains("diagnosticsCoreStatus(snapshot)"));
    assert!(html.contains("diagnosticsRuntimeEvents(snapshot)"));
    assert!(html.contains("diagnosticsLastError(snapshot)"));
    assert!(html.contains("diagnosticsDefaultCore(snapshot)"));
}
```

- [ ] **Step 3: Run RED tests**

Run:

```powershell
cargo test -p keli-desktop-shell diagnostics_ -- --nocapture
```

Expected: FAIL because the Diagnostics panel does not yet render health summary fields.

## Task 2: Implement Diagnostics Summary

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add Rust helpers**

Add helpers for:

- `diagnostics_core_status(snapshot)`
- `diagnostics_runtime_events(snapshot)`
- `diagnostics_last_error(snapshot)`
- `diagnostics_default_core(snapshot)`

Reuse existing `system_proxy_dependency(snapshot)` and `tun_dependency(snapshot)`.

- [ ] **Step 2: Add Diagnostics DOM elements**

Inside the Diagnostics section, add:

```html
<div class="value" id="diagnostics-core-status">{diagnostics_core_status}</div>
<div class="muted" id="diagnostics-runtime-events">{diagnostics_runtime_events}</div>
<div class="muted" id="diagnostics-last-error">{diagnostics_last_error}</div>
<div class="muted" id="diagnostics-system-proxy">{diagnostics_system_proxy}</div>
<div class="muted" id="diagnostics-tun">{diagnostics_tun}</div>
<div class="muted" id="diagnostics-default-core">{diagnostics_default_core}</div>
```

- [ ] **Step 3: Add JavaScript helpers**

Add equivalent JS helpers and update the elements inside `window.keliSetShell`.

- [ ] **Step 4: Run focused tests**

Run:

```powershell
cargo test -p keli-desktop-shell diagnostics_ -- --nocapture
```

Expected: PASS.

## Task 3: Verify, Commit, Push

**Files:**
- `crates/keli-desktop-shell/src/html.rs`
- `docs/superpowers/plans/2026-06-12-desktop-diagnostics-summary.md`

- [ ] **Step 1: Shell tests**

Run:

```powershell
cargo fmt
cargo test -p keli-desktop-shell
```

Expected: PASS.

- [ ] **Step 2: Gates**

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
git add crates\keli-desktop-shell\src\html.rs docs\superpowers\plans\2026-06-12-desktop-diagnostics-summary.md
git commit -m "Show desktop diagnostics summary"
git push origin main
```

## Self-Review

- Spec coverage: covers current core status, event count, last error, system proxy status, TUN diagnostics, and default native core in the desktop Diagnostics panel.
- Placeholder scan: no TBD/TODO/fill-in items.
- Type consistency: all helpers consume the existing `DesktopShellState` snapshot.
