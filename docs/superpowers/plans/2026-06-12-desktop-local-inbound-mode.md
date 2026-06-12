# Desktop Local Inbound Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the desktop shell treat Local inbound as a first-class traffic mode so users can start Keli from the GUI even when system proxy or TUN dependencies are unavailable.

**Architecture:** Keep the existing `DesktopTrafficMode::MixedInboundOnly` runtime behavior. Update shell readiness derivation to evaluate the currently selected traffic mode, and add a Local inbound mode button to the subscription controls. Do not weaken system proxy or TUN dependency checks when those modes are selected.

**Tech Stack:** Rust desktop crates, shell HTML string renderer, existing `cargo test` and desktop gate PowerShell scripts.

---

### Task 1: Plan

**Files:**
- Create: `docs/superpowers/plans/2026-06-12-desktop-local-inbound-mode.md`

- [ ] **Step 1: Save this implementation plan**

Use `apply_patch` to add this file.

- [ ] **Step 2: Commit the plan**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-local-inbound-mode.md
git commit -m "Plan desktop local inbound mode"
git push
```

Expected: commit and push succeed.

### Task 2: Shell Readiness

**Files:**
- Modify: `crates/keli-desktop/src/shell.rs`

- [ ] **Step 1: Write the failing tests**

Add tests:

```rust
#[test]
fn local_inbound_mode_can_start_when_proxy_and_tun_are_blocked() {
    let mut local = status(DesktopRunState::Stopped);
    local.traffic_mode = DesktopTrafficMode::MixedInboundOnly;

    let shell = DesktopShellState::new(local, blocked_dependencies());

    assert_eq!(
        shell.primary_action.command,
        DesktopShellPrimaryCommand::Start
    );
    assert!(shell.primary_action.enabled);
    assert!(shell.can_start);
}

#[test]
fn tun_mode_stays_blocked_when_tun_dependency_is_blocked() {
    let mut tun = status(DesktopRunState::Stopped);
    tun.traffic_mode = DesktopTrafficMode::Tun;

    let shell = DesktopShellState::new(tun, blocked_dependencies());

    assert_eq!(
        shell.primary_action.command,
        DesktopShellPrimaryCommand::Blocked
    );
    assert!(!shell.primary_action.enabled);
    assert!(!shell.can_start);
}
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```powershell
cargo test -p keli-desktop local_inbound_mode_can_start_when_proxy_and_tun_are_blocked tun_mode_stays_blocked_when_tun_dependency_is_blocked -- --test-threads=1
```

Expected: at least `local_inbound_mode_can_start_when_proxy_and_tun_are_blocked` fails because current readiness ignores `MixedInboundOnly`.

- [ ] **Step 3: Implement selected-mode readiness**

Replace dependency-only readiness with selected traffic mode readiness:

```rust
fn can_start_for_traffic_mode(
    status: &DesktopStatusSnapshot,
    dependencies: &DesktopDependencyReport,
) -> bool {
    match status.traffic_mode {
        crate::status::DesktopTrafficMode::MixedInboundOnly => true,
        crate::status::DesktopTrafficMode::SystemProxy => {
            dependencies.first_run.can_start_system_proxy_mode
        }
        crate::status::DesktopTrafficMode::Tun => dependencies.first_run.can_start_tun_mode,
    }
}
```

Use this helper in `DesktopShellState::new`, `rebuild_derived`, and `derive_primary_action`.

- [ ] **Step 4: Run tests to verify GREEN**

Run:

```powershell
cargo test -p keli-desktop local_inbound_mode_can_start_when_proxy_and_tun_are_blocked tun_mode_stays_blocked_when_tun_dependency_is_blocked -- --test-threads=1
```

Expected: both tests pass.

### Task 3: Shell UI Control

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Write the failing HTML test**

Add a test:

```rust
#[test]
fn subscription_mode_controls_include_local_inbound() {
    let html = render_shell_html(&snapshot());

    assert!(html.contains("postTrafficMode('mixed-inbound-only')"));
    assert!(html.contains("Local inbound"));
}
```

- [ ] **Step 2: Run test to verify RED**

Run:

```powershell
cargo test -p keli-desktop-shell subscription_mode_controls_include_local_inbound -- --test-threads=1
```

Expected: fails because the Local inbound button is not rendered.

- [ ] **Step 3: Add the Local inbound mode button**

In the subscription action row, render:

```html
<button onclick="postTrafficMode('mixed-inbound-only')">Local inbound</button>
```

- [ ] **Step 4: Run test to verify GREEN**

Run:

```powershell
cargo test -p keli-desktop-shell subscription_mode_controls_include_local_inbound -- --test-threads=1
```

Expected: test passes.

### Task 4: Verification and Commit

**Files:**
- Modify: `crates/keli-desktop/src/shell.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Format**

Run:

```powershell
cargo fmt
```

- [ ] **Step 2: Focused tests**

Run:

```powershell
cargo test -p keli-desktop local_inbound_mode -- --test-threads=1
cargo test -p keli-desktop-shell subscription_mode_controls_include_local_inbound -- --test-threads=1
```

- [ ] **Step 3: Package tests**

Run:

```powershell
cargo test -p keli-desktop -- --test-threads=1
cargo test -p keli-desktop-shell -- --test-threads=1
```

- [ ] **Step 4: Desktop gates**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
```

Expected: MVP gate passes. Public release gate remains blocked only by `artifact-signature-missing` and `signing-certificate-missing` until a code signing certificate is configured. Readiness reports `machine_takeover_status` as `ready`.

- [ ] **Step 5: Commit and push implementation**

Run:

```powershell
git add crates/keli-desktop/src/shell.rs crates/keli-desktop-shell/src/html.rs
git commit -m "Expose desktop local inbound mode"
git push
```

Expected: commit and push succeed.

---

## Self-Review

- Spec coverage: the plan makes local inbound selectable from GUI and keeps system proxy/TUN blockers mode-specific.
- Placeholder scan: no TBD/TODO/fill-in placeholders remain.
- Type consistency: uses existing `DesktopTrafficMode::MixedInboundOnly` and existing JSON value `mixed-inbound-only`.
- Scope: limited to shell readiness and UI controls; no runtime refactor or release gate weakening.
