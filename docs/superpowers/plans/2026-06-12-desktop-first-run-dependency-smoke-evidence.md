# Desktop First Run Dependency Smoke Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make desktop install and release evidence prove that first-run dependency blockers have visible UI recovery actions, not only that the shell has generic workflow entrypoints.

**Architecture:** Extend the existing `keli-desktop-shell --smoke` report with structured first-run dependency fields copied from the already-rendered shell snapshot. `scripts\desktop-install-smoke.ps1` validates and preserves those fields, and `scripts\desktop-release-evidence.ps1` embeds them under `smoke.install` so release evidence can explain how the UI handles Wintun/system proxy blockers.

**Tech Stack:** Rust `keli-desktop-shell`, PowerShell 5+ desktop install and release evidence scripts.

---

## Scope Check

This slice covers:

- Launch smoke first-run readiness fields:
  - `first_run_system_proxy_ready`
  - `first_run_tun_ready`
  - `first_run_blockers`
  - `dependency_action_entrypoints`
- Install smoke validation and result preservation for those fields.
- Release evidence preservation for install smoke first-run dependency diagnostics.
- Tests that prove a Wintun blocker records `code = wintun-missing` and `action = install-wintun`.

This slice does not cover:

- Installing Wintun automatically.
- Changing runtime dependency decisions.
- Changing public release signing blockers.
- Adding new UI controls; this records existing controls as evidence.

## File Structure

- Modify: `crates/keli-desktop-shell/src/main.rs`
  - Add a serializable `DesktopShellSmokeBlocker`.
  - Extend `DesktopShellSmokeReport`.
  - Add helper functions that collect blocker and dependency-action evidence.
  - Add Rust tests for first-run dependency evidence.
- Modify: `scripts/desktop-install-smoke.tests.ps1`
  - Add PlanOnly expectations for dependency action evidence.
- Modify: `scripts/desktop-install-smoke.ps1`
  - Require first-run dependency fields from launch smoke.
  - Preserve them in `desktop-install-smoke.json`.
- Modify: `scripts/desktop-release-evidence.tests.ps1`
  - Add PlanOnly expectation and clean evidence assertion.
- Modify: `scripts/desktop-release-evidence.ps1`
  - Copy install smoke dependency diagnostics into release evidence.

## Task 1: RED Shell Smoke Dependency Evidence Test

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add a failing Rust test**

Add a test near the existing smoke report tests:

```rust
#[test]
fn smoke_report_records_first_run_dependency_blockers_and_actions() {
    let mut snapshot = smoke_snapshot();
    snapshot.dependencies.first_run.tun_ready = false;
    snapshot.dependencies.first_run.can_start_tun_mode = false;
    snapshot.dependencies.first_run.blockers = vec![keli_desktop::DesktopBlocker {
        code: "wintun-missing".to_string(),
        message: "Wintun library was not found".to_string(),
        action: Some("install-wintun".to_string()),
    }];
    snapshot.dependencies.tun_backend.action = Some("install-wintun".to_string());

    let html = render_shell_html(&snapshot);
    let script = shell_snapshot_script(&snapshot).expect("snapshot script");
    let report = build_smoke_report(&snapshot, &html, &script);

    assert!(!report.first_run_tun_ready);
    assert!(report.first_run_system_proxy_ready);
    assert_eq!(report.first_run_blockers.len(), 1);
    assert_eq!(report.first_run_blockers[0].code, "wintun-missing");
    assert_eq!(
        report.first_run_blockers[0].action.as_deref(),
        Some("install-wintun")
    );
    assert!(
        report
            .dependency_action_entrypoints
            .iter()
            .any(|action| action == "install-wintun")
    );
}
```

- [ ] **Step 2: Run RED Rust test**

Run:

```powershell
cargo test -p keli-desktop-shell smoke_report_records_first_run_dependency_blockers_and_actions
```

Expected: FAIL because `DesktopShellSmokeReport` does not expose these fields.

## Task 2: GREEN Shell Smoke Dependency Evidence

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add smoke blocker DTO**

Add above `DesktopShellSmokeReport`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct DesktopShellSmokeBlocker {
    code: String,
    message: String,
    action: Option<String>,
}
```

- [ ] **Step 2: Extend smoke report struct**

Add fields:

```rust
first_run_system_proxy_ready: bool,
first_run_tun_ready: bool,
first_run_blockers: Vec<DesktopShellSmokeBlocker>,
dependency_action_entrypoints: Vec<String>,
```

- [ ] **Step 3: Add collection helpers**

Add helpers near `smoke_workflow_entrypoints`:

```rust
fn smoke_first_run_blockers(snapshot: &DesktopShellState) -> Vec<DesktopShellSmokeBlocker> {
    snapshot
        .dependencies
        .first_run
        .blockers
        .iter()
        .map(|blocker| DesktopShellSmokeBlocker {
            code: blocker.code.clone(),
            message: blocker.message.clone(),
            action: blocker.action.clone(),
        })
        .collect()
}

fn smoke_dependency_action_entrypoints(snapshot: &DesktopShellState, html: &str) -> Vec<String> {
    let mut actions = Vec::new();
    let mut add = |action: Option<&str>| {
        if let Some(action) = action {
            if !action.is_empty() && !actions.iter().any(|existing| existing == action) {
                actions.push(action.to_string());
            }
        }
    };
    add(snapshot.dependencies.system_proxy.action.as_deref());
    add(snapshot.dependencies.tun_backend.action.as_deref());
    for blocker in &snapshot.dependencies.first_run.blockers {
        add(blocker.action.as_deref());
    }
    actions.retain(|action| html.contains(&format!("data-dependency-action=\"{action}\"")));
    actions
}
```

- [ ] **Step 4: Populate report fields**

Inside `build_smoke_report`, compute:

```rust
let first_run_blockers = smoke_first_run_blockers(snapshot);
let dependency_action_entrypoints = smoke_dependency_action_entrypoints(snapshot, html);
```

Then populate:

```rust
first_run_system_proxy_ready: snapshot.dependencies.first_run.system_proxy_ready,
first_run_tun_ready: snapshot.dependencies.first_run.tun_ready,
first_run_blockers,
dependency_action_entrypoints,
```

- [ ] **Step 5: Run GREEN Rust test**

Run:

```powershell
cargo test -p keli-desktop-shell smoke_report_records_first_run_dependency_blockers_and_actions
```

Expected: PASS.

## Task 3: RED Install And Release Evidence Tests

**Files:**
- Modify: `scripts/desktop-install-smoke.tests.ps1`
- Modify: `scripts/desktop-release-evidence.tests.ps1`

- [ ] **Step 1: Add install PlanOnly expectations**

Add expected lines:

```powershell
'launch_smoke first_run_dependency_blockers',
'launch_smoke dependency_action_entrypoint install-wintun',
```

- [ ] **Step 2: Add release evidence PlanOnly expectation**

Add:

```powershell
'metadata install_smoke_first_run_dependency_actions',
```

- [ ] **Step 3: Add release evidence assertion**

After the clean release evidence run, assert:

```powershell
if ($cleanReleaseEvidence.smoke.install.first_run_blockers.Count -lt 1) {
    throw 'clean release evidence should preserve install first-run blockers'
}
if (($cleanReleaseEvidence.smoke.install.dependency_action_entrypoints -join ',') -notlike '*install-wintun*') {
    throw "clean release evidence should preserve install dependency action entrypoints: $($cleanReleaseEvidence.smoke.install.dependency_action_entrypoints -join ',')"
}
```

- [ ] **Step 4: Run RED PowerShell tests**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
```

Expected: FAIL because scripts do not surface the new evidence fields yet.

## Task 4: GREEN Install And Release Evidence Propagation

**Files:**
- Modify: `scripts/desktop-install-smoke.ps1`
- Modify: `scripts/desktop-release-evidence.ps1`

- [ ] **Step 1: Extend install PlanOnly**

Add:

```powershell
Write-Output 'launch_smoke first_run_dependency_blockers'
Write-Output 'launch_smoke dependency_action_entrypoint install-wintun'
```

- [ ] **Step 2: Validate launch smoke fields**

After launch smoke readiness checks, add:

```powershell
if ($null -eq $launchSmoke.PSObject.Properties['first_run_blockers']) {
    throw 'desktop shell launch smoke first_run_blockers is missing'
}
if ($null -eq $launchSmoke.PSObject.Properties['dependency_action_entrypoints']) {
    throw 'desktop shell launch smoke dependency_action_entrypoints is missing'
}
```

- [ ] **Step 3: Preserve install smoke fields**

Add to `$result`:

```powershell
first_run_system_proxy_ready = [bool]$launchSmoke.first_run_system_proxy_ready
first_run_tun_ready = [bool]$launchSmoke.first_run_tun_ready
first_run_blockers = @($launchSmoke.first_run_blockers)
dependency_action_entrypoints = @($launchSmoke.dependency_action_entrypoints)
```

- [ ] **Step 4: Extend release evidence smoke reader**

In `Read-SmokeStatus`, read optional fields:

```powershell
$firstRunBlockers = @()
if ($null -ne $smoke.PSObject.Properties['first_run_blockers']) {
    $firstRunBlockers = @($smoke.first_run_blockers)
}

$dependencyActionEntrypoints = @()
if ($null -ne $smoke.PSObject.Properties['dependency_action_entrypoints']) {
    $dependencyActionEntrypoints = @($smoke.dependency_action_entrypoints | ForEach-Object { [string]$_ })
}
```

Then add them to `$status` when present:

```powershell
if ($null -ne $smoke.PSObject.Properties['first_run_system_proxy_ready']) {
    $status['first_run_system_proxy_ready'] = [bool]$smoke.first_run_system_proxy_ready
}
if ($null -ne $smoke.PSObject.Properties['first_run_tun_ready']) {
    $status['first_run_tun_ready'] = [bool]$smoke.first_run_tun_ready
}
if ($firstRunBlockers.Count -gt 0) {
    $status['first_run_blockers'] = $firstRunBlockers
}
if ($dependencyActionEntrypoints.Count -gt 0) {
    $status['dependency_action_entrypoints'] = $dependencyActionEntrypoints
}
```

- [ ] **Step 5: Extend release evidence PlanOnly**

Add:

```powershell
Write-Output 'metadata install_smoke_first_run_dependency_actions'
```

- [ ] **Step 6: Run GREEN tests**

Run:

```powershell
cargo test -p keli-desktop-shell smoke_report_records_first_run_dependency_blockers_and_actions
powershell -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
```

Expected: PASS.

## Task 5: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-first-run-dependency-smoke-evidence.md`
- `crates/keli-desktop-shell/src/main.rs`
- `scripts/desktop-install-smoke.ps1`
- `scripts/desktop-install-smoke.tests.ps1`
- `scripts/desktop-release-evidence.ps1`
- `scripts/desktop-release-evidence.tests.ps1`

- [ ] **Step 1: Focused tests**

Run:

```powershell
cargo test -p keli-desktop-shell smoke_report_records_first_run_dependency_blockers_and_actions
powershell -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Regenerate package, install smoke, and release evidence**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-package.ps1 -SkipBuild
powershell -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1
```

Expected: PASS and `target\desktop-install-smoke\desktop-install-smoke.json` includes `dependency_action_entrypoints`.

- [ ] **Step 3: Full desktop MVP gate**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS.

- [ ] **Step 4: Public release honesty check**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: FAIL only with signing blockers until a real signing certificate signs the EXE/MSI.

- [ ] **Step 5: Diff check**

Run:

```powershell
git diff --check
```

Expected: PASS.

- [ ] **Step 6: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-first-run-dependency-smoke-evidence.md
git commit -m "Plan first run dependency smoke evidence"
git push
git add crates/keli-desktop-shell/src/main.rs scripts/desktop-install-smoke.ps1 scripts/desktop-install-smoke.tests.ps1 scripts/desktop-release-evidence.ps1 scripts/desktop-release-evidence.tests.ps1
git commit -m "Expose first run dependency smoke evidence"
git push
```

## Self-Review Checklist

- Spec coverage: first-run dependency blockers and UI recovery actions are visible in install/release evidence.
- Placeholder scan: no placeholder markers remain.
- Type consistency: blocker fields use `code`, `message`, and `action`; action lists are string arrays.
- Scope: runtime dependency behavior is unchanged.
- Release honesty: public release remains blocked by signing until real signatures exist.
