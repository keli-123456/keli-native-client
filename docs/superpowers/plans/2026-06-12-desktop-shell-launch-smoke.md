# Desktop Shell Launch Smoke Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an automated packaged-executable smoke path that proves `keli-desktop-shell.exe` can initialize the native desktop command host, render the shell snapshot, and exit without opening a GUI window.

**Architecture:** Add a `--smoke` CLI mode to `keli-desktop-shell` before the single-instance and wry window path. The mode constructs `DesktopShellController::new_native()`, renders the initial HTML and snapshot script, prints a small JSON report, and exits. Extend `desktop-install-smoke.ps1` to execute the packaged exe with `--smoke` and validate the JSON.

**Tech Stack:** Rust 2021, serde JSON, PowerShell install smoke script, existing desktop MVP gate.

---

## Scope Check

This plan covers:

- A non-GUI `keli-desktop-shell.exe --smoke` mode.
- Unit tests for smoke report shape and argument detection.
- Install smoke script execution of the packaged exe.
- Plan-only script output documenting the new executable smoke step.

This plan does not cover:

- Interactive GUI automation.
- WebView2 runtime probing beyond the existing package README requirement.
- Real system proxy or TUN packet flow smoke.

## File Structure

- Modify: `crates/keli-desktop-shell/src/main.rs`
  - Add `--smoke` argument detection, smoke report DTO, and unit tests.
- Modify: `scripts/desktop-install-smoke.ps1`
  - Run `keli-desktop-shell.exe --smoke`, parse JSON, and include the result path in the smoke output.
- Modify: `scripts/desktop-install-smoke.tests.ps1`
  - Assert plan-only output includes the launch smoke step and result file.

## Task 1: RED Tests

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`
- Modify: `scripts/desktop-install-smoke.tests.ps1`

- [ ] **Step 1: Add failing Rust tests**

Add tests in `main.rs`:

```rust
#[test]
fn smoke_arg_detection_accepts_smoke_flag() {
    assert!(is_smoke_mode(["keli-desktop-shell", "--smoke"]));
    assert!(!is_smoke_mode(["keli-desktop-shell"]));
}

#[test]
fn smoke_report_confirms_shell_rendering_contract() {
    let snapshot = smoke_snapshot();
    let html = render_shell_html(&snapshot);
    let script = shell_snapshot_script(&snapshot).expect("snapshot script");
    let report = build_smoke_report(&snapshot, &html, &script);

    assert_eq!(report.status, "passed");
    assert!(report.native_core_default);
    assert!(report.html_ready);
    assert!(report.snapshot_script_ready);
}
```

- [ ] **Step 2: Add failing PowerShell plan test**

Extend `desktop-install-smoke.tests.ps1` expected output with:

```powershell
'run target\desktop-install-smoke\Keli\keli-desktop-shell.exe --smoke',
'result target\desktop-install-smoke\desktop-shell-launch-smoke.json'
```

- [ ] **Step 3: Run RED tests**

Run:

```powershell
cargo test -p keli-desktop-shell smoke -- --test-threads=1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
```

Expected: FAIL because `is_smoke_mode`, `build_smoke_report`, and the new plan output do not exist.

## Task 2: Implement Smoke Mode

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add smoke mode before GUI launch**

At the start of `main()`:

```rust
if is_smoke_mode(std::env::args()) {
    return run_smoke();
}
```

- [ ] **Step 2: Add report DTO and helpers**

Add:

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct DesktopShellSmokeReport {
    status: String,
    native_core_default: bool,
    run_state: DesktopRunState,
    traffic_mode: keli_desktop::DesktopTrafficMode,
    primary_action_id: String,
    can_start: bool,
    dependency_blocker_count: usize,
    html_ready: bool,
    snapshot_script_ready: bool,
}
```

Implement `is_smoke_mode`, `run_smoke`, and `build_smoke_report`.

- [ ] **Step 3: Run Rust GREEN tests**

Run: `cargo test -p keli-desktop-shell smoke -- --test-threads=1`

Expected: PASS.

## Task 3: Wire Install Smoke Script

**Files:**
- Modify: `scripts/desktop-install-smoke.ps1`
- Modify: `scripts/desktop-install-smoke.tests.ps1`

- [ ] **Step 1: Add plan output**

In `-PlanOnly`, output:

```powershell
Write-Output 'run target\desktop-install-smoke\Keli\keli-desktop-shell.exe --smoke'
Write-Output 'result target\desktop-install-smoke\desktop-shell-launch-smoke.json'
```

- [ ] **Step 2: Execute smoke mode after extraction**

Run:

```powershell
& $exePath --smoke | Set-Content -LiteralPath $launchSmokePath -Encoding ASCII
```

Parse the JSON and require:

```powershell
$launchSmoke.status -eq 'passed'
$launchSmoke.native_core_default -eq $true
$launchSmoke.html_ready -eq $true
$launchSmoke.snapshot_script_ready -eq $true
```

- [ ] **Step 3: Include launch smoke in install result**

Add `launch_smoke = 'target\desktop-install-smoke\desktop-shell-launch-smoke.json'` to `desktop-install-smoke.json`.

- [ ] **Step 4: Run script GREEN tests**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1`

Expected: PASS.

## Task 4: Verification, Commit, And Push

**Files:**
- `crates/keli-desktop-shell/src/main.rs`
- `scripts/desktop-install-smoke.ps1`
- `scripts/desktop-install-smoke.tests.ps1`
- `docs/superpowers/plans/2026-06-12-desktop-shell-launch-smoke.md`

- [ ] **Step 1: Format and whitespace**

Run:

```powershell
cargo fmt --check
git diff --check
```

Expected: PASS.

- [ ] **Step 2: Focused tests**

Run:

```powershell
cargo test -p keli-desktop-shell smoke -- --test-threads=1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
```

Expected: PASS.

- [ ] **Step 3: Full gate**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1`

Expected: PASS and produce `target\desktop-install-smoke\desktop-shell-launch-smoke.json`.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-shell-launch-smoke.md
git commit -m "Plan desktop shell launch smoke"
git push origin main
git add crates/keli-desktop-shell/src/main.rs scripts/desktop-install-smoke.ps1 scripts/desktop-install-smoke.tests.ps1
git commit -m "Add desktop shell launch smoke"
git push origin main
```

## Self-Review Checklist

- Spec coverage: closes part of the release gate gap by executing the packaged desktop shell binary.
- Safety: smoke mode does not start proxy/TUN or open a GUI.
- Automation: install smoke fails if the packaged exe cannot initialize shell state.
- Scope: real interactive GUI and OS proxy/TUN smoke remain separate manual or elevated-machine checks.
