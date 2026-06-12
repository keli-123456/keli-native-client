# Desktop Smoke Workflow Entrypoints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make desktop install smoke evidence prove that the packaged shell exposes UI entrypoints for each MVP manual smoke workflow, not only that those workflow names exist in the manifest.

**Architecture:** Extend the desktop shell `--smoke` report with a deterministic `ui_workflow_entrypoints` array derived from rendered HTML and snapshot script checks. Then make `desktop-install-smoke.ps1` require every manifest manual smoke case to appear in that launch smoke report and include the verified list in the install smoke result.

**Tech Stack:** Rust `keli-desktop-shell` smoke report, PowerShell install smoke scripts, existing desktop MVP gate.

---

### Task 1: Shell Launch Smoke Entrypoints

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Write the failing smoke report test**

Add this assertion to `smoke_report_confirms_shell_rendering_contract`:

```rust
assert_eq!(
    report.ui_workflow_entrypoints,
    vec![
        "open-desktop-shell",
        "import-subscription",
        "select-node",
        "start-stop-system-proxy",
        "tun-preflight",
        "export-support-bundle",
    ]
);
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
cargo test -p keli-desktop-shell smoke_report_confirms_shell_rendering_contract -- --nocapture
```

Expected: FAIL because `DesktopShellSmokeReport` does not expose `ui_workflow_entrypoints`.

- [ ] **Step 3: Implement entrypoint detection**

Add `ui_workflow_entrypoints: Vec<String>` to `DesktopShellSmokeReport`.

Add a helper:

```rust
fn smoke_workflow_entrypoints(html: &str, snapshot_script: &str) -> Vec<String> {
    let mut entrypoints = Vec::new();
    if html.contains("id=\"run-state\"") && html.contains("id=\"primary-button\"") {
        entrypoints.push("open-desktop-shell".to_string());
    }
    if html.contains("id=\"subscription-url\"")
        && html.contains("import-subscription-url")
        && html.contains("import-subscription-config")
    {
        entrypoints.push("import-subscription".to_string());
    }
    if html.contains("id=\"node-list\"")
        && html.contains("select-node")
        && snapshot_script.contains("window.keliSetShell")
    {
        entrypoints.push("select-node".to_string());
    }
    if html.contains("postTrafficMode('system-proxy')")
        && html.contains("id=\"primary-button\"")
        && html.contains("id=\"system-proxy-dependency\"")
    {
        entrypoints.push("start-stop-system-proxy".to_string());
    }
    if html.contains("postTrafficMode('tun')")
        && html.contains("id=\"tun-dependency\"")
        && html.contains("id=\"wintun-source-path\"")
    {
        entrypoints.push("tun-preflight".to_string());
    }
    if html.contains("export-support-bundle") && html.contains("id=\"support-export-status\"") {
        entrypoints.push("export-support-bundle".to_string());
    }
    entrypoints
}
```

In `build_smoke_report`, compute:

```rust
let ui_workflow_entrypoints = smoke_workflow_entrypoints(html, snapshot_script);
```

Include it in the report.

- [ ] **Step 4: Run shell smoke tests**

Run:

```powershell
cargo test -p keli-desktop-shell smoke_report -- --nocapture
```

Expected: PASS.

### Task 2: Install Smoke Requires Entrypoint Evidence

**Files:**
- Modify: `scripts/desktop-install-smoke.ps1`
- Modify: `scripts/desktop-install-smoke.tests.ps1`

- [ ] **Step 1: Write the failing PowerShell plan test**

Add these expected plan lines to `scripts/desktop-install-smoke.tests.ps1`:

```powershell
'launch_smoke ui_workflow_entrypoint import-subscription',
'launch_smoke ui_workflow_entrypoint select-node',
'launch_smoke ui_workflow_entrypoint start-stop-system-proxy',
'launch_smoke ui_workflow_entrypoint tun-preflight',
'launch_smoke ui_workflow_entrypoint export-support-bundle',
```

- [ ] **Step 2: Run the script test to verify it fails**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
```

Expected: FAIL because `desktop-install-smoke.ps1 -PlanOnly` does not yet describe launch smoke entrypoint checks.

- [ ] **Step 3: Implement launch smoke entrypoint checks**

In `desktop-install-smoke.ps1`, add:

```powershell
function Require-LaunchSmokeEntrypoint {
    param(
        [Parameter(Mandatory = $true)]
        [object]$LaunchSmoke,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (!($LaunchSmoke.ui_workflow_entrypoints -contains $Name)) {
        throw "desktop shell launch smoke ui_workflow_entrypoints is missing: $Name"
    }
}
```

In `-PlanOnly`, output the five `launch_smoke ui_workflow_entrypoint ...` lines from Step 1 plus `open-desktop-shell`.

After manifest checks, for each manual smoke case call both `Require-SmokeCase` and `Require-LaunchSmokeEntrypoint`.

Add this result field:

```powershell
verified_ui_workflow_entrypoints = $launchSmoke.ui_workflow_entrypoints
```

- [ ] **Step 4: Run script test and shell smoke test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
cargo test -p keli-desktop-shell smoke_report -- --nocapture
```

Expected: PASS.

### Task 3: Gate Verification And Commit

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`
- Modify: `scripts/desktop-install-smoke.ps1`
- Modify: `scripts/desktop-install-smoke.tests.ps1`

- [ ] **Step 1: Format and run targeted tests**

Run:

```powershell
cargo fmt
cargo test -p keli-desktop-shell smoke_report -- --nocapture
powershell -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Run full MVP gate and release readiness**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
```

Expected: MVP gate PASS. Release readiness should still report `machine_takeover_status = "ready"` and only signing blockers until a code-signing certificate is configured.

- [ ] **Step 3: Commit and push implementation**

Run:

```powershell
git add crates/keli-desktop-shell/src/main.rs scripts/desktop-install-smoke.ps1 scripts/desktop-install-smoke.tests.ps1
git commit -m "Verify desktop smoke workflow entrypoints"
git push
```

Expected: commit pushed to `origin/main`.
