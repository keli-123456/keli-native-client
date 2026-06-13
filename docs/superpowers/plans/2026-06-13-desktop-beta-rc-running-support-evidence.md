# Desktop Beta RC Running Support Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Require the running support bundle smoke in packaged desktop Beta RC evidence and expose it in the unsigned Beta manifest.

**Architecture:** Extend the existing PowerShell release chain. Package smoke scripts run the packaged `keli-desktop-shell.exe --startup-connect-support-smoke`, release evidence copies the result fields, MVP status requires them, and the Beta RC manifest summarizes the paths.

**Tech Stack:** PowerShell 5+, existing `keli-desktop-shell` smoke commands, existing desktop package/release evidence scripts, existing script tests.

---

### Task 1: Red Tests For Package Smoke Plans

**Files:**
- Modify: `scripts/desktop-install-smoke.tests.ps1`
- Modify: `scripts/desktop-msi.tests.ps1`

- [ ] **Step 1: Extend install smoke plan expectations**

Require these PlanOnly lines:

```powershell
'run target\desktop-install-smoke\Keli\keli-desktop-shell.exe --startup-connect-support-smoke'
'running_support_smoke status passed'
'running_support_smoke desktop_status_running true'
'running_support_smoke diagnosis_selected true'
'running_support_smoke stopped_after_smoke true'
'result target\desktop-install-smoke\desktop-startup-connect-support-smoke.json'
```

- [ ] **Step 2: Extend MSI smoke plan expectations**

Require these PlanOnly lines:

```powershell
'admin_extract running_support_smoke target\desktop\keli-desktop-msi-startup-connect-support-smoke.json'
'admin_extract running_support_desktop_status_running true'
'admin_extract running_support_diagnosis_selected true'
'admin_extract running_support_stopped_after_smoke true'
```

- [ ] **Step 3: Verify red**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
```

Expected: fail because the install smoke plan does not mention running support smoke yet.

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-msi.tests.ps1
```

Expected: fail because the MSI smoke plan does not mention running support smoke yet.

### Task 2: Implement Package Smoke Evidence

**Files:**
- Modify: `scripts/desktop-install-smoke.ps1`
- Modify: `scripts/desktop-msi.ps1`

- [ ] **Step 1: Add install smoke execution**

In `scripts\desktop-install-smoke.ps1`, add `desktop-startup-connect-support-smoke.json`, run:

```powershell
$runningSupportOutput = & $exePath --startup-connect-support-smoke
```

Parse the JSON and require `status`, `desktop_status_running`, `desktop_status_selected`, `managed_status_selected`, `diagnosis_selected`, `redaction_ready`, and `stopped_after_smoke`.

- [ ] **Step 2: Add install result fields**

Write the result fields:

```powershell
running_support_smoke = 'target\desktop-install-smoke\desktop-startup-connect-support-smoke.json'
running_support_desktop_status_running = [bool]$runningSupportSmoke.desktop_status_running
running_support_desktop_status_selected = [bool]$runningSupportSmoke.desktop_status_selected
running_support_managed_status_selected = [bool]$runningSupportSmoke.managed_status_selected
running_support_diagnosis_selected = [bool]$runningSupportSmoke.diagnosis_selected
running_support_redaction_ready = [bool]$runningSupportSmoke.redaction_ready
running_support_stopped_after_smoke = [bool]$runningSupportSmoke.stopped_after_smoke
```

- [ ] **Step 3: Add MSI smoke execution**

In `scripts\desktop-msi.ps1`, pass a new running support smoke path into `Write-MsiSmoke`, run extracted EXE `--startup-connect-support-smoke`, validate the same fields, and store them in the MSI smoke JSON.

- [ ] **Step 4: Verify package plan tests green**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-msi.tests.ps1
```

Expected: both pass.

### Task 3: Red Tests For Release Evidence And MVP Status

**Files:**
- Modify: `scripts/desktop-release-evidence.tests.ps1`
- Modify: `scripts/desktop-mvp-status.tests.ps1`

- [ ] **Step 1: Extend release evidence plan and fixture checks**

Require plan lines:

```powershell
'metadata install_smoke_running_support_smoke'
'metadata msi_smoke_running_support_smoke'
```

Add fixture fields for install and MSI running support smoke and assert they survive into `target\desktop\keli-desktop-release-evidence.json`.

- [ ] **Step 2: Extend MVP status plan and fixture checks**

Require plan line:

```powershell
'require running-support-bundle-export smoke evidence'
```

Add fixture fields, require `running-support-bundle-export` and `msi-running-support-bundle-export` to be `ready`, and add a blocked fixture that removes one field and fails with the matching requirement id.

- [ ] **Step 3: Verify red**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
```

Expected: both fail on missing running support evidence behavior.

### Task 4: Implement Release Evidence And MVP Status

**Files:**
- Modify: `scripts/desktop-release-evidence.ps1`
- Modify: `scripts/desktop-mvp-status.ps1`

- [ ] **Step 1: Copy running support fields in release evidence**

Teach `Read-SmokeStatus` to copy the running support path and booleans into install/MSI smoke status objects.

- [ ] **Step 2: Require running support fields in MVP status**

Add `Test-RunningSupportEvidence` and the two requirements:

```powershell
running-support-bundle-export
msi-running-support-bundle-export
```

- [ ] **Step 3: Verify green**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
```

Expected: both pass.

### Task 5: Beta RC Manifest Evidence

**Files:**
- Modify: `scripts/desktop-beta-rc.ps1`
- Modify: `scripts/desktop-beta-rc.tests.ps1`

- [ ] **Step 1: Red test manifest smoke evidence**

Extend the fixture with running support fields and assert:

```powershell
$manifest.smoke_evidence.install.running_support_smoke
$manifest.smoke_evidence.msi.running_support_smoke
```

- [ ] **Step 2: Implement manifest fields**

Add `smoke_evidence` to `New-BetaManifest` with install/MSI support export and running support smoke paths.

- [ ] **Step 3: Verify green**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-beta-rc.tests.ps1
```

Expected: pass.

### Task 6: Final Verification

**Files:**
- Modified script and test files from earlier tasks.

- [ ] **Step 1: Run focused script tests**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-msi.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-beta-rc.tests.ps1
```

- [ ] **Step 2: Run direct desktop smoke**

Run:

```powershell
cargo run -q -p keli-desktop-shell -- --startup-connect-support-smoke
```

Expected: `"status": "passed"` and `"stopped_after_smoke": true`.

- [ ] **Step 3: Run Rust impacted tests**

Run:

```powershell
cargo test -p keli-desktop-shell -- --test-threads=1
cargo test -p keli-desktop -- --test-threads=1
```

- [ ] **Step 4: Patch hygiene**

Run:

```powershell
git diff --check
```

- [ ] **Step 5: Commit and push**

Run:

```powershell
git add docs/superpowers/specs/2026-06-13-desktop-beta-rc-running-support-evidence-design.md docs/superpowers/plans/2026-06-13-desktop-beta-rc-running-support-evidence.md
git commit -m "docs: plan beta rc running support evidence"
git add scripts/desktop-install-smoke.ps1 scripts/desktop-install-smoke.tests.ps1 scripts/desktop-msi.ps1 scripts/desktop-msi.tests.ps1 scripts/desktop-release-evidence.ps1 scripts/desktop-release-evidence.tests.ps1 scripts/desktop-mvp-status.ps1 scripts/desktop-mvp-status.tests.ps1 scripts/desktop-beta-rc.ps1 scripts/desktop-beta-rc.tests.ps1
git commit -m "feat: require running support smoke in beta rc evidence"
git push origin main
```

## Self-Review

- Spec coverage: package smoke, release evidence, MVP status, Beta manifest, and verification are covered.
- Placeholder review: no unfinished markers remain.
- Type consistency: running support field names match across smoke JSON, release evidence, MVP status, and manifest.
- Scope: no signing behavior or public release gate semantics are changed.
