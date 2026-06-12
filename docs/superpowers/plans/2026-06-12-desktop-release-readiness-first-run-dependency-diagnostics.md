# Desktop Release Readiness First Run Dependency Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose first-run dependency readiness, blockers, and UI recovery actions in `desktop-release-readiness.ps1` JSON and text output.

**Architecture:** Keep `target\desktop\keli-desktop-release-evidence.json` as the source of truth. `desktop-release-readiness.ps1` already summarizes signing and machine takeover; this slice adds an `install_first_run` summary sourced from `smoke.install` without changing gate semantics.

**Tech Stack:** PowerShell 5+, existing desktop release readiness script and tests.

---

## Scope Check

This slice covers:

- Release readiness JSON field `install_first_run`.
- Text output lines for system proxy readiness, TUN readiness, first-run blocker codes, and dependency action entrypoints.
- PlanOnly output documenting the new evidence read.
- Tests proving Wintun blocker/action diagnostics are preserved.

This slice does not cover:

- Changing install smoke generation.
- Changing MVP/public release gate blockers.
- Signing artifacts.
- Changing runtime dependency behavior.

## File Structure

- Modify: `scripts/desktop-release-readiness.tests.ps1`
  - Add PlanOnly expectation for `smoke.install` first-run fields.
  - Add install first-run fixture evidence.
  - Assert JSON preserves blocker and action fields.
  - Assert text output includes the concise dependency diagnostics.
- Modify: `scripts/desktop-release-readiness.ps1`
  - Read `smoke.install`.
  - Add `install_first_run` to report JSON.
  - Print first-run dependency diagnostic lines.
  - Extend PlanOnly output.

## Task 1: RED Readiness Dependency Diagnostics Tests

**Files:**
- Modify: `scripts/desktop-release-readiness.tests.ps1`

- [ ] **Step 1: Add PlanOnly expectation**

Update the expected PlanOnly lines to include:

```powershell
'read smoke.install.first_run_system_proxy_ready smoke.install.first_run_tun_ready smoke.install.first_run_blockers smoke.install.dependency_action_entrypoints',
```

- [ ] **Step 2: Add install first-run fixture**

Inside `$fixture.smoke`, add:

```powershell
install = [ordered]@{
    first_run_system_proxy_ready = $true
    first_run_tun_ready = $false
    first_run_blockers = @(
        [ordered]@{
            code = 'wintun-missing'
            message = 'Wintun library was not found'
            action = 'install-wintun'
        }
    )
    dependency_action_entrypoints = @('install-wintun')
}
```

- [ ] **Step 3: Add JSON assertions**

After signing assertions, add:

```powershell
if ($report.install_first_run.system_proxy_ready -ne $true) {
    throw 'readiness install first-run system proxy should be ready'
}
if ($report.install_first_run.tun_ready -ne $false) {
    throw 'readiness install first-run TUN should be blocked'
}
if ($report.install_first_run.blockers.Count -ne 1) {
    throw "readiness install first-run blocker count mismatch: $($report.install_first_run.blockers.Count)"
}
if ($report.install_first_run.blockers[0].code -ne 'wintun-missing') {
    throw "readiness install first-run blocker code mismatch: $($report.install_first_run.blockers[0].code)"
}
if (($report.install_first_run.dependency_action_entrypoints -join ',') -ne 'install-wintun') {
    throw "readiness install dependency action entrypoints mismatch: $($report.install_first_run.dependency_action_entrypoints -join ',')"
}
```

- [ ] **Step 4: Add text output assertions**

After the JSON assertions, run text mode:

```powershell
$textOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $readinessScript -EvidencePath $fixturePath
if ($LASTEXITCODE -ne 0) {
    throw "desktop-release-readiness.ps1 text mode exited with $LASTEXITCODE"
}
$text = $textOutput -join "`n"
foreach ($item in @(
    'install_first_run_system_proxy_ready true',
    'install_first_run_tun_ready false',
    'install_first_run_blockers wintun-missing',
    'install_dependency_action_entrypoints install-wintun'
)) {
    if (!$text.Contains($item)) {
        throw "readiness text output missing: $item"
    }
}
```

- [ ] **Step 5: Run RED test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
```

Expected: FAIL because PlanOnly and report fields do not exist yet.

## Task 2: GREEN Readiness Dependency Diagnostics

**Files:**
- Modify: `scripts/desktop-release-readiness.ps1`

- [ ] **Step 1: Add blocker helper**

Add near `Get-SignCommandPreviewsProperty`:

```powershell
function Get-FirstRunBlockersProperty {
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (!(Test-JsonProperty -InputObject $InputObject -Name $Name)) {
        return @()
    }

    return @($InputObject.$Name | ForEach-Object {
        [ordered]@{
            code = Get-StringProperty -InputObject $_ -Name 'code'
            message = Get-StringProperty -InputObject $_ -Name 'message'
            action = Get-StringProperty -InputObject $_ -Name 'action'
        }
    })
}
```

- [ ] **Step 2: Read install smoke**

Inside `New-ReadinessReport`, add:

```powershell
$install = if (Test-JsonProperty -InputObject $smoke -Name 'install') { $smoke.install } else { $null }
```

- [ ] **Step 3: Add report field**

Add to the report:

```powershell
install_first_run = [ordered]@{
    system_proxy_ready = Get-BoolProperty -InputObject $install -Name 'first_run_system_proxy_ready'
    tun_ready = Get-BoolProperty -InputObject $install -Name 'first_run_tun_ready'
    blockers = @(Get-FirstRunBlockersProperty -InputObject $install -Name 'first_run_blockers')
    dependency_action_entrypoints = @(Get-StringArrayProperty -InputObject $install -Name 'dependency_action_entrypoints')
}
```

- [ ] **Step 4: Print text lines**

Inside `Write-ReadinessText`, add:

```powershell
Write-Output "install_first_run_system_proxy_ready $(Format-Bool -Value $Report.install_first_run.system_proxy_ready)"
Write-Output "install_first_run_tun_ready $(Format-Bool -Value $Report.install_first_run.tun_ready)"
Write-Output "install_first_run_blockers $($Report.install_first_run.blockers.code -join ',')"
Write-Output "install_dependency_action_entrypoints $($Report.install_first_run.dependency_action_entrypoints -join ',')"
```

- [ ] **Step 5: Extend PlanOnly**

Add:

```powershell
Write-Output 'read smoke.install.first_run_system_proxy_ready smoke.install.first_run_tun_ready smoke.install.first_run_blockers smoke.install.dependency_action_entrypoints'
```

- [ ] **Step 6: Run GREEN test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
```

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-release-readiness-first-run-dependency-diagnostics.md`
- `scripts/desktop-release-readiness.ps1`
- `scripts/desktop-release-readiness.tests.ps1`

- [ ] **Step 1: Focused test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Real readiness output**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1
```

Expected: PASS and show install first-run dependency diagnostics.

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
git add docs/superpowers/plans/2026-06-12-desktop-release-readiness-first-run-dependency-diagnostics.md
git commit -m "Plan readiness dependency diagnostics"
git push
git add scripts/desktop-release-readiness.ps1 scripts/desktop-release-readiness.tests.ps1
git commit -m "Expose readiness dependency diagnostics"
git push
```

## Self-Review Checklist

- Spec coverage: release readiness now shows Wintun/system-proxy first-run diagnostics.
- Placeholder scan: no placeholder markers remain.
- Type consistency: JSON field is `install_first_run`; text keys start with `install_first_run_` or `install_dependency_`.
- Scope: gate behavior and signing behavior remain unchanged.
- Release honesty: public release remains blocked by signing until real signatures exist.
