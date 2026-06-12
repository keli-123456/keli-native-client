# Desktop MVP Status First Run Dependency Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `desktop-mvp-status.ps1` require first-run dependency blocker and UI action evidence before reporting the local desktop MVP as ready.

**Architecture:** Treat `target\desktop\keli-desktop-release-evidence.json` as the source of release audit truth. The install smoke evidence already carries `first_run_blockers` and `dependency_action_entrypoints`; this slice adds a local MVP requirement that proves each first-run blocker with an action has a matching UI action entrypoint.

**Tech Stack:** PowerShell 5+, existing desktop MVP status audit script and tests.

---

## Scope Check

This slice covers:

- New local MVP requirement: `install-first-run-dependencies`.
- JSON/text status output showing that requirement.
- `-FailOnMvpBlocked` failing when dependency evidence is missing or incomplete.
- Tests proving the requirement is ready when Wintun blocker action evidence is present.

This slice does not cover:

- Changing desktop shell HTML.
- Changing install smoke generation.
- Changing public release signing blockers.
- Adding a new public release gate blocker; the MVP status audit is the local gate source for this slice.

## File Structure

- Modify: `scripts/desktop-mvp-status.tests.ps1`
  - Add PlanOnly expectation.
  - Add first-run dependency fields to the ready fixture.
  - Assert `install-first-run-dependencies` is ready.
  - Add a blocked fixture that removes the dependency action entrypoint and assert the failure names this requirement.
- Modify: `scripts/desktop-mvp-status.ps1`
  - Add helper to validate install first-run dependency evidence.
  - Add the helper result as a local requirement.
  - Extend PlanOnly output.

## Task 1: RED MVP Status Dependency Evidence Tests

**Files:**
- Modify: `scripts/desktop-mvp-status.tests.ps1`

- [ ] **Step 1: Add PlanOnly expectation**

Add:

```powershell
'require install first_run dependency blockers have action entrypoints',
```

- [ ] **Step 2: Add dependency fields to ready fixture**

Inside `$fixture.smoke.install`, add:

```powershell
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
```

- [ ] **Step 3: Assert new requirement is ready**

Update the ready requirement loop to include:

```powershell
'install-first-run-dependencies'
```

- [ ] **Step 4: Add blocked dependency evidence fixture**

Add a second blocked fixture after the existing workflow-blocked check:

```powershell
$dependencyBlockedFixturePath = Join-Path $tempDir 'release-evidence-dependency-blocked.json'
$dependencyBlockedFixture = $fixture
$dependencyBlockedFixture.smoke.install.dependency_action_entrypoints = @()
$dependencyBlockedFixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $dependencyBlockedFixturePath -Encoding ASCII

$dependencyStdoutPath = Join-Path $tempDir 'status-dependency-blocked-stdout.txt'
$dependencyStderrPath = Join-Path $tempDir 'status-dependency-blocked-stderr.txt'
$dependencyProcess = Start-Process `
    -FilePath 'powershell' `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $statusScript, '-EvidencePath', $dependencyBlockedFixturePath, '-FailOnMvpBlocked') `
    -NoNewWindow `
    -Wait `
    -PassThru `
    -RedirectStandardOutput $dependencyStdoutPath `
    -RedirectStandardError $dependencyStderrPath
if ($dependencyProcess.ExitCode -eq 0) {
    throw 'desktop-mvp-status.ps1 -FailOnMvpBlocked should fail missing dependency action evidence'
}
$dependencyFailureText = @(
    if (Test-Path -LiteralPath $dependencyStdoutPath) {
        Get-Content -LiteralPath $dependencyStdoutPath
    }
    if (Test-Path -LiteralPath $dependencyStderrPath) {
        Get-Content -LiteralPath $dependencyStderrPath
    }
) -join "`n"
if (!$dependencyFailureText.Contains('Desktop MVP status blocked: install-first-run-dependencies')) {
    throw "dependency blocked failure did not name install-first-run-dependencies: $dependencyFailureText"
}
```

- [ ] **Step 5: Run RED test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
```

Expected: FAIL because the PlanOnly output and requirement do not exist yet.

## Task 2: GREEN MVP Status Requirement

**Files:**
- Modify: `scripts/desktop-mvp-status.ps1`

- [ ] **Step 1: Add helper for dependency evidence**

Add near `Test-StringArrayContainsAll`:

```powershell
function Test-InstallFirstRunDependencyEvidence {
    param(
        [AllowNull()]
        [object]$InstallSmoke
    )

    if (!(Test-JsonProperty -InputObject $InstallSmoke -Name 'first_run_system_proxy_ready')) {
        return $false
    }
    if (!(Test-JsonProperty -InputObject $InstallSmoke -Name 'first_run_tun_ready')) {
        return $false
    }
    if (!(Test-JsonProperty -InputObject $InstallSmoke -Name 'first_run_blockers')) {
        return $false
    }
    if (!(Test-JsonProperty -InputObject $InstallSmoke -Name 'dependency_action_entrypoints')) {
        return $false
    }

    $actions = Get-StringArrayProperty -InputObject $InstallSmoke -Name 'dependency_action_entrypoints'
    $blockerActions = @($InstallSmoke.first_run_blockers |
        ForEach-Object {
            if ($null -ne $_.PSObject.Properties['action']) { [string]$_.action }
        } |
        Where-Object { ![string]::IsNullOrWhiteSpace($_) })

    foreach ($action in $blockerActions) {
        if ($actions -notcontains $action) {
            return $false
        }
    }
    return $true
}
```

- [ ] **Step 2: Add requirement**

Inside `New-DesktopMvpStatus`, compute:

```powershell
$installFirstRunDependencyReady = Test-InstallFirstRunDependencyEvidence -InstallSmoke $installSmoke
```

Add to `$localRequirements`:

```powershell
(New-Requirement -Id 'install-first-run-dependencies' -Ready $installFirstRunDependencyReady -Evidence 'release.smoke.install.first_run_blockers'),
```

- [ ] **Step 3: Extend PlanOnly**

Add:

```powershell
Write-Output 'require install first_run dependency blockers have action entrypoints'
```

- [ ] **Step 4: Run GREEN test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
```

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-mvp-status-first-run-dependency-evidence.md`
- `scripts/desktop-mvp-status.ps1`
- `scripts/desktop-mvp-status.tests.ps1`

- [ ] **Step 1: Focused test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Full desktop MVP gate**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS, with `requirement.install-first-run-dependencies ready`.

- [ ] **Step 3: Public release honesty check**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: FAIL only with signing blockers until a real signing certificate signs the EXE/MSI.

- [ ] **Step 4: Diff check**

Run:

```powershell
git diff --check
```

Expected: PASS.

- [ ] **Step 5: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-mvp-status-first-run-dependency-evidence.md
git commit -m "Plan MVP dependency evidence status"
git push
git add scripts/desktop-mvp-status.ps1 scripts/desktop-mvp-status.tests.ps1
git commit -m "Require MVP dependency evidence status"
git push
```

## Self-Review Checklist

- Spec coverage: local MVP readiness now requires proof that first-run dependency blockers have UI action entrypoints.
- Placeholder scan: no placeholder markers remain.
- Type consistency: requirement ID is `install-first-run-dependencies` everywhere.
- Scope: signing and runtime dependency behavior remain unchanged.
- Release honesty: public release remains blocked by signing until real signatures exist.
