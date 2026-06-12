# Desktop Public Gate First Run Dependency Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `desktop-public-release-gate.ps1` directly reject release evidence that lacks first-run dependency blocker UI action evidence, even when the gate is run with `-SkipGate -EvidencePath`.

**Architecture:** Reuse the same evidence contract now enforced by `desktop-mvp-status.ps1`: install smoke must carry `first_run_system_proxy_ready`, `first_run_tun_ready`, `first_run_blockers`, and matching `dependency_action_entrypoints` for every blocker action. Public release gate adds a dedicated blocker when this evidence is absent or incomplete.

**Tech Stack:** PowerShell 5+, existing desktop public release gate script and tests.

---

## Scope Check

This slice covers:

- New public gate requirement line for install first-run dependency action evidence.
- New public gate blocker: `install-first-run-dependency-evidence-missing`.
- Tests proving weak evidence with missing dependency action entrypoints is blocked.
- Existing signing diagnostics remain unchanged.

This slice does not cover:

- Changing desktop shell HTML or install smoke generation.
- Changing MVP status output.
- Signing artifacts or changing signing blockers.

## File Structure

- Modify: `scripts/desktop-public-release-gate.tests.ps1`
  - Add PlanOnly expectation.
  - Add first-run dependency evidence to the normal fixture.
  - Add a weak-evidence fixture with missing `dependency_action_entrypoints`.
  - Assert the weak fixture names `install-first-run-dependency-evidence-missing`.
- Modify: `scripts/desktop-public-release-gate.ps1`
  - Add helper to validate first-run dependency evidence.
  - Add the blocker inside workflow evidence validation.
  - Extend PlanOnly output.

## Task 1: RED Public Gate Dependency Evidence Tests

**Files:**
- Modify: `scripts/desktop-public-release-gate.tests.ps1`

- [ ] **Step 1: Add PlanOnly expectation**

Add:

```powershell
'require smoke.install first_run dependency blockers have action entrypoints',
```

- [ ] **Step 2: Add dependency evidence to existing fixture**

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

- [ ] **Step 3: Add weak evidence fixture**

After the current blocked-output assertions, add:

```powershell
$dependencyFixturePath = Join-Path $tempDir 'release-evidence-missing-dependency-action.json'
$dependencyFixture = Get-Content -Raw -LiteralPath $fixturePath | ConvertFrom-Json
$dependencyFixture.smoke.install.dependency_action_entrypoints = @()
$dependencyFixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $dependencyFixturePath -Encoding ASCII

$dependencyStdoutPath = Join-Path $tempDir 'gate-dependency-stdout.txt'
$dependencyStderrPath = Join-Path $tempDir 'gate-dependency-stderr.txt'
$dependencyProcess = Start-Process `
    -FilePath 'powershell' `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $gateScript, '-SkipGate', '-EvidencePath', $dependencyFixturePath) `
    -NoNewWindow `
    -Wait `
    -PassThru `
    -RedirectStandardOutput $dependencyStdoutPath `
    -RedirectStandardError $dependencyStderrPath
if ($dependencyProcess.ExitCode -eq 0) {
    throw 'desktop-public-release-gate.ps1 should fail missing dependency action evidence'
}
$dependencyFailureText = @(
    if (Test-Path -LiteralPath $dependencyStdoutPath) {
        Get-Content -LiteralPath $dependencyStdoutPath
    }
    if (Test-Path -LiteralPath $dependencyStderrPath) {
        Get-Content -LiteralPath $dependencyStderrPath
    }
) -join "`n"
$normalizedDependencyFailureText = $dependencyFailureText -replace "(`r`n|`n|`r)", ''
if (!$normalizedDependencyFailureText.Contains('install-first-run-dependency-evidence-missing')) {
    throw "dependency evidence failure did not name install-first-run-dependency-evidence-missing: $dependencyFailureText"
}
```

- [ ] **Step 4: Run RED test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: FAIL because the PlanOnly requirement and blocker do not exist yet.

## Task 2: GREEN Public Gate Dependency Evidence Requirement

**Files:**
- Modify: `scripts/desktop-public-release-gate.ps1`

- [ ] **Step 1: Add helper**

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

    $systemProxyReady = [bool]$InstallSmoke.first_run_system_proxy_ready
    $tunReady = [bool]$InstallSmoke.first_run_tun_ready
    $blockers = @()
    if (Test-JsonProperty -InputObject $InstallSmoke -Name 'first_run_blockers') {
        $blockers = @($InstallSmoke.first_run_blockers)
    }

    if ((!$systemProxyReady -or !$tunReady) -and $blockers.Count -eq 0) {
        return $false
    }
    if ($blockers.Count -eq 0) {
        return $true
    }
    if (!(Test-JsonProperty -InputObject $InstallSmoke -Name 'dependency_action_entrypoints')) {
        return $false
    }

    $actions = Get-StringArrayProperty -InputObject $InstallSmoke -Name 'dependency_action_entrypoints'
    foreach ($blocker in $blockers) {
        if (!(Test-JsonProperty -InputObject $blocker -Name 'action')) {
            return $false
        }
        $action = [string]$blocker.action
        if ([string]::IsNullOrWhiteSpace($action) -or $actions -notcontains $action) {
            return $false
        }
    }
    return $true
}
```

- [ ] **Step 2: Add blocker**

Inside `Add-WorkflowEvidenceBlockers`, after install workflow checks, add:

```powershell
if (!(Test-InstallFirstRunDependencyEvidence -InstallSmoke $Evidence.smoke.install)) {
    $Blockers = Add-UniqueBlocker -Blockers $Blockers -Blocker 'install-first-run-dependency-evidence-missing'
}
```

- [ ] **Step 3: Extend PlanOnly**

Add:

```powershell
Write-Output 'require smoke.install first_run dependency blockers have action entrypoints'
```

- [ ] **Step 4: Run GREEN test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-public-gate-first-run-dependency-evidence.md`
- `scripts/desktop-public-release-gate.ps1`
- `scripts/desktop-public-release-gate.tests.ps1`

- [ ] **Step 1: Focused test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Full desktop MVP gate**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS.

- [ ] **Step 3: Public release honesty check**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: FAIL only with signing blockers for current real evidence.

- [ ] **Step 4: Diff check**

Run:

```powershell
git diff --check
```

Expected: PASS.

- [ ] **Step 5: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-public-gate-first-run-dependency-evidence.md
git commit -m "Plan public gate dependency evidence"
git push
git add scripts/desktop-public-release-gate.ps1 scripts/desktop-public-release-gate.tests.ps1
git commit -m "Require public gate dependency evidence"
git push
```

## Self-Review Checklist

- Spec coverage: hard public gate rejects release evidence missing first-run dependency action evidence.
- Placeholder scan: no placeholder markers remain.
- Type consistency: blocker ID is `install-first-run-dependency-evidence-missing`.
- Scope: runtime behavior and signing behavior remain unchanged.
- Release honesty: current real evidence still fails only on signing blockers.
