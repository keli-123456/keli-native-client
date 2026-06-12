# Desktop MVP Status Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a machine-readable desktop MVP status audit that separates local desktop MVP readiness from public release signing readiness.

**Architecture:** Read the existing `target\desktop\keli-desktop-release-evidence.json` as the single source of truth. Derive a compact requirement list for the user-facing desktop MVP workflows, packaging evidence, machine takeover evidence, and public release state without regenerating artifacts or weakening any release gate.

**Tech Stack:** PowerShell 5+, existing desktop release evidence JSON, existing smoke workflow IDs and public release blocker fields.

---

## Scope Check

This slice covers:

- A new `scripts/desktop-mvp-status.ps1` script with `-PlanOnly`, `-Json`, and optional `-EvidencePath`.
- A focused test fixture proving the script reports `desktop_mvp_ready = true` while `public_release_ready = false` when only signing blockers remain.
- Requirement records for:
  - `native-core-default`
  - `package-artifacts`
  - `install-smoke-workflows`
  - `msi-smoke-workflows`
  - `machine-takeover`
  - `public-release-signing`
- Text output for quick operator status and JSON output for automation.

This slice does not cover:

- Signing artifacts.
- Regenerating release evidence.
- Changing the public release gate.
- Claiming the full long-running goal is complete while public release signing remains blocked.

## File Structure

- Create: `scripts/desktop-mvp-status.ps1`
  - Reads release evidence and derives a status report.
  - Defaults to `target\desktop\keli-desktop-release-evidence.json`.
  - Supports `-Json` for automation and text output for quick CLI checks.
- Create: `scripts/desktop-mvp-status.tests.ps1`
  - Verifies `-PlanOnly`.
  - Creates a fixture release evidence file.
  - Asserts the JSON report distinguishes local MVP readiness from public release readiness.

## Task 1: RED Desktop MVP Status Test

**Files:**
- Create: `scripts/desktop-mvp-status.tests.ps1`

- [ ] **Step 1: Create the failing test**

Create `scripts/desktop-mvp-status.tests.ps1`:

```powershell
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$statusScript = Join-Path $scriptDir 'desktop-mvp-status.ps1'

if (!(Test-Path -LiteralPath $statusScript)) {
    throw 'desktop-mvp-status.ps1 was not found'
}

$planOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $statusScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-mvp-status.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $planOutput -join "`n"
$expectedPlan = @(
    'input target\desktop\keli-desktop-release-evidence.json',
    'read native_core_default artifacts smoke.install smoke.msi smoke.machine signing public_release_blockers public_release_next_steps',
    'require workflow ids open-desktop-shell import-subscription select-node start-stop-system-proxy tun-preflight export-support-bundle',
    'output desktop_mvp_ready and public_release_ready',
    'output json when -Json is provided'
)
foreach ($item in $expectedPlan) {
    if (!$plan.Contains($item)) {
        throw "desktop MVP status plan is missing: $item"
    }
}

$tempDir = Join-Path $repoRoot 'target\desktop-mvp-status-tests'
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
$fixturePath = Join-Path $tempDir 'release-evidence.json'
$workflowIds = @(
    'open-desktop-shell',
    'import-subscription',
    'select-node',
    'start-stop-system-proxy',
    'tun-preflight',
    'export-support-bundle'
)

$fixture = [ordered]@{
    status = 'passed'
    native_core_default = $true
    public_release_ready = $false
    public_release_blockers = @('artifact-signature-missing', 'signing-certificate-missing')
    public_release_next_steps = @('configure-code-signing-certificate', 'run-desktop-signing-sign', 'run-public-release-gate')
    artifacts = @(
        [ordered]@{ kind = 'desktop-shell-exe'; path = 'target\release\keli-desktop-shell.exe' },
        [ordered]@{ kind = 'portable-zip'; path = 'target\desktop\keli-desktop-mvp-windows-x64.zip' },
        [ordered]@{ kind = 'desktop-msi'; path = 'target\desktop\keli-desktop-mvp-windows-x64.msi' }
    )
    signing = [ordered]@{
        can_sign = $false
        signtool_available = $true
        unsigned_artifacts = @('target\release\keli-desktop-shell.exe', 'target\desktop\keli-desktop-mvp-windows-x64.msi')
    }
    smoke = [ordered]@{
        install = [ordered]@{
            status = 'passed'
            native_core_default = $true
            readme_subscription_import = 'subscription-url-or-config'
            manual_smoke_cases = $workflowIds
            verified_ui_workflow_entrypoints = $workflowIds
        }
        msi = [ordered]@{
            status = 'passed'
            native_core_default = $true
            readme_subscription_import = 'subscription-url-or-config'
            manual_smoke_cases = $workflowIds
        }
        machine = [ordered]@{
            status = 'passed'
            native_core_default = $true
            machine_takeover_status = 'ready'
        }
    }
}
$fixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $fixturePath -Encoding ASCII

$jsonOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $statusScript -EvidencePath $fixturePath -Json
if ($LASTEXITCODE -ne 0) {
    throw "desktop-mvp-status.ps1 -Json exited with $LASTEXITCODE"
}

$report = $jsonOutput -join "`n" | ConvertFrom-Json
if ($report.desktop_mvp_ready -ne $true) {
    throw 'desktop MVP should be ready when all local workflow/package/machine requirements pass'
}
if ($report.public_release_ready -ne $false) {
    throw 'public release should remain blocked in the unsigned fixture'
}
if (($report.public_release_blockers -join ',') -ne 'artifact-signature-missing,signing-certificate-missing') {
    throw "public release blockers mismatch: $($report.public_release_blockers -join ',')"
}
if (($report.remaining_external_blockers -join ',') -ne 'artifact-signature-missing,signing-certificate-missing') {
    throw "external blockers mismatch: $($report.remaining_external_blockers -join ',')"
}
$requirementStatuses = @{}
foreach ($requirement in $report.requirements) {
    $requirementStatuses[[string]$requirement.id] = [string]$requirement.status
}
foreach ($id in @('native-core-default', 'package-artifacts', 'install-smoke-workflows', 'msi-smoke-workflows', 'machine-takeover')) {
    if ($requirementStatuses[$id] -ne 'ready') {
        throw "requirement $id should be ready but was $($requirementStatuses[$id])"
    }
}
if ($requirementStatuses['public-release-signing'] -ne 'blocked') {
    throw "public-release-signing should be blocked but was $($requirementStatuses['public-release-signing'])"
}

Write-Output 'desktop MVP status tests passed'
```

- [ ] **Step 2: Run RED test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
```

Expected: FAIL because `desktop-mvp-status.ps1` does not exist yet.

## Task 2: GREEN Desktop MVP Status Script

**Files:**
- Create: `scripts/desktop-mvp-status.ps1`

- [ ] **Step 1: Implement parameters and common readers**

Add:

```powershell
[CmdletBinding()]
param(
    [string]$EvidencePath,
    [switch]$Json,
    [switch]$PlanOnly
)
```

Include helpers:

```powershell
Resolve-RepoRoot
Require-File
Test-JsonProperty
Get-StringArrayProperty
Get-BoolProperty
```

- [ ] **Step 2: Implement workflow and artifact checks**

Use these expected workflow IDs:

```powershell
$expectedWorkflows = @(
    'open-desktop-shell',
    'import-subscription',
    'select-node',
    'start-stop-system-proxy',
    'tun-preflight',
    'export-support-bundle'
)
```

Check artifact kinds:

```powershell
desktop-shell-exe
portable-zip
desktop-msi
```

- [ ] **Step 3: Build requirement records**

Return ordered requirement objects:

```powershell
[ordered]@{
    id = 'native-core-default'
    status = 'ready'
    evidence = 'release.native_core_default'
}
```

Use `ready` or `blocked`. The first five local requirements must drive `desktop_mvp_ready`. `public-release-signing` is separate and should be `ready` only when `public_release_ready` is true and no release blockers remain.

- [ ] **Step 4: Implement text and JSON output**

JSON report fields:

```powershell
desktop_mvp_ready
public_release_ready
public_release_blockers
public_release_next_steps
remaining_external_blockers
requirements
```

Text output lines:

```powershell
desktop_mvp_ready true
public_release_ready false
public_release_blockers artifact-signature-missing,signing-certificate-missing
remaining_external_blockers artifact-signature-missing,signing-certificate-missing
requirement.native-core-default ready
```

- [ ] **Step 5: Run GREEN test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
```

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-mvp-status-audit.md`
- `scripts/desktop-mvp-status.ps1`
- `scripts/desktop-mvp-status.tests.ps1`

- [ ] **Step 1: Focused test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Actual status report**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.ps1 -Json
```

Expected: `desktop_mvp_ready = true`, `public_release_ready = false`, and remaining blockers are only signing.

- [ ] **Step 3: Full desktop MVP gate**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-mvp-status-audit.md
git commit -m "Plan desktop MVP status audit"
git push
git add scripts/desktop-mvp-status.ps1 scripts/desktop-mvp-status.tests.ps1
git commit -m "Add desktop MVP status audit"
git push
```

## Self-Review Checklist

- Spec coverage: every user-facing MVP objective maps to an evidence-backed requirement.
- Placeholder scan: all paths, IDs, fields, and commands are concrete.
- Type consistency: requirement IDs match test assertions.
- Scope: the audit is read-only and does not regenerate artifacts or change gates.
- Release honesty: `desktop_mvp_ready` is separate from `public_release_ready`, and signing blockers remain visible.
