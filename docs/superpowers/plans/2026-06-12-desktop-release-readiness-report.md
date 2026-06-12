# Desktop Release Readiness Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one operator-friendly readiness entry point that summarizes whether the desktop public release can ship, why it is blocked, and which exact release commands to run next.

**Architecture:** Keep `scripts/desktop-release-evidence.ps1` as the source of truth and keep `scripts/desktop-public-release-gate.ps1` as the pass/fail gate. Add a read-only `scripts/desktop-release-readiness.ps1` that consumes the existing evidence JSON and formats the current blockers, next steps, signing readiness, machine takeover state, and safe command hints without printing secrets.

**Tech Stack:** PowerShell 5+, existing desktop release evidence JSON, existing signing and public release scripts.

---

## Scope Check

This slice covers:

- A new read-only release readiness script.
- Plan-only output that documents the script contract.
- JSON output for automation and text output for operators.
- Focused tests for the plan contract and JSON summary contract.
- Actual verification against the current release evidence.

This slice does not cover:

- Installing or generating a code signing certificate.
- Signing artifacts.
- Changing public release gate pass/fail criteria.
- Publishing GitHub Releases.

## File Structure

- Create: `scripts/desktop-release-readiness.ps1`
  - Reads `target\desktop\keli-desktop-release-evidence.json`.
  - Outputs a normalized readiness report as text or JSON.
  - Emits safe commands sourced from existing signing evidence when present.
- Create: `scripts/desktop-release-readiness.tests.ps1`
  - Verifies `-PlanOnly` output.
  - Verifies `-Json` output against a temporary fixture.

## Task 1: RED Readiness Tests

**Files:**
- Create: `scripts/desktop-release-readiness.tests.ps1`

- [ ] **Step 1: Add failing plan and JSON tests**

Create the test file with:

```powershell
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$readinessScript = Join-Path $scriptDir 'desktop-release-readiness.ps1'

if (!(Test-Path -LiteralPath $readinessScript)) {
    throw 'desktop-release-readiness.ps1 was not found'
}

$planOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $readinessScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-release-readiness.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $planOutput -join "`n"
$expectedPlan = @(
    'input target\desktop\keli-desktop-release-evidence.json',
    'read public_release_ready public_release_blockers public_release_next_steps',
    'read signing.can_sign signing.store_certificate_candidates_count signing.release_commands',
    'read smoke.machine.machine_takeover_status',
    'output desktop public release readiness report',
    'output json when -Json is provided'
)

foreach ($item in $expectedPlan) {
    if (!$plan.Contains($item)) {
        throw "desktop release readiness plan is missing: $item"
    }
}

$tempDir = Join-Path $repoRoot 'target\desktop-readiness-tests'
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
$fixturePath = Join-Path $tempDir 'release-evidence.json'

$fixture = [ordered]@{
    public_release_ready = $false
    public_release_blockers = @('artifact-signature-missing', 'signing-certificate-missing')
    public_release_next_steps = @('configure-code-signing-certificate', 'run-desktop-signing-sign', 'run-public-release-gate')
    signing = [ordered]@{
        can_sign = $false
        store_certificate_candidates_count = 0
        release_commands = [ordered]@{
            inspect = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1'
            sign = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign'
            public_release_gate = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1'
        }
    }
    smoke = [ordered]@{
        machine = [ordered]@{
            machine_takeover_status = 'ready'
        }
    }
}
$fixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $fixturePath -Encoding ASCII

$jsonOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $readinessScript -EvidencePath $fixturePath -Json
if ($LASTEXITCODE -ne 0) {
    throw "desktop-release-readiness.ps1 -Json exited with $LASTEXITCODE"
}

$report = $jsonOutput -join "`n" | ConvertFrom-Json
if ($report.public_release_ready -ne $false) {
    throw 'readiness report should preserve public_release_ready false'
}
if (($report.blockers -join ',') -ne 'artifact-signature-missing,signing-certificate-missing') {
    throw "readiness blockers mismatch: $($report.blockers -join ',')"
}
if (($report.next_steps -join ',') -ne 'configure-code-signing-certificate,run-desktop-signing-sign,run-public-release-gate') {
    throw "readiness next steps mismatch: $($report.next_steps -join ',')"
}
if ($report.signing.can_sign -ne $false) {
    throw 'readiness signing can_sign should be false'
}
if ($report.signing.store_certificate_candidates_count -ne 0) {
    throw "readiness signing certificate candidate count mismatch: $($report.signing.store_certificate_candidates_count)"
}
if ($report.machine_takeover_status -ne 'ready') {
    throw "readiness machine takeover status mismatch: $($report.machine_takeover_status)"
}
if ($report.commands.sign -ne 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign') {
    throw "readiness sign command mismatch: $($report.commands.sign)"
}

Write-Output 'desktop release readiness tests passed'
```

- [ ] **Step 2: Run RED test**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
```

Expected: FAIL because `scripts\desktop-release-readiness.ps1` does not exist.

## Task 2: Implement Readiness Script

**Files:**
- Create: `scripts/desktop-release-readiness.ps1`

- [ ] **Step 1: Add script parameters and plan-only contract**

Implement parameters:

```powershell
param(
    [string]$EvidencePath,
    [switch]$Json,
    [switch]$PlanOnly
)
```

For `-PlanOnly`, output:

```powershell
input target\desktop\keli-desktop-release-evidence.json
read public_release_ready public_release_blockers public_release_next_steps
read signing.can_sign signing.store_certificate_candidates_count signing.release_commands
read smoke.machine.machine_takeover_status
output desktop public release readiness report
output json when -Json is provided
```

- [ ] **Step 2: Build normalized report**

Read evidence JSON and build an ordered object with:

```powershell
public_release_ready
blockers
next_steps
machine_takeover_status
signing.can_sign
signing.store_certificate_candidates_count
commands.inspect
commands.sign
commands.public_release_gate
```

- [ ] **Step 3: Add JSON and text output**

When `-Json` is provided, emit `ConvertTo-Json -Depth 8`. Otherwise print concise lines:

```powershell
ready false
blockers artifact-signature-missing,signing-certificate-missing
next_steps configure-code-signing-certificate,run-desktop-signing-sign,run-public-release-gate
machine_takeover_status ready
signing_can_sign false
signing_certificate_candidates 0
command.sign powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign
command.public_release_gate powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1
```

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-release-readiness-report.md`
- `scripts/desktop-release-readiness.ps1`
- `scripts/desktop-release-readiness.tests.ps1`

- [ ] **Step 1: Focused tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Actual readiness JSON**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
```

Expected: PASS and report shows `public_release_ready=false`, signing blockers, next steps, and `machine_takeover_status=ready`.

- [ ] **Step 3: Existing public release gate still blocks correctly**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: FAIL with signing blockers and `next_steps=configure-code-signing-certificate,run-desktop-signing-sign,run-public-release-gate`.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-release-readiness-report.md
git commit -m "Plan desktop release readiness report"
git push origin main
git add scripts/desktop-release-readiness.ps1 scripts/desktop-release-readiness.tests.ps1
git commit -m "Add desktop release readiness report"
git push origin main
```

## Self-Review Checklist

- Spec coverage: operator gets one command to inspect release readiness.
- Placeholder scan: script names, fields, commands, and expected outputs are concrete.
- Scope: the report is read-only and cannot bypass signing or public release gates.
- Secret safety: no certificate password or secret value is printed.
