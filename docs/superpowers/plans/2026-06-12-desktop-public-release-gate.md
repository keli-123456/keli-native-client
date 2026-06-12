# Desktop Public Release Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a hard public-release gate that runs the desktop MVP gate with real machine takeover and fails unless release evidence says the Windows desktop artifacts are ready for public release.

**Architecture:** Add a standalone PowerShell script that can regenerate release evidence by running `scripts\desktop-mvp-gate.ps1 -IncludeMachineTakeover`, then reads `target\desktop\keli-desktop-release-evidence.json`. The script passes only when `public_release_ready` is true, machine takeover is ready, signing can sign, and no public-release blockers remain. It is intentionally separate from the local MVP gate because unsigned local builds should keep passing while public release remains blocked.

**Tech Stack:** PowerShell 5+, existing desktop MVP gate, existing release evidence JSON.

---

## Scope Check

This slice covers:

- A standalone public-release gate command.
- Plan-only output that documents required inputs and pass/fail criteria.
- A skip-regeneration mode for focused tests against the current evidence file.
- Clear nonzero failure with blocker names when public release is not ready.

This slice does not cover:

- Installing or provisioning a signing certificate.
- Signing artifacts.
- Publishing GitHub Releases.
- Changing the local desktop MVP gate success criteria.

## File Structure

- Create: `scripts/desktop-public-release-gate.ps1`
  - Runs `desktop-mvp-gate.ps1 -IncludeMachineTakeover` unless `-SkipGate` is supplied.
  - Reads `target\desktop\keli-desktop-release-evidence.json`.
  - Fails if public release is blocked.
- Create: `scripts/desktop-public-release-gate.tests.ps1`
  - Verifies `-PlanOnly` output includes the underlying gate command, release evidence input, readiness requirements, failure behavior, and output marker.

## Task 1: RED Plan Test

**Files:**
- Create: `scripts/desktop-public-release-gate.tests.ps1`

- [ ] **Step 1: Add public release gate plan test**

Create `scripts/desktop-public-release-gate.tests.ps1`:

```powershell
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$gateScript = Join-Path $scriptDir 'desktop-public-release-gate.ps1'

if (!(Test-Path -LiteralPath $gateScript)) {
    throw "desktop-public-release-gate.ps1 was not found"
}

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $gateScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-public-release-gate.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $output -join "`n"
$expected = @(
    'command powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1 -IncludeMachineTakeover',
    'input target\desktop\keli-desktop-release-evidence.json',
    'require public_release_ready true',
    'require smoke.machine.machine_takeover_status ready',
    'require signing.can_sign true',
    'require public_release_blockers empty',
    'failure print blockers and exit nonzero',
    'output public release gate passed'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop public release gate plan is missing: $item"
    }
}

Write-Output 'desktop public release gate plan test passed'
```

- [ ] **Step 2: Run RED test**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: FAIL because `desktop-public-release-gate.ps1` does not exist.

## Task 2: Implement Public Release Gate Script

**Files:**
- Create: `scripts/desktop-public-release-gate.ps1`

- [ ] **Step 1: Add parameters and helpers**

Add:

```powershell
[switch]$PlanOnly
[switch]$SkipGate

Resolve-RepoRoot
Require-File
Invoke-CommandLine
Read-ReleaseEvidence
```

- [ ] **Step 2: Implement plan-only output**

`-PlanOnly` must emit:

```powershell
command powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1 -IncludeMachineTakeover
input target\desktop\keli-desktop-release-evidence.json
require public_release_ready true
require smoke.machine.machine_takeover_status ready
require signing.can_sign true
require public_release_blockers empty
failure print blockers and exit nonzero
output public release gate passed
```

- [ ] **Step 3: Implement gate behavior**

Default behavior:

1. Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1 -IncludeMachineTakeover
```

2. Read `target\desktop\keli-desktop-release-evidence.json`.
3. Fail if any of these is false:
   - `public_release_ready -eq $true`
   - `smoke.machine.machine_takeover_status -eq 'ready'`
   - `signing.can_sign -eq $true`
   - `public_release_blockers` is empty
4. Print the blocker list and exit nonzero when blocked.

`-SkipGate` behavior:

- Do not regenerate artifacts.
- Read the current release evidence file and apply the same checks.
- This is used for quick verification that the gate fails honestly while signing is not configured.

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-public-release-gate.md`
- `scripts/desktop-public-release-gate.ps1`
- `scripts/desktop-public-release-gate.tests.ps1`

- [ ] **Step 1: Focused test**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Blocked gate check**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: FAIL with blockers `artifact-signature-missing` and `signing-certificate-missing` while the signing certificate is not configured.

- [ ] **Step 3: Full public release gate check**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1
```

Expected: FAIL after regenerating evidence, with the same signing blockers until a valid signing certificate is configured.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-public-release-gate.md
git commit -m "Plan desktop public release gate"
git push origin main
git add scripts/desktop-public-release-gate.ps1 scripts/desktop-public-release-gate.tests.ps1
git commit -m "Add desktop public release gate"
git push origin main
```

## Self-Review Checklist

- Spec coverage: converts release evidence into a hard public-release decision.
- Placeholder scan: no incomplete commands or expected outputs.
- Scope: does not change unsigned local MVP gate behavior.
- Release honesty: fails clearly while signing blockers remain.
