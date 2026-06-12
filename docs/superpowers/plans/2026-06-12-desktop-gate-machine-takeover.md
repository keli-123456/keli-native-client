# Desktop Gate Machine Takeover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the desktop MVP gate explicitly request real machine takeover smoke while preserving the default safe-probe behavior.

**Architecture:** Add an `-IncludeMachineTakeover` switch to `scripts/desktop-mvp-gate.ps1`. The default gate continues to run `scripts\desktop-machine-smoke.ps1` without side effects; when the switch is present, the gate passes `-IncludeMachineTakeover` through to the machine smoke step so release evidence can capture a real takeover result.

**Tech Stack:** PowerShell 5+, existing desktop MVP gate, existing desktop machine smoke script.

---

## Scope Check

This slice covers:

- A gate-level `-IncludeMachineTakeover` switch.
- Plan output that proves the switch changes only the machine smoke command.
- Safe default behavior without takeover.
- Full verification through the normal desktop MVP gate and an explicit takeover run.

This slice does not cover:

- Changing the internals of `default-core-certify`.
- Installing Wintun.
- Signing release artifacts.
- Making takeover mandatory for the default local gate.

## File Structure

- Modify: `scripts/desktop-mvp-gate.ps1`
  - Add `-IncludeMachineTakeover`.
  - Build the machine smoke command dynamically.
- Modify: `scripts/desktop-mvp-gate.tests.ps1`
  - Keep the default plan expectation unchanged.
  - Add a second plan check for `-PlanOnly -IncludeMachineTakeover`.

## Task 1: RED Plan Test

**Files:**
- Modify: `scripts/desktop-mvp-gate.tests.ps1`

- [ ] **Step 1: Add takeover plan assertion**

Append this check after the existing default plan assertions:

```powershell
$takeoverOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $gateScript -PlanOnly -IncludeMachineTakeover
if ($LASTEXITCODE -ne 0) {
    throw "desktop-mvp-gate.ps1 -PlanOnly -IncludeMachineTakeover exited with $LASTEXITCODE"
}

$takeoverPlan = $takeoverOutput -join "`n"
$takeoverExpected = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.ps1 -IncludeMachineTakeover'
if (!$takeoverPlan.Contains($takeoverExpected)) {
    throw "desktop MVP gate takeover plan is missing: $takeoverExpected"
}
```

- [ ] **Step 2: Run RED test**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: FAIL because `desktop-mvp-gate.ps1` does not accept `-IncludeMachineTakeover`.

## Task 2: Implement Gate Switch

**Files:**
- Modify: `scripts/desktop-mvp-gate.ps1`

- [ ] **Step 1: Add parameter**

Change the parameter block to:

```powershell
param(
    [switch]$PlanOnly,
    [switch]$IncludeMachineTakeover
)
```

- [ ] **Step 2: Build machine smoke command dynamically**

Add:

```powershell
function New-MachineSmokeCommand {
    param(
        [switch]$IncludeMachineTakeover
    )

    $command = @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-machine-smoke.ps1')
    if ($IncludeMachineTakeover) {
        $command += '-IncludeMachineTakeover'
    }
    return $command
}
```

- [ ] **Step 3: Pass the switch into gate steps**

Change `Get-DesktopMvpGateSteps` to accept the switch and use:

```powershell
New-GateStep -Name 'Desktop machine smoke evidence' -Command (New-MachineSmokeCommand -IncludeMachineTakeover:$IncludeMachineTakeover)
```

Then set:

```powershell
$steps = Get-DesktopMvpGateSteps -IncludeMachineTakeover:$IncludeMachineTakeover
```

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-gate-machine-takeover.md`
- `scripts/desktop-mvp-gate.ps1`
- `scripts/desktop-mvp-gate.tests.ps1`

- [ ] **Step 1: Focused test**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: PASS and validate both default and takeover plan modes.

- [ ] **Step 2: Safe full gate**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS with the default safe-probe machine smoke.

- [ ] **Step 3: Explicit takeover gate**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1 -IncludeMachineTakeover
```

Expected: PASS if this machine can complete real takeover; otherwise the failure and machine smoke JSON identify the concrete blocker.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-gate-machine-takeover.md
git commit -m "Plan desktop gate machine takeover"
git push origin main
git add scripts/desktop-mvp-gate.ps1 scripts/desktop-mvp-gate.tests.ps1
git commit -m "Add desktop gate machine takeover switch"
git push origin main
```

## Self-Review Checklist

- Spec coverage: makes real machine takeover runnable through the desktop gate.
- Placeholder scan: no incomplete commands or paths.
- Safety: default gate remains side-effect-light.
- Release honesty: explicit takeover evidence can replace `machine-takeover-smoke-not-run`; failure remains observable.
