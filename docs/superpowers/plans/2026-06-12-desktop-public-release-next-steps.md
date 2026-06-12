# Desktop Public Release Next Steps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface actionable public-release next steps at the top level of release evidence and in the public release gate failure message.

**Architecture:** Keep blocker computation unchanged. Extend `scripts/desktop-release-evidence.ps1` to derive `public_release_next_steps` from existing signing operator next steps plus machine-smoke blockers when applicable. Extend `scripts/desktop-public-release-gate.ps1` to print those next steps when it blocks, without treating any blocker as success.

**Tech Stack:** PowerShell 5+, existing desktop release evidence JSON, existing public release gate script.

---

## Scope Check

This slice covers:

- Top-level `public_release_next_steps` in `target\desktop\keli-desktop-release-evidence.json`.
- Plan-only metadata for the new field.
- Public release gate blocked output that includes `next_steps=...`.
- Focused tests for plan output contracts.
- Actual script verification against the current unsigned artifacts.

This slice does not cover:

- Signing artifacts.
- Installing a signing certificate.
- Changing public release pass/fail criteria.
- Adding GitHub Releases or upload automation.

## File Structure

- Modify: `scripts/desktop-release-evidence.ps1`
  - Add `public_release_next_steps` top-level metadata.
  - Build next steps from signing next steps and machine takeover blocker categories.
- Modify: `scripts/desktop-release-evidence.tests.ps1`
  - Extend plan-only expectations.
- Modify: `scripts/desktop-public-release-gate.ps1`
  - Add helper to read next steps from evidence.
  - Include `next_steps=...` in blocked error output.
- Modify: `scripts/desktop-public-release-gate.tests.ps1`
  - Extend plan-only expectations.

## Task 1: RED Plan Tests

**Files:**
- Modify: `scripts/desktop-release-evidence.tests.ps1`
- Modify: `scripts/desktop-public-release-gate.tests.ps1`

- [ ] **Step 1: Extend release evidence plan expectation**

Add this expected string:

```powershell
'metadata public_release_next_steps'
```

- [ ] **Step 2: Extend public release gate plan expectation**

Add this expected string:

```powershell
'failure print blockers next_steps and exit nonzero'
```

- [ ] **Step 3: Run RED tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: FAIL because plan-only output does not mention top-level next steps or blocked next-step output.

## Task 2: Add Release Evidence Next Steps

**Files:**
- Modify: `scripts/desktop-release-evidence.ps1`

- [ ] **Step 1: Add plan-only metadata**

Add:

```powershell
Write-Output 'metadata public_release_next_steps'
```

- [ ] **Step 2: Add unique string helper**

Add:

```powershell
function Add-UniqueString {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Values,

        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ($Values -notcontains $Value) {
        return @($Values + $Value)
    }
    return $Values
}
```

- [ ] **Step 3: Add next-step derivation**

Add:

```powershell
function Get-PublicReleaseNextSteps {
    param(
        [Parameter(Mandatory = $true)]
        [object]$SigningStatus,

        [Parameter(Mandatory = $true)]
        [object]$MachineSmoke
    )

    $steps = @()
    foreach ($step in $SigningStatus.operator_next_steps) {
        $steps = Add-UniqueString -Values $steps -Value $step
    }
    if ($MachineSmoke.machine_takeover_status -ne 'ready') {
        $steps = Add-UniqueString -Values $steps -Value 'run-machine-takeover-smoke'
        foreach ($blocker in $MachineSmoke.blockers) {
            if ($blocker -eq 'machine-takeover-certification-failed') {
                $steps = Add-UniqueString -Values $steps -Value 'inspect-machine-takeover-certification'
            }
            if ($blocker -eq 'machine-takeover-smoke-not-run') {
                $steps = Add-UniqueString -Values $steps -Value 'rerun-public-release-gate'
            }
        }
    }
    if ($steps.Count -eq 0) {
        $steps = Add-UniqueString -Values $steps -Value 'rerun-public-release-gate'
    }
    return $steps
}
```

- [ ] **Step 4: Include top-level field**

Before `$evidence`, compute:

```powershell
$publicReleaseNextSteps = Get-PublicReleaseNextSteps -SigningStatus $signingStatus -MachineSmoke $machineSmoke
```

Then add:

```powershell
public_release_next_steps = $publicReleaseNextSteps
```

## Task 3: Print Next Steps From Public Release Gate

**Files:**
- Modify: `scripts/desktop-public-release-gate.ps1`

- [ ] **Step 1: Add next-step helper**

Add:

```powershell
function Get-ReleaseNextSteps {
    param([Parameter(Mandatory = $true)][object]$Evidence)

    if ($null -ne $Evidence.PSObject.Properties['public_release_next_steps']) {
        return @($Evidence.public_release_next_steps | ForEach-Object { [string]$_ })
    }
    if ($null -ne $Evidence.signing -and $null -ne $Evidence.signing.PSObject.Properties['operator_next_steps']) {
        return @($Evidence.signing.operator_next_steps | ForEach-Object { [string]$_ })
    }
    return @()
}
```

- [ ] **Step 2: Extend blocked output**

Change blocked failure to:

```powershell
$nextSteps = Get-ReleaseNextSteps -Evidence $evidence
if ($nextSteps.Count -gt 0) {
    throw "Desktop public release gate blocked: $($blockers -join ',') next_steps=$($nextSteps -join ',')"
}
throw "Desktop public release gate blocked: $($blockers -join ',')"
```

## Task 4: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-public-release-next-steps.md`
- `scripts/desktop-release-evidence.ps1`
- `scripts/desktop-release-evidence.tests.ps1`
- `scripts/desktop-public-release-gate.ps1`
- `scripts/desktop-public-release-gate.tests.ps1`

- [ ] **Step 1: Focused tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Actual release evidence**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1
```

Expected: PASS and top-level `public_release_next_steps` includes `configure-code-signing-certificate`, `run-desktop-signing-sign`, and `run-public-release-gate`.

- [ ] **Step 3: Public release gate blocked output**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: FAIL with signing blockers and `next_steps=configure-code-signing-certificate,run-desktop-signing-sign,run-public-release-gate`.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-public-release-next-steps.md
git commit -m "Plan desktop public release next steps"
git push origin main
git add scripts/desktop-release-evidence.ps1 scripts/desktop-release-evidence.tests.ps1 scripts/desktop-public-release-gate.ps1 scripts/desktop-public-release-gate.tests.ps1
git commit -m "Add desktop public release next steps"
git push origin main
```

## Self-Review Checklist

- Spec coverage: public release evidence and gate output explain the next operator action.
- Placeholder scan: commands and metadata names are concrete.
- Scope: no gate pass/fail semantics are weakened.
- Release honesty: missing signing still blocks public release.
