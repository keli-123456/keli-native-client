# Desktop Signing Mode Release Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make release/readiness/public-gate diagnostics distinguish "signing inspect passed" from "artifacts were actually signed" by exposing `signing.mode` everywhere the operator sees signing status.

**Architecture:** Keep `scripts\desktop-signing.ps1` as the signing source of truth. It already writes `mode = inspect` or `mode = sign`; this slice promotes that field through release evidence plan metadata, release readiness JSON/text output, and public release gate blocked diagnostics.

**Tech Stack:** PowerShell 5+, existing desktop signing, release evidence, readiness, and public release gate scripts.

---

## Scope Check

This slice covers:

- `metadata signing_mode` in release evidence PlanOnly output.
- `signing.mode` in release readiness JSON.
- `signing_mode ...` in release readiness text output.
- `signing_mode=...` in public release gate blocked diagnostics.
- Focused tests proving `inspect` and `sign` modes stay visible.

This slice does not cover:

- Signing artifacts.
- Installing or creating certificates.
- Changing public release blockers.
- Changing local desktop MVP gate readiness.

## File Structure

- Modify: `scripts/desktop-release-evidence.tests.ps1`
  - Add PlanOnly expectation for `metadata signing_mode`.
  - Assert failed signing fixture preserves `mode = sign`.
- Modify: `scripts/desktop-release-evidence.ps1`
  - Add signing mode PlanOnly metadata.
- Modify: `scripts/desktop-release-readiness.tests.ps1`
  - Add `mode = sign` to the fixture and JSON assertion.
  - Add PlanOnly expectation for `signing.mode`.
- Modify: `scripts/desktop-release-readiness.ps1`
  - Expose and print signing mode.
- Modify: `scripts/desktop-public-release-gate.tests.ps1`
  - Add fixture mode and blocked-output assertion.
- Modify: `scripts/desktop-public-release-gate.ps1`
  - Print signing mode in blocked diagnostics when available.

## Task 1: RED Signing Mode Tests

**Files:**
- Modify: `scripts/desktop-release-evidence.tests.ps1`
- Modify: `scripts/desktop-release-readiness.tests.ps1`
- Modify: `scripts/desktop-public-release-gate.tests.ps1`

- [ ] **Step 1: Add release evidence PlanOnly expectation**

Add:

```powershell
'metadata signing_mode'
```

Also assert the failed signing fixture keeps:

```powershell
if ($releaseEvidence.signing.mode -ne 'sign') {
    throw "release evidence signing mode mismatch: $($releaseEvidence.signing.mode)"
}
```

- [ ] **Step 2: Add readiness fixture and assertions**

In the readiness fixture signing object add:

```powershell
mode = 'sign'
```

Update the PlanOnly read line to include `signing.mode`, and assert:

```powershell
if ($report.signing.mode -ne 'sign') {
    throw "readiness signing mode mismatch: $($report.signing.mode)"
}
```

- [ ] **Step 3: Add public gate diagnostics assertion**

In the public gate fixture signing object add:

```powershell
mode = 'sign'
```

Require blocked output:

```powershell
'signing_mode=sign'
```

- [ ] **Step 4: Run RED tests**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: FAIL because mode is not fully surfaced yet.

## Task 2: GREEN Signing Mode Propagation

**Files:**
- Modify: `scripts/desktop-release-evidence.ps1`
- Modify: `scripts/desktop-release-readiness.ps1`
- Modify: `scripts/desktop-public-release-gate.ps1`

- [ ] **Step 1: Extend release evidence PlanOnly**

Add:

```powershell
Write-Output 'metadata signing_mode'
```

- [ ] **Step 2: Extend readiness report**

Add `mode` under `signing`, print `signing_mode`, and include `signing.mode` in PlanOnly.

- [ ] **Step 3: Extend public gate diagnostics**

Inside `Get-OptionalSigningDiagnostics`, add:

```powershell
if (Test-JsonProperty -InputObject $signing -Name 'mode') {
    $parts += "signing_mode=$([string]$signing.mode)"
}
```

- [ ] **Step 4: Run GREEN tests**

Run the three focused tests again. Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-signing-mode-release-diagnostics.md`
- `scripts/desktop-release-evidence.ps1`
- `scripts/desktop-release-evidence.tests.ps1`
- `scripts/desktop-release-readiness.ps1`
- `scripts/desktop-release-readiness.tests.ps1`
- `scripts/desktop-public-release-gate.ps1`
- `scripts/desktop-public-release-gate.tests.ps1`

- [ ] **Step 1: Focused tests**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Regenerate real evidence and readiness**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
```

Expected: PASS and clearly report `signing.mode = inspect` while public release stays blocked by signing.

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

Expected: FAIL only with signing blockers and print `signing_mode=inspect`.

- [ ] **Step 5: Diff check**

Run:

```powershell
git diff --check
```

Expected: PASS.

- [ ] **Step 6: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-signing-mode-release-diagnostics.md
git commit -m "Plan signing mode release diagnostics"
git push
git add scripts/desktop-release-evidence.ps1 scripts/desktop-release-evidence.tests.ps1 scripts/desktop-release-readiness.ps1 scripts/desktop-release-readiness.tests.ps1 scripts/desktop-public-release-gate.ps1 scripts/desktop-public-release-gate.tests.ps1
git commit -m "Expose signing mode release diagnostics"
git push
```

## Self-Review Checklist

- Spec coverage: release operator diagnostics no longer blur inspect success with signing completion.
- Placeholder scan: no TBD/TODO/fill-in placeholders remain.
- Type consistency: `signing.mode` is a string copied from signing evidence.
- Scope: public release readiness rules are unchanged.
- Release honesty: unsigned artifacts remain blocked until real signatures exist.
