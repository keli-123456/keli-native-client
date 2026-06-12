# Desktop Sign Failed Evidence Status Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make signing evidence report `status = failed` when `desktop-signing.ps1 -Sign` cannot produce valid signatures.

**Architecture:** Keep `sign_verification_failures` as the source for post-sign verification failure. Derive the top-level signing evidence `status` from that array so inspect mode and successful sign mode report `passed`, while failed sign mode reports `failed` before throwing.

**Tech Stack:** PowerShell 5+, existing desktop signing script and tests.

---

## Scope Check

This slice covers:

- `target\desktop\keli-desktop-signing.json.status = "failed"` when `-Sign` leaves artifacts unsigned.
- A deterministic fake signtool test assertion for the failed status.

This slice does not cover:

- Changing local inspect mode status.
- Changing public release blockers.
- Signing real artifacts.
- Propagating failed signing evidence into release evidence.

## File Structure

- Modify: `scripts/desktop-signing.tests.ps1`
  - Assert fake-success signtool failure evidence has `status = failed`.
- Modify: `scripts/desktop-signing.ps1`
  - Set evidence `status` from `sign_verification_failures`.

## Task 1: RED Failed Status Test

**Files:**
- Modify: `scripts/desktop-signing.tests.ps1`

- [ ] **Step 1: Add fake sign evidence status assertion**

After reading `$failedSignEvidence`, add:

```powershell
if ($failedSignEvidence.status -ne 'failed') {
    throw "failed sign evidence status mismatch: $($failedSignEvidence.status)"
}
```

- [ ] **Step 2: Run RED test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-signing.tests.ps1
```

Expected: FAIL because fake-success `-Sign` currently writes `status = passed` before throwing.

## Task 2: GREEN Failed Status

**Files:**
- Modify: `scripts/desktop-signing.ps1`

- [ ] **Step 1: Set status from sign verification failures**

Replace:

```powershell
status = 'passed'
```

with:

```powershell
status = if ($signVerificationFailures.Count -gt 0) { 'failed' } else { 'passed' }
```

- [ ] **Step 2: Run GREEN test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-signing.tests.ps1
```

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-sign-failed-evidence-status.md`
- `scripts/desktop-signing.ps1`
- `scripts/desktop-signing.tests.ps1`

- [ ] **Step 1: Focused signing test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-signing.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Actual signing inspect**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1
```

Expected: PASS and inspect evidence status remains `passed`.

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
git add docs/superpowers/plans/2026-06-12-desktop-sign-failed-evidence-status.md
git commit -m "Plan failed signing evidence status"
git push
git add scripts/desktop-signing.ps1 scripts/desktop-signing.tests.ps1
git commit -m "Mark failed signing evidence status"
git push
```

## Self-Review Checklist

- Spec coverage: failed `-Sign` evidence no longer claims `passed`.
- Placeholder scan: no TBD/TODO/fill-in placeholders remain.
- Type consistency: status values remain `passed` or `failed`.
- Scope: inspect mode and unsigned local MVP gates still pass.
- Release honesty: public release remains blocked until real valid signatures exist.
