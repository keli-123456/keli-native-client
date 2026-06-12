# Desktop Subject Match Readiness Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface signing certificate subject match count in release evidence, readiness output, and public gate diagnostics.

**Architecture:** Keep subject matching in `scripts/desktop-signing.ps1`. Propagate only the non-secret `certificate_subject_match_count` into `scripts/desktop-release-evidence.ps1`, expose it through `scripts/desktop-release-readiness.ps1`, and include it in hard public gate failure diagnostics when available.

**Tech Stack:** PowerShell 5+, existing desktop release evidence, readiness, and public gate scripts.

---

## Scope Check

This slice covers:

- `signing.certificate_subject_match_count` in release evidence.
- `signing.certificate_subject_match_count` in readiness JSON and text.
- `signing_certificate_subject_matches=N` in public release gate blocked output.

This slice does not cover:

- Recomputing subject matches outside signing evidence.
- Printing certificate subject strings in public gate exceptions.
- Installing certificates.
- Signing artifacts.
- Changing public release pass/fail semantics.

## File Structure

- Modify: `scripts/desktop-release-evidence.tests.ps1`
  - Add PlanOnly expectation for subject match count.
- Modify: `scripts/desktop-release-readiness.tests.ps1`
  - Add PlanOnly expectation, fixture field, and JSON assertion.
- Modify: `scripts/desktop-public-release-gate.tests.ps1`
  - Add fixture field and blocked-output assertion.
- Modify: `scripts/desktop-release-evidence.ps1`
  - Read `configuration.certificate_subject_match_count`.
- Modify: `scripts/desktop-release-readiness.ps1`
  - Expose `certificate_subject_match_count` in JSON/text.
- Modify: `scripts/desktop-public-release-gate.ps1`
  - Print `signing_certificate_subject_matches=N` when available.

## Task 1: RED Diagnostics Tests

**Files:**
- Modify: `scripts/desktop-release-evidence.tests.ps1`
- Modify: `scripts/desktop-release-readiness.tests.ps1`
- Modify: `scripts/desktop-public-release-gate.tests.ps1`

- [ ] **Step 1: Add release evidence PlanOnly expectation**

Add:

```powershell
'metadata signing_certificate_subject_match_count'
```

- [ ] **Step 2: Add readiness PlanOnly expectation**

Replace the signing read expectation with one that includes:

```powershell
signing.certificate_subject_match_count
```

Add fixture field:

```powershell
certificate_subject_match_count = 0
```

Assert:

```powershell
if ($report.signing.certificate_subject_match_count -ne 0) {
    throw "readiness signing subject match count mismatch: $($report.signing.certificate_subject_match_count)"
}
```

- [ ] **Step 3: Add public gate fixture expectation**

Add `certificate_subject_match_count = 0` under `signing`, then require blocked output:

```powershell
'signing_certificate_subject_matches=0'
```

- [ ] **Step 4: Run RED tests**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: FAIL because the scripts do not yet declare or expose subject match count.

## Task 2: GREEN Subject Match Propagation

**Files:**
- Modify: `scripts/desktop-release-evidence.ps1`
- Modify: `scripts/desktop-release-readiness.ps1`
- Modify: `scripts/desktop-public-release-gate.ps1`

- [ ] **Step 1: Extend release evidence**

Read:

```powershell
$certificateSubjectMatchCount = 0
if ($null -ne $signing.configuration.PSObject.Properties['certificate_subject_match_count']) {
    $certificateSubjectMatchCount = [int]$signing.configuration.certificate_subject_match_count
}
```

Add under `signing`:

```powershell
certificate_subject_match_count = $certificateSubjectMatchCount
```

Add PlanOnly line:

```powershell
Write-Output 'metadata signing_certificate_subject_match_count'
```

- [ ] **Step 2: Extend readiness**

Add to report signing object:

```powershell
certificate_subject_match_count = Get-IntProperty -InputObject $signing -Name 'certificate_subject_match_count'
```

Print:

```powershell
Write-Output "signing_certificate_subject_matches $($Report.signing.certificate_subject_match_count)"
```

Update PlanOnly read line.

- [ ] **Step 3: Extend public gate diagnostics**

Inside `Get-OptionalSigningDiagnostics`, add:

```powershell
if (Test-JsonProperty -InputObject $signing -Name 'certificate_subject_match_count') {
    $parts += "signing_certificate_subject_matches=$([int]$signing.certificate_subject_match_count)"
}
```

- [ ] **Step 4: Run GREEN tests**

Run the three focused tests again. Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-subject-match-readiness-diagnostics.md`
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

- [ ] **Step 2: Real release evidence and readiness**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
```

Expected: PASS and readiness JSON includes `signing.certificate_subject_match_count`.

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
git add docs/superpowers/plans/2026-06-12-desktop-subject-match-readiness-diagnostics.md
git commit -m "Plan subject match readiness diagnostics"
git push
git add scripts/desktop-release-evidence.ps1 scripts/desktop-release-evidence.tests.ps1 scripts/desktop-release-readiness.ps1 scripts/desktop-release-readiness.tests.ps1 scripts/desktop-public-release-gate.ps1 scripts/desktop-public-release-gate.tests.ps1
git commit -m "Expose signing subject match diagnostics"
git push
```

## Self-Review Checklist

- Spec coverage: subject match count is visible from top-level release/readiness/public gate outputs.
- Placeholder scan: no TBD/TODO/fill-in placeholders remain.
- Type consistency: field name is `certificate_subject_match_count` in release/readiness JSON.
- Scope: no subject strings, secrets, or certificate paths are printed by public gate diagnostics.
- Release honesty: public release remains blocked until real signatures and signing configuration are valid.
