# Desktop Failed Signing Release Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve failed signing evidence in top-level release/readiness/public-gate diagnostics instead of throwing away the failure context.

**Architecture:** Treat `scripts\desktop-signing.ps1` as the source of signing status. `scripts\desktop-release-evidence.ps1` should accept both `passed` and `failed` signing evidence, add `sign-verification-failed` as a blocker when `sign_verification_failures` is non-empty, and carry those paths into readiness and public gate diagnostics.

**Tech Stack:** PowerShell 5+, existing release evidence, readiness, and public release gate scripts.

---

## Scope Check

This slice covers:

- `signing.status` in readiness JSON/text.
- `signing.sign_verification_failures` in release evidence and readiness JSON.
- `sign-verification-failed` blocker in release evidence when signing evidence says `status = failed` or has verification failures.
- Public gate diagnostics for `signing_status` and `signing_verification_failures`.

This slice does not cover:

- Signing artifacts.
- Creating or installing certificates.
- Making failed signing evidence public-release-ready.
- Changing local MVP gate behavior.

## File Structure

- Modify: `scripts/desktop-release-evidence.tests.ps1`
  - Add PlanOnly expectations.
  - Add a deterministic failed-signing fixture using current generated artifacts and smoke evidence.
- Modify: `scripts/desktop-release-readiness.tests.ps1`
  - Add readiness fixture fields and JSON assertions.
- Modify: `scripts/desktop-public-release-gate.tests.ps1`
  - Add public gate fixture fields and blocked-output assertions.
- Modify: `scripts/desktop-release-evidence.ps1`
  - Stop throwing on signing status `failed`.
  - Read `sign_verification_failures`.
  - Add `sign-verification-failed` blocker.
- Modify: `scripts/desktop-release-readiness.ps1`
  - Expose signing status and verification failures.
- Modify: `scripts/desktop-public-release-gate.ps1`
  - Print signing status and verification failures in blocked diagnostics.

## Task 1: RED Failed Signing Diagnostics Tests

**Files:**
- Modify: `scripts/desktop-release-evidence.tests.ps1`
- Modify: `scripts/desktop-release-readiness.tests.ps1`
- Modify: `scripts/desktop-public-release-gate.tests.ps1`

- [ ] **Step 1: Add release evidence PlanOnly expectations**

Add:

```powershell
'metadata signing_status',
'metadata signing_verification_failures'
```

- [ ] **Step 2: Add release evidence failed-signing fixture**

Append a fixture that backs up `target\desktop\keli-desktop-signing.json`, writes failed signing evidence, runs `desktop-release-evidence.ps1`, asserts it exits 0, and restores the original signing evidence:

```powershell
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$signingPath = Join-Path $repoRoot 'target\desktop\keli-desktop-signing.json'
$backupSigningPath = Join-Path $repoRoot 'target\desktop-release-evidence-tests\keli-desktop-signing.backup.json'
$backupDir = Split-Path -Parent $backupSigningPath
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
if (!(Test-Path -LiteralPath $signingPath)) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $scriptDir 'desktop-signing.ps1')
    if ($LASTEXITCODE -ne 0) {
        throw "desktop-signing.ps1 setup exited with $LASTEXITCODE"
    }
}
Copy-Item -LiteralPath $signingPath -Destination $backupSigningPath -Force
try {
    $failedSigning = Get-Content -Raw -LiteralPath $signingPath | ConvertFrom-Json
    $failedSigning.status = 'failed'
    $failedSigning.mode = 'sign'
    $failedSigning.sign_verification_failures = @(
        'target\release\keli-desktop-shell.exe',
        'target\desktop\keli-desktop-mvp-windows-x64.msi'
    )
    $failedSigning | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $signingPath -Encoding ASCII

    & powershell -NoProfile -ExecutionPolicy Bypass -File $releaseScript
    if ($LASTEXITCODE -ne 0) {
        throw "desktop-release-evidence.ps1 failed signing fixture exited with $LASTEXITCODE"
    }

    $releaseEvidencePath = Join-Path $repoRoot 'target\desktop\keli-desktop-release-evidence.json'
    $releaseEvidence = Get-Content -Raw -LiteralPath $releaseEvidencePath | ConvertFrom-Json
    if ($releaseEvidence.signing.status -ne 'failed') {
        throw "release evidence signing status mismatch: $($releaseEvidence.signing.status)"
    }
    if ($releaseEvidence.signing.sign_verification_failures.Count -ne 2) {
        throw "release evidence signing verification failure count mismatch: $($releaseEvidence.signing.sign_verification_failures.Count)"
    }
    if (($releaseEvidence.public_release_blockers -join ',') -notlike '*sign-verification-failed*') {
        throw "release evidence blockers missing sign-verification-failed: $($releaseEvidence.public_release_blockers -join ',')"
    }
} finally {
    Copy-Item -LiteralPath $backupSigningPath -Destination $signingPath -Force
}
```

- [ ] **Step 3: Add readiness fields and assertions**

In the readiness fixture signing object add:

```powershell
status = 'failed'
sign_verification_failures = @('target\release\keli-desktop-shell.exe')
```

Update PlanOnly read line to include:

```powershell
signing.status signing.sign_verification_failures
```

Assert:

```powershell
if ($report.signing.status -ne 'failed') {
    throw "readiness signing status mismatch: $($report.signing.status)"
}
if (($report.signing.sign_verification_failures -join ',') -ne 'target\release\keli-desktop-shell.exe') {
    throw "readiness signing verification failures mismatch: $($report.signing.sign_verification_failures -join ',')"
}
```

- [ ] **Step 4: Add public gate diagnostics assertions**

In the public gate fixture signing object add:

```powershell
status = 'failed'
sign_verification_failures = @('target\release\keli-desktop-shell.exe')
```

Require blocked output:

```powershell
'signing_status=failed',
'signing_verification_failures=target\release\keli-desktop-shell.exe'
```

- [ ] **Step 5: Run RED tests**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: FAIL because failed signing evidence is not propagated yet.

## Task 2: GREEN Diagnostics Propagation

**Files:**
- Modify: `scripts/desktop-release-evidence.ps1`
- Modify: `scripts/desktop-release-readiness.ps1`
- Modify: `scripts/desktop-public-release-gate.ps1`

- [ ] **Step 1: Accept failed signing evidence**

Replace the strict signing status check in `Read-SigningStatus` with:

```powershell
if ($signing.status -notin @('passed', 'failed')) {
    throw "signing status mismatch: $($signing.status)"
}
```

- [ ] **Step 2: Read verification failures**

Add:

```powershell
$signVerificationFailures = @()
if ($null -ne $signing.PSObject.Properties['sign_verification_failures']) {
    $signVerificationFailures = @($signing.sign_verification_failures | ForEach-Object { [string]$_ } | Where-Object { ![string]::IsNullOrWhiteSpace($_) })
}
```

Include:

```powershell
sign_verification_failures = $signVerificationFailures
```

- [ ] **Step 3: Add release blocker**

After adding signing blockers:

```powershell
if ($signingStatus.status -eq 'failed' -or $signingStatus.sign_verification_failures.Count -gt 0) {
    $blockers = Add-UniqueBlocker -Blockers $blockers -Blocker 'sign-verification-failed'
}
```

- [ ] **Step 4: Extend PlanOnly**

Add:

```powershell
Write-Output 'metadata signing_status'
Write-Output 'metadata signing_verification_failures'
```

- [ ] **Step 5: Extend readiness**

Add `status` and `sign_verification_failures` under `signing`, print them in text output, and update PlanOnly.

- [ ] **Step 6: Extend public gate diagnostics**

Inside `Get-OptionalSigningDiagnostics`, add:

```powershell
if (Test-JsonProperty -InputObject $signing -Name 'status') {
    $parts += "signing_status=$([string]$signing.status)"
}
$verificationFailures = Get-StringArrayProperty -InputObject $signing -Name 'sign_verification_failures'
if ($verificationFailures.Count -gt 0) {
    $parts += "signing_verification_failures=$($verificationFailures -join ',')"
}
```

- [ ] **Step 7: Run GREEN tests**

Run the three focused tests again. Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-failed-signing-release-diagnostics.md`
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

Expected: PASS. Current unsigned inspect evidence reports signing status `passed`, no sign verification failures, and public release blocked only by signing.

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
git add docs/superpowers/plans/2026-06-12-desktop-failed-signing-release-diagnostics.md
git commit -m "Plan failed signing release diagnostics"
git push
git add scripts/desktop-release-evidence.ps1 scripts/desktop-release-evidence.tests.ps1 scripts/desktop-release-readiness.ps1 scripts/desktop-release-readiness.tests.ps1 scripts/desktop-public-release-gate.ps1 scripts/desktop-public-release-gate.tests.ps1
git commit -m "Expose failed signing release diagnostics"
git push
```

## Self-Review Checklist

- Spec coverage: failed signing evidence reaches release/readiness/public gate diagnostics.
- Placeholder scan: no TBD/TODO/fill-in placeholders remain.
- Type consistency: `sign_verification_failures` is an array of artifact paths.
- Scope: local inspect and MVP gate behavior remain unchanged.
- Release honesty: failed signing evidence cannot be public-release-ready.
