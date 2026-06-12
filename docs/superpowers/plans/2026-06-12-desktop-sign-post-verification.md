# Desktop Sign Post Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `scripts\desktop-signing.ps1 -Sign` exit nonzero when the signing command returns success but the EXE/MSI still do not have valid Authenticode signatures.

**Architecture:** Keep signtool invocation and signature inspection inside `scripts/desktop-signing.ps1`. After `-Sign` invokes signtool and re-reads artifact signatures, record unsigned artifacts in evidence and throw after writing evidence if any signable artifact is still unsigned.

**Tech Stack:** PowerShell 5+, existing signing evidence script and tests.

---

## Scope Check

This slice covers:

- A deterministic test where a fake signtool exits 0 without modifying artifacts.
- `desktop-signing.ps1 -Sign` failing when artifacts remain unsigned after signing.
- Evidence field `sign_verification_failures` listing the unsigned artifact paths after a failed `-Sign`.
- PlanOnly metadata documenting post-signature verification.

This slice does not cover:

- Creating or installing certificates.
- Replacing signtool.
- Making unsigned local MVP gates fail.
- Changing public release blockers.

## File Structure

- Modify: `scripts/desktop-signing.tests.ps1`
  - Add PlanOnly expectation.
  - Add fake-success signtool fixture for `-Sign`.
- Modify: `scripts/desktop-signing.ps1`
  - Add post-signature verification after artifact evidence is collected.
  - Include failures in evidence.
  - Throw after writing evidence when `-Sign` did not produce valid signatures.

## Task 1: RED Fake Success Sign Test

**Files:**
- Modify: `scripts/desktop-signing.tests.ps1`

- [ ] **Step 1: Add PlanOnly expectation**

Add:

```powershell
'metadata sign_verification_failures'
```

- [ ] **Step 2: Add fake-success signtool fixture**

Append:

```powershell
$fakeSuccessSignToolPath = Join-Path $tempDir 'fake-signtool-success.cmd'
Set-Content -LiteralPath $fakeSuccessSignToolPath -Value "@echo off`r`nexit /b 0`r`n" -Encoding ASCII
$signFailureStdoutPath = Join-Path $tempDir 'sign-failure-stdout.txt'
$signFailureStderrPath = Join-Path $tempDir 'sign-failure-stderr.txt'
$signFailureProcess = Start-Process `
    -FilePath 'powershell' `
    -ArgumentList @(
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        $signingScript,
        '-Sign',
        '-SignToolPath',
        $fakeSuccessSignToolPath,
        '-CertificatePath',
        $fakePfxPath,
        '-CertificatePassword',
        'secret-password',
        '-CertificateSubject',
        ' ',
        '-SkipCertificateStoreDiscovery'
    ) `
    -NoNewWindow `
    -Wait `
    -PassThru `
    -RedirectStandardOutput $signFailureStdoutPath `
    -RedirectStandardError $signFailureStderrPath
if ($signFailureProcess.ExitCode -eq 0) {
    throw 'desktop-signing.ps1 -Sign should fail when signtool exits 0 but artifacts remain unsigned'
}
$signFailureText = @(
    if (Test-Path -LiteralPath $signFailureStdoutPath) {
        Get-Content -LiteralPath $signFailureStdoutPath
    }
    if (Test-Path -LiteralPath $signFailureStderrPath) {
        Get-Content -LiteralPath $signFailureStderrPath
    }
) -join "`n"
if (!$signFailureText.Contains('desktop signing -Sign did not produce valid signatures')) {
    throw "sign failure output did not explain unsigned artifacts: $signFailureText"
}
$failedSignEvidence = Get-Content -Raw -LiteralPath $evidencePath | ConvertFrom-Json
if ($failedSignEvidence.sign_verification_failures.Count -ne 2) {
    throw "expected two sign verification failures, got $($failedSignEvidence.sign_verification_failures.Count)"
}
```

- [ ] **Step 3: Run RED test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-signing.tests.ps1
```

Expected: FAIL because `-Sign` currently exits 0 when a fake signtool returns 0 without signing the artifacts.

## Task 2: GREEN Post-Sign Verification

**Files:**
- Modify: `scripts/desktop-signing.ps1`

- [ ] **Step 1: Add PlanOnly metadata**

Add:

```powershell
Write-Output 'metadata sign_verification_failures'
```

- [ ] **Step 2: Compute post-sign failures**

After `$artifacts` is created:

```powershell
$signVerificationFailures = @()
if ($Sign) {
    $signVerificationFailures = @($artifacts |
        Where-Object { !$_.signature.signed } |
        ForEach-Object { [string]$_.path })
}
```

- [ ] **Step 3: Include failures in evidence**

Add to `$evidence`:

```powershell
sign_verification_failures = @($signVerificationFailures)
```

- [ ] **Step 4: Throw after evidence is written**

After writing evidence:

```powershell
if ($signVerificationFailures.Count -gt 0) {
    throw "desktop signing -Sign did not produce valid signatures: $($signVerificationFailures -join ',')"
}
```

- [ ] **Step 5: Run GREEN test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-signing.tests.ps1
```

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-sign-post-verification.md`
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

Expected: PASS and `sign_verification_failures` is empty in inspect mode.

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
git add docs/superpowers/plans/2026-06-12-desktop-sign-post-verification.md
git commit -m "Plan desktop sign post verification"
git push
git add scripts/desktop-signing.ps1 scripts/desktop-signing.tests.ps1
git commit -m "Fail desktop signing when artifacts remain unsigned"
git push
```

## Self-Review Checklist

- Spec coverage: `-Sign` no longer exits 0 when the artifacts remain unsigned.
- Placeholder scan: no TBD/TODO/fill-in placeholders remain.
- Type consistency: `sign_verification_failures` is an array of artifact paths.
- Scope: inspect mode and local MVP gate still tolerate unsigned artifacts.
- Release honesty: public release remains blocked until real valid signatures exist.
