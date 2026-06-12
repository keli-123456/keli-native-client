# Desktop Store Subject Signing Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent store-subject signing configuration from reporting `can_sign=true` unless the configured certificate subject matches a discovered code-signing certificate.

**Architecture:** Keep `scripts/desktop-signing.ps1` as the signing source of truth. Extend its read-only certificate-store discovery summary with subject match diagnostics, and make `configuration.can_sign` require either an existing PFX path or a discovered store-subject match.

**Tech Stack:** PowerShell 5+, existing desktop signing evidence script and tests.

---

## Scope Check

This slice covers:

- `configuration.certificate_subject_match_count` and `configuration.certificate_subject_matches` in signing evidence.
- `configuration.can_sign=false` when `-CertificateSubject` is configured but no matching discovered certificate exists.
- A `fix-certificate-subject` operator next step for unmatched store-subject configuration.
- Deterministic tests using `-SkipCertificateStoreDiscovery` so a configured subject has zero matches.

This slice does not cover:

- Installing a certificate.
- Signing artifacts.
- Validating a PFX certificate chain.
- Trusting self-signed certificates.
- Changing public release readiness semantics.

## File Structure

- Modify: `scripts/desktop-signing.tests.ps1`
  - Add PlanOnly expectation for subject match diagnostics.
  - Add a deterministic unmatched store-subject fixture.
- Modify: `scripts/desktop-signing.ps1`
  - Add subject match computation.
  - Gate store-subject `can_sign` on at least one match.
  - Add an operator next step for unmatched subjects.

## Task 1: RED Unmatched Store Subject Test

**Files:**
- Modify: `scripts/desktop-signing.tests.ps1`

- [ ] **Step 1: Add PlanOnly expectation**

Add:

```powershell
'metadata certificate_subject_matches'
```

- [ ] **Step 2: Add unmatched store-subject fixture**

Append after the preview fixture:

```powershell
& powershell -NoProfile -ExecutionPolicy Bypass -File $signingScript `
    -SignToolPath $fakeSignToolPath `
    -CertificatePath ' ' `
    -CertificatePassword ' ' `
    -CertificateSubject 'CN=Missing Keli Code Signing' `
    -SkipCertificateStoreDiscovery
if ($LASTEXITCODE -ne 0) {
    throw "desktop-signing.ps1 unmatched subject inspect exited with $LASTEXITCODE"
}

$subjectEvidence = Get-Content -Raw -LiteralPath $evidencePath | ConvertFrom-Json
if ($subjectEvidence.configuration.can_sign -ne $false) {
    throw 'unmatched store-subject configuration should not be able to sign'
}
if ($subjectEvidence.configuration.certificate_subject_match_count -ne 0) {
    throw "expected zero subject matches, got $($subjectEvidence.configuration.certificate_subject_match_count)"
}
$subjectNextStepIds = @($subjectEvidence.operator_next_steps | ForEach-Object { [string]$_.id })
if ($subjectNextStepIds -notcontains 'fix-certificate-subject') {
    throw 'unmatched store-subject evidence should include fix-certificate-subject next step'
}
if (($subjectEvidence.public_release_blockers -join ',') -notlike '*signing-certificate-missing*') {
    throw "unmatched store-subject evidence should remain blocked on signing certificate: $($subjectEvidence.public_release_blockers -join ',')"
}
```

- [ ] **Step 3: Run RED test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-signing.tests.ps1
```

Expected: FAIL because PlanOnly and evidence do not yet expose subject matches and unmatched subjects still report `can_sign=true`.

## Task 2: GREEN Subject Match Validation

**Files:**
- Modify: `scripts/desktop-signing.ps1`

- [ ] **Step 1: Add subject match helper**

Add:

```powershell
function Get-CertificateSubjectMatches {
    param(
        [Parameter(Mandatory = $true)]
        [object]$CertificateStoreDiscovery,

        [AllowNull()]
        [string]$ConfiguredCertificateSubject
    )

    if ([string]::IsNullOrWhiteSpace($ConfiguredCertificateSubject)) {
        return @()
    }

    return @($CertificateStoreDiscovery.candidates | Where-Object {
        $subject = [string]$_.subject
        $subject.IndexOf($ConfiguredCertificateSubject, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
    })
}
```

- [ ] **Step 2: Gate `can_sign`**

Inside `Get-SigningConfiguration`, compute:

```powershell
$subjectMatches = @(Get-CertificateSubjectMatches -CertificateStoreDiscovery $CertificateStoreDiscovery -ConfiguredCertificateSubject $ConfiguredCertificateSubject)
$storeSubjectCanSign = $subjectConfigured -and ($subjectMatches.Count -gt 0)
$canSign = [bool]$SignTool.available -and (($method -eq 'pfx') -or ($method -eq 'store-subject' -and $storeSubjectCanSign))
```

Add:

```powershell
certificate_subject_match_count = $subjectMatches.Count
certificate_subject_matches = $subjectMatches
can_sign = $canSign
```

- [ ] **Step 3: Add operator next step**

In `Get-OperatorNextSteps`, add a branch for configured unmatched store subjects:

```powershell
if (!$Configuration.certificate_path_exists -and $Configuration.certificate_subject_configured -and $Configuration.certificate_subject_match_count -eq 0) {
    $steps = Add-OperatorNextStep -Steps $steps -Step (New-OperatorNextStep `
        -Id 'fix-certificate-subject' `
        -Detail 'KELI_SIGN_CERT_SUBJECT is configured but no discovered code-signing certificate subject matched it; install the certificate or correct the subject.' `
        -Command $null)
}
```

- [ ] **Step 4: Add PlanOnly metadata**

Add:

```powershell
Write-Output 'metadata certificate_subject_matches'
```

- [ ] **Step 5: Run GREEN test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-signing.tests.ps1
```

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-store-subject-signing-validation.md`
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

Expected: PASS and write signing evidence. Without a configured certificate, public release remains blocked by signing.

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
git add docs/superpowers/plans/2026-06-12-desktop-store-subject-signing-validation.md
git commit -m "Plan store subject signing validation"
git push
git add scripts/desktop-signing.ps1 scripts/desktop-signing.tests.ps1
git commit -m "Validate store subject signing configuration"
git push
```

## Self-Review Checklist

- Spec coverage: store-subject can-sign status is tied to discovered certificate evidence.
- Placeholder scan: no TBD/TODO/fill-in placeholders remain.
- Type consistency: field names match `configuration.certificate_subject_*`.
- Scope: no certificate installation or signing occurs.
- Release honesty: public release remains blocked until real signatures and signing configuration are valid.
