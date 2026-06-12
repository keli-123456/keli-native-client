# Desktop Signing Readiness Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make desktop public-release readiness explain the remaining signing blocker with machine-readable diagnostics for signing method, timestamp URL, signtool availability, and unsigned artifacts.

**Architecture:** Keep `scripts/desktop-signing.ps1` as the source of signing truth and do not change signing behavior. Extend `scripts/desktop-release-evidence.ps1` to summarize additional non-secret signing diagnostics from the existing signing JSON, then extend `scripts/desktop-release-readiness.ps1` to expose those fields in text and JSON reports.

**Tech Stack:** PowerShell 5+, existing desktop signing evidence JSON, existing desktop release evidence and readiness scripts.

---

## Scope Check

This slice covers:

- Release evidence summary fields for `signing_method`, `timestamp_url`, and `unsigned_artifacts`.
- Readiness JSON/text fields for `signing.signtool_available`, `signing.signing_method`, `signing.timestamp_url`, and `signing.unsigned_artifacts`.
- Focused tests that fail before implementation and pass after the fields are wired.

This slice does not cover:

- Installing, generating, trusting, or selecting a signing certificate.
- Printing certificate passwords or secret values.
- Treating unsigned artifacts as public-release ready.
- Changing the signing command or public release gate requirements.

## File Structure

- Modify: `scripts/desktop-release-evidence.tests.ps1`
  - Add `-PlanOnly` expectations for signing diagnostics metadata.
- Modify: `scripts/desktop-release-evidence.ps1`
  - Add signing diagnostics metadata in `-PlanOnly`.
  - Summarize signing method, timestamp URL, and unsigned artifact paths from signing evidence.
- Modify: `scripts/desktop-release-readiness.tests.ps1`
  - Add plan expectations and fixture assertions for the new readiness fields.
- Modify: `scripts/desktop-release-readiness.ps1`
  - Read and output the new signing diagnostics in text and JSON reports.

## Task 1: RED Release Evidence Diagnostics Test

**Files:**
- Modify: `scripts/desktop-release-evidence.tests.ps1`

- [ ] **Step 1: Add plan expectations**

Add these expected strings to `scripts/desktop-release-evidence.tests.ps1`:

```powershell
'metadata signing_method'
'metadata signing_timestamp_url'
'metadata signing_unsigned_artifacts'
```

- [ ] **Step 2: Run RED test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
```

Expected: FAIL because `desktop-release-evidence.ps1 -PlanOnly` does not yet declare those metadata fields.

## Task 2: GREEN Release Evidence Diagnostics

**Files:**
- Modify: `scripts/desktop-release-evidence.ps1`

- [ ] **Step 1: Add plan metadata**

Add these lines after the existing signing metadata:

```powershell
Write-Output 'metadata signing_method'
Write-Output 'metadata signing_timestamp_url'
Write-Output 'metadata signing_unsigned_artifacts'
```

- [ ] **Step 2: Summarize diagnostics in `Read-SigningStatus`**

Read non-secret values from the signing evidence:

```powershell
$signingMethod = ''
if ($null -ne $signing.configuration.PSObject.Properties['signing_method'] -and $null -ne $signing.configuration.signing_method) {
    $signingMethod = [string]$signing.configuration.signing_method
}
$timestampUrl = ''
if ($null -ne $signing.configuration.PSObject.Properties['timestamp_url']) {
    $timestampUrl = [string]$signing.configuration.timestamp_url
}
$unsignedArtifacts = @()
if ($null -ne $signing.PSObject.Properties['artifacts']) {
    $unsignedArtifacts = @($signing.artifacts | Where-Object { !$_.signature.signed } | ForEach-Object { [string]$_.path })
}
```

Return:

```powershell
signing_method = $signingMethod
timestamp_url = $timestampUrl
unsigned_artifacts = $unsignedArtifacts
```

- [ ] **Step 3: Run GREEN test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
```

Expected: PASS.

## Task 3: RED Readiness Diagnostics Test

**Files:**
- Modify: `scripts/desktop-release-readiness.tests.ps1`

- [ ] **Step 1: Add readiness plan expectation**

Replace the existing signing read line with:

```powershell
'read signing.can_sign signing.signtool_available signing.signing_method signing.timestamp_url signing.store_certificate_candidates_count signing.unsigned_artifacts signing.release_commands'
```

- [ ] **Step 2: Extend the fixture**

Add these fields under `signing` in the fixture:

```powershell
signtool_available = $true
signing_method = ''
timestamp_url = 'http://timestamp.digicert.com'
unsigned_artifacts = @('target\release\keli-desktop-shell.exe', 'target\desktop\keli-desktop-mvp-windows-x64.msi')
```

- [ ] **Step 3: Add JSON assertions**

Assert:

```powershell
if ($report.signing.signtool_available -ne $true) {
    throw 'readiness signing signtool_available should be true'
}
if ($report.signing.signing_method -ne '') {
    throw "readiness signing method mismatch: $($report.signing.signing_method)"
}
if ($report.signing.timestamp_url -ne 'http://timestamp.digicert.com') {
    throw "readiness timestamp URL mismatch: $($report.signing.timestamp_url)"
}
if (($report.signing.unsigned_artifacts -join ',') -ne 'target\release\keli-desktop-shell.exe,target\desktop\keli-desktop-mvp-windows-x64.msi') {
    throw "readiness unsigned artifacts mismatch: $($report.signing.unsigned_artifacts -join ',')"
}
```

- [ ] **Step 4: Run RED test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
```

Expected: FAIL because readiness does not yet read the expanded signing diagnostics.

## Task 4: GREEN Readiness Diagnostics

**Files:**
- Modify: `scripts/desktop-release-readiness.ps1`

- [ ] **Step 1: Update `-PlanOnly` output**

Replace the signing read line with:

```powershell
Write-Output 'read signing.can_sign signing.signtool_available signing.signing_method signing.timestamp_url signing.store_certificate_candidates_count signing.unsigned_artifacts signing.release_commands'
```

- [ ] **Step 2: Extend `New-ReadinessReport`**

Add fields under `signing`:

```powershell
signtool_available = Get-BoolProperty -InputObject $signing -Name 'signtool_available'
signing_method = Get-StringProperty -InputObject $signing -Name 'signing_method'
timestamp_url = Get-StringProperty -InputObject $signing -Name 'timestamp_url'
unsigned_artifacts = Get-StringArrayProperty -InputObject $signing -Name 'unsigned_artifacts'
```

- [ ] **Step 3: Extend text output**

Add:

```powershell
Write-Output "signing_signtool_available $(Format-Bool -Value $Report.signing.signtool_available)"
Write-Output "signing_method $($Report.signing.signing_method)"
Write-Output "signing_timestamp_url $($Report.signing.timestamp_url)"
Write-Output "signing_unsigned_artifacts $($Report.signing.unsigned_artifacts -join ',')"
```

- [ ] **Step 4: Run GREEN test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
```

Expected: PASS.

## Task 5: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-signing-readiness-diagnostics.md`
- `scripts/desktop-release-evidence.ps1`
- `scripts/desktop-release-evidence.tests.ps1`
- `scripts/desktop-release-readiness.ps1`
- `scripts/desktop-release-readiness.tests.ps1`

- [ ] **Step 1: Focused tests**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Regenerate evidence and inspect readiness**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
```

Expected: readiness JSON includes signing diagnostics and still reports public release blocked only by signing.

- [ ] **Step 3: Full gate**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-signing-readiness-diagnostics.md
git commit -m "Plan desktop signing readiness diagnostics"
git push
git add scripts/desktop-release-evidence.ps1 scripts/desktop-release-evidence.tests.ps1 scripts/desktop-release-readiness.ps1 scripts/desktop-release-readiness.tests.ps1
git commit -m "Expose desktop signing readiness diagnostics"
git push
```

## Self-Review Checklist

- Spec coverage: this plan makes the remaining signing blocker explainable without changing release readiness semantics.
- Placeholder scan: all paths, commands, and field names are concrete.
- Type consistency: string, bool, and array field names match between release evidence and readiness.
- Scope: no secrets or certificate material are printed.
- Release honesty: public release remains blocked until real signatures and signing configuration are valid.
