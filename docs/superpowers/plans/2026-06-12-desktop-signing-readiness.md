# Desktop Signing Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the remaining desktop public-release signing blocker actionable by adding read-only certificate-store discovery, structured operator next steps, and release evidence remediation metadata.

**Architecture:** Keep `scripts/desktop-signing.ps1` as the signing source of truth. Extend its inspect mode with a read-only certificate-store scan and a deterministic `operator_next_steps` array that never prints secret values. Then summarize those fields in `scripts/desktop-release-evidence.ps1` so the public release evidence file shows both the blocker and the next command or configuration action.

**Tech Stack:** PowerShell 5+, Windows certificate stores, Windows SDK `signtool.exe`, existing desktop signing and release evidence scripts.

---

## Scope Check

This slice covers:

- Read-only discovery of code-signing certificates in `Cert:\CurrentUser\My` and `Cert:\LocalMachine\My`.
- A deterministic test mode that skips certificate-store discovery so CI/local tests do not depend on machine state.
- Structured `operator_next_steps` and `release_commands` in `target\desktop\keli-desktop-signing.json`.
- A release evidence summary of signing certificate candidate count and next step IDs.
- Focused tests that first fail on the missing readiness metadata, then pass after implementation.

This slice does not cover:

- Buying, installing, exporting, or trusting a code signing certificate.
- Printing certificate passwords or secret values.
- Automatically selecting a certificate.
- Weakening the public release gate or marking unsigned artifacts ready.

## File Structure

- Modify: `scripts/desktop-signing.ps1`
  - Add `-SkipCertificateStoreDiscovery`.
  - Add read-only certificate-store discovery helpers.
  - Add `operator_next_steps` and `release_commands` to signing evidence JSON.
- Modify: `scripts/desktop-signing.tests.ps1`
  - Extend `-PlanOnly` expectations.
  - Run inspect mode with `-SkipCertificateStoreDiscovery`.
  - Assert JSON contains deterministic missing-certificate next steps.
- Modify: `scripts/desktop-release-evidence.ps1`
  - Include signing store candidate count, operator next step IDs, and release commands in the release evidence signing summary.
- Modify: `scripts/desktop-release-evidence.tests.ps1`
  - Extend `-PlanOnly` expectations for remediation metadata.

## Task 1: RED Signing Readiness Tests

**Files:**
- Modify: `scripts/desktop-signing.tests.ps1`
- Modify: `scripts/desktop-release-evidence.tests.ps1`

- [ ] **Step 1: Extend signing plan expectations**

Add these expected strings to `scripts/desktop-signing.tests.ps1`:

```powershell
'discover certificate_store_code_signing_candidates'
'config -SkipCertificateStoreDiscovery deterministic_tests'
'metadata operator_next_steps'
'metadata release_commands'
```

- [ ] **Step 2: Add deterministic signing evidence assertions**

Append this focused behavior check to `scripts/desktop-signing.tests.ps1`:

```powershell
& powershell -NoProfile -ExecutionPolicy Bypass -File $signingScript -SignToolPath '' -CertificatePath '' -CertificatePassword '' -CertificateSubject '' -SkipCertificateStoreDiscovery
if ($LASTEXITCODE -ne 0) {
    throw "desktop-signing.ps1 inspect exited with $LASTEXITCODE"
}

$repoRoot = Resolve-Path -LiteralPath (Join-Path $scriptDir '..')
$evidencePath = Join-Path $repoRoot 'target\desktop\keli-desktop-signing.json'
$evidence = Get-Content -Raw -LiteralPath $evidencePath | ConvertFrom-Json

if ($evidence.configuration.store_certificate_discovery.enabled -ne $false) {
    throw 'expected certificate-store discovery to be disabled for deterministic test'
}
if ($evidence.configuration.store_certificate_candidates_count -ne 0) {
    throw 'expected no certificate candidates when discovery is skipped'
}
$nextStepIds = @($evidence.operator_next_steps | ForEach-Object { [string]$_.id })
foreach ($id in @('configure-code-signing-certificate', 'run-desktop-signing-sign', 'run-public-release-gate')) {
    if ($nextStepIds -notcontains $id) {
        throw "signing evidence is missing operator next step: $id"
    }
}
if ([string]$evidence.release_commands.sign -ne 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign') {
    throw 'signing evidence sign command mismatch'
}
```

- [ ] **Step 3: Extend release evidence plan expectations**

Add these expected strings to `scripts/desktop-release-evidence.tests.ps1`:

```powershell
'metadata signing_store_certificate_candidates_count'
'metadata signing_operator_next_steps'
'metadata signing_release_commands'
```

- [ ] **Step 4: Run RED tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
```

Expected: FAIL because the signing script does not yet emit certificate-store discovery, operator next steps, release commands, or release evidence remediation metadata.

## Task 2: Implement Signing Readiness Evidence

**Files:**
- Modify: `scripts/desktop-signing.ps1`

- [ ] **Step 1: Add deterministic test switch**

Add parameter:

```powershell
[switch]$SkipCertificateStoreDiscovery
```

Update `-PlanOnly` output with:

```powershell
discover certificate_store_code_signing_candidates
config -SkipCertificateStoreDiscovery deterministic_tests
metadata operator_next_steps
metadata release_commands
```

- [ ] **Step 2: Add certificate-store discovery helpers**

Add helpers:

```powershell
function Get-CodeSigningCertificateCandidates {
    param([switch]$SkipDiscovery)

    $stores = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')
    if ($SkipDiscovery) {
        return [ordered]@{
            enabled = $false
            stores = $stores
            candidates = @()
            count = 0
        }
    }

    $candidates = @()
    foreach ($store in $stores) {
        if (!(Test-Path -LiteralPath $store)) {
            continue
        }
        $certificates = Get-ChildItem -LiteralPath $store -CodeSigningCert -ErrorAction SilentlyContinue
        foreach ($certificate in $certificates) {
            $candidates += [ordered]@{
                store = $store
                subject = [string]$certificate.Subject
                thumbprint = [string]$certificate.Thumbprint
                not_after = $certificate.NotAfter.ToUniversalTime().ToString('o')
                has_private_key = [bool]$certificate.HasPrivateKey
            }
        }
    }

    [ordered]@{
        enabled = $true
        stores = $stores
        candidates = $candidates
        count = $candidates.Count
    }
}
```

- [ ] **Step 3: Add release commands and next steps**

Add:

```powershell
function Get-ReleaseCommands {
    [ordered]@{
        inspect = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1'
        sign = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign'
        public_release_gate = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1'
    }
}
```

Add operator next steps with these IDs:

```powershell
signtool-missing
fix-certificate-path
choose-store-certificate-subject
configure-code-signing-certificate
run-desktop-signing-sign
run-public-release-gate
```

Only include the IDs that apply to the current evidence. Always include `run-desktop-signing-sign` while any signable artifact remains unsigned, and always include `run-public-release-gate` while public release is not ready.

## Task 3: Summarize Readiness In Release Evidence

**Files:**
- Modify: `scripts/desktop-release-evidence.ps1`

- [ ] **Step 1: Extend plan-only metadata**

Add:

```powershell
metadata signing_store_certificate_candidates_count
metadata signing_operator_next_steps
metadata signing_release_commands
```

- [ ] **Step 2: Extend signing summary**

In `Read-SigningStatus`, include:

```powershell
store_certificate_candidates_count = [int]$signing.configuration.store_certificate_candidates_count
operator_next_steps = @($signing.operator_next_steps | ForEach-Object { [string]$_.id })
release_commands = $signing.release_commands
```

## Task 4: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-signing-readiness.md`
- `scripts/desktop-signing.ps1`
- `scripts/desktop-signing.tests.ps1`
- `scripts/desktop-release-evidence.ps1`
- `scripts/desktop-release-evidence.tests.ps1`

- [ ] **Step 1: Focused tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Actual signing evidence inspect**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1
```

Expected: PASS and write `target\desktop\keli-desktop-signing.json` with `operator_next_steps` and `release_commands`. Without a configured certificate, public release remains blocked by `artifact-signature-missing` and `signing-certificate-missing`.

- [ ] **Step 3: Actual release evidence**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1
```

Expected: PASS and write `target\desktop\keli-desktop-release-evidence.json` with signing next step IDs and release commands in the `signing` object.

- [ ] **Step 4: Public release gate honesty check**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: FAIL with signing blockers until a valid certificate is configured and artifacts are signed.

- [ ] **Step 5: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-signing-readiness.md
git commit -m "Plan desktop signing readiness"
git push origin main
git add scripts/desktop-signing.ps1 scripts/desktop-signing.tests.ps1 scripts/desktop-release-evidence.ps1 scripts/desktop-release-evidence.tests.ps1
git commit -m "Add desktop signing readiness evidence"
git push origin main
```

## Self-Review Checklist

- Spec coverage: this plan moves the known signing blocker from a generic failure to an actionable release-operator workflow.
- Placeholder scan: every command, output path, and expected metadata field is concrete.
- Scope: no secret material is printed, stored, generated, or assumed.
- Release honesty: public release remains blocked until real signing evidence is valid.
