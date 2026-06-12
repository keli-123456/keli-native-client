# Desktop Signing Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a desktop signing evidence gate that discovers `signtool`, records signing configuration readiness, optionally signs EXE/MSI artifacts, and feeds signature readiness into the desktop release evidence manifest.

**Architecture:** Add a PowerShell signing script that defaults to inspection-only mode for local gates. It discovers Windows SDK `signtool.exe`, checks certificate configuration through environment variables or parameters, records Authenticode status for signable artifacts, and writes `target\desktop\keli-desktop-signing.json`. A future release worker can pass `-Sign` with a PFX file or certificate-store subject to actually sign artifacts; unsigned or unconfigured signing remains a public-release blocker but does not block local MVP verification.

**Tech Stack:** PowerShell 5+, Windows SDK `signtool.exe`, Authenticode, existing desktop EXE/MSI artifacts, existing desktop MVP gate and release evidence scripts.

---

## Scope Check

This slice covers:

- Discovering `signtool.exe` from PATH, `KELI_SIGNTOOL_PATH`, and Windows Kits locations.
- Recording certificate configuration readiness without printing secrets.
- Inspecting current Authenticode status for `keli-desktop-shell.exe` and the MSI.
- Supporting explicit signing with either a PFX file or a certificate store subject.
- Writing a signing evidence JSON artifact.
- Adding signing evidence to the desktop MVP gate before release evidence.
- Adding signing blockers to release evidence.

This slice does not cover:

- Buying or provisioning a code signing certificate.
- Storing certificate secrets.
- Uploading release artifacts.
- Making local unsigned gates fail.

## File Structure

- Create: `scripts/desktop-signing.ps1`
  - Produces `target\desktop\keli-desktop-signing.json`.
  - Defaults to inspect-only mode.
  - Signs only when `-Sign` is supplied.
- Create: `scripts/desktop-signing.tests.ps1`
  - Verifies `-PlanOnly` output includes signable artifacts, tool discovery, config variables, modes, blockers, and output path.
- Modify: `scripts/desktop-mvp-gate.ps1`
  - Adds `Desktop signing evidence` after machine smoke and before release evidence.
- Modify: `scripts/desktop-mvp-gate.tests.ps1`
  - Asserts the gate plan includes the signing command and signing artifact.
- Modify: `scripts/desktop-release-evidence.ps1`
  - Reads signing evidence, embeds it under `signing`, and uses its blockers for public release readiness.
- Modify: `scripts/desktop-release-evidence.tests.ps1`
  - Asserts release evidence plan includes signing input and signing blocker metadata.

## Task 1: RED Plan Tests

**Files:**
- Create: `scripts/desktop-signing.tests.ps1`
- Modify: `scripts/desktop-mvp-gate.tests.ps1`
- Modify: `scripts/desktop-release-evidence.tests.ps1`

- [ ] **Step 1: Add signing plan test**

Create `scripts/desktop-signing.tests.ps1`:

```powershell
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$signingScript = Join-Path $scriptDir 'desktop-signing.ps1'

if (!(Test-Path -LiteralPath $signingScript)) {
    throw "desktop-signing.ps1 was not found"
}

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $signingScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-signing.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $output -join "`n"
$expected = @(
    'input target\release\keli-desktop-shell.exe',
    'input target\desktop\keli-desktop-mvp-windows-x64.msi',
    'discover signtool.exe',
    'config KELI_SIGNTOOL_PATH optional',
    'config KELI_SIGN_CERT_PATH optional_pfx',
    'config KELI_SIGN_CERT_SUBJECT optional_store_subject',
    'config KELI_SIGN_CERT_PASSWORD optional_secret',
    'config KELI_SIGN_TIMESTAMP_URL default http://timestamp.digicert.com',
    'mode inspect default',
    'mode sign requires -Sign',
    'metadata public_release_blocker artifact-signature-missing',
    'metadata public_release_blocker signing-certificate-missing',
    'output target\desktop\keli-desktop-signing.json'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop signing plan is missing: $item"
    }
}

Write-Output 'desktop signing plan test passed'
```

- [ ] **Step 2: Extend MVP gate plan test**

Add these expected strings to `scripts/desktop-mvp-gate.tests.ps1`:

```powershell
'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1',
'target\desktop\keli-desktop-signing.json'
```

- [ ] **Step 3: Extend release evidence plan test**

Add these expected strings to `scripts/desktop-release-evidence.tests.ps1`:

```powershell
'input target\desktop\keli-desktop-signing.json',
'metadata public_release_ready false_when_signing_missing'
```

- [ ] **Step 4: Run RED tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
```

Expected: FAIL because `desktop-signing.ps1`, the gate step, and release evidence input do not exist yet.

## Task 2: Implement Signing Evidence Script

**Files:**
- Create: `scripts/desktop-signing.ps1`

- [ ] **Step 1: Add script parameters and helpers**

Add:

```powershell
[switch]$PlanOnly
[switch]$Sign
[string]$SignToolPath = $env:KELI_SIGNTOOL_PATH
[string]$CertificatePath = $env:KELI_SIGN_CERT_PATH
[string]$CertificatePassword = $env:KELI_SIGN_CERT_PASSWORD
[string]$CertificateSubject = $env:KELI_SIGN_CERT_SUBJECT
[string]$TimestampUrl = $(if ($env:KELI_SIGN_TIMESTAMP_URL) { $env:KELI_SIGN_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' })
```

Add helpers:

```powershell
Resolve-RepoRoot
Find-SignTool
Require-File
Get-SignatureEvidence
Get-SigningConfiguration
Invoke-SignToolSign
Add-UniqueBlocker
```

- [ ] **Step 2: Implement inspect-only output**

Default output must include:

```json
{
  "status": "passed",
  "mode": "inspect",
  "signtool": {
    "available": true,
    "path": "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\...\\x64\\signtool.exe"
  },
  "configuration": {
    "certificate_path_configured": false,
    "certificate_path_exists": false,
    "certificate_subject_configured": false,
    "certificate_password_configured": false,
    "timestamp_url": "http://timestamp.digicert.com",
    "can_sign": false
  },
  "artifacts": [
    {
      "kind": "desktop-shell-exe",
      "path": "target\\release\\keli-desktop-shell.exe",
      "signature": { "status": "NotSigned", "signed": false }
    },
    {
      "kind": "desktop-msi",
      "path": "target\\desktop\\keli-desktop-mvp-windows-x64.msi",
      "signature": { "status": "NotSigned", "signed": false }
    }
  ],
  "public_release_blockers": [
    "artifact-signature-missing",
    "signing-certificate-missing"
  ]
}
```

- [ ] **Step 3: Implement explicit signing**

When `-Sign` is supplied:

- fail if `signtool` is unavailable;
- sign EXE and MSI using PFX mode when `CertificatePath` is configured;
- otherwise sign using certificate-store subject mode when `CertificateSubject` is configured;
- pass `/fd SHA256 /td SHA256 /tr <timestamp-url>`;
- re-read Authenticode signatures after signing;
- keep blockers if signatures are still not valid.

## Task 3: Gate And Release Evidence Integration

**Files:**
- Modify: `scripts/desktop-mvp-gate.ps1`
- Modify: `scripts/desktop-release-evidence.ps1`

- [ ] **Step 1: Add MVP gate step**

Add after `Desktop machine smoke evidence` and before `Desktop release evidence`:

```powershell
New-GateStep -Name 'Desktop signing evidence' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-signing.ps1')
```

Add this plan artifact:

```powershell
Write-Output 'artifact target\desktop\keli-desktop-signing.json'
```

- [ ] **Step 2: Add release evidence input**

`scripts/desktop-release-evidence.ps1 -PlanOnly` must include:

```powershell
input target\desktop\keli-desktop-signing.json
metadata public_release_ready false_when_signing_missing
```

Actual release evidence must read signing JSON and embed:

```json
"signing": {
  "path": "target\\desktop\\keli-desktop-signing.json",
  "status": "passed",
  "mode": "inspect",
  "signtool_available": true,
  "can_sign": false,
  "blockers": ["artifact-signature-missing", "signing-certificate-missing"]
}
```

Release evidence must add signing blockers from the signing JSON and avoid duplicating the same blocker twice.

## Task 4: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-signing-evidence.md`
- `scripts/desktop-signing.ps1`
- `scripts/desktop-signing.tests.ps1`
- `scripts/desktop-mvp-gate.ps1`
- `scripts/desktop-mvp-gate.tests.ps1`
- `scripts/desktop-release-evidence.ps1`
- `scripts/desktop-release-evidence.tests.ps1`

- [ ] **Step 1: Focused tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Focused actual scripts**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1
```

Expected: PASS and write signing and release evidence JSON. Without a certificate, release blockers include `artifact-signature-missing` and `signing-certificate-missing`.

- [ ] **Step 3: Full desktop MVP gate**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS and include desktop signing evidence before release evidence.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-signing-evidence.md
git commit -m "Plan desktop signing evidence"
git push origin main
git add scripts/desktop-signing.ps1 scripts/desktop-signing.tests.ps1 scripts/desktop-mvp-gate.ps1 scripts/desktop-mvp-gate.tests.ps1 scripts/desktop-release-evidence.ps1 scripts/desktop-release-evidence.tests.ps1
git commit -m "Add desktop signing evidence"
git push origin main
```

## Self-Review Checklist

- Spec coverage: advances signing from an informal blocker to an executable, auditable release gate.
- Placeholder scan: no missing commands, paths, or expected outputs.
- Scope: no secrets are stored or printed; actual signing is explicit through `-Sign`.
- Release honesty: unsigned artifacts and missing certificate configuration remain public-release blockers.
