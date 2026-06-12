# Desktop Signing Command Preview Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add non-secret signing command previews to desktop signing evidence so release operators can verify the exact signtool argument shape before running real signing.

**Architecture:** Keep `scripts/desktop-signing.ps1` as the signing source of truth. Reuse the same argument construction as `Invoke-SignToolSign`, but expose a redacted preview under `sign_command_previews` in inspect evidence without invoking signtool or weakening release blockers.

**Tech Stack:** PowerShell 5+, existing desktop signing evidence script and test.

---

## Scope Check

This slice covers:

- `sign_command_previews` in `target\desktop\keli-desktop-signing.json`.
- Preview records for EXE and MSI artifacts when a signing method is configured.
- Redacted password display as `<redacted>` when `KELI_SIGN_CERT_PASSWORD` or `-CertificatePassword` is set.
- PFX previews using `<KELI_SIGN_CERT_PATH>` instead of printing the local PFX path.
- Store-subject previews with the configured subject.
- PlanOnly metadata documenting the preview field.

This slice does not cover:

- Signing artifacts.
- Validating PFX contents.
- Printing certificate passwords.
- Marking public release ready without valid signatures.
- Changing public release gate behavior.

## File Structure

- Modify: `scripts/desktop-signing.tests.ps1`
  - Add PlanOnly expectation for signing command previews.
  - Add a deterministic PFX preview fixture using a temporary empty PFX path and fake signtool path.
  - Assert previews exist for EXE/MSI and password is redacted.
- Modify: `scripts/desktop-signing.ps1`
  - Add helpers that build signtool preview arguments from the same configuration fields used by real signing.
  - Add `sign_command_previews` to evidence.

## Task 1: RED Signing Preview Test

**Files:**
- Modify: `scripts/desktop-signing.tests.ps1`

- [ ] **Step 1: Add PlanOnly expectation**

Add:

```powershell
'metadata sign_command_previews redacted'
```

- [ ] **Step 2: Add deterministic PFX preview fixture**

Append:

```powershell
$tempDir = Join-Path $repoRoot 'target\desktop-signing-tests'
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
$fakePfxPath = Join-Path $tempDir 'codesign-test.pfx'
Set-Content -LiteralPath $fakePfxPath -Value 'not-a-real-pfx' -Encoding ASCII
$fakeSignToolPath = Join-Path $env:SystemRoot 'System32\cmd.exe'

& powershell -NoProfile -ExecutionPolicy Bypass -File $signingScript `
    -SignToolPath $fakeSignToolPath `
    -CertificatePath $fakePfxPath `
    -CertificatePassword 'secret-password' `
    -CertificateSubject ' ' `
    -SkipCertificateStoreDiscovery
if ($LASTEXITCODE -ne 0) {
    throw "desktop-signing.ps1 preview inspect exited with $LASTEXITCODE"
}

$previewEvidence = Get-Content -Raw -LiteralPath $evidencePath | ConvertFrom-Json
if ($previewEvidence.sign_command_previews.Count -ne 2) {
    throw "expected two signing command previews, got $($previewEvidence.sign_command_previews.Count)"
}
foreach ($preview in $previewEvidence.sign_command_previews) {
    if ($preview.command -notlike 'signtool sign *') {
        throw "preview command should start with signtool sign: $($preview.command)"
    }
    if (!$preview.command.Contains('/f <KELI_SIGN_CERT_PATH>')) {
        throw "preview command should redact PFX path: $($preview.command)"
    }
    if (!$preview.command.Contains('/p <redacted>')) {
        throw "preview command should redact password: $($preview.command)"
    }
    if ($preview.command.Contains('secret-password')) {
        throw 'preview command leaked the certificate password'
    }
    if ($preview.command.Contains($fakePfxPath)) {
        throw 'preview command leaked the local PFX path'
    }
}
```

- [ ] **Step 3: Run RED test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-signing.tests.ps1
```

Expected: FAIL because PlanOnly and evidence do not yet include signing command previews.

## Task 2: GREEN Signing Preview Evidence

**Files:**
- Modify: `scripts/desktop-signing.ps1`

- [ ] **Step 1: Add PlanOnly metadata**

Add:

```powershell
Write-Output 'metadata sign_command_previews redacted'
```

- [ ] **Step 2: Add preview argument helpers**

Add:

```powershell
function Get-SignToolPreviewArguments {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Configuration,
        [AllowNull()]
        [string]$ConfiguredCertificatePassword,
        [AllowNull()]
        [string]$ConfiguredCertificateSubject,
        [Parameter(Mandatory = $true)]
        [string]$ArtifactRelativePath
    )

    $arguments = @('sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', $Configuration.timestamp_url)
    if ($Configuration.signing_method -eq 'pfx') {
        $arguments += @('/f', '<KELI_SIGN_CERT_PATH>')
        if (![string]::IsNullOrWhiteSpace($ConfiguredCertificatePassword)) {
            $arguments += @('/p', '<redacted>')
        }
    } elseif ($Configuration.signing_method -eq 'store-subject') {
        $arguments += @('/n', $ConfiguredCertificateSubject)
    } else {
        return @()
    }
    $arguments += $ArtifactRelativePath
    return $arguments
}

function Format-PreviewCommand {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $parts = @('signtool')
    foreach ($argument in $Arguments) {
        if ($argument -match '\s') {
            $parts += '"' + ($argument -replace '"', '\"') + '"'
        } else {
            $parts += $argument
        }
    }
    return $parts -join ' '
}

function Get-SignCommandPreviews {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Configuration,
        [Parameter(Mandatory = $true)]
        [object[]]$Artifacts,
        [AllowNull()]
        [string]$ConfiguredCertificatePassword,
        [AllowNull()]
        [string]$ConfiguredCertificateSubject
    )

    $previews = @()
    foreach ($artifact in $Artifacts) {
        $arguments = Get-SignToolPreviewArguments -Configuration $Configuration -ConfiguredCertificatePassword $ConfiguredCertificatePassword -ConfiguredCertificateSubject $ConfiguredCertificateSubject -ArtifactRelativePath ([string]$artifact.path)
        if ($arguments.Count -eq 0) {
            continue
        }
        $previews += [ordered]@{
            artifact = [string]$artifact.path
            signing_method = [string]$Configuration.signing_method
            command = Format-PreviewCommand -Arguments $arguments
        }
    }
    return $previews
}
```

- [ ] **Step 3: Add previews to evidence**

After `$artifacts` is created, compute:

```powershell
$signCommandPreviews = Get-SignCommandPreviews -Configuration $configuration -Artifacts $artifacts -ConfiguredCertificatePassword $CertificatePassword -ConfiguredCertificateSubject $CertificateSubject
```

Then add to evidence:

```powershell
sign_command_previews = $signCommandPreviews
```

- [ ] **Step 4: Run GREEN test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-signing.tests.ps1
```

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-signing-command-preview.md`
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

Expected: PASS and no previews when no signing method is configured.

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

- [ ] **Step 5: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-signing-command-preview.md
git commit -m "Plan desktop signing command preview"
git push
git add scripts/desktop-signing.ps1 scripts/desktop-signing.tests.ps1
git commit -m "Add desktop signing command previews"
git push
```

## Self-Review Checklist

- Spec coverage: signing command shape becomes auditable before real signing.
- Placeholder scan: paths, commands, and expected redactions are concrete.
- Type consistency: `sign_command_previews` has stable `artifact`, `signing_method`, and `command` fields.
- Scope: no password or local PFX path is printed.
- Release honesty: unsigned artifacts and missing certificate configuration remain public-release blockers.
