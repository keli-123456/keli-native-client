# Desktop Public Gate Signing Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make public release gate failures self-contained by printing non-secret signing diagnostics and by allowing deterministic fixture-based gate tests.

**Architecture:** Keep the default public gate behavior unchanged: it still regenerates release evidence unless `-SkipGate` is supplied and it still fails on every current blocker. Add an optional `-EvidencePath` parameter that defaults to `target\desktop\keli-desktop-release-evidence.json`, then build a compact signing diagnostics suffix from fields already present in release evidence.

**Tech Stack:** PowerShell 5+, existing desktop release evidence JSON, existing public release gate script and tests.

---

## Scope Check

This slice covers:

- `scripts/desktop-public-release-gate.ps1 -EvidencePath <path>` for deterministic fixture tests.
- PlanOnly output that documents the custom evidence path and signing diagnostics behavior.
- Failure messages that include `signing_signtool_available`, `signing_method`, and `signing_unsigned_artifacts` when those fields are present.
- A fixture-based test proving the failure message is actionable without regenerating the whole desktop package.

This slice does not cover:

- Changing the public release readiness criteria.
- Signing artifacts.
- Printing certificate passwords, certificate paths, or secret material.
- Changing the normal `scripts\desktop-public-release-gate.ps1` command used by release operators.

## File Structure

- Modify: `scripts/desktop-public-release-gate.tests.ps1`
  - Extend PlanOnly expectations.
  - Add a fixture release evidence file under `target\desktop-public-release-gate-tests`.
  - Run the gate with `-SkipGate -EvidencePath <fixture>` and assert the failure output includes blockers, next steps, and signing diagnostics.
- Modify: `scripts/desktop-public-release-gate.ps1`
  - Add optional `-EvidencePath`.
  - Add helper functions to read string/bool/array fields and format signing diagnostics.
  - Append diagnostics to failure messages when present.

## Task 1: RED Public Gate Diagnostics Test

**Files:**
- Modify: `scripts/desktop-public-release-gate.tests.ps1`

- [ ] **Step 1: Extend PlanOnly expectations**

Add expected lines:

```powershell
'config -EvidencePath optional'
'failure print signing diagnostics when available'
```

- [ ] **Step 2: Add fixture evidence**

Add this fixture after PlanOnly assertions:

```powershell
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$tempDir = Join-Path $repoRoot 'target\desktop-public-release-gate-tests'
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
$fixturePath = Join-Path $tempDir 'release-evidence.json'

$workflowIds = @(
    'open-desktop-shell',
    'import-subscription',
    'select-node',
    'start-stop-system-proxy',
    'tun-preflight',
    'export-support-bundle'
)
$fixture = [ordered]@{
    status = 'passed'
    public_release_ready = $false
    public_release_blockers = @('artifact-signature-missing', 'signing-certificate-missing')
    public_release_next_steps = @('configure-code-signing-certificate', 'run-desktop-signing-sign', 'run-public-release-gate')
    signing = [ordered]@{
        can_sign = $false
        signtool_available = $true
        signing_method = ''
        unsigned_artifacts = @('target\release\keli-desktop-shell.exe', 'target\desktop\keli-desktop-mvp-windows-x64.msi')
    }
    smoke = [ordered]@{
        install = [ordered]@{
            readme_subscription_import = 'subscription-url-or-config'
            manual_smoke_cases = $workflowIds
            verified_ui_workflow_entrypoints = $workflowIds
        }
        msi = [ordered]@{
            readme_subscription_import = 'subscription-url-or-config'
            manual_smoke_cases = $workflowIds
        }
        machine = [ordered]@{
            machine_takeover_status = 'ready'
        }
    }
}
$fixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $fixturePath -Encoding ASCII
```

- [ ] **Step 3: Assert actionable failure output**

Append:

```powershell
$failureOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $gateScript -SkipGate -EvidencePath $fixturePath 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'desktop-public-release-gate.ps1 fixture run should fail'
}
$failureText = $failureOutput -join "`n"
foreach ($item in @(
    'Desktop public release gate blocked: artifact-signature-missing,signing-certificate-missing',
    'next_steps=configure-code-signing-certificate,run-desktop-signing-sign,run-public-release-gate',
    'signing_signtool_available=true',
    'signing_method=none',
    'signing_unsigned_artifacts=target\release\keli-desktop-shell.exe,target\desktop\keli-desktop-mvp-windows-x64.msi'
)) {
    if (!$failureText.Contains($item)) {
        throw "desktop public release gate fixture output is missing: $item"
    }
}
```

- [ ] **Step 4: Run RED test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: FAIL because `-EvidencePath` and signing diagnostic output do not exist yet.

## Task 2: GREEN Public Gate Diagnostics

**Files:**
- Modify: `scripts/desktop-public-release-gate.ps1`

- [ ] **Step 1: Add parameter and default path handling**

Add parameter:

```powershell
[string]$EvidencePath
```

After computing `$repoRoot`, keep the same default:

```powershell
if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    $EvidencePath = Join-Path $repoRoot $releaseEvidenceRelativePath
}
```

- [ ] **Step 2: Add diagnostic helpers**

Add helpers:

```powershell
function Test-JsonProperty {
    param([AllowNull()][object]$InputObject, [Parameter(Mandatory = $true)][string]$Name)
    return ($null -ne $InputObject -and $null -ne $InputObject.PSObject.Properties[$Name])
}

function Get-StringArrayProperty {
    param([AllowNull()][object]$InputObject, [Parameter(Mandatory = $true)][string]$Name)
    if (!(Test-JsonProperty -InputObject $InputObject -Name $Name)) { return @() }
    return @($InputObject.$Name | ForEach-Object { [string]$_ } | Where-Object { ![string]::IsNullOrWhiteSpace($_) })
}

function Get-OptionalSigningDiagnostics {
    param([Parameter(Mandatory = $true)][object]$Evidence)

    if (!(Test-JsonProperty -InputObject $Evidence -Name 'signing')) {
        return ''
    }
    $signing = $Evidence.signing
    $parts = @()
    if (Test-JsonProperty -InputObject $signing -Name 'signtool_available') {
        $parts += "signing_signtool_available=$(([bool]$signing.signtool_available).ToString().ToLowerInvariant())"
    }
    if (Test-JsonProperty -InputObject $signing -Name 'signing_method') {
        $method = [string]$signing.signing_method
        if ([string]::IsNullOrWhiteSpace($method)) { $method = 'none' }
        $parts += "signing_method=$method"
    }
    $unsignedArtifacts = Get-StringArrayProperty -InputObject $signing -Name 'unsigned_artifacts'
    if ($unsignedArtifacts.Count -gt 0) {
        $parts += "signing_unsigned_artifacts=$($unsignedArtifacts -join ',')"
    }
    if ($parts.Count -eq 0) {
        return ''
    }
    return $parts -join ' '
}
```

- [ ] **Step 3: Append diagnostics to failure messages**

Before throwing blocker messages:

```powershell
$diagnostics = Get-OptionalSigningDiagnostics -Evidence $evidence
$diagnosticSuffix = if ([string]::IsNullOrWhiteSpace($diagnostics)) { '' } else { " $diagnostics" }
```

Append `$diagnosticSuffix` to both blocker throw messages.

- [ ] **Step 4: Update PlanOnly output**

Add:

```powershell
Write-Output 'config -EvidencePath optional'
Write-Output 'failure print signing diagnostics when available'
```

- [ ] **Step 5: Run GREEN test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-public-gate-signing-diagnostics.md`
- `scripts/desktop-public-release-gate.ps1`
- `scripts/desktop-public-release-gate.tests.ps1`

- [ ] **Step 1: Focused public gate test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: PASS and fixture failure output includes signing diagnostics.

- [ ] **Step 2: Real public gate failure check**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: FAIL because signing is still unavailable; output includes signing diagnostics and no workflow/machine blockers.

- [ ] **Step 3: Full desktop MVP gate**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-public-gate-signing-diagnostics.md
git commit -m "Plan desktop public gate signing diagnostics"
git push
git add scripts/desktop-public-release-gate.ps1 scripts/desktop-public-release-gate.tests.ps1
git commit -m "Print desktop public gate signing diagnostics"
git push
```

## Self-Review Checklist

- Spec coverage: failure logs become actionable while the gate remains strict.
- Placeholder scan: all commands, fields, paths, and expected output fragments are concrete.
- Type consistency: `signing.signtool_available`, `signing.signing_method`, and `signing.unsigned_artifacts` match release evidence.
- Scope: no certificate secrets or local certificate paths are printed.
- Release honesty: unsigned artifacts and missing certificate configuration still fail public release.
