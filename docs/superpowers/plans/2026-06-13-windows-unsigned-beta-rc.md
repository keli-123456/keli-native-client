# Windows Unsigned Beta Release Candidate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an unsigned Beta RC gate that turns the existing desktop MVP artifacts and release evidence into a tester-ready manifest and release notes while allowing only signing-related public release blockers.

**Architecture:** Create a new PowerShell script, `scripts\desktop-beta-rc.ps1`, that reads `keli-desktop-release-evidence.json`, validates current MVP status, validates that public release blockers are signing-only, and writes `keli-desktop-unsigned-beta-manifest.json` plus `keli-desktop-unsigned-beta-release-notes.md`. Keep the formal public release gate unchanged.

**Tech Stack:** PowerShell 5+, existing desktop MVP gate, existing release evidence JSON, existing MVP status script.

---

### Task 1: Beta RC Gate Red Test

**Files:**
- Create: `scripts/desktop-beta-rc.tests.ps1`

- [ ] **Step 1: Add PlanOnly expectations**

Create `scripts\desktop-beta-rc.tests.ps1` with a PlanOnly check requiring these lines:

```powershell
$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$betaScript = Join-Path $scriptDir 'desktop-beta-rc.ps1'

if (!(Test-Path -LiteralPath $betaScript)) {
    throw 'desktop-beta-rc.ps1 was not found'
}

$planOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $betaScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-beta-rc.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $planOutput -join "`n"
$expectedPlan = @(
    'input target\desktop\keli-desktop-release-evidence.json',
    'input desktop MVP status from scripts\desktop-mvp-status.ps1 -Json',
    'require desktop_mvp_ready true',
    'require release evidence status passed',
    'require artifacts desktop-shell-exe portable-zip desktop-msi with sha256',
    'allow public_release_blockers artifact-signature-missing signing-certificate-missing only',
    'write target\desktop\keli-desktop-unsigned-beta-manifest.json',
    'write target\desktop\keli-desktop-unsigned-beta-release-notes.md',
    'output unsigned beta rc ready'
)
foreach ($item in $expectedPlan) {
    if (!$plan.Contains($item)) {
        throw "desktop beta RC plan is missing: $item"
    }
}
```

- [ ] **Step 2: Add a passing fixture**

In the same test file, write a release evidence fixture to `target\desktop-beta-rc-tests\release-evidence.json`:

```powershell
$tempDir = Join-Path $repoRoot 'target\desktop-beta-rc-tests'
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
$fixturePath = Join-Path $tempDir 'release-evidence.json'
$manifestPath = Join-Path $tempDir 'keli-desktop-unsigned-beta-manifest.json'
$notesPath = Join-Path $tempDir 'keli-desktop-unsigned-beta-release-notes.md'

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
    version = '0.1.425'
    native_core_default = $true
    public_release_ready = $false
    public_release_blockers = @('artifact-signature-missing', 'signing-certificate-missing')
    public_release_next_steps = @('configure-code-signing-certificate', 'run-desktop-signing-sign', 'run-public-release-gate')
    artifacts = @(
        [ordered]@{ kind = 'desktop-shell-exe'; path = 'target\release\keli-desktop-shell.exe'; bytes = 100; sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; signature = [ordered]@{ signed = $false; status = 'NotSigned' } },
        [ordered]@{ kind = 'portable-zip'; path = 'target\desktop\keli-desktop-mvp-windows-x64.zip'; bytes = 200; sha256 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' },
        [ordered]@{ kind = 'desktop-msi'; path = 'target\desktop\keli-desktop-mvp-windows-x64.msi'; bytes = 300; sha256 = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'; signature = [ordered]@{ signed = $false; status = 'NotSigned' } }
    )
    signing = [ordered]@{
        status = 'passed'
        mode = 'inspect'
        can_sign = $false
        signtool_available = $true
        unsigned_artifacts = @('target\release\keli-desktop-shell.exe', 'target\desktop\keli-desktop-mvp-windows-x64.msi')
    }
    smoke = [ordered]@{
        install = [ordered]@{
            status = 'passed'
            native_core_default = $true
            readme_subscription_import = 'subscription-url-or-config'
            manual_smoke_cases = $workflowIds
            verified_ui_workflow_entrypoints = $workflowIds
            first_run_system_proxy_ready = $true
            first_run_tun_ready = $false
            first_run_blockers = @([ordered]@{ code = 'wintun-missing'; message = 'Wintun library was not found'; action = 'install-wintun' })
            dependency_action_entrypoints = @('install-wintun')
            support_export_smoke = 'target\desktop-install-smoke\desktop-support-export-smoke.json'
            support_export_kind = 'keli_desktop_support_bundle'
            support_export_desktop_dependencies = $true
        }
        msi = [ordered]@{
            status = 'passed'
            native_core_default = $true
            readme_subscription_import = 'subscription-url-or-config'
            manual_smoke_cases = $workflowIds
            support_export_smoke = 'target\desktop\keli-desktop-msi-support-export-smoke.json'
            support_export_kind = 'keli_desktop_support_bundle'
            support_export_desktop_dependencies = $true
        }
        machine = [ordered]@{
            status = 'passed'
            native_core_default = $true
            machine_takeover_status = 'ready'
        }
    }
}
$fixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $fixturePath -Encoding ASCII
```

- [ ] **Step 3: Assert pass output and generated files**

Call the script with explicit fixture/output paths and assert:

```powershell
$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $betaScript -EvidencePath $fixturePath -ManifestPath $manifestPath -ReleaseNotesPath $notesPath
if ($LASTEXITCODE -ne 0) {
    throw "desktop-beta-rc.ps1 fixture exited with $LASTEXITCODE"
}
$text = $output -join "`n"
foreach ($item in @(
    'unsigned_beta_rc_ready true',
    'version 0.1.425',
    'channel unsigned-beta',
    'allowed_public_release_blockers artifact-signature-missing,signing-certificate-missing'
)) {
    if (!$text.Contains($item)) {
        throw "desktop beta RC output missing: $item"
    }
}
if (!(Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'desktop beta RC manifest was not written'
}
if (!(Test-Path -LiteralPath $notesPath -PathType Leaf)) {
    throw 'desktop beta RC release notes were not written'
}

$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
if ($manifest.channel -ne 'unsigned-beta') { throw "manifest channel mismatch: $($manifest.channel)" }
if ($manifest.version -ne '0.1.425') { throw "manifest version mismatch: $($manifest.version)" }
if ($manifest.unsigned -ne $true) { throw 'manifest unsigned must be true' }
if (($manifest.allowed_public_release_blockers -join ',') -ne 'artifact-signature-missing,signing-certificate-missing') {
    throw "manifest allowed blockers mismatch: $($manifest.allowed_public_release_blockers -join ',')"
}
if ($manifest.artifacts.Count -ne 3) { throw "manifest artifact count mismatch: $($manifest.artifacts.Count)" }
if (($manifest.verification_commands -join "`n") -notlike '*scripts\desktop-beta-rc.ps1*') {
    throw 'manifest verification commands must include beta RC gate'
}

$notes = Get-Content -Raw -LiteralPath $notesPath
foreach ($item in @(
    '# Keli Desktop Unsigned Beta RC 0.1.425',
    'This is an unsigned Beta build for testing.',
    'Windows may show SmartScreen or publisher warnings.',
    'Verify SHA256 hashes before running artifacts.',
    'scripts\desktop-beta-rc.ps1',
    'Support bundles'
)) {
    if (!$notes.Contains($item)) {
        throw "desktop beta RC release notes missing: $item"
    }
}
```

- [ ] **Step 4: Add a failing fixture for extra blockers**

Copy the fixture, append `machine-takeover-smoke-not-ready`, and require failure text:

```powershell
$blockedFixturePath = Join-Path $tempDir 'release-evidence-extra-blocker.json'
$blockedFixture = Get-Content -Raw -LiteralPath $fixturePath | ConvertFrom-Json
$blockedFixture.public_release_blockers = @('artifact-signature-missing', 'signing-certificate-missing', 'machine-takeover-smoke-not-ready')
$blockedFixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $blockedFixturePath -Encoding ASCII

$stdoutPath = Join-Path $tempDir 'blocked-stdout.txt'
$stderrPath = Join-Path $tempDir 'blocked-stderr.txt'
$process = Start-Process `
    -FilePath 'powershell' `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $betaScript, '-EvidencePath', $blockedFixturePath, '-ManifestPath', $manifestPath, '-ReleaseNotesPath', $notesPath) `
    -NoNewWindow `
    -Wait `
    -PassThru `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath
if ($process.ExitCode -eq 0) {
    throw 'desktop-beta-rc.ps1 should fail when non-signing blockers are present'
}
$failureText = @(
    if (Test-Path -LiteralPath $stdoutPath) { Get-Content -LiteralPath $stdoutPath }
    if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath }
) -join "`n"
if (!$failureText.Contains('Desktop unsigned beta RC blocked: machine-takeover-smoke-not-ready')) {
    throw "extra blocker failure did not name machine-takeover-smoke-not-ready: $failureText"
}
```

- [ ] **Step 5: Add a failing fixture for local MVP blockers**

Copy the fixture, remove MSI support export dependency evidence, and require failure text:

```powershell
$mvpBlockedFixturePath = Join-Path $tempDir 'release-evidence-mvp-blocked.json'
$mvpBlockedFixture = Get-Content -Raw -LiteralPath $fixturePath | ConvertFrom-Json
$mvpBlockedFixture.smoke.msi.support_export_desktop_dependencies = $false
$mvpBlockedFixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $mvpBlockedFixturePath -Encoding ASCII

$mvpStdoutPath = Join-Path $tempDir 'mvp-blocked-stdout.txt'
$mvpStderrPath = Join-Path $tempDir 'mvp-blocked-stderr.txt'
$mvpProcess = Start-Process `
    -FilePath 'powershell' `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $betaScript, '-EvidencePath', $mvpBlockedFixturePath, '-ManifestPath', $manifestPath, '-ReleaseNotesPath', $notesPath) `
    -NoNewWindow `
    -Wait `
    -PassThru `
    -RedirectStandardOutput $mvpStdoutPath `
    -RedirectStandardError $mvpStderrPath
if ($mvpProcess.ExitCode -eq 0) {
    throw 'desktop-beta-rc.ps1 should fail when desktop MVP status is blocked'
}
$mvpFailureText = @(
    if (Test-Path -LiteralPath $mvpStdoutPath) { Get-Content -LiteralPath $mvpStdoutPath }
    if (Test-Path -LiteralPath $mvpStderrPath) { Get-Content -LiteralPath $mvpStderrPath }
) -join "`n"
if (!$mvpFailureText.Contains('Desktop unsigned beta RC blocked: desktop-mvp-not-ready')) {
    throw "MVP blocked failure did not name desktop-mvp-not-ready: $mvpFailureText"
}
```

- [ ] **Step 6: Verify RED**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-beta-rc.tests.ps1
```

Expected: FAIL because `scripts\desktop-beta-rc.ps1` does not exist yet.

### Task 2: Beta RC Script Implementation

**Files:**
- Create: `scripts/desktop-beta-rc.ps1`
- Modify: `scripts/desktop-beta-rc.tests.ps1` only if a test typo prevents the red test from exercising the intended missing behavior.

- [ ] **Step 1: Add script parameters and defaults**

Create `scripts\desktop-beta-rc.ps1`:

```powershell
[CmdletBinding()]
param(
    [string]$EvidencePath,
    [string]$ManifestPath,
    [string]$ReleaseNotesPath,
    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
```

- [ ] **Step 2: Add helpers**

Implement helpers:

```powershell
function Resolve-RepoRoot {
    $scriptDir = Split-Path -Parent $PSCommandPath
    return (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
}

function Require-File {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "required desktop unsigned beta RC input is missing: $Path"
    }
}

function Test-JsonProperty {
    param([AllowNull()][object]$InputObject, [Parameter(Mandatory = $true)][string]$Name)
    return ($null -ne $InputObject -and $null -ne $InputObject.PSObject.Properties[$Name])
}

function Get-StringArrayProperty {
    param([AllowNull()][object]$InputObject, [Parameter(Mandatory = $true)][string]$Name)
    if (!(Test-JsonProperty -InputObject $InputObject -Name $Name)) { return @() }
    return @($InputObject.$Name | ForEach-Object { [string]$_ } | Where-Object { ![string]::IsNullOrWhiteSpace($_) })
}

function Get-ArtifactByKind {
    param([Parameter(Mandatory = $true)][object]$Evidence, [Parameter(Mandatory = $true)][string]$Kind)
    $matches = @($Evidence.artifacts | Where-Object { [string]$_.kind -eq $Kind })
    if ($matches.Count -ne 1) {
        throw "desktop unsigned beta RC requires one artifact of kind $Kind, found $($matches.Count)"
    }
    $artifact = $matches[0]
    if ([string]::IsNullOrWhiteSpace([string]$artifact.path)) {
        throw "desktop unsigned beta RC artifact path is missing for $Kind"
    }
    if ([string]::IsNullOrWhiteSpace([string]$artifact.sha256)) {
        throw "desktop unsigned beta RC artifact sha256 is missing for $Kind"
    }
    return $artifact
}
```

- [ ] **Step 3: Add validation and output writers**

Implement:

```powershell
function Assert-UnsignedBetaReady {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [Parameter(Mandatory = $true)][object]$MvpStatus
    )

    if ([string]$Evidence.status -ne 'passed') {
        throw "Desktop unsigned beta RC blocked: release-evidence-status-$($Evidence.status)"
    }
    if ($MvpStatus.desktop_mvp_ready -ne $true) {
        throw 'Desktop unsigned beta RC blocked: desktop-mvp-not-ready'
    }
    foreach ($kind in @('desktop-shell-exe', 'portable-zip', 'desktop-msi')) {
        Get-ArtifactByKind -Evidence $Evidence -Kind $kind | Out-Null
    }
    $allowed = @('artifact-signature-missing', 'signing-certificate-missing')
    $blockers = @(Get-StringArrayProperty -InputObject $Evidence -Name 'public_release_blockers')
    $unexpected = @($blockers | Where-Object { $allowed -notcontains $_ })
    if ($unexpected.Count -gt 0) {
        throw "Desktop unsigned beta RC blocked: $($unexpected -join ',')"
    }
    return $allowed
}

function Read-DesktopMvpStatus {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$EvidencePath
    )

    $statusScript = Join-Path $RepoRoot 'scripts\desktop-mvp-status.ps1'
    $jsonOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $statusScript -EvidencePath $EvidencePath -Json
    if ($LASTEXITCODE -ne 0) {
        throw "Desktop unsigned beta RC blocked: desktop-mvp-status-failed"
    }
    return ($jsonOutput -join "`n" | ConvertFrom-Json)
}

function New-BetaManifest {
    param([Parameter(Mandatory = $true)][object]$Evidence, [Parameter(Mandatory = $true)][string[]]$AllowedBlockers)

    [ordered]@{
        status = 'passed'
        channel = 'unsigned-beta'
        version = [string]$Evidence.version
        unsigned = ($AllowedBlockers -contains 'artifact-signature-missing')
        allowed_public_release_blockers = $AllowedBlockers
        public_release_ready = [bool]$Evidence.public_release_ready
        artifacts = @(@('desktop-shell-exe', 'portable-zip', 'desktop-msi') | ForEach-Object {
            $artifact = Get-ArtifactByKind -Evidence $Evidence -Kind $_
            [ordered]@{
                kind = [string]$artifact.kind
                path = [string]$artifact.path
                bytes = [int64]$artifact.bytes
                sha256 = [string]$artifact.sha256
            }
        })
        verification_commands = @(
            'scripts\desktop-mvp-gate.ps1',
            'scripts\desktop-public-release-gate.ps1 -SkipGate',
            'scripts\desktop-beta-rc.ps1'
        )
    }
}

function Write-BetaReleaseNotes {
    param([Parameter(Mandatory = $true)][object]$Manifest, [Parameter(Mandatory = $true)][string]$Path)

    $artifactLines = @($Manifest.artifacts | ForEach-Object {
        "- $($_.kind): `$($_.path)` SHA256 `$($_.sha256)`"
    })
    @(
        "# Keli Desktop Unsigned Beta RC $($Manifest.version)",
        '',
        'This is an unsigned Beta build for testing.',
        'Windows may show SmartScreen or publisher warnings.',
        'Verify SHA256 hashes before running artifacts.',
        '',
        '## Artifacts',
        $artifactLines,
        '',
        '## Install Notes',
        '- Use the portable zip for no-installer testing.',
        '- Use the MSI for installer smoke testing.',
        '- Microsoft Edge WebView2 Runtime is required.',
        '- TUN mode requires Wintun; system proxy mode can be tested first.',
        '- Support bundles are exported from Diagnostics under the user Documents Keli Support directory.',
        '',
        '## Verification Commands',
        '- `scripts\desktop-mvp-gate.ps1`',
        '- `scripts\desktop-public-release-gate.ps1 -SkipGate`',
        '- `scripts\desktop-beta-rc.ps1`',
        '',
        '## Support bundles',
        'Export a support bundle from Diagnostics when reporting Beta issues.'
    ) | Set-Content -LiteralPath $Path -Encoding ASCII
}
```

- [ ] **Step 4: Wire main flow**

Add:

```powershell
$repoRoot = Resolve-RepoRoot
$evidenceRelativePath = 'target\desktop\keli-desktop-release-evidence.json'
$manifestRelativePath = 'target\desktop\keli-desktop-unsigned-beta-manifest.json'
$notesRelativePath = 'target\desktop\keli-desktop-unsigned-beta-release-notes.md'

if ([string]::IsNullOrWhiteSpace($EvidencePath)) { $EvidencePath = Join-Path $repoRoot $evidenceRelativePath }
if ([string]::IsNullOrWhiteSpace($ManifestPath)) { $ManifestPath = Join-Path $repoRoot $manifestRelativePath }
if ([string]::IsNullOrWhiteSpace($ReleaseNotesPath)) { $ReleaseNotesPath = Join-Path $repoRoot $notesRelativePath }

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        Write-Output "input $evidenceRelativePath"
        Write-Output 'input desktop MVP status from scripts\desktop-mvp-status.ps1 -Json'
        Write-Output 'require desktop_mvp_ready true'
        Write-Output 'require release evidence status passed'
        Write-Output 'require artifacts desktop-shell-exe portable-zip desktop-msi with sha256'
        Write-Output 'allow public_release_blockers artifact-signature-missing signing-certificate-missing only'
        Write-Output "write $manifestRelativePath"
        Write-Output "write $notesRelativePath"
        Write-Output 'output unsigned beta rc ready'
        return
    }

    Require-File -Path $EvidencePath
    $evidence = Get-Content -Raw -LiteralPath $EvidencePath | ConvertFrom-Json
    $mvpStatus = Read-DesktopMvpStatus -RepoRoot $repoRoot -EvidencePath $EvidencePath
    $allowedBlockers = Assert-UnsignedBetaReady -Evidence $evidence -MvpStatus $mvpStatus
    $manifest = New-BetaManifest -Evidence $evidence -AllowedBlockers $allowedBlockers
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ManifestPath) | Out-Null
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ManifestPath -Encoding ASCII
    Write-BetaReleaseNotes -Manifest $manifest -Path $ReleaseNotesPath

    Write-Output 'unsigned_beta_rc_ready true'
    Write-Output "version $($manifest.version)"
    Write-Output "channel $($manifest.channel)"
    Write-Output "allowed_public_release_blockers $($manifest.allowed_public_release_blockers -join ',')"
} finally {
    Pop-Location
}
```

- [ ] **Step 5: Verify GREEN**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-beta-rc.tests.ps1
```

Expected: PASS and generated fixture manifest/notes assertions pass.

### Task 3: Current Build Beta RC Verification

**Files:**
- Modify: `README.md`
- Modify: `scripts\desktop-mvp-gate.ps1`
- Modify: `scripts\desktop-mvp-gate.tests.ps1`

- [ ] **Step 1: Add MVP gate plan expectation**

In `scripts\desktop-mvp-gate.tests.ps1`, require:

```powershell
'Desktop unsigned beta RC'
'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-beta-rc.ps1'
'artifact target\desktop\keli-desktop-unsigned-beta-manifest.json'
'artifact target\desktop\keli-desktop-unsigned-beta-release-notes.md'
```

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: FAIL because the MVP gate does not yet invoke the Beta RC step.

- [ ] **Step 2: Add the Beta RC step to MVP gate**

In `scripts\desktop-mvp-gate.ps1`, add a gate step after `Desktop release evidence`:

```powershell
New-GateStep -Name 'Desktop unsigned beta RC' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-beta-rc.ps1')
```

Add PlanOnly artifact lines:

```powershell
Write-Output 'artifact target\desktop\keli-desktop-unsigned-beta-manifest.json'
Write-Output 'artifact target\desktop\keli-desktop-unsigned-beta-release-notes.md'
```

- [ ] **Step 3: Add README verification command**

In `README.md` under Verify, add:

```powershell
scripts\desktop-mvp-gate.ps1
scripts\desktop-public-release-gate.ps1 -SkipGate
scripts\desktop-beta-rc.ps1
```

Also add one short paragraph stating that unsigned Beta RC builds are tester builds and Windows may show publisher warnings.

- [ ] **Step 4: Verify focused tests**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-beta-rc.tests.ps1
```

Expected: PASS.

### Task 4: Full Verification, Commit, Push

**Files:**
- Modified files from Tasks 1-3

- [ ] **Step 1: Run full MVP gate**

Run:

```powershell
scripts\desktop-mvp-gate.ps1
```

Expected: PASS, writes:

- `target\desktop\keli-desktop-unsigned-beta-manifest.json`
- `target\desktop\keli-desktop-unsigned-beta-release-notes.md`

- [ ] **Step 2: Verify public release gate honesty**

Run:

```powershell
scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: FAIL only with:

- `artifact-signature-missing`
- `signing-certificate-missing`

- [ ] **Step 3: Verify Beta RC gate directly**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-beta-rc.ps1
```

Expected: PASS with:

```text
unsigned_beta_rc_ready true
channel unsigned-beta
```

- [ ] **Step 4: Diff check, commit, push**

Run:

```powershell
git diff --check
git add docs/superpowers/plans/2026-06-13-windows-unsigned-beta-rc.md scripts/desktop-beta-rc.ps1 scripts/desktop-beta-rc.tests.ps1 scripts/desktop-mvp-gate.ps1 scripts/desktop-mvp-gate.tests.ps1 README.md
git commit -m "Add unsigned beta release candidate gate"
git push
```

## Self-Review

- Spec coverage: plan covers Beta gate semantics, manifest, notes, signing-only blocker allowance, docs, and full verification.
- Placeholder scan: no TBD/TODO/fill-in placeholders remain.
- Type consistency: `channel`, `version`, `unsigned`, `allowed_public_release_blockers`, `artifacts`, and `verification_commands` are used consistently.
- Scope: formal signed public release behavior remains unchanged.
