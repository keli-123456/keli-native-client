[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$auditScript = Join-Path $scriptDir 'desktop-beta-rc-audit.ps1'

if (!(Test-Path -LiteralPath $auditScript)) {
    throw 'desktop-beta-rc-audit.ps1 was not found'
}

$planOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $auditScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-beta-rc-audit.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $planOutput -join "`n"
$expectedPlan = @(
    'input target\desktop\keli-desktop-unsigned-beta-manifest.json',
    'input target\desktop\keli-desktop-unsigned-beta-release-notes.md',
    'verify artifacts desktop-shell-exe portable-zip desktop-msi bytes sha256',
    'verify release notes version artifacts hashes unsigned warning commands',
    'verify smoke evidence support and running support reports',
    'write target\desktop\keli-desktop-beta-rc-audit.json',
    'output beta rc audit ready'
)
foreach ($item in $expectedPlan) {
    if (!$plan.Contains($item)) {
        throw "desktop beta RC audit plan is missing: $item"
    }
}

function New-FixtureArtifact {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath,

        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $path = Join-Path $repoRoot $RelativePath
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
    Set-Content -LiteralPath $path -Value $Content -Encoding ASCII
    $item = Get-Item -LiteralPath $path
    $hash = Get-FileHash -LiteralPath $path -Algorithm SHA256
    [ordered]@{
        path = $RelativePath
        bytes = $item.Length
        sha256 = $hash.Hash.ToLowerInvariant()
    }
}

function Write-PassingSmoke {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath,

        [switch]$Running
    )

    $path = Join-Path $repoRoot $RelativePath
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
    $json = if ($Running) {
        [ordered]@{
            status = 'passed'
            desktop_status_running = $true
            desktop_status_selected = $true
            managed_status_selected = $true
            diagnosis_selected = $true
            redaction_ready = $true
            stopped_after_smoke = $true
        }
    } else {
        [ordered]@{
            status = 'passed'
            kind = 'keli_desktop_support_bundle'
            desktop_dependencies = $true
        }
    }
    $json | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding ASCII
}

$tempDir = Join-Path $repoRoot 'target\desktop-beta-rc-audit-tests'
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

$exe = New-FixtureArtifact -RelativePath 'target\desktop-beta-rc-audit-tests\keli-desktop-shell.exe' -Content 'desktop shell exe fixture'
$zip = New-FixtureArtifact -RelativePath 'target\desktop-beta-rc-audit-tests\keli-desktop.zip' -Content 'portable zip fixture'
$msi = New-FixtureArtifact -RelativePath 'target\desktop-beta-rc-audit-tests\keli-desktop.msi' -Content 'msi fixture'

$installSupportSmoke = 'target\desktop-beta-rc-audit-tests\install-support-export.json'
$installRunningSmoke = 'target\desktop-beta-rc-audit-tests\install-running-support.json'
$msiSupportSmoke = 'target\desktop-beta-rc-audit-tests\msi-support-export.json'
$msiRunningSmoke = 'target\desktop-beta-rc-audit-tests\msi-running-support.json'
Write-PassingSmoke -RelativePath $installSupportSmoke
Write-PassingSmoke -RelativePath $installRunningSmoke -Running
Write-PassingSmoke -RelativePath $msiSupportSmoke
Write-PassingSmoke -RelativePath $msiRunningSmoke -Running

$manifestPath = Join-Path $tempDir 'manifest.json'
$notesPath = Join-Path $tempDir 'release-notes.md'
$reportPath = Join-Path $tempDir 'audit.json'
$manifest = [ordered]@{
    status = 'passed'
    channel = 'unsigned-beta'
    version = '0.1.425'
    unsigned = $true
    artifacts = @(
        [ordered]@{ kind = 'desktop-shell-exe'; path = $exe.path; bytes = $exe.bytes; sha256 = $exe.sha256 },
        [ordered]@{ kind = 'portable-zip'; path = $zip.path; bytes = $zip.bytes; sha256 = $zip.sha256 },
        [ordered]@{ kind = 'desktop-msi'; path = $msi.path; bytes = $msi.bytes; sha256 = $msi.sha256 }
    )
    smoke_evidence = [ordered]@{
        install = [ordered]@{
            support_export_smoke = $installSupportSmoke
            running_support_smoke = $installRunningSmoke
        }
        msi = [ordered]@{
            support_export_smoke = $msiSupportSmoke
            running_support_smoke = $msiRunningSmoke
        }
    }
    verification_commands = @(
        'scripts\desktop-mvp-gate.ps1',
        'scripts\desktop-public-release-gate.ps1 -SkipGate',
        'scripts\desktop-beta-rc.ps1',
        'scripts\desktop-beta-rc-audit.ps1'
    )
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding ASCII

$notes = @(
    '# Keli Desktop Unsigned Beta RC 0.1.425',
    'This is an unsigned Beta build for testing.',
    'Windows may show SmartScreen or publisher warnings.',
    'Verify SHA256 hashes before running artifacts.',
    "- desktop-shell-exe: ``$($exe.path)`` SHA256 ``$($exe.sha256)``",
    "- portable-zip: ``$($zip.path)`` SHA256 ``$($zip.sha256)``",
    "- desktop-msi: ``$($msi.path)`` SHA256 ``$($msi.sha256)``",
    '- `scripts\desktop-beta-rc.ps1`',
    '- `scripts\desktop-beta-rc-audit.ps1`'
)
$notes | Set-Content -LiteralPath $notesPath -Encoding ASCII

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $auditScript -ManifestPath $manifestPath -ReleaseNotesPath $notesPath -ReportPath $reportPath
if ($LASTEXITCODE -ne 0) {
    throw "desktop-beta-rc-audit.ps1 fixture exited with $LASTEXITCODE"
}
$text = $output -join "`n"
foreach ($item in @(
    'beta_rc_audit_ready true',
    'channel unsigned-beta',
    'artifact_count 3',
    'smoke_evidence_ready true'
)) {
    if (!$text.Contains($item)) {
        throw "desktop beta RC audit output missing: $item"
    }
}
if (!(Test-Path -LiteralPath $reportPath -PathType Leaf)) {
    throw 'desktop beta RC audit report was not written'
}

$report = Get-Content -Raw -LiteralPath $reportPath | ConvertFrom-Json
if ($report.status -ne 'passed') {
    throw "audit report status mismatch: $($report.status)"
}
if ($report.artifact_count -ne 3) {
    throw "audit report artifact count mismatch: $($report.artifact_count)"
}
if ($report.release_notes_ready -ne $true) {
    throw 'audit release notes should be ready'
}
if ($report.smoke_evidence_ready -ne $true) {
    throw 'audit smoke evidence should be ready'
}
if ($report.smoke_evidence.install.running_support_smoke.status -ne 'passed') {
    throw 'audit install running support smoke should pass'
}

Set-Content -LiteralPath (Join-Path $repoRoot $zip.path) -Value 'changed zip fixture!' -Encoding ASCII
$blockedStdoutPath = Join-Path $tempDir 'blocked-stdout.txt'
$blockedStderrPath = Join-Path $tempDir 'blocked-stderr.txt'
$blockedReportPath = Join-Path $tempDir 'blocked-audit.json'
$process = Start-Process `
    -FilePath 'powershell' `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $auditScript, '-ManifestPath', $manifestPath, '-ReleaseNotesPath', $notesPath, '-ReportPath', $blockedReportPath) `
    -NoNewWindow `
    -Wait `
    -PassThru `
    -RedirectStandardOutput $blockedStdoutPath `
    -RedirectStandardError $blockedStderrPath
if ($process.ExitCode -eq 0) {
    throw 'desktop-beta-rc-audit.ps1 should fail when an artifact hash changes'
}
$failureText = @(
    if (Test-Path -LiteralPath $blockedStdoutPath) {
        Get-Content -LiteralPath $blockedStdoutPath
    }
    if (Test-Path -LiteralPath $blockedStderrPath) {
        Get-Content -LiteralPath $blockedStderrPath
    }
) -join "`n"
if (!$failureText.Contains('artifact SHA256 mismatch for portable-zip')) {
    throw "artifact mismatch failure did not name portable-zip: $failureText"
}

Write-Output 'desktop beta RC audit tests passed'
