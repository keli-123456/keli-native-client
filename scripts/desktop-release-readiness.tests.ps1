[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$readinessScript = Join-Path $scriptDir 'desktop-release-readiness.ps1'

if (!(Test-Path -LiteralPath $readinessScript)) {
    throw 'desktop-release-readiness.ps1 was not found'
}

$planOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $readinessScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-release-readiness.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $planOutput -join "`n"
$expectedPlan = @(
    'input target\desktop\keli-desktop-release-evidence.json',
    'read public_release_ready public_release_blockers public_release_next_steps',
    'read signing.can_sign signing.signtool_available signing.signing_method signing.timestamp_url signing.store_certificate_candidates_count signing.unsigned_artifacts signing.sign_command_previews signing.release_commands',
    'read smoke.machine.machine_takeover_status',
    'output desktop public release readiness report',
    'output json when -Json is provided'
)

foreach ($item in $expectedPlan) {
    if (!$plan.Contains($item)) {
        throw "desktop release readiness plan is missing: $item"
    }
}

$tempDir = Join-Path $repoRoot 'target\desktop-readiness-tests'
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
$fixturePath = Join-Path $tempDir 'release-evidence.json'

$fixture = [ordered]@{
    public_release_ready = $false
    public_release_blockers = @('artifact-signature-missing', 'signing-certificate-missing')
    public_release_next_steps = @('configure-code-signing-certificate', 'run-desktop-signing-sign', 'run-public-release-gate')
    signing = [ordered]@{
        can_sign = $false
        signtool_available = $true
        signing_method = ''
        timestamp_url = 'http://timestamp.digicert.com'
        store_certificate_candidates_count = 0
        unsigned_artifacts = @('target\release\keli-desktop-shell.exe', 'target\desktop\keli-desktop-mvp-windows-x64.msi')
        sign_command_previews = @(
            [ordered]@{
                artifact = 'target\release\keli-desktop-shell.exe'
                signing_method = 'pfx'
                command = 'signtool sign /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com /f <KELI_SIGN_CERT_PATH> /p <redacted> target\release\keli-desktop-shell.exe'
            }
        )
        release_commands = [ordered]@{
            inspect = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1'
            sign = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign'
            public_release_gate = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1'
        }
    }
    smoke = [ordered]@{
        machine = [ordered]@{
            machine_takeover_status = 'ready'
        }
    }
}
$fixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $fixturePath -Encoding ASCII

$jsonOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $readinessScript -EvidencePath $fixturePath -Json
if ($LASTEXITCODE -ne 0) {
    throw "desktop-release-readiness.ps1 -Json exited with $LASTEXITCODE"
}

$report = $jsonOutput -join "`n" | ConvertFrom-Json
if ($report.public_release_ready -ne $false) {
    throw 'readiness report should preserve public_release_ready false'
}
if (($report.blockers -join ',') -ne 'artifact-signature-missing,signing-certificate-missing') {
    throw "readiness blockers mismatch: $($report.blockers -join ',')"
}
if (($report.next_steps -join ',') -ne 'configure-code-signing-certificate,run-desktop-signing-sign,run-public-release-gate') {
    throw "readiness next steps mismatch: $($report.next_steps -join ',')"
}
if ($report.signing.can_sign -ne $false) {
    throw 'readiness signing can_sign should be false'
}
if ($report.signing.signtool_available -ne $true) {
    throw 'readiness signing signtool_available should be true'
}
if ($report.signing.signing_method -ne '') {
    throw "readiness signing method mismatch: $($report.signing.signing_method)"
}
if ($report.signing.timestamp_url -ne 'http://timestamp.digicert.com') {
    throw "readiness timestamp URL mismatch: $($report.signing.timestamp_url)"
}
if ($report.signing.store_certificate_candidates_count -ne 0) {
    throw "readiness signing certificate candidate count mismatch: $($report.signing.store_certificate_candidates_count)"
}
if (($report.signing.unsigned_artifacts -join ',') -ne 'target\release\keli-desktop-shell.exe,target\desktop\keli-desktop-mvp-windows-x64.msi') {
    throw "readiness unsigned artifacts mismatch: $($report.signing.unsigned_artifacts -join ',')"
}
if ($report.signing.sign_command_previews.Count -ne 1) {
    throw "readiness signing command preview count mismatch: $($report.signing.sign_command_previews.Count)"
}
$previewCommand = [string]$report.signing.sign_command_previews[0].command
if (!$previewCommand.Contains('/f <KELI_SIGN_CERT_PATH>')) {
    throw "readiness signing command preview did not preserve redacted PFX path: $previewCommand"
}
if (!$previewCommand.Contains('/p <redacted>')) {
    throw "readiness signing command preview did not preserve redacted password: $previewCommand"
}
if ($previewCommand.Contains('secret-password')) {
    throw 'readiness signing command preview leaked a certificate password'
}
if ($report.machine_takeover_status -ne 'ready') {
    throw "readiness machine takeover status mismatch: $($report.machine_takeover_status)"
}
if ($report.commands.sign -ne 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign') {
    throw "readiness sign command mismatch: $($report.commands.sign)"
}

Write-Output 'desktop release readiness tests passed'
