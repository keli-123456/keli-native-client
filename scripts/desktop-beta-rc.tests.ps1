[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
    'allow public_release_blockers artifact-signature-missing signing-certificate-missing machine-takeover-smoke-not-run only',
    'include smoke_evidence running_support_smoke',
    'include verification command scripts\desktop-beta-rc-audit.ps1',
    'write target\desktop\keli-desktop-unsigned-beta-manifest.json',
    'write target\desktop\keli-desktop-unsigned-beta-release-notes.md',
    'output unsigned beta rc ready'
)
foreach ($item in $expectedPlan) {
    if (!$plan.Contains($item)) {
        throw "desktop beta RC plan is missing: $item"
    }
}

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
        [ordered]@{
            kind = 'desktop-shell-exe'
            path = 'target\release\keli-desktop-shell.exe'
            bytes = 100
            sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            signature = [ordered]@{
                signed = $false
                status = 'NotSigned'
            }
        },
        [ordered]@{
            kind = 'portable-zip'
            path = 'target\desktop\keli-desktop-mvp-windows-x64.zip'
            bytes = 200
            sha256 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        },
        [ordered]@{
            kind = 'desktop-msi'
            path = 'target\desktop\keli-desktop-mvp-windows-x64.msi'
            bytes = 300
            sha256 = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
            signature = [ordered]@{
                signed = $false
                status = 'NotSigned'
            }
        }
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
            first_run_blockers = @(
                [ordered]@{
                    code = 'wintun-missing'
                    message = 'Wintun library was not found'
                    action = 'install-wintun'
                }
            )
            dependency_action_entrypoints = @('install-wintun')
            support_export_smoke = 'target\desktop-install-smoke\desktop-support-export-smoke.json'
            support_export_kind = 'keli_desktop_support_bundle'
            support_export_desktop_dependencies = $true
            running_support_smoke = 'target\desktop-install-smoke\desktop-startup-connect-support-smoke.json'
            running_support_desktop_status_running = $true
            running_support_desktop_status_selected = $true
            running_support_managed_status_selected = $true
            running_support_diagnosis_selected = $true
            running_support_redaction_ready = $true
            running_support_stopped_after_smoke = $true
        }
        msi = [ordered]@{
            status = 'passed'
            native_core_default = $true
            readme_subscription_import = 'subscription-url-or-config'
            manual_smoke_cases = $workflowIds
            support_export_smoke = 'target\desktop\keli-desktop-msi-support-export-smoke.json'
            support_export_kind = 'keli_desktop_support_bundle'
            support_export_desktop_dependencies = $true
            running_support_smoke = 'target\desktop\keli-desktop-msi-startup-connect-support-smoke.json'
            running_support_desktop_status_running = $true
            running_support_desktop_status_selected = $true
            running_support_managed_status_selected = $true
            running_support_diagnosis_selected = $true
            running_support_redaction_ready = $true
            running_support_stopped_after_smoke = $true
        }
        machine = [ordered]@{
            status = 'passed'
            native_core_default = $true
            machine_takeover_status = 'ready'
        }
    }
}
$fixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $fixturePath -Encoding ASCII

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $betaScript -EvidencePath $fixturePath -ManifestPath $manifestPath -ReleaseNotesPath $notesPath
if ($LASTEXITCODE -ne 0) {
    throw "desktop-beta-rc.ps1 fixture exited with $LASTEXITCODE"
}
$text = $output -join "`n"
foreach ($item in @(
    'unsigned_beta_rc_ready true',
    'version 0.1.425',
    'channel unsigned-beta',
    'allowed_public_release_blockers artifact-signature-missing,signing-certificate-missing,machine-takeover-smoke-not-run'
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
if ($manifest.channel -ne 'unsigned-beta') {
    throw "manifest channel mismatch: $($manifest.channel)"
}
if ($manifest.version -ne '0.1.425') {
    throw "manifest version mismatch: $($manifest.version)"
}
if ($manifest.unsigned -ne $true) {
    throw 'manifest unsigned must be true'
}
if (($manifest.allowed_public_release_blockers -join ',') -ne 'artifact-signature-missing,signing-certificate-missing,machine-takeover-smoke-not-run') {
    throw "manifest allowed blockers mismatch: $($manifest.allowed_public_release_blockers -join ',')"
}
if ($manifest.artifacts.Count -ne 3) {
    throw "manifest artifact count mismatch: $($manifest.artifacts.Count)"
}
if (($manifest.verification_commands -join "`n") -notlike '*scripts\desktop-beta-rc.ps1*') {
    throw 'manifest verification commands must include beta RC gate'
}
if (($manifest.verification_commands -join "`n") -notlike '*scripts\desktop-beta-rc-audit.ps1*') {
    throw 'manifest verification commands must include beta RC audit'
}
if ($manifest.smoke_evidence.install.running_support_smoke -ne 'target\desktop-install-smoke\desktop-startup-connect-support-smoke.json') {
    throw "manifest install running support smoke mismatch: $($manifest.smoke_evidence.install.running_support_smoke)"
}
if ($manifest.smoke_evidence.msi.running_support_smoke -ne 'target\desktop\keli-desktop-msi-startup-connect-support-smoke.json') {
    throw "manifest MSI running support smoke mismatch: $($manifest.smoke_evidence.msi.running_support_smoke)"
}

$notes = Get-Content -Raw -LiteralPath $notesPath
foreach ($item in @(
    '# Keli Desktop Unsigned Beta RC 0.1.425',
    'This is an unsigned Beta build for testing.',
    'Windows may show SmartScreen or publisher warnings.',
    'Verify SHA256 hashes before running artifacts.',
    'scripts\desktop-beta-rc.ps1',
    'scripts\desktop-beta-rc-audit.ps1',
    'Support bundles'
)) {
if (!$notes.Contains($item)) {
        throw "desktop beta RC release notes missing: $item"
    }
}

$safeProbeFixturePath = Join-Path $tempDir 'release-evidence-safe-probe-machine-not-run.json'
$safeProbeManifestPath = Join-Path $tempDir 'keli-desktop-safe-probe-unsigned-beta-manifest.json'
$safeProbeNotesPath = Join-Path $tempDir 'keli-desktop-safe-probe-unsigned-beta-release-notes.md'
$safeProbeFixture = Get-Content -Raw -LiteralPath $fixturePath | ConvertFrom-Json
$safeProbeFixture.public_release_blockers = @('artifact-signature-missing', 'signing-certificate-missing', 'machine-takeover-smoke-not-run')
$safeProbeFixture.smoke.machine = [pscustomobject][ordered]@{
    status = 'passed'
    native_core_default = $true
    machine_takeover_status = 'not-run'
    blockers = @('machine-takeover-smoke-not-run')
}
$safeProbeFixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $safeProbeFixturePath -Encoding ASCII

$safeProbeOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $betaScript -EvidencePath $safeProbeFixturePath -ManifestPath $safeProbeManifestPath -ReleaseNotesPath $safeProbeNotesPath
if ($LASTEXITCODE -ne 0) {
    throw "desktop-beta-rc.ps1 safe-probe fixture exited with $LASTEXITCODE"
}
$safeProbeText = $safeProbeOutput -join "`n"
if (!$safeProbeText.Contains('allowed_public_release_blockers artifact-signature-missing,signing-certificate-missing,machine-takeover-smoke-not-run')) {
    throw "safe-probe beta RC output missing machine-takeover-smoke-not-run allowance: $safeProbeText"
}
$safeProbeManifest = Get-Content -Raw -LiteralPath $safeProbeManifestPath | ConvertFrom-Json
if (($safeProbeManifest.allowed_public_release_blockers -join ',') -ne 'artifact-signature-missing,signing-certificate-missing,machine-takeover-smoke-not-run') {
    throw "safe-probe manifest allowed blockers mismatch: $($safeProbeManifest.allowed_public_release_blockers -join ',')"
}

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
    if (Test-Path -LiteralPath $stdoutPath) {
        Get-Content -LiteralPath $stdoutPath
    }
    if (Test-Path -LiteralPath $stderrPath) {
        Get-Content -LiteralPath $stderrPath
    }
) -join "`n"
if (!$failureText.Contains('Desktop unsigned beta RC blocked: machine-takeover-smoke-not-ready')) {
    throw "extra blocker failure did not name machine-takeover-smoke-not-ready: $failureText"
}

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
    if (Test-Path -LiteralPath $mvpStdoutPath) {
        Get-Content -LiteralPath $mvpStdoutPath
    }
    if (Test-Path -LiteralPath $mvpStderrPath) {
        Get-Content -LiteralPath $mvpStderrPath
    }
) -join "`n"
if (!$mvpFailureText.Contains('Desktop unsigned beta RC blocked: desktop-mvp-not-ready msi-support-bundle-export')) {
    throw "MVP blocked failure did not name concrete blocked requirement: $mvpFailureText"
}

Write-Output 'desktop beta RC tests passed'
