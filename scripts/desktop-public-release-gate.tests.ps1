[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$gateScript = Join-Path $scriptDir 'desktop-public-release-gate.ps1'

if (!(Test-Path -LiteralPath $gateScript)) {
    throw "desktop-public-release-gate.ps1 was not found"
}

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $gateScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-public-release-gate.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $output -join "`n"
$expected = @(
    'command powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1 -IncludeMachineTakeover',
    'input target\desktop\keli-desktop-release-evidence.json',
    'config -EvidencePath optional',
    'require public_release_ready true',
    'require smoke.machine.machine_takeover_status ready',
    'require smoke.install.verified_ui_workflow_entrypoints all_manual_smoke',
    'require smoke.install.readme_subscription_import subscription-url-or-config',
    'require smoke.msi.manual_smoke_cases all_manual_smoke',
    'require smoke.msi.readme_subscription_import subscription-url-or-config',
    'require signing.can_sign true',
    'require public_release_blockers empty',
    'failure print blockers and exit nonzero',
    'failure print blockers next_steps and exit nonzero',
    'failure print signing diagnostics when available',
    'output public release gate passed'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop public release gate plan is missing: $item"
    }
}

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

$stdoutPath = Join-Path $tempDir 'gate-stdout.txt'
$stderrPath = Join-Path $tempDir 'gate-stderr.txt'
$process = Start-Process `
    -FilePath 'powershell' `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $gateScript, '-SkipGate', '-EvidencePath', $fixturePath) `
    -NoNewWindow `
    -Wait `
    -PassThru `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath
if ($process.ExitCode -eq 0) {
    throw 'desktop-public-release-gate.ps1 fixture run should fail'
}
$failureText = @(
    if (Test-Path -LiteralPath $stdoutPath) {
        Get-Content -LiteralPath $stdoutPath
    }
    if (Test-Path -LiteralPath $stderrPath) {
        Get-Content -LiteralPath $stderrPath
    }
) -join "`n"
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

Write-Output 'desktop public release gate plan test passed'
