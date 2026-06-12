[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$statusScript = Join-Path $scriptDir 'desktop-mvp-status.ps1'

if (!(Test-Path -LiteralPath $statusScript)) {
    throw 'desktop-mvp-status.ps1 was not found'
}

$planOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $statusScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-mvp-status.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $planOutput -join "`n"
$expectedPlan = @(
    'input target\desktop\keli-desktop-release-evidence.json',
    'read native_core_default artifacts smoke.install smoke.msi smoke.machine signing public_release_blockers public_release_next_steps',
    'require workflow ids open-desktop-shell import-subscription select-node start-stop-system-proxy tun-preflight export-support-bundle',
    'output desktop_mvp_ready and public_release_ready',
    'output json when -Json is provided'
)
foreach ($item in $expectedPlan) {
    if (!$plan.Contains($item)) {
        throw "desktop MVP status plan is missing: $item"
    }
}

$tempDir = Join-Path $repoRoot 'target\desktop-mvp-status-tests'
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
    native_core_default = $true
    public_release_ready = $false
    public_release_blockers = @('artifact-signature-missing', 'signing-certificate-missing')
    public_release_next_steps = @('configure-code-signing-certificate', 'run-desktop-signing-sign', 'run-public-release-gate')
    artifacts = @(
        [ordered]@{ kind = 'desktop-shell-exe'; path = 'target\release\keli-desktop-shell.exe' },
        [ordered]@{ kind = 'portable-zip'; path = 'target\desktop\keli-desktop-mvp-windows-x64.zip' },
        [ordered]@{ kind = 'desktop-msi'; path = 'target\desktop\keli-desktop-mvp-windows-x64.msi' }
    )
    signing = [ordered]@{
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
        }
        msi = [ordered]@{
            status = 'passed'
            native_core_default = $true
            readme_subscription_import = 'subscription-url-or-config'
            manual_smoke_cases = $workflowIds
        }
        machine = [ordered]@{
            status = 'passed'
            native_core_default = $true
            machine_takeover_status = 'ready'
        }
    }
}
$fixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $fixturePath -Encoding ASCII

$jsonOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $statusScript -EvidencePath $fixturePath -Json
if ($LASTEXITCODE -ne 0) {
    throw "desktop-mvp-status.ps1 -Json exited with $LASTEXITCODE"
}

$report = $jsonOutput -join "`n" | ConvertFrom-Json
if ($report.desktop_mvp_ready -ne $true) {
    throw 'desktop MVP should be ready when all local workflow/package/machine requirements pass'
}
if ($report.public_release_ready -ne $false) {
    throw 'public release should remain blocked in the unsigned fixture'
}
if (($report.public_release_blockers -join ',') -ne 'artifact-signature-missing,signing-certificate-missing') {
    throw "public release blockers mismatch: $($report.public_release_blockers -join ',')"
}
if (($report.remaining_external_blockers -join ',') -ne 'artifact-signature-missing,signing-certificate-missing') {
    throw "external blockers mismatch: $($report.remaining_external_blockers -join ',')"
}
$requirementStatuses = @{}
foreach ($requirement in $report.requirements) {
    $requirementStatuses[[string]$requirement.id] = [string]$requirement.status
}
foreach ($id in @('native-core-default', 'package-artifacts', 'install-smoke-workflows', 'msi-smoke-workflows', 'machine-takeover')) {
    if ($requirementStatuses[$id] -ne 'ready') {
        throw "requirement $id should be ready but was $($requirementStatuses[$id])"
    }
}
if ($requirementStatuses['public-release-signing'] -ne 'blocked') {
    throw "public-release-signing should be blocked but was $($requirementStatuses['public-release-signing'])"
}

Write-Output 'desktop MVP status tests passed'
