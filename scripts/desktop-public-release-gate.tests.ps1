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
    'output public release gate passed'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop public release gate plan is missing: $item"
    }
}

Write-Output 'desktop public release gate plan test passed'
