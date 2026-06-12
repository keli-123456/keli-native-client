[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$smokeScript = Join-Path $scriptDir 'desktop-install-smoke.ps1'

if (!(Test-Path -LiteralPath $smokeScript)) {
    throw "desktop-install-smoke.ps1 was not found"
}

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $smokeScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-install-smoke.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $output -join "`n"
$expected = @(
    'input target\desktop\keli-desktop-mvp-windows-x64.zip',
    'install target\desktop-install-smoke\Keli',
    'check target\desktop-install-smoke\Keli\keli-desktop-shell.exe',
    'check target\desktop-install-smoke\Keli\README.txt',
    'readme manual_smoke import-subscription-url-or-config',
    'check target\desktop-install-smoke\Keli\keli-desktop-manifest.json',
    'run target\desktop-install-smoke\Keli\keli-desktop-shell.exe --smoke',
    'manifest native_core_default true',
    'manifest manual_smoke import-subscription',
    'launch_smoke ui_workflow_entrypoint open-desktop-shell',
    'launch_smoke ui_workflow_entrypoint import-subscription',
    'launch_smoke ui_workflow_entrypoint select-node',
    'launch_smoke ui_workflow_entrypoint start-stop-system-proxy',
    'launch_smoke ui_workflow_entrypoint tun-preflight',
    'launch_smoke ui_workflow_entrypoint export-support-bundle',
    'launch_smoke first_run_dependency_blockers',
    'launch_smoke dependency_action_entrypoint install-wintun',
    'result target\desktop-install-smoke\desktop-shell-launch-smoke.json',
    'result target\desktop-install-smoke\desktop-install-smoke.json'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop install smoke plan is missing: $item"
    }
}

Write-Output 'desktop install smoke plan test passed'
