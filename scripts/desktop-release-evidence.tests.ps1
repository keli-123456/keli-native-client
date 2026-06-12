[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$releaseScript = Join-Path $scriptDir 'desktop-release-evidence.ps1'

if (!(Test-Path -LiteralPath $releaseScript)) {
    throw "desktop-release-evidence.ps1 was not found"
}

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $releaseScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-release-evidence.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $output -join "`n"
$expected = @(
    'input target\release\keli-desktop-shell.exe',
    'input target\desktop\keli-desktop-mvp-windows-x64.zip',
    'input target\desktop\keli-desktop-mvp-windows-x64.msi',
    'input target\desktop-install-smoke\desktop-install-smoke.json',
    'input target\desktop\keli-desktop-msi-smoke.json',
    'hash sha256 exe zip msi',
    'signature authenticode exe msi',
    'metadata native_core_default true',
    'metadata public_release_ready false_when_unsigned',
    'output target\desktop\keli-desktop-release-evidence.json'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop release evidence plan is missing: $item"
    }
}

Write-Output 'desktop release evidence plan test passed'
