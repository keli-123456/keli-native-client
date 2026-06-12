[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$packageScript = Join-Path $scriptDir 'desktop-package.ps1'

if (!(Test-Path -LiteralPath $packageScript)) {
    throw "desktop-package.ps1 was not found"
}

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $packageScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-package.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $output -join "`n"
$expected = @(
    'cargo build --release -p keli-desktop-shell',
    'stage target\desktop\keli-desktop-mvp-windows-x64',
    'file target\desktop\keli-desktop-mvp-windows-x64\keli-desktop-shell.exe',
    'file target\desktop\keli-desktop-mvp-windows-x64\README.txt',
    'file target\desktop\keli-desktop-mvp-windows-x64\keli-desktop-manifest.json',
    'zip target\desktop\keli-desktop-mvp-windows-x64.zip'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop package plan is missing: $item"
    }
}

Write-Output 'desktop package plan test passed'
