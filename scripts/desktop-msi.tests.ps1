[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$msiScript = Join-Path $scriptDir 'desktop-msi.ps1'

if (!(Test-Path -LiteralPath $msiScript)) {
    throw "desktop-msi.ps1 was not found"
}

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $msiScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-msi.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $output -join "`n"
$expected = @(
    'input target\desktop\keli-desktop-mvp-windows-x64\keli-desktop-shell.exe',
    'input target\desktop\keli-desktop-mvp-windows-x64\README.txt',
    'input target\desktop\keli-desktop-mvp-windows-x64\keli-desktop-manifest.json',
    'msi target\desktop\keli-desktop-mvp-windows-x64.msi',
    'metadata native_core_default true',
    'metadata upgrade_code {C49D6E5F-57E0-4D2C-A479-28F7C792E2E9}',
    'shortcut ProgramMenuFolder\Keli\Keli.lnk',
    'admin_extract target\desktop-msi-admin-smoke',
    'admin_extract readme import-subscription-url-or-config',
    'admin_extract manifest manual_smoke import-subscription',
    'admin_extract support_export_smoke target\desktop\keli-desktop-msi-support-export-smoke.json',
    'admin_extract support_export_kind keli_desktop_support_bundle',
    'admin_extract support_export_desktop_dependencies true',
    'smoke target\desktop\keli-desktop-msi-smoke.json'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop MSI plan is missing: $item"
    }
}

Write-Output 'desktop MSI plan test passed'
