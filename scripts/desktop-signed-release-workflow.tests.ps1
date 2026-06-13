[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$workflowPath = Join-Path $repoRoot '.github\workflows\windows-signed-public-release.yml'

if (!(Test-Path -LiteralPath $workflowPath -PathType Leaf)) {
    throw 'windows signed public release workflow was not found'
}

$workflow = Get-Content -Raw -LiteralPath $workflowPath
$expected = @(
    'name: Windows Signed Public Release',
    'workflow_dispatch:',
    'KELI_SIGN_CERT_PFX_BASE64',
    'KELI_SIGN_CERT_PASSWORD',
    'KELI_SIGN_CERT_PATH',
    '.\scripts\desktop-signed-release.ps1',
    'target/desktop/keli-desktop-mvp-windows-x64.zip',
    'target/desktop/keli-desktop-mvp-windows-x64.msi',
    'target/desktop/keli-desktop-release-evidence.json',
    'target/desktop/keli-desktop-signing.json',
    'target/desktop/keli-desktop-signed-release.json',
    'target/desktop/SHA256SUMS',
    'Remove-Item -LiteralPath $env:KELI_SIGN_CERT_PATH -Force'
)

foreach ($item in $expected) {
    if (!$workflow.Contains($item)) {
        throw "windows signed public release workflow is missing: $item"
    }
}

Write-Output 'desktop signed release workflow tests passed'
