[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$signingScript = Join-Path $scriptDir 'desktop-signing.ps1'

if (!(Test-Path -LiteralPath $signingScript)) {
    throw "desktop-signing.ps1 was not found"
}

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $signingScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-signing.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $output -join "`n"
$expected = @(
    'input target\release\keli-desktop-shell.exe',
    'input target\desktop\keli-desktop-mvp-windows-x64.msi',
    'discover signtool.exe',
    'config KELI_SIGNTOOL_PATH optional',
    'config KELI_SIGN_CERT_PATH optional_pfx',
    'config KELI_SIGN_CERT_SUBJECT optional_store_subject',
    'config KELI_SIGN_CERT_PASSWORD optional_secret',
    'config KELI_SIGN_TIMESTAMP_URL default http://timestamp.digicert.com',
    'mode inspect default',
    'mode sign requires -Sign',
    'metadata public_release_blocker artifact-signature-missing',
    'metadata public_release_blocker signing-certificate-missing',
    'output target\desktop\keli-desktop-signing.json'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop signing plan is missing: $item"
    }
}

Write-Output 'desktop signing plan test passed'
