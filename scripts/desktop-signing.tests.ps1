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
    'discover certificate_store_code_signing_candidates',
    'config -SkipCertificateStoreDiscovery deterministic_tests',
    'mode inspect default',
    'mode sign requires -Sign',
    'metadata public_release_blocker artifact-signature-missing',
    'metadata public_release_blocker signing-certificate-missing',
    'metadata operator_next_steps',
    'metadata release_commands',
    'output target\desktop\keli-desktop-signing.json'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop signing plan is missing: $item"
    }
}

& powershell -NoProfile -ExecutionPolicy Bypass -File $signingScript -SignToolPath ' ' -CertificatePath ' ' -CertificatePassword ' ' -CertificateSubject ' ' -SkipCertificateStoreDiscovery
if ($LASTEXITCODE -ne 0) {
    throw "desktop-signing.ps1 inspect exited with $LASTEXITCODE"
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$evidencePath = Join-Path $repoRoot 'target\desktop\keli-desktop-signing.json'
$evidence = Get-Content -Raw -LiteralPath $evidencePath | ConvertFrom-Json

if ($evidence.configuration.store_certificate_discovery.enabled -ne $false) {
    throw 'expected certificate-store discovery to be disabled for deterministic test'
}
if ($evidence.configuration.store_certificate_candidates_count -ne 0) {
    throw 'expected no certificate candidates when discovery is skipped'
}
$nextStepIds = @($evidence.operator_next_steps | ForEach-Object { [string]$_.id })
foreach ($id in @('configure-code-signing-certificate', 'run-desktop-signing-sign', 'run-public-release-gate')) {
    if ($nextStepIds -notcontains $id) {
        throw "signing evidence is missing operator next step: $id"
    }
}
if ([string]$evidence.release_commands.sign -ne 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign') {
    throw 'signing evidence sign command mismatch'
}

Write-Output 'desktop signing plan test passed'
