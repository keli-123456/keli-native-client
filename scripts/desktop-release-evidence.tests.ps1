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
    'input target\desktop\keli-desktop-machine-smoke.json',
    'input target\desktop\keli-desktop-signing.json',
    'hash sha256 exe zip msi',
    'signature authenticode exe msi',
    'metadata native_core_default true',
    'metadata install_smoke_ui_workflow_entrypoints',
    'metadata install_smoke_readme_subscription_import',
    'metadata msi_smoke_manual_smoke_cases',
    'metadata msi_smoke_readme_subscription_import',
    'metadata public_release_ready false_when_unsigned',
    'metadata public_release_ready false_when_machine_takeover_missing',
    'metadata public_release_ready false_when_signing_missing',
    'metadata signing_store_certificate_candidates_count',
    'metadata signing_operator_next_steps',
    'metadata signing_release_commands',
    'metadata signing_status',
    'metadata signing_method',
    'metadata signing_timestamp_url',
    'metadata signing_unsigned_artifacts',
    'metadata signing_verification_failures',
    'metadata signing_certificate_subject_match_count',
    'metadata signing_command_previews',
    'metadata public_release_next_steps',
    'output target\desktop\keli-desktop-release-evidence.json'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop release evidence plan is missing: $item"
    }
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$signingPath = Join-Path $repoRoot 'target\desktop\keli-desktop-signing.json'
$backupSigningPath = Join-Path $repoRoot 'target\desktop-release-evidence-tests\keli-desktop-signing.backup.json'
$backupDir = Split-Path -Parent $backupSigningPath
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
if (!(Test-Path -LiteralPath $signingPath)) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $scriptDir 'desktop-signing.ps1')
    if ($LASTEXITCODE -ne 0) {
        throw "desktop-signing.ps1 setup exited with $LASTEXITCODE"
    }
}
Copy-Item -LiteralPath $signingPath -Destination $backupSigningPath -Force
try {
    $failedSigning = Get-Content -Raw -LiteralPath $signingPath | ConvertFrom-Json
    $failedSigning.status = 'failed'
    $failedSigning.mode = 'sign'
    $failedSigning.sign_verification_failures = @(
        'target\release\keli-desktop-shell.exe',
        'target\desktop\keli-desktop-mvp-windows-x64.msi'
    )
    $failedSigning | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $signingPath -Encoding ASCII

    & powershell -NoProfile -ExecutionPolicy Bypass -File $releaseScript
    if ($LASTEXITCODE -ne 0) {
        throw "desktop-release-evidence.ps1 failed signing fixture exited with $LASTEXITCODE"
    }

    $releaseEvidencePath = Join-Path $repoRoot 'target\desktop\keli-desktop-release-evidence.json'
    $releaseEvidence = Get-Content -Raw -LiteralPath $releaseEvidencePath | ConvertFrom-Json
    if ($releaseEvidence.signing.status -ne 'failed') {
        throw "release evidence signing status mismatch: $($releaseEvidence.signing.status)"
    }
    if ($releaseEvidence.signing.sign_verification_failures.Count -ne 2) {
        throw "release evidence signing verification failure count mismatch: $($releaseEvidence.signing.sign_verification_failures.Count)"
    }
    if (($releaseEvidence.public_release_blockers -join ',') -notlike '*sign-verification-failed*') {
        throw "release evidence blockers missing sign-verification-failed: $($releaseEvidence.public_release_blockers -join ',')"
    }
} finally {
    Copy-Item -LiteralPath $backupSigningPath -Destination $signingPath -Force
}

& powershell -NoProfile -ExecutionPolicy Bypass -File $releaseScript
if ($LASTEXITCODE -ne 0) {
    throw "desktop-release-evidence.ps1 clean signing fixture exited with $LASTEXITCODE"
}
$cleanReleaseEvidencePath = Join-Path $repoRoot 'target\desktop\keli-desktop-release-evidence.json'
$cleanReleaseEvidence = Get-Content -Raw -LiteralPath $cleanReleaseEvidencePath | ConvertFrom-Json
if ($cleanReleaseEvidence.signing.sign_verification_failures.Count -ne 0) {
    throw "clean release evidence verification failures should be an empty array, got $($cleanReleaseEvidence.signing.sign_verification_failures)"
}

Write-Output 'desktop release evidence plan test passed'
