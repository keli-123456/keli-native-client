[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$gateScript = Join-Path $scriptDir 'desktop-mvp-gate.ps1'

if (!(Test-Path -LiteralPath $gateScript)) {
    throw "desktop-mvp-gate.ps1 was not found"
}

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $gateScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-mvp-gate.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $output -join "`n"
$expected = @(
    'cargo fmt --check',
    'git diff --check',
    'cargo test -p keli-desktop -- --test-threads=1',
    'cargo test -p keli-desktop-shell',
    'cargo check -p keli-desktop-shell',
    'cargo build --release -p keli-desktop-shell',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-package.ps1 -SkipBuild',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.ps1',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-msi.ps1',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.ps1',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-beta-rc.ps1',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.ps1 -FailOnMvpBlocked',
    'target\release\keli-desktop-shell.exe',
    'target\desktop\keli-desktop-mvp-windows-x64.zip',
    'target\desktop\keli-desktop-mvp-windows-x64.msi',
    'target\desktop\keli-desktop-msi-smoke.json',
    'target\desktop\keli-desktop-machine-smoke.json',
    'target\desktop\keli-desktop-signing.json',
    'target\desktop\keli-desktop-release-evidence.json',
    'target\desktop\keli-desktop-unsigned-beta-manifest.json',
    'target\desktop\keli-desktop-unsigned-beta-release-notes.md',
    'target\desktop-install-smoke\desktop-install-smoke.json'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop MVP gate plan is missing: $item"
    }
}

$takeoverOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $gateScript -PlanOnly -IncludeMachineTakeover
if ($LASTEXITCODE -ne 0) {
    throw "desktop-mvp-gate.ps1 -PlanOnly -IncludeMachineTakeover exited with $LASTEXITCODE"
}

$takeoverPlan = $takeoverOutput -join "`n"
$takeoverExpected = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.ps1 -IncludeMachineTakeover'
if (!$takeoverPlan.Contains($takeoverExpected)) {
    throw "desktop MVP gate takeover plan is missing: $takeoverExpected"
}
$takeoverRetryExpected = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.ps1 -IncludeMachineTakeover -MachineTakeoverAttempts 2'
if (!$takeoverPlan.Contains($takeoverRetryExpected)) {
    throw "desktop MVP gate takeover retry plan is missing: $takeoverRetryExpected"
}

Write-Output 'desktop MVP gate plan test passed'
