[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$signedReleaseScript = Join-Path $scriptDir 'desktop-signed-release.ps1'

if (!(Test-Path -LiteralPath $signedReleaseScript)) {
    throw 'desktop-signed-release.ps1 was not found'
}

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $signedReleaseScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-signed-release.ps1 -PlanOnly exited with $LASTEXITCODE"
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
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.ps1 -IncludeMachineTakeover -MachineTakeoverAttempts 2',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign',
    'rebuild portable package after exe signing',
    'rebuild MSI after signed exe is staged',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate',
    'write target\desktop\keli-desktop-signed-release.json',
    'output signed public release ready'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop signed release plan is missing: $item"
    }
}

$signCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign'
$firstSign = $plan.IndexOf($signCommand, [System.StringComparison]::Ordinal)
$secondSign = if ($firstSign -ge 0) {
    $plan.IndexOf($signCommand, $firstSign + $signCommand.Length, [System.StringComparison]::Ordinal)
} else {
    -1
}
if ($firstSign -lt 0 -or $secondSign -lt 0) {
    throw 'desktop signed release plan must include two signing passes'
}

$rebuildPackage = $plan.IndexOf('rebuild portable package after exe signing', [System.StringComparison]::Ordinal)
$rebuildMsi = $plan.IndexOf('rebuild MSI after signed exe is staged', [System.StringComparison]::Ordinal)
$publicGate = $plan.IndexOf('powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate', [System.StringComparison]::Ordinal)

if (!($firstSign -lt $rebuildPackage -and $rebuildPackage -lt $rebuildMsi -and $rebuildMsi -lt $secondSign -and $secondSign -lt $publicGate)) {
    throw 'desktop signed release plan order must sign exe before final packaging, sign final MSI, then run public gate without rebuilding'
}

Write-Output 'desktop signed release tests passed'
