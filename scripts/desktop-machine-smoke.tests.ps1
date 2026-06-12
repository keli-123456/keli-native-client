[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$smokeScript = Join-Path $scriptDir 'desktop-machine-smoke.ps1'

if (!(Test-Path -LiteralPath $smokeScript)) {
    throw "desktop-machine-smoke.ps1 was not found"
}

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $smokeScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-machine-smoke.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $output -join "`n"
$expected = @(
    'probe system_proxy registry_snapshot no_side_effects',
    'command cargo run -q -p keli-cli -- tun-backend-check --format json',
    'command cargo run -q -p keli-cli -- tun-preflight --format json',
    'optional command cargo run -q -p keli-cli -- default-core-certify --format json --machine-takeover-gate',
    'config MachineTakeoverAttempts default 1',
    'config MachineTakeoverRetryDelaySeconds default 1',
    'metadata native_core_default true',
    'metadata machine_takeover_requested false_by_default',
    'metadata machine_takeover_attempts',
    'metadata machine_takeover_max_attempts',
    'metadata machine_takeover_retry_delay_seconds',
    'metadata machine_takeover_attempt_history',
    'metadata public_release_blocker machine-takeover-smoke-not-run',
    'failure machine_takeover_not_ready exits_nonzero_when_requested',
    'output target\desktop\keli-desktop-machine-smoke.json'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop machine smoke plan is missing: $item"
    }
}

Write-Output 'desktop machine smoke plan test passed'
