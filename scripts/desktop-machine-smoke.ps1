[CmdletBinding()]
param(
    [switch]$PlanOnly,
    [switch]$IncludeMachineTakeover
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoRoot {
    $scriptDir = Split-Path -Parent $PSCommandPath
    return (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
}

function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Invoke-TextCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Command
    )

    $executable = $Command[0]
    $arguments = @()
    if ($Command.Count -gt 1) {
        $arguments = $Command[1..($Command.Count - 1)]
    }

    $output = & $executable @arguments
    [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Output = ($output -join "`n")
        Command = ($Command -join ' ')
    }
}

function Convert-JsonCommandOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Output,

        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    $trimmed = $Output.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        throw "command produced empty JSON output: $Command"
    }

    try {
        return $trimmed | ConvertFrom-Json
    } catch {
        throw "command produced invalid JSON output: $Command`n$($_.Exception.Message)"
    }
}

function Invoke-JsonCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Command
    )

    $result = Invoke-TextCommand -Command $Command
    if ($result.ExitCode -ne 0) {
        throw "command failed with exit code $($result.ExitCode): $($result.Command)"
    }
    return Convert-JsonCommandOutput -Output $result.Output -Command $result.Command
}

function Get-SystemProxySnapshot {
    $snapshot = [ordered]@{
        platform = 'Windows'
        supported = $true
        snapshot_available = $false
        proxy_enabled = $null
        proxy_server_present = $false
        proxy_override_present = $false
        auto_config_url_present = $false
        error = $null
        real_smoke = [ordered]@{
            requested = $false
            status = 'not-run'
        }
    }

    try {
        $properties = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        $proxyEnable = Get-ObjectPropertyValue -Object $properties -Name 'ProxyEnable'
        $proxyServer = Get-ObjectPropertyValue -Object $properties -Name 'ProxyServer'
        $proxyOverride = Get-ObjectPropertyValue -Object $properties -Name 'ProxyOverride'
        $autoConfigUrl = Get-ObjectPropertyValue -Object $properties -Name 'AutoConfigURL'

        $snapshot['snapshot_available'] = $true
        $snapshot['proxy_enabled'] = ($null -ne $proxyEnable -and [int]$proxyEnable -ne 0)
        $snapshot['proxy_server_present'] = ![string]::IsNullOrWhiteSpace([string]$proxyServer)
        $snapshot['proxy_override_present'] = ![string]::IsNullOrWhiteSpace([string]$proxyOverride)
        $snapshot['auto_config_url_present'] = ![string]::IsNullOrWhiteSpace([string]$autoConfigUrl)
    } catch {
        $snapshot['snapshot_available'] = $false
        $snapshot['error'] = $_.Exception.Message
    }

    return $snapshot
}

function Get-TunBackendEvidence {
    $report = Invoke-JsonCommand -Command @('cargo', 'run', '-q', '-p', 'keli-cli', '--', 'tun-backend-check', '--format', 'json')
    [ordered]@{
        status = [string]$report.status
        supported = [bool]$report.backend.supported
        backend = [string]$report.backend.backend
        platform = [string]$report.backend.platform
        driver_library_present = [bool]$report.backend.driver_library_present
        driver_api_available = [bool]$report.backend.driver_api_available
        install_required = [bool]$report.backend.install_required
        lifecycle_wired = [bool]$report.backend.lifecycle_wired
        packet_io_wired = [bool]$report.backend.packet_io_wired
        route_takeover_wired = [bool]$report.backend.route_takeover_wired
        reason = if ($null -ne $report.backend.reason) { [string]$report.backend.reason } else { $null }
    }
}

function Get-TunPreflightEvidence {
    $report = Invoke-JsonCommand -Command @('cargo', 'run', '-q', '-p', 'keli-cli', '--', 'tun-preflight', '--format', 'json')
    [ordered]@{
        status = [string]$report.status
        ready = [bool]$report.ready
        reason = if ($null -ne $report.reason) { [string]$report.reason } else { $null }
        interface_name = [string]$report.config.interface_name
        address_cidr = [string]$report.config.address_cidr
        mtu = [int]$report.config.mtu
        dns_hijack = [bool]$report.config.dns_hijack
        device_state = [string]$report.device.state
        lifecycle_available = [bool]$report.device.lifecycle_available
        packet_io_available = [bool]$report.device.packet_io_available
        running = [bool]$report.device.running
    }
}

function Get-MachineTakeoverStatus {
    param(
        [switch]$Requested
    )

    $rerunCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.ps1 -IncludeMachineTakeover'
    if (!$Requested) {
        return [ordered]@{
            requested = $false
            status = 'not-run'
            blockers = @('machine-takeover-smoke-not-run')
            rerun_command = $rerunCommand
            certification = $null
        }
    }

    $command = @('cargo', 'run', '-q', '-p', 'keli-cli', '--', 'default-core-certify', '--format', 'json', '--machine-takeover-gate')
    $result = Invoke-TextCommand -Command $command
    $certification = $null
    $blockers = @()
    $status = 'failed'

    if (![string]::IsNullOrWhiteSpace($result.Output)) {
        try {
            $certification = Convert-JsonCommandOutput -Output $result.Output -Command $result.Command
        } catch {
            $blockers += 'machine-takeover-certification-json-invalid'
        }
    } else {
        $blockers += 'machine-takeover-certification-output-empty'
    }

    if ($result.ExitCode -eq 0 -and $null -ne $certification) {
        $verdict = Get-ObjectPropertyValue -Object $certification -Name 'default_core_promotion_verdict'
        if ($verdict -eq 'machine-takeover-ready') {
            $status = 'ready'
        } else {
            $status = 'failed'
            $blockers += 'machine-takeover-not-ready'
        }
    } elseif ($result.ExitCode -ne 0) {
        $blockers += 'machine-takeover-certification-failed'
    }

    [ordered]@{
        requested = $true
        status = $status
        blockers = $blockers
        rerun_command = $rerunCommand
        certification = if ($null -ne $certification) {
            [ordered]@{
                exit_code = $result.ExitCode
                default_core_promotion_verdict = Get-ObjectPropertyValue -Object $certification -Name 'default_core_promotion_verdict'
                release_gate = Get-ObjectPropertyValue -Object $certification -Name 'release_gate'
            }
        } else {
            [ordered]@{
                exit_code = $result.ExitCode
                default_core_promotion_verdict = $null
                release_gate = $null
            }
        }
    }
}

$repoRoot = Resolve-RepoRoot
$evidenceRelativePath = 'target\desktop\keli-desktop-machine-smoke.json'
$evidencePath = Join-Path $repoRoot $evidenceRelativePath

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        Write-Output 'probe system_proxy registry_snapshot no_side_effects'
        Write-Output 'command cargo run -q -p keli-cli -- tun-backend-check --format json'
        Write-Output 'command cargo run -q -p keli-cli -- tun-preflight --format json'
        Write-Output 'optional command cargo run -q -p keli-cli -- default-core-certify --format json --machine-takeover-gate'
        Write-Output 'metadata native_core_default true'
        Write-Output 'metadata machine_takeover_requested false_by_default'
        Write-Output 'metadata public_release_blocker machine-takeover-smoke-not-run'
        Write-Output "output $evidenceRelativePath"
        return
    }

    $report = [ordered]@{
        status = 'passed'
        mode = if ($IncludeMachineTakeover) { 'machine-takeover' } else { 'safe-probe' }
        native_core_default = $true
        system_proxy = Get-SystemProxySnapshot
        tun_backend = Get-TunBackendEvidence
        tun_preflight = Get-TunPreflightEvidence
        machine_takeover = Get-MachineTakeoverStatus -Requested:$IncludeMachineTakeover
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $evidencePath) | Out-Null
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $evidencePath -Encoding ASCII
    Write-Host "Desktop machine smoke evidence written: $evidencePath"
} finally {
    Pop-Location
}
