[CmdletBinding()]
param(
    [switch]$PlanOnly,
    [switch]$IncludeMachineTakeover,
    [int]$MachineTakeoverAttempts = 1,
    [int]$MachineTakeoverRetryDelaySeconds = 1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($MachineTakeoverAttempts -lt 1) {
    throw 'MachineTakeoverAttempts must be at least 1'
}
if ($MachineTakeoverRetryDelaySeconds -lt 0) {
    throw 'MachineTakeoverRetryDelaySeconds must be at least 0'
}

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

function Invoke-MachineTakeoverCertificationAttempt {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Attempt
    )

    $command = @('cargo', 'run', '-q', '-p', 'keli-cli', '--', 'default-core-certify', '--format', 'json', '--machine-takeover-gate')
    $result = Invoke-TextCommand -Command $command
    $certification = $null
    $parseError = $null
    $outputEmpty = [string]::IsNullOrWhiteSpace($result.Output)

    if (!$outputEmpty) {
        try {
            $certification = Convert-JsonCommandOutput -Output $result.Output -Command $result.Command
        } catch {
            $parseError = $_.Exception.Message
        }
    }

    [ordered]@{
        attempt = $Attempt
        exit_code = $result.ExitCode
        command = $result.Command
        output_empty = $outputEmpty
        parse_error = $parseError
        certification = $certification
    }
}

function Get-MachineTakeoverAttemptReleaseGate {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Attempt
    )

    $certification = $Attempt['certification']
    if ($null -eq $certification) {
        return $null
    }
    return Get-ObjectPropertyValue -Object $certification -Name 'release_gate'
}

function Get-MachineTakeoverAttemptReady {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Attempt
    )

    if ($Attempt['exit_code'] -ne 0) {
        return $false
    }
    $releaseGate = Get-MachineTakeoverAttemptReleaseGate -Attempt $Attempt
    if ($null -eq $releaseGate) {
        return $false
    }
    $gateReady = Get-ObjectPropertyValue -Object $releaseGate -Name 'machine_takeover_ready'
    $takeover = Get-ObjectPropertyValue -Object $releaseGate -Name 'takeover'
    $takeoverReady = if ($null -ne $takeover) { Get-ObjectPropertyValue -Object $takeover -Name 'ready' } else { $null }
    return ($gateReady -eq $true -or $takeoverReady -eq $true)
}

function Get-MachineTakeoverAttemptBlockers {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Attempt
    )

    $blockers = @()
    if ($Attempt['output_empty']) {
        $blockers += 'machine-takeover-certification-output-empty'
    }
    if (![string]::IsNullOrWhiteSpace([string]$Attempt['parse_error'])) {
        $blockers += 'machine-takeover-certification-json-invalid'
    }
    if ($Attempt['exit_code'] -ne 0) {
        $blockers += 'machine-takeover-certification-failed'
    }

    $releaseGate = Get-MachineTakeoverAttemptReleaseGate -Attempt $Attempt
    if ($null -ne $releaseGate) {
        $releaseGateBlockers = Get-ObjectPropertyValue -Object $releaseGate -Name 'blockers'
        if ($null -ne $releaseGateBlockers) {
            foreach ($blocker in $releaseGateBlockers) {
                $blockers += [string]$blocker
            }
        }
    }

    if (!(Get-MachineTakeoverAttemptReady -Attempt $Attempt) -and $blockers.Count -eq 0) {
        $blockers += 'machine-takeover-not-ready'
    }

    return @($blockers | Select-Object -Unique)
}

function Convert-MachineTakeoverAttemptEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Attempt
    )

    $releaseGate = Get-MachineTakeoverAttemptReleaseGate -Attempt $Attempt
    $ready = Get-MachineTakeoverAttemptReady -Attempt $Attempt
    $blockers = Get-MachineTakeoverAttemptBlockers -Attempt $Attempt

    [ordered]@{
        attempt = [int]$Attempt['attempt']
        exit_code = [int]$Attempt['exit_code']
        ready = [bool]$ready
        status = if ($ready) { 'ready' } else { 'failed' }
        blockers = $blockers
        release_gate_status = if ($null -ne $releaseGate) { [string](Get-ObjectPropertyValue -Object $releaseGate -Name 'status') } else { $null }
    }
}

function Get-MachineTakeoverStatus {
    param(
        [switch]$Requested,
        [Parameter(Mandatory = $true)]
        [int]$MaxAttempts,
        [Parameter(Mandatory = $true)]
        [int]$RetryDelaySeconds
    )

    $rerunCommand = "powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.ps1 -IncludeMachineTakeover -MachineTakeoverAttempts $MaxAttempts"
    if (!$Requested) {
        return [ordered]@{
            requested = $false
            status = 'not-run'
            attempts = 0
            max_attempts = $MaxAttempts
            retry_delay_seconds = $RetryDelaySeconds
            attempt_history = @()
            blockers = @('machine-takeover-smoke-not-run')
            rerun_command = $rerunCommand
            certification = $null
        }
    }

    $attempts = @()
    for ($attemptNumber = 1; $attemptNumber -le $MaxAttempts; $attemptNumber++) {
        $attempt = Invoke-MachineTakeoverCertificationAttempt -Attempt $attemptNumber
        $attempts += $attempt
        if (Get-MachineTakeoverAttemptReady -Attempt $attempt) {
            break
        }
        if ($attemptNumber -lt $MaxAttempts -and $RetryDelaySeconds -gt 0) {
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }

    $readyAttempts = @($attempts | Where-Object { Get-MachineTakeoverAttemptReady -Attempt $_ })
    $selectedAttempt = if ($readyAttempts.Count -gt 0) { $readyAttempts[0] } else { $attempts[-1] }
    $certification = $selectedAttempt['certification']
    $blockers = if ($readyAttempts.Count -gt 0) { @() } else { Get-MachineTakeoverAttemptBlockers -Attempt $selectedAttempt }
    $status = if ($readyAttempts.Count -gt 0) { 'ready' } else { 'failed' }
    $verdict = $null

    if ($status -eq 'ready' -and $null -ne $certification) {
        $verdict = Get-ObjectPropertyValue -Object $certification -Name 'default_core_promotion_verdict'
        if ($null -eq $verdict) {
            $verdict = 'machine-takeover-ready'
        }
    }

    [ordered]@{
        requested = $true
        status = $status
        attempts = $attempts.Count
        max_attempts = $MaxAttempts
        retry_delay_seconds = $RetryDelaySeconds
        attempt_history = @($attempts | ForEach-Object { Convert-MachineTakeoverAttemptEvidence -Attempt $_ })
        blockers = $blockers
        rerun_command = $rerunCommand
        certification = if ($null -ne $certification) {
            [ordered]@{
                exit_code = $selectedAttempt['exit_code']
                default_core_promotion_verdict = $verdict
                release_gate = Get-ObjectPropertyValue -Object $certification -Name 'release_gate'
            }
        } else {
            [ordered]@{
                exit_code = $selectedAttempt['exit_code']
                default_core_promotion_verdict = $null
                release_gate = $null
            }
        }
    }
}

function Read-ExistingMachineTakeoverEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EvidencePath
    )

    if (!(Test-Path -LiteralPath $EvidencePath -PathType Leaf)) {
        return $null
    }

    try {
        $existing = Get-Content -Raw -LiteralPath $EvidencePath | ConvertFrom-Json
    } catch {
        return $null
    }

    if ($null -eq $existing.PSObject.Properties['machine_takeover']) {
        return $null
    }

    if ([string]$existing.machine_takeover.status -ne 'ready') {
        return $null
    }

    return $existing.machine_takeover
}

function Get-PreservedMachineTakeoverStatus {
    param(
        [AllowNull()]
        [object]$ExistingMachineTakeover,

        [Parameter(Mandatory = $true)]
        [int]$MaxAttempts,

        [Parameter(Mandatory = $true)]
        [int]$RetryDelaySeconds
    )

    if ($null -eq $ExistingMachineTakeover) {
        return Get-MachineTakeoverStatus `
            -Requested:$false `
            -MaxAttempts $MaxAttempts `
            -RetryDelaySeconds $RetryDelaySeconds
    }

    $preserved = [ordered]@{}
    foreach ($property in $ExistingMachineTakeover.PSObject.Properties) {
        $preserved[$property.Name] = $property.Value
    }
    $preserved['preserved_from_previous_ready_evidence'] = $true
    $preserved['preserved_by_mode'] = 'safe-probe'
    return $preserved
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
        Write-Output 'config MachineTakeoverAttempts default 1'
        Write-Output 'config MachineTakeoverRetryDelaySeconds default 1'
        Write-Output 'metadata native_core_default true'
        Write-Output 'metadata machine_takeover_requested false_by_default'
        Write-Output 'metadata machine_takeover_attempts'
        Write-Output 'metadata machine_takeover_max_attempts'
        Write-Output 'metadata machine_takeover_retry_delay_seconds'
        Write-Output 'metadata machine_takeover_attempt_history'
        Write-Output 'metadata machine_takeover_ready_evidence_preserved_on_safe_probe'
        Write-Output 'metadata public_release_blocker machine-takeover-smoke-not-run'
        Write-Output 'failure machine_takeover_not_ready exits_nonzero_when_requested'
        Write-Output "output $evidenceRelativePath"
        return
    }

    $existingMachineTakeover = if ($IncludeMachineTakeover) {
        $null
    } else {
        Read-ExistingMachineTakeoverEvidence -EvidencePath $evidencePath
    }
    $machineTakeover = if ($IncludeMachineTakeover) {
        Get-MachineTakeoverStatus `
            -Requested:$true `
            -MaxAttempts $MachineTakeoverAttempts `
            -RetryDelaySeconds $MachineTakeoverRetryDelaySeconds
    } else {
        Get-PreservedMachineTakeoverStatus `
            -ExistingMachineTakeover $existingMachineTakeover `
            -MaxAttempts $MachineTakeoverAttempts `
            -RetryDelaySeconds $MachineTakeoverRetryDelaySeconds
    }

    $report = [ordered]@{
        status = 'passed'
        mode = if ($IncludeMachineTakeover) { 'machine-takeover' } else { 'safe-probe' }
        native_core_default = $true
        system_proxy = Get-SystemProxySnapshot
        tun_backend = Get-TunBackendEvidence
        tun_preflight = Get-TunPreflightEvidence
        machine_takeover = $machineTakeover
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $evidencePath) | Out-Null
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $evidencePath -Encoding ASCII
    Write-Host "Desktop machine smoke evidence written: $evidencePath"
    if ($IncludeMachineTakeover -and $report.machine_takeover.status -ne 'ready') {
        $blockers = $report.machine_takeover.blockers -join ','
        throw "Desktop machine takeover smoke failed: status=$($report.machine_takeover.status) blockers=$blockers"
    }
} finally {
    Pop-Location
}
