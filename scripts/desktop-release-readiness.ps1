[CmdletBinding()]
param(
    [string]$EvidencePath,
    [switch]$Json,
    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoRoot {
    $scriptDir = Split-Path -Parent $PSCommandPath
    return (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
}

function Require-File {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "required desktop release evidence is missing: $Path"
    }
}

function Test-JsonProperty {
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($null -ne $InputObject -and $null -ne $InputObject.PSObject.Properties[$Name])
}

function Get-StringArrayProperty {
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (!(Test-JsonProperty -InputObject $InputObject -Name $Name)) {
        return @()
    }

    return @($InputObject.$Name | ForEach-Object { [string]$_ } | Where-Object { ![string]::IsNullOrWhiteSpace($_) })
}

function Get-BoolProperty {
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [bool]$Default = $false
    )

    if (!(Test-JsonProperty -InputObject $InputObject -Name $Name)) {
        return $Default
    }
    return [bool]$InputObject.$Name
}

function Get-IntProperty {
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [int]$Default = 0
    )

    if (!(Test-JsonProperty -InputObject $InputObject -Name $Name)) {
        return $Default
    }
    return [int]$InputObject.$Name
}

function Get-StringProperty {
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [string]$Default = ''
    )

    if (!(Test-JsonProperty -InputObject $InputObject -Name $Name)) {
        return $Default
    }
    return [string]$InputObject.$Name
}

function Get-SignCommandPreviewsProperty {
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (!(Test-JsonProperty -InputObject $InputObject -Name $Name)) {
        return @()
    }

    return @($InputObject.$Name | ForEach-Object {
        [ordered]@{
            artifact = Get-StringProperty -InputObject $_ -Name 'artifact'
            signing_method = Get-StringProperty -InputObject $_ -Name 'signing_method'
            command = Get-StringProperty -InputObject $_ -Name 'command'
        }
    })
}

function Get-FirstRunBlockersProperty {
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (!(Test-JsonProperty -InputObject $InputObject -Name $Name)) {
        return @()
    }

    return @($InputObject.$Name | ForEach-Object {
        [ordered]@{
            code = Get-StringProperty -InputObject $_ -Name 'code'
            message = Get-StringProperty -InputObject $_ -Name 'message'
            action = Get-StringProperty -InputObject $_ -Name 'action'
        }
    })
}

function Get-ReleaseCommands {
    param(
        [AllowNull()]
        [object]$Signing
    )

    $defaults = [ordered]@{
        inspect = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1'
        sign = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign'
        public_release_gate = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1'
    }

    if (!(Test-JsonProperty -InputObject $Signing -Name 'release_commands')) {
        return $defaults
    }

    $commands = $Signing.release_commands
    foreach ($name in @('inspect', 'sign', 'public_release_gate')) {
        if ((Test-JsonProperty -InputObject $commands -Name $name) -and ![string]::IsNullOrWhiteSpace([string]$commands.$name)) {
            $defaults[$name] = [string]$commands.$name
        }
    }
    return $defaults
}

function New-ReadinessReport {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Evidence
    )

    $signing = if (Test-JsonProperty -InputObject $Evidence -Name 'signing') { $Evidence.signing } else { $null }
    $smoke = if (Test-JsonProperty -InputObject $Evidence -Name 'smoke') { $Evidence.smoke } else { $null }
    $install = if (Test-JsonProperty -InputObject $smoke -Name 'install') { $smoke.install } else { $null }
    $msi = if (Test-JsonProperty -InputObject $smoke -Name 'msi') { $smoke.msi } else { $null }
    $machine = if (Test-JsonProperty -InputObject $smoke -Name 'machine') { $smoke.machine } else { $null }
    $commands = Get-ReleaseCommands -Signing $signing

    [ordered]@{
        public_release_ready = Get-BoolProperty -InputObject $Evidence -Name 'public_release_ready'
        blockers = Get-StringArrayProperty -InputObject $Evidence -Name 'public_release_blockers'
        next_steps = Get-StringArrayProperty -InputObject $Evidence -Name 'public_release_next_steps'
        machine_takeover_status = Get-StringProperty -InputObject $machine -Name 'machine_takeover_status' -Default 'unknown'
        install_first_run = [ordered]@{
            system_proxy_ready = Get-BoolProperty -InputObject $install -Name 'first_run_system_proxy_ready'
            tun_ready = Get-BoolProperty -InputObject $install -Name 'first_run_tun_ready'
            blockers = @(Get-FirstRunBlockersProperty -InputObject $install -Name 'first_run_blockers')
            dependency_action_entrypoints = @(Get-StringArrayProperty -InputObject $install -Name 'dependency_action_entrypoints')
        }
        support_export = [ordered]@{
            smoke = Get-StringProperty -InputObject $install -Name 'support_export_smoke'
            path = Get-StringProperty -InputObject $install -Name 'support_export_path'
            kind = Get-StringProperty -InputObject $install -Name 'support_export_kind'
            desktop_dependencies = Get-BoolProperty -InputObject $install -Name 'support_export_desktop_dependencies'
        }
        msi_support_export = [ordered]@{
            smoke = Get-StringProperty -InputObject $msi -Name 'support_export_smoke'
            path = Get-StringProperty -InputObject $msi -Name 'support_export_path'
            kind = Get-StringProperty -InputObject $msi -Name 'support_export_kind'
            desktop_dependencies = Get-BoolProperty -InputObject $msi -Name 'support_export_desktop_dependencies'
        }
        signing = [ordered]@{
            status = Get-StringProperty -InputObject $signing -Name 'status'
            mode = Get-StringProperty -InputObject $signing -Name 'mode'
            can_sign = Get-BoolProperty -InputObject $signing -Name 'can_sign'
            signtool_available = Get-BoolProperty -InputObject $signing -Name 'signtool_available'
            signing_method = Get-StringProperty -InputObject $signing -Name 'signing_method'
            timestamp_url = Get-StringProperty -InputObject $signing -Name 'timestamp_url'
            store_certificate_candidates_count = Get-IntProperty -InputObject $signing -Name 'store_certificate_candidates_count'
            certificate_subject_match_count = Get-IntProperty -InputObject $signing -Name 'certificate_subject_match_count'
            unsigned_artifacts = Get-StringArrayProperty -InputObject $signing -Name 'unsigned_artifacts'
            sign_verification_failures = @(Get-StringArrayProperty -InputObject $signing -Name 'sign_verification_failures')
            sign_command_previews = @(Get-SignCommandPreviewsProperty -InputObject $signing -Name 'sign_command_previews')
        }
        commands = $commands
    }
}

function Format-Bool {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Value
    )

    return $Value.ToString().ToLowerInvariant()
}

function Write-ReadinessText {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Report
    )

    Write-Output "ready $(Format-Bool -Value $Report.public_release_ready)"
    Write-Output "blockers $($Report.blockers -join ',')"
    Write-Output "next_steps $($Report.next_steps -join ',')"
    Write-Output "machine_takeover_status $($Report.machine_takeover_status)"
    Write-Output "install_first_run_system_proxy_ready $(Format-Bool -Value $Report.install_first_run.system_proxy_ready)"
    Write-Output "install_first_run_tun_ready $(Format-Bool -Value $Report.install_first_run.tun_ready)"
    Write-Output "install_first_run_blockers $($Report.install_first_run.blockers.code -join ',')"
    Write-Output "install_dependency_action_entrypoints $($Report.install_first_run.dependency_action_entrypoints -join ',')"
    Write-Output "support_export_smoke $($Report.support_export.smoke)"
    Write-Output "support_export_kind $($Report.support_export.kind)"
    Write-Output "support_export_desktop_dependencies $(Format-Bool -Value $Report.support_export.desktop_dependencies)"
    Write-Output "msi_support_export_smoke $($Report.msi_support_export.smoke)"
    Write-Output "msi_support_export_kind $($Report.msi_support_export.kind)"
    Write-Output "msi_support_export_desktop_dependencies $(Format-Bool -Value $Report.msi_support_export.desktop_dependencies)"
    Write-Output "signing_status $($Report.signing.status)"
    Write-Output "signing_mode $($Report.signing.mode)"
    Write-Output "signing_can_sign $(Format-Bool -Value $Report.signing.can_sign)"
    Write-Output "signing_signtool_available $(Format-Bool -Value $Report.signing.signtool_available)"
    Write-Output "signing_method $($Report.signing.signing_method)"
    Write-Output "signing_timestamp_url $($Report.signing.timestamp_url)"
    Write-Output "signing_certificate_candidates $($Report.signing.store_certificate_candidates_count)"
    Write-Output "signing_certificate_subject_matches $($Report.signing.certificate_subject_match_count)"
    Write-Output "signing_unsigned_artifacts $($Report.signing.unsigned_artifacts -join ',')"
    Write-Output "signing_verification_failures $($Report.signing.sign_verification_failures -join ',')"
    Write-Output "signing_command_previews_count $(@($Report.signing.sign_command_previews).Count)"
    Write-Output "command.inspect $($Report.commands.inspect)"
    Write-Output "command.sign $($Report.commands.sign)"
    Write-Output "command.public_release_gate $($Report.commands.public_release_gate)"
}

$repoRoot = Resolve-RepoRoot
$releaseEvidenceRelativePath = 'target\desktop\keli-desktop-release-evidence.json'
if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    $EvidencePath = Join-Path $repoRoot $releaseEvidenceRelativePath
}

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        Write-Output "input $releaseEvidenceRelativePath"
        Write-Output 'read public_release_ready public_release_blockers public_release_next_steps'
        Write-Output 'read signing.status signing.mode signing.can_sign signing.signtool_available signing.signing_method signing.timestamp_url signing.store_certificate_candidates_count signing.certificate_subject_match_count signing.unsigned_artifacts signing.sign_verification_failures signing.sign_command_previews signing.release_commands'
        Write-Output 'read smoke.install.first_run_system_proxy_ready smoke.install.first_run_tun_ready smoke.install.first_run_blockers smoke.install.dependency_action_entrypoints'
        Write-Output 'read smoke.install.support_export_smoke smoke.install.support_export_kind smoke.install.support_export_desktop_dependencies'
        Write-Output 'read smoke.msi.support_export_smoke smoke.msi.support_export_kind smoke.msi.support_export_desktop_dependencies'
        Write-Output 'read smoke.machine.machine_takeover_status'
        Write-Output 'output desktop public release readiness report'
        Write-Output 'output json when -Json is provided'
        return
    }

    Require-File -Path $EvidencePath
    $evidence = Get-Content -Raw -LiteralPath $EvidencePath | ConvertFrom-Json
    $report = New-ReadinessReport -Evidence $evidence

    if ($Json) {
        $report | ConvertTo-Json -Depth 8
        return
    }

    Write-ReadinessText -Report $report
} finally {
    Pop-Location
}
