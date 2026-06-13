[CmdletBinding()]
param(
    [string]$EvidencePath,
    [switch]$Json,
    [switch]$PlanOnly,
    [switch]$FailOnMvpBlocked
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
        throw "required desktop MVP release evidence is missing: $Path"
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

function Test-StringArrayContainsAll {
    param(
        [AllowNull()]
        [object]$Values,

        [Parameter(Mandatory = $true)]
        [string[]]$Expected
    )

    if ($null -eq $Values) {
        return $false
    }
    $actual = @($Values | ForEach-Object { [string]$_ })
    foreach ($item in $Expected) {
        if ($actual -notcontains $item) {
            return $false
        }
    }
    return $true
}

function Test-InstallFirstRunDependencyEvidence {
    param(
        [AllowNull()]
        [object]$InstallSmoke
    )

    if (!(Test-JsonProperty -InputObject $InstallSmoke -Name 'first_run_system_proxy_ready')) {
        return $false
    }
    if (!(Test-JsonProperty -InputObject $InstallSmoke -Name 'first_run_tun_ready')) {
        return $false
    }

    $systemProxyReady = [bool]$InstallSmoke.first_run_system_proxy_ready
    $tunReady = [bool]$InstallSmoke.first_run_tun_ready
    $blockers = @()
    if (Test-JsonProperty -InputObject $InstallSmoke -Name 'first_run_blockers') {
        $blockers = @($InstallSmoke.first_run_blockers)
    }

    if ((!$systemProxyReady -or !$tunReady) -and $blockers.Count -eq 0) {
        return $false
    }
    if ($blockers.Count -eq 0) {
        return $true
    }
    if (!(Test-JsonProperty -InputObject $InstallSmoke -Name 'dependency_action_entrypoints')) {
        return $false
    }

    $actions = Get-StringArrayProperty -InputObject $InstallSmoke -Name 'dependency_action_entrypoints'
    foreach ($blocker in $blockers) {
        if (!(Test-JsonProperty -InputObject $blocker -Name 'action')) {
            return $false
        }
        $action = [string]$blocker.action
        if ([string]::IsNullOrWhiteSpace($action) -or $actions -notcontains $action) {
            return $false
        }
    }
    return $true
}

function Test-SupportExportEvidence {
    param(
        [AllowNull()]
        [object]$InstallSmoke
    )

    if ($null -eq $InstallSmoke) {
        return $false
    }

    return (
        (Test-StringArrayContainsAll -Values $InstallSmoke.manual_smoke_cases -Expected @('export-support-bundle')) -and
        (Test-StringArrayContainsAll -Values $InstallSmoke.verified_ui_workflow_entrypoints -Expected @('export-support-bundle')) -and
        ([string]$InstallSmoke.support_export_smoke -eq 'target\desktop-install-smoke\desktop-support-export-smoke.json') -and
        ([string]$InstallSmoke.support_export_kind -eq 'keli_desktop_support_bundle') -and
        (Get-BoolProperty -InputObject $InstallSmoke -Name 'support_export_desktop_dependencies')
    )
}

function Test-MsiSupportExportEvidence {
    param(
        [AllowNull()]
        [object]$MsiSmoke
    )

    if ($null -eq $MsiSmoke) {
        return $false
    }

    return (
        ([string]$MsiSmoke.support_export_smoke -eq 'target\desktop\keli-desktop-msi-support-export-smoke.json') -and
        ([string]$MsiSmoke.support_export_kind -eq 'keli_desktop_support_bundle') -and
        (Get-BoolProperty -InputObject $MsiSmoke -Name 'support_export_desktop_dependencies')
    )
}

function Test-RunningSupportEvidence {
    param(
        [AllowNull()]
        [object]$Smoke,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedSmokePath
    )

    if ($null -eq $Smoke) {
        return $false
    }

    return (
        ([string]$Smoke.running_support_smoke -eq $ExpectedSmokePath) -and
        (Get-BoolProperty -InputObject $Smoke -Name 'running_support_desktop_status_running') -and
        (Get-BoolProperty -InputObject $Smoke -Name 'running_support_desktop_status_selected') -and
        (Get-BoolProperty -InputObject $Smoke -Name 'running_support_managed_status_selected') -and
        (Get-BoolProperty -InputObject $Smoke -Name 'running_support_diagnosis_selected') -and
        (Get-BoolProperty -InputObject $Smoke -Name 'running_support_redaction_ready') -and
        (Get-BoolProperty -InputObject $Smoke -Name 'running_support_stopped_after_smoke')
    )
}

function Test-MachineSmokeEvidence {
    param(
        [AllowNull()]
        [object]$MachineSmoke
    )

    if ($null -eq $MachineSmoke) {
        return $false
    }

    return (
        ([string]$MachineSmoke.status -eq 'passed') -and
        (Get-BoolProperty -InputObject $MachineSmoke -Name 'native_core_default')
    )
}

function New-Requirement {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [bool]$Ready,

        [Parameter(Mandatory = $true)]
        [string]$Evidence,

        [string[]]$Blockers = @()
    )

    [ordered]@{
        id = $Id
        status = if ($Ready) { 'ready' } else { 'blocked' }
        evidence = $Evidence
        blockers = @($Blockers)
    }
}

function Get-ArtifactKinds {
    param(
        [AllowNull()]
        [object]$Evidence
    )

    if (!(Test-JsonProperty -InputObject $Evidence -Name 'artifacts')) {
        return @()
    }
    return @($Evidence.artifacts | ForEach-Object { [string]$_.kind })
}

function New-DesktopMvpStatus {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Evidence
    )

    $expectedWorkflows = @(
        'open-desktop-shell',
        'import-subscription',
        'select-node',
        'start-stop-system-proxy',
        'tun-preflight',
        'export-support-bundle'
    )
    $expectedArtifacts = @('desktop-shell-exe', 'portable-zip', 'desktop-msi')

    $smoke = if (Test-JsonProperty -InputObject $Evidence -Name 'smoke') { $Evidence.smoke } else { $null }
    $installSmoke = if (Test-JsonProperty -InputObject $smoke -Name 'install') { $smoke.install } else { $null }
    $msiSmoke = if (Test-JsonProperty -InputObject $smoke -Name 'msi') { $smoke.msi } else { $null }
    $machineSmoke = if (Test-JsonProperty -InputObject $smoke -Name 'machine') { $smoke.machine } else { $null }

    $artifactKinds = Get-ArtifactKinds -Evidence $Evidence
    $artifactReady = Test-StringArrayContainsAll -Values $artifactKinds -Expected $expectedArtifacts
    $installWorkflowReady = (
        (Get-BoolProperty -InputObject $installSmoke -Name 'native_core_default') -and
        ([string]$installSmoke.readme_subscription_import -eq 'subscription-url-or-config') -and
        (Test-StringArrayContainsAll -Values $installSmoke.manual_smoke_cases -Expected $expectedWorkflows) -and
        (Test-StringArrayContainsAll -Values $installSmoke.verified_ui_workflow_entrypoints -Expected $expectedWorkflows)
    )
    $supportBundleReady = Test-SupportExportEvidence -InstallSmoke $installSmoke
    $runningSupportBundleReady = Test-RunningSupportEvidence `
        -Smoke $installSmoke `
        -ExpectedSmokePath 'target\desktop-install-smoke\desktop-startup-connect-support-smoke.json'
    $installFirstRunDependencyReady = Test-InstallFirstRunDependencyEvidence -InstallSmoke $installSmoke
    $msiWorkflowReady = (
        (Get-BoolProperty -InputObject $msiSmoke -Name 'native_core_default') -and
        ([string]$msiSmoke.readme_subscription_import -eq 'subscription-url-or-config') -and
        (Test-StringArrayContainsAll -Values $msiSmoke.manual_smoke_cases -Expected $expectedWorkflows)
    )
    $msiSupportBundleReady = Test-MsiSupportExportEvidence -MsiSmoke $msiSmoke
    $msiRunningSupportBundleReady = Test-RunningSupportEvidence `
        -Smoke $msiSmoke `
        -ExpectedSmokePath 'target\desktop\keli-desktop-msi-startup-connect-support-smoke.json'
    $machineReady = Test-MachineSmokeEvidence -MachineSmoke $machineSmoke
    $nativeCoreReady = Get-BoolProperty -InputObject $Evidence -Name 'native_core_default'

    $publicReleaseBlockers = Get-StringArrayProperty -InputObject $Evidence -Name 'public_release_blockers'
    $publicReleaseNextSteps = Get-StringArrayProperty -InputObject $Evidence -Name 'public_release_next_steps'
    $publicReleaseReady = (Get-BoolProperty -InputObject $Evidence -Name 'public_release_ready') -and ($publicReleaseBlockers.Count -eq 0)
    $localRequirements = @(
        (New-Requirement -Id 'native-core-default' -Ready $nativeCoreReady -Evidence 'release.native_core_default'),
        (New-Requirement -Id 'package-artifacts' -Ready $artifactReady -Evidence 'release.artifacts'),
        (New-Requirement -Id 'install-smoke-workflows' -Ready $installWorkflowReady -Evidence 'release.smoke.install'),
        (New-Requirement -Id 'support-bundle-export' -Ready $supportBundleReady -Evidence 'release.smoke.install.support_export_smoke'),
        (New-Requirement -Id 'running-support-bundle-export' -Ready $runningSupportBundleReady -Evidence 'release.smoke.install.running_support_smoke'),
        (New-Requirement -Id 'install-first-run-dependencies' -Ready $installFirstRunDependencyReady -Evidence 'release.smoke.install.first_run_blockers'),
        (New-Requirement -Id 'msi-smoke-workflows' -Ready $msiWorkflowReady -Evidence 'release.smoke.msi'),
        (New-Requirement -Id 'msi-support-bundle-export' -Ready $msiSupportBundleReady -Evidence 'release.smoke.msi.support_export_smoke'),
        (New-Requirement -Id 'msi-running-support-bundle-export' -Ready $msiRunningSupportBundleReady -Evidence 'release.smoke.msi.running_support_smoke'),
        (New-Requirement -Id 'machine-takeover' -Ready $machineReady -Evidence 'release.smoke.machine')
    )
    $requirements = @($localRequirements + (New-Requirement -Id 'public-release-signing' -Ready $publicReleaseReady -Evidence 'release.public_release_ready' -Blockers $publicReleaseBlockers))
    $localBlocked = @($localRequirements | Where-Object { $_.status -ne 'ready' })

    [ordered]@{
        desktop_mvp_ready = ($localBlocked.Count -eq 0)
        public_release_ready = $publicReleaseReady
        public_release_blockers = $publicReleaseBlockers
        public_release_next_steps = $publicReleaseNextSteps
        remaining_external_blockers = $publicReleaseBlockers
        requirements = $requirements
    }
}

function Format-Bool {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Value
    )

    return $Value.ToString().ToLowerInvariant()
}

function Write-DesktopMvpStatusText {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Report
    )

    Write-Output "desktop_mvp_ready $(Format-Bool -Value $Report.desktop_mvp_ready)"
    Write-Output "public_release_ready $(Format-Bool -Value $Report.public_release_ready)"
    Write-Output "public_release_blockers $($Report.public_release_blockers -join ',')"
    Write-Output "public_release_next_steps $($Report.public_release_next_steps -join ',')"
    Write-Output "remaining_external_blockers $($Report.remaining_external_blockers -join ',')"
    foreach ($requirement in $Report.requirements) {
        Write-Output "requirement.$($requirement.id) $($requirement.status)"
    }
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
        Write-Output 'config -FailOnMvpBlocked optional'
        Write-Output 'read native_core_default artifacts smoke.install smoke.msi smoke.machine signing public_release_blockers public_release_next_steps'
        Write-Output 'require workflow ids open-desktop-shell import-subscription select-node start-stop-system-proxy tun-preflight export-support-bundle'
        Write-Output 'require support-bundle-export workflow and export smoke evidence'
        Write-Output 'require running-support-bundle-export smoke evidence'
        Write-Output 'require msi-support-bundle-export smoke evidence'
        Write-Output 'require install first_run dependency blockers have action entrypoints'
        Write-Output 'output desktop_mvp_ready and public_release_ready'
        Write-Output 'output json when -Json is provided'
        return
    }

    Require-File -Path $EvidencePath
    $evidence = Get-Content -Raw -LiteralPath $EvidencePath | ConvertFrom-Json
    $report = New-DesktopMvpStatus -Evidence $evidence
    if ($FailOnMvpBlocked -and !$report.desktop_mvp_ready) {
        $blockedRequirements = @($report.requirements | Where-Object {
                $_.id -ne 'public-release-signing' -and $_.status -ne 'ready'
            } | ForEach-Object { [string]$_.id })
        throw "Desktop MVP status blocked: $($blockedRequirements -join ',')"
    }

    if ($Json) {
        $report | ConvertTo-Json -Depth 8
        return
    }

    Write-DesktopMvpStatusText -Report $report
} finally {
    Pop-Location
}
