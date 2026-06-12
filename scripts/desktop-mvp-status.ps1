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
    $msiWorkflowReady = (
        (Get-BoolProperty -InputObject $msiSmoke -Name 'native_core_default') -and
        ([string]$msiSmoke.readme_subscription_import -eq 'subscription-url-or-config') -and
        (Test-StringArrayContainsAll -Values $msiSmoke.manual_smoke_cases -Expected $expectedWorkflows)
    )
    $machineReady = ([string]$machineSmoke.machine_takeover_status -eq 'ready')
    $nativeCoreReady = Get-BoolProperty -InputObject $Evidence -Name 'native_core_default'

    $publicReleaseBlockers = Get-StringArrayProperty -InputObject $Evidence -Name 'public_release_blockers'
    $publicReleaseNextSteps = Get-StringArrayProperty -InputObject $Evidence -Name 'public_release_next_steps'
    $publicReleaseReady = (Get-BoolProperty -InputObject $Evidence -Name 'public_release_ready') -and ($publicReleaseBlockers.Count -eq 0)
    $localRequirements = @(
        (New-Requirement -Id 'native-core-default' -Ready $nativeCoreReady -Evidence 'release.native_core_default'),
        (New-Requirement -Id 'package-artifacts' -Ready $artifactReady -Evidence 'release.artifacts'),
        (New-Requirement -Id 'install-smoke-workflows' -Ready $installWorkflowReady -Evidence 'release.smoke.install'),
        (New-Requirement -Id 'msi-smoke-workflows' -Ready $msiWorkflowReady -Evidence 'release.smoke.msi'),
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
