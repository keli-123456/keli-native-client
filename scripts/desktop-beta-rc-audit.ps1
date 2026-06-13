[CmdletBinding()]
param(
    [string]$ManifestPath,
    [string]$ReleaseNotesPath,
    [string]$ReportPath,
    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoRoot {
    $scriptDir = Split-Path -Parent $PSCommandPath
    return (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
}

function Resolve-RepoPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return (Join-Path $RepoRoot $Path)
}

function Require-File {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "required desktop beta RC audit input is missing for $Name`: $Path"
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

function Get-BoolProperty {
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (!(Test-JsonProperty -InputObject $InputObject -Name $Name)) {
        return $false
    }
    return [bool]$InputObject.$Name
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

function Get-ArtifactByKind {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$Kind
    )

    $matches = @($Manifest.artifacts | Where-Object { [string]$_.kind -eq $Kind })
    if ($matches.Count -ne 1) {
        throw "desktop beta RC audit requires one artifact of kind $Kind, found $($matches.Count)"
    }
    return $matches[0]
}

function Test-Artifact {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [object]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$Kind
    )

    $artifact = Get-ArtifactByKind -Manifest $Manifest -Kind $Kind
    $relativePath = [string]$artifact.path
    if ([string]::IsNullOrWhiteSpace($relativePath)) {
        throw "artifact path is missing for $Kind"
    }
    $path = Resolve-RepoPath -RepoRoot $RepoRoot -Path $relativePath
    Require-File -Path $path -Name $Kind

    $item = Get-Item -LiteralPath $path
    $expectedBytes = [int64]$artifact.bytes
    if ($item.Length -ne $expectedBytes) {
        throw "artifact byte count mismatch for $Kind`: expected $expectedBytes actual $($item.Length)"
    }

    $expectedHash = ([string]$artifact.sha256).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($expectedHash)) {
        throw "artifact SHA256 is missing for $Kind"
    }
    $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "artifact SHA256 mismatch for $Kind`: expected $expectedHash actual $actualHash"
    }

    [ordered]@{
        kind = $Kind
        path = $relativePath
        bytes = $item.Length
        sha256 = $actualHash
    }
}

function Test-ReleaseNotes {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [object]$Manifest,

        [Parameter(Mandatory = $true)]
        [object[]]$Artifacts
    )

    $version = [string]$Manifest.version
    foreach ($needle in @(
        $version,
        'This is an unsigned Beta build for testing.',
        'Windows may show SmartScreen or publisher warnings.',
        'Verify SHA256 hashes before running artifacts.',
        'scripts\desktop-beta-rc.ps1'
    )) {
        if (!$Text.Contains($needle)) {
            throw "desktop beta RC release notes missing: $needle"
        }
    }

    foreach ($artifact in $Artifacts) {
        foreach ($needle in @([string]$artifact.path, [string]$artifact.sha256)) {
            if (!$Text.Contains($needle)) {
                throw "desktop beta RC release notes missing artifact detail: $needle"
            }
        }
    }

    return $true
}

function Test-SupportSmoke {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($RelativePath)) {
        throw "desktop beta RC support smoke path is missing for $Name"
    }
    $path = Resolve-RepoPath -RepoRoot $RepoRoot -Path $RelativePath
    Require-File -Path $path -Name $Name
    $smoke = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
    if ([string]$smoke.status -ne 'passed') {
        throw "desktop beta RC support smoke status mismatch for $Name`: $($smoke.status)"
    }
    if ((Test-JsonProperty -InputObject $smoke -Name 'kind') -and [string]$smoke.kind -ne 'keli_desktop_support_bundle') {
        throw "desktop beta RC support smoke kind mismatch for $Name`: $($smoke.kind)"
    }

    [ordered]@{
        path = $RelativePath
        status = [string]$smoke.status
        kind = Get-StringProperty -InputObject $smoke -Name 'kind'
    }
}

function Test-RunningSupportSmoke {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($RelativePath)) {
        throw "desktop beta RC running support smoke path is missing for $Name"
    }
    $path = Resolve-RepoPath -RepoRoot $RepoRoot -Path $RelativePath
    Require-File -Path $path -Name $Name
    $smoke = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
    if ([string]$smoke.status -ne 'passed') {
        throw "desktop beta RC running support smoke status mismatch for $Name`: $($smoke.status)"
    }
    foreach ($field in @('desktop_status_running', 'diagnosis_selected', 'redaction_ready', 'stopped_after_smoke')) {
        if (!(Get-BoolProperty -InputObject $smoke -Name $field)) {
            throw "desktop beta RC running support smoke $field must be true for $Name"
        }
    }

    [ordered]@{
        path = $RelativePath
        status = [string]$smoke.status
        desktop_status_running = Get-BoolProperty -InputObject $smoke -Name 'desktop_status_running'
        diagnosis_selected = Get-BoolProperty -InputObject $smoke -Name 'diagnosis_selected'
        redaction_ready = Get-BoolProperty -InputObject $smoke -Name 'redaction_ready'
        stopped_after_smoke = Get-BoolProperty -InputObject $smoke -Name 'stopped_after_smoke'
    }
}

function Test-SmokeEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [object]$Manifest
    )

    if (!(Test-JsonProperty -InputObject $Manifest -Name 'smoke_evidence')) {
        throw 'desktop beta RC manifest smoke_evidence is missing'
    }
    $install = $Manifest.smoke_evidence.install
    $msi = $Manifest.smoke_evidence.msi

    [ordered]@{
        install = [ordered]@{
            support_export_smoke = Test-SupportSmoke -RepoRoot $RepoRoot -RelativePath ([string]$install.support_export_smoke) -Name 'install support export'
            running_support_smoke = Test-RunningSupportSmoke -RepoRoot $RepoRoot -RelativePath ([string]$install.running_support_smoke) -Name 'install running support'
        }
        msi = [ordered]@{
            support_export_smoke = Test-SupportSmoke -RepoRoot $RepoRoot -RelativePath ([string]$msi.support_export_smoke) -Name 'MSI support export'
            running_support_smoke = Test-RunningSupportSmoke -RepoRoot $RepoRoot -RelativePath ([string]$msi.running_support_smoke) -Name 'MSI running support'
        }
    }
}

$repoRoot = Resolve-RepoRoot
$manifestRelativePath = 'target\desktop\keli-desktop-unsigned-beta-manifest.json'
$notesRelativePath = 'target\desktop\keli-desktop-unsigned-beta-release-notes.md'
$reportRelativePath = 'target\desktop\keli-desktop-beta-rc-audit.json'

if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $repoRoot $manifestRelativePath
}
if ([string]::IsNullOrWhiteSpace($ReleaseNotesPath)) {
    $ReleaseNotesPath = Join-Path $repoRoot $notesRelativePath
}
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $repoRoot $reportRelativePath
}

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        Write-Output "input $manifestRelativePath"
        Write-Output "input $notesRelativePath"
        Write-Output 'verify artifacts desktop-shell-exe portable-zip desktop-msi bytes sha256'
        Write-Output 'verify release notes version artifacts hashes unsigned warning commands'
        Write-Output 'verify smoke evidence support and running support reports'
        Write-Output "write $reportRelativePath"
        Write-Output 'output beta rc audit ready'
        return
    }

    Require-File -Path $ManifestPath -Name 'manifest'
    Require-File -Path $ReleaseNotesPath -Name 'release notes'
    $manifest = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json
    if ([string]$manifest.status -ne 'passed') {
        throw "desktop beta RC manifest status mismatch: $($manifest.status)"
    }
    if ([string]$manifest.channel -ne 'unsigned-beta') {
        throw "desktop beta RC manifest channel mismatch: $($manifest.channel)"
    }

    $artifacts = @(
        (Test-Artifact -RepoRoot $repoRoot -Manifest $manifest -Kind 'desktop-shell-exe'),
        (Test-Artifact -RepoRoot $repoRoot -Manifest $manifest -Kind 'portable-zip'),
        (Test-Artifact -RepoRoot $repoRoot -Manifest $manifest -Kind 'desktop-msi')
    )
    $notesText = Get-Content -Raw -LiteralPath $ReleaseNotesPath
    $releaseNotesReady = Test-ReleaseNotes -Text $notesText -Manifest $manifest -Artifacts $artifacts
    $smokeEvidence = Test-SmokeEvidence -RepoRoot $repoRoot -Manifest $manifest
    $verificationCommands = Get-StringArrayProperty -InputObject $manifest -Name 'verification_commands'

    $report = [ordered]@{
        status = 'passed'
        channel = [string]$manifest.channel
        version = [string]$manifest.version
        artifact_count = $artifacts.Count
        artifacts = $artifacts
        release_notes_ready = $releaseNotesReady
        smoke_evidence_ready = $true
        smoke_evidence = $smokeEvidence
        verification_commands = $verificationCommands
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ReportPath) | Out-Null
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ReportPath -Encoding ASCII

    Write-Output 'beta_rc_audit_ready true'
    Write-Output "channel $($report.channel)"
    Write-Output "artifact_count $($report.artifact_count)"
    Write-Output "smoke_evidence_ready $($report.smoke_evidence_ready.ToString().ToLowerInvariant())"
} finally {
    Pop-Location
}
