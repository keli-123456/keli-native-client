[CmdletBinding()]
param(
    [string]$EvidencePath,
    [string]$ManifestPath,
    [string]$ReleaseNotesPath,
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
        throw "required desktop unsigned beta RC input is missing: $Path"
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

function Get-ArtifactByKind {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Evidence,

        [Parameter(Mandatory = $true)]
        [string]$Kind
    )

    $matches = @($Evidence.artifacts | Where-Object { [string]$_.kind -eq $Kind })
    if ($matches.Count -ne 1) {
        throw "desktop unsigned beta RC requires one artifact of kind $Kind, found $($matches.Count)"
    }

    $artifact = $matches[0]
    if ([string]::IsNullOrWhiteSpace([string]$artifact.path)) {
        throw "desktop unsigned beta RC artifact path is missing for $Kind"
    }
    if ([string]::IsNullOrWhiteSpace([string]$artifact.sha256)) {
        throw "desktop unsigned beta RC artifact sha256 is missing for $Kind"
    }
    return $artifact
}

function Read-DesktopMvpStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string]$EvidencePath
    )

    $statusScript = Join-Path $RepoRoot 'scripts\desktop-mvp-status.ps1'
    $jsonOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $statusScript -EvidencePath $EvidencePath -Json
    if ($LASTEXITCODE -ne 0) {
        throw 'Desktop unsigned beta RC blocked: desktop-mvp-status-failed'
    }
    return ($jsonOutput -join "`n" | ConvertFrom-Json)
}

function Get-BlockedDesktopMvpRequirements {
    param(
        [Parameter(Mandatory = $true)]
        [object]$MvpStatus
    )

    if (!(Test-JsonProperty -InputObject $MvpStatus -Name 'requirements')) {
        return @()
    }

    return @($MvpStatus.requirements |
        Where-Object { [string]$_.id -ne 'public-release-signing' -and [string]$_.status -ne 'ready' } |
        ForEach-Object { [string]$_.id } |
        Where-Object { ![string]::IsNullOrWhiteSpace($_) })
}

function Assert-UnsignedBetaReady {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Evidence,

        [Parameter(Mandatory = $true)]
        [object]$MvpStatus
    )

    if ([string]$Evidence.status -ne 'passed') {
        throw "Desktop unsigned beta RC blocked: release-evidence-status-$($Evidence.status)"
    }
    if ($MvpStatus.desktop_mvp_ready -ne $true) {
        $blockedRequirements = @(Get-BlockedDesktopMvpRequirements -MvpStatus $MvpStatus)
        $suffix = if ($blockedRequirements.Count -gt 0) { " $($blockedRequirements -join ',')" } else { '' }
        throw "Desktop unsigned beta RC blocked: desktop-mvp-not-ready$suffix"
    }

    foreach ($kind in @('desktop-shell-exe', 'portable-zip', 'desktop-msi')) {
        Get-ArtifactByKind -Evidence $Evidence -Kind $kind | Out-Null
    }

    $allowed = @('artifact-signature-missing', 'signing-certificate-missing', 'machine-takeover-smoke-not-run')
    $blockers = @(Get-StringArrayProperty -InputObject $Evidence -Name 'public_release_blockers')
    $unexpected = @($blockers | Where-Object { $allowed -notcontains $_ })
    if ($unexpected.Count -gt 0) {
        throw "Desktop unsigned beta RC blocked: $($unexpected -join ',')"
    }

    return $allowed
}

function New-BetaManifest {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Evidence,

        [Parameter(Mandatory = $true)]
        [string[]]$AllowedBlockers
    )

    [ordered]@{
        status = 'passed'
        channel = 'unsigned-beta'
        version = [string]$Evidence.version
        unsigned = (@(Get-StringArrayProperty -InputObject $Evidence -Name 'public_release_blockers') -contains 'artifact-signature-missing')
        allowed_public_release_blockers = $AllowedBlockers
        public_release_ready = [bool]$Evidence.public_release_ready
        artifacts = @(@('desktop-shell-exe', 'portable-zip', 'desktop-msi') | ForEach-Object {
            $artifact = Get-ArtifactByKind -Evidence $Evidence -Kind $_
            [ordered]@{
                kind = [string]$artifact.kind
                path = [string]$artifact.path
                bytes = [int64]$artifact.bytes
                sha256 = [string]$artifact.sha256
            }
        })
        smoke_evidence = [ordered]@{
            install = [ordered]@{
                support_export_smoke = [string]$Evidence.smoke.install.support_export_smoke
                running_support_smoke = [string]$Evidence.smoke.install.running_support_smoke
            }
            msi = [ordered]@{
                support_export_smoke = [string]$Evidence.smoke.msi.support_export_smoke
                running_support_smoke = [string]$Evidence.smoke.msi.running_support_smoke
            }
        }
        verification_commands = @(
            'scripts\desktop-mvp-gate.ps1',
            'scripts\desktop-public-release-gate.ps1 -SkipGate',
            'scripts\desktop-beta-rc.ps1',
            'scripts\desktop-beta-rc-audit.ps1'
        )
    }
}

function Write-BetaReleaseNotes {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $artifactLines = @($Manifest.artifacts | ForEach-Object {
        "- {0}: ``{1}`` SHA256 ``{2}``" -f $_.kind, $_.path, $_.sha256
    })
    $content = @(
        "# Keli Desktop Unsigned Beta RC $($Manifest.version)",
        '',
        'This is an unsigned Beta build for testing.',
        'Windows may show SmartScreen or publisher warnings.',
        'Verify SHA256 hashes before running artifacts.',
        '',
        '## Artifacts'
    ) + $artifactLines + @(
        '',
        '## Install Notes',
        '- Use the portable zip for no-installer testing.',
        '- Use the MSI for installer smoke testing.',
        '- Microsoft Edge WebView2 Runtime is required.',
        '- TUN mode requires Wintun; system proxy mode can be tested first.',
        '- Support bundles are exported from Diagnostics under the user Documents Keli Support directory.',
        '- The manifest lists packaged support export and running support smoke evidence.',
        '',
        '## Verification Commands',
        '- `scripts\desktop-mvp-gate.ps1`',
        '- `scripts\desktop-public-release-gate.ps1 -SkipGate`',
        '- `scripts\desktop-beta-rc.ps1`',
        '- `scripts\desktop-beta-rc-audit.ps1`',
        '',
        '## Support bundles',
        'Export a support bundle from Diagnostics when reporting Beta issues.'
    )
    $content | Set-Content -LiteralPath $Path -Encoding ASCII
}

$repoRoot = Resolve-RepoRoot
$evidenceRelativePath = 'target\desktop\keli-desktop-release-evidence.json'
$manifestRelativePath = 'target\desktop\keli-desktop-unsigned-beta-manifest.json'
$notesRelativePath = 'target\desktop\keli-desktop-unsigned-beta-release-notes.md'

if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    $EvidencePath = Join-Path $repoRoot $evidenceRelativePath
}
if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $repoRoot $manifestRelativePath
}
if ([string]::IsNullOrWhiteSpace($ReleaseNotesPath)) {
    $ReleaseNotesPath = Join-Path $repoRoot $notesRelativePath
}

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        Write-Output "input $evidenceRelativePath"
        Write-Output 'input desktop MVP status from scripts\desktop-mvp-status.ps1 -Json'
        Write-Output 'require desktop_mvp_ready true'
        Write-Output 'require release evidence status passed'
        Write-Output 'require artifacts desktop-shell-exe portable-zip desktop-msi with sha256'
        Write-Output 'allow public_release_blockers artifact-signature-missing signing-certificate-missing machine-takeover-smoke-not-run only'
        Write-Output 'include smoke_evidence running_support_smoke'
        Write-Output 'include verification command scripts\desktop-beta-rc-audit.ps1'
        Write-Output "write $manifestRelativePath"
        Write-Output "write $notesRelativePath"
        Write-Output 'output unsigned beta rc ready'
        return
    }

    Require-File -Path $EvidencePath
    $evidence = Get-Content -Raw -LiteralPath $EvidencePath | ConvertFrom-Json
    $mvpStatus = Read-DesktopMvpStatus -RepoRoot $repoRoot -EvidencePath $EvidencePath
    $allowedBlockers = Assert-UnsignedBetaReady -Evidence $evidence -MvpStatus $mvpStatus
    $manifest = New-BetaManifest -Evidence $evidence -AllowedBlockers $allowedBlockers

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ManifestPath) | Out-Null
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ReleaseNotesPath) | Out-Null
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ManifestPath -Encoding ASCII
    Write-BetaReleaseNotes -Manifest $manifest -Path $ReleaseNotesPath

    Write-Output 'unsigned_beta_rc_ready true'
    Write-Output "version $($manifest.version)"
    Write-Output "channel $($manifest.channel)"
    Write-Output "allowed_public_release_blockers $($manifest.allowed_public_release_blockers -join ',')"
} finally {
    Pop-Location
}
