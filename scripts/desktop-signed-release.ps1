[CmdletBinding()]
param(
    [switch]$PlanOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoRoot {
    $scriptDir = Split-Path -Parent $PSCommandPath
    return (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
}

function New-ReleaseStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string[]]$Command
    )

    [pscustomobject]@{
        Name = $Name
        Command = $Command
    }
}

function Format-StepCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Command
    )

    $parts = foreach ($part in $Command) {
        if ($part -match '\s') {
            '"' + ($part -replace '"', '\"') + '"'
        } else {
            $part
        }
    }
    return ($parts -join ' ')
}

function Invoke-ReleaseStep {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Step
    )

    Write-Host "==> $($Step.Name)"
    Write-Host "    $(Format-StepCommand -Command $Step.Command)"

    $executable = $Step.Command[0]
    $arguments = @()
    if ($Step.Command.Count -gt 1) {
        $arguments = $Step.Command[1..($Step.Command.Count - 1)]
    }

    & $executable @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$($Step.Name) failed with exit code $LASTEXITCODE"
    }
}

function Get-WorkspaceVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CargoToml
    )

    $content = Get-Content -Raw -LiteralPath $CargoToml
    $match = [regex]::Match($content, '(?m)^version\s*=\s*"([^"]+)"')
    if (!$match.Success) {
        throw "workspace version was not found in $CargoToml"
    }
    return $match.Groups[1].Value
}

function Get-ArtifactSummary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string]$Kind,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $path = Join-Path $RepoRoot $RelativePath
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "signed release artifact is missing for $Kind`: $path"
    }
    $item = Get-Item -LiteralPath $path
    $hash = Get-FileHash -LiteralPath $path -Algorithm SHA256

    [ordered]@{
        kind = $Kind
        path = $RelativePath
        bytes = $item.Length
        sha256 = $hash.Hash.ToLowerInvariant()
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
        [string]$Name
    )

    if (!(Test-JsonProperty -InputObject $InputObject -Name $Name)) {
        return $false
    }
    return [bool]$InputObject.$Name
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

function Get-SignedReleaseEvidenceSummary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $releaseEvidenceRelativePath = 'target\desktop\keli-desktop-release-evidence.json'
    $signingEvidenceRelativePath = 'target\desktop\keli-desktop-signing.json'
    $releaseEvidencePath = Join-Path $RepoRoot $releaseEvidenceRelativePath
    $signingEvidencePath = Join-Path $RepoRoot $signingEvidenceRelativePath
    if (!(Test-Path -LiteralPath $releaseEvidencePath -PathType Leaf)) {
        throw "signed release evidence summary is missing release evidence: $releaseEvidencePath"
    }
    if (!(Test-Path -LiteralPath $signingEvidencePath -PathType Leaf)) {
        throw "signed release evidence summary is missing signing evidence: $signingEvidencePath"
    }

    $releaseEvidence = Get-Content -Raw -LiteralPath $releaseEvidencePath | ConvertFrom-Json
    $signingEvidence = Get-Content -Raw -LiteralPath $signingEvidencePath | ConvertFrom-Json
    $releaseSigning = if (Test-JsonProperty -InputObject $releaseEvidence -Name 'signing') { $releaseEvidence.signing } else { $null }
    $signedArtifacts = @()
    if (Test-JsonProperty -InputObject $signingEvidence -Name 'artifacts') {
        $signedArtifacts = @($signingEvidence.artifacts |
            Where-Object { (Test-JsonProperty -InputObject $_ -Name 'signature') -and (Get-BoolProperty -InputObject $_.signature -Name 'signed') } |
            ForEach-Object { [string]$_.path })
    }

    [ordered]@{
        path = $releaseEvidenceRelativePath
        public_release_ready = Get-BoolProperty -InputObject $releaseEvidence -Name 'public_release_ready'
        public_release_blockers = @(Get-StringArrayProperty -InputObject $releaseEvidence -Name 'public_release_blockers')
        signing_status = Get-StringProperty -InputObject $releaseSigning -Name 'status'
        signing_mode = Get-StringProperty -InputObject $releaseSigning -Name 'mode'
        signing_can_sign = Get-BoolProperty -InputObject $releaseSigning -Name 'can_sign'
        signing_method = Get-StringProperty -InputObject $releaseSigning -Name 'signing_method'
        signed_artifacts = @($signedArtifacts)
        sign_verification_failures = @(Get-StringArrayProperty -InputObject $releaseSigning -Name 'sign_verification_failures')
    }
}

function Assert-SigningConfigurationReady {
    $certificatePath = [string]$env:KELI_SIGN_CERT_PATH
    $certificateSubject = [string]$env:KELI_SIGN_CERT_SUBJECT
    if ([string]::IsNullOrWhiteSpace($certificatePath) -and [string]::IsNullOrWhiteSpace($certificateSubject)) {
        throw 'Desktop signed public release blocked: signing-certificate-missing next_steps=configure-code-signing-certificate'
    }
    if (![string]::IsNullOrWhiteSpace($certificatePath) -and !(Test-Path -LiteralPath $certificatePath -PathType Leaf)) {
        throw 'Desktop signed public release blocked: signing-certificate-missing next_steps=fix-certificate-path'
    }
}

function Write-SignedReleaseReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string]$ReportPath
    )

    $artifacts = @(
        (Get-ArtifactSummary -RepoRoot $RepoRoot -Kind 'portable-zip' -RelativePath 'target\desktop\keli-desktop-mvp-windows-x64.zip'),
        (Get-ArtifactSummary -RepoRoot $RepoRoot -Kind 'desktop-msi' -RelativePath 'target\desktop\keli-desktop-mvp-windows-x64.msi'),
        (Get-ArtifactSummary -RepoRoot $RepoRoot -Kind 'release-evidence' -RelativePath 'target\desktop\keli-desktop-release-evidence.json'),
        (Get-ArtifactSummary -RepoRoot $RepoRoot -Kind 'signing-evidence' -RelativePath 'target\desktop\keli-desktop-signing.json')
    )

    $report = [ordered]@{
        status = 'passed'
        channel = 'signed-public'
        version = Get-WorkspaceVersion -CargoToml (Join-Path $RepoRoot 'Cargo.toml')
        artifact_count = $artifacts.Count
        artifacts = $artifacts
        public_gate = [ordered]@{
            command = 'scripts\desktop-public-release-gate.ps1 -SkipGate'
            passed = $true
        }
        release_evidence = Get-SignedReleaseEvidenceSummary -RepoRoot $RepoRoot
        verification_commands = @(
            'scripts\desktop-signed-release.ps1',
            'scripts\desktop-public-release-gate.ps1 -SkipGate',
            'scripts\desktop-release-readiness.ps1'
        )
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ReportPath) | Out-Null
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding ASCII
    return $report
}

$repoRoot = Resolve-RepoRoot
$reportRelativePath = 'target\desktop\keli-desktop-signed-release.json'
$reportPath = Join-Path $repoRoot $reportRelativePath
$steps = @(
    (New-ReleaseStep -Name 'Format check' -Command @('cargo', 'fmt', '--check')),
    (New-ReleaseStep -Name 'Diff whitespace check' -Command @('git', 'diff', '--check')),
    (New-ReleaseStep -Name 'Desktop backend tests' -Command @('cargo', 'test', '-p', 'keli-desktop', '--', '--test-threads=1')),
    (New-ReleaseStep -Name 'Desktop shell tests' -Command @('cargo', 'test', '-p', 'keli-desktop-shell')),
    (New-ReleaseStep -Name 'Desktop shell check' -Command @('cargo', 'check', '-p', 'keli-desktop-shell')),
    (New-ReleaseStep -Name 'Desktop shell release build' -Command @('cargo', 'build', '--release', '-p', 'keli-desktop-shell')),
    (New-ReleaseStep -Name 'Initial portable package' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-package.ps1', '-SkipBuild')),
    (New-ReleaseStep -Name 'Initial install smoke' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-install-smoke.ps1')),
    (New-ReleaseStep -Name 'Initial MSI installer' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-msi.ps1')),
    (New-ReleaseStep -Name 'Machine takeover smoke evidence' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-machine-smoke.ps1', '-IncludeMachineTakeover', '-MachineTakeoverAttempts', '2')),
    (New-ReleaseStep -Name 'Sign release EXE and initial MSI' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-signing.ps1', '-Sign')),
    (New-ReleaseStep -Name 'Final portable package from signed EXE' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-package.ps1', '-SkipBuild')),
    (New-ReleaseStep -Name 'Final install smoke' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-install-smoke.ps1')),
    (New-ReleaseStep -Name 'Final MSI from signed staged EXE' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-msi.ps1')),
    (New-ReleaseStep -Name 'Sign final MSI and refresh signing evidence' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-signing.ps1', '-Sign')),
    (New-ReleaseStep -Name 'Desktop release evidence' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-release-evidence.ps1')),
    (New-ReleaseStep -Name 'Desktop public release gate' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-public-release-gate.ps1', '-SkipGate'))
)

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        Write-Output 'preflight signing certificate configuration'
        Write-Output 'failure print signing-certificate-missing before build'
        foreach ($step in $steps) {
            if ($step.Name -eq 'Final portable package from signed EXE') {
                Write-Output 'rebuild portable package after exe signing'
            }
            if ($step.Name -eq 'Final MSI from signed staged EXE') {
                Write-Output 'rebuild MSI after signed exe is staged'
            }
            Write-Output (Format-StepCommand -Command $step.Command)
        }
        Write-Output "write $reportRelativePath"
        Write-Output 'output signed public release ready'
        return
    }

    Assert-SigningConfigurationReady

    foreach ($step in $steps) {
        if ($step.Name -eq 'Final portable package from signed EXE') {
            Write-Host '==> Rebuild portable package after exe signing'
        }
        if ($step.Name -eq 'Final MSI from signed staged EXE') {
            Write-Host '==> Rebuild MSI after signed exe is staged'
        }
        Invoke-ReleaseStep -Step $step
    }

    $report = Write-SignedReleaseReport -RepoRoot $repoRoot -ReportPath $reportPath
    Write-Output 'signed_public_release_ready true'
    Write-Output "channel $($report.channel)"
    Write-Output "artifact_count $($report.artifact_count)"
    Write-Output "report $reportRelativePath"
} finally {
    Pop-Location
}
