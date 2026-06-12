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

function Require-File {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "required release evidence input is missing: $Path"
    }
}

function Get-SignatureEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $certificate = $signature.SignerCertificate

    [ordered]@{
        status = $signature.Status.ToString()
        signed = ($signature.Status.ToString() -eq 'Valid')
        signer_subject = if ($null -ne $certificate) { $certificate.Subject } else { $null }
        issuer = if ($null -ne $certificate) { $certificate.Issuer } else { $null }
        not_after = if ($null -ne $certificate) { $certificate.NotAfter.ToUniversalTime().ToString('o') } else { $null }
    }
}

function Get-ArtifactEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Kind,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath,

        [switch]$IncludeSignature
    )

    Require-File -Path $Path
    $item = Get-Item -LiteralPath $Path
    $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256
    if ([string]::IsNullOrWhiteSpace($hash.Hash)) {
        throw "SHA256 hash was empty for $Path"
    }

    $evidence = [ordered]@{
        kind = $Kind
        path = $RelativePath
        bytes = $item.Length
        sha256 = $hash.Hash.ToLowerInvariant()
    }

    if ($IncludeSignature) {
        $evidence['signature'] = Get-SignatureEvidence -Path $Path
    }

    return $evidence
}

function Read-SmokeStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    Require-File -Path $Path
    $smoke = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    if ($smoke.status -ne 'passed') {
        throw "$Name smoke status mismatch: $($smoke.status)"
    }
    if ($smoke.native_core_default -ne $true) {
        throw "$Name smoke native_core_default must be true"
    }

    [ordered]@{
        path = $RelativePath
        status = [string]$smoke.status
        native_core_default = $true
    }
}

function Read-MachineSmokeStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    Require-File -Path $Path
    $smoke = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    if ($smoke.status -ne 'passed') {
        throw "machine smoke status mismatch: $($smoke.status)"
    }
    if ($smoke.native_core_default -ne $true) {
        throw 'machine smoke native_core_default must be true'
    }

    $takeoverStatus = [string]$smoke.machine_takeover.status
    $blockers = @()
    if ($null -ne $smoke.machine_takeover.blockers) {
        $blockers = @($smoke.machine_takeover.blockers | ForEach-Object { [string]$_ })
    }

    [ordered]@{
        path = $RelativePath
        status = [string]$smoke.status
        mode = [string]$smoke.mode
        native_core_default = $true
        machine_takeover_status = $takeoverStatus
        blockers = $blockers
    }
}

function Read-SigningStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    Require-File -Path $Path
    $signing = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    if ($signing.status -ne 'passed') {
        throw "signing status mismatch: $($signing.status)"
    }

    $blockers = @()
    if ($null -ne $signing.public_release_blockers) {
        $blockers = @($signing.public_release_blockers | ForEach-Object { [string]$_ })
    }

    $storeCertificateCandidatesCount = 0
    if ($null -ne $signing.configuration.PSObject.Properties['store_certificate_candidates_count']) {
        $storeCertificateCandidatesCount = [int]$signing.configuration.store_certificate_candidates_count
    }

    $operatorNextSteps = @()
    if ($null -ne $signing.PSObject.Properties['operator_next_steps']) {
        $operatorNextSteps = @($signing.operator_next_steps | ForEach-Object { [string]$_.id })
    }

    $releaseCommands = [ordered]@{}
    if ($null -ne $signing.PSObject.Properties['release_commands']) {
        $releaseCommands = $signing.release_commands
    }

    [ordered]@{
        path = $RelativePath
        status = [string]$signing.status
        mode = [string]$signing.mode
        signtool_available = [bool]$signing.signtool.available
        can_sign = [bool]$signing.configuration.can_sign
        store_certificate_candidates_count = $storeCertificateCandidatesCount
        operator_next_steps = $operatorNextSteps
        release_commands = $releaseCommands
        blockers = $blockers
    }
}

function Add-UniqueBlocker {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Blockers,

        [Parameter(Mandatory = $true)]
        [string]$Blocker
    )

    if ($Blockers -notcontains $Blocker) {
        return @($Blockers + $Blocker)
    }
    return $Blockers
}

function Add-UniqueString {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Values,

        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ($Values -notcontains $Value) {
        return @($Values + $Value)
    }
    return $Values
}

function Get-PublicReleaseNextSteps {
    param(
        [Parameter(Mandatory = $true)]
        [object]$SigningStatus,

        [Parameter(Mandatory = $true)]
        [object]$MachineSmoke
    )

    $steps = @()
    foreach ($step in $SigningStatus.operator_next_steps) {
        $steps = Add-UniqueString -Values $steps -Value $step
    }
    if ($MachineSmoke.machine_takeover_status -ne 'ready') {
        $steps = Add-UniqueString -Values $steps -Value 'run-machine-takeover-smoke'
        foreach ($blocker in $MachineSmoke.blockers) {
            if ($blocker -eq 'machine-takeover-certification-failed') {
                $steps = Add-UniqueString -Values $steps -Value 'inspect-machine-takeover-certification'
            }
            if ($blocker -eq 'machine-takeover-smoke-not-run') {
                $steps = Add-UniqueString -Values $steps -Value 'rerun-public-release-gate'
            }
        }
    }
    if ($steps.Count -eq 0) {
        $steps = Add-UniqueString -Values $steps -Value 'rerun-public-release-gate'
    }
    return $steps
}

$repoRoot = Resolve-RepoRoot
$exeRelativePath = 'target\release\keli-desktop-shell.exe'
$zipRelativePath = 'target\desktop\keli-desktop-mvp-windows-x64.zip'
$msiRelativePath = 'target\desktop\keli-desktop-mvp-windows-x64.msi'
$installSmokeRelativePath = 'target\desktop-install-smoke\desktop-install-smoke.json'
$msiSmokeRelativePath = 'target\desktop\keli-desktop-msi-smoke.json'
$machineSmokeRelativePath = 'target\desktop\keli-desktop-machine-smoke.json'
$signingRelativePath = 'target\desktop\keli-desktop-signing.json'
$evidenceRelativePath = 'target\desktop\keli-desktop-release-evidence.json'

$exePath = Join-Path $repoRoot $exeRelativePath
$zipPath = Join-Path $repoRoot $zipRelativePath
$msiPath = Join-Path $repoRoot $msiRelativePath
$installSmokePath = Join-Path $repoRoot $installSmokeRelativePath
$msiSmokePath = Join-Path $repoRoot $msiSmokeRelativePath
$machineSmokePath = Join-Path $repoRoot $machineSmokeRelativePath
$signingPath = Join-Path $repoRoot $signingRelativePath
$evidencePath = Join-Path $repoRoot $evidenceRelativePath

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        Write-Output "input $exeRelativePath"
        Write-Output "input $zipRelativePath"
        Write-Output "input $msiRelativePath"
        Write-Output "input $installSmokeRelativePath"
        Write-Output "input $msiSmokeRelativePath"
        Write-Output "input $machineSmokeRelativePath"
        Write-Output "input $signingRelativePath"
        Write-Output 'hash sha256 exe zip msi'
        Write-Output 'signature authenticode exe msi'
        Write-Output 'metadata native_core_default true'
        Write-Output 'metadata public_release_ready false_when_unsigned'
        Write-Output 'metadata public_release_ready false_when_machine_takeover_missing'
        Write-Output 'metadata public_release_ready false_when_signing_missing'
        Write-Output 'metadata signing_store_certificate_candidates_count'
        Write-Output 'metadata signing_operator_next_steps'
        Write-Output 'metadata signing_release_commands'
        Write-Output 'metadata public_release_next_steps'
        Write-Output "output $evidenceRelativePath"
        return
    }

    $artifacts = @(
        (Get-ArtifactEvidence -Kind 'desktop-shell-exe' -Path $exePath -RelativePath $exeRelativePath -IncludeSignature),
        (Get-ArtifactEvidence -Kind 'portable-zip' -Path $zipPath -RelativePath $zipRelativePath),
        (Get-ArtifactEvidence -Kind 'desktop-msi' -Path $msiPath -RelativePath $msiRelativePath -IncludeSignature)
    )
    $installSmoke = Read-SmokeStatus -Name 'install' -Path $installSmokePath -RelativePath $installSmokeRelativePath
    $msiSmoke = Read-SmokeStatus -Name 'msi' -Path $msiSmokePath -RelativePath $msiSmokeRelativePath
    $machineSmoke = Read-MachineSmokeStatus -Path $machineSmokePath -RelativePath $machineSmokeRelativePath
    $signingStatus = Read-SigningStatus -Path $signingPath -RelativePath $signingRelativePath

    $unsignedArtifacts = @($artifacts | Where-Object {
        $_.Contains('signature') -and !$_.signature.signed
    })
    $blockers = @()
    if ($unsignedArtifacts.Count -gt 0) {
        $blockers = Add-UniqueBlocker -Blockers $blockers -Blocker 'artifact-signature-missing'
    }
    foreach ($blocker in $signingStatus.blockers) {
        $blockers = Add-UniqueBlocker -Blockers $blockers -Blocker $blocker
    }
    if ($machineSmoke.machine_takeover_status -ne 'ready') {
        if ($machineSmoke.blockers.Count -gt 0) {
            foreach ($blocker in $machineSmoke.blockers) {
                $blockers = Add-UniqueBlocker -Blockers $blockers -Blocker $blocker
            }
        } else {
            $blockers = Add-UniqueBlocker -Blockers $blockers -Blocker 'machine-takeover-smoke-not-ready'
        }
    }
    $publicReleaseReady = ($blockers.Count -eq 0)
    $publicReleaseNextSteps = Get-PublicReleaseNextSteps -SigningStatus $signingStatus -MachineSmoke $machineSmoke

    $evidence = [ordered]@{
        status = 'passed'
        version = Get-WorkspaceVersion -CargoToml (Join-Path $repoRoot 'Cargo.toml')
        native_core_default = $true
        public_release_ready = $publicReleaseReady
        public_release_blockers = $blockers
        public_release_next_steps = $publicReleaseNextSteps
        artifacts = $artifacts
        signing = $signingStatus
        smoke = [ordered]@{
            install = $installSmoke
            msi = $msiSmoke
            machine = $machineSmoke
        }
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $evidencePath) | Out-Null
    $evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $evidencePath -Encoding ASCII
    Write-Host "Desktop release evidence written: $evidencePath"
} finally {
    Pop-Location
}
