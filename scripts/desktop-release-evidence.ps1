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

$repoRoot = Resolve-RepoRoot
$exeRelativePath = 'target\release\keli-desktop-shell.exe'
$zipRelativePath = 'target\desktop\keli-desktop-mvp-windows-x64.zip'
$msiRelativePath = 'target\desktop\keli-desktop-mvp-windows-x64.msi'
$installSmokeRelativePath = 'target\desktop-install-smoke\desktop-install-smoke.json'
$msiSmokeRelativePath = 'target\desktop\keli-desktop-msi-smoke.json'
$evidenceRelativePath = 'target\desktop\keli-desktop-release-evidence.json'

$exePath = Join-Path $repoRoot $exeRelativePath
$zipPath = Join-Path $repoRoot $zipRelativePath
$msiPath = Join-Path $repoRoot $msiRelativePath
$installSmokePath = Join-Path $repoRoot $installSmokeRelativePath
$msiSmokePath = Join-Path $repoRoot $msiSmokeRelativePath
$evidencePath = Join-Path $repoRoot $evidenceRelativePath

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        Write-Output "input $exeRelativePath"
        Write-Output "input $zipRelativePath"
        Write-Output "input $msiRelativePath"
        Write-Output "input $installSmokeRelativePath"
        Write-Output "input $msiSmokeRelativePath"
        Write-Output 'hash sha256 exe zip msi'
        Write-Output 'signature authenticode exe msi'
        Write-Output 'metadata native_core_default true'
        Write-Output 'metadata public_release_ready false_when_unsigned'
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

    $unsignedArtifacts = @($artifacts | Where-Object {
        $_.Contains('signature') -and !$_.signature.signed
    })
    $publicReleaseReady = ($unsignedArtifacts.Count -eq 0)
    $blockers = @()
    if (!$publicReleaseReady) {
        $blockers += 'artifact-signature-missing'
    }

    $evidence = [ordered]@{
        status = 'passed'
        version = Get-WorkspaceVersion -CargoToml (Join-Path $repoRoot 'Cargo.toml')
        native_core_default = $true
        public_release_ready = $publicReleaseReady
        public_release_blockers = $blockers
        artifacts = $artifacts
        smoke = [ordered]@{
            install = $installSmoke
            msi = $msiSmoke
        }
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $evidencePath) | Out-Null
    $evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $evidencePath -Encoding ASCII
    Write-Host "Desktop release evidence written: $evidencePath"
} finally {
    Pop-Location
}
