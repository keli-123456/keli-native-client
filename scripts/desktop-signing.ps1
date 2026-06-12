[CmdletBinding()]
param(
    [switch]$PlanOnly,
    [switch]$Sign,
    [string]$SignToolPath = $env:KELI_SIGNTOOL_PATH,
    [string]$CertificatePath = $env:KELI_SIGN_CERT_PATH,
    [string]$CertificatePassword = $env:KELI_SIGN_CERT_PASSWORD,
    [string]$CertificateSubject = $env:KELI_SIGN_CERT_SUBJECT,
    [string]$TimestampUrl = $env:KELI_SIGN_TIMESTAMP_URL,
    [switch]$SkipCertificateStoreDiscovery
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($TimestampUrl)) {
    $TimestampUrl = 'http://timestamp.digicert.com'
}

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
        throw "required signing input is missing: $Path"
    }
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

function Find-SignTool {
    param(
        [AllowNull()]
        [string]$ConfiguredPath
    )

    $candidates = @()
    if (![string]::IsNullOrWhiteSpace($ConfiguredPath)) {
        $candidates = Add-UniqueString -Values $candidates -Value $ConfiguredPath
    }

    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        $candidates = Add-UniqueString -Values $candidates -Value $command.Source
    }

    $kitRoot = 'C:\Program Files (x86)\Windows Kits\10'
    if (Test-Path -LiteralPath $kitRoot) {
        $patterns = @(
            (Join-Path $kitRoot 'bin\*\x64\signtool.exe'),
            (Join-Path $kitRoot 'App Certification Kit\signtool.exe'),
            (Join-Path $kitRoot 'bin\*\x86\signtool.exe'),
            (Join-Path $kitRoot 'bin\*\arm64\signtool.exe')
        )
        foreach ($pattern in $patterns) {
            $kitTools = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue |
                Sort-Object FullName -Descending |
                ForEach-Object { $_.FullName }
            foreach ($path in $kitTools) {
                $candidates = Add-UniqueString -Values $candidates -Value $path
            }
        }
    }

    foreach ($path in $candidates) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            return [ordered]@{
                available = $true
                path = $path
                searched_paths = $candidates
            }
        }
    }

    [ordered]@{
        available = $false
        path = $null
        searched_paths = $candidates
    }
}

function Get-CodeSigningCertificateCandidates {
    param(
        [switch]$SkipDiscovery
    )

    $stores = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')
    if ($SkipDiscovery) {
        return [ordered]@{
            enabled = $false
            stores = $stores
            candidates = @()
            count = 0
        }
    }

    $candidates = @()
    foreach ($store in $stores) {
        if (!(Test-Path -LiteralPath $store)) {
            continue
        }

        $certificates = Get-ChildItem -Path $store -CodeSigningCert -ErrorAction SilentlyContinue
        foreach ($certificate in $certificates) {
            $candidates += [ordered]@{
                store = $store
                subject = [string]$certificate.Subject
                thumbprint = [string]$certificate.Thumbprint
                not_after = $certificate.NotAfter.ToUniversalTime().ToString('o')
                has_private_key = [bool]$certificate.HasPrivateKey
            }
        }
    }

    [ordered]@{
        enabled = $true
        stores = $stores
        candidates = $candidates
        count = $candidates.Count
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

function Get-SignableArtifactEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Kind,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    Require-File -Path $Path
    [ordered]@{
        kind = $Kind
        path = $RelativePath
        signature = Get-SignatureEvidence -Path $Path
    }
}

function Get-SigningConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [object]$SignTool,

        [AllowNull()]
        [string]$ConfiguredCertificatePath,

        [AllowNull()]
        [string]$ConfiguredCertificatePassword,

        [AllowNull()]
        [string]$ConfiguredCertificateSubject,

        [Parameter(Mandatory = $true)]
        [object]$CertificateStoreDiscovery,

        [Parameter(Mandatory = $true)]
        [string]$ConfiguredTimestampUrl
    )

    $pathConfigured = ![string]::IsNullOrWhiteSpace($ConfiguredCertificatePath)
    $pathExists = $pathConfigured -and (Test-Path -LiteralPath $ConfiguredCertificatePath -PathType Leaf)
    $subjectConfigured = ![string]::IsNullOrWhiteSpace($ConfiguredCertificateSubject)
    $method = $null
    if ($pathExists) {
        $method = 'pfx'
    } elseif ($subjectConfigured) {
        $method = 'store-subject'
    }

    [ordered]@{
        certificate_path_configured = $pathConfigured
        certificate_path_exists = $pathExists
        certificate_subject_configured = $subjectConfigured
        certificate_password_configured = ![string]::IsNullOrWhiteSpace($ConfiguredCertificatePassword)
        timestamp_url = $ConfiguredTimestampUrl
        signing_method = $method
        store_certificate_discovery = [ordered]@{
            enabled = [bool]$CertificateStoreDiscovery.enabled
            stores = @($CertificateStoreDiscovery.stores)
        }
        store_certificate_candidates_count = [int]$CertificateStoreDiscovery.count
        store_certificate_candidates = @($CertificateStoreDiscovery.candidates)
        can_sign = ([bool]$SignTool.available -and $null -ne $method)
    }
}

function Get-ReleaseCommands {
    [ordered]@{
        inspect = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1'
        sign = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign'
        public_release_gate = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1'
    }
}

function New-OperatorNextStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string]$Detail,

        [AllowNull()]
        [string]$Command
    )

    [ordered]@{
        id = $Id
        detail = $Detail
        command = $Command
    }
}

function Add-OperatorNextStep {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Steps,

        [Parameter(Mandatory = $true)]
        [object]$Step
    )

    $existingIds = @($Steps | ForEach-Object { [string]$_.id })
    if ($existingIds -contains [string]$Step.id) {
        return $Steps
    }
    return @($Steps + $Step)
}

function Get-OperatorNextSteps {
    param(
        [Parameter(Mandatory = $true)]
        [object]$SignTool,

        [Parameter(Mandatory = $true)]
        [object]$Configuration,

        [Parameter(Mandatory = $true)]
        [object[]]$Artifacts,

        [Parameter(Mandatory = $true)]
        [string[]]$Blockers,

        [Parameter(Mandatory = $true)]
        [object]$ReleaseCommands
    )

    $steps = @()
    if (!$SignTool.available) {
        $steps = Add-OperatorNextStep -Steps $steps -Step (New-OperatorNextStep `
            -Id 'signtool-missing' `
            -Detail 'Install Windows SDK signtool.exe or set KELI_SIGNTOOL_PATH to signtool.exe.' `
            -Command $null)
    }
    if ($Configuration.certificate_path_configured -and !$Configuration.certificate_path_exists) {
        $steps = Add-OperatorNextStep -Steps $steps -Step (New-OperatorNextStep `
            -Id 'fix-certificate-path' `
            -Detail 'KELI_SIGN_CERT_PATH is configured but the PFX file was not found; set it to an existing code-signing PFX.' `
            -Command $null)
    }
    if (!$Configuration.certificate_path_exists -and !$Configuration.certificate_subject_configured) {
        if ($Configuration.store_certificate_candidates_count -gt 0) {
            $steps = Add-OperatorNextStep -Steps $steps -Step (New-OperatorNextStep `
                -Id 'choose-store-certificate-subject' `
                -Detail 'A code-signing certificate exists in the Windows certificate store; set KELI_SIGN_CERT_SUBJECT to the certificate subject before signing.' `
                -Command $null)
        } else {
            $steps = Add-OperatorNextStep -Steps $steps -Step (New-OperatorNextStep `
                -Id 'configure-code-signing-certificate' `
                -Detail 'Provide a trusted code-signing certificate with KELI_SIGN_CERT_PATH or KELI_SIGN_CERT_SUBJECT before public release signing.' `
                -Command $null)
        }
    }

    $unsignedArtifacts = @($Artifacts | Where-Object { !$_.signature.signed })
    if ($unsignedArtifacts.Count -gt 0) {
        $steps = Add-OperatorNextStep -Steps $steps -Step (New-OperatorNextStep `
            -Id 'run-desktop-signing-sign' `
            -Detail 'After certificate configuration is ready, sign the desktop EXE and MSI artifacts.' `
            -Command $ReleaseCommands.sign)
    }
    if ($Blockers.Count -gt 0) {
        $steps = Add-OperatorNextStep -Steps $steps -Step (New-OperatorNextStep `
            -Id 'run-public-release-gate' `
            -Detail 'After signing succeeds, rerun the hard public release gate to regenerate evidence and confirm readiness.' `
            -Command $ReleaseCommands.public_release_gate)
    }

    return $steps
}

function Invoke-SignToolSign {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SignTool,

        [Parameter(Mandatory = $true)]
        [string]$ArtifactPath,

        [Parameter(Mandatory = $true)]
        [object]$Configuration,

        [AllowNull()]
        [string]$ConfiguredCertificatePath,

        [AllowNull()]
        [string]$ConfiguredCertificatePassword,

        [AllowNull()]
        [string]$ConfiguredCertificateSubject
    )

    $arguments = @('sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', $Configuration.timestamp_url)
    if ($Configuration.signing_method -eq 'pfx') {
        $arguments += @('/f', $ConfiguredCertificatePath)
        if (![string]::IsNullOrWhiteSpace($ConfiguredCertificatePassword)) {
            $arguments += @('/p', $ConfiguredCertificatePassword)
        }
    } elseif ($Configuration.signing_method -eq 'store-subject') {
        $arguments += @('/n', $ConfiguredCertificateSubject)
    } else {
        throw 'signing configuration does not provide a signing method'
    }
    $arguments += $ArtifactPath

    & $SignTool @arguments | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "signtool failed with exit code $LASTEXITCODE for $ArtifactPath"
    }
}

$repoRoot = Resolve-RepoRoot
$exeRelativePath = 'target\release\keli-desktop-shell.exe'
$msiRelativePath = 'target\desktop\keli-desktop-mvp-windows-x64.msi'
$evidenceRelativePath = 'target\desktop\keli-desktop-signing.json'
$exePath = Join-Path $repoRoot $exeRelativePath
$msiPath = Join-Path $repoRoot $msiRelativePath
$evidencePath = Join-Path $repoRoot $evidenceRelativePath

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        Write-Output "input $exeRelativePath"
        Write-Output "input $msiRelativePath"
        Write-Output 'discover signtool.exe'
        Write-Output 'config KELI_SIGNTOOL_PATH optional'
        Write-Output 'config KELI_SIGN_CERT_PATH optional_pfx'
        Write-Output 'config KELI_SIGN_CERT_SUBJECT optional_store_subject'
        Write-Output 'config KELI_SIGN_CERT_PASSWORD optional_secret'
        Write-Output 'config KELI_SIGN_TIMESTAMP_URL default http://timestamp.digicert.com'
        Write-Output 'discover certificate_store_code_signing_candidates'
        Write-Output 'config -SkipCertificateStoreDiscovery deterministic_tests'
        Write-Output 'mode inspect default'
        Write-Output 'mode sign requires -Sign'
        Write-Output 'metadata public_release_blocker artifact-signature-missing'
        Write-Output 'metadata public_release_blocker signing-certificate-missing'
        Write-Output 'metadata operator_next_steps'
        Write-Output 'metadata release_commands'
        Write-Output "output $evidenceRelativePath"
        return
    }

    Require-File -Path $exePath
    Require-File -Path $msiPath

    $signTool = Find-SignTool -ConfiguredPath $SignToolPath
    $certificateStoreDiscovery = Get-CodeSigningCertificateCandidates -SkipDiscovery:$SkipCertificateStoreDiscovery
    $configuration = Get-SigningConfiguration `
        -SignTool $signTool `
        -ConfiguredCertificatePath $CertificatePath `
        -ConfiguredCertificatePassword $CertificatePassword `
        -ConfiguredCertificateSubject $CertificateSubject `
        -CertificateStoreDiscovery $certificateStoreDiscovery `
        -ConfiguredTimestampUrl $TimestampUrl

    if ($Sign) {
        if (!$signTool.available) {
            throw 'signtool.exe is required when -Sign is supplied'
        }
        if (!$configuration.can_sign) {
            throw 'a configured PFX path or certificate store subject is required when -Sign is supplied'
        }
        Invoke-SignToolSign -SignTool $signTool.path -ArtifactPath $exePath -Configuration $configuration -ConfiguredCertificatePath $CertificatePath -ConfiguredCertificatePassword $CertificatePassword -ConfiguredCertificateSubject $CertificateSubject
        Invoke-SignToolSign -SignTool $signTool.path -ArtifactPath $msiPath -Configuration $configuration -ConfiguredCertificatePath $CertificatePath -ConfiguredCertificatePassword $CertificatePassword -ConfiguredCertificateSubject $CertificateSubject
    }

    $artifacts = @(
        (Get-SignableArtifactEvidence -Kind 'desktop-shell-exe' -Path $exePath -RelativePath $exeRelativePath),
        (Get-SignableArtifactEvidence -Kind 'desktop-msi' -Path $msiPath -RelativePath $msiRelativePath)
    )

    $blockers = @()
    if (@($artifacts | Where-Object { !$_.signature.signed }).Count -gt 0) {
        $blockers = Add-UniqueString -Values $blockers -Value 'artifact-signature-missing'
    }
    if (!$configuration.can_sign) {
        $blockers = Add-UniqueString -Values $blockers -Value 'signing-certificate-missing'
    }
    if (!$signTool.available) {
        $blockers = Add-UniqueString -Values $blockers -Value 'signtool-missing'
    }

    $releaseCommands = Get-ReleaseCommands
    $operatorNextSteps = Get-OperatorNextSteps `
        -SignTool $signTool `
        -Configuration $configuration `
        -Artifacts $artifacts `
        -Blockers $blockers `
        -ReleaseCommands $releaseCommands

    $evidence = [ordered]@{
        status = 'passed'
        mode = if ($Sign) { 'sign' } else { 'inspect' }
        signtool = $signTool
        configuration = $configuration
        artifacts = $artifacts
        operator_next_steps = $operatorNextSteps
        release_commands = $releaseCommands
        public_release_ready = ($blockers.Count -eq 0)
        public_release_blockers = $blockers
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $evidencePath) | Out-Null
    $evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $evidencePath -Encoding ASCII
    Write-Host "Desktop signing evidence written: $evidencePath"
} finally {
    Pop-Location
}
