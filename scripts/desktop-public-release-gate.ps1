[CmdletBinding()]
param(
    [switch]$PlanOnly,
    [switch]$SkipGate,
    [string]$EvidencePath
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
        throw "required public release evidence is missing: $Path"
    }
}

function Invoke-CommandLine {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Command
    )

    $executable = $Command[0]
    $arguments = @()
    if ($Command.Count -gt 1) {
        $arguments = $Command[1..($Command.Count - 1)]
    }

    & $executable @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "command failed with exit code $LASTEXITCODE`: $($Command -join ' ')"
    }
}

function Read-ReleaseEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    Require-File -Path $Path
    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
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

function Get-OptionalSigningDiagnostics {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Evidence
    )

    if (!(Test-JsonProperty -InputObject $Evidence -Name 'signing')) {
        return ''
    }

    $signing = $Evidence.signing
    $parts = @()
    if (Test-JsonProperty -InputObject $signing -Name 'status') {
        $parts += "signing_status=$([string]$signing.status)"
    }
    if (Test-JsonProperty -InputObject $signing -Name 'mode') {
        $parts += "signing_mode=$([string]$signing.mode)"
    }
    if (Test-JsonProperty -InputObject $signing -Name 'signtool_available') {
        $parts += "signing_signtool_available=$(([bool]$signing.signtool_available).ToString().ToLowerInvariant())"
    }
    if (Test-JsonProperty -InputObject $signing -Name 'signing_method') {
        $method = [string]$signing.signing_method
        if ([string]::IsNullOrWhiteSpace($method)) {
            $method = 'none'
        }
        $parts += "signing_method=$method"
    }
    if (Test-JsonProperty -InputObject $signing -Name 'certificate_subject_match_count') {
        $parts += "signing_certificate_subject_matches=$([int]$signing.certificate_subject_match_count)"
    }

    $unsignedArtifacts = @(Get-StringArrayProperty -InputObject $signing -Name 'unsigned_artifacts')
    if ($unsignedArtifacts.Count -gt 0) {
        $parts += "signing_unsigned_artifacts=$($unsignedArtifacts -join ',')"
    }

    $verificationFailures = @(Get-StringArrayProperty -InputObject $signing -Name 'sign_verification_failures')
    if ($verificationFailures.Count -gt 0) {
        $parts += "signing_verification_failures=$($verificationFailures -join ',')"
    }

    if (Test-JsonProperty -InputObject $signing -Name 'sign_command_previews') {
        $previewArtifacts = @($signing.sign_command_previews |
            ForEach-Object { [string]$_.artifact } |
            Where-Object { ![string]::IsNullOrWhiteSpace($_) })
        if ($previewArtifacts.Count -gt 0) {
            $parts += "signing_command_previews_count=$($previewArtifacts.Count)"
            $parts += "signing_command_preview_artifacts=$($previewArtifacts -join ',')"
        }
    }

    if ($parts.Count -eq 0) {
        return ''
    }
    return $parts -join ' '
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

function Add-WorkflowEvidenceBlockers {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Blockers,

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
    if ($Evidence.smoke.install.readme_subscription_import -ne 'subscription-url-or-config') {
        $Blockers = Add-UniqueBlocker -Blockers $Blockers -Blocker 'install-readme-subscription-evidence-missing'
    }
    if (!(Test-StringArrayContainsAll -Values $Evidence.smoke.install.manual_smoke_cases -Expected $expectedWorkflows)) {
        $Blockers = Add-UniqueBlocker -Blockers $Blockers -Blocker 'install-manual-smoke-cases-missing'
    }
    if (!(Test-StringArrayContainsAll -Values $Evidence.smoke.install.verified_ui_workflow_entrypoints -Expected $expectedWorkflows)) {
        $Blockers = Add-UniqueBlocker -Blockers $Blockers -Blocker 'install-ui-workflow-entrypoints-missing'
    }
    if ($Evidence.smoke.msi.readme_subscription_import -ne 'subscription-url-or-config') {
        $Blockers = Add-UniqueBlocker -Blockers $Blockers -Blocker 'msi-readme-subscription-evidence-missing'
    }
    if (!(Test-StringArrayContainsAll -Values $Evidence.smoke.msi.manual_smoke_cases -Expected $expectedWorkflows)) {
        $Blockers = Add-UniqueBlocker -Blockers $Blockers -Blocker 'msi-manual-smoke-cases-missing'
    }
    return $Blockers
}

function Get-ReleaseBlockers {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Evidence
    )

    $blockers = @()
    if ($Evidence.public_release_ready -ne $true) {
        if ($null -ne $Evidence.public_release_blockers) {
            $blockers += @($Evidence.public_release_blockers | ForEach-Object { [string]$_ })
        }
        if ($blockers.Count -eq 0) {
            $blockers += 'public-release-not-ready'
        }
    }
    if ($Evidence.smoke.machine.machine_takeover_status -ne 'ready') {
        $blockers = Add-UniqueBlocker -Blockers $blockers -Blocker 'machine-takeover-not-ready'
    }
    $blockers = Add-WorkflowEvidenceBlockers -Blockers $blockers -Evidence $Evidence
    if ($Evidence.signing.can_sign -ne $true) {
        $blockers = Add-UniqueBlocker -Blockers $blockers -Blocker 'signing-certificate-missing'
    }
    if ($null -ne $Evidence.public_release_blockers -and @($Evidence.public_release_blockers).Count -gt 0) {
        foreach ($blocker in $Evidence.public_release_blockers) {
            $blockers = Add-UniqueBlocker -Blockers $blockers -Blocker ([string]$blocker)
        }
    }
    return @($blockers | Select-Object -Unique)
}

function Get-ReleaseNextSteps {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Evidence
    )

    if ($null -ne $Evidence.PSObject.Properties['public_release_next_steps']) {
        return @($Evidence.public_release_next_steps | ForEach-Object { [string]$_ })
    }
    if ($null -ne $Evidence.signing -and $null -ne $Evidence.signing.PSObject.Properties['operator_next_steps']) {
        return @($Evidence.signing.operator_next_steps | ForEach-Object { [string]$_ })
    }
    return @()
}

$repoRoot = Resolve-RepoRoot
$releaseEvidenceRelativePath = 'target\desktop\keli-desktop-release-evidence.json'
if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    $EvidencePath = Join-Path $repoRoot $releaseEvidenceRelativePath
}
$mvpGateCommand = @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-mvp-gate.ps1', '-IncludeMachineTakeover')

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        Write-Output 'command powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1 -IncludeMachineTakeover'
        Write-Output "input $releaseEvidenceRelativePath"
        Write-Output 'config -EvidencePath optional'
        Write-Output 'require public_release_ready true'
        Write-Output 'require smoke.machine.machine_takeover_status ready'
        Write-Output 'require smoke.install.verified_ui_workflow_entrypoints all_manual_smoke'
        Write-Output 'require smoke.install.readme_subscription_import subscription-url-or-config'
        Write-Output 'require smoke.msi.manual_smoke_cases all_manual_smoke'
        Write-Output 'require smoke.msi.readme_subscription_import subscription-url-or-config'
        Write-Output 'require signing.can_sign true'
        Write-Output 'require public_release_blockers empty'
        Write-Output 'failure print blockers and exit nonzero'
        Write-Output 'failure print blockers next_steps and exit nonzero'
        Write-Output 'failure print signing diagnostics when available'
        Write-Output 'failure print signing command preview diagnostics when available'
        Write-Output 'output public release gate passed'
        return
    }

    if (!$SkipGate) {
        Invoke-CommandLine -Command $mvpGateCommand
    }

    $evidence = Read-ReleaseEvidence -Path $EvidencePath
    if ($evidence.status -ne 'passed') {
        throw "release evidence status mismatch: $($evidence.status)"
    }

    $blockers = Get-ReleaseBlockers -Evidence $evidence
    if ($blockers.Count -gt 0) {
        $nextSteps = Get-ReleaseNextSteps -Evidence $evidence
        $diagnostics = Get-OptionalSigningDiagnostics -Evidence $evidence
        $diagnosticSuffix = if ([string]::IsNullOrWhiteSpace($diagnostics)) { '' } else { " $diagnostics" }
        if ($nextSteps.Count -gt 0) {
            throw "Desktop public release gate blocked: $($blockers -join ',') next_steps=$($nextSteps -join ',')$diagnosticSuffix"
        }
        throw "Desktop public release gate blocked: $($blockers -join ',')$diagnosticSuffix"
    }

    Write-Host 'Desktop public release gate passed'
} finally {
    Pop-Location
}
