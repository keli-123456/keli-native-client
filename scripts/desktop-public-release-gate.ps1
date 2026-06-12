[CmdletBinding()]
param(
    [switch]$PlanOnly,
    [switch]$SkipGate
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
$releaseEvidencePath = Join-Path $repoRoot $releaseEvidenceRelativePath
$mvpGateCommand = @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-mvp-gate.ps1', '-IncludeMachineTakeover')

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        Write-Output 'command powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1 -IncludeMachineTakeover'
        Write-Output "input $releaseEvidenceRelativePath"
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
        Write-Output 'output public release gate passed'
        return
    }

    if (!$SkipGate) {
        Invoke-CommandLine -Command $mvpGateCommand
    }

    $evidence = Read-ReleaseEvidence -Path $releaseEvidencePath
    if ($evidence.status -ne 'passed') {
        throw "release evidence status mismatch: $($evidence.status)"
    }

    $blockers = Get-ReleaseBlockers -Evidence $evidence
    if ($blockers.Count -gt 0) {
        $nextSteps = Get-ReleaseNextSteps -Evidence $evidence
        if ($nextSteps.Count -gt 0) {
            throw "Desktop public release gate blocked: $($blockers -join ',') next_steps=$($nextSteps -join ',')"
        }
        throw "Desktop public release gate blocked: $($blockers -join ',')"
    }

    Write-Host 'Desktop public release gate passed'
} finally {
    Pop-Location
}
