[CmdletBinding()]
param(
    [switch]$PlanOnly,
    [switch]$IncludeMachineTakeover
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoRoot {
    $scriptDir = Split-Path -Parent $PSCommandPath
    return (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
}

function New-GateStep {
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

function New-MachineSmokeCommand {
    param(
        [switch]$IncludeMachineTakeover
    )

    $command = @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-machine-smoke.ps1')
    if ($IncludeMachineTakeover) {
        $command += '-IncludeMachineTakeover'
        $command += @('-MachineTakeoverAttempts', '2')
    }
    return $command
}

function Get-DesktopMvpGateSteps {
    param(
        [switch]$IncludeMachineTakeover
    )

    @(
        New-GateStep -Name 'Format check' -Command @('cargo', 'fmt', '--check')
        New-GateStep -Name 'Diff whitespace check' -Command @('git', 'diff', '--check')
        New-GateStep -Name 'Desktop backend tests' -Command @('cargo', 'test', '-p', 'keli-desktop', '--', '--test-threads=1')
        New-GateStep -Name 'Desktop shell tests' -Command @('cargo', 'test', '-p', 'keli-desktop-shell')
        New-GateStep -Name 'Desktop shell check' -Command @('cargo', 'check', '-p', 'keli-desktop-shell')
        New-GateStep -Name 'Desktop shell release build' -Command @('cargo', 'build', '--release', '-p', 'keli-desktop-shell')
        New-GateStep -Name 'Desktop portable package' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-package.ps1', '-SkipBuild')
        New-GateStep -Name 'Desktop install smoke' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-install-smoke.ps1')
        New-GateStep -Name 'Desktop MSI installer' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-msi.ps1')
        New-GateStep -Name 'Desktop machine smoke evidence' -Command (New-MachineSmokeCommand -IncludeMachineTakeover:$IncludeMachineTakeover)
        New-GateStep -Name 'Desktop signing evidence' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-signing.ps1')
        New-GateStep -Name 'Desktop release evidence' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-release-evidence.ps1')
        New-GateStep -Name 'Desktop unsigned beta RC' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-beta-rc.ps1')
        New-GateStep -Name 'Desktop beta RC delivery audit' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-beta-rc-audit.ps1')
        New-GateStep -Name 'Desktop MVP status audit' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-mvp-status.ps1', '-FailOnMvpBlocked')
    )
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

function Invoke-GateStep {
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

$repoRoot = Resolve-RepoRoot
$artifactPath = Join-Path $repoRoot 'target\release\keli-desktop-shell.exe'
$steps = Get-DesktopMvpGateSteps -IncludeMachineTakeover:$IncludeMachineTakeover

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        foreach ($step in $steps) {
            Write-Output (Format-StepCommand -Command $step.Command)
        }
        Write-Output 'artifact target\release\keli-desktop-shell.exe'
        Write-Output 'artifact target\desktop\keli-desktop-mvp-windows-x64.zip'
        Write-Output 'artifact target\desktop\keli-desktop-mvp-windows-x64.msi'
        Write-Output 'artifact target\desktop\keli-desktop-msi-smoke.json'
        Write-Output 'artifact target\desktop\keli-desktop-machine-smoke.json'
        Write-Output 'artifact target\desktop\keli-desktop-signing.json'
        Write-Output 'artifact target\desktop\keli-desktop-release-evidence.json'
        Write-Output 'artifact target\desktop\keli-desktop-unsigned-beta-manifest.json'
        Write-Output 'artifact target\desktop\keli-desktop-unsigned-beta-release-notes.md'
        Write-Output 'artifact target\desktop\keli-desktop-beta-rc-audit.json'
        Write-Output 'artifact target\desktop-install-smoke\desktop-install-smoke.json'
        return
    }

    foreach ($step in $steps) {
        Invoke-GateStep -Step $step
    }

    if (!(Test-Path -LiteralPath $artifactPath)) {
        throw "release artifact was not produced: $artifactPath"
    }

    Write-Host "Desktop MVP gate passed: $artifactPath"
} finally {
    Pop-Location
}
