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

function Get-DesktopMvpGateSteps {
    @(
        New-GateStep -Name 'Format check' -Command @('cargo', 'fmt', '--check')
        New-GateStep -Name 'Diff whitespace check' -Command @('git', 'diff', '--check')
        New-GateStep -Name 'Desktop backend tests' -Command @('cargo', 'test', '-p', 'keli-desktop', '--', '--test-threads=1')
        New-GateStep -Name 'Desktop shell tests' -Command @('cargo', 'test', '-p', 'keli-desktop-shell')
        New-GateStep -Name 'Desktop shell check' -Command @('cargo', 'check', '-p', 'keli-desktop-shell')
        New-GateStep -Name 'Desktop shell release build' -Command @('cargo', 'build', '--release', '-p', 'keli-desktop-shell')
        New-GateStep -Name 'Desktop portable package' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-package.ps1', '-SkipBuild')
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
$steps = Get-DesktopMvpGateSteps

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        foreach ($step in $steps) {
            Write-Output (Format-StepCommand -Command $step.Command)
        }
        Write-Output 'artifact target\release\keli-desktop-shell.exe'
        Write-Output 'artifact target\desktop\keli-desktop-mvp-windows-x64.zip'
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
