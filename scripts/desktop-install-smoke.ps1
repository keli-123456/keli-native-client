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

function Assert-PathInside {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Parent,

        [Parameter(Mandatory = $true)]
        [string]$Child
    )

    $parentPath = (Resolve-Path -LiteralPath $Parent).Path.TrimEnd('\') + '\'
    $childFullPath = [System.IO.Path]::GetFullPath($Child)
    if (!$childFullPath.StartsWith($parentPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to operate outside expected directory: $childFullPath"
    }
}

function Require-File {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "required installed file is missing: $Path"
    }
}

function Require-SmokeCase {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (!($Manifest.manual_smoke -contains $Name)) {
        throw "manifest manual_smoke is missing: $Name"
    }
}

$repoRoot = Resolve-RepoRoot
$zipPath = Join-Path $repoRoot 'target\desktop\keli-desktop-mvp-windows-x64.zip'
$smokeRoot = Join-Path $repoRoot 'target\desktop-install-smoke'
$installDir = Join-Path $smokeRoot 'Keli'
$exePath = Join-Path $installDir 'keli-desktop-shell.exe'
$readmePath = Join-Path $installDir 'README.txt'
$manifestPath = Join-Path $installDir 'keli-desktop-manifest.json'
$resultPath = Join-Path $smokeRoot 'desktop-install-smoke.json'

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        Write-Output 'input target\desktop\keli-desktop-mvp-windows-x64.zip'
        Write-Output 'install target\desktop-install-smoke\Keli'
        Write-Output 'check target\desktop-install-smoke\Keli\keli-desktop-shell.exe'
        Write-Output 'check target\desktop-install-smoke\Keli\README.txt'
        Write-Output 'check target\desktop-install-smoke\Keli\keli-desktop-manifest.json'
        Write-Output 'manifest native_core_default true'
        Write-Output 'manifest manual_smoke import-subscription'
        Write-Output 'result target\desktop-install-smoke\desktop-install-smoke.json'
        return
    }

    if (!(Test-Path -LiteralPath $zipPath -PathType Leaf)) {
        throw "desktop portable package zip was not found: $zipPath"
    }

    New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'target') | Out-Null
    New-Item -ItemType Directory -Force -Path $smokeRoot | Out-Null
    Assert-PathInside -Parent (Join-Path $repoRoot 'target') -Child $smokeRoot
    Assert-PathInside -Parent $smokeRoot -Child $installDir

    if (Test-Path -LiteralPath $installDir) {
        Remove-Item -LiteralPath $installDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null

    Expand-Archive -LiteralPath $zipPath -DestinationPath $installDir -Force

    Require-File -Path $exePath
    Require-File -Path $readmePath
    Require-File -Path $manifestPath

    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    if ($manifest.executable -ne 'keli-desktop-shell.exe') {
        throw "manifest executable mismatch: $($manifest.executable)"
    }
    if ($manifest.native_core_default -ne $true) {
        throw 'manifest native_core_default must be true'
    }
    if ($manifest.package_type -ne 'portable-zip') {
        throw "manifest package_type mismatch: $($manifest.package_type)"
    }
    foreach ($case in @('open-desktop-shell', 'import-subscription', 'select-node', 'start-stop-system-proxy', 'tun-preflight', 'export-support-bundle')) {
        Require-SmokeCase -Manifest $manifest -Name $case
    }

    $result = [ordered]@{
        status = 'passed'
        package = 'target\desktop\keli-desktop-mvp-windows-x64.zip'
        install_dir = 'target\desktop-install-smoke\Keli'
        executable = 'keli-desktop-shell.exe'
        native_core_default = $true
        manual_smoke_cases = $manifest.manual_smoke
    }
    $result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $resultPath -Encoding ASCII

    Write-Host "Desktop install smoke passed: $resultPath"
} finally {
    Pop-Location
}
