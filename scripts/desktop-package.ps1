[CmdletBinding()]
param(
    [switch]$PlanOnly,
    [switch]$SkipBuild
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

function Write-PortableReadme {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    @(
        'Keli Desktop MVP Portable Package',
        '',
        'Run keli-desktop-shell.exe to open the tray-first desktop client.',
        'The native Keli core is embedded in this executable and is used as the default runtime.',
        'Microsoft Edge WebView2 Runtime is required on Windows for the desktop window.',
        'TUN mode requires Wintun. If Wintun is missing, use system proxy mode or install Wintun before TUN smoke testing.',
        'Support bundles exported from the UI are saved under %USERPROFILE%\Documents\Keli\Support.',
        '',
        'Manual smoke checklist:',
        '1. Open keli-desktop-shell.exe without a command prompt.',
        '2. Import a subscription URL or local subscription config.',
        '3. Select a node.',
        '4. Start and stop system proxy mode and confirm Windows proxy state is restored.',
        '5. Run TUN preflight and confirm Wintun state is clear.',
        '6. Export a support bundle from Diagnostics.'
    ) | Set-Content -LiteralPath $Path -Encoding ASCII
}

function Write-PortableManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Version
    )

    $manifest = [ordered]@{
        name = 'keli-desktop-mvp'
        version = $Version
        platform = 'windows-x64'
        executable = 'keli-desktop-shell.exe'
        native_core_default = $true
        package_type = 'portable-zip'
        requires = @(
            'Microsoft Edge WebView2 Runtime',
            'Wintun for TUN mode'
        )
        support_bundle_directory = '%USERPROFILE%\Documents\Keli\Support'
        manual_smoke = @(
            'open-desktop-shell',
            'import-subscription',
            'select-node',
            'start-stop-system-proxy',
            'tun-preflight',
            'export-support-bundle'
        )
    }

    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Path -Encoding ASCII
}

$repoRoot = Resolve-RepoRoot
$version = Get-WorkspaceVersion -CargoToml (Join-Path $repoRoot 'Cargo.toml')
$releaseExe = Join-Path $repoRoot 'target\release\keli-desktop-shell.exe'
$stageDir = Join-Path $repoRoot 'target\desktop\keli-desktop-mvp-windows-x64'
$zipPath = Join-Path $repoRoot 'target\desktop\keli-desktop-mvp-windows-x64.zip'
$stageExe = Join-Path $stageDir 'keli-desktop-shell.exe'
$readmePath = Join-Path $stageDir 'README.txt'
$manifestPath = Join-Path $stageDir 'keli-desktop-manifest.json'

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        if (!$SkipBuild) {
            Write-Output 'cargo build --release -p keli-desktop-shell'
        }
        Write-Output 'stage target\desktop\keli-desktop-mvp-windows-x64'
        Write-Output 'file target\desktop\keli-desktop-mvp-windows-x64\keli-desktop-shell.exe'
        Write-Output 'file target\desktop\keli-desktop-mvp-windows-x64\README.txt'
        Write-Output 'readme manual_smoke import-subscription-url-or-config'
        Write-Output 'file target\desktop\keli-desktop-mvp-windows-x64\keli-desktop-manifest.json'
        Write-Output 'zip target\desktop\keli-desktop-mvp-windows-x64.zip'
        return
    }

    if (!$SkipBuild) {
        cargo build --release -p keli-desktop-shell
        if ($LASTEXITCODE -ne 0) {
            throw "desktop shell release build failed with exit code $LASTEXITCODE"
        }
    }

    if (!(Test-Path -LiteralPath $releaseExe)) {
        throw "release executable was not found: $releaseExe"
    }

    New-Item -ItemType Directory -Force -Path $stageDir | Out-Null
    Copy-Item -LiteralPath $releaseExe -Destination $stageExe -Force
    Write-PortableReadme -Path $readmePath
    Write-PortableManifest -Path $manifestPath -Version $version

    $zipInputs = @($stageExe, $readmePath, $manifestPath)
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $zipPath) | Out-Null
    Compress-Archive -Path $zipInputs -DestinationPath $zipPath -Force

    Write-Host "Desktop portable package staged: $stageDir"
    Write-Host "Desktop portable package zip: $zipPath"
} finally {
    Pop-Location
}
