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

function Require-FileContains {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $content = Get-Content -Raw -LiteralPath $Path
    if (!$content.Contains($Text)) {
        throw "required installed file content is missing from $Path`: $Text"
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

function Require-LaunchSmokeEntrypoint {
    param(
        [Parameter(Mandatory = $true)]
        [object]$LaunchSmoke,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $LaunchSmoke.PSObject.Properties['ui_workflow_entrypoints']) {
        throw 'desktop shell launch smoke ui_workflow_entrypoints is missing'
    }
    if (!($LaunchSmoke.ui_workflow_entrypoints -contains $Name)) {
        throw "desktop shell launch smoke ui_workflow_entrypoints is missing: $Name"
    }
}

function Convert-SmokeOutputToJsonText {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Output,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $text = ($Output | ForEach-Object { [string]$_ }) -join "`n"
    $start = $text.IndexOf('{')
    $end = $text.LastIndexOf('}')
    if ($start -lt 0 -or $end -lt $start) {
        throw "$Name smoke JSON output was not found"
    }
    return $text.Substring($start, $end - $start + 1)
}

function Require-RunningSupportSmokeEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Smoke,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($Smoke.status -ne 'passed') {
        throw "$Name running support smoke status mismatch: $($Smoke.status)"
    }
    if ($Smoke.desktop_status_running -ne $true) {
        throw "$Name running support smoke desktop_status_running must be true"
    }
    if ($Smoke.desktop_status_selected -ne $true) {
        throw "$Name running support smoke desktop_status_selected must be true"
    }
    if ($Smoke.managed_status_selected -ne $true) {
        throw "$Name running support smoke managed_status_selected must be true"
    }
    if ($Smoke.diagnosis_selected -ne $true) {
        throw "$Name running support smoke diagnosis_selected must be true"
    }
    if ($Smoke.redaction_ready -ne $true) {
        throw "$Name running support smoke redaction_ready must be true"
    }
    if ($Smoke.stopped_after_smoke -ne $true) {
        throw "$Name running support smoke stopped_after_smoke must be true"
    }
}

$repoRoot = Resolve-RepoRoot
$zipPath = Join-Path $repoRoot 'target\desktop\keli-desktop-mvp-windows-x64.zip'
$smokeRoot = Join-Path $repoRoot 'target\desktop-install-smoke'
$installDir = Join-Path $smokeRoot 'Keli'
$exePath = Join-Path $installDir 'keli-desktop-shell.exe'
$readmePath = Join-Path $installDir 'README.txt'
$manifestPath = Join-Path $installDir 'keli-desktop-manifest.json'
$launchSmokePath = Join-Path $smokeRoot 'desktop-shell-launch-smoke.json'
$supportExportSmokeDir = Join-Path $smokeRoot 'support-export'
$supportExportSmokePath = Join-Path $smokeRoot 'desktop-support-export-smoke.json'
$runningSupportSmokePath = Join-Path $smokeRoot 'desktop-startup-connect-support-smoke.json'
$resultPath = Join-Path $smokeRoot 'desktop-install-smoke.json'

Push-Location $repoRoot
try {
    if ($PlanOnly) {
        Write-Output 'input target\desktop\keli-desktop-mvp-windows-x64.zip'
        Write-Output 'install target\desktop-install-smoke\Keli'
        Write-Output 'check target\desktop-install-smoke\Keli\keli-desktop-shell.exe'
        Write-Output 'check target\desktop-install-smoke\Keli\README.txt'
        Write-Output 'readme manual_smoke import-subscription-url-or-config'
        Write-Output 'check target\desktop-install-smoke\Keli\keli-desktop-manifest.json'
        Write-Output 'run target\desktop-install-smoke\Keli\keli-desktop-shell.exe --smoke'
        Write-Output 'run target\desktop-install-smoke\Keli\keli-desktop-shell.exe --support-export-smoke target\desktop-install-smoke\support-export'
        Write-Output 'run target\desktop-install-smoke\Keli\keli-desktop-shell.exe --startup-connect-support-smoke'
        Write-Output 'manifest native_core_default true'
        Write-Output 'manifest manual_smoke import-subscription'
        Write-Output 'launch_smoke ui_workflow_entrypoint open-desktop-shell'
        Write-Output 'launch_smoke ui_workflow_entrypoint import-subscription'
        Write-Output 'launch_smoke ui_workflow_entrypoint select-node'
        Write-Output 'launch_smoke ui_workflow_entrypoint start-stop-system-proxy'
        Write-Output 'launch_smoke ui_workflow_entrypoint tun-preflight'
        Write-Output 'launch_smoke ui_workflow_entrypoint export-support-bundle'
        Write-Output 'launch_smoke first_run_dependency_blockers'
        Write-Output 'launch_smoke dependency_action_entrypoint install-wintun'
        Write-Output 'support_export_smoke status passed'
        Write-Output 'support_export_smoke kind keli_desktop_support_bundle'
        Write-Output 'support_export_smoke desktop_dependencies true'
        Write-Output 'running_support_smoke status passed'
        Write-Output 'running_support_smoke desktop_status_running true'
        Write-Output 'running_support_smoke diagnosis_selected true'
        Write-Output 'running_support_smoke stopped_after_smoke true'
        Write-Output 'result target\desktop-install-smoke\desktop-shell-launch-smoke.json'
        Write-Output 'result target\desktop-install-smoke\desktop-support-export-smoke.json'
        Write-Output 'result target\desktop-install-smoke\desktop-startup-connect-support-smoke.json'
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
    Require-FileContains -Path $readmePath -Text 'Import a subscription URL or local subscription config.'
    Require-File -Path $manifestPath

    $launchOutput = & $exePath --smoke
    if ($LASTEXITCODE -ne 0) {
        throw "desktop shell launch smoke failed with exit code $LASTEXITCODE"
    }
    $launchOutput | Set-Content -LiteralPath $launchSmokePath -Encoding ASCII
    $launchSmoke = Get-Content -Raw -LiteralPath $launchSmokePath | ConvertFrom-Json
    if ($launchSmoke.status -ne 'passed') {
        throw "desktop shell launch smoke status mismatch: $($launchSmoke.status)"
    }
    if ($launchSmoke.native_core_default -ne $true) {
        throw 'desktop shell launch smoke native_core_default must be true'
    }
    if ($launchSmoke.html_ready -ne $true) {
        throw 'desktop shell launch smoke html_ready must be true'
    }
    if ($launchSmoke.snapshot_script_ready -ne $true) {
        throw 'desktop shell launch smoke snapshot_script_ready must be true'
    }
    if ($null -eq $launchSmoke.PSObject.Properties['first_run_blockers']) {
        throw 'desktop shell launch smoke first_run_blockers is missing'
    }
    if ($null -eq $launchSmoke.PSObject.Properties['dependency_action_entrypoints']) {
        throw 'desktop shell launch smoke dependency_action_entrypoints is missing'
    }

    New-Item -ItemType Directory -Force -Path $supportExportSmokeDir | Out-Null
    $supportExportOutput = & $exePath --support-export-smoke $supportExportSmokeDir
    if ($LASTEXITCODE -ne 0) {
        throw "desktop shell support export smoke failed with exit code $LASTEXITCODE"
    }
    $supportExportOutput | Set-Content -LiteralPath $supportExportSmokePath -Encoding ASCII
    $supportExportSmoke = Get-Content -Raw -LiteralPath $supportExportSmokePath | ConvertFrom-Json
    if ($supportExportSmoke.status -ne 'passed') {
        throw "desktop shell support export smoke status mismatch: $($supportExportSmoke.status)"
    }
    if ($supportExportSmoke.kind -ne 'keli_desktop_support_bundle') {
        throw "desktop shell support export smoke kind mismatch: $($supportExportSmoke.kind)"
    }
    if ($supportExportSmoke.desktop_dependencies -ne $true) {
        throw 'desktop shell support export smoke desktop_dependencies must be true'
    }

    $runningSupportOutput = & $exePath --startup-connect-support-smoke
    if ($LASTEXITCODE -ne 0) {
        throw "desktop shell running support smoke failed with exit code $LASTEXITCODE"
    }
    $runningSupportJson = Convert-SmokeOutputToJsonText -Output $runningSupportOutput -Name 'desktop shell running support'
    $runningSupportJson | Set-Content -LiteralPath $runningSupportSmokePath -Encoding ASCII
    $runningSupportSmoke = $runningSupportJson | ConvertFrom-Json
    Require-RunningSupportSmokeEvidence -Smoke $runningSupportSmoke -Name 'desktop shell'

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
        Require-LaunchSmokeEntrypoint -LaunchSmoke $launchSmoke -Name $case
    }

    $result = [ordered]@{
        status = 'passed'
        package = 'target\desktop\keli-desktop-mvp-windows-x64.zip'
        install_dir = 'target\desktop-install-smoke\Keli'
        executable = 'keli-desktop-shell.exe'
        native_core_default = $true
        launch_smoke = 'target\desktop-install-smoke\desktop-shell-launch-smoke.json'
        support_export_smoke = 'target\desktop-install-smoke\desktop-support-export-smoke.json'
        support_export_path = [string]$supportExportSmoke.path
        support_export_kind = [string]$supportExportSmoke.kind
        support_export_desktop_dependencies = [bool]$supportExportSmoke.desktop_dependencies
        running_support_smoke = 'target\desktop-install-smoke\desktop-startup-connect-support-smoke.json'
        running_support_desktop_status_running = [bool]$runningSupportSmoke.desktop_status_running
        running_support_desktop_status_selected = [bool]$runningSupportSmoke.desktop_status_selected
        running_support_managed_status_selected = [bool]$runningSupportSmoke.managed_status_selected
        running_support_diagnosis_selected = [bool]$runningSupportSmoke.diagnosis_selected
        running_support_redaction_ready = [bool]$runningSupportSmoke.redaction_ready
        running_support_stopped_after_smoke = [bool]$runningSupportSmoke.stopped_after_smoke
        readme_subscription_import = 'subscription-url-or-config'
        manual_smoke_cases = $manifest.manual_smoke
        verified_ui_workflow_entrypoints = $launchSmoke.ui_workflow_entrypoints
        first_run_system_proxy_ready = [bool]$launchSmoke.first_run_system_proxy_ready
        first_run_tun_ready = [bool]$launchSmoke.first_run_tun_ready
        first_run_blockers = @($launchSmoke.first_run_blockers)
        dependency_action_entrypoints = @($launchSmoke.dependency_action_entrypoints | ForEach-Object { [string]$_ })
    }
    $result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $resultPath -Encoding ASCII

    Write-Host "Desktop install smoke passed: $resultPath"
} finally {
    Pop-Location
}
