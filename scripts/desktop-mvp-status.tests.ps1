[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$statusScript = Join-Path $scriptDir 'desktop-mvp-status.ps1'

if (!(Test-Path -LiteralPath $statusScript)) {
    throw 'desktop-mvp-status.ps1 was not found'
}

$planOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $statusScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-mvp-status.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $planOutput -join "`n"
$expectedPlan = @(
    'input target\desktop\keli-desktop-release-evidence.json',
    'config -FailOnMvpBlocked optional',
    'read native_core_default artifacts smoke.install smoke.msi smoke.machine signing public_release_blockers public_release_next_steps',
    'require workflow ids open-desktop-shell import-subscription select-node start-stop-system-proxy tun-preflight export-support-bundle',
    'require support-bundle-export workflow and export smoke evidence',
    'require msi-support-bundle-export smoke evidence',
    'require install first_run dependency blockers have action entrypoints',
    'output desktop_mvp_ready and public_release_ready',
    'output json when -Json is provided'
)
foreach ($item in $expectedPlan) {
    if (!$plan.Contains($item)) {
        throw "desktop MVP status plan is missing: $item"
    }
}

$tempDir = Join-Path $repoRoot 'target\desktop-mvp-status-tests'
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
$fixturePath = Join-Path $tempDir 'release-evidence.json'
$workflowIds = @(
    'open-desktop-shell',
    'import-subscription',
    'select-node',
    'start-stop-system-proxy',
    'tun-preflight',
    'export-support-bundle'
)

$fixture = [ordered]@{
    status = 'passed'
    native_core_default = $true
    public_release_ready = $false
    public_release_blockers = @('artifact-signature-missing', 'signing-certificate-missing')
    public_release_next_steps = @('configure-code-signing-certificate', 'run-desktop-signing-sign', 'run-public-release-gate')
    artifacts = @(
        [ordered]@{ kind = 'desktop-shell-exe'; path = 'target\release\keli-desktop-shell.exe' },
        [ordered]@{ kind = 'portable-zip'; path = 'target\desktop\keli-desktop-mvp-windows-x64.zip' },
        [ordered]@{ kind = 'desktop-msi'; path = 'target\desktop\keli-desktop-mvp-windows-x64.msi' }
    )
    signing = [ordered]@{
        can_sign = $false
        signtool_available = $true
        unsigned_artifacts = @('target\release\keli-desktop-shell.exe', 'target\desktop\keli-desktop-mvp-windows-x64.msi')
    }
    smoke = [ordered]@{
        install = [ordered]@{
            status = 'passed'
            native_core_default = $true
            readme_subscription_import = 'subscription-url-or-config'
            manual_smoke_cases = $workflowIds
            verified_ui_workflow_entrypoints = $workflowIds
            support_export_smoke = 'target\desktop-install-smoke\desktop-support-export-smoke.json'
            support_export_kind = 'keli_desktop_support_bundle'
            support_export_desktop_dependencies = $true
            first_run_system_proxy_ready = $true
            first_run_tun_ready = $false
            first_run_blockers = @(
                [ordered]@{
                    code = 'wintun-missing'
                    message = 'Wintun library was not found'
                    action = 'install-wintun'
                }
            )
            dependency_action_entrypoints = @('install-wintun')
        }
        msi = [ordered]@{
            status = 'passed'
            native_core_default = $true
            readme_subscription_import = 'subscription-url-or-config'
            manual_smoke_cases = $workflowIds
            support_export_smoke = 'target\desktop\keli-desktop-msi-support-export-smoke.json'
            support_export_kind = 'keli_desktop_support_bundle'
            support_export_desktop_dependencies = $true
        }
        machine = [ordered]@{
            status = 'passed'
            native_core_default = $true
            machine_takeover_status = 'ready'
        }
    }
}
$fixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $fixturePath -Encoding ASCII

$jsonOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $statusScript -EvidencePath $fixturePath -Json
if ($LASTEXITCODE -ne 0) {
    throw "desktop-mvp-status.ps1 -Json exited with $LASTEXITCODE"
}

$report = $jsonOutput -join "`n" | ConvertFrom-Json
if ($report.desktop_mvp_ready -ne $true) {
    throw 'desktop MVP should be ready when all local workflow/package/machine requirements pass'
}
if ($report.public_release_ready -ne $false) {
    throw 'public release should remain blocked in the unsigned fixture'
}
if (($report.public_release_blockers -join ',') -ne 'artifact-signature-missing,signing-certificate-missing') {
    throw "public release blockers mismatch: $($report.public_release_blockers -join ',')"
}
if (($report.remaining_external_blockers -join ',') -ne 'artifact-signature-missing,signing-certificate-missing') {
    throw "external blockers mismatch: $($report.remaining_external_blockers -join ',')"
}
$requirementStatuses = @{}
foreach ($requirement in $report.requirements) {
    $requirementStatuses[[string]$requirement.id] = [string]$requirement.status
}
foreach ($id in @('native-core-default', 'package-artifacts', 'install-smoke-workflows', 'support-bundle-export', 'install-first-run-dependencies', 'msi-smoke-workflows', 'msi-support-bundle-export', 'machine-takeover')) {
    if ($requirementStatuses[$id] -ne 'ready') {
        throw "requirement $id should be ready but was $($requirementStatuses[$id])"
    }
}
if ($requirementStatuses['public-release-signing'] -ne 'blocked') {
    throw "public-release-signing should be blocked but was $($requirementStatuses['public-release-signing'])"
}

& powershell -NoProfile -ExecutionPolicy Bypass -File $statusScript -EvidencePath $fixturePath -FailOnMvpBlocked
if ($LASTEXITCODE -ne 0) {
    throw 'desktop-mvp-status.ps1 -FailOnMvpBlocked should ignore signing-only public release blockers'
}

$safeProbeFixturePath = Join-Path $tempDir 'release-evidence-safe-probe-machine-not-run.json'
$safeProbeFixture = Get-Content -Raw -LiteralPath $fixturePath | ConvertFrom-Json
$safeProbeFixture.public_release_blockers = @('artifact-signature-missing', 'signing-certificate-missing', 'machine-takeover-smoke-not-run')
$safeProbeFixture.smoke.machine = [pscustomobject][ordered]@{
    status = 'passed'
    native_core_default = $true
    machine_takeover_status = 'not-run'
    blockers = @('machine-takeover-smoke-not-run')
}
$safeProbeFixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $safeProbeFixturePath -Encoding ASCII

$safeProbeJsonOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $statusScript -EvidencePath $safeProbeFixturePath -Json
if ($LASTEXITCODE -ne 0) {
    throw "desktop-mvp-status.ps1 safe-probe fixture exited with $LASTEXITCODE"
}
$safeProbeReport = $safeProbeJsonOutput -join "`n" | ConvertFrom-Json
if ($safeProbeReport.desktop_mvp_ready -ne $true) {
    throw 'desktop MVP should be ready for unsigned beta when machine takeover is only a public-release blocker'
}
if (($safeProbeReport.remaining_external_blockers -join ',') -ne 'artifact-signature-missing,signing-certificate-missing,machine-takeover-smoke-not-run') {
    throw "safe-probe external blockers mismatch: $($safeProbeReport.remaining_external_blockers -join ',')"
}
& powershell -NoProfile -ExecutionPolicy Bypass -File $statusScript -EvidencePath $safeProbeFixturePath -FailOnMvpBlocked
if ($LASTEXITCODE -ne 0) {
    throw 'desktop-mvp-status.ps1 -FailOnMvpBlocked should allow safe-probe machine takeover blocker for unsigned beta'
}

$blockedFixturePath = Join-Path $tempDir 'release-evidence-local-blocked.json'
$blockedFixture = $fixture
$blockedFixture.smoke.install.verified_ui_workflow_entrypoints = @(
    'open-desktop-shell',
    'import-subscription',
    'select-node',
    'start-stop-system-proxy',
    'tun-preflight'
)
$blockedFixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $blockedFixturePath -Encoding ASCII

$stdoutPath = Join-Path $tempDir 'status-blocked-stdout.txt'
$stderrPath = Join-Path $tempDir 'status-blocked-stderr.txt'
$process = Start-Process `
    -FilePath 'powershell' `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $statusScript, '-EvidencePath', $blockedFixturePath, '-FailOnMvpBlocked') `
    -NoNewWindow `
    -Wait `
    -PassThru `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath
if ($process.ExitCode -eq 0) {
    throw 'desktop-mvp-status.ps1 -FailOnMvpBlocked should fail local blocked fixture'
}
$failureText = @(
    if (Test-Path -LiteralPath $stdoutPath) {
        Get-Content -LiteralPath $stdoutPath
    }
    if (Test-Path -LiteralPath $stderrPath) {
        Get-Content -LiteralPath $stderrPath
    }
) -join "`n"
if (!$failureText.Contains('Desktop MVP status blocked: install-smoke-workflows')) {
    throw "local blocked failure did not name install-smoke-workflows: $failureText"
}

$dependencyBlockedFixturePath = Join-Path $tempDir 'release-evidence-dependency-blocked.json'
$dependencyBlockedFixture = Get-Content -Raw -LiteralPath $fixturePath | ConvertFrom-Json
$dependencyBlockedFixture.smoke.install.dependency_action_entrypoints = @()
$dependencyBlockedFixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $dependencyBlockedFixturePath -Encoding ASCII

$dependencyStdoutPath = Join-Path $tempDir 'status-dependency-blocked-stdout.txt'
$dependencyStderrPath = Join-Path $tempDir 'status-dependency-blocked-stderr.txt'
$dependencyProcess = Start-Process `
    -FilePath 'powershell' `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $statusScript, '-EvidencePath', $dependencyBlockedFixturePath, '-FailOnMvpBlocked') `
    -NoNewWindow `
    -Wait `
    -PassThru `
    -RedirectStandardOutput $dependencyStdoutPath `
    -RedirectStandardError $dependencyStderrPath
if ($dependencyProcess.ExitCode -eq 0) {
    throw 'desktop-mvp-status.ps1 -FailOnMvpBlocked should fail missing dependency action evidence'
}
$dependencyFailureText = @(
    if (Test-Path -LiteralPath $dependencyStdoutPath) {
        Get-Content -LiteralPath $dependencyStdoutPath
    }
    if (Test-Path -LiteralPath $dependencyStderrPath) {
        Get-Content -LiteralPath $dependencyStderrPath
    }
) -join "`n"
if (!$dependencyFailureText.Contains('Desktop MVP status blocked: install-first-run-dependencies')) {
    throw "dependency blocked failure did not name install-first-run-dependencies: $dependencyFailureText"
}

$supportExportBlockedFixturePath = Join-Path $tempDir 'release-evidence-support-export-blocked.json'
$supportExportBlockedFixture = Get-Content -Raw -LiteralPath $fixturePath | ConvertFrom-Json
$supportExportBlockedFixture.smoke.install.support_export_desktop_dependencies = $false
$supportExportBlockedFixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $supportExportBlockedFixturePath -Encoding ASCII

$supportExportStdoutPath = Join-Path $tempDir 'status-support-export-blocked-stdout.txt'
$supportExportStderrPath = Join-Path $tempDir 'status-support-export-blocked-stderr.txt'
$supportExportProcess = Start-Process `
    -FilePath 'powershell' `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $statusScript, '-EvidencePath', $supportExportBlockedFixturePath, '-FailOnMvpBlocked') `
    -NoNewWindow `
    -Wait `
    -PassThru `
    -RedirectStandardOutput $supportExportStdoutPath `
    -RedirectStandardError $supportExportStderrPath
if ($supportExportProcess.ExitCode -eq 0) {
    throw 'desktop-mvp-status.ps1 -FailOnMvpBlocked should fail missing support export smoke evidence'
}
$supportExportFailureText = @(
    if (Test-Path -LiteralPath $supportExportStdoutPath) {
        Get-Content -LiteralPath $supportExportStdoutPath
    }
    if (Test-Path -LiteralPath $supportExportStderrPath) {
        Get-Content -LiteralPath $supportExportStderrPath
    }
) -join "`n"
if (!$supportExportFailureText.Contains('Desktop MVP status blocked: support-bundle-export')) {
    throw "support export blocked failure did not name support-bundle-export: $supportExportFailureText"
}

$msiSupportExportBlockedFixturePath = Join-Path $tempDir 'release-evidence-msi-support-export-blocked.json'
$msiSupportExportBlockedFixture = Get-Content -Raw -LiteralPath $fixturePath | ConvertFrom-Json
$msiSupportExportBlockedFixture.smoke.msi.support_export_desktop_dependencies = $false
$msiSupportExportBlockedFixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $msiSupportExportBlockedFixturePath -Encoding ASCII

$msiSupportExportStdoutPath = Join-Path $tempDir 'status-msi-support-export-blocked-stdout.txt'
$msiSupportExportStderrPath = Join-Path $tempDir 'status-msi-support-export-blocked-stderr.txt'
$msiSupportExportProcess = Start-Process `
    -FilePath 'powershell' `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $statusScript, '-EvidencePath', $msiSupportExportBlockedFixturePath, '-FailOnMvpBlocked') `
    -NoNewWindow `
    -Wait `
    -PassThru `
    -RedirectStandardOutput $msiSupportExportStdoutPath `
    -RedirectStandardError $msiSupportExportStderrPath
if ($msiSupportExportProcess.ExitCode -eq 0) {
    throw 'desktop-mvp-status.ps1 -FailOnMvpBlocked should fail missing MSI support export smoke evidence'
}
$msiSupportExportFailureText = @(
    if (Test-Path -LiteralPath $msiSupportExportStdoutPath) {
        Get-Content -LiteralPath $msiSupportExportStdoutPath
    }
    if (Test-Path -LiteralPath $msiSupportExportStderrPath) {
        Get-Content -LiteralPath $msiSupportExportStderrPath
    }
) -join "`n"
if (!$msiSupportExportFailureText.Contains('Desktop MVP status blocked: msi-support-bundle-export')) {
    throw "MSI support export blocked failure did not name msi-support-bundle-export: $msiSupportExportFailureText"
}

Write-Output 'desktop MVP status tests passed'
