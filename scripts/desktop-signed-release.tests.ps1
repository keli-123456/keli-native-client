[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$signedReleaseScript = Join-Path $scriptDir 'desktop-signed-release.ps1'

if (!(Test-Path -LiteralPath $signedReleaseScript)) {
    throw 'desktop-signed-release.ps1 was not found'
}

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $signedReleaseScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-signed-release.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $output -join "`n"
$expected = @(
    'preflight signing certificate configuration',
    'failure print signing-certificate-missing before build',
    'cargo fmt --check',
    'git diff --check',
    'cargo test -p keli-desktop -- --test-threads=1',
    'cargo test -p keli-desktop-shell',
    'cargo check -p keli-desktop-shell',
    'cargo build --release -p keli-desktop-shell',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-package.ps1 -SkipBuild',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.ps1',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-msi.ps1',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.ps1 -IncludeMachineTakeover -MachineTakeoverAttempts 2',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign',
    'rebuild portable package after exe signing',
    'rebuild MSI after signed exe is staged',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate',
    'write target\desktop\keli-desktop-signed-release.json',
    'output signed public release ready'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop signed release plan is missing: $item"
    }
}

$signCommand = 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign'
$firstSign = $plan.IndexOf($signCommand, [System.StringComparison]::Ordinal)
$secondSign = if ($firstSign -ge 0) {
    $plan.IndexOf($signCommand, $firstSign + $signCommand.Length, [System.StringComparison]::Ordinal)
} else {
    -1
}
if ($firstSign -lt 0 -or $secondSign -lt 0) {
    throw 'desktop signed release plan must include two signing passes'
}

$rebuildPackage = $plan.IndexOf('rebuild portable package after exe signing', [System.StringComparison]::Ordinal)
$rebuildMsi = $plan.IndexOf('rebuild MSI after signed exe is staged', [System.StringComparison]::Ordinal)
$publicGate = $plan.IndexOf('powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate', [System.StringComparison]::Ordinal)

if (!($firstSign -lt $rebuildPackage -and $rebuildPackage -lt $rebuildMsi -and $rebuildMsi -lt $secondSign -and $secondSign -lt $publicGate)) {
    throw 'desktop signed release plan order must sign exe before final packaging, sign final MSI, then run public gate without rebuilding'
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$tempDir = Join-Path $repoRoot 'target\desktop-signed-release-tests'
$shimDir = Join-Path $tempDir 'shims'
$backupDir = Join-Path $tempDir 'backup'
$logPath = Join-Path $tempDir 'command-log.txt'
$fakePowerShellScript = Join-Path $tempDir 'fake-powershell.ps1'
$realPowerShell = (Get-Process -Id $PID).Path
New-Item -ItemType Directory -Force -Path $shimDir, $backupDir | Out-Null
if (Test-Path -LiteralPath $logPath) {
    Remove-Item -LiteralPath $logPath -Force
}

$managedFiles = @(
    'target\release\keli-desktop-shell.exe',
    'target\desktop\keli-desktop-mvp-windows-x64.zip',
    'target\desktop\keli-desktop-mvp-windows-x64.msi',
    'target\desktop\keli-desktop-release-evidence.json',
    'target\desktop\keli-desktop-signing.json',
    'target\desktop\keli-desktop-signed-release.json',
    'target\desktop-install-smoke\desktop-install-smoke.json',
    'target\desktop\keli-desktop-msi-smoke.json',
    'target\desktop\keli-desktop-machine-smoke.json'
)
$backupMap = @{}
foreach ($relativePath in $managedFiles) {
    $source = Join-Path $repoRoot $relativePath
    $backup = Join-Path $backupDir (($relativePath -replace '[\\/:]', '_') + '.backup')
    $backupMap[$relativePath] = [ordered]@{
        source = $source
        backup = $backup
        existed = (Test-Path -LiteralPath $source -PathType Leaf)
    }
    if ($backupMap[$relativePath].existed) {
        Copy-Item -LiteralPath $source -Destination $backup -Force
    }
}

@'
@echo off
echo cargo %*>> "%KELI_SIGNED_RELEASE_TEST_LOG%"
if "%1"=="build" (
  if not exist "target\release" mkdir "target\release"
  > "target\release\keli-desktop-shell.exe" echo fake signed exe input
)
exit /b 0
'@ | Set-Content -LiteralPath (Join-Path $shimDir 'cargo.cmd') -Encoding ASCII

@'
@echo off
echo git %*>> "%KELI_SIGNED_RELEASE_TEST_LOG%"
exit /b 0
'@ | Set-Content -LiteralPath (Join-Path $shimDir 'git.cmd') -Encoding ASCII

@'
@echo off
"%KELI_REAL_POWERSHELL%" -NoProfile -ExecutionPolicy Bypass -File "%KELI_SIGNED_RELEASE_TEST_SHIM%" %*
exit /b %ERRORLEVEL%
'@ | Set-Content -LiteralPath (Join-Path $shimDir 'powershell.cmd') -Encoding ASCII

@'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$joinedArgs = $args -join ' '
Add-Content -LiteralPath $env:KELI_SIGNED_RELEASE_TEST_LOG -Value "powershell $joinedArgs"

$fileIndex = [array]::IndexOf($args, '-File')
$scriptPath = if ($fileIndex -ge 0 -and $fileIndex + 1 -lt $args.Count) { [string]$args[$fileIndex + 1] } else { '' }

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    $Value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding ASCII
}

if ($scriptPath -like '*desktop-package.ps1') {
    New-Item -ItemType Directory -Force -Path 'target\desktop\keli-desktop-mvp-windows-x64' | Out-Null
    Set-Content -LiteralPath 'target\desktop\keli-desktop-mvp-windows-x64\keli-desktop-shell.exe' -Value 'signed exe in portable package' -Encoding ASCII
    Set-Content -LiteralPath 'target\desktop\keli-desktop-mvp-windows-x64\README.txt' -Value 'readme' -Encoding ASCII
    Set-Content -LiteralPath 'target\desktop\keli-desktop-mvp-windows-x64\keli-desktop-manifest.json' -Value '{"manual_smoke":["open-desktop-shell"]}' -Encoding ASCII
    Set-Content -LiteralPath 'target\desktop\keli-desktop-mvp-windows-x64.zip' -Value 'fake signed portable zip' -Encoding ASCII
    exit 0
}

if ($scriptPath -like '*desktop-install-smoke.ps1') {
    Write-JsonFile -Path 'target\desktop-install-smoke\desktop-install-smoke.json' -Value ([ordered]@{
        status = 'passed'
        native_core_default = $true
    })
    exit 0
}

if ($scriptPath -like '*desktop-msi.ps1') {
    Set-Content -LiteralPath 'target\desktop\keli-desktop-mvp-windows-x64.msi' -Value 'fake signed msi' -Encoding ASCII
    Write-JsonFile -Path 'target\desktop\keli-desktop-msi-smoke.json' -Value ([ordered]@{
        status = 'passed'
        native_core_default = $true
    })
    exit 0
}

if ($scriptPath -like '*desktop-machine-smoke.ps1') {
    Write-JsonFile -Path 'target\desktop\keli-desktop-machine-smoke.json' -Value ([ordered]@{
        status = 'passed'
        native_core_default = $true
        machine_takeover = [ordered]@{
            status = 'ready'
            blockers = @()
        }
    })
    exit 0
}

if ($scriptPath -like '*desktop-signing.ps1') {
    Write-JsonFile -Path 'target\desktop\keli-desktop-signing.json' -Value ([ordered]@{
        status = 'passed'
        mode = 'sign'
        signtool = [ordered]@{
            available = $true
            path = 'fake-signtool.exe'
        }
        configuration = [ordered]@{
            can_sign = $true
            signing_method = 'pfx'
            timestamp_url = 'http://timestamp.digicert.com'
        }
        artifacts = @(
            [ordered]@{
                kind = 'desktop-shell-exe'
                path = 'target\release\keli-desktop-shell.exe'
                signature = [ordered]@{ status = 'Valid'; signed = $true; signer_subject = 'CN=Keli Test' }
            },
            [ordered]@{
                kind = 'desktop-msi'
                path = 'target\desktop\keli-desktop-mvp-windows-x64.msi'
                signature = [ordered]@{ status = 'Valid'; signed = $true; signer_subject = 'CN=Keli Test' }
            }
        )
        sign_verification_failures = @()
        public_release_ready = $true
        public_release_blockers = @()
    })
    exit 0
}

if ($scriptPath -like '*desktop-release-evidence.ps1') {
    Write-JsonFile -Path 'target\desktop\keli-desktop-release-evidence.json' -Value ([ordered]@{
        status = 'passed'
        public_release_ready = $true
        public_release_blockers = @()
        signing = [ordered]@{
            status = 'passed'
            mode = 'sign'
            can_sign = $true
            signtool_available = $true
            signing_method = 'pfx'
            unsigned_artifacts = @()
            sign_verification_failures = @()
        }
        smoke = [ordered]@{
            machine = [ordered]@{ machine_takeover_status = 'ready' }
            install = [ordered]@{}
            msi = [ordered]@{}
        }
    })
    exit 0
}

if ($scriptPath -like '*desktop-public-release-gate.ps1') {
    Add-Content -LiteralPath $env:KELI_SIGNED_RELEASE_TEST_LOG -Value 'public release gate passed'
    exit 0
}

exit 0
'@ | Set-Content -LiteralPath $fakePowerShellScript -Encoding ASCII

$oldPath = $env:Path
$oldRealPowerShell = $env:KELI_REAL_POWERSHELL
$oldShim = $env:KELI_SIGNED_RELEASE_TEST_SHIM
$oldLog = $env:KELI_SIGNED_RELEASE_TEST_LOG
$oldCertPath = $env:KELI_SIGN_CERT_PATH
$oldCertPassword = $env:KELI_SIGN_CERT_PASSWORD
$oldCertSubject = $env:KELI_SIGN_CERT_SUBJECT
try {
    $env:Path = "$shimDir;$oldPath"
    $env:KELI_REAL_POWERSHELL = $realPowerShell
    $env:KELI_SIGNED_RELEASE_TEST_SHIM = $fakePowerShellScript
    $env:KELI_SIGNED_RELEASE_TEST_LOG = $logPath
    $env:KELI_SIGN_CERT_PATH = ''
    $env:KELI_SIGN_CERT_PASSWORD = ''
    $env:KELI_SIGN_CERT_SUBJECT = ''

    $blockedStdoutPath = Join-Path $tempDir 'no-cert-stdout.txt'
    $blockedStderrPath = Join-Path $tempDir 'no-cert-stderr.txt'
    $blockedProcess = Start-Process `
        -FilePath $realPowerShell `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $signedReleaseScript) `
        -NoNewWindow `
        -Wait `
        -PassThru `
        -RedirectStandardOutput $blockedStdoutPath `
        -RedirectStandardError $blockedStderrPath
    if ($blockedProcess.ExitCode -eq 0) {
        throw 'desktop-signed-release.ps1 should fail before build when signing certificate configuration is missing'
    }
    $blockedText = @(
        if (Test-Path -LiteralPath $blockedStdoutPath) {
            Get-Content -LiteralPath $blockedStdoutPath
        }
        if (Test-Path -LiteralPath $blockedStderrPath) {
            Get-Content -LiteralPath $blockedStderrPath
        }
    ) -join "`n"
    if (!$blockedText.Contains('Desktop signed public release blocked: signing-certificate-missing')) {
        throw "missing-certificate failure did not name signing-certificate-missing: $blockedText"
    }
    if ((Test-Path -LiteralPath $logPath) -and ((Get-Content -LiteralPath $logPath) -join "`n").Contains('cargo ')) {
        throw 'missing-certificate preflight should fail before cargo commands run'
    }

    $fakePfxPath = Join-Path $tempDir 'fake-codesign.pfx'
    Set-Content -LiteralPath $fakePfxPath -Value 'fake pfx for signed release fixture' -Encoding ASCII
    $env:KELI_SIGN_CERT_PATH = $fakePfxPath
    $env:KELI_SIGN_CERT_PASSWORD = 'fixture-password'
    $env:KELI_SIGN_CERT_SUBJECT = ''
    if (Test-Path -LiteralPath $logPath) {
        Remove-Item -LiteralPath $logPath -Force
    }
    $runOutput = & $realPowerShell -NoProfile -ExecutionPolicy Bypass -File $signedReleaseScript
    if ($LASTEXITCODE -ne 0) {
        throw "desktop-signed-release.ps1 fixture run exited with $LASTEXITCODE"
    }
    $runText = $runOutput -join "`n"
    if (!$runText.Contains('signed_public_release_ready true')) {
        throw "desktop signed release fixture did not report readiness: $runText"
    }

    $reportPath = Join-Path $repoRoot 'target\desktop\keli-desktop-signed-release.json'
    if (!(Test-Path -LiteralPath $reportPath -PathType Leaf)) {
        throw 'desktop signed release report was not written'
    }
    $report = Get-Content -Raw -LiteralPath $reportPath | ConvertFrom-Json
    if ($null -eq $report.PSObject.Properties['release_evidence']) {
        throw 'desktop signed release report must include release_evidence summary'
    }
    if ($report.release_evidence.public_release_ready -ne $true) {
        throw 'desktop signed release report should record public_release_ready true'
    }
    if ($report.public_gate.passed -ne $true) {
        throw 'desktop signed release report should record public gate pass'
    }
    if ($report.release_evidence.signing_can_sign -ne $true) {
        throw 'desktop signed release report should record signing_can_sign true'
    }

    $executionLog = Get-Content -LiteralPath $logPath
    $signRuns = @($executionLog | Where-Object { $_ -like '*scripts\desktop-signing.ps1* -Sign*' })
    if ($signRuns.Count -ne 2) {
        throw "expected two signing executions, got $($signRuns.Count): $($executionLog -join '; ')"
    }
    if (($executionLog -join "`n").IndexOf('scripts\desktop-release-evidence.ps1', [System.StringComparison]::Ordinal) -gt ($executionLog -join "`n").IndexOf('scripts\desktop-public-release-gate.ps1 -SkipGate', [System.StringComparison]::Ordinal)) {
        throw 'public release gate should run after release evidence'
    }
} finally {
    $env:Path = $oldPath
    $env:KELI_REAL_POWERSHELL = $oldRealPowerShell
    $env:KELI_SIGNED_RELEASE_TEST_SHIM = $oldShim
    $env:KELI_SIGNED_RELEASE_TEST_LOG = $oldLog
    $env:KELI_SIGN_CERT_PATH = $oldCertPath
    $env:KELI_SIGN_CERT_PASSWORD = $oldCertPassword
    $env:KELI_SIGN_CERT_SUBJECT = $oldCertSubject

    foreach ($relativePath in $managedFiles) {
        $entry = $backupMap[$relativePath]
        if ($entry.existed) {
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $entry.source) | Out-Null
            Copy-Item -LiteralPath $entry.backup -Destination $entry.source -Force
        } elseif (Test-Path -LiteralPath $entry.source -PathType Leaf) {
            Remove-Item -LiteralPath $entry.source -Force
        }
    }
}

Write-Output 'desktop signed release tests passed'
