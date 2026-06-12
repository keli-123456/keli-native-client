[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $scriptDir '..')).Path
$workflowPath = Join-Path $repoRoot '.github\workflows\windows-unsigned-beta-release.yml'

if (!(Test-Path -LiteralPath $workflowPath -PathType Leaf)) {
    throw 'windows unsigned beta release workflow was not found'
}

$workflow = Get-Content -Raw -LiteralPath $workflowPath
$expected = @(
    'name: Windows Unsigned Beta Release',
    'contents: write',
    'workflow_dispatch:',
    'tags:',
    "'v*'",
    'runs-on: windows-latest',
    'actions/checkout@v4',
    'dtolnay/rust-toolchain@stable',
    '.\scripts\desktop-mvp-gate.ps1',
    '.\scripts\desktop-beta-rc.ps1',
    'target\desktop\SHA256SUMS',
    'Get-FileHash',
    'actions/upload-artifact@v4',
    'softprops/action-gh-release@v2',
    'prerelease: true',
    'body_path: target/desktop/keli-desktop-unsigned-beta-release-notes.md',
    'target/desktop/keli-desktop-mvp-windows-x64.zip',
    'target/desktop/keli-desktop-mvp-windows-x64.msi',
    'target/desktop/keli-desktop-release-evidence.json',
    'target/desktop/keli-desktop-unsigned-beta-manifest.json',
    'target/desktop/keli-desktop-unsigned-beta-release-notes.md',
    'target/desktop/SHA256SUMS'
)

foreach ($item in $expected) {
    if (!$workflow.Contains($item)) {
        throw "windows unsigned beta release workflow is missing: $item"
    }
}

Write-Output 'desktop GitHub release workflow tests passed'
