# Desktop Portable Package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a repeatable portable Windows package step that stages `keli-desktop-shell.exe`, package metadata, operator instructions, and a ZIP artifact, then wire it into the desktop MVP release gate.

**Architecture:** Keep packaging in PowerShell under `scripts/` so it runs on the same Windows machine as the desktop shell. The package script consumes the release executable, writes a small portable directory under `target\desktop\keli-desktop-mvp-windows-x64`, creates `keli-desktop-manifest.json` and `README.txt`, and compresses those files into `target\desktop\keli-desktop-mvp-windows-x64.zip`. The existing desktop MVP gate remains responsible for tests and release build, then calls the package script with `-SkipBuild`.

**Tech Stack:** PowerShell 5+, Cargo, existing `keli-desktop-shell` release binary, built-in `Compress-Archive`.

---

## Scope Check

This slice creates a portable ZIP package and proves it through the local desktop MVP gate. It does not create an MSI, NSIS, WiX, code signing, updater, Start Menu shortcut, or elevation flow. Those are follow-up installer slices after this package has a stable artifact shape.

## File Structure

- Create: `scripts/desktop-package.tests.ps1`
  - Verifies `desktop-package.ps1 -PlanOnly` advertises the release build command, staging directory, files, and ZIP artifact.
- Create: `scripts/desktop-package.ps1`
  - Builds or consumes `target\release\keli-desktop-shell.exe`, writes package metadata and instructions, copies the executable to a portable staging directory, and creates the ZIP.
- Modify: `scripts/desktop-mvp-gate.ps1`
  - Add a final package step that invokes `desktop-package.ps1 -SkipBuild` after the release build.
- Modify: `scripts/desktop-mvp-gate.tests.ps1`
  - Assert the gate plan includes the packaging script command and ZIP artifact.

## Task 1: Package Script Plan Test

**Files:**
- Create: `scripts/desktop-package.tests.ps1`

- [ ] **Step 1: Write the failing package plan test**

Create `scripts/desktop-package.tests.ps1`:

```powershell
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$packageScript = Join-Path $scriptDir 'desktop-package.ps1'

if (!(Test-Path -LiteralPath $packageScript)) {
    throw "desktop-package.ps1 was not found"
}

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $packageScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-package.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $output -join "`n"
$expected = @(
    'cargo build --release -p keli-desktop-shell',
    'stage target\desktop\keli-desktop-mvp-windows-x64',
    'file target\desktop\keli-desktop-mvp-windows-x64\keli-desktop-shell.exe',
    'file target\desktop\keli-desktop-mvp-windows-x64\README.txt',
    'file target\desktop\keli-desktop-mvp-windows-x64\keli-desktop-manifest.json',
    'zip target\desktop\keli-desktop-mvp-windows-x64.zip'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop package plan is missing: $item"
    }
}

Write-Output 'desktop package plan test passed'
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-package.tests.ps1
```

Expected: FAIL with `desktop-package.ps1 was not found`.

## Task 2: Gate Plan Test For Packaging

**Files:**
- Modify: `scripts/desktop-mvp-gate.tests.ps1`

- [ ] **Step 1: Extend the failing gate plan test**

Modify the `$expected` array in `scripts/desktop-mvp-gate.tests.ps1` to include the package script and ZIP artifact:

```powershell
$expected = @(
    'cargo fmt --check',
    'git diff --check',
    'cargo test -p keli-desktop -- --test-threads=1',
    'cargo test -p keli-desktop-shell',
    'cargo check -p keli-desktop-shell',
    'cargo build --release -p keli-desktop-shell',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-package.ps1 -SkipBuild',
    'target\release\keli-desktop-shell.exe',
    'target\desktop\keli-desktop-mvp-windows-x64.zip'
)
```

- [ ] **Step 2: Run the gate test to verify it fails**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: FAIL with `desktop MVP gate plan is missing: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-package.ps1 -SkipBuild`.

## Task 3: Portable Package Script

**Files:**
- Create: `scripts/desktop-package.ps1`

- [ ] **Step 1: Implement the package script**

Create `scripts/desktop-package.ps1`:

```powershell
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

function ConvertTo-RelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $root = $RepoRoot.TrimEnd('\') + '\'
    if ($Path.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $Path.Substring($root.Length)
    }
    return $Path
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
        '2. Import a subscription config.',
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
```

- [ ] **Step 2: Run the package plan test**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-package.tests.ps1
```

Expected: PASS with `desktop package plan test passed`.

## Task 4: Desktop MVP Gate Packaging Integration

**Files:**
- Modify: `scripts/desktop-mvp-gate.ps1`

- [ ] **Step 1: Add the package step to the gate**

Modify `Get-DesktopMvpGateSteps` in `scripts/desktop-mvp-gate.ps1` so the returned array includes this step after `Desktop shell release build`:

```powershell
        New-GateStep -Name 'Desktop portable package' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-package.ps1', '-SkipBuild')
```

Modify the `-PlanOnly` block so it also prints the ZIP artifact after the existing exe artifact:

```powershell
        Write-Output 'artifact target\release\keli-desktop-shell.exe'
        Write-Output 'artifact target\desktop\keli-desktop-mvp-windows-x64.zip'
```

- [ ] **Step 2: Run the gate plan test**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: PASS with `desktop MVP gate plan test passed`.

## Task 5: Full Verification

**Files:**
- No source changes expected unless verification finds a defect.

- [ ] **Step 1: Run script tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-package.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: both PASS.

- [ ] **Step 2: Run the full desktop MVP gate**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS. It must create `target\desktop\keli-desktop-mvp-windows-x64.zip`.

- [ ] **Step 3: Inspect package contents**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::OpenRead('target\desktop\keli-desktop-mvp-windows-x64.zip').Entries | Select-Object FullName"
```

Expected: includes `keli-desktop-shell.exe`, `README.txt`, and `keli-desktop-manifest.json`.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add scripts\desktop-package.ps1 scripts\desktop-package.tests.ps1 scripts\desktop-mvp-gate.ps1 scripts\desktop-mvp-gate.tests.ps1
git commit -m "Add desktop portable package gate"
git push origin main
```

## Self-Review Checklist

- Spec coverage: this plan advances packaging and release gate integration by producing a user-transferable portable ZIP and package metadata. It does not claim installer completion; MSI/NSIS, code signing, shortcuts, elevation, and installed-app smoke remain follow-up slices.
- Placeholder scan: every file, command, expected failure, expected pass output, and script body is specified.
- Type and command consistency: the package script emits exactly the plan strings tested by `desktop-package.tests.ps1`, and the gate script emits the package command tested by `desktop-mvp-gate.tests.ps1`.
