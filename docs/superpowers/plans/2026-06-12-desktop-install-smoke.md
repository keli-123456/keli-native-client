# Desktop Install Smoke Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an automated install-smoke step that extracts the portable desktop package into a clean target directory, verifies the installed files and manifest, and wires that check into the desktop MVP release gate.

**Architecture:** Keep this as a non-GUI smoke so it can run reliably in the local gate and CI-like environments. The smoke consumes `target\desktop\keli-desktop-mvp-windows-x64.zip`, extracts it to `target\desktop-install-smoke\Keli`, validates `keli-desktop-shell.exe`, `README.txt`, and `keli-desktop-manifest.json`, and checks that the manifest advertises the native core default and required manual smoke cases. GUI launch and real system proxy/TUN operations remain manual-machine smoke checks for a later slice.

**Tech Stack:** PowerShell 5+, built-in `Expand-Archive`, existing portable package ZIP and manifest.

---

## Scope Check

This slice proves that the produced portable package can be extracted and has the files and metadata needed for a user-facing install smoke. It does not open the GUI, create shortcuts, request elevation, modify Windows proxy settings, install Wintun, or perform real TUN/system-proxy traffic smoke. Those are separate machine-affecting checks.

## File Structure

- Create: `scripts/desktop-install-smoke.tests.ps1`
  - Verifies `desktop-install-smoke.ps1 -PlanOnly` advertises the package input, install directory, required file checks, manifest checks, and smoke summary output.
- Create: `scripts/desktop-install-smoke.ps1`
  - Extracts the portable ZIP into `target\desktop-install-smoke\Keli`, validates installed files, validates manifest fields, and writes a smoke result JSON under `target\desktop-install-smoke\desktop-install-smoke.json`.
- Modify: `scripts/desktop-mvp-gate.ps1`
  - Add a final `Desktop install smoke` step after `Desktop portable package`.
- Modify: `scripts/desktop-mvp-gate.tests.ps1`
  - Assert the gate plan includes the install smoke command and result artifact.

## Task 1: Install Smoke Plan Test

**Files:**
- Create: `scripts/desktop-install-smoke.tests.ps1`

- [ ] **Step 1: Write the failing install smoke plan test**

Create `scripts/desktop-install-smoke.tests.ps1`:

```powershell
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$smokeScript = Join-Path $scriptDir 'desktop-install-smoke.ps1'

if (!(Test-Path -LiteralPath $smokeScript)) {
    throw "desktop-install-smoke.ps1 was not found"
}

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $smokeScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-install-smoke.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $output -join "`n"
$expected = @(
    'input target\desktop\keli-desktop-mvp-windows-x64.zip',
    'install target\desktop-install-smoke\Keli',
    'check target\desktop-install-smoke\Keli\keli-desktop-shell.exe',
    'check target\desktop-install-smoke\Keli\README.txt',
    'check target\desktop-install-smoke\Keli\keli-desktop-manifest.json',
    'manifest native_core_default true',
    'manifest manual_smoke import-subscription',
    'result target\desktop-install-smoke\desktop-install-smoke.json'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop install smoke plan is missing: $item"
    }
}

Write-Output 'desktop install smoke plan test passed'
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
```

Expected: FAIL with `desktop-install-smoke.ps1 was not found`.

## Task 2: Gate Plan Test For Install Smoke

**Files:**
- Modify: `scripts/desktop-mvp-gate.tests.ps1`

- [ ] **Step 1: Extend the failing gate plan test**

Modify the `$expected` array in `scripts/desktop-mvp-gate.tests.ps1` to include:

```powershell
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.ps1',
    'target\desktop-install-smoke\desktop-install-smoke.json'
```

The array should become:

```powershell
$expected = @(
    'cargo fmt --check',
    'git diff --check',
    'cargo test -p keli-desktop -- --test-threads=1',
    'cargo test -p keli-desktop-shell',
    'cargo check -p keli-desktop-shell',
    'cargo build --release -p keli-desktop-shell',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-package.ps1 -SkipBuild',
    'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.ps1',
    'target\release\keli-desktop-shell.exe',
    'target\desktop\keli-desktop-mvp-windows-x64.zip',
    'target\desktop-install-smoke\desktop-install-smoke.json'
)
```

- [ ] **Step 2: Run the gate test to verify it fails**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: FAIL with `desktop MVP gate plan is missing: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.ps1`.

## Task 3: Install Smoke Script

**Files:**
- Create: `scripts/desktop-install-smoke.ps1`

- [ ] **Step 1: Implement the install smoke script**

Create `scripts/desktop-install-smoke.ps1`:

```powershell
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
```

- [ ] **Step 2: Run the install smoke plan test**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
```

Expected: PASS with `desktop install smoke plan test passed`.

## Task 4: Desktop MVP Gate Install Smoke Integration

**Files:**
- Modify: `scripts/desktop-mvp-gate.ps1`

- [ ] **Step 1: Add the install smoke step to the gate**

Modify `Get-DesktopMvpGateSteps` in `scripts/desktop-mvp-gate.ps1` so the returned array includes this step after `Desktop portable package`:

```powershell
        New-GateStep -Name 'Desktop install smoke' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-install-smoke.ps1')
```

Modify the `-PlanOnly` block so it also prints the install smoke result artifact:

```powershell
        Write-Output 'artifact target\desktop-install-smoke\desktop-install-smoke.json'
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
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: both PASS.

- [ ] **Step 2: Run the full desktop MVP gate**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS. It must create `target\desktop-install-smoke\desktop-install-smoke.json`.

- [ ] **Step 3: Inspect the install smoke result**

Run:

```powershell
Get-Content -Raw target\desktop-install-smoke\desktop-install-smoke.json
```

Expected: JSON has `"status": "passed"`, `"native_core_default": true`, and includes all six manual smoke case names.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add scripts\desktop-install-smoke.ps1 scripts\desktop-install-smoke.tests.ps1 scripts\desktop-mvp-gate.ps1 scripts\desktop-mvp-gate.tests.ps1
git commit -m "Add desktop install smoke gate"
git push origin main
```

## Self-Review Checklist

- Spec coverage: this plan advances packaging, install smoke, and release gate integration by adding a repeatable extracted-install validation. It does not claim that GUI launch, proxy mutation, TUN runtime, Wintun install, code signing, or Start Menu integration are complete.
- Placeholder scan: every file, command, expected failure, expected pass output, and script body is specified.
- Type and command consistency: the install smoke script emits exactly the plan strings tested by `desktop-install-smoke.tests.ps1`, and the gate script emits the install smoke command and result artifact tested by `desktop-mvp-gate.tests.ps1`.
