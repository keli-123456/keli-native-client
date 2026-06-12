# Desktop Release Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a repeatable Windows desktop MVP gate that validates formatting, desktop tests, desktop shell compilation, release binary build, and the expected `keli-desktop-shell.exe` artifact.

**Architecture:** Create a PowerShell gate under `scripts/` so Windows developers can run one local command before packaging or smoke testing. Keep the script repository-local, deterministic, and testable through a `-PlanOnly` mode plus a small PowerShell test that proves the expected commands and artifact check are wired.

**Tech Stack:** PowerShell 5+, Cargo, existing Rust workspace crates `keli-desktop` and `keli-desktop-shell`.

---

## Scope Check

This plan covers the first release gate layer only. It does not create an MSI, NSIS, WiX, updater, code signing flow, or GitHub Actions workflow. Those remain separate slices after we have a local command that reliably produces and validates the desktop release executable.

## File Structure

- Create: `scripts/desktop-mvp-gate.tests.ps1`
  - A lightweight script test that runs the gate in `-PlanOnly` mode and asserts the expected validation commands and release artifact path are present.
- Create: `scripts/desktop-mvp-gate.ps1`
  - The actual local release gate. It runs checks in order and fails fast on the first broken step. In `-PlanOnly` mode, it prints the commands and artifact path without running Cargo.

## Task 1: PowerShell Gate Test

**Files:**
- Create: `scripts/desktop-mvp-gate.tests.ps1`

- [ ] **Step 1: Write the failing test**

Create `scripts/desktop-mvp-gate.tests.ps1`:

```powershell
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $PSCommandPath
$gateScript = Join-Path $scriptDir 'desktop-mvp-gate.ps1'

if (!(Test-Path -LiteralPath $gateScript)) {
    throw "desktop-mvp-gate.ps1 was not found"
}

$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $gateScript -PlanOnly
if ($LASTEXITCODE -ne 0) {
    throw "desktop-mvp-gate.ps1 -PlanOnly exited with $LASTEXITCODE"
}

$plan = $output -join "`n"
$expected = @(
    'cargo fmt --check',
    'git diff --check',
    'cargo test -p keli-desktop -- --test-threads=1',
    'cargo test -p keli-desktop-shell',
    'cargo check -p keli-desktop-shell',
    'cargo build --release -p keli-desktop-shell',
    'target\release\keli-desktop-shell.exe'
)

foreach ($item in $expected) {
    if (!$plan.Contains($item)) {
        throw "desktop MVP gate plan is missing: $item"
    }
}

Write-Output 'desktop MVP gate plan test passed'
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: FAIL with `desktop-mvp-gate.ps1 was not found`.

## Task 2: Desktop MVP Gate Script

**Files:**
- Create: `scripts/desktop-mvp-gate.ps1`
- Modify: `scripts/desktop-mvp-gate.tests.ps1` only if the test command needs a path correction discovered during execution.

- [ ] **Step 1: Write the minimal implementation**

Create `scripts/desktop-mvp-gate.ps1`:

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
    )
}

function Format-StepCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Command
    )

    return ($Command | ForEach-Object {
        if ($_ -match '\s') {
            return '"' + ($_ -replace '"', '\"') + '"'
        }
        $_
    }) -join ' '
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
```

- [ ] **Step 2: Run the focused gate test**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: PASS with `desktop MVP gate plan test passed`.

- [ ] **Step 3: Commit and push**

Run:

```powershell
git add scripts\desktop-mvp-gate.ps1 scripts\desktop-mvp-gate.tests.ps1
git commit -m "Add desktop MVP release gate script"
git push origin main
```

## Task 3: Full Gate Verification

**Files:**
- No source changes expected.

- [ ] **Step 1: Run the dry plan**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1 -PlanOnly
```

Expected: output includes all six commands and `target\release\keli-desktop-shell.exe`.

- [ ] **Step 2: Run the full local gate**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS and prints `Desktop MVP gate passed:` with the absolute `target\release\keli-desktop-shell.exe` path.

- [ ] **Step 3: Confirm clean sync**

Run:

```powershell
git status --short
git rev-parse HEAD
git rev-parse origin/main
```

Expected: no status output and both revisions match.

## Self-Review Checklist

- Spec coverage: this plan implements release gate integration for the desktop shell release binary. It leaves installer technology, code signing, update flow, and manual installed-app smoke as follow-up slices.
- Placeholder scan: every command, file path, script body, and expected result is concrete.
- Type and command consistency: the test expects the exact commands and artifact path emitted by `desktop-mvp-gate.ps1 -PlanOnly`.
