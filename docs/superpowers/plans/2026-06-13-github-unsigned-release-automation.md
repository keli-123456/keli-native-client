# GitHub Unsigned Release Automation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a GitHub Actions workflow that builds and publishes Windows unsigned Beta release artifacts with SHA256SUMS.

**Architecture:** Keep local release truth in `scripts\desktop-mvp-gate.ps1` and `scripts\desktop-beta-rc.ps1`. Add a thin workflow file plus a PowerShell workflow-contract test that checks triggers, commands, checksum generation, upload, and release payload paths.

**Tech Stack:** GitHub Actions YAML, PowerShell 5+, existing Windows desktop release scripts.

---

### Task 1: Workflow Contract Red Test

**Files:**
- Create: `scripts/desktop-github-release-workflow.tests.ps1`

- [ ] **Step 1: Add workflow existence and content checks**

Create `scripts\desktop-github-release-workflow.tests.ps1`:

```powershell
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
    "tags:",
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
```

- [ ] **Step 2: Verify RED**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-github-release-workflow.tests.ps1
```

Expected: FAIL because `.github\workflows\windows-unsigned-beta-release.yml` does not exist yet.

### Task 2: GitHub Actions Workflow

**Files:**
- Create: `.github/workflows/windows-unsigned-beta-release.yml`

- [ ] **Step 1: Add workflow**

Create `.github/workflows/windows-unsigned-beta-release.yml`:

```yaml
name: Windows Unsigned Beta Release

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

permissions:
  contents: write

jobs:
  windows-unsigned-beta:
    name: Build Windows unsigned beta
    runs-on: windows-latest
    env:
      CARGO_INCREMENTAL: "0"
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Run desktop MVP gate
        shell: pwsh
        run: .\scripts\desktop-mvp-gate.ps1

      - name: Verify unsigned beta RC
        shell: pwsh
        run: .\scripts\desktop-beta-rc.ps1

      - name: Generate SHA256SUMS
        shell: pwsh
        run: |
          $ErrorActionPreference = 'Stop'
          $payload = @(
            'target\desktop\keli-desktop-mvp-windows-x64.zip',
            'target\desktop\keli-desktop-mvp-windows-x64.msi',
            'target\desktop\keli-desktop-release-evidence.json',
            'target\desktop\keli-desktop-unsigned-beta-manifest.json',
            'target\desktop\keli-desktop-unsigned-beta-release-notes.md'
          )
          $lines = foreach ($path in $payload) {
            if (!(Test-Path -LiteralPath $path -PathType Leaf)) {
              throw "required release payload is missing: $path"
            }
            $hash = Get-FileHash -LiteralPath $path -Algorithm SHA256
            "$($hash.Hash.ToLowerInvariant())  $(Split-Path -Leaf $path)"
          }
          $lines | Set-Content -LiteralPath 'target\desktop\SHA256SUMS' -Encoding ASCII

      - name: Upload unsigned beta payload
        uses: actions/upload-artifact@v4
        with:
          name: keli-windows-unsigned-beta-${{ github.ref_name }}
          if-no-files-found: error
          path: |
            target/desktop/keli-desktop-mvp-windows-x64.zip
            target/desktop/keli-desktop-mvp-windows-x64.msi
            target/desktop/keli-desktop-release-evidence.json
            target/desktop/keli-desktop-unsigned-beta-manifest.json
            target/desktop/keli-desktop-unsigned-beta-release-notes.md
            target/desktop/SHA256SUMS

      - name: Publish GitHub prerelease
        if: startsWith(github.ref, 'refs/tags/')
        uses: softprops/action-gh-release@v2
        with:
          prerelease: true
          body_path: target/desktop/keli-desktop-unsigned-beta-release-notes.md
          files: |
            target/desktop/keli-desktop-mvp-windows-x64.zip
            target/desktop/keli-desktop-mvp-windows-x64.msi
            target/desktop/keli-desktop-release-evidence.json
            target/desktop/keli-desktop-unsigned-beta-manifest.json
            target/desktop/keli-desktop-unsigned-beta-release-notes.md
            target/desktop/SHA256SUMS
```

- [ ] **Step 2: Verify GREEN**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-github-release-workflow.tests.ps1
```

Expected: PASS.

### Task 3: README Release Workflow Note

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add README text**

Under `Windows Unsigned Beta RC`, add:

```markdown
Pushing a `v*` tag runs `.github\workflows\windows-unsigned-beta-release.yml`.
The workflow runs the desktop MVP gate, regenerates the unsigned Beta manifest
and release notes, writes `target\desktop\SHA256SUMS`, uploads the payload as a
workflow artifact, and publishes a GitHub prerelease for tag runs.
```

- [ ] **Step 2: Add verify command reference**

In the Verify command block, add:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-github-release-workflow.tests.ps1
```

### Task 4: Verification, Commit, Push

**Files:**
- Modified files from Tasks 1-3

- [ ] **Step 1: Focused tests**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-github-release-workflow.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-beta-rc.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Full local gate**

Run:

```powershell
scripts\desktop-mvp-gate.ps1
```

Expected: PASS and regenerate unsigned Beta manifest/release notes.

- [ ] **Step 3: Direct Beta RC gate**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-beta-rc.ps1
```

Expected: PASS with `unsigned_beta_rc_ready true`.

- [ ] **Step 4: Diff check, commit, push**

Run:

```powershell
git diff --check
git add docs/superpowers/plans/2026-06-13-github-unsigned-release-automation.md .github/workflows/windows-unsigned-beta-release.yml scripts/desktop-github-release-workflow.tests.ps1 README.md
git commit -m "Add GitHub unsigned beta release workflow"
git push
```

## Self-Review

- Spec coverage: workflow handles tag/manual triggers, Windows build, existing gates, SHA256SUMS, artifact upload, and GitHub prerelease publication.
- Placeholder scan: no TBD/TODO/fill-in placeholders remain.
- Type consistency: payload paths match files produced by `desktop-mvp-gate` and `desktop-beta-rc`.
- Scope: no code-signing or hard public-release behavior changes.
