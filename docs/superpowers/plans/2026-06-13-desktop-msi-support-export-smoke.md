# Desktop MSI Support Export Smoke Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the desktop shell executable extracted from the MSI can export a support bundle and carry that evidence in MSI smoke JSON.

**Architecture:** Reuse the existing `keli-desktop-shell.exe --support-export-smoke <dir>` headless command. After MSI administrative extraction, run the extracted EXE against an MSI-specific support export directory, validate the smoke report shape, and copy the same non-secret support export fields into `keli-desktop-msi-smoke.json`.

**Tech Stack:** PowerShell MSI smoke script, existing Rust shell support export smoke command, existing release evidence field names.

---

### Task 1: MSI Plan Red Test

**Files:**
- Modify: `scripts/desktop-msi.tests.ps1`

- [ ] **Step 1: Add expected PlanOnly lines**

Add these expected strings before the final smoke output line:

```powershell
'admin_extract support_export_smoke target\desktop\keli-desktop-msi-support-export-smoke.json',
'admin_extract support_export_kind keli_desktop_support_bundle',
'admin_extract support_export_desktop_dependencies true',
```

- [ ] **Step 2: Verify RED**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-msi.tests.ps1
```

Expected: FAIL because `desktop-msi.ps1 -PlanOnly` does not yet mention MSI support export smoke evidence.

### Task 2: MSI Smoke Implementation

**Files:**
- Modify: `scripts/desktop-msi.ps1`

- [ ] **Step 1: Extend `Write-MsiSmoke` parameters**

Add:

```powershell
[Parameter(Mandatory = $true)]
[string]$SupportExportSmokePath,

[Parameter(Mandatory = $true)]
[string]$SupportExportDir
```

- [ ] **Step 2: Run support export smoke after manifest checks**

Add:

```powershell
$extractedExe = Join-Path $AdminExtractDir 'Keli\keli-desktop-shell.exe'
New-Item -ItemType Directory -Force -Path $SupportExportDir | Out-Null
$supportExportOutput = & $extractedExe --support-export-smoke $SupportExportDir
if ($LASTEXITCODE -ne 0) {
    throw "MSI extracted support export smoke failed with exit code $LASTEXITCODE"
}
$supportExportOutput | Set-Content -LiteralPath $SupportExportSmokePath -Encoding ASCII
$supportExportSmoke = Get-Content -Raw -LiteralPath $SupportExportSmokePath | ConvertFrom-Json
if ($supportExportSmoke.status -ne 'passed') {
    throw "MSI extracted support export smoke status mismatch: $($supportExportSmoke.status)"
}
if ($supportExportSmoke.kind -ne 'keli_desktop_support_bundle') {
    throw "MSI extracted support export smoke kind mismatch: $($supportExportSmoke.kind)"
}
if ($supportExportSmoke.desktop_dependencies -ne $true) {
    throw 'MSI extracted support export smoke desktop_dependencies must be true'
}
```

- [ ] **Step 3: Add result JSON fields**

Add to `$result`:

```powershell
support_export_smoke = 'target\desktop\keli-desktop-msi-support-export-smoke.json'
support_export_path = [string]$supportExportSmoke.path
support_export_kind = [string]$supportExportSmoke.kind
support_export_desktop_dependencies = [bool]$supportExportSmoke.desktop_dependencies
```

- [ ] **Step 4: Add top-level paths and pass them**

Add:

```powershell
$supportExportSmokePath = Join-Path $repoRoot 'target\desktop\keli-desktop-msi-support-export-smoke.json'
$supportExportDir = Join-Path $repoRoot 'target\desktop-msi-support-export-smoke'
```

Pass both into `Write-MsiSmoke`.

- [ ] **Step 5: Add PlanOnly output lines**

Add:

```powershell
Write-Output 'admin_extract support_export_smoke target\desktop\keli-desktop-msi-support-export-smoke.json'
Write-Output 'admin_extract support_export_kind keli_desktop_support_bundle'
Write-Output 'admin_extract support_export_desktop_dependencies true'
```

### Task 3: Verification And Commit

**Files:**
- Modified files from Tasks 1-2

- [ ] **Step 1: Focused plan test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-msi.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Full MVP gate**

Run:

```powershell
scripts\desktop-mvp-gate.ps1
```

Expected: PASS and MSI smoke writes `support_export_desktop_dependencies = true`.

- [ ] **Step 3: Public release gate honesty**

Run:

```powershell
scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: FAIL only with:

- `artifact-signature-missing`
- `signing-certificate-missing`

- [ ] **Step 4: Diff check, commit, push**

Run:

```powershell
git diff --check
git add docs/superpowers/plans/2026-06-13-desktop-msi-support-export-smoke.md scripts/desktop-msi.ps1 scripts/desktop-msi.tests.ps1
git commit -m "Verify MSI support bundle export"
git push
```

## Self-Review

- Spec coverage: this plan strengthens the installer validation requirement by proving the MSI-extracted desktop shell can export a support bundle.
- Placeholder scan: no TBD/TODO/fill-in placeholders remain.
- Type consistency: result JSON field names match existing support export evidence fields used by release evidence.
- Scope: normal GUI behavior, portable install smoke, and signing policy remain unchanged.
