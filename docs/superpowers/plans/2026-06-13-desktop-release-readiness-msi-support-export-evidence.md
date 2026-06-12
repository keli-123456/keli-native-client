# Desktop Release Readiness MSI Support Export Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface MSI support bundle export evidence in the desktop public release readiness report.

**Architecture:** Reuse the MSI smoke support export fields already emitted into release evidence. Add a sibling `msi_support_export` report object and matching text output so public release diagnostics show both install-smoke and MSI-smoke support bundle coverage.

**Tech Stack:** PowerShell release readiness script and existing release evidence JSON.

---

### Task 1: Red Test

**Files:**
- Modify: `scripts/desktop-release-readiness.tests.ps1`

- [ ] **Step 1: Add PlanOnly expectation**

Add:

```powershell
'read smoke.msi.support_export_smoke smoke.msi.support_export_kind smoke.msi.support_export_desktop_dependencies',
```

- [ ] **Step 2: Add MSI fixture support export fields**

Under `smoke.msi`, add:

```powershell
support_export_smoke = 'target\desktop\keli-desktop-msi-support-export-smoke.json'
support_export_path = 'target\desktop-msi-support-export-smoke\keli-support-1.json'
support_export_kind = 'keli_desktop_support_bundle'
support_export_desktop_dependencies = $true
```

- [ ] **Step 3: Assert JSON output**

Require:

```powershell
$report.msi_support_export.path
$report.msi_support_export.kind
$report.msi_support_export.desktop_dependencies
```

- [ ] **Step 4: Assert text output**

Require:

```powershell
msi_support_export_smoke target\desktop\keli-desktop-msi-support-export-smoke.json
msi_support_export_kind keli_desktop_support_bundle
msi_support_export_desktop_dependencies true
```

- [ ] **Step 5: Verify RED**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
```

Expected: FAIL because the readiness script does not yet emit MSI support export evidence.

### Task 2: Implementation

**Files:**
- Modify: `scripts/desktop-release-readiness.ps1`

- [ ] **Step 1: Read MSI smoke**

Add:

```powershell
$msi = if (Test-JsonProperty -InputObject $smoke -Name 'msi') { $smoke.msi } else { $null }
```

- [ ] **Step 2: Add report object**

Add:

```powershell
msi_support_export = [ordered]@{
    smoke = Get-StringProperty -InputObject $msi -Name 'support_export_smoke'
    path = Get-StringProperty -InputObject $msi -Name 'support_export_path'
    kind = Get-StringProperty -InputObject $msi -Name 'support_export_kind'
    desktop_dependencies = Get-BoolProperty -InputObject $msi -Name 'support_export_desktop_dependencies'
}
```

- [ ] **Step 3: Add text output**

Add:

```powershell
Write-Output "msi_support_export_smoke $($Report.msi_support_export.smoke)"
Write-Output "msi_support_export_kind $($Report.msi_support_export.kind)"
Write-Output "msi_support_export_desktop_dependencies $(Format-Bool -Value $Report.msi_support_export.desktop_dependencies)"
```

- [ ] **Step 4: Add PlanOnly output**

Add:

```powershell
Write-Output 'read smoke.msi.support_export_smoke smoke.msi.support_export_kind smoke.msi.support_export_desktop_dependencies'
```

### Task 3: Verification And Commit

**Files:**
- Modified files from Tasks 1-2

- [ ] **Step 1: Focused test**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
```

- [ ] **Step 2: Full MVP gate**

```powershell
scripts\desktop-mvp-gate.ps1
```

Expected: PASS and readiness output includes MSI support export evidence.

- [ ] **Step 3: Public release gate honesty**

```powershell
scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: FAIL only with:

- `artifact-signature-missing`
- `signing-certificate-missing`

- [ ] **Step 4: Diff check, commit, push**

```powershell
git diff --check
git add docs/superpowers/plans/2026-06-13-desktop-release-readiness-msi-support-export-evidence.md scripts/desktop-release-readiness.ps1 scripts/desktop-release-readiness.tests.ps1
git commit -m "Expose MSI support export readiness evidence"
git push
```

## Self-Review

- Spec coverage: public release readiness now exposes MSI support export evidence.
- Placeholder scan: no TBD/TODO/fill-in placeholders remain.
- Type consistency: field names match MSI smoke JSON and release evidence.
- Scope: signing, packaging, and smoke execution behavior remain unchanged.
