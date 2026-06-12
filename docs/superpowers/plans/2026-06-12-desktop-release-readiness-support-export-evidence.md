# Desktop Release Readiness Support Export Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose packaged support bundle export smoke evidence in `desktop-release-readiness.ps1` JSON and text output.

**Architecture:** Read the support export fields already carried by `release.smoke.install`, add a `support_export` object to the readiness report, and print concise text lines for operators and CI logs.

**Tech Stack:** PowerShell release readiness script and existing release evidence JSON.

---

### Task 1: Red Test

**Files:**
- Modify: `scripts/desktop-release-readiness.tests.ps1`

- [ ] **Step 1: Add PlanOnly expectation**

Add:

```powershell
'read smoke.install.support_export_smoke smoke.install.support_export_kind smoke.install.support_export_desktop_dependencies',
```

- [ ] **Step 2: Add fixture support export fields**

Under `smoke.install`, add:

```powershell
support_export_smoke = 'target\desktop-install-smoke\desktop-support-export-smoke.json'
support_export_path = 'target\desktop-install-smoke\support-export\keli-support-1.json'
support_export_kind = 'keli_desktop_support_bundle'
support_export_desktop_dependencies = $true
```

- [ ] **Step 3: Add JSON assertions**

Assert:

```powershell
if ($report.support_export.path -ne 'target\desktop-install-smoke\support-export\keli-support-1.json') { throw ... }
if ($report.support_export.kind -ne 'keli_desktop_support_bundle') { throw ... }
if ($report.support_export.desktop_dependencies -ne $true) { throw ... }
```

- [ ] **Step 4: Add text output assertions**

Expect:

```powershell
'support_export_kind keli_desktop_support_bundle',
'support_export_desktop_dependencies true',
'support_export_smoke target\desktop-install-smoke\desktop-support-export-smoke.json'
```

- [ ] **Step 5: Verify RED**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
```

Expected: FAIL because the readiness report does not yet include support export evidence.

### Task 2: Readiness Implementation

**Files:**
- Modify: `scripts/desktop-release-readiness.ps1`

- [ ] **Step 1: Add support export object**

In `New-ReadinessReport`, under `install_first_run`, add:

```powershell
support_export = [ordered]@{
    smoke = [string]$install.support_export_smoke
    path = [string]$install.support_export_path
    kind = [string]$install.support_export_kind
    desktop_dependencies = Get-BoolProperty -InputObject $install -Name 'support_export_desktop_dependencies'
}
```

- [ ] **Step 2: Add text output lines**

In `Write-ReadinessText`, add:

```powershell
Write-Output "support_export_smoke $($Report.support_export.smoke)"
Write-Output "support_export_kind $($Report.support_export.kind)"
Write-Output "support_export_desktop_dependencies $(Format-Bool -Value $Report.support_export.desktop_dependencies)"
```

- [ ] **Step 3: Add PlanOnly line**

```powershell
Write-Output 'read smoke.install.support_export_smoke smoke.install.support_export_kind smoke.install.support_export_desktop_dependencies'
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

Expected: PASS.

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
git add docs/superpowers/plans/2026-06-12-desktop-release-readiness-support-export-evidence.md scripts/desktop-release-readiness.ps1 scripts/desktop-release-readiness.tests.ps1
git commit -m "Expose support export readiness evidence"
git push
```

## Self-Review

- Spec coverage: exposes the support export smoke result in the operator-facing readiness report.
- Placeholder scan: no TBD/TODO/fill-in placeholders remain.
- Type consistency: field names match release evidence output.
- Scope: no change to signing policy or normal desktop runtime behavior.
