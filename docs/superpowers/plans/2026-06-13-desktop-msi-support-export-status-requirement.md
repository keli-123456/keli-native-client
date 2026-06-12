# Desktop MSI Support Export Status Requirement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make MSI support bundle export readiness visible as its own MVP status requirement.

**Architecture:** Reuse the support export evidence already emitted by MSI smoke and propagated by release evidence. Add a dedicated `msi-support-bundle-export` requirement that validates MSI smoke support export path, bundle kind, and desktop dependency evidence.

**Tech Stack:** PowerShell MVP status script and existing release evidence JSON.

---

### Task 1: Red Test

**Files:**
- Modify: `scripts/desktop-mvp-status.tests.ps1`

- [ ] **Step 1: Add PlanOnly expectation**

Add:

```powershell
'require msi-support-bundle-export smoke evidence',
```

- [ ] **Step 2: Add MSI fixture support export fields**

Under `smoke.msi`, add:

```powershell
support_export_smoke = 'target\desktop\keli-desktop-msi-support-export-smoke.json'
support_export_kind = 'keli_desktop_support_bundle'
support_export_desktop_dependencies = $true
```

- [ ] **Step 3: Require the new ready status**

Add `msi-support-bundle-export` to the ready requirement list.

- [ ] **Step 4: Add blocked fixture**

Create a fixture that sets:

```powershell
$msiSupportExportBlockedFixture.smoke.msi.support_export_desktop_dependencies = $false
```

Run status with `-FailOnMvpBlocked` and assert the failure text contains:

```powershell
'Desktop MVP status blocked: msi-support-bundle-export'
```

- [ ] **Step 5: Verify RED**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
```

Expected: FAIL because the status script does not yet emit `msi-support-bundle-export`.

### Task 2: Implementation

**Files:**
- Modify: `scripts/desktop-mvp-status.ps1`

- [ ] **Step 1: Add helper**

Add:

```powershell
function Test-MsiSupportExportEvidence {
    param([AllowNull()][object]$MsiSmoke)
    if ($null -eq $MsiSmoke) { return $false }
    return (
        ([string]$MsiSmoke.support_export_smoke -eq 'target\desktop\keli-desktop-msi-support-export-smoke.json') -and
        ([string]$MsiSmoke.support_export_kind -eq 'keli_desktop_support_bundle') -and
        (Get-BoolProperty -InputObject $MsiSmoke -Name 'support_export_desktop_dependencies')
    )
}
```

- [ ] **Step 2: Compute readiness**

Add:

```powershell
$msiSupportBundleReady = Test-MsiSupportExportEvidence -MsiSmoke $msiSmoke
```

- [ ] **Step 3: Add requirement**

Add:

```powershell
(New-Requirement -Id 'msi-support-bundle-export' -Ready $msiSupportBundleReady -Evidence 'release.smoke.msi.support_export_smoke'),
```

- [ ] **Step 4: Add PlanOnly output**

```powershell
Write-Output 'require msi-support-bundle-export smoke evidence'
```

### Task 3: Verification And Commit

**Files:**
- Modified files from Tasks 1-2

- [ ] **Step 1: Focused test**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
```

- [ ] **Step 2: Full MVP gate**

```powershell
scripts\desktop-mvp-gate.ps1
```

Expected: PASS and text output includes `requirement.msi-support-bundle-export ready`.

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
git add docs/superpowers/plans/2026-06-13-desktop-msi-support-export-status-requirement.md scripts/desktop-mvp-status.ps1 scripts/desktop-mvp-status.tests.ps1
git commit -m "Require MSI support export evidence"
git push
```

## Self-Review

- Spec coverage: this plan makes MSI support export evidence part of the MVP status gate.
- Placeholder scan: no TBD/TODO/fill-in placeholders remain.
- Type consistency: field names match MSI smoke JSON and release evidence.
- Scope: release signing policy, portable install smoke, and normal GUI behavior remain unchanged.
