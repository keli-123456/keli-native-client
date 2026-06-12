# Desktop Support Export Release Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Carry the packaged support bundle export smoke evidence from install smoke into release evidence and make the MVP status `support-bundle-export` requirement depend on the real export result.

**Architecture:** Extend `Read-SmokeStatus` in `desktop-release-evidence.ps1` to copy non-secret support export fields already produced by `desktop-install-smoke.ps1`. Then update `desktop-mvp-status.ps1` so `support-bundle-export` requires both the UI workflow entrypoint and successful support export smoke JSON evidence.

**Tech Stack:** PowerShell release scripts and existing JSON evidence DTOs.

---

### Task 1: Red Tests

**Files:**
- Modify: `scripts/desktop-release-evidence.tests.ps1`
- Modify: `scripts/desktop-mvp-status.tests.ps1`

- [ ] **Step 1: Release evidence plan expectations**

Add to expected PlanOnly lines:

```powershell
'metadata install_smoke_support_export_smoke',
```

- [ ] **Step 2: Release evidence fixture assertions**

Add these install smoke fixture fields before running `desktop-release-evidence.ps1`:

```powershell
$installSmoke | Add-Member -NotePropertyName support_export_smoke -NotePropertyValue 'target\desktop-install-smoke\desktop-support-export-smoke.json' -Force
$installSmoke | Add-Member -NotePropertyName support_export_kind -NotePropertyValue 'keli_desktop_support_bundle' -Force
$installSmoke | Add-Member -NotePropertyName support_export_desktop_dependencies -NotePropertyValue $true -Force
```

Assert:

```powershell
if ($dependencyReleaseEvidence.smoke.install.support_export_kind -ne 'keli_desktop_support_bundle') {
    throw "release evidence support export kind mismatch: $($dependencyReleaseEvidence.smoke.install.support_export_kind)"
}
if ($dependencyReleaseEvidence.smoke.install.support_export_desktop_dependencies -ne $true) {
    throw 'release evidence support export desktop dependency evidence must be true'
}
```

- [ ] **Step 3: MVP status fixture and blocked assertion**

Add these fields to the base install smoke fixture in `desktop-mvp-status.tests.ps1`:

```powershell
support_export_smoke = 'target\desktop-install-smoke\desktop-support-export-smoke.json'
support_export_kind = 'keli_desktop_support_bundle'
support_export_desktop_dependencies = $true
```

Add a blocked fixture that sets:

```powershell
$supportExportBlockedFixture.smoke.install.support_export_desktop_dependencies = $false
```

Run with `-FailOnMvpBlocked` and assert the failure text contains:

```powershell
'Desktop MVP status blocked: support-bundle-export'
```

- [ ] **Step 4: Verify RED**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
```

Expected: FAIL before implementation, because release evidence does not yet propagate the support export fields and MVP status does not yet require them.

### Task 2: Release Evidence Propagation

**Files:**
- Modify: `scripts/desktop-release-evidence.ps1`

- [ ] **Step 1: Read support export fields**

Inside `Read-SmokeStatus`, after dependency action entrypoints, read:

```powershell
$supportExportSmoke = $null
if ($null -ne $smoke.PSObject.Properties['support_export_smoke']) {
    $supportExportSmoke = [string]$smoke.support_export_smoke
}
$supportExportPath = $null
if ($null -ne $smoke.PSObject.Properties['support_export_path']) {
    $supportExportPath = [string]$smoke.support_export_path
}
$supportExportKind = $null
if ($null -ne $smoke.PSObject.Properties['support_export_kind']) {
    $supportExportKind = [string]$smoke.support_export_kind
}
$supportExportDesktopDependencies = $null
if ($null -ne $smoke.PSObject.Properties['support_export_desktop_dependencies']) {
    $supportExportDesktopDependencies = [bool]$smoke.support_export_desktop_dependencies
}
```

- [ ] **Step 2: Copy support export fields into `$status`**

Add fields when present:

```powershell
if (![string]::IsNullOrWhiteSpace($supportExportSmoke)) {
    $status['support_export_smoke'] = $supportExportSmoke
}
if (![string]::IsNullOrWhiteSpace($supportExportPath)) {
    $status['support_export_path'] = $supportExportPath
}
if (![string]::IsNullOrWhiteSpace($supportExportKind)) {
    $status['support_export_kind'] = $supportExportKind
}
if ($null -ne $supportExportDesktopDependencies) {
    $status['support_export_desktop_dependencies'] = $supportExportDesktopDependencies
}
```

- [ ] **Step 3: Add PlanOnly metadata line**

```powershell
Write-Output 'metadata install_smoke_support_export_smoke'
```

### Task 3: MVP Status Requirement

**Files:**
- Modify: `scripts/desktop-mvp-status.ps1`

- [ ] **Step 1: Add helper**

Add:

```powershell
function Test-SupportExportEvidence {
    param([AllowNull()][object]$InstallSmoke)
    return (
        (Test-StringArrayContainsAll -Values $InstallSmoke.manual_smoke_cases -Expected @('export-support-bundle')) -and
        (Test-StringArrayContainsAll -Values $InstallSmoke.verified_ui_workflow_entrypoints -Expected @('export-support-bundle')) -and
        ([string]$InstallSmoke.support_export_smoke -eq 'target\desktop-install-smoke\desktop-support-export-smoke.json') -and
        ([string]$InstallSmoke.support_export_kind -eq 'keli_desktop_support_bundle') -and
        (Get-BoolProperty -InputObject $InstallSmoke -Name 'support_export_desktop_dependencies')
    )
}
```

- [ ] **Step 2: Replace `$supportBundleReady` expression**

Use:

```powershell
$supportBundleReady = Test-SupportExportEvidence -InstallSmoke $installSmoke
```

- [ ] **Step 3: Update evidence label and PlanOnly line**

Change evidence label to:

```powershell
release.smoke.install.support_export_smoke
```

Change PlanOnly text:

```powershell
Write-Output 'require support-bundle-export workflow and export smoke evidence'
```

### Task 4: Verification And Commit

**Files:**
- Modified files from Tasks 1-3

- [ ] **Step 1: Run focused tests**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
```

- [ ] **Step 2: Full MVP gate**

```powershell
scripts\desktop-mvp-gate.ps1
```

Expected: PASS and `requirement.support-bundle-export ready`.

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
git add docs/superpowers/plans/2026-06-12-desktop-support-export-release-evidence.md scripts/desktop-release-evidence.ps1 scripts/desktop-release-evidence.tests.ps1 scripts/desktop-mvp-status.ps1 scripts/desktop-mvp-status.tests.ps1
git commit -m "Require support export smoke evidence"
git push
```

## Self-Review

- Spec coverage: this plan strengthens the support-bundle-export MVP requirement from UI affordance evidence to real packaged export evidence.
- Placeholder scan: no TBD/TODO/fill-in placeholders remain.
- Type consistency: field names match `desktop-install-smoke.ps1` output.
- Scope: signing blockers and normal runtime behavior remain unchanged.
