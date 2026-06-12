# Desktop Release Evidence Workflows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve install and MSI workflow evidence in the final desktop release evidence artifact, so release review can see that packaged UI entrypoints, README subscription import guidance, and manual smoke workflow ids were verified.

**Architecture:** Extend `Read-SmokeStatus` in `desktop-release-evidence.ps1` to carry optional fields from smoke JSON: `readme_subscription_import`, `manual_smoke_cases`, and `verified_ui_workflow_entrypoints`. Update the PlanOnly contract test so this evidence path is explicit. The existing release readiness calculation remains unchanged because signing is still the only public-release blocker.

**Tech Stack:** PowerShell release evidence scripts, existing desktop MVP gate.

---

### Task 1: Release Evidence Plan Contract

**Files:**
- Modify: `scripts/desktop-release-evidence.tests.ps1`
- Modify: `scripts/desktop-release-evidence.ps1`

- [ ] **Step 1: Write the failing release evidence plan test**

Add these expected lines to `scripts/desktop-release-evidence.tests.ps1`:

```powershell
'metadata install_smoke_ui_workflow_entrypoints',
'metadata install_smoke_readme_subscription_import',
'metadata msi_smoke_manual_smoke_cases',
'metadata msi_smoke_readme_subscription_import',
```

- [ ] **Step 2: Run the release evidence plan test to verify it fails**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
```

Expected: FAIL because `desktop-release-evidence.ps1 -PlanOnly` does not yet declare these metadata lines.

- [ ] **Step 3: Add PlanOnly metadata lines**

In `desktop-release-evidence.ps1 -PlanOnly`, after `metadata native_core_default true`, add:

```powershell
Write-Output 'metadata install_smoke_ui_workflow_entrypoints'
Write-Output 'metadata install_smoke_readme_subscription_import'
Write-Output 'metadata msi_smoke_manual_smoke_cases'
Write-Output 'metadata msi_smoke_readme_subscription_import'
```

- [ ] **Step 4: Run the release evidence plan test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
```

Expected: PASS.

### Task 2: Preserve Smoke Workflow Fields

**Files:**
- Modify: `scripts/desktop-release-evidence.ps1`

- [ ] **Step 1: Extend `Read-SmokeStatus`**

In `Read-SmokeStatus`, before returning the ordered object, collect optional fields:

```powershell
$readmeSubscriptionImport = $null
if ($null -ne $smoke.PSObject.Properties['readme_subscription_import']) {
    $readmeSubscriptionImport = [string]$smoke.readme_subscription_import
}

$manualSmokeCases = @()
if ($null -ne $smoke.PSObject.Properties['manual_smoke_cases']) {
    $manualSmokeCases = @($smoke.manual_smoke_cases | ForEach-Object { [string]$_ })
}

$verifiedUiWorkflowEntrypoints = @()
if ($null -ne $smoke.PSObject.Properties['verified_ui_workflow_entrypoints']) {
    $verifiedUiWorkflowEntrypoints = @($smoke.verified_ui_workflow_entrypoints | ForEach-Object { [string]$_ })
}
```

Build `$status = [ordered]@{ ... }` with the existing path/status/native fields, then add optional fields only when present:

```powershell
if (![string]::IsNullOrWhiteSpace($readmeSubscriptionImport)) {
    $status['readme_subscription_import'] = $readmeSubscriptionImport
}
if ($manualSmokeCases.Count -gt 0) {
    $status['manual_smoke_cases'] = $manualSmokeCases
}
if ($verifiedUiWorkflowEntrypoints.Count -gt 0) {
    $status['verified_ui_workflow_entrypoints'] = $verifiedUiWorkflowEntrypoints
}
return $status
```

- [ ] **Step 2: Run release evidence script**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1
```

Expected: PASS and `target\desktop\keli-desktop-release-evidence.json` contains:

```json
"smoke": {
  "install": {
    "readme_subscription_import": "subscription-url-or-config",
    "manual_smoke_cases": [...],
    "verified_ui_workflow_entrypoints": [...]
  },
  "msi": {
    "readme_subscription_import": "subscription-url-or-config",
    "manual_smoke_cases": [...]
  }
}
```

### Task 3: Gate Verification And Commit

**Files:**
- Modify: `scripts/desktop-release-evidence.ps1`
- Modify: `scripts/desktop-release-evidence.tests.ps1`

- [ ] **Step 1: Run targeted tests**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1
```

Expected: PASS.

- [ ] **Step 2: Run full MVP gate and release readiness**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
```

Expected: MVP gate PASS. Release readiness should still report `machine_takeover_status = "ready"` and only signing blockers until a code-signing certificate is configured.

- [ ] **Step 3: Commit and push implementation**

Run:

```powershell
git add scripts/desktop-release-evidence.ps1 scripts/desktop-release-evidence.tests.ps1
git commit -m "Preserve desktop workflow release evidence"
git push
```

Expected: commit pushed to `origin/main`.
