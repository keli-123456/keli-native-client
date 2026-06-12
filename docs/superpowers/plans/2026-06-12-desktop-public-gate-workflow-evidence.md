# Desktop Public Gate Workflow Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the public release gate require the install/MSI workflow evidence now preserved in release evidence, so a signed build cannot pass public release without proving the packaged UI entrypoints and subscription README guidance.

**Architecture:** Add workflow-evidence checks to `desktop-public-release-gate.ps1` when computing release blockers. The gate will require install smoke to carry `verified_ui_workflow_entrypoints`, install and MSI smoke to carry `manual_smoke_cases`, and both install/MSI smoke to carry `readme_subscription_import = "subscription-url-or-config"`. PlanOnly output will declare these requirements for script-level tests.

**Tech Stack:** PowerShell public release gate, existing release evidence JSON, existing desktop MVP gate.

---

### Task 1: Public Gate Plan Contract

**Files:**
- Modify: `scripts/desktop-public-release-gate.tests.ps1`
- Modify: `scripts/desktop-public-release-gate.ps1`

- [ ] **Step 1: Write the failing public gate plan test**

Add these expected lines to `scripts/desktop-public-release-gate.tests.ps1`:

```powershell
'require smoke.install.verified_ui_workflow_entrypoints all_manual_smoke',
'require smoke.install.readme_subscription_import subscription-url-or-config',
'require smoke.msi.manual_smoke_cases all_manual_smoke',
'require smoke.msi.readme_subscription_import subscription-url-or-config',
```

- [ ] **Step 2: Run the public gate plan test to verify it fails**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: FAIL because `desktop-public-release-gate.ps1 -PlanOnly` does not yet declare these workflow evidence requirements.

- [ ] **Step 3: Add PlanOnly requirement lines**

In `desktop-public-release-gate.ps1 -PlanOnly`, after:

```powershell
Write-Output 'require smoke.machine.machine_takeover_status ready'
```

add:

```powershell
Write-Output 'require smoke.install.verified_ui_workflow_entrypoints all_manual_smoke'
Write-Output 'require smoke.install.readme_subscription_import subscription-url-or-config'
Write-Output 'require smoke.msi.manual_smoke_cases all_manual_smoke'
Write-Output 'require smoke.msi.readme_subscription_import subscription-url-or-config'
```

- [ ] **Step 4: Run public gate plan test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: PASS.

### Task 2: Public Gate Workflow Blockers

**Files:**
- Modify: `scripts/desktop-public-release-gate.ps1`

- [ ] **Step 1: Add helper functions**

Add these helpers near `Get-ReleaseBlockers`:

```powershell
function Add-UniqueBlocker {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Blockers,

        [Parameter(Mandatory = $true)]
        [string]$Blocker
    )

    if ($Blockers -notcontains $Blocker) {
        return @($Blockers + $Blocker)
    }
    return $Blockers
}

function Test-StringArrayContainsAll {
    param(
        [AllowNull()]
        [object]$Values,

        [Parameter(Mandatory = $true)]
        [string[]]$Expected
    )

    if ($null -eq $Values) {
        return $false
    }
    $actual = @($Values | ForEach-Object { [string]$_ })
    foreach ($item in $Expected) {
        if ($actual -notcontains $item) {
            return $false
        }
    }
    return $true
}

function Add-WorkflowEvidenceBlockers {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Blockers,

        [Parameter(Mandatory = $true)]
        [object]$Evidence
    )

    $expectedWorkflows = @('open-desktop-shell', 'import-subscription', 'select-node', 'start-stop-system-proxy', 'tun-preflight', 'export-support-bundle')
    if (![bool]($Evidence.smoke.install.readme_subscription_import -eq 'subscription-url-or-config')) {
        $Blockers = Add-UniqueBlocker -Blockers $Blockers -Blocker 'install-readme-subscription-evidence-missing'
    }
    if (!(Test-StringArrayContainsAll -Values $Evidence.smoke.install.manual_smoke_cases -Expected $expectedWorkflows)) {
        $Blockers = Add-UniqueBlocker -Blockers $Blockers -Blocker 'install-manual-smoke-cases-missing'
    }
    if (!(Test-StringArrayContainsAll -Values $Evidence.smoke.install.verified_ui_workflow_entrypoints -Expected $expectedWorkflows)) {
        $Blockers = Add-UniqueBlocker -Blockers $Blockers -Blocker 'install-ui-workflow-entrypoints-missing'
    }
    if (![bool]($Evidence.smoke.msi.readme_subscription_import -eq 'subscription-url-or-config')) {
        $Blockers = Add-UniqueBlocker -Blockers $Blockers -Blocker 'msi-readme-subscription-evidence-missing'
    }
    if (!(Test-StringArrayContainsAll -Values $Evidence.smoke.msi.manual_smoke_cases -Expected $expectedWorkflows)) {
        $Blockers = Add-UniqueBlocker -Blockers $Blockers -Blocker 'msi-manual-smoke-cases-missing'
    }
    return $Blockers
}
```

- [ ] **Step 2: Use workflow blockers in `Get-ReleaseBlockers`**

In `Get-ReleaseBlockers`, after the machine takeover check and before signing checks, add:

```powershell
$blockers = Add-WorkflowEvidenceBlockers -Blockers $blockers -Evidence $Evidence
```

Refactor existing duplicate-blocker additions to use `Add-UniqueBlocker` so new blockers remain unique.

- [ ] **Step 3: Run public gate plan test and current blocked gate**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: plan test PASS. Public gate exits nonzero because signing blockers remain, and the failure message should not include any of the new workflow blocker ids when current release evidence is intact.

### Task 3: Gate Verification And Commit

**Files:**
- Modify: `scripts/desktop-public-release-gate.ps1`
- Modify: `scripts/desktop-public-release-gate.tests.ps1`

- [ ] **Step 1: Run full MVP gate and release readiness**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
```

Expected: MVP gate PASS. Release readiness should still report `machine_takeover_status = "ready"` and only signing blockers until a code-signing certificate is configured.

- [ ] **Step 2: Commit and push implementation**

Run:

```powershell
git add scripts/desktop-public-release-gate.ps1 scripts/desktop-public-release-gate.tests.ps1
git commit -m "Require desktop workflow public gate evidence"
git push
```

Expected: commit pushed to `origin/main`.
