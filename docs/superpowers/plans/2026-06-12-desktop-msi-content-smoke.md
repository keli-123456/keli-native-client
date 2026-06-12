# Desktop MSI Content Smoke Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make MSI smoke evidence prove that the MSI-embedded README and manifest carry the same subscription and workflow evidence as the portable package.

**Architecture:** Extend `desktop-msi.ps1` administrative extraction smoke to read the extracted `README.txt` and `keli-desktop-manifest.json`. The smoke will require the subscription URL/local-config README instruction and all desktop MVP manual smoke workflow ids, then include those verified fields in `keli-desktop-msi-smoke.json`.

**Tech Stack:** PowerShell MSI packaging/smoke, existing desktop MVP gate.

---

### Task 1: MSI Plan Contract

**Files:**
- Modify: `scripts/desktop-msi.tests.ps1`
- Modify: `scripts/desktop-msi.ps1`

- [ ] **Step 1: Write the failing MSI plan test**

Add these expected lines to `scripts/desktop-msi.tests.ps1`:

```powershell
'admin_extract readme import-subscription-url-or-config',
'admin_extract manifest manual_smoke import-subscription',
```

- [ ] **Step 2: Run the MSI plan test to verify it fails**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-msi.tests.ps1
```

Expected: FAIL because `desktop-msi.ps1 -PlanOnly` does not yet declare README/manifest content checks.

- [ ] **Step 3: Add PlanOnly content evidence lines**

In `desktop-msi.ps1 -PlanOnly`, after:

```powershell
Write-Output 'admin_extract target\desktop-msi-admin-smoke'
```

add:

```powershell
Write-Output 'admin_extract readme import-subscription-url-or-config'
Write-Output 'admin_extract manifest manual_smoke import-subscription'
```

- [ ] **Step 4: Run the MSI plan test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-msi.tests.ps1
```

Expected: PASS.

### Task 2: MSI Admin Extract Content Checks

**Files:**
- Modify: `scripts/desktop-msi.ps1`

- [ ] **Step 1: Add helper functions**

Add these helpers near the existing file/path helper functions:

```powershell
function Require-FileContains {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $content = Get-Content -Raw -LiteralPath $Path
    if (!$content.Contains($Text)) {
        throw "required MSI extracted file content is missing from $Path`: $Text"
    }
}

function Require-ManifestSmokeCase {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Manifest,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (!($Manifest.manual_smoke -contains $Name)) {
        throw "MSI extracted manifest manual_smoke is missing: $Name"
    }
}
```

- [ ] **Step 2: Validate extracted README and manifest**

After verifying the three extracted files exist, add:

```powershell
$extractedReadme = Join-Path $AdminExtractDir 'Keli\README.txt'
$extractedManifestPath = Join-Path $AdminExtractDir 'Keli\keli-desktop-manifest.json'
Require-FileContains -Path $extractedReadme -Text 'Import a subscription URL or local subscription config.'
$extractedManifest = Get-Content -Raw -LiteralPath $extractedManifestPath | ConvertFrom-Json
foreach ($case in @('open-desktop-shell', 'import-subscription', 'select-node', 'start-stop-system-proxy', 'tun-preflight', 'export-support-bundle')) {
    Require-ManifestSmokeCase -Manifest $extractedManifest -Name $case
}
```

Add these fields to the smoke result:

```powershell
readme_subscription_import = 'subscription-url-or-config'
manual_smoke_cases = $extractedManifest.manual_smoke
```

- [ ] **Step 3: Run MSI plan test and full MVP gate**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-msi.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS.

### Task 3: Release Readiness And Commit

**Files:**
- Modify: `scripts/desktop-msi.ps1`
- Modify: `scripts/desktop-msi.tests.ps1`

- [ ] **Step 1: Check release readiness**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
```

Expected: `machine_takeover_status = "ready"` and public release blockers remain only signing blockers until a code-signing certificate is configured.

- [ ] **Step 2: Commit and push implementation**

Run:

```powershell
git add scripts/desktop-msi.ps1 scripts/desktop-msi.tests.ps1
git commit -m "Verify desktop MSI content smoke"
git push
```

Expected: commit pushed to `origin/main`.
