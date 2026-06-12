# Desktop Machine Takeover Evidence Preservation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep public-release readiness stable after the ordinary desktop MVP gate by preserving prior ready machine-takeover evidence during safe-probe machine smoke runs.

**Architecture:** `scripts/desktop-machine-smoke.ps1` remains the source of machine evidence. When run without `-IncludeMachineTakeover`, it still performs safe local probes, but if the existing machine smoke evidence already contains a ready machine-takeover result, the new report carries that takeover result forward with explicit preservation metadata. Explicit `-IncludeMachineTakeover` runs still execute fresh certification attempts and overwrite the evidence.

**Tech Stack:** PowerShell 5+, existing desktop gate scripts, existing JSON evidence files under `target\desktop`.

---

### Task 1: Plan-Only Contract

**Files:**
- Modify: `scripts/desktop-machine-smoke.tests.ps1`
- Modify: `scripts/desktop-machine-smoke.ps1`

- [ ] **Step 1: Write the failing plan-only test**

Add this expected plan marker to `scripts/desktop-machine-smoke.tests.ps1`:

```powershell
'metadata machine_takeover_ready_evidence_preserved_on_safe_probe',
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.tests.ps1
```

Expected: FAIL with `desktop machine smoke plan is missing: metadata machine_takeover_ready_evidence_preserved_on_safe_probe`.

- [ ] **Step 3: Add the plan marker**

Add this line to the `-PlanOnly` output in `scripts/desktop-machine-smoke.ps1`:

```powershell
Write-Output 'metadata machine_takeover_ready_evidence_preserved_on_safe_probe'
```

- [ ] **Step 4: Run the test to verify it passes**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.tests.ps1
```

Expected: PASS with `desktop machine smoke plan test passed`.

### Task 2: Safe-Probe Preservation

**Files:**
- Modify: `scripts/desktop-machine-smoke.ps1`

- [ ] **Step 1: Add preservation helpers**

Add helpers that read existing machine smoke JSON only when safe-probe mode is used:

```powershell
function Read-ExistingMachineTakeoverEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EvidencePath
    )

    if (!(Test-Path -LiteralPath $EvidencePath -PathType Leaf)) {
        return $null
    }

    try {
        $existing = Get-Content -Raw -LiteralPath $EvidencePath | ConvertFrom-Json
    } catch {
        return $null
    }

    if ($null -eq $existing.PSObject.Properties['machine_takeover']) {
        return $null
    }

    if ([string]$existing.machine_takeover.status -ne 'ready') {
        return $null
    }

    return $existing.machine_takeover
}

function Get-PreservedMachineTakeoverStatus {
    param(
        [AllowNull()]
        [object]$ExistingMachineTakeover,

        [Parameter(Mandatory = $true)]
        [int]$MaxAttempts,

        [Parameter(Mandatory = $true)]
        [int]$RetryDelaySeconds
    )

    if ($null -eq $ExistingMachineTakeover) {
        return Get-MachineTakeoverStatus -Requested:$false -MaxAttempts $MaxAttempts -RetryDelaySeconds $RetryDelaySeconds
    }

    $preserved = [ordered]@{}
    foreach ($property in $ExistingMachineTakeover.PSObject.Properties) {
        $preserved[$property.Name] = $property.Value
    }
    $preserved['preserved_from_previous_ready_evidence'] = $true
    $preserved['preserved_by_mode'] = 'safe-probe'
    return $preserved
}
```

- [ ] **Step 2: Use the helpers when building the report**

Before `$report = [ordered]@{ ... }`, add:

```powershell
$existingMachineTakeover = if ($IncludeMachineTakeover) { $null } else { Read-ExistingMachineTakeoverEvidence -EvidencePath $evidencePath }
$machineTakeover = if ($IncludeMachineTakeover) {
    Get-MachineTakeoverStatus -Requested:$true -MaxAttempts $MachineTakeoverAttempts -RetryDelaySeconds $MachineTakeoverRetryDelaySeconds
} else {
    Get-PreservedMachineTakeoverStatus -ExistingMachineTakeover $existingMachineTakeover -MaxAttempts $MachineTakeoverAttempts -RetryDelaySeconds $MachineTakeoverRetryDelaySeconds
}
```

Then set the report field to:

```powershell
machine_takeover = $machineTakeover
```

- [ ] **Step 3: Run focused script test**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.tests.ps1
```

Expected: PASS.

### Task 3: End-to-End Evidence Check

**Files:**
- Modify: `scripts/desktop-machine-smoke.ps1`
- Test evidence: `target\desktop\keli-desktop-machine-smoke.json`
- Test evidence: `target\desktop\keli-desktop-release-evidence.json`

- [ ] **Step 1: Generate ready takeover evidence**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.ps1 -IncludeMachineTakeover -MachineTakeoverAttempts 2
```

Expected: exit 0 and `target\desktop\keli-desktop-machine-smoke.json` has `machine_takeover.status = "ready"`.

- [ ] **Step 2: Run the ordinary MVP gate**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: exit 0. The generated machine smoke evidence still has `machine_takeover.status = "ready"` and includes `preserved_from_previous_ready_evidence = true`.

- [ ] **Step 3: Verify release readiness**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
```

Expected: `machine_takeover_status = "ready"`. Public release remains blocked only by `artifact-signature-missing` and `signing-certificate-missing`.

### Task 4: Commit

**Files:**
- Modify: `scripts/desktop-machine-smoke.ps1`
- Modify: `scripts/desktop-machine-smoke.tests.ps1`

- [ ] **Step 1: Commit implementation**

Run:

```powershell
git add scripts/desktop-machine-smoke.ps1 scripts/desktop-machine-smoke.tests.ps1
git commit -m "Preserve desktop machine takeover evidence"
git push
```

Expected: commit pushed to `origin/main`.
