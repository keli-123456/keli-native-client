# Desktop MVP Status Fail On Blocked Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the desktop MVP gate fail when local MVP requirements regress while still allowing public release signing blockers to remain visible but non-fatal for the local gate.

**Architecture:** Extend `scripts/desktop-mvp-status.ps1` with `-FailOnMvpBlocked`. The switch exits nonzero only when `desktop_mvp_ready` is false. Update `scripts/desktop-mvp-gate.ps1` to run the status audit with that switch as the final step.

**Tech Stack:** PowerShell 5+, existing desktop MVP status report, existing desktop MVP gate.

---

## Scope Check

This slice covers:

- `scripts/desktop-mvp-status.ps1 -FailOnMvpBlocked`.
- A deterministic fixture test proving local MVP blockers fail the status script.
- A deterministic fixture test proving signing-only public release blockers do not fail `-FailOnMvpBlocked`.
- Updating the MVP gate final step to use `-FailOnMvpBlocked`.

This slice does not cover:

- Failing the local MVP gate for public release signing blockers.
- Changing public release gate behavior.
- Signing artifacts.
- Changing status JSON shape.

## File Structure

- Modify: `scripts/desktop-mvp-status.tests.ps1`
  - Add PlanOnly expectation for `-FailOnMvpBlocked`.
  - Assert signing-only fixture exits 0 with `-FailOnMvpBlocked`.
  - Add a local-blocked fixture and assert `-FailOnMvpBlocked` exits nonzero with the blocked requirement ID.
- Modify: `scripts/desktop-mvp-status.ps1`
  - Add `-FailOnMvpBlocked` switch.
  - Throw only when `desktop_mvp_ready` is false.
- Modify: `scripts/desktop-mvp-gate.tests.ps1`
  - Expect the status audit command with `-FailOnMvpBlocked`.
- Modify: `scripts/desktop-mvp-gate.ps1`
  - Run status audit with `-FailOnMvpBlocked`.

## Task 1: RED Status Fail-On-Blocked Tests

**Files:**
- Modify: `scripts/desktop-mvp-status.tests.ps1`

- [ ] **Step 1: Add PlanOnly expectation**

Add:

```powershell
'config -FailOnMvpBlocked optional'
```

- [ ] **Step 2: Prove signing-only blockers do not fail local status**

After the existing JSON fixture assertions, add:

```powershell
& powershell -NoProfile -ExecutionPolicy Bypass -File $statusScript -EvidencePath $fixturePath -FailOnMvpBlocked
if ($LASTEXITCODE -ne 0) {
    throw "desktop-mvp-status.ps1 -FailOnMvpBlocked should ignore signing-only public release blockers"
}
```

- [ ] **Step 3: Add local-blocked fixture**

Create a second fixture by copying `$fixture`, but remove one install workflow:

```powershell
$blockedFixturePath = Join-Path $tempDir 'release-evidence-local-blocked.json'
$blockedFixture = $fixture
$blockedFixture.smoke.install.verified_ui_workflow_entrypoints = @(
    'open-desktop-shell',
    'import-subscription',
    'select-node',
    'start-stop-system-proxy',
    'tun-preflight'
)
$blockedFixture | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $blockedFixturePath -Encoding ASCII
```

- [ ] **Step 4: Assert local-blocked exit**

Run the script in a child process and assert nonzero plus blocked requirement text:

```powershell
$stdoutPath = Join-Path $tempDir 'status-blocked-stdout.txt'
$stderrPath = Join-Path $tempDir 'status-blocked-stderr.txt'
$process = Start-Process `
    -FilePath 'powershell' `
    -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $statusScript, '-EvidencePath', $blockedFixturePath, '-FailOnMvpBlocked') `
    -NoNewWindow `
    -Wait `
    -PassThru `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath
if ($process.ExitCode -eq 0) {
    throw 'desktop-mvp-status.ps1 -FailOnMvpBlocked should fail local blocked fixture'
}
$failureText = @(
    if (Test-Path -LiteralPath $stdoutPath) { Get-Content -LiteralPath $stdoutPath }
    if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath }
) -join "`n"
if (!$failureText.Contains('Desktop MVP status blocked: install-smoke-workflows')) {
    throw "local blocked failure did not name install-smoke-workflows: $failureText"
}
```

- [ ] **Step 5: Run RED test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
```

Expected: FAIL because `-FailOnMvpBlocked` is not implemented.

## Task 2: GREEN Status Fail-On-Blocked

**Files:**
- Modify: `scripts/desktop-mvp-status.ps1`

- [ ] **Step 1: Add switch**

Add parameter:

```powershell
[switch]$FailOnMvpBlocked
```

- [ ] **Step 2: Add PlanOnly line**

Add:

```powershell
Write-Output 'config -FailOnMvpBlocked optional'
```

- [ ] **Step 3: Throw on local MVP blockers**

After `$report = New-DesktopMvpStatus -Evidence $evidence`, before output:

```powershell
if ($FailOnMvpBlocked -and !$report.desktop_mvp_ready) {
    $blockedRequirements = @($report.requirements | Where-Object {
        $_.id -ne 'public-release-signing' -and $_.status -ne 'ready'
    } | ForEach-Object { [string]$_.id })
    throw "Desktop MVP status blocked: $($blockedRequirements -join ',')"
}
```

- [ ] **Step 4: Run GREEN status test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
```

Expected: PASS.

## Task 3: RED/GREEN Gate Integration

**Files:**
- Modify: `scripts/desktop-mvp-gate.tests.ps1`
- Modify: `scripts/desktop-mvp-gate.ps1`

- [ ] **Step 1: RED gate plan expectation**

Replace:

```powershell
'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.ps1'
```

with:

```powershell
'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.ps1 -FailOnMvpBlocked'
```

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: FAIL until the gate command is updated.

- [ ] **Step 2: Update final gate command**

Change the final gate step to:

```powershell
New-GateStep -Name 'Desktop MVP status audit' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-mvp-status.ps1', '-FailOnMvpBlocked')
```

- [ ] **Step 3: Run GREEN gate test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: PASS.

## Task 4: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-mvp-status-fail-on-blocked.md`
- `scripts/desktop-mvp-status.ps1`
- `scripts/desktop-mvp-status.tests.ps1`
- `scripts/desktop-mvp-gate.ps1`
- `scripts/desktop-mvp-gate.tests.ps1`

- [ ] **Step 1: Focused tests**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Actual fail-on-blocked status**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.ps1 -FailOnMvpBlocked
```

Expected: PASS because current local MVP requirements are ready.

- [ ] **Step 3: Full desktop MVP gate**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS and status audit runs with `-FailOnMvpBlocked`.

- [ ] **Step 4: Public release honesty check**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: FAIL only with signing blockers until a signing certificate is configured.

- [ ] **Step 5: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-mvp-status-fail-on-blocked.md
git commit -m "Plan desktop MVP status fail on blocked"
git push
git add scripts/desktop-mvp-status.ps1 scripts/desktop-mvp-status.tests.ps1 scripts/desktop-mvp-gate.ps1 scripts/desktop-mvp-gate.tests.ps1
git commit -m "Fail desktop MVP gate on local status blockers"
git push
```

## Self-Review Checklist

- Spec coverage: local MVP regressions now fail the local gate.
- Placeholder scan: commands, flags, and expected failure text are concrete.
- Type consistency: `desktop_mvp_ready` and requirement IDs match the status script.
- Scope: public release signing blockers stay visible but do not fail local MVP status.
- Release honesty: public release gate remains the hard signing gate.
