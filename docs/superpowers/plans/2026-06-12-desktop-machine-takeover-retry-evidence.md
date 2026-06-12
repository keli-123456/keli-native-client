# Desktop Machine Takeover Retry Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the hard desktop public-release gate less sensitive to transient machine-takeover smoke noise while keeping every certification attempt auditable.

**Architecture:** Extend `scripts/desktop-machine-smoke.ps1` with bounded machine-takeover certification attempts. The default script behavior remains one attempt, while `scripts/desktop-mvp-gate.ps1 -IncludeMachineTakeover` asks for two attempts for the public-release path. The machine smoke JSON records attempt count, max attempts, per-attempt exit codes/status/blockers, and marks ready only when at least one real certification attempt reports machine takeover ready.

**Tech Stack:** PowerShell 5+, existing `keli-cli default-core-certify --machine-takeover-gate`, existing desktop MVP/public release gate scripts.

---

## Scope Check

This slice covers:

- `-MachineTakeoverAttempts` and `-MachineTakeoverRetryDelaySeconds` parameters on `scripts/desktop-machine-smoke.ps1`.
- Plan-only output that documents retry controls and attempt evidence.
- Per-attempt evidence in `target\desktop\keli-desktop-machine-smoke.json`.
- Public release path using two attempts by passing the setting through `scripts/desktop-mvp-gate.ps1 -IncludeMachineTakeover`.
- Focused tests for plan output only; real retry behavior is verified by running the actual gate.

This slice does not cover:

- Retrying safe probes, packaging, signing, or release evidence generation.
- Treating failed machine takeover as success.
- Changing local safe MVP gate behavior.
- Hiding or deleting failed certification evidence.

## File Structure

- Modify: `scripts/desktop-machine-smoke.ps1`
  - Add retry parameters and per-attempt evidence.
  - Keep default one-attempt behavior.
- Modify: `scripts/desktop-machine-smoke.tests.ps1`
  - Extend plan-only expectations for retry controls and attempt metadata.
- Modify: `scripts/desktop-mvp-gate.ps1`
  - Pass `-MachineTakeoverAttempts 2` only when `-IncludeMachineTakeover` is supplied.
- Modify: `scripts/desktop-mvp-gate.tests.ps1`
  - Assert takeover plan includes the public-release retry setting.

## Task 1: RED Plan Tests

**Files:**
- Modify: `scripts/desktop-machine-smoke.tests.ps1`
- Modify: `scripts/desktop-mvp-gate.tests.ps1`

- [ ] **Step 1: Extend machine smoke plan expectations**

Add these expected strings to `scripts/desktop-machine-smoke.tests.ps1`:

```powershell
'config MachineTakeoverAttempts default 1',
'config MachineTakeoverRetryDelaySeconds default 1',
'metadata machine_takeover_attempts',
'metadata machine_takeover_max_attempts',
'metadata machine_takeover_retry_delay_seconds',
'metadata machine_takeover_attempt_history'
```

- [ ] **Step 2: Extend MVP gate takeover plan expectation**

Add this expected string to `scripts/desktop-mvp-gate.tests.ps1`:

```powershell
'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.ps1 -IncludeMachineTakeover -MachineTakeoverAttempts 2'
```

- [ ] **Step 3: Run RED tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: FAIL because retry controls and attempt metadata are not in plan output yet.

## Task 2: Implement Machine Takeover Attempt Evidence

**Files:**
- Modify: `scripts/desktop-machine-smoke.ps1`

- [ ] **Step 1: Add parameters**

Add:

```powershell
[int]$MachineTakeoverAttempts = 1,
[int]$MachineTakeoverRetryDelaySeconds = 1
```

Add validation after `$ErrorActionPreference = 'Stop'`:

```powershell
if ($MachineTakeoverAttempts -lt 1) {
    throw 'MachineTakeoverAttempts must be at least 1'
}
if ($MachineTakeoverRetryDelaySeconds -lt 0) {
    throw 'MachineTakeoverRetryDelaySeconds must be at least 0'
}
```

- [ ] **Step 2: Extend plan-only output**

Add:

```powershell
config MachineTakeoverAttempts default 1
config MachineTakeoverRetryDelaySeconds default 1
metadata machine_takeover_attempts
metadata machine_takeover_max_attempts
metadata machine_takeover_retry_delay_seconds
metadata machine_takeover_attempt_history
```

- [ ] **Step 3: Split one certification attempt**

Create:

```powershell
function Invoke-MachineTakeoverCertificationAttempt {
    param([int]$Attempt)

    $command = @('cargo', 'run', '-q', '-p', 'keli-cli', '--', 'default-core-certify', '--format', 'json', '--machine-takeover-gate')
    $result = Invoke-TextCommand -Command $command
    $certification = $null
    $parseError = $null
    if (![string]::IsNullOrWhiteSpace($result.Output)) {
        try {
            $certification = Convert-JsonCommandOutput -Output $result.Output -Command $result.Command
        } catch {
            $parseError = $_.Exception.Message
        }
    }

    [ordered]@{
        attempt = $Attempt
        exit_code = $result.ExitCode
        command = $result.Command
        certification = $certification
        parse_error = $parseError
    }
}
```

- [ ] **Step 4: Summarize attempts**

Add helpers that convert an attempt to compact JSON:

```powershell
Get-MachineTakeoverAttemptReady
Get-MachineTakeoverAttemptBlockers
Convert-MachineTakeoverAttemptEvidence
```

`Convert-MachineTakeoverAttemptEvidence` must output:

```powershell
[ordered]@{
    attempt = $Attempt.attempt
    exit_code = $Attempt.exit_code
    ready = $ready
    status = if ($ready) { 'ready' } else { 'failed' }
    blockers = $blockers
    release_gate_status = $releaseGateStatus
}
```

- [ ] **Step 5: Retry requested machine takeover**

Update `Get-MachineTakeoverStatus` so requested takeover:

- runs up to `$MaxAttempts`;
- stops early after a ready attempt;
- sleeps `$RetryDelaySeconds` between failed attempts;
- stores compact attempts under `attempt_history`;
- sets `attempts` and `max_attempts`;
- keeps the final certification summary for compatibility;
- returns `status='ready'` only if a ready attempt exists.

## Task 3: Wire Public Release Path To Two Attempts

**Files:**
- Modify: `scripts/desktop-mvp-gate.ps1`

- [ ] **Step 1: Extend machine smoke command**

Change `New-MachineSmokeCommand` so it appends:

```powershell
'-MachineTakeoverAttempts', '2'
```

only when `$IncludeMachineTakeover` is set.

## Task 4: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-machine-takeover-retry-evidence.md`
- `scripts/desktop-machine-smoke.ps1`
- `scripts/desktop-machine-smoke.tests.ps1`
- `scripts/desktop-mvp-gate.ps1`
- `scripts/desktop-mvp-gate.tests.ps1`

- [ ] **Step 1: Focused tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Actual one-attempt smoke**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.ps1 -IncludeMachineTakeover
```

Expected: PASS on a ready machine and JSON includes `attempts: 1`, `max_attempts: 1`, and one `attempt_history` item.

- [ ] **Step 3: Public release gate**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1
```

Expected: FAIL only with signing blockers `artifact-signature-missing` and `signing-certificate-missing` until a signing certificate is configured. Release evidence machine status remains `ready`.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-machine-takeover-retry-evidence.md
git commit -m "Plan desktop machine takeover retry evidence"
git push origin main
git add scripts/desktop-machine-smoke.ps1 scripts/desktop-machine-smoke.tests.ps1 scripts/desktop-mvp-gate.ps1 scripts/desktop-mvp-gate.tests.ps1
git commit -m "Add desktop machine takeover retry evidence"
git push origin main
```

## Self-Review Checklist

- Spec coverage: supports public-release stability while preserving hard machine takeover evidence.
- Placeholder scan: commands, parameters, and JSON fields are concrete.
- Scope: no signing or packaging behavior changes.
- Release honesty: failed attempts remain visible, and public release still requires real machine takeover readiness plus signing readiness.
