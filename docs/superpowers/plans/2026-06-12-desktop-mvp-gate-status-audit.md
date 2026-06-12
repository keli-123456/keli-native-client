# Desktop MVP Gate Status Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the desktop MVP status audit automatically at the end of the desktop MVP gate.

**Architecture:** Keep `scripts/desktop-mvp-status.ps1` as a read-only report over generated release evidence. Add it as the final `scripts/desktop-mvp-gate.ps1` step after release evidence generation, so every full gate run prints the local MVP/public release split without changing pass/fail semantics.

**Tech Stack:** PowerShell 5+, existing desktop MVP gate steps, existing desktop release evidence and MVP status scripts.

---

## Scope Check

This slice covers:

- Adding `Desktop MVP status audit` as the final MVP gate step.
- Extending `scripts/desktop-mvp-gate.tests.ps1` PlanOnly expectations.
- Exposing the status audit command and script path in gate output.

This slice does not cover:

- Changing public release gate criteria.
- Failing the local MVP gate when public release signing is still blocked.
- Regenerating a new status artifact file.
- Signing artifacts.

## File Structure

- Modify: `scripts/desktop-mvp-gate.tests.ps1`
  - Add the status audit command to PlanOnly expectations.
- Modify: `scripts/desktop-mvp-gate.ps1`
  - Add `Desktop MVP status audit` as the final gate step after `Desktop release evidence`.

## Task 1: RED Gate Plan Test

**Files:**
- Modify: `scripts/desktop-mvp-gate.tests.ps1`

- [ ] **Step 1: Add expected status command**

Add this expected command after the release evidence command:

```powershell
'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.ps1'
```

- [ ] **Step 2: Run RED test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: FAIL because the MVP gate plan does not yet include the status audit command.

## Task 2: GREEN Gate Integration

**Files:**
- Modify: `scripts/desktop-mvp-gate.ps1`

- [ ] **Step 1: Add final gate step**

After the `Desktop release evidence` step, add:

```powershell
New-GateStep -Name 'Desktop MVP status audit' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-mvp-status.ps1')
```

- [ ] **Step 2: Run GREEN test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-mvp-gate-status-audit.md`
- `scripts/desktop-mvp-gate.ps1`
- `scripts/desktop-mvp-gate.tests.ps1`

- [ ] **Step 1: Focused tests**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Full desktop MVP gate**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS and print `Desktop MVP status audit` after `Desktop release evidence`.

- [ ] **Step 3: Actual status report**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.ps1 -Json
```

Expected: `desktop_mvp_ready = true`, `public_release_ready = false`, and remaining blockers are only signing blockers until a valid certificate is configured.

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-mvp-gate-status-audit.md
git commit -m "Plan desktop MVP gate status audit"
git push
git add scripts/desktop-mvp-gate.ps1 scripts/desktop-mvp-gate.tests.ps1
git commit -m "Run desktop MVP status audit in gate"
git push
```

## Self-Review Checklist

- Spec coverage: every full desktop MVP gate now reports local MVP and public release status.
- Placeholder scan: commands and paths are concrete.
- Type consistency: the command matches the existing `desktop-mvp-status.ps1` interface.
- Scope: no release criteria are weakened or broadened.
- Release honesty: signing blockers remain visible in the status audit and public gate.
