# Desktop Release Signing Preview Aggregation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Carry redacted signing command previews from signing evidence into release evidence and readiness output so release operators can inspect the signing command shape from the top-level reports.

**Architecture:** Keep `scripts/desktop-signing.ps1` as the source of truth for preview generation. `scripts/desktop-release-evidence.ps1` reads and preserves the non-secret preview records. `scripts/desktop-release-readiness.ps1` exposes those records in JSON and a short text count without changing readiness semantics.

**Tech Stack:** PowerShell 5+, existing desktop release evidence and readiness scripts.

---

## Scope Check

This slice covers:

- `signing.sign_command_previews` in `target\desktop\keli-desktop-release-evidence.json`.
- `signing.sign_command_previews` in `desktop-release-readiness.ps1 -Json`.
- A text readiness count so operators can see whether previews are present.
- Tests that preserve redacted command text and reject missing aggregation.

This slice does not cover:

- Generating previews in signing evidence.
- Signing artifacts.
- Installing or creating certificates.
- Changing public release readiness semantics.
- Printing certificate passwords or local PFX paths.

## File Structure

- Modify: `scripts/desktop-release-evidence.tests.ps1`
  - Add PlanOnly expectation for signing command previews.
- Modify: `scripts/desktop-release-readiness.tests.ps1`
  - Add PlanOnly expectation and JSON fixture assertions for redacted previews.
- Modify: `scripts/desktop-release-evidence.ps1`
  - Read `sign_command_previews` from signing evidence and include it under `signing`.
- Modify: `scripts/desktop-release-readiness.ps1`
  - Read `signing.sign_command_previews`, expose it in JSON, and print a count in text mode.

## Task 1: RED Release/Readiness Preview Tests

**Files:**
- Modify: `scripts/desktop-release-evidence.tests.ps1`
- Modify: `scripts/desktop-release-readiness.tests.ps1`

- [ ] **Step 1: Add release evidence PlanOnly expectation**

Add:

```powershell
'metadata signing_command_previews'
```

- [ ] **Step 2: Add readiness PlanOnly expectation**

Replace the signing read expectation with one that includes:

```powershell
signing.sign_command_previews
```

- [ ] **Step 3: Add readiness JSON fixture assertions**

Add a fixture preview:

```powershell
sign_command_previews = @(
    [ordered]@{
        artifact = 'target\release\keli-desktop-shell.exe'
        signing_method = 'pfx'
        command = 'signtool sign /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com /f <KELI_SIGN_CERT_PATH> /p <redacted> target\release\keli-desktop-shell.exe'
    }
)
```

Assert that the readiness JSON preserves the preview command and still does not contain a real password.

- [ ] **Step 4: Run RED tests**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
```

Expected: FAIL because the scripts do not yet declare or expose signing command previews.

## Task 2: GREEN Preview Aggregation

**Files:**
- Modify: `scripts/desktop-release-evidence.ps1`
- Modify: `scripts/desktop-release-readiness.ps1`

- [ ] **Step 1: Extend release evidence PlanOnly**

Add:

```powershell
Write-Output 'metadata signing_command_previews'
```

- [ ] **Step 2: Preserve previews in release evidence signing summary**

Read `sign_command_previews` from signing evidence into stable objects:

```powershell
$signCommandPreviews = @()
if ($null -ne $signing.PSObject.Properties['sign_command_previews']) {
    $signCommandPreviews = @($signing.sign_command_previews | ForEach-Object {
        [ordered]@{
            artifact = [string]$_.artifact
            signing_method = [string]$_.signing_method
            command = [string]$_.command
        }
    })
}
```

Add `sign_command_previews = $signCommandPreviews` under `signing`.

- [ ] **Step 3: Expose previews in readiness report**

Add a helper that reads preview objects from `signing.sign_command_previews`, include the array under `Report.signing`, and print:

```powershell
signing_command_previews_count N
```

- [ ] **Step 4: Run GREEN tests**

Run the two focused tests again. Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-release-signing-preview-aggregation.md`
- `scripts/desktop-release-evidence.ps1`
- `scripts/desktop-release-evidence.tests.ps1`
- `scripts/desktop-release-readiness.ps1`
- `scripts/desktop-release-readiness.tests.ps1`

- [ ] **Step 1: Focused tests**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Regenerate real release evidence and readiness**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
```

Expected: PASS. With no signing method configured, preview arrays are empty and public release remains blocked only by signing.

- [ ] **Step 3: Full desktop MVP gate**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS.

- [ ] **Step 4: Public release honesty check**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: FAIL only with signing blockers until a real signing certificate signs the EXE/MSI.

- [ ] **Step 5: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-release-signing-preview-aggregation.md
git commit -m "Plan desktop release signing preview aggregation"
git push
git add scripts/desktop-release-evidence.ps1 scripts/desktop-release-evidence.tests.ps1 scripts/desktop-release-readiness.ps1 scripts/desktop-release-readiness.tests.ps1
git commit -m "Expose desktop signing previews in release readiness"
git push
```

## Self-Review Checklist

- Spec coverage: top-level release/readiness reports expose the same redacted command previews as signing evidence.
- Placeholder scan: no real passwords, PFX paths, or secrets appear in tests or outputs.
- Type consistency: preview records keep stable `artifact`, `signing_method`, and `command` fields.
- Scope: release readiness semantics remain unchanged.
- Release honesty: public release remains blocked until real signatures and signing configuration are valid.
