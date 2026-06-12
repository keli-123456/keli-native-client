# Desktop Public Gate Signing Preview Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the hard public release gate failure output show whether redacted signing command previews are available for the blocked artifacts.

**Architecture:** Keep signing command construction in `scripts/desktop-signing.ps1` and aggregation in release evidence/readiness. Extend only `scripts/desktop-public-release-gate.ps1` diagnostics so it reports preview count and preview artifact paths when `signing.sign_command_previews` is present.

**Tech Stack:** PowerShell 5+, existing public release gate fixture tests.

---

## Scope Check

This slice covers:

- PlanOnly documentation for preview diagnostics in `desktop-public-release-gate.ps1`.
- Blocked public gate output containing `signing_command_previews_count=N` when previews exist.
- Blocked public gate output containing `signing_command_preview_artifacts=...` when previews exist.

This slice does not cover:

- Printing full signing commands in public gate exceptions.
- Generating signing previews.
- Signing artifacts.
- Installing or creating certificates.
- Changing public release pass/fail semantics.

## File Structure

- Modify: `scripts/desktop-public-release-gate.tests.ps1`
  - Add a fixture `signing.sign_command_previews` record.
  - Require PlanOnly to mention signing command preview diagnostics.
  - Require blocked output to include preview count and preview artifact paths.
- Modify: `scripts/desktop-public-release-gate.ps1`
  - Extend optional signing diagnostics to include preview count and artifact list.

## Task 1: RED Public Gate Preview Diagnostics Test

**Files:**
- Modify: `scripts/desktop-public-release-gate.tests.ps1`

- [ ] **Step 1: Add PlanOnly expectation**

Add:

```powershell
'failure print signing command preview diagnostics when available'
```

- [ ] **Step 2: Add preview fixture**

Add under `signing`:

```powershell
sign_command_previews = @(
    [ordered]@{
        artifact = 'target\release\keli-desktop-shell.exe'
        signing_method = 'pfx'
        command = 'signtool sign /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com /f <KELI_SIGN_CERT_PATH> /p <redacted> target\release\keli-desktop-shell.exe'
    }
)
```

- [ ] **Step 3: Add blocked-output expectations**

Add:

```powershell
'signing_command_previews_count=1',
'signing_command_preview_artifacts=target\release\keli-desktop-shell.exe'
```

- [ ] **Step 4: Run RED test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: FAIL because the gate does not yet declare or print preview diagnostics.

## Task 2: GREEN Preview Diagnostics

**Files:**
- Modify: `scripts/desktop-public-release-gate.ps1`

- [ ] **Step 1: Extend optional signing diagnostics**

Add this after unsigned artifact diagnostics:

```powershell
if (Test-JsonProperty -InputObject $signing -Name 'sign_command_previews') {
    $previewArtifacts = @($signing.sign_command_previews |
        ForEach-Object { [string]$_.artifact } |
        Where-Object { ![string]::IsNullOrWhiteSpace($_) })
    if ($previewArtifacts.Count -gt 0) {
        $parts += "signing_command_previews_count=$($previewArtifacts.Count)"
        $parts += "signing_command_preview_artifacts=$($previewArtifacts -join ',')"
    }
}
```

- [ ] **Step 2: Extend PlanOnly output**

Add:

```powershell
Write-Output 'failure print signing command preview diagnostics when available'
```

- [ ] **Step 3: Run GREEN test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `docs/superpowers/plans/2026-06-12-desktop-public-gate-signing-preview-diagnostics.md`
- `scripts/desktop-public-release-gate.ps1`
- `scripts/desktop-public-release-gate.tests.ps1`

- [ ] **Step 1: Focused test**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Real public gate honesty check**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: FAIL only with signing blockers. On the current unsigned local machine with no configured signing method, preview diagnostics may be absent because no previews are configured.

- [ ] **Step 3: Full desktop MVP gate**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: PASS.

- [ ] **Step 4: Diff check**

Run:

```powershell
git diff --check
```

Expected: PASS.

- [ ] **Step 5: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-public-gate-signing-preview-diagnostics.md
git commit -m "Plan public gate signing preview diagnostics"
git push
git add scripts/desktop-public-release-gate.ps1 scripts/desktop-public-release-gate.tests.ps1
git commit -m "Print public gate signing preview diagnostics"
git push
```

## Self-Review Checklist

- Spec coverage: blocked public gate output makes preview availability visible.
- Placeholder scan: no TBD/TODO/fill-in placeholders remain.
- Type consistency: field names match `signing.sign_command_previews` from release evidence.
- Scope: full commands are not printed in gate exceptions.
- Release honesty: public release remains blocked until real signatures and signing configuration are valid.
