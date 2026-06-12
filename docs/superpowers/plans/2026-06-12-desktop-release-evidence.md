# Desktop Release Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate a release evidence manifest for the Windows desktop MVP artifacts so every local release gate records artifact hashes, version, smoke results, signing status, and remaining public-release blockers.

**Architecture:** Add a PowerShell release evidence script after MSI generation in the desktop MVP gate. The script reads existing portable, install-smoke, and MSI-smoke outputs, computes SHA-256 hashes for the EXE/ZIP/MSI, records Authenticode status for signable artifacts, and writes a single JSON file under `target\desktop\keli-desktop-release-evidence.json`. Local MVP gates may pass with unsigned artifacts, but the evidence must explicitly report a public-release blocker when signatures are missing.

**Tech Stack:** PowerShell 5+, built-in `Get-FileHash`, `Get-AuthenticodeSignature`, existing desktop package/install/MSI smoke artifacts.

---

## Scope Check

This plan covers:

- Release evidence JSON for desktop EXE, portable ZIP, and MSI.
- Artifact SHA-256, byte size, and Authenticode signature status.
- Version and native-core-default metadata.
- Inclusion of install smoke and MSI smoke status.
- Gate integration after MSI generation.
- A clear `public_release_ready` boolean and blocker list.

This plan does not cover:

- Actually signing artifacts.
- Timestamp server configuration.
- Certificate provisioning or secret management.
- Publishing GitHub releases.

## File Structure

- Create: `scripts/desktop-release-evidence.ps1`
  - Generates and validates `target\desktop\keli-desktop-release-evidence.json`.
- Create: `scripts/desktop-release-evidence.tests.ps1`
  - Verifies plan-only output includes inputs, artifact hashes, signature status, smoke inputs, and output JSON.
- Modify: `scripts/desktop-mvp-gate.ps1`
  - Add `Desktop release evidence` step after `Desktop MSI installer`.
- Modify: `scripts/desktop-mvp-gate.tests.ps1`
  - Assert plan output includes release evidence script and artifact.

## Task 1: RED Tests

**Files:**
- Create: `scripts/desktop-release-evidence.tests.ps1`
- Modify: `scripts/desktop-mvp-gate.tests.ps1`

- [ ] **Step 1: Add release evidence plan test**

Create `scripts/desktop-release-evidence.tests.ps1`:

```powershell
$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $releaseScript -PlanOnly
$plan = $output -join "`n"
$expected = @(
    'input target\release\keli-desktop-shell.exe',
    'input target\desktop\keli-desktop-mvp-windows-x64.zip',
    'input target\desktop\keli-desktop-mvp-windows-x64.msi',
    'input target\desktop-install-smoke\desktop-install-smoke.json',
    'input target\desktop\keli-desktop-msi-smoke.json',
    'hash sha256 exe zip msi',
    'signature authenticode exe msi',
    'metadata native_core_default true',
    'metadata public_release_ready false_when_unsigned',
    'output target\desktop\keli-desktop-release-evidence.json'
)
```

- [ ] **Step 2: Add MVP gate plan expectations**

Add these expected strings to `scripts/desktop-mvp-gate.tests.ps1`:

```powershell
'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1',
'target\desktop\keli-desktop-release-evidence.json'
```

- [ ] **Step 3: Run RED tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: FAIL because the script and gate step do not exist.

## Task 2: Implement Release Evidence Script

**Files:**
- Create: `scripts/desktop-release-evidence.ps1`

- [ ] **Step 1: Add helpers**

Add:

```powershell
Resolve-RepoRoot
Get-WorkspaceVersion
Require-File
Get-ArtifactEvidence
Get-SignatureEvidence
Read-SmokeStatus
```

- [ ] **Step 2: Generate evidence**

The evidence JSON must include:

```json
{
  "status": "passed",
  "version": "0.1.x",
  "native_core_default": true,
  "public_release_ready": false,
  "public_release_blockers": ["artifact-signature-missing"],
  "artifacts": [
    {
      "kind": "desktop-shell-exe",
      "path": "target\\release\\keli-desktop-shell.exe",
      "sha256": "...",
      "bytes": 123,
      "signature": { "status": "NotSigned", "signed": false }
    }
  ],
  "smoke": {
    "install": { "status": "passed" },
    "msi": { "status": "passed" }
  }
}
```

- [ ] **Step 3: Validate evidence before writing success**

Require:

- all artifacts exist and have non-empty SHA-256 hashes;
- install smoke status is `passed`;
- MSI smoke status is `passed`;
- at least EXE and MSI have signature evidence;
- `public_release_ready` is false if any signable artifact is unsigned.

## Task 3: Gate Integration

**Files:**
- Modify: `scripts/desktop-mvp-gate.ps1`
- Modify: `scripts/desktop-mvp-gate.tests.ps1`

- [ ] **Step 1: Add gate step**

Add:

```powershell
New-GateStep -Name 'Desktop release evidence' -Command @('powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts\desktop-release-evidence.ps1')
```

- [ ] **Step 2: Add plan artifact**

Add:

```powershell
Write-Output 'artifact target\desktop\keli-desktop-release-evidence.json'
```

- [ ] **Step 3: Run GREEN plan tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
```

Expected: PASS.

## Task 4: Verification, Commit, And Push

**Files:**
- `scripts/desktop-release-evidence.ps1`
- `scripts/desktop-release-evidence.tests.ps1`
- `scripts/desktop-mvp-gate.ps1`
- `scripts/desktop-mvp-gate.tests.ps1`
- `docs/superpowers/plans/2026-06-12-desktop-release-evidence.md`

- [ ] **Step 1: Focused tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1
```

Expected: PASS and writes `target\desktop\keli-desktop-release-evidence.json`.

- [ ] **Step 2: Full gate**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1`

Expected: PASS and include release evidence generation.

- [ ] **Step 3: Commit and push**

Run:

```powershell
git add docs/superpowers/plans/2026-06-12-desktop-release-evidence.md
git commit -m "Plan desktop release evidence"
git push origin main
git add scripts/desktop-release-evidence.ps1 scripts/desktop-release-evidence.tests.ps1 scripts/desktop-mvp-gate.ps1 scripts/desktop-mvp-gate.tests.ps1
git commit -m "Add desktop release evidence gate"
git push origin main
```

## Self-Review Checklist

- Spec coverage: improves release gate evidence and makes artifact integrity auditable.
- Honesty: unsigned artifacts are allowed for local MVP gate but explicitly block public release.
- Scope: no certificate secrets or signing implementation are introduced.
- Gate: release evidence runs only after ZIP/MSI/install/MSI smoke artifacts exist.
