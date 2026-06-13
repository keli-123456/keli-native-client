# Desktop Beta RC Delivery Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a final Beta RC audit script that validates artifact hashes, release notes, and packaged smoke evidence before tester handoff.

**Architecture:** Create a PowerShell audit script that reads the already-generated Beta manifest and release notes, validates current filesystem artifacts and smoke evidence JSON, writes an audit report, and exits non-zero on mismatch. Add fixture tests before implementation.

**Tech Stack:** PowerShell 5+, existing Beta manifest JSON, existing release notes, existing smoke evidence JSON.

---

### Task 1: Red Tests

**Files:**
- Create: `scripts/desktop-beta-rc-audit.tests.ps1`

- [ ] **Step 1: Add PlanOnly expectations**

Require these lines:

```powershell
'input target\desktop\keli-desktop-unsigned-beta-manifest.json'
'input target\desktop\keli-desktop-unsigned-beta-release-notes.md'
'verify artifacts desktop-shell-exe portable-zip desktop-msi bytes sha256'
'verify release notes version artifacts hashes unsigned warning commands'
'verify smoke evidence support and running support reports'
'write target\desktop\keli-desktop-beta-rc-audit.json'
'output beta rc audit ready'
```

- [ ] **Step 2: Add passing fixture**

Create a temporary fixture directory with three artifact files, a manifest with matching byte counts and hashes, four passing smoke JSON reports, and release notes containing the version, artifact paths, hashes, unsigned warning, and verification command. Assert the audit writes `status = passed`.

- [ ] **Step 3: Add failing fixture**

Change one artifact after writing the manifest and assert the audit fails with a SHA256 mismatch mentioning that artifact kind.

- [ ] **Step 4: Verify red**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-beta-rc-audit.tests.ps1
```

Expected: fail because the script does not exist yet.

### Task 2: Implement Audit Script

**Files:**
- Create: `scripts/desktop-beta-rc-audit.ps1`

- [ ] **Step 1: Add parameters**

Support:

```powershell
[string]$ManifestPath
[string]$ReleaseNotesPath
[string]$ReportPath
[switch]$PlanOnly
```

- [ ] **Step 2: Add artifact validation**

For each required artifact kind, verify exactly one manifest entry, non-empty path, existing file, matching `bytes`, and matching lowercase SHA256.

- [ ] **Step 3: Add notes validation**

Verify release notes contain manifest version, every artifact path, every artifact hash, `This is an unsigned Beta build for testing.`, and `scripts\desktop-beta-rc.ps1`.

- [ ] **Step 4: Add smoke evidence validation**

Verify install/MSI support export smoke and running support smoke paths exist. Parse each JSON and require `status = passed`; for running support require `desktop_status_running`, `diagnosis_selected`, `redaction_ready`, and `stopped_after_smoke`.

- [ ] **Step 5: Write report and output**

Write `target\desktop\keli-desktop-beta-rc-audit.json` and output:

```text
beta_rc_audit_ready true
channel unsigned-beta
artifact_count 3
smoke_evidence_ready true
```

### Task 3: Wire Delivery Evidence

**Files:**
- Modify: `scripts/desktop-beta-rc.ps1`
- Modify: `scripts/desktop-beta-rc.tests.ps1`
- Modify: `.github/workflows/windows-unsigned-beta-release.yml`

- [ ] **Step 1: Add audit command to manifest**

Add `scripts\desktop-beta-rc-audit.ps1` to manifest verification commands and release notes verification commands.

- [ ] **Step 2: Add workflow audit step**

Run the audit script after the Beta RC script and upload `target\desktop\keli-desktop-beta-rc-audit.json`.

- [ ] **Step 3: Verify focused tests**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-beta-rc-audit.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-beta-rc.tests.ps1
```

### Task 4: Final Verification

**Files:**
- Created/modified files from earlier tasks.

- [ ] **Step 1: Run current audit**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-beta-rc-audit.ps1
```

- [ ] **Step 2: Run main gate**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

- [ ] **Step 3: Run script tests and patch hygiene**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-beta-rc-audit.tests.ps1
powershell -ExecutionPolicy Bypass -File scripts\desktop-beta-rc.tests.ps1
git diff --check
```

- [ ] **Step 4: Commit and push**

Run:

```powershell
git add docs/superpowers/specs/2026-06-13-desktop-beta-rc-delivery-audit-design.md docs/superpowers/plans/2026-06-13-desktop-beta-rc-delivery-audit.md
git commit -m "docs: plan beta rc delivery audit"
git add scripts/desktop-beta-rc-audit.ps1 scripts/desktop-beta-rc-audit.tests.ps1 scripts/desktop-beta-rc.ps1 scripts/desktop-beta-rc.tests.ps1 .github/workflows/windows-unsigned-beta-release.yml
git commit -m "feat: add beta rc delivery audit"
git push origin main
```

## Self-Review

- Spec coverage: artifact hashes, notes, smoke evidence, report output, and workflow upload are covered.
- Placeholder review: no unfinished markers remain.
- Type consistency: report fields and script output names match across tests and implementation.
- Scope: audit validates existing evidence and does not rebuild, sign, or change runtime behavior.
