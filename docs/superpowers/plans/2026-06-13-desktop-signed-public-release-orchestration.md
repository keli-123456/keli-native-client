# Desktop Signed Public Release Orchestration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a repeatable signed Windows public release orchestration command and GitHub workflow contract.

**Architecture:** Add `scripts\desktop-signed-release.ps1` as the local and CI orchestration layer. Keep signing details in `scripts\desktop-signing.ps1`; the new script sequences existing gates so the EXE is signed before packaging and the final MSI is signed before public release evidence is checked.

**Tech Stack:** PowerShell 5+, Windows SDK `signtool.exe`, existing desktop package/MSI/signing/release evidence scripts, GitHub Actions on `windows-latest`.

---

## File Structure

- Create: `scripts/desktop-signed-release.ps1`
  - Plan-only output for the signed release sequence.
  - Runs existing build, smoke, signing, release evidence, and public release gate commands in a safe order.
  - Writes `target\desktop\keli-desktop-signed-release.json` only after the public release gate passes.
- Create: `scripts/desktop-signed-release.tests.ps1`
  - Verifies plan-only output and ordering-sensitive command sequence.
- Create: `.github/workflows/windows-signed-public-release.yml`
  - Decodes PFX secret into a temporary file.
  - Runs `scripts\desktop-signed-release.ps1`.
  - Publishes signed release payloads and evidence.
- Create: `scripts/desktop-signed-release-workflow.tests.ps1`
  - Verifies workflow name, secrets, signed release command, cleanup, and payload paths.
- Modify: `README.md`
  - Add a short Windows signed public release section with required secrets and local command.

## Task 1: RED Signed Release Script Tests

**Files:**
- Create: `scripts/desktop-signed-release.tests.ps1`

- [ ] **Step 1: Write the failing plan test**

Create `scripts\desktop-signed-release.tests.ps1` with checks for these plan-only lines:

```powershell
'cargo fmt --check'
'git diff --check'
'cargo test -p keli-desktop -- --test-threads=1'
'cargo test -p keli-desktop-shell'
'cargo check -p keli-desktop-shell'
'cargo build --release -p keli-desktop-shell'
'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-package.ps1 -SkipBuild'
'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.ps1'
'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-msi.ps1'
'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.ps1 -IncludeMachineTakeover -MachineTakeoverAttempts 2'
'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign'
'rebuild portable package after exe signing'
'rebuild MSI after signed exe is staged'
'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1'
'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate'
'write target\desktop\keli-desktop-signed-release.json'
'output signed public release ready'
```

- [ ] **Step 2: Run RED test**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signed-release.tests.ps1
```

Expected: FAIL because `scripts\desktop-signed-release.ps1` does not exist.

## Task 2: Implement Signed Release Script

**Files:**
- Create: `scripts/desktop-signed-release.ps1`

- [ ] **Step 1: Add command helpers**

Implement helpers equivalent to the existing gate scripts:

```powershell
Resolve-RepoRoot
New-ReleaseStep
Format-StepCommand
Invoke-ReleaseStep
Get-WorkspaceVersion
Get-ArtifactSummary
```

- [ ] **Step 2: Add plan-only output**

`-PlanOnly` must emit the command sequence in Task 1, including the two explicit rebuild markers and the signed release report path.

- [ ] **Step 3: Add execution sequence**

Run the sequence:

```powershell
cargo fmt --check
git diff --check
cargo test -p keli-desktop -- --test-threads=1
cargo test -p keli-desktop-shell
cargo check -p keli-desktop-shell
cargo build --release -p keli-desktop-shell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-package.ps1 -SkipBuild
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-install-smoke.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-msi.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-machine-smoke.ps1 -IncludeMachineTakeover -MachineTakeoverAttempts 2
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-package.ps1 -SkipBuild
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-msi.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.ps1 -Sign
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate
```

- [ ] **Step 4: Write report after gate passes**

Write `target\desktop\keli-desktop-signed-release.json` with:

```json
{
  "status": "passed",
  "channel": "signed-public",
  "version": "<workspace version>",
  "artifacts": [
    { "kind": "portable-zip", "path": "target\\desktop\\keli-desktop-mvp-windows-x64.zip", "bytes": 0, "sha256": "<sha256>" },
    { "kind": "desktop-msi", "path": "target\\desktop\\keli-desktop-mvp-windows-x64.msi", "bytes": 0, "sha256": "<sha256>" },
    { "kind": "release-evidence", "path": "target\\desktop\\keli-desktop-release-evidence.json", "bytes": 0, "sha256": "<sha256>" },
    { "kind": "signing-evidence", "path": "target\\desktop\\keli-desktop-signing.json", "bytes": 0, "sha256": "<sha256>" }
  ],
  "verification_commands": [
    "scripts\\desktop-signed-release.ps1",
    "scripts\\desktop-public-release-gate.ps1 -SkipGate",
    "scripts\\desktop-release-readiness.ps1"
  ]
}
```

## Task 3: RED Signed Workflow Tests

**Files:**
- Create: `scripts/desktop-signed-release-workflow.tests.ps1`

- [ ] **Step 1: Write workflow fixture expectations**

The test should read `.github\workflows\windows-signed-public-release.yml` and require:

```powershell
'name: Windows Signed Public Release'
'workflow_dispatch:'
'KELI_SIGN_CERT_PFX_BASE64'
'KELI_SIGN_CERT_PASSWORD'
'KELI_SIGN_CERT_PATH'
'.\scripts\desktop-signed-release.ps1'
'target/desktop/keli-desktop-mvp-windows-x64.zip'
'target/desktop/keli-desktop-mvp-windows-x64.msi'
'target/desktop/keli-desktop-release-evidence.json'
'target/desktop/keli-desktop-signing.json'
'target/desktop/keli-desktop-signed-release.json'
'target/desktop/SHA256SUMS'
'Remove-Item -LiteralPath $env:KELI_SIGN_CERT_PATH -Force'
```

- [ ] **Step 2: Run RED test**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signed-release-workflow.tests.ps1
```

Expected: FAIL because the workflow does not exist.

## Task 4: Implement Signed Workflow And README

**Files:**
- Create: `.github/workflows/windows-signed-public-release.yml`
- Modify: `README.md`

- [ ] **Step 1: Create signed public release workflow**

The workflow must:

1. Run on `workflow_dispatch`.
2. Decode `secrets.KELI_SIGN_CERT_PFX_BASE64` into `$env:RUNNER_TEMP\keli-codesign.pfx`.
3. Export `KELI_SIGN_CERT_PATH` and `KELI_SIGN_CERT_PASSWORD`.
4. Run `.\scripts\desktop-signed-release.ps1`.
5. Generate `target\desktop\SHA256SUMS`.
6. Upload zip, MSI, release evidence, signing evidence, signed release report, and SHA256SUMS.
7. Remove the temporary PFX in a cleanup step.

- [ ] **Step 2: Document operator setup**

Add README text:

```markdown
### Windows signed public release

Use `scripts\desktop-signed-release.ps1` for a signed public release. It requires Windows SDK `signtool.exe` and either `KELI_SIGN_CERT_PATH` plus `KELI_SIGN_CERT_PASSWORD`, or a certificate-store subject through `KELI_SIGN_CERT_SUBJECT`.

GitHub Actions workflow `Windows Signed Public Release` expects repository secrets `KELI_SIGN_CERT_PFX_BASE64` and `KELI_SIGN_CERT_PASSWORD`.
```

## Task 5: Verification, Commit, And Push

**Files:**
- `docs/superpowers/specs/2026-06-13-desktop-signed-public-release-orchestration-design.md`
- `docs/superpowers/plans/2026-06-13-desktop-signed-public-release-orchestration.md`
- `scripts/desktop-signed-release.ps1`
- `scripts/desktop-signed-release.tests.ps1`
- `scripts/desktop-signed-release-workflow.tests.ps1`
- `.github/workflows/windows-signed-public-release.yml`
- `README.md`

- [ ] **Step 1: Focused tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signed-release.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signed-release-workflow.tests.ps1
```

Expected: PASS.

- [ ] **Step 2: Existing signing and gate tests**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signing.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-evidence.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.tests.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-github-release-workflow.tests.ps1
```

Expected: PASS.

- [ ] **Step 3: Plan-only command**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-signed-release.ps1 -PlanOnly
```

Expected: PASS and print the signed release command sequence. Do not run the full signed release command without a real certificate.

- [ ] **Step 4: Honest no-certificate status**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1 -SkipGate
```

Expected: FAIL with signing blockers until a valid certificate is configured.

- [ ] **Step 5: Commit and push**

Run:

```powershell
git add docs/superpowers/specs/2026-06-13-desktop-signed-public-release-orchestration-design.md docs/superpowers/plans/2026-06-13-desktop-signed-public-release-orchestration.md
git commit -m "docs: plan signed public release orchestration"
git add scripts/desktop-signed-release.ps1 scripts/desktop-signed-release.tests.ps1 scripts/desktop-signed-release-workflow.tests.ps1 .github/workflows/windows-signed-public-release.yml README.md
git commit -m "feat: add signed public release orchestration"
git push origin main
```

## Self-Review Checklist

- Spec coverage: signed release order, GitHub secret contract, evidence, and public gate behavior are all covered.
- Placeholder scan: no unfinished markers or unspecified commands remain.
- Scope: no certificate bytes, passwords, or private keys are committed.
- Release honesty: public release still requires valid Authenticode signatures.
