# Desktop Beta RC Delivery Audit Design

Date: 2026-06-13

## Goal

Add a final Windows desktop Beta RC delivery audit that proves the generated tester payload is internally consistent and backed by smoke evidence.

## Why

`scripts\desktop-beta-rc.ps1` now produces an unsigned Beta manifest and release notes. The next Beta RC gap is a final handoff check: verify that the manifest points to real artifacts, artifact sizes and SHA256 hashes still match the current files, release notes mention the same artifacts and verification commands, and packaged smoke evidence exists for support export and running support export.

## Design

Add `scripts\desktop-beta-rc-audit.ps1`.

The script should:

1. Read `target\desktop\keli-desktop-unsigned-beta-manifest.json`.
2. Read `target\desktop\keli-desktop-unsigned-beta-release-notes.md`.
3. Recompute SHA256 and byte counts for each manifest artifact.
4. Verify required artifact kinds: `desktop-shell-exe`, `portable-zip`, and `desktop-msi`.
5. Verify `channel = unsigned-beta` and `status = passed`.
6. Verify the release notes include the manifest version, artifact paths, SHA256 hashes, unsigned warning, and `scripts\desktop-beta-rc.ps1`.
7. Verify smoke evidence paths exist and their JSON reports still pass:
   - install support export smoke
   - install running support smoke
   - MSI support export smoke
   - MSI running support smoke
8. Write `target\desktop\keli-desktop-beta-rc-audit.json`.
9. Exit non-zero when any required item is missing or mismatched.

## Report Shape

The audit report should include:

- `status`
- `channel`
- `version`
- `artifact_count`
- `artifacts`
- `release_notes_ready`
- `smoke_evidence_ready`
- `smoke_evidence`
- `verification_commands`

## Non-goals

- Do not sign binaries.
- Do not change public release gate behavior.
- Do not rebuild artifacts.
- Do not run long smoke suites; this audit validates already-produced evidence.

## Verification

- Add PowerShell fixture tests first and watch them fail.
- Run the audit against the current generated Beta RC payload.
- Keep `scripts\desktop-beta-rc.ps1`, `scripts\desktop-mvp-gate.ps1`, and relevant Rust tests green.
