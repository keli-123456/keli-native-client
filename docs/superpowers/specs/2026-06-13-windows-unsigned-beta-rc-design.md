# Windows Unsigned Beta Release Candidate Design

## Goal

Produce a Windows desktop unsigned Beta Release Candidate for Keli. The release should be safe to hand to testers even without a code-signing certificate: artifacts are generated, checksummed, documented, and verified by automated gates, while the remaining public-release blockers are explicitly limited to signing.

This stage starts after the Windows desktop MVP is ready. It does not try to bypass Windows SmartScreen or pretend unsigned binaries are production-ready.

## Non-Goals

- Acquiring or configuring a code-signing certificate.
- Marking the build as a signed public release.
- Changing core runtime, protocol, subscription, proxy, or TUN behavior.
- Building an updater, auto-update channel, or installer telemetry.
- Supporting macOS, Linux, or mobile release packages.

## Chosen Approach

The chosen path is an unsigned beta release gate layered on top of the existing desktop MVP gate and release evidence. It treats the current signing failures as expected external blockers only when every other Beta RC requirement is satisfied.

Two alternatives were rejected:

- A formal public release gate would continue to fail until a certificate exists, so it is not useful as the next goal.
- A loose manual zip handoff would move quickly but would not leave enough evidence for testers or future release automation.

## Release Shape

The Beta RC should produce a small release directory under `target\desktop` containing:

- Portable zip: `target\desktop\keli-desktop-mvp-windows-x64.zip`.
- MSI installer: `target\desktop\keli-desktop-mvp-windows-x64.msi`.
- Release evidence: `target\desktop\keli-desktop-release-evidence.json`.
- Beta manifest: a machine-readable JSON file that records version, channel, artifact paths, SHA256 hashes, unsigned status, allowed blockers, and verification commands.
- Release notes: a tester-facing text or Markdown file that explains installation, unsigned Windows warnings, WebView2, Wintun/TUN, system proxy behavior, and support bundle export.

The artifact names can keep the existing `mvp` stem for compatibility in this stage, but the manifest and notes must identify the channel as `unsigned-beta`.

## Beta Gate Semantics

The Beta RC gate passes only when:

- `scripts\desktop-mvp-gate.ps1` passes.
- Release evidence status is `passed`.
- `desktop_mvp_ready` is true.
- Artifacts include the desktop shell EXE, portable zip, and MSI with non-empty SHA256 values.
- Install smoke, MSI smoke, MSI support export smoke, support bundle export, first-run dependency evidence, and machine takeover evidence are ready.
- `scripts\desktop-public-release-gate.ps1 -SkipGate` fails only with:
  - `artifact-signature-missing`
  - `signing-certificate-missing`
- The Beta manifest and release notes exist and match the current release evidence version and artifacts.

The gate must fail if any non-signing blocker appears. That includes missing package files, missing checksums, missing smoke evidence, missing Wintun/system proxy dependency action evidence, failed support export evidence, or machine takeover not ready.

## User-Facing Notes

The release notes must be honest and practical:

- State that this is an unsigned Beta build for testing.
- Warn that Windows may show SmartScreen or publisher warnings.
- Tell testers to verify SHA256 hashes from the manifest before running artifacts.
- Explain portable zip versus MSI installation.
- Explain that WebView2 is required.
- Explain that TUN mode requires Wintun and may need setup, while system proxy mode can be tested first.
- Tell testers where support bundles are exported.
- Include the exact commands for local verification:
  - `scripts\desktop-mvp-gate.ps1`
  - `scripts\desktop-public-release-gate.ps1 -SkipGate`
  - the new Beta RC gate command.

## Data Flow

1. Existing build and packaging scripts create the desktop EXE, portable zip, MSI, smoke results, signing inspection, and release evidence.
2. A Beta RC script reads the release evidence and MVP status.
3. The script validates that only expected signing blockers remain.
4. The script writes a Beta manifest with version, channel, artifacts, hashes, unsigned status, blockers, and verification commands.
5. The script writes release notes from the same evidence so testers see the same version and artifact list as automation.
6. The script exits successfully only after the manifest and notes are internally consistent with release evidence.

## Error Handling

Failures should be explicit:

- If release evidence is missing, instruct the operator to run `scripts\desktop-mvp-gate.ps1`.
- If an artifact is missing or lacks a SHA256 hash, report the artifact kind and path.
- If a non-signing blocker appears, list it and fail the Beta gate.
- If signing blockers are absent because a future signed build is ready, the Beta gate may still pass but must report that the build is no longer unsigned.
- If release notes or manifest generation fails, fail before reporting a Beta RC as ready.

## Testing And Verification

The implementation must use test-first slices:

- Unit-style PowerShell tests for the Beta RC gate plan output.
- Fixture tests that prove the gate passes with only the two expected signing blockers.
- Fixture tests that prove the gate fails when an extra blocker is present.
- Fixture tests that prove generated manifest and notes contain version, channel, artifact hashes, unsigned warning, and verification commands.
- Full `scripts\desktop-mvp-gate.ps1` after implementation.
- `scripts\desktop-public-release-gate.ps1 -SkipGate` must still fail only on signing blockers.

## Completion Criteria

This goal is complete when:

- A committed Beta RC spec and implementation plan exist.
- A Beta RC script produces manifest and release notes from current release evidence.
- A Beta RC gate passes on the current unsigned desktop build.
- The full desktop MVP gate passes.
- The public release SkipGate output is still honest and only contains signing blockers.
- All changes are committed and pushed to GitHub in small verified slices.
