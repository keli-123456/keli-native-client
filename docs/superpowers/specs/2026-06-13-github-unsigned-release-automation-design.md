# GitHub Unsigned Release Automation Design

## Goal

Automate the Windows unsigned Beta release path from GitHub Actions. A pushed version tag or manual workflow run should build the Windows desktop artifacts, run the existing desktop MVP and unsigned Beta gates, generate SHA256SUMS, and upload the tester-ready files to GitHub Releases.

This follows the practical open-source pattern used by projects that publish unsigned Windows builds with checksums before they have a code-signing certificate.

## Non-Goals

- Acquiring or using a Windows code-signing certificate.
- Making the hard public release gate pass.
- Publishing to Microsoft Store, winget, Chocolatey, Scoop, or any app store.
- Replacing the local `scripts\desktop-mvp-gate.ps1` or `scripts\desktop-beta-rc.ps1` release logic.
- Building macOS, Linux, Android, or iOS packages.

## Trigger Model

The workflow should support:

- `push` tags matching `v*`.
- `workflow_dispatch` for manual dry runs.

Tag runs publish a GitHub prerelease. Manual runs build and upload workflow artifacts but do not create a GitHub Release unless the run is attached to a tag.

## Workflow Shape

Create `.github\workflows\windows-unsigned-beta-release.yml`.

The workflow should:

1. Run on a Windows GitHub-hosted runner.
2. Check out the repository.
3. Install the stable Rust toolchain if the runner does not already have it.
4. Run `scripts\desktop-mvp-gate.ps1`.
5. Run `scripts\desktop-beta-rc.ps1` explicitly after the gate for readable CI logs.
6. Generate `target\desktop\SHA256SUMS` for the release payload.
7. Upload the release payload as a workflow artifact.
8. On tag runs, publish a GitHub prerelease with the same payload.

## Release Payload

The uploaded payload must include:

- `target\desktop\keli-desktop-mvp-windows-x64.zip`.
- `target\desktop\keli-desktop-mvp-windows-x64.msi`.
- `target\desktop\keli-desktop-release-evidence.json`.
- `target\desktop\keli-desktop-unsigned-beta-manifest.json`.
- `target\desktop\keli-desktop-unsigned-beta-release-notes.md`.
- `target\desktop\SHA256SUMS`.

The GitHub Release body should use `keli-desktop-unsigned-beta-release-notes.md`.

## Checksums

The workflow should generate checksums after `desktop-mvp-gate` and `desktop-beta-rc` have produced the payload. Each line in `SHA256SUMS` should include the SHA256 hash and the release payload file name. This mirrors the simple GitHub Release checksum pattern used by projects such as FlClash.

## Failure Behavior

The workflow should fail if:

- `desktop-mvp-gate` fails.
- `desktop-beta-rc` fails.
- Any required release payload file is missing.
- SHA256SUMS cannot be generated.

The workflow should not run the hard public release gate because the current unsigned Beta stage is expected to keep `artifact-signature-missing` and `signing-certificate-missing` as external blockers.

## Testing And Verification

The implementation must include a PowerShell test that validates the workflow file exists and contains:

- The `v*` tag trigger and manual dispatch.
- `permissions: contents: write`.
- Windows runner selection.
- Checkout and Rust toolchain setup.
- `scripts\desktop-mvp-gate.ps1`.
- `scripts\desktop-beta-rc.ps1`.
- SHA256SUMS generation.
- Workflow artifact upload.
- `softprops/action-gh-release@v2`.
- All release payload file paths.

The final local verification should run the new workflow test, the existing Beta RC test, and the MVP gate plan test. A full local `scripts\desktop-mvp-gate.ps1` run should remain passing.

## Completion Criteria

This goal is complete when:

- The workflow exists and is covered by a local test.
- The workflow payload includes ZIP, MSI, evidence, manifest, notes, and SHA256SUMS.
- README mentions the tag-based unsigned Beta release workflow.
- Local verification passes.
- Changes are committed and pushed to GitHub.
