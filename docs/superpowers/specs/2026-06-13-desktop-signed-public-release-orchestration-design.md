# Desktop Signed Public Release Orchestration Design

## Goal

Move the Windows desktop release path from "unsigned Beta RC only" to a signed public release path that is executable as soon as a real code-signing certificate is configured. The project must keep blocking public release without a certificate, but the blocker should be expressed through a repeatable local and GitHub Actions workflow rather than an operator guessing which scripts to run.

## Current Context

The desktop MVP gate already builds and validates the app, package, MSI, machine smoke, signing evidence, release evidence, unsigned Beta RC, and Beta RC audit. The public release gate already reads release evidence and fails when signatures or signing configuration are missing.

The missing piece is orchestration. A signed public release must build the executable, sign the executable before packaging, rebuild the portable zip and MSI from the signed executable, sign the final MSI, regenerate release evidence, and then run the public release gate against that already signed evidence. If this order is wrong, the zip or MSI can contain an unsigned executable even when the loose EXE and MSI container look signed.

## Design

Add `scripts/desktop-signed-release.ps1` as the signed release source of truth. It should run the same verification and smoke steps as the desktop MVP gate, but it must own the signing order:

1. Run format, diff, tests, check, and release build.
2. Build an initial portable package and MSI so the current signing script can sign both known artifact paths.
3. Run install smoke and machine takeover smoke.
4. Run `scripts\desktop-signing.ps1 -Sign` to sign the release EXE and current MSI.
5. Rebuild the portable package from the signed release EXE so the zip contains the signed executable.
6. Rebuild the MSI from the signed staged executable.
7. Run `scripts\desktop-signing.ps1 -Sign` again so the final MSI container is signed and signing evidence is refreshed.
8. Regenerate release evidence.
9. Run `scripts\desktop-public-release-gate.ps1 -SkipGate` so the gate validates the just-signed evidence without rebuilding over signed artifacts.
10. Emit a signed release report at `target\desktop\keli-desktop-signed-release.json`.

The double signing call is intentionally conservative because `desktop-signing.ps1` currently signs both fixed artifact paths. This avoids introducing a partial-signing API in the signing script and keeps the change focused on orchestration.

## GitHub Actions

Add a separate `Windows Signed Public Release` workflow instead of modifying the unsigned Beta workflow. It should require these repository secrets:

- `KELI_SIGN_CERT_PFX_BASE64`: base64-encoded PFX file.
- `KELI_SIGN_CERT_PASSWORD`: PFX password.

The workflow decodes the PFX into `$env:RUNNER_TEMP`, exports `KELI_SIGN_CERT_PATH` and `KELI_SIGN_CERT_PASSWORD` for the job, runs `scripts\desktop-signed-release.ps1`, uploads signed payload evidence, and deletes the temporary PFX in an `always()` cleanup step.

## Non-Goals

- Buying, issuing, exporting, or storing a real certificate.
- Committing certificate material or passwords.
- Weakening the unsigned Beta RC path.
- Marking public release ready without valid Authenticode signatures.

## Success Criteria

- `desktop-signed-release.ps1 -PlanOnly` documents the exact signed release order.
- Tests assert that the signed release script uses the correct rebuild and public gate order.
- A GitHub workflow test asserts the signed workflow requires the PFX and password secrets, runs the signed release script, and uploads signed release evidence.
- Without a real certificate, existing gates still report signing blockers.
- With a real certificate configured through environment variables or GitHub secrets, the signed release script has a single command path to reach `public_release_ready true`.
