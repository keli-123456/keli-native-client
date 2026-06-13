# Desktop Beta RC Running Support Evidence Design

Date: 2026-06-13

## Goal

Make the running support bundle smoke part of the Windows desktop Beta RC evidence chain, not a standalone manual check.

## Why

The desktop shell can now prove `--startup-connect-support-smoke`: restore a subscription, auto-start the managed core, export a support bundle while running, verify diagnosis/redaction, then stop cleanly. The Beta RC gate should require that evidence from packaged artifacts so a tester handoff proves diagnostics work after the one-click connection path, not only from the development binary.

## Chosen Approach

Add running support evidence to both package smoke paths:

- Portable install smoke runs `keli-desktop-shell.exe --startup-connect-support-smoke` and stores `target\desktop-install-smoke\desktop-startup-connect-support-smoke.json`.
- MSI admin-extract smoke runs the same command against the extracted executable and stores `target\desktop\keli-desktop-msi-startup-connect-support-smoke.json`.
- Release evidence reads those fields from install/MSI smoke JSON.
- Desktop MVP status requires both running support evidence items before `desktop_mvp_ready` can be true.
- Beta RC manifest and release notes expose the smoke evidence paths so the handoff is self-describing.

Two alternatives were rejected:

- Keeping the new smoke as a developer-only manual command would leave Beta RC evidence weaker than the current runtime behavior.
- Running the smoke only against the development binary would not prove packaged EXE behavior.

## Required Evidence

Each package smoke result must include:

- `running_support_smoke`: the JSON report path.
- `running_support_desktop_status_running = true`.
- `running_support_desktop_status_selected = true`.
- `running_support_managed_status_selected = true`.
- `running_support_diagnosis_selected = true`.
- `running_support_redaction_ready = true`.
- `running_support_stopped_after_smoke = true`.

The release evidence should preserve those fields under `smoke.install` and `smoke.msi`.

The MVP status should expose two local requirements:

- `running-support-bundle-export`
- `msi-running-support-bundle-export`

The Beta RC manifest should include a `smoke_evidence` object with install and MSI support paths, including the new running support smoke paths.

## Non-goals

- Do not add external internet connectivity checks.
- Do not enable system proxy or TUN for this smoke.
- Do not change formal signed public release rules.
- Do not mark unsigned artifacts as production ready.

## Verification

- Update PowerShell plan tests first and watch them fail.
- Run install smoke, MSI, release evidence, MVP status, and Beta RC tests.
- Run the direct shell smoke command after implementation.
- Run `scripts\desktop-beta-rc.ps1` against current evidence.
- Keep Rust shell/desktop tests green.
