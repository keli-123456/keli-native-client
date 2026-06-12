# Desktop Support Bundle Status Requirement

## Goal

Make the desktop MVP status audit show support bundle export readiness as its own requirement instead of hiding it inside the broad install-smoke workflow requirement.

## Current State

- `desktop-install-smoke.ps1` records `export-support-bundle` in `verified_ui_workflow_entrypoints`.
- `desktop-mvp-status.ps1` already requires the workflow id, but the visible requirement list only reports the broad `install-smoke-workflows` line.
- The desktop support bundle now embeds `desktop_dependencies`, so the export path should be a first-class MVP status item.

## Scope

In scope:

- Add a `support-bundle-export` requirement to `desktop-mvp-status.ps1`.
- Keep its readiness tied to the existing install smoke `export-support-bundle` workflow evidence.
- Update status tests so text output includes the requirement.

Out of scope:

- Changing support bundle JSON schema again.
- Changing shell UI or export file location.
- Changing public release signing blockers.

## TDD Plan

1. Update `desktop-mvp-status.tests.ps1` expected output to require:
   - `requirement.support-bundle-export ready`
2. Run the status tests and confirm they fail because the requirement is missing.
3. Add `$supportBundleReady` based on the existing workflow entrypoint check.
4. Add `New-Requirement -Id 'support-bundle-export'`.
5. Re-run tests and MVP gate.

## Verification

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-status.tests.ps1
scripts\desktop-mvp-gate.ps1
scripts\desktop-public-release-gate.ps1 -SkipGate
git diff --check
```

Expected public release gate result remains blocked only by external signing:

- `artifact-signature-missing`
- `signing-certificate-missing`

## Done

- MVP status text includes `requirement.support-bundle-export ready`.
- MVP gate remains green.
- Public release gate blocker set is unchanged.
- Changes are committed and pushed.
