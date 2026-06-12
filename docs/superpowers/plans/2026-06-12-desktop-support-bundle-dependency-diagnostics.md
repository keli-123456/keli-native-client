# Desktop Support Bundle Dependency Diagnostics

## Goal

Add desktop dependency diagnostics to the exported desktop support bundle so a user support export captures first-run readiness, system proxy status, TUN/Wintun status, dependency blockers, and action entrypoints without requiring a separate CLI or readiness command.

## Current State

- `DesktopRuntimeService::export_support_bundle()` writes the core support bundle, captures `desktop_status`, and embeds `managed_runtime_status`.
- `DesktopDependencyReport` already serializes first-run readiness, system proxy dependency state, and TUN backend state.
- The shell state already carries dependency reports for first-run UI and smoke reports.
- The support bundle JSON does not currently include desktop dependency diagnostics.

## Scope

In scope:

- Add `desktop_dependencies` to `keli_desktop_support_bundle`.
- Generate it from native dependency detection when exporting through `DesktopRuntimeService`.
- Preserve existing redaction behavior and runtime/core support bundle fields.
- Add focused regression assertions for first-run readiness, blocker action, and TUN state.

Out of scope:

- Changing Wintun install behavior.
- Changing support bundle file save paths or shell UI copy.
- Reworking public release signing gates.

## TDD Plan

1. Update `support_bundle_export_embeds_runtime_status_and_redacts_profile` to assert:
   - `bundle["desktop_dependencies"]["first_run"]["system_proxy_ready"]` is present.
   - `bundle["desktop_dependencies"]["first_run"]["tun_ready"]` is present.
   - `bundle["desktop_dependencies"]["first_run"]["blockers"][0]["action"] == "install-wintun"` when the native machine is missing Wintun.
   - `bundle["desktop_dependencies"]["tun_backend"]["action"] == "install-wintun"` when the native machine is missing Wintun.
2. Run the focused test and confirm it fails because `desktop_dependencies` is missing.
3. Add a dependency-report parameter to `build_desktop_support_bundle_export`.
4. Have `DesktopRuntimeService::export_support_bundle()` pass `DesktopDependencyReport::detect_native()`.
5. Re-run focused tests and broader gates.

## Verification

Focused:

```powershell
cargo test -p keli-desktop support_bundle_export_embeds_runtime_status_and_redacts_profile -- --nocapture
```

Broader:

```powershell
cargo fmt
cargo test -p keli-desktop --lib -- --test-threads=1
scripts\desktop-mvp-gate.ps1
scripts\desktop-public-release-gate.ps1 -SkipGate
git diff --check
```

Expected public release gate result remains blocked only by external signing:

- `artifact-signature-missing`
- `signing-certificate-missing`

## Risks

- Native dependency detection is platform-sensitive. Assertions should check shape and action values that match current Windows runner state only where the existing gate already relies on that state.
- The support bundle must continue to omit credentials, profile text, and server endpoints.

## Done

- Desktop support bundle JSON contains `desktop_dependencies`.
- Tests prove runtime status, core bundle redaction, and dependency diagnostics are exported together.
- MVP gate still passes.
- Changes are committed and pushed.
