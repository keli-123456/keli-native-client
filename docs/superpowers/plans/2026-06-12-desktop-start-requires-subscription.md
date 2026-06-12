# Desktop Start Requires Subscription

## Goal

Prevent the desktop shell from offering Start or Retry until a usable subscription is present, so first-time users are guided to import a subscription before launching the native core.

## Scope

- Shell state derives `can_start` and the primary action from both traffic-mode dependencies and subscription readiness.
- Missing or unusable subscription shows a clear blocked reason before Start/Retry.
- Refreshing a subscription recomputes primary action, tray action, and `can_start`.
- Dependency blockers still win once a usable subscription exists but the selected traffic mode is not ready.
- Shell controller and IPC tests reflect the new user flow.

## Verification

- `cargo test -p keli-desktop`
- `cargo test -p keli-desktop-shell`
- `scripts\desktop-mvp-gate.ps1`
- `scripts\desktop-public-release-gate.ps1` remains blocked only by signing readiness.
