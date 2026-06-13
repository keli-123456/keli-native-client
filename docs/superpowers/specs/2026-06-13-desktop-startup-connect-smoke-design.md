# Desktop Startup Connect Smoke Design

Date: 2026-06-13

## Goal

Add a desktop shell smoke command that proves the restored subscription, restored selected node, persisted startup setting, and managed core lifecycle work together.

## Why

The Beta RC needs more than a rendered shell and a restored subscription. It needs evidence that a launch-time restored node can automatically start the core through the same `auto_start_core` path used by the desktop app.

## Design

Add `--startup-connect-smoke` to `keli-desktop-shell`.

The command should:

1. Create a temporary `DesktopSubscriptionStore`.
2. Save a fixture subscription with `SS-RESTORED` as the persisted selected outbound.
3. Build startup settings with `auto_start_core = true`, `traffic_mode = MixedInboundOnly`, and `mixed_port = 0`.
4. Create `DesktopShellController::new_with_subscription_store(DesktopNativeCommandService::new(), store)`.
5. Call the existing `apply_desktop_startup_settings` helper.
6. Render the resulting shell and snapshot script.
7. Build a JSON report.
8. Dispatch `RequestStop` if the smoke started the core.
9. Delete only the temporary smoke subscription file.

The report passes only when:

- The startup helper reaches `DesktopRunState::Running`.
- The restored and running selected outbound is `SS-RESTORED`.
- The managed runtime exposes a `127.0.0.1:*` listen address.
- The primary action becomes `stop-service`.
- The rendered HTML and snapshot script both carry the selected node.
- Cleanup stops the core before the command exits.

## Non-goals

- Do not touch the real `%APPDATA%\Keli\desktop-subscription.json`.
- Do not enable system proxy or TUN in this smoke.
- Do not test external outbound connectivity.
- Do not leave the managed core running after the command exits.

## Verification

- Unit test the report builder.
- Unit test flag detection.
- Run `cargo run -q -p keli-desktop-shell -- --startup-connect-smoke`.
- Keep shell tests, desktop tests, and existing smoke commands green.
