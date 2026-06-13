# Desktop Startup Restore Smoke Design

Date: 2026-06-13

## Goal

Add a desktop shell smoke command that proves the launch-time subscription restore path is usable for the Beta RC connection flow.

## Why

`DesktopShellController::new_native()` already restores a persisted subscription and selected node through `DesktopSubscriptionStore`, but the existing desktop shell smoke output only proves the UI shell renders. The Beta RC needs a direct artifact showing that launch can recover the subscription and selected outbound needed by one-click connect and auto-start.

## Design

Add `--startup-restore-smoke` to `keli-desktop-shell`.

The command should:

1. Create a temporary `DesktopSubscriptionStore`.
2. Save a fixture subscription with two Shadowsocks nodes and `SS-RESTORED` as the persisted selected outbound.
3. Start a `DesktopShellController` with `DesktopNativeCommandService` and that temporary store.
4. Build a JSON report from the restored snapshot and rendered HTML.
5. Delete the temporary store file before returning.

The report passes only when:

- A usable subscription is restored.
- The restored subscription selected outbound is `SS-RESTORED`.
- The runtime status selected outbound is also `SS-RESTORED`.
- The selected node is visible in the rendered shell HTML.
- The restored shell can start from the current traffic mode.
- The shell snapshot script contains the restored node.

## Non-goals

- Do not mutate the real `%APPDATA%\Keli\desktop-subscription.json`.
- Do not start the core process in this smoke.
- Do not require panel credentials, network access, or a subscription URL.

## Verification

- Unit test the report builder.
- Unit test flag detection.
- Run `cargo run -q -p keli-desktop-shell -- --startup-restore-smoke`.
- Keep the existing desktop shell and desktop crate tests green.
