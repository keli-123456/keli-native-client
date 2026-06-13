# Desktop Running Support Smoke Design

Date: 2026-06-13

## Goal

Add a desktop shell smoke command that proves the support bundle can be exported while the managed core is running after startup auto-connect.

## Why

The Beta RC already has evidence for startup restore and startup connect. The remaining gap is operational evidence: after launch-time auto-connect succeeds, the user must be able to export a support bundle that captures the running desktop status, managed runtime status, connection diagnosis, and redacted core support data.

## Design

Add `--startup-connect-support-smoke` to `keli-desktop-shell`.

The command should:

1. Create a temporary `DesktopSubscriptionStore`.
2. Save the same fixture subscription used by startup restore/connect smoke tests.
3. Persist `SS-RESTORED` as the selected outbound.
4. Apply startup settings with `auto_start_core = true`, `traffic_mode = MixedInboundOnly`, and `mixed_port = 0`.
5. Export a support bundle while the managed core is still running.
6. Write the support bundle into a temporary smoke directory.
7. Parse the exported JSON and build a report.
8. Dispatch `RequestStop` after the export.
9. Delete only the temporary smoke subscription file and temporary smoke export directory.

The report passes only when:

- The support bundle is saved as JSON and has kind `keli_desktop_support_bundle`.
- `desktop_status.run_state` is `running`.
- `desktop_status.selected_outbound` is `SS-RESTORED`.
- `managed_runtime_status.selected_outbound` is `SS-RESTORED`.
- `desktop_diagnosis.connection.evidence.selected_outbound` is `SS-RESTORED`.
- `desktop_diagnosis.connection.level` is present.
- The embedded core support bundle keeps profile config text redacted.
- The last support export record matches the saved bundle.
- Cleanup stops the core before the command exits.

## Non-goals

- Do not test external outbound connectivity.
- Do not enable system proxy or TUN in this smoke.
- Do not write into the real support export directory.
- Do not leave the managed core running after the command exits.

## Verification

- Unit test the report builder.
- Unit test flag detection.
- Run `cargo run -q -p keli-desktop-shell -- --startup-connect-support-smoke`.
- Keep startup connect, startup restore, shell smoke, shell tests, and desktop tests green.
