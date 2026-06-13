# Desktop Startup Restore Smoke Plan

Date: 2026-06-13

## Target

Strengthen Beta RC evidence for the startup connection flow by adding a smoke command that verifies persisted subscription and selected node restore.

## Steps

1. Add failing tests.
   - `startup_restore_smoke_arg_detection_accepts_flag`.
   - `startup_restore_smoke_report_confirms_subscription_and_selected_node_restore`.

2. Add the smoke report.
   - Define `DesktopShellStartupRestoreSmokeReport`.
   - Add `build_startup_restore_smoke_report`.
   - Require restored subscription, selected outbound match, visible selected node, snapshot script readiness, and `can_start`.

3. Add the smoke command.
   - Add `--startup-restore-smoke` detection in `main`.
   - Write a fixture subscription to a temporary store.
   - Instantiate `DesktopShellController::new_with_subscription_store`.
   - Render HTML and snapshot script.
   - Print JSON and return non-zero on failure.
   - Remove only the temporary smoke file.

4. Verify.
   - Run focused red test before implementation.
   - Run `cargo test -p keli-desktop-shell -- --test-threads=1`.
   - Run `cargo run -q -p keli-desktop-shell -- --startup-restore-smoke`.
   - Run `cargo run -q -p keli-desktop-shell -- --smoke`.
   - Run `cargo test -p keli-desktop -- --test-threads=1`.
   - Run `git diff --check`.

5. Commit and push.
