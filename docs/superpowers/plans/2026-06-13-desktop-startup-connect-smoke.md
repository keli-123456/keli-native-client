# Desktop Startup Connect Smoke Plan

Date: 2026-06-13

## Target

Strengthen the Windows desktop Beta RC evidence by adding an automatic startup connect smoke that restores a node, applies `auto_start_core`, starts the managed core, proves the running state, then stops it.

## Steps

1. Add failing tests.
   - `startup_connect_smoke_arg_detection_accepts_flag`.
   - `startup_connect_smoke_report_confirms_auto_started_connection`.

2. Add the smoke report.
   - Define `DesktopShellStartupConnectSmokeReport`.
   - Add `build_startup_connect_smoke_report`.
   - Require running state, selected outbound, listen address, stop primary action, HTML readiness, and snapshot script readiness.

3. Add the smoke command.
   - Detect `--startup-connect-smoke`.
   - Reuse the startup restore fixture config.
   - Use `DesktopShellSettings { auto_start_core: true, mixed_port: 0, traffic_mode: MixedInboundOnly, ..Default::default() }`.
   - Call `apply_desktop_startup_settings`.
   - Stop the core with `RequestStop` after report generation.
   - Delete only the temporary smoke store file.

4. Verify.
   - Run the focused red test before implementation.
   - Run `cargo test -p keli-desktop-shell -- --test-threads=1`.
   - Run `cargo test -p keli-desktop -- --test-threads=1`.
   - Run `cargo run -q -p keli-desktop-shell -- --startup-connect-smoke`.
   - Run `cargo run -q -p keli-desktop-shell -- --startup-restore-smoke`.
   - Run `cargo run -q -p keli-desktop-shell -- --smoke`.
   - Run `git diff --check`.

5. Commit and push.
