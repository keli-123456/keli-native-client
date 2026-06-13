# Desktop Auto Start Core Plan

Date: 2026-06-13

## Target

Advance the Windows desktop Beta RC goal by wiring the persisted `auto_start_core` setting into desktop launch behavior.

## Steps

1. Add a failing unit test for `desktop_settings_auto_start_action`.
   - Build a shell snapshot that becomes startable only after a usable subscription is restored.
   - Assert the helper returns `RequestStart` when the setting is enabled.
   - Assert it returns `None` when disabled or when `can_start` is false.

2. Add a failing smoke-contract assertion for `settings_auto_start_ready`.
   - Add the field to `DesktopShellSmokeReport`.
   - Require the auto-start checkbox id and `auto_start_core` payload field.

3. Implement the minimal startup helper.
   - Keep `desktop_settings_auto_start_action` pure.
   - Add `apply_desktop_startup_settings` to apply runtime settings and optionally dispatch `RequestStart`.
   - Replace the launch path's raw `apply_desktop_settings` call with the startup helper.
   - Keep save-settings IPC on `apply_desktop_settings` only.

4. Verify.
   - Run the new focused unit test and confirm red before implementation.
   - Run `cargo test -p keli-desktop-shell -- --test-threads=1`.
   - Run `cargo run -q -p keli-desktop-shell -- --smoke`.
   - Run `git diff --check`.

5. Commit and push.
   - Commit docs separately if useful.
   - Commit implementation with focused message.
