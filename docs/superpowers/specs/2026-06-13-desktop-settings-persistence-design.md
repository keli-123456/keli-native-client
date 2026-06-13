# Desktop Settings Persistence Design

## Goal

Make the desktop Settings view persist user-editable runtime preferences so the shell can reopen with the same startup toggles, network fields, and default traffic mode instead of resetting to hard-coded HTML values.

## Context

The desktop shell already persists imported subscriptions and selected nodes in `%APPDATA%\Keli\desktop-subscription.json`. The Settings view currently renders controls for startup behavior, ports, DNS mode, TUN stack, and traffic mode, but only traffic mode is wired to the backend. The other fields are UI-only and reset when the app restarts.

This slice keeps the persistence boundary in `keli-desktop-shell` because these controls are shell preferences today. The existing `keli-desktop` runtime will still own subscription import, node selection, start/stop, and real traffic mode behavior.

## Non Goals

- Mutating Windows startup registry entries.
- Reconfiguring the running core listener ports.
- Changing system DNS or TUN stack behavior.
- Adding a settings database or account sync.

Those can follow once the core exposes a typed runtime settings API. This slice makes the UI state durable and applies the already-supported traffic mode to the desktop controller.

## Design

Add `crates/keli-desktop-shell/src/settings.rs` to own shell settings persistence:

- `DesktopShellSettings` stores `traffic_mode`, startup toggles, ports, DNS mode, and TUN stack.
- `DesktopShellSettingsSaveSummary` is serialized to the WebView after save or restore.
- `default_desktop_shell_settings_path()` returns `%APPDATA%\Keli\desktop-settings.json`, falling back to `%TEMP%\keli\desktop-settings.json`.
- `read_desktop_shell_settings(path)` returns defaults for a missing or invalid file so a corrupted settings file cannot block launch.
- `write_desktop_shell_settings(path, settings)` writes pretty JSON and reports path/status.

Wire one IPC command through `actions.rs`:

- JSON type: `save-desktop-settings`
- Payload field: `settings`
- Event: `DesktopShellUiEvent::SaveDesktopSettings(DesktopShellSettings)`

Wire startup and save behavior through `main.rs`:

- Load settings before rendering the initial WebView.
- Apply persisted `traffic_mode` to `DesktopShellController` before `render_shell_html`.
- After WebView creation, evaluate a settings status script so form fields match persisted values.
- On save, write settings, re-apply traffic mode, sync the form, and refresh the shell snapshot.

Wire UI behavior through `html.rs`:

- Add a compact save button/status to the Settings network panel.
- Add `collectDesktopSettings()` and `postSaveDesktopSettings()`.
- Add `window.keliSetDesktopSettings(summary)` to update inputs after startup and save.
- Keep settings inside the existing non-scrolling Settings view; no new page or nested card.

## Validation

- Unit tests cover settings default/read/write behavior.
- IPC tests cover `save-desktop-settings` JSON mapping.
- HTML tests cover save controls, script entrypoints, and startup sync hook.
- Smoke workflow entrypoints include `save-desktop-settings`.
- `cargo test -p keli-desktop-shell -- --test-threads=1` passes.
- `cargo run -q -p keli-desktop-shell -- --smoke` reports `passed`.
