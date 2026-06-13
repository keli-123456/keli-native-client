# Desktop Auto Start Core Design

Date: 2026-06-13

## Goal

Make the persisted `auto_start_core` desktop setting affect launch behavior. When the desktop shell starts and the setting is enabled, it should reuse the existing start command path once the restored shell state says the core can start.

## Non-goals

- Do not implement Windows login startup registration in this slice.
- Do not add retry loops or a background service supervisor.
- Do not start the core when the shell reports missing subscription or blocked dependencies.
- Do not make saving the setting immediately start the core; the label means client launch behavior.

## Design

The shell already persists and restores `auto_start_core`, and the controller already owns the safe start path through `DesktopShellAction::RequestStart`. This slice adds a small launch helper that converts restored settings plus a derived shell snapshot into an optional shell action:

```rust
fn desktop_settings_auto_start_action(
    settings: &DesktopShellSettings,
    shell: &DesktopShellState,
) -> Option<DesktopShellAction>
```

The helper returns `Some(DesktopShellAction::RequestStart)` only when:

- `settings.auto_start_core` is true.
- `shell.can_start` is true after settings have been applied.

Desktop startup should call a startup-specific settings helper before the first HTML render:

1. Apply persisted runtime settings, including traffic mode and mixed listen port.
2. Inspect the derived shell state.
3. Dispatch `RequestStart` only when the auto-start helper returns an action.
4. If start dispatch fails, log the error and keep launching the UI with the current controller snapshot.

The normal save-settings IPC continues to apply runtime settings only. That avoids surprising users by starting the core while they are editing settings.

## Verification

- Unit test the auto-start action helper for enabled, disabled, and blocked states.
- Extend the desktop smoke report with `settings_auto_start_ready`.
- Run the shell crate tests and the desktop shell smoke command.
