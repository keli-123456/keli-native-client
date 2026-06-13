# Desktop Settings Runtime Application Design

## Goal

Make the persisted Settings network port affect the real desktop runtime listen address, so saving `mixed_port` changes the address used by future one-click starts.

## Context

The desktop shell now persists Settings form values in `%APPDATA%\Keli\desktop-settings.json` and restores them on launch. The runtime backend already supports `DesktopRuntimeService::set_listen` and `DesktopNativeCommandService::set_listen`, but `DesktopShellController` only exposes traffic mode. That means the saved `mixed_port` currently restores in the UI but does not influence the start path.

## Scope

This slice applies only `mixed_port` because it maps directly to the existing managed mixed inbound listen address. The `socks_port`, `http_port`, `dns_mode`, `tun_stack`, `start_with_windows`, `launch_minimized`, and `auto_start_core` fields remain persisted UI preferences until the desktop runtime exposes matching typed behavior.

## Design

Expose listen configuration through the existing desktop controller boundary:

- Add `set_listen(&mut self, listen: String)` to `DesktopShellCommandHost`.
- Forward it in `DesktopNativeCommandService`.
- Add `DesktopShellController::set_listen(listen)` that calls the host, refreshes status, and returns the updated shell snapshot.
- Extend the fake host in `keli-desktop` tests so controller behavior can be verified without starting the real core.

Apply saved settings in `keli-desktop-shell`:

- Add a helper that converts `DesktopShellSettings::mixed_port` to `127.0.0.1:<port>`.
- On launch, after applying persisted traffic mode, apply the persisted listen address before rendering initial HTML.
- On settings save, write JSON, apply traffic mode, apply listen, then sync the WebView.

Expose evidence in smoke:

- Add `settings_runtime_ready` to the shell smoke report.
- Treat smoke as passed only when the settings save workflow and listen application evidence are present.
- Keep `settings_persistence_ready` for the previously completed persistence slice.

## Validation

- `keli-desktop` tests prove `DesktopShellController::set_listen` forwards to the command host and refreshes shell status.
- `keli-desktop-shell` tests prove the settings helper formats the listen address and smoke reports runtime readiness.
- `cargo test -p keli-desktop -- --test-threads=1` passes.
- `cargo test -p keli-desktop-shell -- --test-threads=1` passes.
- `cargo run -q -p keli-desktop-shell -- --smoke` reports both `settings_persistence_ready` and `settings_runtime_ready`.
