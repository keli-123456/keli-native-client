# One Click Connection State Closure Design

## Context

The desktop shell already has a one click connection surface. The UI can show the selected node, traffic mode, listener address, system proxy takeover status, and repair actions. The current weak point is the state boundary after lifecycle actions.

`DesktopShellController::request_start` and `request_stop` call the host lifecycle methods and refresh `DesktopStatusSnapshot`, but they do not refresh `DesktopDependencyReport`. System proxy takeover and restore verification depends on `DesktopDependencyReport.system_proxy`, so the UI can show a stale proxy snapshot after start or stop until the user manually refreshes.

## Goal

Make the one click connection state reflect the real post-action machine state after start and stop:

- After start, the shell snapshot includes the latest status and dependency report.
- In system proxy mode, the unified connection status can verify whether the system proxy was actually enabled and points to the active listener.
- After stop, the shell snapshot includes the latest dependency report so the UI can confirm system proxy restoration or show a repair action.

## Non Goals

- No new page layout or visual redesign.
- No new traffic mode semantics.
- No background polling loop in this step.
- No changes to KeliBoard API import or node list behavior.
- No direct platform registry or network code in the shell layer.

## Approaches

### Recommended: Refresh Dependencies In Controller Lifecycle

After `host.start()` and `host.stop()`, refresh both status and dependencies inside `DesktopShellController`. This keeps the shell snapshot internally consistent before it reaches WebView sync, tray state, and tests.

Tradeoff: each lifecycle action performs one extra dependency detection. This is acceptable because start and stop are user-triggered, low-frequency actions.

### Alternative: Refresh Dependencies In Shell Event Handler

Keep the controller unchanged and call `controller.refresh()` after lifecycle events in `keli-desktop-shell`.

Tradeoff: this helps the current WebView path, but other controller consumers and tests can still observe stale snapshots. The boundary is weaker.

### Alternative: Add Short Post-Start Polling

After start, poll until system proxy takeover appears or a timeout expires.

Tradeoff: this may become necessary later for slower OS propagation, but it is a larger behavioral change. It should come after the snapshot refresh boundary is correct.

## Design

The controller remains the owner of shell snapshot consistency. `request_start` and `request_stop` will update dependencies immediately after refreshing status:

1. Validate the primary action is allowed.
2. Call `host.start()` or `host.stop()`.
3. Refresh shell status with the returned `DesktopStatusSnapshot`.
4. Refresh shell dependencies with `host.dependency_report()`.
5. Return the updated `DesktopShellState`.

This makes lifecycle results match the data needs of `html.rs` connection summaries without making the UI know when dependencies must be refreshed.

## Data Flow

Start flow:

1. UI posts `primary`.
2. Shell maps it to `DesktopShellAction::RequestStart`.
3. Controller calls `host.start()`.
4. Controller records the returned runtime status.
5. Controller records a fresh dependency report.
6. WebView receives one updated snapshot.
7. The existing unified connection status renders system proxy takeover from the fresh dependency report.

Stop flow:

1. UI posts `primary`.
2. Shell maps it to `DesktopShellAction::RequestStop`.
3. Controller calls `host.stop()`.
4. Controller records stopped status.
5. Controller records a fresh dependency report.
6. WebView receives one updated snapshot.
7. The existing unified connection status can show restored or still enabled system proxy state.

## Error Handling

If `host.start()` or `host.stop()` returns an error, the existing error path remains unchanged and no dependency refresh is required for this step.

If dependency detection fails, the host already converts platform state into `DesktopDependencyReport`. This design does not introduce a new fallible controller method.

## Testing

Add controller tests around the existing fake host:

- Start refreshes dependencies after the host lifecycle updates proxy state.
- Stop refreshes dependencies after the host lifecycle updates proxy state.

The fake host should simulate post-action dependency changes:

- Before start: system proxy disabled.
- After start: system proxy enabled and server points to `127.0.0.1:7890`.
- Before stop: system proxy enabled.
- After stop: system proxy disabled and server is cleared.

Run focused tests first, then the full `keli-desktop` package tests, then desktop shell smoke checks if any shell-facing behavior changes.

## Acceptance Criteria

- `DesktopShellController::dispatch(RequestStart)` returns a shell snapshot with fresh dependencies.
- `DesktopShellController::dispatch(RequestStop)` returns a shell snapshot with fresh dependencies.
- Existing start, stop, import, and UI shell tests continue to pass.
- No new user confirmation, page, or manual refresh is required for the UI to see post-action proxy state.

## Implementation Boundary

Expected code changes are limited to:

- `crates/keli-desktop/src/app.rs` controller lifecycle methods.
- Controller fake host or tests in the same file.

`crates/keli-desktop-shell/src/html.rs` should not need changes in this step because it already consumes the dependency report.
