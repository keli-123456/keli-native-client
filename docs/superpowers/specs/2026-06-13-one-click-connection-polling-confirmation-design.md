# One Click Connection Polling Confirmation Design

## Context

The desktop controller now refreshes dependencies after successful start and stop. The shell UI can therefore render system proxy takeover and restoration from real machine snapshots.

One practical gap remains: operating system proxy state can lag behind the runtime lifecycle result. A start request may return with the core running and a listener available while the system proxy snapshot still shows the old state for a short moment. A stop request can have the same issue while the proxy setting is being restored.

## Goal

Add a short confirmation loop after one click start and stop so the UI automatically refreshes until it can confirm the real connection outcome:

- Start succeeds only when the current mode is connected. In system proxy mode, this includes proxy takeover verification.
- Stop succeeds only when the core is stopped. In system proxy mode, this includes proxy restoration verification.
- If confirmation does not become true within a small bounded number of refreshes, the UI keeps the existing repair actions visible and reports a timeout-style failure.

## Non Goals

- No new layout or visual redesign.
- No long-running background polling.
- No blocking wait inside `keli-desktop` controller lifecycle methods.
- No platform registry logic in the WebView.
- No changes to node import, KeliBoard API integration, or subscription storage.

## Approaches

### Recommended: WebView Short Polling While A Core Intent Is Pending

The existing `pendingCoreConnectionIntent` already tracks whether the user clicked start or stop. Extend that state with a bounded timer and attempt counter. `syncCoreConnectionStatus(snapshot)` decides whether the latest snapshot confirms completion. If not, it schedules one more `refresh` IPC.

Tradeoff: this keeps confirmation behavior close to the UI state it drives. It is bounded and does not change backend lifecycle semantics.

### Alternative: Block In The Controller Until Confirmation

The controller could call dependency detection repeatedly after start or stop before returning.

Tradeoff: the UI would get a simpler final snapshot, but lifecycle commands would block longer and the backend would learn UI confirmation policy.

### Alternative: Continuous Background Status Polling

The shell could poll status all the time while the app is open.

Tradeoff: this may become useful later for live metrics, but it is unnecessary for this focused connection confirmation step.

## Design

Add a bounded poll controller to the WebView script in `crates/keli-desktop-shell/src/html.rs`:

- `pendingCoreConnectionIntent` remains the source of truth for whether the user is waiting on start or stop.
- Add constants for poll limit and interval.
- Add attempt and timer state.
- When a primary start or stop is posted, reset polling state and mark the pending intent.
- When a shell snapshot arrives, compute the existing `coreConnectionSummary(snapshot)`.
- If the pending intent is confirmed, clear polling and publish the summary to the unified operation status.
- If the pending intent is not confirmed, schedule a bounded `refresh`.
- If the limit is reached, clear the pending intent, keep the current connection status visible, and publish an error summary explaining that confirmation timed out.

The terminal rules are:

- Start in local inbound or TUN mode: running plus listener confirms.
- Start in system proxy mode: running plus listener plus non-error system proxy takeover summary confirms.
- Stop in local inbound or TUN mode: stopped confirms.
- Stop in system proxy mode: stopped plus non-error system proxy restoration summary confirms.
- `last_error` or `failed` confirms a terminal error immediately.

## Data Flow

1. User clicks the primary action.
2. `postOperation("primary", primaryOperationPending())` marks a pending start or stop intent.
3. The backend handles the action and syncs a shell snapshot.
4. `syncCoreConnectionStatus(snapshot)` renders the current state.
5. If the snapshot does not confirm the pending intent, the script schedules `window.ipc.postMessage("refresh")`.
6. Each refreshed snapshot repeats the same confirmation check.
7. Confirmation, failure, or poll exhaustion clears the pending intent.

## Error Handling

The poll loop is bounded. It will not create unbounded refresh traffic.

If the backend returns `last_error` or `failed`, polling stops immediately and the existing error message is shown.

If system proxy takeover or restoration remains incomplete when the poll limit is reached, the UI reports a connection confirmation timeout and leaves existing repair actions available.

## Testing

Use `html.rs` render tests to verify the generated WebView script contains the polling contract:

- Poll state and constants exist.
- `markCoreConnectionPending` resets poll state.
- `syncCoreConnectionStatus` schedules additional refreshes while the pending intent is not terminal.
- Terminal confirmation uses the `coreConnectionSummary` result, not only raw `run_state`.
- Timeout publishes an error and clears the pending intent.

The tests stay at render-contract level because the desktop shell currently tests WebView behavior by asserting generated script contracts rather than running a browser engine.

## Acceptance Criteria

- One click start does not complete the pending operation status until the snapshot confirms the connection.
- In system proxy mode, start confirmation waits for real proxy takeover.
- One click stop does not complete the pending operation status until proxy restoration is confirmed when applicable.
- Confirmation polling is bounded.
- Existing desktop shell tests and smoke checks continue to pass.

## Implementation Boundary

Expected code changes are limited to:

- `crates/keli-desktop-shell/src/html.rs`

No changes are expected in `keli-desktop`, `keli-client-core`, or platform crates for this step.
