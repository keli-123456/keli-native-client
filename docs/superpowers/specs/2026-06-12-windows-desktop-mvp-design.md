# Windows Desktop Client MVP Design

## Goal

Build the first Windows desktop MVP around the completed native Keli core. A user should be able to install and open Keli, import a subscription, choose a node, start or stop proxy service, enable system proxy or TUN mode, inspect status, and export a support bundle without using the command line.

This goal starts after the native core has passed the default-core release gate. The desktop app should treat the native core as the default runtime, not as an experimental fallback.

## Non-Goals

- Mobile clients.
- Multi-account billing or panel administration.
- A full visual redesign beyond a focused, usable Windows desktop shell.
- Replacing the existing core certification gates.
- Supporting platforms other than Windows in this MVP.

## Product Shape

The MVP has two visible surfaces:

1. A tray-first background app for everyday control.
2. A compact main window for setup, node selection, status, diagnostics, and settings.

The app should feel like an operational network tool: clear, dense enough for repeated use, and restrained. It should prioritize current connection state, selected node, traffic mode, and recovery actions over decorative layout.

## User Workflows

### First Run

The first-run flow checks whether the native core can run as the default engine on this machine:

- Detect packaged core binary/library availability.
- Check Wintun availability for TUN mode.
- Check system proxy capability.
- Show blockers as actionable setup steps.
- Allow the user to continue with system proxy mode if TUN is not ready.

### Subscription Setup

The user can paste or edit a subscription URL, fetch it, and see a redacted result:

- Source host and path shape, without exposing tokens.
- Supported node count.
- Skipped node count and reasons.
- Default node.
- Last fetch/update result.

The app should reuse the existing subscription fetch/update planning behavior so failed updates do not replace a working runtime.

### Connect And Disconnect

The primary action starts or stops the managed native core:

- Start with the selected node and selected mode.
- Stop cleanly and restore system proxy state.
- Keep a stopped status snapshot available for diagnostics.
- Show clear states: stopped, starting, running, stopping, degraded, blocked.

### Node Selection

The node list should expose the current subscription nodes with enough signal to choose safely:

- Name/tag.
- Protocol and transport summary.
- TCP health.
- UDP health when available.
- Latency or last failure.
- Recommended node marker.

Changing nodes while running should use the managed reload path and preserve service if the requested update fails.

### Traffic Mode

The MVP supports:

- System proxy mode.
- TUN mode when Wintun and platform checks pass.

The app should make it obvious which mode is active and whether machine takeover is fully ready.

### Diagnostics

The support surface exports a support bundle and shows a short health summary:

- Current core status.
- Recent runtime events.
- Last error.
- System proxy snapshot/restore status.
- TUN diagnostics when enabled or available.
- Default-core certification summary.

Sensitive values such as subscription tokens must remain redacted.

## Architecture

### Desktop Shell

Use a Windows desktop shell that can support:

- Tray icon and tray menu.
- Single-instance behavior.
- Main window with settings and status.
- Background process lifetime separate from window visibility.
- Local packaged native core access.

The shell should call a narrow local backend API instead of duplicating core logic in UI code.

### Local Backend Boundary

Create a desktop-facing runtime service boundary around the existing managed controller. This boundary owns:

- Core start/status/reload/stop commands.
- Subscription fetch/update commands.
- Node health probe commands.
- TUN backend check/install reporting.
- Support bundle export.
- Default-core certification status.

It should expose stable, typed DTOs for UI consumption. The existing CLI JSON shape can guide the DTOs, but the UI boundary should not require shelling out for every ordinary action if a direct Rust library path is available.

### Core Runtime

The native core remains the source of truth for:

- Protocol support.
- Routing and DNS policy.
- System proxy apply/restore.
- TUN lifecycle and diagnostics.
- Subscription parsing and reload planning.
- Support bundle and readiness evidence.

The desktop layer should not create parallel routing, subscription, or health logic.

## Data Flow

1. User enters a subscription URL.
2. Desktop backend fetches and validates it through existing subscription boundaries.
3. UI receives a redacted subscription summary and node list.
4. User selects a node and traffic mode.
5. Backend starts managed native core.
6. UI polls or subscribes to status updates.
7. Runtime events, metrics, health, and failures are reflected in the UI.
8. Support bundle export captures the same evidence used by CLI diagnostics.

## Error Handling

Failures should be recoverable and specific:

- Missing Wintun: show install/check action and keep system proxy mode available.
- System proxy apply failure: stop startup, restore previous state when possible, and show restore evidence.
- Subscription fetch failure: preserve the current runtime and show redacted source metadata.
- Bad subscription update: reject the update without replacing the active runtime.
- Core start failure: leave the app stopped with a concrete blocker.
- Core stop timeout: surface worker-drain diagnostics and avoid hiding residual state.

## Testing And Verification

The MVP is complete when these checks pass:

- Existing native-core workspace tests still pass.
- Desktop backend unit tests cover state transitions and DTO mapping.
- Subscription setup tests cover success, invalid URL, failed fetch, and unusable subscription.
- Runtime control tests cover start, status, reload, stop, and stop diagnostics.
- TUN/Wintun UI boundary tests cover missing, ready, and installed states.
- Support bundle export test verifies redaction and embedded certification evidence.
- Manual Windows smoke: install/open, import subscription, start system proxy mode, stop and restore proxy, run TUN preflight, export support bundle.

## Release Gate

The desktop MVP can be considered ready for a first internal release when:

- The packaged app opens without command-line setup.
- The native core is the default runtime.
- A user can complete the core workflow from UI only.
- The app can recover from failed subscription updates without dropping the active runtime.
- The app restores Windows system proxy state on stop.
- TUN mode is clearly blocked, ready, or running based on Wintun and preflight evidence.
- Support diagnostics can be exported from the UI.
- The existing default-core release gate remains passing.

## Implementation Slices

1. Desktop shell and single-instance tray app scaffold.
2. Backend API around managed core status and lifecycle.
3. Subscription import, node list, and selected node persistence.
4. Start/stop/reload controls with system proxy mode.
5. TUN/Wintun readiness and TUN mode controls.
6. Diagnostics screen and support bundle export.
7. Packaging, install smoke, and release gate integration.

## Open Decisions

- Exact desktop shell technology should be chosen during implementation planning after checking existing project constraints and build tooling.
- The first visual pass should be functional and restrained; richer branding can follow after the operational MVP works.
