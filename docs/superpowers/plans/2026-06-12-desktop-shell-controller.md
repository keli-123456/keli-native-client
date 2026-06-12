# Desktop Shell Controller Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for the implementation tasks and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect the unified desktop shell state model to the existing desktop command host so a future tray/window frontend can dispatch one typed action and receive a refreshed shell snapshot.

**Architecture:** Keep `DesktopNativeCommandService` and `DesktopCommandService` as the runtime command boundary. Add a small controller that owns any command host implementing a shell host trait, owns `DesktopShellState`, and maps shell actions to command calls or local window state transitions.

**Tech Stack:** Rust 2021, serde DTOs, existing `DesktopCommandError`, `DesktopNativeCommandService`, `DesktopShellState`, and desktop status/dependency DTOs.

---

## Scope Check

This plan covers:

- A testable shell command host trait for start, stop, status, and dependency refresh.
- A `DesktopShellController` that owns shell state and a command host.
- Dispatch for local shell actions: show, hide, diagnostics, and quit.
- Dispatch for runtime actions: request start and request stop.
- A controller-level error for blocked or invalid shell actions.
- Native constructor wiring for the real desktop command host.

This plan does not cover:

- Subscription form commands.
- Visible UI rendering.
- Background polling loops.
- Persisted settings.
- Installer packaging.

## File Structure

- Add: `crates/keli-desktop/src/app.rs`
  - Define `DesktopShellCommandHost`.
  - Define `DesktopShellController`.
  - Define `DesktopShellControllerError`.
  - Add tests with a fake command host.
- Modify: `crates/keli-desktop/src/lib.rs`
  - Export controller DTOs.

## Task 1: Controller Tests

**Files:**
- Add: `crates/keli-desktop/src/app.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Write failing tests**

Add tests that expect:

- The controller starts from host status plus dependency report.
- Local window actions update shell state without calling start or stop.
- `RequestStart` calls the host once and refreshes the shell to running.
- `RequestStop` calls the host once and refreshes the shell to stopped.
- A blocked shell refuses `RequestStart` before calling the host and returns a serializable controller error.
- `refresh()` refreshes both status and dependencies.

- [ ] **Step 2: Run tests to verify RED**

Run: `cargo test -p keli-desktop shell_controller -- --test-threads=1`

Expected: FAIL because the controller module does not exist.

## Task 2: Implement Controller

**Files:**
- Add: `crates/keli-desktop/src/app.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Define command host trait**

The trait should expose:

- `status`
- `dependency_report`
- `start`
- `stop`

Implement it for `DesktopNativeCommandService`.

- [ ] **Step 2: Define controller error**

Use a serializable error with fields:

- `operation`
- `kind`
- `message`

Map command errors without losing their operation/kind/message.

- [ ] **Step 3: Define controller**

`DesktopShellController<H>` owns:

- `host: H`
- `shell: DesktopShellState`

It exposes:

- `new(host)`
- `new_native()`
- `snapshot()`
- `refresh()`
- `dispatch(action)`

- [ ] **Step 4: Runtime dispatch**

For `RequestStart`:

- Check current `primary_action.enabled`.
- Check command is `Start` or `Retry`.
- Call host `start`.
- Refresh shell status from result.

For `RequestStop`:

- Check current `primary_action.enabled`.
- Check command is `Stop`.
- Call host `stop`.
- Refresh shell status from result.

- [ ] **Step 5: Local dispatch**

For non-runtime actions, apply them to `DesktopShellState` only.

- [ ] **Step 6: Run controller tests to verify GREEN**

Run: `cargo test -p keli-desktop shell_controller -- --test-threads=1`

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `crates/keli-desktop/src/app.rs`
- `crates/keli-desktop/src/lib.rs`
- `docs/superpowers/plans/2026-06-12-desktop-shell-controller.md`

- [ ] **Step 1: Format check**

Run: `cargo fmt --check`

Expected: PASS.

- [ ] **Step 2: Diff whitespace check**

Run: `git diff --check`

Expected: PASS.

- [ ] **Step 3: Desktop crate tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 4: Commit and push**

Commit the plan first, then commit the implementation after verification. Push each commit to `origin/main`.

## Self-Review Checklist

- Spec coverage: advances the tray/window shell by giving UI code one action dispatcher over the native command host.
- Scope: subscription entry and visual rendering stay out of this slice.
- Runtime ownership: start/stop remains in the command host and managed core.
- UI readiness: controller returns serializable snapshots and errors.
