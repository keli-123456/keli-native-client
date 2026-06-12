# Desktop Shell IPC Actions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for the implementation tasks and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the first desktop shell interactive by routing WebView and tray actions through `DesktopShellController`, then reflecting the refreshed shell snapshot back into the WebView.

**Architecture:** Keep `DesktopShellController` as the only runtime action dispatcher. Add pure mapping helpers in `keli-desktop-shell` for WebView IPC messages and tray item IDs. Extend the static HTML with stable element IDs, command buttons, and a small `window.keliSetShell(snapshot)` updater. The binary should translate WebView IPC into user events, dispatch through the controller, and evaluate a snapshot-update script.

**Tech Stack:** Rust 2021, `keli-desktop`, `wry` IPC, `serde_json`.

---

## Scope Check

This plan covers:

- WebView IPC messages for primary action, refresh, diagnostics, show/hide, and quit.
- Tray `toggle-service` routing that chooses start or stop from the current shell primary action.
- Snapshot update JavaScript generated from `DesktopShellState`.
- Tests for IPC mapping and generated snapshot script.
- `cargo check -p keli-desktop-shell` proving the interactive shell compiles.

This plan does not cover:

- Subscription URL input.
- Node selection UI.
- Live event streaming.
- Installer packaging.
- Real start smoke with a user subscription.

## File Structure

- Add: `crates/keli-desktop-shell/src/actions.rs`
  - Define `DesktopShellUiEvent`.
  - Map WebView IPC messages and tray IDs to controller actions.
- Modify: `crates/keli-desktop-shell/src/html.rs`
  - Add action buttons and stable DOM IDs.
  - Add `shell_snapshot_script`.
  - Add tests.
- Modify: `crates/keli-desktop-shell/src/main.rs`
  - Register Wry IPC handler.
  - Dispatch UI events through the controller.
  - Update the WebView after actions and refresh.

## Task 1: RED Tests

**Files:**
- Add: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Write failing tests**

Add tests that expect:

- Stopped shell primary IPC maps to `RequestStart`.
- Running shell primary IPC maps to `RequestStop`.
- Busy or blocked primary IPC is ignored.
- Tray `toggle-service` uses the same primary-action mapping.
- Refresh IPC maps to a refresh event.
- Generated HTML includes `window.ipc.postMessage('primary')`.
- Generated update script calls `window.keliSetShell` with serialized shell JSON.

- [ ] **Step 2: Run tests to verify RED**

Run: `cargo test -p keli-desktop-shell ipc -- --test-threads=1`

Expected: FAIL because the IPC action helpers and update script do not exist.

## Task 2: Implement IPC Actions

**Files:**
- Add: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add action mapping helper**

Map:

- `primary`
- `refresh`
- `show-main-window`
- `hide-main-window`
- `open-diagnostics`
- `quit`

- [ ] **Step 2: Add tray mapping helper**

Map tray IDs from `DesktopShellTrayMenu`, with `toggle-service` choosing start or stop from the current primary action.

- [ ] **Step 3: Add HTML buttons and updater**

Expose stable element IDs and a `window.keliSetShell(snapshot)` function.

- [ ] **Step 4: Wire Wry IPC**

Use `with_ipc_handler` to forward messages to the Tao event loop.

- [ ] **Step 5: Sync snapshot after dispatch**

After dispatch or refresh, call `webview.evaluate_script(shell_snapshot_script(snapshot))`.

## Task 3: Verification, Commit, And Push

**Files:**
- `crates/keli-desktop-shell/src/actions.rs`
- `crates/keli-desktop-shell/src/html.rs`
- `crates/keli-desktop-shell/src/main.rs`
- `docs/superpowers/plans/2026-06-12-desktop-shell-ipc-actions.md`

- [ ] **Step 1: Format check**

Run: `cargo fmt --check`

Expected: PASS.

- [ ] **Step 2: Diff whitespace check**

Run: `git diff --check`

Expected: PASS.

- [ ] **Step 3: Shell crate tests and check**

Run:

- `cargo test -p keli-desktop-shell`
- `cargo check -p keli-desktop-shell`

Expected: PASS.

- [ ] **Step 4: Existing desktop backend tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Commit and push**

Commit the plan first, then commit the IPC implementation after verification. Push each commit to `origin/main`.

## Self-Review Checklist

- Spec coverage: the shell now has a usable action path instead of static-only state.
- Scope: subscription and node workflows remain separate slices.
- Runtime ownership: WebView and tray actions always go through `DesktopShellController`.
- Product direction: the visible shell starts to behave like the future main window while remaining compact.
