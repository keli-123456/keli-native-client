# Desktop Shell State Unification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for the implementation tasks and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a UI-framework-neutral desktop shell state model that unifies tray, window, lifecycle, dependency, and primary connect/disconnect intent around the existing native desktop command host.

**Architecture:** Keep `DesktopNativeCommandService` as the runtime command boundary. Add a small `shell` module in `keli-desktop` that exposes typed DTOs for visible shell state and deterministic actions. The module should not duplicate core runtime logic; it only translates status and dependency reports into shell-ready state and next commands.

**Tech Stack:** Rust 2021, serde DTOs, existing `DesktopStatusSnapshot`, `DesktopDependencyReport`, and `DesktopNativeCommandService`.

---

## Scope Check

This plan covers:

- A single shell state snapshot for tray and main window bindings.
- Window visibility and quit intent transitions.
- Primary action mapping for start, stop, blocked, and busy states.
- Tray menu item enablement derived from runtime status and dependency readiness.
- Tests for all shell state transitions and DTO mapping.

This plan does not cover:

- A visible Tauri/wry/Electron window.
- Icon assets or installer packaging.
- Persisted settings.
- Real OS single-instance locks.

## File Structure

- Add: `crates/keli-desktop/src/shell.rs`
  - Define `DesktopShellState`, `DesktopShellAction`, `DesktopShellPrimaryAction`, `DesktopShellTrayMenu`, and related DTOs.
  - Add deterministic reducers for window/tray actions.
- Modify: `crates/keli-desktop/src/lib.rs`
  - Export shell DTOs.

## Task 1: Shell State Tests

**Files:**
- Add: `crates/keli-desktop/src/shell.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Write failing tests**

Add tests that expect:

- The default shell starts with a hidden main window, no quit intent, stopped runtime, and primary `start` action.
- `ShowMainWindow`, `HideMainWindow`, and `ToggleMainWindow` update visibility without changing runtime state.
- Running status maps primary action to `stop`.
- Starting, stopping, reloading, and failed status map primary action to disabled busy/error-safe states.
- A dependency report that blocks both system proxy and TUN maps primary action to blocked and disables start.
- The tray menu exposes stable IDs for show, start/stop, diagnostics, and quit.

- [ ] **Step 2: Run tests to verify RED**

Run: `cargo test -p keli-desktop shell -- --test-threads=1`

Expected: FAIL because the shell module and DTOs do not exist.

## Task 2: Implement Shell State Model

**Files:**
- Add: `crates/keli-desktop/src/shell.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Define action and state DTOs**

Use serde-friendly enums and structs:

- `DesktopShellAction`
- `DesktopShellPrimaryAction`
- `DesktopShellWindowState`
- `DesktopShellTrayMenu`
- `DesktopShellTrayItem`
- `DesktopShellState`

- [ ] **Step 2: Add constructors and reducers**

Implement:

- `DesktopShellState::new(status, dependencies)`
- `DesktopShellState::apply(action)`
- `DesktopShellState::refresh_status(status)`
- `DesktopShellState::refresh_dependencies(dependencies)`

- [ ] **Step 3: Derive primary action and tray menu**

Keep mapping deterministic:

- stopped + at least one runnable mode => start enabled
- running/reloading => stop enabled
- starting/stopping => busy disabled
- failed => start enabled when dependency readiness allows retry
- no runnable mode => blocked disabled

- [ ] **Step 4: Export module**

Update `crates/keli-desktop/src/lib.rs` to expose the shell module and DTOs.

- [ ] **Step 5: Run shell tests to verify GREEN**

Run: `cargo test -p keli-desktop shell -- --test-threads=1`

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `crates/keli-desktop/src/shell.rs`
- `crates/keli-desktop/src/lib.rs`
- `docs/superpowers/plans/2026-06-12-desktop-shell-state-unification.md`

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

- Spec coverage: advances desktop shell and single-instance tray scaffold by giving the visible shell one canonical state model.
- Scope: no visual UI or heavy desktop framework dependency is introduced in this slice.
- Runtime ownership: shell state does not duplicate native core lifecycle logic.
- UI readiness: DTOs are serializable and stable enough for a future Tauri/wry command bridge.
