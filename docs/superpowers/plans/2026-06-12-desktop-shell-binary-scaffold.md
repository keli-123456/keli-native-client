# Desktop Shell Binary Scaffold Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for the implementation tasks and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the first compileable Windows desktop shell binary around the existing `keli-desktop` controller so Keli has a non-CLI application entry point.

**Architecture:** Add a separate workspace crate, `keli-desktop-shell`, that depends on `keli-desktop`. Use `tao` for the event loop/window, `wry` for a compact local WebView, `tray-icon` for the system tray, and `single-instance` for a process-level single-instance gate. Keep the first visual surface static and minimal; controller IPC, subscription forms, and packaging get separate slices.

**Tech Stack:** Rust 2021, `keli-desktop`, `tao`, `wry`, `tray-icon`, `single-instance`, `serde_json`.

---

## Scope Check

This plan covers:

- A new workspace member: `crates/keli-desktop-shell`.
- A binary entry point that checks single instance before starting the UI event loop.
- A main window titled `Keli`.
- A local WebView that renders a compact shell snapshot from `DesktopShellController::new_native()`.
- A tray icon with menu item IDs aligned to `DesktopShellState` tray IDs.
- Close-window-to-hide behavior so the process can remain tray-first.
- Compile verification with `cargo check -p keli-desktop-shell`.

This plan does not cover:

- Full visual product UI.
- JavaScript command IPC.
- Subscription input and node list UI.
- Installer packaging.
- Runtime smoke involving real system proxy or TUN.

## File Structure

- Modify: `Cargo.toml`
  - Add `crates/keli-desktop-shell` to the workspace.
  - Add workspace dependencies for `tao`, `wry`, `tray-icon`, and `single-instance`.
- Add: `crates/keli-desktop-shell/Cargo.toml`
- Add: `crates/keli-desktop-shell/src/main.rs`
- Add: `crates/keli-desktop-shell/src/html.rs`
  - Pure helper for shell HTML generation with unit tests.

## Task 1: Scaffold RED Check

**Files:**
- Modify: `Cargo.toml`
- Add: `crates/keli-desktop-shell/*`

- [ ] **Step 1: Run missing crate check**

Run: `cargo check -p keli-desktop-shell`

Expected: FAIL because the crate does not exist yet.

## Task 2: Add Shell Binary Crate

**Files:**
- Modify: `Cargo.toml`
- Add: `crates/keli-desktop-shell/Cargo.toml`
- Add: `crates/keli-desktop-shell/src/main.rs`
- Add: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add workspace member and dependencies**

Use:

- `tao = "0.35.3"`
- `wry = "0.55.1"`
- `tray-icon = { version = "0.24.1", default-features = false, features = ["common-controls-v6"] }`
- `single-instance = "0.3.3"`

- [ ] **Step 2: Add HTML helper tests**

Test that generated HTML includes:

- `Keli`
- runtime state
- selected outbound when present
- tray item IDs from the shell snapshot

- [ ] **Step 3: Add binary entry**

The binary should:

- Create a `SingleInstance` gate.
- Build `DesktopShellController::new_native()`.
- Build a tray menu from the shell snapshot.
- Build a `tao` window and `wry` WebView with generated HTML.
- Hide the window on close request.
- Exit when the shell quit action is requested from the tray menu.

- [ ] **Step 4: Run target checks**

Run:

- `cargo test -p keli-desktop-shell`
- `cargo check -p keli-desktop-shell`

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `Cargo.toml`
- `Cargo.lock`
- `crates/keli-desktop-shell/**`
- `docs/superpowers/plans/2026-06-12-desktop-shell-binary-scaffold.md`

- [ ] **Step 1: Format check**

Run: `cargo fmt --check`

Expected: PASS.

- [ ] **Step 2: Diff whitespace check**

Run: `git diff --check`

Expected: PASS.

- [ ] **Step 3: Desktop shell crate checks**

Run:

- `cargo test -p keli-desktop-shell`
- `cargo check -p keli-desktop-shell`

Expected: PASS.

- [ ] **Step 4: Existing desktop backend tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Commit and push**

Commit the plan first, then commit the scaffold implementation after verification. Push each commit to `origin/main`.

## Self-Review Checklist

- Spec coverage: advances from backend-only work to a real desktop application entry point.
- Scope: visual and IPC depth remain separate follow-up slices.
- Runtime ownership: the binary uses `DesktopShellController::new_native()` and does not duplicate core logic.
- Product direction: the shell is tray-first and keeps process lifetime separate from window visibility.
