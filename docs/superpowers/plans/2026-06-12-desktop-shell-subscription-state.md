# Desktop Shell Subscription State Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for the implementation tasks and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the unified desktop shell/controller boundary so subscription import and node selection update the same shell snapshot used by the window and tray.

**Architecture:** Keep subscription parsing and reload behavior inside the existing desktop command host. Add subscription state to `DesktopShellState`, extend `DesktopShellCommandHost` with import/select/mode setters, and expose controller methods that call the host then refresh shell state.

**Tech Stack:** Rust 2021, `keli-desktop`, existing `DesktopSubscriptionSummary`, `DesktopShellController`.

---

## Scope Check

This plan covers:

- `DesktopShellState.subscription`.
- Controller import of raw subscription config text.
- Controller selected-node changes.
- Controller traffic-mode changes.
- Tests with a fake shell command host.

This plan does not cover:

- Subscription URL fetching UI.
- WebView textarea/form IPC.
- Persisting subscriptions to disk.
- Node latency/health probes.

## File Structure

- Modify: `crates/keli-desktop/src/shell.rs`
  - Add optional subscription summary to shell state.
  - Add helper to refresh subscription state.
- Modify: `crates/keli-desktop/src/app.rs`
  - Extend `DesktopShellCommandHost`.
  - Add controller import/select/mode methods.
  - Add tests.

## Task 1: RED Tests

**Files:**
- Modify: `crates/keli-desktop/src/shell.rs`
- Modify: `crates/keli-desktop/src/app.rs`

- [ ] **Step 1: Write failing tests**

Add tests that expect:

- New shell snapshots start with `subscription == None`.
- Refreshing shell subscription stores the summary.
- Controller import calls host import once and stores the returned subscription in the shell snapshot.
- Controller select node calls host select once and updates the stored subscription.
- Controller traffic mode setter calls host setter and refreshes shell status.

- [ ] **Step 2: Run tests to verify RED**

Run: `cargo test -p keli-desktop shell_subscription -- --test-threads=1`

Expected: FAIL because shell subscription state and controller methods do not exist.

## Task 2: Implement Shell Subscription State

**Files:**
- Modify: `crates/keli-desktop/src/shell.rs`
- Modify: `crates/keli-desktop/src/app.rs`

- [ ] **Step 1: Add subscription field**

Add:

```rust
pub subscription: Option<DesktopSubscriptionSummary>
```

Initialize it to `None` in `DesktopShellState::new`.

- [ ] **Step 2: Add shell refresh helper**

Add:

```rust
pub fn refresh_subscription(&mut self, subscription: Option<DesktopSubscriptionSummary>)
```

- [ ] **Step 3: Extend command host trait**

Add:

- `import_subscription_config`
- `select_node`
- `set_traffic_mode`

Implement them for `DesktopNativeCommandService`.

- [ ] **Step 4: Add controller methods**

Add:

- `import_subscription_config`
- `select_node`
- `set_traffic_mode`

Each method should refresh the shell status after host mutation.

- [ ] **Step 5: Run target tests**

Run: `cargo test -p keli-desktop shell_subscription -- --test-threads=1`

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `crates/keli-desktop/src/shell.rs`
- `crates/keli-desktop/src/app.rs`
- `docs/superpowers/plans/2026-06-12-desktop-shell-subscription-state.md`

- [ ] **Step 1: Format check**

Run: `cargo fmt --check`

Expected: PASS.

- [ ] **Step 2: Diff whitespace check**

Run: `git diff --check`

Expected: PASS.

- [ ] **Step 3: Desktop backend tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 4: Shell crate tests and check**

Run:

- `cargo test -p keli-desktop-shell`
- `cargo check -p keli-desktop-shell`

Expected: PASS.

- [ ] **Step 5: Commit and push**

Commit the plan first, then commit the implementation after verification. Push each commit to `origin/main`.

## Self-Review Checklist

- Spec coverage: advances import subscription and node selection into the unified desktop state boundary.
- Scope: no persistence or subscription URL fetching in this slice.
- Runtime ownership: controller delegates parsing and selection to the existing command host.
- UI readiness: the WebView can consume subscription summary from the same serialized shell snapshot.
