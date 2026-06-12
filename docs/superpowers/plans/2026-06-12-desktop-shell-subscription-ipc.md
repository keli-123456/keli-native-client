# Desktop Shell Subscription IPC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for the implementation tasks and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the first desktop WebView import a subscription config and update the unified shell snapshot without command-line interaction.

**Architecture:** Extend `keli-desktop-shell` IPC parsing from plain action strings to JSON commands. Keep all subscription parsing and node selection in `DesktopShellController`. The HTML adds a compact config editor, mode controls, and a node summary that updates from `DesktopShellState.subscription`.

**Tech Stack:** Rust 2021, `serde`, `serde_json`, `keli-desktop-shell`, `keli-desktop`.

---

## Scope Check

This plan covers:

- JSON IPC for raw subscription config import.
- JSON IPC for selecting a node.
- JSON IPC for setting traffic mode.
- WebView controls for config import, mode selection, and node summary.
- Snapshot-driven rendering of supported/skipped node counts and node tags.

This plan does not cover:

- Subscription URL fetching.
- Persisted config storage.
- Detailed node health or latency.
- User-facing error surface beyond the current snapshot refresh.
- Real system proxy/TUN smoke.

## File Structure

- Modify: `crates/keli-desktop-shell/Cargo.toml`
  - Add `serde`.
- Modify: `crates/keli-desktop-shell/src/actions.rs`
  - Extend `DesktopShellUiEvent`.
  - Parse JSON IPC messages.
- Modify: `crates/keli-desktop-shell/src/html.rs`
  - Add subscription config textarea and import button.
  - Add mode buttons and subscription summary rendering.
- Modify: `crates/keli-desktop-shell/src/main.rs`
  - Dispatch import/select/mode UI events through `DesktopShellController`.

## Task 1: RED Tests

**Files:**
- Modify: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Write failing tests**

Add tests that expect:

- JSON `{ "type": "import-subscription-config", "configText": "..." }` maps to `ImportSubscriptionConfig`.
- JSON `{ "type": "select-node", "outboundTag": "SS-READY" }` maps to `SelectNode`.
- JSON `{ "type": "set-traffic-mode", "trafficMode": "tun" }` maps to `SetTrafficMode(Tun)`.
- HTML includes a subscription config field and import command.
- HTML renders subscription summary when the snapshot has a subscription.

- [ ] **Step 2: Run tests to verify RED**

Run: `cargo test -p keli-desktop-shell subscription_ipc -- --test-threads=1`

Expected: FAIL because the JSON IPC variants and HTML controls do not exist.

## Task 2: Implement Subscription IPC

**Files:**
- Modify: `crates/keli-desktop-shell/Cargo.toml`
- Modify: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add serde dependency**

Use workspace `serde`.

- [ ] **Step 2: Extend UI event enum**

Add:

- `ImportSubscriptionConfig(String)`
- `SelectNode(String)`
- `SetTrafficMode(DesktopTrafficMode)`

- [ ] **Step 3: Parse JSON IPC**

Support camelCase keys used by the WebView:

- `configText`
- `outboundTag`
- `trafficMode`

- [ ] **Step 4: Add HTML controls**

Add:

- `subscription-config` textarea
- import button
- mode buttons for system proxy and TUN
- node list rendered from subscription snapshot

- [ ] **Step 5: Dispatch new UI events**

Call:

- `controller.import_subscription_config`
- `controller.select_node`
- `controller.set_traffic_mode`

Then sync the WebView snapshot.

## Task 3: Verification, Commit, And Push

**Files:**
- `crates/keli-desktop-shell/Cargo.toml`
- `crates/keli-desktop-shell/src/actions.rs`
- `crates/keli-desktop-shell/src/html.rs`
- `crates/keli-desktop-shell/src/main.rs`
- `docs/superpowers/plans/2026-06-12-desktop-shell-subscription-ipc.md`

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

- [ ] **Step 4: Desktop backend tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Commit and push**

Commit the plan first, then commit the implementation after verification. Push each commit to `origin/main`.

## Self-Review Checklist

- Spec coverage: advances subscription setup without requiring the CLI.
- Scope: URL fetching and persistence remain separate.
- Runtime ownership: import/select/mode still go through `DesktopShellController`.
- UI readiness: snapshot JSON now carries enough subscription data for the first visible workflow.
