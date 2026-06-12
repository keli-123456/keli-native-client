# Desktop Node Health Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a desktop user refresh node health from the GUI without using CLI commands.

**Architecture:** Reuse existing managed-core `probe_all_node_health` sweep logic. Add a desktop runtime service method that builds conservative probe options, then expose it through the command host, shell controller, IPC parser, and shell HTML button. Refresh the desktop status and subscription summary from the managed status after the sweep.

**Tech Stack:** Rust workspace crates `keli-desktop`, `keli-desktop-shell`, existing `keli-cli` managed probe types, Serde JSON, cargo tests.

---

### Task 1: Runtime Service Health Refresh

**Files:**
- Modify: `crates/keli-desktop/src/managed.rs`
- Modify: `crates/keli-desktop/src/service.rs`
- Modify: `crates/keli-desktop/src/commands.rs`

- [ ] **Step 1: Write failing tests**

Add tests proving that:
- `DesktopManagedCoreService::refresh_node_health()` errors when the managed core is stopped.
- `DesktopRuntimeService::refresh_node_health()` returns a `DesktopSubscriptionSummary` with checked health when the core is running.

Expected wished-for assertion:

```rust
let summary = service.refresh_node_health().expect("refresh health");
let node = summary.nodes.iter().find(|node| node.tag == "SS-READY").expect("node");
assert!(matches!(node.health_state.as_deref(), Some("healthy") | Some("unhealthy")));
assert!(node.tcp_available.is_some());
```

- [ ] **Step 2: Verify red**

Run: `cargo test -p keli-desktop refresh_node_health -- --test-threads=1`

Expected: FAIL because no desktop refresh method exists.

- [ ] **Step 3: Implement minimal code**

Add `DesktopManagedCoreService::refresh_node_health()` that calls `ManagedMixedController::probe_all_node_health` with:
- `target = "example.com:443"`
- empty payload and expect
- `inbound = SmokeInboundKind::Socks5`
- `first_byte_timeout = Duration::from_millis(750)`
- `udp_available = None`
- `udp_probe = None`

Add `DesktopRuntimeService::refresh_node_health()` that calls the managed service, updates `selected_outbound` from returned status, and returns `DesktopSubscriptionSummary::from_managed`.

Add command-host passthrough methods.

- [ ] **Step 4: Verify green**

Run: `cargo test -p keli-desktop refresh_node_health -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Commit and push**

```bash
git add crates/keli-desktop/src/managed.rs crates/keli-desktop/src/service.rs crates/keli-desktop/src/commands.rs
git commit -m "Add desktop node health refresh command"
git push
```

### Task 2: Shell IPC And UI Button

**Files:**
- Modify: `crates/keli-desktop/src/app.rs`
- Modify: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Write failing tests**

Add tests proving:
- JSON IPC `{"type":"refresh-node-health"}` maps to `DesktopShellUiEvent::RefreshNodeHealth`.
- Shell controller calls host refresh and updates `snapshot.subscription`.
- HTML includes a `refresh-node-health` button and a live status script target.
- Operation success message reports `Node health refreshed`.

- [ ] **Step 2: Verify red**

Run: `cargo test -p keli-desktop-shell refresh_node_health -- --test-threads=1`

Expected: FAIL because IPC/UI paths do not exist.

- [ ] **Step 3: Implement minimal code**

Add `RefreshNodeHealth` event, button next to node controls, shell controller method, main handler branch, operation success message, and refresh subscription/status after success.

- [ ] **Step 4: Verify green**

Run: `cargo test -p keli-desktop-shell refresh_node_health -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Commit and push**

```bash
git add crates/keli-desktop/src/app.rs crates/keli-desktop-shell/src/actions.rs crates/keli-desktop-shell/src/main.rs crates/keli-desktop-shell/src/html.rs
git commit -m "Wire desktop node health refresh UI"
git push
```

### Task 3: Verification And Gates

**Files:**
- Verify only.

- [ ] **Step 1: Format**

Run: `cargo fmt`

Expected: exit 0.

- [ ] **Step 2: Package tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Run: `cargo test -p keli-desktop-shell -- --test-threads=1`

Expected: both PASS.

- [ ] **Step 3: MVP gate**

Run: `powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1`

Expected: exit 0.

- [ ] **Step 4: Public release gate**

Run: `powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1`

Expected: exit 1 only for signing blockers.

- [ ] **Step 5: Readiness JSON**

Run: `powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json`

Expected: `machine_takeover_status = "ready"`, `signing.can_sign = false`, and only signing blockers.
