# Desktop Node Health List Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show per-node health evidence in the desktop node list using existing managed-core node health data.

**Architecture:** Keep health probing owned by the existing managed core. Extend `DesktopNodeSummary` with UI-safe health fields, add a `DesktopSubscriptionSummary::from_managed` projection for `ManagedSubscriptionStatus`, and render those fields in the desktop shell node list for both initial HTML and live updates.

**Tech Stack:** Rust workspace crates `keli-desktop`, `keli-desktop-shell`, existing `keli-cli` managed subscription health structures, Serde JSON, cargo tests.

---

### Task 1: Subscription Summary Health Fields

**Files:**
- Modify: `crates/keli-desktop/src/subscription.rs`

- [ ] **Step 1: Write the failing tests**

Add tests that describe the wished-for DTO:

```rust
#[test]
fn subscription_summary_from_preflight_marks_node_health_unknown() {
    let config = r#"
proxies:
  - name: SS-A
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#;
    let report = preflight_subscription_config(config).expect("preflight");

    let summary = DesktopSubscriptionSummary::from_preflight(&report, Some("SS-A"), Some("SS-A"));
    let node = summary.nodes.iter().find(|node| node.tag == "SS-A").expect("SS-A");

    assert_eq!(node.health_state.as_deref(), Some("unknown"));
    assert_eq!(node.tcp_available, None);
    assert_eq!(node.udp_available, None);
    assert_eq!(node.latency_ms, None);
    assert_eq!(node.health_error, None);
}
```

Add a second test using a running managed core:

```rust
#[test]
fn subscription_summary_from_managed_maps_node_health() {
    let platform_controller = FakeSystemProxyController::new();
    let mut core = ManagedMixedController::new(&platform_controller);
    core.start_from_subscription_config_text(&ss_config("SS-A"), managed_options())
        .expect("start core");
    let status = core
        .record_node_health(keli_cli::ManagedNodeHealthStatus::healthy(
            "SS-A",
            Some(42),
            true,
            true,
        ))
        .expect("record health");
    let managed = status.subscription.as_ref().expect("managed subscription");

    let summary = DesktopSubscriptionSummary::from_managed(managed);
    let node = summary.nodes.iter().find(|node| node.tag == "SS-A").expect("SS-A");

    assert_eq!(node.health_state.as_deref(), Some("healthy"));
    assert_eq!(node.tcp_available, Some(true));
    assert_eq!(node.udp_available, Some(true));
    assert_eq!(node.latency_ms, Some(42));
    assert_eq!(node.health_error, None);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p keli-desktop subscription_summary_from_ -- --test-threads=1`

Expected: FAIL because `DesktopNodeSummary` does not have health fields and `DesktopSubscriptionSummary::from_managed` does not exist.

- [ ] **Step 3: Write minimal implementation**

Add these fields to `DesktopNodeSummary`:

```rust
pub health_state: Option<String>,
pub tcp_available: Option<bool>,
pub udp_available: Option<bool>,
pub latency_ms: Option<u64>,
pub health_error: Option<String>,
```

Add `DesktopSubscriptionSummary::from_managed(status: &keli_cli::ManagedSubscriptionStatus) -> Self` that copies capability data and maps each node's `ManagedNodeHealthStatus`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p keli-desktop subscription_summary_from_ -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/keli-desktop/src/subscription.rs
git commit -m "Expose desktop node health summary"
git push
```

### Task 2: Node List Health Rendering

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Modify test fixtures in `crates/keli-desktop/src/app.rs`, `crates/keli-desktop/src/shell.rs`, and shell tests if needed.

- [ ] **Step 1: Write the failing tests**

Extend node-list tests so a node with health fields renders:

```rust
summary.nodes[0].health_state = Some("healthy".to_string());
summary.nodes[0].tcp_available = Some(true);
summary.nodes[0].udp_available = Some(true);
summary.nodes[0].latency_ms = Some(42);
assert!(html.contains("Health healthy"));
assert!(html.contains("TCP ready"));
assert!(html.contains("UDP live"));
assert!(html.contains("42 ms"));
```

Also extend live-renderer tests to look for `node.health_state`, `node.tcp_available`, `node.udp_available`, and `node.latency_ms`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p keli-desktop-shell subscription_node_list_ -- --test-threads=1`

Expected: FAIL because node list rendering ignores health fields.

- [ ] **Step 3: Write minimal implementation**

Update Rust `node_buttons` and JavaScript `renderNodeList` to render:
- `Health <state>` when `health_state` exists
- `TCP ready` / `TCP failed` when `tcp_available` is known
- `UDP live` / `UDP failed` when `udp_available` is known
- `<latency_ms> ms` when latency exists
- `Last failure <health_error>` when health error exists

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p keli-desktop-shell subscription_node_list_ -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/keli-desktop-shell/src/html.rs crates/keli-desktop/src/app.rs crates/keli-desktop/src/shell.rs
git commit -m "Show desktop node health details"
git push
```

### Task 3: Verification And Gates

**Files:**
- Verify only.

- [ ] **Step 1: Format**

Run: `cargo fmt`

Expected: exit 0.

- [ ] **Step 2: Desktop crate tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 3: Desktop shell tests**

Run: `cargo test -p keli-desktop-shell -- --test-threads=1`

Expected: PASS.

- [ ] **Step 4: MVP gate**

Run: `powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1`

Expected: exit 0.

- [ ] **Step 5: Public release gate**

Run: `powershell -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1`

Expected: exit 1 only for signing blockers (`artifact-signature-missing`, `signing-certificate-missing`).

- [ ] **Step 6: Release readiness JSON**

Run: `powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json`

Expected: JSON reports `machine_takeover_status = "ready"`, `signing.can_sign = false`, and no blockers other than signing.
