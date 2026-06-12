# Desktop Runtime Evidence Summary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface existing managed-core runtime evidence in the desktop status model, diagnostics panel, and support bundle without inventing health or latency values.

**Architecture:** Keep the desktop layer as a thin projection over `ManagedMixedStatusSnapshot`. Add serializable summary DTOs to `crates/keli-desktop/src/status.rs`, populate them from `connection_metrics`, `recent_events`, and `subscription.health_summary`, then render those fields in `crates/keli-desktop-shell/src/html.rs`. The raw managed status remains the source of truth for deeper support analysis.

**Tech Stack:** Rust workspace crates `keli-desktop`, `keli-desktop-shell`, existing `keli-cli` managed mixed core types, Serde JSON, cargo tests.

---

### Task 1: Desktop Status Evidence DTOs

**Files:**
- Modify: `crates/keli-desktop/src/status.rs`

- [ ] **Step 1: Write the failing tests**

Add tests in the existing `#[cfg(test)]` module:

```rust
#[test]
fn managed_mixed_status_exposes_runtime_evidence_summary() {
    let platform_controller = FakeSystemProxyController::new();
    let mut core = ManagedMixedController::new(&platform_controller);
    let status = core
        .start_from_subscription_config_text(
            &ss_config("SS-READY"),
            keli_cli::ManagedMixedOptions::default(),
        )
        .expect("start managed core");

    let status = DesktopStatusSnapshot::from_managed_mixed_status(
        &status,
        DesktopTrafficMode::MixedInboundOnly,
    );

    assert_eq!(status.connection_metrics.total, 0);
    assert_eq!(status.connection_metrics.success, 0);
    assert_eq!(status.connection_metrics.failure, 0);
    assert_eq!(status.connection_metrics.average_connect_ms, None);
    assert_eq!(status.node_health.node_count, 1);
    assert_eq!(status.node_health.unknown_count, 1);
    assert_eq!(status.node_health.checked_count, 0);
    assert_eq!(status.node_health.selected_state.as_deref(), Some("unknown"));
    assert_eq!(status.node_health.recommended_state.as_deref(), Some("unknown"));
    assert!(!status.node_health.recommended_switch_ready);
    assert!(!status.recent_events.is_empty());
    assert!(status
        .recent_events
        .iter()
        .any(|event| event.status == DesktopRunState::Running));
    assert!(status
        .recent_events
        .iter()
        .any(|event| event.note.as_deref() == Some("runtime running")));
}

#[test]
fn managed_mixed_status_exposes_recorded_node_health_summary() {
    let platform_controller = FakeSystemProxyController::new();
    let mut core = ManagedMixedController::new(&platform_controller);
    core.start_from_subscription_config_text(
        &ss_config("SS-READY"),
        keli_cli::ManagedMixedOptions::default(),
    )
    .expect("start managed core");

    let status = core
        .record_node_health(keli_cli::ManagedNodeHealthStatus::healthy(
            "SS-READY",
            Some(42),
            true,
            true,
        ))
        .expect("record node health");

    let status = DesktopStatusSnapshot::from_managed_mixed_status(
        &status,
        DesktopTrafficMode::MixedInboundOnly,
    );

    assert_eq!(status.node_health.node_count, 1);
    assert_eq!(status.node_health.healthy_count, 1);
    assert_eq!(status.node_health.checked_count, 1);
    assert_eq!(status.node_health.udp_available_count, 1);
    assert_eq!(status.node_health.selected_state.as_deref(), Some("healthy"));
    assert_eq!(status.node_health.recommended_state.as_deref(), Some("healthy"));
    assert!(status.node_health.selected_outbound_healthy);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p keli-desktop managed_mixed_status_exposes -- --test-threads=1`

Expected: FAIL because `DesktopStatusSnapshot` has no `connection_metrics`, `node_health`, or `recent_events` fields.

- [ ] **Step 3: Write minimal implementation**

Add serializable DTOs and mapping helpers:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopConnectionMetricsSummary {
    pub total: u64,
    pub success: u64,
    pub failure: u64,
    pub average_connect_ms: Option<u64>,
    pub average_first_byte_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopNodeHealthSummary {
    pub node_count: usize,
    pub healthy_count: usize,
    pub unhealthy_count: usize,
    pub unknown_count: usize,
    pub checked_count: usize,
    pub unchecked_count: usize,
    pub udp_available_count: usize,
    pub selected_state: Option<String>,
    pub recommended_state: Option<String>,
    pub selected_outbound_healthy: bool,
    pub recommended_switch_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopRecentRuntimeEvent {
    pub status: DesktopRunState,
    pub note: Option<String>,
}
```

Add the fields to `DesktopStatusSnapshot` and populate them from `ManagedMixedStatusSnapshot`; use zero/empty defaults for `from_client_runtime`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p keli-desktop managed_mixed_status_exposes -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/keli-desktop/src/status.rs
git commit -m "Expose desktop runtime evidence summary"
```

### Task 2: Diagnostics Panel Rendering

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Write the failing tests**

Add expectations to the existing diagnostics tests:

```rust
snapshot.status.connection_metrics.total = 3;
snapshot.status.connection_metrics.success = 2;
snapshot.status.connection_metrics.failure = 1;
snapshot.status.connection_metrics.average_connect_ms = Some(25);
snapshot.status.node_health.node_count = 2;
snapshot.status.node_health.healthy_count = 1;
snapshot.status.node_health.unhealthy_count = 1;
snapshot.status.node_health.checked_count = 2;
snapshot.status.node_health.selected_state = Some("healthy".to_string());
snapshot.status.recent_events = vec![keli_desktop::DesktopRecentRuntimeEvent {
    status: DesktopRunState::Running,
    note: Some("runtime running".to_string()),
}];
assert!(html.contains("Connections 3 total, 2 ok, 1 failed, avg connect 25 ms"));
assert!(html.contains("Node health 1 healthy, 1 unhealthy, 0 unknown, checked 2/2, selected healthy"));
assert!(html.contains("Recent event: Running - runtime running"));
```

Also extend `diagnostics_live_renderer_updates_health_summary` to expect the new JavaScript renderers and DOM ids.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p keli-desktop-shell diagnostics_ -- --test-threads=1`

Expected: FAIL because the diagnostics panel does not yet render the new summaries.

- [ ] **Step 3: Write minimal implementation**

Add three diagnostics rows:

```html
<div class="muted" id="diagnostics-connection-metrics">{diagnostics_connection_metrics}</div>
<div class="muted" id="diagnostics-node-health">{diagnostics_node_health}</div>
<div class="muted" id="diagnostics-recent-event">{diagnostics_recent_event}</div>
```

Implement matching Rust helper functions and JavaScript `diagnosticsConnectionMetrics`, `diagnosticsNodeHealth`, and `diagnosticsRecentEvent`. Use `No runtime health evidence yet` when no nodes or events have evidence.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p keli-desktop-shell diagnostics_ -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/keli-desktop-shell/src/html.rs
git commit -m "Show desktop runtime evidence diagnostics"
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

Expected: JSON still reports machine takeover ready and signing unavailable until a certificate exists.

- [ ] **Step 7: Push**

```bash
git status --short --branch
git push
```

Expected: branch pushed to `origin/main`; worktree clean except ignored build artifacts.
