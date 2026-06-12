# Desktop Node List Details Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the desktop subscription node list show enough information for a user to choose safely: node tag, protocol, transport, security, UDP support, selected marker, recommended marker, and skipped-node reasons.

**Architecture:** Reuse existing `DesktopNodeSummary` and `DesktopSubscriptionSummary.skipped` fields. Update only the desktop shell HTML/CSS/JavaScript rendering helpers so initial server-rendered HTML and live `window.keliSetShell` updates produce the same richer node controls.

**Tech Stack:** Rust 2021, existing `keli-desktop-shell` HTML renderer, DOM APIs, existing shell tests.

---

## Scope Check

This slice covers:

- Richer node button content for initial HTML render.
- Richer node button content for live JavaScript snapshot updates.
- Selected and recommended badges.
- UDP supported/disabled text.
- Skipped node reason rendering from existing redacted summaries.
- Focused shell tests and desktop MVP/public release gate verification.

This slice does not cover:

- Real latency probes.
- Health check scheduling.
- Changing subscription parsing or backend DTOs.
- New visual design system.

## File Structure

- Modify: `crates/keli-desktop-shell/src/html.rs`
  - Add compact CSS for node detail buttons and skipped entries.
  - Update Rust `node_buttons`.
  - Update JavaScript `renderNodeList`.
  - Add focused tests.

## Task 1: RED Node Detail Tests

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add initial render tests**

Add tests:

```rust
#[test]
fn subscription_node_list_renders_protocol_transport_security_and_badges() {
    let mut snapshot = snapshot();
    snapshot.refresh_subscription(Some(subscription("SS-READY")));

    let html = render_shell_html(&snapshot);

    assert!(html.contains("SS-READY"));
    assert!(html.contains("ss / tcp / none"));
    assert!(html.contains("UDP ready"));
    assert!(html.contains("Selected"));
    assert!(html.contains("Recommended"));
}

#[test]
fn subscription_node_list_renders_skipped_reasons() {
    let mut snapshot = snapshot();
    let mut summary = subscription("SS-READY");
    summary.skipped_count = 1;
    summary.skipped = vec!["BROKEN: unsupported protocol".to_string()];
    snapshot.refresh_subscription(Some(summary));

    let html = render_shell_html(&snapshot);

    assert!(html.contains("Skipped"));
    assert!(html.contains("BROKEN: unsupported protocol"));
}
```

- [ ] **Step 2: Add live-render test**

Assert the HTML JavaScript contains the DOM classes/text hooks needed for live rendering:

```rust
#[test]
fn subscription_node_list_live_renderer_includes_detail_fields() {
    let html = render_shell_html(&snapshot());

    assert!(html.contains("node-meta"));
    assert!(html.contains("node-badge"));
    assert!(html.contains("node.skipped"));
}
```

- [ ] **Step 3: Run RED tests**

Run:

```powershell
cargo test -p keli-desktop-shell subscription_node_list -- --nocapture
```

Expected: FAIL because node details and skipped rendering are not present.

## Task 2: Implement Rich Node Rendering

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add CSS**

Add `.node-list button`, `.node-tag`, `.node-meta`, `.node-badges`, `.node-badge`, and `.node-skipped` styles. Keep the existing restrained UI palette.

- [ ] **Step 2: Add Rust helper rendering**

Change `node_buttons` to render:

- escaped node tag
- `{protocol} / {transport} / {security}`
- `UDP ready` or `UDP unavailable`
- `Selected` badge when selected
- `Recommended` badge when recommended
- skipped entries below supported nodes

- [ ] **Step 3: Add JavaScript helper rendering**

Change `renderNodeList(subscription)` to create the same structure with `textContent`, including skipped entries from `subscription.skipped || []`.

- [ ] **Step 4: Run focused tests**

Run:

```powershell
cargo test -p keli-desktop-shell subscription_node_list -- --nocapture
```

Expected: PASS.

## Task 3: Verify, Commit, Push

**Files:**
- `crates/keli-desktop-shell/src/html.rs`
- `docs/superpowers/plans/2026-06-12-desktop-node-list-details.md`

- [ ] **Step 1: Shell tests**

Run:

```powershell
cargo fmt
cargo test -p keli-desktop-shell
```

Expected: PASS.

- [ ] **Step 2: Gates**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
```

Expected: MVP gate PASS. Public release gate remains blocked only by `artifact-signature-missing` and `signing-certificate-missing`; readiness reports `machine_takeover_status` as `ready`.

- [ ] **Step 3: Commit and push**

Run:

```powershell
git add crates\keli-desktop-shell\src\html.rs docs\superpowers\plans\2026-06-12-desktop-node-list-details.md
git commit -m "Show desktop node details"
git push origin main
```

## Self-Review

- Spec coverage: advances the MVP node-selection requirement for name, protocol/transport summary, UDP signal, and recommended marker.
- Placeholder scan: no TBD/TODO/fill-in items.
- Type consistency: uses existing `DesktopNodeSummary` and `DesktopSubscriptionSummary.skipped` fields.
