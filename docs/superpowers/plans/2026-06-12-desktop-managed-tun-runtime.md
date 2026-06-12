# Desktop Managed TUN Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the desktop runtime start TUN mode through the same managed native core lifecycle used by mixed and system proxy modes.

**Architecture:** Add an optional TUN background runtime handle to `keli-cli` managed mixed sessions, then expose it through `DesktopManagedCoreService` and `DesktopRuntimeService`. TUN packet I/O remains owned by the existing platform controller and packet loop; desktop code only selects the mode and default TUN config.

**Tech Stack:** Rust 2021, `keli-cli::ManagedMixedController`, `keli-platform::TunPacketIoController`, `keli-platform::TunDeviceConfig`, `keli-desktop` runtime facade tests.

---

## Scope Check

This plan covers:

- Starting managed mixed core with an optional TUN device in background mode.
- Stopping the listener, packet loop, TUN device, and system proxy state through one managed `stop`.
- Recording the existing TUN packet loop diagnostic when managed TUN mode stops.
- Allowing desktop `DesktopTrafficMode::Tun` to call the managed core instead of returning a hardcoded not-wired error.
- Preserving the existing mixed-only and system-proxy paths.

This plan does not cover:

- A visual desktop UI.
- Wintun install UI.
- Full release packaging.
- New routing logic inside the desktop crate.

## File Structure

- Modify: `crates/keli-cli/src/lib.rs`
  - Add managed TUN background runtime storage and start/stop helpers.
  - Add `tun_device` to `ManagedMixedOptions`.
  - Add a controller start path that accepts a TUN packet I/O controller.
- Modify: `crates/keli-cli/tests/managed_mixed.rs`
  - Add fake TUN controller tests for managed background lifecycle.
- Modify: `crates/keli-desktop/src/managed.rs`
  - Add TUN start options and route them to managed core.
- Modify: `crates/keli-desktop/src/service.rs`
  - Remove the hardcoded TUN block and use default Windows MVP TUN config.
- Modify: `crates/keli-desktop/src/lib.rs`
  - Export any new desktop TUN DTO only if needed.

## Task 1: CLI Managed TUN Background Tests

**Files:**
- Modify: `crates/keli-cli/tests/managed_mixed.rs`

- [ ] **Step 1: Write the failing lifecycle test**

Add fake TUN controller and packet I/O helpers in `managed_mixed.rs`, then add a test named `managed_mixed_controller_start_with_tun_stops_packet_loop_and_device`.

The test should:

- Start `ManagedMixedController` with `ManagedMixedOptions { tun_device: Some(config), listen: "127.0.0.1:0", ..Default::default() }`.
- Assert fake controller observed one `start` and one `open_packet_io`.
- Stop the controller.
- Assert fake controller observed one `stop`.
- Assert stopped status recent events include `RuntimeDiagnostic::TunPacketLoop`.

- [ ] **Step 2: Run the test to verify RED**

Run: `cargo test -p keli-cli --test managed_mixed managed_mixed_controller_start_with_tun_stops_packet_loop_and_device -- --exact --test-threads=1`

Expected: FAIL because `ManagedMixedOptions` has no `tun_device` field and the managed controller has no TUN-aware start path.

## Task 2: CLI Managed TUN Background Implementation

**Files:**
- Modify: `crates/keli-cli/src/lib.rs`

- [ ] **Step 1: Add TUN option and background handle**

Add `pub tun_device: Option<TunDeviceConfig>` to `ManagedMixedOptions` and default it to `None`.

Add a private `ManagedTunBackgroundRuntime<'a>` that stores:

- TUN config.
- Start snapshot.
- `owns_device`.
- Stop flag.
- TUN packet loop thread.
- Stop-device closure.

- [ ] **Step 2: Spawn and stop managed TUN background**

Add a helper that:

- Runs `apply_tun_device_for_config`.
- Opens packet I/O.
- Spawns the existing managed TUN packet loop on a background thread.
- On stop, signals the packet loop, joins the thread, stops the device when owned, and returns `ManagedTunPacketLoopReport`.

- [ ] **Step 3: Route controller start through optional TUN**

Add `ManagedMixedController::start_from_subscription_config_text_with_tun_controller`.

Keep `start_from_subscription_config_text` as the mixed/system-proxy-only convenience path. It should continue to work for existing callers and reject `tun_device` only if a caller uses the convenience path with `Some`.

- [ ] **Step 4: Record diagnostics on stop**

Update `ManagedMixedHandle::stop` so a successful TUN report records:

```rust
self.state.record_status_diagnostic(
    managed_tun_runtime_report_note(&report),
    managed_tun_runtime_report_diagnostic(&report),
);
```

- [ ] **Step 5: Run CLI test to verify GREEN**

Run: `cargo test -p keli-cli --test managed_mixed managed_mixed_controller_start_with_tun_stops_packet_loop_and_device -- --exact --test-threads=1`

Expected: PASS.

## Task 3: Desktop TUN Facade Tests

**Files:**
- Modify: `crates/keli-desktop/src/managed.rs`
- Modify: `crates/keli-desktop/src/service.rs`

- [ ] **Step 1: Write failing desktop tests**

Add tests that prove:

- `DesktopManagedCoreService` can start TUN mode through an injected fake TUN controller.
- `DesktopRuntimeService` no longer returns `"TUN traffic mode is not wired into desktop runtime service"` when a TUN-capable controller is supplied.
- `status().traffic_mode` is `DesktopTrafficMode::Tun` while running and after stop.

- [ ] **Step 2: Run desktop tests to verify RED**

Run: `cargo test -p keli-desktop tun -- --test-threads=1`

Expected: FAIL because desktop services only accept a system proxy controller and still block TUN mode.

## Task 4: Desktop TUN Facade Implementation

**Files:**
- Modify: `crates/keli-desktop/src/managed.rs`
- Modify: `crates/keli-desktop/src/service.rs`

- [ ] **Step 1: Add TUN-aware constructors**

Keep the current `new(&system_proxy_controller)` constructor for ordinary callers. Add a TUN-aware constructor for tests and future UI wiring that accepts `&T` where `T: TunPacketIoController`.

- [ ] **Step 2: Add TUN start options**

Extend `DesktopManagedStartOptions` with `tun_device: Option<TunDeviceConfig>` and a `tun_mode` constructor.

- [ ] **Step 3: Remove hardcoded TUN block**

When `DesktopRuntimeService` uses `DesktopTrafficMode::Tun`, build default MVP config:

```rust
TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500)
```

Then pass it through `DesktopManagedCoreService`.

- [ ] **Step 4: Run desktop tests to verify GREEN**

Run: `cargo test -p keli-desktop tun -- --test-threads=1`

Expected: PASS.

## Task 5: Verification, Commit, And Push

**Files:**
- All modified files above.

- [ ] **Step 1: Format check**

Run: `cargo fmt --check`

Expected: PASS.

- [ ] **Step 2: Diff whitespace check**

Run: `git diff --check`

Expected: PASS.

- [ ] **Step 3: Desktop crate tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 4: Targeted CLI regression**

Run: `cargo test -p keli-cli --test managed_mixed managed_mixed_controller_start_with_tun_stops_packet_loop_and_device -- --exact --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Push commits**

Run: `git push`

Expected: the current branch pushes successfully to `origin/main`.

## Self-Review Checklist

- Spec coverage: this plan advances the desktop MVP TUN mode requirement by wiring it into managed lifecycle instead of leaving a desktop-only block.
- Scope: this is a backend/runtime slice; UI and packaging remain later slices.
- No placeholder steps remain.
- Type consistency: `ManagedMixedOptions`, `ManagedMixedController`, `DesktopManagedCoreService`, and `DesktopRuntimeService` are the only lifecycle boundaries changed.
