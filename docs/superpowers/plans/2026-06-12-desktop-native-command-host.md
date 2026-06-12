# Desktop Native Command Host Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide a long-lived native desktop command host that owns the real Windows platform controllers and exposes the existing command facade to a future desktop shell.

**Architecture:** Keep `DesktopCommandService` as the testable facade over `DesktopRuntimeService`. Add `DesktopNativeCommandService` that initializes process-lifetime native system proxy and TUN controllers through static singletons, then builds a command service using those references.

**Tech Stack:** Rust 2021, `OnceLock`, `keli-platform::NativeSystemProxyController`, `keli-platform::NativeTunDeviceController`, existing desktop command facade.

---

## Scope Check

This plan covers:

- A native desktop command host suitable for a tray/window shell state container.
- Process-lifetime native system proxy and TUN controller references.
- UI-style methods forwarded to `DesktopCommandService`.
- Tests that prove the native host can be created, import a subscription, start mixed-only mode, report status, and stop.

This plan does not cover:

- Visible UI windows.
- Tray icon integration.
- Persisted user settings.
- TUN start smoke with real Wintun.

## File Structure

- Modify: `crates/keli-desktop/src/commands.rs`
  - Add `DesktopNativeCommandService`.
  - Add tests for the native command host.
- Modify: `crates/keli-desktop/src/lib.rs`
  - Export `DesktopNativeCommandService`.

## Task 1: Native Command Host Tests

**Files:**
- Modify: `crates/keli-desktop/src/commands.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Write failing tests**

Add tests that expect:

- `DesktopNativeCommandService::new()` starts in stopped state.
- A native host can import a Shadowsocks subscription config, bind mixed-only mode on `127.0.0.1:0`, start, report running status, stop, and report stopped status.

- [ ] **Step 2: Run tests to verify RED**

Run: `cargo test -p keli-desktop native_command -- --test-threads=1`

Expected: FAIL because `DesktopNativeCommandService` does not exist.

## Task 2: Implement Native Command Host

**Files:**
- Modify: `crates/keli-desktop/src/commands.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Add static native controllers**

Use:

```rust
static NATIVE_SYSTEM_PROXY_CONTROLLER: OnceLock<NativeSystemProxyController> = OnceLock::new();
static NATIVE_TUN_CONTROLLER: OnceLock<NativeTunDeviceController> = OnceLock::new();
```

- [ ] **Step 2: Add `DesktopNativeCommandService`**

Create a struct that owns:

```rust
commands: DesktopCommandService<'static, NativeSystemProxyController, NativeTunDeviceController>
```

Its `new()` method should create a `DesktopRuntimeService::new_with_tun_controller` from the static controllers.

- [ ] **Step 3: Forward command methods**

Forward:

- `import_subscription_config`
- `import_subscription_url`
- `select_node`
- `update_subscription_url`
- `set_traffic_mode`
- `set_listen`
- `start`
- `stop`
- `status`
- `export_support_bundle`
- `dependency_report`

- [ ] **Step 4: Export native host**

Update `crates/keli-desktop/src/lib.rs`:

```rust
pub use commands::{DesktopCommandError, DesktopCommandService, DesktopNativeCommandService};
```

- [ ] **Step 5: Run native command tests to verify GREEN**

Run: `cargo test -p keli-desktop native_command -- --test-threads=1`

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `crates/keli-desktop/src/commands.rs`
- `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Format check**

Run: `cargo fmt --check`

Expected: PASS.

- [ ] **Step 2: Diff whitespace check**

Run: `git diff --check`

Expected: PASS.

- [ ] **Step 3: Desktop crate tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 4: Push commits**

Run: `git push`

Expected: current branch pushes to `origin/main`.

## Self-Review Checklist

- Spec coverage: this plan advances the MVP by giving the desktop shell one native command object that can drive import, status, start/stop, dependency readiness, and diagnostics.
- Scope: it does not implement the visible window/tray yet.
- No placeholder steps remain.
- Type consistency: `DesktopNativeCommandService`, `DesktopCommandService`, and `DesktopRuntimeService` use the existing controller types consistently.
