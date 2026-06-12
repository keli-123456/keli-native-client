# Desktop Dependency Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose desktop-facing system proxy and Wintun dependency status so the Windows UI can show whether proxy/TUN mode is ready, blocked, or installable without shelling out to CLI commands.

**Architecture:** Add a small `keli-desktop` dependency boundary that wraps existing `keli-platform` status and Wintun install reports into serializable DTOs. Keep lifecycle and device logic in `keli-platform`; the desktop crate only maps native evidence into UI-safe fields and actions.

**Tech Stack:** Rust 2021, `keli-platform::{PlatformCapabilities, SystemProxyStatus, TunBackendStatus, WintunInstallReport}`, existing `DesktopFirstRunReport`, serde DTOs.

---

## Scope Check

This plan covers:

- A desktop dependency report that embeds first-run readiness, system proxy status, TUN backend status, and Wintun install guidance.
- A Wintun install result DTO that can be returned to UI code after installing a DLL from a file or unpacked Wintun directory.
- Native collection methods that call existing platform detection APIs.
- Tests for missing Wintun, ready Wintun, and install-result mapping.

This plan does not cover:

- Running an installer UI.
- Downloading Wintun from the internet.
- Starting TUN mode; that was wired in the previous managed TUN runtime slice.
- Packaging the final desktop app.

## File Structure

- Create: `crates/keli-desktop/src/dependencies.rs`
  - Defines dependency and Wintun install DTOs.
  - Provides native detection and install wrappers.
- Modify: `crates/keli-desktop/src/lib.rs`
  - Exports the new dependency module and DTOs.

## Task 1: Dependency DTO Tests

**Files:**
- Create: `crates/keli-desktop/src/dependencies.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Write failing tests**

Add tests that expect:

- `DesktopDependencyReport::from_platform` marks `tun_backend_state` as `"install-required"` when `TunBackendStatus.install_required == true`.
- `DesktopDependencyReport::from_platform` marks `tun_backend_state` as `"ready"` when `TunBackendStatus::is_ready()` is true.
- `DesktopWintunInstallSummary::from_platform_report` exposes `source_kind`, `target_path`, `copied_bytes`, `driver_api_available`, and `ready_after_install`.

- [ ] **Step 2: Run tests to verify RED**

Run: `cargo test -p keli-desktop dependencies -- --test-threads=1`

Expected: FAIL because `dependencies.rs` and its exported DTOs do not exist.

## Task 2: Implement Dependency DTOs

**Files:**
- Create: `crates/keli-desktop/src/dependencies.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Implement dependency report mapping**

Create:

```rust
pub struct DesktopDependencyReport {
    pub first_run: DesktopFirstRunReport,
    pub system_proxy: DesktopSystemProxyDependency,
    pub tun_backend: DesktopTunBackendDependency,
}
```

Use `DesktopFirstRunReport::from_platform` for first-run readiness and map TUN backend state to exactly one of:

- `"ready"`
- `"install-required"`
- `"unavailable"`

- [ ] **Step 2: Implement native collection**

Add `DesktopDependencyReport::detect_native()` using:

```rust
PlatformCapabilities::detect()
SystemProxyStatus::detect()
TunBackendStatus::detect()
```

- [ ] **Step 3: Implement Wintun install summary**

Create `DesktopWintunInstallSummary::from_platform_report(&WintunInstallReport)` and native wrappers:

```rust
pub fn install_wintun_from_file(source: impl AsRef<Path>, target_dir: Option<impl AsRef<Path>>) -> Result<DesktopWintunInstallSummary, DesktopDependencyError>
pub fn install_wintun_from_directory(source_dir: impl AsRef<Path>, target_dir: Option<impl AsRef<Path>>) -> Result<DesktopWintunInstallSummary, DesktopDependencyError>
```

The wrappers call `keli_platform::install_wintun_library` and `keli_platform::install_wintun_library_from_source_dir`.

- [ ] **Step 4: Export the module**

Update `crates/keli-desktop/src/lib.rs` with:

```rust
pub mod dependencies;
pub use dependencies::{
    DesktopDependencyError, DesktopDependencyReport, DesktopSystemProxyDependency,
    DesktopTunBackendDependency, DesktopWintunInstallSummary,
};
```

- [ ] **Step 5: Run dependency tests to verify GREEN**

Run: `cargo test -p keli-desktop dependencies -- --test-threads=1`

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `crates/keli-desktop/src/dependencies.rs`
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

- Spec coverage: this plan advances the MVP requirement to handle Wintun and system proxy dependencies from the desktop UI boundary.
- Scope: it does not replace platform detection or TUN lifecycle logic.
- No placeholder steps remain.
- Type consistency: `DesktopDependencyReport`, `DesktopWintunInstallSummary`, and `DesktopFirstRunReport` are used consistently.
