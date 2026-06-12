# Desktop Managed Core Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect the desktop backend crate to the existing real managed mixed core so the future Windows UI can start, reload, stop, and read status from the native core instead of the temporary `ClientRuntime` wrapper.

**Architecture:** Keep `keli-desktop` as the UI boundary and add a narrow managed-core adapter around `keli_cli::ManagedMixedController`. Reuse the managed mixed controller for lifecycle and system proxy ownership, then map its status snapshot into the existing `DesktopStatusSnapshot` DTO. This plan does not extract the managed controller into a new runtime crate; that can happen after the desktop bridge is proven.

**Tech Stack:** Rust 2021, Cargo workspace, `keli-cli` library API, `keli-platform::SystemProxyController`, existing `serde` DTOs.

---

## Scope Check

The Windows desktop MVP spec requires a tray/window app, subscription import, node selection, start/stop controls, TUN readiness, diagnostics, support bundles, packaging, and manual Windows smoke tests. This plan implements one self-contained backend slice:

- Add a direct Rust dependency from `keli-desktop` to the existing `keli-cli` library API.
- Map `ManagedMixedStatusSnapshot` into desktop-safe status DTOs.
- Add a desktop managed-core service that starts, reloads, reports status, and stops the real managed mixed controller.
- Verify the bridge with real managed core lifecycle tests and existing desktop tests.

The following work is not covered in this plan:

- Visible tray/window shell.
- Subscription URL fetch UI.
- TUN lifecycle controls.
- Support bundle export.
- Installer and packaging.

## File Structure

- Modify: `Cargo.toml`
  - Add `keli-cli` to workspace dependencies so `keli-desktop` can use the managed mixed library API.
- Modify: `crates/keli-desktop/Cargo.toml`
  - Add `keli-cli.workspace = true`.
- Modify: `crates/keli-desktop/src/lib.rs`
  - Export the managed bridge module and public service types.
- Modify: `crates/keli-desktop/src/status.rs`
  - Add `DesktopStatusSnapshot::from_managed_mixed_status`.
- Create: `crates/keli-desktop/src/managed.rs`
  - Own the desktop-facing wrapper around `ManagedMixedController`.

## Task 1: Workspace Dependency And Managed Status Mapping

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/keli-desktop/Cargo.toml`
- Modify: `crates/keli-desktop/src/status.rs`

- [ ] **Step 1: Add the dependency wiring needed for the test**

Add `keli-cli` to root `Cargo.toml` workspace dependencies:

```toml
[workspace.dependencies]
keli-client-core = { path = "crates/keli-client-core" }
keli-net-core = { path = "crates/keli-net-core" }
keli-platform = { path = "crates/keli-platform" }
keli-protocol = { path = "crates/keli-protocol" }
keli-cli = { path = "crates/keli-cli" }
```

Add the crate dependency to `crates/keli-desktop/Cargo.toml`:

```toml
[dependencies]
keli-cli.workspace = true
keli-client-core.workspace = true
keli-platform.workspace = true
serde.workspace = true
```

- [ ] **Step 2: Write the failing managed status mapper test**

Append this test support and test case inside `crates/keli-desktop/src/status.rs` under the existing `#[cfg(test)] mod tests` block:

```rust
    use std::cell::RefCell;

    use keli_cli::ManagedMixedController;
    use keli_platform::{
        SystemProxyConfig, SystemProxyController, SystemProxyError, SystemProxySnapshot,
    };

    #[derive(Debug)]
    struct FakeSystemProxyController {
        snapshot: SystemProxySnapshot,
        applied: RefCell<Vec<SystemProxyConfig>>,
        restored: RefCell<Vec<SystemProxySnapshot>>,
    }

    impl FakeSystemProxyController {
        fn new() -> Self {
            Self {
                snapshot: SystemProxySnapshot::default(),
                applied: RefCell::new(Vec::new()),
                restored: RefCell::new(Vec::new()),
            }
        }
    }

    impl SystemProxyController for FakeSystemProxyController {
        fn snapshot(&self) -> Result<SystemProxySnapshot, SystemProxyError> {
            Ok(self.snapshot.clone())
        }

        fn apply(&self, config: &SystemProxyConfig) -> Result<SystemProxySnapshot, SystemProxyError> {
            self.applied.borrow_mut().push(config.clone());
            Ok(self.snapshot.clone())
        }

        fn restore(&self, snapshot: &SystemProxySnapshot) -> Result<(), SystemProxyError> {
            self.restored.borrow_mut().push(snapshot.clone());
            Ok(())
        }
    }

    #[test]
    fn managed_mixed_status_maps_to_stopped_desktop_status() {
        let platform_controller = FakeSystemProxyController::new();
        let core = ManagedMixedController::new(&platform_controller);

        let status = DesktopStatusSnapshot::from_managed_mixed_status(
            &core.status(),
            DesktopTrafficMode::MixedInboundOnly,
        );

        assert_eq!(status.run_state, DesktopRunState::Stopped);
        assert_eq!(status.traffic_mode, DesktopTrafficMode::MixedInboundOnly);
        assert_eq!(status.selected_outbound, None);
        assert_eq!(status.listen, None);
        assert_eq!(status.generation, 0);
        assert_eq!(status.event_count, 0);
        assert_eq!(status.last_error, None);
    }
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p keli-desktop managed_mixed_status_maps_to_stopped_desktop_status -- --exact`

Expected: FAIL because `DesktopStatusSnapshot::from_managed_mixed_status` does not exist.

- [ ] **Step 4: Add the managed status mapper**

Add the import at the top of `crates/keli-desktop/src/status.rs`:

```rust
use keli_cli::ManagedMixedStatusSnapshot;
```

Add this method to `impl DesktopStatusSnapshot`:

```rust
    pub fn from_managed_mixed_status(
        status: &ManagedMixedStatusSnapshot,
        traffic_mode: DesktopTrafficMode,
    ) -> Self {
        Self {
            run_state: run_state(&status.status),
            traffic_mode,
            selected_outbound: status.selected_outbound.clone(),
            listen: status.listen_addr.map(|addr| addr.to_string()),
            generation: status.generation,
            event_count: status.event_count,
            last_error: status.last_error.as_ref().map(error_label),
        }
    }
```

- [ ] **Step 5: Run the mapper test**

Run: `cargo test -p keli-desktop managed_mixed_status_maps_to_stopped_desktop_status -- --exact`

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```powershell
git add Cargo.toml Cargo.lock crates/keli-desktop/Cargo.toml crates/keli-desktop/src/status.rs
git commit -m "Bridge desktop status to managed core"
```

## Task 2: Desktop Managed Core Service

**Files:**
- Modify: `crates/keli-desktop/src/lib.rs`
- Create: `crates/keli-desktop/src/managed.rs`

- [ ] **Step 1: Export the module names needed by the failing test**

Modify `crates/keli-desktop/src/lib.rs`:

```rust
pub mod managed;
pub mod readiness;
pub mod service;
pub mod status;
pub mod subscription;

pub use managed::{DesktopManagedCoreService, DesktopManagedStartOptions};
pub use readiness::{DesktopBlocker, DesktopFirstRunReport};
pub use service::{DesktopRuntimeCommand, DesktopRuntimeService};
pub use status::{DesktopRunState, DesktopStatusSnapshot, DesktopTrafficMode};
pub use subscription::{DesktopNodeSummary, DesktopSubscriptionSummary};
```

- [ ] **Step 2: Write failing lifecycle tests**

Create `crates/keli-desktop/src/managed.rs` with:

```rust
use keli_platform::SystemProxyController;

use crate::status::{DesktopRunState, DesktopStatusSnapshot, DesktopTrafficMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopManagedStartOptions {
    pub config_text: String,
    pub selected_outbound: Option<String>,
    pub listen: String,
    pub system_proxy: bool,
}

impl DesktopManagedStartOptions {
    pub fn mixed_inbound_only(
        config_text: impl Into<String>,
        selected_outbound: Option<String>,
    ) -> Self {
        Self {
            config_text: config_text.into(),
            selected_outbound,
            listen: "127.0.0.1:7890".to_string(),
            system_proxy: false,
        }
    }

    pub fn system_proxy_mode(
        config_text: impl Into<String>,
        selected_outbound: Option<String>,
    ) -> Self {
        Self {
            config_text: config_text.into(),
            selected_outbound,
            listen: "127.0.0.1:7890".to_string(),
            system_proxy: true,
        }
    }

    pub fn with_listen(mut self, listen: impl Into<String>) -> Self {
        self.listen = listen.into();
        self
    }
}

pub struct DesktopManagedCoreService<'a, C: SystemProxyController + ?Sized> {
    controller: &'a C,
}

impl<'a, C: SystemProxyController + ?Sized> DesktopManagedCoreService<'a, C> {
    pub fn new(controller: &'a C) -> Self {
        Self { controller }
    }

    pub fn is_running(&self) -> bool {
        let _ = self.controller;
        false
    }

    pub fn status(&self) -> DesktopStatusSnapshot {
        DesktopStatusSnapshot {
            run_state: DesktopRunState::Stopped,
            traffic_mode: DesktopTrafficMode::MixedInboundOnly,
            selected_outbound: None,
            listen: None,
            generation: 0,
            event_count: 0,
            last_error: None,
        }
    }

    pub fn start(
        &mut self,
        options: DesktopManagedStartOptions,
    ) -> Result<DesktopStatusSnapshot, String> {
        let _ = options;
        Err("managed mixed core bridge is not wired".to_string())
    }

    pub fn reload_from_subscription_config(
        &mut self,
        config_text: &str,
        selected_outbound: Option<String>,
    ) -> Result<DesktopStatusSnapshot, String> {
        let _ = (config_text, selected_outbound);
        Err("managed mixed core bridge is not wired".to_string())
    }

    pub fn stop(&mut self) -> Result<DesktopStatusSnapshot, String> {
        Err("managed mixed core bridge is not wired".to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use keli_platform::{
        SystemProxyConfig, SystemProxyController, SystemProxyError, SystemProxySnapshot,
    };

    fn ss_config(tag: &str) -> String {
        format!(
            r#"
proxies:
  - name: {tag}
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#
        )
    }

    #[derive(Debug)]
    struct FakeSystemProxyController {
        snapshot: SystemProxySnapshot,
        applied: RefCell<Vec<SystemProxyConfig>>,
        restored: RefCell<Vec<SystemProxySnapshot>>,
    }

    impl FakeSystemProxyController {
        fn new() -> Self {
            Self {
                snapshot: SystemProxySnapshot::default(),
                applied: RefCell::new(Vec::new()),
                restored: RefCell::new(Vec::new()),
            }
        }
    }

    impl SystemProxyController for FakeSystemProxyController {
        fn snapshot(&self) -> Result<SystemProxySnapshot, SystemProxyError> {
            Ok(self.snapshot.clone())
        }

        fn apply(&self, config: &SystemProxyConfig) -> Result<SystemProxySnapshot, SystemProxyError> {
            self.applied.borrow_mut().push(config.clone());
            Ok(self.snapshot.clone())
        }

        fn restore(&self, snapshot: &SystemProxySnapshot) -> Result<(), SystemProxyError> {
            self.restored.borrow_mut().push(snapshot.clone());
            Ok(())
        }
    }

    #[test]
    fn service_reports_stopped_status_before_start() {
        let platform_controller = FakeSystemProxyController::new();
        let service = DesktopManagedCoreService::new(&platform_controller);

        let status = service.status();

        assert!(!service.is_running());
        assert_eq!(status.run_state, DesktopRunState::Stopped);
        assert_eq!(status.traffic_mode, DesktopTrafficMode::MixedInboundOnly);
    }

    #[test]
    fn service_starts_and_stops_real_managed_core_without_system_proxy() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopManagedCoreService::new(&platform_controller);

        let running = service
            .start(
                DesktopManagedStartOptions::mixed_inbound_only(
                    ss_config("SS-READY"),
                    Some("SS-READY".to_string()),
                )
                .with_listen("127.0.0.1:0"),
            )
            .expect("start managed core");

        assert!(service.is_running());
        assert_eq!(running.run_state, DesktopRunState::Running);
        assert_eq!(running.traffic_mode, DesktopTrafficMode::MixedInboundOnly);
        assert_eq!(running.selected_outbound.as_deref(), Some("SS-READY"));
        assert!(running.listen.as_deref().unwrap_or("").starts_with("127.0.0.1:"));
        assert_eq!(platform_controller.applied.borrow().len(), 0);

        let stopped = service.stop().expect("stop managed core");

        assert!(!service.is_running());
        assert_eq!(stopped.run_state, DesktopRunState::Stopped);
        assert_eq!(stopped.traffic_mode, DesktopTrafficMode::MixedInboundOnly);
    }

    #[test]
    fn service_reloads_running_core_to_selected_node() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopManagedCoreService::new(&platform_controller);
        service
            .start(
                DesktopManagedStartOptions::mixed_inbound_only(
                    ss_config("SS-READY"),
                    Some("SS-READY".to_string()),
                )
                .with_listen("127.0.0.1:0"),
            )
            .expect("start managed core");

        let reloaded = service
            .reload_from_subscription_config(
                &ss_config("SS-NEXT"),
                Some("SS-NEXT".to_string()),
            )
            .expect("reload managed core");

        assert_eq!(reloaded.run_state, DesktopRunState::Running);
        assert_eq!(reloaded.selected_outbound.as_deref(), Some("SS-NEXT"));

        service.stop().expect("stop managed core");
    }

    #[test]
    fn service_applies_and_restores_system_proxy_when_requested() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopManagedCoreService::new(&platform_controller);

        let running = service
            .start(
                DesktopManagedStartOptions::system_proxy_mode(
                    ss_config("SS-READY"),
                    Some("SS-READY".to_string()),
                )
                .with_listen("127.0.0.1:0"),
            )
            .expect("start managed core");

        assert_eq!(running.traffic_mode, DesktopTrafficMode::SystemProxy);
        assert_eq!(platform_controller.applied.borrow().len(), 1);

        service.stop().expect("stop managed core");

        assert_eq!(platform_controller.restored.borrow().len(), 1);
    }
}
```

- [ ] **Step 3: Run tests to verify failure**

Run: `cargo test -p keli-desktop managed -- --test-threads=1`

Expected: FAIL because the service returns `"managed mixed core bridge is not wired"` for lifecycle methods.

- [ ] **Step 4: Replace the stub with the real managed controller wrapper**

Replace the top-level implementation in `crates/keli-desktop/src/managed.rs` with:

```rust
use keli_cli::{ManagedMixedController, ManagedMixedOptions};
use keli_platform::SystemProxyController;

use crate::status::{DesktopStatusSnapshot, DesktopTrafficMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopManagedStartOptions {
    pub config_text: String,
    pub selected_outbound: Option<String>,
    pub listen: String,
    pub system_proxy: bool,
}

impl DesktopManagedStartOptions {
    pub fn mixed_inbound_only(
        config_text: impl Into<String>,
        selected_outbound: Option<String>,
    ) -> Self {
        Self {
            config_text: config_text.into(),
            selected_outbound,
            listen: "127.0.0.1:7890".to_string(),
            system_proxy: false,
        }
    }

    pub fn system_proxy_mode(
        config_text: impl Into<String>,
        selected_outbound: Option<String>,
    ) -> Self {
        Self {
            config_text: config_text.into(),
            selected_outbound,
            listen: "127.0.0.1:7890".to_string(),
            system_proxy: true,
        }
    }

    pub fn with_listen(mut self, listen: impl Into<String>) -> Self {
        self.listen = listen.into();
        self
    }
}

pub struct DesktopManagedCoreService<'a, C: SystemProxyController + ?Sized> {
    core: ManagedMixedController<'a, C>,
    traffic_mode: DesktopTrafficMode,
}

impl<'a, C: SystemProxyController + ?Sized> DesktopManagedCoreService<'a, C> {
    pub fn new(controller: &'a C) -> Self {
        Self {
            core: ManagedMixedController::new(controller),
            traffic_mode: DesktopTrafficMode::MixedInboundOnly,
        }
    }

    pub fn is_running(&self) -> bool {
        self.core.is_running()
    }

    pub fn status(&self) -> DesktopStatusSnapshot {
        DesktopStatusSnapshot::from_managed_mixed_status(&self.core.status(), self.traffic_mode)
    }

    pub fn start(
        &mut self,
        options: DesktopManagedStartOptions,
    ) -> Result<DesktopStatusSnapshot, String> {
        self.traffic_mode = if options.system_proxy {
            DesktopTrafficMode::SystemProxy
        } else {
            DesktopTrafficMode::MixedInboundOnly
        };
        let status = self.core.start_from_subscription_config_text(
            &options.config_text,
            ManagedMixedOptions {
                listen: options.listen,
                outbound_tag: options.selected_outbound,
                system_proxy: options.system_proxy,
                ..ManagedMixedOptions::default()
            },
        )?;
        Ok(DesktopStatusSnapshot::from_managed_mixed_status(
            &status,
            self.traffic_mode,
        ))
    }

    pub fn reload_from_subscription_config(
        &mut self,
        config_text: &str,
        selected_outbound: Option<String>,
    ) -> Result<DesktopStatusSnapshot, String> {
        let status = self
            .core
            .reload_from_subscription_config_text(config_text, selected_outbound)?;
        Ok(DesktopStatusSnapshot::from_managed_mixed_status(
            &status,
            self.traffic_mode,
        ))
    }

    pub fn stop(&mut self) -> Result<DesktopStatusSnapshot, String> {
        self.core.stop()?;
        Ok(self.status())
    }
}
```

Keep the tests from Step 2 unchanged.

- [ ] **Step 5: Run managed service tests**

Run: `cargo test -p keli-desktop managed -- --test-threads=1`

Expected: PASS.

- [ ] **Step 6: Run full desktop crate tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 7: Commit**

Run:

```powershell
git add crates/keli-desktop/src/lib.rs crates/keli-desktop/src/managed.rs
git commit -m "Add desktop managed core service"
```

## Task 3: Verification And Push

**Files:**
- No source changes unless verification reveals a defect.

- [ ] **Step 1: Format check**

Run: `cargo fmt --check`

Expected: PASS.

- [ ] **Step 2: Diff whitespace check**

Run: `git diff --check`

Expected: PASS.

- [ ] **Step 3: Desktop crate tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 4: Relevant managed-core regression tests**

Run: `cargo test -p keli-cli --test managed_mixed managed_mixed_controller_start_status_reload_and_stop -- --exact --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Focused workspace tests**

Run: `cargo test -p keli-client-core -p keli-platform -p keli-cli -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 6: Push commits**

Run:

```powershell
git push
```

Expected: the current branch pushes successfully to `origin/main`.

## Self-Review Checklist

- Spec coverage: this plan covers the desktop backend lifecycle boundary around the real native managed core and creates a UI-safe status DTO path.
- Spec gaps: visible Windows shell, TUN controls, diagnostics export, packaging, and manual smoke remain outside this specific bridge slice.
- No incomplete-task markers remain; each code-changing step includes concrete paths, code, commands, and expected results.
- Type consistency: `DesktopManagedCoreService`, `DesktopManagedStartOptions`, `DesktopStatusSnapshot`, and `DesktopTrafficMode` are used consistently across tasks.
