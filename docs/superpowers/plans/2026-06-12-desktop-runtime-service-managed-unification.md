# Desktop Runtime Service Managed Unification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `DesktopRuntimeService` the single desktop-facing runtime facade for subscription import, node selection, start, reload, status, and stop by routing lifecycle commands through the real managed mixed core.

**Architecture:** Replace the temporary `ClientRuntime` field in `DesktopRuntimeService` with `DesktopManagedCoreService<'a, C>`, where `C: SystemProxyController`. Keep subscription preflight and node summary mapping in `keli-desktop`, but use managed mixed reload when a user changes nodes while running. TUN mode remains explicitly blocked in this facade until the desktop TUN lifecycle is wired.

**Tech Stack:** Rust 2021, `keli-client-core` subscription preflight, `keli-platform::SystemProxyController`, `keli-cli::ManagedMixedController` through `DesktopManagedCoreService`, existing desktop DTOs.

---

## Scope Check

This plan covers:

- Refactoring `DesktopRuntimeService` so UI code has one runtime facade backed by real managed core.
- Preserving subscription import and node list summaries.
- Starting and stopping the real managed core from the high-level desktop service.
- Reloading the real managed core when node selection changes while running.
- Surfacing a typed desktop runtime error wrapper.
- Explicitly rejecting TUN start requests from this facade until TUN lifecycle wiring is added.

This plan does not cover:

- Subscription URL fetch/update UI.
- Managed subscription URL update plan DTOs.
- Actual TUN device lifecycle.
- Tray/window shell.
- Support bundle export.

## File Structure

- Modify: `crates/keli-desktop/src/lib.rs`
  - Export `DesktopRuntimeError`.
- Modify: `crates/keli-desktop/src/service.rs`
  - Replace temporary `ClientRuntime` implementation with managed-core-backed runtime facade and tests.
- Modify: `crates/keli-desktop/src/managed.rs`
  - No planned behavior change; used by `service.rs`.

## Task 1: Managed Runtime Facade Tests

**Files:**
- Modify: `crates/keli-desktop/src/service.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Write failing tests and desired API**

Replace `crates/keli-desktop/src/service.rs` with this managed facade shell and tests:

```rust
use keli_client_core::{preflight_subscription_config, ClientErrorKind};
use keli_platform::SystemProxyController;
use serde::{Deserialize, Serialize};

use crate::managed::{DesktopManagedCoreService, DesktopManagedStartOptions};
use crate::status::{DesktopStatusSnapshot, DesktopTrafficMode};
use crate::subscription::DesktopSubscriptionSummary;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesktopRuntimeCommand {
    ImportSubscription,
    SelectNode,
    Start,
    Reload,
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopRuntimeError {
    Client(ClientErrorKind),
    Managed(String),
}

impl From<ClientErrorKind> for DesktopRuntimeError {
    fn from(error: ClientErrorKind) -> Self {
        Self::Client(error)
    }
}

impl From<String> for DesktopRuntimeError {
    fn from(error: String) -> Self {
        Self::Managed(error)
    }
}

pub struct DesktopRuntimeService<'a, C: SystemProxyController + ?Sized> {
    core: DesktopManagedCoreService<'a, C>,
    subscription_config: Option<String>,
    selected_outbound: Option<String>,
    traffic_mode: DesktopTrafficMode,
    listen: String,
}

impl<'a, C: SystemProxyController + ?Sized> DesktopRuntimeService<'a, C> {
    pub fn new(controller: &'a C) -> Self {
        Self {
            core: DesktopManagedCoreService::new(controller),
            subscription_config: None,
            selected_outbound: None,
            traffic_mode: DesktopTrafficMode::MixedInboundOnly,
            listen: "127.0.0.1:7890".to_string(),
        }
    }

    pub fn import_subscription_config(
        &mut self,
        config_text: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, DesktopRuntimeError> {
        let _ = config_text.into();
        Err(DesktopRuntimeError::Client(
            ClientErrorKind::NoSupportedOutbounds,
        ))
    }

    pub fn select_node(
        &mut self,
        outbound_tag: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, DesktopRuntimeError> {
        let _ = outbound_tag.into();
        Err(DesktopRuntimeError::Client(
            ClientErrorKind::NoSupportedOutbounds,
        ))
    }

    pub fn set_traffic_mode(&mut self, traffic_mode: DesktopTrafficMode) {
        self.traffic_mode = traffic_mode;
    }

    pub fn set_listen(&mut self, listen: impl Into<String>) {
        self.listen = listen.into();
    }

    pub fn is_running(&self) -> bool {
        self.core.is_running()
    }

    pub fn start(&mut self) -> Result<DesktopStatusSnapshot, DesktopRuntimeError> {
        Err(DesktopRuntimeError::Client(
            ClientErrorKind::NoSupportedOutbounds,
        ))
    }

    pub fn stop(&mut self) -> Result<DesktopStatusSnapshot, DesktopRuntimeError> {
        Ok(self.status())
    }

    pub fn status(&self) -> DesktopStatusSnapshot {
        self.core.status()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::status::DesktopRunState;
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

    fn ss_config_with_tags(tags: &[&str]) -> String {
        let mut config = String::from("proxies:\n");
        for tag in tags {
            config.push_str(&format!(
                r#"  - name: {tag}
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#
            ));
        }
        config
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
    fn import_subscription_exposes_desktop_summary() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);

        let summary = service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");

        assert!(summary.usable);
        assert_eq!(summary.selected_outbound.as_deref(), Some("SS-READY"));
        assert_eq!(summary.nodes[0].tag, "SS-READY");
        assert!(summary.nodes[0].selected);
    }

    #[test]
    fn select_node_rejects_missing_outbound_without_changing_runtime() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");

        let error = service.select_node("MISSING").expect_err("missing node");

        assert_eq!(
            error,
            DesktopRuntimeError::Client(ClientErrorKind::OutboundNotFound(
                "MISSING".to_string(),
            ))
        );
        assert_eq!(service.status().run_state, DesktopRunState::Stopped);
    }

    #[test]
    fn start_and_stop_use_real_managed_core() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");
        service.set_listen("127.0.0.1:0");

        let running = service.start().expect("start service");

        assert!(service.is_running());
        assert_eq!(running.run_state, DesktopRunState::Running);
        assert_eq!(running.traffic_mode, DesktopTrafficMode::MixedInboundOnly);
        assert_eq!(running.selected_outbound.as_deref(), Some("SS-READY"));

        let stopped = service.stop().expect("stop service");

        assert!(!service.is_running());
        assert_eq!(stopped.run_state, DesktopRunState::Stopped);
        assert_eq!(stopped.traffic_mode, DesktopTrafficMode::MixedInboundOnly);
    }

    #[test]
    fn running_node_selection_reloads_real_managed_core() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config_with_tags(&["SS-READY", "SS-NEXT"]))
            .expect("import subscription");
        service.set_listen("127.0.0.1:0");
        service.start().expect("start service");

        let summary = service.select_node("SS-NEXT").expect("select node");

        assert_eq!(summary.selected_outbound.as_deref(), Some("SS-NEXT"));
        assert_eq!(
            service.status().selected_outbound.as_deref(),
            Some("SS-NEXT")
        );
        assert_eq!(service.status().run_state, DesktopRunState::Running);

        service.stop().expect("stop service");
    }

    #[test]
    fn system_proxy_mode_applies_and_restores_proxy() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");
        service.set_traffic_mode(DesktopTrafficMode::SystemProxy);
        service.set_listen("127.0.0.1:0");

        let running = service.start().expect("start service");

        assert_eq!(running.traffic_mode, DesktopTrafficMode::SystemProxy);
        assert_eq!(platform_controller.applied.borrow().len(), 1);

        service.stop().expect("stop service");

        assert_eq!(platform_controller.restored.borrow().len(), 1);
    }

    #[test]
    fn tun_mode_start_is_blocked_until_tun_lifecycle_is_wired() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");
        service.set_traffic_mode(DesktopTrafficMode::Tun);

        let error = service.start().expect_err("tun mode blocked");

        assert_eq!(
            error,
            DesktopRuntimeError::Managed(
                "TUN traffic mode is not wired into desktop runtime service".to_string()
            )
        );
        assert_eq!(service.status().run_state, DesktopRunState::Stopped);
    }
}
```

Modify `crates/keli-desktop/src/lib.rs` export:

```rust
pub use service::{DesktopRuntimeCommand, DesktopRuntimeError, DesktopRuntimeService};
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test -p keli-desktop service -- --test-threads=1`

Expected: FAIL because `import_subscription_config`, `start`, and running node selection still return stub errors.

## Task 2: Implement Managed Runtime Facade

**Files:**
- Modify: `crates/keli-desktop/src/service.rs`

- [ ] **Step 1: Implement subscription import, selection, start, and stop**

Replace the stub methods in `DesktopRuntimeService` with:

```rust
    pub fn import_subscription_config(
        &mut self,
        config_text: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, DesktopRuntimeError> {
        let config_text = config_text.into();
        let report = preflight_subscription_config(&config_text)?;
        let selected = report.default_outbound().map(str::to_string);
        self.subscription_config = Some(config_text);
        self.selected_outbound = selected.clone();
        Ok(DesktopSubscriptionSummary::from_preflight(
            &report,
            selected.as_deref(),
            selected.as_deref(),
        ))
    }

    pub fn select_node(
        &mut self,
        outbound_tag: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, DesktopRuntimeError> {
        let outbound_tag = outbound_tag.into();
        let config_text = self
            .subscription_config
            .as_deref()
            .ok_or(ClientErrorKind::NoSupportedOutbounds)?;
        let report = preflight_subscription_config(config_text)?;
        report.select_outbound(Some(&outbound_tag))?;
        if self.core.is_running() {
            self.core
                .reload_from_subscription_config(config_text, Some(outbound_tag.clone()))?;
        }
        self.selected_outbound = Some(outbound_tag.clone());
        Ok(DesktopSubscriptionSummary::from_preflight(
            &report,
            Some(&outbound_tag),
            Some(&outbound_tag),
        ))
    }

    pub fn start(&mut self) -> Result<DesktopStatusSnapshot, DesktopRuntimeError> {
        let config_text = self
            .subscription_config
            .clone()
            .ok_or(ClientErrorKind::NoSupportedOutbounds)?;
        if self.traffic_mode == DesktopTrafficMode::Tun {
            return Err(DesktopRuntimeError::Managed(
                "TUN traffic mode is not wired into desktop runtime service".to_string(),
            ));
        }
        let options = if self.traffic_mode == DesktopTrafficMode::SystemProxy {
            DesktopManagedStartOptions::system_proxy_mode(config_text, self.selected_outbound.clone())
        } else {
            DesktopManagedStartOptions::mixed_inbound_only(
                config_text,
                self.selected_outbound.clone(),
            )
        }
        .with_listen(self.listen.clone());
        Ok(self.core.start(options)?)
    }

    pub fn stop(&mut self) -> Result<DesktopStatusSnapshot, DesktopRuntimeError> {
        if self.core.is_running() {
            Ok(self.core.stop()?)
        } else {
            Ok(self.status())
        }
    }
```

- [ ] **Step 2: Run service tests**

Run: `cargo test -p keli-desktop service -- --test-threads=1`

Expected: PASS.

- [ ] **Step 3: Run full desktop crate tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 4: Commit**

Run:

```powershell
git add crates/keli-desktop/src/lib.rs crates/keli-desktop/src/service.rs
git commit -m "Unify desktop runtime service on managed core"
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

- [ ] **Step 4: Managed core regression**

Run: `cargo test -p keli-cli --test managed_mixed managed_mixed_controller_start_status_reload_and_stop -- --exact --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Push commits**

Run:

```powershell
git push
```

Expected: the current branch pushes successfully to `origin/main`.

## Self-Review Checklist

- Spec coverage: this plan makes the desktop backend service use the real managed native core for ordinary runtime control.
- Spec gaps: subscription URL fetch/update DTOs, TUN lifecycle, diagnostics export, visible UI, and packaging remain separate slices.
- No incomplete-task markers remain; code-changing steps include concrete paths, code, commands, and expected results.
- Type consistency: `DesktopRuntimeService`, `DesktopRuntimeError`, `DesktopManagedCoreService`, and `DesktopTrafficMode` are used consistently.
