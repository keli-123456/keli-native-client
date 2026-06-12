# Desktop Subscription Update Preserve Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a desktop subscription update path that uses the managed core update planner so a running desktop session can accept good subscription updates and reject unusable updates without dropping the active runtime.

**Architecture:** Expose managed mixed update-plan reload through `DesktopManagedCoreService`, add a UI-safe `DesktopSubscriptionUpdateSummary`, and add `DesktopRuntimeService::update_subscription_config`. When the core is running, the method delegates to `ManagedMixedController::reload_from_subscription_config_text_with_update_plan`; when stopped, it updates local subscription state using the same client-core planner.

**Tech Stack:** Rust 2021, `keli-cli::ManagedSubscriptionUpdateOutcome`, `keli-client-core::SubscriptionUpdateReport`, existing desktop DTOs and managed core service.

---

## Scope Check

This plan covers:

- Config-text subscription update from the desktop runtime service.
- Running update success with selected outbound preservation.
- Running update fallback to the new default when the old selected outbound is missing.
- Running update rejection when the new subscription has no supported outbounds.
- UI-safe update summary DTO.

This plan does not cover:

- Fetching subscription text from a URL.
- Persisting subscription URLs or credentials.
- Scheduling background updates.
- Rendering update results in a GUI.

## File Structure

- Modify: `crates/keli-desktop/src/managed.rs`
  - Add a wrapper for managed update-plan reload.
- Modify: `crates/keli-desktop/src/subscription.rs`
  - Add `DesktopSubscriptionUpdateSummary`.
- Modify: `crates/keli-desktop/src/service.rs`
  - Add `update_subscription_config` and service tests.
- Modify: `crates/keli-desktop/src/lib.rs`
  - Export `DesktopSubscriptionUpdateSummary`.

## Task 1: Failing Subscription Update Tests

**Files:**
- Modify: `crates/keli-desktop/src/service.rs`
- Modify: `crates/keli-desktop/src/subscription.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Add the desired DTO shell**

Add this struct and constructor shell to `crates/keli-desktop/src/subscription.rs`:

```rust
use keli_client_core::{SubscriptionPreflightReport, SubscriptionUpdateReport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopSubscriptionUpdateSummary {
    pub applied: bool,
    pub error: Option<String>,
    pub reason: String,
    pub current_supported_count: usize,
    pub new_supported_count: usize,
    pub new_skipped_count: usize,
    pub current_selected_outbound: Option<String>,
    pub planned_selected_outbound: Option<String>,
    pub selected_outbound_preserved: bool,
    pub selected_outbound_changed: bool,
    pub added_tags: Vec<String>,
    pub removed_tags: Vec<String>,
    pub retained_tags: Vec<String>,
    pub subscription: DesktopSubscriptionSummary,
}

impl DesktopSubscriptionUpdateSummary {
    pub fn from_report(
        report: &SubscriptionUpdateReport,
        applied: bool,
        error: Option<String>,
        subscription: DesktopSubscriptionSummary,
    ) -> Self {
        let _ = (report, applied, error, subscription);
        Self {
            applied: false,
            error: None,
            reason: "initial-subscription".to_string(),
            current_supported_count: 0,
            new_supported_count: 0,
            new_skipped_count: 0,
            current_selected_outbound: None,
            planned_selected_outbound: None,
            selected_outbound_preserved: false,
            selected_outbound_changed: false,
            added_tags: Vec::new(),
            removed_tags: Vec::new(),
            retained_tags: Vec::new(),
            subscription: DesktopSubscriptionSummary {
                usable: false,
                supported_count: 0,
                skipped_count: 0,
                default_outbound: None,
                selected_outbound: None,
                recommended_outbound: None,
                nodes: Vec::new(),
                skipped: Vec::new(),
            },
        }
    }
}
```

Update `crates/keli-desktop/src/lib.rs`:

```rust
pub use subscription::{
    DesktopNodeSummary, DesktopSubscriptionSummary, DesktopSubscriptionUpdateSummary,
};
```

- [ ] **Step 2: Add failing service tests**

In `crates/keli-desktop/src/service.rs`, import the new DTO:

```rust
use crate::subscription::{DesktopSubscriptionSummary, DesktopSubscriptionUpdateSummary};
```

Add a stub method to `impl DesktopRuntimeService`:

```rust
    pub fn update_subscription_config(
        &mut self,
        config_text: impl Into<String>,
    ) -> Result<DesktopSubscriptionUpdateSummary, DesktopRuntimeError> {
        let _ = config_text.into();
        Err(DesktopRuntimeError::Managed(
            "desktop subscription update is not wired".to_string(),
        ))
    }
```

Add this helper and tests to the service test module:

```rust
    fn unusable_config() -> &'static str {
        r#"
proxies:
  - name: WG-SKIPPED
    type: wireguard
    server: wg.example.com
    port: 51820
    password: ignored
"#
    }

    #[test]
    fn running_subscription_update_preserves_selected_outbound() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config_with_tags(&["SS-OLD", "SS-STAY"]))
            .expect("import subscription");
        service.select_node("SS-STAY").expect("select node");
        service.set_listen("127.0.0.1:0");
        service.start().expect("start service");

        let update = service
            .update_subscription_config(ss_config_with_tags(&["SS-STAY", "SS-NEW"]))
            .expect("update subscription");

        assert!(update.applied);
        assert_eq!(update.error, None);
        assert_eq!(update.reason, "selected-outbound-preserved");
        assert_eq!(update.current_selected_outbound.as_deref(), Some("SS-STAY"));
        assert_eq!(update.planned_selected_outbound.as_deref(), Some("SS-STAY"));
        assert!(update.selected_outbound_preserved);
        assert!(!update.selected_outbound_changed);
        assert_eq!(update.added_tags, vec!["SS-NEW".to_string()]);
        assert_eq!(update.removed_tags, vec!["SS-OLD".to_string()]);
        assert_eq!(
            service.status().selected_outbound.as_deref(),
            Some("SS-STAY")
        );

        service.stop().expect("stop service");
    }

    #[test]
    fn running_subscription_update_falls_back_to_new_default() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config_with_tags(&["SS-A", "SS-B"]))
            .expect("import subscription");
        service.select_node("SS-B").expect("select node");
        service.set_listen("127.0.0.1:0");
        service.start().expect("start service");

        let update = service
            .update_subscription_config(ss_config_with_tags(&["SS-C", "SS-D"]))
            .expect("update subscription");

        assert!(update.applied);
        assert_eq!(update.reason, "selected-outbound-missing-use-default");
        assert_eq!(update.current_selected_outbound.as_deref(), Some("SS-B"));
        assert_eq!(update.planned_selected_outbound.as_deref(), Some("SS-C"));
        assert!(!update.selected_outbound_preserved);
        assert!(update.selected_outbound_changed);
        assert_eq!(service.status().selected_outbound.as_deref(), Some("SS-C"));

        service.stop().expect("stop service");
    }

    #[test]
    fn unusable_running_subscription_update_keeps_runtime() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");
        service.set_listen("127.0.0.1:0");
        service.start().expect("start service");

        let update = service
            .update_subscription_config(unusable_config())
            .expect("update subscription");

        assert!(!update.applied);
        assert_eq!(
            update.error.as_deref(),
            Some("subscription update rejected: no supported outbounds")
        );
        assert_eq!(update.reason, "no-supported-outbounds");
        assert_eq!(update.new_supported_count, 0);
        assert_eq!(update.new_skipped_count, 1);
        assert_eq!(update.planned_selected_outbound, None);
        assert_eq!(
            service.status().selected_outbound.as_deref(),
            Some("SS-READY")
        );
        assert_eq!(service.status().run_state, DesktopRunState::Running);

        service.stop().expect("stop service");
    }
```

- [ ] **Step 3: Run tests to verify failure**

Run: `cargo test -p keli-desktop service::tests::running_subscription_update -- --test-threads=1`

Expected: FAIL because `update_subscription_config` returns `"desktop subscription update is not wired"`.

## Task 2: Implement Managed Subscription Update

**Files:**
- Modify: `crates/keli-desktop/src/managed.rs`
- Modify: `crates/keli-desktop/src/subscription.rs`
- Modify: `crates/keli-desktop/src/service.rs`

- [ ] **Step 1: Expose managed update-plan reload**

Add `ManagedSubscriptionUpdateOutcome` to the `keli_cli` import in `crates/keli-desktop/src/managed.rs`:

```rust
use keli_cli::{ManagedMixedController, ManagedMixedOptions, ManagedSubscriptionUpdateOutcome};
```

Add this method to `DesktopManagedCoreService`:

```rust
    pub fn reload_subscription_config_with_update_plan(
        &mut self,
        config_text: &str,
    ) -> Result<ManagedSubscriptionUpdateOutcome, String> {
        self.core
            .reload_from_subscription_config_text_with_update_plan(config_text)
    }
```

- [ ] **Step 2: Implement update summary mapping**

Replace `DesktopSubscriptionUpdateSummary::from_report` with:

```rust
    pub fn from_report(
        report: &SubscriptionUpdateReport,
        applied: bool,
        error: Option<String>,
        subscription: DesktopSubscriptionSummary,
    ) -> Self {
        Self {
            applied,
            error,
            reason: report.reason.label().to_string(),
            current_supported_count: report.current_supported_count,
            new_supported_count: report.new_supported_count,
            new_skipped_count: report.new_skipped_count,
            current_selected_outbound: report.current_selected_outbound.clone(),
            planned_selected_outbound: report.planned_selected_outbound.clone(),
            selected_outbound_preserved: report.selected_outbound_preserved,
            selected_outbound_changed: report.selected_outbound_changed,
            added_tags: report.added_tags.clone(),
            removed_tags: report.removed_tags.clone(),
            retained_tags: report.retained_tags.clone(),
            subscription,
        }
    }
```

- [ ] **Step 3: Implement desktop runtime update method**

Add `plan_subscription_update` to the `keli_client_core` import in `service.rs`:

```rust
use keli_client_core::{plan_subscription_update, preflight_subscription_config, ClientErrorKind};
```

Replace `update_subscription_config` with:

```rust
    pub fn update_subscription_config(
        &mut self,
        config_text: impl Into<String>,
    ) -> Result<DesktopSubscriptionUpdateSummary, DesktopRuntimeError> {
        let config_text = config_text.into();
        if self.core.is_running() {
            let outcome = self
                .core
                .reload_subscription_config_with_update_plan(&config_text)?;
            let preflight = preflight_subscription_config(&config_text)?;
            let planned_selected = outcome.report.planned_selected_outbound.clone();
            let subscription = DesktopSubscriptionSummary::from_preflight(
                &preflight,
                planned_selected.as_deref(),
                planned_selected.as_deref(),
            );
            if outcome.applied {
                self.subscription_config = Some(config_text);
                self.selected_outbound = outcome.status.selected_outbound.clone();
            }
            return Ok(DesktopSubscriptionUpdateSummary::from_report(
                &outcome.report,
                outcome.applied,
                outcome.error,
                subscription,
            ));
        }

        let preflight = preflight_subscription_config(&config_text)?;
        let report = plan_subscription_update(
            self.subscription_config.as_deref(),
            &config_text,
            self.selected_outbound.as_deref(),
        )?;
        let selected = report.planned_selected_outbound.clone();
        let subscription = DesktopSubscriptionSummary::from_preflight(
            &preflight,
            selected.as_deref(),
            selected.as_deref(),
        );
        self.subscription_config = Some(config_text);
        self.selected_outbound = selected.clone();
        Ok(DesktopSubscriptionUpdateSummary::from_report(
            &report,
            true,
            None,
            subscription,
        ))
    }
```

- [ ] **Step 4: Run update tests**

Run: `cargo test -p keli-desktop service::tests::running_subscription_update -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Run full desktop crate tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```powershell
git add crates/keli-desktop/src/lib.rs crates/keli-desktop/src/managed.rs crates/keli-desktop/src/service.rs crates/keli-desktop/src/subscription.rs
git commit -m "Add desktop subscription update preservation"
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

- [ ] **Step 4: Managed core update-plan regression tests**

Run: `cargo test -p keli-cli --test managed_mixed managed_mixed_controller_update_plan -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Push commits**

Run:

```powershell
git push
```

Expected: the current branch pushes successfully to `origin/main`.

## Self-Review Checklist

- Spec coverage: this plan covers the failure-preserving subscription update path needed before exposing subscription updates in UI.
- Spec gaps: URL fetch, credentials, background updates, GUI, and packaging remain separate slices.
- No incomplete-task markers remain; every code-changing step includes concrete paths, code, commands, and expected results.
- Type consistency: `DesktopSubscriptionUpdateSummary`, `DesktopRuntimeService::update_subscription_config`, and `DesktopManagedCoreService::reload_subscription_config_with_update_plan` are used consistently.
