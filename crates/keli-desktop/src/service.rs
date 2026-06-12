use keli_client_core::{plan_subscription_update, preflight_subscription_config, ClientErrorKind};
use keli_platform::SystemProxyController;
use serde::{Deserialize, Serialize};

use crate::managed::{DesktopManagedCoreService, DesktopManagedStartOptions};
use crate::status::{DesktopStatusSnapshot, DesktopTrafficMode};
use crate::subscription::{DesktopSubscriptionSummary, DesktopSubscriptionUpdateSummary};

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
            .clone()
            .ok_or(ClientErrorKind::NoSupportedOutbounds)?;
        let report = preflight_subscription_config(&config_text)?;
        report.select_outbound(Some(&outbound_tag))?;
        if self.core.is_running() {
            self.core
                .reload_from_subscription_config(&config_text, Some(outbound_tag.clone()))?;
        }
        self.selected_outbound = Some(outbound_tag.clone());
        Ok(DesktopSubscriptionSummary::from_preflight(
            &report,
            Some(&outbound_tag),
            Some(&outbound_tag),
        ))
    }

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
        self.selected_outbound = selected;
        Ok(DesktopSubscriptionUpdateSummary::from_report(
            &report,
            true,
            None,
            subscription,
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
            DesktopManagedStartOptions::system_proxy_mode(
                config_text,
                self.selected_outbound.clone(),
            )
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
            self.core.stop()?;
        }
        Ok(self.status())
    }

    pub fn status(&self) -> DesktopStatusSnapshot {
        let mut status = self.core.status();
        status.traffic_mode = self.traffic_mode;
        status
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

        fn apply(
            &self,
            config: &SystemProxyConfig,
        ) -> Result<SystemProxySnapshot, SystemProxyError> {
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
            DesktopRuntimeError::Client(ClientErrorKind::OutboundNotFound("MISSING".to_string()))
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
