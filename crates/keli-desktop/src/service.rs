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
