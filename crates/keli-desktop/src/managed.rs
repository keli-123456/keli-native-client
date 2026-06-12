use keli_cli::{ManagedMixedController, ManagedMixedOptions, ManagedSubscriptionUpdateOutcome};
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
        let traffic_mode = if options.system_proxy {
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
        self.traffic_mode = traffic_mode;
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

    pub fn reload_subscription_config_with_update_plan(
        &mut self,
        config_text: &str,
    ) -> Result<ManagedSubscriptionUpdateOutcome, String> {
        self.core
            .reload_from_subscription_config_text_with_update_plan(config_text)
    }

    pub fn stop(&mut self) -> Result<DesktopStatusSnapshot, String> {
        self.core.stop()?;
        Ok(self.status())
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
        assert!(running
            .listen
            .as_deref()
            .unwrap_or("")
            .starts_with("127.0.0.1:"));
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
            .reload_from_subscription_config(&ss_config("SS-NEXT"), Some("SS-NEXT".to_string()))
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
