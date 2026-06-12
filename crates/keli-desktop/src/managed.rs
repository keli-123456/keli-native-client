use std::time::Duration;

use keli_cli::{
    fetch_subscription_url_config_text, managed_mixed_status_json_value, ManagedMixedController,
    ManagedMixedOptions, ManagedSubscriptionUpdateOutcome,
    ManagedSubscriptionUrlConfigFetchOutcome, ManagedSubscriptionUrlConfigUpdateOutcome,
};
use keli_platform::{SystemProxyController, TunDeviceConfig, TunPacketIoController};

use crate::status::{DesktopStatusSnapshot, DesktopTrafficMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopManagedStartOptions {
    pub config_text: String,
    pub selected_outbound: Option<String>,
    pub listen: String,
    pub system_proxy: bool,
    pub tun_device: Option<TunDeviceConfig>,
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
            tun_device: None,
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
            tun_device: None,
        }
    }

    pub fn tun_mode(
        config_text: impl Into<String>,
        selected_outbound: Option<String>,
        tun_device: TunDeviceConfig,
    ) -> Self {
        Self {
            config_text: config_text.into(),
            selected_outbound,
            listen: "127.0.0.1:7890".to_string(),
            system_proxy: false,
            tun_device: Some(tun_device),
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

    pub fn fetch_subscription_url_config(
        url: &str,
        timeout: Duration,
        max_bytes: usize,
    ) -> ManagedSubscriptionUrlConfigFetchOutcome {
        fetch_subscription_url_config_text(url, timeout, max_bytes)
    }

    pub fn is_running(&self) -> bool {
        self.core.is_running()
    }

    pub fn status(&self) -> DesktopStatusSnapshot {
        DesktopStatusSnapshot::from_managed_mixed_status(&self.core.status(), self.traffic_mode)
    }

    pub fn managed_status_json(&self) -> serde_json::Value {
        managed_mixed_status_json_value(&self.core.status())
    }

    pub fn start(
        &mut self,
        options: DesktopManagedStartOptions,
    ) -> Result<DesktopStatusSnapshot, String> {
        if options.tun_device.is_some() {
            return Err("desktop managed TUN start requires a TUN controller".to_string());
        }
        self.start_without_tun(options)
    }

    pub fn start_with_tun_controller<T>(
        &mut self,
        options: DesktopManagedStartOptions,
        tun_controller: &'a T,
    ) -> Result<DesktopStatusSnapshot, String>
    where
        T: TunPacketIoController + ?Sized,
        T::PacketIo: Send + 'static,
    {
        let traffic_mode = if options.tun_device.is_some() {
            DesktopTrafficMode::Tun
        } else if options.system_proxy {
            DesktopTrafficMode::SystemProxy
        } else {
            DesktopTrafficMode::MixedInboundOnly
        };
        let status = self
            .core
            .start_from_subscription_config_text_with_tun_controller(
                &options.config_text,
                ManagedMixedOptions {
                    listen: options.listen,
                    outbound_tag: options.selected_outbound,
                    system_proxy: options.system_proxy,
                    tun_device: options.tun_device,
                    ..ManagedMixedOptions::default()
                },
                tun_controller,
            )?;
        self.traffic_mode = traffic_mode;
        Ok(DesktopStatusSnapshot::from_managed_mixed_status(
            &status,
            self.traffic_mode,
        ))
    }

    fn start_without_tun(
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

    pub fn reload_subscription_url_with_update_plan_and_config_text(
        &mut self,
        url: &str,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<ManagedSubscriptionUrlConfigUpdateOutcome, String> {
        self.core
            .reload_from_subscription_url_with_update_plan_and_config_text(url, timeout, max_bytes)
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
        TunDeviceConfig, TunDeviceController, TunDeviceError, TunDeviceSnapshot, TunPacketIo,
        TunPacketIoController,
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

    #[derive(Debug, Default)]
    struct FakeTunDeviceController {
        starts: RefCell<Vec<TunDeviceConfig>>,
        opens: RefCell<Vec<TunDeviceConfig>>,
        stops: RefCell<usize>,
        running: RefCell<Option<TunDeviceConfig>>,
    }

    #[derive(Debug, Default)]
    struct FakeTunPacketIo;

    impl FakeTunDeviceController {
        fn stopped_snapshot() -> TunDeviceSnapshot {
            TunDeviceSnapshot {
                supported: true,
                lifecycle_available: true,
                packet_io_available: true,
                running: false,
                interface_name: None,
                address_cidr: None,
                mtu: None,
                dns_hijack: None,
            }
        }
    }

    impl TunDeviceController for FakeTunDeviceController {
        fn snapshot(&self) -> Result<TunDeviceSnapshot, TunDeviceError> {
            Ok(self
                .running
                .borrow()
                .as_ref()
                .map(TunDeviceSnapshot::running)
                .unwrap_or_else(Self::stopped_snapshot))
        }

        fn start(&self, config: &TunDeviceConfig) -> Result<TunDeviceSnapshot, TunDeviceError> {
            self.starts.borrow_mut().push(config.clone());
            self.running.borrow_mut().replace(config.clone());
            Ok(TunDeviceSnapshot::running(config))
        }

        fn stop(&self) -> Result<TunDeviceSnapshot, TunDeviceError> {
            *self.stops.borrow_mut() += 1;
            self.running.borrow_mut().take();
            Ok(Self::stopped_snapshot())
        }
    }

    impl TunPacketIo for FakeTunPacketIo {
        fn read_packet(&mut self) -> Result<Option<Vec<u8>>, TunDeviceError> {
            Ok(None)
        }

        fn write_packet(&mut self, _packet: &[u8]) -> Result<(), TunDeviceError> {
            Ok(())
        }
    }

    impl TunPacketIoController for FakeTunDeviceController {
        type PacketIo = FakeTunPacketIo;

        fn open_packet_io(
            &self,
            config: &TunDeviceConfig,
        ) -> Result<Self::PacketIo, TunDeviceError> {
            self.opens.borrow_mut().push(config.clone());
            Ok(FakeTunPacketIo)
        }
    }

    fn tun_config() -> TunDeviceConfig {
        TunDeviceConfig::new("keli-tun0", "10.7.0.1/24", 1500).expect("valid TUN config")
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

    #[test]
    fn service_starts_and_stops_real_managed_core_with_tun_controller() {
        let platform_controller = FakeSystemProxyController::new();
        let tun_controller = FakeTunDeviceController::default();
        let tun_device = tun_config();
        let mut service = DesktopManagedCoreService::new(&platform_controller);

        let running = service
            .start_with_tun_controller(
                DesktopManagedStartOptions::tun_mode(
                    ss_config("SS-READY"),
                    Some("SS-READY".to_string()),
                    tun_device.clone(),
                )
                .with_listen("127.0.0.1:0"),
                &tun_controller,
            )
            .expect("start managed core with TUN");

        assert!(service.is_running());
        assert_eq!(running.run_state, DesktopRunState::Running);
        assert_eq!(running.traffic_mode, DesktopTrafficMode::Tun);
        assert_eq!(
            tun_controller.starts.borrow().as_slice(),
            &[tun_device.clone()]
        );
        assert_eq!(tun_controller.opens.borrow().as_slice(), &[tun_device]);

        let stopped = service.stop().expect("stop managed core");

        assert!(!service.is_running());
        assert_eq!(stopped.run_state, DesktopRunState::Stopped);
        assert_eq!(stopped.traffic_mode, DesktopTrafficMode::Tun);
        assert_eq!(*tun_controller.stops.borrow(), 1);
    }
}
