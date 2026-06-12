use std::sync::OnceLock;
use std::time::Duration;

use keli_client_core::ClientErrorKind;
use keli_platform::{
    NativeSystemProxyController, NativeTunDeviceController, PlatformCapabilities,
    SystemProxyController, SystemProxyStatus, TunBackendStatus, TunPacketIoController,
};
use serde::{Deserialize, Serialize};

use crate::dependencies::DesktopDependencyReport;
use crate::service::{DesktopRuntimeError, DesktopRuntimeService};
use crate::status::{DesktopStatusSnapshot, DesktopTrafficMode};
use crate::subscription::{
    DesktopSubscriptionSummary, DesktopSubscriptionUrlImportSummary,
    DesktopSubscriptionUrlUpdateSummary,
};
use crate::support::DesktopSupportBundleExport;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopCommandError {
    pub operation: String,
    pub kind: String,
    pub message: String,
}

impl DesktopCommandError {
    fn runtime(operation: &'static str, error: DesktopRuntimeError) -> Self {
        match error {
            DesktopRuntimeError::Client(error) => Self {
                operation: operation.to_string(),
                kind: "client".to_string(),
                message: client_error_message(&error),
            },
            DesktopRuntimeError::Managed(error) => Self {
                operation: operation.to_string(),
                kind: "managed".to_string(),
                message: error,
            },
        }
    }
}

fn client_error_message(error: &ClientErrorKind) -> String {
    format!("{error:?}")
}

pub struct DesktopCommandService<
    'a,
    C: SystemProxyController + ?Sized,
    T: TunPacketIoController + ?Sized = NativeTunDeviceController,
> {
    runtime: DesktopRuntimeService<'a, C, T>,
}

static NATIVE_SYSTEM_PROXY_CONTROLLER: OnceLock<NativeSystemProxyController> = OnceLock::new();
static NATIVE_TUN_CONTROLLER: OnceLock<NativeTunDeviceController> = OnceLock::new();

fn native_system_proxy_controller() -> &'static NativeSystemProxyController {
    NATIVE_SYSTEM_PROXY_CONTROLLER.get_or_init(NativeSystemProxyController::new)
}

fn native_tun_controller() -> &'static NativeTunDeviceController {
    NATIVE_TUN_CONTROLLER.get_or_init(NativeTunDeviceController::new)
}

pub struct DesktopNativeCommandService {
    commands:
        DesktopCommandService<'static, NativeSystemProxyController, NativeTunDeviceController>,
}

impl DesktopNativeCommandService {
    pub fn new() -> Self {
        let runtime = DesktopRuntimeService::new_with_tun_controller(
            native_system_proxy_controller(),
            native_tun_controller(),
        );
        Self {
            commands: DesktopCommandService::from_runtime(runtime),
        }
    }

    pub fn import_subscription_config(
        &mut self,
        config_text: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, DesktopCommandError> {
        self.commands.import_subscription_config(config_text)
    }

    pub fn import_subscription_url(
        &mut self,
        url: &str,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<DesktopSubscriptionUrlImportSummary, DesktopCommandError> {
        self.commands
            .import_subscription_url(url, timeout, max_bytes)
    }

    pub fn select_node(
        &mut self,
        outbound_tag: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, DesktopCommandError> {
        self.commands.select_node(outbound_tag)
    }

    pub fn update_subscription_url(
        &mut self,
        url: &str,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<DesktopSubscriptionUrlUpdateSummary, DesktopCommandError> {
        self.commands
            .update_subscription_url(url, timeout, max_bytes)
    }

    pub fn set_traffic_mode(&mut self, traffic_mode: DesktopTrafficMode) {
        self.commands.set_traffic_mode(traffic_mode);
    }

    pub fn set_listen(&mut self, listen: impl Into<String>) {
        self.commands.set_listen(listen);
    }

    pub fn start(&mut self) -> Result<DesktopStatusSnapshot, DesktopCommandError> {
        self.commands.start()
    }

    pub fn stop(&mut self) -> Result<DesktopStatusSnapshot, DesktopCommandError> {
        self.commands.stop()
    }

    pub fn status(&self) -> DesktopStatusSnapshot {
        self.commands.status()
    }

    pub fn export_support_bundle(&self) -> Result<DesktopSupportBundleExport, DesktopCommandError> {
        self.commands.export_support_bundle()
    }

    pub fn dependency_report() -> DesktopDependencyReport {
        DesktopCommandService::<
            NativeSystemProxyController,
            NativeTunDeviceController,
        >::dependency_report()
    }
}

impl Default for DesktopNativeCommandService {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, C, T> DesktopCommandService<'a, C, T>
where
    C: SystemProxyController + ?Sized,
    T: TunPacketIoController + ?Sized,
    T::PacketIo: Send + 'static,
{
    pub fn from_runtime(runtime: DesktopRuntimeService<'a, C, T>) -> Self {
        Self { runtime }
    }

    pub fn import_subscription_config(
        &mut self,
        config_text: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, DesktopCommandError> {
        self.runtime
            .import_subscription_config(config_text)
            .map_err(|error| DesktopCommandError::runtime("import-subscription", error))
    }

    pub fn import_subscription_url(
        &mut self,
        url: &str,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<DesktopSubscriptionUrlImportSummary, DesktopCommandError> {
        self.runtime
            .import_subscription_url(url, timeout, max_bytes)
            .map_err(|error| DesktopCommandError::runtime("import-subscription-url", error))
    }

    pub fn select_node(
        &mut self,
        outbound_tag: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, DesktopCommandError> {
        self.runtime
            .select_node(outbound_tag)
            .map_err(|error| DesktopCommandError::runtime("select-node", error))
    }

    pub fn update_subscription_url(
        &mut self,
        url: &str,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<DesktopSubscriptionUrlUpdateSummary, DesktopCommandError> {
        self.runtime
            .update_subscription_url(url, timeout, max_bytes)
            .map_err(|error| DesktopCommandError::runtime("update-subscription-url", error))
    }

    pub fn set_traffic_mode(&mut self, traffic_mode: DesktopTrafficMode) {
        self.runtime.set_traffic_mode(traffic_mode);
    }

    pub fn set_listen(&mut self, listen: impl Into<String>) {
        self.runtime.set_listen(listen);
    }

    pub fn start(&mut self) -> Result<DesktopStatusSnapshot, DesktopCommandError> {
        self.runtime
            .start()
            .map_err(|error| DesktopCommandError::runtime("start", error))
    }

    pub fn stop(&mut self) -> Result<DesktopStatusSnapshot, DesktopCommandError> {
        self.runtime
            .stop()
            .map_err(|error| DesktopCommandError::runtime("stop", error))
    }

    pub fn status(&self) -> DesktopStatusSnapshot {
        self.runtime.status()
    }

    pub fn export_support_bundle(&self) -> Result<DesktopSupportBundleExport, DesktopCommandError> {
        self.runtime
            .export_support_bundle()
            .map_err(|error| DesktopCommandError::runtime("export-support-bundle", error))
    }

    pub fn dependency_report() -> DesktopDependencyReport {
        DesktopDependencyReport::detect_native()
    }

    pub fn dependency_report_from_platform(
        capabilities: &PlatformCapabilities,
        system_proxy: &SystemProxyStatus,
        tun_backend: &TunBackendStatus,
    ) -> DesktopDependencyReport {
        DesktopDependencyReport::from_platform(capabilities, system_proxy, tun_backend)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::service::DesktopRuntimeService;
    use crate::status::{DesktopRunState, DesktopTrafficMode};
    use keli_platform::{
        PlatformCapabilities, PlatformKind, SystemProxyConfig, SystemProxyController,
        SystemProxyError, SystemProxySnapshot, SystemProxyStatus, TunBackendStatus,
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

    fn system_proxy_status() -> SystemProxyStatus {
        SystemProxyStatus {
            supported: true,
            enabled: Some(false),
            server: None,
            error: None,
        }
    }

    fn ready_tun_backend() -> TunBackendStatus {
        TunBackendStatus {
            platform: PlatformKind::Windows,
            backend: "wintun".to_string(),
            supported: true,
            lifecycle_wired: true,
            packet_io_wired: true,
            route_takeover_wired: true,
            driver_library_present: true,
            driver_api_available: true,
            driver_library_path: Some("C:\\Keli\\wintun.dll".to_string()),
            driver_api_error: None,
            install_required: false,
            searched_paths: vec!["C:\\Keli\\wintun.dll".to_string()],
            reason: None,
        }
    }

    fn windows_capabilities() -> PlatformCapabilities {
        PlatformCapabilities {
            platform: PlatformKind::Windows,
            system_proxy: true,
            tun: true,
            secure_storage: true,
            process_supervision: true,
        }
    }

    #[test]
    fn command_service_imports_starts_reports_status_and_stops() {
        let platform_controller = FakeSystemProxyController::new();
        let runtime = DesktopRuntimeService::new(&platform_controller);
        let mut commands = DesktopCommandService::from_runtime(runtime);

        let subscription = commands
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");
        commands.set_traffic_mode(DesktopTrafficMode::MixedInboundOnly);
        commands.set_listen("127.0.0.1:0");

        let running = commands.start().expect("start service");

        assert_eq!(subscription.selected_outbound.as_deref(), Some("SS-READY"));
        assert_eq!(running.run_state, DesktopRunState::Running);
        assert_eq!(
            commands.status().selected_outbound.as_deref(),
            Some("SS-READY")
        );

        let stopped = commands.stop().expect("stop service");

        assert_eq!(stopped.run_state, DesktopRunState::Stopped);
    }

    #[test]
    fn command_service_controls_system_proxy_mode() {
        let platform_controller = FakeSystemProxyController::new();
        let runtime = DesktopRuntimeService::new(&platform_controller);
        let mut commands = DesktopCommandService::from_runtime(runtime);
        commands
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");
        commands.set_traffic_mode(DesktopTrafficMode::SystemProxy);
        commands.set_listen("127.0.0.1:0");

        let running = commands.start().expect("start system proxy mode");

        assert_eq!(running.traffic_mode, DesktopTrafficMode::SystemProxy);
        assert_eq!(platform_controller.applied.borrow().len(), 1);

        commands.stop().expect("stop system proxy mode");

        assert_eq!(platform_controller.restored.borrow().len(), 1);
    }

    #[test]
    fn command_service_maps_runtime_errors_to_serializable_error() {
        let platform_controller = FakeSystemProxyController::new();
        let runtime = DesktopRuntimeService::new(&platform_controller);
        let mut commands = DesktopCommandService::from_runtime(runtime);
        commands
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");

        let error = commands
            .select_node("MISSING")
            .expect_err("missing node should fail");

        assert_eq!(error.operation, "select-node");
        assert_eq!(error.kind, "client");
        assert!(error.message.contains("OutboundNotFound"));
    }

    #[test]
    fn command_service_maps_dependency_report_for_ui() {
        let report = DesktopCommandService::<
            FakeSystemProxyController,
            keli_platform::NativeTunDeviceController,
        >::dependency_report_from_platform(
            &windows_capabilities(),
            &system_proxy_status(),
            &ready_tun_backend(),
        );

        assert!(report.first_run.can_start_tun_mode);
        assert_eq!(report.system_proxy.state, "ready");
        assert_eq!(report.tun_backend.state, "ready");
    }

    #[test]
    fn native_command_service_starts_stopped() {
        let commands = DesktopNativeCommandService::new();

        assert_eq!(commands.status().run_state, DesktopRunState::Stopped);
    }

    #[test]
    fn native_command_service_runs_mixed_only_lifecycle() {
        let mut commands = DesktopNativeCommandService::new();
        commands
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");
        commands.set_traffic_mode(DesktopTrafficMode::MixedInboundOnly);
        commands.set_listen("127.0.0.1:0");

        let running = commands.start().expect("start native host");

        assert_eq!(running.run_state, DesktopRunState::Running);
        assert_eq!(running.traffic_mode, DesktopTrafficMode::MixedInboundOnly);
        assert_eq!(
            commands.status().selected_outbound.as_deref(),
            Some("SS-READY")
        );

        let stopped = commands.stop().expect("stop native host");

        assert_eq!(stopped.run_state, DesktopRunState::Stopped);
    }
}
