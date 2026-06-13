use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use keli_client_core::panel::{PanelApiClient, PanelApiError, PanelHttpTransport, PanelSession};
use keli_client_core::ClientErrorKind;
use keli_platform::{
    NativeSystemProxyController, NativeTunDeviceController, PlatformCapabilities,
    SystemProxyController, SystemProxyStatus, TunBackendStatus, TunPacketIoController,
};
use serde::{Deserialize, Serialize};

use crate::dependencies::{
    install_wintun_from_directory, install_wintun_from_file, DesktopDependencyReport,
    DesktopWintunInstallSummary,
};
use crate::panel::{
    DesktopPanelConfigImportSummary, DesktopPanelEndpointSummary, DesktopPanelSnapshot,
};
use crate::persistence::DesktopPersistedSubscription;
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

    fn dependency(
        operation: &'static str,
        error: crate::dependencies::DesktopDependencyError,
    ) -> Self {
        Self {
            operation: operation.to_string(),
            kind: "dependency".to_string(),
            message: format!("{error:?}"),
        }
    }

    fn panel(operation: &'static str, error: PanelApiError) -> Self {
        Self {
            operation: operation.to_string(),
            kind: error.kind,
            message: error.message,
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
    panel_session: Option<PanelSession>,
}

impl DesktopNativeCommandService {
    pub fn new() -> Self {
        let runtime = DesktopRuntimeService::new_with_tun_controller(
            native_system_proxy_controller(),
            native_tun_controller(),
        );
        Self {
            commands: DesktopCommandService::from_runtime(runtime),
            panel_session: None,
        }
    }

    pub fn connect_panel(
        &mut self,
        endpoint: impl AsRef<str>,
        email: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<DesktopPanelSnapshot, DesktopCommandError> {
        let transport = PanelHttpTransport::default();
        let client = PanelApiClient::new(endpoint.as_ref(), &transport)
            .map_err(|error| DesktopCommandError::panel("connect-panel", error))?;
        let session = client
            .login(email.as_ref(), password.as_ref())
            .map_err(|error| DesktopCommandError::panel("connect-panel", error))?;
        let bootstrap = client
            .bootstrap(&session)
            .map_err(|error| DesktopCommandError::panel("connect-panel", error))?;
        let snapshot = DesktopPanelSnapshot::from_bootstrap(
            DesktopPanelEndpointSummary {
                panel_host: panel_host_from_api_base(&session.api_base),
                api_base_redacted: session.api_base.clone(),
                api_prefix: session.api_prefix.clone(),
                source: "login".to_string(),
            },
            &bootstrap,
        );
        self.panel_session = Some(session);
        Ok(snapshot)
    }

    pub fn import_subscription_config(
        &mut self,
        config_text: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, DesktopCommandError> {
        self.commands.import_subscription_config(config_text)
    }

    pub fn import_panel_config(
        &mut self,
        server_id: i64,
        server_name: impl Into<String>,
        config_text: impl Into<String>,
    ) -> Result<DesktopPanelConfigImportSummary, DesktopCommandError> {
        self.commands
            .import_panel_config(server_id, server_name, config_text)
    }

    pub fn import_panel_session_config(
        &mut self,
        server_id: i64,
        server_name: impl Into<String>,
    ) -> Result<DesktopPanelConfigImportSummary, DesktopCommandError> {
        let server_name = server_name.into();
        let session = self
            .panel_session
            .clone()
            .ok_or_else(|| DesktopCommandError {
                operation: "import-panel-session-config".to_string(),
                kind: "panel-session".to_string(),
                message: "请先登录面板".to_string(),
            })?;
        let transport = PanelHttpTransport::default();
        let client = PanelApiClient::new(&session.api_base, &transport)
            .map_err(|error| DesktopCommandError::panel("import-panel-session-config", error))?;
        let config_text = client
            .sing_box_config_for_server(&session, server_id, "windows", None)
            .map_err(|error| DesktopCommandError::panel("import-panel-session-config", error))?;
        self.import_panel_config(server_id, server_name, config_text)
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

    pub fn refresh_node_health(
        &mut self,
    ) -> Result<DesktopSubscriptionSummary, DesktopCommandError> {
        self.commands.refresh_node_health()
    }

    pub fn set_traffic_mode(&mut self, traffic_mode: DesktopTrafficMode) {
        self.commands.set_traffic_mode(traffic_mode);
    }

    pub fn set_listen(&mut self, listen: impl Into<String>) {
        self.commands.set_listen(listen);
    }

    pub fn persisted_subscription(&self) -> Option<DesktopPersistedSubscription> {
        self.commands.persisted_subscription()
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

    pub fn install_wintun_from_path(
        &mut self,
        source_path: impl AsRef<Path>,
    ) -> Result<DesktopWintunInstallSummary, DesktopCommandError> {
        let source_path = source_path.as_ref();
        if source_path.is_dir() {
            install_wintun_from_directory(source_path, None)
        } else {
            install_wintun_from_file(source_path, None)
        }
        .map_err(|error| DesktopCommandError::dependency("install-wintun", error))
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

fn panel_host_from_api_base(api_base: &str) -> String {
    api_base
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .filter(|host| !host.is_empty())
        .unwrap_or(api_base)
        .to_string()
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

    pub fn import_panel_config(
        &mut self,
        server_id: i64,
        server_name: impl Into<String>,
        config_text: impl Into<String>,
    ) -> Result<DesktopPanelConfigImportSummary, DesktopCommandError> {
        self.runtime
            .import_panel_config(server_id, server_name, config_text)
            .map_err(|error| DesktopCommandError::runtime("import-panel-config", error))
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

    pub fn refresh_node_health(
        &mut self,
    ) -> Result<DesktopSubscriptionSummary, DesktopCommandError> {
        self.runtime
            .refresh_node_health()
            .map_err(|error| DesktopCommandError::runtime("refresh-node-health", error))
    }

    pub fn set_traffic_mode(&mut self, traffic_mode: DesktopTrafficMode) {
        self.runtime.set_traffic_mode(traffic_mode);
    }

    pub fn set_listen(&mut self, listen: impl Into<String>) {
        self.runtime.set_listen(listen);
    }

    pub fn persisted_subscription(&self) -> Option<DesktopPersistedSubscription> {
        self.runtime.persisted_subscription()
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
    fn command_service_maps_node_health_refresh_error() {
        let platform_controller = FakeSystemProxyController::new();
        let runtime = DesktopRuntimeService::new(&platform_controller);
        let mut commands = DesktopCommandService::from_runtime(runtime);

        let error = commands
            .refresh_node_health()
            .expect_err("stopped health refresh should fail");

        assert_eq!(error.operation, "refresh-node-health");
        assert_eq!(error.kind, "managed");
        assert!(error.message.contains("managed mixed core is not running"));
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

    #[test]
    fn native_command_service_maps_missing_wintun_source_to_install_error() {
        let mut commands = DesktopNativeCommandService::new();

        let error = commands
            .install_wintun_from_path("C:\\definitely-missing-keli-wintun.dll")
            .expect_err("missing Wintun source should fail");

        assert_eq!(error.operation, "install-wintun");
        assert_eq!(error.kind, "dependency");
        assert!(error.message.contains("Wintun source DLL was not found"));
    }
}
