use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::commands::{DesktopCommandError, DesktopNativeCommandService};
use crate::dependencies::{DesktopDependencyReport, DesktopWintunInstallSummary};
use crate::persistence::{DesktopPersistedSubscription, DesktopSubscriptionStore};
use crate::shell::{DesktopShellAction, DesktopShellPrimaryCommand, DesktopShellState};
use crate::status::{DesktopStatusSnapshot, DesktopTrafficMode};
use crate::subscription::{
    DesktopSubscriptionSummary, DesktopSubscriptionUrlImportSummary,
    DesktopSubscriptionUrlUpdateSummary,
};
use crate::support::DesktopSupportBundleExport;

const DEFAULT_SUBSCRIPTION_URL_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_SUBSCRIPTION_URL_MAX_BYTES: usize = 4 * 1024 * 1024;

pub trait DesktopShellCommandHost {
    fn status(&self) -> DesktopStatusSnapshot;
    fn dependency_report(&self) -> DesktopDependencyReport;
    fn start(&mut self) -> Result<DesktopStatusSnapshot, DesktopCommandError>;
    fn stop(&mut self) -> Result<DesktopStatusSnapshot, DesktopCommandError>;
    fn import_subscription_config(
        &mut self,
        config_text: String,
    ) -> Result<DesktopSubscriptionSummary, DesktopCommandError>;
    fn import_subscription_url(
        &mut self,
        url: String,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<DesktopSubscriptionUrlImportSummary, DesktopCommandError>;
    fn update_subscription_url(
        &mut self,
        url: String,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<DesktopSubscriptionUrlUpdateSummary, DesktopCommandError>;
    fn select_node(
        &mut self,
        outbound_tag: String,
    ) -> Result<DesktopSubscriptionSummary, DesktopCommandError>;
    fn refresh_node_health(&mut self) -> Result<DesktopSubscriptionSummary, DesktopCommandError>;
    fn set_traffic_mode(&mut self, traffic_mode: DesktopTrafficMode);
    fn persisted_subscription(&self) -> Option<DesktopPersistedSubscription>;
    fn export_support_bundle(&self) -> Result<DesktopSupportBundleExport, DesktopCommandError>;
    fn install_wintun_from_path(
        &mut self,
        source_path: String,
    ) -> Result<DesktopWintunInstallSummary, DesktopCommandError>;
}

impl DesktopShellCommandHost for DesktopNativeCommandService {
    fn status(&self) -> DesktopStatusSnapshot {
        self.status()
    }

    fn dependency_report(&self) -> DesktopDependencyReport {
        DesktopNativeCommandService::dependency_report()
    }

    fn start(&mut self) -> Result<DesktopStatusSnapshot, DesktopCommandError> {
        self.start()
    }

    fn stop(&mut self) -> Result<DesktopStatusSnapshot, DesktopCommandError> {
        self.stop()
    }

    fn import_subscription_config(
        &mut self,
        config_text: String,
    ) -> Result<DesktopSubscriptionSummary, DesktopCommandError> {
        self.import_subscription_config(config_text)
    }

    fn import_subscription_url(
        &mut self,
        url: String,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<DesktopSubscriptionUrlImportSummary, DesktopCommandError> {
        self.import_subscription_url(&url, timeout, max_bytes)
    }

    fn update_subscription_url(
        &mut self,
        url: String,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<DesktopSubscriptionUrlUpdateSummary, DesktopCommandError> {
        self.update_subscription_url(&url, timeout, max_bytes)
    }

    fn select_node(
        &mut self,
        outbound_tag: String,
    ) -> Result<DesktopSubscriptionSummary, DesktopCommandError> {
        self.select_node(outbound_tag)
    }

    fn refresh_node_health(&mut self) -> Result<DesktopSubscriptionSummary, DesktopCommandError> {
        self.refresh_node_health()
    }

    fn set_traffic_mode(&mut self, traffic_mode: DesktopTrafficMode) {
        self.set_traffic_mode(traffic_mode);
    }

    fn persisted_subscription(&self) -> Option<DesktopPersistedSubscription> {
        DesktopNativeCommandService::persisted_subscription(self)
    }

    fn export_support_bundle(&self) -> Result<DesktopSupportBundleExport, DesktopCommandError> {
        self.export_support_bundle()
    }

    fn install_wintun_from_path(
        &mut self,
        source_path: String,
    ) -> Result<DesktopWintunInstallSummary, DesktopCommandError> {
        self.install_wintun_from_path(source_path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopShellControllerError {
    pub operation: String,
    pub kind: String,
    pub message: String,
}

impl DesktopShellControllerError {
    fn shell_blocked(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            operation: operation.to_string(),
            kind: "shell-blocked".to_string(),
            message: message.into(),
        }
    }
}

impl From<DesktopCommandError> for DesktopShellControllerError {
    fn from(error: DesktopCommandError) -> Self {
        Self {
            operation: error.operation,
            kind: error.kind,
            message: error.message,
        }
    }
}

pub struct DesktopShellController<H: DesktopShellCommandHost> {
    host: H,
    shell: DesktopShellState,
    subscription_store: Option<DesktopSubscriptionStore>,
}

impl DesktopShellController<DesktopNativeCommandService> {
    pub fn new_native() -> Self {
        Self::new_with_subscription_store(
            DesktopNativeCommandService::new(),
            DesktopSubscriptionStore::new(DesktopSubscriptionStore::default_path()),
        )
    }
}

impl<H: DesktopShellCommandHost> DesktopShellController<H> {
    pub fn new(host: H) -> Self {
        Self::from_parts(host, None)
    }

    pub fn new_with_subscription_store(host: H, store: DesktopSubscriptionStore) -> Self {
        Self::from_parts(host, Some(store))
    }

    fn from_parts(host: H, subscription_store: Option<DesktopSubscriptionStore>) -> Self {
        let status = host.status();
        let dependencies = host.dependency_report();
        let mut controller = Self {
            host,
            shell: DesktopShellState::new(status, dependencies),
            subscription_store,
        };
        controller.restore_persisted_subscription();
        controller
    }

    pub fn snapshot(&self) -> &DesktopShellState {
        &self.shell
    }

    pub fn refresh(&mut self) -> DesktopShellState {
        let status = self.host.status();
        let dependencies = self.host.dependency_report();
        self.shell.refresh_status(status);
        self.shell.refresh_dependencies(dependencies);
        self.shell.clone()
    }

    pub fn refresh_panel_snapshot(
        &mut self,
        panel: Option<crate::panel::DesktopPanelSnapshot>,
    ) -> DesktopShellState {
        self.shell.refresh_panel(panel);
        self.shell.clone()
    }

    pub fn dispatch(
        &mut self,
        action: DesktopShellAction,
    ) -> Result<DesktopShellState, DesktopShellControllerError> {
        match action {
            DesktopShellAction::RequestStart => self.request_start(),
            DesktopShellAction::RequestStop => self.request_stop(),
            action => {
                self.shell.apply(action);
                Ok(self.shell.clone())
            }
        }
    }

    pub fn import_subscription_config(
        &mut self,
        config_text: impl Into<String>,
    ) -> Result<DesktopShellState, DesktopShellControllerError> {
        let subscription = self.host.import_subscription_config(config_text.into())?;
        self.shell.refresh_subscription(Some(subscription));
        self.shell.refresh_status(self.host.status());
        self.persist_current_subscription();
        Ok(self.shell.clone())
    }

    pub fn import_subscription_url(
        &mut self,
        url: impl Into<String>,
    ) -> Result<DesktopSubscriptionUrlImportSummary, DesktopShellControllerError> {
        let imported = self.host.import_subscription_url(
            url.into(),
            DEFAULT_SUBSCRIPTION_URL_TIMEOUT,
            DEFAULT_SUBSCRIPTION_URL_MAX_BYTES,
        )?;
        if let Some(subscription) = imported.subscription.clone() {
            self.shell.refresh_subscription(Some(subscription));
            self.shell.refresh_status(self.host.status());
            self.persist_current_subscription();
        }
        Ok(imported)
    }

    pub fn update_subscription_url(
        &mut self,
        url: impl Into<String>,
    ) -> Result<DesktopSubscriptionUrlUpdateSummary, DesktopShellControllerError> {
        let updated = self.host.update_subscription_url(
            url.into(),
            DEFAULT_SUBSCRIPTION_URL_TIMEOUT,
            DEFAULT_SUBSCRIPTION_URL_MAX_BYTES,
        )?;
        if updated.applied {
            if let Some(update) = updated.update.as_ref() {
                self.shell
                    .refresh_subscription(Some(update.subscription.clone()));
            }
            self.persist_current_subscription();
        }
        self.shell.refresh_status(updated.runtime_status.clone());
        Ok(updated)
    }

    pub fn select_node(
        &mut self,
        outbound_tag: impl Into<String>,
    ) -> Result<DesktopShellState, DesktopShellControllerError> {
        let subscription = self.host.select_node(outbound_tag.into())?;
        self.shell.refresh_subscription(Some(subscription));
        self.shell.refresh_status(self.host.status());
        self.persist_current_subscription();
        Ok(self.shell.clone())
    }

    pub fn refresh_node_health(
        &mut self,
    ) -> Result<DesktopShellState, DesktopShellControllerError> {
        let subscription = self.host.refresh_node_health()?;
        self.shell.refresh_subscription(Some(subscription));
        self.shell.refresh_status(self.host.status());
        Ok(self.shell.clone())
    }

    pub fn set_traffic_mode(&mut self, traffic_mode: DesktopTrafficMode) -> DesktopShellState {
        self.host.set_traffic_mode(traffic_mode);
        self.shell.refresh_status(self.host.status());
        self.shell.clone()
    }

    pub fn export_support_bundle(
        &self,
    ) -> Result<DesktopSupportBundleExport, DesktopShellControllerError> {
        self.host.export_support_bundle().map_err(Into::into)
    }

    pub fn install_wintun_from_path(
        &mut self,
        source_path: impl Into<String>,
    ) -> Result<DesktopWintunInstallSummary, DesktopShellControllerError> {
        let summary = self.host.install_wintun_from_path(source_path.into())?;
        self.shell.refresh_status(self.host.status());
        self.shell
            .refresh_dependencies(self.host.dependency_report());
        Ok(summary)
    }

    fn request_start(&mut self) -> Result<DesktopShellState, DesktopShellControllerError> {
        if !self.shell.primary_action.enabled
            || !matches!(
                self.shell.primary_action.command,
                DesktopShellPrimaryCommand::Start | DesktopShellPrimaryCommand::Retry
            )
        {
            return Err(DesktopShellControllerError::shell_blocked(
                "request-start",
                self.shell.primary_action.reason.clone().unwrap_or_else(|| {
                    "start is not available in the current shell state".to_string()
                }),
            ));
        }
        let status = self.host.start()?;
        self.shell.refresh_status(status);
        Ok(self.shell.clone())
    }

    fn request_stop(&mut self) -> Result<DesktopShellState, DesktopShellControllerError> {
        if !self.shell.primary_action.enabled
            || self.shell.primary_action.command != DesktopShellPrimaryCommand::Stop
        {
            return Err(DesktopShellControllerError::shell_blocked(
                "request-stop",
                self.shell.primary_action.reason.clone().unwrap_or_else(|| {
                    "stop is not available in the current shell state".to_string()
                }),
            ));
        }
        let status = self.host.stop()?;
        self.shell.refresh_status(status);
        Ok(self.shell.clone())
    }

    fn restore_persisted_subscription(&mut self) {
        let Some(store) = self.subscription_store.clone() else {
            return;
        };
        let persisted = match store.load() {
            Ok(Some(persisted)) => persisted,
            Ok(None) => return,
            Err(error) => {
                eprintln!("desktop subscription persistence load failed: {error}");
                return;
            }
        };
        match self
            .host
            .import_subscription_config(persisted.config_text.clone())
        {
            Ok(subscription) => {
                self.shell.refresh_subscription(Some(subscription));
            }
            Err(error) => {
                eprintln!(
                    "desktop subscription persistence restore failed: {} {} {}",
                    error.operation, error.kind, error.message
                );
                return;
            }
        }
        if let Some(selected_outbound) = persisted.selected_outbound {
            match self.host.select_node(selected_outbound) {
                Ok(subscription) => {
                    self.shell.refresh_subscription(Some(subscription));
                }
                Err(error) => {
                    eprintln!(
                        "desktop subscription persistence selection restore failed: {} {} {}",
                        error.operation, error.kind, error.message
                    );
                }
            }
        }
        self.shell.refresh_status(self.host.status());
    }

    fn persist_current_subscription(&self) {
        let Some(store) = self.subscription_store.as_ref() else {
            return;
        };
        let Some(subscription) = self.host.persisted_subscription() else {
            return;
        };
        if let Err(error) = store.save(&subscription) {
            eprintln!("desktop subscription persistence save failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::dependencies::{
        DesktopDependencyReport, DesktopSystemProxyDependency, DesktopTunBackendDependency,
    };
    use crate::persistence::{DesktopPersistedSubscription, DesktopSubscriptionStore};
    use crate::readiness::{DesktopBlocker, DesktopFirstRunReport};
    use crate::shell::{DesktopShellAction, DesktopShellPrimaryCommand};
    use crate::status::{
        DesktopNodeHealthSummary, DesktopRunState, DesktopStatusSnapshot, DesktopTrafficMode,
    };
    use crate::subscription::{
        DesktopNodeSummary, DesktopSubscriptionSummary, DesktopSubscriptionUpdateSummary,
        DesktopSubscriptionUrlFetchSummary, DesktopSubscriptionUrlImportSummary,
        DesktopSubscriptionUrlUpdateSummary,
    };
    use crate::support::DesktopSupportBundleExport;

    #[derive(Debug, Clone)]
    struct FakeHost {
        inner: Rc<RefCell<FakeHostState>>,
    }

    #[derive(Debug, Clone)]
    struct FakeHostState {
        status: DesktopStatusSnapshot,
        dependencies: DesktopDependencyReport,
        starts: usize,
        stops: usize,
        imports: usize,
        selects: usize,
        modes: Vec<DesktopTrafficMode>,
        subscription: DesktopSubscriptionSummary,
        subscription_config: Option<String>,
        url_imports: Vec<String>,
        url_updates: Vec<String>,
        exports: usize,
        wintun_installs: Vec<String>,
    }

    impl FakeHost {
        fn new(status: DesktopStatusSnapshot, dependencies: DesktopDependencyReport) -> Self {
            Self {
                inner: Rc::new(RefCell::new(FakeHostState {
                    status,
                    dependencies,
                    starts: 0,
                    stops: 0,
                    imports: 0,
                    selects: 0,
                    modes: Vec::new(),
                    subscription: subscription("SS-READY"),
                    subscription_config: None,
                    url_imports: Vec::new(),
                    url_updates: Vec::new(),
                    exports: 0,
                    wintun_installs: Vec::new(),
                })),
            }
        }

        fn starts(&self) -> usize {
            self.inner.borrow().starts
        }

        fn stops(&self) -> usize {
            self.inner.borrow().stops
        }

        fn imports(&self) -> usize {
            self.inner.borrow().imports
        }

        fn selects(&self) -> usize {
            self.inner.borrow().selects
        }

        fn modes(&self) -> Vec<DesktopTrafficMode> {
            self.inner.borrow().modes.clone()
        }

        fn exports(&self) -> usize {
            self.inner.borrow().exports
        }

        fn wintun_installs(&self) -> Vec<String> {
            self.inner.borrow().wintun_installs.clone()
        }

        fn url_imports(&self) -> Vec<String> {
            self.inner.borrow().url_imports.clone()
        }

        fn url_updates(&self) -> Vec<String> {
            self.inner.borrow().url_updates.clone()
        }

        fn set_status(&self, status: DesktopStatusSnapshot) {
            self.inner.borrow_mut().status = status;
        }

        fn set_dependencies(&self, dependencies: DesktopDependencyReport) {
            self.inner.borrow_mut().dependencies = dependencies;
        }
    }

    impl DesktopShellCommandHost for FakeHost {
        fn status(&self) -> DesktopStatusSnapshot {
            self.inner.borrow().status.clone()
        }

        fn dependency_report(&self) -> DesktopDependencyReport {
            self.inner.borrow().dependencies.clone()
        }

        fn start(&mut self) -> Result<DesktopStatusSnapshot, DesktopCommandError> {
            let mut inner = self.inner.borrow_mut();
            inner.starts += 1;
            inner.status = status(DesktopRunState::Running);
            Ok(inner.status.clone())
        }

        fn stop(&mut self) -> Result<DesktopStatusSnapshot, DesktopCommandError> {
            let mut inner = self.inner.borrow_mut();
            inner.stops += 1;
            inner.status = status(DesktopRunState::Stopped);
            Ok(inner.status.clone())
        }

        fn import_subscription_config(
            &mut self,
            config_text: String,
        ) -> Result<DesktopSubscriptionSummary, DesktopCommandError> {
            let mut inner = self.inner.borrow_mut();
            inner.imports += 1;
            inner.subscription_config = Some(config_text);
            inner.subscription = subscription("SS-READY");
            Ok(inner.subscription.clone())
        }

        fn import_subscription_url(
            &mut self,
            url: String,
            _timeout: std::time::Duration,
            _max_bytes: usize,
        ) -> Result<DesktopSubscriptionUrlImportSummary, DesktopCommandError> {
            let mut inner = self.inner.borrow_mut();
            inner.url_imports.push(url);
            inner.subscription_config = Some(ss_config("URL-READY"));
            inner.subscription = subscription("URL-READY");
            inner.status.selected_outbound = Some("URL-READY".to_string());
            Ok(DesktopSubscriptionUrlImportSummary {
                fetch: DesktopSubscriptionUrlFetchSummary {
                    ok: true,
                    scheme: Some("https".to_string()),
                    host: Some("sub.example.com".to_string()),
                    port: None,
                    default_port: Some(true),
                    path_present: Some(true),
                    query_present: Some(true),
                    http_status: Some(200),
                    body_bytes: Some(128),
                    elapsed_ms: Some(9),
                    error_kind: None,
                    error_detail: None,
                },
                subscription: Some(inner.subscription.clone()),
                error: None,
            })
        }

        fn update_subscription_url(
            &mut self,
            url: String,
            _timeout: std::time::Duration,
            _max_bytes: usize,
        ) -> Result<DesktopSubscriptionUrlUpdateSummary, DesktopCommandError> {
            let mut inner = self.inner.borrow_mut();
            inner.url_updates.push(url);
            let updated = url_update_summary("URL-STAY");
            inner.subscription_config = Some(ss_config("URL-STAY"));
            inner.subscription = updated
                .update
                .as_ref()
                .map(|update| update.subscription.clone())
                .unwrap_or_else(|| subscription("URL-STAY"));
            inner.status = updated.runtime_status.clone();
            Ok(updated)
        }

        fn select_node(
            &mut self,
            outbound_tag: String,
        ) -> Result<DesktopSubscriptionSummary, DesktopCommandError> {
            let mut inner = self.inner.borrow_mut();
            inner.selects += 1;
            inner.subscription = subscription(&outbound_tag);
            inner.status.selected_outbound = Some(outbound_tag);
            Ok(inner.subscription.clone())
        }

        fn refresh_node_health(
            &mut self,
        ) -> Result<DesktopSubscriptionSummary, DesktopCommandError> {
            let mut inner = self.inner.borrow_mut();
            let tag = inner
                .status
                .selected_outbound
                .clone()
                .unwrap_or_else(|| "SS-READY".to_string());
            let mut subscription = subscription(&tag);
            if let Some(node) = subscription.nodes.first_mut() {
                node.health_state = Some("healthy".to_string());
                node.tcp_available = Some(true);
                node.latency_ms = Some(42);
            }
            inner.subscription = subscription;
            inner.status.node_health = DesktopNodeHealthSummary {
                node_count: 1,
                healthy_count: 1,
                checked_count: 1,
                selected_state: Some("healthy".to_string()),
                recommended_state: Some("healthy".to_string()),
                selected_outbound_healthy: true,
                recommended_switch_ready: true,
                ..DesktopNodeHealthSummary::default()
            };
            Ok(inner.subscription.clone())
        }

        fn set_traffic_mode(&mut self, traffic_mode: DesktopTrafficMode) {
            let mut inner = self.inner.borrow_mut();
            inner.modes.push(traffic_mode);
            inner.status.traffic_mode = traffic_mode;
        }

        fn persisted_subscription(&self) -> Option<DesktopPersistedSubscription> {
            let inner = self.inner.borrow();
            inner
                .subscription_config
                .as_ref()
                .map(|config_text| DesktopPersistedSubscription {
                    config_text: config_text.clone(),
                    selected_outbound: inner.status.selected_outbound.clone(),
                })
        }

        fn export_support_bundle(&self) -> Result<DesktopSupportBundleExport, DesktopCommandError> {
            self.inner.borrow_mut().exports += 1;
            Ok(DesktopSupportBundleExport {
                format: "json".to_string(),
                byte_count: 18,
                bytes: br#"{"status":"ok"}"#.to_vec(),
            })
        }

        fn install_wintun_from_path(
            &mut self,
            source_path: String,
        ) -> Result<crate::dependencies::DesktopWintunInstallSummary, DesktopCommandError> {
            let mut inner = self.inner.borrow_mut();
            inner.wintun_installs.push(source_path.clone());
            inner.dependencies.first_run.tun_ready = true;
            inner.dependencies.first_run.can_start_tun_mode = true;
            inner.dependencies.first_run.blockers.clear();
            inner.dependencies.tun_backend.state = "ready".to_string();
            inner.dependencies.tun_backend.driver_library_present = true;
            inner.dependencies.tun_backend.driver_api_available = true;
            inner.dependencies.tun_backend.install_required = false;
            inner.dependencies.tun_backend.action = None;
            Ok(crate::dependencies::DesktopWintunInstallSummary {
                status: "ready".to_string(),
                source_kind: "directory".to_string(),
                source_path,
                source_candidates: Vec::new(),
                target_path: "C:\\Program Files\\Keli\\wintun.dll".to_string(),
                copied_bytes: 12345,
                previous_target_present: false,
                driver_api_available: true,
                ready_after_install: true,
            })
        }
    }

    fn status(run_state: DesktopRunState) -> DesktopStatusSnapshot {
        DesktopStatusSnapshot {
            run_state,
            traffic_mode: DesktopTrafficMode::SystemProxy,
            selected_outbound: Some("SS-READY".to_string()),
            listen: Some("127.0.0.1:7890".to_string()),
            generation: 9,
            event_count: 4,
            last_error: None,
            connection_metrics: Default::default(),
            node_health: Default::default(),
            recent_events: Vec::new(),
        }
    }

    fn ready_dependencies() -> DesktopDependencyReport {
        DesktopDependencyReport {
            first_run: DesktopFirstRunReport {
                platform: "Windows".to_string(),
                system_proxy_ready: true,
                tun_ready: true,
                can_start_system_proxy_mode: true,
                can_start_tun_mode: true,
                blockers: Vec::new(),
            },
            system_proxy: DesktopSystemProxyDependency {
                state: "ready".to_string(),
                supported: true,
                ready: true,
                enabled: Some(false),
                server: None,
                error: None,
                action: None,
            },
            tun_backend: DesktopTunBackendDependency {
                state: "ready".to_string(),
                platform: "Windows".to_string(),
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
                action: None,
            },
        }
    }

    fn blocked_dependencies() -> DesktopDependencyReport {
        let mut dependencies = ready_dependencies();
        dependencies.first_run.system_proxy_ready = false;
        dependencies.first_run.tun_ready = false;
        dependencies.first_run.can_start_system_proxy_mode = false;
        dependencies.first_run.can_start_tun_mode = false;
        dependencies.first_run.blockers = vec![DesktopBlocker {
            code: "system-proxy-unavailable".to_string(),
            message: "System proxy control is unavailable".to_string(),
            action: Some("check-system-proxy".to_string()),
        }];
        dependencies.system_proxy.state = "unavailable".to_string();
        dependencies.system_proxy.ready = false;
        dependencies.system_proxy.error = Some("System proxy control is unavailable".to_string());
        dependencies.tun_backend.state = "install-required".to_string();
        dependencies.tun_backend.driver_library_present = false;
        dependencies.tun_backend.driver_api_available = false;
        dependencies.tun_backend.install_required = true;
        dependencies
    }

    fn subscription(tag: &str) -> DesktopSubscriptionSummary {
        DesktopSubscriptionSummary {
            usable: true,
            supported_count: 1,
            skipped_count: 0,
            default_outbound: Some(tag.to_string()),
            selected_outbound: Some(tag.to_string()),
            recommended_outbound: Some(tag.to_string()),
            nodes: vec![DesktopNodeSummary {
                tag: tag.to_string(),
                protocol: "ss".to_string(),
                transport: "tcp".to_string(),
                security: "none".to_string(),
                udp_supported: true,
                selected: true,
                recommended: true,
                health_state: Some("unknown".to_string()),
                tcp_available: None,
                udp_available: None,
                latency_ms: None,
                health_error: None,
            }],
            skipped: Vec::new(),
        }
    }

    fn ss_config(tag: &str) -> String {
        ss_config_with_tags(&[tag])
    }

    fn ss_config_with_tags(tags: &[&str]) -> String {
        let proxies = tags
            .iter()
            .map(|tag| {
                format!(
                    r#"  - name: {tag}
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: aes-128-gcm
    password: pass"#
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!("proxies:\n{proxies}\n")
    }

    fn test_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("keli-desktop-controller-{name}-{unique}.json"))
    }

    fn url_update_summary(tag: &str) -> DesktopSubscriptionUrlUpdateSummary {
        let subscription = subscription(tag);
        DesktopSubscriptionUrlUpdateSummary {
            applied: true,
            error: None,
            fetch: DesktopSubscriptionUrlFetchSummary {
                ok: true,
                scheme: Some("https".to_string()),
                host: Some("sub.example.com".to_string()),
                port: None,
                default_port: Some(true),
                path_present: Some(true),
                query_present: Some(true),
                http_status: Some(200),
                body_bytes: Some(256),
                elapsed_ms: Some(12),
                error_kind: None,
                error_detail: None,
            },
            update: Some(DesktopSubscriptionUpdateSummary {
                applied: true,
                error: None,
                reason: "selected-outbound-preserved".to_string(),
                current_supported_count: 1,
                new_supported_count: 1,
                new_skipped_count: 0,
                current_selected_outbound: Some(tag.to_string()),
                planned_selected_outbound: Some(tag.to_string()),
                selected_outbound_preserved: true,
                selected_outbound_changed: false,
                added_tags: Vec::new(),
                removed_tags: Vec::new(),
                retained_tags: vec![tag.to_string()],
                subscription,
            }),
            runtime_status: DesktopStatusSnapshot {
                run_state: DesktopRunState::Running,
                traffic_mode: DesktopTrafficMode::SystemProxy,
                selected_outbound: Some(tag.to_string()),
                listen: Some("127.0.0.1:7890".to_string()),
                generation: 10,
                event_count: 5,
                last_error: None,
                connection_metrics: Default::default(),
                node_health: Default::default(),
                recent_events: Vec::new(),
            },
        }
    }

    #[test]
    fn shell_controller_starts_from_host_snapshot_and_dependencies() {
        let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
        let controller = DesktopShellController::new(host);

        assert_eq!(
            controller.snapshot().status.run_state,
            DesktopRunState::Stopped
        );
        assert!(!controller.snapshot().can_start);
        assert_eq!(
            controller.snapshot().primary_action.command,
            DesktopShellPrimaryCommand::Blocked
        );
        assert_eq!(
            controller.snapshot().primary_action.reason.as_deref(),
            Some("请先导入订阅，再启动 Keli")
        );
    }

    #[test]
    fn shell_controller_local_actions_do_not_call_lifecycle() {
        let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
        let observed = host.clone();
        let mut controller = DesktopShellController::new(host);

        controller
            .dispatch(DesktopShellAction::ShowMainWindow)
            .expect("show window");
        controller
            .dispatch(DesktopShellAction::OpenDiagnostics)
            .expect("open diagnostics");

        assert!(controller.snapshot().window.main_visible);
        assert!(controller.snapshot().window.diagnostics_visible);
        assert_eq!(observed.starts(), 0);
        assert_eq!(observed.stops(), 0);
    }

    #[test]
    fn shell_controller_request_start_updates_to_running() {
        let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
        let observed = host.clone();
        let mut controller = DesktopShellController::new(host);

        controller
            .import_subscription_config("proxies: []")
            .expect("import subscription");
        let shell = controller
            .dispatch(DesktopShellAction::RequestStart)
            .expect("request start");

        assert_eq!(observed.starts(), 1);
        assert_eq!(shell.status.run_state, DesktopRunState::Running);
        assert_eq!(
            shell.primary_action.command,
            DesktopShellPrimaryCommand::Stop
        );
    }

    #[test]
    fn shell_controller_request_stop_updates_to_stopped() {
        let host = FakeHost::new(status(DesktopRunState::Running), ready_dependencies());
        let observed = host.clone();
        let mut controller = DesktopShellController::new(host);

        controller
            .import_subscription_config("proxies: []")
            .expect("import subscription");
        let shell = controller
            .dispatch(DesktopShellAction::RequestStop)
            .expect("request stop");

        assert_eq!(observed.stops(), 1);
        assert_eq!(shell.status.run_state, DesktopRunState::Stopped);
        assert_eq!(
            shell.primary_action.command,
            DesktopShellPrimaryCommand::Start
        );
    }

    #[test]
    fn shell_controller_blocked_start_fails_before_calling_host() {
        let host = FakeHost::new(status(DesktopRunState::Stopped), blocked_dependencies());
        let observed = host.clone();
        let mut controller = DesktopShellController::new(host);

        controller
            .import_subscription_config("proxies: []")
            .expect("import subscription");
        let error = controller
            .dispatch(DesktopShellAction::RequestStart)
            .expect_err("blocked start should fail");

        assert_eq!(error.operation, "request-start");
        assert_eq!(error.kind, "shell-blocked");
        assert!(error
            .message
            .contains("System proxy control is unavailable"));
        assert_eq!(observed.starts(), 0);
    }

    #[test]
    fn shell_controller_refresh_reads_status_and_dependencies() {
        let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
        let observed = host.clone();
        let mut controller = DesktopShellController::new(host);
        observed.set_status(status(DesktopRunState::Running));
        observed.set_dependencies(blocked_dependencies());

        let shell = controller.refresh();

        assert_eq!(shell.status.run_state, DesktopRunState::Running);
        assert!(!shell.can_start);
        assert_eq!(
            shell.primary_action.command,
            DesktopShellPrimaryCommand::Stop
        );
    }

    #[test]
    fn shell_subscription_import_updates_shell_snapshot() {
        let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
        let observed = host.clone();
        let mut controller = DesktopShellController::new(host);

        let shell = controller
            .import_subscription_config("proxies: []")
            .expect("import subscription");

        assert_eq!(observed.imports(), 1);
        assert_eq!(
            shell
                .subscription
                .as_ref()
                .and_then(|subscription| subscription.selected_outbound.as_deref()),
            Some("SS-READY")
        );
    }

    #[test]
    fn shell_subscription_persistence_restores_selected_node() {
        let store = DesktopSubscriptionStore::new(test_path("restore-selected"));
        store
            .save(&DesktopPersistedSubscription {
                config_text: ss_config_with_tags(&["SS-OLD", "SS-READY"]),
                selected_outbound: Some("SS-READY".to_string()),
            })
            .expect("save persisted subscription");
        let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
        let observed = host.clone();

        let controller = DesktopShellController::new_with_subscription_store(host, store.clone());

        assert_eq!(observed.imports(), 1);
        assert_eq!(observed.selects(), 1);
        assert_eq!(
            controller
                .snapshot()
                .subscription
                .as_ref()
                .and_then(|subscription| subscription.selected_outbound.as_deref()),
            Some("SS-READY")
        );

        let _ = std::fs::remove_file(store.path());
    }

    #[test]
    fn shell_subscription_persistence_saves_import_and_selected_node() {
        let store = DesktopSubscriptionStore::new(test_path("persist-import-select"));
        let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
        let mut controller =
            DesktopShellController::new_with_subscription_store(host, store.clone());

        controller
            .import_subscription_config(ss_config_with_tags(&["SS-A", "SS-B"]))
            .expect("import subscription");
        controller.select_node("SS-B").expect("select node");

        let persisted = store
            .load()
            .expect("load persisted subscription")
            .expect("persisted subscription");
        assert!(persisted.config_text.contains("SS-A"));
        assert_eq!(persisted.selected_outbound.as_deref(), Some("SS-B"));

        let _ = std::fs::remove_file(store.path());
    }

    #[test]
    fn shell_subscription_persistence_saves_url_import_config() {
        let store = DesktopSubscriptionStore::new(test_path("persist-url-import"));
        let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
        let mut controller =
            DesktopShellController::new_with_subscription_store(host, store.clone());

        controller
            .import_subscription_url("https://sub.example.com/panel?token=secret")
            .expect("import subscription URL");

        let persisted = store
            .load()
            .expect("load persisted subscription")
            .expect("persisted subscription");
        assert!(persisted.config_text.contains("URL-READY"));
        assert_eq!(persisted.selected_outbound.as_deref(), Some("URL-READY"));

        let _ = std::fs::remove_file(store.path());
    }

    #[test]
    fn shell_subscription_persistence_saves_url_update_config() {
        let store = DesktopSubscriptionStore::new(test_path("persist-url-update"));
        let host = FakeHost::new(status(DesktopRunState::Running), ready_dependencies());
        let mut controller =
            DesktopShellController::new_with_subscription_store(host, store.clone());

        controller
            .update_subscription_url("https://sub.example.com/panel?token=secret")
            .expect("update subscription URL");

        let persisted = store
            .load()
            .expect("load persisted subscription")
            .expect("persisted subscription");
        assert!(persisted.config_text.contains("URL-STAY"));
        assert_eq!(persisted.selected_outbound.as_deref(), Some("URL-STAY"));

        let _ = std::fs::remove_file(store.path());
    }

    #[test]
    fn shell_subscription_url_import_calls_host_and_updates_shell_snapshot() {
        let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
        let observed = host.clone();
        let mut controller = DesktopShellController::new(host);

        let imported = controller
            .import_subscription_url("https://sub.example.com/panel?token=secret")
            .expect("import subscription URL");

        assert_eq!(
            observed.url_imports(),
            vec!["https://sub.example.com/panel?token=secret".to_string()]
        );
        assert!(imported.fetch.ok);
        assert_eq!(imported.fetch.host.as_deref(), Some("sub.example.com"));
        assert_eq!(
            controller
                .snapshot()
                .subscription
                .as_ref()
                .and_then(|subscription| subscription.selected_outbound.as_deref()),
            Some("URL-READY")
        );
        assert_eq!(
            controller.snapshot().status.selected_outbound.as_deref(),
            Some("URL-READY")
        );
    }

    #[test]
    fn shell_subscription_url_update_calls_host_and_updates_shell_snapshot() {
        let host = FakeHost::new(status(DesktopRunState::Running), ready_dependencies());
        let observed = host.clone();
        let mut controller = DesktopShellController::new(host);

        let updated = controller
            .update_subscription_url("https://sub.example.com/panel?token=secret")
            .expect("update subscription URL");

        assert_eq!(
            observed.url_updates(),
            vec!["https://sub.example.com/panel?token=secret".to_string()]
        );
        assert!(updated.applied);
        assert_eq!(
            controller.snapshot().status.selected_outbound.as_deref(),
            Some("URL-STAY")
        );
        assert_eq!(
            controller
                .snapshot()
                .subscription
                .as_ref()
                .and_then(|subscription| subscription.selected_outbound.as_deref()),
            Some("URL-STAY")
        );
    }

    #[test]
    fn controller_refresh_panel_snapshot_updates_shell_without_touching_subscription_url() {
        let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
        let mut controller = DesktopShellController::new(host);

        let snapshot = controller
            .refresh_panel_snapshot(Some(crate::panel::DesktopPanelSnapshot::fixture_ready()));

        assert!(snapshot.panel.is_some());
        assert!(snapshot.subscription.is_none());
        assert_eq!(
            snapshot.panel.as_ref().unwrap().nodes[0].name,
            "JP Tokyo 01"
        );
    }

    #[test]
    fn shell_subscription_select_node_updates_shell_snapshot() {
        let host = FakeHost::new(status(DesktopRunState::Running), ready_dependencies());
        let observed = host.clone();
        let mut controller = DesktopShellController::new(host);
        controller
            .import_subscription_config("proxies: []")
            .expect("import subscription");

        let shell = controller.select_node("SS-ALT").expect("select node");

        assert_eq!(observed.selects(), 1);
        assert_eq!(shell.status.selected_outbound.as_deref(), Some("SS-ALT"));
        assert_eq!(
            shell
                .subscription
                .as_ref()
                .and_then(|subscription| subscription.selected_outbound.as_deref()),
            Some("SS-ALT")
        );
    }

    #[test]
    fn shell_controller_refresh_node_health_updates_subscription_and_status() {
        let host = FakeHost::new(status(DesktopRunState::Running), ready_dependencies());
        let mut controller = DesktopShellController::new(host);

        let shell = controller
            .refresh_node_health()
            .expect("refresh node health");
        let node = shell
            .subscription
            .as_ref()
            .and_then(|subscription| subscription.nodes.first())
            .expect("refreshed node");

        assert_eq!(node.health_state.as_deref(), Some("healthy"));
        assert_eq!(node.tcp_available, Some(true));
        assert_eq!(node.latency_ms, Some(42));
        assert_eq!(shell.status.node_health.checked_count, 1);
    }

    #[test]
    fn shell_subscription_traffic_mode_setter_refreshes_status() {
        let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
        let observed = host.clone();
        let mut controller = DesktopShellController::new(host);

        let shell = controller.set_traffic_mode(DesktopTrafficMode::Tun);

        assert_eq!(observed.modes(), vec![DesktopTrafficMode::Tun]);
        assert_eq!(shell.status.traffic_mode, DesktopTrafficMode::Tun);
    }

    #[test]
    fn shell_support_export_calls_host_and_returns_bundle() {
        let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
        let observed = host.clone();
        let controller = DesktopShellController::new(host);

        let export = controller
            .export_support_bundle()
            .expect("export support bundle");

        assert_eq!(observed.exports(), 1);
        assert_eq!(export.format, "json");
        assert_eq!(export.bytes, br#"{"status":"ok"}"#.to_vec());
    }

    #[test]
    fn shell_controller_install_wintun_path_calls_host_and_refreshes_dependencies() {
        let host = FakeHost::new(status(DesktopRunState::Stopped), blocked_dependencies());
        let observed = host.clone();
        let mut controller = DesktopShellController::new(host);

        let summary = controller
            .install_wintun_from_path("C:\\Downloads\\wintun")
            .expect("install Wintun");

        assert_eq!(
            observed.wintun_installs(),
            vec!["C:\\Downloads\\wintun".to_string()]
        );
        assert_eq!(summary.status, "ready");
        assert!(controller.snapshot().dependencies.first_run.tun_ready);
        assert_eq!(
            controller.snapshot().dependencies.tun_backend.state,
            "ready"
        );
    }
}
