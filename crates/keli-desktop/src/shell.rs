use serde::{Deserialize, Serialize};

use crate::dependencies::DesktopDependencyReport;
use crate::status::{DesktopRunState, DesktopStatusSnapshot, DesktopTrafficMode};
use crate::subscription::DesktopSubscriptionSummary;

const MISSING_SUBSCRIPTION_REASON: &str = "请先导入订阅，再启动 Keli";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesktopShellAction {
    ShowMainWindow,
    HideMainWindow,
    ToggleMainWindow,
    OpenDiagnostics,
    CloseDiagnostics,
    RequestStart,
    RequestStop,
    RequestQuit,
    CancelQuit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesktopShellPrimaryCommand {
    Start,
    Stop,
    Busy,
    Retry,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopShellPrimaryAction {
    pub id: String,
    pub command: DesktopShellPrimaryCommand,
    pub label: String,
    pub enabled: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopShellWindowState {
    pub main_visible: bool,
    pub diagnostics_visible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopShellTrayItem {
    pub id: String,
    pub label: String,
    pub enabled: bool,
    pub checked: bool,
    pub action: DesktopShellAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopShellTrayMenu {
    pub items: Vec<DesktopShellTrayItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopShellState {
    pub window: DesktopShellWindowState,
    pub status: DesktopStatusSnapshot,
    pub dependencies: DesktopDependencyReport,
    pub subscription: Option<DesktopSubscriptionSummary>,
    pub primary_action: DesktopShellPrimaryAction,
    pub tray_menu: DesktopShellTrayMenu,
    pub can_start: bool,
    pub quit_requested: bool,
}

impl DesktopShellState {
    pub fn new(status: DesktopStatusSnapshot, dependencies: DesktopDependencyReport) -> Self {
        let window = DesktopShellWindowState {
            main_visible: false,
            diagnostics_visible: false,
        };
        let can_start = can_start_for_shell(&status, &dependencies, None);
        let primary_action = derive_primary_action(&status, &dependencies, None);
        let tray_menu = derive_tray_menu(&window, &primary_action);
        Self {
            window,
            status,
            dependencies,
            subscription: None,
            primary_action,
            tray_menu,
            can_start,
            quit_requested: false,
        }
    }

    pub fn apply(&mut self, action: DesktopShellAction) {
        match action {
            DesktopShellAction::ShowMainWindow => self.window.main_visible = true,
            DesktopShellAction::HideMainWindow => self.window.main_visible = false,
            DesktopShellAction::ToggleMainWindow => {
                self.window.main_visible = !self.window.main_visible
            }
            DesktopShellAction::OpenDiagnostics => {
                self.window.main_visible = true;
                self.window.diagnostics_visible = true;
            }
            DesktopShellAction::CloseDiagnostics => self.window.diagnostics_visible = false,
            DesktopShellAction::RequestQuit => self.quit_requested = true,
            DesktopShellAction::CancelQuit => self.quit_requested = false,
            DesktopShellAction::RequestStart | DesktopShellAction::RequestStop => {}
        }
        self.rebuild_derived();
    }

    pub fn refresh_status(&mut self, status: DesktopStatusSnapshot) {
        self.status = status;
        self.rebuild_derived();
    }

    pub fn refresh_dependencies(&mut self, dependencies: DesktopDependencyReport) {
        self.dependencies = dependencies;
        self.rebuild_derived();
    }

    pub fn refresh_subscription(&mut self, subscription: Option<DesktopSubscriptionSummary>) {
        self.subscription = subscription;
        self.rebuild_derived();
    }

    fn rebuild_derived(&mut self) {
        self.can_start =
            can_start_for_shell(&self.status, &self.dependencies, self.subscription.as_ref());
        self.primary_action =
            derive_primary_action(&self.status, &self.dependencies, self.subscription.as_ref());
        self.tray_menu = derive_tray_menu(&self.window, &self.primary_action);
    }
}

fn can_start_for_shell(
    status: &DesktopStatusSnapshot,
    dependencies: &DesktopDependencyReport,
    subscription: Option<&DesktopSubscriptionSummary>,
) -> bool {
    has_usable_subscription(subscription) && can_start_for_traffic_mode(status, dependencies)
}

fn has_usable_subscription(subscription: Option<&DesktopSubscriptionSummary>) -> bool {
    subscription
        .map(|subscription| {
            subscription.usable
                && subscription.supported_count > 0
                && !subscription.nodes.is_empty()
        })
        .unwrap_or(false)
}

fn can_start_for_traffic_mode(
    status: &DesktopStatusSnapshot,
    dependencies: &DesktopDependencyReport,
) -> bool {
    match status.traffic_mode {
        DesktopTrafficMode::MixedInboundOnly => true,
        DesktopTrafficMode::SystemProxy => dependencies.first_run.can_start_system_proxy_mode,
        DesktopTrafficMode::Tun => dependencies.first_run.can_start_tun_mode,
    }
}

fn derive_primary_action(
    status: &DesktopStatusSnapshot,
    dependencies: &DesktopDependencyReport,
    subscription: Option<&DesktopSubscriptionSummary>,
) -> DesktopShellPrimaryAction {
    let has_subscription = has_usable_subscription(subscription);
    let can_start = has_subscription && can_start_for_traffic_mode(status, dependencies);
    match status.run_state {
        DesktopRunState::Stopped => {
            if can_start {
                primary_action(
                    "start-service",
                    DesktopShellPrimaryCommand::Start,
                    "启动 Keli",
                    true,
                    None,
                )
            } else if !has_subscription {
                missing_subscription_primary_action()
            } else {
                blocked_primary_action(dependencies)
            }
        }
        DesktopRunState::Running => primary_action(
            "stop-service",
            DesktopShellPrimaryCommand::Stop,
            "停止 Keli",
            true,
            None,
        ),
        DesktopRunState::Starting => busy_primary_action("正在启动"),
        DesktopRunState::Reloading => busy_primary_action("正在更新"),
        DesktopRunState::Stopping => busy_primary_action("正在停止"),
        DesktopRunState::Failed => {
            if can_start {
                primary_action(
                    "retry-service",
                    DesktopShellPrimaryCommand::Retry,
                    "重试",
                    true,
                    status.last_error.clone(),
                )
            } else if !has_subscription {
                missing_subscription_primary_action()
            } else {
                blocked_primary_action(dependencies)
            }
        }
    }
}

fn primary_action(
    id: &str,
    command: DesktopShellPrimaryCommand,
    label: &str,
    enabled: bool,
    reason: Option<String>,
) -> DesktopShellPrimaryAction {
    DesktopShellPrimaryAction {
        id: id.to_string(),
        command,
        label: label.to_string(),
        enabled,
        reason,
    }
}

fn busy_primary_action(label: &str) -> DesktopShellPrimaryAction {
    primary_action(
        "busy-service",
        DesktopShellPrimaryCommand::Busy,
        label,
        false,
        None,
    )
}

fn missing_subscription_primary_action() -> DesktopShellPrimaryAction {
    primary_action(
        "blocked-service",
        DesktopShellPrimaryCommand::Blocked,
        "启动受阻",
        false,
        Some(MISSING_SUBSCRIPTION_REASON.to_string()),
    )
}

fn blocked_primary_action(dependencies: &DesktopDependencyReport) -> DesktopShellPrimaryAction {
    primary_action(
        "blocked-service",
        DesktopShellPrimaryCommand::Blocked,
        "启动受阻",
        false,
        Some(blocked_reason(dependencies)),
    )
}

fn blocked_reason(dependencies: &DesktopDependencyReport) -> String {
    if dependencies.first_run.blockers.is_empty() {
        return "没有可用的流量模式".to_string();
    }
    dependencies
        .first_run
        .blockers
        .iter()
        .map(|blocker| blocker.message.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

fn derive_tray_menu(
    window: &DesktopShellWindowState,
    primary_action: &DesktopShellPrimaryAction,
) -> DesktopShellTrayMenu {
    DesktopShellTrayMenu {
        items: vec![
            DesktopShellTrayItem {
                id: "show-main-window".to_string(),
                label: if window.main_visible {
                    "隐藏 Keli"
                } else {
                    "显示 Keli"
                }
                .to_string(),
                enabled: true,
                checked: window.main_visible,
                action: if window.main_visible {
                    DesktopShellAction::HideMainWindow
                } else {
                    DesktopShellAction::ShowMainWindow
                },
            },
            DesktopShellTrayItem {
                id: "toggle-service".to_string(),
                label: primary_action.label.clone(),
                enabled: primary_action.enabled,
                checked: primary_action.command == DesktopShellPrimaryCommand::Stop,
                action: match primary_action.command {
                    DesktopShellPrimaryCommand::Stop => DesktopShellAction::RequestStop,
                    DesktopShellPrimaryCommand::Start | DesktopShellPrimaryCommand::Retry => {
                        DesktopShellAction::RequestStart
                    }
                    DesktopShellPrimaryCommand::Busy | DesktopShellPrimaryCommand::Blocked => {
                        DesktopShellAction::RequestStart
                    }
                },
            },
            DesktopShellTrayItem {
                id: "open-diagnostics".to_string(),
                label: "诊断".to_string(),
                enabled: true,
                checked: window.diagnostics_visible,
                action: DesktopShellAction::OpenDiagnostics,
            },
            DesktopShellTrayItem {
                id: "quit".to_string(),
                label: "退出 Keli".to_string(),
                enabled: true,
                checked: false,
                action: DesktopShellAction::RequestQuit,
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependencies::{
        DesktopDependencyReport, DesktopSystemProxyDependency, DesktopTunBackendDependency,
    };
    use crate::readiness::{DesktopBlocker, DesktopFirstRunReport};
    use crate::status::{DesktopRunState, DesktopStatusSnapshot, DesktopTrafficMode};
    use crate::subscription::{DesktopNodeSummary, DesktopSubscriptionSummary};

    fn status(run_state: DesktopRunState) -> DesktopStatusSnapshot {
        DesktopStatusSnapshot {
            run_state,
            traffic_mode: DesktopTrafficMode::SystemProxy,
            selected_outbound: Some("SS-READY".to_string()),
            listen: Some("127.0.0.1:7890".to_string()),
            generation: 7,
            event_count: 3,
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
        DesktopDependencyReport {
            first_run: DesktopFirstRunReport {
                platform: "Windows".to_string(),
                system_proxy_ready: false,
                tun_ready: false,
                can_start_system_proxy_mode: false,
                can_start_tun_mode: false,
                blockers: vec![
                    DesktopBlocker {
                        code: "system-proxy-unavailable".to_string(),
                        message: "System proxy control is unavailable".to_string(),
                        action: Some("check-system-proxy".to_string()),
                    },
                    DesktopBlocker {
                        code: "wintun-missing".to_string(),
                        message: "Wintun library was not found".to_string(),
                        action: Some("install-wintun".to_string()),
                    },
                ],
            },
            system_proxy: DesktopSystemProxyDependency {
                state: "unavailable".to_string(),
                supported: false,
                ready: false,
                enabled: None,
                server: None,
                error: Some("System proxy control is unavailable".to_string()),
                action: Some("check-system-proxy".to_string()),
            },
            tun_backend: DesktopTunBackendDependency {
                state: "install-required".to_string(),
                platform: "Windows".to_string(),
                backend: "wintun".to_string(),
                supported: true,
                lifecycle_wired: true,
                packet_io_wired: true,
                route_takeover_wired: true,
                driver_library_present: false,
                driver_api_available: false,
                driver_library_path: None,
                driver_api_error: None,
                install_required: true,
                searched_paths: vec!["C:\\Keli\\wintun.dll".to_string()],
                reason: Some("Wintun library was not found".to_string()),
                action: Some("install-wintun".to_string()),
            },
        }
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

    #[test]
    fn default_shell_requires_subscription_before_start() {
        let shell = DesktopShellState::new(status(DesktopRunState::Stopped), ready_dependencies());

        assert!(!shell.window.main_visible);
        assert!(!shell.window.diagnostics_visible);
        assert!(!shell.quit_requested);
        assert_eq!(shell.subscription, None);
        assert_eq!(shell.status.run_state, DesktopRunState::Stopped);
        assert_eq!(
            shell.primary_action.command,
            DesktopShellPrimaryCommand::Blocked
        );
        assert!(!shell.primary_action.enabled);
        assert!(!shell.can_start);
        assert_eq!(
            shell.primary_action.reason.as_deref(),
            Some("请先导入订阅，再启动 Keli")
        );
    }

    #[test]
    fn primary_action_copy_is_localized_for_chinese_desktop_ui() {
        let blocked =
            DesktopShellState::new(status(DesktopRunState::Stopped), ready_dependencies());
        assert_eq!(blocked.primary_action.label, "启动受阻");
        assert_eq!(
            blocked.primary_action.reason.as_deref(),
            Some("请先导入订阅，再启动 Keli")
        );

        let mut startable =
            DesktopShellState::new(status(DesktopRunState::Stopped), ready_dependencies());
        startable.refresh_subscription(Some(subscription("SS-READY")));
        assert_eq!(startable.primary_action.label, "启动 Keli");

        let running =
            DesktopShellState::new(status(DesktopRunState::Running), ready_dependencies());
        assert_eq!(running.primary_action.label, "停止 Keli");
    }

    #[test]
    fn window_actions_update_visibility_without_touching_runtime_status() {
        let mut shell =
            DesktopShellState::new(status(DesktopRunState::Stopped), ready_dependencies());
        let original_status = shell.status.clone();

        shell.apply(DesktopShellAction::ShowMainWindow);
        assert!(shell.window.main_visible);
        shell.apply(DesktopShellAction::HideMainWindow);
        assert!(!shell.window.main_visible);
        shell.apply(DesktopShellAction::ToggleMainWindow);
        assert!(shell.window.main_visible);
        shell.apply(DesktopShellAction::RequestQuit);
        assert!(shell.quit_requested);
        shell.apply(DesktopShellAction::CancelQuit);
        assert!(!shell.quit_requested);

        assert_eq!(shell.status, original_status);
    }

    #[test]
    fn running_status_maps_primary_action_to_stop() {
        let shell = DesktopShellState::new(status(DesktopRunState::Running), ready_dependencies());

        assert_eq!(
            shell.primary_action.command,
            DesktopShellPrimaryCommand::Stop
        );
        assert!(shell.primary_action.enabled);
        assert_eq!(
            shell
                .tray_menu
                .items
                .iter()
                .find(|item| item.id == "toggle-service")
                .map(|item| item.action),
            Some(DesktopShellAction::RequestStop)
        );
    }

    #[test]
    fn transient_status_maps_primary_action_to_disabled_busy() {
        for run_state in [
            DesktopRunState::Starting,
            DesktopRunState::Reloading,
            DesktopRunState::Stopping,
        ] {
            let shell = DesktopShellState::new(status(run_state), ready_dependencies());

            assert_eq!(
                shell.primary_action.command,
                DesktopShellPrimaryCommand::Busy
            );
            assert!(!shell.primary_action.enabled);
        }
    }

    #[test]
    fn failed_status_allows_retry_when_dependencies_are_ready() {
        let mut failed = status(DesktopRunState::Failed);
        failed.last_error = Some("Managed(\"bind failed\")".to_string());

        let mut shell = DesktopShellState::new(failed, ready_dependencies());
        shell.refresh_subscription(Some(subscription("SS-READY")));

        assert_eq!(
            shell.primary_action.command,
            DesktopShellPrimaryCommand::Retry
        );
        assert!(shell.primary_action.enabled);
        assert_eq!(
            shell.primary_action.reason.as_deref(),
            Some("Managed(\"bind failed\")")
        );
    }

    #[test]
    fn blocked_dependencies_disable_primary_start() {
        let mut shell =
            DesktopShellState::new(status(DesktopRunState::Stopped), blocked_dependencies());
        shell.refresh_subscription(Some(subscription("SS-READY")));

        assert_eq!(
            shell.primary_action.command,
            DesktopShellPrimaryCommand::Blocked
        );
        assert!(!shell.primary_action.enabled);
        assert!(!shell.can_start);
        assert!(shell
            .primary_action
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("System proxy control is unavailable"));
    }

    #[test]
    fn local_inbound_mode_can_start_when_proxy_and_tun_are_blocked() {
        let mut local = status(DesktopRunState::Stopped);
        local.traffic_mode = DesktopTrafficMode::MixedInboundOnly;

        let mut shell = DesktopShellState::new(local, blocked_dependencies());
        shell.refresh_subscription(Some(subscription("SS-READY")));

        assert_eq!(
            shell.primary_action.command,
            DesktopShellPrimaryCommand::Start
        );
        assert!(shell.primary_action.enabled);
        assert!(shell.can_start);
    }

    #[test]
    fn tun_mode_stays_blocked_when_tun_dependency_is_blocked() {
        let mut tun = status(DesktopRunState::Stopped);
        tun.traffic_mode = DesktopTrafficMode::Tun;

        let mut shell = DesktopShellState::new(tun, blocked_dependencies());
        shell.refresh_subscription(Some(subscription("SS-READY")));

        assert_eq!(
            shell.primary_action.command,
            DesktopShellPrimaryCommand::Blocked
        );
        assert!(!shell.primary_action.enabled);
        assert!(!shell.can_start);
    }

    #[test]
    fn tray_menu_exposes_stable_shell_item_ids() {
        let shell = DesktopShellState::new(status(DesktopRunState::Stopped), ready_dependencies());
        let ids: Vec<&str> = shell
            .tray_menu
            .items
            .iter()
            .map(|item| item.id.as_str())
            .collect();

        assert_eq!(
            ids,
            vec![
                "show-main-window",
                "toggle-service",
                "open-diagnostics",
                "quit"
            ]
        );
    }

    #[test]
    fn refresh_recomputes_primary_action_while_preserving_window_state() {
        let mut shell =
            DesktopShellState::new(status(DesktopRunState::Stopped), ready_dependencies());
        shell.apply(DesktopShellAction::ShowMainWindow);

        shell.refresh_status(status(DesktopRunState::Running));

        assert!(shell.window.main_visible);
        assert_eq!(
            shell.primary_action.command,
            DesktopShellPrimaryCommand::Stop
        );
    }

    #[test]
    fn shell_subscription_refresh_stores_latest_summary() {
        let mut shell =
            DesktopShellState::new(status(DesktopRunState::Stopped), ready_dependencies());

        shell.refresh_subscription(Some(subscription("SS-READY")));

        assert_eq!(
            shell
                .subscription
                .as_ref()
                .and_then(|subscription| subscription.selected_outbound.as_deref()),
            Some("SS-READY")
        );
        assert_eq!(
            shell.primary_action.command,
            DesktopShellPrimaryCommand::Start
        );
        assert!(shell.primary_action.enabled);
        assert!(shell.can_start);
    }
}
