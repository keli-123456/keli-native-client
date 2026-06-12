use serde::{Deserialize, Serialize};

use crate::dependencies::DesktopDependencyReport;
use crate::status::{DesktopRunState, DesktopStatusSnapshot};

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
        let can_start = can_start_from_dependencies(&dependencies);
        let primary_action = derive_primary_action(&status, &dependencies);
        let tray_menu = derive_tray_menu(&window, &primary_action);
        Self {
            window,
            status,
            dependencies,
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

    fn rebuild_derived(&mut self) {
        self.can_start = can_start_from_dependencies(&self.dependencies);
        self.primary_action = derive_primary_action(&self.status, &self.dependencies);
        self.tray_menu = derive_tray_menu(&self.window, &self.primary_action);
    }
}

fn can_start_from_dependencies(dependencies: &DesktopDependencyReport) -> bool {
    dependencies.first_run.can_start_system_proxy_mode || dependencies.first_run.can_start_tun_mode
}

fn derive_primary_action(
    status: &DesktopStatusSnapshot,
    dependencies: &DesktopDependencyReport,
) -> DesktopShellPrimaryAction {
    let can_start = can_start_from_dependencies(dependencies);
    match status.run_state {
        DesktopRunState::Stopped => {
            if can_start {
                primary_action(
                    "start-service",
                    DesktopShellPrimaryCommand::Start,
                    "Start Keli",
                    true,
                    None,
                )
            } else {
                blocked_primary_action(dependencies)
            }
        }
        DesktopRunState::Running => primary_action(
            "stop-service",
            DesktopShellPrimaryCommand::Stop,
            "Stop Keli",
            true,
            None,
        ),
        DesktopRunState::Starting => busy_primary_action("Starting Keli"),
        DesktopRunState::Reloading => busy_primary_action("Updating Keli"),
        DesktopRunState::Stopping => busy_primary_action("Stopping Keli"),
        DesktopRunState::Failed => {
            if can_start {
                primary_action(
                    "retry-service",
                    DesktopShellPrimaryCommand::Retry,
                    "Retry Keli",
                    true,
                    status.last_error.clone(),
                )
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

fn blocked_primary_action(dependencies: &DesktopDependencyReport) -> DesktopShellPrimaryAction {
    primary_action(
        "blocked-service",
        DesktopShellPrimaryCommand::Blocked,
        "Start Blocked",
        false,
        Some(blocked_reason(dependencies)),
    )
}

fn blocked_reason(dependencies: &DesktopDependencyReport) -> String {
    if dependencies.first_run.blockers.is_empty() {
        return "No desktop traffic mode is ready".to_string();
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
                    "Hide Keli"
                } else {
                    "Show Keli"
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
                label: "Diagnostics".to_string(),
                enabled: true,
                checked: window.diagnostics_visible,
                action: DesktopShellAction::OpenDiagnostics,
            },
            DesktopShellTrayItem {
                id: "quit".to_string(),
                label: "Quit Keli".to_string(),
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

    fn status(run_state: DesktopRunState) -> DesktopStatusSnapshot {
        DesktopStatusSnapshot {
            run_state,
            traffic_mode: DesktopTrafficMode::SystemProxy,
            selected_outbound: Some("SS-READY".to_string()),
            listen: Some("127.0.0.1:7890".to_string()),
            generation: 7,
            event_count: 3,
            last_error: None,
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

    #[test]
    fn default_shell_starts_hidden_stopped_with_start_primary_action() {
        let shell = DesktopShellState::new(status(DesktopRunState::Stopped), ready_dependencies());

        assert!(!shell.window.main_visible);
        assert!(!shell.window.diagnostics_visible);
        assert!(!shell.quit_requested);
        assert_eq!(shell.status.run_state, DesktopRunState::Stopped);
        assert_eq!(
            shell.primary_action.command,
            DesktopShellPrimaryCommand::Start
        );
        assert!(shell.primary_action.enabled);
        assert!(shell.can_start);
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

        let shell = DesktopShellState::new(failed, ready_dependencies());

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
        let shell =
            DesktopShellState::new(status(DesktopRunState::Stopped), blocked_dependencies());

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
}
