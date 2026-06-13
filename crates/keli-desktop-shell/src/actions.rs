use keli_desktop::{
    DesktopShellAction, DesktopShellPrimaryCommand, DesktopShellState, DesktopTrafficMode,
};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopShellUiEvent {
    Action(DesktopShellAction),
    Refresh,
    LoadPanelFixture,
    RefreshNodeHealth,
    PanelLogin {
        endpoint: String,
        email: String,
        password: String,
    },
    PanelFetchConfig {
        server_id: i64,
        server_name: String,
    },
    ImportSubscriptionConfig(String),
    PanelImportConfig {
        server_id: i64,
        server_name: String,
        config_text: String,
    },
    ImportSubscriptionUrl(String),
    UpdateSubscriptionUrl(String),
    SelectNode(String),
    SetTrafficMode(DesktopTrafficMode),
    ExportSupportBundle,
    DependencyAction(String),
    InstallWintunPath(String),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpcCommand {
    #[serde(rename = "type")]
    command_type: String,
    config_text: Option<String>,
    endpoint: Option<String>,
    email: Option<String>,
    password: Option<String>,
    subscription_url: Option<String>,
    outbound_tag: Option<String>,
    server_id: Option<i64>,
    server_name: Option<String>,
    traffic_mode: Option<DesktopTrafficMode>,
    action: Option<String>,
    source_path: Option<String>,
}

pub fn ipc_event_for_message(
    message: &str,
    shell: &DesktopShellState,
) -> Option<DesktopShellUiEvent> {
    match message.trim() {
        "primary" => primary_event(shell),
        "refresh" => Some(DesktopShellUiEvent::Refresh),
        "load-panel-fixture" => Some(DesktopShellUiEvent::LoadPanelFixture),
        "show-main-window" => Some(DesktopShellUiEvent::Action(
            DesktopShellAction::ShowMainWindow,
        )),
        "hide-main-window" => Some(DesktopShellUiEvent::Action(
            DesktopShellAction::HideMainWindow,
        )),
        "open-diagnostics" => Some(DesktopShellUiEvent::Action(
            DesktopShellAction::OpenDiagnostics,
        )),
        "export-support-bundle" => Some(DesktopShellUiEvent::ExportSupportBundle),
        "quit" => Some(DesktopShellUiEvent::Action(DesktopShellAction::RequestQuit)),
        _ => json_ipc_event(message),
    }
}

fn json_ipc_event(message: &str) -> Option<DesktopShellUiEvent> {
    let command: IpcCommand = serde_json::from_str(message).ok()?;
    match command.command_type.as_str() {
        "import-subscription-config" => command
            .config_text
            .map(DesktopShellUiEvent::ImportSubscriptionConfig),
        "panel-login" => Some(DesktopShellUiEvent::PanelLogin {
            endpoint: command.endpoint?,
            email: command.email?,
            password: command.password?,
        }),
        "panel-fetch-config" => Some(DesktopShellUiEvent::PanelFetchConfig {
            server_id: command.server_id?,
            server_name: command.server_name?,
        }),
        "panel-import-config" => Some(DesktopShellUiEvent::PanelImportConfig {
            server_id: command.server_id?,
            server_name: command.server_name?,
            config_text: command.config_text?,
        }),
        "import-subscription-url" => command
            .subscription_url
            .map(DesktopShellUiEvent::ImportSubscriptionUrl),
        "update-subscription-url" => command
            .subscription_url
            .map(DesktopShellUiEvent::UpdateSubscriptionUrl),
        "refresh-node-health" => Some(DesktopShellUiEvent::RefreshNodeHealth),
        "select-node" => command.outbound_tag.map(DesktopShellUiEvent::SelectNode),
        "set-traffic-mode" => command
            .traffic_mode
            .map(DesktopShellUiEvent::SetTrafficMode),
        "dependency-action" => command.action.map(DesktopShellUiEvent::DependencyAction),
        "install-wintun-path" => command
            .source_path
            .map(DesktopShellUiEvent::InstallWintunPath),
        _ => None,
    }
}

pub fn tray_event_for_id(id: &str, shell: &DesktopShellState) -> Option<DesktopShellUiEvent> {
    match id {
        "show-main-window" => Some(DesktopShellUiEvent::Action(
            DesktopShellAction::ShowMainWindow,
        )),
        "toggle-service" => primary_event(shell),
        "open-diagnostics" => Some(DesktopShellUiEvent::Action(
            DesktopShellAction::OpenDiagnostics,
        )),
        "quit" => Some(DesktopShellUiEvent::Action(DesktopShellAction::RequestQuit)),
        _ => None,
    }
}

fn primary_event(shell: &DesktopShellState) -> Option<DesktopShellUiEvent> {
    if !shell.primary_action.enabled {
        return None;
    }
    match shell.primary_action.command {
        DesktopShellPrimaryCommand::Start | DesktopShellPrimaryCommand::Retry => Some(
            DesktopShellUiEvent::Action(DesktopShellAction::RequestStart),
        ),
        DesktopShellPrimaryCommand::Stop => {
            Some(DesktopShellUiEvent::Action(DesktopShellAction::RequestStop))
        }
        DesktopShellPrimaryCommand::Busy | DesktopShellPrimaryCommand::Blocked => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keli_desktop::{
        DesktopDependencyReport, DesktopFirstRunReport, DesktopNodeSummary, DesktopRunState,
        DesktopShellAction, DesktopShellState, DesktopStatusSnapshot, DesktopSubscriptionSummary,
        DesktopSystemProxyDependency, DesktopTrafficMode, DesktopTunBackendDependency,
    };

    fn shell(run_state: DesktopRunState, can_start: bool) -> DesktopShellState {
        let mut shell = DesktopShellState::new(
            DesktopStatusSnapshot {
                run_state,
                traffic_mode: DesktopTrafficMode::SystemProxy,
                selected_outbound: Some("SS-READY".to_string()),
                listen: Some("127.0.0.1:7890".to_string()),
                generation: 1,
                event_count: 2,
                last_error: None,
                connection_metrics: Default::default(),
                node_health: Default::default(),
                recent_events: Vec::new(),
            },
            DesktopDependencyReport {
                first_run: DesktopFirstRunReport {
                    platform: "Windows".to_string(),
                    system_proxy_ready: can_start,
                    tun_ready: can_start,
                    can_start_system_proxy_mode: can_start,
                    can_start_tun_mode: can_start,
                    blockers: Vec::new(),
                },
                system_proxy: DesktopSystemProxyDependency {
                    state: if can_start { "ready" } else { "unavailable" }.to_string(),
                    supported: can_start,
                    ready: can_start,
                    enabled: Some(false),
                    server: None,
                    error: None,
                    action: None,
                },
                tun_backend: DesktopTunBackendDependency {
                    state: if can_start {
                        "ready"
                    } else {
                        "install-required"
                    }
                    .to_string(),
                    platform: "Windows".to_string(),
                    backend: "wintun".to_string(),
                    supported: true,
                    lifecycle_wired: true,
                    packet_io_wired: true,
                    route_takeover_wired: true,
                    driver_library_present: can_start,
                    driver_api_available: can_start,
                    driver_library_path: can_start.then(|| "C:\\Keli\\wintun.dll".to_string()),
                    driver_api_error: None,
                    install_required: !can_start,
                    searched_paths: vec!["C:\\Keli\\wintun.dll".to_string()],
                    reason: None,
                    action: None,
                },
            },
        );
        if can_start {
            shell.refresh_subscription(Some(subscription("SS-READY")));
        }
        shell
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
    fn ipc_primary_maps_stopped_shell_to_start() {
        assert_eq!(
            ipc_event_for_message("primary", &shell(DesktopRunState::Stopped, true)),
            Some(DesktopShellUiEvent::Action(
                DesktopShellAction::RequestStart
            ))
        );
    }

    #[test]
    fn ipc_primary_maps_running_shell_to_stop() {
        assert_eq!(
            ipc_event_for_message("primary", &shell(DesktopRunState::Running, true)),
            Some(DesktopShellUiEvent::Action(DesktopShellAction::RequestStop))
        );
    }

    #[test]
    fn ipc_primary_ignores_busy_or_blocked_shell() {
        assert_eq!(
            ipc_event_for_message("primary", &shell(DesktopRunState::Starting, true)),
            None
        );
        assert_eq!(
            ipc_event_for_message("primary", &shell(DesktopRunState::Stopped, false)),
            None
        );
    }

    #[test]
    fn ipc_refresh_maps_to_refresh_event() {
        assert_eq!(
            ipc_event_for_message("refresh", &shell(DesktopRunState::Stopped, true)),
            Some(DesktopShellUiEvent::Refresh)
        );
    }

    #[test]
    fn ipc_load_panel_fixture_maps_to_preview_event() {
        assert_eq!(
            ipc_event_for_message("load-panel-fixture", &shell(DesktopRunState::Stopped, true)),
            Some(DesktopShellUiEvent::LoadPanelFixture)
        );
    }

    #[test]
    fn tray_toggle_uses_current_primary_action() {
        assert_eq!(
            tray_event_for_id("toggle-service", &shell(DesktopRunState::Stopped, true)),
            Some(DesktopShellUiEvent::Action(
                DesktopShellAction::RequestStart
            ))
        );
        assert_eq!(
            tray_event_for_id("toggle-service", &shell(DesktopRunState::Running, true)),
            Some(DesktopShellUiEvent::Action(DesktopShellAction::RequestStop))
        );
    }

    #[test]
    fn subscription_ipc_import_config_json_maps_to_import_event() {
        assert_eq!(
            ipc_event_for_message(
                r#"{"type":"import-subscription-config","configText":"proxies:\n  - name: SS-READY"}"#,
                &shell(DesktopRunState::Stopped, true),
            ),
            Some(DesktopShellUiEvent::ImportSubscriptionConfig(
                "proxies:\n  - name: SS-READY".to_string()
            ))
        );
    }

    #[test]
    fn panel_import_config_json_maps_to_panel_event() {
        assert_eq!(
            ipc_event_for_message(
                r#"{"type":"panel-import-config","serverId":51,"serverName":"JP Tokyo 01","configText":"proxies:\n  - name: JP Tokyo 01"}"#,
                &shell(DesktopRunState::Stopped, true),
            ),
            Some(DesktopShellUiEvent::PanelImportConfig {
                server_id: 51,
                server_name: "JP Tokyo 01".to_string(),
                config_text: "proxies:\n  - name: JP Tokyo 01".to_string(),
            })
        );
    }

    #[test]
    fn panel_login_json_maps_to_panel_login_event() {
        assert_eq!(
            ipc_event_for_message(
                r#"{"type":"panel-login","endpoint":"https://panel.example.com","email":"user@example.com","password":"secret"}"#,
                &shell(DesktopRunState::Stopped, true),
            ),
            Some(DesktopShellUiEvent::PanelLogin {
                endpoint: "https://panel.example.com".to_string(),
                email: "user@example.com".to_string(),
                password: "secret".to_string(),
            })
        );
    }

    #[test]
    fn panel_fetch_config_json_maps_to_session_fetch_event() {
        assert_eq!(
            ipc_event_for_message(
                r#"{"type":"panel-fetch-config","serverId":51,"serverName":"JP Tokyo 01"}"#,
                &shell(DesktopRunState::Stopped, true),
            ),
            Some(DesktopShellUiEvent::PanelFetchConfig {
                server_id: 51,
                server_name: "JP Tokyo 01".to_string(),
            })
        );
    }

    #[test]
    fn subscription_ipc_import_url_json_maps_to_import_url_event() {
        assert_eq!(
            ipc_event_for_message(
                r#"{"type":"import-subscription-url","subscriptionUrl":"https://sub.example.com/panel?token=secret"}"#,
                &shell(DesktopRunState::Stopped, true),
            ),
            Some(DesktopShellUiEvent::ImportSubscriptionUrl(
                "https://sub.example.com/panel?token=secret".to_string()
            ))
        );
    }

    #[test]
    fn subscription_ipc_update_url_json_maps_to_update_url_event() {
        assert_eq!(
            ipc_event_for_message(
                r#"{"type":"update-subscription-url","subscriptionUrl":"https://sub.example.com/panel?token=secret"}"#,
                &shell(DesktopRunState::Running, true),
            ),
            Some(DesktopShellUiEvent::UpdateSubscriptionUrl(
                "https://sub.example.com/panel?token=secret".to_string()
            ))
        );
    }

    #[test]
    fn subscription_ipc_select_node_json_maps_to_select_event() {
        assert_eq!(
            ipc_event_for_message(
                r#"{"type":"select-node","outboundTag":"SS-READY"}"#,
                &shell(DesktopRunState::Stopped, true),
            ),
            Some(DesktopShellUiEvent::SelectNode("SS-READY".to_string()))
        );
    }

    #[test]
    fn subscription_ipc_refresh_node_health_json_maps_to_refresh_event() {
        assert_eq!(
            ipc_event_for_message(
                r#"{"type":"refresh-node-health"}"#,
                &shell(DesktopRunState::Running, true),
            ),
            Some(DesktopShellUiEvent::RefreshNodeHealth)
        );
    }

    #[test]
    fn subscription_ipc_traffic_mode_json_maps_to_mode_event() {
        assert_eq!(
            ipc_event_for_message(
                r#"{"type":"set-traffic-mode","trafficMode":"tun"}"#,
                &shell(DesktopRunState::Stopped, true),
            ),
            Some(DesktopShellUiEvent::SetTrafficMode(DesktopTrafficMode::Tun))
        );
    }

    #[test]
    fn support_export_ipc_maps_to_export_event() {
        assert_eq!(
            ipc_event_for_message(
                "export-support-bundle",
                &shell(DesktopRunState::Stopped, true)
            ),
            Some(DesktopShellUiEvent::ExportSupportBundle)
        );
    }

    #[test]
    fn dependency_action_ipc_maps_to_dependency_action_event() {
        assert_eq!(
            ipc_event_for_message(
                r#"{"type":"dependency-action","action":"install-wintun"}"#,
                &shell(DesktopRunState::Stopped, true),
            ),
            Some(DesktopShellUiEvent::DependencyAction(
                "install-wintun".to_string()
            ))
        );
    }

    #[test]
    fn install_wintun_path_ipc_maps_to_install_event() {
        assert_eq!(
            ipc_event_for_message(
                r#"{"type":"install-wintun-path","sourcePath":"C:\\Downloads\\wintun"}"#,
                &shell(DesktopRunState::Stopped, true),
            ),
            Some(DesktopShellUiEvent::InstallWintunPath(
                "C:\\Downloads\\wintun".to_string()
            ))
        );
    }
}
