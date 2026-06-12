use keli_desktop::{DesktopShellAction, DesktopShellPrimaryCommand, DesktopShellState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopShellUiEvent {
    Action(DesktopShellAction),
    Refresh,
}

pub fn ipc_event_for_message(
    message: &str,
    shell: &DesktopShellState,
) -> Option<DesktopShellUiEvent> {
    match message.trim() {
        "primary" => primary_event(shell),
        "refresh" => Some(DesktopShellUiEvent::Refresh),
        "show-main-window" => Some(DesktopShellUiEvent::Action(
            DesktopShellAction::ShowMainWindow,
        )),
        "hide-main-window" => Some(DesktopShellUiEvent::Action(
            DesktopShellAction::HideMainWindow,
        )),
        "open-diagnostics" => Some(DesktopShellUiEvent::Action(
            DesktopShellAction::OpenDiagnostics,
        )),
        "quit" => Some(DesktopShellUiEvent::Action(DesktopShellAction::RequestQuit)),
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
        DesktopDependencyReport, DesktopFirstRunReport, DesktopRunState, DesktopShellAction,
        DesktopShellState, DesktopStatusSnapshot, DesktopSystemProxyDependency, DesktopTrafficMode,
        DesktopTunBackendDependency,
    };

    fn shell(run_state: DesktopRunState, can_start: bool) -> DesktopShellState {
        DesktopShellState::new(
            DesktopStatusSnapshot {
                run_state,
                traffic_mode: DesktopTrafficMode::SystemProxy,
                selected_outbound: Some("SS-READY".to_string()),
                listen: Some("127.0.0.1:7890".to_string()),
                generation: 1,
                event_count: 2,
                last_error: None,
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
        )
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
}
