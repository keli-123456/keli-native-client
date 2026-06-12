use serde::{Deserialize, Serialize};

use crate::commands::{DesktopCommandError, DesktopNativeCommandService};
use crate::dependencies::DesktopDependencyReport;
use crate::shell::{DesktopShellAction, DesktopShellPrimaryCommand, DesktopShellState};
use crate::status::DesktopStatusSnapshot;

pub trait DesktopShellCommandHost {
    fn status(&self) -> DesktopStatusSnapshot;
    fn dependency_report(&self) -> DesktopDependencyReport;
    fn start(&mut self) -> Result<DesktopStatusSnapshot, DesktopCommandError>;
    fn stop(&mut self) -> Result<DesktopStatusSnapshot, DesktopCommandError>;
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
}

impl DesktopShellController<DesktopNativeCommandService> {
    pub fn new_native() -> Self {
        Self::new(DesktopNativeCommandService::new())
    }
}

impl<H: DesktopShellCommandHost> DesktopShellController<H> {
    pub fn new(host: H) -> Self {
        let status = host.status();
        let dependencies = host.dependency_report();
        Self {
            host,
            shell: DesktopShellState::new(status, dependencies),
        }
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
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    use crate::dependencies::{
        DesktopDependencyReport, DesktopSystemProxyDependency, DesktopTunBackendDependency,
    };
    use crate::readiness::{DesktopBlocker, DesktopFirstRunReport};
    use crate::shell::{DesktopShellAction, DesktopShellPrimaryCommand};
    use crate::status::{DesktopRunState, DesktopStatusSnapshot, DesktopTrafficMode};

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
    }

    impl FakeHost {
        fn new(status: DesktopStatusSnapshot, dependencies: DesktopDependencyReport) -> Self {
            Self {
                inner: Rc::new(RefCell::new(FakeHostState {
                    status,
                    dependencies,
                    starts: 0,
                    stops: 0,
                })),
            }
        }

        fn starts(&self) -> usize {
            self.inner.borrow().starts
        }

        fn stops(&self) -> usize {
            self.inner.borrow().stops
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

    #[test]
    fn shell_controller_starts_from_host_snapshot_and_dependencies() {
        let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
        let controller = DesktopShellController::new(host);

        assert_eq!(
            controller.snapshot().status.run_state,
            DesktopRunState::Stopped
        );
        assert!(controller.snapshot().can_start);
        assert_eq!(
            controller.snapshot().primary_action.command,
            DesktopShellPrimaryCommand::Start
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
}
