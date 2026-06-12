use std::path::Path;

use keli_platform::{
    install_wintun_library, install_wintun_library_from_source_dir, PlatformCapabilities,
    SystemProxyStatus, TunBackendStatus, WintunInstallReport,
};
use serde::{Deserialize, Serialize};

use crate::readiness::DesktopFirstRunReport;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopDependencyReport {
    pub first_run: DesktopFirstRunReport,
    pub system_proxy: DesktopSystemProxyDependency,
    pub tun_backend: DesktopTunBackendDependency,
}

impl DesktopDependencyReport {
    pub fn detect_native() -> Self {
        Self::from_platform(
            &PlatformCapabilities::detect(),
            &SystemProxyStatus::detect(),
            &TunBackendStatus::detect(),
        )
    }

    pub fn from_platform(
        capabilities: &PlatformCapabilities,
        system_proxy: &SystemProxyStatus,
        tun_backend: &TunBackendStatus,
    ) -> Self {
        Self {
            first_run: DesktopFirstRunReport::from_platform(
                capabilities,
                system_proxy,
                tun_backend,
            ),
            system_proxy: DesktopSystemProxyDependency::from_platform_status(system_proxy),
            tun_backend: DesktopTunBackendDependency::from_platform_status(tun_backend),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopSystemProxyDependency {
    pub state: String,
    pub supported: bool,
    pub ready: bool,
    pub enabled: Option<bool>,
    pub server: Option<String>,
    pub error: Option<String>,
    pub action: Option<String>,
}

impl DesktopSystemProxyDependency {
    pub fn from_platform_status(status: &SystemProxyStatus) -> Self {
        let ready = status.supported && status.error.is_none();
        Self {
            state: if ready { "ready" } else { "unavailable" }.to_string(),
            supported: status.supported,
            ready,
            enabled: status.enabled,
            server: status.server.clone(),
            error: status.error.clone(),
            action: (!ready).then(|| "check-system-proxy".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopTunBackendDependency {
    pub state: String,
    pub platform: String,
    pub backend: String,
    pub supported: bool,
    pub lifecycle_wired: bool,
    pub packet_io_wired: bool,
    pub route_takeover_wired: bool,
    pub driver_library_present: bool,
    pub driver_api_available: bool,
    pub driver_library_path: Option<String>,
    pub driver_api_error: Option<String>,
    pub install_required: bool,
    pub searched_paths: Vec<String>,
    pub reason: Option<String>,
    pub action: Option<String>,
}

impl DesktopTunBackendDependency {
    pub fn from_platform_status(status: &TunBackendStatus) -> Self {
        let ready = status.is_ready();
        let state = if ready {
            "ready"
        } else if status.install_required {
            "install-required"
        } else {
            "unavailable"
        };
        let action = if ready {
            None
        } else if status.install_required {
            Some("install-wintun".to_string())
        } else {
            Some("check-tun".to_string())
        };
        Self {
            state: state.to_string(),
            platform: format!("{:?}", status.platform),
            backend: status.backend.clone(),
            supported: status.supported,
            lifecycle_wired: status.lifecycle_wired,
            packet_io_wired: status.packet_io_wired,
            route_takeover_wired: status.route_takeover_wired,
            driver_library_present: status.driver_library_present,
            driver_api_available: status.driver_api_available,
            driver_library_path: status.driver_library_path.clone(),
            driver_api_error: status.driver_api_error.clone(),
            install_required: status.install_required,
            searched_paths: status.searched_paths.clone(),
            reason: status.reason.clone(),
            action,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopWintunInstallSummary {
    pub status: String,
    pub source_kind: String,
    pub source_path: String,
    pub source_candidates: Vec<String>,
    pub target_path: String,
    pub copied_bytes: u64,
    pub previous_target_present: bool,
    pub driver_api_available: bool,
    pub ready_after_install: bool,
}

impl DesktopWintunInstallSummary {
    pub fn from_platform_report(report: &WintunInstallReport) -> Self {
        Self {
            status: if report.ready_after_install {
                "ready"
            } else {
                "not-ready"
            }
            .to_string(),
            source_kind: report.source_kind.clone(),
            source_path: report.source_path.clone(),
            source_candidates: report.source_candidates.clone(),
            target_path: report.target_path.clone(),
            copied_bytes: report.copied_bytes,
            previous_target_present: report.previous_target_present,
            driver_api_available: report.driver_api_available,
            ready_after_install: report.ready_after_install,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesktopDependencyError {
    Platform(String),
}

impl From<keli_platform::TunDeviceError> for DesktopDependencyError {
    fn from(error: keli_platform::TunDeviceError) -> Self {
        Self::Platform(error.to_string())
    }
}

pub fn install_wintun_from_file(
    source: impl AsRef<Path>,
    target_dir: Option<&Path>,
) -> Result<DesktopWintunInstallSummary, DesktopDependencyError> {
    let report = install_wintun_library(source.as_ref(), target_dir)?;
    Ok(DesktopWintunInstallSummary::from_platform_report(&report))
}

pub fn install_wintun_from_directory(
    source_dir: impl AsRef<Path>,
    target_dir: Option<&Path>,
) -> Result<DesktopWintunInstallSummary, DesktopDependencyError> {
    let report = install_wintun_library_from_source_dir(source_dir.as_ref(), target_dir)?;
    Ok(DesktopWintunInstallSummary::from_platform_report(&report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keli_platform::{
        PlatformCapabilities, PlatformKind, SystemProxyStatus, TunBackendStatus,
        WintunInstallReport,
    };

    fn windows_capabilities() -> PlatformCapabilities {
        PlatformCapabilities {
            platform: PlatformKind::Windows,
            system_proxy: true,
            tun: true,
            secure_storage: true,
            process_supervision: true,
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

    fn tun_backend_status(ready: bool) -> TunBackendStatus {
        TunBackendStatus {
            platform: PlatformKind::Windows,
            backend: "wintun".to_string(),
            supported: true,
            lifecycle_wired: true,
            packet_io_wired: true,
            route_takeover_wired: true,
            driver_library_present: ready,
            driver_api_available: ready,
            driver_library_path: ready.then(|| "C:\\Keli\\wintun.dll".to_string()),
            driver_api_error: None,
            install_required: !ready,
            searched_paths: vec!["C:\\Keli\\wintun.dll".to_string()],
            reason: (!ready).then(|| "Wintun library was not found".to_string()),
        }
    }

    #[test]
    fn dependency_report_marks_missing_wintun_as_install_required() {
        let report = DesktopDependencyReport::from_platform(
            &windows_capabilities(),
            &system_proxy_status(),
            &tun_backend_status(false),
        );

        assert!(report.first_run.system_proxy_ready);
        assert!(!report.first_run.tun_ready);
        assert_eq!(report.tun_backend.state, "install-required");
        assert_eq!(report.tun_backend.action.as_deref(), Some("install-wintun"));
        assert!(report.tun_backend.install_required);
        assert!(!report.tun_backend.driver_api_available);
    }

    #[test]
    fn dependency_report_marks_ready_wintun_as_ready() {
        let report = DesktopDependencyReport::from_platform(
            &windows_capabilities(),
            &system_proxy_status(),
            &tun_backend_status(true),
        );

        assert!(report.first_run.can_start_tun_mode);
        assert_eq!(report.tun_backend.state, "ready");
        assert_eq!(report.tun_backend.action, None);
        assert!(report.tun_backend.driver_api_available);
        assert_eq!(
            report.tun_backend.driver_library_path.as_deref(),
            Some("C:\\Keli\\wintun.dll")
        );
    }

    #[test]
    fn wintun_install_summary_maps_platform_report() {
        let platform_report = WintunInstallReport {
            source_kind: "directory".to_string(),
            source_path: "C:\\Downloads\\wintun".to_string(),
            source_candidates: vec![
                "C:\\Downloads\\wintun\\wintun.dll".to_string(),
                "C:\\Downloads\\wintun\\bin\\amd64\\wintun.dll".to_string(),
            ],
            target_path: "C:\\Program Files\\Keli\\wintun.dll".to_string(),
            copied_bytes: 12345,
            previous_target_present: true,
            driver_api_available: true,
            ready_after_install: true,
        };

        let summary = DesktopWintunInstallSummary::from_platform_report(&platform_report);

        assert_eq!(summary.status, "ready");
        assert_eq!(summary.source_kind, "directory");
        assert_eq!(summary.target_path, "C:\\Program Files\\Keli\\wintun.dll");
        assert_eq!(summary.copied_bytes, 12345);
        assert!(summary.previous_target_present);
        assert!(summary.driver_api_available);
        assert!(summary.ready_after_install);
        assert_eq!(summary.source_candidates.len(), 2);
    }
}
