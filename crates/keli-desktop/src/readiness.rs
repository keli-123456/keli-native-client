use keli_platform::{PlatformCapabilities, SystemProxyStatus, TunBackendStatus};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopBlocker {
    pub code: String,
    pub message: String,
    pub action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopFirstRunReport {
    pub platform: String,
    pub system_proxy_ready: bool,
    pub tun_ready: bool,
    pub can_start_system_proxy_mode: bool,
    pub can_start_tun_mode: bool,
    pub blockers: Vec<DesktopBlocker>,
}

impl DesktopFirstRunReport {
    pub fn from_platform(
        capabilities: &PlatformCapabilities,
        system_proxy: &SystemProxyStatus,
        tun_backend: &TunBackendStatus,
    ) -> Self {
        let system_proxy_ready =
            capabilities.system_proxy && system_proxy.supported && system_proxy.error.is_none();
        let tun_ready = capabilities.tun && tun_backend.is_ready();
        let mut blockers = Vec::new();

        if !system_proxy_ready {
            blockers.push(DesktopBlocker {
                code: "system-proxy-unavailable".to_string(),
                message: system_proxy.error.clone().unwrap_or_else(|| {
                    "System proxy control is unavailable on this machine".to_string()
                }),
                action: Some("check-system-proxy".to_string()),
            });
        }

        if !tun_ready {
            let code = if tun_backend.install_required {
                "wintun-missing"
            } else {
                "tun-unavailable"
            };
            blockers.push(DesktopBlocker {
                code: code.to_string(),
                message: tun_backend
                    .reason
                    .clone()
                    .unwrap_or_else(|| "TUN mode is unavailable on this machine".to_string()),
                action: Some(if tun_backend.install_required {
                    "install-wintun".to_string()
                } else {
                    "check-tun".to_string()
                }),
            });
        }

        Self {
            platform: format!("{:?}", capabilities.platform),
            system_proxy_ready,
            tun_ready,
            can_start_system_proxy_mode: system_proxy_ready,
            can_start_tun_mode: tun_ready,
            blockers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keli_platform::PlatformKind;

    fn windows_capabilities() -> PlatformCapabilities {
        PlatformCapabilities {
            platform: PlatformKind::Windows,
            system_proxy: true,
            tun: true,
            secure_storage: true,
            process_supervision: true,
        }
    }

    fn system_proxy_ready() -> SystemProxyStatus {
        SystemProxyStatus {
            supported: true,
            enabled: Some(false),
            server: None,
            error: None,
        }
    }

    fn tun_backend(ready: bool) -> TunBackendStatus {
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
    fn ready_windows_machine_allows_system_proxy_and_tun_modes() {
        let report = DesktopFirstRunReport::from_platform(
            &windows_capabilities(),
            &system_proxy_ready(),
            &tun_backend(true),
        );

        assert_eq!(report.platform, "Windows");
        assert!(report.system_proxy_ready);
        assert!(report.tun_ready);
        assert!(report.can_start_system_proxy_mode);
        assert!(report.can_start_tun_mode);
        assert!(report.blockers.is_empty());
    }

    #[test]
    fn missing_wintun_blocks_only_tun_mode() {
        let report = DesktopFirstRunReport::from_platform(
            &windows_capabilities(),
            &system_proxy_ready(),
            &tun_backend(false),
        );

        assert!(report.system_proxy_ready);
        assert!(!report.tun_ready);
        assert!(report.can_start_system_proxy_mode);
        assert!(!report.can_start_tun_mode);
        assert_eq!(report.blockers[0].code, "wintun-missing");
        assert_eq!(report.blockers[0].action.as_deref(), Some("install-wintun"));
    }
}
