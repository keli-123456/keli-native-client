use serde::{Deserialize, Serialize};

use crate::dependencies::DesktopDependencyReport;
use crate::status::{DesktopRunState, DesktopStatusSnapshot, DesktopTrafficMode};

pub const DESKTOP_SUPPORT_BUNDLE_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopSupportBundleExport {
    pub format: String,
    pub byte_count: usize,
    pub bytes: Vec<u8>,
}

fn error_contains_any(error: &str, needles: &[&str]) -> bool {
    let error = error.to_lowercase();
    needles.iter().any(|needle| error.contains(needle))
}

fn is_port_conflict_error(error: &str) -> bool {
    error_contains_any(
        error,
        &[
            "bind",
            "listen",
            "address already in use",
            "addrinuse",
            "os error 10048",
            "端口",
            "占用",
        ],
    )
}

fn is_node_unreachable_error(error: &str) -> bool {
    error_contains_any(
        error,
        &[
            "dial",
            "connect",
            "timeout",
            "timed out",
            "refused",
            "unreachable",
            "connection reset",
            "no route",
        ],
    )
}

fn selected_node_unhealthy(desktop_status: &DesktopStatusSnapshot) -> bool {
    matches!(
        desktop_status.node_health.selected_state.as_deref(),
        Some("failed" | "unhealthy")
    )
}

fn system_proxy_takeover_error(
    desktop_status: &DesktopStatusSnapshot,
    desktop_dependencies: &DesktopDependencyReport,
) -> Option<String> {
    if desktop_status.traffic_mode != DesktopTrafficMode::SystemProxy {
        return None;
    }
    if desktop_status.run_state != DesktopRunState::Running {
        return None;
    }
    let listen = desktop_status.listen.as_deref()?;
    let proxy = &desktop_dependencies.system_proxy;
    if proxy.enabled != Some(true) {
        return Some("系统代理未接管：系统代理未启用".to_string());
    }
    let Some(server) = proxy.server.as_deref() else {
        return Some("系统代理未接管：没有代理服务器".to_string());
    };
    if server != listen {
        return Some(format!("系统代理未接管：当前指向 {server}"));
    }
    None
}

fn connection_diagnosis_value(
    desktop_status: &DesktopStatusSnapshot,
    desktop_dependencies: &DesktopDependencyReport,
) -> serde_json::Value {
    let last_error = desktop_status.last_error.as_deref();
    let (level, title, detail, action) = if let Some(error) = last_error {
        if is_port_conflict_error(error) {
            (
                "port-conflict",
                "端口被占用",
                format!("最后错误：{error}；请关闭占用端口的程序，或切换本地监听"),
                "关闭占用端口或切换本地监听",
            )
        } else if is_node_unreachable_error(error) || selected_node_unhealthy(desktop_status) {
            (
                "node-unreachable",
                "节点不可用",
                format!("最后错误：{error}；请测试节点或切换推荐节点"),
                "测试节点或切换到推荐节点",
            )
        } else {
            ("error", "核心失败", error.to_string(), "查看诊断或刷新状态")
        }
    } else if let Some(detail) = system_proxy_takeover_error(desktop_status, desktop_dependencies) {
        (
            "proxy-takeover",
            "系统代理未接管",
            detail,
            "打开代理设置或切换本地入站",
        )
    } else if !desktop_dependencies.first_run.blockers.is_empty() {
        (
            "blocked",
            "依赖阻塞",
            desktop_dependencies
                .first_run
                .blockers
                .iter()
                .map(|blocker| blocker.message.as_str())
                .collect::<Vec<_>>()
                .join("；"),
            "先处理依赖动作",
        )
    } else if desktop_status.run_state == DesktopRunState::Running {
        (
            "healthy",
            "连接正常",
            format!(
                "当前节点 {}，监听 {}",
                desktop_status
                    .selected_outbound
                    .as_deref()
                    .unwrap_or("未选择节点"),
                desktop_status.listen.as_deref().unwrap_or("未监听")
            ),
            "需要切换时先测试节点健康",
        )
    } else {
        (
            "ready",
            "可以启动",
            "连接条件已就绪".to_string(),
            "点击启动核心",
        )
    };

    serde_json::json!({
        "level": level,
        "title": title,
        "detail": detail,
        "action": action,
        "evidence": {
            "run_state": desktop_status.run_state,
            "traffic_mode": desktop_status.traffic_mode,
            "selected_outbound": desktop_status.selected_outbound.as_deref(),
            "listen": desktop_status.listen.as_deref(),
            "last_error": desktop_status.last_error.as_deref(),
            "system_proxy_enabled": desktop_dependencies.system_proxy.enabled,
            "system_proxy_server": desktop_dependencies.system_proxy.server.as_deref(),
            "selected_node_health": desktop_status.node_health.selected_state.as_deref(),
            "recommended_switch_ready": desktop_status.node_health.recommended_switch_ready
        }
    })
}

pub fn build_desktop_support_bundle_export(
    core_support_bundle: serde_json::Value,
    desktop_status: &DesktopStatusSnapshot,
    managed_runtime_status: serde_json::Value,
    desktop_dependencies: &DesktopDependencyReport,
) -> Result<DesktopSupportBundleExport, String> {
    let connection_diagnosis = connection_diagnosis_value(desktop_status, desktop_dependencies);
    let value = serde_json::json!({
        "status": "ok",
        "kind": "keli_desktop_support_bundle",
        "schema_version": DESKTOP_SUPPORT_BUNDLE_SCHEMA_VERSION,
        "desktop_status": desktop_status,
        "desktop_diagnosis": {
            "connection": connection_diagnosis
        },
        "managed_runtime_status": managed_runtime_status,
        "desktop_dependencies": desktop_dependencies,
        "core_support_bundle": core_support_bundle,
        "redaction": {
            "profile_config_text": "omitted",
            "credentials": "omitted",
            "server_endpoints": "omitted",
            "subscription_url": "scheme-host-port-flags-only"
        },
    });
    let bytes = serde_json::to_vec_pretty(&value).map_err(|error| error.to_string())?;
    Ok(DesktopSupportBundleExport {
        format: "json".to_string(),
        byte_count: bytes.len(),
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::dependencies::{DesktopSystemProxyDependency, DesktopTunBackendDependency};
    use crate::readiness::DesktopFirstRunReport;
    use crate::status::{
        DesktopConnectionMetricsSummary, DesktopNodeHealthSummary, DesktopRunState,
        DesktopStatusSnapshot, DesktopTrafficMode,
    };

    fn status_with_error(error: Option<&str>) -> DesktopStatusSnapshot {
        DesktopStatusSnapshot {
            run_state: error.map_or(DesktopRunState::Stopped, |_| DesktopRunState::Failed),
            traffic_mode: DesktopTrafficMode::SystemProxy,
            selected_outbound: Some("SS-READY".to_string()),
            listen: Some("127.0.0.1:7890".to_string()),
            generation: 7,
            event_count: 3,
            last_error: error.map(str::to_string),
            connection_metrics: DesktopConnectionMetricsSummary::default(),
            node_health: DesktopNodeHealthSummary::default(),
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
                enabled: Some(true),
                server: Some("127.0.0.1:7890".to_string()),
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

    fn support_bundle(
        status: &DesktopStatusSnapshot,
        dependencies: &DesktopDependencyReport,
    ) -> serde_json::Value {
        let export = build_desktop_support_bundle_export(
            json!({"kind": "keli_support_bundle"}),
            status,
            json!({"selected_outbound": "SS-READY"}),
            dependencies,
        )
        .expect("support bundle export");
        serde_json::from_slice(&export.bytes).expect("support bundle JSON")
    }

    #[test]
    fn support_bundle_includes_port_conflict_connection_diagnosis() {
        let status = status_with_error(Some("Managed(\"bind failed: address already in use\")"));
        let dependencies = ready_dependencies();

        let bundle = support_bundle(&status, &dependencies);
        let diagnosis = &bundle["desktop_diagnosis"]["connection"];

        assert_eq!(bundle["schema_version"], 2);
        assert_eq!(diagnosis["level"], "port-conflict");
        assert_eq!(diagnosis["title"], "端口被占用");
        assert_eq!(diagnosis["action"], "关闭占用端口或切换本地监听");
        assert_eq!(
            diagnosis["evidence"]["last_error"],
            "Managed(\"bind failed: address already in use\")"
        );
        assert_eq!(diagnosis["evidence"]["listen"], "127.0.0.1:7890");
    }

    #[test]
    fn support_bundle_includes_node_unreachable_connection_diagnosis() {
        let mut status = status_with_error(Some("Managed(\"dial timeout\")"));
        status.node_health.node_count = 2;
        status.node_health.checked_count = 2;
        status.node_health.unhealthy_count = 1;
        status.node_health.selected_state = Some("failed".to_string());
        status.node_health.recommended_switch_ready = true;
        let dependencies = ready_dependencies();

        let bundle = support_bundle(&status, &dependencies);
        let diagnosis = &bundle["desktop_diagnosis"]["connection"];

        assert_eq!(diagnosis["level"], "node-unreachable");
        assert_eq!(diagnosis["title"], "节点不可用");
        assert_eq!(diagnosis["action"], "测试节点或切换到推荐节点");
        assert_eq!(diagnosis["evidence"]["selected_node_health"], "failed");
        assert_eq!(diagnosis["evidence"]["recommended_switch_ready"], true);
    }

    #[test]
    fn support_bundle_includes_system_proxy_takeover_connection_diagnosis() {
        let mut status = status_with_error(None);
        status.run_state = DesktopRunState::Running;
        status.traffic_mode = DesktopTrafficMode::SystemProxy;
        status.listen = Some("127.0.0.1:7890".to_string());
        let mut dependencies = ready_dependencies();
        dependencies.system_proxy.enabled = Some(false);
        dependencies.system_proxy.server = None;

        let bundle = support_bundle(&status, &dependencies);
        let diagnosis = &bundle["desktop_diagnosis"]["connection"];

        assert_eq!(diagnosis["level"], "proxy-takeover");
        assert_eq!(diagnosis["title"], "系统代理未接管");
        assert_eq!(diagnosis["action"], "打开代理设置或切换本地入站");
        assert_eq!(diagnosis["evidence"]["system_proxy_enabled"], false);
        assert!(diagnosis["evidence"]["system_proxy_server"].is_null());
    }
}
