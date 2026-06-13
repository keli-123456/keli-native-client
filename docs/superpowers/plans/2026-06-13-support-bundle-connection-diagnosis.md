# Support Bundle Connection Diagnosis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `desktop_diagnosis.connection` to desktop support bundle JSON so exported diagnostics carry the same actionable connection failure category shown in the UI.

**Architecture:** Implement classification inside `crates/keli-desktop/src/support.rs`, where the support bundle is assembled from `DesktopStatusSnapshot` and `DesktopDependencyReport`. Tests exercise the public support bundle builder and parse the resulting JSON.

**Tech Stack:** Rust, serde/serde_json, `keli-desktop` unit tests, desktop shell support-export smoke.

---

## File Structure

- Modify: `crates/keli-desktop/src/support.rs`
  - Bump desktop support bundle schema version.
  - Add `desktop_diagnosis.connection` JSON construction.
  - Add classifier helpers and unit tests.
- Modify: `crates/keli-desktop/src/service.rs`
  - Extend the existing support bundle export test with a diagnosis assertion if the generic support builder tests do not cover the service path enough.

No shell UI files should change.

---

### Task 1: Add Failing Support Bundle Diagnosis Tests

**Files:**
- Modify: `crates/keli-desktop/src/support.rs`
- Test: `crates/keli-desktop/src/support.rs`

- [ ] **Step 1: Add test helpers**

Add this `#[cfg(test)]` module at the bottom of `crates/keli-desktop/src/support.rs`:

```rust
#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::dependencies::{
        DesktopSystemProxyDependency, DesktopTunBackendDependency,
    };
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

    fn support_bundle(status: &DesktopStatusSnapshot, dependencies: &DesktopDependencyReport) -> serde_json::Value {
        let export = build_desktop_support_bundle_export(
            json!({"kind": "keli_support_bundle"}),
            status,
            json!({"selected_outbound": "SS-READY"}),
            dependencies,
        )
        .expect("support bundle export");
        serde_json::from_slice(&export.bytes).expect("support bundle JSON")
    }
}
```

- [ ] **Step 2: Add port conflict diagnosis test**

Inside the same test module, add:

```rust
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
```

- [ ] **Step 3: Add node unreachable diagnosis test**

Inside the same test module, add:

```rust
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
```

- [ ] **Step 4: Add system proxy takeover diagnosis test**

Inside the same test module, add:

```rust
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
```

- [ ] **Step 5: Run the focused tests and verify they fail**

Run:

```powershell
cargo test -p keli-desktop support_bundle_includes_ -- --test-threads=1
```

Expected: FAIL because `schema_version` is still `1` and `desktop_diagnosis.connection` does not exist.

---

### Task 2: Implement Support Bundle Connection Diagnosis

**Files:**
- Modify: `crates/keli-desktop/src/support.rs`
- Test: `crates/keli-desktop/src/support.rs`

- [ ] **Step 1: Bump schema version**

Change:

```rust
pub const DESKTOP_SUPPORT_BUNDLE_SCHEMA_VERSION: u32 = 1;
```

to:

```rust
pub const DESKTOP_SUPPORT_BUNDLE_SCHEMA_VERSION: u32 = 2;
```

- [ ] **Step 2: Add classifier helpers before `build_desktop_support_bundle_export`**

Add:

```rust
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

fn system_proxy_takeover_error(
    desktop_status: &DesktopStatusSnapshot,
    desktop_dependencies: &DesktopDependencyReport,
) -> Option<String> {
    if desktop_status.traffic_mode != crate::status::DesktopTrafficMode::SystemProxy {
        return None;
    }
    if desktop_status.run_state != crate::status::DesktopRunState::Running {
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
        } else if is_node_unreachable_error(error) || desktop_status.node_health.selected_state.as_deref() == Some("failed") {
            (
                "node-unreachable",
                "节点不可用",
                format!("最后错误：{error}；请测试节点或切换推荐节点"),
                "测试节点或切换到推荐节点",
            )
        } else {
            (
                "error",
                "核心失败",
                error.to_string(),
                "查看诊断或刷新状态",
            )
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
    } else if desktop_status.run_state == crate::status::DesktopRunState::Running {
        (
            "healthy",
            "连接正常",
            format!(
                "当前节点 {}，监听 {}",
                desktop_status.selected_outbound.as_deref().unwrap_or("未选择节点"),
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
            "selected_outbound": desktop_status.selected_outbound,
            "listen": desktop_status.listen,
            "last_error": desktop_status.last_error,
            "system_proxy_enabled": desktop_dependencies.system_proxy.enabled,
            "system_proxy_server": desktop_dependencies.system_proxy.server,
            "selected_node_health": desktop_status.node_health.selected_state,
            "recommended_switch_ready": desktop_status.node_health.recommended_switch_ready
        }
    })
}
```

- [ ] **Step 3: Include diagnosis in bundle JSON**

Inside `build_desktop_support_bundle_export`, add:

```rust
let connection_diagnosis =
    connection_diagnosis_value(desktop_status, desktop_dependencies);
```

Then add this field to the `serde_json::json!` object:

```rust
"desktop_diagnosis": {
    "connection": connection_diagnosis
},
```

- [ ] **Step 4: Run focused tests**

Run:

```powershell
cargo test -p keli-desktop support_bundle_includes_ -- --test-threads=1
```

Expected: PASS.

---

### Task 3: Extend Service Export Coverage

**Files:**
- Modify: `crates/keli-desktop/src/service.rs`
- Test: `crates/keli-desktop/src/service.rs`

- [ ] **Step 1: Add service-level assertions**

In `support_bundle_export_embeds_runtime_status_and_redacts_profile`, after the dependency assertions, add:

```rust
assert_eq!(
    bundle["desktop_diagnosis"]["connection"]["level"],
    "healthy"
);
assert_eq!(
    bundle["desktop_diagnosis"]["connection"]["evidence"]["selected_outbound"],
    "SS-READY"
);
```

- [ ] **Step 2: Run service test**

Run:

```powershell
cargo test -p keli-desktop support_bundle_export_embeds_runtime_status_and_redacts_profile -- --test-threads=1
```

Expected: PASS.

---

### Task 4: Verify, Commit, And Push

**Files:**
- Modify: `crates/keli-desktop/src/support.rs`
- Modify: `crates/keli-desktop/src/service.rs`

- [ ] **Step 1: Format Rust code**

Run:

```powershell
cargo fmt
```

Expected: exit code 0.

- [ ] **Step 2: Run full `keli-desktop` tests**

Run:

```powershell
cargo test -p keli-desktop -- --test-threads=1
```

Expected: all tests pass.

- [ ] **Step 3: Run desktop shell support-export smoke**

Run:

```powershell
cargo run -q -p keli-desktop-shell -- --support-export-smoke target\desktop-support-export-smoke
```

Expected: JSON output reports a passed support export smoke.

- [ ] **Step 4: Run desktop shell smoke**

Run:

```powershell
cargo run -q -p keli-desktop-shell -- --smoke
```

Expected: JSON output contains `"status": "passed"`.

- [ ] **Step 5: Run whitespace check**

Run:

```powershell
git diff --check
```

Expected: exit code 0.

- [ ] **Step 6: Inspect changed files**

Run:

```powershell
git status --short
git diff --stat
```

Expected: implementation changes are limited to `crates/keli-desktop/src/support.rs` and `crates/keli-desktop/src/service.rs`.

- [ ] **Step 7: Commit implementation**

Run:

```powershell
git add crates/keli-desktop/src/support.rs crates/keli-desktop/src/service.rs
git commit -m "feat: export connection diagnosis in support bundle"
```

Expected: one implementation commit.

- [ ] **Step 8: Push `main`**

Run:

```powershell
git push origin main
```

Expected: remote `main` advances successfully.
