# Windows Desktop MVP Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the first desktop-facing Rust crate that gives the future Windows UI typed status, readiness, subscription, and runtime-control DTOs without duplicating core logic.

**Architecture:** Create a new `keli-desktop` workspace crate as the desktop backend boundary. It will reuse `keli-client-core` for subscription and runtime state and `keli-platform` for Windows capability, system proxy, and Wintun evidence. This plan intentionally avoids visual shell work; tray/window implementation gets a separate plan after this backend boundary is stable.

**Tech Stack:** Rust 2021, Cargo workspace, `serde` for UI DTO serialization, existing `keli-client-core` and `keli-platform` crates.

---

## Scope Check

The MVP spec includes backend boundaries, visible desktop UI, tray behavior, packaging, and manual Windows smoke checks. Those are related but not small enough for one safe implementation pass. This plan implements the backend foundation only:

- Workspace crate and module boundaries.
- Desktop status DTOs.
- First-run readiness summary.
- Subscription and node DTOs.
- A non-visual runtime service state wrapper that can start, reload, and stop the existing client-core state model.

The following are explicitly deferred to later implementation plans:

- Tray icon and main window technology choice.
- Actual packaged GUI app.
- Direct managed mixed core extraction from `keli-cli`.
- Installer and update flow.

## File Structure

- Modify: `Cargo.toml`
  - Add `crates/keli-desktop` to the workspace members.
- Create: `crates/keli-desktop/Cargo.toml`
  - Define the desktop backend crate and dependencies.
- Create: `crates/keli-desktop/src/lib.rs`
  - Public module surface and re-exports.
- Create: `crates/keli-desktop/src/status.rs`
  - UI-safe runtime state labels and status snapshots.
- Create: `crates/keli-desktop/src/readiness.rs`
  - First-run readiness and dependency blocker DTOs.
- Create: `crates/keli-desktop/src/subscription.rs`
  - Subscription and node summaries for desktop setup screens.
- Create: `crates/keli-desktop/src/service.rs`
  - In-memory desktop runtime service wrapper around `ClientRuntime`.

## Task 1: Workspace Crate Skeleton

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/keli-desktop/Cargo.toml`
- Create: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Write the failing crate smoke test**

Create `crates/keli-desktop/src/lib.rs` with:

```rust
pub mod readiness;
pub mod service;
pub mod status;
pub mod subscription;

pub use readiness::{DesktopBlocker, DesktopFirstRunReport};
pub use service::{DesktopRuntimeCommand, DesktopRuntimeService};
pub use status::{DesktopRunState, DesktopStatusSnapshot, DesktopTrafficMode};
pub use subscription::{DesktopNodeSummary, DesktopSubscriptionSummary};

#[cfg(test)]
mod tests {
    #[test]
    fn desktop_crate_exports_public_modules() {
        assert_eq!("keli-desktop", env!("CARGO_PKG_NAME"));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p keli-desktop desktop_crate_exports_public_modules -- --exact`

Expected: FAIL because `keli-desktop` is not yet a workspace package and its modules do not exist.

- [ ] **Step 3: Add the crate to the workspace**

Add `"crates/keli-desktop",` to the root `Cargo.toml` workspace members:

```toml
members = [
    "crates/keli-client-core",
    "crates/keli-net-core",
    "crates/keli-platform",
    "crates/keli-protocol",
    "crates/keli-cli",
    "crates/keli-desktop",
]
```

Create `crates/keli-desktop/Cargo.toml`:

```toml
[package]
name = "keli-desktop"
edition.workspace = true
license.workspace = true
version.workspace = true

[dependencies]
keli-client-core.workspace = true
keli-platform.workspace = true
serde.workspace = true
```

Create empty module files so the crate compiles:

```rust
// crates/keli-desktop/src/readiness.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopBlocker;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopFirstRunReport;
```

```rust
// crates/keli-desktop/src/service.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopRuntimeCommand {}

#[derive(Debug, Default)]
pub struct DesktopRuntimeService;
```

```rust
// crates/keli-desktop/src/status.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopRunState {
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopTrafficMode {
    SystemProxy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopStatusSnapshot;
```

```rust
// crates/keli-desktop/src/subscription.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopNodeSummary;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopSubscriptionSummary;
```

- [ ] **Step 4: Run the smoke test**

Run: `cargo test -p keli-desktop desktop_crate_exports_public_modules -- --exact`

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```powershell
git add Cargo.toml Cargo.lock crates/keli-desktop
git commit -m "Add desktop backend crate"
```

## Task 2: Desktop Status DTOs

**Files:**
- Modify: `crates/keli-desktop/src/status.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Write failing status mapping tests**

Replace `crates/keli-desktop/src/status.rs` with:

```rust
use keli_client_core::{ClientErrorKind, ClientRuntime, RuntimeStatus};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesktopRunState {
    Stopped,
    Starting,
    Running,
    Reloading,
    Stopping,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesktopTrafficMode {
    SystemProxy,
    Tun,
    MixedInboundOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopStatusSnapshot {
    pub run_state: DesktopRunState,
    pub traffic_mode: DesktopTrafficMode,
    pub selected_outbound: Option<String>,
    pub listen: Option<String>,
    pub generation: u64,
    pub event_count: usize,
    pub last_error: Option<String>,
}

impl DesktopStatusSnapshot {
    pub fn from_client_runtime(runtime: &ClientRuntime, traffic_mode: DesktopTrafficMode) -> Self {
        let _ = runtime;
        Self {
            run_state: DesktopRunState::Stopped,
            traffic_mode,
            selected_outbound: None,
            listen: None,
            generation: 0,
            event_count: 0,
            last_error: None,
        }
    }
}

fn error_label(error: &ClientErrorKind) -> String {
    format!("{error:?}")
}

fn run_state(status: &RuntimeStatus) -> DesktopRunState {
    match status {
        RuntimeStatus::Stopped => DesktopRunState::Stopped,
        RuntimeStatus::Starting => DesktopRunState::Starting,
        RuntimeStatus::Running { .. } => DesktopRunState::Running,
        RuntimeStatus::Reloading { .. } => DesktopRunState::Reloading,
        RuntimeStatus::Stopping { .. } => DesktopRunState::Stopping,
        RuntimeStatus::Failed(_) => DesktopRunState::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keli_client_core::RuntimeConfig;

    fn ss_config(tag: &str) -> String {
        format!(
            r#"
proxies:
  - name: {tag}
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#
        )
    }

    #[test]
    fn stopped_runtime_maps_to_stopped_desktop_status() {
        let runtime = ClientRuntime::default();

        let status = DesktopStatusSnapshot::from_client_runtime(
            &runtime,
            DesktopTrafficMode::SystemProxy,
        );

        assert_eq!(status.run_state, DesktopRunState::Stopped);
        assert_eq!(status.traffic_mode, DesktopTrafficMode::SystemProxy);
        assert_eq!(status.selected_outbound, None);
        assert_eq!(status.listen, None);
        assert_eq!(status.generation, 0);
        assert_eq!(status.last_error, None);
    }

    #[test]
    fn running_runtime_exposes_selected_outbound_and_listen_address() {
        let mut runtime = ClientRuntime::default();
        runtime
            .start(RuntimeConfig::new(
                ss_config("SS-READY"),
                Some("SS-READY"),
                "127.0.0.1:7890",
            ))
            .expect("start runtime");

        let status = DesktopStatusSnapshot::from_client_runtime(
            &runtime,
            DesktopTrafficMode::Tun,
        );

        assert_eq!(status.run_state, DesktopRunState::Running);
        assert_eq!(status.traffic_mode, DesktopTrafficMode::Tun);
        assert_eq!(status.selected_outbound.as_deref(), Some("SS-READY"));
        assert_eq!(status.listen.as_deref(), Some("127.0.0.1:7890"));
        assert_eq!(status.generation, 1);
        assert!(status.event_count >= 2);
    }
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test -p keli-desktop status -- --test-threads=1`

Expected: FAIL because `running_runtime_exposes_selected_outbound_and_listen_address` still receives the stopped stub.

- [ ] **Step 3: Implement the status mapper**

Replace `from_client_runtime` with:

```rust
    pub fn from_client_runtime(runtime: &ClientRuntime, traffic_mode: DesktopTrafficMode) -> Self {
        let (selected_outbound, listen) = match runtime.status() {
            RuntimeStatus::Running {
                selected_outbound,
                listen,
                ..
            } => (Some(selected_outbound.clone()), Some(listen.clone())),
            _ => (None, None),
        };
        Self {
            run_state: run_state(runtime.status()),
            traffic_mode,
            selected_outbound,
            listen,
            generation: runtime.generation(),
            event_count: runtime.event_count(),
            last_error: runtime.last_error().map(error_label),
        }
    }
```

- [ ] **Step 4: Run status tests**

Run: `cargo test -p keli-desktop status -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```powershell
git add crates/keli-desktop/src/status.rs crates/keli-desktop/src/lib.rs
git commit -m "Add desktop status DTOs"
```

## Task 3: First-Run Readiness DTOs

**Files:**
- Modify: `crates/keli-desktop/src/readiness.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Write failing readiness tests**

Replace `crates/keli-desktop/src/readiness.rs` with:

```rust
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
        let _ = (capabilities, system_proxy, tun_backend);
        Self {
            platform: "Unknown".to_string(),
            system_proxy_ready: false,
            tun_ready: false,
            can_start_system_proxy_mode: false,
            can_start_tun_mode: false,
            blockers: Vec::new(),
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
        assert_eq!(
            report.blockers[0].action.as_deref(),
            Some("install-wintun")
        );
    }
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test -p keli-desktop readiness -- --test-threads=1`

Expected: FAIL because `ready_windows_machine_allows_system_proxy_and_tun_modes` still receives the unavailable stub.

- [ ] **Step 3: Implement readiness mapping**

Implement `from_platform` with:

```rust
    pub fn from_platform(
        capabilities: &PlatformCapabilities,
        system_proxy: &SystemProxyStatus,
        tun_backend: &TunBackendStatus,
    ) -> Self {
        let system_proxy_ready = capabilities.system_proxy && system_proxy.supported && system_proxy.error.is_none();
        let tun_ready = capabilities.tun && tun_backend.is_ready();
        let mut blockers = Vec::new();

        if !system_proxy_ready {
            blockers.push(DesktopBlocker {
                code: "system-proxy-unavailable".to_string(),
                message: system_proxy
                    .error
                    .clone()
                    .unwrap_or_else(|| "System proxy control is unavailable on this machine".to_string()),
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
```

- [ ] **Step 4: Run readiness tests**

Run: `cargo test -p keli-desktop readiness -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```powershell
git add crates/keli-desktop/src/readiness.rs crates/keli-desktop/src/lib.rs
git commit -m "Add desktop first-run readiness DTOs"
```

## Task 4: Subscription DTOs

**Files:**
- Modify: `crates/keli-desktop/src/subscription.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Write failing subscription summary tests**

Replace `crates/keli-desktop/src/subscription.rs` with:

```rust
use keli_client_core::SubscriptionPreflightReport;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopNodeSummary {
    pub tag: String,
    pub protocol: String,
    pub transport: String,
    pub security: String,
    pub udp_supported: bool,
    pub selected: bool,
    pub recommended: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopSubscriptionSummary {
    pub usable: bool,
    pub supported_count: usize,
    pub skipped_count: usize,
    pub default_outbound: Option<String>,
    pub selected_outbound: Option<String>,
    pub recommended_outbound: Option<String>,
    pub nodes: Vec<DesktopNodeSummary>,
    pub skipped: Vec<String>,
}

impl DesktopSubscriptionSummary {
    pub fn from_preflight(
        report: &SubscriptionPreflightReport,
        selected_outbound: Option<&str>,
        recommended_outbound: Option<&str>,
    ) -> Self {
        let _ = (report, selected_outbound, recommended_outbound);
        Self {
            usable: false,
            supported_count: 0,
            skipped_count: 0,
            default_outbound: None,
            selected_outbound: None,
            recommended_outbound: None,
            nodes: Vec::new(),
            skipped: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keli_client_core::preflight_subscription_config;

    #[test]
    fn subscription_summary_marks_selected_and_recommended_nodes() {
        let config = r#"
proxies:
  - name: SS-A
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
  - name: VMESS-B
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00112233-4455-6677-8899-aabbccddeeff
"#;
        let report = preflight_subscription_config(config).expect("preflight");

        let summary = DesktopSubscriptionSummary::from_preflight(
            &report,
            Some("VMESS-B"),
            Some("SS-A"),
        );

        assert!(summary.usable);
        assert_eq!(summary.supported_count, 2);
        assert_eq!(summary.skipped_count, 0);
        assert_eq!(summary.default_outbound.as_deref(), Some("SS-A"));
        assert_eq!(summary.selected_outbound.as_deref(), Some("VMESS-B"));
        assert_eq!(summary.recommended_outbound.as_deref(), Some("SS-A"));
        assert!(summary.nodes.iter().any(|node| node.tag == "VMESS-B" && node.selected));
        assert!(summary.nodes.iter().any(|node| node.tag == "SS-A" && node.recommended));
    }
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test -p keli-desktop subscription -- --test-threads=1`

Expected: FAIL because `subscription_summary_marks_selected_and_recommended_nodes` still receives the empty summary stub.

- [ ] **Step 3: Implement subscription summary mapping**

Replace `from_preflight` with:

```rust
    pub fn from_preflight(
        report: &SubscriptionPreflightReport,
        selected_outbound: Option<&str>,
        recommended_outbound: Option<&str>,
    ) -> Self {
        let selected_outbound = selected_outbound
            .map(str::to_string)
            .or_else(|| report.default_outbound().map(str::to_string));
        let recommended_outbound = recommended_outbound
            .map(str::to_string)
            .or_else(|| selected_outbound.clone());
        let nodes = report
            .supported()
            .iter()
            .map(|node| DesktopNodeSummary {
                tag: node.tag.clone(),
                protocol: node.protocol.clone(),
                transport: node.transport.clone(),
                security: node.security.clone(),
                udp_supported: node.udp_supported,
                selected: selected_outbound.as_deref() == Some(node.tag.as_str()),
                recommended: recommended_outbound.as_deref() == Some(node.tag.as_str()),
            })
            .collect();
        Self {
            usable: report.is_usable(),
            supported_count: report.supported_count(),
            skipped_count: report.skipped_count(),
            default_outbound: report.default_outbound().map(str::to_string),
            selected_outbound,
            recommended_outbound,
            nodes,
            skipped: report
                .skipped()
                .iter()
                .map(|skipped| format!("{}: {}", skipped.name, skipped.reason))
                .collect(),
        }
    }
```

- [ ] **Step 4: Run subscription tests**

Run: `cargo test -p keli-desktop subscription -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```powershell
git add crates/keli-desktop/src/subscription.rs crates/keli-desktop/src/lib.rs
git commit -m "Add desktop subscription DTOs"
```

## Task 5: Runtime Service State Wrapper

**Files:**
- Modify: `crates/keli-desktop/src/service.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Write failing runtime service tests**

Replace `crates/keli-desktop/src/service.rs` with:

```rust
use keli_client_core::{
    preflight_subscription_config, ClientErrorKind, ClientRuntime, RuntimeConfig,
};
use serde::{Deserialize, Serialize};

use crate::status::{DesktopStatusSnapshot, DesktopTrafficMode};
use crate::subscription::DesktopSubscriptionSummary;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesktopRuntimeCommand {
    ImportSubscription,
    SelectNode,
    Start,
    Reload,
    Stop,
}

#[derive(Debug)]
pub struct DesktopRuntimeService {
    runtime: ClientRuntime,
    subscription_config: Option<String>,
    selected_outbound: Option<String>,
    traffic_mode: DesktopTrafficMode,
    listen: String,
}

impl Default for DesktopRuntimeService {
    fn default() -> Self {
        Self {
            runtime: ClientRuntime::default(),
            subscription_config: None,
            selected_outbound: None,
            traffic_mode: DesktopTrafficMode::SystemProxy,
            listen: "127.0.0.1:7890".to_string(),
        }
    }
}

impl DesktopRuntimeService {
    pub fn import_subscription_config(
        &mut self,
        config_text: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, ClientErrorKind> {
        let _ = config_text.into();
        Err(ClientErrorKind::NoSupportedOutbounds)
    }

    pub fn select_node(
        &mut self,
        outbound_tag: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, ClientErrorKind> {
        let _ = outbound_tag.into();
        Err(ClientErrorKind::NoSupportedOutbounds)
    }

    pub fn set_traffic_mode(&mut self, traffic_mode: DesktopTrafficMode) {
        self.traffic_mode = traffic_mode;
    }

    pub fn start(&mut self) -> Result<DesktopStatusSnapshot, ClientErrorKind> {
        Err(ClientErrorKind::NoSupportedOutbounds)
    }

    pub fn stop(&mut self) -> DesktopStatusSnapshot {
        self.runtime.stop();
        self.status()
    }

    pub fn status(&self) -> DesktopStatusSnapshot {
        DesktopStatusSnapshot::from_client_runtime(&self.runtime, self.traffic_mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::DesktopRunState;

    fn ss_config(tag: &str) -> String {
        format!(
            r#"
proxies:
  - name: {tag}
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#
        )
    }

    #[test]
    fn import_subscription_exposes_desktop_summary() {
        let mut service = DesktopRuntimeService::default();

        let summary = service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");

        assert!(summary.usable);
        assert_eq!(summary.selected_outbound.as_deref(), Some("SS-READY"));
        assert_eq!(summary.nodes[0].tag, "SS-READY");
        assert!(summary.nodes[0].selected);
    }

    #[test]
    fn select_node_rejects_missing_outbound_without_changing_runtime() {
        let mut service = DesktopRuntimeService::default();
        service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");

        let error = service.select_node("MISSING").expect_err("missing node");

        assert_eq!(error, ClientErrorKind::OutboundNotFound("MISSING".to_string()));
        assert_eq!(service.status().run_state, DesktopRunState::Stopped);
    }

    #[test]
    fn start_and_stop_use_selected_subscription_node() {
        let mut service = DesktopRuntimeService::default();
        service
            .import_subscription_config(ss_config("SS-READY"))
            .expect("import subscription");
        service.set_traffic_mode(DesktopTrafficMode::Tun);

        let running = service.start().expect("start service");

        assert_eq!(running.run_state, DesktopRunState::Running);
        assert_eq!(running.traffic_mode, DesktopTrafficMode::Tun);
        assert_eq!(running.selected_outbound.as_deref(), Some("SS-READY"));

        let stopped = service.stop();

        assert_eq!(stopped.run_state, DesktopRunState::Stopped);
        assert_eq!(stopped.traffic_mode, DesktopTrafficMode::Tun);
    }
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test -p keli-desktop service -- --test-threads=1`

Expected: FAIL because `import_subscription_exposes_desktop_summary` still receives the no-supported-outbounds stub.

- [ ] **Step 3: Implement service methods**

Use:

```rust
    pub fn import_subscription_config(
        &mut self,
        config_text: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, ClientErrorKind> {
        let config_text = config_text.into();
        let report = preflight_subscription_config(&config_text)?;
        let selected = report.default_outbound().map(str::to_string);
        self.subscription_config = Some(config_text);
        self.selected_outbound = selected.clone();
        Ok(DesktopSubscriptionSummary::from_preflight(
            &report,
            selected.as_deref(),
            selected.as_deref(),
        ))
    }

    pub fn select_node(
        &mut self,
        outbound_tag: impl Into<String>,
    ) -> Result<DesktopSubscriptionSummary, ClientErrorKind> {
        let outbound_tag = outbound_tag.into();
        let config_text = self
            .subscription_config
            .as_deref()
            .ok_or(ClientErrorKind::NoSupportedOutbounds)?;
        let report = preflight_subscription_config(config_text)?;
        report.select_outbound(Some(&outbound_tag))?;
        self.selected_outbound = Some(outbound_tag.clone());
        Ok(DesktopSubscriptionSummary::from_preflight(
            &report,
            Some(&outbound_tag),
            Some(&outbound_tag),
        ))
    }

    pub fn start(&mut self) -> Result<DesktopStatusSnapshot, ClientErrorKind> {
        let config_text = self
            .subscription_config
            .clone()
            .ok_or(ClientErrorKind::NoSupportedOutbounds)?;
        self.runtime.start(RuntimeConfig::new(
            config_text,
            self.selected_outbound.clone(),
            self.listen.clone(),
        ))?;
        Ok(self.status())
    }
```

- [ ] **Step 4: Run service tests**

Run: `cargo test -p keli-desktop service -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Run full desktop crate tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```powershell
git add crates/keli-desktop
git commit -m "Add desktop runtime service foundation"
```

## Task 6: Workspace Verification

**Files:**
- No source changes unless verification reveals a defect.

- [ ] **Step 1: Format check**

Run: `cargo fmt --check`

Expected: PASS.

- [ ] **Step 2: Diff check**

Run: `git diff --check`

Expected: PASS.

- [ ] **Step 3: Desktop crate tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 4: Core regression tests**

Run: `cargo test -p keli-client-core -p keli-platform -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Commit any verification fixes**

If a fix was needed, run:

```powershell
git add <changed-files>
git commit -m "Fix desktop foundation verification"
```

If no fix was needed, do not create an empty commit.

## Self-Review Checklist

- Spec goal covered by this plan: desktop backend boundary, first-run readiness, subscription setup, basic start/stop state, and UI-safe DTOs.
- Spec goal not covered by this plan: visible tray/window app, real managed mixed core extraction, support bundle export UI, packaging, and manual Windows smoke. These need subsequent plans because they are separate implementation slices.
- No incomplete-task markers remain; every code-changing task has concrete file paths, code, commands, and expected results.
- Type names are consistent across modules: `DesktopStatusSnapshot`, `DesktopTrafficMode`, `DesktopSubscriptionSummary`, and `DesktopRuntimeService`.
