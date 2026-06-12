# Desktop Subscription URL Config Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the desktop backend import and update subscriptions from URLs while keeping its local subscription config synchronized with successful managed-core URL updates.

**Architecture:** Add safe managed-core wrappers that return fetched subscription config text to Rust callers without including the sensitive body in `Debug` or JSON output. Use those wrappers from `keli-desktop` to implement URL import and running URL update summaries, and update the desktop service's local config only when the managed core applies the fetched subscription.

**Tech Stack:** Rust 2021, existing `keli-cli` subscription fetch and managed mixed controller, `keli-desktop` DTOs, local HTTP test servers.

---

## Scope Check

This plan covers:

- Safe Rust-only access to fetched subscription config text.
- Desktop URL import while stopped.
- Running desktop URL update through the managed core update-plan path.
- Syncing the desktop service's local config after successful URL updates.
- Keeping URL fetch source redacted to host/port/path/query presence in desktop DTOs.

This plan does not cover:

- Saving subscription URLs or credentials.
- Scheduled background refresh.
- GUI rendering.
- Installer packaging.

## File Structure

- Modify: `crates/keli-cli/src/lib.rs`
  - Add safe config-carrying fetch/update wrappers and a controller URL update method.
- Modify: `crates/keli-cli/tests/managed_mixed.rs`
  - Test that the new wrapper exposes config text to Rust callers and redacts it from debug output.
- Modify: `crates/keli-desktop/src/managed.rs`
  - Add desktop-facing wrappers for subscription URL fetch and update.
- Modify: `crates/keli-desktop/src/subscription.rs`
  - Add URL fetch/import/update DTOs.
- Modify: `crates/keli-desktop/src/service.rs`
  - Add URL import/update service methods and tests.
- Modify: `crates/keli-desktop/src/lib.rs`
  - Export URL DTOs.

## Task 1: Core URL Config Wrapper

**Files:**
- Modify: `crates/keli-cli/src/lib.rs`
- Modify: `crates/keli-cli/tests/managed_mixed.rs`

- [ ] **Step 1: Write failing core tests**

Add `ManagedSubscriptionUrlConfigUpdateOutcome` to the `use keli_cli::{ ... }` list in `crates/keli-cli/tests/managed_mixed.rs`.

Add this test near the existing subscription URL update tests:

```rust
#[test]
fn managed_mixed_controller_url_config_update_exposes_body_without_debug_leak() {
    let platform_controller = FakeSystemProxyController::new(SystemProxySnapshot::default());
    let mut core = ManagedMixedController::new(&platform_controller);
    core.start_from_subscription_config_text(
        &ss_config_with_tags(&["SS-OLD", "SS-STAY"]),
        ManagedMixedOptions {
            listen: "127.0.0.1:0".to_string(),
            outbound_tag: Some("SS-STAY".to_string()),
            ..ManagedMixedOptions::default()
        },
    )
    .expect("start managed mixed controller");
    let fetched_config = ss_config_with_tags(&["SS-STAY", "SS-NEW"]);
    let (url, request_thread) = spawn_subscription_http_server(200, "OK", fetched_config.clone());

    let result = core
        .reload_from_subscription_url_with_update_plan_and_config_text(
            &url,
            Duration::from_secs(2),
            4096,
        )
        .expect("subscription URL config update");
    request_thread.join().expect("subscription request");

    assert!(result.outcome().applied);
    assert_eq!(result.applied_config_text(), Some(fetched_config.as_str()));
    assert_eq!(result.fetched_config_text(), Some(fetched_config.as_str()));
    let debug = format!("{result:?}");
    assert!(!debug.contains("password: secret"));
    assert!(!debug.contains(&fetched_config));

    core.stop().expect("stop managed mixed controller");
}
```

- [ ] **Step 2: Run the failing test**

Run: `cargo test -p keli-cli --test managed_mixed managed_mixed_controller_url_config_update_exposes_body_without_debug_leak -- --exact --test-threads=1`

Expected: FAIL because `ManagedSubscriptionUrlConfigUpdateOutcome` and `reload_from_subscription_url_with_update_plan_and_config_text` do not exist.

- [ ] **Step 3: Add safe config-carrying wrappers**

In `crates/keli-cli/src/lib.rs`, add `fmt` to the standard imports if it is not already imported:

```rust
use std::fmt;
```

Add these structs after `ManagedSubscriptionUrlUpdateOutcome`:

```rust
#[derive(Clone, PartialEq, Eq)]
pub struct ManagedSubscriptionUrlConfigFetchOutcome {
    pub fetch: ManagedSubscriptionUrlFetchOutcome,
    config_text: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ManagedSubscriptionUrlConfigUpdateOutcome {
    pub outcome: ManagedSubscriptionUrlUpdateOutcome,
    fetched_config_text: Option<String>,
    applied_config_text: Option<String>,
}

impl fmt::Debug for ManagedSubscriptionUrlConfigFetchOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSubscriptionUrlConfigFetchOutcome")
            .field("fetch", &self.fetch)
            .field("config_text", &self.config_text.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl fmt::Debug for ManagedSubscriptionUrlConfigUpdateOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSubscriptionUrlConfigUpdateOutcome")
            .field("outcome", &self.outcome)
            .field(
                "fetched_config_text",
                &self.fetched_config_text.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "applied_config_text",
                &self.applied_config_text.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl ManagedSubscriptionUrlConfigFetchOutcome {
    pub fn config_text(&self) -> Option<&str> {
        self.config_text.as_deref()
    }

    pub fn into_parts(self) -> (ManagedSubscriptionUrlFetchOutcome, Option<String>) {
        (self.fetch, self.config_text)
    }
}

impl ManagedSubscriptionUrlConfigUpdateOutcome {
    pub fn outcome(&self) -> &ManagedSubscriptionUrlUpdateOutcome {
        &self.outcome
    }

    pub fn fetched_config_text(&self) -> Option<&str> {
        self.fetched_config_text.as_deref()
    }

    pub fn applied_config_text(&self) -> Option<&str> {
        self.applied_config_text.as_deref()
    }

    pub fn into_parts(self) -> (ManagedSubscriptionUrlUpdateOutcome, Option<String>, Option<String>) {
        (
            self.outcome,
            self.fetched_config_text,
            self.applied_config_text,
        )
    }

    pub fn into_outcome(self) -> ManagedSubscriptionUrlUpdateOutcome {
        self.outcome
    }
}
```

- [ ] **Step 4: Add public fetch wrapper**

Add this function near `subscription_fetch_options` and `fetch_subscription_config_text`:

```rust
pub fn fetch_subscription_url_config_text(
    url: &str,
    timeout: Duration,
    max_bytes: usize,
) -> ManagedSubscriptionUrlConfigFetchOutcome {
    match fetch_subscription_config_text(&subscription_fetch_options(url, timeout, max_bytes)) {
        Ok(response) => ManagedSubscriptionUrlConfigFetchOutcome {
            fetch: ManagedSubscriptionUrlFetchOutcome::from_response(&response),
            config_text: Some(response.body),
        },
        Err(error) => ManagedSubscriptionUrlConfigFetchOutcome {
            fetch: ManagedSubscriptionUrlFetchOutcome::from_error(&error),
            config_text: None,
        },
    }
}
```

- [ ] **Step 5: Add controller URL update with config sync**

Add this method to `impl ManagedMixedController` and refactor the existing URL update method to call it:

```rust
    pub fn reload_from_subscription_url_with_update_plan(
        &mut self,
        url: &str,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<ManagedSubscriptionUrlUpdateOutcome, String> {
        Ok(self
            .reload_from_subscription_url_with_update_plan_and_config_text(
                url, timeout, max_bytes,
            )?
            .into_outcome())
    }

    pub fn reload_from_subscription_url_with_update_plan_and_config_text(
        &mut self,
        url: &str,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<ManagedSubscriptionUrlConfigUpdateOutcome, String> {
        self.ensure_panel_allows_traffic()?;
        if self.handle.is_none() {
            return Err("managed mixed core is not running".to_string());
        }

        let fetched = fetch_subscription_url_config_text(url, timeout, max_bytes);
        let (fetch, fetched_config_text) = fetched.into_parts();
        let Some(config_text) = fetched_config_text.clone() else {
            let error_message = format!(
                "subscription URL fetch failed: {}",
                fetch.error_kind.as_deref().unwrap_or("unknown")
            );
            let url_update_status = ManagedSubscriptionUrlUpdateStatus::new(
                fetch.clone(),
                None,
                false,
                Some(error_message.clone()),
            );
            if let Some(handle) = self.handle.as_mut() {
                handle.record_subscription_url_fetch_rejected(
                    &url_update_status,
                    &error_message,
                );
            }
            return Ok(ManagedSubscriptionUrlConfigUpdateOutcome {
                outcome: ManagedSubscriptionUrlUpdateOutcome {
                    fetch,
                    update: None,
                    status: self.status(),
                    applied: false,
                    error: Some(error_message),
                },
                fetched_config_text: None,
                applied_config_text: None,
            });
        };

        match self.reload_from_subscription_config_text_with_update_plan(&config_text) {
            Ok(update) => {
                let url_update_status = ManagedSubscriptionUrlUpdateStatus::new(
                    fetch.clone(),
                    Some(update.report.clone()),
                    update.applied,
                    update.error.clone(),
                );
                if let Some(handle) = self.handle.as_mut() {
                    handle.record_subscription_url_update_status(url_update_status);
                }
                let applied_config_text = update.applied.then_some(config_text.clone());
                Ok(ManagedSubscriptionUrlConfigUpdateOutcome {
                    outcome: ManagedSubscriptionUrlUpdateOutcome {
                        fetch,
                        update: Some(update.report),
                        status: self.status(),
                        applied: update.applied,
                        error: update.error,
                    },
                    fetched_config_text: Some(config_text),
                    applied_config_text,
                })
            }
            Err(error) => {
                let url_update_status = ManagedSubscriptionUrlUpdateStatus::new(
                    fetch.clone(),
                    None,
                    false,
                    Some(error.clone()),
                );
                if let Some(handle) = self.handle.as_mut() {
                    handle.record_subscription_url_update_status(url_update_status);
                }
                Ok(ManagedSubscriptionUrlConfigUpdateOutcome {
                    outcome: ManagedSubscriptionUrlUpdateOutcome {
                        fetch,
                        update: None,
                        status: self.status(),
                        applied: false,
                        error: Some(error),
                    },
                    fetched_config_text: Some(config_text),
                    applied_config_text: None,
                })
            }
        }
    }
```

- [ ] **Step 6: Run the core test**

Run: `cargo test -p keli-cli --test managed_mixed managed_mixed_controller_url_config_update_exposes_body_without_debug_leak -- --exact --test-threads=1`

Expected: PASS.

- [ ] **Step 7: Commit**

Run:

```powershell
git add crates/keli-cli/src/lib.rs crates/keli-cli/tests/managed_mixed.rs
git commit -m "Expose safe subscription URL config sync"
```

## Task 2: Desktop URL Import And Update

**Files:**
- Modify: `crates/keli-desktop/src/managed.rs`
- Modify: `crates/keli-desktop/src/subscription.rs`
- Modify: `crates/keli-desktop/src/service.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Write failing desktop tests**

Add these imports to the test module in `crates/keli-desktop/src/service.rs`:

```rust
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;
```

Add this local HTTP helper to the same test module:

```rust
fn spawn_subscription_http_server(
    status_code: u16,
    reason: &str,
    body: String,
) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind subscription HTTP server");
    let port = listener.local_addr().expect("subscription server addr").port();
    let url = format!("http://127.0.0.1:{port}/panel/private/sub?token=super-secret-token");
    let reason = reason.to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept subscription fetch");
        let mut request = Vec::new();
        let mut byte = [0; 1];
        while stream.read(&mut byte).expect("read subscription request") != 0 {
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).expect("subscription request utf8");
        let response = format!(
            "HTTP/1.1 {status_code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write subscription response");
        request.lines().next().unwrap_or_default().to_string()
    });
    (url, handle)
}
```

Add these tests:

```rust
#[test]
fn import_subscription_url_fetches_config_and_redacts_source() {
    let platform_controller = FakeSystemProxyController::new();
    let mut service = DesktopRuntimeService::new(&platform_controller);
    let (url, request_thread) =
        spawn_subscription_http_server(200, "OK", ss_config("SS-READY"));

    let imported = service
        .import_subscription_url(&url, Duration::from_secs(2), 4096)
        .expect("import subscription URL");
    let request_line = request_thread.join().expect("subscription request");

    assert_eq!(
        request_line,
        "GET /panel/private/sub?token=super-secret-token HTTP/1.1"
    );
    assert!(imported.fetch.ok);
    assert_eq!(imported.fetch.host.as_deref(), Some("127.0.0.1"));
    assert_eq!(imported.fetch.path_present, Some(true));
    assert_eq!(imported.fetch.query_present, Some(true));
    assert_eq!(
        imported
            .subscription
            .as_ref()
            .and_then(|summary| summary.selected_outbound.as_deref()),
        Some("SS-READY")
    );
    assert!(!format!("{imported:?}").contains("super-secret-token"));
}

#[test]
fn running_subscription_url_update_syncs_config_for_next_node_selection() {
    let platform_controller = FakeSystemProxyController::new();
    let mut service = DesktopRuntimeService::new(&platform_controller);
    service
        .import_subscription_config(ss_config_with_tags(&["SS-OLD", "SS-STAY"]))
        .expect("import subscription");
    service.select_node("SS-STAY").expect("select node");
    service.set_listen("127.0.0.1:0");
    service.start().expect("start service");
    let (url, request_thread) =
        spawn_subscription_http_server(200, "OK", ss_config_with_tags(&["SS-STAY", "SS-NEW"]));

    let update = service
        .update_subscription_url(&url, Duration::from_secs(2), 4096)
        .expect("update subscription URL");
    request_thread.join().expect("subscription request");

    assert!(update.applied);
    assert_eq!(update.error, None);
    assert_eq!(update.fetch.host.as_deref(), Some("127.0.0.1"));
    assert_eq!(
        update
            .update
            .as_ref()
            .map(|summary| summary.reason.as_str()),
        Some("selected-outbound-preserved")
    );

    service.select_node("SS-NEW").expect("select new node");

    assert_eq!(service.status().selected_outbound.as_deref(), Some("SS-NEW"));
    service.stop().expect("stop service");
}

#[test]
fn failed_subscription_url_update_keeps_runtime_and_old_config() {
    let platform_controller = FakeSystemProxyController::new();
    let mut service = DesktopRuntimeService::new(&platform_controller);
    service
        .import_subscription_config(ss_config("SS-READY"))
        .expect("import subscription");
    service.set_listen("127.0.0.1:0");
    service.start().expect("start service");
    let (url, request_thread) =
        spawn_subscription_http_server(500, "Panel Error", "panel failed".to_string());

    let update = service
        .update_subscription_url(&url, Duration::from_secs(2), 4096)
        .expect("update subscription URL");
    request_thread.join().expect("subscription request");

    assert!(!update.applied);
    assert_eq!(
        update.error.as_deref(),
        Some("subscription URL fetch failed: http-status")
    );
    assert_eq!(update.fetch.error_kind.as_deref(), Some("http-status"));
    assert_eq!(service.status().selected_outbound.as_deref(), Some("SS-READY"));
    assert_eq!(service.status().run_state, DesktopRunState::Running);

    service.stop().expect("stop service");
}
```

- [ ] **Step 2: Run failing desktop tests**

Run: `cargo test -p keli-desktop subscription_url -- --test-threads=1`

Expected: FAIL because `import_subscription_url`, `update_subscription_url`, and URL DTOs do not exist.

- [ ] **Step 3: Add managed wrappers**

Update `crates/keli-desktop/src/managed.rs` imports:

```rust
use std::time::Duration;

use keli_cli::{
    fetch_subscription_url_config_text, ManagedMixedController, ManagedMixedOptions,
    ManagedSubscriptionUpdateOutcome, ManagedSubscriptionUrlConfigFetchOutcome,
    ManagedSubscriptionUrlConfigUpdateOutcome,
};
```

Add methods to `DesktopManagedCoreService`:

```rust
    pub fn fetch_subscription_url_config(
        url: &str,
        timeout: Duration,
        max_bytes: usize,
    ) -> ManagedSubscriptionUrlConfigFetchOutcome {
        fetch_subscription_url_config_text(url, timeout, max_bytes)
    }

    pub fn reload_subscription_url_with_update_plan_and_config_text(
        &mut self,
        url: &str,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<ManagedSubscriptionUrlConfigUpdateOutcome, String> {
        self.core
            .reload_from_subscription_url_with_update_plan_and_config_text(
                url, timeout, max_bytes,
            )
    }
```

- [ ] **Step 4: Add URL DTOs**

Add these DTOs to `crates/keli-desktop/src/subscription.rs`:

```rust
use keli_cli::{ManagedSubscriptionUrlFetchOutcome, ManagedSubscriptionUrlUpdateOutcome};

use crate::status::{DesktopStatusSnapshot, DesktopTrafficMode};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopSubscriptionUrlFetchSummary {
    pub ok: bool,
    pub scheme: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub default_port: Option<bool>,
    pub path_present: Option<bool>,
    pub query_present: Option<bool>,
    pub http_status: Option<u16>,
    pub body_bytes: Option<usize>,
    pub elapsed_ms: Option<u64>,
    pub error_kind: Option<String>,
    pub error_detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopSubscriptionUrlImportSummary {
    pub fetch: DesktopSubscriptionUrlFetchSummary,
    pub subscription: Option<DesktopSubscriptionSummary>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopSubscriptionUrlUpdateSummary {
    pub applied: bool,
    pub error: Option<String>,
    pub fetch: DesktopSubscriptionUrlFetchSummary,
    pub update: Option<DesktopSubscriptionUpdateSummary>,
    pub runtime_status: DesktopStatusSnapshot,
}

impl DesktopSubscriptionUrlFetchSummary {
    pub fn from_managed(fetch: &ManagedSubscriptionUrlFetchOutcome) -> Self {
        let source = fetch.source.as_ref();
        Self {
            ok: fetch.ok,
            scheme: source.map(|source| source.scheme.clone()),
            host: source.map(|source| source.host.clone()),
            port: source.map(|source| source.port),
            default_port: source.map(|source| source.default_port),
            path_present: source.map(|source| source.path_present),
            query_present: source.map(|source| source.query_present),
            http_status: fetch.http_status,
            body_bytes: fetch.body_bytes,
            elapsed_ms: fetch
                .elapsed
                .map(|elapsed| elapsed.as_millis().min(u128::from(u64::MAX)) as u64),
            error_kind: fetch.error_kind.clone(),
            error_detail: fetch.error_detail.clone(),
        }
    }
}

impl DesktopSubscriptionUrlImportSummary {
    pub fn fetch_error(fetch: DesktopSubscriptionUrlFetchSummary) -> Self {
        let error = Some(format!(
            "subscription URL fetch failed: {}",
            fetch.error_kind.as_deref().unwrap_or("unknown")
        ));
        Self {
            fetch,
            subscription: None,
            error,
        }
    }
}

impl DesktopSubscriptionUrlUpdateSummary {
    pub fn from_managed(
        outcome: &ManagedSubscriptionUrlUpdateOutcome,
        update: Option<DesktopSubscriptionUpdateSummary>,
        traffic_mode: DesktopTrafficMode,
    ) -> Self {
        Self {
            applied: outcome.applied,
            error: outcome.error.clone(),
            fetch: DesktopSubscriptionUrlFetchSummary::from_managed(&outcome.fetch),
            update,
            runtime_status: DesktopStatusSnapshot::from_managed_mixed_status(
                &outcome.status,
                traffic_mode,
            ),
        }
    }
}
```

Update `crates/keli-desktop/src/lib.rs` exports:

```rust
pub use subscription::{
    DesktopNodeSummary, DesktopSubscriptionSummary, DesktopSubscriptionUpdateSummary,
    DesktopSubscriptionUrlFetchSummary, DesktopSubscriptionUrlImportSummary,
    DesktopSubscriptionUrlUpdateSummary,
};
```

- [ ] **Step 5: Add desktop service methods**

Update service imports:

```rust
use std::time::Duration;

use crate::subscription::{
    DesktopSubscriptionSummary, DesktopSubscriptionUpdateSummary,
    DesktopSubscriptionUrlFetchSummary, DesktopSubscriptionUrlImportSummary,
    DesktopSubscriptionUrlUpdateSummary,
};
```

Add methods to `DesktopRuntimeService`:

```rust
    pub fn import_subscription_url(
        &mut self,
        url: &str,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<DesktopSubscriptionUrlImportSummary, DesktopRuntimeError> {
        let fetched =
            DesktopManagedCoreService::<C>::fetch_subscription_url_config(url, timeout, max_bytes);
        let (fetch, config_text) = fetched.into_parts();
        let fetch_summary = DesktopSubscriptionUrlFetchSummary::from_managed(&fetch);
        let Some(config_text) = config_text else {
            return Ok(DesktopSubscriptionUrlImportSummary::fetch_error(
                fetch_summary,
            ));
        };
        let subscription = self.import_subscription_config(config_text)?;
        Ok(DesktopSubscriptionUrlImportSummary {
            fetch: fetch_summary,
            subscription: Some(subscription),
            error: None,
        })
    }

    pub fn update_subscription_url(
        &mut self,
        url: &str,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<DesktopSubscriptionUrlUpdateSummary, DesktopRuntimeError> {
        if !self.core.is_running() {
            return Err(DesktopRuntimeError::Managed(
                "desktop subscription URL update requires running core".to_string(),
            ));
        }
        let result = self
            .core
            .reload_subscription_url_with_update_plan_and_config_text(url, timeout, max_bytes)?;
        let (outcome, fetched_config_text, applied_config_text) = result.into_parts();
        let update = match (outcome.update.as_ref(), fetched_config_text.as_deref()) {
            (Some(report), Some(config_text)) => {
                let preflight = preflight_subscription_config(config_text)?;
                let planned_selected = report.planned_selected_outbound.clone();
                let subscription = DesktopSubscriptionSummary::from_preflight(
                    &preflight,
                    planned_selected.as_deref(),
                    planned_selected.as_deref(),
                );
                Some(DesktopSubscriptionUpdateSummary::from_report(
                    report,
                    outcome.applied,
                    outcome.error.clone(),
                    subscription,
                ))
            }
            _ => None,
        };
        if outcome.applied {
            if let Some(config_text) = applied_config_text {
                self.subscription_config = Some(config_text);
            }
            self.selected_outbound = outcome.status.selected_outbound.clone();
        }
        Ok(DesktopSubscriptionUrlUpdateSummary::from_managed(
            &outcome,
            update,
            self.traffic_mode,
        ))
    }
```

- [ ] **Step 6: Run desktop URL tests**

Run: `cargo test -p keli-desktop subscription_url -- --test-threads=1`

Expected: PASS.

- [ ] **Step 7: Run full desktop tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 8: Commit**

Run:

```powershell
git add crates/keli-desktop/src/lib.rs crates/keli-desktop/src/managed.rs crates/keli-desktop/src/service.rs crates/keli-desktop/src/subscription.rs
git commit -m "Add desktop subscription URL sync"
```

## Task 3: Verification And Push

**Files:**
- No source changes unless verification reveals a defect.

- [ ] **Step 1: Format check**

Run: `cargo fmt --check`

Expected: PASS.

- [ ] **Step 2: Diff whitespace check**

Run: `git diff --check`

Expected: PASS.

- [ ] **Step 3: Desktop crate tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 4: Core URL update tests**

Run: `cargo test -p keli-cli --test managed_mixed subscription_url -- --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Push commits**

Run:

```powershell
git push
```

Expected: the current branch pushes successfully to `origin/main`.

## Self-Review Checklist

- Spec coverage: URL import/update now moves closer to ordinary-user subscription setup and preserves running core state on URL failures.
- Spec gaps: scheduled refresh, saved credentials, GUI, diagnostics export, TUN lifecycle, and packaging remain separate slices.
- Sensitive config text is not included in public debug output or desktop DTOs; URL path/query are only booleans.
- No incomplete-task markers remain; every code-changing step includes paths, code, commands, and expected results.
