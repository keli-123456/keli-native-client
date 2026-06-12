# Desktop Support Bundle Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a desktop backend support bundle export that combines the existing redacted CLI support bundle with the current desktop runtime and managed-core status.

**Architecture:** Keep the CLI support bundle as the source of truth for doctor, interop, TUN preflight, profile summary, and redaction. Add a small `keli-desktop` support module that wraps that JSON with desktop-specific status snapshots and managed runtime status JSON, then expose it through `DesktopRuntimeService::export_support_bundle`.

**Tech Stack:** Rust 2021, `keli-cli` support bundle and managed status JSON helpers, `serde_json`, existing desktop status DTOs.

---

## Scope Check

This plan covers:

- A desktop backend method that returns support bundle bytes for the UI to save.
- Redacted profile evidence based on the currently imported subscription config.
- Current desktop status snapshot.
- Current managed mixed runtime status including recent events, last error, selected outbound, system proxy status, subscription state, and URL update state when available.
- Tests proving the exported bundle is valid JSON and does not contain profile credentials or server endpoints.

This plan does not cover:

- A GUI button or file picker.
- Running default-core certification during export.
- Compressing or attaching logs from the filesystem.
- Packaging the support bundle into a zip.

## File Structure

- Modify: `crates/keli-desktop/Cargo.toml`
  - Add `serde_json.workspace = true`.
- Modify: `crates/keli-desktop/src/lib.rs`
  - Export a new `support` module and DTOs.
- Create: `crates/keli-desktop/src/support.rs`
  - Build the desktop support bundle JSON bytes and return export metadata.
- Modify: `crates/keli-desktop/src/managed.rs`
  - Add a method to expose redacted managed runtime status JSON.
- Modify: `crates/keli-desktop/src/service.rs`
  - Add `export_support_bundle` and tests.

## Task 1: Failing Desktop Support Bundle Test

**Files:**
- Modify: `crates/keli-desktop/Cargo.toml`
- Modify: `crates/keli-desktop/src/service.rs`

- [ ] **Step 1: Add test dependency wiring**

Add this dependency to `crates/keli-desktop/Cargo.toml`:

```toml
serde_json.workspace = true
```

- [ ] **Step 2: Write the failing service test**

Add this test to `crates/keli-desktop/src/service.rs`:

```rust
    #[test]
    fn support_bundle_export_embeds_runtime_status_and_redacts_profile() {
        let platform_controller = FakeSystemProxyController::new();
        let mut service = DesktopRuntimeService::new(&platform_controller);
        let config = r#"
proxies:
  - name: SS-READY
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
"#;
        service
            .import_subscription_config(config)
            .expect("import subscription");
        service.set_listen("127.0.0.1:0");
        service.start().expect("start service");

        let export = service
            .export_support_bundle()
            .expect("export support bundle");
        let bundle: serde_json::Value =
            serde_json::from_slice(&export.bytes).expect("support bundle JSON");
        let serialized = String::from_utf8(export.bytes.clone()).expect("support bundle UTF-8");

        assert_eq!(export.format, "json");
        assert_eq!(export.byte_count, export.bytes.len());
        assert_eq!(bundle["kind"], "keli_desktop_support_bundle");
        assert_eq!(bundle["desktop_status"]["run_state"], "running");
        assert_eq!(bundle["desktop_status"]["selected_outbound"], "SS-READY");
        assert_eq!(bundle["managed_runtime_status"]["selected_outbound"], "SS-READY");
        assert_eq!(bundle["core_support_bundle"]["kind"], "keli_support_bundle");
        assert_eq!(bundle["core_support_bundle"]["profile"]["status"], "ok");
        assert_eq!(
            bundle["core_support_bundle"]["redaction"]["profile_config_text"],
            "omitted"
        );
        assert!(!serialized.contains("password: secret"));
        assert!(!serialized.contains("ss.example.com"));

        service.stop().expect("stop service");
    }
```

- [ ] **Step 3: Run the failing test**

Run: `cargo test -p keli-desktop support_bundle_export_embeds_runtime_status_and_redacts_profile -- --exact --test-threads=1`

Expected: FAIL because `DesktopRuntimeService::export_support_bundle` and `DesktopSupportBundleExport` do not exist.

## Task 2: Implement Desktop Support Bundle Export

**Files:**
- Modify: `crates/keli-desktop/src/lib.rs`
- Create: `crates/keli-desktop/src/support.rs`
- Modify: `crates/keli-desktop/src/managed.rs`
- Modify: `crates/keli-desktop/src/service.rs`

- [ ] **Step 1: Add support module exports**

Modify `crates/keli-desktop/src/lib.rs`:

```rust
pub mod support;
pub use support::{DesktopSupportBundleExport, DESKTOP_SUPPORT_BUNDLE_SCHEMA_VERSION};
```

- [ ] **Step 2: Add managed status JSON helper**

Add `managed_mixed_status_json_value` to the `keli_cli` imports in `crates/keli-desktop/src/managed.rs`, then add:

```rust
    pub fn managed_status_json(&self) -> serde_json::Value {
        managed_mixed_status_json_value(&self.core.status())
    }
```

- [ ] **Step 3: Implement the support module**

Create `crates/keli-desktop/src/support.rs`:

```rust
use serde::{Deserialize, Serialize};

use crate::status::DesktopStatusSnapshot;

pub const DESKTOP_SUPPORT_BUNDLE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopSupportBundleExport {
    pub format: String,
    pub byte_count: usize,
    pub bytes: Vec<u8>,
}

pub fn build_desktop_support_bundle_export(
    core_support_bundle: serde_json::Value,
    desktop_status: &DesktopStatusSnapshot,
    managed_runtime_status: serde_json::Value,
) -> Result<DesktopSupportBundleExport, String> {
    let value = serde_json::json!({
        "status": "ok",
        "kind": "keli_desktop_support_bundle",
        "schema_version": DESKTOP_SUPPORT_BUNDLE_SCHEMA_VERSION,
        "desktop_status": desktop_status,
        "managed_runtime_status": managed_runtime_status,
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
```

- [ ] **Step 4: Implement service export method**

Add these imports to `crates/keli-desktop/src/service.rs`:

```rust
use keli_cli::write_support_bundle_report;
use crate::support::{build_desktop_support_bundle_export, DesktopSupportBundleExport};
```

Add this method to `impl DesktopRuntimeService`:

```rust
    pub fn export_support_bundle(&self) -> Result<DesktopSupportBundleExport, DesktopRuntimeError> {
        let mut core_bundle_bytes = Vec::new();
        write_support_bundle_report(self.subscription_config.as_deref(), &mut core_bundle_bytes)?;
        let core_support_bundle: serde_json::Value =
            serde_json::from_slice(&core_bundle_bytes).map_err(|error| {
                DesktopRuntimeError::Managed(format!("support bundle JSON parse failed: {error}"))
            })?;
        let desktop_status = self.status();
        build_desktop_support_bundle_export(
            core_support_bundle,
            &desktop_status,
            self.core.managed_status_json(),
        )
        .map_err(DesktopRuntimeError::Managed)
    }
```

- [ ] **Step 5: Run support bundle test**

Run: `cargo test -p keli-desktop support_bundle_export_embeds_runtime_status_and_redacts_profile -- --exact --test-threads=1`

Expected: PASS.

- [ ] **Step 6: Run full desktop tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 7: Commit**

Run:

```powershell
git add crates/keli-desktop/Cargo.toml Cargo.lock crates/keli-desktop/src/lib.rs crates/keli-desktop/src/managed.rs crates/keli-desktop/src/service.rs crates/keli-desktop/src/support.rs
git commit -m "Add desktop support bundle export"
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

- [ ] **Step 3: Desktop tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 4: CLI support bundle regression**

Run: `cargo test -p keli-cli --test support_bundle support_bundle_includes_doctor_and_redacted_profile_summary -- --exact --test-threads=1`

Expected: PASS.

- [ ] **Step 5: Push commits**

Run:

```powershell
git push
```

Expected: the current branch pushes successfully to `origin/main`.

## Self-Review Checklist

- Spec coverage: this plan adds the backend export surface needed for a desktop diagnostics screen to save a support bundle.
- Spec gaps: visual diagnostics UI, zip packaging, filesystem logs, installer integration, and TUN lifecycle remain separate slices.
- Sensitive profile config text, credentials, and server endpoints remain omitted from the exported desktop bundle.
- No incomplete-task markers remain; code-changing steps include paths, code, commands, and expected results.
