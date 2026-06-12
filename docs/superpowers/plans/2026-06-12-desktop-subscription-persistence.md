# Desktop Subscription Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for implementation and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist imported desktop subscription config and the selected node so the Windows desktop MVP can reopen with the user's last usable subscription without requiring command-line setup or repeated paste/import.

**Architecture:** Keep runtime validation authoritative. Store only the raw subscription config text and selected outbound tag in a JSON file, then restore by replaying `import_subscription_config` and optional `select_node` through the existing desktop command host. Failed restore must leave the shell empty and never bypass preflight validation.

**Tech Stack:** Rust 2021, `keli-desktop`, `serde_json`, `std::fs`, existing `DesktopShellController`, existing `DesktopRuntimeService`.

---

## Scope Check

This slice covers:

- A small `DesktopPersistedSubscription` DTO with config text and optional selected outbound.
- A `DesktopSubscriptionStore` that reads/writes JSON under a supplied path.
- A default Windows-friendly path for native controller startup.
- Controller restore on creation by replaying the persisted config through existing host methods.
- Controller writes after successful local config import, URL import, URL update, and node selection.
- A command-host persistence snapshot so URL fetch/update paths can save the fetched config text without UI guessing.
- Focused backend tests and full desktop gate verification.

This slice does not cover:

- Encrypting subscription secrets.
- Persisting runtime running/stopped state.
- Auto-start on login.
- A UI file picker.
- Cloud sync or account state.

## File Structure

- Add: `crates/keli-desktop/src/persistence.rs`
  - Own persisted subscription DTO, JSON read/write helpers, and default storage path.
- Modify: `crates/keli-desktop/src/lib.rs`
  - Export persistence DTOs/helpers.
- Modify: `crates/keli-desktop/src/app.rs`
  - Add optional store support to `DesktopShellController`.
  - Add host persistence snapshot method.
  - Restore persisted subscription during native startup.
  - Save persisted subscription after successful import/update/select operations.
- Modify: `crates/keli-desktop/src/service.rs`
  - Expose the runtime's current config text and selected outbound for persistence.
- Modify: `crates/keli-desktop/src/commands.rs`
  - Forward the persistence snapshot through `DesktopNativeCommandService`.

## Task 1: RED Persistence Store Tests

**Files:**
- Add: `crates/keli-desktop/src/persistence.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Add failing persistence tests**

Add tests to `persistence.rs`:

```rust
#[test]
fn subscription_store_round_trips_config_and_selected_node() {
    let path = test_path("round-trip");
    let store = DesktopSubscriptionStore::new(&path);
    let persisted = DesktopPersistedSubscription {
        config_text: "proxies:\n  - name: SS-READY".to_string(),
        selected_outbound: Some("SS-READY".to_string()),
    };

    store.save(&persisted).expect("save persisted subscription");

    assert_eq!(
        store.load().expect("load persisted subscription"),
        Some(persisted)
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn subscription_store_missing_file_loads_empty() {
    let store = DesktopSubscriptionStore::new(test_path("missing"));

    assert_eq!(store.load().expect("load missing store"), None);
}
```

- [ ] **Step 2: Export module shell**

Add `pub mod persistence;` and public re-exports in `lib.rs`.

- [ ] **Step 3: Run RED test**

Run:

```powershell
cargo test -p keli-desktop persistence -- --test-threads=1
```

Expected: FAIL because persistence types and functions do not exist yet.

## Task 2: Implement Persistence Store

**Files:**
- Add: `crates/keli-desktop/src/persistence.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Add DTO and store**

Implement:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopPersistedSubscription {
    pub config_text: String,
    pub selected_outbound: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopSubscriptionStore {
    path: PathBuf,
}
```

- [ ] **Step 2: Add load/save**

`load` returns `Ok(None)` for missing files. `save` creates the parent directory and writes pretty JSON.

- [ ] **Step 3: Add default path helper**

Use `%APPDATA%\Keli\desktop-subscription.json` on Windows when available; otherwise fall back to `std::env::temp_dir().join("keli").join("desktop-subscription.json")`.

- [ ] **Step 4: Run focused tests**

Run:

```powershell
cargo test -p keli-desktop persistence -- --test-threads=1
```

Expected: PASS.

## Task 3: RED Controller Restore/Save Tests

**Files:**
- Modify: `crates/keli-desktop/src/app.rs`
- Modify: `crates/keli-desktop/src/service.rs`
- Modify: `crates/keli-desktop/src/commands.rs`

- [ ] **Step 1: Add controller tests**

Add tests that use `FakeHost`:

```rust
#[test]
fn controller_restores_persisted_subscription_and_selected_node() {
    let store = DesktopSubscriptionStore::new(test_path("restore-selected"));
    store.save(&DesktopPersistedSubscription {
        config_text: ss_config_with_tags(&["SS-OLD", "SS-READY"]),
        selected_outbound: Some("SS-READY".to_string()),
    }).expect("save persisted subscription");

    let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
    let controller = DesktopShellController::new_with_subscription_store(host, store.clone());

    assert_eq!(
        controller.snapshot().subscription.as_ref().and_then(|subscription| {
            subscription.selected_outbound.as_deref()
        }),
        Some("SS-READY")
    );

    let _ = std::fs::remove_file(store.path());
}

#[test]
fn controller_persists_import_and_selected_node() {
    let store = DesktopSubscriptionStore::new(test_path("persist-import-select"));
    let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
    let mut controller = DesktopShellController::new_with_subscription_store(host, store.clone());

    controller
        .import_subscription_config(ss_config_with_tags(&["SS-A", "SS-B"]))
        .expect("import subscription");
    controller.select_node("SS-B").expect("select node");

    let persisted = store.load().expect("load persisted subscription").expect("persisted");
    assert!(persisted.config_text.contains("SS-A"));
    assert_eq!(persisted.selected_outbound.as_deref(), Some("SS-B"));

    let _ = std::fs::remove_file(store.path());
}
```

- [ ] **Step 2: Run RED controller tests**

Run:

```powershell
cargo test -p keli-desktop shell_subscription_persistence -- --test-threads=1
```

Expected: FAIL because controller store wiring does not exist.

## Task 4: Implement Controller Restore/Save

**Files:**
- Modify: `crates/keli-desktop/src/app.rs`
- Modify: `crates/keli-desktop/src/service.rs`
- Modify: `crates/keli-desktop/src/commands.rs`

- [ ] **Step 1: Add store field and constructors**

Add `subscription_store: Option<DesktopSubscriptionStore>` to `DesktopShellController`. Keep `new(host)` unchanged with no store. Add `new_with_subscription_store(host, store)` and make `new_native()` use `DesktopSubscriptionStore::default_path()`.

- [ ] **Step 2: Add host persistence snapshot**

Add this method to `DesktopShellCommandHost`:

```rust
fn persisted_subscription(&self) -> Option<DesktopPersistedSubscription>;
```

Implement it for `DesktopNativeCommandService` by forwarding to `DesktopCommandService` and `DesktopRuntimeService`. Runtime returns `None` until a config has been imported; otherwise it returns cloned `subscription_config` and `selected_outbound`.

- [ ] **Step 3: Restore on construction**

After building the shell, call store `load()`. If a persisted subscription exists, replay `host.import_subscription_config(config_text)`. If `selected_outbound` is present, replay `host.select_node(selected)`. Refresh shell subscription/status only on success.

- [ ] **Step 4: Save after import/update/select**

After successful import/update/select, call `host.persisted_subscription()` and save that snapshot if present. This makes local config import, URL import, URL update, and node selection share the same persistence path.

- [ ] **Step 5: Preserve failures safely**

If loading, validation, or save fails, keep the shell usable and continue without panicking. The bad persisted file remains for diagnostics; it is not loaded into shell state.

- [ ] **Step 6: Run focused controller tests**

Run:

```powershell
cargo test -p keli-desktop shell_subscription_persistence -- --test-threads=1
```

Expected: PASS.

## Task 5: Verify, Commit, Push

**Files:**
- `crates/keli-desktop/src/persistence.rs`
- `crates/keli-desktop/src/lib.rs`
- `crates/keli-desktop/src/app.rs`
- `crates/keli-desktop/src/service.rs`
- `crates/keli-desktop/src/commands.rs`
- `docs/superpowers/plans/2026-06-12-desktop-subscription-persistence.md`

- [ ] **Step 1: Focused and full tests**

Run:

```powershell
cargo fmt
cargo test -p keli-desktop persistence shell_subscription_persistence -- --test-threads=1
cargo test -p keli-desktop -- --test-threads=1
cargo test -p keli-desktop-shell
```

Expected: PASS.

- [ ] **Step 2: Gates**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-public-release-gate.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
```

Expected: MVP gate PASS. Public release gate remains blocked only by `artifact-signature-missing` and `signing-certificate-missing`; readiness reports `machine_takeover_status` as `ready`.

- [ ] **Step 3: Commit and push**

Run:

```powershell
git add crates\keli-desktop\src\persistence.rs crates\keli-desktop\src\lib.rs crates\keli-desktop\src\app.rs crates\keli-desktop\src\service.rs crates\keli-desktop\src\commands.rs docs\superpowers\plans\2026-06-12-desktop-subscription-persistence.md
git commit -m "Persist desktop subscription selection"
git push origin main
```

## Self-Review

- Spec coverage: implements the explicit MVP slice for subscription import, node list, and selected node persistence.
- Placeholder scan: no TBD/TODO/fill-in language remains.
- Type consistency: `DesktopPersistedSubscription`, `DesktopSubscriptionStore`, and `new_with_subscription_store` are used consistently.
