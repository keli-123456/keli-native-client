# Desktop Command Facade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a desktop-facing command facade so a future Windows UI can call import, node selection, traffic mode, start, stop, status, dependency readiness, and support bundle operations without knowing the internal service layout.

**Architecture:** Keep `DesktopRuntimeService` as the runtime owner and add a thin `DesktopCommandService` wrapper that maps UI-style command methods to existing runtime/dependency APIs. Add a serializable `DesktopCommandError` so frontend command handlers have a stable error shape instead of Rust debug strings.

**Tech Stack:** Rust 2021, `keli-desktop` runtime DTOs, serde DTOs, existing fake platform and TUN controllers in tests.

---

## Scope Check

This plan covers:

- A command facade around `DesktopRuntimeService`.
- Stable command error mapping for runtime failures.
- Methods for subscription import, node selection, traffic mode, start, stop, status, support bundle export, and dependency readiness.
- Tests that exercise the facade through the same real managed core path used by `DesktopRuntimeService`.

This plan does not cover:

- Tauri or another visible desktop shell.
- Native controller ownership inside a shell state container.
- Persistent settings storage.
- Installer packaging.

## File Structure

- Create: `crates/keli-desktop/src/commands.rs`
  - Defines `DesktopCommandService` and `DesktopCommandError`.
  - Provides UI-facing methods that call runtime/dependency services.
- Modify: `crates/keli-desktop/src/lib.rs`
  - Exports the command module and DTOs.

## Task 1: Command Facade Tests

**Files:**
- Create: `crates/keli-desktop/src/commands.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Write failing tests**

Add tests that expect:

- `DesktopCommandService::from_runtime(runtime)` can import a subscription config, start mixed mode, return running status, stop, and return stopped status.
- `set_traffic_mode(DesktopTrafficMode::SystemProxy)` starts system proxy mode and restores proxy on stop.
- Missing node selection returns `DesktopCommandError { kind: "client", operation: "select-node", ... }`.
- `dependency_report_from_platform` returns a `DesktopDependencyReport`.

- [ ] **Step 2: Run tests to verify RED**

Run: `cargo test -p keli-desktop commands -- --test-threads=1`

Expected: FAIL because `commands.rs`, `DesktopCommandService`, and `DesktopCommandError` do not exist.

## Task 2: Implement Command Facade

**Files:**
- Create: `crates/keli-desktop/src/commands.rs`
- Modify: `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Implement `DesktopCommandError`**

Create:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopCommandError {
    pub operation: String,
    pub kind: String,
    pub message: String,
}
```

Map `DesktopRuntimeError::Client` to `kind = "client"` and `DesktopRuntimeError::Managed` to `kind = "managed"`.

- [ ] **Step 2: Implement `DesktopCommandService`**

Create:

```rust
pub struct DesktopCommandService<'a, C, T> {
    runtime: DesktopRuntimeService<'a, C, T>,
}
```

Expose methods:

- `import_subscription_config`
- `select_node`
- `set_traffic_mode`
- `start`
- `stop`
- `status`
- `export_support_bundle`
- `dependency_report_from_platform`

- [ ] **Step 3: Export command module**

Update `crates/keli-desktop/src/lib.rs`:

```rust
pub mod commands;
pub use commands::{DesktopCommandError, DesktopCommandService};
```

- [ ] **Step 4: Run command tests to verify GREEN**

Run: `cargo test -p keli-desktop commands -- --test-threads=1`

Expected: PASS.

## Task 3: Verification, Commit, And Push

**Files:**
- `crates/keli-desktop/src/commands.rs`
- `crates/keli-desktop/src/lib.rs`

- [ ] **Step 1: Format check**

Run: `cargo fmt --check`

Expected: PASS.

- [ ] **Step 2: Diff whitespace check**

Run: `git diff --check`

Expected: PASS.

- [ ] **Step 3: Desktop crate tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: PASS.

- [ ] **Step 4: Push commits**

Run: `git push`

Expected: current branch pushes to `origin/main`.

## Self-Review Checklist

- Spec coverage: this plan advances the MVP requirement that the UI can drive import, node choice, start/stop, dependency readiness, status, and support export without shelling out.
- Scope: it creates a backend command facade, not the visible shell.
- No placeholder steps remain.
- Type consistency: `DesktopCommandService`, `DesktopCommandError`, and existing runtime/dependency DTOs are used consistently.
