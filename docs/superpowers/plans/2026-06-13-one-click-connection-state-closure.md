# One Click Connection State Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make desktop one click start and stop return shell snapshots with fresh dependency reports, so system proxy takeover and restoration status are accurate without a manual refresh.

**Architecture:** Keep snapshot consistency inside `DesktopShellController`. Lifecycle methods already own start and stop status updates, so they will also refresh `DesktopDependencyReport` immediately after successful lifecycle calls.

**Tech Stack:** Rust workspace, `keli-desktop` controller tests, existing fake `DesktopShellCommandHost`, Cargo test runner.

---

## File Structure

- Modify: `crates/keli-desktop/src/app.rs`
  - Controller lifecycle methods `request_start` and `request_stop`.
  - Existing test module helpers and lifecycle tests.

No new production files are needed. No shell HTML or WebView code should change in this plan.

---

### Task 1: Add Failing Controller Tests For Lifecycle Dependency Refresh

**Files:**
- Modify: `crates/keli-desktop/src/app.rs`
- Test: `crates/keli-desktop/src/app.rs`

- [ ] **Step 1: Add a test helper for enabled system proxy dependencies**

Add this helper inside the existing `#[cfg(test)] mod tests` near `ready_dependencies()`:

```rust
fn system_proxy_enabled_dependencies(server: &str) -> DesktopDependencyReport {
    let mut dependencies = ready_dependencies();
    dependencies.system_proxy.enabled = Some(true);
    dependencies.system_proxy.server = Some(server.to_string());
    dependencies
}
```

- [ ] **Step 2: Add the failing start refresh test**

Add this test near `shell_controller_request_start_updates_to_running`:

```rust
#[test]
fn shell_controller_request_start_refreshes_dependencies_after_lifecycle() {
    let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
    let observed = host.clone();
    let mut controller = DesktopShellController::new(host);

    controller
        .import_subscription_config("proxies: []")
        .expect("import subscription");
    observed.set_dependencies(system_proxy_enabled_dependencies("127.0.0.1:7890"));

    let shell = controller
        .dispatch(DesktopShellAction::RequestStart)
        .expect("request start");

    assert_eq!(observed.starts(), 1);
    assert_eq!(shell.status.run_state, DesktopRunState::Running);
    assert_eq!(shell.dependencies.system_proxy.enabled, Some(true));
    assert_eq!(
        shell.dependencies.system_proxy.server.as_deref(),
        Some("127.0.0.1:7890")
    );
}
```

- [ ] **Step 3: Add the failing stop refresh test**

Add this test near `shell_controller_request_stop_updates_to_stopped`:

```rust
#[test]
fn shell_controller_request_stop_refreshes_dependencies_after_lifecycle() {
    let host = FakeHost::new(
        status(DesktopRunState::Running),
        system_proxy_enabled_dependencies("127.0.0.1:7890"),
    );
    let observed = host.clone();
    let mut controller = DesktopShellController::new(host);

    controller
        .import_subscription_config("proxies: []")
        .expect("import subscription");
    observed.set_dependencies(ready_dependencies());

    let shell = controller
        .dispatch(DesktopShellAction::RequestStop)
        .expect("request stop");

    assert_eq!(observed.stops(), 1);
    assert_eq!(shell.status.run_state, DesktopRunState::Stopped);
    assert_eq!(shell.dependencies.system_proxy.enabled, Some(false));
    assert_eq!(shell.dependencies.system_proxy.server, None);
}
```

- [ ] **Step 4: Run the start test to verify it fails**

Run:

```powershell
cargo test -p keli-desktop shell_controller_request_start_refreshes_dependencies_after_lifecycle -- --test-threads=1
```

Expected: FAIL because `shell.dependencies.system_proxy.enabled` is still `Some(false)`.

- [ ] **Step 5: Run the stop test to verify it fails**

Run:

```powershell
cargo test -p keli-desktop shell_controller_request_stop_refreshes_dependencies_after_lifecycle -- --test-threads=1
```

Expected: FAIL because `shell.dependencies.system_proxy.enabled` is still `Some(true)`.

---

### Task 2: Refresh Dependencies After Successful Start And Stop

**Files:**
- Modify: `crates/keli-desktop/src/app.rs`
- Test: `crates/keli-desktop/src/app.rs`

- [ ] **Step 1: Update `request_start`**

Change the successful path of `request_start` from:

```rust
let status = self.host.start()?;
self.shell.refresh_status(status);
Ok(self.shell.clone())
```

to:

```rust
let status = self.host.start()?;
self.shell.refresh_status(status);
self.shell.refresh_dependencies(self.host.dependency_report());
Ok(self.shell.clone())
```

- [ ] **Step 2: Update `request_stop`**

Change the successful path of `request_stop` from:

```rust
let status = self.host.stop()?;
self.shell.refresh_status(status);
Ok(self.shell.clone())
```

to:

```rust
let status = self.host.stop()?;
self.shell.refresh_status(status);
self.shell.refresh_dependencies(self.host.dependency_report());
Ok(self.shell.clone())
```

- [ ] **Step 3: Run the focused start test**

Run:

```powershell
cargo test -p keli-desktop shell_controller_request_start_refreshes_dependencies_after_lifecycle -- --test-threads=1
```

Expected: PASS.

- [ ] **Step 4: Run the focused stop test**

Run:

```powershell
cargo test -p keli-desktop shell_controller_request_stop_refreshes_dependencies_after_lifecycle -- --test-threads=1
```

Expected: PASS.

---

### Task 3: Format, Verify, Commit, And Push

**Files:**
- Modify: `crates/keli-desktop/src/app.rs`

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

- [ ] **Step 3: Run desktop shell smoke**

Run:

```powershell
cargo run -q -p keli-desktop-shell -- --smoke
```

Expected: JSON output contains `"status": "passed"`.

- [ ] **Step 4: Run whitespace check**

Run:

```powershell
git diff --check
```

Expected: exit code 0.

- [ ] **Step 5: Inspect changed files**

Run:

```powershell
git status --short
git diff --stat
```

Expected: only `crates/keli-desktop/src/app.rs` changed for implementation.

- [ ] **Step 6: Commit implementation**

Run:

```powershell
git add crates/keli-desktop/src/app.rs
git commit -m "feat: refresh dependencies after lifecycle actions"
```

Expected: one commit containing the tests and controller change.

- [ ] **Step 7: Push `main`**

Run:

```powershell
git push origin main
```

Expected: remote `main` advances successfully.
