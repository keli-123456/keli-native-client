# Desktop Settings Runtime Application Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make persisted `mixed_port` settings apply to the real desktop runtime listen address before one-click start.

**Architecture:** Add a small listen setter to the existing `keli-desktop` shell controller boundary, then have `keli-desktop-shell` translate settings into `127.0.0.1:<mixed_port>` on startup and save. Smoke evidence distinguishes persistence from runtime application.

**Tech Stack:** Rust 2021, existing `keli-desktop` controller/host trait, existing `keli-desktop-shell` Wry shell and smoke report.

---

## File Structure

- Modify: `crates/keli-desktop/src/app.rs`
  - Add `set_listen` to `DesktopShellCommandHost`, native forwarding, controller method, and fake-host tests.
- Modify: `crates/keli-desktop-shell/src/main.rs`
  - Add settings-to-listen helper, apply settings on launch/save, and extend smoke evidence.
- Add docs:
  - `docs/superpowers/specs/2026-06-13-desktop-settings-runtime-application-design.md`
  - `docs/superpowers/plans/2026-06-13-desktop-settings-runtime-application.md`

## Task 1: Controller Listen Setter

- [ ] **Step 1: Write failing test**

In `crates/keli-desktop/src/app.rs`, add a test beside `shell_subscription_traffic_mode_setter_refreshes_status`:

```rust
#[test]
fn shell_subscription_listen_setter_refreshes_status() {
    let host = FakeHost::new(status(DesktopRunState::Stopped), ready_dependencies());
    let observed = host.clone();
    let mut controller = DesktopShellController::new(host);

    let shell = controller.set_listen("127.0.0.1:17890");

    assert_eq!(observed.listens(), vec!["127.0.0.1:17890".to_string()]);
    assert_eq!(shell.status.listen.as_deref(), Some("127.0.0.1:17890"));
}
```

- [ ] **Step 2: Verify red**

Run: `cargo test -p keli-desktop shell_subscription_listen_setter_refreshes_status -- --test-threads=1`

Expected: FAIL because `DesktopShellController::set_listen` and fake-host listen tracking do not exist.

- [ ] **Step 3: Implement minimal controller support**

Add `fn set_listen(&mut self, listen: String);` to `DesktopShellCommandHost`, forward it through `DesktopNativeCommandService`, and add:

```rust
pub fn set_listen(&mut self, listen: impl Into<String>) -> DesktopShellState {
    self.host.set_listen(listen.into());
    self.shell.refresh_status(self.host.status());
    self.shell.clone()
}
```

Update `FakeHostState` with `listens: Vec<String>`, `FakeHost::listens()`, and fake `set_listen` implementation that updates `status.listen`.

- [ ] **Step 4: Verify green**

Run: `cargo test -p keli-desktop shell_subscription_listen_setter_refreshes_status -- --test-threads=1`

Expected: PASS.

## Task 2: Shell Settings Apply Listen

- [ ] **Step 1: Write failing shell tests**

In `crates/keli-desktop-shell/src/main.rs`, add tests:

```rust
#[test]
fn desktop_settings_listen_address_uses_mixed_port() {
    let mut settings = DesktopShellSettings::default();
    settings.mixed_port = 17890;

    assert_eq!(desktop_settings_listen_address(&settings), "127.0.0.1:17890");
}
```

Extend `smoke_report_confirms_shell_rendering_contract` with:

```rust
assert!(report.settings_runtime_ready);
```

- [ ] **Step 2: Verify red**

Run: `cargo test -p keli-desktop-shell desktop_settings_listen_address_uses_mixed_port -- --test-threads=1`

Expected: FAIL because helper does not exist.

- [ ] **Step 3: Apply settings on launch/save**

Add:

```rust
fn desktop_settings_listen_address(settings: &DesktopShellSettings) -> String {
    format!("127.0.0.1:{}", settings.mixed_port)
}

fn apply_desktop_settings(
    controller: &mut DesktopShellController<keli_desktop::DesktopNativeCommandService>,
    settings: &DesktopShellSettings,
) -> DesktopShellState {
    controller.set_traffic_mode(settings.traffic_mode);
    controller.set_listen(desktop_settings_listen_address(settings))
}
```

Use `apply_desktop_settings` on launch and in `save_desktop_settings`.

- [ ] **Step 4: Extend smoke**

Add `settings_runtime_ready: bool` to `DesktopShellSmokeReport`. Set it true when HTML has settings persistence entrypoints and `settings_persistence_ready` is true. Include it in pass/fail.

- [ ] **Step 5: Verify shell tests**

Run: `cargo test -p keli-desktop-shell desktop_settings_listen_address_uses_mixed_port smoke_report_confirms_shell_rendering_contract -- --test-threads=1`

Because Cargo accepts one filter at a time, run the two named tests separately.

Expected: both PASS.

## Task 3: Final Verification

- [ ] **Step 1: Format**

Run: `cargo fmt`

Expected: exit code 0.

- [ ] **Step 2: Run desktop tests**

Run: `cargo test -p keli-desktop -- --test-threads=1`

Expected: all tests pass.

- [ ] **Step 3: Run shell tests**

Run: `cargo test -p keli-desktop-shell -- --test-threads=1`

Expected: all tests pass.

- [ ] **Step 4: Run shell smoke**

Run: `cargo run -q -p keli-desktop-shell -- --smoke`

Expected JSON includes `"status": "passed"`, `"settings_persistence_ready": true`, and `"settings_runtime_ready": true`.

- [ ] **Step 5: Check diff and commit**

Run: `git diff --check`

Expected: no whitespace errors.

Commit:

```bash
git add docs/superpowers/specs/2026-06-13-desktop-settings-runtime-application-design.md docs/superpowers/plans/2026-06-13-desktop-settings-runtime-application.md crates/keli-desktop/src/app.rs crates/keli-desktop-shell/src/main.rs
git commit -m "feat: apply desktop settings listen port"
```

## Self Review

- Spec coverage: the plan wires `mixed_port` to runtime listen, keeps non-mapped settings as persistence-only, and adds smoke evidence.
- Placeholder scan: no TBD/TODO placeholders.
- Type consistency: `set_listen`, `desktop_settings_listen_address`, `settings_runtime_ready`, and `DesktopShellSettings::mixed_port` are consistently named.
