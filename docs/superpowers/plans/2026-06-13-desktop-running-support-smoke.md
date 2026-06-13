# Desktop Running Support Smoke Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a smoke command that auto-starts the managed desktop core, exports a support bundle while it is running, verifies diagnostic evidence, then stops and cleans up.

**Architecture:** Reuse the existing desktop startup smoke fixture and controller path in `keli-desktop-shell`. Add a report builder that checks the saved support bundle shape and the running-state diagnostic fields without touching real user support directories.

**Tech Stack:** Rust, Cargo, `keli-desktop-shell`, `keli-desktop`, `serde_json`, existing shell support export helpers.

---

### Task 1: Failing Tests

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add flag detection test**

Add a unit test named `startup_connect_support_smoke_arg_detection_accepts_flag` that expects `is_startup_connect_support_smoke_mode(["keli-desktop-shell", "--startup-connect-support-smoke"])` to be true and `is_startup_connect_support_smoke_mode(["keli-desktop-shell", "--startup-connect-smoke"])` to be false.

- [ ] **Step 2: Add report builder test**

Add a unit test named `running_support_smoke_report_confirms_running_diagnostics` with a JSON bundle containing:

```json
{
  "kind": "keli_desktop_support_bundle",
  "desktop_status": {
    "run_state": "running",
    "selected_outbound": "SS-RESTORED",
    "listen": "127.0.0.1:45678"
  },
  "managed_runtime_status": {
    "selected_outbound": "SS-RESTORED",
    "listen": "127.0.0.1:45678"
  },
  "desktop_diagnosis": {
    "connection": {
      "level": "healthy",
      "evidence": {
        "selected_outbound": "SS-RESTORED",
        "listen": "127.0.0.1:45678"
      }
    }
  },
  "core_support_bundle": {
    "kind": "keli_support_bundle",
    "redaction": {
      "profile_config_text": "omitted"
    }
  }
}
```

Assert that the report status is `passed` and that the running status, selected outbound, diagnosis evidence, redaction, last-record match, and stopped-after-smoke fields are all true.

- [ ] **Step 3: Verify red**

Run:

```powershell
cargo test -p keli-desktop-shell running_support_smoke_report_confirms_running_diagnostics -- --test-threads=1
```

Expected: compile failure or test failure because the new report builder and flag detection do not exist yet.

### Task 2: Smoke Report and CLI Flag

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add report struct**

Define `DesktopShellRunningSupportSmokeReport` with fields for status, path, byte count, format, `support_saved`, `desktop_status_running`, `desktop_status_selected`, `managed_status_selected`, `diagnosis_selected`, `connection_level`, `redaction_ready`, `last_record_matches`, and `stopped_after_smoke`.

- [ ] **Step 2: Add report builder**

Implement `build_running_support_smoke_report(summary, format, bundle, bundle_text, last_record_matches, stopped_after_smoke, expected_outbound)`. The status is `passed` only when every required field from the design is present and the bundle text does not expose `password: pass` or a raw `"password"` key.

- [ ] **Step 3: Add flag detection**

Implement `is_startup_connect_support_smoke_mode(args)` by checking for `--startup-connect-support-smoke`.

- [ ] **Step 4: Verify green for unit tests**

Run:

```powershell
cargo test -p keli-desktop-shell running_support_smoke_report_confirms_running_diagnostics -- --test-threads=1
cargo test -p keli-desktop-shell startup_connect_support_smoke_arg_detection_accepts_flag -- --test-threads=1
```

Expected: both tests pass.

### Task 3: Smoke Command

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Add temporary support directory helper**

Add `startup_connect_support_smoke_dir()` that returns a unique directory under `std::env::temp_dir()`.

- [ ] **Step 2: Add runner**

Implement `run_startup_connect_support_smoke()` to create the fixture store, apply startup connect settings, export the support bundle while running, write it to the temporary smoke directory, build and print the report, stop the core, clean up temp artifacts, and fail when the report status is not `passed`.

- [ ] **Step 3: Wire main**

Call `run_startup_connect_support_smoke()` when `--startup-connect-support-smoke` is present, before the narrower startup connect smoke branch.

- [ ] **Step 4: Verify command**

Run:

```powershell
cargo run -q -p keli-desktop-shell -- --startup-connect-support-smoke
```

Expected: JSON report with `"status": "passed"` and `"stopped_after_smoke": true`.

### Task 4: Regression Verification

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Format**

Run:

```powershell
cargo fmt
```

- [ ] **Step 2: Run shell and desktop tests**

Run:

```powershell
cargo test -p keli-desktop-shell -- --test-threads=1
cargo test -p keli-desktop -- --test-threads=1
```

Expected: both commands pass.

- [ ] **Step 3: Run smoke commands**

Run:

```powershell
cargo run -q -p keli-desktop-shell -- --startup-connect-support-smoke
cargo run -q -p keli-desktop-shell -- --startup-connect-smoke
cargo run -q -p keli-desktop-shell -- --startup-restore-smoke
cargo run -q -p keli-desktop-shell -- --smoke
```

Expected: every smoke command prints a JSON report with `"status": "passed"`.

- [ ] **Step 4: Check patch hygiene**

Run:

```powershell
git diff --check
```

Expected: no whitespace errors.

### Task 5: Commit and Push

**Files:**
- Add: `docs/superpowers/specs/2026-06-13-desktop-running-support-smoke-design.md`
- Add: `docs/superpowers/plans/2026-06-13-desktop-running-support-smoke.md`
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Commit docs**

Run:

```powershell
git add docs/superpowers/specs/2026-06-13-desktop-running-support-smoke-design.md docs/superpowers/plans/2026-06-13-desktop-running-support-smoke.md
git commit -m "docs: plan desktop running support smoke"
```

- [ ] **Step 2: Commit code**

Run:

```powershell
git add crates/keli-desktop-shell/src/main.rs
git commit -m "feat: add desktop running support smoke"
```

- [ ] **Step 3: Push**

Run:

```powershell
git push origin main
```
