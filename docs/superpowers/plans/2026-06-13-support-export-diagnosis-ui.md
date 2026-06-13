# Support Export Diagnosis UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show the live connection diagnosis next to support bundle export controls so the user can see what the exported support bundle will explain.

**Architecture:** Reuse the existing `connection_diagnosis(snapshot)` model in `crates/keli-desktop-shell/src/html.rs`. Render compact diagnosis summary/action text into support export panels at initial HTML render time, then keep those DOM nodes fresh through a small JavaScript sync helper that calls the existing `connectionDiagnosis(snapshot)`.

**Tech Stack:** Rust HTML string rendering, embedded JavaScript, `keli-desktop-shell` unit tests, desktop shell smoke tests.

---

## File Structure

- Modify: `crates/keli-desktop-shell/src/html.rs`
  - Add Rust helper functions that turn `ConnectionDiagnosis` into support export summary strings.
  - Add support diagnosis DOM nodes in support export areas.
  - Add JavaScript helper functions and live sync call.
  - Add tests that prove the diagnosis is visible and live-updated.

No desktop core, support bundle JSON, or IPC command files should change.

---

### Task 1: Add Failing Support Diagnosis UI Tests

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Test: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Extend the support export HTML test**

In `support_export_html_includes_export_button_and_status`, add these assertions after the existing support status assertion:

```rust
assert!(html.contains("id=\"support-export-diagnosis\""));
assert!(html.contains("id=\"support-export-action\""));
assert!(html.contains("支持包将包含：未配置订阅"));
assert!(html.contains("建议动作：登录面板或导入订阅"));
```

- [ ] **Step 2: Extend the diagnostics support panel test**

In `diagnostics_baseline_includes_support_settings_and_live_sync`, add these assertions after the diagnostics support status assertion:

```rust
assert!(html.contains("id=\"diagnostics-support-diagnosis\""));
assert!(html.contains("id=\"diagnostics-support-action\""));
assert!(html.contains("syncSupportDiagnosis(snapshot)"));
```

- [ ] **Step 3: Add a classified diagnosis rendering test**

Add this test near `support_export_html_includes_export_button_and_status`:

```rust
#[test]
fn support_export_ui_summarizes_connection_diagnosis() {
    let mut snapshot = snapshot();
    snapshot.status.last_error =
        Some("Managed(\"bind failed: address already in use\")".to_string());

    let html = render_shell_html(&snapshot);

    assert!(html.contains("支持包将包含：端口被占用"));
    assert!(html.contains("关闭占用端口或切换本地监听"));
    assert!(html.contains("function supportDiagnosisSummary(diagnosis)"));
    assert!(html.contains("function syncSupportDiagnosis(snapshot)"));
}
```

- [ ] **Step 4: Run focused tests and verify they fail**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_html_includes_export_button_and_status -- --test-threads=1
cargo test -p keli-desktop-shell diagnostics_baseline_includes_support_settings_and_live_sync -- --test-threads=1
cargo test -p keli-desktop-shell support_export_ui_summarizes_connection_diagnosis -- --test-threads=1
```

Expected result: at least one command FAILS because `support-export-diagnosis`, `diagnostics-support-diagnosis`, `supportDiagnosisSummary`, and `syncSupportDiagnosis` do not exist yet.

---

### Task 2: Render Support Diagnosis In Static HTML

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Test: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add support diagnosis strings in `render_shell_html`**

After:

```rust
let connection_diagnosis = connection_diagnosis(snapshot);
let connection_diagnosis_actions = connection_diagnosis_action_buttons(snapshot);
```

add:

```rust
let support_diagnosis_summary = support_diagnosis_summary(&connection_diagnosis);
let support_diagnosis_action = support_diagnosis_action(&connection_diagnosis);
```

- [ ] **Step 2: Add support export diagnosis DOM nodes to the legacy support area**

In the legacy diagnostics section after:

```html
<div class="muted" id="support-export-status">尚未导出支持包</div>
```

add:

```html
<div class="muted" id="support-export-diagnosis">{support_diagnosis_summary}</div>
<div class="muted" id="support-export-action">{support_diagnosis_action}</div>
```

- [ ] **Step 3: Add support export diagnosis DOM nodes to the diagnostics support panel**

In `diagnostics-support-panel` after:

```html
<div class="muted" id="diagnostics-support-status">尚未导出支持包</div>
```

add:

```html
<div class="muted" id="diagnostics-support-diagnosis">{support_diagnosis_summary}</div>
<div class="muted" id="diagnostics-support-action">{support_diagnosis_action}</div>
```

- [ ] **Step 4: Add format arguments**

In the final `format!` argument list for `render_shell_html`, add:

```rust
support_diagnosis_summary = escape_html(&support_diagnosis_summary),
support_diagnosis_action = escape_html(&support_diagnosis_action),
```

Place these near the other `connection_diagnosis_*` format arguments.

- [ ] **Step 5: Add Rust helper functions**

After `struct ConnectionDiagnosis`, add:

```rust
fn support_diagnosis_summary(diagnosis: &ConnectionDiagnosis) -> String {
    format!("支持包将包含：{} - {}", diagnosis.title, diagnosis.detail)
}

fn support_diagnosis_action(diagnosis: &ConnectionDiagnosis) -> String {
    format!("建议动作：{}", diagnosis.action)
}
```

- [ ] **Step 6: Run focused static rendering tests**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_html_includes_export_button_and_status -- --test-threads=1
cargo test -p keli-desktop-shell support_export_ui_summarizes_connection_diagnosis -- --test-threads=1
```

Expected: the static rendering assertions pass, while live-sync assertions may still fail until Task 3.

---

### Task 3: Keep Support Diagnosis Fresh In Live Sync

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Test: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Add JavaScript support diagnosis helpers**

After `function setText(id, value)`, add:

```javascript
function supportDiagnosisSummary(diagnosis) {
  return `支持包将包含：${diagnosis.title} - ${diagnosis.detail}`;
}
function supportDiagnosisAction(diagnosis) {
  return `建议动作：${diagnosis.action}`;
}
function syncSupportDiagnosis(snapshot) {
  const diagnosis = connectionDiagnosis(snapshot);
  const summary = supportDiagnosisSummary(diagnosis);
  const action = supportDiagnosisAction(diagnosis);
  setText("support-export-diagnosis", summary);
  setText("support-export-action", action);
  setText("diagnostics-support-diagnosis", summary);
  setText("diagnostics-support-action", action);
}
```

- [ ] **Step 2: Call support diagnosis sync from dashboard sync**

In `window.keliSyncDashboard = (snapshot) => { ... }`, after:

```javascript
renderDependencyActions(snapshot);
```

add:

```javascript
syncSupportDiagnosis(snapshot);
```

- [ ] **Step 3: Call support diagnosis sync from diagnostics sync**

In `window.keliSyncDiagnosticsView = (snapshot) => { ... }`, after:

```javascript
renderDiagnosticsRuntimeLog(snapshot);
```

add:

```javascript
syncSupportDiagnosis(snapshot);
```

- [ ] **Step 4: Run focused live-sync tests**

Run:

```powershell
cargo test -p keli-desktop-shell diagnostics_baseline_includes_support_settings_and_live_sync -- --test-threads=1
cargo test -p keli-desktop-shell diagnostics_live_renderer_updates_health_summary -- --test-threads=1
```

Expected: PASS.

---

### Task 4: Verify, Commit, And Push

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Format Rust code**

Run:

```powershell
cargo fmt
```

Expected: exit code 0.

- [ ] **Step 2: Run full shell tests**

Run:

```powershell
cargo test -p keli-desktop-shell -- --test-threads=1
```

Expected: all tests pass.

- [ ] **Step 3: Run desktop shell smoke**

Run:

```powershell
cargo run -q -p keli-desktop-shell -- --smoke
```

Expected: JSON output contains `"status": "passed"`.

- [ ] **Step 4: Run support export smoke**

Run:

```powershell
cargo run -q -p keli-desktop-shell -- --support-export-smoke target\desktop-support-export-smoke
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

Expected: implementation changes are limited to `crates/keli-desktop-shell/src/html.rs`.

- [ ] **Step 7: Commit implementation**

Run:

```powershell
git add crates/keli-desktop-shell/src/html.rs
git commit -m "feat: show support export diagnosis in shell"
```

Expected: one implementation commit.

- [ ] **Step 8: Push `main`**

Run:

```powershell
git push origin main
```

Expected: remote `main` advances successfully.
