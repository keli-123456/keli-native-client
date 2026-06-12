# Desktop URL Button Initial State Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the initial desktop HTML render disable subscription URL buttons consistently with live shell snapshot updates.

**Architecture:** `render_shell_html` will derive initial button disabled attributes from `snapshot.status.run_state`, matching the existing `window.keliSetShell` logic. Stopped shells allow importing a URL and disable updating; running shells disable importing a fresh URL and allow updating the running subscription URL.

**Tech Stack:** Rust desktop shell HTML rendering, existing `DesktopRunState`, existing `keli-desktop-shell` tests.

---

### Task 1: Initial URL Button State

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Write the failing stopped-state test**

Add this test near `subscription_url_html_includes_running_update_controls`:

```rust
#[test]
fn subscription_url_update_button_starts_disabled_when_stopped() {
    let html = render_shell_html(&snapshot());

    assert!(html.contains("id=\"import-subscription-url-button\" class=\"primary\" onclick=\"postImportSubscriptionUrl()\">Import URL</button>"));
    assert!(html.contains("id=\"update-subscription-url-button\" onclick=\"postUpdateSubscriptionUrl()\" disabled>Update URL</button>"));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
cargo test -p keli-desktop-shell subscription_url_update_button_starts_disabled_when_stopped -- --nocapture
```

Expected: FAIL because the Update URL button is initially enabled in stopped state.

- [ ] **Step 3: Write the failing running-state test**

Add this test:

```rust
#[test]
fn subscription_url_import_button_starts_disabled_when_running() {
    let mut snapshot = snapshot();
    snapshot.refresh_status(DesktopStatusSnapshot {
        run_state: DesktopRunState::Running,
        ..snapshot.status.clone()
    });

    let html = render_shell_html(&snapshot);

    assert!(html.contains("id=\"import-subscription-url-button\" class=\"primary\" onclick=\"postImportSubscriptionUrl()\" disabled>Import URL</button>"));
    assert!(html.contains("id=\"update-subscription-url-button\" onclick=\"postUpdateSubscriptionUrl()\">Update URL</button>"));
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run:

```powershell
cargo test -p keli-desktop-shell subscription_url_import_button_starts_disabled_when_running -- --nocapture
```

Expected: FAIL because the Import URL button is initially enabled in running state.

- [ ] **Step 5: Implement initial disabled attributes**

In `render_shell_html`, add:

```rust
let import_subscription_url_disabled = if snapshot.status.run_state == DesktopRunState::Running {
    " disabled"
} else {
    ""
};
let update_subscription_url_disabled = if snapshot.status.run_state == DesktopRunState::Running {
    ""
} else {
    " disabled"
};
```

Update the two button templates:

```html
<button id="import-subscription-url-button" class="primary" onclick="postImportSubscriptionUrl()"{import_subscription_url_disabled}>Import URL</button>
<button id="update-subscription-url-button" onclick="postUpdateSubscriptionUrl()"{update_subscription_url_disabled}>Update URL</button>
```

Pass both new values into the final `format!`.

- [ ] **Step 6: Run shell tests**

Run:

```powershell
cargo test -p keli-desktop-shell -- --nocapture
```

Expected: PASS.

### Task 2: Gate Verification

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Format and gate**

Run:

```powershell
cargo fmt
powershell -ExecutionPolicy Bypass -File scripts\desktop-mvp-gate.ps1
```

Expected: MVP gate PASS.

- [ ] **Step 2: Check release readiness**

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\desktop-release-readiness.ps1 -Json
```

Expected: `machine_takeover_status = "ready"` and public release blockers remain only `artifact-signature-missing` and `signing-certificate-missing`.

### Task 3: Commit

**Files:**
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Commit implementation**

Run:

```powershell
git add crates/keli-desktop-shell/src/html.rs
git commit -m "Align desktop URL button initial state"
git push
```

Expected: commit pushed to `origin/main`.
