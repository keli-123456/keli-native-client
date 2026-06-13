# Support Export Last Record Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist the latest successful desktop support bundle export summary and restore it into the UI on launch.

**Architecture:** Keep persistence in `keli-desktop-shell/src/support.rs` by writing `last-support-export.json` beside exported bundles. Startup in `main.rs` reads that summary and evaluates the existing support export status script after the WebView is created. Smoke mode verifies the persisted record matches the exported bundle path.

**Tech Stack:** Rust 2021, `serde_json`, existing Wry WebView script bridge, existing desktop shell smoke commands.

---

## File Structure

- Modify `crates/keli-desktop-shell/src/support.rs`
  - Add record path, write, and read helpers.
  - Persist the summary after a successful export.
  - Add support-layer tests for persisted, missing, and invalid records.
- Modify `crates/keli-desktop-shell/src/main.rs`
  - Import the read helper.
  - Restore the persisted summary after WebView creation.
  - Extend support export smoke report with `last_record_matches`.
- No HTML structural changes are required because `window.keliSetSupportExport` already accepts `SupportBundleSaveSummary` and enables the open-directory buttons.

## Task 1: Persist Support Export Summary

**Files:**
- Modify: `crates/keli-desktop-shell/src/support.rs`

- [ ] **Step 1: Write failing test for persisted record**

Add this test after `support_export_writer_creates_json_file_and_reports_path`:

```rust
#[test]
fn support_export_writer_persists_last_export_record() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("keli-support-export-record-test-{unique}"));

    let summary = write_support_bundle_export(&export(), &dir).expect("write support bundle");
    let restored = read_last_support_bundle_export(&dir)
        .expect("read support record")
        .expect("support record");

    assert_eq!(restored, summary);

    let _ = fs::remove_dir_all(dir);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_writer_persists_last_export_record -- --test-threads=1
```

Expected: FAIL because `read_last_support_bundle_export` is not defined.

- [ ] **Step 3: Add record persistence helpers**

In `support.rs`, change the serde import:

```rust
use serde::{Deserialize, Serialize};
```

Change the derive:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportBundleSaveSummary {
```

Add helpers after `default_support_export_dir`:

```rust
pub fn support_export_record_path(directory: impl AsRef<Path>) -> PathBuf {
    directory.as_ref().join("last-support-export.json")
}

pub fn read_last_support_bundle_export(
    directory: impl AsRef<Path>,
) -> io::Result<Option<SupportBundleSaveSummary>> {
    let path = support_export_record_path(directory);
    match fs::read(&path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn write_last_support_bundle_export(
    directory: impl AsRef<Path>,
    summary: &SupportBundleSaveSummary,
) -> io::Result<()> {
    let path = support_export_record_path(directory);
    let bytes = serde_json::to_vec_pretty(summary)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    fs::write(path, bytes)
}
```

In `write_support_bundle_export`, build the summary, write the record, then return it:

```rust
let summary = SupportBundleSaveSummary {
    status: "saved".to_string(),
    path: path.to_string_lossy().into_owned(),
    directory: directory.to_string_lossy().into_owned(),
    byte_count: export.bytes.len(),
};
write_last_support_bundle_export(directory, &summary)?;
Ok(summary)
```

- [ ] **Step 4: Run persisted record test**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_writer_persists_last_export_record -- --test-threads=1
```

Expected: PASS.

- [ ] **Step 5: Add missing and invalid record tests**

Add:

```rust
#[test]
fn support_export_record_reader_ignores_missing_record() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("keli-support-export-missing-record-test-{unique}"));

    let restored = read_last_support_bundle_export(&dir).expect("read missing support record");

    assert_eq!(restored, None);
}

#[test]
fn support_export_record_reader_ignores_invalid_json() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("keli-support-export-invalid-record-test-{unique}"));
    fs::create_dir_all(&dir).expect("create dir");
    fs::write(support_export_record_path(&dir), b"{not-json").expect("write invalid record");

    let restored = read_last_support_bundle_export(&dir).expect("read invalid support record");

    assert_eq!(restored, None);

    let _ = fs::remove_dir_all(dir);
}
```

- [ ] **Step 6: Run support tests**

Run:

```powershell
cargo test -p keli-desktop-shell support_export -- --test-threads=1
```

Expected: PASS.

- [ ] **Step 7: Commit support persistence**

Run:

```powershell
git add crates/keli-desktop-shell/src/support.rs
git commit -m "feat: persist last support export summary"
```

## Task 2: Restore Persisted Summary On Launch

**Files:**
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Write failing smoke report test**

In `support_export_smoke_report_confirms_bundle_shape`, add:

```rust
last_record_matches: true,
```

to the expected `SupportBundleSaveSummary` report inputs if needed by the new report field, then add:

```rust
assert!(report.last_record_matches);
```

This will fail after adding the assertion because `DesktopShellSupportExportSmokeReport` does not yet have the field.

- [ ] **Step 2: Run test to verify it fails**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_smoke_report_confirms_bundle_shape -- --test-threads=1
```

Expected: FAIL because `last_record_matches` is not defined.

- [ ] **Step 3: Extend smoke report**

Import the read helper:

```rust
use support::{default_support_export_dir, read_last_support_bundle_export, write_support_bundle_export};
```

Add the field:

```rust
last_record_matches: bool,
```

Change `build_support_export_smoke_report` to accept `last_record_matches: bool`:

```rust
fn build_support_export_smoke_report(
    summary: &support::SupportBundleSaveSummary,
    format: &str,
    bundle: &serde_json::Value,
    last_record_matches: bool,
) -> DesktopShellSupportExportSmokeReport {
```

Include it in the status condition:

```rust
&& last_record_matches
```

and report:

```rust
last_record_matches,
```

Update callers:

```rust
let last_record_matches = read_last_support_bundle_export(&summary.directory)
    .ok()
    .flatten()
    .map(|record| record.path == summary.path && record.directory == summary.directory)
    .unwrap_or(false);
let report = build_support_export_smoke_report(&summary, &export.format, &bundle, last_record_matches);
```

Test fixture call should pass `true`.

- [ ] **Step 4: Add startup restore helper**

After WebView creation in `main`, call:

```rust
sync_last_support_export(&webview);
```

Add helper near `sync_support_export_failure`:

```rust
fn sync_last_support_export(webview: &WebView) {
    match read_last_support_bundle_export(default_support_export_dir()) {
        Ok(Some(summary)) => match support_export_status_script(&summary) {
            Ok(script) => {
                if let Err(error) = webview.evaluate_script(&script) {
                    eprintln!("last support export restore sync failed: {error}");
                }
            }
            Err(error) => {
                eprintln!("last support export restore serialization failed: {error}");
            }
        },
        Ok(None) => {}
        Err(error) => {
            eprintln!("last support export restore read failed: {error}");
        }
    }
}
```

- [ ] **Step 5: Run smoke report test**

Run:

```powershell
cargo test -p keli-desktop-shell support_export_smoke_report_confirms_bundle_shape -- --test-threads=1
```

Expected: PASS.

- [ ] **Step 6: Run support export smoke**

Run:

```powershell
cargo run -q -p keli-desktop-shell -- --support-export-smoke target\desktop-support-export-smoke
```

Expected: PASS and JSON includes `"last_record_matches": true`.

- [ ] **Step 7: Commit launch restore**

Run:

```powershell
git add crates/keli-desktop-shell/src/main.rs
git commit -m "feat: restore last support export in shell"
```

## Task 3: Full Verification

**Files:**
- Verify full workspace state.

- [ ] **Step 1: Format**

Run:

```powershell
cargo fmt
```

Expected: exit 0.

- [ ] **Step 2: Desktop shell tests**

Run:

```powershell
cargo test -p keli-desktop-shell -- --test-threads=1
```

Expected: all tests pass.

- [ ] **Step 3: Desktop smoke**

Run:

```powershell
cargo run -q -p keli-desktop-shell -- --smoke
```

Expected: JSON status is `passed`.

- [ ] **Step 4: Support export smoke**

Run:

```powershell
cargo run -q -p keli-desktop-shell -- --support-export-smoke target\desktop-support-export-smoke
```

Expected: JSON status is `passed` and `last_record_matches` is `true`.

- [ ] **Step 5: Diff check**

Run:

```powershell
git diff --check
git status --short
```

Expected: no whitespace errors; only intentional files changed before final commit.

- [ ] **Step 6: Commit and push if final verification changed formatted files**

If `cargo fmt` changed files after previous commits, commit:

```powershell
git add crates/keli-desktop-shell/src/support.rs crates/keli-desktop-shell/src/main.rs
git commit -m "chore: format support export persistence"
```

Then push:

```powershell
git push origin main
```

## Self-Review

- Spec coverage: the plan persists the latest summary, restores it on launch, and verifies smoke metadata.
- Placeholder scan: no placeholder markers or vague test instructions remain.
- Type consistency: `SupportBundleSaveSummary`, `read_last_support_bundle_export`, and `last_record_matches` are named consistently across support and main tasks.
