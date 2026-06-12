# Desktop Shell Support Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for the implementation tasks and superpowers:verification-before-completion before completion claims. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a Windows desktop user export a redacted diagnostics support bundle from the WebView without using the command line.

**Architecture:** Keep support bundle generation in `keli-desktop`. Extend `DesktopShellCommandHost` and `DesktopShellController` to expose `export_support_bundle`. Add shell-side file writing in `keli-desktop-shell`, because the visible desktop shell owns user-facing filesystem destinations. The WebView sends an `export-support-bundle` IPC message and receives a snapshot/status update after the file is written.

**Tech Stack:** Rust 2021, `keli-desktop`, `keli-desktop-shell`, existing `DesktopSupportBundleExport`, `std::fs`.

---

## Scope Check

This plan covers:

- Controller support bundle export through the existing native command host.
- Shell-side export file naming and writing.
- JSON IPC for `export-support-bundle`.
- WebView diagnostics section with export status and path.
- Tests for export controller dispatch, file writing, IPC parsing, and HTML rendering.

This plan does not cover:

- A native save-file dialog.
- Zip packaging.
- Persisted export history.
- Opening the exported file/folder.
- Manual Windows diagnostics smoke.

## File Structure

- Modify: `crates/keli-desktop/src/app.rs`
  - Extend `DesktopShellCommandHost`.
  - Add `DesktopShellController::export_support_bundle`.
- Add: `crates/keli-desktop-shell/src/support.rs`
  - Define `SupportBundleSaveSummary`.
  - Write support bundle bytes to a user-facing path.
- Modify: `crates/keli-desktop-shell/src/actions.rs`
  - Add `ExportSupportBundle`.
- Modify: `crates/keli-desktop-shell/src/html.rs`
  - Add diagnostics export controls and status updater.
- Modify: `crates/keli-desktop-shell/src/main.rs`
  - Dispatch export event, write file, update WebView.

## Task 1: RED Tests

**Files:**
- Modify: `crates/keli-desktop/src/app.rs`
- Add/modify: `crates/keli-desktop-shell/src/support.rs`
- Modify: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`

- [ ] **Step 1: Write failing tests**

Add tests that expect:

- `DesktopShellController::export_support_bundle` calls the host and returns bytes.
- `write_support_bundle_export` creates a `.json` file and reports path/byte count.
- IPC message `export-support-bundle` maps to `ExportSupportBundle`.
- HTML includes an export support bundle button and status elements.
- Support export status script calls `window.keliSetSupportExport`.

- [ ] **Step 2: Run tests to verify RED**

Run:

- `cargo test -p keli-desktop shell_support -- --test-threads=1`
- `cargo test -p keli-desktop-shell support_export -- --test-threads=1`

Expected: FAIL because these APIs and UI hooks do not exist.

## Task 2: Implement Support Export

**Files:**
- Modify: `crates/keli-desktop/src/app.rs`
- Add: `crates/keli-desktop-shell/src/support.rs`
- Modify: `crates/keli-desktop-shell/src/actions.rs`
- Modify: `crates/keli-desktop-shell/src/html.rs`
- Modify: `crates/keli-desktop-shell/src/main.rs`

- [ ] **Step 1: Extend controller**

Add host trait method:

- `export_support_bundle`

Implement for native host and fake host tests.

- [ ] **Step 2: Add shell file writer**

Default destination:

- `%USERPROFILE%\Documents\Keli\Support` on Windows when available.
- `std::env::temp_dir()/keli/support` fallback.

- [ ] **Step 3: Add IPC and HTML**

Add:

- `ExportSupportBundle` UI event.
- export button.
- `window.keliSetSupportExport(summary)` updater.

- [ ] **Step 4: Dispatch export in shell binary**

Call controller export, write file, evaluate the support export status script, then sync the shell snapshot.

## Task 3: Verification, Commit, And Push

**Files:**
- `crates/keli-desktop/src/app.rs`
- `crates/keli-desktop-shell/src/support.rs`
- `crates/keli-desktop-shell/src/actions.rs`
- `crates/keli-desktop-shell/src/html.rs`
- `crates/keli-desktop-shell/src/main.rs`
- `docs/superpowers/plans/2026-06-12-desktop-shell-support-export.md`

- [ ] **Step 1: Format check**

Run: `cargo fmt --check`

Expected: PASS.

- [ ] **Step 2: Diff whitespace check**

Run: `git diff --check`

Expected: PASS.

- [ ] **Step 3: Target tests**

Run:

- `cargo test -p keli-desktop shell_support -- --test-threads=1`
- `cargo test -p keli-desktop-shell support_export -- --test-threads=1`

Expected: PASS.

- [ ] **Step 4: Full affected checks**

Run:

- `cargo test -p keli-desktop -- --test-threads=1`
- `cargo test -p keli-desktop-shell`
- `cargo check -p keli-desktop-shell`

Expected: PASS.

- [ ] **Step 5: Commit and push**

Commit the plan first, then commit the implementation after verification. Push each commit to `origin/main`.

## Self-Review Checklist

- Spec coverage: advances diagnostics support bundle export without command-line use.
- Scope: no native file dialog or zip packaging in this slice.
- Runtime ownership: generated bundle still comes from existing desktop backend support export.
- UI readiness: the visible shell can show exactly where the support JSON was written.
