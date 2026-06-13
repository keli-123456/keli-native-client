# Support Export Last Record Design

## Context

The desktop shell can export a support bundle, show the saved file path, and open the default support directory. That state only lives in the current WebView session. After restarting the client, the support panel goes back to "尚未导出支持包" even if the latest bundle is still on disk.

Users need the diagnostics path to survive a restart so they can find the last generated support bundle without exporting again.

## Goal

Persist the latest successful support bundle export summary and restore it into the desktop UI on startup.

## Options

Recommended: write a small JSON metadata file beside the exported bundles in the default support directory.

Tradeoff: this keeps the implementation local to the desktop shell and avoids adding a database or changing the core desktop controller. The metadata is easy to inspect and safe to ignore if corrupted.

Alternative: derive the latest bundle by scanning `keli-support-*.json` files.

Tradeoff: this avoids one metadata file but requires filename ordering, file metadata handling, and format assumptions. It is more fragile than writing the exact summary we already have after export.

Alternative: add a persisted field to `DesktopShellState`.

Tradeoff: this would make startup rendering cleaner later, but it pushes a desktop-shell-only file path concern into the shared desktop model.

## Design

`crates/keli-desktop-shell/src/support.rs` owns the persisted record:

- `support_export_record_path(directory)` returns `<directory>/last-support-export.json`.
- `write_support_bundle_export` writes the support bundle and then writes the serialized `SupportBundleSaveSummary` to that metadata path.
- `read_last_support_bundle_export(directory)` reads and deserializes the summary.
- Missing, unreadable, or invalid metadata returns `Ok(None)` so startup and support export smoke are not blocked by stale local state.

The metadata schema reuses `SupportBundleSaveSummary`:

- `status`
- `path`
- `directory`
- `byte_count`

`crates/keli-desktop-shell/src/main.rs` restores the record after creating the WebView:

- Render the shell normally.
- Read `read_last_support_bundle_export(default_support_export_dir())`.
- If a saved summary exists, evaluate `support_export_status_script(&summary)`.
- Log restore errors but do not fail application launch.

The support export smoke path should also prove persistence by reading the metadata after export and reporting whether it matches the exported path.

## UI Behavior

On a fresh machine, the support panel remains unchanged: status says no bundle was exported and the open-directory button stays disabled.

After one successful export, future launches show the last exported file and directory immediately. The open-directory button is enabled because the restored summary includes a directory.

If the metadata is corrupt, the UI behaves like no export has happened. The next successful export overwrites the metadata.

## Testing

Add support module tests for:

- Writing an export creates `last-support-export.json`.
- Reading the record returns the same path, directory, and byte count.
- Reading a missing record returns `None`.
- Reading invalid JSON returns `None`.

Add shell smoke coverage:

- `DesktopShellSupportExportSmokeReport` includes `last_record_matches`.
- The support export smoke command passes only when the exported bundle shape is valid and the persisted record matches the exported path.

Existing HTML tests continue to cover that a restored summary enables the path display through `window.keliSetSupportExport`.
