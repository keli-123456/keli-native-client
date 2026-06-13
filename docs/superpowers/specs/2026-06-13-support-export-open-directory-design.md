# Support Export Open Directory Design

## Goal

After a support bundle is exported, the desktop UI should show where the file was saved and provide a direct "open directory" action so users can find the JSON without manually browsing the filesystem.

## Context

The shell already writes support bundles through `write_support_bundle_export`, then sends `SupportBundleSaveSummary` to `window.keliSetSupportExport`. The UI currently shows a status line such as saved byte count and full file path, but there is no dedicated path field or action to open the containing folder.

The shell already has platform-specific launch helpers for dependency actions. This feature should follow that pattern while avoiding arbitrary path launches from webview input.

## Chosen Approach

Add the export directory to the save summary, display both file and directory in the support panels, and add a disabled-by-default "打开目录" button that becomes enabled after a successful export.

Alternatives considered:

- Let the browser derive the directory from the file path and send it back over IPC. This is flexible, but it trusts front-end path input.
- Open the exported file directly. This may invoke an editor and is less useful for sharing or attaching the file.
- Open the app-owned support export directory from Rust. This is safer and matches the current export behavior. This is the selected approach.

## UI Behavior

Before export:

- Status remains `尚未导出支持包`.
- File and directory fields show `尚未生成`.
- "打开目录" is disabled.

After successful export:

- Status shows the saved byte count.
- File field shows the exported JSON path.
- Directory field shows the containing support directory.
- "打开目录" is enabled and sends `open-support-export-dir`.

On export failure:

- Status shows the failure.
- File and directory fields return to `尚未生成`.
- "打开目录" is disabled.

## Runtime Behavior

`SupportBundleSaveSummary` gains:

```json
"directory": "C:\\Users\\...\\Documents\\Keli\\Support"
```

The webview never sends a filesystem path for this action. `DesktopShellUiEvent::OpenSupportExportDirectory` opens `default_support_export_dir()` after ensuring the directory exists.

Platform launch behavior:

- Windows: `explorer.exe <directory>`
- macOS: `open <directory>`
- Linux/Unix: `xdg-open <directory>`

## Testing

Add tests for:

- Save summary includes `directory`.
- IPC maps `open-support-export-dir` to `OpenSupportExportDirectory`.
- HTML includes file/directory fields and disabled open-directory buttons.
- Support export status script includes the directory.
- Shell smoke still lists `export-support-bundle`.

Full verification should run `keli-desktop-shell` tests, the desktop shell smoke, and support export smoke.
