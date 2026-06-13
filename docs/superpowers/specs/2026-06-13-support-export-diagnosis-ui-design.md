# Support Export Diagnosis UI Design

## Goal

Show the current connection diagnosis next to support bundle export controls so the desktop UI tells the user what the exported bundle will explain before they open the JSON.

## Context

The desktop shell already renders a Chinese connection diagnosis in the nodes view through `connection_diagnosis(snapshot)` and syncs it live with `syncConnectionDiagnosis(snapshot)`. The desktop support bundle now exports the same concept as `desktop_diagnosis.connection`.

The diagnostics view currently has a compact support panel with export and copy-log controls, but it only shows export save status. Users cannot see that the support bundle includes the current connection diagnosis.

## Chosen Approach

Reuse the existing shell connection diagnosis model and display a compact support export diagnosis summary in support bundle panels.

Alternatives considered:

- Parse the just-written support bundle JSON and echo `desktop_diagnosis.connection` after export. This proves the file contents, but it only helps after export and adds file parsing to the shell path.
- Add a large dedicated diagnosis card. This is clearer, but it consumes too much space in the default diagnostics layout.
- Reuse the existing live diagnosis from the current shell snapshot. This keeps the UI compact, updates before export, and stays aligned with the nodes view. This is the selected approach.

## UI Behavior

The support bundle panel shows:

- Export status: unchanged save/failure status.
- Diagnosis summary: `支持包将包含：<title> - <detail>`.
- Suggested action: `建议动作：<action>`.

The summary appears in the diagnostics support panel and the legacy support status area. It is also available to the live renderer so refreshing status updates it without requiring an export.

## Data Flow

`render_shell_html` computes `connection_diagnosis(snapshot)` once and passes the title, detail, and action into the support export sections.

The browser-side `syncSupportDiagnosis(snapshot)` calls the existing JavaScript `connectionDiagnosis(snapshot)` and updates the support diagnosis DOM nodes during shell sync.

`window.keliSetSupportExport(summary)` continues to update only save/failure status. It does not replace the diagnosis, because diagnosis comes from the live shell snapshot.

## Error Handling

If the snapshot is missing or partial, the existing `connectionDiagnosis(snapshot)` fallback behavior applies:

- Missing subscription -> tell the user to import a subscription.
- Dependency blockers -> show dependency action.
- Last error -> classify or show core failure.

No new IPC error path is added.

## Testing

Add shell HTML tests that require:

- Support export areas include diagnosis summary and action DOM nodes.
- A port-conflict snapshot renders `支持包将包含：端口被占用`.
- The live renderer contains `syncSupportDiagnosis(snapshot)` and updates the support diagnosis fields.

Run focused shell HTML tests first, then full `keli-desktop-shell` tests and smoke commands.
