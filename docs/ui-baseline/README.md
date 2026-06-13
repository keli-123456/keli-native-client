# Keli UI Baseline

These mockups are the visual baseline for the Windows desktop Beta UI.

## Screens

- `keli-dashboard-baseline.png` - main control console with core status, mode switch, runtime activity, recent events, dependency status, and support actions.
- `keli-nodes-baseline.png` - subscription and node management with URL import/update, health filters, node table, selected node details, and quick actions.
- `keli-diagnostics-baseline.png` - readiness, runtime events, metrics, support bundle export, and core settings.

## Implementation Notes

- Keep the UI a desktop network-tool console, not a marketing page.
- Prefer a light theme, subtle borders, compact rows, and restrained status color.
- Use green for ready/running/healthy, amber for beta warnings or dependency blockers, and red only for hard failures.
- Keep radii at 8px or less.
- Use a persistent left navigation rail: Dashboard, Nodes, Diagnostics, Settings.
- The generated text is visual guidance only. Implementation copy should use the real Keli labels and state strings from the desktop shell.
- The diagnostics baseline has a slightly stronger blue accent than the target. When implementing, pull accents back toward the existing Keli green system.

## First Implementation Target

Match the structure first:

1. Dashboard overview with primary start/stop, mode control, quick status, activity, recent events, and dependencies.
2. Nodes view with subscription URL actions, summary metrics, filter tabs, node table, and detail panel.
3. Diagnostics view with readiness checklist, runtime event log, metrics, support export, and settings controls.
