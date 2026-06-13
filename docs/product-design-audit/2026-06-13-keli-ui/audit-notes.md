# Keli Desktop UI Audit

Date: 2026-06-13
Scope: Keli Windows desktop debug shell, Dashboard / Nodes / Diagnostics / Settings navigation.
Language target: Chinese user-facing client.

## Evidence

- `03-dashboard-fresh.png` - accepted Dashboard screenshot, 1196 x 799.
- `04-nodes.png` - accepted Nodes click state screenshot, 1196 x 799.
- `05-diagnostics.png` - accepted Diagnostics click state screenshot, 1196 x 799.
- `06-settings.png` - accepted Settings click state screenshot, 1196 x 799.
- `02-dashboard-top.png` - rejected screenshot, captured hidden/minimized 16 x 16 state.

## Step Health

1. Dashboard: usable but visually noisy.
   - Main action, status, dependency summary, activity, events, support bundle, mode, node, primary, tray all compete in one long page.
   - A horizontal scrollbar appears at desktop width, which makes the shell feel broken even before the user interacts.
   - Dependency details overflow and get clipped on the right.

2. Nodes: unhealthy.
   - The nav item highlights Nodes, but the main content still shows Dashboard content first.
   - The user gets a status message saying the view is part of the UI baseline instead of seeing the Nodes screen immediately.
   - This creates a strong "navigation did not work" impression.

3. Diagnostics: unhealthy.
   - Same problem as Nodes: left nav changes, main content remains Dashboard first.
   - Diagnostic controls are hidden lower in the page, so the page does not match the user's selected destination.

4. Settings: unhealthy.
   - Same problem as Nodes and Diagnostics.
   - Settings should feel quieter and form-like, but the first visible content is still operational Dashboard state.

## Root Cause Notes

- `dashboard-view` is not marked with `data-app-view`, while Nodes, Diagnostics, and Settings are.
- `postViewTarget()` hides only elements matching `[data-app-view]`, so Dashboard never gets hidden when changing views.
- The app is still declared as `lang="en"` and most visible labels are English.

Relevant source:

- `crates/keli-desktop-shell/src/html.rs:81`
- `crates/keli-desktop-shell/src/html.rs:824`
- `crates/keli-desktop-shell/src/html.rs:848`
- `crates/keli-desktop-shell/src/html.rs:998`
- `crates/keli-desktop-shell/src/html.rs:1068`
- `crates/keli-desktop-shell/src/html.rs:1180`
- `crates/keli-desktop-shell/src/html.rs:1270`

## Design Findings

1. The current UI reads as an engineering dashboard, not a consumer VPN/proxy client.
   - Too many raw states are visible at once: generation, event count, dependency internals, route mode, tray state, support bundle.
   - A normal user mainly needs: connection state, selected node, traffic mode, one primary action, and next fix if blocked.

2. Navigation and content are inconsistent.
   - A selected nav item must show the selected page's content at the top.
   - The current implementation makes non-Dashboard pages feel like placeholders.

3. Information hierarchy is flat.
   - Many cards use similar visual weight, so the eye cannot quickly find the main action.
   - Status chips, headings, labels, and table-like rows are all competing.

4. Chinese localization is not ready.
   - Mixed English labels make the UI feel unfinished.
   - User-facing text should be Chinese, while protocol names such as TUN, Wintun, SOCKS, HTTP can remain technical.

5. Layout has overflow risk.
   - The horizontal scrollbar and clipped dependency copy are strong quality signals.
   - Long paths and dependency detail should wrap, collapse, or move into Diagnostics.

6. Diagnostics content belongs mostly in Diagnostics, not Dashboard.
   - Dashboard should summarize dependency state.
   - Full Wintun path, packet I/O bridge, driver details, snapshot JSON, and support bundle internals should move behind Diagnostics.

## Recommended Fix Order

1. Fix view switching first.
   - Add `app-view` and `data-app-view` to Dashboard, or change the JS to hide/show all four view containers.
   - Ensure each nav click scrolls the main content to top.

2. Remove horizontal overflow.
   - Audit fixed/min widths and long dependency strings.
   - Add wrapping for paths and diagnostic values.

3. Redesign Dashboard as one clear control surface.
   - Top: connection state and primary action.
   - Middle: selected node and traffic mode.
   - Bottom: compact health summary with one "查看诊断" link when blocked.

4. Localize user-facing copy to Chinese.
   - Suggested nav: 概览 / 节点 / 诊断 / 设置.
   - Suggested primary states: 已停止 / 连接中 / 运行中 / 停止中 / 启动受阻.

5. Split page responsibility.
   - Nodes: subscription import, node table/list, selected node details.
   - Diagnostics: readiness checklist, logs, metrics, support bundle.
   - Settings: startup, traffic mode defaults, ports, subscription defaults.

6. Polish visual system after structure is stable.
   - Keep the restrained operational style.
   - Reduce card count, align spacing, use consistent button hierarchy, and avoid showing raw technical strings in the main view.

## Evidence Limits

- This audit is based on screenshots and source inspection, not full keyboard or screen-reader testing.
- It did not test a real imported subscription state.
- It did not inspect high-DPI, narrow mobile-sized, or Windows accessibility theme variants.
