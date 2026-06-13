use keli_desktop::{
    DesktopRunState, DesktopShellState, DesktopSubscriptionSummary,
    DesktopSubscriptionUrlImportSummary, DesktopSubscriptionUrlUpdateSummary, DesktopTrafficMode,
    DesktopWintunInstallSummary,
};

use crate::support::SupportBundleSaveSummary;

pub fn render_shell_html(snapshot: &DesktopShellState) -> String {
    let run_state = run_state_label(snapshot.status.run_state);
    let traffic_mode = traffic_mode_label(snapshot.status.traffic_mode);
    let selected = snapshot
        .status
        .selected_outbound
        .as_deref()
        .unwrap_or("No node selected");
    let listen = snapshot.status.listen.as_deref().unwrap_or("Not listening");
    let primary = &snapshot.primary_action;
    let tray_ids = snapshot
        .tray_menu
        .items
        .iter()
        .map(|item| item.id.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let snapshot_json = serde_json::to_string_pretty(snapshot)
        .unwrap_or_else(|error| format!("{{\"error\":\"{error}\"}}"));
    let primary_disabled = if primary.enabled { "" } else { " disabled" };
    let is_running = snapshot.status.run_state == DesktopRunState::Running;
    let import_subscription_url_disabled = if is_running { " disabled" } else { "" };
    let update_subscription_url_disabled = if is_running { "" } else { " disabled" };
    let primary_state = primary.reason.as_deref().unwrap_or(if primary.enabled {
        "Enabled"
    } else {
        "Disabled"
    });
    let subscription_summary = subscription_summary(snapshot.subscription.as_ref());
    let node_buttons = node_buttons(snapshot.subscription.as_ref());
    let dependency_summary = dependency_summary(snapshot);
    let system_proxy_dependency = system_proxy_dependency(snapshot);
    let tun_dependency = tun_dependency(snapshot);
    let dependency_blockers = dependency_blockers(snapshot);
    let dependency_actions = dependency_action_buttons(snapshot);
    let diagnostics_core_status = diagnostics_core_status(snapshot);
    let diagnostics_runtime_events = diagnostics_runtime_events(snapshot);
    let diagnostics_last_error = diagnostics_last_error(snapshot);
    let diagnostics_connection_metrics = diagnostics_connection_metrics(snapshot);
    let diagnostics_node_health = diagnostics_node_health(snapshot);
    let diagnostics_recent_event = diagnostics_recent_event(snapshot);
    let runtime_event_items = runtime_event_items(snapshot);
    let diagnostics_system_proxy = diagnostics_system_proxy(snapshot);
    let diagnostics_tun = diagnostics_tun(snapshot);
    let diagnostics_default_core = diagnostics_default_core(snapshot);
    let activity_summary = format!("{diagnostics_runtime_events}; {diagnostics_recent_event}");
    let top_core_status = format!("Core status: {run_state}");
    let top_dependency_status = if snapshot.dependencies.first_run.blockers.is_empty()
        && snapshot.dependencies.first_run.system_proxy_ready
        && snapshot.dependencies.first_run.tun_ready
    {
        "Dependencies ready"
    } else {
        "Dependencies need attention"
    };
    let local_inbound_pressed =
        aria_pressed(snapshot.status.traffic_mode == DesktopTrafficMode::MixedInboundOnly);
    let system_proxy_pressed =
        aria_pressed(snapshot.status.traffic_mode == DesktopTrafficMode::SystemProxy);
    let tun_pressed = aria_pressed(snapshot.status.traffic_mode == DesktopTrafficMode::Tun);

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Keli</title>
  <style>
    :root {{
      color-scheme: light dark;
      font-family: "Segoe UI", Arial, sans-serif;
      background: #f6f7f8;
      color: #171a1f;
    }}
    * {{
      box-sizing: border-box;
    }}
    body {{
      margin: 0;
      min-width: 360px;
      min-height: 520px;
      background: #f6f7f8;
    }}
    .desktop-layout {{
      min-height: 100vh;
      display: grid;
      grid-template-columns: 220px minmax(0, 1fr);
      background: #f6f7f8;
    }}
    .nav-rail {{
      min-height: 100vh;
      display: grid;
      grid-template-rows: auto 1fr auto;
      gap: 18px;
      padding: 24px 14px;
      border-right: 1px solid #d9dee5;
      background: #ffffff;
    }}
    .nav-brand {{
      display: flex;
      align-items: center;
      gap: 10px;
      min-height: 42px;
      padding: 0 8px;
      color: #171a1f;
      font-size: 25px;
      font-weight: 750;
      letter-spacing: 0;
    }}
    .nav-mark {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 34px;
      height: 34px;
      border-radius: 8px;
      background: #0f8a43;
      color: #ffffff;
      font-size: 20px;
      font-weight: 800;
    }}
    .nav-list {{
      display: grid;
      align-content: start;
      gap: 6px;
      margin-top: 8px;
    }}
    .nav-item {{
      width: 100%;
      min-height: 44px;
      display: flex;
      align-items: center;
      justify-content: flex-start;
      border-color: transparent;
      background: transparent;
      color: #343b46;
      text-align: left;
    }}
    .nav-item[aria-current="page"] {{
      border-color: #cde4d6;
      background: #eaf6ef;
      color: #0f6b36;
    }}
    .nav-footer {{
      display: grid;
      gap: 8px;
      padding: 10px 8px;
      color: #657386;
      font-size: 12px;
    }}
    .app-shell {{
      min-height: 100vh;
      padding: 0 22px 22px;
      display: grid;
      grid-template-rows: auto auto auto 1fr auto;
      gap: 18px;
      align-content: start;
    }}
    .top-status-bar {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      min-height: 68px;
      border-bottom: 1px solid #d9dee5;
      background: #f6f7f8;
    }}
    .top-status-group {{
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      min-width: 0;
      color: #4d5968;
      font-size: 13px;
      font-weight: 650;
    }}
    .top-status-item {{
      display: inline-flex;
      align-items: center;
      gap: 7px;
      min-height: 32px;
      padding: 0 10px;
      border-left: 1px solid #d9dee5;
      overflow-wrap: anywhere;
    }}
    .top-status-item:first-child {{
      border-left: 0;
      padding-left: 0;
    }}
    .status-dot {{
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #0f8a43;
    }}
    h1 {{
      margin: 0;
      font-size: 22px;
      font-weight: 650;
      letter-spacing: 0;
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 0 10px;
      border-radius: 6px;
      background: #e6f4ec;
      color: #145a32;
      font-size: 13px;
      font-weight: 600;
      white-space: nowrap;
    }}
    .command-panel {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 14px 18px;
      align-items: start;
      min-height: 0;
    }}
    .command-title {{
      margin: 0;
      color: #171a1f;
      font-size: 24px;
      font-weight: 700;
      letter-spacing: 0;
      overflow-wrap: anywhere;
    }}
    .quick-status {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 8px 14px;
      grid-column: 1 / -1;
      padding-top: 4px;
    }}
    .quick-status-item {{
      min-width: 0;
    }}
    .quick-label {{
      color: #657386;
      font-size: 12px;
      font-weight: 650;
      text-transform: uppercase;
    }}
    .quick-value {{
      margin-top: 3px;
      color: #171a1f;
      font-size: 14px;
      font-weight: 650;
      overflow-wrap: anywhere;
    }}
    .segmented-control {{
      display: inline-flex;
      flex-wrap: wrap;
      gap: 6px;
      grid-column: 1 / -1;
    }}
    .segmented-control button {{
      min-width: 116px;
    }}
    .segmented-control button[aria-pressed="true"] {{
      border-color: #277d56;
      background: #e6f4ec;
      color: #145a32;
    }}
    .activity-strip {{
      grid-column: 1 / -1;
      min-height: 30px;
      display: flex;
      align-items: center;
      border-top: 1px solid #d9dee5;
      padding-top: 10px;
      color: #4d5968;
      font-size: 13px;
      overflow-wrap: anywhere;
    }}
    .dashboard-view {{
      display: grid;
      gap: 14px;
    }}
    .dashboard-row {{
      display: grid;
      grid-template-columns: minmax(0, 1.2fr) minmax(320px, 0.8fr);
      gap: 14px;
    }}
    .activity-header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 10px;
    }}
    .activity-metrics {{
      color: #4d5968;
      font-size: 13px;
      overflow-wrap: anywhere;
    }}
    .activity-rail {{
      display: grid;
      gap: 8px;
      margin-top: 12px;
    }}
    .activity-line {{
      min-height: 30px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      border-top: 1px solid #edf0f3;
      color: #4d5968;
      font-size: 12px;
    }}
    .status-list {{
      display: grid;
      gap: 0;
      border-top: 1px solid #edf0f3;
    }}
    .status-row {{
      min-height: 42px;
      display: grid;
      grid-template-columns: minmax(120px, 1fr) minmax(96px, auto);
      align-items: center;
      gap: 10px;
      border-bottom: 1px solid #edf0f3;
      color: #4d5968;
      font-size: 13px;
    }}
    .status-row strong {{
      color: #171a1f;
      font-weight: 650;
    }}
    .status-ok {{
      color: #0f8a43;
      font-weight: 700;
    }}
    .support-actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
    }}
    .operation-status {{
      min-height: 34px;
      display: flex;
      align-items: center;
      padding: 0 12px;
      border: 1px solid #d9dee5;
      border-radius: 8px;
      background: #ffffff;
      color: #4d5968;
      font-size: 13px;
      font-weight: 600;
      overflow-wrap: anywhere;
    }}
    .operation-status[data-kind="success"] {{
      border-color: #add7bf;
      background: #e6f4ec;
      color: #145a32;
    }}
    .operation-status[data-kind="error"] {{
      border-color: #efb0a7;
      background: #fff1ef;
      color: #8f2618;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
      align-content: start;
    }}
    section {{
      min-height: 104px;
      padding: 14px;
      border: 1px solid #d9dee5;
      border-radius: 8px;
      background: #ffffff;
    }}
    section.wide {{
      grid-column: 1 / -1;
    }}
    h2 {{
      margin: 0 0 10px;
      color: #4d5968;
      font-size: 13px;
      font-weight: 650;
      letter-spacing: 0;
      text-transform: uppercase;
    }}
    .value {{
      color: #171a1f;
      font-size: 17px;
      font-weight: 650;
      overflow-wrap: anywhere;
    }}
    .muted {{
      margin-top: 8px;
      color: #657386;
      font-size: 13px;
      overflow-wrap: anywhere;
    }}
    .actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
    }}
    button {{
      min-width: 88px;
      min-height: 34px;
      border: 1px solid #b7c0ca;
      border-radius: 6px;
      background: #ffffff;
      color: #171a1f;
      font: inherit;
      font-size: 13px;
      font-weight: 650;
    }}
    button.primary {{
      border-color: #277d56;
      background: #277d56;
      color: #ffffff;
    }}
    button:disabled {{
      border-color: #d9dee5;
      background: #edf0f3;
      color: #8a95a3;
    }}
    input {{
      width: 100%;
      min-height: 34px;
      border: 1px solid #b7c0ca;
      border-radius: 6px;
      padding: 8px 10px;
      background: #ffffff;
      color: #171a1f;
      font: inherit;
      font-size: 13px;
    }}
    textarea {{
      width: 100%;
      min-height: 128px;
      resize: vertical;
      border: 1px solid #b7c0ca;
      border-radius: 6px;
      padding: 10px;
      background: #ffffff;
      color: #171a1f;
      font: 12px Consolas, "Cascadia Mono", monospace;
      line-height: 1.45;
    }}
    .node-list {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }}
    .node-list button {{
      min-width: 172px;
      display: grid;
      justify-items: start;
      gap: 3px;
      text-align: left;
    }}
    .node-list button[aria-pressed="true"] {{
      border-color: #277d56;
      color: #145a32;
      background: #e6f4ec;
    }}
    .node-tag {{
      font-weight: 700;
    }}
    .node-meta {{
      color: #657386;
      font-size: 12px;
      font-weight: 500;
    }}
    .node-badges {{
      display: flex;
      flex-wrap: wrap;
      gap: 4px;
    }}
    .node-badge {{
      display: inline-flex;
      align-items: center;
      min-height: 20px;
      padding: 0 6px;
      border: 1px solid #d9dee5;
      border-radius: 6px;
      background: #edf0f3;
      color: #4d5968;
      font-size: 11px;
      font-weight: 700;
    }}
    .node-skipped {{
      min-width: 172px;
      display: grid;
      gap: 4px;
      padding: 8px 10px;
      border: 1px dashed #d9dee5;
      border-radius: 6px;
      color: #657386;
      font-size: 12px;
      overflow-wrap: anywhere;
    }}
    .event-list {{
      display: grid;
      gap: 6px;
      margin-top: 10px;
    }}
    .event-row {{
      display: grid;
      grid-template-columns: 92px minmax(0, 1fr);
      gap: 8px;
      color: #4d5968;
      font-size: 12px;
      overflow-wrap: anywhere;
    }}
    .event-state {{
      color: #171a1f;
      font-weight: 700;
    }}
    pre {{
      max-height: 160px;
      overflow: auto;
      margin: 0;
      padding: 12px;
      border: 1px solid #d9dee5;
      border-radius: 8px;
      background: #111820;
      color: #e8edf3;
      font-size: 12px;
      line-height: 1.45;
    }}
    @media (max-width: 720px) {{
      .desktop-layout {{
        grid-template-columns: 1fr;
      }}
      .nav-rail {{
        min-height: 0;
        grid-template-rows: auto auto;
        padding: 12px;
        border-right: 0;
        border-bottom: 1px solid #d9dee5;
      }}
      .nav-list {{
        grid-template-columns: repeat(4, minmax(0, 1fr));
      }}
      .nav-footer {{
        display: none;
      }}
      .app-shell {{
        padding: 0 14px 14px;
      }}
      .top-status-bar {{
        align-items: flex-start;
        flex-direction: column;
        padding: 10px 0;
      }}
      .grid,
      .quick-status,
      .dashboard-row {{
        grid-template-columns: 1fr;
      }}
      .command-panel {{
        grid-template-columns: 1fr;
      }}
      .command-actions {{
        width: 100%;
      }}
      .command-actions button,
      .segmented-control button {{
        flex: 1 1 130px;
      }}
    }}
  </style>
</head>
<body>
  <div class="desktop-layout">
    <aside class="nav-rail" id="app-navigation" aria-label="Keli navigation">
      <div class="nav-brand"><span class="nav-mark" aria-hidden="true">K</span><span>Keli</span></div>
      <nav class="nav-list">
        <button class="nav-item" data-view-target="dashboard-view" aria-current="page" onclick="postViewTarget('dashboard-view')">Dashboard</button>
        <button class="nav-item" data-view-target="nodes-view" onclick="postViewTarget('nodes-view')">Nodes</button>
        <button class="nav-item" data-view-target="diagnostics-view" onclick="postViewTarget('diagnostics-view')">Diagnostics</button>
        <button class="nav-item" data-view-target="settings-view" onclick="postViewTarget('settings-view')">Settings</button>
      </nav>
      <div class="nav-footer">
        <span>Core: native Rust</span>
        <span id="nav-run-state">{run_state}</span>
      </div>
    </aside>
    <main class="app-shell">
      <header class="top-status-bar" id="top-status-bar">
        <div class="top-status-group">
          <span class="pill" id="run-state">{run_state}</span>
          <span class="top-status-item" id="top-core-status"><span class="status-dot" aria-hidden="true"></span>{top_core_status}</span>
          <span class="top-status-item">Mode: <strong id="top-traffic-mode">{traffic_mode}</strong></span>
          <span class="top-status-item">Node: <strong id="top-selected-node">{selected}</strong></span>
        </div>
        <div class="top-status-group">
          <span class="top-status-item" id="top-dependency-status"><span class="status-dot" aria-hidden="true"></span>{top_dependency_status}</span>
          <span class="top-status-item" id="top-activity-status">{activity_summary}</span>
        </div>
      </header>
    <div class="operation-status" id="operation-status" data-kind="info">Ready</div>
    <div class="dashboard-view" id="dashboard-view">
    <section class="command-panel" id="core-command-panel">
      <div>
        <h2>Core</h2>
        <div class="command-title"><span id="quick-run-state">{run_state}</span> via <span id="quick-traffic-mode">{traffic_mode}</span></div>
        <div class="muted" id="quick-primary-state">{primary_state}</div>
      </div>
      <div class="actions command-actions">
        <button id="quick-primary-button" class="primary" onclick="window.ipc.postMessage('primary')"{primary_disabled}>{primary_label}</button>
        <button id="quick-refresh-button" onclick="window.ipc.postMessage('refresh')">Refresh</button>
      </div>
      <div class="quick-status" aria-label="Core status">
        <div class="quick-status-item">
          <div class="quick-label">Node</div>
          <div class="quick-value" id="quick-selected-node">{selected}</div>
        </div>
        <div class="quick-status-item">
          <div class="quick-label">Listen</div>
          <div class="quick-value" id="quick-listen-address">{listen}</div>
        </div>
        <div class="quick-status-item">
          <div class="quick-label">Dependencies</div>
          <div class="quick-value" id="quick-dependency-summary">{dependency_summary}</div>
        </div>
        <div class="quick-status-item">
          <div class="quick-label">Subscription</div>
          <div class="quick-value" id="quick-subscription-summary">{subscription_summary}</div>
        </div>
      </div>
      <div class="segmented-control" id="mode-segmented-control" role="group" aria-label="Traffic mode">
        <button data-traffic-mode-button="mixed-inbound-only" aria-pressed="{local_inbound_pressed}" onclick="postTrafficMode('mixed-inbound-only')">Local inbound</button>
        <button data-traffic-mode-button="system-proxy" aria-pressed="{system_proxy_pressed}" onclick="postTrafficMode('system-proxy')">System proxy</button>
        <button data-traffic-mode-button="tun" aria-pressed="{tun_pressed}" onclick="postTrafficMode('tun')">TUN</button>
      </div>
      <div class="activity-strip" id="activity-summary">{activity_summary}</div>
    </section>
    <section id="connection-activity-panel">
      <div class="activity-header">
        <h2>Connection activity</h2>
        <div class="activity-metrics" id="activity-metrics">{diagnostics_connection_metrics}</div>
      </div>
      <div class="activity-rail" aria-label="Connection activity summary">
        <div class="activity-line"><span>Recent runtime generation</span><strong>{generation}</strong></div>
        <div class="activity-line"><span>Runtime events</span><strong>{events}</strong></div>
        <div class="activity-line"><span>Selected route mode</span><strong>{traffic_mode}</strong></div>
      </div>
    </section>
    <div class="dashboard-row">
      <section id="dashboard-events-panel">
        <h2>Recent events</h2>
        <div class="event-list" id="dashboard-runtime-event-list">{runtime_event_items}</div>
      </section>
      <section id="dashboard-dependencies-panel">
        <h2>Dependency status</h2>
        <div class="value" id="dashboard-dependency-summary">{dependency_summary}</div>
        <div class="status-list">
          <div class="status-row"><strong>System proxy</strong><span class="status-ok" id="dashboard-system-proxy-status">{system_proxy_dependency}</span></div>
          <div class="status-row"><strong>TUN / Wintun</strong><span class="status-ok" id="dashboard-tun-status">{tun_dependency}</span></div>
          <div class="status-row"><strong>Blockers</strong><span id="dashboard-blockers">{dependency_blockers}</span></div>
        </div>
        <div class="actions" id="dashboard-dependency-actions">{dependency_actions}</div>
      </section>
    </div>
    <section id="support-actions-panel">
      <h2>Support bundle</h2>
      <div class="value">Diagnostics export</div>
      <div class="muted">Export redacted runtime state, dependency checks, and core support evidence.</div>
      <div class="support-actions">
        <button id="dashboard-export-support-button" class="primary" onclick="window.ipc.postMessage('export-support-bundle')">Export diagnostics</button>
        <button onclick="window.ipc.postMessage('refresh')">Refresh status</button>
      </div>
    </section>
    <div class="grid">
      <section>
        <h2>Mode</h2>
        <div class="value" id="traffic-mode">{traffic_mode}</div>
        <div class="muted" id="listen-address">{listen}</div>
      </section>
      <section>
        <h2>Node</h2>
        <div class="value" id="selected-outbound">{selected}</div>
        <div class="muted" id="runtime-meta">Generation {generation}, events {events}</div>
      </section>
      <section>
        <h2>Primary</h2>
        <div class="value" id="primary-label">{primary_label}</div>
        <div class="muted" id="primary-state">{primary_state}</div>
        <div class="actions">
          <button id="primary-button" class="primary" onclick="window.ipc.postMessage('primary')"{primary_disabled}>{primary_label}</button>
          <button id="refresh-button" onclick="window.ipc.postMessage('refresh')">Refresh</button>
        </div>
      </section>
      <section>
        <h2>Tray</h2>
        <div class="value" id="tray-ids">{tray_ids}</div>
        <div class="muted" id="window-visible">Window visible: {window_visible}</div>
      </section>
      <section class="wide">
        <h2>Dependencies</h2>
        <div class="value" id="dependency-summary">{dependency_summary}</div>
        <div class="muted" id="system-proxy-dependency">{system_proxy_dependency}</div>
        <div class="muted" id="tun-dependency">{tun_dependency}</div>
        <div class="muted" id="dependency-blockers">{dependency_blockers}</div>
        <div class="actions" id="dependency-actions">{dependency_actions}</div>
        <input id="wintun-source-path" type="text" placeholder="C:\Downloads\wintun or C:\Downloads\wintun.dll" />
        <div class="actions">
          <button id="install-wintun-path-button" onclick="postInstallWintunPath()">Install Wintun from path</button>
        </div>
        <div class="muted" id="wintun-install-status">No local Wintun install attempted</div>
      </section>
      <section class="wide">
        <h2>Subscription</h2>
        <input id="subscription-url" type="url" placeholder="https://example.com/subscription" />
        <div class="actions">
          <button id="import-subscription-url-button" class="primary" onclick="postImportSubscriptionUrl()"{import_subscription_url_disabled}>Import URL</button>
          <button id="update-subscription-url-button" onclick="postUpdateSubscriptionUrl()"{update_subscription_url_disabled}>Update URL</button>
          <button id="refresh-node-health-button" onclick="postRefreshNodeHealth()">Refresh health</button>
        </div>
        <div class="muted" id="subscription-url-status">No subscription URL imported</div>
        <textarea id="subscription-config" spellcheck="false"></textarea>
        <div class="muted" id="subscription-config-status">No local subscription config imported</div>
        <div class="actions">
          <button id="import-subscription-button" class="primary" onclick="postImportSubscription()">Import</button>
          <button onclick="postTrafficMode('mixed-inbound-only')">Local inbound</button>
          <button onclick="postTrafficMode('system-proxy')">System proxy</button>
          <button onclick="postTrafficMode('tun')">TUN</button>
        </div>
        <div class="muted" id="subscription-summary">{subscription_summary}</div>
        <div class="node-list" id="node-list">{node_buttons}</div>
      </section>
      <section class="wide">
        <h2>Diagnostics</h2>
        <div class="value" id="diagnostics-core-status">{diagnostics_core_status}</div>
        <div class="muted" id="diagnostics-runtime-events">{diagnostics_runtime_events}</div>
        <div class="muted" id="diagnostics-last-error">{diagnostics_last_error}</div>
        <div class="muted" id="diagnostics-connection-metrics">{diagnostics_connection_metrics}</div>
        <div class="muted" id="diagnostics-node-health">{diagnostics_node_health}</div>
        <div class="muted" id="diagnostics-recent-event">{diagnostics_recent_event}</div>
        <div class="event-list" id="runtime-event-list">{runtime_event_items}</div>
        <div class="muted" id="diagnostics-system-proxy">{diagnostics_system_proxy}</div>
        <div class="muted" id="diagnostics-tun">{diagnostics_tun}</div>
        <div class="muted" id="diagnostics-default-core">{diagnostics_default_core}</div>
        <div class="value">Support bundle</div>
        <div class="muted" id="support-export-status">No support bundle exported</div>
        <div class="actions">
          <button id="export-support-button" onclick="window.ipc.postMessage('export-support-bundle')">Export support bundle</button>
        </div>
      </section>
    </div>
    </div>
    <pre id="snapshot-json">{snapshot_json}</pre>
  </main>
  </div>
  <script>
    const runStateLabels = {{
      "stopped": "Stopped",
      "starting": "Starting",
      "running": "Running",
      "reloading": "Reloading",
      "stopping": "Stopping",
      "failed": "Failed"
    }};
    const trafficModeLabels = {{
      "system-proxy": "System proxy",
      "tun": "TUN",
      "mixed-inbound-only": "Local inbound"
    }};
    function postJson(payload) {{
      window.ipc.postMessage(JSON.stringify(payload));
    }}
    function postViewTarget(viewId) {{
      document.querySelectorAll("[data-view-target]").forEach((button) => {{
        button.setAttribute("aria-current", button.dataset.viewTarget === viewId ? "page" : "false");
      }});
      if (viewId !== "dashboard-view") {{
        window.keliSetOperationStatus({{
          kind: "info",
          message: `${{viewId.replace("-view", "")}} view is part of the UI baseline and will use the same live shell state.`
        }});
      }}
    }}
    function postImportSubscription() {{
      postJson({{
        type: "import-subscription-config",
        configText: document.getElementById("subscription-config").value
      }});
    }}
    function postImportSubscriptionUrl() {{
      postJson({{
        type: "import-subscription-url",
        subscriptionUrl: document.getElementById("subscription-url").value
      }});
    }}
    function postUpdateSubscriptionUrl() {{
      postJson({{
        type: "update-subscription-url",
        subscriptionUrl: document.getElementById("subscription-url").value
      }});
    }}
    function postRefreshNodeHealth() {{
      postJson({{
        type: "refresh-node-health"
      }});
    }}
    function postTrafficMode(trafficMode) {{
      postJson({{
        type: "set-traffic-mode",
        trafficMode
      }});
    }}
    function postSelectNode(outboundTag) {{
      postJson({{
        type: "select-node",
        outboundTag
      }});
    }}
    const dependencyActionLabels = {{
      "check-system-proxy": "Open proxy settings",
      "install-wintun": "Open Wintun download",
      "check-tun": "Open TUN help"
    }};
    function postDependencyAction(action) {{
      postJson({{
        type: "dependency-action",
        action
      }});
    }}
    function postInstallWintunPath() {{
      postJson({{
        type: "install-wintun-path",
        sourcePath: document.getElementById("wintun-source-path").value
      }});
    }}
    function collectDependencyActions(snapshot) {{
      const actions = [];
      const add = (action) => {{
        if (action && !actions.includes(action)) actions.push(action);
      }};
      add(snapshot.dependencies.system_proxy.action);
      add(snapshot.dependencies.tun_backend.action);
      for (const blocker of snapshot.dependencies.first_run.blockers || []) {{
        add(blocker.action);
      }}
      return actions;
    }}
    function renderDependencyActionsInto(containerId, snapshot) {{
      const container = document.getElementById(containerId);
      if (!container) return;
      container.replaceChildren();
      for (const action of collectDependencyActions(snapshot)) {{
        const button = document.createElement("button");
        button.dataset.dependencyAction = action;
        button.textContent = dependencyActionLabels[action] || action;
        button.onclick = () => postDependencyAction(action);
        container.appendChild(button);
      }}
    }}
    function renderDependencyActions(snapshot) {{
      renderDependencyActionsInto("dependency-actions", snapshot);
      renderDependencyActionsInto("dashboard-dependency-actions", snapshot);
    }}
    function subscriptionSummary(subscription) {{
      if (!subscription) return "No subscription imported";
      return `Supported ${{subscription.supported_count}}, skipped ${{subscription.skipped_count}}`;
    }}
    function renderNodeList(subscription) {{
      const nodeList = document.getElementById("node-list");
      nodeList.replaceChildren();
      if (!subscription || (!subscription.nodes.length && !(subscription.skipped || []).length)) {{
        const empty = document.createElement("span");
        empty.className = "muted";
        empty.textContent = "No nodes";
        nodeList.appendChild(empty);
        return;
      }}
      if (!subscription.nodes.length) {{
        const empty = document.createElement("span");
        empty.className = "muted";
        empty.textContent = "No nodes";
        nodeList.appendChild(empty);
      }}
      for (const node of subscription.nodes) {{
        const button = document.createElement("button");
        const tag = document.createElement("span");
        const meta = document.createElement("span");
        const udp = document.createElement("span");
        const health = document.createElement("span");
        const badges = document.createElement("span");
        button.dataset.nodeTag = node.tag;
        button.setAttribute("aria-pressed", node.selected ? "true" : "false");
        button.onclick = () => postSelectNode(node.tag);
        tag.className = "node-tag";
        tag.textContent = node.tag;
        meta.className = "node-meta";
        meta.textContent = `${{node.protocol || "unknown"}} / ${{node.transport || "unknown"}} / ${{node.security || "unknown"}}`;
        udp.className = "node-meta";
        udp.textContent = node.udp_supported ? "UDP ready" : "UDP unavailable";
        health.className = "node-meta";
        health.textContent = nodeHealthDetail(node);
        badges.className = "node-badges";
        if (node.selected) {{
          const badge = document.createElement("span");
          badge.className = "node-badge";
          badge.textContent = "Selected";
          badges.appendChild(badge);
        }}
        if (node.recommended) {{
          const badge = document.createElement("span");
          badge.className = "node-badge";
          badge.textContent = "Recommended";
          badges.appendChild(badge);
        }}
        button.append(tag, meta, udp, health, badges);
        nodeList.appendChild(button);
      }}
      for (const skipped of subscription.skipped || []) {{
        const item = document.createElement("div");
        const badge = document.createElement("span");
        const detail = document.createElement("span");
        item.className = "node-skipped";
        badge.className = "node-badge";
        badge.textContent = "Skipped";
        detail.textContent = skipped;
        item.append(badge, detail);
        nodeList.appendChild(item);
      }}
    }}
    function nodeHealthDetail(node) {{
      const parts = [];
      if (node.health_state) parts.push(`Health ${{node.health_state}}`);
      if (node.tcp_available === true) parts.push("TCP ready");
      if (node.tcp_available === false) parts.push("TCP failed");
      if (node.udp_available === true) parts.push("UDP live");
      if (node.udp_available === false) parts.push("UDP failed");
      if (node.latency_ms !== null && node.latency_ms !== undefined) parts.push(`${{node.latency_ms}} ms`);
      if (node.health_error) parts.push(`Last failure ${{node.health_error}}`);
      return parts.length ? parts.join(", ") : "Health unknown";
    }}
    window.keliSetOperationStatus = (summary) => {{
      const status = document.getElementById("operation-status");
      const kind = summary.kind || "info";
      status.dataset.kind = kind;
      status.textContent = summary.message || "Ready";
    }};
    window.keliSetSupportExport = (summary) => {{
      const label = summary.status === "saved"
        ? `Saved ${{summary.byte_count}} bytes to ${{summary.path}}`
        : `${{summary.status}}: ${{summary.path || ""}}`;
      const kind = summary.status === "saved" ? "success" : "error";
      document.getElementById("support-export-status").textContent = label;
      window.keliSetOperationStatus({{ kind: kind, message: label }});
    }};
    window.keliSetWintunInstall = (summary) => {{
      const label = summary.error
        ? `${{summary.status}}: ${{summary.error}}`
        : `${{summary.status}}: ${{summary.target_path || ""}} (${{summary.copied_bytes || 0}} bytes)`;
      const kind = summary.error ? "error" : "success";
      document.getElementById("wintun-install-status").textContent = label;
      window.keliSetOperationStatus({{ kind: kind, message: label }});
    }};
    function subscriptionSource(fetch) {{
      const source = fetch.host
        ? `${{fetch.scheme || "url"}}://${{fetch.host}}`
        : "subscription URL";
      return source;
    }}
    window.keliSetSubscriptionUrlImport = (summary) => {{
      const fetch = summary.fetch || {{}};
      const source = subscriptionSource(fetch);
      const label = summary.error
        ? `Import failed from ${{source}}: ${{summary.error}}`
        : `Imported ${{summary.subscription ? summary.subscription.supported_count : 0}} nodes from ${{source}}`;
      const kind = summary.error ? "error" : "success";
      document.getElementById("subscription-url-status").textContent = label;
      window.keliSetOperationStatus({{ kind: kind, message: label }});
    }};
    window.keliSetSubscriptionUrlUpdate = (summary) => {{
      const fetch = summary.fetch || {{}};
      const source = subscriptionSource(fetch);
      const update = summary.update || {{}};
      const reason = update.reason ? `, ${{update.reason}}` : "";
      const selected = summary.runtime_status && summary.runtime_status.selected_outbound
        ? `, selected ${{summary.runtime_status.selected_outbound}}`
        : "";
      const label = summary.error
        ? `Update failed from ${{source}}: ${{summary.error}}`
        : summary.applied
          ? `Updated from ${{source}}${{reason}}${{selected}}`
          : `Update not applied from ${{source}}: ${{fetch.error_kind || "unknown"}}`;
      const kind = summary.error || !summary.applied ? "error" : "success";
      document.getElementById("subscription-url-status").textContent = label;
      window.keliSetOperationStatus({{ kind: kind, message: label }});
    }};
    window.keliSetSubscriptionConfigImport = (summary) => {{
      const label = summary.error
        ? `Import failed: ${{summary.error}}`
        : `Imported ${{summary.supported_count || 0}} nodes, skipped ${{summary.skipped_count || 0}}`;
      const kind = summary.error ? "error" : "success";
      document.getElementById("subscription-config-status").textContent = label;
      window.keliSetOperationStatus({{ kind: kind, message: label }});
    }};
    function dependencySummary(snapshot) {{
      const firstRun = snapshot.dependencies.first_run;
      const system = firstRun.system_proxy_ready ? "System proxy ready" : "System proxy blocked";
      const tun = firstRun.tun_ready ? "TUN ready" : "TUN blocked";
      return `${{system}}, ${{tun}}`;
    }}
    function systemProxyDependency(snapshot) {{
      const proxy = snapshot.dependencies.system_proxy;
      const parts = [`System proxy ${{proxy.state}}`];
      if (proxy.enabled !== null && proxy.enabled !== undefined) parts.push(`enabled=${{proxy.enabled}}`);
      if (proxy.server) parts.push(`server=${{proxy.server}}`);
      if (proxy.error) parts.push(proxy.error);
      if (proxy.action) parts.push(`action=${{proxy.action}}`);
      return parts.join(", ");
    }}
    function tunDependency(snapshot) {{
      const tun = snapshot.dependencies.tun_backend;
      const parts = [
        `Wintun ${{tun.state}}`,
        `driver_present=${{tun.driver_library_present}}`,
        `api_available=${{tun.driver_api_available}}`
      ];
      if (tun.driver_library_path) parts.push(`path=${{tun.driver_library_path}}`);
      if (tun.reason) parts.push(tun.reason);
      if (tun.action) parts.push(`action=${{tun.action}}`);
      return parts.join(", ");
    }}
    function dependencyBlockers(snapshot) {{
      const blockers = snapshot.dependencies.first_run.blockers || [];
      if (!blockers.length) return "No dependency blockers";
      return blockers.map((blocker) => {{
        const action = blocker.action ? ` action=${{blocker.action}}` : "";
        return `${{blocker.code}}: ${{blocker.message}}${{action}}`;
      }}).join("; ");
    }}
    function diagnosticsCoreStatus(snapshot) {{
      const status = snapshot.status;
      const run = runStateLabels[status.run_state] || status.run_state;
      const mode = trafficModeLabels[status.traffic_mode] || status.traffic_mode;
      return `Core ${{run.toLowerCase()}} via ${{mode}}`;
    }}
    function diagnosticsRuntimeEvents(snapshot) {{
      const status = snapshot.status;
      return `Generation ${{status.generation}}, events ${{status.event_count}}`;
    }}
    function diagnosticsLastError(snapshot) {{
      const lastError = snapshot.status.last_error || "none";
      return `Last error: ${{lastError}}`;
    }}
    function diagnosticsConnectionMetrics(snapshot) {{
      const metrics = snapshot.status.connection_metrics || {{}};
      const average = metrics.average_connect_ms === null || metrics.average_connect_ms === undefined
        ? "n/a"
        : `${{metrics.average_connect_ms}} ms`;
      return `Connections ${{metrics.total || 0}} total, ${{metrics.success || 0}} ok, ${{metrics.failure || 0}} failed, avg connect ${{average}}`;
    }}
    function diagnosticsNodeHealth(snapshot) {{
      const health = snapshot.status.node_health || {{}};
      const nodeCount = health.node_count || 0;
      if (!nodeCount) return "No runtime health evidence yet";
      const selected = health.selected_state || "unknown";
      return `Node health ${{health.healthy_count || 0}} healthy, ${{health.unhealthy_count || 0}} unhealthy, ${{health.unknown_count || 0}} unknown, checked ${{health.checked_count || 0}}/${{nodeCount}}, selected ${{selected}}`;
    }}
    function diagnosticsRecentEvent(snapshot) {{
      const event = (snapshot.status.recent_events || [])[0];
      if (!event) return "Recent event: none";
      const status = runStateLabels[event.status] || event.status;
      const note = event.note ? ` - ${{event.note}}` : "";
      return `Recent event: ${{status}}${{note}}`;
    }}
    function appendRuntimeEventRow(container, status, note) {{
      const row = document.createElement("div");
      const state = document.createElement("span");
      const detail = document.createElement("span");
      row.className = "event-row";
      state.className = "event-state";
      state.textContent = status;
      detail.textContent = note;
      row.append(state, detail);
      container.appendChild(row);
    }}
    function renderRuntimeEventListInto(containerId, snapshot) {{
      const container = document.getElementById(containerId);
      if (!container) return;
      container.replaceChildren();
      const events = (snapshot.status.recent_events || []).slice(0, 6);
      if (!events.length) {{
        appendRuntimeEventRow(container, "Idle", "No runtime events");
        return;
      }}
      for (const event of events) {{
        appendRuntimeEventRow(
          container,
          runStateLabels[event.status] || event.status,
          event.note || "No event detail"
        );
      }}
    }}
    function renderRuntimeEventList(snapshot) {{
      renderRuntimeEventListInto("runtime-event-list", snapshot);
      renderRuntimeEventListInto("dashboard-runtime-event-list", snapshot);
    }}
    function diagnosticsSystemProxy(snapshot) {{
      return `System proxy: ${{systemProxyDependency(snapshot)}}`;
    }}
    function diagnosticsTun(snapshot) {{
      return `TUN: ${{tunDependency(snapshot)}}`;
    }}
    function diagnosticsDefaultCore(snapshot) {{
      return snapshot ? "Native core default, support bundle includes certification evidence" : "Native core default";
    }}
    function setText(id, value) {{
      const element = document.getElementById(id);
      if (element) element.textContent = value;
    }}
    function syncPrimaryButton(id, primary) {{
      const button = document.getElementById(id);
      if (!button) return;
      button.textContent = primary.label;
      button.disabled = !primary.enabled;
    }}
    function syncTrafficModeButtons(trafficMode) {{
      document.querySelectorAll("[data-traffic-mode-button]").forEach((button) => {{
        button.setAttribute("aria-pressed", button.dataset.trafficModeButton === trafficMode ? "true" : "false");
      }});
    }}
    function overviewActivity(snapshot) {{
      return `${{diagnosticsRuntimeEvents(snapshot)}}; ${{diagnosticsRecentEvent(snapshot)}}`;
    }}
    function topCoreStatus(snapshot) {{
      const run = runStateLabels[snapshot.status.run_state] || snapshot.status.run_state;
      return `Core status: ${{run}}`;
    }}
    function topDependencyStatus(snapshot) {{
      const firstRun = snapshot.dependencies.first_run;
      return firstRun.system_proxy_ready && firstRun.tun_ready && !(firstRun.blockers || []).length
        ? "Dependencies ready"
        : "Dependencies need attention";
    }}
    window.keliSyncDashboard = (snapshot) => {{
      const status = snapshot.status;
      setText("nav-run-state", runStateLabels[status.run_state] || status.run_state);
      setText("top-core-status", topCoreStatus(snapshot));
      setText("top-traffic-mode", trafficModeLabels[status.traffic_mode] || status.traffic_mode);
      setText("top-selected-node", status.selected_outbound || "No node selected");
      setText("top-dependency-status", topDependencyStatus(snapshot));
      setText("top-activity-status", overviewActivity(snapshot));
      setText("activity-metrics", diagnosticsConnectionMetrics(snapshot));
      setText("dashboard-dependency-summary", dependencySummary(snapshot));
      setText("dashboard-system-proxy-status", systemProxyDependency(snapshot));
      setText("dashboard-tun-status", tunDependency(snapshot));
      setText("dashboard-blockers", dependencyBlockers(snapshot));
      renderRuntimeEventList(snapshot);
      renderDependencyActions(snapshot);
    }};
    window.keliSyncOverview = (snapshot) => {{
      const status = snapshot.status;
      const primary = snapshot.primary_action;
      setText("quick-run-state", runStateLabels[status.run_state] || status.run_state);
      setText("quick-traffic-mode", trafficModeLabels[status.traffic_mode] || status.traffic_mode);
      setText("quick-selected-node", status.selected_outbound || "No node selected");
      setText("quick-listen-address", status.listen || "Not listening");
      setText("quick-primary-state", primary.reason || (primary.enabled ? "Enabled" : "Disabled"));
      setText("quick-dependency-summary", dependencySummary(snapshot));
      setText("quick-subscription-summary", subscriptionSummary(snapshot.subscription));
      setText("activity-summary", overviewActivity(snapshot));
      syncPrimaryButton("quick-primary-button", primary);
      syncTrafficModeButtons(status.traffic_mode);
    }};
    window.keliSetShell = (snapshot) => {{
      const status = snapshot.status;
      const primary = snapshot.primary_action;
      window.keliSyncOverview(snapshot);
      window.keliSyncDashboard(snapshot);
      document.getElementById("run-state").textContent = runStateLabels[status.run_state] || status.run_state;
      document.getElementById("traffic-mode").textContent = trafficModeLabels[status.traffic_mode] || status.traffic_mode;
      document.getElementById("listen-address").textContent = status.listen || "Not listening";
      document.getElementById("selected-outbound").textContent = status.selected_outbound || "No node selected";
      document.getElementById("runtime-meta").textContent = `Generation ${{status.generation}}, events ${{status.event_count}}`;
      document.getElementById("primary-label").textContent = primary.label;
      document.getElementById("primary-state").textContent = primary.reason || (primary.enabled ? "Enabled" : "Disabled");
      const primaryButton = document.getElementById("primary-button");
      primaryButton.textContent = primary.label;
      primaryButton.disabled = !primary.enabled;
      const importUrlButton = document.getElementById("import-subscription-url-button");
      const updateUrlButton = document.getElementById("update-subscription-url-button");
      importUrlButton.disabled = status.run_state === "running";
      updateUrlButton.disabled = status.run_state !== "running";
      document.getElementById("tray-ids").textContent = snapshot.tray_menu.items.map((item) => item.id).join(", ");
      document.getElementById("window-visible").textContent = `Window visible: ${{snapshot.window.main_visible}}`;
      document.getElementById("dependency-summary").textContent = dependencySummary(snapshot);
      document.getElementById("system-proxy-dependency").textContent = systemProxyDependency(snapshot);
      document.getElementById("tun-dependency").textContent = tunDependency(snapshot);
      document.getElementById("dependency-blockers").textContent = dependencyBlockers(snapshot);
      renderDependencyActions(snapshot);
      document.getElementById("subscription-summary").textContent = subscriptionSummary(snapshot.subscription);
      renderNodeList(snapshot.subscription);
      document.getElementById("diagnostics-core-status").textContent = diagnosticsCoreStatus(snapshot);
      document.getElementById("diagnostics-runtime-events").textContent = diagnosticsRuntimeEvents(snapshot);
      document.getElementById("diagnostics-last-error").textContent = diagnosticsLastError(snapshot);
      document.getElementById("diagnostics-connection-metrics").textContent = diagnosticsConnectionMetrics(snapshot);
      document.getElementById("diagnostics-node-health").textContent = diagnosticsNodeHealth(snapshot);
      document.getElementById("diagnostics-recent-event").textContent = diagnosticsRecentEvent(snapshot);
      renderRuntimeEventList(snapshot);
      document.getElementById("diagnostics-system-proxy").textContent = diagnosticsSystemProxy(snapshot);
      document.getElementById("diagnostics-tun").textContent = diagnosticsTun(snapshot);
      document.getElementById("diagnostics-default-core").textContent = diagnosticsDefaultCore(snapshot);
      document.getElementById("snapshot-json").textContent = JSON.stringify(snapshot, null, 2);
    }};
  </script>
</body>
</html>"#,
        run_state = escape_html(run_state),
        top_core_status = escape_html(&top_core_status),
        top_dependency_status = escape_html(top_dependency_status),
        traffic_mode = escape_html(traffic_mode),
        listen = escape_html(listen),
        selected = escape_html(selected),
        generation = snapshot.status.generation,
        events = snapshot.status.event_count,
        primary_label = escape_html(&primary.label),
        primary_state = escape_html(primary_state),
        primary_disabled = primary_disabled,
        import_subscription_url_disabled = import_subscription_url_disabled,
        update_subscription_url_disabled = update_subscription_url_disabled,
        tray_ids = escape_html(&tray_ids),
        window_visible = snapshot.window.main_visible,
        dependency_summary = escape_html(&dependency_summary),
        system_proxy_dependency = escape_html(&system_proxy_dependency),
        tun_dependency = escape_html(&tun_dependency),
        dependency_blockers = escape_html(&dependency_blockers),
        dependency_actions = dependency_actions,
        diagnostics_core_status = escape_html(&diagnostics_core_status),
        diagnostics_runtime_events = escape_html(&diagnostics_runtime_events),
        diagnostics_last_error = escape_html(&diagnostics_last_error),
        diagnostics_connection_metrics = escape_html(&diagnostics_connection_metrics),
        diagnostics_node_health = escape_html(&diagnostics_node_health),
        diagnostics_recent_event = escape_html(&diagnostics_recent_event),
        runtime_event_items = runtime_event_items,
        diagnostics_system_proxy = escape_html(&diagnostics_system_proxy),
        diagnostics_tun = escape_html(&diagnostics_tun),
        diagnostics_default_core = escape_html(&diagnostics_default_core),
        activity_summary = escape_html(&activity_summary),
        local_inbound_pressed = local_inbound_pressed,
        system_proxy_pressed = system_proxy_pressed,
        tun_pressed = tun_pressed,
        subscription_summary = escape_html(&subscription_summary),
        node_buttons = node_buttons,
        snapshot_json = escape_html(&snapshot_json),
    )
}

pub fn shell_snapshot_script(snapshot: &DesktopShellState) -> serde_json::Result<String> {
    let snapshot_json = serde_json::to_string(snapshot)?;
    Ok(format!(
        "window.keliSetShell && window.keliSetShell({snapshot_json});"
    ))
}

#[derive(serde::Serialize)]
struct OperationStatus<'a> {
    kind: &'a str,
    message: &'a str,
}

pub fn operation_status_script(kind: &str, message: &str) -> serde_json::Result<String> {
    let status = OperationStatus { kind, message };
    let status_json = serde_json::to_string(&status)?;
    Ok(format!(
        "window.keliSetOperationStatus && window.keliSetOperationStatus({status_json});"
    ))
}

pub fn support_export_status_script(
    summary: &SupportBundleSaveSummary,
) -> serde_json::Result<String> {
    let summary_json = serde_json::to_string(summary)?;
    Ok(format!(
        "window.keliSetSupportExport && window.keliSetSupportExport({summary_json});"
    ))
}

#[derive(serde::Serialize)]
struct SupportExportFailureStatus<'a> {
    status: &'static str,
    error: &'a str,
}

pub fn support_export_failure_status_script(error: &str) -> serde_json::Result<String> {
    let status = SupportExportFailureStatus {
        status: "failed",
        error,
    };
    let status_json = serde_json::to_string(&status)?;
    Ok(format!(
        "window.keliSetSupportExport && window.keliSetSupportExport({status_json});"
    ))
}

pub fn wintun_install_status_script(
    summary: &DesktopWintunInstallSummary,
) -> serde_json::Result<String> {
    let summary_json = serde_json::to_string(summary)?;
    Ok(format!(
        "window.keliSetWintunInstall && window.keliSetWintunInstall({summary_json});"
    ))
}

#[derive(serde::Serialize)]
struct WintunInstallFailureStatus<'a> {
    status: &'static str,
    source_path: &'a str,
    error: &'a str,
}

pub fn wintun_install_failure_status_script(
    source_path: &str,
    error: &str,
) -> serde_json::Result<String> {
    let status = WintunInstallFailureStatus {
        status: "failed",
        source_path,
        error,
    };
    let status_json = serde_json::to_string(&status)?;
    Ok(format!(
        "window.keliSetWintunInstall && window.keliSetWintunInstall({status_json});"
    ))
}

#[derive(serde::Serialize)]
struct SubscriptionConfigImportStatus<'a> {
    status: &'static str,
    supported_count: usize,
    skipped_count: usize,
    default_outbound: Option<&'a str>,
    selected_outbound: Option<&'a str>,
}

#[derive(serde::Serialize)]
struct SubscriptionConfigImportFailureStatus<'a> {
    status: &'static str,
    error: &'a str,
}

#[derive(serde::Serialize)]
struct SubscriptionUrlFailureStatus<'a> {
    status: &'static str,
    error: &'a str,
}

pub fn subscription_config_import_status_script(
    summary: &DesktopSubscriptionSummary,
) -> serde_json::Result<String> {
    let status = SubscriptionConfigImportStatus {
        status: "imported",
        supported_count: summary.supported_count,
        skipped_count: summary.skipped_count,
        default_outbound: summary.default_outbound.as_deref(),
        selected_outbound: summary.selected_outbound.as_deref(),
    };
    let status_json = serde_json::to_string(&status)?;
    Ok(format!(
        "window.keliSetSubscriptionConfigImport && window.keliSetSubscriptionConfigImport({status_json});"
    ))
}

pub fn subscription_config_import_failure_status_script(error: &str) -> serde_json::Result<String> {
    let status = SubscriptionConfigImportFailureStatus {
        status: "failed",
        error,
    };
    let status_json = serde_json::to_string(&status)?;
    Ok(format!(
        "window.keliSetSubscriptionConfigImport && window.keliSetSubscriptionConfigImport({status_json});"
    ))
}

pub fn subscription_url_import_status_script(
    summary: &DesktopSubscriptionUrlImportSummary,
) -> serde_json::Result<String> {
    let summary_json = serde_json::to_string(summary)?;
    Ok(format!(
        "window.keliSetSubscriptionUrlImport && window.keliSetSubscriptionUrlImport({summary_json});"
    ))
}

pub fn subscription_url_import_failure_status_script(error: &str) -> serde_json::Result<String> {
    let status = SubscriptionUrlFailureStatus {
        status: "failed",
        error,
    };
    let status_json = serde_json::to_string(&status)?;
    Ok(format!(
        "window.keliSetSubscriptionUrlImport && window.keliSetSubscriptionUrlImport({status_json});"
    ))
}

pub fn subscription_url_update_status_script(
    summary: &DesktopSubscriptionUrlUpdateSummary,
) -> serde_json::Result<String> {
    let summary_json = serde_json::to_string(summary)?;
    Ok(format!(
        "window.keliSetSubscriptionUrlUpdate && window.keliSetSubscriptionUrlUpdate({summary_json});"
    ))
}

pub fn subscription_url_update_failure_status_script(error: &str) -> serde_json::Result<String> {
    let status = SubscriptionUrlFailureStatus {
        status: "failed",
        error,
    };
    let status_json = serde_json::to_string(&status)?;
    Ok(format!(
        "window.keliSetSubscriptionUrlUpdate && window.keliSetSubscriptionUrlUpdate({status_json});"
    ))
}

fn run_state_label(run_state: DesktopRunState) -> &'static str {
    match run_state {
        DesktopRunState::Stopped => "Stopped",
        DesktopRunState::Starting => "Starting",
        DesktopRunState::Running => "Running",
        DesktopRunState::Reloading => "Reloading",
        DesktopRunState::Stopping => "Stopping",
        DesktopRunState::Failed => "Failed",
    }
}

fn traffic_mode_label(traffic_mode: DesktopTrafficMode) -> &'static str {
    match traffic_mode {
        DesktopTrafficMode::SystemProxy => "System proxy",
        DesktopTrafficMode::Tun => "TUN",
        DesktopTrafficMode::MixedInboundOnly => "Local inbound",
    }
}

fn aria_pressed(pressed: bool) -> &'static str {
    if pressed {
        "true"
    } else {
        "false"
    }
}

fn dependency_summary(snapshot: &DesktopShellState) -> String {
    let system = if snapshot.dependencies.first_run.system_proxy_ready {
        "System proxy ready"
    } else {
        "System proxy blocked"
    };
    let tun = if snapshot.dependencies.first_run.tun_ready {
        "TUN ready"
    } else {
        "TUN blocked"
    };
    format!("{system}, {tun}")
}

fn system_proxy_dependency(snapshot: &DesktopShellState) -> String {
    let proxy = &snapshot.dependencies.system_proxy;
    let mut parts = vec![format!("System proxy {}", proxy.state)];
    if let Some(enabled) = proxy.enabled {
        parts.push(format!("enabled={enabled}"));
    }
    if let Some(server) = proxy.server.as_deref() {
        parts.push(format!("server={server}"));
    }
    if let Some(error) = proxy.error.as_deref() {
        parts.push(error.to_string());
    }
    if let Some(action) = proxy.action.as_deref() {
        parts.push(format!("action={action}"));
    }
    parts.join(", ")
}

fn tun_dependency(snapshot: &DesktopShellState) -> String {
    let tun = &snapshot.dependencies.tun_backend;
    let mut parts = vec![format!("Wintun {}", tun.state)];
    parts.push(format!("driver_present={}", tun.driver_library_present));
    parts.push(format!("api_available={}", tun.driver_api_available));
    if let Some(path) = tun.driver_library_path.as_deref() {
        parts.push(format!("path={path}"));
    }
    if let Some(reason) = tun.reason.as_deref() {
        parts.push(reason.to_string());
    }
    if let Some(action) = tun.action.as_deref() {
        parts.push(format!("action={action}"));
    }
    parts.join(", ")
}

fn dependency_blockers(snapshot: &DesktopShellState) -> String {
    if snapshot.dependencies.first_run.blockers.is_empty() {
        return "No dependency blockers".to_string();
    }
    snapshot
        .dependencies
        .first_run
        .blockers
        .iter()
        .map(|blocker| {
            let action = blocker
                .action
                .as_deref()
                .map(|action| format!(" action={action}"))
                .unwrap_or_default();
            format!("{}: {}{}", blocker.code, blocker.message, action)
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn diagnostics_core_status(snapshot: &DesktopShellState) -> String {
    format!(
        "Core {} via {}",
        run_state_label(snapshot.status.run_state).to_ascii_lowercase(),
        traffic_mode_label(snapshot.status.traffic_mode)
    )
}

fn diagnostics_runtime_events(snapshot: &DesktopShellState) -> String {
    format!(
        "Generation {}, events {}",
        snapshot.status.generation, snapshot.status.event_count
    )
}

fn diagnostics_last_error(snapshot: &DesktopShellState) -> String {
    format!(
        "Last error: {}",
        snapshot.status.last_error.as_deref().unwrap_or("none")
    )
}

fn diagnostics_connection_metrics(snapshot: &DesktopShellState) -> String {
    let metrics = &snapshot.status.connection_metrics;
    let average = metrics
        .average_connect_ms
        .map(|value| format!("{value} ms"))
        .unwrap_or_else(|| "n/a".to_string());
    format!(
        "Connections {} total, {} ok, {} failed, avg connect {}",
        metrics.total, metrics.success, metrics.failure, average
    )
}

fn diagnostics_node_health(snapshot: &DesktopShellState) -> String {
    let health = &snapshot.status.node_health;
    if health.node_count == 0 {
        return "No runtime health evidence yet".to_string();
    }

    format!(
        "Node health {} healthy, {} unhealthy, {} unknown, checked {}/{}, selected {}",
        health.healthy_count,
        health.unhealthy_count,
        health.unknown_count,
        health.checked_count,
        health.node_count,
        health.selected_state.as_deref().unwrap_or("unknown")
    )
}

fn diagnostics_recent_event(snapshot: &DesktopShellState) -> String {
    let Some(event) = snapshot.status.recent_events.first() else {
        return "Recent event: none".to_string();
    };
    let note = event
        .note
        .as_deref()
        .map(|note| format!(" - {note}"))
        .unwrap_or_default();
    format!("Recent event: {}{}", run_state_label(event.status), note)
}

fn runtime_event_items(snapshot: &DesktopShellState) -> String {
    if snapshot.status.recent_events.is_empty() {
        return r#"<div class="event-row"><span class="event-state">Idle</span><span>No runtime events</span></div>"#
            .to_string();
    }

    snapshot
        .status
        .recent_events
        .iter()
        .take(6)
        .map(|event| {
            let status = escape_html(run_state_label(event.status));
            let note = escape_html(event.note.as_deref().unwrap_or("No event detail"));
            format!(
                r#"<div class="event-row"><span class="event-state">{status}</span><span>{note}</span></div>"#
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn diagnostics_system_proxy(snapshot: &DesktopShellState) -> String {
    format!("System proxy: {}", system_proxy_dependency(snapshot))
}

fn diagnostics_tun(snapshot: &DesktopShellState) -> String {
    format!("TUN: {}", tun_dependency(snapshot))
}

fn diagnostics_default_core(_snapshot: &DesktopShellState) -> String {
    "Native core default, support bundle includes certification evidence".to_string()
}

fn dependency_action_buttons(snapshot: &DesktopShellState) -> String {
    let mut actions = Vec::new();
    add_dependency_action(
        &mut actions,
        snapshot.dependencies.system_proxy.action.as_deref(),
    );
    add_dependency_action(
        &mut actions,
        snapshot.dependencies.tun_backend.action.as_deref(),
    );
    for blocker in &snapshot.dependencies.first_run.blockers {
        add_dependency_action(&mut actions, blocker.action.as_deref());
    }

    actions
        .iter()
        .map(|action| {
            let action_value = escape_html(action);
            let label = escape_html(dependency_action_label(action));
            format!(
                r#"<button data-dependency-action="{action_value}" onclick="postDependencyAction(this.dataset.dependencyAction)">{label}</button>"#
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn add_dependency_action(actions: &mut Vec<String>, action: Option<&str>) {
    let Some(action) = action else {
        return;
    };
    if action.trim().is_empty() || actions.iter().any(|existing| existing == action) {
        return;
    }
    actions.push(action.to_string());
}

fn dependency_action_label(action: &str) -> &str {
    match action {
        "check-system-proxy" => "Open proxy settings",
        "install-wintun" => "Open Wintun download",
        "check-tun" => "Open TUN help",
        _ => action,
    }
}

fn subscription_summary(subscription: Option<&DesktopSubscriptionSummary>) -> String {
    match subscription {
        Some(subscription) => format!(
            "Supported {}, skipped {}",
            subscription.supported_count, subscription.skipped_count
        ),
        None => "No subscription imported".to_string(),
    }
}

fn node_buttons(subscription: Option<&DesktopSubscriptionSummary>) -> String {
    let Some(subscription) = subscription else {
        return r#"<span class="muted">No nodes</span>"#.to_string();
    };
    let mut nodes = Vec::new();
    if subscription.nodes.is_empty() {
        nodes.push(r#"<span class="muted">No nodes</span>"#.to_string());
    }
    nodes.extend(subscription.nodes.iter().map(|node| {
        let selected = if node.selected { "true" } else { "false" };
        let tag = escape_html(&node.tag);
        let meta = escape_html(&format!(
            "{} / {} / {}",
            node.protocol, node.transport, node.security
        ));
        let udp = if node.udp_supported {
            "UDP ready"
        } else {
            "UDP unavailable"
        };
        let health = escape_html(&node_health_detail(node));
        let mut badges = Vec::new();
        if node.selected {
            badges.push(r#"<span class="node-badge">Selected</span>"#.to_string());
        }
        if node.recommended {
            badges.push(r#"<span class="node-badge">Recommended</span>"#.to_string());
        }
        let badges = badges.join("");
        format!(
            r#"<button data-node-tag="{tag}" aria-pressed="{selected}" onclick="postSelectNode(this.dataset.nodeTag)"><span class="node-tag">{tag}</span><span class="node-meta">{meta}</span><span class="node-meta">{udp}</span><span class="node-meta">{health}</span><span class="node-badges">{badges}</span></button>"#
        )
    }));
    nodes.extend(subscription.skipped.iter().map(|skipped| {
        let skipped = escape_html(skipped);
        format!(
            r#"<div class="node-skipped"><span class="node-badge">Skipped</span><span>{skipped}</span></div>"#
        )
    }));
    nodes.join("")
}

fn node_health_detail(node: &keli_desktop::DesktopNodeSummary) -> String {
    let mut parts = Vec::new();
    if let Some(state) = node.health_state.as_deref() {
        parts.push(format!("Health {state}"));
    }
    match node.tcp_available {
        Some(true) => parts.push("TCP ready".to_string()),
        Some(false) => parts.push("TCP failed".to_string()),
        None => {}
    }
    match node.udp_available {
        Some(true) => parts.push("UDP live".to_string()),
        Some(false) => parts.push("UDP failed".to_string()),
        None => {}
    }
    if let Some(latency_ms) = node.latency_ms {
        parts.push(format!("{latency_ms} ms"));
    }
    if let Some(error) = node.health_error.as_deref() {
        parts.push(format!("Last failure {error}"));
    }
    if parts.is_empty() {
        "Health unknown".to_string()
    } else {
        parts.join(", ")
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use keli_desktop::{
        DesktopDependencyReport, DesktopFirstRunReport, DesktopNodeSummary,
        DesktopRecentRuntimeEvent, DesktopShellState, DesktopStatusSnapshot,
        DesktopSubscriptionSummary, DesktopSubscriptionUpdateSummary,
        DesktopSubscriptionUrlFetchSummary, DesktopSubscriptionUrlImportSummary,
        DesktopSubscriptionUrlUpdateSummary, DesktopSystemProxyDependency, DesktopTrafficMode,
        DesktopTunBackendDependency,
    };

    fn snapshot() -> DesktopShellState {
        DesktopShellState::new(
            DesktopStatusSnapshot {
                run_state: DesktopRunState::Stopped,
                traffic_mode: DesktopTrafficMode::SystemProxy,
                selected_outbound: Some("SS-READY".to_string()),
                listen: Some("127.0.0.1:7890".to_string()),
                generation: 3,
                event_count: 5,
                last_error: None,
                connection_metrics: Default::default(),
                node_health: Default::default(),
                recent_events: Vec::new(),
            },
            DesktopDependencyReport {
                first_run: DesktopFirstRunReport {
                    platform: "Windows".to_string(),
                    system_proxy_ready: true,
                    tun_ready: true,
                    can_start_system_proxy_mode: true,
                    can_start_tun_mode: true,
                    blockers: Vec::new(),
                },
                system_proxy: DesktopSystemProxyDependency {
                    state: "ready".to_string(),
                    supported: true,
                    ready: true,
                    enabled: Some(false),
                    server: None,
                    error: None,
                    action: None,
                },
                tun_backend: DesktopTunBackendDependency {
                    state: "ready".to_string(),
                    platform: "Windows".to_string(),
                    backend: "wintun".to_string(),
                    supported: true,
                    lifecycle_wired: true,
                    packet_io_wired: true,
                    route_takeover_wired: true,
                    driver_library_present: true,
                    driver_api_available: true,
                    driver_library_path: Some("C:\\Keli\\wintun.dll".to_string()),
                    driver_api_error: None,
                    install_required: false,
                    searched_paths: vec!["C:\\Keli\\wintun.dll".to_string()],
                    reason: None,
                    action: None,
                },
            },
        )
    }

    fn subscription(tag: &str) -> DesktopSubscriptionSummary {
        DesktopSubscriptionSummary {
            usable: true,
            supported_count: 1,
            skipped_count: 0,
            default_outbound: Some(tag.to_string()),
            selected_outbound: Some(tag.to_string()),
            recommended_outbound: Some(tag.to_string()),
            nodes: vec![DesktopNodeSummary {
                tag: tag.to_string(),
                protocol: "ss".to_string(),
                transport: "tcp".to_string(),
                security: "none".to_string(),
                udp_supported: true,
                selected: true,
                recommended: true,
                health_state: Some("unknown".to_string()),
                tcp_available: None,
                udp_available: None,
                latency_ms: None,
                health_error: None,
            }],
            skipped: Vec::new(),
        }
    }

    #[test]
    fn shell_html_includes_snapshot_state_and_tray_ids() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("Keli"));
        assert!(html.contains("window.ipc.postMessage('primary')"));
        assert!(html.contains("id=\"run-state\""));
        assert!(html.contains("Stopped"));
        assert!(html.contains("SS-READY"));
        assert!(html.contains("show-main-window"));
        assert!(html.contains("toggle-service"));
        assert!(html.contains("open-diagnostics"));
        assert!(html.contains("quit"));
    }

    #[test]
    fn ui_mvp_first_screen_surfaces_core_controls() {
        let mut snapshot = snapshot();
        snapshot.refresh_subscription(Some(subscription("SS-READY")));

        let html = render_shell_html(&snapshot);

        assert!(html.contains("class=\"app-shell\""));
        assert!(html.contains("id=\"core-command-panel\""));
        assert!(html.contains("id=\"quick-run-state\""));
        assert!(html.contains("id=\"quick-traffic-mode\""));
        assert!(html.contains("id=\"quick-selected-node\""));
        assert!(html.contains("id=\"quick-listen-address\""));
        assert!(html.contains("id=\"quick-primary-button\""));
        assert!(html.contains("id=\"mode-segmented-control\""));
        assert!(html.contains("data-traffic-mode-button=\"system-proxy\""));
        assert!(html.contains("id=\"activity-summary\""));
        assert!(html.contains("window.keliSyncOverview"));
    }

    #[test]
    fn dashboard_baseline_includes_shell_navigation_and_top_status() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("class=\"desktop-layout\""));
        assert!(html.contains("id=\"app-navigation\""));
        assert!(html.contains("data-view-target=\"dashboard-view\""));
        assert!(html.contains("data-view-target=\"nodes-view\""));
        assert!(html.contains("data-view-target=\"diagnostics-view\""));
        assert!(html.contains("data-view-target=\"settings-view\""));
        assert!(html.contains("id=\"top-status-bar\""));
        assert!(html.contains("id=\"top-core-status\""));
        assert!(html.contains("id=\"top-dependency-status\""));
        assert!(html.contains("id=\"top-selected-node\""));
        assert!(html.contains("id=\"dashboard-view\""));
    }

    #[test]
    fn dashboard_baseline_includes_activity_dependency_and_support_panels() {
        let mut snapshot = snapshot();
        snapshot.status.connection_metrics.total = 12;
        snapshot.status.connection_metrics.success = 11;
        snapshot.status.connection_metrics.failure = 1;
        snapshot.status.connection_metrics.average_connect_ms = Some(18);
        snapshot.refresh_subscription(Some(subscription("SS-READY")));

        let html = render_shell_html(&snapshot);

        assert!(html.contains("id=\"connection-activity-panel\""));
        assert!(html.contains("id=\"activity-metrics\""));
        assert!(html.contains("id=\"dashboard-events-panel\""));
        assert!(html.contains("id=\"dashboard-dependencies-panel\""));
        assert!(html.contains("id=\"support-actions-panel\""));
        assert!(html.contains("id=\"dashboard-export-support-button\""));
        assert!(html.contains("window.keliSyncDashboard"));
    }

    #[test]
    fn shell_html_shows_primary_blocked_reason_before_subscription() {
        let html = render_shell_html(&snapshot());

        assert!(
            html.contains("id=\"primary-state\">Import a subscription before starting Keli</div>")
        );
        assert!(html.contains("id=\"primary-button\" class=\"primary\" onclick=\"window.ipc.postMessage('primary')\" disabled>Start Blocked</button>"));
    }

    #[test]
    fn shell_html_live_update_prefers_primary_reason() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("primary.reason || (primary.enabled ? \"Enabled\" : \"Disabled\")"));
    }

    #[test]
    fn shell_html_escapes_snapshot_values() {
        let mut snapshot = snapshot();
        snapshot.status.selected_outbound = Some("<node>&\"".to_string());

        let html = render_shell_html(&snapshot);

        assert!(html.contains("&lt;node&gt;&amp;&quot;"));
        assert!(!html.contains("<node>&\""));
    }

    #[test]
    fn shell_snapshot_script_updates_webview_snapshot() {
        let script = shell_snapshot_script(&snapshot()).expect("snapshot script");

        assert!(script.contains("window.keliSetShell"));
        assert!(script.contains("SS-READY"));
        assert!(script.contains("show-main-window"));
    }

    #[test]
    fn operation_status_html_includes_unified_target_and_setter() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("id=\"operation-status\""));
        assert!(html.contains("window.keliSetOperationStatus"));
        assert!(html.contains("data-kind=\"info\""));
    }

    #[test]
    fn existing_status_setters_mirror_to_operation_status() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("window.keliSetOperationStatus({ kind:"));
        assert!(html.contains("document.getElementById(\"operation-status\")"));
    }

    #[test]
    fn operation_status_script_reports_kind_and_message() {
        let script =
            operation_status_script("error", "Start failed").expect("operation status script");

        assert!(script.contains("window.keliSetOperationStatus"));
        assert!(script.contains("\"kind\":\"error\""));
        assert!(script.contains("Start failed"));
    }

    #[test]
    fn subscription_ipc_html_includes_config_import_controls() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("id=\"subscription-config\""));
        assert!(html.contains("import-subscription-config"));
        assert!(html.contains("set-traffic-mode"));
        assert!(html.contains("select-node"));
    }

    #[test]
    fn subscription_config_import_html_includes_local_status_target() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("id=\"subscription-config-status\""));
        assert!(html.contains("window.keliSetSubscriptionConfigImport"));
    }

    #[test]
    fn subscription_config_import_status_script_reports_success_counts() {
        let script = subscription_config_import_status_script(&subscription("SS-READY"))
            .expect("subscription config import status script");

        assert!(script.contains("window.keliSetSubscriptionConfigImport"));
        assert!(script.contains("\"status\":\"imported\""));
        assert!(script.contains("\"supported_count\":1"));
    }

    #[test]
    fn subscription_config_import_failure_status_script_reports_error() {
        let script = subscription_config_import_failure_status_script(
            "import-subscription client InvalidSubscription",
        )
        .expect("subscription config import failure script");

        assert!(script.contains("window.keliSetSubscriptionConfigImport"));
        assert!(script.contains("\"status\":\"failed\""));
        assert!(script.contains("InvalidSubscription"));
    }

    #[test]
    fn subscription_url_html_includes_url_import_controls() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("id=\"subscription-url\""));
        assert!(html.contains("import-subscription-url"));
        assert!(html.contains("id=\"subscription-url-status\""));
        assert!(html.contains("window.keliSetSubscriptionUrlImport"));
    }

    #[test]
    fn subscription_url_html_includes_running_update_controls() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("id=\"update-subscription-url-button\""));
        assert!(html.contains("update-subscription-url"));
        assert!(html.contains("window.keliSetSubscriptionUrlUpdate"));
    }

    #[test]
    fn subscription_url_update_button_starts_disabled_when_stopped() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains(
            "id=\"import-subscription-url-button\" class=\"primary\" onclick=\"postImportSubscriptionUrl()\">Import URL</button>"
        ));
        assert!(html.contains(
            "id=\"update-subscription-url-button\" onclick=\"postUpdateSubscriptionUrl()\" disabled>Update URL</button>"
        ));
    }

    #[test]
    fn subscription_url_import_button_starts_disabled_when_running() {
        let mut snapshot = snapshot();
        snapshot.refresh_status(DesktopStatusSnapshot {
            run_state: DesktopRunState::Running,
            ..snapshot.status.clone()
        });

        let html = render_shell_html(&snapshot);

        assert!(html.contains(
            "id=\"import-subscription-url-button\" class=\"primary\" onclick=\"postImportSubscriptionUrl()\" disabled>Import URL</button>"
        ));
        assert!(html.contains(
            "id=\"update-subscription-url-button\" onclick=\"postUpdateSubscriptionUrl()\">Update URL</button>"
        ));
    }

    #[test]
    fn subscription_health_refresh_html_includes_button_and_ipc() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("id=\"refresh-node-health-button\""));
        assert!(html.contains("postRefreshNodeHealth()"));
        assert!(html.contains("refresh-node-health"));
    }

    #[test]
    fn subscription_mode_controls_include_local_inbound() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("postTrafficMode('mixed-inbound-only')"));
        assert!(html.contains("Local inbound"));
    }

    #[test]
    fn subscription_url_status_script_updates_redacted_fetch_status() {
        let summary = DesktopSubscriptionUrlImportSummary {
            fetch: DesktopSubscriptionUrlFetchSummary {
                ok: true,
                scheme: Some("https".to_string()),
                host: Some("sub.example.com".to_string()),
                port: None,
                default_port: Some(true),
                path_present: Some(true),
                query_present: Some(true),
                http_status: Some(200),
                body_bytes: Some(128),
                elapsed_ms: Some(9),
                error_kind: None,
                error_detail: None,
            },
            subscription: Some(subscription("URL-READY")),
            error: None,
        };

        let script = subscription_url_import_status_script(&summary)
            .expect("subscription URL import script");

        assert!(script.contains("window.keliSetSubscriptionUrlImport"));
        assert!(script.contains("sub.example.com"));
        assert!(!script.contains("token=secret"));
    }

    #[test]
    fn subscription_url_import_failure_status_script_reports_error() {
        let script =
            subscription_url_import_failure_status_script("import-subscription-url fetch Timeout")
                .expect("subscription URL import failure script");

        assert!(script.contains("window.keliSetSubscriptionUrlImport"));
        assert!(script.contains("\"status\":\"failed\""));
        assert!(script.contains("fetch Timeout"));
    }

    #[test]
    fn subscription_url_update_status_script_updates_redacted_runtime_status() {
        let subscription = subscription("URL-STAY");
        let summary = DesktopSubscriptionUrlUpdateSummary {
            applied: true,
            error: None,
            fetch: DesktopSubscriptionUrlFetchSummary {
                ok: true,
                scheme: Some("https".to_string()),
                host: Some("sub.example.com".to_string()),
                port: None,
                default_port: Some(true),
                path_present: Some(true),
                query_present: Some(true),
                http_status: Some(200),
                body_bytes: Some(256),
                elapsed_ms: Some(12),
                error_kind: None,
                error_detail: None,
            },
            update: Some(DesktopSubscriptionUpdateSummary {
                applied: true,
                error: None,
                reason: "selected-outbound-preserved".to_string(),
                current_supported_count: 1,
                new_supported_count: 1,
                new_skipped_count: 0,
                current_selected_outbound: Some("URL-STAY".to_string()),
                planned_selected_outbound: Some("URL-STAY".to_string()),
                selected_outbound_preserved: true,
                selected_outbound_changed: false,
                added_tags: Vec::new(),
                removed_tags: Vec::new(),
                retained_tags: vec!["URL-STAY".to_string()],
                subscription,
            }),
            runtime_status: DesktopStatusSnapshot {
                run_state: DesktopRunState::Running,
                traffic_mode: DesktopTrafficMode::SystemProxy,
                selected_outbound: Some("URL-STAY".to_string()),
                listen: Some("127.0.0.1:7890".to_string()),
                generation: 8,
                event_count: 6,
                last_error: None,
                connection_metrics: Default::default(),
                node_health: Default::default(),
                recent_events: Vec::new(),
            },
        };

        let script = subscription_url_update_status_script(&summary)
            .expect("subscription URL update script");

        assert!(script.contains("window.keliSetSubscriptionUrlUpdate"));
        assert!(script.contains("selected-outbound-preserved"));
        assert!(!script.contains("token=secret"));
    }

    #[test]
    fn subscription_url_update_failure_status_script_reports_error() {
        let script = subscription_url_update_failure_status_script(
            "update-subscription-url fetch InvalidStatus",
        )
        .expect("subscription URL update failure script");

        assert!(script.contains("window.keliSetSubscriptionUrlUpdate"));
        assert!(script.contains("\"status\":\"failed\""));
        assert!(script.contains("fetch InvalidStatus"));
    }

    #[test]
    fn dependency_html_includes_readiness_targets() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("id=\"dependency-summary\""));
        assert!(html.contains("id=\"system-proxy-dependency\""));
        assert!(html.contains("id=\"tun-dependency\""));
        assert!(html.contains("id=\"dependency-blockers\""));
        assert!(html.contains("System proxy ready"));
        assert!(html.contains("TUN ready"));
    }

    #[test]
    fn dependency_html_renders_missing_wintun_action() {
        let mut snapshot = snapshot();
        snapshot.dependencies.first_run.tun_ready = false;
        snapshot.dependencies.first_run.can_start_tun_mode = false;
        snapshot.dependencies.first_run.blockers = vec![keli_desktop::DesktopBlocker {
            code: "wintun-missing".to_string(),
            message: "Wintun library was not found".to_string(),
            action: Some("install-wintun".to_string()),
        }];
        snapshot.dependencies.tun_backend.state = "install-required".to_string();
        snapshot.dependencies.tun_backend.driver_library_present = false;
        snapshot.dependencies.tun_backend.driver_api_available = false;
        snapshot.dependencies.tun_backend.install_required = true;
        snapshot.dependencies.tun_backend.reason = Some("Wintun library was not found".to_string());
        snapshot.dependencies.tun_backend.action = Some("install-wintun".to_string());

        let html = render_shell_html(&snapshot);

        assert!(html.contains("id=\"dependency-actions\""));
        assert!(html.contains("dependency-action"));
        assert!(html.contains("Open Wintun download"));
        assert!(html.contains("Wintun install-required"));
        assert!(html.contains("Wintun library was not found"));
        assert!(html.contains("install-wintun"));
        assert!(html.contains("System proxy ready"));
    }

    #[test]
    fn dependency_html_renders_system_proxy_action_button() {
        let mut snapshot = snapshot();
        snapshot.dependencies.first_run.system_proxy_ready = false;
        snapshot.dependencies.first_run.can_start_system_proxy_mode = false;
        snapshot.dependencies.first_run.blockers = vec![keli_desktop::DesktopBlocker {
            code: "system-proxy-unavailable".to_string(),
            message: "System proxy control is unavailable".to_string(),
            action: Some("check-system-proxy".to_string()),
        }];
        snapshot.dependencies.system_proxy.state = "unavailable".to_string();
        snapshot.dependencies.system_proxy.ready = false;
        snapshot.dependencies.system_proxy.supported = false;
        snapshot.dependencies.system_proxy.error =
            Some("System proxy control is unavailable".to_string());
        snapshot.dependencies.system_proxy.action = Some("check-system-proxy".to_string());

        let html = render_shell_html(&snapshot);

        assert!(html.contains("id=\"dependency-actions\""));
        assert!(html.contains("check-system-proxy"));
        assert!(html.contains("Open proxy settings"));
    }

    #[test]
    fn shell_snapshot_script_carries_dependency_updates() {
        let script = shell_snapshot_script(&snapshot()).expect("snapshot script");

        assert!(script.contains("dependencies"));
        assert!(script.contains("window.keliSetShell"));
    }

    #[test]
    fn subscription_ipc_html_renders_subscription_summary() {
        let mut snapshot = snapshot();
        snapshot.refresh_subscription(Some(subscription("SS-READY")));

        let html = render_shell_html(&snapshot);

        assert!(html.contains("Supported 1"));
        assert!(html.contains("SS-READY"));
        assert!(html.contains("data-node-tag=\"SS-READY\""));
    }

    #[test]
    fn subscription_node_list_renders_protocol_transport_security_and_badges() {
        let mut snapshot = snapshot();
        let mut summary = subscription("SS-READY");
        summary.nodes[0].health_state = Some("healthy".to_string());
        summary.nodes[0].tcp_available = Some(true);
        summary.nodes[0].udp_available = Some(true);
        summary.nodes[0].latency_ms = Some(42);
        snapshot.refresh_subscription(Some(summary));

        let html = render_shell_html(&snapshot);

        assert!(html.contains("SS-READY"));
        assert!(html.contains("ss / tcp / none"));
        assert!(html.contains("UDP ready"));
        assert!(html.contains("Health healthy"));
        assert!(html.contains("TCP ready"));
        assert!(html.contains("UDP live"));
        assert!(html.contains("42 ms"));
        assert!(html.contains("Selected"));
        assert!(html.contains("Recommended"));
    }

    #[test]
    fn subscription_node_list_renders_skipped_reasons() {
        let mut snapshot = snapshot();
        let mut summary = subscription("SS-READY");
        summary.skipped_count = 1;
        summary.skipped = vec!["BROKEN: unsupported protocol".to_string()];
        snapshot.refresh_subscription(Some(summary));

        let html = render_shell_html(&snapshot);

        assert!(html.contains("Skipped"));
        assert!(html.contains("BROKEN: unsupported protocol"));
    }

    #[test]
    fn subscription_node_list_live_renderer_includes_detail_fields() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("node-meta"));
        assert!(html.contains("node-badge"));
        assert!(html.contains("node.health_state"));
        assert!(html.contains("node.tcp_available"));
        assert!(html.contains("node.udp_available"));
        assert!(html.contains("node.latency_ms"));
        assert!(html.contains("subscription.skipped"));
    }

    #[test]
    fn support_export_html_includes_export_button_and_status() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("export-support-bundle"));
        assert!(html.contains("id=\"support-export-status\""));
        assert!(html.contains("window.keliSetSupportExport"));
    }

    #[test]
    fn diagnostics_html_includes_health_summary() {
        let mut snapshot = snapshot();
        snapshot.status.last_error = Some("Managed(\"bind failed\")".to_string());
        snapshot.status.connection_metrics.total = 3;
        snapshot.status.connection_metrics.success = 2;
        snapshot.status.connection_metrics.failure = 1;
        snapshot.status.connection_metrics.average_connect_ms = Some(25);
        snapshot.status.node_health.node_count = 2;
        snapshot.status.node_health.healthy_count = 1;
        snapshot.status.node_health.unhealthy_count = 1;
        snapshot.status.node_health.checked_count = 2;
        snapshot.status.node_health.selected_state = Some("healthy".to_string());
        snapshot.status.recent_events = vec![DesktopRecentRuntimeEvent {
            status: DesktopRunState::Running,
            note: Some("runtime running".to_string()),
        }];

        let html = render_shell_html(&snapshot);

        assert!(html.contains("id=\"diagnostics-core-status\""));
        assert!(html.contains("Core stopped via System proxy"));
        assert!(html.contains("id=\"diagnostics-runtime-events\""));
        assert!(html.contains("Generation 3, events 5"));
        assert!(html.contains("Last error: Managed(&quot;bind failed&quot;)"));
        assert!(html.contains("id=\"diagnostics-system-proxy\""));
        assert!(html.contains("id=\"diagnostics-tun\""));
        assert!(html.contains("Connections 3 total, 2 ok, 1 failed, avg connect 25 ms"));
        assert!(html.contains(
            "Node health 1 healthy, 1 unhealthy, 0 unknown, checked 2/2, selected healthy"
        ));
        assert!(html.contains("Recent event: Running - runtime running"));
        assert!(html.contains("Native core default"));
    }

    #[test]
    fn diagnostics_html_renders_recent_runtime_event_list() {
        let mut snapshot = snapshot();
        snapshot.status.recent_events = vec![
            DesktopRecentRuntimeEvent {
                status: DesktopRunState::Running,
                note: Some("listener ready".to_string()),
            },
            DesktopRecentRuntimeEvent {
                status: DesktopRunState::Stopped,
                note: Some("stopped cleanly".to_string()),
            },
        ];

        let html = render_shell_html(&snapshot);

        assert!(html.contains("id=\"runtime-event-list\""));
        assert!(html.contains("listener ready"));
        assert!(html.contains("stopped cleanly"));
        assert!(html.contains("renderRuntimeEventList(snapshot)"));
    }

    #[test]
    fn diagnostics_live_renderer_updates_health_summary() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("diagnosticsCoreStatus(snapshot)"));
        assert!(html.contains("diagnosticsRuntimeEvents(snapshot)"));
        assert!(html.contains("diagnosticsLastError(snapshot)"));
        assert!(html.contains("id=\"diagnostics-connection-metrics\""));
        assert!(html.contains("id=\"diagnostics-node-health\""));
        assert!(html.contains("id=\"diagnostics-recent-event\""));
        assert!(html.contains("diagnosticsConnectionMetrics(snapshot)"));
        assert!(html.contains("diagnosticsNodeHealth(snapshot)"));
        assert!(html.contains("diagnosticsRecentEvent(snapshot)"));
        assert!(html.contains("diagnosticsDefaultCore(snapshot)"));
    }

    #[test]
    fn support_export_status_script_updates_export_status() {
        let summary = crate::support::SupportBundleSaveSummary {
            status: "saved".to_string(),
            path: "C:\\Users\\Administrator\\Documents\\Keli\\Support\\keli-support.json"
                .to_string(),
            byte_count: 15,
        };

        let script = support_export_status_script(&summary).expect("support export script");

        assert!(script.contains("window.keliSetSupportExport"));
        assert!(script.contains("keli-support.json"));
    }

    #[test]
    fn support_export_failure_status_script_reports_error() {
        let script =
            support_export_failure_status_script("write support bundle failed: access denied")
                .expect("support export failure script");

        assert!(script.contains("window.keliSetSupportExport"));
        assert!(script.contains("\"status\":\"failed\""));
        assert!(script.contains("access denied"));
    }

    #[test]
    fn wintun_install_html_includes_local_path_controls() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("id=\"wintun-source-path\""));
        assert!(html.contains("install-wintun-path"));
        assert!(html.contains("id=\"wintun-install-status\""));
        assert!(html.contains("window.keliSetWintunInstall"));
    }

    #[test]
    fn wintun_install_status_script_updates_install_status() {
        let summary = keli_desktop::DesktopWintunInstallSummary {
            status: "ready".to_string(),
            source_kind: "directory".to_string(),
            source_path: "C:\\Downloads\\wintun".to_string(),
            source_candidates: Vec::new(),
            target_path: "C:\\Program Files\\Keli\\wintun.dll".to_string(),
            copied_bytes: 12345,
            previous_target_present: false,
            driver_api_available: true,
            ready_after_install: true,
        };

        let script = wintun_install_status_script(&summary).expect("Wintun install script");

        assert!(script.contains("window.keliSetWintunInstall"));
        assert!(script.contains("ready"));
        assert!(script.contains("wintun.dll"));
    }

    #[test]
    fn wintun_install_failure_status_script_updates_install_status() {
        let script = wintun_install_failure_status_script(
            "C:\\Downloads\\missing-wintun.dll",
            "install-wintun dependency Platform(\"Wintun source DLL was not found\")",
        )
        .expect("Wintun install failure script");

        assert!(script.contains("window.keliSetWintunInstall"));
        assert!(script.contains("\"status\":\"failed\""));
        assert!(script.contains("missing-wintun.dll"));
        assert!(script.contains("Wintun source DLL was not found"));
    }
}
