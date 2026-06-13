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
        .unwrap_or("未选择节点");
    let listen = snapshot.status.listen.as_deref().unwrap_or("未监听");
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
        "可用"
    } else {
        "不可用"
    });
    let subscription_summary = subscription_summary(snapshot.subscription.as_ref());
    let node_buttons = node_buttons(snapshot.subscription.as_ref());
    let nodes_supported_count = nodes_supported_count(snapshot.subscription.as_ref());
    let nodes_skipped_count = nodes_skipped_count(snapshot.subscription.as_ref());
    let nodes_healthy_count = nodes_healthy_count(snapshot.subscription.as_ref());
    let nodes_udp_ready_count = nodes_udp_ready_count(snapshot.subscription.as_ref());
    let nodes_recommended = nodes_recommended(snapshot.subscription.as_ref());
    let nodes_table_rows = nodes_table_rows(snapshot.subscription.as_ref());
    let selected_node_title = selected_node_title(snapshot.subscription.as_ref());
    let selected_node_detail = selected_node_detail(snapshot.subscription.as_ref());
    let dependency_summary = dependency_summary(snapshot);
    let system_proxy_dependency = system_proxy_dependency(snapshot);
    let tun_dependency = tun_dependency(snapshot);
    let dependency_blockers = dependency_blockers(snapshot);
    let dashboard_system_proxy_status = dashboard_system_proxy_status(snapshot);
    let dashboard_tun_status = dashboard_tun_status(snapshot);
    let dashboard_dependency_blockers = dashboard_dependency_blockers(snapshot);
    let dependency_actions = dependency_action_buttons(snapshot);
    let diagnostics_core_status = diagnostics_core_status(snapshot);
    let diagnostics_runtime_events = diagnostics_runtime_events(snapshot);
    let diagnostics_last_error = diagnostics_last_error(snapshot);
    let diagnostics_connection_metrics = diagnostics_connection_metrics(snapshot);
    let diagnostics_node_health = diagnostics_node_health(snapshot);
    let diagnostics_recent_event = diagnostics_recent_event(snapshot);
    let runtime_event_items = runtime_event_items(snapshot);
    let diagnostics_runtime_log_rows = diagnostics_runtime_log_rows(snapshot);
    let diagnostics_system_proxy = diagnostics_system_proxy(snapshot);
    let diagnostics_tun = diagnostics_tun(snapshot);
    let diagnostics_default_core = diagnostics_default_core(snapshot);
    let readiness_system_proxy_detail = readiness_system_proxy_detail(snapshot);
    let readiness_tun_detail = readiness_tun_detail(snapshot);
    let activity_summary = format!("{diagnostics_runtime_events}；{diagnostics_recent_event}");
    let panel_account = panel_account_summary(snapshot);
    let panel_subscription = panel_subscription_summary(snapshot);
    let panel_nodes = panel_nodes_summary(snapshot);
    let panel_notice = panel_notice_summary(snapshot);
    let top_core_status = format!("核心状态：{run_state}");
    let top_dependency_status = if snapshot.dependencies.first_run.blockers.is_empty()
        && snapshot.dependencies.first_run.system_proxy_ready
        && snapshot.dependencies.first_run.tun_ready
    {
        "依赖已就绪"
    } else {
        "依赖需要处理"
    };
    let local_inbound_pressed =
        aria_pressed(snapshot.status.traffic_mode == DesktopTrafficMode::MixedInboundOnly);
    let system_proxy_pressed =
        aria_pressed(snapshot.status.traffic_mode == DesktopTrafficMode::SystemProxy);
    let tun_pressed = aria_pressed(snapshot.status.traffic_mode == DesktopTrafficMode::Tun);

    format!(
        r#"<!doctype html>
<html lang="zh-CN">
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
    html,
    body {{
      margin: 0;
      width: 100%;
      height: 100%;
      min-width: 360px;
      background: #f6f7f8;
      overflow: hidden;
    }}
    .desktop-layout {{
      height: 100vh;
      min-height: 0;
      display: grid;
      grid-template-columns: 220px minmax(0, 1fr);
      background: #f6f7f8;
      overflow: hidden;
    }}
    .nav-rail {{
      height: 100vh;
      min-height: 0;
      display: grid;
      grid-template-rows: auto 1fr auto;
      gap: 18px;
      padding: 24px 14px;
      border-right: 1px solid #d9dee5;
      background: #ffffff;
      overflow: hidden;
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
      height: 100vh;
      min-height: 0;
      padding: 0 18px 18px;
      display: grid;
      grid-template-rows: auto auto minmax(0, 1fr);
      gap: 12px;
      align-content: start;
      overflow: hidden;
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
      min-height: 26px;
      display: flex;
      align-items: center;
      border-top: 1px solid #d9dee5;
      padding-top: 8px;
      color: #4d5968;
      font-size: 13px;
      overflow-wrap: anywhere;
    }}
    .app-view {{
      min-height: 0;
      height: 100%;
      overflow: hidden;
    }}
    .dashboard-view {{
      display: grid;
      grid-template-rows: auto auto minmax(0, 1fr);
      gap: 12px;
    }}
    .app-view[hidden] {{
      display: none;
    }}
    .nodes-view {{
      display: grid;
      grid-template-rows: auto auto minmax(0, 1fr);
      gap: 12px;
    }}
    .nodes-toolbar {{
      display: grid;
      grid-template-columns: minmax(220px, 1fr) auto;
      gap: 10px;
      align-items: end;
    }}
    .nodes-summary-strip {{
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 10px;
    }}
    .nodes-summary-item {{
      min-height: 68px;
      padding: 10px;
      border: 1px solid #d9dee5;
      border-radius: 8px;
      background: #ffffff;
    }}
    .nodes-summary-value {{
      color: #171a1f;
      font-size: 24px;
      font-weight: 750;
    }}
    .nodes-summary-label {{
      margin-top: 4px;
      color: #657386;
      font-size: 12px;
      font-weight: 650;
    }}
    .nodes-content {{
      min-height: 0;
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(300px, 360px);
      gap: 12px;
      align-items: start;
    }}
    .panel-grid {{
      min-height: 0;
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(280px, 0.9fr);
      gap: 12px;
      overflow: hidden;
    }}
    .bounded-list {{
      min-height: 0;
      max-height: 320px;
      overflow: auto;
    }}
    .panel-kpi-row {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }}
    .panel-kpi {{
      min-width: 0;
      padding: 10px;
      border: 1px solid #d9dee5;
      border-radius: 8px;
      background: #ffffff;
      overflow: hidden;
    }}
    .node-filter-tabs {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-bottom: 10px;
    }}
    .node-filter-tabs button[aria-pressed="true"] {{
      border-color: #277d56;
      background: #e6f4ec;
      color: #145a32;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}
    th,
    td {{
      min-height: 38px;
      padding: 10px 8px;
      border-bottom: 1px solid #edf0f3;
      color: #4d5968;
      text-align: left;
      vertical-align: middle;
      overflow-wrap: anywhere;
    }}
    th {{
      color: #657386;
      font-size: 12px;
      font-weight: 700;
    }}
    tr[data-selected="true"] td {{
      background: #f2fbf5;
      color: #145a32;
    }}
    .selected-node-detail {{
      display: grid;
      gap: 12px;
    }}
    .detail-list {{
      display: grid;
      gap: 8px;
      color: #4d5968;
      font-size: 13px;
    }}
    .detail-list div {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      border-bottom: 1px solid #edf0f3;
      padding-bottom: 7px;
    }}
    .diagnostics-view {{
      display: grid;
      grid-template-rows: auto minmax(0, 1fr) auto;
      gap: 12px;
    }}
    .settings-view {{
      display: grid;
      grid-template-rows: auto auto minmax(0, 1fr);
      gap: 12px;
    }}
    .settings-grid {{
      min-height: 0;
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(320px, 0.78fr);
      gap: 12px;
      align-items: start;
    }}
    .settings-stack {{
      display: grid;
      gap: 8px;
    }}
    .settings-toggle-list {{
      display: grid;
      gap: 8px;
      color: #4d5968;
      font-size: 13px;
    }}
    .settings-toggle-list label {{
      min-height: 36px;
      display: flex;
      align-items: center;
      gap: 9px;
      border-bottom: 1px solid #edf0f3;
    }}
    .settings-toggle-list input {{
      width: auto;
      min-height: 0;
    }}
    .settings-mode-control {{
      margin: 10px 0 12px;
    }}
    .readiness-list {{
      display: grid;
      border-top: 1px solid #edf0f3;
    }}
    .readiness-row {{
      min-height: 40px;
      display: grid;
      grid-template-columns: minmax(160px, 1fr) minmax(100px, auto) minmax(220px, 2fr) auto;
      gap: 10px;
      align-items: center;
      border-bottom: 1px solid #edf0f3;
      color: #4d5968;
      font-size: 13px;
      overflow-wrap: anywhere;
    }}
    .readiness-row strong {{
      color: #171a1f;
      font-weight: 650;
    }}
    .status-warning {{
      color: #9a5b00;
      font-weight: 700;
    }}
    .diagnostics-grid {{
      min-height: 0;
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(320px, 0.85fr);
      gap: 12px;
      align-items: start;
    }}
    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 8px;
    }}
    .metric-tile {{
      min-height: 64px;
      padding: 8px;
      border: 1px solid #d9dee5;
      border-radius: 8px;
      background: #ffffff;
      overflow: hidden;
    }}
    .metric-value {{
      color: #171a1f;
      font-size: 12px;
      font-weight: 750;
      line-height: 1.25;
      overflow-wrap: anywhere;
    }}
    .metric-label {{
      margin-top: 3px;
      color: #657386;
      font-size: 12px;
      font-weight: 650;
    }}
    .settings-strip {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
    }}
    #settings-network-panel .settings-strip {{
      grid-template-columns: repeat(5, minmax(0, 1fr));
    }}
    .settings-subscription-status-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px 16px;
      margin-top: 8px;
    }}
    .settings-subscription-status-row .muted {{
      margin-top: 0;
    }}
    .settings-field label {{
      display: block;
      margin-bottom: 6px;
      color: #657386;
      font-size: 12px;
      font-weight: 650;
    }}
    .toggle-row {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      min-height: 34px;
      color: #4d5968;
      font-size: 13px;
      font-weight: 650;
    }}
    .toggle-row input {{
      width: auto;
      min-height: 0;
    }}
    .dashboard-row {{
      display: grid;
      grid-template-columns: minmax(0, 1.2fr) minmax(320px, 0.8fr);
      gap: 12px;
      min-height: 0;
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
      overflow-wrap: anywhere;
    }}
    .support-actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
    }}
    .operation-status {{
      min-height: 32px;
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
    .legacy-workflow-surface,
    #connection-activity-panel,
    #support-actions-panel,
    pre[hidden] {{
      display: none;
    }}
    section {{
      min-height: 0;
      padding: 12px;
      border: 1px solid #d9dee5;
      border-radius: 8px;
      background: #ffffff;
      overflow: hidden;
    }}
    .nodes-content > section:first-child,
    #diagnostics-runtime-log-panel,
    #readiness-checklist {{
      overflow: auto;
    }}
    section.wide {{
      grid-column: 1 / -1;
    }}
    h2 {{
      margin: 0 0 8px;
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
      margin-top: 10px;
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
      .dashboard-row,
      .diagnostics-grid,
      .settings-grid,
      .metrics-grid,
      .panel-grid,
      .panel-kpi-row,
      .settings-strip,
      .nodes-toolbar,
      .nodes-summary-strip,
      .nodes-content {{
        grid-template-columns: 1fr;
      }}
      .readiness-row {{
        grid-template-columns: 1fr;
        gap: 4px;
        padding: 10px 0;
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
    <aside class="nav-rail" id="app-navigation" aria-label="Keli 导航">
      <div class="nav-brand"><span class="nav-mark" aria-hidden="true">K</span><span>Keli</span></div>
      <nav class="nav-list">
        <button class="nav-item" data-view-target="dashboard-view" aria-current="page" onclick="postViewTarget('dashboard-view')">概览</button>
        <button class="nav-item" data-view-target="nodes-view" onclick="postViewTarget('nodes-view')">节点</button>
        <button class="nav-item" data-view-target="subscription-view" onclick="postViewTarget('subscription-view')">订阅</button>
        <button class="nav-item" data-view-target="store-view" onclick="postViewTarget('store-view')">商店</button>
        <button class="nav-item" data-view-target="support-view" onclick="postViewTarget('support-view')">支持</button>
        <button class="nav-item" data-view-target="diagnostics-view" onclick="postViewTarget('diagnostics-view')">诊断</button>
        <button class="nav-item" data-view-target="settings-view" onclick="postViewTarget('settings-view')">设置</button>
      </nav>
      <div class="nav-footer">
        <span>核心：原生 Rust</span>
        <span id="nav-run-state">{run_state}</span>
      </div>
    </aside>
    <main class="app-shell">
      <header class="top-status-bar" id="top-status-bar">
        <div class="top-status-group">
          <span class="pill" id="run-state">{run_state}</span>
          <span class="top-status-item" id="top-core-status"><span class="status-dot" aria-hidden="true"></span>{top_core_status}</span>
          <span class="top-status-item">模式：<strong id="top-traffic-mode">{traffic_mode}</strong></span>
          <span class="top-status-item">节点：<strong id="top-selected-node">{selected}</strong></span>
        </div>
        <div class="top-status-group">
          <span class="top-status-item" id="top-dependency-status"><span class="status-dot" aria-hidden="true"></span>{top_dependency_status}</span>
          <span class="top-status-item" id="top-activity-status">{activity_summary}</span>
        </div>
      </header>
    <div class="operation-status" id="operation-status" data-kind="info">就绪</div>
    <div class="app-view dashboard-view" id="dashboard-view" data-app-view>
    <section class="command-panel" id="core-command-panel">
      <div>
        <h2>核心</h2>
        <div class="command-title"><span id="quick-run-state">{run_state}</span> · <span id="quick-traffic-mode">{traffic_mode}</span></div>
        <div class="muted" id="quick-primary-state">{primary_state}</div>
      </div>
      <div class="actions command-actions">
        <button id="quick-primary-button" class="primary" onclick="window.ipc.postMessage('primary')"{primary_disabled}>{primary_label}</button>
        <button id="quick-refresh-button" onclick="window.ipc.postMessage('refresh')">刷新</button>
      </div>
      <div class="quick-status" aria-label="核心状态">
        <div class="quick-status-item">
          <div class="quick-label">节点</div>
          <div class="quick-value" id="quick-selected-node">{selected}</div>
        </div>
        <div class="quick-status-item">
          <div class="quick-label">监听</div>
          <div class="quick-value" id="quick-listen-address">{listen}</div>
        </div>
        <div class="quick-status-item">
          <div class="quick-label">依赖</div>
          <div class="quick-value" id="quick-dependency-summary">{dependency_summary}</div>
        </div>
        <div class="quick-status-item">
          <div class="quick-label">订阅</div>
          <div class="quick-value" id="quick-subscription-summary">{subscription_summary}</div>
        </div>
      </div>
      <div class="segmented-control" id="mode-segmented-control" role="group" aria-label="流量模式">
        <button data-traffic-mode-button="mixed-inbound-only" aria-pressed="{local_inbound_pressed}" onclick="postTrafficMode('mixed-inbound-only')">本地入站</button>
        <button data-traffic-mode-button="system-proxy" aria-pressed="{system_proxy_pressed}" onclick="postTrafficMode('system-proxy')">系统代理</button>
        <button data-traffic-mode-button="tun" aria-pressed="{tun_pressed}" onclick="postTrafficMode('tun')">TUN</button>
      </div>
      <div class="activity-strip" id="activity-summary">{activity_summary}</div>
    </section>
    <section id="dashboard-panel-account">
      <h2>账号</h2>
      <div class="panel-kpi-row">
        <div class="panel-kpi"><div class="metric-label">账号</div><strong>{panel_account}</strong></div>
        <div class="panel-kpi"><div class="metric-label">订阅</div><strong>{panel_subscription}</strong></div>
        <div class="panel-kpi"><div class="metric-label">公告</div><strong>{panel_notice}</strong></div>
      </div>
    </section>
    <section id="connection-activity-panel">
      <div class="activity-header">
        <h2>连接活动</h2>
        <div class="activity-metrics" id="activity-metrics">{diagnostics_connection_metrics}</div>
      </div>
      <div class="activity-rail" aria-label="连接活动摘要">
        <div class="activity-line"><span>最近运行代次</span><strong>{generation}</strong></div>
        <div class="activity-line"><span>运行事件</span><strong>{events}</strong></div>
        <div class="activity-line"><span>当前流量模式</span><strong>{traffic_mode}</strong></div>
      </div>
    </section>
    <div class="dashboard-row">
      <section id="dashboard-events-panel">
        <h2>最近事件</h2>
        <div class="event-list" id="dashboard-runtime-event-list">{runtime_event_items}</div>
      </section>
      <section id="dashboard-dependencies-panel">
        <h2>依赖状态</h2>
        <div class="value" id="dashboard-dependency-summary">{dependency_summary}</div>
        <div class="status-list">
          <div class="status-row"><strong>系统代理</strong><span class="status-ok" id="dashboard-system-proxy-status">{dashboard_system_proxy_status}</span></div>
          <div class="status-row"><strong>TUN / Wintun</strong><span class="status-ok" id="dashboard-tun-status">{dashboard_tun_status}</span></div>
          <div class="status-row"><strong>阻塞项</strong><span id="dashboard-blockers">{dashboard_dependency_blockers}</span></div>
        </div>
        <div class="actions" id="dashboard-dependency-actions">{dependency_actions}</div>
      </section>
    </div>
    <section id="support-actions-panel" hidden>
      <h2>支持包</h2>
      <div class="value">诊断导出</div>
      <div class="muted">导出脱敏后的运行状态、依赖检查和核心支持证据。</div>
      <div class="support-actions">
        <button id="dashboard-export-support-button" class="primary" onclick="window.ipc.postMessage('export-support-bundle')">导出诊断</button>
        <button onclick="window.ipc.postMessage('refresh')">刷新状态</button>
      </div>
    </section>
    <div class="grid legacy-workflow-surface" hidden>
      <section>
        <h2>模式</h2>
        <div class="value" id="traffic-mode">{traffic_mode}</div>
        <div class="muted" id="listen-address">{listen}</div>
      </section>
      <section>
        <h2>节点</h2>
        <div class="value" id="selected-outbound">{selected}</div>
        <div class="muted" id="runtime-meta">代次 {generation}，事件 {events}</div>
      </section>
      <section>
        <h2>主操作</h2>
        <div class="value" id="primary-label">{primary_label}</div>
        <div class="muted" id="primary-state">{primary_state}</div>
        <div class="actions">
          <button id="primary-button" class="primary" onclick="window.ipc.postMessage('primary')"{primary_disabled}>{primary_label}</button>
          <button id="refresh-button" onclick="window.ipc.postMessage('refresh')">刷新</button>
        </div>
      </section>
      <section>
        <h2>托盘</h2>
        <div class="value" id="tray-ids">{tray_ids}</div>
        <div class="muted" id="window-visible">窗口可见：{window_visible}</div>
      </section>
      <section class="wide">
        <h2>依赖</h2>
        <div class="value" id="dependency-summary">{dependency_summary}</div>
        <div class="muted" id="system-proxy-dependency">{system_proxy_dependency}</div>
        <div class="muted" id="tun-dependency">{tun_dependency}</div>
        <div class="muted" id="dependency-blockers">{dependency_blockers}</div>
        <div class="actions" id="dependency-actions">{dependency_actions}</div>
        <input id="wintun-source-path" type="text" placeholder="C:\Downloads\wintun or C:\Downloads\wintun.dll" />
        <div class="actions">
          <button id="install-wintun-path-button" onclick="postInstallWintunPath()">从路径安装 Wintun</button>
        </div>
        <div class="muted" id="wintun-install-status">尚未尝试本地 Wintun 安装</div>
      </section>
      <section class="wide">
        <h2>订阅</h2>
        <input id="subscription-url" type="url" placeholder="https://example.com/subscription" />
        <div class="actions">
          <button id="import-subscription-url-button" class="primary" onclick="postImportSubscriptionUrl()"{import_subscription_url_disabled}>导入 URL</button>
          <button id="update-subscription-url-button" onclick="postUpdateSubscriptionUrl()"{update_subscription_url_disabled}>更新 URL</button>
          <button id="refresh-node-health-button" onclick="postRefreshNodeHealth()">刷新健康</button>
        </div>
        <div class="muted" id="subscription-url-status">尚未导入订阅 URL</div>
        <textarea id="subscription-config" spellcheck="false"></textarea>
        <div class="muted" id="subscription-config-status">尚未导入本地订阅配置</div>
        <div class="actions">
          <button id="import-subscription-button" class="primary" onclick="postImportSubscription()">导入</button>
          <button onclick="postTrafficMode('mixed-inbound-only')">本地入站</button>
          <button onclick="postTrafficMode('system-proxy')">系统代理</button>
          <button onclick="postTrafficMode('tun')">TUN</button>
        </div>
        <div class="muted" id="subscription-summary">{subscription_summary}</div>
        <div class="node-list" id="node-list">{node_buttons}</div>
      </section>
      <section class="wide">
        <h2>诊断</h2>
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
        <div class="value">支持包</div>
        <div class="muted" id="support-export-status">尚未导出支持包</div>
        <div class="actions">
          <button id="export-support-button" onclick="window.ipc.postMessage('export-support-bundle')">导出支持包</button>
        </div>
      </section>
    </div>
    </div>
    <section class="app-view nodes-view" id="nodes-view" data-app-view hidden>
      <section>
        <h2>订阅 URL</h2>
        <div class="nodes-toolbar">
          <input id="nodes-subscription-url" type="url" placeholder="https://example.com/subscription" />
          <div class="actions">
            <button id="nodes-import-url-button" class="primary" onclick="postImportNodesSubscriptionUrl()"{import_subscription_url_disabled}>导入 URL</button>
            <button id="nodes-update-url-button" onclick="postUpdateNodesSubscriptionUrl()"{update_subscription_url_disabled}>更新 URL</button>
            <button id="nodes-refresh-health-button" onclick="postRefreshNodeHealth()">刷新健康</button>
          </div>
        </div>
        <div class="muted" id="nodes-subscription-url-status">尚未导入订阅 URL</div>
      </section>
      <div class="nodes-summary-strip" id="nodes-summary-strip">
        <div class="nodes-summary-item">
          <div class="nodes-summary-value" id="nodes-supported-count">{nodes_supported_count}</div>
          <div class="nodes-summary-label">支持节点</div>
        </div>
        <div class="nodes-summary-item">
          <div class="nodes-summary-value" id="nodes-skipped-count">{nodes_skipped_count}</div>
          <div class="nodes-summary-label">跳过节点</div>
        </div>
        <div class="nodes-summary-item">
          <div class="nodes-summary-value" id="nodes-healthy-count">{nodes_healthy_count}</div>
          <div class="nodes-summary-label">健康</div>
        </div>
        <div class="nodes-summary-item">
          <div class="nodes-summary-value" id="nodes-udp-ready-count">{nodes_udp_ready_count}</div>
          <div class="nodes-summary-label">UDP 就绪</div>
        </div>
        <div class="nodes-summary-item">
          <div class="nodes-summary-value" id="nodes-recommended">{nodes_recommended}</div>
          <div class="nodes-summary-label">推荐</div>
        </div>
      </div>
      <div class="nodes-content">
        <section>
          <div class="node-filter-tabs" id="node-filter-tabs" role="group" aria-label="节点筛选">
            <button data-node-filter="all" aria-pressed="true" onclick="postNodeFilter('all')">全部</button>
            <button data-node-filter="healthy" aria-pressed="false" onclick="postNodeFilter('healthy')">健康</button>
            <button data-node-filter="failed" aria-pressed="false" onclick="postNodeFilter('failed')">失败</button>
            <button data-node-filter="udp-ready" aria-pressed="false" onclick="postNodeFilter('udp-ready')">UDP 就绪</button>
            <button data-node-filter="skipped" aria-pressed="false" onclick="postNodeFilter('skipped')">已跳过</button>
          </div>
          <table aria-label="节点">
            <thead>
              <tr>
                <th>名称</th>
                <th>协议</th>
                <th>传输</th>
                <th>延迟</th>
                <th>TCP</th>
                <th>UDP</th>
                <th>健康</th>
              </tr>
            </thead>
            <tbody id="nodes-table-body">{nodes_table_rows}</tbody>
          </table>
        </section>
        <section class="selected-node-detail" id="selected-node-detail">
          <h2>当前节点</h2>
          <div class="value" id="selected-node-title">{selected_node_title}</div>
          <div class="detail-list" id="selected-node-detail-list">{selected_node_detail}</div>
          <div class="actions">
            <button class="primary" onclick="postSelectNode(document.getElementById('selected-node-title').textContent)">选择</button>
            <button onclick="postRefreshNodeHealth()">测试</button>
          </div>
        </section>
      </div>
    </section>
    <div class="app-view subscription-view" id="subscription-view" data-app-view hidden>
      <div class="panel-grid">
        <section>
          <h2>订阅</h2>
          <div class="value">{panel_subscription}</div>
          <div class="muted">账号模式优先；订阅 URL 导入保留为兼容入口。</div>
        </section>
        <section>
          <h2>面板节点</h2>
          <div class="bounded-list">{panel_nodes}</div>
        </section>
      </div>
    </div>
    <div class="app-view store-view" id="store-view" data-app-view hidden>
      <section>
        <h2>商店</h2>
        <div class="value">套餐、订单、支付接口已进入客户端契约。</div>
        <div class="muted">下一步接入套餐和订单快照。</div>
      </section>
    </div>
    <div class="app-view support-view" id="support-view" data-app-view hidden>
      <section>
        <h2>支持</h2>
        <div class="value">{panel_notice}</div>
        <div class="muted">公告先接入；知识库和工单动作单独规划。</div>
      </section>
    </div>
    <div class="app-view diagnostics-view" id="diagnostics-view" data-app-view hidden>
      <section id="readiness-checklist">
        <h2>就绪检查</h2>
        <div class="readiness-list">
          <div class="readiness-row" id="readiness-system-proxy">
            <strong>系统代理</strong>
            <span class="status-ok" id="readiness-system-proxy-state">已跟踪</span>
            <span id="readiness-system-proxy-detail">{readiness_system_proxy_detail}</span>
            <button onclick="postDependencyAction('refresh-system-proxy')">检查</button>
          </div>
          <div class="readiness-row" id="readiness-tun-wintun">
            <strong>TUN / Wintun</strong>
            <span class="status-ok" id="readiness-tun-wintun-state">已跟踪</span>
            <span id="readiness-tun-wintun-detail">{readiness_tun_detail}</span>
            <button onclick="postDependencyAction('install-wintun')">安装</button>
          </div>
          <div class="readiness-row" id="readiness-dns-policy">
            <strong>DNS 策略</strong>
            <span class="status-ok">就绪</span>
            <span id="readiness-dns-policy-detail">已有运行时 DNS 策略冒烟证据</span>
            <button onclick="window.ipc.postMessage('refresh')">刷新</button>
          </div>
          <div class="readiness-row" id="readiness-route-takeover">
            <strong>路由接管</strong>
            <span class="status-ok">就绪</span>
            <span id="readiness-route-takeover-detail">当前模式：{traffic_mode}</span>
            <button onclick="postTrafficMode('tun')">TUN</button>
          </div>
          <div class="readiness-row" id="readiness-subscription-updater">
            <strong>订阅更新</strong>
            <span class="status-ok">就绪</span>
            <span id="readiness-subscription-updater-detail">{subscription_summary}</span>
            <button onclick="postRefreshNodeHealth()">健康</button>
          </div>
          <div class="readiness-row" id="readiness-signing-status">
            <strong>签名状态</strong>
            <span class="status-warning">未签名测试版</span>
            <span id="readiness-signing-status-detail">证书采购完成前，发布链可先发布未签名构建</span>
            <button onclick="window.ipc.postMessage('refresh')">检查</button>
          </div>
        </div>
      </section>
      <div class="diagnostics-grid">
        <section id="diagnostics-runtime-log-panel">
          <h2>运行事件</h2>
          <table aria-label="诊断运行日志">
            <thead>
              <tr>
                <th>#</th>
                <th>状态</th>
                <th>说明</th>
              </tr>
            </thead>
            <tbody id="diagnostics-runtime-log-body">{diagnostics_runtime_log_rows}</tbody>
          </table>
        </section>
        <section id="diagnostics-metrics-panel">
          <h2>指标</h2>
          <div class="metrics-grid">
            <div class="metric-tile">
              <div class="metric-value" id="diagnostics-metric-connections">{diagnostics_connection_metrics}</div>
              <div class="metric-label">连接</div>
            </div>
            <div class="metric-tile">
              <div class="metric-value" id="diagnostics-metric-node-health">{diagnostics_node_health}</div>
              <div class="metric-label">节点健康</div>
            </div>
            <div class="metric-tile">
              <div class="metric-value" id="diagnostics-metric-last-error">{diagnostics_last_error}</div>
              <div class="metric-label">最后错误</div>
            </div>
            <div class="metric-tile">
              <div class="metric-value" id="diagnostics-metric-activity">{activity_summary}</div>
              <div class="metric-label">活动</div>
            </div>
          </div>
        </section>
      </div>
      <div class="diagnostics-grid">
        <section id="diagnostics-support-panel">
          <h2>支持包</h2>
          <div class="value">诊断导出</div>
          <div class="muted" id="diagnostics-support-status">尚未导出支持包</div>
          <div class="support-actions">
            <button id="diagnostics-export-button" class="primary" onclick="window.ipc.postMessage('export-support-bundle')">导出诊断</button>
            <button id="diagnostics-copy-logs-button" onclick="postCopyDiagnosticsLogs()">复制日志</button>
            <label class="toggle-row"><input id="include-certification-toggle" type="checkbox" checked /> 包含认证证据</label>
          </div>
        </section>
        <section id="diagnostics-settings-panel">
          <h2>设置</h2>
          <div class="settings-strip">
            <div class="settings-field">
              <label for="diagnostics-mixed-port">混合端口</label>
              <input id="diagnostics-mixed-port" type="number" inputmode="numeric" value="7890" />
            </div>
            <div class="settings-field">
              <label for="diagnostics-socks-port">SOCKS port</label>
              <input id="diagnostics-socks-port" type="number" inputmode="numeric" value="7891" />
            </div>
            <div class="settings-field">
              <label for="diagnostics-http-port">HTTP port</label>
              <input id="diagnostics-http-port" type="number" inputmode="numeric" value="7892" />
            </div>
            <div class="settings-field">
              <label for="diagnostics-max-workers">工作线程</label>
              <input id="diagnostics-max-workers" type="number" inputmode="numeric" value="4" />
            </div>
          </div>
        </section>
      </div>
    </div>
    <div class="app-view settings-view" id="settings-view" data-app-view hidden>
      <div class="settings-grid">
        <section id="settings-runtime-panel">
          <h2>运行时</h2>
          <div class="settings-stack">
            <div class="value" id="settings-run-state">{run_state}</div>
            <div class="muted">模式：<strong id="settings-traffic-mode">{traffic_mode}</strong></div>
            <div class="muted">节点：<strong id="settings-selected-node">{selected}</strong></div>
            <div class="muted">监听：<strong id="settings-listen-address">{listen}</strong></div>
            <div class="muted">依赖：<strong id="settings-dependency-summary">{dependency_summary}</strong></div>
            <div class="muted" id="settings-primary-state">{primary_state}</div>
          </div>
          <div class="actions">
            <button id="settings-primary-button" class="primary" onclick="window.ipc.postMessage('primary')"{primary_disabled}>{primary_label}</button>
            <button id="settings-refresh-button" onclick="window.ipc.postMessage('refresh')">刷新</button>
            <button id="settings-load-panel-fixture-button" onclick="window.ipc.postMessage('load-panel-fixture')">加载面板示例</button>
          </div>
        </section>
        <section id="settings-startup-panel">
          <h2>启动</h2>
          <div class="settings-toggle-list">
            <label><input id="settings-start-with-windows" type="checkbox" /> 开机启动</label>
            <label><input id="settings-launch-minimized" type="checkbox" checked /> 启动后最小化</label>
            <label><input id="settings-auto-start-core" type="checkbox" /> 启动客户端后自动启动核心</label>
          </div>
        </section>
      </div>
      <section id="settings-network-panel">
        <h2>网络</h2>
        <div class="segmented-control settings-mode-control" id="settings-traffic-mode-control" role="group" aria-label="默认流量模式">
          <button data-settings-traffic-mode="mixed-inbound-only" data-traffic-mode-button="mixed-inbound-only" aria-pressed="{local_inbound_pressed}" onclick="postTrafficMode('mixed-inbound-only')">本地入站</button>
          <button data-settings-traffic-mode="system-proxy" data-traffic-mode-button="system-proxy" aria-pressed="{system_proxy_pressed}" onclick="postTrafficMode('system-proxy')">系统代理</button>
          <button data-settings-traffic-mode="tun" data-traffic-mode-button="tun" aria-pressed="{tun_pressed}" onclick="postTrafficMode('tun')">TUN</button>
        </div>
        <div class="settings-strip">
          <div class="settings-field">
            <label for="settings-mixed-port">混合端口</label>
            <input id="settings-mixed-port" type="number" inputmode="numeric" value="7890" />
          </div>
          <div class="settings-field">
            <label for="settings-socks-port">SOCKS port</label>
            <input id="settings-socks-port" type="number" inputmode="numeric" value="7891" />
          </div>
          <div class="settings-field">
            <label for="settings-http-port">HTTP port</label>
            <input id="settings-http-port" type="number" inputmode="numeric" value="7892" />
          </div>
          <div class="settings-field">
            <label for="settings-dns-mode">DNS 模式</label>
            <input id="settings-dns-mode" value="fake-ip" />
          </div>
          <div class="settings-field">
            <label for="settings-tun-stack">TUN 栈</label>
            <input id="settings-tun-stack" value="system" />
          </div>
        </div>
      </section>
      <section id="settings-subscription-panel">
        <h2>订阅</h2>
        <div class="nodes-toolbar">
          <input id="settings-subscription-url" type="url" placeholder="https://example.com/subscription" />
          <div class="actions">
            <button id="settings-import-url-button" class="primary" onclick="postImportSettingsSubscriptionUrl()"{import_subscription_url_disabled}>导入 URL</button>
            <button id="settings-update-url-button" onclick="postUpdateSettingsSubscriptionUrl()"{update_subscription_url_disabled}>更新 URL</button>
            <button id="settings-refresh-health-button" onclick="postRefreshNodeHealth()">刷新健康</button>
          </div>
        </div>
        <div class="settings-subscription-status-row">
          <span class="muted" id="settings-subscription-url-status">尚未导入订阅 URL</span>
          <span class="muted" id="settings-subscription-summary">{subscription_summary}</span>
        </div>
      </section>
    </div>
    <pre id="snapshot-json" hidden>{snapshot_json}</pre>
  </main>
  </div>
  <script>
    const runStateLabels = {{
      "stopped": "已停止",
      "starting": "启动中",
      "running": "运行中",
      "reloading": "更新中",
      "stopping": "停止中",
      "failed": "失败"
    }};
    const trafficModeLabels = {{
      "system-proxy": "系统代理",
      "tun": "TUN",
      "mixed-inbound-only": "本地入站"
    }};
    function postJson(payload) {{
      window.ipc.postMessage(JSON.stringify(payload));
    }}
    function postViewTarget(viewId) {{
      document.querySelectorAll("[data-view-target]").forEach((button) => {{
        button.setAttribute("aria-current", button.dataset.viewTarget === viewId ? "page" : "false");
      }});
      document.querySelectorAll("[data-app-view]").forEach((view) => {{
        view.hidden = view.id !== viewId;
      }});
      const shell = document.querySelector(".app-shell");
      if (shell && shell.scrollTo) {{
        shell.scrollTo(0, 0);
      }}
      window.keliSetOperationStatus({{ kind: "info", message: "就绪" }});
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
    function postImportNodesSubscriptionUrl() {{
      postJson({{
        type: "import-subscription-url",
        subscriptionUrl: document.getElementById("nodes-subscription-url").value
      }});
    }}
    function postUpdateNodesSubscriptionUrl() {{
      postJson({{
        type: "update-subscription-url",
        subscriptionUrl: document.getElementById("nodes-subscription-url").value
      }});
    }}
    function postImportSettingsSubscriptionUrl() {{
      postJson({{
        type: "import-subscription-url",
        subscriptionUrl: document.getElementById("settings-subscription-url").value
      }});
    }}
    function postUpdateSettingsSubscriptionUrl() {{
      postJson({{
        type: "update-subscription-url",
        subscriptionUrl: document.getElementById("settings-subscription-url").value
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
    function postCopyDiagnosticsLogs() {{
      const snapshot = document.getElementById("snapshot-json");
      const text = snapshot ? snapshot.textContent : "";
      if (navigator.clipboard && navigator.clipboard.writeText) {{
        navigator.clipboard.writeText(text).then(
          () => window.keliSetOperationStatus({{ kind: "success", message: "已复制诊断快照" }}),
          () => window.keliSetOperationStatus({{ kind: "error", message: "无法复制诊断快照" }})
        );
        return;
      }}
      window.keliSetOperationStatus({{ kind: "info", message: "诊断快照可在下方查看" }});
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
    function postNodeFilter(filter) {{
      document.querySelectorAll("[data-node-filter]").forEach((button) => {{
        button.setAttribute("aria-pressed", button.dataset.nodeFilter === filter ? "true" : "false");
      }});
    }}
    const dependencyActionLabels = {{
      "check-system-proxy": "打开代理设置",
      "install-wintun": "打开 Wintun 下载",
      "check-tun": "打开 TUN 帮助"
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
      if (!subscription) return "没有导入订阅";
      return `支持 ${{subscription.supported_count}}，跳过 ${{subscription.skipped_count}}`;
    }}
    function renderNodeList(subscription) {{
      const nodeList = document.getElementById("node-list");
      nodeList.replaceChildren();
      if (!subscription || (!subscription.nodes.length && !(subscription.skipped || []).length)) {{
        const empty = document.createElement("span");
        empty.className = "muted";
        empty.textContent = "没有节点";
        nodeList.appendChild(empty);
        return;
      }}
      if (!subscription.nodes.length) {{
        const empty = document.createElement("span");
        empty.className = "muted";
        empty.textContent = "没有节点";
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
        meta.textContent = `${{node.protocol || "未知"}} / ${{node.transport || "未知"}} / ${{node.security || "未知"}}`;
        udp.className = "node-meta";
        udp.textContent = node.udp_supported ? "UDP 就绪" : "UDP 不可用";
        health.className = "node-meta";
        health.textContent = nodeHealthDetail(node);
        badges.className = "node-badges";
        if (node.selected) {{
          const badge = document.createElement("span");
          badge.className = "node-badge";
          badge.textContent = "已选择";
          badges.appendChild(badge);
        }}
        if (node.recommended) {{
          const badge = document.createElement("span");
          badge.className = "node-badge";
          badge.textContent = "推荐";
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
        badge.textContent = "已跳过";
        detail.textContent = skipped;
        item.append(badge, detail);
        nodeList.appendChild(item);
      }}
    }}
    function nodeHealthDetail(node) {{
      const parts = [];
      if (node.health_state) parts.push(`健康状态 ${{node.health_state}}`);
      if (node.tcp_available === true) parts.push("TCP 就绪");
      if (node.tcp_available === false) parts.push("TCP 失败");
      if (node.udp_available === true) parts.push("UDP 在线");
      if (node.udp_available === false) parts.push("UDP 失败");
      if (node.latency_ms !== null && node.latency_ms !== undefined) parts.push(`${{node.latency_ms}} ms`);
      if (node.health_error) parts.push(`最近失败 ${{node.health_error}}`);
      return parts.length ? parts.join("，") : "健康未知";
    }}
    function nodesHealthyCount(subscription) {{
      if (!subscription) return 0;
      return subscription.nodes.filter((node) => node.health_state === "healthy" || node.tcp_available === true).length;
    }}
    function nodesUdpReadyCount(subscription) {{
      if (!subscription) return 0;
      return subscription.nodes.filter((node) => node.udp_supported || node.udp_available === true).length;
    }}
    function nodesRecommended(subscription) {{
      return subscription && subscription.recommended_outbound ? subscription.recommended_outbound : "无";
    }}
    function selectedNode(subscription) {{
      if (!subscription || !subscription.nodes.length) return null;
      return subscription.nodes.find((node) => node.selected)
        || subscription.nodes.find((node) => node.tag === subscription.selected_outbound)
        || subscription.nodes[0];
    }}
    function renderNodesTable(subscription) {{
      const body = document.getElementById("nodes-table-body");
      if (!body) return;
      body.replaceChildren();
      if (!subscription || !subscription.nodes.length) {{
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 7;
        cell.textContent = "没有节点";
        row.appendChild(cell);
        body.appendChild(row);
        return;
      }}
      for (const node of subscription.nodes) {{
        const row = document.createElement("tr");
        row.dataset.selected = node.selected ? "true" : "false";
        row.onclick = () => postSelectNode(node.tag);
        const values = [
          node.tag,
          node.protocol || "未知",
          node.transport || "未知",
          node.latency_ms === null || node.latency_ms === undefined ? "-" : `${{node.latency_ms}} ms`,
          node.tcp_available === false ? "失败" : "就绪",
          node.udp_supported || node.udp_available === true ? "就绪" : "不可用",
          nodeHealthDetail(node)
        ];
        for (const value of values) {{
          const cell = document.createElement("td");
          cell.textContent = value;
          row.appendChild(cell);
        }}
        body.appendChild(row);
      }}
    }}
    function renderSelectedNodeDetail(subscription) {{
      const node = selectedNode(subscription);
      setText("selected-node-title", node ? node.tag : "未选择节点");
      const detail = document.getElementById("selected-node-detail-list");
      if (!detail) return;
      detail.replaceChildren();
      const pairs = node ? [
        ["协议", node.protocol || "未知"],
        ["传输", node.transport || "未知"],
        ["安全", node.security || "未知"],
        ["延迟", node.latency_ms === null || node.latency_ms === undefined ? "-" : `${{node.latency_ms}} ms`],
        ["TCP", node.tcp_available === false ? "失败" : "就绪"],
        ["UDP", node.udp_supported || node.udp_available === true ? "就绪" : "不可用"],
        ["健康", nodeHealthDetail(node)]
      ] : [["状态", "导入订阅后才能选择节点"]];
      for (const [label, value] of pairs) {{
        const row = document.createElement("div");
        const labelElement = document.createElement("span");
        const valueElement = document.createElement("strong");
        labelElement.textContent = label;
        valueElement.textContent = value;
        row.append(labelElement, valueElement);
        detail.appendChild(row);
      }}
    }}
    window.keliSyncNodes = (snapshot) => {{
      const subscription = snapshot.subscription;
      setText("nodes-supported-count", subscription ? subscription.supported_count : 0);
      setText("nodes-skipped-count", subscription ? subscription.skipped_count : 0);
      setText("nodes-healthy-count", nodesHealthyCount(subscription));
      setText("nodes-udp-ready-count", nodesUdpReadyCount(subscription));
      setText("nodes-recommended", nodesRecommended(subscription));
      const importUrlButton = document.getElementById("nodes-import-url-button");
      const updateUrlButton = document.getElementById("nodes-update-url-button");
      if (importUrlButton) importUrlButton.disabled = snapshot.status.run_state === "running";
      if (updateUrlButton) updateUrlButton.disabled = snapshot.status.run_state !== "running";
      renderNodesTable(subscription);
      renderSelectedNodeDetail(subscription);
    }};
    window.keliSetOperationStatus = (summary) => {{
      const status = document.getElementById("operation-status");
      const kind = summary.kind || "info";
      status.dataset.kind = kind;
      status.textContent = summary.message || "就绪";
    }};
    window.keliSetSupportExport = (summary) => {{
      const label = summary.status === "saved"
        ? `已保存 ${{summary.byte_count}} 字节到 ${{summary.path}}`
        : `${{summary.status}}: ${{summary.path || ""}}`;
      const kind = summary.status === "saved" ? "success" : "error";
      document.getElementById("support-export-status").textContent = label;
      setText("diagnostics-support-status", label);
      window.keliSetOperationStatus({{ kind: kind, message: label }});
    }};
    window.keliSetWintunInstall = (summary) => {{
      const label = summary.error
        ? `${{summary.status}}: ${{summary.error}}`
        : `${{summary.status}}: ${{summary.target_path || ""}} (${{summary.copied_bytes || 0}} 字节)`;
      const kind = summary.error ? "error" : "success";
      document.getElementById("wintun-install-status").textContent = label;
      window.keliSetOperationStatus({{ kind: kind, message: label }});
    }};
    function subscriptionSource(fetch) {{
      const source = fetch.host
        ? `${{fetch.scheme || "url"}}://${{fetch.host}}`
        : "订阅 URL";
      return source;
    }}
    window.keliSetSubscriptionUrlImport = (summary) => {{
      const fetch = summary.fetch || {{}};
      const source = subscriptionSource(fetch);
      const label = summary.error
        ? `从 ${{source}} 导入失败：${{summary.error}}`
        : `已从 ${{source}} 导入 ${{summary.subscription ? summary.subscription.supported_count : 0}} 个节点`;
      const kind = summary.error ? "error" : "success";
      document.getElementById("subscription-url-status").textContent = label;
      setText("nodes-subscription-url-status", label);
      setText("settings-subscription-url-status", label);
      window.keliSetOperationStatus({{ kind: kind, message: label }});
    }};
    window.keliSetSubscriptionUrlUpdate = (summary) => {{
      const fetch = summary.fetch || {{}};
      const source = subscriptionSource(fetch);
      const update = summary.update || {{}};
      const reason = update.reason ? `, ${{update.reason}}` : "";
      const selected = summary.runtime_status && summary.runtime_status.selected_outbound
        ? `，当前节点 ${{summary.runtime_status.selected_outbound}}`
        : "";
      const label = summary.error
        ? `从 ${{source}} 更新失败：${{summary.error}}`
        : summary.applied
          ? `已从 ${{source}} 更新${{reason}}${{selected}}`
          : `未应用来自 ${{source}} 的更新：${{fetch.error_kind || "未知"}}`;
      const kind = summary.error || !summary.applied ? "error" : "success";
      document.getElementById("subscription-url-status").textContent = label;
      setText("nodes-subscription-url-status", label);
      setText("settings-subscription-url-status", label);
      window.keliSetOperationStatus({{ kind: kind, message: label }});
    }};
    window.keliSetSubscriptionConfigImport = (summary) => {{
      const label = summary.error
        ? `导入失败：${{summary.error}}`
        : `已导入 ${{summary.supported_count || 0}} 个节点，跳过 ${{summary.skipped_count || 0}} 个`;
      const kind = summary.error ? "error" : "success";
      document.getElementById("subscription-config-status").textContent = label;
      window.keliSetOperationStatus({{ kind: kind, message: label }});
    }};
    function dependencySummary(snapshot) {{
      const firstRun = snapshot.dependencies.first_run;
      const system = firstRun.system_proxy_ready ? "系统代理就绪" : "系统代理受阻";
      const tun = firstRun.tun_ready ? "TUN 就绪" : "TUN 受阻";
      return `${{system}}，${{tun}}`;
    }}
    function systemProxyDependency(snapshot) {{
      const proxy = snapshot.dependencies.system_proxy;
      const parts = [`系统代理状态：${{proxy.state}}`];
      if (proxy.enabled !== null && proxy.enabled !== undefined) parts.push(`已启用=${{proxy.enabled}}`);
      if (proxy.server) parts.push(`服务器=${{proxy.server}}`);
      if (proxy.error) parts.push(proxy.error);
      if (proxy.action) parts.push(`操作=${{proxy.action}}`);
      return parts.join("，");
    }}
    function tunDependency(snapshot) {{
      const tun = snapshot.dependencies.tun_backend;
      const parts = [
        `Wintun 状态：${{tun.state}}`,
        `驱动存在=${{tun.driver_library_present}}`,
        `API可用=${{tun.driver_api_available}}`
      ];
      if (tun.driver_library_path) parts.push(`路径=${{tun.driver_library_path}}`);
      if (tun.reason) parts.push(tun.reason);
      if (tun.action) parts.push(`操作=${{tun.action}}`);
      return parts.join("，");
    }}
    function dependencyBlockers(snapshot) {{
      const blockers = snapshot.dependencies.first_run.blockers || [];
      if (!blockers.length) return "没有依赖阻塞项";
      return blockers.map((blocker) => {{
        const action = blocker.action ? ` 操作=${{blocker.action}}` : "";
        return `${{blocker.code}}: ${{blocker.message}}${{action}}`;
      }}).join("; ");
    }}
    function dashboardSystemProxyStatus(snapshot) {{
      return snapshot.dependencies.first_run.system_proxy_ready ? "就绪" : "需要处理";
    }}
    function dashboardTunStatus(snapshot) {{
      return snapshot.dependencies.first_run.tun_ready ? "就绪" : "需要处理";
    }}
    function dashboardDependencyBlockers(snapshot) {{
      const blockers = snapshot.dependencies.first_run.blockers || [];
      if (!blockers.length) return "无阻塞项";
      return `${{blockers.length}} 个阻塞项`;
    }}
    function readinessSystemProxyDetail(snapshot) {{
      const proxy = snapshot.dependencies.system_proxy;
      if (snapshot.dependencies.first_run.system_proxy_ready) {{
        return proxy.enabled === true ? "系统代理已启用" : "系统代理可用";
      }}
      return proxy.error || "系统代理需要处理";
    }}
    function readinessTunDetail(snapshot) {{
      const tun = snapshot.dependencies.tun_backend;
      if (snapshot.dependencies.first_run.tun_ready) {{
        return "Wintun 驱动和包 I/O 已就绪";
      }}
      return tun.reason || "Wintun 需要处理";
    }}
    function diagnosticsCoreStatus(snapshot) {{
      const status = snapshot.status;
      const run = runStateLabels[status.run_state] || status.run_state;
      const mode = trafficModeLabels[status.traffic_mode] || status.traffic_mode;
      return `核心${{run}} · ${{mode}}`;
    }}
    function diagnosticsRuntimeEvents(snapshot) {{
      const status = snapshot.status;
      return `运行代次 ${{status.generation}}，事件 ${{status.event_count}}`;
    }}
    function diagnosticsLastError(snapshot) {{
      const lastError = snapshot.status.last_error || "无";
      return `最后错误：${{lastError}}`;
    }}
    function diagnosticsConnectionMetrics(snapshot) {{
      const metrics = snapshot.status.connection_metrics || {{}};
      const average = metrics.average_connect_ms === null || metrics.average_connect_ms === undefined
        ? "无"
        : `${{metrics.average_connect_ms}} ms`;
      return `连接 ${{metrics.total || 0}} 次，成功 ${{metrics.success || 0}}，失败 ${{metrics.failure || 0}}，平均连接 ${{average}}`;
    }}
    function diagnosticsNodeHealth(snapshot) {{
      const health = snapshot.status.node_health || {{}};
      const nodeCount = health.node_count || 0;
      if (!nodeCount) return "暂无运行健康证据";
      const selected = health.selected_state || "未知";
      return `节点健康：${{health.healthy_count || 0}} 健康，${{health.unhealthy_count || 0}} 异常，${{health.unknown_count || 0}} 未知，已检查 ${{health.checked_count || 0}}/${{nodeCount}}，当前 ${{selected}}`;
    }}
    function diagnosticsRecentEvent(snapshot) {{
      const event = (snapshot.status.recent_events || [])[0];
      if (!event) return "最近事件：无";
      const status = runStateLabels[event.status] || event.status;
      const note = event.note ? ` - ${{event.note}}` : "";
      return `最近事件：${{status}}${{note}}`;
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
        appendRuntimeEventRow(container, "空闲", "暂无运行事件");
        return;
      }}
      for (const event of events) {{
        appendRuntimeEventRow(
          container,
          runStateLabels[event.status] || event.status,
          event.note || "无事件详情"
        );
      }}
    }}
    function renderRuntimeEventList(snapshot) {{
      renderRuntimeEventListInto("runtime-event-list", snapshot);
      renderRuntimeEventListInto("dashboard-runtime-event-list", snapshot);
    }}
    function appendDiagnosticsRuntimeLogRow(container, index, status, note) {{
      const row = document.createElement("tr");
      for (const value of [index, status, note]) {{
        const cell = document.createElement("td");
        cell.textContent = value;
        row.appendChild(cell);
      }}
      container.appendChild(row);
    }}
    function renderDiagnosticsRuntimeLog(snapshot) {{
      const body = document.getElementById("diagnostics-runtime-log-body");
      if (!body) return;
      body.replaceChildren();
      const events = (snapshot.status.recent_events || []).slice(0, 8);
      if (!events.length) {{
        appendDiagnosticsRuntimeLogRow(body, "空闲", "核心", "暂无运行事件");
        return;
      }}
      events.forEach((event, index) => {{
        appendDiagnosticsRuntimeLogRow(
          body,
          index + 1,
          runStateLabels[event.status] || event.status,
          event.note || "无事件详情"
        );
      }});
    }}
    function diagnosticsSystemProxy(snapshot) {{
      return `系统代理：${{systemProxyDependency(snapshot)}}`;
    }}
    function diagnosticsTun(snapshot) {{
      return `TUN: ${{tunDependency(snapshot)}}`;
    }}
    function diagnosticsDefaultCore(snapshot) {{
      return snapshot ? "默认使用原生核心，支持包包含认证证据" : "默认使用原生核心";
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
      return `${{diagnosticsRuntimeEvents(snapshot)}}；${{diagnosticsRecentEvent(snapshot)}}`;
    }}
    function topCoreStatus(snapshot) {{
      const run = runStateLabels[snapshot.status.run_state] || snapshot.status.run_state;
      return `核心状态：${{run}}`;
    }}
    function topDependencyStatus(snapshot) {{
      const firstRun = snapshot.dependencies.first_run;
      return firstRun.system_proxy_ready && firstRun.tun_ready && !(firstRun.blockers || []).length
        ? "依赖已就绪"
        : "依赖需要处理";
    }}
    function setReadiness(prefix, ready, detail) {{
      const state = document.getElementById(`${{prefix}}-state`);
      if (state) {{
        state.textContent = ready ? "就绪" : "需要处理";
        state.className = ready ? "status-ok" : "status-warning";
      }}
      setText(`${{prefix}}-detail`, detail);
    }}
    window.keliSyncDashboard = (snapshot) => {{
      const status = snapshot.status;
      setText("nav-run-state", runStateLabels[status.run_state] || status.run_state);
      setText("top-core-status", topCoreStatus(snapshot));
      setText("top-traffic-mode", trafficModeLabels[status.traffic_mode] || status.traffic_mode);
      setText("top-selected-node", status.selected_outbound || "未选择节点");
      setText("top-dependency-status", topDependencyStatus(snapshot));
      setText("top-activity-status", overviewActivity(snapshot));
      setText("activity-metrics", diagnosticsConnectionMetrics(snapshot));
      setText("dashboard-dependency-summary", dependencySummary(snapshot));
      setText("dashboard-system-proxy-status", dashboardSystemProxyStatus(snapshot));
      setText("dashboard-tun-status", dashboardTunStatus(snapshot));
      setText("dashboard-blockers", dashboardDependencyBlockers(snapshot));
      renderRuntimeEventList(snapshot);
      renderDependencyActions(snapshot);
    }};
    window.keliSyncDiagnosticsView = (snapshot) => {{
      const firstRun = snapshot.dependencies.first_run;
      setReadiness(
        "readiness-system-proxy",
        firstRun.system_proxy_ready,
        readinessSystemProxyDetail(snapshot)
      );
      setReadiness("readiness-tun-wintun", firstRun.tun_ready, readinessTunDetail(snapshot));
      setText(
        "readiness-route-takeover-detail",
        `当前模式：${{trafficModeLabels[snapshot.status.traffic_mode] || snapshot.status.traffic_mode}}`
      );
      setText("readiness-subscription-updater-detail", subscriptionSummary(snapshot.subscription));
      setText("diagnostics-metric-connections", diagnosticsConnectionMetrics(snapshot));
      setText("diagnostics-metric-node-health", diagnosticsNodeHealth(snapshot));
      setText("diagnostics-metric-last-error", diagnosticsLastError(snapshot));
      setText("diagnostics-metric-activity", overviewActivity(snapshot));
      renderDiagnosticsRuntimeLog(snapshot);
    }};
    window.keliSyncSettings = (snapshot) => {{
      const status = snapshot.status;
      const primary = snapshot.primary_action;
      setText("settings-run-state", runStateLabels[status.run_state] || status.run_state);
      setText("settings-traffic-mode", trafficModeLabels[status.traffic_mode] || status.traffic_mode);
      setText("settings-selected-node", status.selected_outbound || "未选择节点");
      setText("settings-listen-address", status.listen || "未监听");
      setText("settings-dependency-summary", dependencySummary(snapshot));
      setText("settings-primary-state", primary.reason || (primary.enabled ? "可用" : "不可用"));
      setText("settings-subscription-summary", subscriptionSummary(snapshot.subscription));
      syncPrimaryButton("settings-primary-button", primary);
      syncTrafficModeButtons(status.traffic_mode);
      const importUrlButton = document.getElementById("settings-import-url-button");
      const updateUrlButton = document.getElementById("settings-update-url-button");
      if (importUrlButton) importUrlButton.disabled = status.run_state === "running";
      if (updateUrlButton) updateUrlButton.disabled = status.run_state !== "running";
    }};
    window.keliSyncOverview = (snapshot) => {{
      const status = snapshot.status;
      const primary = snapshot.primary_action;
      setText("quick-run-state", runStateLabels[status.run_state] || status.run_state);
      setText("quick-traffic-mode", trafficModeLabels[status.traffic_mode] || status.traffic_mode);
      setText("quick-selected-node", status.selected_outbound || "未选择节点");
      setText("quick-listen-address", status.listen || "未监听");
      setText("quick-primary-state", primary.reason || (primary.enabled ? "可用" : "不可用"));
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
      window.keliSyncNodes(snapshot);
      window.keliSyncDiagnosticsView(snapshot);
      window.keliSyncSettings(snapshot);
      document.getElementById("run-state").textContent = runStateLabels[status.run_state] || status.run_state;
      document.getElementById("traffic-mode").textContent = trafficModeLabels[status.traffic_mode] || status.traffic_mode;
      document.getElementById("listen-address").textContent = status.listen || "未监听";
      document.getElementById("selected-outbound").textContent = status.selected_outbound || "未选择节点";
      document.getElementById("runtime-meta").textContent = `代次 ${{status.generation}}，事件 ${{status.event_count}}`;
      document.getElementById("primary-label").textContent = primary.label;
      document.getElementById("primary-state").textContent = primary.reason || (primary.enabled ? "可用" : "不可用");
      const primaryButton = document.getElementById("primary-button");
      primaryButton.textContent = primary.label;
      primaryButton.disabled = !primary.enabled;
      const importUrlButton = document.getElementById("import-subscription-url-button");
      const updateUrlButton = document.getElementById("update-subscription-url-button");
      importUrlButton.disabled = status.run_state === "running";
      updateUrlButton.disabled = status.run_state !== "running";
      document.getElementById("tray-ids").textContent = snapshot.tray_menu.items.map((item) => item.id).join(", ");
      document.getElementById("window-visible").textContent = `窗口可见：${{snapshot.window.main_visible}}`;
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
        dashboard_system_proxy_status = escape_html(&dashboard_system_proxy_status),
        dashboard_tun_status = escape_html(&dashboard_tun_status),
        dashboard_dependency_blockers = escape_html(&dashboard_dependency_blockers),
        dependency_actions = dependency_actions,
        diagnostics_core_status = escape_html(&diagnostics_core_status),
        diagnostics_runtime_events = escape_html(&diagnostics_runtime_events),
        diagnostics_last_error = escape_html(&diagnostics_last_error),
        diagnostics_connection_metrics = escape_html(&diagnostics_connection_metrics),
        diagnostics_node_health = escape_html(&diagnostics_node_health),
        diagnostics_recent_event = escape_html(&diagnostics_recent_event),
        runtime_event_items = runtime_event_items,
        diagnostics_runtime_log_rows = diagnostics_runtime_log_rows,
        diagnostics_system_proxy = escape_html(&diagnostics_system_proxy),
        diagnostics_tun = escape_html(&diagnostics_tun),
        diagnostics_default_core = escape_html(&diagnostics_default_core),
        panel_account = escape_html(&panel_account),
        panel_subscription = escape_html(&panel_subscription),
        panel_nodes = panel_nodes,
        panel_notice = escape_html(&panel_notice),
        readiness_system_proxy_detail = escape_html(&readiness_system_proxy_detail),
        readiness_tun_detail = escape_html(&readiness_tun_detail),
        activity_summary = escape_html(&activity_summary),
        nodes_supported_count = nodes_supported_count,
        nodes_skipped_count = nodes_skipped_count,
        nodes_healthy_count = nodes_healthy_count,
        nodes_udp_ready_count = nodes_udp_ready_count,
        nodes_recommended = escape_html(&nodes_recommended),
        nodes_table_rows = nodes_table_rows,
        selected_node_title = escape_html(&selected_node_title),
        selected_node_detail = selected_node_detail,
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
        DesktopRunState::Stopped => "已停止",
        DesktopRunState::Starting => "启动中",
        DesktopRunState::Running => "运行中",
        DesktopRunState::Reloading => "更新中",
        DesktopRunState::Stopping => "停止中",
        DesktopRunState::Failed => "失败",
    }
}

fn traffic_mode_label(traffic_mode: DesktopTrafficMode) -> &'static str {
    match traffic_mode {
        DesktopTrafficMode::SystemProxy => "系统代理",
        DesktopTrafficMode::Tun => "TUN",
        DesktopTrafficMode::MixedInboundOnly => "本地入站",
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
        "系统代理就绪"
    } else {
        "系统代理受阻"
    };
    let tun = if snapshot.dependencies.first_run.tun_ready {
        "TUN 就绪"
    } else {
        "TUN 受阻"
    };
    format!("{system}，{tun}")
}

fn system_proxy_dependency(snapshot: &DesktopShellState) -> String {
    let proxy = &snapshot.dependencies.system_proxy;
    let mut parts = vec![format!("系统代理状态：{}", proxy.state)];
    if let Some(enabled) = proxy.enabled {
        parts.push(format!("已启用={enabled}"));
    }
    if let Some(server) = proxy.server.as_deref() {
        parts.push(format!("服务器={server}"));
    }
    if let Some(error) = proxy.error.as_deref() {
        parts.push(error.to_string());
    }
    if let Some(action) = proxy.action.as_deref() {
        parts.push(format!("操作={action}"));
    }
    parts.join("，")
}

fn tun_dependency(snapshot: &DesktopShellState) -> String {
    let tun = &snapshot.dependencies.tun_backend;
    let mut parts = vec![format!("Wintun 状态：{}", tun.state)];
    parts.push(format!("驱动存在={}", tun.driver_library_present));
    parts.push(format!("API可用={}", tun.driver_api_available));
    if let Some(path) = tun.driver_library_path.as_deref() {
        parts.push(format!("路径={path}"));
    }
    if let Some(reason) = tun.reason.as_deref() {
        parts.push(reason.to_string());
    }
    if let Some(action) = tun.action.as_deref() {
        parts.push(format!("操作={action}"));
    }
    parts.join("，")
}

fn dependency_blockers(snapshot: &DesktopShellState) -> String {
    if snapshot.dependencies.first_run.blockers.is_empty() {
        return "没有依赖阻塞项".to_string();
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
                .map(|action| format!(" 操作={action}"))
                .unwrap_or_default();
            format!("{}: {}{}", blocker.code, blocker.message, action)
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn dashboard_system_proxy_status(snapshot: &DesktopShellState) -> &'static str {
    if snapshot.dependencies.first_run.system_proxy_ready {
        "就绪"
    } else {
        "需要处理"
    }
}

fn dashboard_tun_status(snapshot: &DesktopShellState) -> &'static str {
    if snapshot.dependencies.first_run.tun_ready {
        "就绪"
    } else {
        "需要处理"
    }
}

fn dashboard_dependency_blockers(snapshot: &DesktopShellState) -> String {
    let count = snapshot.dependencies.first_run.blockers.len();
    match count {
        0 => "无阻塞项".to_string(),
        _ => format!("{count} 个阻塞项"),
    }
}

fn diagnostics_core_status(snapshot: &DesktopShellState) -> String {
    format!(
        "核心{} · {}",
        run_state_label(snapshot.status.run_state),
        traffic_mode_label(snapshot.status.traffic_mode)
    )
}

fn diagnostics_runtime_events(snapshot: &DesktopShellState) -> String {
    format!(
        "运行代次 {}，事件 {}",
        snapshot.status.generation, snapshot.status.event_count
    )
}

fn diagnostics_last_error(snapshot: &DesktopShellState) -> String {
    format!(
        "最后错误：{}",
        snapshot.status.last_error.as_deref().unwrap_or("无")
    )
}

fn diagnostics_connection_metrics(snapshot: &DesktopShellState) -> String {
    let metrics = &snapshot.status.connection_metrics;
    let average = metrics
        .average_connect_ms
        .map(|value| format!("{value} ms"))
        .unwrap_or_else(|| "无".to_string());
    format!(
        "连接 {} 次，成功 {}，失败 {}，平均连接 {}",
        metrics.total, metrics.success, metrics.failure, average
    )
}

fn diagnostics_node_health(snapshot: &DesktopShellState) -> String {
    let health = &snapshot.status.node_health;
    if health.node_count == 0 {
        return "暂无运行健康证据".to_string();
    }

    format!(
        "节点健康：{} 健康，{} 异常，{} 未知，已检查 {}/{}，当前 {}",
        health.healthy_count,
        health.unhealthy_count,
        health.unknown_count,
        health.checked_count,
        health.node_count,
        health.selected_state.as_deref().unwrap_or("未知")
    )
}

fn diagnostics_recent_event(snapshot: &DesktopShellState) -> String {
    let Some(event) = snapshot.status.recent_events.first() else {
        return "最近事件：无".to_string();
    };
    let note = event
        .note
        .as_deref()
        .map(|note| format!(" - {note}"))
        .unwrap_or_default();
    format!("最近事件：{}{}", run_state_label(event.status), note)
}

fn runtime_event_items(snapshot: &DesktopShellState) -> String {
    if snapshot.status.recent_events.is_empty() {
        return r#"<div class="event-row"><span class="event-state">空闲</span><span>暂无运行事件</span></div>"#
            .to_string();
    }

    snapshot
        .status
        .recent_events
        .iter()
        .take(6)
        .map(|event| {
            let status = escape_html(run_state_label(event.status));
            let note = escape_html(event.note.as_deref().unwrap_or("无事件详情"));
            format!(
                r#"<div class="event-row"><span class="event-state">{status}</span><span>{note}</span></div>"#
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn diagnostics_runtime_log_rows(snapshot: &DesktopShellState) -> String {
    if snapshot.status.recent_events.is_empty() {
        return r#"<tr><td>空闲</td><td>核心</td><td>暂无运行事件</td></tr>"#.to_string();
    }

    snapshot
        .status
        .recent_events
        .iter()
        .take(8)
        .enumerate()
        .map(|(index, event)| {
            let number = index + 1;
            let status = escape_html(run_state_label(event.status));
            let note = escape_html(event.note.as_deref().unwrap_or("无事件详情"));
            format!(r#"<tr><td>{number}</td><td>{status}</td><td>{note}</td></tr>"#)
        })
        .collect::<Vec<_>>()
        .join("")
}

fn diagnostics_system_proxy(snapshot: &DesktopShellState) -> String {
    format!("系统代理：{}", system_proxy_dependency(snapshot))
}

fn diagnostics_tun(snapshot: &DesktopShellState) -> String {
    format!("TUN: {}", tun_dependency(snapshot))
}

fn diagnostics_default_core(_snapshot: &DesktopShellState) -> String {
    "默认使用原生核心，支持包包含认证证据".to_string()
}

fn readiness_system_proxy_detail(snapshot: &DesktopShellState) -> String {
    if snapshot.dependencies.first_run.system_proxy_ready {
        if snapshot.dependencies.system_proxy.enabled == Some(true) {
            "系统代理已启用".to_string()
        } else {
            "系统代理可用".to_string()
        }
    } else {
        snapshot
            .dependencies
            .system_proxy
            .error
            .clone()
            .unwrap_or_else(|| "系统代理需要处理".to_string())
    }
}

fn readiness_tun_detail(snapshot: &DesktopShellState) -> String {
    if snapshot.dependencies.first_run.tun_ready {
        "Wintun 驱动和包 I/O 已就绪".to_string()
    } else {
        snapshot
            .dependencies
            .tun_backend
            .reason
            .clone()
            .unwrap_or_else(|| "Wintun 需要处理".to_string())
    }
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
        "check-system-proxy" => "打开代理设置",
        "install-wintun" => "打开 Wintun 下载",
        "check-tun" => "打开 TUN 帮助",
        _ => action,
    }
}

fn subscription_summary(subscription: Option<&DesktopSubscriptionSummary>) -> String {
    match subscription {
        Some(subscription) => format!(
            "支持 {}，跳过 {}",
            subscription.supported_count, subscription.skipped_count
        ),
        None => "没有导入订阅".to_string(),
    }
}

fn node_buttons(subscription: Option<&DesktopSubscriptionSummary>) -> String {
    let Some(subscription) = subscription else {
        return r#"<span class="muted">没有节点</span>"#.to_string();
    };
    let mut nodes = Vec::new();
    if subscription.nodes.is_empty() {
        nodes.push(r#"<span class="muted">没有节点</span>"#.to_string());
    }
    nodes.extend(subscription.nodes.iter().map(|node| {
        let selected = if node.selected { "true" } else { "false" };
        let tag = escape_html(&node.tag);
        let meta = escape_html(&format!(
            "{} / {} / {}",
            node.protocol, node.transport, node.security
        ));
        let udp = if node.udp_supported {
            "UDP 就绪"
        } else {
            "UDP 不可用"
        };
        let health = escape_html(&node_health_detail(node));
        let mut badges = Vec::new();
        if node.selected {
            badges.push(r#"<span class="node-badge">已选择</span>"#.to_string());
        }
        if node.recommended {
            badges.push(r#"<span class="node-badge">推荐</span>"#.to_string());
        }
        let badges = badges.join("");
        format!(
            r#"<button data-node-tag="{tag}" aria-pressed="{selected}" onclick="postSelectNode(this.dataset.nodeTag)"><span class="node-tag">{tag}</span><span class="node-meta">{meta}</span><span class="node-meta">{udp}</span><span class="node-meta">{health}</span><span class="node-badges">{badges}</span></button>"#
        )
    }));
    nodes.extend(subscription.skipped.iter().map(|skipped| {
        let skipped = escape_html(skipped);
        format!(
            r#"<div class="node-skipped"><span class="node-badge">已跳过</span><span>{skipped}</span></div>"#
        )
    }));
    nodes.join("")
}

fn nodes_supported_count(subscription: Option<&DesktopSubscriptionSummary>) -> usize {
    subscription
        .map(|subscription| subscription.supported_count)
        .unwrap_or(0)
}

fn nodes_skipped_count(subscription: Option<&DesktopSubscriptionSummary>) -> usize {
    subscription
        .map(|subscription| subscription.skipped_count)
        .unwrap_or(0)
}

fn nodes_healthy_count(subscription: Option<&DesktopSubscriptionSummary>) -> usize {
    subscription
        .map(|subscription| {
            subscription
                .nodes
                .iter()
                .filter(|node| {
                    node.health_state.as_deref() == Some("healthy")
                        || node.tcp_available == Some(true)
                })
                .count()
        })
        .unwrap_or(0)
}

fn nodes_udp_ready_count(subscription: Option<&DesktopSubscriptionSummary>) -> usize {
    subscription
        .map(|subscription| {
            subscription
                .nodes
                .iter()
                .filter(|node| node.udp_supported || node.udp_available == Some(true))
                .count()
        })
        .unwrap_or(0)
}

fn nodes_recommended(subscription: Option<&DesktopSubscriptionSummary>) -> String {
    subscription
        .and_then(|subscription| subscription.recommended_outbound.as_deref())
        .unwrap_or("无")
        .to_string()
}

fn selected_node(
    subscription: Option<&DesktopSubscriptionSummary>,
) -> Option<&keli_desktop::DesktopNodeSummary> {
    let subscription = subscription?;
    subscription
        .nodes
        .iter()
        .find(|node| node.selected)
        .or_else(|| {
            subscription
                .selected_outbound
                .as_deref()
                .and_then(|selected| subscription.nodes.iter().find(|node| node.tag == selected))
        })
        .or_else(|| subscription.nodes.first())
}

fn nodes_table_rows(subscription: Option<&DesktopSubscriptionSummary>) -> String {
    let Some(subscription) = subscription else {
        return r#"<tr><td colspan="7">没有节点</td></tr>"#.to_string();
    };
    if subscription.nodes.is_empty() {
        return r#"<tr><td colspan="7">没有节点</td></tr>"#.to_string();
    }

    subscription
        .nodes
        .iter()
        .map(|node| {
            let selected = if node.selected { "true" } else { "false" };
            let tag = escape_html(&node.tag);
            let protocol = escape_html(&node.protocol);
            let transport = escape_html(&node.transport);
            let latency = node
                .latency_ms
                .map(|latency| format!("{latency} ms"))
                .unwrap_or_else(|| "-".to_string());
            let tcp = if node.tcp_available == Some(false) {
                "失败"
            } else {
                "就绪"
            };
            let udp = if node.udp_supported || node.udp_available == Some(true) {
                "就绪"
            } else {
                "不可用"
            };
            let health = escape_html(&node_health_detail(node));
            format!(
                r#"<tr data-selected="{selected}" onclick="postSelectNode(this.dataset.nodeTag)" data-node-tag="{tag}"><td>{tag}</td><td>{protocol}</td><td>{transport}</td><td>{latency}</td><td>{tcp}</td><td>{udp}</td><td>{health}</td></tr>"#
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn selected_node_title(subscription: Option<&DesktopSubscriptionSummary>) -> String {
    selected_node(subscription)
        .map(|node| node.tag.clone())
        .unwrap_or_else(|| "未选择节点".to_string())
}

fn selected_node_detail(subscription: Option<&DesktopSubscriptionSummary>) -> String {
    let Some(node) = selected_node(subscription) else {
        return r#"<div><span>状态</span><strong>导入订阅后才能选择节点</strong></div>"#
            .to_string();
    };

    let latency = node
        .latency_ms
        .map(|latency| format!("{latency} ms"))
        .unwrap_or_else(|| "-".to_string());
    let tcp = if node.tcp_available == Some(false) {
        "失败"
    } else {
        "就绪"
    };
    let udp = if node.udp_supported || node.udp_available == Some(true) {
        "就绪"
    } else {
        "不可用"
    };
    [
        ("协议", node.protocol.as_str()),
        ("传输", node.transport.as_str()),
        ("安全", node.security.as_str()),
        ("延迟", latency.as_str()),
        ("TCP", tcp),
        ("UDP", udp),
        ("健康", node_health_detail(node).as_str()),
    ]
    .iter()
    .map(|(label, value)| {
        format!(
            r#"<div><span>{}</span><strong>{}</strong></div>"#,
            escape_html(label),
            escape_html(value)
        )
    })
    .collect::<Vec<_>>()
    .join("")
}

fn node_health_detail(node: &keli_desktop::DesktopNodeSummary) -> String {
    let mut parts = Vec::new();
    if let Some(state) = node.health_state.as_deref() {
        parts.push(format!("健康状态 {state}"));
    }
    match node.tcp_available {
        Some(true) => parts.push("TCP 就绪".to_string()),
        Some(false) => parts.push("TCP 失败".to_string()),
        None => {}
    }
    match node.udp_available {
        Some(true) => parts.push("UDP 在线".to_string()),
        Some(false) => parts.push("UDP 失败".to_string()),
        None => {}
    }
    if let Some(latency_ms) = node.latency_ms {
        parts.push(format!("{latency_ms} ms"));
    }
    if let Some(error) = node.health_error.as_deref() {
        parts.push(format!("最近失败 {error}"));
    }
    if parts.is_empty() {
        "健康未知".to_string()
    } else {
        parts.join("，")
    }
}

fn panel_account_summary(snapshot: &DesktopShellState) -> String {
    snapshot
        .panel
        .as_ref()
        .map(|panel| panel.account.email_redacted.clone())
        .unwrap_or_else(|| "未登录面板".to_string())
}

fn panel_subscription_summary(snapshot: &DesktopShellState) -> String {
    let Some(panel) = snapshot.panel.as_ref() else {
        return "未加载订阅".to_string();
    };
    let plan = panel
        .subscription
        .plan_name
        .as_deref()
        .unwrap_or("未命名套餐");
    let used = panel.subscription.used_bytes.unwrap_or(0);
    let total = panel.subscription.total_bytes.unwrap_or(0);
    format!(
        "{plan}，已用 {} / {}",
        bytes_label(used),
        bytes_label(total)
    )
}

fn panel_notice_summary(snapshot: &DesktopShellState) -> String {
    snapshot
        .panel
        .as_ref()
        .and_then(|panel| panel.notices.iter().find(|notice| notice.show))
        .map(|notice| notice.title.clone())
        .unwrap_or_else(|| "暂无公告".to_string())
}

fn panel_nodes_summary(snapshot: &DesktopShellState) -> String {
    let Some(panel) = snapshot.panel.as_ref() else {
        return r#"<div class="muted">未加载面板节点</div>"#.to_string();
    };
    if panel.nodes.is_empty() {
        return r#"<div class="muted">没有可用节点</div>"#.to_string();
    }
    panel
        .nodes
        .iter()
        .map(|node| {
            let protocol = node.protocol.as_deref().unwrap_or("未知协议");
            format!(
                r#"<div class="status-row"><strong>{}</strong><span>{}</span></div>"#,
                escape_html(&node.name),
                escape_html(protocol)
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn bytes_label(bytes: i64) -> String {
    let gb = bytes as f64 / 1024.0 / 1024.0 / 1024.0;
    format!("{gb:.1} GB")
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
        assert!(html.contains("已停止"));
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
    fn desktop_shell_renders_chinese_user_facing_copy() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains(r#"<html lang="zh-CN">"#));
        assert!(html.contains(">概览</button>"));
        assert!(html.contains(">节点</button>"));
        assert!(html.contains(">诊断</button>"));
        assert!(html.contains(">设置</button>"));
        assert!(html.contains("核心状态：已停止"));
        assert!(html.contains("模式："));
        assert!(html.contains("节点："));
        assert!(html.contains("依赖已就绪"));
        assert!(html.contains("未选择节点"));
        assert!(html.contains("没有导入订阅"));
        assert!(html.contains("启动受阻"));
        assert!(html.contains("刷新"));
        assert!(html.contains("就绪"));
        assert!(!html.contains(">Dashboard</button>"));
        assert!(!html.contains(">Refresh</button>"));
    }

    #[test]
    fn panel_ui_baseline_includes_account_subscription_store_and_support_views() {
        let mut snapshot = snapshot();
        snapshot.panel = Some(keli_desktop::DesktopPanelSnapshot::fixture_ready());

        let html = render_shell_html(&snapshot);

        assert!(html.contains("data-view-target=\"subscription-view\""));
        assert!(html.contains("data-view-target=\"store-view\""));
        assert!(html.contains("data-view-target=\"support-view\""));
        assert!(html.contains(">订阅</button>"));
        assert!(html.contains(">商店</button>"));
        assert!(html.contains(">支持</button>"));
        assert!(html.contains("id=\"dashboard-panel-account\""));
        assert!(html.contains("u***@example.com"));
        assert!(html.contains("Pro，已用 4.0 GB / 10.0 GB"));
        assert!(html.contains("欢迎使用 Keli"));
        assert!(!html.contains("https://panel.example.com/s/token"));
    }

    #[test]
    fn panel_ui_keeps_page_level_scrolling_disabled() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("html,\n    body {"));
        assert!(html.contains("overflow: hidden;"));
        assert!(html.contains(".bounded-list"));
        assert!(html.contains(".panel-grid"));
    }

    #[test]
    fn desktop_shell_keeps_primary_views_inside_default_window() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("html,\n    body {"));
        assert!(html.contains("height: 100%;"));
        assert!(html.contains("overflow: hidden;"));
        assert!(html.contains(".desktop-layout {\n      height: 100vh;"));
        assert!(html.contains(".app-shell {\n      height: 100vh;"));
        assert!(html.contains("grid-template-rows: auto auto minmax(0, 1fr);"));
        assert!(html.contains(".app-view {\n      min-height: 0;"));
        assert!(
            html.contains("class=\"app-view dashboard-view\" id=\"dashboard-view\" data-app-view")
        );
    }

    #[test]
    fn dashboard_default_view_hides_legacy_workflow_surface() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("class=\"grid legacy-workflow-surface\" hidden"));
        assert!(html.contains("#connection-activity-panel,"));
        assert!(html.contains("<pre id=\"snapshot-json\" hidden>"));
        assert!(html.contains("id=\"dashboard-tun-status\">就绪</span>"));
        assert!(!html.contains("id=\"dashboard-tun-status\">Wintun ready"));
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
    fn nodes_baseline_includes_subscription_toolbar_summary_and_filters() {
        let mut snapshot = snapshot();
        snapshot.refresh_subscription(Some(subscription("SS-READY")));

        let html = render_shell_html(&snapshot);

        assert!(html.contains("id=\"nodes-view\""));
        assert!(html.contains("id=\"nodes-subscription-url\""));
        assert!(html.contains("postImportNodesSubscriptionUrl()"));
        assert!(html.contains("postUpdateNodesSubscriptionUrl()"));
        assert!(html.contains("id=\"nodes-summary-strip\""));
        assert!(html.contains("id=\"nodes-supported-count\""));
        assert!(html.contains("id=\"nodes-skipped-count\""));
        assert!(html.contains("id=\"nodes-healthy-count\""));
        assert!(html.contains("id=\"nodes-udp-ready-count\""));
        assert!(html.contains("id=\"node-filter-tabs\""));
        assert!(html.contains("data-node-filter=\"udp-ready\""));
    }

    #[test]
    fn nodes_baseline_renders_table_detail_and_live_sync() {
        let mut snapshot = snapshot();
        let mut summary = subscription("SS-READY");
        summary.nodes[0].health_state = Some("healthy".to_string());
        summary.nodes[0].tcp_available = Some(true);
        summary.nodes[0].udp_available = Some(true);
        summary.nodes[0].latency_ms = Some(42);
        snapshot.refresh_subscription(Some(summary));

        let html = render_shell_html(&snapshot);

        assert!(html.contains("id=\"nodes-table-body\""));
        assert!(html.contains("名称"));
        assert!(html.contains("协议"));
        assert!(html.contains("传输"));
        assert!(html.contains("延迟"));
        assert!(html.contains("SS-READY"));
        assert!(html.contains("id=\"selected-node-detail\""));
        assert!(html.contains("id=\"selected-node-title\""));
        assert!(html.contains("42 ms"));
        assert!(html.contains("window.keliSyncNodes"));
    }

    #[test]
    fn diagnostics_baseline_includes_readiness_runtime_and_metrics_panels() {
        let mut snapshot = snapshot();
        snapshot.status.connection_metrics.total = 12;
        snapshot.status.connection_metrics.success = 11;
        snapshot.status.connection_metrics.failure = 1;
        snapshot.status.connection_metrics.average_connect_ms = Some(18);
        snapshot.status.recent_events = vec![DesktopRecentRuntimeEvent {
            status: DesktopRunState::Running,
            note: Some("listener ready".to_string()),
        }];

        let html = render_shell_html(&snapshot);

        assert!(html.contains("id=\"diagnostics-view\""));
        assert!(html.contains("id=\"readiness-checklist\""));
        assert!(html.contains("id=\"readiness-system-proxy\""));
        assert!(html.contains("id=\"readiness-tun-wintun\""));
        assert!(html.contains("id=\"readiness-dns-policy\""));
        assert!(html.contains("id=\"readiness-route-takeover\""));
        assert!(html.contains("id=\"readiness-signing-status\""));
        assert!(html.contains("id=\"diagnostics-runtime-log-panel\""));
        assert!(html.contains("id=\"diagnostics-runtime-log-body\""));
        assert!(html.contains("listener ready"));
        assert!(html.contains("id=\"diagnostics-metrics-panel\""));
        assert!(html.contains("连接 12 次，成功 11，失败 1，平均连接 18 ms"));
    }

    #[test]
    fn diagnostics_baseline_includes_support_settings_and_live_sync() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("id=\"diagnostics-support-panel\""));
        assert!(html.contains("id=\"diagnostics-export-button\""));
        assert!(html.contains("id=\"diagnostics-copy-logs-button\""));
        assert!(html.contains("id=\"include-certification-toggle\""));
        assert!(html.contains("id=\"diagnostics-settings-panel\""));
        assert!(html.contains("id=\"diagnostics-mixed-port\""));
        assert!(html.contains("id=\"diagnostics-socks-port\""));
        assert!(html.contains("id=\"diagnostics-http-port\""));
        assert!(html.contains("id=\"diagnostics-max-workers\""));
        assert!(html.contains("window.keliSyncDiagnosticsView"));
    }

    #[test]
    fn settings_baseline_includes_runtime_startup_and_network_controls() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("id=\"settings-view\""));
        assert!(html.contains("id=\"settings-runtime-panel\""));
        assert!(html.contains("id=\"settings-primary-button\""));
        assert!(html.contains("id=\"settings-refresh-button\""));
        assert!(html.contains("id=\"settings-traffic-mode-control\""));
        assert!(html.contains("data-settings-traffic-mode=\"mixed-inbound-only\""));
        assert!(html.contains("data-settings-traffic-mode=\"system-proxy\""));
        assert!(html.contains("data-settings-traffic-mode=\"tun\""));
        assert!(html.contains("id=\"settings-startup-panel\""));
        assert!(html.contains("id=\"settings-start-with-windows\""));
        assert!(html.contains("id=\"settings-launch-minimized\""));
        assert!(html.contains("id=\"settings-auto-start-core\""));
        assert!(html.contains("id=\"settings-network-panel\""));
        assert!(html.contains("id=\"settings-mixed-port\""));
        assert!(html.contains("id=\"settings-socks-port\""));
        assert!(html.contains("id=\"settings-http-port\""));
        assert!(html.contains("id=\"settings-dns-mode\""));
        assert!(html.contains("id=\"settings-tun-stack\""));
        assert!(html.contains("id=\"settings-load-panel-fixture-button\""));
        assert!(html.contains("load-panel-fixture"));
    }

    #[test]
    fn settings_baseline_includes_subscription_status_and_live_sync() {
        let mut snapshot = snapshot();
        snapshot.refresh_subscription(Some(subscription("SS-READY")));

        let html = render_shell_html(&snapshot);

        assert!(html.contains("id=\"settings-subscription-panel\""));
        assert!(html.contains("id=\"settings-subscription-url\""));
        assert!(html.contains("postImportSettingsSubscriptionUrl()"));
        assert!(html.contains("postUpdateSettingsSubscriptionUrl()"));
        assert!(html.contains("id=\"settings-subscription-summary\""));
        assert!(html.contains("id=\"settings-selected-node\""));
        assert!(html.contains("id=\"settings-listen-address\""));
        assert!(html.contains("id=\"settings-dependency-summary\""));
        assert!(html.contains("SS-READY"));
        assert!(html.contains("window.keliSyncSettings"));
    }

    #[test]
    fn settings_subscription_status_is_compact_for_default_window() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("class=\"settings-subscription-status-row\""));
        assert!(html.contains(".settings-subscription-status-row {\n      display: flex;"));
        assert!(html.contains(".settings-subscription-status-row .muted {\n      margin-top: 0;"));
    }

    #[test]
    fn shell_html_shows_primary_blocked_reason_before_subscription() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("id=\"primary-state\">请先导入订阅，再启动 Keli</div>"));
        assert!(html.contains("id=\"primary-button\" class=\"primary\" onclick=\"window.ipc.postMessage('primary')\" disabled>启动受阻</button>"));
    }

    #[test]
    fn shell_html_live_update_prefers_primary_reason() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("primary.reason || (primary.enabled ? \"可用\" : \"不可用\")"));
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
            "id=\"import-subscription-url-button\" class=\"primary\" onclick=\"postImportSubscriptionUrl()\">导入 URL</button>"
        ));
        assert!(html.contains(
            "id=\"update-subscription-url-button\" onclick=\"postUpdateSubscriptionUrl()\" disabled>更新 URL</button>"
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
            "id=\"import-subscription-url-button\" class=\"primary\" onclick=\"postImportSubscriptionUrl()\" disabled>导入 URL</button>"
        ));
        assert!(html.contains(
            "id=\"update-subscription-url-button\" onclick=\"postUpdateSubscriptionUrl()\">更新 URL</button>"
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
        assert!(html.contains("本地入站"));
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
        assert!(html.contains("系统代理就绪"));
        assert!(html.contains("TUN 就绪"));
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
        assert!(html.contains("打开 Wintun 下载"));
        assert!(html.contains("Wintun 状态：install-required"));
        assert!(html.contains("Wintun library was not found"));
        assert!(html.contains("install-wintun"));
        assert!(html.contains("系统代理就绪"));
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
        assert!(html.contains("打开代理设置"));
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

        assert!(html.contains("支持 1"));
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
        assert!(html.contains("UDP 就绪"));
        assert!(html.contains("健康状态 healthy"));
        assert!(html.contains("TCP 就绪"));
        assert!(html.contains("UDP 在线"));
        assert!(html.contains("42 ms"));
        assert!(html.contains("已选择"));
        assert!(html.contains("推荐"));
    }

    #[test]
    fn subscription_node_list_renders_skipped_reasons() {
        let mut snapshot = snapshot();
        let mut summary = subscription("SS-READY");
        summary.skipped_count = 1;
        summary.skipped = vec!["BROKEN: unsupported protocol".to_string()];
        snapshot.refresh_subscription(Some(summary));

        let html = render_shell_html(&snapshot);

        assert!(html.contains("已跳过"));
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
        assert!(html.contains("核心已停止 · 系统代理"));
        assert!(html.contains("id=\"diagnostics-runtime-events\""));
        assert!(html.contains("运行代次 3，事件 5"));
        assert!(html.contains("最后错误：Managed(&quot;bind failed&quot;)"));
        assert!(html.contains("id=\"diagnostics-system-proxy\""));
        assert!(html.contains("id=\"diagnostics-tun\""));
        assert!(html.contains("连接 3 次，成功 2，失败 1，平均连接 25 ms"));
        assert!(html.contains("节点健康：1 健康，1 异常，0 未知，已检查 2/2，当前 healthy"));
        assert!(html.contains("最近事件：运行中 - runtime running"));
        assert!(html.contains("默认使用原生核心"));
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
