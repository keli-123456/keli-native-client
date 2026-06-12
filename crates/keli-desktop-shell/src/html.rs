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
    let subscription_summary = subscription_summary(snapshot.subscription.as_ref());
    let node_buttons = node_buttons(snapshot.subscription.as_ref());
    let dependency_summary = dependency_summary(snapshot);
    let system_proxy_dependency = system_proxy_dependency(snapshot);
    let tun_dependency = tun_dependency(snapshot);
    let dependency_blockers = dependency_blockers(snapshot);
    let dependency_actions = dependency_action_buttons(snapshot);

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
    main {{
      width: min(760px, 100vw);
      min-height: 100vh;
      margin: 0 auto;
      padding: 20px;
      display: grid;
      grid-template-rows: auto 1fr auto;
      gap: 18px;
    }}
    header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding-bottom: 14px;
      border-bottom: 1px solid #d9dee5;
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
    .node-list button[aria-pressed="true"] {{
      border-color: #277d56;
      color: #145a32;
      background: #e6f4ec;
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
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Keli</h1>
      <span class="pill" id="run-state">{run_state}</span>
    </header>
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
          <button id="import-subscription-url-button" class="primary" onclick="postImportSubscriptionUrl()">Import URL</button>
          <button id="update-subscription-url-button" onclick="postUpdateSubscriptionUrl()">Update URL</button>
        </div>
        <div class="muted" id="subscription-url-status">No subscription URL imported</div>
        <textarea id="subscription-config" spellcheck="false"></textarea>
        <div class="actions">
          <button id="import-subscription-button" class="primary" onclick="postImportSubscription()">Import</button>
          <button onclick="postTrafficMode('system-proxy')">System proxy</button>
          <button onclick="postTrafficMode('tun')">TUN</button>
        </div>
        <div class="muted" id="subscription-summary">{subscription_summary}</div>
        <div class="node-list" id="node-list">{node_buttons}</div>
      </section>
      <section class="wide">
        <h2>Diagnostics</h2>
        <div class="value">Support bundle</div>
        <div class="muted" id="support-export-status">No support bundle exported</div>
        <div class="actions">
          <button id="export-support-button" onclick="window.ipc.postMessage('export-support-bundle')">Export support bundle</button>
        </div>
      </section>
    </div>
    <pre id="snapshot-json">{snapshot_json}</pre>
  </main>
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
    function renderDependencyActions(snapshot) {{
      const container = document.getElementById("dependency-actions");
      container.replaceChildren();
      for (const action of collectDependencyActions(snapshot)) {{
        const button = document.createElement("button");
        button.dataset.dependencyAction = action;
        button.textContent = dependencyActionLabels[action] || action;
        button.onclick = () => postDependencyAction(action);
        container.appendChild(button);
      }}
    }}
    function subscriptionSummary(subscription) {{
      if (!subscription) return "No subscription imported";
      return `Supported ${{subscription.supported_count}}, skipped ${{subscription.skipped_count}}`;
    }}
    function renderNodeList(subscription) {{
      const nodeList = document.getElementById("node-list");
      nodeList.replaceChildren();
      if (!subscription || !subscription.nodes.length) {{
        const empty = document.createElement("span");
        empty.className = "muted";
        empty.textContent = "No nodes";
        nodeList.appendChild(empty);
        return;
      }}
      for (const node of subscription.nodes) {{
        const button = document.createElement("button");
        button.dataset.nodeTag = node.tag;
        button.textContent = node.tag;
        button.setAttribute("aria-pressed", node.selected ? "true" : "false");
        button.onclick = () => postSelectNode(node.tag);
        nodeList.appendChild(button);
      }}
    }}
    window.keliSetSupportExport = (summary) => {{
      const label = summary.status === "saved"
        ? `Saved ${{summary.byte_count}} bytes to ${{summary.path}}`
        : `${{summary.status}}: ${{summary.path || ""}}`;
      document.getElementById("support-export-status").textContent = label;
    }};
    window.keliSetWintunInstall = (summary) => {{
      const label = summary.error
        ? `${{summary.status}}: ${{summary.error}}`
        : `${{summary.status}}: ${{summary.target_path || ""}} (${{summary.copied_bytes || 0}} bytes)`;
      document.getElementById("wintun-install-status").textContent = label;
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
      document.getElementById("subscription-url-status").textContent = label;
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
      document.getElementById("subscription-url-status").textContent = label;
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
    window.keliSetShell = (snapshot) => {{
      const status = snapshot.status;
      const primary = snapshot.primary_action;
      document.getElementById("run-state").textContent = runStateLabels[status.run_state] || status.run_state;
      document.getElementById("traffic-mode").textContent = trafficModeLabels[status.traffic_mode] || status.traffic_mode;
      document.getElementById("listen-address").textContent = status.listen || "Not listening";
      document.getElementById("selected-outbound").textContent = status.selected_outbound || "No node selected";
      document.getElementById("runtime-meta").textContent = `Generation ${{status.generation}}, events ${{status.event_count}}`;
      document.getElementById("primary-label").textContent = primary.label;
      document.getElementById("primary-state").textContent = primary.enabled ? "Enabled" : "Disabled";
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
      document.getElementById("snapshot-json").textContent = JSON.stringify(snapshot, null, 2);
    }};
  </script>
</body>
</html>"#,
        run_state = escape_html(run_state),
        traffic_mode = escape_html(traffic_mode),
        listen = escape_html(listen),
        selected = escape_html(selected),
        generation = snapshot.status.generation,
        events = snapshot.status.event_count,
        primary_label = escape_html(&primary.label),
        primary_state = if primary.enabled {
            "Enabled"
        } else {
            "Disabled"
        },
        primary_disabled = primary_disabled,
        tray_ids = escape_html(&tray_ids),
        window_visible = snapshot.window.main_visible,
        dependency_summary = escape_html(&dependency_summary),
        system_proxy_dependency = escape_html(&system_proxy_dependency),
        tun_dependency = escape_html(&tun_dependency),
        dependency_blockers = escape_html(&dependency_blockers),
        dependency_actions = dependency_actions,
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

pub fn support_export_status_script(
    summary: &SupportBundleSaveSummary,
) -> serde_json::Result<String> {
    let summary_json = serde_json::to_string(summary)?;
    Ok(format!(
        "window.keliSetSupportExport && window.keliSetSupportExport({summary_json});"
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

pub fn subscription_url_import_status_script(
    summary: &DesktopSubscriptionUrlImportSummary,
) -> serde_json::Result<String> {
    let summary_json = serde_json::to_string(summary)?;
    Ok(format!(
        "window.keliSetSubscriptionUrlImport && window.keliSetSubscriptionUrlImport({summary_json});"
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
    if subscription.nodes.is_empty() {
        return r#"<span class="muted">No nodes</span>"#.to_string();
    }
    subscription
        .nodes
        .iter()
        .map(|node| {
            let selected = if node.selected { "true" } else { "false" };
            let tag = escape_html(&node.tag);
            format!(
                r#"<button data-node-tag="{tag}" aria-pressed="{selected}" onclick="postSelectNode(this.dataset.nodeTag)">{tag}</button>"#
            )
        })
        .collect::<Vec<_>>()
        .join("")
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
        DesktopDependencyReport, DesktopFirstRunReport, DesktopNodeSummary, DesktopShellState,
        DesktopStatusSnapshot, DesktopSubscriptionSummary, DesktopSubscriptionUpdateSummary,
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
    fn subscription_ipc_html_includes_config_import_controls() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("id=\"subscription-config\""));
        assert!(html.contains("import-subscription-config"));
        assert!(html.contains("set-traffic-mode"));
        assert!(html.contains("select-node"));
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
            },
        };

        let script = subscription_url_update_status_script(&summary)
            .expect("subscription URL update script");

        assert!(script.contains("window.keliSetSubscriptionUrlUpdate"));
        assert!(script.contains("selected-outbound-preserved"));
        assert!(!script.contains("token=secret"));
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
    fn support_export_html_includes_export_button_and_status() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("export-support-bundle"));
        assert!(html.contains("id=\"support-export-status\""));
        assert!(html.contains("window.keliSetSupportExport"));
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
