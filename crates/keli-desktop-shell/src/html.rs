use keli_desktop::{DesktopRunState, DesktopShellState, DesktopTrafficMode};

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
      <span class="pill">{run_state}</span>
    </header>
    <div class="grid">
      <section>
        <h2>Mode</h2>
        <div class="value">{traffic_mode}</div>
        <div class="muted">{listen}</div>
      </section>
      <section>
        <h2>Node</h2>
        <div class="value">{selected}</div>
        <div class="muted">Generation {generation}, events {events}</div>
      </section>
      <section>
        <h2>Primary</h2>
        <div class="value">{primary_label}</div>
        <div class="muted">{primary_state}</div>
      </section>
      <section>
        <h2>Tray</h2>
        <div class="value">{tray_ids}</div>
        <div class="muted">Window visible: {window_visible}</div>
      </section>
    </div>
    <pre>{snapshot_json}</pre>
  </main>
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
        tray_ids = escape_html(&tray_ids),
        window_visible = snapshot.window.main_visible,
        snapshot_json = escape_html(&snapshot_json),
    )
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
        DesktopDependencyReport, DesktopFirstRunReport, DesktopShellState, DesktopStatusSnapshot,
        DesktopSystemProxyDependency, DesktopTrafficMode, DesktopTunBackendDependency,
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

    #[test]
    fn shell_html_includes_snapshot_state_and_tray_ids() {
        let html = render_shell_html(&snapshot());

        assert!(html.contains("Keli"));
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
}
