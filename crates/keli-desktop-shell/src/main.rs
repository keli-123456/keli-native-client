mod actions;
mod html;
mod support;

use std::error::Error;

use actions::{ipc_event_for_message, tray_event_for_id, DesktopShellUiEvent};
use html::{
    operation_status_script, render_shell_html, shell_snapshot_script,
    subscription_config_import_failure_status_script, subscription_config_import_status_script,
    subscription_url_import_failure_status_script, subscription_url_import_status_script,
    subscription_url_update_failure_status_script, subscription_url_update_status_script,
    support_export_status_script, wintun_install_failure_status_script,
    wintun_install_status_script,
};
use keli_desktop::{
    DesktopRunState, DesktopShellAction, DesktopShellController, DesktopShellControllerError,
    DesktopShellState,
};
use single_instance::SingleInstance;
use support::{default_support_export_dir, write_support_bundle_export};
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem},
    Icon, TrayIconBuilder,
};
use wry::{http::Request, WebView, WebViewBuilder};

#[derive(Debug)]
enum UserEvent {
    TrayMenu(String),
    Ipc(String),
}

fn main() -> Result<(), Box<dyn Error>> {
    if is_smoke_mode(std::env::args()) {
        return run_smoke();
    }

    let instance = SingleInstance::new("keli-native-client-desktop-shell")?;
    if !instance.is_single() {
        return Ok(());
    }

    let mut controller = DesktopShellController::new_native();
    let initial_html = render_shell_html(controller.snapshot());
    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let window = WindowBuilder::new()
        .with_title("Keli")
        .with_inner_size(LogicalSize::new(760.0, 560.0))
        .with_min_inner_size(LogicalSize::new(420.0, 480.0))
        .build(&event_loop)?;
    let ipc_proxy = event_loop.create_proxy();
    let webview = WebViewBuilder::new()
        .with_html(initial_html)
        .with_ipc_handler(move |request: Request<String>| {
            let _ = ipc_proxy.send_event(UserEvent::Ipc(request.body().to_string()));
        })
        .build(&window)?;
    let menu_proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        let _ = menu_proxy.send_event(UserEvent::TrayMenu(event.id().as_ref().to_string()));
    }));
    let tray_menu = build_tray_menu(controller.snapshot())?;
    let tray_icon = TrayIconBuilder::new()
        .with_tooltip("Keli")
        .with_icon(app_icon()?)
        .with_menu(Box::new(tray_menu))
        .build()?;
    let tray_icon = Some(tray_icon);

    event_loop.run(move |event, _, control_flow| {
        let _keep_tray_icon_alive = &tray_icon;
        *control_flow = ControlFlow::Wait;

        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                window.set_visible(false);
                let _ = controller.dispatch(DesktopShellAction::HideMainWindow);
            }
            Event::UserEvent(UserEvent::TrayMenu(id)) => {
                if let Some(event) = tray_event_for_id(&id, controller.snapshot()) {
                    handle_ui_event(&mut controller, event, &webview, &window, control_flow);
                }
            }
            Event::UserEvent(UserEvent::Ipc(message)) => {
                if let Some(event) = ipc_event_for_message(&message, controller.snapshot()) {
                    handle_ui_event(&mut controller, event, &webview, &window, control_flow);
                }
            }
            _ => {}
        }
    });
}

fn build_tray_menu(shell: &keli_desktop::DesktopShellState) -> Result<Menu, Box<dyn Error>> {
    let menu = Menu::new();
    for item in &shell.tray_menu.items {
        let menu_item = MenuItem::with_id(item.id.clone(), item.label.as_str(), item.enabled, None);
        menu.append(&menu_item)?;
    }
    Ok(menu)
}

fn handle_ui_event(
    controller: &mut DesktopShellController<keli_desktop::DesktopNativeCommandService>,
    event: DesktopShellUiEvent,
    webview: &WebView,
    window: &tao::window::Window,
    control_flow: &mut ControlFlow,
) {
    if let DesktopShellUiEvent::ImportSubscriptionConfig(config_text) = &event {
        match import_subscription_config(controller, config_text.clone(), webview) {
            Ok(shell) => {
                window.set_visible(shell.window.main_visible);
                sync_webview(webview, &shell);
                if shell.quit_requested {
                    *control_flow = ControlFlow::Exit;
                }
            }
            Err(message) => {
                eprintln!("desktop shell subscription config import failed: {message}");
                sync_subscription_config_import_failure(webview, &message);
                sync_webview(webview, controller.snapshot());
            }
        }
        return;
    }

    if let DesktopShellUiEvent::ImportSubscriptionUrl(url) = &event {
        match import_subscription_url(controller, url.clone(), webview) {
            Ok(shell) => {
                window.set_visible(shell.window.main_visible);
                sync_webview(webview, &shell);
                if shell.quit_requested {
                    *control_flow = ControlFlow::Exit;
                }
            }
            Err(message) => {
                eprintln!("desktop shell subscription URL import failed: {message}");
                sync_subscription_url_import_failure(webview, &message);
                sync_webview(webview, controller.snapshot());
                sync_operation_status(webview, "error", &message);
            }
        }
        return;
    }

    if let DesktopShellUiEvent::UpdateSubscriptionUrl(url) = &event {
        match update_subscription_url(controller, url.clone(), webview) {
            Ok(shell) => {
                window.set_visible(shell.window.main_visible);
                sync_webview(webview, &shell);
                if shell.quit_requested {
                    *control_flow = ControlFlow::Exit;
                }
            }
            Err(message) => {
                eprintln!("desktop shell subscription URL update failed: {message}");
                sync_subscription_url_update_failure(webview, &message);
                sync_webview(webview, controller.snapshot());
                sync_operation_status(webview, "error", &message);
            }
        }
        return;
    }

    if matches!(event, DesktopShellUiEvent::ExportSupportBundle) {
        match export_support_bundle(controller, webview) {
            Ok(shell) => {
                window.set_visible(shell.window.main_visible);
                sync_webview(webview, &shell);
                if shell.quit_requested {
                    *control_flow = ControlFlow::Exit;
                }
            }
            Err(message) => {
                eprintln!("desktop shell support export failed: {message}");
                sync_webview(webview, controller.snapshot());
                sync_operation_status(webview, "error", &message);
            }
        }
        return;
    }

    if let DesktopShellUiEvent::InstallWintunPath(path) = &event {
        match install_wintun_path(controller, path.clone(), webview) {
            Ok(shell) => {
                window.set_visible(shell.window.main_visible);
                sync_webview(webview, &shell);
                if shell.quit_requested {
                    *control_flow = ControlFlow::Exit;
                }
            }
            Err(message) => {
                eprintln!("desktop shell Wintun install failed: {message}");
                sync_wintun_install_failure(webview, path, &message);
                sync_webview(webview, controller.snapshot());
            }
        }
        return;
    }

    if let DesktopShellUiEvent::DependencyAction(action) = &event {
        let operation_status = match open_dependency_action(action) {
            Ok(()) => (
                "success",
                operation_success_message(&event)
                    .unwrap_or_else(|| format!("Dependency action opened: {action}")),
            ),
            Err(message) => {
                eprintln!("desktop shell dependency action failed: {message}");
                ("error", message)
            }
        };
        let shell = controller.refresh();
        window.set_visible(shell.window.main_visible);
        sync_webview(webview, &shell);
        sync_operation_status(webview, operation_status.0, &operation_status.1);
        if shell.quit_requested {
            *control_flow = ControlFlow::Exit;
        }
        return;
    }

    let operation_success = operation_success_message(&event);
    match dispatch_ui_event(controller, event) {
        Ok(shell) => {
            window.set_visible(shell.window.main_visible);
            sync_webview(webview, &shell);
            if let Some(message) = operation_success.as_deref() {
                sync_operation_status(webview, "success", message);
            }
            if shell.quit_requested {
                *control_flow = ControlFlow::Exit;
            }
        }
        Err(error) => {
            let message = format!("{} {} {}", error.operation, error.kind, error.message);
            eprintln!("desktop shell action failed: {message}");
            sync_webview(webview, controller.snapshot());
            sync_operation_status(webview, "error", &message);
        }
    }
}

fn dispatch_ui_event(
    controller: &mut DesktopShellController<keli_desktop::DesktopNativeCommandService>,
    event: DesktopShellUiEvent,
) -> Result<DesktopShellState, DesktopShellControllerError> {
    match event {
        DesktopShellUiEvent::Action(action) => controller.dispatch(action),
        DesktopShellUiEvent::Refresh => Ok(controller.refresh()),
        DesktopShellUiEvent::RefreshNodeHealth => controller.refresh_node_health(),
        DesktopShellUiEvent::ImportSubscriptionConfig(config_text) => {
            controller.import_subscription_config(config_text)
        }
        DesktopShellUiEvent::ImportSubscriptionUrl(_) => Ok(controller.refresh()),
        DesktopShellUiEvent::UpdateSubscriptionUrl(_) => Ok(controller.refresh()),
        DesktopShellUiEvent::SelectNode(outbound_tag) => controller.select_node(outbound_tag),
        DesktopShellUiEvent::SetTrafficMode(traffic_mode) => {
            Ok(controller.set_traffic_mode(traffic_mode))
        }
        DesktopShellUiEvent::ExportSupportBundle => Ok(controller.refresh()),
        DesktopShellUiEvent::DependencyAction(_) => Ok(controller.refresh()),
        DesktopShellUiEvent::InstallWintunPath(_) => Ok(controller.refresh()),
    }
}

fn import_subscription_config(
    controller: &mut DesktopShellController<keli_desktop::DesktopNativeCommandService>,
    config_text: String,
    webview: &WebView,
) -> Result<DesktopShellState, String> {
    let shell = controller
        .import_subscription_config(config_text)
        .map_err(|error| format!("{} {} {}", error.operation, error.kind, error.message))?;
    if let Some(subscription) = shell.subscription.as_ref() {
        let script = subscription_config_import_status_script(subscription).map_err(|error| {
            format!("subscription config import status serialization failed: {error}")
        })?;
        webview
            .evaluate_script(&script)
            .map_err(|error| format!("subscription config import status sync failed: {error}"))?;
    }
    Ok(shell)
}

fn sync_subscription_config_import_failure(webview: &WebView, message: &str) {
    match subscription_config_import_failure_status_script(message) {
        Ok(script) => {
            if let Err(error) = webview.evaluate_script(&script) {
                eprintln!("subscription config import failure status sync failed: {error}");
            }
        }
        Err(error) => {
            eprintln!("subscription config import failure status serialization failed: {error}");
        }
    }
}

fn sync_subscription_url_import_failure(webview: &WebView, message: &str) {
    match subscription_url_import_failure_status_script(message) {
        Ok(script) => {
            if let Err(error) = webview.evaluate_script(&script) {
                eprintln!("subscription URL import failure status sync failed: {error}");
            }
        }
        Err(error) => {
            eprintln!("subscription URL import failure status serialization failed: {error}");
        }
    }
}

fn sync_subscription_url_update_failure(webview: &WebView, message: &str) {
    match subscription_url_update_failure_status_script(message) {
        Ok(script) => {
            if let Err(error) = webview.evaluate_script(&script) {
                eprintln!("subscription URL update failure status sync failed: {error}");
            }
        }
        Err(error) => {
            eprintln!("subscription URL update failure status serialization failed: {error}");
        }
    }
}

fn import_subscription_url(
    controller: &mut DesktopShellController<keli_desktop::DesktopNativeCommandService>,
    url: String,
    webview: &WebView,
) -> Result<DesktopShellState, String> {
    let imported = controller
        .import_subscription_url(url)
        .map_err(|error| format!("{} {} {}", error.operation, error.kind, error.message))?;
    let script = subscription_url_import_status_script(&imported)
        .map_err(|error| format!("subscription URL import status serialization failed: {error}"))?;
    webview
        .evaluate_script(&script)
        .map_err(|error| format!("subscription URL import status sync failed: {error}"))?;
    Ok(controller.refresh())
}

fn update_subscription_url(
    controller: &mut DesktopShellController<keli_desktop::DesktopNativeCommandService>,
    url: String,
    webview: &WebView,
) -> Result<DesktopShellState, String> {
    let updated = controller
        .update_subscription_url(url)
        .map_err(|error| format!("{} {} {}", error.operation, error.kind, error.message))?;
    let script = subscription_url_update_status_script(&updated)
        .map_err(|error| format!("subscription URL update status serialization failed: {error}"))?;
    webview
        .evaluate_script(&script)
        .map_err(|error| format!("subscription URL update status sync failed: {error}"))?;
    Ok(controller.refresh())
}

fn export_support_bundle(
    controller: &mut DesktopShellController<keli_desktop::DesktopNativeCommandService>,
    webview: &WebView,
) -> Result<DesktopShellState, String> {
    let export = controller
        .export_support_bundle()
        .map_err(|error| format!("{} {} {}", error.operation, error.kind, error.message))?;
    let summary = write_support_bundle_export(&export, default_support_export_dir())
        .map_err(|error| format!("write support bundle failed: {error}"))?;
    let script = support_export_status_script(&summary)
        .map_err(|error| format!("support export status serialization failed: {error}"))?;
    webview
        .evaluate_script(&script)
        .map_err(|error| format!("support export status sync failed: {error}"))?;
    Ok(controller.refresh())
}

fn install_wintun_path(
    controller: &mut DesktopShellController<keli_desktop::DesktopNativeCommandService>,
    source_path: String,
    webview: &WebView,
) -> Result<DesktopShellState, String> {
    let installed = controller
        .install_wintun_from_path(source_path)
        .map_err(|error| format!("{} {} {}", error.operation, error.kind, error.message))?;
    let script = wintun_install_status_script(&installed)
        .map_err(|error| format!("Wintun install status serialization failed: {error}"))?;
    webview
        .evaluate_script(&script)
        .map_err(|error| format!("Wintun install status sync failed: {error}"))?;
    Ok(controller.refresh())
}

fn sync_wintun_install_failure(webview: &WebView, source_path: &str, message: &str) {
    match wintun_install_failure_status_script(source_path, message) {
        Ok(script) => {
            if let Err(error) = webview.evaluate_script(&script) {
                eprintln!("Wintun install failure status sync failed: {error}");
            }
        }
        Err(error) => {
            eprintln!("Wintun install failure status serialization failed: {error}");
        }
    }
}

fn sync_operation_status(webview: &WebView, kind: &str, message: &str) {
    match operation_status_script(kind, message) {
        Ok(script) => {
            if let Err(error) = webview.evaluate_script(&script) {
                eprintln!("operation status sync failed: {error}");
            }
        }
        Err(error) => {
            eprintln!("operation status serialization failed: {error}");
        }
    }
}

fn sync_webview(webview: &WebView, shell: &DesktopShellState) {
    match shell_snapshot_script(shell) {
        Ok(script) => {
            if let Err(error) = webview.evaluate_script(&script) {
                eprintln!("desktop shell snapshot sync failed: {error}");
            }
        }
        Err(error) => {
            eprintln!("desktop shell snapshot serialization failed: {error}");
        }
    }
}

fn operation_success_message(event: &DesktopShellUiEvent) -> Option<String> {
    match event {
        DesktopShellUiEvent::Action(DesktopShellAction::RequestStart) => {
            Some("Start requested".to_string())
        }
        DesktopShellUiEvent::Action(DesktopShellAction::RequestStop) => {
            Some("Stop requested".to_string())
        }
        DesktopShellUiEvent::Refresh => Some("Status refreshed".to_string()),
        DesktopShellUiEvent::RefreshNodeHealth => Some("Node health refreshed".to_string()),
        DesktopShellUiEvent::SelectNode(outbound_tag) => {
            Some(format!("Selected node {outbound_tag}"))
        }
        DesktopShellUiEvent::SetTrafficMode(traffic_mode) => Some(format!(
            "Traffic mode set to {}",
            traffic_mode_label(*traffic_mode)
        )),
        DesktopShellUiEvent::DependencyAction(action) => {
            Some(format!("Dependency action opened: {action}"))
        }
        _ => None,
    }
}

fn traffic_mode_label(traffic_mode: keli_desktop::DesktopTrafficMode) -> &'static str {
    match traffic_mode {
        keli_desktop::DesktopTrafficMode::SystemProxy => "System proxy",
        keli_desktop::DesktopTrafficMode::Tun => "TUN",
        keli_desktop::DesktopTrafficMode::MixedInboundOnly => "Local inbound",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DependencyActionLaunchTarget {
    target: &'static str,
}

fn dependency_action_launch_target(action: &str) -> Option<DependencyActionLaunchTarget> {
    match action {
        "check-system-proxy" => Some(DependencyActionLaunchTarget {
            target: "ms-settings:network-proxy",
        }),
        "install-wintun" | "check-tun" => Some(DependencyActionLaunchTarget {
            target: "https://www.wintun.net/",
        }),
        _ => None,
    }
}

fn open_dependency_action(action: &str) -> Result<(), String> {
    let target = dependency_action_launch_target(action)
        .ok_or_else(|| format!("unknown dependency action: {action}"))?;
    open_launch_target(target.target).map_err(|error| format!("open {}: {error}", target.target))
}

fn open_launch_target(target: &str) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", target])
            .spawn()?;
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(target).spawn()?;
        return Ok(());
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open").arg(target).spawn()?;
        return Ok(());
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", unix)))]
    {
        let _ = target;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "opening dependency action targets is unsupported on this platform",
        ))
    }
}

fn app_icon() -> Result<Icon, Box<dyn Error>> {
    const SIZE: u32 = 16;
    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let border = x == 0 || y == 0 || x == SIZE - 1 || y == SIZE - 1;
            if border {
                rgba.extend_from_slice(&[23, 26, 31, 255]);
            } else if x >= 5 && x <= 10 && y >= 4 && y <= 11 {
                rgba.extend_from_slice(&[39, 125, 86, 255]);
            } else {
                rgba.extend_from_slice(&[238, 243, 247, 255]);
            }
        }
    }
    Ok(Icon::from_rgba(rgba, SIZE, SIZE)?)
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct DesktopShellSmokeReport {
    status: String,
    native_core_default: bool,
    run_state: DesktopRunState,
    traffic_mode: keli_desktop::DesktopTrafficMode,
    primary_action_id: String,
    can_start: bool,
    dependency_blocker_count: usize,
    html_ready: bool,
    snapshot_script_ready: bool,
}

fn is_smoke_mode<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .skip(1)
        .any(|arg| arg.as_ref() == "--smoke")
}

fn run_smoke() -> Result<(), Box<dyn Error>> {
    let controller = DesktopShellController::new_native();
    let snapshot = controller.snapshot();
    let html = render_shell_html(snapshot);
    let script = shell_snapshot_script(snapshot)?;
    let report = build_smoke_report(snapshot, &html, &script);
    let passed = report.status == "passed";

    println!("{}", serde_json::to_string_pretty(&report)?);

    if passed {
        Ok(())
    } else {
        Err("desktop shell smoke report failed".into())
    }
}

fn build_smoke_report(
    snapshot: &DesktopShellState,
    html: &str,
    snapshot_script: &str,
) -> DesktopShellSmokeReport {
    let html_ready = html.contains("id=\"run-state\"")
        && html.contains("id=\"primary-button\"")
        && html.contains("id=\"subscription-url\"")
        && html.contains("id=\"dependency-summary\"")
        && html.contains("id=\"dependency-actions\"")
        && html.contains("id=\"wintun-source-path\"");
    let snapshot_script_ready =
        snapshot_script.contains("window.keliSetShell") && snapshot_script.contains("\"status\"");
    let status = if html_ready && snapshot_script_ready {
        "passed"
    } else {
        "failed"
    };

    DesktopShellSmokeReport {
        status: status.to_string(),
        native_core_default: true,
        run_state: snapshot.status.run_state,
        traffic_mode: snapshot.status.traffic_mode,
        primary_action_id: snapshot.primary_action.id.clone(),
        can_start: snapshot.can_start,
        dependency_blocker_count: snapshot.dependencies.first_run.blockers.len(),
        html_ready,
        snapshot_script_ready,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keli_desktop::{
        DesktopDependencyReport, DesktopFirstRunReport, DesktopRunState, DesktopShellState,
        DesktopStatusSnapshot, DesktopSystemProxyDependency, DesktopTrafficMode,
        DesktopTunBackendDependency,
    };

    fn smoke_snapshot() -> DesktopShellState {
        DesktopShellState::new(
            DesktopStatusSnapshot {
                run_state: DesktopRunState::Stopped,
                traffic_mode: DesktopTrafficMode::SystemProxy,
                selected_outbound: Some("SS-READY".to_string()),
                listen: Some("127.0.0.1:7890".to_string()),
                generation: 1,
                event_count: 0,
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

    #[test]
    fn smoke_arg_detection_accepts_smoke_flag() {
        assert!(is_smoke_mode(["keli-desktop-shell", "--smoke"]));
        assert!(!is_smoke_mode(["keli-desktop-shell"]));
    }

    #[test]
    fn smoke_report_confirms_shell_rendering_contract() {
        let snapshot = smoke_snapshot();
        let html = render_shell_html(&snapshot);
        let script = shell_snapshot_script(&snapshot).expect("snapshot script");

        let report = build_smoke_report(&snapshot, &html, &script);

        assert_eq!(report.status, "passed");
        assert!(report.native_core_default);
        assert!(report.html_ready);
        assert!(report.snapshot_script_ready);
        assert!(html.contains("id=\"dependency-actions\""));
        assert!(html.contains("id=\"wintun-source-path\""));
    }

    #[test]
    fn smoke_report_requires_dependency_action_container() {
        let snapshot = smoke_snapshot();
        let html = render_shell_html(&snapshot).replace(
            "id=\"dependency-actions\"",
            "id=\"missing-dependency-actions\"",
        );
        let script = shell_snapshot_script(&snapshot).expect("snapshot script");

        let report = build_smoke_report(&snapshot, &html, &script);

        assert_eq!(report.status, "failed");
        assert!(!report.html_ready);
    }

    #[test]
    fn smoke_report_requires_wintun_install_controls() {
        let snapshot = smoke_snapshot();
        let html = render_shell_html(&snapshot).replace(
            "id=\"wintun-source-path\"",
            "id=\"missing-wintun-source-path\"",
        );
        let script = shell_snapshot_script(&snapshot).expect("snapshot script");

        let report = build_smoke_report(&snapshot, &html, &script);

        assert_eq!(report.status, "failed");
        assert!(!report.html_ready);
    }

    #[test]
    fn operation_success_message_covers_generic_actions() {
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::Refresh).as_deref(),
            Some("Status refreshed")
        );
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::RefreshNodeHealth).as_deref(),
            Some("Node health refreshed")
        );
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::Action(
                DesktopShellAction::RequestStart
            ))
            .as_deref(),
            Some("Start requested")
        );
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::Action(
                DesktopShellAction::RequestStop
            ))
            .as_deref(),
            Some("Stop requested")
        );
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::SelectNode("SS-READY".to_string()))
                .as_deref(),
            Some("Selected node SS-READY")
        );
    }

    #[test]
    fn operation_success_message_covers_mode_and_dependency_actions() {
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::SetTrafficMode(
                DesktopTrafficMode::Tun
            ))
            .as_deref(),
            Some("Traffic mode set to TUN")
        );
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::DependencyAction(
                "install-wintun".to_string()
            ))
            .as_deref(),
            Some("Dependency action opened: install-wintun")
        );
    }

    #[test]
    fn wintun_install_failure_script_preserves_source_path_and_error() {
        let script = wintun_install_failure_status_script(
            "C:\\Downloads\\missing-wintun.dll",
            "install-wintun dependency Platform(\"Wintun source DLL was not found\")",
        )
        .expect("failure script");

        assert!(script.contains("missing-wintun.dll"));
        assert!(script.contains("Wintun source DLL was not found"));
    }

    #[test]
    fn subscription_config_import_failure_script_preserves_error() {
        let script = subscription_config_import_failure_status_script(
            "import-subscription client InvalidSubscription",
        )
        .expect("failure script");

        assert!(script.contains("InvalidSubscription"));
    }

    #[test]
    fn dependency_action_launch_targets_are_fixed_and_safe() {
        assert_eq!(
            dependency_action_launch_target("check-system-proxy").map(|target| target.target),
            Some("ms-settings:network-proxy")
        );
        assert_eq!(
            dependency_action_launch_target("install-wintun").map(|target| target.target),
            Some("https://www.wintun.net/")
        );
        assert_eq!(
            dependency_action_launch_target("check-tun").map(|target| target.target),
            Some("https://www.wintun.net/")
        );
        assert!(dependency_action_launch_target("unknown").is_none());
    }
}
