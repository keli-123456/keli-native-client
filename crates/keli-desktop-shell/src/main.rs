mod actions;
mod html;
mod settings;
mod support;

use std::error::Error;
use std::fs;
use std::path::Path;

use actions::{ipc_event_for_message, tray_event_for_id, DesktopShellUiEvent};
use html::{
    desktop_settings_status_script, operation_status_script, render_shell_html,
    shell_snapshot_script, subscription_config_import_failure_status_script,
    subscription_config_import_status_script, subscription_url_import_failure_status_script,
    subscription_url_import_status_script, subscription_url_update_failure_status_script,
    subscription_url_update_status_script, support_export_cleanup_status_script,
    support_export_failure_status_script, support_export_status_script,
    support_export_storage_status_script, wintun_install_failure_status_script,
    wintun_install_status_script,
};
use keli_desktop::{
    DesktopNativeCommandService, DesktopPersistedSubscription, DesktopRunState, DesktopShellAction,
    DesktopShellController, DesktopShellControllerError, DesktopShellState,
    DesktopSubscriptionStore,
};
use settings::{
    default_desktop_shell_settings_path, read_desktop_shell_settings, write_desktop_shell_settings,
    DesktopShellSettings, DesktopShellSettingsSaveSummary,
};
use single_instance::SingleInstance;
use support::{
    clear_support_export_directory, default_support_export_dir, read_last_support_bundle_export,
    summarize_support_export_directory, write_support_bundle_export,
};
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

const STARTUP_RESTORE_SMOKE_SELECTED_OUTBOUND: &str = "SS-RESTORED";

fn main() -> Result<(), Box<dyn Error>> {
    if is_support_export_smoke_mode(std::env::args()) {
        return run_support_export_smoke();
    }
    if is_startup_connect_support_smoke_mode(std::env::args()) {
        return run_startup_connect_support_smoke();
    }
    if is_startup_connect_smoke_mode(std::env::args()) {
        return run_startup_connect_smoke();
    }
    if is_startup_restore_smoke_mode(std::env::args()) {
        return run_startup_restore_smoke();
    }
    if is_smoke_mode(std::env::args()) {
        return run_smoke();
    }

    let instance = SingleInstance::new("keli-native-client-desktop-shell")?;
    if !instance.is_single() {
        return Ok(());
    }

    let settings = load_desktop_settings();
    let mut controller = DesktopShellController::new_native();
    let initial_shell = match apply_desktop_startup_settings(&mut controller, &settings) {
        Ok(shell) => shell,
        Err(error) => {
            eprintln!(
                "desktop shell auto-start failed: {} {} {}",
                error.operation, error.kind, error.message
            );
            controller.refresh()
        }
    };
    let initial_html = render_shell_html(&initial_shell);
    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let window = WindowBuilder::new()
        .with_title("Keli")
        .with_inner_size(LogicalSize::new(1180.0, 760.0))
        .with_min_inner_size(LogicalSize::new(860.0, 620.0))
        .build(&event_loop)?;
    let ipc_proxy = event_loop.create_proxy();
    let webview = WebViewBuilder::new()
        .with_html(initial_html)
        .with_ipc_handler(move |request: Request<String>| {
            let _ = ipc_proxy.send_event(UserEvent::Ipc(request.body().to_string()));
        })
        .build(&window)?;
    sync_desktop_settings(&webview, &settings);
    sync_last_support_export(&webview);
    sync_support_export_storage(&webview);
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
                sync_support_export_failure(webview, &message);
                sync_webview(webview, controller.snapshot());
                sync_operation_status(webview, "error", &message);
            }
        }
        return;
    }

    if matches!(event, DesktopShellUiEvent::OpenSupportExportDirectory) {
        let operation_status = match open_support_export_directory() {
            Ok(()) => ("success", "已打开支持包目录".to_string()),
            Err(message) => {
                eprintln!("desktop shell open support export directory failed: {message}");
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

    if matches!(event, DesktopShellUiEvent::ClearSupportExports) {
        let operation_status = match clear_support_exports(webview) {
            Ok(()) => ("success", "已清理旧支持包".to_string()),
            Err(message) => {
                eprintln!("desktop shell support cleanup failed: {message}");
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
                    .unwrap_or_else(|| format!("已打开依赖操作：{action}")),
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

    if let DesktopShellUiEvent::SaveDesktopSettings(settings) = &event {
        match save_desktop_settings(controller, settings.clone(), webview) {
            Ok(shell) => {
                window.set_visible(shell.window.main_visible);
                sync_webview(webview, &shell);
                sync_operation_status(webview, "success", "设置已保存");
                if shell.quit_requested {
                    *control_flow = ControlFlow::Exit;
                }
            }
            Err(message) => {
                eprintln!("desktop shell settings save failed: {message}");
                sync_webview(webview, controller.snapshot());
                sync_operation_status(webview, "error", &message);
            }
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
        DesktopShellUiEvent::LoadPanelFixture => Ok(controller
            .refresh_panel_snapshot(Some(keli_desktop::DesktopPanelSnapshot::fixture_ready()))),
        DesktopShellUiEvent::RefreshNodeHealth => controller.refresh_node_health(),
        DesktopShellUiEvent::PanelLogin {
            endpoint,
            email,
            password,
        } => controller.connect_panel(endpoint, email, password),
        DesktopShellUiEvent::PanelFetchConfig {
            server_id,
            server_name,
        } => {
            controller.import_panel_session_config(server_id, server_name)?;
            Ok(controller.snapshot().clone())
        }
        DesktopShellUiEvent::ImportSubscriptionConfig(config_text) => {
            controller.import_subscription_config(config_text)
        }
        DesktopShellUiEvent::PanelImportConfig {
            server_id,
            server_name,
            config_text,
        } => {
            controller.import_panel_config(server_id, server_name, config_text)?;
            Ok(controller.snapshot().clone())
        }
        DesktopShellUiEvent::ImportSubscriptionUrl(_) => Ok(controller.refresh()),
        DesktopShellUiEvent::UpdateSubscriptionUrl(_) => Ok(controller.refresh()),
        DesktopShellUiEvent::SelectNode(outbound_tag) => controller.select_node(outbound_tag),
        DesktopShellUiEvent::SetTrafficMode(traffic_mode) => {
            Ok(controller.set_traffic_mode(traffic_mode))
        }
        DesktopShellUiEvent::SaveDesktopSettings(_) => Ok(controller.refresh()),
        DesktopShellUiEvent::ExportSupportBundle => Ok(controller.refresh()),
        DesktopShellUiEvent::OpenSupportExportDirectory => Ok(controller.refresh()),
        DesktopShellUiEvent::ClearSupportExports => Ok(controller.refresh()),
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

fn load_desktop_settings() -> DesktopShellSettings {
    match read_desktop_shell_settings(default_desktop_shell_settings_path()) {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("desktop settings load failed: {error}");
            DesktopShellSettings::default()
        }
    }
}

fn desktop_settings_listen_address(settings: &DesktopShellSettings) -> String {
    format!("127.0.0.1:{}", settings.mixed_port)
}

fn apply_desktop_settings(
    controller: &mut DesktopShellController<keli_desktop::DesktopNativeCommandService>,
    settings: &DesktopShellSettings,
) -> DesktopShellState {
    controller.set_traffic_mode(settings.traffic_mode);
    controller.set_listen(desktop_settings_listen_address(settings))
}

fn desktop_settings_auto_start_action(
    settings: &DesktopShellSettings,
    shell: &DesktopShellState,
) -> Option<DesktopShellAction> {
    if settings.auto_start_core && shell.can_start {
        Some(DesktopShellAction::RequestStart)
    } else {
        None
    }
}

fn apply_desktop_startup_settings(
    controller: &mut DesktopShellController<keli_desktop::DesktopNativeCommandService>,
    settings: &DesktopShellSettings,
) -> Result<DesktopShellState, DesktopShellControllerError> {
    let shell = apply_desktop_settings(controller, settings);
    if let Some(action) = desktop_settings_auto_start_action(settings, &shell) {
        controller.dispatch(action)
    } else {
        Ok(shell)
    }
}

fn sync_desktop_settings(webview: &WebView, settings: &DesktopShellSettings) {
    let summary = DesktopShellSettingsSaveSummary {
        status: "restored".to_string(),
        path: default_desktop_shell_settings_path()
            .to_string_lossy()
            .into_owned(),
        settings: settings.clone(),
    };
    match desktop_settings_status_script(&summary) {
        Ok(script) => {
            if let Err(error) = webview.evaluate_script(&script) {
                eprintln!("desktop settings restore sync failed: {error}");
            }
        }
        Err(error) => {
            eprintln!("desktop settings restore serialization failed: {error}");
        }
    }
}

fn save_desktop_settings(
    controller: &mut DesktopShellController<keli_desktop::DesktopNativeCommandService>,
    settings: DesktopShellSettings,
    webview: &WebView,
) -> Result<DesktopShellState, String> {
    let summary = write_desktop_shell_settings(default_desktop_shell_settings_path(), &settings)
        .map_err(|error| format!("write desktop settings failed: {error}"))?;
    let shell = apply_desktop_settings(controller, &settings);
    let script = desktop_settings_status_script(&summary)
        .map_err(|error| format!("desktop settings status serialization failed: {error}"))?;
    webview
        .evaluate_script(&script)
        .map_err(|error| format!("desktop settings status sync failed: {error}"))?;
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

fn sync_support_export_failure(webview: &WebView, message: &str) {
    match support_export_failure_status_script(message) {
        Ok(script) => {
            if let Err(error) = webview.evaluate_script(&script) {
                eprintln!("support export failure status sync failed: {error}");
            }
        }
        Err(error) => {
            eprintln!("support export failure status serialization failed: {error}");
        }
    }
}

fn sync_last_support_export(webview: &WebView) {
    match read_last_support_bundle_export(default_support_export_dir()) {
        Ok(Some(summary)) => match support_export_status_script(&summary) {
            Ok(script) => {
                if let Err(error) = webview.evaluate_script(&script) {
                    eprintln!("last support export restore sync failed: {error}");
                }
            }
            Err(error) => {
                eprintln!("last support export restore serialization failed: {error}");
            }
        },
        Ok(None) => {}
        Err(error) => {
            eprintln!("last support export restore read failed: {error}");
        }
    }
}

fn sync_support_export_storage(webview: &WebView) {
    match summarize_support_export_directory(default_support_export_dir()) {
        Ok(summary) => match support_export_storage_status_script(&summary) {
            Ok(script) => {
                if let Err(error) = webview.evaluate_script(&script) {
                    eprintln!("support export storage sync failed: {error}");
                }
            }
            Err(error) => {
                eprintln!("support export storage serialization failed: {error}");
            }
        },
        Err(error) => {
            eprintln!("support export storage summary failed: {error}");
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
    sync_support_export_storage(webview);
    Ok(controller.refresh())
}

fn clear_support_exports(webview: &WebView) -> Result<(), String> {
    let summary = clear_support_export_directory(default_support_export_dir())
        .map_err(|error| format!("clear support exports failed: {error}"))?;
    let script = support_export_cleanup_status_script(&summary)
        .map_err(|error| format!("support cleanup status serialization failed: {error}"))?;
    webview
        .evaluate_script(&script)
        .map_err(|error| format!("support cleanup status sync failed: {error}"))
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
            Some("已请求启动".to_string())
        }
        DesktopShellUiEvent::Action(DesktopShellAction::RequestStop) => {
            Some("已请求停止".to_string())
        }
        DesktopShellUiEvent::Refresh => Some("状态已刷新".to_string()),
        DesktopShellUiEvent::LoadPanelFixture => Some("已加载面板示例数据".to_string()),
        DesktopShellUiEvent::RefreshNodeHealth => Some("节点健康已刷新".to_string()),
        DesktopShellUiEvent::PanelLogin { .. } => {
            Some("面板登录成功，已同步全部节点配置".to_string())
        }
        DesktopShellUiEvent::PanelFetchConfig { server_name, .. } => {
            Some(format!("已拉取并导入面板节点配置：{server_name}"))
        }
        DesktopShellUiEvent::PanelImportConfig { server_name, .. } => {
            Some(format!("已导入面板节点配置：{server_name}"))
        }
        DesktopShellUiEvent::SelectNode(outbound_tag) => Some(format!("已应用节点 {outbound_tag}")),
        DesktopShellUiEvent::SetTrafficMode(traffic_mode) => Some(format!(
            "流量模式已切换为 {}",
            traffic_mode_label(*traffic_mode)
        )),
        DesktopShellUiEvent::DependencyAction(action) => Some(format!("已打开依赖操作：{action}")),
        _ => None,
    }
}

fn traffic_mode_label(traffic_mode: keli_desktop::DesktopTrafficMode) -> &'static str {
    match traffic_mode {
        keli_desktop::DesktopTrafficMode::SystemProxy => "系统代理",
        keli_desktop::DesktopTrafficMode::Tun => "TUN",
        keli_desktop::DesktopTrafficMode::MixedInboundOnly => "本地入站",
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

fn open_support_export_directory() -> Result<(), String> {
    let directory = default_support_export_dir();
    fs::create_dir_all(&directory)
        .map_err(|error| format!("create support export dir {}: {error}", directory.display()))?;
    open_directory_target(&directory)
        .map_err(|error| format!("open support export dir {}: {error}", directory.display()))
}

fn open_directory_target(directory: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer.exe")
            .arg(directory)
            .spawn()?;
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(directory).spawn()?;
        return Ok(());
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(directory)
            .spawn()?;
        return Ok(());
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", unix)))]
    {
        let _ = directory;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "opening support export directory is unsupported on this platform",
        ))
    }
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
struct DesktopShellSmokeBlocker {
    code: String,
    message: String,
    action: Option<String>,
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
    first_run_system_proxy_ready: bool,
    first_run_tun_ready: bool,
    first_run_blockers: Vec<DesktopShellSmokeBlocker>,
    dependency_action_entrypoints: Vec<String>,
    html_ready: bool,
    snapshot_script_ready: bool,
    settings_persistence_ready: bool,
    settings_runtime_ready: bool,
    settings_auto_start_ready: bool,
    ui_workflow_entrypoints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct DesktopShellStartupRestoreSmokeReport {
    status: String,
    restored_subscription: bool,
    restored_selected_outbound: Option<String>,
    runtime_selected_outbound: Option<String>,
    restored_supported_count: usize,
    restored_selected_matches: bool,
    can_start_after_restore: bool,
    primary_action_id: String,
    html_ready: bool,
    snapshot_script_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct DesktopShellStartupConnectSmokeReport {
    status: String,
    run_state: DesktopRunState,
    selected_outbound: Option<String>,
    listen: Option<String>,
    auto_started: bool,
    primary_action_id: String,
    html_ready: bool,
    snapshot_script_ready: bool,
    stopped_after_smoke: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct DesktopShellRunningSupportSmokeReport {
    status: String,
    path: String,
    byte_count: usize,
    format: String,
    support_saved: bool,
    desktop_status_running: bool,
    desktop_status_selected: bool,
    managed_status_selected: bool,
    diagnosis_selected: bool,
    connection_level: Option<String>,
    redaction_ready: bool,
    last_record_matches: bool,
    stopped_after_smoke: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct DesktopShellSupportExportSmokeReport {
    status: String,
    path: String,
    byte_count: usize,
    format: String,
    kind: String,
    desktop_dependencies: bool,
    core_support_bundle: bool,
    last_record_matches: bool,
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

fn is_support_export_smoke_mode<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .skip(1)
        .any(|arg| arg.as_ref() == "--support-export-smoke")
}

fn is_startup_restore_smoke_mode<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .skip(1)
        .any(|arg| arg.as_ref() == "--startup-restore-smoke")
}

fn is_startup_connect_smoke_mode<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .skip(1)
        .any(|arg| arg.as_ref() == "--startup-connect-smoke")
}

fn is_startup_connect_support_smoke_mode<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    args.into_iter()
        .skip(1)
        .any(|arg| arg.as_ref() == "--startup-connect-support-smoke")
}

fn support_export_smoke_dir_arg<I, S>(args: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = args.into_iter().skip(1);
    while let Some(arg) = args.next() {
        if arg.as_ref() == "--support-export-smoke" {
            return args.next().map(|value| value.as_ref().to_string());
        }
    }
    None
}

fn run_startup_connect_support_smoke() -> Result<(), Box<dyn Error>> {
    let store_path = startup_restore_smoke_store_path();
    let support_dir = startup_connect_support_smoke_dir();
    let store = DesktopSubscriptionStore::new(&store_path);
    store.save(&DesktopPersistedSubscription {
        config_text: startup_restore_smoke_config(),
        selected_outbound: Some(STARTUP_RESTORE_SMOKE_SELECTED_OUTBOUND.to_string()),
    })?;

    let mut controller = DesktopShellController::new_with_subscription_store(
        DesktopNativeCommandService::new(),
        store,
    );
    let started_shell =
        apply_desktop_startup_settings(&mut controller, &startup_connect_smoke_settings())
            .map_err(|error| format!("{} {} {}", error.operation, error.kind, error.message))?;
    let support_export_result: Result<
        (
            String,
            support::SupportBundleSaveSummary,
            String,
            serde_json::Value,
            bool,
        ),
        String,
    > = (|| {
        let export = controller
            .export_support_bundle()
            .map_err(|error| format!("{} {} {}", error.operation, error.kind, error.message))?;
        let summary = write_support_bundle_export(&export, &support_dir)
            .map_err(|error| format!("write running support bundle failed: {error}"))?;
        let bundle_text = fs::read_to_string(&summary.path)
            .map_err(|error| format!("read running support bundle failed: {error}"))?;
        let bundle: serde_json::Value = serde_json::from_str(&bundle_text)
            .map_err(|error| format!("running support bundle JSON parse failed: {error}"))?;
        let last_record_matches = last_support_export_record_matches(&summary);
        Ok((
            export.format,
            summary,
            bundle_text,
            bundle,
            last_record_matches,
        ))
    })();
    let stopped_after_smoke = stop_smoke_core_if_running(&mut controller, &started_shell);
    let (format, summary, bundle_text, bundle, last_record_matches) = match support_export_result {
        Ok(result) => result,
        Err(message) => {
            cleanup_startup_connect_support_smoke_artifacts(&store_path, &support_dir);
            return Err(message.into());
        }
    };
    let report = build_running_support_smoke_report(
        &summary,
        &format,
        &bundle,
        &bundle_text,
        last_record_matches,
        stopped_after_smoke,
        STARTUP_RESTORE_SMOKE_SELECTED_OUTBOUND,
    );
    let passed = report.status == "passed";

    println!("{}", serde_json::to_string_pretty(&report)?);

    cleanup_startup_connect_support_smoke_artifacts(&store_path, &support_dir);

    if passed {
        Ok(())
    } else {
        Err("desktop startup connect support smoke report failed".into())
    }
}

fn cleanup_startup_connect_support_smoke_artifacts(store_path: &Path, support_dir: &Path) {
    if let Err(error) = fs::remove_file(store_path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            eprintln!("startup connect support smoke store cleanup failed: {error}");
        }
    }
    if let Err(error) = fs::remove_dir_all(support_dir) {
        if error.kind() != std::io::ErrorKind::NotFound {
            eprintln!("startup connect support smoke export cleanup failed: {error}");
        }
    }
}

fn run_startup_connect_smoke() -> Result<(), Box<dyn Error>> {
    let store_path = startup_restore_smoke_store_path();
    let store = DesktopSubscriptionStore::new(&store_path);
    store.save(&DesktopPersistedSubscription {
        config_text: startup_restore_smoke_config(),
        selected_outbound: Some(STARTUP_RESTORE_SMOKE_SELECTED_OUTBOUND.to_string()),
    })?;

    let mut controller = DesktopShellController::new_with_subscription_store(
        DesktopNativeCommandService::new(),
        store,
    );
    let started_shell =
        apply_desktop_startup_settings(&mut controller, &startup_connect_smoke_settings())
            .map_err(|error| format!("{} {} {}", error.operation, error.kind, error.message))?;
    let html = render_shell_html(&started_shell);
    let script = shell_snapshot_script(&started_shell)?;
    let stopped_after_smoke = stop_smoke_core_if_running(&mut controller, &started_shell);
    let report = build_startup_connect_smoke_report(
        &started_shell,
        &html,
        &script,
        STARTUP_RESTORE_SMOKE_SELECTED_OUTBOUND,
        stopped_after_smoke,
    );
    let passed = report.status == "passed";

    println!("{}", serde_json::to_string_pretty(&report)?);

    if let Err(error) = fs::remove_file(&store_path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            eprintln!("startup connect smoke cleanup failed: {error}");
        }
    }

    if passed {
        Ok(())
    } else {
        Err("desktop startup connect smoke report failed".into())
    }
}

fn run_startup_restore_smoke() -> Result<(), Box<dyn Error>> {
    let store_path = startup_restore_smoke_store_path();
    let store = DesktopSubscriptionStore::new(&store_path);
    store.save(&DesktopPersistedSubscription {
        config_text: startup_restore_smoke_config(),
        selected_outbound: Some(STARTUP_RESTORE_SMOKE_SELECTED_OUTBOUND.to_string()),
    })?;

    let controller = DesktopShellController::new_with_subscription_store(
        DesktopNativeCommandService::new(),
        store,
    );
    let snapshot = controller.snapshot();
    let html = render_shell_html(snapshot);
    let script = shell_snapshot_script(snapshot)?;
    let report = build_startup_restore_smoke_report(
        snapshot,
        &html,
        &script,
        STARTUP_RESTORE_SMOKE_SELECTED_OUTBOUND,
    );
    let passed = report.status == "passed";

    println!("{}", serde_json::to_string_pretty(&report)?);

    if let Err(error) = fs::remove_file(&store_path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            eprintln!("startup restore smoke cleanup failed: {error}");
        }
    }

    if passed {
        Ok(())
    } else {
        Err("desktop startup restore smoke report failed".into())
    }
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

fn run_support_export_smoke() -> Result<(), Box<dyn Error>> {
    let directory = support_export_smoke_dir_arg(std::env::args())
        .ok_or("--support-export-smoke requires an export directory")?;
    let controller = DesktopShellController::new_native();
    let export = controller
        .export_support_bundle()
        .map_err(|error| format!("{} {} {}", error.operation, error.kind, error.message))?;
    let summary = write_support_bundle_export(&export, directory)
        .map_err(|error| format!("write support bundle failed: {error}"))?;
    let bundle_bytes =
        fs::read(&summary.path).map_err(|error| format!("read support bundle failed: {error}"))?;
    let bundle: serde_json::Value = serde_json::from_slice(&bundle_bytes)
        .map_err(|error| format!("support bundle JSON parse failed: {error}"))?;
    let last_record_matches = last_support_export_record_matches(&summary);
    let report =
        build_support_export_smoke_report(&summary, &export.format, &bundle, last_record_matches);
    let passed = report.status == "passed";

    println!("{}", serde_json::to_string_pretty(&report)?);

    if passed {
        Ok(())
    } else {
        Err("desktop support export smoke report failed".into())
    }
}

fn startup_connect_smoke_settings() -> DesktopShellSettings {
    let mut settings = DesktopShellSettings::default();
    settings.auto_start_core = true;
    settings.mixed_port = 0;
    settings.traffic_mode = keli_desktop::DesktopTrafficMode::MixedInboundOnly;
    settings
}

fn stop_smoke_core_if_running(
    controller: &mut DesktopShellController<DesktopNativeCommandService>,
    shell: &DesktopShellState,
) -> bool {
    if shell.status.run_state != DesktopRunState::Running {
        return false;
    }
    match controller.dispatch(DesktopShellAction::RequestStop) {
        Ok(stopped) => stopped.status.run_state == DesktopRunState::Stopped,
        Err(error) => {
            eprintln!(
                "startup connect smoke stop failed: {} {} {}",
                error.operation, error.kind, error.message
            );
            false
        }
    }
}

fn startup_restore_smoke_store_path() -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!("keli-desktop-startup-restore-smoke-{unique}.json"))
}

fn startup_connect_support_smoke_dir() -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!(
        "keli-desktop-startup-connect-support-smoke-{unique}"
    ))
}

fn startup_restore_smoke_config() -> String {
    r#"proxies:
  - name: SS-OLD
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: aes-128-gcm
    password: pass
  - name: SS-RESTORED
    type: ss
    server: 127.0.0.1
    port: 8389
    cipher: aes-128-gcm
    password: pass
"#
    .to_string()
}

fn build_support_export_smoke_report(
    summary: &support::SupportBundleSaveSummary,
    format: &str,
    bundle: &serde_json::Value,
    last_record_matches: bool,
) -> DesktopShellSupportExportSmokeReport {
    let kind = bundle["kind"].as_str().unwrap_or_default().to_string();
    let desktop_dependencies = bundle["desktop_dependencies"]["first_run"]["system_proxy_ready"]
        .is_boolean()
        && bundle["desktop_dependencies"]["first_run"]["tun_ready"].is_boolean()
        && bundle["desktop_dependencies"]["tun_backend"]["backend"].as_str() == Some("wintun");
    let core_support_bundle =
        bundle["core_support_bundle"]["kind"].as_str() == Some("keli_support_bundle");
    let status = if summary.status == "saved"
        && kind == "keli_desktop_support_bundle"
        && desktop_dependencies
        && core_support_bundle
        && last_record_matches
    {
        "passed"
    } else {
        "failed"
    };

    DesktopShellSupportExportSmokeReport {
        status: status.to_string(),
        path: summary.path.clone(),
        byte_count: summary.byte_count,
        format: format.to_string(),
        kind,
        desktop_dependencies,
        core_support_bundle,
        last_record_matches,
    }
}

fn build_running_support_smoke_report(
    summary: &support::SupportBundleSaveSummary,
    format: &str,
    bundle: &serde_json::Value,
    bundle_text: &str,
    last_record_matches: bool,
    stopped_after_smoke: bool,
    expected_selected_outbound: &str,
) -> DesktopShellRunningSupportSmokeReport {
    let support_saved = summary.status == "saved"
        && summary.byte_count > 0
        && format == "json"
        && bundle["kind"].as_str() == Some("keli_desktop_support_bundle");
    let desktop_status_running = bundle["desktop_status"]["run_state"].as_str() == Some("running");
    let desktop_status_selected =
        bundle["desktop_status"]["selected_outbound"].as_str() == Some(expected_selected_outbound);
    let managed_status_selected = bundle["managed_runtime_status"]["selected_outbound"].as_str()
        == Some(expected_selected_outbound);
    let diagnosis_selected =
        bundle["desktop_diagnosis"]["connection"]["evidence"]["selected_outbound"].as_str()
            == Some(expected_selected_outbound);
    let connection_level = bundle["desktop_diagnosis"]["connection"]["level"]
        .as_str()
        .filter(|level| !level.trim().is_empty())
        .map(ToString::to_string);
    let redaction_ready = bundle["core_support_bundle"]["kind"].as_str()
        == Some("keli_support_bundle")
        && bundle["core_support_bundle"]["redaction"]["profile_config_text"].as_str()
            == Some("omitted")
        && !bundle_text.contains("password: pass")
        && !bundle_text.contains("\"password\"");
    let status = if support_saved
        && desktop_status_running
        && desktop_status_selected
        && managed_status_selected
        && diagnosis_selected
        && connection_level.is_some()
        && redaction_ready
        && last_record_matches
        && stopped_after_smoke
    {
        "passed"
    } else {
        "failed"
    };

    DesktopShellRunningSupportSmokeReport {
        status: status.to_string(),
        path: summary.path.clone(),
        byte_count: summary.byte_count,
        format: format.to_string(),
        support_saved,
        desktop_status_running,
        desktop_status_selected,
        managed_status_selected,
        diagnosis_selected,
        connection_level,
        redaction_ready,
        last_record_matches,
        stopped_after_smoke,
    }
}

fn build_startup_restore_smoke_report(
    snapshot: &DesktopShellState,
    html: &str,
    snapshot_script: &str,
    expected_selected_outbound: &str,
) -> DesktopShellStartupRestoreSmokeReport {
    let subscription = snapshot.subscription.as_ref();
    let restored_subscription = subscription
        .map(|subscription| {
            subscription.usable
                && subscription.supported_count > 0
                && !subscription.nodes.is_empty()
        })
        .unwrap_or(false);
    let restored_selected_outbound =
        subscription.and_then(|subscription| subscription.selected_outbound.clone());
    let runtime_selected_outbound = snapshot.status.selected_outbound.clone();
    let restored_supported_count = subscription
        .map(|subscription| subscription.supported_count)
        .unwrap_or_default();
    let selected_node_restored = subscription
        .map(|subscription| {
            subscription
                .nodes
                .iter()
                .any(|node| node.tag == expected_selected_outbound && node.selected)
        })
        .unwrap_or(false);
    let restored_selected_matches = restored_selected_outbound.as_deref()
        == Some(expected_selected_outbound)
        && runtime_selected_outbound.as_deref() == Some(expected_selected_outbound)
        && selected_node_restored;
    let html_ready = html.contains("id=\"primary-button\"")
        && html.contains(&format!("data-node-tag=\"{expected_selected_outbound}\""));
    let snapshot_script_ready = snapshot_script.contains("window.keliSetShell")
        && snapshot_script.contains(expected_selected_outbound);
    let can_start_after_restore = snapshot.can_start;
    let status = if restored_subscription
        && restored_selected_matches
        && can_start_after_restore
        && html_ready
        && snapshot_script_ready
    {
        "passed"
    } else {
        "failed"
    };

    DesktopShellStartupRestoreSmokeReport {
        status: status.to_string(),
        restored_subscription,
        restored_selected_outbound,
        runtime_selected_outbound,
        restored_supported_count,
        restored_selected_matches,
        can_start_after_restore,
        primary_action_id: snapshot.primary_action.id.clone(),
        html_ready,
        snapshot_script_ready,
    }
}

fn build_startup_connect_smoke_report(
    snapshot: &DesktopShellState,
    html: &str,
    snapshot_script: &str,
    expected_selected_outbound: &str,
    stopped_after_smoke: bool,
) -> DesktopShellStartupConnectSmokeReport {
    let selected_outbound = snapshot.status.selected_outbound.clone();
    let listen = snapshot.status.listen.clone();
    let auto_started = snapshot.status.run_state == DesktopRunState::Running
        && selected_outbound.as_deref() == Some(expected_selected_outbound)
        && listen
            .as_deref()
            .is_some_and(|listen| listen.starts_with("127.0.0.1:"));
    let html_ready = html.contains("id=\"primary-button\"")
        && html.contains(&format!("data-node-tag=\"{expected_selected_outbound}\""));
    let snapshot_script_ready = snapshot_script.contains("window.keliSetShell")
        && snapshot_script.contains(expected_selected_outbound)
        && snapshot_script.contains("\"running\"");
    let status = if auto_started
        && snapshot.primary_action.id == "stop-service"
        && html_ready
        && snapshot_script_ready
        && stopped_after_smoke
    {
        "passed"
    } else {
        "failed"
    };

    DesktopShellStartupConnectSmokeReport {
        status: status.to_string(),
        run_state: snapshot.status.run_state,
        selected_outbound,
        listen,
        auto_started,
        primary_action_id: snapshot.primary_action.id.clone(),
        html_ready,
        snapshot_script_ready,
        stopped_after_smoke,
    }
}

fn last_support_export_record_matches(summary: &support::SupportBundleSaveSummary) -> bool {
    read_last_support_bundle_export(&summary.directory)
        .ok()
        .flatten()
        .map(|record| {
            record.status == summary.status
                && record.path == summary.path
                && record.directory == summary.directory
                && record.byte_count == summary.byte_count
        })
        .unwrap_or(false)
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
    let ui_workflow_entrypoints = smoke_workflow_entrypoints(html, snapshot_script);
    let settings_persistence_ready = html.contains("id=\"settings-save-button\"")
        && html.contains("save-desktop-settings")
        && html.contains("window.keliSetDesktopSettings");
    let settings_runtime_ready = settings_persistence_ready
        && html.contains("id=\"settings-mixed-port\"")
        && html.contains("mixed_port");
    let settings_auto_start_ready = settings_persistence_ready
        && html.contains("id=\"settings-auto-start-core\"")
        && html.contains("auto_start_core");
    let first_run_blockers = smoke_first_run_blockers(snapshot);
    let dependency_action_entrypoints = smoke_dependency_action_entrypoints(snapshot, html);
    let workflows_ready = expected_smoke_workflows().iter().all(|workflow| {
        ui_workflow_entrypoints
            .iter()
            .any(|entry| entry == workflow)
    });
    let status = if html_ready
        && snapshot_script_ready
        && workflows_ready
        && settings_persistence_ready
        && settings_runtime_ready
        && settings_auto_start_ready
    {
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
        first_run_system_proxy_ready: snapshot.dependencies.first_run.system_proxy_ready,
        first_run_tun_ready: snapshot.dependencies.first_run.tun_ready,
        first_run_blockers,
        dependency_action_entrypoints,
        html_ready,
        snapshot_script_ready,
        settings_persistence_ready,
        settings_runtime_ready,
        settings_auto_start_ready,
        ui_workflow_entrypoints,
    }
}

fn expected_smoke_workflows() -> [&'static str; 8] {
    [
        "open-desktop-shell",
        "import-subscription",
        "select-node",
        "start-stop-system-proxy",
        "tun-preflight",
        "export-support-bundle",
        "clear-support-exports",
        "save-desktop-settings",
    ]
}

fn smoke_workflow_entrypoints(html: &str, snapshot_script: &str) -> Vec<String> {
    let mut entrypoints = Vec::new();
    if html.contains("id=\"run-state\"") && html.contains("id=\"primary-button\"") {
        entrypoints.push("open-desktop-shell".to_string());
    }
    if html.contains("id=\"subscription-url\"")
        && html.contains("import-subscription-url")
        && html.contains("import-subscription-config")
    {
        entrypoints.push("import-subscription".to_string());
    }
    if html.contains("id=\"node-list\"")
        && html.contains("select-node")
        && snapshot_script.contains("window.keliSetShell")
    {
        entrypoints.push("select-node".to_string());
    }
    if html.contains("postTrafficMode('system-proxy')")
        && html.contains("id=\"primary-button\"")
        && html.contains("id=\"system-proxy-dependency\"")
    {
        entrypoints.push("start-stop-system-proxy".to_string());
    }
    if html.contains("postTrafficMode('tun')")
        && html.contains("id=\"tun-dependency\"")
        && html.contains("id=\"wintun-source-path\"")
    {
        entrypoints.push("tun-preflight".to_string());
    }
    if html.contains("export-support-bundle") && html.contains("id=\"support-export-status\"") {
        entrypoints.push("export-support-bundle".to_string());
    }
    if html.contains("clear-support-exports")
        && html.contains("id=\"diagnostics-clear-support-button\"")
    {
        entrypoints.push("clear-support-exports".to_string());
    }
    if html.contains("id=\"settings-save-button\"")
        && html.contains("save-desktop-settings")
        && html.contains("window.keliSetDesktopSettings")
    {
        entrypoints.push("save-desktop-settings".to_string());
    }
    entrypoints
}

fn smoke_first_run_blockers(snapshot: &DesktopShellState) -> Vec<DesktopShellSmokeBlocker> {
    snapshot
        .dependencies
        .first_run
        .blockers
        .iter()
        .map(|blocker| DesktopShellSmokeBlocker {
            code: blocker.code.clone(),
            message: blocker.message.clone(),
            action: blocker.action.clone(),
        })
        .collect()
}

fn smoke_dependency_action_entrypoints(snapshot: &DesktopShellState, html: &str) -> Vec<String> {
    let mut actions = Vec::new();
    add_smoke_dependency_action(
        &mut actions,
        snapshot.dependencies.system_proxy.action.as_deref(),
    );
    add_smoke_dependency_action(
        &mut actions,
        snapshot.dependencies.tun_backend.action.as_deref(),
    );
    for blocker in &snapshot.dependencies.first_run.blockers {
        add_smoke_dependency_action(&mut actions, blocker.action.as_deref());
    }
    actions
        .into_iter()
        .filter(|action| html.contains(&format!("data-dependency-action=\"{action}\"")))
        .collect()
}

fn add_smoke_dependency_action(actions: &mut Vec<String>, action: Option<&str>) {
    let Some(action) = action else {
        return;
    };
    if action.trim().is_empty() || actions.iter().any(|existing| existing == action) {
        return;
    }
    actions.push(action.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    use keli_desktop::{
        DesktopDependencyReport, DesktopFirstRunReport, DesktopNodeSummary, DesktopRunState,
        DesktopShellState, DesktopStatusSnapshot, DesktopSubscriptionSummary,
        DesktopSystemProxyDependency, DesktopTrafficMode, DesktopTunBackendDependency,
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

    fn usable_subscription() -> DesktopSubscriptionSummary {
        usable_subscription_with_tag("SS-READY")
    }

    fn usable_subscription_with_tag(tag: &str) -> DesktopSubscriptionSummary {
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
                health_state: None,
                tcp_available: None,
                udp_available: None,
                latency_ms: None,
                health_error: None,
            }],
            skipped: Vec::new(),
        }
    }

    #[test]
    fn smoke_arg_detection_accepts_smoke_flag() {
        assert!(is_smoke_mode(["keli-desktop-shell", "--smoke"]));
        assert!(!is_smoke_mode(["keli-desktop-shell"]));
    }

    #[test]
    fn support_export_smoke_arg_detection_accepts_directory_flag() {
        assert!(is_support_export_smoke_mode([
            "keli-desktop-shell",
            "--support-export-smoke",
            "C:\\Temp\\KeliSupport",
        ]));
        assert!(!is_support_export_smoke_mode([
            "keli-desktop-shell",
            "--smoke",
        ]));
    }

    #[test]
    fn startup_restore_smoke_arg_detection_accepts_flag() {
        assert!(is_startup_restore_smoke_mode([
            "keli-desktop-shell",
            "--startup-restore-smoke",
        ]));
        assert!(!is_startup_restore_smoke_mode([
            "keli-desktop-shell",
            "--smoke"
        ]));
    }

    #[test]
    fn startup_connect_smoke_arg_detection_accepts_flag() {
        assert!(is_startup_connect_smoke_mode([
            "keli-desktop-shell",
            "--startup-connect-smoke",
        ]));
        assert!(!is_startup_connect_smoke_mode([
            "keli-desktop-shell",
            "--startup-restore-smoke",
        ]));
    }

    #[test]
    fn startup_connect_support_smoke_arg_detection_accepts_flag() {
        assert!(is_startup_connect_support_smoke_mode([
            "keli-desktop-shell",
            "--startup-connect-support-smoke",
        ]));
        assert!(!is_startup_connect_support_smoke_mode([
            "keli-desktop-shell",
            "--startup-connect-smoke",
        ]));
    }

    #[test]
    fn support_export_smoke_report_confirms_bundle_shape() {
        let report = build_support_export_smoke_report(
            &support::SupportBundleSaveSummary {
                status: "saved".to_string(),
                path: "C:\\Temp\\KeliSupport\\keli-support-1.json".to_string(),
                directory: "C:\\Temp\\KeliSupport".to_string(),
                byte_count: 42,
            },
            "json",
            &serde_json::json!({
                "kind": "keli_desktop_support_bundle",
                "desktop_dependencies": {
                    "first_run": {
                        "system_proxy_ready": true,
                        "tun_ready": false
                    },
                    "tun_backend": {
                        "backend": "wintun"
                    }
                },
                "core_support_bundle": {
                    "kind": "keli_support_bundle"
                }
            }),
            true,
        );

        assert_eq!(report.status, "passed");
        assert_eq!(report.path, "C:\\Temp\\KeliSupport\\keli-support-1.json");
        assert_eq!(report.byte_count, 42);
        assert_eq!(report.format, "json");
        assert_eq!(report.kind, "keli_desktop_support_bundle");
        assert!(report.desktop_dependencies);
        assert!(report.core_support_bundle);
        assert!(report.last_record_matches);
    }

    #[test]
    fn running_support_smoke_report_confirms_running_diagnostics() {
        let bundle = serde_json::json!({
            "kind": "keli_desktop_support_bundle",
            "desktop_status": {
                "run_state": "running",
                "selected_outbound": "SS-RESTORED",
                "listen": "127.0.0.1:45678"
            },
            "managed_runtime_status": {
                "selected_outbound": "SS-RESTORED",
                "listen": "127.0.0.1:45678"
            },
            "desktop_diagnosis": {
                "connection": {
                    "level": "healthy",
                    "evidence": {
                        "selected_outbound": "SS-RESTORED",
                        "listen": "127.0.0.1:45678"
                    }
                }
            },
            "core_support_bundle": {
                "kind": "keli_support_bundle",
                "redaction": {
                    "profile_config_text": "omitted"
                }
            }
        });
        let bundle_text = serde_json::to_string(&bundle).expect("bundle text");
        let report = build_running_support_smoke_report(
            &support::SupportBundleSaveSummary {
                status: "saved".to_string(),
                path: "C:\\Temp\\KeliSupport\\keli-support-1.json".to_string(),
                directory: "C:\\Temp\\KeliSupport".to_string(),
                byte_count: bundle_text.len(),
            },
            "json",
            &bundle,
            &bundle_text,
            true,
            true,
            "SS-RESTORED",
        );

        assert_eq!(report.status, "passed");
        assert!(report.support_saved);
        assert!(report.desktop_status_running);
        assert!(report.desktop_status_selected);
        assert!(report.managed_status_selected);
        assert!(report.diagnosis_selected);
        assert_eq!(report.connection_level.as_deref(), Some("healthy"));
        assert!(report.redaction_ready);
        assert!(report.last_record_matches);
        assert!(report.stopped_after_smoke);
    }

    #[test]
    fn startup_restore_smoke_report_confirms_subscription_and_selected_node_restore() {
        let mut snapshot = smoke_snapshot();
        snapshot.status.selected_outbound = Some("SS-RESTORED".to_string());
        snapshot.refresh_status(snapshot.status.clone());
        snapshot.refresh_subscription(Some(usable_subscription_with_tag("SS-RESTORED")));
        let html = render_shell_html(&snapshot);
        let script = shell_snapshot_script(&snapshot).expect("snapshot script");

        let report = build_startup_restore_smoke_report(&snapshot, &html, &script, "SS-RESTORED");

        assert_eq!(report.status, "passed");
        assert!(report.restored_subscription);
        assert_eq!(
            report.restored_selected_outbound.as_deref(),
            Some("SS-RESTORED")
        );
        assert_eq!(
            report.runtime_selected_outbound.as_deref(),
            Some("SS-RESTORED")
        );
        assert_eq!(report.restored_supported_count, 1);
        assert!(report.restored_selected_matches);
        assert!(report.can_start_after_restore);
        assert!(report.html_ready);
        assert!(report.snapshot_script_ready);
    }

    #[test]
    fn startup_connect_smoke_report_confirms_auto_started_connection() {
        let mut snapshot = smoke_snapshot();
        snapshot.status.run_state = DesktopRunState::Running;
        snapshot.status.traffic_mode = DesktopTrafficMode::MixedInboundOnly;
        snapshot.status.selected_outbound = Some("SS-RESTORED".to_string());
        snapshot.status.listen = Some("127.0.0.1:45678".to_string());
        snapshot.refresh_status(snapshot.status.clone());
        snapshot.refresh_subscription(Some(usable_subscription_with_tag("SS-RESTORED")));
        let html = render_shell_html(&snapshot);
        let script = shell_snapshot_script(&snapshot).expect("snapshot script");

        let report =
            build_startup_connect_smoke_report(&snapshot, &html, &script, "SS-RESTORED", true);

        assert_eq!(report.status, "passed");
        assert_eq!(report.run_state, DesktopRunState::Running);
        assert_eq!(report.selected_outbound.as_deref(), Some("SS-RESTORED"));
        assert_eq!(report.listen.as_deref(), Some("127.0.0.1:45678"));
        assert!(report.auto_started);
        assert_eq!(report.primary_action_id, "stop-service");
        assert!(report.html_ready);
        assert!(report.snapshot_script_ready);
        assert!(report.stopped_after_smoke);
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
        assert!(report.settings_persistence_ready);
        assert!(report.settings_runtime_ready);
        assert!(report.settings_auto_start_ready);
        assert_eq!(
            report.ui_workflow_entrypoints,
            vec![
                "open-desktop-shell",
                "import-subscription",
                "select-node",
                "start-stop-system-proxy",
                "tun-preflight",
                "export-support-bundle",
                "clear-support-exports",
                "save-desktop-settings",
            ]
        );
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
    fn smoke_report_records_first_run_dependency_blockers_and_actions() {
        let mut snapshot = smoke_snapshot();
        snapshot.dependencies.first_run.tun_ready = false;
        snapshot.dependencies.first_run.can_start_tun_mode = false;
        snapshot.dependencies.first_run.blockers = vec![keli_desktop::DesktopBlocker {
            code: "wintun-missing".to_string(),
            message: "Wintun library was not found".to_string(),
            action: Some("install-wintun".to_string()),
        }];
        snapshot.dependencies.tun_backend.action = Some("install-wintun".to_string());

        let html = render_shell_html(&snapshot);
        let script = shell_snapshot_script(&snapshot).expect("snapshot script");
        let report = build_smoke_report(&snapshot, &html, &script);

        assert!(!report.first_run_tun_ready);
        assert!(report.first_run_system_proxy_ready);
        assert_eq!(report.first_run_blockers.len(), 1);
        assert_eq!(report.first_run_blockers[0].code, "wintun-missing");
        assert_eq!(
            report.first_run_blockers[0].action.as_deref(),
            Some("install-wintun")
        );
        assert!(report
            .dependency_action_entrypoints
            .iter()
            .any(|action| action == "install-wintun"));
    }

    #[test]
    fn operation_success_message_covers_generic_actions() {
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::Refresh).as_deref(),
            Some("状态已刷新")
        );
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::RefreshNodeHealth).as_deref(),
            Some("节点健康已刷新")
        );
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::Action(
                DesktopShellAction::RequestStart
            ))
            .as_deref(),
            Some("已请求启动")
        );
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::Action(
                DesktopShellAction::RequestStop
            ))
            .as_deref(),
            Some("已请求停止")
        );
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::SelectNode("SS-READY".to_string()))
                .as_deref(),
            Some("已应用节点 SS-READY")
        );
    }

    #[test]
    fn desktop_settings_listen_address_uses_mixed_port() {
        let mut settings = DesktopShellSettings::default();
        settings.mixed_port = 17890;

        assert_eq!(
            desktop_settings_listen_address(&settings),
            "127.0.0.1:17890"
        );
    }

    #[test]
    fn desktop_settings_auto_start_action_requests_start_when_enabled_and_ready() {
        let mut settings = DesktopShellSettings::default();
        settings.auto_start_core = true;
        let mut shell = smoke_snapshot();
        shell.refresh_subscription(Some(usable_subscription()));

        assert!(shell.can_start);
        assert_eq!(
            desktop_settings_auto_start_action(&settings, &shell),
            Some(DesktopShellAction::RequestStart)
        );
    }

    #[test]
    fn desktop_settings_auto_start_action_skips_start_when_disabled() {
        let settings = DesktopShellSettings::default();
        let mut shell = smoke_snapshot();
        shell.refresh_subscription(Some(usable_subscription()));

        assert!(shell.can_start);
        assert_eq!(desktop_settings_auto_start_action(&settings, &shell), None);
    }

    #[test]
    fn desktop_settings_auto_start_action_skips_start_when_blocked() {
        let mut settings = DesktopShellSettings::default();
        settings.auto_start_core = true;
        let mut shell = smoke_snapshot();
        shell.dependencies.first_run.can_start_system_proxy_mode = false;
        shell.refresh_dependencies(shell.dependencies.clone());
        shell.refresh_subscription(Some(usable_subscription()));

        assert!(!shell.can_start);
        assert_eq!(desktop_settings_auto_start_action(&settings, &shell), None);
    }

    #[test]
    fn operation_success_message_covers_mode_and_dependency_actions() {
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::SetTrafficMode(
                DesktopTrafficMode::Tun
            ))
            .as_deref(),
            Some("流量模式已切换为 TUN")
        );
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::DependencyAction(
                "install-wintun".to_string()
            ))
            .as_deref(),
            Some("已打开依赖操作：install-wintun")
        );
    }

    #[test]
    fn operation_success_message_covers_panel_config_import() {
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::PanelImportConfig {
                server_id: 51,
                server_name: "JP Tokyo 01".to_string(),
                config_text: "proxies: []".to_string(),
            })
            .as_deref(),
            Some("已导入面板节点配置：JP Tokyo 01")
        );
    }

    #[test]
    fn operation_success_message_covers_panel_login_and_fetch() {
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::PanelLogin {
                endpoint: "https://panel.example.com".to_string(),
                email: "user@example.com".to_string(),
                password: "secret".to_string(),
            })
            .as_deref(),
            Some("面板登录成功，已同步全部节点配置")
        );
        assert_eq!(
            operation_success_message(&DesktopShellUiEvent::PanelFetchConfig {
                server_id: 51,
                server_name: "JP Tokyo 01".to_string(),
            })
            .as_deref(),
            Some("已拉取并导入面板节点配置：JP Tokyo 01")
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
