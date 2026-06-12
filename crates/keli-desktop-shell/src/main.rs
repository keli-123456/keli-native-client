mod actions;
mod html;
mod support;

use std::error::Error;

use actions::{ipc_event_for_message, tray_event_for_id, DesktopShellUiEvent};
use html::{
    render_shell_html, shell_snapshot_script, subscription_url_import_status_script,
    subscription_url_update_status_script, support_export_status_script,
};
use keli_desktop::{
    DesktopShellAction, DesktopShellController, DesktopShellControllerError, DesktopShellState,
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
                sync_webview(webview, controller.snapshot());
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
                sync_webview(webview, controller.snapshot());
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
            }
        }
        return;
    }

    match dispatch_ui_event(controller, event) {
        Ok(shell) => {
            window.set_visible(shell.window.main_visible);
            sync_webview(webview, &shell);
            if shell.quit_requested {
                *control_flow = ControlFlow::Exit;
            }
        }
        Err(error) => {
            eprintln!(
                "desktop shell action failed: {} {} {}",
                error.operation, error.kind, error.message
            );
            sync_webview(webview, controller.snapshot());
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
