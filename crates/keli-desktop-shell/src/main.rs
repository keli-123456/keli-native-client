mod actions;
mod html;

use std::error::Error;

use actions::{ipc_event_for_message, tray_event_for_id, DesktopShellUiEvent};
use html::{render_shell_html, shell_snapshot_script};
use keli_desktop::{
    DesktopShellAction, DesktopShellController, DesktopShellControllerError, DesktopShellState,
};
use single_instance::SingleInstance;
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
