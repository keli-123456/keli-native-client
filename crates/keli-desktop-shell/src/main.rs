mod html;

use std::error::Error;

use html::render_shell_html;
use keli_desktop::{DesktopShellAction, DesktopShellController};
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
use wry::WebViewBuilder;

#[derive(Debug)]
enum UserEvent {
    TrayMenu(String),
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
    let webview = WebViewBuilder::new()
        .with_html(initial_html)
        .build(&window)?;
    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        let _ = proxy.send_event(UserEvent::TrayMenu(event.id().as_ref().to_string()));
    }));
    let tray_menu = build_tray_menu(controller.snapshot())?;
    let _tray_icon = TrayIconBuilder::new()
        .with_tooltip("Keli")
        .with_icon(app_icon()?)
        .with_menu(Box::new(tray_menu))
        .build()?;
    let webview = Some(webview);

    event_loop.run(move |event, _, control_flow| {
        let _keep_webview_alive = &webview;
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
                if let Some(action) = tray_action(&id) {
                    match controller.dispatch(action) {
                        Ok(shell) => {
                            window.set_visible(shell.window.main_visible);
                            if shell.quit_requested {
                                *control_flow = ControlFlow::Exit;
                            }
                        }
                        Err(error) => {
                            eprintln!(
                                "desktop shell action failed: {} {} {}",
                                error.operation, error.kind, error.message
                            );
                        }
                    }
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

fn tray_action(id: &str) -> Option<DesktopShellAction> {
    match id {
        "show-main-window" => Some(DesktopShellAction::ShowMainWindow),
        "toggle-service" => Some(DesktopShellAction::RequestStart),
        "open-diagnostics" => Some(DesktopShellAction::OpenDiagnostics),
        "quit" => Some(DesktopShellAction::RequestQuit),
        _ => None,
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
