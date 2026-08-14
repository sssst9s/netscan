#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod boot;
mod chrome;
mod filter;
mod fonts;
mod icons;
mod scanform;
mod session;
mod theme;
mod toolbar;
mod views;
mod widgets;

fn main() -> eframe::Result<()> {
    let viewport = egui::ViewportBuilder::default()
        .with_title("netscan")
        .with_inner_size([1280.0, 820.0])
        .with_min_inner_size([900.0, 560.0])
        .with_app_id("netscan");

    let viewport = if cfg!(target_os = "macos") {
        viewport
            .with_fullsize_content_view(true)
            .with_titlebar_shown(false)
            .with_title_shown(false)
            .with_titlebar_buttons_shown(false)
    } else {
        viewport.with_decorations(false).with_transparent(true)
    };

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "netscan",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)) as Box<dyn eframe::App>)),
    )
}
