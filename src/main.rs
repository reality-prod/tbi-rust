use eframe::egui;

mod theme;
mod icons;
mod platform;
mod app;
mod ui;
mod install;

use app::TorBrowserBuilder;

/// This app's own version, shown in the About screen and sent as part of
/// the HTTP User-Agent when talking to the Tor Project's release API.
pub(crate) const APP_VERSION: &str = "0.07";
/// Credited in the About screen.
pub(crate) const APP_AUTHOR: &str = "Ribhav Sai Ramanuja Revalli";

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([620.0, 640.0])
            .with_min_inner_size([480.0, 560.0])
            .with_resizable(true)
            .with_decorations(true),
        ..Default::default()
    };

    eframe::run_native(
        "Tor Browser Installer",
        options,
        Box::new(|cc| Ok(Box::new(TorBrowserBuilder::new(cc)))),
    )
}