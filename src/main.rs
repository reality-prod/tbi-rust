//! Tor Browser Builder
//!
//! A small cross-platform installer/launcher for Tor Browser (macOS, Linux,
//! Windows). The binary is compiled separately per target (that's how Rust
//! works — there is no single file that runs natively on all three OSes),
//! but each build uses `cfg(target_os = ...)` / `cfg(target_arch = ...)` to
//! pick the right release JSON at runtime, download the matching archive
//! format for the platform it's actually running on, and drive the matching
//! install routine (.dmg mount+copy on macOS, .tar.xz extract on Linux,
//! running the NSIS installer on Windows). So "cross platform" here means
//! "the same source produces three OS-appropriate builds that each know how
//! to install themselves," not "one binary that installs on any OS."
//!
//! IMPORTANT SECURITY NOTE
//! ------------------------
//! Downloading and running Tor Browser is a security-sensitive operation.
//! This build verifies the downloaded file's SHA-256 against the value
//! reported by the release API and shows it in the UI, but it does **not**
//! perform full OpenPGP signature verification against the Tor Browser
//! Developers signing key. Before shipping this to real users, add that
//! verification (e.g. with `sequoia-openpgp`) rather than relying on
//! checksum-only integrity checking. Also note that all of this happens over
//! a plain (non-Tor) HTTPS connection — a network observer can see that this
//! machine fetched Tor Browser, which is exactly the kind of metadata Tor
//! Browser itself exists to avoid. Double check the release JSON schema
//! below against the live index at
//! https://aus1.torproject.org/torbrowser/update_3/release/ — the Tor
//! Project has changed this shape before, and per-platform field names may
//! not be identical across download-macos.json / download-linux-*.json /
//! download-windows-*.json.

use eframe::egui;
use egui::{Color32, RichText, Stroke};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

use directories::UserDirs;
use sequoia_openpgp as openpgp;
use openpgp::parse::{Parse, stream::*};
use openpgp::policy::StandardPolicy;

// ---------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------
//
// Rust compiles one binary per target, so "cross platform" support here
// means: this same source file, built once per OS, resolves the right
// release JSON, archive format, and install routine for whichever OS it
// was compiled for. There is no runtime OS-switching within a single
// binary — the cfg(...) blocks below are resolved at compile time.

/// Human-readable label shown in the UI footer.
fn platform_label() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        "this platform"
    }
}

/// Default install location, matching each OS's own conventions.
fn default_install_path() -> PathBuf {
    if let Some(user_dirs) = UserDirs::new() {
        let home = user_dirs.home_dir();
        if cfg!(target_os = "macos") {
            home.join("Applications").join("Tor Browser")
        } else if cfg!(target_os = "windows") {
            // Best-effort: fall back to the home dir if LOCALAPPDATA isn't set.
            std::env::var("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|_| home.to_path_buf())
                .join("Tor Browser")
        } else {
            home.join(".local").join("share").join("tor-browser")
        }
    } else if cfg!(target_os = "windows") {
        PathBuf::from(r"C:\Tor Browser")
    } else {
        PathBuf::from("/opt/tor-browser")
    }
}

/// The release JSON filename for this platform/architecture, matching the
/// files listed at aus1.torproject.org/torbrowser/update_3/release/.
fn release_json_filename() -> &'static str {
    if cfg!(target_os = "macos") {
        "download-macos.json"
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "download-windows-x86_64.json"
    } else if cfg!(target_os = "windows") {
        "download-windows-i686.json"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "download-linux-x86_64.json"
    } else {
        "download-linux-i686.json"
    }
}

/// File extension for the downloaded release archive on this platform.
fn archive_extension() -> &'static str {
    if cfg!(target_os = "macos") {
        "dmg"
    } else if cfg!(target_os = "windows") {
        "exe"
    } else {
        "tar.xz"
    }
}

// ---------------------------------------------------------------------
// Palette (matches the tones already used in the app icon/badge asset)
// ---------------------------------------------------------------------

mod palette {
    #![allow(dead_code)]
    use egui::Color32;

    pub const PURPLE_DARK: Color32 = Color32::from_rgb(66, 12, 93);
    pub const PURPLE: Color32 = Color32::from_rgb(149, 26, 209);
    pub const PURPLE_SOFT: Color32 = Color32::from_rgb(242, 228, 255);
    pub const BG: Color32 = Color32::from_rgb(251, 250, 253);
    pub const SURFACE: Color32 = Color32::from_rgb(255, 255, 255);
    pub const BORDER: Color32 = Color32::from_rgb(232, 226, 240);
    pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(28, 22, 34);
    pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(108, 100, 118);
    pub const SUCCESS: Color32 = Color32::from_rgb(24, 163, 90);
    pub const ERROR: Color32 = Color32::from_rgb(200, 45, 60);
    pub const GOLD: Color32 = Color32::from_rgb(214, 168, 40);
}

mod palette_dark {
    use egui::Color32;

    pub const BG: Color32 = Color32::from_rgb(18, 18, 24);
    pub const SURFACE: Color32 = Color32::from_rgb(28, 28, 36);
    pub const BORDER: Color32 = Color32::from_rgb(50, 50, 65);
    pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(235, 230, 245);
    pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(160, 155, 170);
    pub const PURPLE_SOFT: Color32 = Color32::from_rgb(55, 20, 80);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Theme {
    Light,
    Dark,
}

// ---------------------------------------------------------------------
// Vector icons — no emoji anywhere. Everything below is drawn with the
// egui Painter so it scales cleanly and matches the palette.
// ---------------------------------------------------------------------

mod icons {
    use egui::{Painter, Pos2, Stroke, Vec2};

    pub fn download(painter: &Painter, center: Pos2, size: f32, color: egui::Color32) {
        let stroke = Stroke::new(size * 0.12, color);
        let top = center + Vec2::new(0.0, -size * 0.5);
        let bottom = center + Vec2::new(0.0, size * 0.15);
        painter.line_segment([top, bottom], stroke);
        let tip = bottom;
        painter.line_segment([tip, tip + Vec2::new(-size * 0.28, -size * 0.28)], stroke);
        painter.line_segment([tip, tip + Vec2::new(size * 0.28, -size * 0.28)], stroke);
        let base_y = center.y + size * 0.5;
        painter.line_segment(
            [
                Pos2::new(center.x - size * 0.42, base_y),
                Pos2::new(center.x + size * 0.42, base_y),
            ],
            stroke,
        );
    }

    pub fn check(painter: &Painter, center: Pos2, size: f32, color: egui::Color32) {
        let stroke = Stroke::new(size * 0.14, color);
        let a = center + Vec2::new(-size * 0.32, 0.02 * size);
        let b = center + Vec2::new(-size * 0.06, size * 0.28);
        let c = center + Vec2::new(size * 0.38, -size * 0.32);
        painter.line_segment([a, b], stroke);
        painter.line_segment([b, c], stroke);
    }

    pub fn cross(painter: &Painter, center: Pos2, size: f32, color: egui::Color32) {
        let stroke = Stroke::new(size * 0.13, color);
        let r = size * 0.32;
        painter.line_segment(
            [center + Vec2::new(-r, -r), center + Vec2::new(r, r)],
            stroke,
        );
        painter.line_segment(
            [center + Vec2::new(-r, r), center + Vec2::new(r, -r)],
            stroke,
        );
    }

    pub fn folder(painter: &Painter, center: Pos2, size: f32, color: egui::Color32) {
        let w = size * 0.9;
        let h = size * 0.62;
        let top_left = center + Vec2::new(-w / 2.0, -h / 2.0 + size * 0.06);
        let rect = egui::Rect::from_min_size(top_left, Vec2::new(w, h));
        painter.rect_stroke(
            rect,
            egui::CornerRadius::same((size * 0.08) as u8),
            Stroke::new(size * 0.09, color),
            egui::StrokeKind::Inside,
        );
        let tab = egui::Rect::from_min_size(
            top_left + Vec2::new(size * 0.06, -size * 0.14),
            Vec2::new(w * 0.42, size * 0.16),
        );
        painter.rect_filled(tab, egui::CornerRadius::same((size * 0.06) as u8), color);
    }

    pub fn launch(painter: &Painter, center: Pos2, size: f32, color: egui::Color32) {
        let stroke = Stroke::new(size * 0.12, color);
        let start = center + Vec2::new(-size * 0.35, size * 0.35);
        let end = center + Vec2::new(size * 0.35, -size * 0.35);
        painter.line_segment([start, end], stroke);
        painter.line_segment([end, end + Vec2::new(-size * 0.32, 0.0)], stroke);
        painter.line_segment([end, end + Vec2::new(0.0, size * 0.32)], stroke);
    }

    pub fn lock(painter: &Painter, center: Pos2, size: f32, color: egui::Color32) {
        let body_w = size * 0.7;
        let body_h = size * 0.5;
        let body = egui::Rect::from_center_size(
            center + Vec2::new(0.0, size * 0.15),
            Vec2::new(body_w, body_h),
        );
        painter.rect_filled(body, egui::CornerRadius::same((size * 0.08) as u8), color);
        let shackle_center = center + Vec2::new(0.0, -size * 0.12);
        painter.circle_stroke(
            shackle_center,
            size * 0.24,
            Stroke::new(size * 0.1, color),
        );
    }

    pub fn _unused(_p: egui::Color32) {}
}

// ---------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
enum AppState {
    Idle,
    Checking,
    AlreadyInstalled {
        app_path: PathBuf,
    },
    ConfirmInstall {
        version: String,
        binary_url: String,
        sha256: Option<String>,
        sig_url: Option<String>,
    },
    Downloading {
        progress: f32,
        downloaded_mb: f32,
        total_mb: f32,
    },
    Verifying,
    VerifyingSignature,
    Installing {
        stage: String,
    },
    Complete {
        app_path: PathBuf,
    },
    Error(String),
}

/// Messages sent from the background worker thread back to the UI thread.
enum WorkerEvent {
    State(AppState),
}

struct ReleaseInfo {
    version: String,
    binary_url: String,
    sha256: Option<String>,
    sig_url: Option<String>,
}

struct TorBrowserBuilder {
    state: AppState,
    installation_path: PathBuf,
    install_path_text: String,
    rx: Option<Receiver<WorkerEvent>>,
    confirm_tx: Option<Sender<bool>>,
    logo_bytes: &'static [u8],
    theme: Theme,
}

impl TorBrowserBuilder {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        egui_extras::install_image_loaders(&cc.egui_ctx);

        let mut style = (*cc.egui_ctx.style()).clone();
        style.visuals.selection.bg_fill = palette::PURPLE;
        style.visuals.selection.stroke.color = palette::PURPLE;
        style.visuals.window_fill = palette::BG;
        style.visuals.panel_fill = palette::BG;
        style.spacing.button_padding = egui::vec2(18.0, 10.0);
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        cc.egui_ctx.set_visuals(style.visuals);
        cc.egui_ctx.set_pixels_per_point(1.0);

        let installation_path = default_install_path();
        let install_path_text = installation_path.display().to_string();

        let state = match find_existing_install() {
            Some(path) => AppState::AlreadyInstalled { app_path: path },
            None => AppState::Idle,
        };

        Self {
            state,
            installation_path,
            install_path_text,
            rx: None,
            confirm_tx: None,
            logo_bytes: include_bytes!("assets/tor_logo_tbb.svg"),
            theme: Theme::Light,
        }
    }

    // -------------------------------------------------------------
    // Worker plumbing
    // -------------------------------------------------------------

    fn start_download(&mut self) {
        let (tx, rx): (Sender<WorkerEvent>, Receiver<WorkerEvent>) = std::sync::mpsc::channel();
        let (confirm_tx, confirm_rx): (Sender<bool>, Receiver<bool>) = std::sync::mpsc::channel();
        self.rx = Some(rx);
        self.confirm_tx = Some(confirm_tx);
        self.state = AppState::Checking;

        let install_dir = self.installation_path.clone();
        std::thread::spawn(move || {
            run_install_pipeline(install_dir, tx, confirm_rx);
        });
    }

    fn send_confirm(&mut self, proceed: bool) {
        if let Some(tx) = self.confirm_tx.take() {
            let _ = tx.send(proceed);
        }
    }

    /// Drain any pending worker events. Called once per frame.
    fn poll_worker(&mut self, ctx: &egui::Context) {
        let mut done = false;
        if let Some(rx) = &self.rx {
            while let Ok(event) = rx.try_recv() {
                match event {
                    WorkerEvent::State(s) => {
                        if matches!(s, AppState::Complete { .. } | AppState::Error(_)) {
                            done = true;
                        }
                        self.state = s;
                    }
                }
            }
        }
        if done {
            self.rx = None;
        }
        if self.rx.is_some() {
            ctx.request_repaint_after(Duration::from_millis(80));
        }
    }

    // -------------------------------------------------------------
    // Layout
    // -------------------------------------------------------------

    fn draw_app(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.set_max_width(560.0);
            ui.add_space(28.0);
            self.draw_header(ui);
            ui.add_space(24.0);
            self.draw_card(ui);
            ui.add_space(20.0);
            self.draw_footer(ui);
        });
    }

    fn draw_header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space((ui.available_width() - 420.0).max(0.0) / 2.0);
            ui.add(
                egui::Image::from_bytes("bytes://tor_logo_tbb.svg", self.logo_bytes)
                    .fit_to_exact_size(egui::vec2(84.0, 84.0)),
            );
            ui.add_space(16.0);
            ui.vertical(|ui| {
                ui.add_space(6.0);
                ui.label(
                    RichText::new("Tor Browser")
                        .size(26.0)
                        .strong()
                        .color(self.text_primary()),
                );
                ui.label(
                    RichText::new("Installer")
                        .size(26.0)
                        .strong()
                        .color(palette::PURPLE),
                );
            });
            ui.add_space(ui.available_width().max(0.0));
            let label = if self.theme == Theme::Light { "\u{263E}" } else { "\u{2600}" };
            let theme_btn = ui.add(
                egui::Button::new(
                    RichText::new(label).size(18.0).color(self.text_primary()),
                )
                .fill(self.surface())
                .stroke(Stroke::new(1.0, self.border()))
                .corner_radius(egui::CornerRadius::same(8)),
            );
            if theme_btn.clicked() {
                self.theme = match self.theme {
                    Theme::Light => Theme::Dark,
                    Theme::Dark => Theme::Light,
                };
                self.apply_theme(ui.ctx());
            }
        });
    }

    fn draw_card(&mut self, ui: &mut egui::Ui) {
        let surface = self.surface();
        let border = self.border();
        egui::Frame::NONE
            .fill(surface)
            .stroke(Stroke::new(1.0_f32, border))
            .corner_radius(egui::CornerRadius::same(16))
            .inner_margin(egui::Margin::same(28))
            .show(ui, |ui| {
                ui.set_min_width(500.0);
                match self.state.clone() {
                    AppState::Idle => self.draw_idle(ui),
                    AppState::Checking => Self::draw_checking(ui),
                    AppState::AlreadyInstalled { ref app_path } => {
                        self.draw_already_installed(ui, app_path)
                    }
                    AppState::ConfirmInstall {
                        ref version,
                        ref binary_url,
                        ref sha256,
                        ref sig_url,
                    } => self.draw_confirm(ui, version, binary_url, sha256, sig_url),
                    AppState::Downloading {
                        progress,
                        downloaded_mb,
                        total_mb,
                    } => self.draw_downloading(ui, progress, downloaded_mb, total_mb),
                    AppState::Verifying => Self::draw_verifying(ui),
                    AppState::VerifyingSignature => Self::draw_verifying_signature(ui),
                    AppState::Installing { ref stage } => Self::draw_installing(ui, stage),
                    AppState::Complete { app_path } => self.draw_complete(ui, &app_path),
                    AppState::Error(e) => self.draw_error(ui, &e),
                }
            });
    }

    fn text_primary(&self) -> Color32 {
        match self.theme {
            Theme::Light => palette::TEXT_PRIMARY,
            Theme::Dark => palette_dark::TEXT_PRIMARY,
        }
    }

    fn text_secondary(&self) -> Color32 {
        match self.theme {
            Theme::Light => palette::TEXT_SECONDARY,
            Theme::Dark => palette_dark::TEXT_SECONDARY,
        }
    }

    fn bg(&self) -> Color32 {
        match self.theme {
            Theme::Light => palette::BG,
            Theme::Dark => palette_dark::BG,
        }
    }

    fn surface(&self) -> Color32 {
        match self.theme {
            Theme::Light => palette::SURFACE,
            Theme::Dark => palette_dark::SURFACE,
        }
    }

    fn border(&self) -> Color32 {
        match self.theme {
            Theme::Light => palette::BORDER,
            Theme::Dark => palette_dark::BORDER,
        }
    }

    fn purple_soft(&self) -> Color32 {
        match self.theme {
            Theme::Light => palette::PURPLE_SOFT,
            Theme::Dark => palette_dark::PURPLE_SOFT,
        }
    }

    fn apply_theme(&self, ctx: &egui::Context) {
        let mut style = (*ctx.style()).clone();
        match self.theme {
            Theme::Light => {
                style.visuals.window_fill = palette::BG;
                style.visuals.panel_fill = palette::BG;
                style.visuals.selection.bg_fill = palette::PURPLE;
                style.visuals.selection.stroke.color = palette::PURPLE;
            }
            Theme::Dark => {
                style.visuals.window_fill = palette_dark::BG;
                style.visuals.panel_fill = palette_dark::BG;
                style.visuals.selection.bg_fill = palette::PURPLE;
                style.visuals.selection.stroke.color = palette::PURPLE;
                style.visuals.widgets.noninteractive.bg_fill = palette_dark::SURFACE;
                style.visuals.widgets.inactive.bg_fill = palette_dark::SURFACE;
                style.visuals.widgets.hovered.bg_fill = palette_dark::BORDER;
                style.visuals.widgets.active.bg_fill = palette_dark::BORDER;
            }
        }
        ctx.set_visuals(style.visuals);
    }

    fn draw_idle(&mut self, ui: &mut egui::Ui) {
        let text_primary = self.text_primary();
        let text_secondary = self.text_secondary();
        let bg = self.bg();
        let border_color = self.border();
        ui.vertical(|ui| {
            ui.label(
                RichText::new("Set up Tor Browser")
                    .size(18.0)
                    .strong()
                    .color(text_primary),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "Downloads the current release straight from the Tor Project, \
                     verifies it, and installs it to the folder below.",
                )
                .size(14.0)
                .color(text_secondary),
            );

            ui.add_space(18.0);
            ui.label(
                RichText::new("INSTALL LOCATION")
                    .size(11.0)
                    .color(text_secondary),
            );
            ui.add_space(4.0);
            egui::Frame::NONE
                .fill(bg)
                .stroke(Stroke::new(1.0_f32, border_color))
                .corner_radius(egui::CornerRadius::same(8))
                .inner_margin(egui::Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    let response = ui.add(
                        egui::TextEdit::singleline(&mut self.install_path_text)
                            .frame(false)
                            .desired_width(f32::INFINITY)
                            .text_color(text_primary),
                    );
                    if response.changed() {
                        self.installation_path = PathBuf::from(&self.install_path_text);
                    }
                });

            ui.add_space(22.0);
            let btn = ui.add_sized(
                [ui.available_width(), 46.0],
                egui::Button::new("")
                    .fill(palette::PURPLE)
                    .stroke(Stroke::NONE)
                    .corner_radius(egui::CornerRadius::same(10)),
            );
            let rect = btn.rect;
            let painter = ui.painter();
            let icon_center = egui::pos2(rect.center().x - 60.0, rect.center().y);
            icons::download(painter, icon_center, 18.0, Color32::WHITE);
            painter.text(
                egui::pos2(rect.center().x - 40.0, rect.center().y),
                egui::Align2::LEFT_CENTER,
                "Download & Install Tor Browser",
                egui::FontId::proportional(15.5),
                Color32::WHITE,
            );
            if btn.clicked() {
                self.start_download();
            }

            ui.add_space(10.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    RichText::new(format!("Builds a native install for {}", platform_label()))
                        .size(12.5)
                        .color(text_secondary),
                );
            });
        });
    }

    fn draw_checking(ui: &mut egui::Ui) {
        Self::centered_status(ui, |ui| {
            ui.add(egui::Spinner::new().size(28.0).color(palette::PURPLE));
            ui.add_space(14.0);
            ui.label(
                RichText::new("Checking for the latest release")
                    .size(16.0)
                    .color(palette::TEXT_PRIMARY),
            );
            ui.label(
                RichText::new("Contacting the Tor Project release service")
                    .size(13.0)
                    .color(palette::TEXT_SECONDARY),
            );
        });
    }

    fn draw_already_installed(&mut self, ui: &mut egui::Ui, app_path: &Path) {
        let text_primary = self.text_primary();
        let text_secondary = self.text_secondary();
        let app_path = app_path.to_path_buf();
        ui.vertical_centered(|ui| {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(56.0, 56.0), egui::Sense::hover());
            let painter = ui.painter();
            painter.circle_filled(rect.center(), 28.0, palette::GOLD.gamma_multiply(0.12));
            icons::lock(painter, rect.center(), 24.0, palette::GOLD);

            ui.add_space(10.0);
            ui.label(
                RichText::new("Tor Browser is already installed")
                    .size(19.0)
                    .strong()
                    .color(text_primary),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("Found at {}", app_path.display()))
                    .size(13.0)
                    .color(text_secondary),
            );
            ui.add_space(20.0);

            let launch_btn = ui.add_sized(
                [280.0, 46.0],
                egui::Button::new("")
                    .fill(palette::SUCCESS)
                    .stroke(Stroke::NONE)
                    .corner_radius(egui::CornerRadius::same(10)),
            );
            Self::icon_label_button(ui, &launch_btn, icons::launch, "Launch Tor Browser", Color32::WHITE);
            if launch_btn.clicked() {
                launch_app(&app_path);
            }

            ui.add_space(10.0);
            let reinstall_btn = ui.add_sized(
                [280.0, 46.0],
                egui::Button::new("")
                    .fill(palette::PURPLE)
                    .stroke(Stroke::NONE)
                    .corner_radius(egui::CornerRadius::same(10)),
            );
            Self::icon_label_button(
                ui,
                &reinstall_btn,
                icons::download,
                "Reinstall / Update",
                Color32::WHITE,
            );
            if reinstall_btn.clicked() {
                self.start_download();
            }
        });
    }

    fn draw_confirm(
        &mut self,
        ui: &mut egui::Ui,
        version: &str,
        binary_url: &str,
        sha256: &Option<String>,
        sig_url: &Option<String>,
    ) {
        let text_primary = self.text_primary();
        let text_secondary = self.text_secondary();
        ui.vertical(|ui| {
            ui.label(
                RichText::new("Confirm Download")
                    .size(18.0)
                    .strong()
                    .color(text_primary),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new("Please verify this information before continuing:")
                    .size(14.0)
                    .color(text_secondary),
            );

            ui.add_space(16.0);

            let fields = [
                ("Version", version.to_string()),
                ("Binary URL", binary_url.to_string()),
            ];
            let sha256_str = sha256
                .as_deref()
                .unwrap_or("not available")
                .to_string();
            let sig_str = sig_url
                .as_deref()
                .unwrap_or("not available")
                .to_string();

            for (label, value) in fields.iter().chain(
                [
                    ("SHA-256", sha256_str),
                    ("Signature URL", sig_str),
                ]
                .iter(),
            ) {
                ui.label(
                    RichText::new(*label)
                        .size(11.0)
                        .strong()
                        .color(text_secondary),
                );
                ui.add_space(2.0);
                egui::Frame::NONE
                    .fill(self.bg())
                    .stroke(Stroke::new(1.0, self.border()))
                    .corner_radius(egui::CornerRadius::same(6))
                    .inner_margin(egui::Margin::symmetric(10, 6))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(value)
                                .size(12.5)
                                .monospace()
                                .color(text_primary),
                        );
                    });
                ui.add_space(8.0);
            }

            ui.add_space(8.0);
            let continue_btn = ui.add_sized(
                [ui.available_width(), 46.0],
                egui::Button::new("")
                    .fill(palette::PURPLE)
                    .stroke(Stroke::NONE)
                    .corner_radius(egui::CornerRadius::same(10)),
            );
            let rect = continue_btn.rect;
            let painter = ui.painter();
            icons::check(painter, egui::pos2(rect.center().x - 50.0, rect.center().y), 16.0, Color32::WHITE);
            painter.text(
                egui::pos2(rect.center().x - 30.0, rect.center().y),
                egui::Align2::LEFT_CENTER,
                "Continue",
                egui::FontId::proportional(15.5),
                Color32::WHITE,
            );
            if continue_btn.clicked() {
                self.send_confirm(true);
            }

            ui.add_space(10.0);
            let cancel_btn = ui.add_sized(
                [ui.available_width(), 42.0],
                egui::Button::new(
                    RichText::new("Cancel").size(14.0).color(text_secondary),
                )
                .fill(Color32::TRANSPARENT)
                .stroke(Stroke::new(1.0, self.border()))
                .corner_radius(egui::CornerRadius::same(8)),
            );
            if cancel_btn.clicked() {
                self.send_confirm(false);
                self.rx = None;
                self.confirm_tx = None;
                self.state = AppState::Idle;
            }
        });
    }

    fn draw_downloading(
        &mut self,
        ui: &mut egui::Ui,
        progress: f32,
        downloaded_mb: f32,
        total_mb: f32,
    ) {
        let text_primary = self.text_primary();
        let text_secondary = self.text_secondary();
        ui.vertical(|ui| {
            ui.label(
                RichText::new("Downloading Tor Browser")
                    .size(18.0)
                    .strong()
                    .color(text_primary),
            );
            ui.add_space(16.0);
            ui.add(
                egui::ProgressBar::new(progress)
                    .fill(palette::PURPLE)
                    .corner_radius(egui::CornerRadius::same(8))
                    .desired_height(10.0)
                    .show_percentage(),
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let detail = if total_mb > 0.0 {
                    format!("{downloaded_mb:.1} MB of {total_mb:.1} MB")
                } else {
                    format!("{downloaded_mb:.1} MB downloaded")
                };
                ui.label(RichText::new(detail).size(13.0).color(text_secondary));
            });
            ui.add_space(16.0);
            if ui
                .add(
                    egui::Button::new(
                        RichText::new("Cancel").size(13.0).color(palette::TEXT_SECONDARY),
                    )
                    .fill(Color32::TRANSPARENT)
                    .stroke(Stroke::new(1.0_f32, palette::BORDER))
                    .corner_radius(egui::CornerRadius::same(8)),
                )
                .clicked()
            {
                self.rx = None;
                self.state = AppState::Idle;
            }
        });
    }

    fn draw_verifying(ui: &mut egui::Ui) {
        Self::centered_status(ui, |ui| {
            ui.add(egui::Spinner::new().size(28.0).color(palette::PURPLE));
            ui.add_space(14.0);
            ui.label(
                RichText::new("Verifying SHA-256 checksum")
                    .size(16.0)
                    .color(palette::TEXT_PRIMARY),
            );
            ui.label(
                RichText::new("Checking file integrity before installing")
                    .size(13.0)
                    .color(palette::TEXT_SECONDARY),
            );
        });
    }

    fn draw_verifying_signature(ui: &mut egui::Ui) {
        Self::centered_status(ui, |ui| {
            ui.add(egui::Spinner::new().size(28.0).color(palette::PURPLE));
            ui.add_space(14.0);
            ui.label(
                RichText::new("Verifying PGP signature")
                    .size(16.0)
                    .color(palette::TEXT_PRIMARY),
            );
            ui.label(
                RichText::new("Checking the Tor Project's cryptographic signature")
                    .size(13.0)
                    .color(palette::TEXT_SECONDARY),
            );
        });
    }

    fn draw_installing(ui: &mut egui::Ui, stage: &str) {
        Self::centered_status(ui, |ui| {
            ui.add(egui::Spinner::new().size(28.0).color(palette::PURPLE));
            ui.add_space(14.0);
            ui.label(
                RichText::new("Installing")
                    .size(16.0)
                    .color(palette::TEXT_PRIMARY),
            );
            ui.label(
                RichText::new(stage)
                    .size(13.0)
                    .color(palette::TEXT_SECONDARY),
            );
        });
    }

    fn draw_complete(&mut self, ui: &mut egui::Ui, app_path: &Path) {
        let text_primary = self.text_primary();
        let text_secondary = self.text_secondary();
        let app_path = app_path.to_path_buf();
        ui.vertical_centered(|ui| {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(56.0, 56.0), egui::Sense::hover());
            let painter = ui.painter();
            painter.circle_filled(rect.center(), 28.0, palette::SUCCESS.gamma_multiply(0.12));
            icons::check(painter, rect.center(), 26.0, palette::SUCCESS);

            ui.add_space(10.0);
            ui.label(
                RichText::new("Installed")
                    .size(19.0)
                    .strong()
                    .color(text_primary),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("Tor Browser is ready at {}", app_path.display()))
                    .size(13.0)
                    .color(text_secondary),
            );
            ui.add_space(20.0);

            let launch_btn = ui.add_sized(
                [280.0, 46.0],
                egui::Button::new("")
                    .fill(palette::SUCCESS)
                    .stroke(Stroke::NONE)
                    .corner_radius(egui::CornerRadius::same(10)),
            );
            Self::icon_label_button(ui, &launch_btn, icons::launch, "Launch Tor Browser", Color32::WHITE);
            if launch_btn.clicked() {
                launch_app(&app_path);
            }

            ui.add_space(10.0);
            let folder_btn = ui.add_sized(
                [280.0, 46.0],
                egui::Button::new("")
                    .fill(self.purple_soft())
                    .stroke(Stroke::new(1.0_f32, palette::PURPLE))
                    .corner_radius(egui::CornerRadius::same(10)),
            );
            Self::icon_label_button(
                ui,
                &folder_btn,
                icons::folder,
                "Open Install Folder",
                palette::PURPLE,
            );
            if folder_btn.clicked() {
                if let Some(parent) = app_path.parent() {
                    open_folder(parent);
                }
            }
        });
    }

    fn draw_error(&mut self, ui: &mut egui::Ui, error: &str) {
        let text_primary = self.text_primary();
        let text_secondary = self.text_secondary();
        ui.vertical_centered(|ui| {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(56.0, 56.0), egui::Sense::hover());
            let painter = ui.painter();
            painter.circle_filled(rect.center(), 28.0, palette::ERROR.gamma_multiply(0.12));
            icons::cross(painter, rect.center(), 24.0, palette::ERROR);

            ui.add_space(10.0);
            ui.label(
                RichText::new("Something went wrong")
                    .size(18.0)
                    .strong()
                    .color(text_primary),
            );
            ui.add_space(6.0);
            ui.label(RichText::new(error).size(13.0).color(text_secondary));
            ui.add_space(18.0);

            if ui
                .add_sized(
                    [200.0, 42.0],
                    egui::Button::new(RichText::new("Try Again").size(14.0).color(Color32::WHITE))
                        .fill(palette::PURPLE)
                        .stroke(Stroke::NONE)
                        .corner_radius(egui::CornerRadius::same(10)),
                )
                .clicked()
            {
                self.state = AppState::Idle;
            }
        });
    }

    fn draw_footer(&mut self, ui: &mut egui::Ui) {
        let text_secondary = self.text_secondary();
        ui.horizontal(|ui| {
            ui.add_space((ui.available_width() - 220.0).max(0.0) / 2.0);
            let (rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
            icons::lock(ui.painter(), rect.center(), 14.0, text_secondary);
            ui.label(
                RichText::new("Secure  ·  Private  ·  Free")
                    .size(12.5)
                    .color(text_secondary),
            );
        });
    }

    // -------------------------------------------------------------
    // small helpers
    // -------------------------------------------------------------

    fn centered_status(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
        ui.vertical_centered(|ui| {
            ui.add_space(6.0);
            add_contents(ui);
            ui.add_space(6.0);
        });
    }

    fn icon_label_button(
        ui: &mut egui::Ui,
        response: &egui::Response,
        draw_icon: impl Fn(&egui::Painter, egui::Pos2, f32, Color32),
        label: &str,
        color: Color32,
    ) {
        let rect = response.rect;
        let painter = ui.painter();
        let icon_center = egui::pos2(rect.center().x - 70.0, rect.center().y);
        draw_icon(painter, icon_center, 16.0, color);
        painter.text(
            egui::pos2(rect.center().x - 50.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            label,
            egui::FontId::proportional(14.5),
            color,
        );
    }
}

impl eframe::App for TorBrowserBuilder {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Title("Tor Browser Installer".to_owned()));
        self.poll_worker(ctx);
        let bg = self.bg();
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(bg))
            .show(ctx, |ui| self.draw_app(ui));
    }
}

// ---------------------------------------------------------------------
// Background worker: fetch release info, download, verify, install.
// This runs on its own thread so the UI stays responsive.
// ---------------------------------------------------------------------

fn run_install_pipeline(
    install_dir: PathBuf,
    tx: Sender<WorkerEvent>,
    confirm_rx: Receiver<bool>,
) {
    let send_state = |s: AppState| {
        let _ = tx.send(WorkerEvent::State(s));
    };

    let release = match fetch_release_info() {
        Ok(r) => r,
        Err(e) => {
            send_state(AppState::Error(format!(
                "Could not fetch release information: {e}"
            )));
            return;
        }
    };

    // Ask the user to confirm before downloading
    send_state(AppState::ConfirmInstall {
        version: release.version.clone(),
        binary_url: release.binary_url.clone(),
        sha256: release.sha256.clone(),
        sig_url: release.sig_url.clone(),
    });

    match confirm_rx.recv() {
        Ok(true) => {}
        Ok(false) => {
            return;
        }
        Err(_) => {
            send_state(AppState::Error(
                "Confirmation channel closed unexpectedly".to_string(),
            ));
            return;
        }
    }

    let tmp_dir = std::env::temp_dir().join("tor-browser-builder");
    if let Err(e) = std::fs::create_dir_all(&tmp_dir) {
        send_state(AppState::Error(format!("Could not create temp dir: {e}")));
        return;
    }
    let archive_path = tmp_dir.join(format!(
        "TorBrowser-{}.{}",
        release.version,
        archive_extension()
    ));

    send_state(AppState::Downloading {
        progress: 0.0,
        downloaded_mb: 0.0,
        total_mb: 0.0,
    });

    if let Err(e) = download_with_progress(&release.binary_url, &archive_path, &tx) {
        send_state(AppState::Error(format!("Download failed: {e}")));
        return;
    }

    if let Some(expected) = &release.sha256 {
        send_state(AppState::Verifying);
        match sha256_of_file(&archive_path) {
            Ok(actual) if actual.eq_ignore_ascii_case(expected) => {}
            Ok(actual) => {
                send_state(AppState::Error(format!(
                    "Checksum mismatch — expected {expected}, got {actual}. \
                     The download will not be installed."
                )));
                return;
            }
            Err(e) => {
                send_state(AppState::Error(format!("Could not verify download: {e}")));
                return;
            }
        }
    }

    if let Some(sig_url) = &release.sig_url {
        send_state(AppState::VerifyingSignature);
        match verify_pgp_signature(&archive_path, sig_url) {
            Ok(()) => {}
            Err(e) => {
                send_state(AppState::Error(format!(
                    "PGP signature verification failed: {e}"
                )));
                return;
            }
        }
    }

    send_state(AppState::Installing {
        stage: "Preparing installation...".to_string(),
    });

    match install_release(&archive_path, &install_dir, &tx) {
        Ok(app_path) => send_state(AppState::Complete { app_path }),
        Err(e) => send_state(AppState::Error(format!("Install failed: {e}"))),
    }

    let _ = std::fs::remove_file(&archive_path);
}

/// Fetches release metadata from the Tor Project's release JSON API for
/// whichever platform this binary was built for.
///
/// NOTE: field names below are a best-effort guess at the
/// `download-<platform>.json` schema based on the historical
/// `downloads_v2.json` shape used by torbrowser-launcher. This build has no
/// network access at write time to confirm the *current* schema, so a few
/// plausible key names are tried for both the binary URL and the checksum,
/// per platform. Verify against the live endpoint before shipping —
/// Tor Project has changed this shape before, and it is not guaranteed to
/// be identical across download-macos.json / download-linux-*.json /
/// download-windows-*.json.
fn fetch_release_info() -> Result<ReleaseInfo, String> {
    let url = format!(
        "https://aus1.torproject.org/torbrowser/update_3/release/{}",
        release_json_filename()
    );

    let body: serde_json::Value = reqwest::blocking::Client::builder()
        .user_agent("tor-browser-builder/0.2")
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?
        .get(&url)
        .send()
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?
        .json()
        .map_err(|e| e.to_string())?;

    let version = body
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    // Try a top-level "binary" field first (matches the macOS shape this
    // build was originally written against), then fall back to a few
    // plausible nested pointers per platform.
    let binary_url = body
        .get("binary")
        .and_then(|v| v.as_str())
        .or_else(|| body.get("url").and_then(|v| v.as_str()))
        .or_else(|| {
            let pointer = if cfg!(target_os = "windows") {
                "/downloads/win64/en-US/binary"
            } else if cfg!(target_os = "linux") {
                "/downloads/linux64/en-US/binary"
            } else {
                "/downloads/osx64/en-US/binary"
            };
            body.pointer(pointer).and_then(|v| v.as_str())
        })
        .ok_or_else(|| {
            format!(
                "could not find a {} download URL in the release response",
                platform_label()
            )
        })?
        .to_string();

    // Not all API responses include a checksum field directly; when present
    // we use it, otherwise we skip the checksum step (the sig file, not
    // downloaded here, is the authoritative check — see the module doc).
    let sha_pointer = if cfg!(target_os = "windows") {
        "/downloads/win64/en-US/sha256"
    } else if cfg!(target_os = "linux") {
        "/downloads/linux64/en-US/sha256"
    } else {
        "/downloads/osx64/en-US/sha256"
    };
    let sha256 = body
        .get("sha256")
        .and_then(|v| v.as_str())
        .or_else(|| body.pointer(sha_pointer).and_then(|v| v.as_str()))
        .map(|s| s.to_string());

    // Try to find a signature URL. The Tor Project provides .asc detached
    // signatures alongside release binaries.
    let sig_url = body
        .get("sig")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            // Fallback: construct the signature URL from the binary URL
            // by appending ".asc"
            Some(format!("{binary_url}.asc"))
        });

    Ok(ReleaseInfo {
        version,
        binary_url,
        sha256,
        sig_url,
    })
}

fn download_with_progress(
    url: &str,
    dest: &Path,
    tx: &Sender<WorkerEvent>,
) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("tor-browser-builder/0.2")
        .timeout(Duration::from_secs(600))
        .build()
        .map_err(|e| e.to_string())?;

    let mut response = client.get(url).send().map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("server returned {}", response.status()));
    }

    let total_bytes = response.content_length().unwrap_or(0);
    let mut file = std::fs::File::create(dest).map_err(|e| e.to_string())?;

    let mut buf = [0u8; 64 * 1024];
    let mut downloaded: u64 = 0;
    loop {
        let n = response.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        downloaded += n as u64;

        let progress = if total_bytes > 0 {
            downloaded as f32 / total_bytes as f32
        } else {
            0.0
        };
        let _ = tx.send(WorkerEvent::State(AppState::Downloading {
            progress,
            downloaded_mb: downloaded as f32 / (1024.0 * 1024.0),
            total_mb: total_bytes as f32 / (1024.0 * 1024.0),
        }));
    }

    Ok(())
}

fn sha256_of_file(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Verifies a detached PGP signature against a file using the
/// Tor Browser Developers signing key.
///
/// Downloads the key from keys.openpgp.org at runtime, then verifies the
/// .asc detached signature against the downloaded archive.
fn verify_pgp_signature(file_path: &Path, sig_url: &str) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("tor-browser-builder/0.2")
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    // Download the .asc detached signature
    let sig_bytes = client
        .get(sig_url)
        .send()
        .map_err(|e| format!("failed to download signature: {e}"))?
        .error_for_status()
        .map_err(|e| format!("signature download failed: {e}"))?
        .bytes()
        .map_err(|e| e.to_string())?;

    // Fetch the Tor Browser Developers signing key from keys.openpgp.org
    // Fingerprint: EF6E286DDA85EA2A4BA7DE684E2C6E8793298290
    let key_url = "https://keys.openpgp.org/vks/v1/by-fingerprint/EF6E286DDA85EA2A4BA7DE684E2C6E8793298290";
    let key_bytes = client
        .get(key_url)
        .send()
        .map_err(|e| format!("failed to fetch Tor Browser signing key: {e}"))?
        .error_for_status()
        .map_err(|e| format!("signing key download failed: {e}"))?
        .bytes()
        .map_err(|e| e.to_string())?;

    // Parse the key as an OpenPGP Cert
    let cert = openpgp::Cert::from_bytes(&key_bytes)
        .map_err(|e| format!("failed to parse Tor Browser signing key: {e}"))?;

    // Read the file to verify
    let file_bytes = std::fs::read(file_path).map_err(|e| e.to_string())?;

    // Helper that feeds the Tor Browser Developers key to the verifier
    struct TorKeyHelper {
        cert: openpgp::Cert,
    }

    impl VerificationHelper for TorKeyHelper {
        fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
            Ok(vec![self.cert.clone()])
        }

        fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
            for layer in structure {
                if let MessageLayer::SignatureGroup { results } = layer {
                    if results.iter().any(|r| r.is_ok()) {
                        return Ok(());
                    }
                }
            }
            Err(anyhow::anyhow!(
                "No valid signature found from the Tor Browser Developers"
            ))
        }
    }

    let policy = StandardPolicy::new();
    let helper = TorKeyHelper { cert };

    let mut verifier = DetachedVerifierBuilder::from_bytes(sig_bytes.as_ref())
        .map_err(|e| format!("failed to parse .asc signature: {e}"))?
        .with_policy(&policy, None, helper)
        .map_err(|e| format!("signature verification setup failed: {e}"))?;

    verifier
        .verify_bytes(file_bytes.as_slice())
        .map_err(|e| format!("PGP signature verification failed: {e}"))?;

    Ok(())
}

/// Dispatches to the platform-appropriate install routine. Each build only
/// compiles the branch matching its own `target_os`, so this is resolved at
/// compile time, not runtime — a Windows build never contains the macOS
/// hdiutil code and vice versa.
fn install_release(
    archive_path: &Path,
    install_dir: &Path,
    tx: &Sender<WorkerEvent>,
) -> Result<PathBuf, String> {
    let send_stage = |stage: &str| {
        let _ = tx.send(WorkerEvent::State(AppState::Installing {
            stage: stage.to_string(),
        }));
    };

    #[cfg(target_os = "macos")]
    {
        install_from_dmg(archive_path, install_dir, send_stage)
    }
    #[cfg(target_os = "linux")]
    {
        let _ = send_stage;
        install_from_targz(archive_path, install_dir)
    }
    #[cfg(target_os = "windows")]
    {
        let _ = send_stage;
        install_from_exe(archive_path, install_dir)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (archive_path, install_dir, send_stage);
        Err("automatic installation is not implemented for this platform".to_string())
    }
}

#[cfg(target_os = "macos")]
fn install_from_dmg(
    dmg_path: &Path,
    install_dir: &Path,
    send_stage: impl Fn(&str),
) -> Result<PathBuf, String> {
    use std::process::Command;

    send_stage("Attaching disk image...");
    let attach_output = Command::new("hdiutil")
        .args(["attach", "-nobrowse", "-quiet"])
        .arg(dmg_path)
        .output()
        .map_err(|e| format!("failed to run hdiutil attach: {e}"))?;
    if !attach_output.status.success() {
        return Err(format!(
            "hdiutil attach failed: {}",
            String::from_utf8_lossy(&attach_output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&attach_output.stdout);
    let mount_point = stdout
        .lines()
        .filter_map(|line| line.split('\t').last())
        .map(str::trim)
        .find(|s| s.starts_with("/Volumes/"))
        .ok_or("could not determine mount point from hdiutil output")?
        .to_string();
    let mount_point = PathBuf::from(mount_point);

    send_stage("Locating application bundle...");
    let app_source = std::fs::read_dir(&mount_point)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().map(|ext| ext == "app").unwrap_or(false))
        .ok_or_else(|| {
            let _ = Command::new("hdiutil").args(["detach", "-quiet"]).arg(&mount_point).status();
            "no .app bundle found inside the disk image".to_string()
        })?;

    std::fs::create_dir_all(install_dir).map_err(|e| e.to_string())?;
    let app_name = app_source
        .file_name()
        .ok_or("app bundle had no file name")?;
    let dest = install_dir.join(app_name);

    send_stage("Copying application to install location...");
    if dest.exists() {
        std::fs::remove_dir_all(&dest).map_err(|e| e.to_string())?;
    }
    let copy_status = Command::new("cp")
        .args(["-R"])
        .arg(&app_source)
        .arg(install_dir)
        .status()
        .map_err(|e| format!("failed to run cp: {e}"))?;
    if !copy_status.success() {
        let _ = Command::new("hdiutil").args(["detach", "-quiet"]).arg(&mount_point).status();
        return Err("copying the app bundle failed".to_string());
    }

    send_stage("Unmounting disk image...");
    let _ = Command::new("hdiutil")
        .args(["detach", "-quiet"])
        .arg(&mount_point)
        .status();

    Ok(dest)
}

/// Linux releases ship as a `.tar.xz` containing a top-level `tor-browser/`
/// directory. We extract it into the install dir with the system `tar`
/// (rather than pulling in a `.xz` decoder crate) and locate the launcher
/// script inside it.
#[cfg(target_os = "linux")]
fn install_from_targz(archive_path: &Path, install_dir: &Path) -> Result<PathBuf, String> {
    use std::process::Command;

    std::fs::create_dir_all(install_dir).map_err(|e| e.to_string())?;

    let status = Command::new("tar")
        .arg("-xJf")
        .arg(archive_path)
        .arg("-C")
        .arg(install_dir)
        .status()
        .map_err(|e| format!("failed to run tar (is it installed?): {e}"))?;
    if !status.success() {
        return Err("extracting the .tar.xz archive failed".to_string());
    }

    // Find the launcher script anywhere under the extracted tree instead of
    // hardcoding "tor-browser/Browser/start-tor-browser", since the Tor
    // Project has occasionally changed the top-level directory name.
    let launcher = find_file(install_dir, "start-tor-browser")
        .ok_or("could not find start-tor-browser inside the extracted archive")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&launcher) {
            let mut perms = meta.permissions();
            perms.set_mode(perms.mode() | 0o111);
            let _ = std::fs::set_permissions(&launcher, perms);
        }
    }

    Ok(launcher)
}

/// Windows releases ship as an NSIS-based self-extracting `.exe`. We attempt
/// a silent install (`/S` with an `/D=` target directory, the NSIS
/// convention — `/D=` must be the final argument and unquoted). If that
/// flag isn't actually supported by the current installer build, this will
/// need to fall back to just launching the .exe and letting the person
/// click through it like the "ancient" installer this app is trying to
/// replace — that fallback isn't implemented here since it can't be
/// verified without a live Windows build to test against.
#[cfg(target_os = "windows")]
fn install_from_exe(exe_path: &Path, install_dir: &Path) -> Result<PathBuf, String> {
    use std::process::Command;

    std::fs::create_dir_all(install_dir).map_err(|e| e.to_string())?;

    let target_arg = format!("/D={}", install_dir.display());
    let status = Command::new(exe_path)
        .args(["/S"])
        .arg(target_arg)
        .status()
        .map_err(|e| format!("failed to launch the installer: {e}"))?;
    if !status.success() {
        return Err(
            "the Tor Browser installer exited with an error (silent-install flags may not be \
             supported by this release — try running the downloaded .exe manually)"
                .to_string(),
        );
    }

    let exe = find_file(install_dir, "firefox.exe")
        .or_else(|| find_file(install_dir, "Tor Browser.exe"))
        .ok_or("installer finished but the Tor Browser executable was not found")?;
    Ok(exe)
}

/// Recursively searches `root` for a file whose name matches `target`,
/// returning the first match. Used by the Linux and Windows install paths
/// to locate the launcher inside an extracted/installed tree without
/// depending on an exact directory layout.
fn find_file(root: &Path, target: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(root).ok()?;
    let mut subdirs = Vec::new();
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else if path.file_name().map(|n| n == target).unwrap_or(false) {
            return Some(path);
        }
    }
    for dir in subdirs {
        if let Some(found) = find_file(&dir, target) {
            return Some(found);
        }
    }
    None
}

/// Checks common install locations for an existing Tor Browser installation.
fn find_existing_install() -> Option<PathBuf> {
    let base = default_install_path();
    if cfg!(target_os = "macos") {
        let app = base.join("Tor Browser.app");
        if app.exists() {
            return Some(app);
        }
    } else if cfg!(target_os = "linux") {
        let launcher = find_file(&base, "start-tor-browser");
        if let Some(path) = launcher {
            return Some(path);
        }
    } else if cfg!(target_os = "windows") {
        let exe = find_file(&base, "firefox.exe")
            .or_else(|| find_file(&base, "Tor Browser.exe"));
        if let Some(path) = exe {
            return Some(path);
        }
    }
    None
}

fn launch_app(app_path: &Path) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(app_path).spawn();
    }
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        // On Linux this is the start-tor-browser script; on Windows it's
        // the installed executable. Both are directly spawnable.
        let _ = std::process::Command::new(app_path).spawn();
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = app_path;
    }
}

fn open_folder(folder: &Path) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(folder).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(folder).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("explorer").arg(folder).spawn();
    }
}

// ---------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------

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
        "Tor Browser Builder",
        options,
        Box::new(|cc| Ok(Box::new(TorBrowserBuilder::new(cc)))),
    )
}