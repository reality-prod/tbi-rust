//! App state + the TorBrowserBuilder struct: construction, worker plumbing
//! (start/poll/confirm), and theme color helpers. The big draw_* UI methods
//! live in ui.rs as a second `impl TorBrowserBuilder` block - Rust allows
//! multiple impl blocks for the same type across files in one crate.
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;
use egui::Color32;

use crate::platform::{InstallScope, default_install_path, find_existing_install};
use crate::theme::{Theme, palette, palette_dark};
use crate::install::{self, WorkerEvent};

// ---------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) enum AppState {
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

pub(crate) struct TorBrowserBuilder {
    pub(crate) state: AppState,
    pub(crate) installation_path: PathBuf,
    pub(crate) install_path_text: String,
    pub(crate) rx: Option<Receiver<WorkerEvent>>,
    pub(crate) confirm_tx: Option<Sender<bool>>,
    pub(crate) logo_bytes: &'static [u8],
    pub(crate) theme: Theme,
    /// Whether this run installs for the current user only or system-wide.
    pub(crate) install_scope: InstallScope,
    /// The sudo/administrator password for a Global install. Kept only in
    /// memory, sent once to the worker thread when the install starts, and
    /// never logged.
    pub(crate) sudo_password: String,
    /// Whether the password field shows plain text or dots.
    pub(crate) reveal_password: bool,
    /// Every command the worker has run so far this session, newest last —
    /// shown in the "View commands" panel.
    pub(crate) command_log: Vec<String>,
    /// Whether the "View commands" panel is expanded.
    pub(crate) show_command_log: bool,
    /// Whether the About overlay is open.
    pub(crate) show_about: bool,
}

impl TorBrowserBuilder {
    pub(crate) fn new(cc: &eframe::CreationContext<'_>) -> Self {
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
            install_scope: InstallScope::User,
            sudo_password: String::new(),
            reveal_password: false,
            command_log: Vec::new(),
            show_command_log: false,
            show_about: false,
        }
    }

    // -------------------------------------------------------------
    // Worker plumbing
    // -------------------------------------------------------------

    pub(crate) fn start_download(&mut self) {
        let (tx, rx): (Sender<WorkerEvent>, Receiver<WorkerEvent>) = std::sync::mpsc::channel();
        let (confirm_tx, confirm_rx): (Sender<bool>, Receiver<bool>) = std::sync::mpsc::channel();
        self.rx = Some(rx);
        self.confirm_tx = Some(confirm_tx);
        self.state = AppState::Checking;
        self.command_log.clear();

        let install_dir = self.installation_path.clone();
        let scope = self.install_scope;
        let password = self.sudo_password.clone();
        std::thread::spawn(move || {
            install::run_install_pipeline(install_dir, scope, password, tx, confirm_rx);
        });
    }

    pub(crate) fn send_confirm(&mut self, proceed: bool) {
        if let Some(tx) = self.confirm_tx.take() {
            let _ = tx.send(proceed);
        }
    }

    /// Drain any pending worker events. Called once per frame.
    pub(crate) fn poll_worker(&mut self, ctx: &egui::Context) {
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
                    WorkerEvent::Log(line) => {
                        self.command_log.push(line);
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
}

impl TorBrowserBuilder {
    pub(crate) fn text_primary(&self) -> Color32 {
        match self.theme {
            Theme::Light => palette::TEXT_PRIMARY,
            Theme::Dark => palette_dark::TEXT_PRIMARY,
        }
    }

    pub(crate) fn text_secondary(&self) -> Color32 {
        match self.theme {
            Theme::Light => palette::TEXT_SECONDARY,
            Theme::Dark => palette_dark::TEXT_SECONDARY,
        }
    }

    pub(crate) fn bg(&self) -> Color32 {
        match self.theme {
            Theme::Light => palette::BG,
            Theme::Dark => palette_dark::BG,
        }
    }

    pub(crate) fn surface(&self) -> Color32 {
        match self.theme {
            Theme::Light => palette::SURFACE,
            Theme::Dark => palette_dark::SURFACE,
        }
    }

    pub(crate) fn border(&self) -> Color32 {
        match self.theme {
            Theme::Light => palette::BORDER,
            Theme::Dark => palette_dark::BORDER,
        }
    }

    pub(crate) fn purple_soft(&self) -> Color32 {
        match self.theme {
            Theme::Light => palette::PURPLE_SOFT,
            Theme::Dark => palette_dark::PURPLE_SOFT,
        }
    }

    pub(crate) fn apply_theme(&self, ctx: &egui::Context) {
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
}

impl eframe::App for TorBrowserBuilder {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Title("Tor Browser Installer (Beta)".to_owned()));
        self.poll_worker(ctx);
        let bg = self.bg();
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(bg))
            .show(ctx, |ui| self.draw_app(ui));
    }
}
