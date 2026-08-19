//! All UI drawing: this used to be >1000 lines inside the same impl block
//! as app.rs's worker plumbing. It's its own `impl TorBrowserBuilder` block
//! here, which Rust is fine with as long as the fields/types it touches are
//! visible (see the `pub(crate)` on TorBrowserBuilder's fields in app.rs).
use std::path::{Path, PathBuf};
use egui::{Color32, Rect, RichText, Stroke};

use crate::app::{TorBrowserBuilder, AppState};
use crate::theme::{Theme, palette};
use crate::platform::{InstallScope, platform_label, launch_app, open_folder};
use crate::icons;
use crate::{APP_VERSION, APP_AUTHOR};

impl TorBrowserBuilder {
    // -------------------------------------------------------------
    // Layout
    // -------------------------------------------------------------

    pub(crate) fn draw_app(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.set_max_width(560.0);
            ui.add_space(28.0);
            self.draw_header(ui);
            ui.add_space(24.0);
            self.draw_card(ui);
            ui.add_space(20.0);
            self.draw_footer(ui);
        });
        self.draw_about_overlay(ui.ctx());
    }

    pub(crate) fn draw_header(&mut self, ui: &mut egui::Ui) {
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
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let (icon_rect, _) =
                        ui.allocate_exact_size(egui::vec2(13.0, 13.0), egui::Sense::hover());
                    icons::package(&ui.painter(), icon_rect, palette::GOLD);
                    ui.add_space(3.0);
                    ui.label(
                        RichText::new("Beta")
                            .size(14.0)
                            .strong()
                            .color(palette::TEXT_PRIMARY),
                    );
                });
            });
            ui.add_space((ui.available_width() - 120.0).max(0.0));
            let about_btn = ui.add_sized(
                [36.0, 36.0],
                egui::Button::new("")
                    .fill(self.surface())
                    .stroke(Stroke::new(1.0_f32, self.border()))
                    .corner_radius(egui::CornerRadius::same(8)),
            );
            icons::info(&ui.painter(), about_btn.rect.shrink(9.0), self.text_primary());
            if about_btn.clicked() {
                self.show_about = true;
            }
            ui.add_space(8.0);
            let theme_btn = ui.add_sized(
                [36.0, 36.0],
                egui::Button::new("")
                    .fill(self.surface())
                    .stroke(Stroke::new(1.0_f32, self.border()))
                    .corner_radius(egui::CornerRadius::same(8)),
            );
            let icon_rect = theme_btn.rect.shrink(8.0);
            match self.theme {
                Theme::Light => icons::moon(&ui.painter(), icon_rect, self.text_primary(), self.surface()),
                Theme::Dark => icons::sun(&ui.painter(), icon_rect, self.text_primary()),
            }
            if theme_btn.clicked() {
                self.theme = match self.theme {
                    Theme::Light => Theme::Dark,
                    Theme::Dark => Theme::Light,
                };
                self.apply_theme(ui.ctx());
            }
        });
    }

    pub(crate) fn draw_card(&mut self, ui: &mut egui::Ui) {
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
                self.draw_command_log(ui);
            });
    }

    /// A collapsible "View commands" panel showing every system command the
    /// worker thread has run so far (or is about to run), in order. Hidden
    /// entirely until there's at least one command to show, so it doesn't
    /// clutter the idle screen before an install has started.
    pub(crate) fn draw_command_log(&mut self, ui: &mut egui::Ui) {
        if self.command_log.is_empty() {
            return;
        }
        let text_secondary = self.text_secondary();
        let bg = self.bg();
        let border = self.border();
        ui.add_space(16.0);
        ui.separator();
        ui.add_space(6.0);

        let toggle = ui.add(
            egui::Button::new(
                RichText::new(format!(
                    "   View commands ({} run)",
                    self.command_log.len()
                ))
                .size(12.5)
                .color(text_secondary),
            )
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::NONE),
        );
        let chevron_rect = Rect::from_center_size(
            egui::pos2(toggle.rect.left() + 9.0, toggle.rect.center().y),
            egui::vec2(11.0, 11.0),
        );
        if self.show_command_log {
            icons::chevron_down(&ui.painter(), chevron_rect, text_secondary);
        } else {
            icons::chevron_right(&ui.painter(), chevron_rect, text_secondary);
        }
        if toggle.clicked() {
            self.show_command_log = !self.show_command_log;
        }

        if self.show_command_log {
            ui.add_space(6.0);
            egui::Frame::NONE
                .fill(bg)
                .stroke(Stroke::new(1.0_f32, border))
                .corner_radius(egui::CornerRadius::same(8))
                .inner_margin(egui::Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .max_height(160.0)
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for line in &self.command_log {
                                ui.label(
                                    RichText::new(line.as_str())
                                        .size(11.5)
                                        .monospace()
                                        .color(text_secondary),
                                );
                            }
                        });
                });
        }
    }
}

impl TorBrowserBuilder {
    pub(crate) fn draw_idle(&mut self, ui: &mut egui::Ui) {
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
                RichText::new("Install Location")
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

            ui.add_space(18.0);
            self.draw_scope_selector(ui);

            ui.add_space(22.0);
            let btn = ui.add_sized(
                [ui.available_width(), 46.0],
                egui::Button::new("")
                    .fill(palette::PURPLE)
                    .stroke(Stroke::NONE)
                    .corner_radius(egui::CornerRadius::same(10)),
            );
            let rect = btn.rect;
            let icon_rect = Rect::from_center_size(
                egui::pos2(rect.center().x - 92.0, rect.center().y),
                egui::vec2(18.0, 18.0),
            );
            icons::download(&ui.painter(), icon_rect, Color32::WHITE);
            ui.painter().text(
                egui::pos2(rect.center().x - 74.0, rect.center().y),
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
                    RichText::new(format!("Builds a native install for your {} computer", platform_label()))
                        .size(12.5)
                        .color(text_secondary),
                );
            });
        });
    }

    /// Lets the person choose between a per-user install (default, no
    /// privileges needed) and a system-wide install for every account on
    /// the machine. The latter needs `sudo`, so a password field appears
    /// once it's selected. Only offered on macOS and Linux — Windows uses
    /// its own installer-driven elevation instead.
    pub(crate) fn draw_scope_selector(&mut self, ui: &mut egui::Ui) {
        if !(cfg!(target_os = "macos") || cfg!(target_os = "linux")) {
            return;
        }
        let text_secondary = self.text_secondary();
        let text_primary = self.text_primary();
        let bg = self.bg();
        let border_color = self.border();

        ui.label(RichText::new("INSTALL FOR").size(11.0).color(text_secondary));
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let user_selected = self.install_scope == InstallScope::User;
            if ui.selectable_label(user_selected, "Just me").clicked() && !user_selected {
                self.install_scope = InstallScope::User;
                self.installation_path = InstallScope::User.default_path();
                self.install_path_text = self.installation_path.display().to_string();
            }
            let global_selected = self.install_scope == InstallScope::Global;
            if ui
                .selectable_label(global_selected, "All users")
                .clicked()
                && !global_selected
            {
                self.install_scope = InstallScope::Global;
                self.installation_path = InstallScope::Global.default_path();
                self.install_path_text = self.installation_path.display().to_string();
            }
        });

        if self.install_scope.needs_password() {
            ui.add_space(10.0);
            ui.label(
                RichText::new("ADMINISTRATOR PASSWORD")
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
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.sudo_password)
                                .password(!self.reveal_password)
                                .frame(false)
                                .desired_width(ui.available_width() - 44.0)
                                .text_color(text_primary)
                                .hint_text("Your account password"),
                        );
                        let label = if self.reveal_password { "Hide" } else { "Show" };
                        if ui
                            .add(
                                egui::Button::new(RichText::new(label).size(11.5).color(text_secondary))
                                    .fill(Color32::TRANSPARENT)
                                    .stroke(Stroke::NONE),
                            )
                            .clicked()
                        {
                            self.reveal_password = !self.reveal_password;
                        }
                    });
                });
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "Used locally to run `sudo -s` for this install.",
                )
                .size(11.0)
                .color(text_secondary),
            );
        }
    }

    pub(crate) fn draw_checking(ui: &mut egui::Ui) {
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

    pub(crate) fn draw_already_installed(&mut self, ui: &mut egui::Ui, app_path: &Path) {
        let text_primary = self.text_primary();
        let text_secondary = self.text_secondary();
        let app_path = app_path.to_path_buf();
        ui.vertical_centered(|ui| {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(56.0, 56.0), egui::Sense::hover());
            let painter = ui.painter();
            painter.circle_filled(rect.center(), 28.0, palette::GOLD.gamma_multiply(0.12));
            icons::lock(&painter, Rect::from_center_size(rect.center(), egui::vec2(24.0, 24.0)), palette::GOLD);

            ui.add_space(10.0);
            ui.label(
                RichText::new("Tor Browser is installed already.")
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

            ui.add_space(18.0);
            ui.separator();
            ui.add_space(12.0);
            ui.vertical(|ui| {
                self.draw_scope_selector(ui);
            });
            ui.add_space(14.0);

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

    pub(crate) fn draw_confirm(
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
                    .stroke(Stroke::new(1.0_f32, self.border()))
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
            let icon_rect = Rect::from_center_size(
                egui::pos2(rect.center().x - 48.0, rect.center().y),
                egui::vec2(16.0, 16.0),
            );
            icons::check(&ui.painter(), icon_rect, Color32::WHITE);
            ui.painter().text(
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
                .stroke(Stroke::new(1.0_f32, self.border()))
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

    pub(crate) fn draw_downloading(
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
                RichText::new("Downloading from server...")
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

    pub(crate) fn draw_verifying(ui: &mut egui::Ui) {
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

    pub(crate) fn draw_verifying_signature(ui: &mut egui::Ui) {
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

    pub(crate) fn draw_installing(ui: &mut egui::Ui, stage: &str) {
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

    pub(crate) fn draw_complete(&mut self, ui: &mut egui::Ui, app_path: &Path) {
        let text_primary = self.text_primary();
        let text_secondary = self.text_secondary();
        let app_path = app_path.to_path_buf();
        ui.vertical_centered(|ui| {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(56.0, 56.0), egui::Sense::hover());
            let painter = ui.painter();
            painter.circle_filled(rect.center(), 28.0, palette::SUCCESS.gamma_multiply(0.12));
            icons::check(&painter, Rect::from_center_size(rect.center(), egui::vec2(26.0, 26.0)), palette::SUCCESS);

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

    pub(crate) fn draw_error(&mut self, ui: &mut egui::Ui, error: &str) {
        let text_primary = self.text_primary();
        let text_secondary = self.text_secondary();
        ui.vertical_centered(|ui| {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(56.0, 56.0), egui::Sense::hover());
            let painter = ui.painter();
            painter.circle_filled(rect.center(), 28.0, palette::ERROR.gamma_multiply(0.12));
            icons::cross(&painter, Rect::from_center_size(rect.center(), egui::vec2(24.0, 24.0)), palette::ERROR);

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

    pub(crate) fn draw_footer(&mut self, ui: &mut egui::Ui) {
        let text_secondary = self.text_secondary();
        ui.horizontal(|ui| {
            ui.add_space((ui.available_width() - 260.0).max(0.0) / 2.0);
            let (icon_rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
            icons::lock(&ui.painter(), icon_rect.shrink(1.0), text_secondary);
            ui.add_space(4.0);
            ui.label(
                RichText::new("Browse Privately. Explore Freely.")
                    .size(12.5)
                    .color(text_secondary),
            );
        });
    }

    /// A centered modal with information about the app: what it is, who
    /// built it, and a reminder that it's an unofficial, third-party
    /// installer rather than anything from the Tor Project itself.
    pub(crate) fn draw_about_overlay(&mut self, ctx: &egui::Context) {
        if !self.show_about {
            return;
        }
        let text_primary = self.text_primary();
        let text_secondary = self.text_secondary();
        let surface = self.surface();
        let border = self.border();

        // Dim the rest of the app behind the modal.
        egui::Area::new(egui::Id::new("about_scrim"))
            .order(egui::Order::Foreground)
            .fixed_pos(egui::pos2(0.0, 0.0))
            .show(ctx, |ui| {
                let screen = ctx.screen_rect();
                ui.painter()
                    .rect_filled(screen, 0.0, Color32::from_black_alpha(140));
                // Clicking the scrim closes the modal, same as Cancel.
                if ui
                    .allocate_rect(screen, egui::Sense::click())
                    .clicked()
                {
                    self.show_about = false;
                }
            });

        let mut open = true;
        egui::Window::new("About")
            .id(egui::Id::new("about_window"))
            .order(egui::Order::Foreground)
            .collapsible(false)
            .resizable(false)
            .movable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .open(&mut open)
            .frame(
                egui::Frame::NONE
                    .fill(surface)
                    .stroke(Stroke::new(1.0_f32, border))
                    .corner_radius(egui::CornerRadius::same(16))
                    .inner_margin(egui::Margin::same(24)),
            )
            .show(ctx, |ui| {
                ui.set_width(360.0);
                ui.vertical_centered(|ui| {
                    ui.add(
                        egui::Image::from_bytes("bytes://tor_logo_tbb.svg", self.logo_bytes)
                            .fit_to_exact_size(egui::vec2(56.0, 56.0)),
                    );
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new("Tor Browser Installer")
                            .size(19.0)
                            .strong()
                            .color(text_primary),
                    );
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.add_space((ui.available_width() - 46.0).max(0.0) / 2.0);
                        let (icon_rect, _) =
                            ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
                        icons::package(&ui.painter(), icon_rect, palette::GOLD);
                        ui.add_space(3.0);
                        ui.label(
                            RichText::new("BETA")
                                .size(12.0)
                                .strong()
                                .color(palette::GOLD),
                        );
                    });
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(format!("Version {APP_VERSION}"))
                            .size(12.5)
                            .color(text_secondary),
                    );
                    ui.add_space(16.0);
                    ui.label(
                        RichText::new(
                            "Downloads, verifies, and installs Tor Browser straight from the \
                             Tor Project update servers.",
                        )
                        .size(13.5)
                        .color(text_primary),
                    );
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new(
                            "This is an unofficial, third-party tool and isn't affiliated with \
                             or endorsed by The Tor Project.",
                        )
                        .size(12.0)
                        .color(text_secondary),
                    );
                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(12.0);
                    ui.label(
                        RichText::new(format!("Made by {APP_AUTHOR}"))
                            .size(13.0)
                            .color(text_primary),
                    );
                    ui.add_space(16.0);

                    let close_btn = ui.add_sized(
                        [140.0, 38.0],
                        egui::Button::new(
                            RichText::new("Close").size(13.5).color(Color32::WHITE),
                        )
                        .fill(palette::PURPLE)
                        .stroke(Stroke::NONE)
                        .corner_radius(egui::CornerRadius::same(8)),
                    );
                    if close_btn.clicked() {
                        self.show_about = false;
                    }
                });
            });

        if !open {
            self.show_about = false;
        }
    }

    // -------------------------------------------------------------
    // small helpers
    // -------------------------------------------------------------

    pub(crate) fn centered_status(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
        ui.vertical_centered(|ui| {
            ui.add_space(6.0);
            add_contents(ui);
            ui.add_space(6.0);
        });
    }

    pub(crate) fn icon_label_button(
        ui: &mut egui::Ui,
        response: &egui::Response,
        draw_icon: impl Fn(&egui::Painter, Rect, Color32),
        label: &str,
        color: Color32,
    ) {
        let rect = response.rect;
        // Measure the label so the icon+text pair can be centered as a
        // unit, rather than pinned at a fixed offset that only happened
        // to look right for one particular label string.
        let font_id = egui::FontId::proportional(14.5);
        let galley = ui.painter().layout_no_wrap(label.to_string(), font_id.clone(), color);
        let icon_size = 16.0;
        let gap = 10.0;
        let total_width = icon_size + gap + galley.size().x;
        let start_x = rect.center().x - total_width / 2.0;

        let icon_rect = Rect::from_center_size(
            egui::pos2(start_x + icon_size / 2.0, rect.center().y),
            egui::vec2(icon_size, icon_size),
        );
        draw_icon(&ui.painter(), icon_rect, color);

        ui.painter().text(
            egui::pos2(start_x + icon_size + gap, rect.center().y),
            egui::Align2::LEFT_CENTER,
            label,
            font_id,
            color,
        );
    }
}
