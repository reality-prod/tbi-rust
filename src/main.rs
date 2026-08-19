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
use egui::{Color32, Rect, RichText, Stroke};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

use directories::UserDirs;
use sequoia_openpgp as openpgp;
use openpgp::parse::{Parse, stream::*};
use openpgp::policy::StandardPolicy;

/// This app's own version, shown in the About screen and sent as part of
/// the HTTP User-Agent when talking to the Tor Project's release API.
const APP_VERSION: &str = "0.07";
/// Credited in the About screen.
const APP_AUTHOR: &str = "Ribhav Sai Ramanuja Revalli";

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
///
/// On macOS this is the system-wide `/Applications` folder — the same place
/// Finder puts an app when you drag it out of a mounted `.dmg` — rather
/// than a user-specific subfolder. Writing there may require administrator
/// privileges depending on the account; `install_from_dmg` handles that by
/// falling back to an authenticated install (see `install_app_bundle_privileged`)
/// only if a plain copy is actually refused.
fn default_install_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        return PathBuf::from("/Applications");
    }
    if let Some(user_dirs) = UserDirs::new() {
        let home = user_dirs.home_dir();
        if cfg!(target_os = "windows") {
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

/// Whether the install targets just the current account or the whole
/// machine. A "global" install writes into a system-owned location
/// (`/Applications` on macOS, `/opt` on Linux) that regular users can't
/// write to, so it needs an administrator/root password up front rather
/// than discovering the permission failure partway through the copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallScope {
    /// Installs into a location the current user already owns. No
    /// elevated privileges are needed.
    User,
    /// Installs system-wide so every account on the machine can use it.
    /// On macOS and Linux this is done with `sudo -s`, authenticated with
    /// the password the person enters in the UI.
    Global,
}

impl InstallScope {
    /// The conventional install directory for this scope, matching each
    /// OS's own layout for a per-user vs. system-wide install.
    fn default_path(self) -> PathBuf {
        match self {
            InstallScope::User => default_install_path(),
            InstallScope::Global => {
                if cfg!(target_os = "macos") {
                    // /Applications is already system-owned; User scope on
                    // macOS points here too. Global just means the sudo
                    // password is collected up front instead of only after
                    // a plain copy fails.
                    PathBuf::from("/Applications")
                } else if cfg!(target_os = "linux") {
                    PathBuf::from("/opt/tor-browser")
                } else {
                    default_install_path()
                }
            }
        }
    }

    /// Whether this scope needs a sudo password on this platform. Only
    /// macOS and Linux support the sudo-based privileged install; Windows
    /// uses its own installer-driven elevation (UAC), so Global isn't
    /// offered there.
    fn needs_password(self) -> bool {
        self == InstallScope::Global && (cfg!(target_os = "macos") || cfg!(target_os = "linux"))
    }
}

// ---------------------------------------------------------------------
// Vector icons — no emoji anywhere. Everything below is drawn with the
// egui Painter so it scales cleanly and matches the palette.
// ---------------------------------------------------------------------

mod icons {
    //! Every icon here is painted directly with `egui::Painter` — lines,
    //! arcs, and circles built from primitives that ship with egui itself.
    //! There are no external SVG files to go missing and no reliance on
    //! glyphs being present in whatever font egui happens to load, so
    //! nothing can turn into a "tofu box" (missing-glyph square) or a
    //! blank space.
    //!
    //! Each function below is a direct transliteration of the matching
    //! Feather-style SVG (24x24 viewBox, `stroke="currentColor"`,
    //! `stroke-width="2"`) into `Painter` calls: every `M`/`L`/`H`/`V`/
    //! `line`/`polyline` coordinate is mapped from the SVG's 0..24 space
    //! onto whatever `Rect` the caller hands in via `p()`, so the shapes
    //! match the original artwork rather than being freehand
    //! approximations. Rounded corners in the source paths (the small
    //! `a2 2 0 0 1 ...` arcs) are simplified to straight corners, which
    //! is not visible at icon sizes.
    //!
    //! Each function takes the exact `Rect` to paint into and draws only
    //! inside it — callers are expected to have already worked out where
    //! that rect is (typically a button's own `response.rect`, or a rect
    //! from a single `ui.allocate_exact_size` call). Painting into a rect
    //! something else already allocated (rather than allocating a new,
    //! unrelated one) is what keeps an icon glued to the button/circle it
    //! belongs to.

    use egui::{Color32, Painter, Pos2, Rect, Stroke, Vec2};

    /// Maps a point in the source SVG's 0..24 coordinate space onto `rect`.
    fn p(rect: Rect, x: f32, y: f32) -> Pos2 {
        Pos2::new(
            rect.left() + x / 24.0 * rect.width(),
            rect.top() + y / 24.0 * rect.height(),
        )
    }

    fn stroke(rect: Rect, color: Color32) -> Stroke {
        // stroke-width="2" on a 24-unit viewBox.
        Stroke::new((rect.width() * (2.0 / 24.0)).max(1.4), color)
    }

    /// Draws consecutive line segments through `pts`, open (not closed).
    fn polyline(painter: &Painter, pts: &[Pos2], stroke: Stroke) {
        for pair in pts.windows(2) {
            painter.line_segment([pair[0], pair[1]], stroke);
        }
    }

    fn arc_points(center: Pos2, radius: f32, start_deg: f32, end_deg: f32, segments: usize) -> Vec<Pos2> {
        (0..=segments)
            .map(|i| {
                let t = start_deg + (end_deg - start_deg) * (i as f32 / segments as f32);
                let rad = t.to_radians();
                Pos2::new(center.x + radius * rad.cos(), center.y + radius * rad.sin())
            })
            .collect()
    }

    /// download.svg — tray with a downward arrow.
    pub fn download(painter: &Painter, rect: Rect, color: Color32) {
        let s = stroke(rect, color);
        // M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4 (corners squared off)
        polyline(
            painter,
            &[
                p(rect, 21.0, 15.0),
                p(rect, 21.0, 19.0),
                p(rect, 19.0, 21.0),
                p(rect, 5.0, 21.0),
                p(rect, 3.0, 19.0),
                p(rect, 3.0, 15.0),
            ],
            s,
        );
        // polyline points="7 10 12 15 17 10"
        polyline(
            painter,
            &[p(rect, 7.0, 10.0), p(rect, 12.0, 15.0), p(rect, 17.0, 10.0)],
            s,
        );
        // line x1=12 y1=15 x2=12 y2=3
        painter.line_segment([p(rect, 12.0, 15.0), p(rect, 12.0, 3.0)], s);
    }

    /// check.svg — a checkmark.
    pub fn check(painter: &Painter, rect: Rect, color: Color32) {
        let s = stroke(rect, color);
        // polyline points="20 6 9 17 4 12"
        polyline(
            painter,
            &[p(rect, 20.0, 6.0), p(rect, 9.0, 17.0), p(rect, 4.0, 12.0)],
            s,
        );
    }

    /// cross.svg — an X mark.
    pub fn cross(painter: &Painter, rect: Rect, color: Color32) {
        let s = stroke(rect, color);
        painter.line_segment([p(rect, 18.0, 6.0), p(rect, 6.0, 18.0)], s);
        painter.line_segment([p(rect, 6.0, 6.0), p(rect, 18.0, 18.0)], s);
    }

    /// folder.svg — a folder-plus outline.
    pub fn folder(painter: &Painter, rect: Rect, color: Color32) {
        let s = stroke(rect, color);
        // M22 19a..-2 2H4a..-2-2V5a..2-2h5l2 3h9a..2 2z (corners squared off)
        let pts = [
            p(rect, 22.0, 19.0),
            p(rect, 20.0, 21.0),
            p(rect, 4.0, 21.0),
            p(rect, 2.0, 19.0),
            p(rect, 2.0, 5.0),
            p(rect, 4.0, 3.0),
            p(rect, 9.0, 3.0),
            p(rect, 11.0, 6.0),
            p(rect, 20.0, 6.0),
            p(rect, 22.0, 8.0),
            p(rect, 22.0, 19.0),
        ];
        polyline(painter, &pts, s);
        // line x1=12 y1=11 x2=12 y2=17 (the "+" stem)
        painter.line_segment([p(rect, 12.0, 11.0), p(rect, 12.0, 17.0)], s);
        // line x1=9 y1=14 x2=15 y2=14 (the "+" bar)
        painter.line_segment([p(rect, 9.0, 14.0), p(rect, 15.0, 14.0)], s);
    }

    /// launch.svg — an arrow pointing right.
    pub fn launch(painter: &Painter, rect: Rect, color: Color32) {
        let s = stroke(rect, color);
        // line x1=5 y1=12 x2=19 y2=12
        painter.line_segment([p(rect, 5.0, 12.0), p(rect, 19.0, 12.0)], s);
        // polyline points="12 5 19 12 12 19"
        polyline(
            painter,
            &[p(rect, 12.0, 5.0), p(rect, 19.0, 12.0), p(rect, 12.0, 19.0)],
            s,
        );
    }

    /// lock.svg — a padlock.
    pub fn lock(painter: &Painter, rect: Rect, color: Color32) {
        let s = stroke(rect, color);
        // rect x=3 y=11 width=18 height=11 rx=2 ry=2 (corners squared off)
        let body = [
            p(rect, 3.0, 11.0),
            p(rect, 21.0, 11.0),
            p(rect, 21.0, 22.0),
            p(rect, 3.0, 22.0),
            p(rect, 3.0, 11.0),
        ];
        polyline(painter, &body, s);
        // M7 11V7a5 5 0 0 1 10 0v4 — shackle: down-segment, semicircle arc, down-segment
        painter.line_segment([p(rect, 7.0, 11.0), p(rect, 7.0, 7.0)], s);
        let center = p(rect, 12.0, 7.0);
        let radius = 5.0 / 24.0 * rect.width();
        let arc = arc_points(center, radius, 180.0, 360.0, 16);
        painter.add(egui::Shape::line(arc, s));
        painter.line_segment([p(rect, 17.0, 7.0), p(rect, 17.0, 11.0)], s);
    }

    /// beta.svg — an open box / package, used next to the "BETA" badge.
    pub fn package(painter: &Painter, rect: Rect, color: Color32) {
        let s = stroke(rect, color);
        // M12 2L2 7l10 5 10-5-10-5z (closed top face)
        let top = [
            p(rect, 12.0, 2.0),
            p(rect, 2.0, 7.0),
            p(rect, 12.0, 12.0),
            p(rect, 22.0, 7.0),
            p(rect, 12.0, 2.0),
        ];
        polyline(painter, &top, s);
        // M2 17l10 5 10-5
        polyline(
            painter,
            &[p(rect, 2.0, 17.0), p(rect, 12.0, 22.0), p(rect, 22.0, 17.0)],
            s,
        );
        // M2 12l10 5 10-5
        polyline(
            painter,
            &[p(rect, 2.0, 12.0), p(rect, 12.0, 17.0), p(rect, 22.0, 12.0)],
            s,
        );
    }

    /// A circled "i" — used for the About button. Not from an SVG file;
    /// there's no info-circle in the uploaded set, so this stays
    /// procedurally drawn to match the same visual weight as the others.
    pub fn info(painter: &Painter, rect: Rect, color: Color32) {
        let s = Stroke::new((rect.width() * (2.0 / 24.0)).max(1.4), color);
        let r = rect.width() * 0.40;
        painter.circle_stroke(rect.center(), r, s);
        let dot_r = (rect.width() * 0.06).max(1.2);
        painter.circle_filled(
            Pos2::new(rect.center().x, rect.center().y - r * 0.42),
            dot_r,
            color,
        );
        painter.line_segment(
            [
                Pos2::new(rect.center().x, rect.center().y - r * 0.05),
                Pos2::new(rect.center().x, rect.center().y + r * 0.48),
            ],
            s,
        );
    }

    /// A crescent moon — light-theme toggle indicator. `bg` is the color
    /// behind the icon, used to "cut" the crescent out of a filled circle.
    /// Not from an SVG file (none was provided for this), so it stays
    /// procedurally drawn.
    pub fn moon(painter: &Painter, rect: Rect, color: Color32, bg: Color32) {
        let r = rect.width() * 0.34;
        painter.circle_filled(rect.center(), r, color);
        let cut_center = Pos2::new(rect.center().x + r * 0.55, rect.center().y - r * 0.32);
        painter.circle_filled(cut_center, r * 0.88, bg);
    }

    /// A sun (circle with rays) — dark-theme toggle indicator. Not from
    /// an SVG file, so it stays procedurally drawn.
    pub fn sun(painter: &Painter, rect: Rect, color: Color32) {
        let s = Stroke::new((rect.width() * (2.0 / 24.0)).max(1.4), color);
        let r = rect.width() * 0.20;
        painter.circle_stroke(rect.center(), r, s);
        for i in 0..8 {
            let angle = i as f32 * std::f32::consts::FRAC_PI_4;
            let dir = Vec2::angled(angle);
            let inner = rect.center() + dir * (r * 1.35);
            let outer = rect.center() + dir * (r * 1.9);
            painter.line_segment([inner, outer], s);
        }
    }

    /// A small downward chevron ("expand"). Not from an SVG file.
    pub fn chevron_down(painter: &Painter, rect: Rect, color: Color32) {
        let s = Stroke::new((rect.width() * (2.0 / 24.0)).max(1.4), color);
        let w = rect.width();
        let h = rect.height();
        let p1 = Pos2::new(rect.left() + w * 0.20, rect.top() + h * 0.35);
        let p2 = Pos2::new(rect.center().x, rect.top() + h * 0.65);
        let p3 = Pos2::new(rect.right() - w * 0.20, rect.top() + h * 0.35);
        painter.line_segment([p1, p2], s);
        painter.line_segment([p2, p3], s);
    }

    /// A small rightward chevron ("collapsed"). Not from an SVG file.
    pub fn chevron_right(painter: &Painter, rect: Rect, color: Color32) {
        let s = Stroke::new((rect.width() * (2.0 / 24.0)).max(1.4), color);
        let w = rect.width();
        let h = rect.height();
        let p1 = Pos2::new(rect.left() + w * 0.32, rect.top() + h * 0.18);
        let p2 = Pos2::new(rect.right() - w * 0.32, rect.center().y);
        let p3 = Pos2::new(rect.left() + w * 0.32, rect.bottom() - h * 0.18);
        painter.line_segment([p1, p2], s);
        painter.line_segment([p2, p3], s);
    }

    /// Allocates a fresh square of layout space and paints `draw` into it.
    /// Use this only for a *standalone* icon that owns its own spot in the
    /// layout (e.g. sitting alone in a horizontal row). Never use this for
    /// an icon that belongs inside a rect something else already
    /// allocated (a button, a status circle) — paint directly into that
    /// rect instead, or the icon will land in the wrong place.
    pub fn standalone(
        ui: &mut egui::Ui,
        size: f32,
        draw: impl FnOnce(&Painter, Rect, Color32),
        color: Color32,
    ) -> egui::Response {
        let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
        draw(&ui.painter(), rect, color);
        response
    }
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
    /// A shell/system command the worker is about to run (or its result),
    /// shown to the person in the "View commands" panel. Passwords are
    /// never included in these lines.
    Log(String),
}

/// Sends a line to the "View commands" panel. Centralized so every call
/// site formats log lines the same way and so passwords can never leak
/// into it by accident — callers pass already-redacted text.
fn log_line(tx: &Sender<WorkerEvent>, line: impl Into<String>) {
    let _ = tx.send(WorkerEvent::Log(line.into()));
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
    /// Whether this run installs for the current user only or system-wide.
    install_scope: InstallScope,
    /// The sudo/administrator password for a Global install. Kept only in
    /// memory, sent once to the worker thread when the install starts, and
    /// never logged.
    sudo_password: String,
    /// Whether the password field shows plain text or dots.
    reveal_password: bool,
    /// Every command the worker has run so far this session, newest last —
    /// shown in the "View commands" panel.
    command_log: Vec<String>,
    /// Whether the "View commands" panel is expanded.
    show_command_log: bool,
    /// Whether the About overlay is open.
    show_about: bool,
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

    fn start_download(&mut self) {
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
            run_install_pipeline(install_dir, scope, password, tx, confirm_rx);
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
        self.draw_about_overlay(ui.ctx());
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
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let (icon_rect, _) =
                        ui.allocate_exact_size(egui::vec2(13.0, 13.0), egui::Sense::hover());
                    icons::package(&ui.painter(), icon_rect, palette::GOLD);
                    ui.add_space(3.0);
                    ui.label(
                        RichText::new("BETA")
                            .size(14.0)
                            .strong()
                            .color(palette::GOLD),
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
                self.draw_command_log(ui);
            });
    }

    /// A collapsible "View commands" panel showing every system command the
    /// worker thread has run so far (or is about to run), in order. Hidden
    /// entirely until there's at least one command to show, so it doesn't
    /// clutter the idle screen before an install has started.
    fn draw_command_log(&mut self, ui: &mut egui::Ui) {
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
                    RichText::new(format!("Builds a native install for {}", platform_label()))
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
    fn draw_scope_selector(&mut self, ui: &mut egui::Ui) {
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
                .selectable_label(global_selected, "All users (sudo)")
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
                    "Used locally to run `sudo -s` for this install. Never stored or sent \
                     anywhere.",
                )
                .size(11.0)
                .color(text_secondary),
            );
        }
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
            icons::lock(&painter, Rect::from_center_size(rect.center(), egui::vec2(24.0, 24.0)), palette::GOLD);

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

    fn draw_error(&mut self, ui: &mut egui::Ui, error: &str) {
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

    fn draw_footer(&mut self, ui: &mut egui::Ui) {
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
    fn draw_about_overlay(&mut self, ctx: &egui::Context) {
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
                             Tor Project.",
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

impl eframe::App for TorBrowserBuilder {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Title("Tor Browser Installer BETA".to_owned()));
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
    scope: InstallScope,
    password: String,
    tx: Sender<WorkerEvent>,
    confirm_rx: Receiver<bool>,
) {
    let send_state = |s: AppState| {
        let _ = tx.send(WorkerEvent::State(s));
    };

    if scope.needs_password() {
        log_line(
            &tx,
            format!(
                "Install scope: all users ({}  -  sudo)",
                install_dir.display()
            ),
        );
    } else {
        log_line(
            &tx,
            format!("Install scope: current user ({})", install_dir.display()),
        );
    }

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
                    "Checksum mismatch  -  expected {expected}, got {actual}. \
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

    match install_release(&archive_path, &install_dir, scope, &password, &tx) {
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
        .user_agent(format!("tor-browser-builder/{APP_VERSION}"))
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
        .user_agent(format!("tor-browser-builder/{APP_VERSION}"))
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
        .user_agent(format!("tor-browser-builder/{APP_VERSION}"))
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
    scope: InstallScope,
    password: &str,
    tx: &Sender<WorkerEvent>,
) -> Result<PathBuf, String> {
    let send_stage = |stage: &str| {
        let _ = tx.send(WorkerEvent::State(AppState::Installing {
            stage: stage.to_string(),
        }));
    };

    #[cfg(target_os = "macos")]
    {
        install_from_dmg(archive_path, install_dir, scope, password, send_stage, tx)
    }
    #[cfg(target_os = "linux")]
    {
        let _ = send_stage;
        install_from_targz(archive_path, install_dir, scope, password, tx)
    }
    #[cfg(target_os = "windows")]
    {
        let _ = (send_stage, scope, password);
        install_from_exe(archive_path, install_dir)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (archive_path, install_dir, scope, password, send_stage, tx);
        Err("automatic installation is not implemented for this platform".to_string())
    }
}

/// Runs `shell_cmd` with `sudo -s`, feeding `password` on `sudo`'s stdin so
/// the person only has to type it once in the UI rather than at an
/// interactive terminal prompt. Used for the "install for all users" path
/// on macOS and Linux.
///
/// The command itself (never the password) is sent to the "View commands"
/// panel both before it runs and, on failure, with the captured stderr, so
/// the person can see exactly what was attempted.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_privileged_shell(
    shell_cmd: &str,
    password: &str,
    tx: &Sender<WorkerEvent>,
) -> Result<(), String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    log_line(tx, format!("$ sudo -s -- sh -c \"{shell_cmd}\""));

    let mut child = Command::new("sudo")
        .args(["-S", "-p", "", "-k", "-s", "--"])
        .arg("sh")
        .arg("-c")
        .arg(shell_cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to launch sudo: {e}"))?;

    if let Some(stdin) = child.stdin.as_mut() {
        // sudo -S reads the password up to the first newline from stdin,
        // then hands the rest of stdin (nothing, here) to the command.
        let _ = writeln!(stdin, "{password}");
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("sudo did not complete: {e}"))?;

    if output.status.success() {
        log_line(tx, "  -> ok");
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    log_line(tx, format!("  -> failed: {}", stderr.trim()));
    let lower = stderr.to_lowercase();
    if lower.contains("incorrect password") || lower.contains("sorry, try again") {
        return Err("the administrator password was incorrect".to_string());
    }
    if lower.contains("a password is required") || lower.contains("no tty present") {
        return Err(
            "sudo could not prompt for a password in this environment  -  this usually means \
             the account isn't allowed to use sudo, or a password wasn't entered"
                .to_string(),
        );
    }
    Err(format!("privileged command failed: {}", stderr.trim()))
}

/// Attaches `dmg_path` with `hdiutil` and returns the `/Volumes/...` mount
/// point it was mounted at.
///
/// This used to parse `hdiutil attach`'s plain-text table output by
/// splitting on tabs and taking the last column. That format isn't stable:
/// the column layout has shifted across macOS versions and the mount-point
/// column isn't always tab-delimited the way earlier releases were, so the
/// old code could fail to find a `/Volumes/...` line even though the attach
/// itself succeeded — producing exactly the "could not determine mount
/// point from hdiutil output" error this was fixed for.
///
/// Instead we ask hdiutil for `-plist` output and pull the value out of the
/// `mount-point` key structurally, which is the form Apple documents as
/// stable. The old tab-delimited scan is kept as a fallback in case the
/// plist ever can't be parsed. We also retry the attach itself a few times:
/// `hdiutil attach` can fail transiently (e.g. Disk Arbitration still
/// settling right after a previous image was detached), and on macOS this
/// was previously a hard failure with no retry at all.
///
/// Deliberately NOT passing `-quiet` alongside `-plist`: on at least some
/// macOS/hdiutil versions the combination silently suppresses the plist
/// output entirely even though the attach itself succeeds — confirmed by
/// the fact that a "failed" attach here can still leave a new
/// `/Volumes/Tor Browser N` behind. `-plist` is already the
/// machine-readable, non-chatty mode; `-quiet` has nothing useful left to
/// suppress and was actively breaking output parsing.
#[cfg(target_os = "macos")]
fn attach_dmg_with_retry(
    dmg_path: &Path,
    send_stage: &impl Fn(&str),
) -> Result<PathBuf, String> {
    use std::process::Command;

    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();

    // Clean up any stale mounts left behind by earlier failed attempts
    // (e.g. "Tor Browser 1", "Tor Browser 2", ...) so they don't pile up
    // run after run and so a retry isn't confused by which volume is the
    // one it just attached.
    detach_stale_tor_browser_volumes();

    for attempt in 1..=MAX_ATTEMPTS {
        if attempt > 1 {
            send_stage("Retrying disk image attach...");
            std::thread::sleep(Duration::from_millis(750));
        }

        let volumes_before = list_volume_names();

        let attach_output = match Command::new("hdiutil")
            .args(["attach", "-plist", "-nobrowse"])
            .arg(dmg_path)
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                last_err = format!("failed to run hdiutil attach: {e}");
                continue;
            }
        };

        if !attach_output.status.success() {
            last_err = format!(
                "hdiutil attach failed: {}",
                String::from_utf8_lossy(&attach_output.stderr).trim()
            );
            continue;
        }

        let stdout = String::from_utf8_lossy(&attach_output.stdout);

        if let Some(mp) = mount_points_from_plist(&stdout)
            .into_iter()
            .find(|s| s.starts_with("/Volumes/"))
        {
            return Ok(PathBuf::from(mp));
        }

        // Defense in depth: fall back to the old heuristic in case the
        // plist for some reason couldn't be parsed (e.g. a future hdiutil
        // change to the plist schema itself).
        if let Some(mp) = stdout
            .lines()
            .filter_map(|line| line.split('\t').last())
            .map(str::trim)
            .find(|s| s.starts_with("/Volumes/"))
        {
            return Ok(PathBuf::from(mp));
        }

        // Last resort: we've now confirmed on real hardware that hdiutil
        // can report success (exit 0) with completely empty stdout while
        // still actually mounting the volume. If both parses above came
        // up empty despite a successful exit status, diff /Volumes
        // before/after the attach to find whatever just appeared.
        let volumes_after = list_volume_names();
        if let Some(new_volume) = volumes_after.iter().find(|v| !volumes_before.contains(v)) {
            return Ok(PathBuf::from("/Volumes").join(new_volume));
        }

        last_err = "could not determine mount point from hdiutil output".to_string();
    }

    Err(format!("{last_err} (after {MAX_ATTEMPTS} attempts)"))
}

/// Names of every entry currently under `/Volumes` (best-effort — an
/// unreadable `/Volumes` just yields an empty list rather than an error,
/// since this is only ever used as a diffing aid, not a source of truth).
#[cfg(target_os = "macos")]
fn list_volume_names() -> Vec<String> {
    std::fs::read_dir("/Volumes")
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Detaches any `/Volumes/Tor Browser` / `Tor Browser 1` / `Tor Browser 2`
/// / ... volumes left mounted from previous attach attempts that errored
/// out before reaching their own `hdiutil detach` call. Run once before a
/// fresh attach so repeated failed installs don't pile up duplicate mounts
/// (macOS auto-suffixes a number onto the volume name to avoid a
/// collision, which is where the " 1", " 2", ... come from).
#[cfg(target_os = "macos")]
fn detach_stale_tor_browser_volumes() {
    use std::process::Command;

    let Ok(entries) = std::fs::read_dir("/Volumes") else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_tor_browser_volume = name == "Tor Browser"
            || name
                .strip_prefix("Tor Browser ")
                .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()));
        if is_tor_browser_volume {
            let _ = Command::new("hdiutil")
                .args(["detach", "-quiet"])
                .arg(entry.path())
                .status();
        }
    }
}

/// Extracts every `mount-point` string value from an `hdiutil attach
/// -plist` XML property list, without pulling in a full plist-parsing
/// dependency. `hdiutil`'s plist is a flat, predictable
/// `<key>...</key><string>...</string>` structure for the fields we care
/// about, so a small manual scan is enough and avoids depending on the
/// exact tab/column layout of the text output.
#[cfg(target_os = "macos")]
fn mount_points_from_plist(xml: &str) -> Vec<String> {
    const KEY: &str = "<key>mount-point</key>";
    let mut mount_points = Vec::new();
    let mut rest = xml;

    while let Some(key_idx) = rest.find(KEY) {
        let after_key = &rest[key_idx + KEY.len()..];
        if let Some(str_start) = after_key.find("<string>") {
            let value_start = str_start + "<string>".len();
            if let Some(value_len) = after_key[value_start..].find("</string>") {
                let raw = &after_key[value_start..value_start + value_len];
                mount_points.push(unescape_xml(raw));
            }
        }
        // Continue scanning past this <key>mount-point</key> occurrence so
        // we find every entry in system-entities, not just the first.
        rest = after_key;
    }

    mount_points
}

/// Unescapes the handful of XML entities hdiutil's plist output can contain
/// in a mount-point path (e.g. `&amp;` in "Tor Browser &amp; Friends").
#[cfg(target_os = "macos")]
fn unescape_xml(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

#[cfg(target_os = "macos")]
enum CopyOutcome {
    Ok,
    PermissionDenied,
    Failed(String),
}

/// Copies `app_source` into `install_dir` as a plain (non-privileged)
/// operation, removing any existing bundle of the same name first — i.e.
/// exactly what Finder does when you drag an app out of a mounted disk
/// image onto a folder you already own. Distinguishes a permissions
/// failure from every other failure so the caller can decide whether an
/// authenticated retry makes sense.
#[cfg(target_os = "macos")]
fn copy_app_bundle_plain(
    app_source: &Path,
    install_dir: &Path,
    dest: &Path,
    tx: &Sender<WorkerEvent>,
) -> CopyOutcome {
    use std::io::ErrorKind;
    use std::process::Command;

    if let Err(e) = std::fs::create_dir_all(install_dir) {
        return if e.kind() == ErrorKind::PermissionDenied {
            CopyOutcome::PermissionDenied
        } else {
            CopyOutcome::Failed(e.to_string())
        };
    }

    if dest.exists() {
        if let Err(e) = std::fs::remove_dir_all(dest) {
            return if e.kind() == ErrorKind::PermissionDenied {
                CopyOutcome::PermissionDenied
            } else {
                CopyOutcome::Failed(e.to_string())
            };
        }
    }

    log_line(
        tx,
        format!("$ cp -R {} {}", app_source.display(), install_dir.display()),
    );
    let copy_result = Command::new("cp").args(["-R"]).arg(app_source).arg(install_dir).output();
    match copy_result {
        Ok(output) if output.status.success() => CopyOutcome::Ok,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Permission denied") || stderr.contains("Operation not permitted") {
                CopyOutcome::PermissionDenied
            } else {
                CopyOutcome::Failed(format!("copying the app bundle failed: {}", stderr.trim()))
            }
        }
        Err(e) => CopyOutcome::Failed(format!("failed to run cp: {e}")),
    }
}

/// Same install as `copy_app_bundle_plain`, but run inside a single
/// administrator-authenticated shell command via `osascript`. This is what
/// puts up the standard macOS password/Touch ID prompt, the same
/// mechanism regular signed installers use to write into `/Applications`
/// for a non-admin account, and it's also how an existing Tor Browser
/// install owned by another user/root gets replaced.
///
/// Everything (removing the old bundle, ensuring the target directory
/// exists, and copying the new bundle in) happens as one `do shell script
/// ... with administrator privileges` call so the person only sees a
/// single password prompt, not one per step.
#[cfg(target_os = "macos")]
fn install_app_bundle_privileged(
    app_source: &Path,
    install_dir: &Path,
    dest: &Path,
    tx: &Sender<WorkerEvent>,
) -> Result<(), String> {
    use std::process::Command;

    let shell_cmd = format!(
        "mkdir -p {install_dir} && rm -rf {dest} && cp -R {source} {install_dir}",
        install_dir = shell_quote(install_dir),
        dest = shell_quote(dest),
        source = shell_quote(app_source),
    );
    log_line(
        tx,
        "Requesting administrator access via the macOS password/Touch ID prompt...",
    );
    let apple_script = format!(
        "do shell script \"{}\" with administrator privileges with prompt \"Tor Browser Builder needs your password to install Tor Browser in {}.\"",
        applescript_escape(&shell_cmd),
        applescript_escape(&install_dir.display().to_string()),
    );

    let output = Command::new("osascript")
        .arg("-e")
        .arg(apple_script)
        .output()
        .map_err(|e| format!("failed to launch the administrator authorization prompt: {e}"))?;

    if output.status.success() {
        log_line(tx, "  -> ok");
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    // AppleScript reports a user-cancelled authorization dialog as error
    // -128 ("User canceled."); surface that as a clear, expected outcome
    // rather than a generic failure.
    if stderr.contains("-128") || stderr.to_lowercase().contains("user canceled") {
        log_line(tx, "  -> cancelled by user");
        return Err("installation was cancelled at the administrator password prompt".to_string());
    }
    log_line(tx, format!("  -> failed: {}", stderr.trim()));
    Err(format!("privileged install failed: {}", stderr.trim()))
}

/// Same install as `install_app_bundle_privileged`, but authenticated with
/// `sudo -s` and the password typed into the "All users" field in the UI,
/// instead of the native macOS Touch ID/password dialog. Used when the
/// person has explicitly chosen a system-wide install and supplied a
/// password up front, so installing doesn't have to wait for a plain copy
/// to fail first.
#[cfg(target_os = "macos")]
fn install_app_bundle_privileged_sudo(
    app_source: &Path,
    install_dir: &Path,
    dest: &Path,
    password: &str,
    tx: &Sender<WorkerEvent>,
) -> Result<(), String> {
    let shell_cmd = format!(
        "mkdir -p {install_dir} && rm -rf {dest} && cp -R {source} {install_dir}",
        install_dir = shell_quote(install_dir),
        dest = shell_quote(dest),
        source = shell_quote(app_source),
    );
    run_privileged_shell(&shell_cmd, password, tx)
}

/// Quotes a path for safe interpolation into a POSIX shell command string.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', r"'\''"))
}

/// Escapes a string for interpolation into a double-quoted AppleScript
/// string literal (used to build the `do shell script "..."` command).
#[cfg(target_os = "macos")]
fn applescript_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Installs Tor Browser from a `.dmg`.
///
/// The normal path mounts the image with `hdiutil` and copies the `.app`
/// off it — that's the standard, dependency-free way to get files out of
/// a disk image, and it's exactly what Finder does under the hood.
///
/// If `hdiutil attach` itself won't succeed at all (as opposed to just
/// needing another attempt — `attach_dmg_with_retry` already retries),
/// that usually means something is preventing Disk Arbitration from doing
/// its job in this environment — a corporate MDM restriction, a headless
/// session, or similar. In that case we don't just give up: `.dmg`'s
/// on-disk format (a UDIF wrapper around an HFS+/APFS volume) can be read
/// directly by 7-Zip without going through the mount machinery at all, so
/// we fall back to extracting it that way via `install_via_7z_extraction`.
/// That path requires `7zz`/`7z`/`7za` to be installed (e.g. `brew install
/// sevenzip`), which is why it's the fallback and not the default — it's
/// an extra dependency most people won't have — but it means a broken
/// `hdiutil` no longer has to be a dead end.
#[cfg(target_os = "macos")]
fn install_from_dmg(
    dmg_path: &Path,
    install_dir: &Path,
    scope: InstallScope,
    password: &str,
    send_stage: impl Fn(&str),
    tx: &Sender<WorkerEvent>,
) -> Result<PathBuf, String> {
    send_stage("Attaching disk image...");
    match attach_dmg_with_retry(dmg_path, &send_stage) {
        Ok(mount_point) => {
            install_from_mounted_dmg(&mount_point, install_dir, scope, password, &send_stage, tx)
        }
        Err(attach_err) => {
            send_stage("Disk image would not attach  -  extracting without mounting...");
            install_via_7z_extraction(dmg_path, install_dir, scope, password, &send_stage, tx)
                .map_err(|extract_err| {
                    format!(
                        "hdiutil attach failed ({attach_err}), and the mount-free fallback also \
                         failed ({extract_err})"
                    )
                })
        }
    }
}

/// The normal, mount-based install path: copy the `.app` out of an
/// already-attached disk image at `mount_point`.
#[cfg(target_os = "macos")]
fn install_from_mounted_dmg(
    mount_point: &Path,
    install_dir: &Path,
    scope: InstallScope,
    password: &str,
    send_stage: &impl Fn(&str),
    tx: &Sender<WorkerEvent>,
) -> Result<PathBuf, String> {
    use std::process::Command;

    let detach = || {
        let _ = Command::new("hdiutil").args(["detach", "-quiet"]).arg(mount_point).status();
    };

    send_stage("Locating application bundle...");
    let app_source = std::fs::read_dir(mount_point)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().map(|ext| ext == "app").unwrap_or(false))
        .ok_or_else(|| {
            detach();
            "no .app bundle found inside the disk image".to_string()
        })?;

    let app_name = app_source
        .file_name()
        .ok_or("app bundle had no file name")?;
    let dest = install_dir.join(app_name);

    // This mirrors exactly what Finder does when you drag the .app out of
    // the mounted disk image and drop it on a folder: no separate
    // "extraction" step exists for a .dmg because it isn't an archive
    // format, it's a disk image — the .app bundle inside it is copied as
    // a regular directory once the image is mounted.
    send_stage("Copying application to install location...");
    match install_app_bundle(&app_source, install_dir, &dest, scope, password, tx) {
        Ok(()) => {}
        Err(e) => {
            detach();
            return Err(e);
        }
    }

    send_stage("Unmounting disk image...");
    detach();

    Ok(dest)
}

/// Fallback install path used when `hdiutil attach` won't work at all:
/// reads the `.dmg` directly with 7-Zip (which understands the UDIF/HFS+
/// structure without needing Disk Arbitration to mount anything) and
/// copies the `.app` bundle it finds inside out to `install_dir`.
#[cfg(target_os = "macos")]
fn install_via_7z_extraction(
    dmg_path: &Path,
    install_dir: &Path,
    scope: InstallScope,
    password: &str,
    send_stage: &impl Fn(&str),
    tx: &Sender<WorkerEvent>,
) -> Result<PathBuf, String> {
    use std::process::Command;

    let seven_zip_bin = find_seven_zip_binary().ok_or_else(|| {
        "no 7-Zip binary (7zz/7z/7za) is installed to extract the disk image without mounting \
         it  -  install one with `brew install sevenzip` (or `brew install p7zip`) and try again"
            .to_string()
    })?;

    let extract_dir = std::env::temp_dir()
        .join("tor-browser-builder")
        .join("dmg-extract");
    // Clean up any stale extraction left over from a previous attempt.
    let _ = std::fs::remove_dir_all(&extract_dir);
    std::fs::create_dir_all(&extract_dir).map_err(|e| e.to_string())?;

    send_stage("Extracting disk image contents (7-Zip)...");
    let extract_status = Command::new(seven_zip_bin)
        .arg("x")
        .arg(dmg_path)
        .arg(format!("-o{}", extract_dir.display()))
        .arg("-y")
        .status()
        .map_err(|e| format!("failed to run {seven_zip_bin}: {e}"))?;
    if !extract_status.success() {
        return Err(format!("{seven_zip_bin} could not extract the disk image"));
    }

    // A DMG's internal partition structure sometimes means the .app ends
    // up nested a level or two down (e.g. inside an extracted HFS/APFS
    // partition image rather than at the top level), so search
    // recursively rather than assuming it's directly in extract_dir.
    send_stage("Locating application bundle...");
    let app_source =
        find_app_bundle(&extract_dir).ok_or("no .app bundle found inside the extracted disk image")?;

    let app_name = app_source.file_name().ok_or("app bundle had no file name")?;
    let dest = install_dir.join(app_name);

    send_stage("Copying application to install location...");
    install_app_bundle(&app_source, install_dir, &dest, scope, password, tx)?;

    let _ = std::fs::remove_dir_all(&extract_dir);
    Ok(dest)
}

/// Copies an app bundle into `install_dir`, choosing the right level of
/// privilege for the requested `scope`:
///
/// - `InstallScope::Global` always authenticates up front with `sudo -s`
///   using `password`, since a system-wide destination is expected to need
///   it.
/// - `InstallScope::User` tries a plain copy first (the common case — the
///   person owns the destination) and only falls back to the native macOS
///   administrator prompt if that copy is actually refused.
#[cfg(target_os = "macos")]
fn install_app_bundle(
    app_source: &Path,
    install_dir: &Path,
    dest: &Path,
    scope: InstallScope,
    password: &str,
    tx: &Sender<WorkerEvent>,
) -> Result<(), String> {
    if scope == InstallScope::Global {
        return install_app_bundle_privileged_sudo(app_source, install_dir, dest, password, tx);
    }

    match copy_app_bundle_plain(app_source, install_dir, dest, tx) {
        CopyOutcome::Ok => Ok(()),
        CopyOutcome::PermissionDenied => {
            install_app_bundle_privileged(app_source, install_dir, dest, tx)
        }
        CopyOutcome::Failed(e) => Err(e),
    }
}

/// Looks for an installed 7-Zip command-line binary under any of its
/// common names. `sevenzip` (Homebrew) installs `7zz`; `p7zip` installs
/// `7z`/`7za`. We don't care which one is present, just that one is.
#[cfg(target_os = "macos")]
fn find_seven_zip_binary() -> Option<&'static str> {
    for candidate in ["7zz", "7z", "7za"] {
        if let Ok(output) = std::process::Command::new("which").arg(candidate).output() {
            if output.status.success() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Recursively searches `root` for the first entry whose extension is
/// `.app`, since an extracted disk image's `.app` bundle isn't guaranteed
/// to be at the top level.
#[cfg(target_os = "macos")]
fn find_app_bundle(root: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(root).ok()?;
    let mut subdirs = Vec::new();
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().map(|ext| ext == "app").unwrap_or(false) {
            return Some(path);
        }
        if path.is_dir() {
            subdirs.push(path);
        }
    }
    for dir in subdirs {
        if let Some(found) = find_app_bundle(&dir) {
            return Some(found);
        }
    }
    None
}

/// Linux releases ship as a `.tar.xz` containing a top-level `tor-browser/`
/// directory. We extract it into the install dir with the system `tar`
/// (rather than pulling in a `.xz` decoder crate) and locate the launcher
/// script inside it.
#[cfg(target_os = "linux")]
fn install_from_targz(
    archive_path: &Path,
    install_dir: &Path,
    scope: InstallScope,
    password: &str,
    tx: &Sender<WorkerEvent>,
) -> Result<PathBuf, String> {
    use std::process::Command;

    if scope == InstallScope::Global {
        // /opt (and similar system locations) generally aren't writable by
        // a regular account, so the whole extraction — creating the
        // directory, un-tarring the archive, and making the launcher
        // executable — runs as one `sudo -s` command rather than trying an
        // unprivileged attempt first.
        let shell_cmd = format!(
            "mkdir -p {install_dir} && tar -xJf {archive} -C {install_dir} && \
             find {install_dir} -name start-tor-browser -exec chmod +x {{}} + && \
             chmod -R a+rX {install_dir}",
            install_dir = shell_quote(install_dir),
            archive = shell_quote(archive_path),
        );
        run_privileged_shell(&shell_cmd, password, tx)?;
    } else {
        std::fs::create_dir_all(install_dir).map_err(|e| e.to_string())?;

        log_line(
            tx,
            format!(
                "$ tar -xJf {} -C {}",
                archive_path.display(),
                install_dir.display()
            ),
        );
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
    }

    // Find the launcher script anywhere under the extracted tree instead of
    // hardcoding "tor-browser/Browser/start-tor-browser", since the Tor
    // Project has occasionally changed the top-level directory name.
    let launcher = find_file(install_dir, "start-tor-browser")
        .ok_or("could not find start-tor-browser inside the extracted archive")?;

    if scope != InstallScope::Global {
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
             supported by this release - try running the downloaded .exe manually)"
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
        // Check the current system-wide default (/Applications) first...
        let app = base.join("Tor Browser.app");
        if app.exists() {
            return Some(app);
        }
        // ...then fall back to where earlier versions of this app used to
        // install (a per-user ~/Applications/Tor Browser/ subfolder), so an
        // existing install isn't "lost" just because the default changed.
        if let Some(user_dirs) = UserDirs::new() {
            let legacy = user_dirs
                .home_dir()
                .join("Applications")
                .join("Tor Browser")
                .join("Tor Browser.app");
            if legacy.exists() {
                return Some(legacy);
            }
        }
    } else if cfg!(target_os = "linux") {
        if let Some(path) = find_file(&base, "start-tor-browser") {
            return Some(path);
        }
        // Also check the system-wide (Global scope) location, so a
        // previous "all users" install is found even though the per-user
        // location is the default search base.
        let global_base = InstallScope::Global.default_path();
        if global_base != base {
            if let Some(path) = find_file(&global_base, "start-tor-browser") {
                return Some(path);
            }
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