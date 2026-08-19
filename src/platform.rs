//! Platform detection, install-scope logic, and launching/locating an
//! existing install. Split out of main.rs by split_main.sh.
use std::path::{Path, PathBuf};
use directories::UserDirs;

// ---------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------
/// Human-readable label shown in the UI footer.
pub(crate) fn platform_label() -> &'static str {
    if cfg!(target_os = "macos") {
        "Mac"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        "this platform"
    }
}

/// Default install location, matching each OS's own conventions.
pub(crate) fn default_install_path() -> PathBuf {
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
pub(crate) fn release_json_filename() -> &'static str {
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
pub(crate) fn archive_extension() -> &'static str {
    if cfg!(target_os = "macos") {
        "dmg"
    } else if cfg!(target_os = "windows") {
        "exe"
    } else {
        "tar.xz"
    }
}

/// Whether the install targets just the current account or the whole
/// machine. A "global" install writes into a system-owned location
/// (`/Applications` on macOS, `/opt` on Linux) that regular users can't
/// write to, so it needs an administrator/root password up front rather
/// than discovering the permission failure partway through the copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstallScope {
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
    pub(crate) fn default_path(self) -> PathBuf {
        match self {
            InstallScope::User => default_install_path(),
            InstallScope::Global => {
                if cfg!(target_os = "macos") {
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
    pub(crate) fn needs_password(self) -> bool {
        self == InstallScope::Global && (cfg!(target_os = "macos") || cfg!(target_os = "linux"))
    }
}

/// Recursively searches `root` for a file whose name matches `target`,
/// returning the first match. Used by the Linux and Windows install paths
/// to locate the launcher inside an extracted/installed tree without
/// depending on an exact directory layout.
pub(crate) fn find_file(root: &Path, target: &str) -> Option<PathBuf> {
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
pub(crate) fn find_existing_install() -> Option<PathBuf> {
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

pub(crate) fn launch_app(app_path: &Path) {
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

pub(crate) fn open_folder(folder: &Path) {
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
