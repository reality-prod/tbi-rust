//! Background worker: fetch release info, download, verify, install. Runs
//! on its own thread (spawned from app.rs::start_download) so the UI stays
//! responsive; talks back to the UI thread via WorkerEvent.
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

use sequoia_openpgp as openpgp;
use openpgp::parse::{Parse, stream::*};
use openpgp::policy::StandardPolicy;

use crate::APP_VERSION;
use crate::app::AppState;
use crate::platform::{InstallScope, platform_label, release_json_filename, archive_extension, find_file};

/// Messages sent from the background worker thread back to the UI thread.
pub(crate) enum WorkerEvent {
    State(AppState),
    /// A shell/system command the worker is about to run (or its result),
    /// shown to the person in the "View commands" panel. Passwords are
    /// never included in these lines.
    Log(String),
}

/// Sends a line to the "View commands" panel. Centralized so every call
/// site formats log lines the same way and so passwords can never leak
/// into it by accident — callers pass already-redacted text.
pub(crate) fn log_line(tx: &Sender<WorkerEvent>, line: impl Into<String>) {
    let _ = tx.send(WorkerEvent::Log(line.into()));
}

struct ReleaseInfo {
    version: String,
    binary_url: String,
    sha256: Option<String>,
    sig_url: Option<String>,
}

pub(crate) fn run_install_pipeline(
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
                "Install scope: all users ({} - admin)",
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
                "Could not fetch release information from server: {e}"
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
        stage: "Please Wait...".to_string(),
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
