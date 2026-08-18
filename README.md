# Tor Browser Installer

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A **cross-platform** installer and launcher for [Tor Browser](https://www.torproject.org/download/) with a modern, user-friendly UI. Built with Rust and [egui](https://github.com/emilk/egui) for native performance and a clean, approachable interface.

## Features

- **One-click installation** – Downloads the latest Tor Browser directly from the Tor Project
- **Automatic verification** – SHA-256 checksum and PGP signature verification for security
- **Cross-platform** – Native builds for macOS, Linux, and Windows
- **Modern UI** – Clean, intuitive interface that doesn't look "hacker-like"
- **Flexible installation** – Install for current user or system-wide (sudo)
- **Dark/Light mode** – Theme toggle for your preference
- **Transparent operations** – View all commands executed during installation

## Screenshots

The installer provides a streamlined experience:

- **Idle state**: Choose installation location and scope
- **Download**: Progress bar with speed and size information
- **Verification**: SHA-256 and PGP signature checks
- **Installation**: Automatic extraction and setup for your platform
- **Completion**: Launch Tor Browser directly from the installer

## Installation

### From Source

1. **Clone the repository:**
   ```bash
   git clone https://github.com/A100BH/tbi-rust.git
   cd tbi-rust
   ```

2. **Install Rust:**
   If you don't have Rust installed, get it from [rustup.rs](https://rustup.rs/)

3. **Build and run:**
   ```bash
   cargo run --release
   ```

### Platform-Specific Builds

Build for a specific target:

```bash
# macOS
cargo build --release --target x86_64-apple-darwin

# Linux (x86_64)
cargo build --release --target x86_64-unknown-linux-gnu

# Windows (x86_64)
cargo build --release --target x86_64-pc-windows-msvc
```

The binary will be in `target/release/` (or the specified target directory).

## Usage

1. **Launch the installer** – Run the compiled binary
2. **Choose installation location** – Defaults to platform conventions:
   - macOS: `/Applications`
   - Linux: `~/.local/share/tor-browser` or `/opt/tor-browser`
   - Windows: `%LOCALAPPDATA%\Tor Browser` or `C:\Tor Browser`
3. **Select installation scope** – "Just me" (user-only) or "All users" (system-wide, requires admin)
4. **Click "Download & Install"** – The installer will:
   - Fetch the latest release info from Tor Project
   - Show you the version and download URL for confirmation
   - Download Tor Browser with progress tracking
   - Verify the SHA-256 checksum
   - Verify the PGP signature (when available)
   - Install to your chosen location
5. **Launch Tor Browser** – Directly from the completion screen

## Security

⚠️ **Important Security Notes:**

- This installer downloads Tor Browser over **plain HTTPS** (not Tor). A network observer can see that you're downloading Tor Browser.
- The installer verifies **SHA-256 checksums** against the Tor Project's release API.
- **PGP signature verification** is implemented using `sequoia-openpgp` and the Tor Browser Developers signing key.
- All verification happens **before** installation. If any check fails, the download is discarded.
- The installer itself is **not affiliated with or endorsed by The Tor Project**.

### Verification Process

1. **Checksum verification** – Compares the downloaded file's SHA-256 hash against the expected value from the release JSON
2. **PGP signature verification** – Downloads the detached `.asc` signature and verifies it against the Tor Browser Developers key

## Project Structure

```
tbi-rust/
├── Cargo.toml          # Dependencies and build configuration
├── src/
│   └── main.rs         # Main application code (UI + logic)
└── assets/
    └── tor_logo_tbb.svg # Tor Browser logo
```

## Dependencies

- **[eframe](https://github.com/emilk/egui)** – Cross-platform GUI framework
- **[egui](https://github.com/emilk/egui)** – Immediate mode GUI library
- **[reqwest](https://github.com/seanmonstar/reqwest)** – HTTP client for downloads
- **[sequoia-openpgp](https://gitlab.com/sequoia-pgp/sequoia)** – PGP signature verification
- **[sha2](https://github.com/RustCrypto/utils)** – SHA-256 hashing
- **[directories](https://github.com/dirs-dev/directories-rs)** – Platform-specific path handling

## Configuration

The installer uses platform-specific defaults, but you can customize:

- **Installation path** – Edit the text field before starting the download
- **Installation scope** – Toggle between user-only and system-wide
- **Theme** – Switch between light and dark mode with the sun/moon icon

## Troubleshooting

### Common Issues

**"Could not fetch release information"**
- Check your internet connection
- The Tor Project's release API might be temporarily unavailable
- Try again later

**"Checksum mismatch"**
- The download was corrupted or intercepted
- The installer will **not** install the file
- Try downloading again

**"PGP signature verification failed"**
- The signature doesn't match the Tor Browser Developers key
- The installer will **not** install the file
- This could indicate a compromised download

**Permission denied on macOS/Linux**
- For system-wide installation, you need to enter your administrator password
- The password is used only for `sudo -s` and is never stored or transmitted

### Viewing Commands

Click "View commands" to see all system commands executed during the installation process. This is useful for debugging and transparency.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run `cargo check` and `cargo clippy` to ensure code quality
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **[The Tor Project](https://www.torproject.org/)** – For building and maintaining Tor Browser
- **[egui](https://github.com/emilk/egui)** – For the excellent GUI framework
- **[Rust](https://www.rust-lang.org/)** – For the amazing language and ecosystem

---

**Made with ❤️ and Rust**

*This is an unofficial, third-party tool and is not affiliated with or endorsed by The Tor Project.*
