# FerrumVault User Guide

## Overview
FerrumVault is a cross-platform desktop password manager that stores encrypted vaults locally and optionally synchronizes encrypted bundles to Google Drive. This guide walks through installing the desktop application, creating or opening a vault, and managing synchronization workflows.

## System Requirements

- **Operating systems**: macOS 12+, Windows 10+, or modern Linux distribution with GTK.
- **Hardware**: 4 GB RAM, 300 MB free disk space.
- **Dependencies** (during build): Rust toolchain, Node.js 18+, `npm`, and the Tauri CLI.
- **Optional**: Apple Developer ID for signing/notarizing macOS DMGs.

## Installation

### macOS (DMG)

1. Download the latest `FerrumVault_*.dmg` from the GitHub release or published download page.
2. Double-click the DMG, drag `FerrumVault.app` into `/Applications`, and eject the disk image when finished.
3. Unsigned builds may require right-click → **Open** the first time to satisfy Gatekeeper.

### Windows (MSI / NSIS)

FerrumVault ships two installer formats under `src-tauri/target/release/bundle/` once `tauri build` completes:

- **MSI** (`msi/FerrumVault_*.msi`) – double-click to launch the Windows Installer wizard. This registers FerrumVault in Programs & Features and supports silent installs, e.g. `msiexec /i FerrumVault_x64.msi /qn`.
- **NSIS** (`nsis/FerrumVault_*.exe`) – a themed NSIS wizard that supports per-user installs and desktop/start-menu shortcut prompts.

When downloading from Releases, pick whichever installer style you prefer; both install the same signed `credmanager_app.exe` binary.

### Linux

`tauri build` emits Linux bundles suitable for most distributions:

- **AppImage** (`appimage/FerrumVault*.AppImage`) – portable and distro-agnostic. Mark it executable (`chmod +x FerrumVault.AppImage`) and launch directly. Ideal for Fedora, Arch, or any environment without DEB/RPM tooling.
- **DEB** (`deb/FerrumVault*.deb`) – install on Debian, Ubuntu, Pop!_OS, Linux Mint, Elementary, etc. with `sudo apt install ./FerrumVault_<version>.deb`.

Need an RPM for RHEL-based systems? Convert the generated DEB with `alien` (or a similar tool) on a Linux host:

```bash
sudo apt-get install -y alien rpm
cd src-tauri/target/release/bundle/deb
sudo alien --to-rpm FerrumVault_<version>_amd64.deb
```

The resulting `FerrumVault-<version>.rpm` installs on RHEL, Fedora, Alma, or Rocky via `sudo dnf install ./FerrumVault-<version>.rpm`. AppImage remains the quickest option when you simply need a portable binary.

### Configure Google OAuth Credentials

FerrumVault’s Drive sync flow relies on a Google OAuth client ID/secret. The public repository redacts these values, so you must supply your own:

1. Follow Google’s guide for native/Desktop apps: [Create OAuth 2.0 credentials](https://developers.google.com/identity/protocols/oauth2/native-app).
2. In Google Cloud Console, create an OAuth 2.0 Client ID with application type **Desktop** and add `http://localhost` as an authorized redirect URI.
3. Note the generated **Client ID** and **Client Secret**. Store them securely.
4. Open `src/sync.rs` and replace the placeholder strings `__SET_GOOGLE_OAUTH_CLIENT_ID__` and `__SET_GOOGLE_OAUTH_CLIENT_SECRET__` inside the `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET` constants.
5. Rebuild (`npm run tauri:build`) so the binaries embed your credentials. Desktop-flow secrets are semi-public; rotate them in Google Cloud if you suspect exposure.

### Building from Source

```bash
# Clone the repository
git clone https://github.com/your-org/credmanager.git
cd credmanager

# Install dependencies (Rust, Node, Tauri CLI) beforehand
npm install
npm run tauri:build
```

- macOS `.app` bundles land in `src-tauri/target/release/bundle/macos/`, DMGs in `.../dmg/`.
- Windows MSI/NSIS installers are emitted under `.../bundle/msi` and `.../bundle/nsis`.
- Linux AppImage/DEB installers appear under `.../bundle/appimage` and `.../bundle/deb`; convert the DEB to RPM with `alien` if you need a package for RHEL-based distributions.

## First Launch

1. Run the application.
2. Choose the vault base directory (defaults to `~/credmanager`) and profile (defaults to `default`).
3. Enter the master password for existing vaults or create a new one for fresh installations.
4. The dashboard lists folders and credentials on the left, and the selected credential detail pane on the right.

## Managing Credentials

- Use the **New Credential** button to create credentials. Required fields include app name, folder, username, and password.
- You can edit a credential by selecting it and clicking **Edit**.
- Password history is accessible inside the credential detail panel under **Password History**; FerrumVault maintains timestamped versions automatically.

## Google Drive Synchronization

1. Open the menu (☰) → **Settings**.
2. Under **Google Drive Connection**, click **Connect with Google**. The built-in OAuth flow opens a browser. Once Google redirects back to the local listener, FerrumVault stores the refresh token securely.
3. To upload manually, use menu → **Sync to Google Drive** and click **Upload now**. FerrumVault bundles the vault (SQLite databases), encrypts the bundle, and uploads it to Drive.
4. To restore, use **Import from Google Drive**, select a bundle, and click **Download selected bundle**.
5. Advanced manual override (pasting authorization codes or refresh tokens) is hidden under **Manually configure Google account**.

## Command Palette & Keyboard Shortcuts

- `⌘/Ctrl` + `K`: opens the command palette.
- Arrow keys / search inputs filter folders and credentials immediately.
- The session timer indicates remaining unlock time; re-authenticate when it expires.

## Troubleshooting

- **Session expired**: dialogs close and the app returns to the login screen. Simply re-enter the master password.
- **Google Drive errors**: ensure the refresh token is stored; check Settings for connection status. For upload/download issues inspect the toast notifications or run `npm run tauri:dev` to view console logs.
- **Missing DMG**: run `npm run tauri:build` on macOS. If `src-tauri/target/release/bundle/dmg` only contains support files, rerun the build to capture `bundle_dmg.sh` errors.

## Support

- File bugs and feature requests in the GitHub repository.
- For security disclosures, contact the FerrumVault security team at `security@your-domain.com`.
