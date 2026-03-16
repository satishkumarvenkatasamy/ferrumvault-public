#!/usr/bin/env bash
cat <<'DOC'
FerrumVault Build Instructions (public repo)
==========================================

Prerequisites
-------------
1. Install the Rust toolchain (`rustup` recommended, use `rustup update stable`).
2. Install Node.js 18+ and npm.
3. Install the Tauri CLI v1.5.10 (one-time):
   npm install -g @tauri-apps/cli@1.5.10
   # or run per-command without global install:
   # npx --yes @tauri-apps/cli@1.5.10 tauri <command>
4. Clone the public repository and install JavaScript deps:
   git clone https://github.com/satishkumarvenkatasamy/ferrumvault-public.git
   cd ferrumvault-public
   npm install

macOS Build (App + DMG)
-----------------------
cd ferrumvault-public
npm run tauri:build
# or
cd src-tauri && tauri build
Artifacts:
  - src-tauri/target/release/bundle/macos/FerrumVault.app
  - src-tauri/target/release/bundle/dmg/FerrumVault_*.dmg

Windows Build (EXE + MSI/NSIS)
------------------------------
Ensure the Tauri CLI is v1.5.10 (see prerequisites).
cd ferrumvault-public
npm run tauri:build
Artifacts:
  - target/release/credmanager_app.exe (raw binary)
  - src-tauri/target/release/bundle/msi/FerrumVault_*.msi
  - src-tauri/target/release/bundle/nsis/FerrumVault_*.exe

Linux Build (AppImage + DEB)
---------------------------
Install system deps (example for Debian/Ubuntu):
  sudo apt-get update && sudo apt-get install -y libgtk-3-dev libwebkit2gtk-4.1-dev pkg-config libssl-dev
cd ferrumvault-public
npm run tauri:build
Artifacts:
  - src-tauri/target/release/bundle/appimage/FerrumVault*.AppImage
  - src-tauri/target/release/bundle/deb/FerrumVault*.deb
Need an RPM? Convert the DEB with alien:
  sudo apt-get install -y alien rpm
  cd src-tauri/target/release/bundle/deb
  sudo alien --to-rpm FerrumVault_<version>_amd64.deb

General Notes
-------------
- Use `npm run tauri:dev` for a live-reload dev session (requires the Tauri CLI and frontend assets).
- Replace the placeholders `__SET_GOOGLE_OAUTH_CLIENT_ID__`/`SECRET` in `src/sync.rs` with your own Google OAuth credentials before building release artifacts.
- Clean previous outputs with `cargo clean && rm -rf src-tauri/target target` if you hit linker or bundler issues.
DOC
