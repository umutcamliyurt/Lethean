#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib/common.sh
cd "$CLIENT_DIR"

[ -d "src-tauri" ] || die "client/src-tauri not found — run scripts/setup-tauri.sh first."

need_cmd cargo "Install the Rust toolchain: https://www.rust-lang.org/tools/install"

if [ -z "${ANDROID_HOME:-}" ] && [ -z "${ANDROID_SDK_ROOT:-}" ]; then
  die "ANDROID_HOME / ANDROID_SDK_ROOT not set — install Android Studio + SDK, then export it."
fi
if [ -z "${NDK_HOME:-}" ]; then
  die "NDK_HOME not set — install the NDK via Android Studio's SDK Manager and export NDK_HOME."
fi

if ! command -v cargo-tauri >/dev/null 2>&1; then
  log "Installing tauri-cli via cargo (used for Android only)..."
  cargo install tauri-cli --version "^2.11" --locked
fi

if [ -d "src-tauri/gen/android" ]; then
  log "Android project already scaffolded, skipping."
else
  log "Scaffolding Android project (non-interactive)..."
  cargo tauri android init
fi

log "Android scaffold ready."
log "Next: npm --prefix client run tauri:android:dev     (development, on a device/emulator)"
log "  or: npm --prefix client run tauri:android:build   (release APK — see README for signing setup)"