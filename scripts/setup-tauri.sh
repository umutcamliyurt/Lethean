#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib/common.sh

log "Checking prerequisites..."
need_cmd node  "Install Node.js 18+: https://nodejs.org"
need_cmd npm   "Node.js 18+ bundles npm."
need_cmd cargo "Install the Rust toolchain: https://www.rust-lang.org/tools/install"
need_cmd rustc "Install the Rust toolchain: https://www.rust-lang.org/tools/install"

case "$(uname -s)" in
  Linux*)
    warn "Linux also needs: libwebkit2gtk-4.1-dev libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev build-essential curl wget file (Debian/Ubuntu package names)"
    ;;
  Darwin*)
    xcode-select -p >/dev/null 2>&1 || warn "Run 'xcode-select --install' to get the macOS build tools Tauri needs."
    ;;
esac

cd "$CLIENT_DIR"

log "Installing npm dependencies in client/..."
npm install

if [ -d "src-tauri" ]; then
  log "client/src-tauri already exists, skipping 'tauri init'."
else
  log "Scaffolding client/src-tauri (non-interactive)..."
  npx tauri init --ci \
    --app-name "lethean" \
    --window-title "Lethean" \
    --frontend-dist "../dist" \
    --before-dev-command "npm run build" \
    --before-build-command "npm run build"
fi

CONF="src-tauri/tauri.conf.json"
[ -f "$CONF" ] || die "Expected $CONF after 'tauri init' but it's missing."

log "Setting a real bundle identifier in $CONF..."
node -e '
const fs = require("fs");
const p = "src-tauri/tauri.conf.json";
const conf = JSON.parse(fs.readFileSync(p, "utf8"));
conf.productName = conf.productName || "Lethean";
conf.identifier = "com.lethean.app";
conf.app = conf.app || {};
conf.app.security = conf.app.security || {};
if (conf.app.security.csp === undefined) conf.app.security.csp = null;
conf.app.withGlobalTauri = true;
fs.writeFileSync(p, JSON.stringify(conf, null, 2) + "\n");
'

log "Extending the CSP in index.html / share.html for the Tauri webview origin..."
bash "$REPO_ROOT/scripts/patch-csp-for-tauri.sh"

log "Adding the opener, dialog, and fs plugins (needed by client/src/platform.ts)..."
cd src-tauri
cargo add tauri-plugin-opener tauri-plugin-dialog tauri-plugin-fs
cd ..
warn "Manual step still needed: register each plugin in src-tauri/src/lib.rs, e.g.:"
warn '  .plugin(tauri_plugin_opener::init())'
warn '  .plugin(tauri_plugin_dialog::init())'
warn '  .plugin(tauri_plugin_fs::init())'
warn "and grant them permission in src-tauri/capabilities/default.json (opener:default, dialog:default, fs:default)."

log "Ignoring Tauri build artifacts in client/.gitignore..."
GITIGNORE="$CLIENT_DIR/.gitignore"
touch "$GITIGNORE"
for entry in "src-tauri/target/" "src-tauri/gen/"; do
  grep -qxF "$entry" "$GITIGNORE" || echo "$entry" >> "$GITIGNORE"
done

log "Desktop scaffold ready."
log "Next: npm --prefix client run tauri:dev   (or tauri:build for a release binary)"
log "Mobile targets: scripts/setup-tauri-mobile.sh"
