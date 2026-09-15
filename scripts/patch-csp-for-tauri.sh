#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib/common.sh
cd "$CLIENT_DIR"

need_cmd perl "Needed to safely patch the CSP meta tag in place."

TAURI_CONNECT="ipc: http://ipc.localhost https:"

for f in index.html share.html; do
  [ -f "$f" ] || { warn "$f not found, skipping."; continue; }
  if grep -q "ipc.localhost" "$f"; then
    log "$f already patched, skipping."
    continue
  fi
  log "Patching connect-src in $f..."
  perl -0pi -e "s#(connect-src [^;]*)#\$1 $TAURI_CONNECT#" "$f"
  grep -q "ipc.localhost" "$f" || die "Failed to patch $f — check the CSP meta tag format hasn't changed."
done

warn "Reminder: connect-src still only lists http://localhost:8000 for the API."
warn "Add your production API origin before shipping a build that talks to a real server."