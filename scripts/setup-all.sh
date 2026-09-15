#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

./setup-tauri.sh

echo
read -r -p "Also scaffold the Android target now? [y/N] " ans
case "$ans" in
  [yY]*) ./setup-tauri-android.sh ;;
  *) echo "Skipping Android scaffold — run scripts/setup-tauri-android.sh whenever you're ready." ;;
esac