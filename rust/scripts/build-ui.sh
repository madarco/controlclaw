#!/bin/bash
# Build the page assets the firewall agent serves (`dist-ui/`: the stylesheet, the Logs page
# script, the Doctor start script, and the local panel `panel.*`) into <out>, one file per line of
# rust/scripts/box-ui.
#
#   rust/scripts/build-ui.sh <out>
#
# The Node build inlines them; the Rust mitm-agent reads them from `dist-ui/` next to its binary
# (core/fw_shell.rs; the panel's in cc-local `panel.rs`, standalone only). They come from
# apps/firewall-panel: scripts/build-fw-files.mjs (the pages' stylesheet and the Logs and Doctor
# scripts, from packages/console-ui) and its Vite build (the panel), with the repo's
# node_modules (`pnpm install`), so the lockfile decides the bytes. A stylesheet that came out
# empty, or is not the console's, stops the build: without it every firewall page is unstyled.
set -euo pipefail

OUT="${1:?usage: build-ui.sh <out>}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
mapfile -t FILES < "$(dirname "$0")/box-ui"
[ -d "$REPO/node_modules" ] || { echo "build-ui: no node_modules in $REPO: run pnpm install first" >&2; exit 1; }
(cd "$REPO/apps/firewall-panel" && node scripts/build-fw-files.mjs dist-fw >/dev/null && node_modules/.bin/vite build --logLevel error)
rm -rf "$OUT"; mkdir -p "$OUT"
for f in "${FILES[@]}"; do
  case "$f" in
    panel.*) SRC="$REPO/apps/firewall-panel/dist" ;;
    *) SRC="$REPO/apps/firewall-panel/dist-fw" ;;
  esac
  [ -s "$SRC/$f" ] || { echo "build-ui: $f is missing or empty" >&2; exit 1; }
  cp "$SRC/$f" "$OUT/$f"
done
grep -q -- '--background:' "$OUT/app.css" || { echo "build-ui: app.css is not the console's stylesheet" >&2; exit 1; }
