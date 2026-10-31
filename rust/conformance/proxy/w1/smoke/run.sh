#!/bin/bash
# Run the mitmproxy smoke rigs (packages/mitm-proxy/smoke/run-*.sh) against cc-proxy, unchanged:
# the scripts run in a copy of the smoke folder whose compose files run cc-proxy as `proxy`.
#
#   rust/conformance/proxy/w1/smoke/run.sh                 # all six
#   rust/conformance/proxy/w1/smoke/run.sh run-smoke.sh    # one
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RUST_DIR="$(cd "$HERE/../../../.." && pwd)"
REPO="$(cd "$RUST_DIR/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
TARGET=x86_64-unknown-linux-musl
. "$HERE/../musl-env.sh"
cargo build -q --locked --target "$TARGET" \
  --manifest-path "$RUST_DIR/Cargo.toml" -p cc-proxy || exit 1
BIN="${CARGO_TARGET_DIR:-$RUST_DIR/target}/$TARGET/debug/cc-proxy"

CTX="$(mktemp -d)"; WORK="$(mktemp -d)"
trap 'rm -rf "$CTX" "$WORK"' EXIT
cp "$BIN" "$HERE/Dockerfile" "$CTX/"
docker build -q -t controlclaw-cc-proxy-smoke:local "$CTX" >/dev/null || exit 1

mkdir -p "$WORK/mitm-proxy"
cp -R "$REPO/packages/mitm-proxy/smoke" "$REPO/packages/mitm-proxy/config" \
  "$REPO/packages/mitm-proxy/addon.py" "$REPO/packages/mitm-proxy/gen-ca.sh" "$WORK/mitm-proxy/"
python3 "$HERE/as-cc-proxy.py" "$WORK"/mitm-proxy/smoke/docker-compose.*.yml || exit 1
python3 "$HERE/differences.py" "$WORK/mitm-proxy/smoke" || exit 1

scripts=("$@")
[ ${#scripts[@]} -eq 0 ] && scripts=(run-smoke.sh run-permission.sh run-ai.sh run-p8.sh run-transparent.sh run-residential.sh)
status=0
for s in "${scripts[@]}"; do
  echo "######## $s (cc-proxy)"
  if bash "$WORK/mitm-proxy/smoke/$s"; then echo "######## $s: PASS"; else echo "######## $s: FAIL"; status=1; fi
done
exit $status
