#!/bin/bash
# Run the W1 proxy cases against mitmproxy 12.2.2 with addon.py and against cc-proxy, in a
# container (the runner puts addresses on lo and names in /etc/hosts, so it needs its own).
#
#   rust/conformance/proxy/w1/run.sh                       # every case, both proxies
#   rust/conformance/proxy/w1/run.sh --target cc-proxy --filter drop
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RUST_DIR="$(cd "$HERE/../../.." && pwd)"
REPO="$(cd "$RUST_DIR/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"

# Static, so it runs in the rig whatever the host's libc (the musl cross toolchain: musl-env.sh).
TARGET=x86_64-unknown-linux-musl
. "$HERE/musl-env.sh"
cargo build -q --locked --target "$TARGET" \
  --manifest-path "$RUST_DIR/Cargo.toml" -p cc-proxy
BIN="${CARGO_TARGET_DIR:-$RUST_DIR/target}/$TARGET/debug/cc-proxy"
docker build -q -t controlclaw-proxy-rig:local "$HERE" >/dev/null
exec docker run --rm --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
  -v "$REPO:/repo:ro" -v "$BIN:/usr/local/bin/cc-proxy:ro" \
  -e CC_PROXY_BIN=/usr/local/bin/cc-proxy \
  -e CC_RIG_SHOW_LOG="${CC_RIG_SHOW_LOG:-}" -e RUST_LOG="${RUST_LOG:-info}" \
  controlclaw-proxy-rig:local "$@"
