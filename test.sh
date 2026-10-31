#!/bin/bash
# Every check of this repo: the Rust format, lints and tests, the control-plane cases against the
# local control plane (cc-local), the TS packages' types, lint and tests, the panel's build and the
# firewall's own pages (Logs, Doctor, and the stylesheet the others link).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
step() { printf '\n==> %s\n' "$*"; }

cd "$ROOT/rust"
step "cargo fmt --check"
cargo fmt --all --check
step "cargo clippy (warnings are errors)"
cargo clippy --workspace --all-targets --locked -- -D warnings
step "cargo test"
cargo test --workspace --locked
step "conformance: the control-plane cases on cc-local"
cargo build -q --locked -p cc-conformance
cargo build -q --locked -p cc-local --features contract
target/debug/cc-conformance --repo "$ROOT" --target local conformance/cases/cp

cd "$ROOT"
step "the release signature check (openssl), against a vector minisign signed"
standalone/release/verify.test.sh
step "TS packages"
pnpm install >/dev/null
pnpm -r typecheck
pnpm -r --if-present run lint
pnpm -r test
pnpm --filter @controlclaw/firewall-panel build
pnpm --filter @controlclaw/firewall-panel build:fw
