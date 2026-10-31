#!/bin/bash
# The openssl minisign check (cc_minisign_verify in standalone/lib/firstrun.sh) against a fixed
# vector signed by the minisign tool itself (testdata/; its secret key was deleted). The CLI's check
# has the same vector (packages/cli/src/release.test.ts).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=SCRIPTDIR/../lib/firstrun.sh
. "$HERE/../lib/firstrun.sh"
T="$HERE/testdata"
# The check runs where install.sh does (Ubuntu, OpenSSL 3); LibreSSL (macOS) has no Ed25519 -rawin.
case "$(openssl version 2>/dev/null)" in
  "OpenSSL "[3-9].*) ;;
  *) echo "skipped: needs OpenSSL 3 (this machine has: $(openssl version 2>/dev/null || echo none))"; exit 0 ;;
esac
PK="$(sed -n 2p "$T/vector.pub")"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
fails=0
ok() { if "$@" 2>/dev/null; then echo "ok: $*"; else echo "FAILED: $*"; fails=$((fails + 1)); fi; }
refused() { if "$@" 2>/dev/null; then echo "FAILED (accepted): $*"; fails=$((fails + 1)); else echo "ok, refused: $*"; fi; }

ok cc_minisign_verify "$PK" "$T/vector.txt" "$T/vector.txt.minisig"
if [ "$(sed -n 3p "$T/vector.txt.minisig")" = "trusted comment: controlclaw 0.0.0-vector" ]; then
  echo "ok: trusted comment"
else
  echo "FAILED: trusted comment"; fails=$((fails + 1))
fi

# Another file, another comment, another key, the legacy (not prehashed) form.
printf 'a fixed test vector for the minisign checks (standalone/release/SIGNING.md)!\n' > "$W/other.txt"
refused cc_minisign_verify "$PK" "$W/other.txt" "$T/vector.txt.minisig"
sed '3s/.*/trusted comment: controlclaw 9.9.9/' "$T/vector.txt.minisig" > "$W/comment.minisig"
refused cc_minisign_verify "$PK" "$T/vector.txt" "$W/comment.minisig"
other="$(printf 'Ed%s' "$(head -c 40 /dev/zero | tr '\0' 'x')" | base64 | tr -d '\n')"
refused cc_minisign_verify "$other" "$T/vector.txt" "$T/vector.txt.minisig"
legacy="$(sed -n 2p "$T/vector.txt.minisig" | base64 -d | { printf 'Ed'; tail -c +3; } | base64 | tr -d '\n')"
sed "2s|.*|$legacy|" "$T/vector.txt.minisig" > "$W/legacy.minisig"
refused cc_minisign_verify "$PK" "$T/vector.txt" "$W/legacy.minisig"

[ "$fails" = 0 ] || { echo "$fails failed"; exit 1; }
echo "all passed"
