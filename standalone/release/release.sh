#!/bin/bash
# Make a release of the standalone firewall, locally. Publishes nothing: it prints the upload lines.
#
#   standalone/release/release.sh 0.3.0
#   CC_MINISIGN_KEY=~/.minisign/controlclaw.key standalone/release/release.sh 0.3.0   # and sign it
#   standalone/release/release.sh --check 0.3.0   # after signing by hand: check, then the publish lines
#   CC_RELEASE_DRY_RUN=1 CC_RELEASE_PUBKEY_FILE=test.pub CC_MINISIGN_KEY=test.key \
#     standalone/release/release.sh 0.0.1                                             # a try
#
# Releases are built only here, in the private repo: they are pinned by its lockfile and made with
# the role's release script (rust/scripts/release.sh), neither of which the public export has.
#
# Writes, to rust/dist/standalone/<version>/ (a try: rust/dist/standalone-dry/<version>/, and no
# publish lines):
#   <bin>-<arch>-linux-musl, mitm-agent-ui-*   the box binaries and page assets, both architectures,
#                                              built twice and compared (rust/scripts/release.sh)
#   controlclaw-firewall-<version>.oci.tar     the image, both platforms (standalone/docker/build.sh)
#   controlclaw-<version>.tgz                  the CLI for npm, with the release URL and key stamped in
#   controlclaw-install-<version>.tar.gz       install.sh and its lib files, with the same stamps
#   SHA256SUMS, SHA256SUMS.minisig             their hashes, and the signature (SIGNING.md)
# The trusted comment of the signature is "controlclaw <version>": install.sh and the CLI check it, so
# an older signed release cannot be served as this one.
set -euo pipefail

CHECK=0
[ "${1:-}" != --check ] || { CHECK=1; shift; }
VERSION="${1:-}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: release.sh [--check] <major.minor.patch>" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
{ [ -f "$REPO/rust/scripts/release.sh" ] && [ -f "$REPO/pnpm-lock.yaml" ]; } \
  || { echo "releases are built in ControlClaw's private repo, not in the public export (no rust/scripts/release.sh or pnpm-lock.yaml here)" >&2; exit 1; }
# shellcheck source=SCRIPTDIR/release.conf
. "$HERE/release.conf"
# shellcheck source=SCRIPTDIR/../lib/firstrun.sh
. "$REPO/standalone/lib/firstrun.sh"
DRY="${CC_RELEASE_DRY_RUN:-0}"
URL="https://github.com/$CC_PUBLIC_REPO/releases/download/v{version}"
OUT="$REPO/rust/dist/standalone/$VERSION"
# A try never lands where a release is looked for, and prints nothing to publish.
[ "$DRY" != 1 ] || OUT="$REPO/rust/dist/standalone-dry/$VERSION"
COMMENT="controlclaw $VERSION"

# The key the release is checked with. Another one only for a try: a real release is signed with the
# key install.sh and the CLI of this commit carry.
PUBFILE="$HERE/controlclaw.pub"
if [ -n "${CC_RELEASE_PUBKEY_FILE:-}" ]; then
  [ "$DRY" = 1 ] || { echo "CC_RELEASE_PUBKEY_FILE is for a try (CC_RELEASE_DRY_RUN=1) only" >&2; exit 1; }
  PUBFILE="$CC_RELEASE_PUBKEY_FILE"
fi
PUBKEY="$(sed -n 2p "$PUBFILE")"
case "$PUBKEY" in ""|*PLACEHOLDER*) echo "$PUBFILE has no release key yet: see $HERE/SIGNING.md" >&2; exit 1 ;; esac

# The signature over SHA256SUMS: this commit's key, the prehashed form, this version's trusted
# comment, and every asset matching its line. Then what to publish (none for a try).
check_and_print() {
  [ -f "$OUT/SHA256SUMS.minisig" ] || { echo "no $OUT/SHA256SUMS.minisig: sign SHA256SUMS first" >&2; exit 1; }
  cc_minisign_verify "$PUBKEY" "$OUT/SHA256SUMS" "$OUT/SHA256SUMS.minisig" || { echo "the signature does not match $PUBFILE" >&2; exit 1; }
  [ "$(sed -n 3p "$OUT/SHA256SUMS.minisig")" = "trusted comment: $COMMENT" ] \
    || { echo "the signature's trusted comment is not \"$COMMENT\"" >&2; exit 1; }
  (cd "$OUT" && sha256sum -c --quiet SHA256SUMS) || { echo "an asset in $OUT does not match SHA256SUMS" >&2; exit 1; }
  # Everything in the folder is published: nothing may be there that the signature does not cover.
  extra="$(cd "$OUT" && find . -mindepth 1 -maxdepth 1 ! -name SHA256SUMS ! -name SHA256SUMS.minisig -printf '%f\n' \
    | LC_ALL=C sort | comm -23 - <(sed 's/^[0-9a-f]*  //' SHA256SUMS | LC_ALL=C sort))"
  [ -z "$extra" ] || { echo "$OUT has files SHA256SUMS does not list, which would be published unsigned: $extra" >&2; exit 1; }
  [ -s "$OUT.commit" ] || { echo "no $OUT.commit: the commit the release was built from is unknown" >&2; exit 1; }
  echo "signed and checked: $OUT/SHA256SUMS.minisig"
  if [ "$DRY" = 1 ]; then echo "a try ($OUT): nothing to publish"; return; fi
  cat <<EOF

Release $VERSION in $OUT. Nothing is published. To publish (host):
  gh release create v$VERSION --repo $CC_PUBLIC_REPO --title "ControlClaw firewall $VERSION" \\
    --notes "Built from controlclaw $(cat "$OUT.commit")." $OUT/*
  npm publish $OUT/$CC_NPM_NAME-$VERSION.tgz --access public
  skopeo copy --all oci-archive:$OUT/controlclaw-firewall-$VERSION.oci.tar docker://$CC_IMAGE:$VERSION
EOF
}
if [ "$CHECK" = 1 ]; then
  [ -f "$OUT/SHA256SUMS" ] || { echo "no release in $OUT" >&2; exit 1; }
  check_and_print
  exit 0
fi
[ ! -e "$OUT" ] || { echo "$OUT exists: version $VERSION was made already" >&2; exit 1; }
[ -n "${CC_MINISIGN_KEY:-}" ] || command -v minisign >/dev/null || echo "note: no minisign here; sign SHA256SUMS on the machine that has the key" >&2
# What this script packs itself must be the commit it names too (rust/scripts/release.sh checks
# rust/, apps/firewall-panel, packages/ and the lockfile).
if [ "$DRY" != 1 ] && [ -n "$(git -C "$REPO" status --porcelain -- standalone)" ]; then
  echo "standalone/ has changes that are not committed; a release is built from a commit" >&2
  exit 1
fi

WORK="$(mktemp -d)"
# A release that stops before its assets are all made is removed, so the version can be made again.
# One that is built but fails to sign is kept: sign it by hand, then --check.
done=0
trap 'rm -rf "$WORK"; [ "$done" = 1 ] || rm -rf "$OUT"' EXIT

# 1. The box binaries: the role's release script, without the role's vars.
CC_RELEASE_STANDALONE=1 CC_RELEASE_REPO="$CC_PUBLIC_REPO" CC_RELEASE_OUT="$OUT" "$REPO/rust/scripts/release.sh" "$VERSION"
# The commit's time for the image's and the install archive's timestamps. The image is still not
# byte-for-byte reproducible: its Alpine packages are not pinned (docs/plans/standalone-backlog.md).
SOURCE_DATE_EPOCH="$(git -C "$REPO" log -1 --format=%ct)"; export SOURCE_DATE_EPOCH

# 2. The image, from those binaries.
echo "==> image"
CC_IMAGE_OUT="$WORK/image" TAG="$VERSION" "$REPO/standalone/docker/build.sh" --release "$OUT" >/dev/null
mv "$WORK/image/controlclaw-firewall.oci.tar" "$OUT/controlclaw-firewall-$VERSION.oci.tar"

# The stamps: the release URL and key, in a copy only. The repo's files keep their defaults.
stamp_cli() {
  sed -i -e "s|^const RELEASE_URL = \"\";|const RELEASE_URL = \"$URL\";|" \
    -e "s|^const RELEASE_PUBKEY = \"\";|const RELEASE_PUBKEY = \"$PUBKEY\";|" "$1"
  grep -q "^const RELEASE_PUBKEY = \"$PUBKEY\";" "$1" || { echo "could not stamp $1" >&2; exit 1; }
}
stamp_install() {
  sed -i -e "s|^BASE_URL_DEFAULT=.*|BASE_URL_DEFAULT=https://github.com/$CC_PUBLIC_REPO/releases/download|" \
    -e "s|^RELEASE_PUBKEY=\"\"|RELEASE_PUBKEY=\"$PUBKEY\"|" "$1"
  grep -q "^RELEASE_PUBKEY=\"$PUBKEY\"" "$1" || { echo "could not stamp $1" >&2; exit 1; }
}

# 3. The CLI: a copy of packages/cli with the npm name, the version and the stamps, packed by npm.
echo "==> CLI"
cp -r "$REPO/packages/cli" "$WORK/cli"
rm -rf "$WORK/cli/node_modules" "$WORK/cli/dist"
cp "$REPO/standalone/oss/root/LICENSE" "$WORK/cli/LICENSE"
ln -s "$REPO/packages/cli/node_modules" "$WORK/cli/node_modules"
stamp_cli "$WORK/cli/src/release.ts"
# shellcheck disable=SC2016 # JS, not shell
node -e '
  const fs = require("fs"), p = process.argv[1], j = JSON.parse(fs.readFileSync(p, "utf8"));
  j.name = process.argv[2]; j.version = process.argv[3]; j.files = [...j.files, "LICENSE"];
  j.repository = { type: "git", url: `git+https://github.com/${process.argv[4]}.git`, directory: "packages/cli" };
  fs.writeFileSync(p, JSON.stringify(j, null, 2) + "\n");
' "$WORK/cli/package.json" "$CC_NPM_NAME" "$VERSION" "$CC_PUBLIC_REPO"
(cd "$WORK/cli" && ./node_modules/.bin/tsup >/dev/null && npm pack --quiet --pack-destination "$OUT" >/dev/null)
[ -f "$OUT/$CC_NPM_NAME-$VERSION.tgz" ] || { echo "npm pack made no $CC_NPM_NAME-$VERSION.tgz" >&2; exit 1; }
tar -xOzf "$OUT/$CC_NPM_NAME-$VERSION.tgz" package/dist/index.js | grep -F "$PUBKEY" >/dev/null || { echo "the packed CLI has no release key" >&2; exit 1; }

# 4. install.sh with its lib files next to it, as it looks for them.
echo "==> install script"
I="$WORK/controlclaw-install-$VERSION"; mkdir -p "$I"
cp "$REPO/standalone/install/install.sh" "$REPO"/standalone/lib/* "$I/"
stamp_install "$I/install.sh"
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -C "$WORK" -cf - "controlclaw-install-$VERSION" \
  | gzip -n > "$OUT/controlclaw-install-$VERSION.tar.gz"

# 5. The hashes of every asset, then the signature over them.
(cd "$OUT" && rm SHA256SUMS && find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' -printf '%f\n' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS)
# The commit, beside the folder (not an asset), for the release notes --check prints.
git -C "$REPO" rev-parse HEAD > "$OUT.commit"
done=1
if [ -n "${CC_MINISIGN_KEY:-}" ]; then
  minisign -S -H -s "$CC_MINISIGN_KEY" -m "$OUT/SHA256SUMS" -t "$COMMENT" \
    || { echo "not signed: $OUT is built; sign SHA256SUMS by hand, then: standalone/release/release.sh --check $VERSION" >&2; exit 1; }
  check_and_print
else
  echo "not signed yet: on the machine with the key, from $OUT:"
  echo "  minisign -S -H -s <key> -m SHA256SUMS -t \"$COMMENT\""
  echo "then: standalone/release/release.sh --check $VERSION"
fi
