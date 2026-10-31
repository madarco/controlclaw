#!/bin/bash
# The musl cross toolchains BoringSSL (cc-proxy's upstream TLS) is built with: musl.cc's
# x86_64-linux-musl-cross and aarch64-linux-musl-cross (both GCC 11.2.1), pinned by the hash of
# their tarballs. This file is the one place the hashes are written.
#
#   musl-cross.sh install [dir] [arch]   download, check the hash, unpack to dir (default /opt/musl-cross)
#   musl-cross.sh check [dir] [arch]     fail unless dir was installed from the pinned tarball
#
# arch is x86_64 (the default) or aarch64.
#
# The tarball is fetched from our own copy first (a release asset, so a change upstream cannot
# reach a build), then from musl.cc, whose URL has no version. Either must have the pinned hash.
set -euo pipefail

cmd="${1:-}"
dir="${2:-/opt/musl-cross}"
arch="${3:-x86_64}"
case "$arch" in
  x86_64) SHA256=c5d410d9f82a4f24c549fe5d24f988f85b2679b452413a9f7e5f7b956f2fe7ea ;;
  aarch64) SHA256=c909817856d6ceda86aa510894fa3527eac7989f0ef6e87b5721c58737a06c38 ;;
  *) echo "musl-cross.sh: arch is x86_64 or aarch64, not $arch" >&2; exit 2 ;;
esac
# MUSL_CROSS_MIRROR is the x86_64 copy (the only one with a mirror today); an aarch64 copy goes
# under the same release as aarch64-linux-musl-cross.tgz when it is uploaded.
mirror="https://github.com/madarco/controlclaw-oss/releases/download/toolchain-musl-cross-11.2.1/$arch-linux-musl-cross.tgz"
[ "$arch" = x86_64 ] && mirror="${MUSL_CROSS_MIRROR:-$mirror}"
URLS=("$mirror" "https://musl.cc/$arch-linux-musl-cross.tgz")
# Written next to the unpacked toolchain: the hash of the tarball it came from.
MARKER=.tarball-sha256
case "$cmd" in
  install)
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    for url in "${URLS[@]}"; do
      if curl -sSfLo "$tmp/t.tgz" "$url" && echo "$SHA256  $tmp/t.tgz" | sha256sum -c --status -; then
        # Into an empty folder, then in place of the old one: nothing of an earlier toolchain
        # is left beside the pinned one.
        mkdir "$tmp/x"
        tar -xzf "$tmp/t.tgz" -C "$tmp/x" --strip-components=1
        echo "$SHA256" > "$tmp/x/$MARKER"
        rm -rf "$dir"
        mkdir -p "$(dirname "$dir")"
        mv "$tmp/x" "$dir"
        echo "musl cross toolchain from $url in $dir"
        exit 0
      fi
      echo "musl-cross.sh: $url: not fetched or not the pinned tarball" >&2
    done
    exit 1
    ;;
  check)
    dir="$(readlink -f "$dir" 2>/dev/null || echo "$dir")"
    if [ "$(cat "$dir/$MARKER" 2>/dev/null)" != "$SHA256" ]; then
      echo "$dir is not the pinned musl cross toolchain (sha256 $SHA256). Install it with:" >&2
      echo "  sudo $(cd "$(dirname "$0")" && pwd)/musl-cross.sh install $dir $arch" >&2
      exit 1
    fi
    ;;
  *)
    echo "usage: musl-cross.sh install|check [dir] [x86_64|aarch64]" >&2
    exit 2
    ;;
esac
