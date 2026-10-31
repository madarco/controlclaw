#!/bin/bash
# Build the firewall image for linux/amd64 and linux/arm64.
#
#   standalone/docker/build.sh              # build the binaries (build-box.sh --docker, both arches), then the image
#   standalone/docker/build.sh --no-bins    # use what is in rust/dist/<arch>-unknown-linux-musl/ already
#   standalone/docker/build.sh --release D  # use a release's assets (rust/scripts/release.sh output in D)
#
# Writes rust/dist/docker/controlclaw-firewall.oci.tar (both platforms, for `docker buildx imagetools`
# or a registry push later) and loads one image per platform into the local Docker as
# controlclaw-firewall:<tag>-amd64 and -arm64 (TAG, default dev), for tests and `docker save`.
# Building the arm64 image on an amd64 machine runs its one RUN step under QEMU: the binfmt
# handlers are installed once with `docker run --privileged --rm tonistiigi/binfmt --install arm64`.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
TAG="${TAG:-dev}"
BUILDER=controlclaw-firewall
OUT="${CC_IMAGE_OUT:-$REPO/rust/dist/docker}"
RELEASE=""
[ "${1:-}" != --release ] || RELEASE="${2:?--release takes the release folder}"

if [ "${1:-}" != --no-bins ] && [ -z "$RELEASE" ]; then
  "$REPO/rust/scripts/build-box.sh" --docker --arch x86_64
  "$REPO/rust/scripts/build-box.sh" --docker --arch aarch64
fi

CTX="$(mktemp -d)"; trap 'rm -rf "$CTX"' EXIT
mkdir -p "$CTX/bin" "$CTX/lib" "$CTX/docker"
for pair in amd64:x86_64 arm64:aarch64; do
  if [ -n "$RELEASE" ]; then
    # The release's assets are flat: <bin>-<arch>-linux-musl, mitm-agent-ui-<file>.
    src="$CTX/rel-${pair#*:}"; mkdir -p "$src/dist-ui"
    for b in mitm-agent cc-proxy; do install -m 755 "$RELEASE/$b-${pair#*:}-linux-musl" "$src/$b"; done
    for f in "$RELEASE"/mitm-agent-ui-*; do cp "$f" "$src/dist-ui/${f##*/mitm-agent-ui-}"; done
  else
    src="$REPO/rust/dist/${pair#*:}-unknown-linux-musl"
  fi
  [ -x "$src/mitm-agent" ] || { echo "no binaries in $src: run without --no-bins" >&2; exit 1; }
  # The binaries the firewall runs, and their page assets; not the vm-agent or cc-migrate.
  mkdir -p "$CTX/bin/${pair%%:*}"
  cp -r "$src/mitm-agent" "$src/cc-proxy" "$CTX/bin/${pair%%:*}/"
  # No page assets in a build without node_modules (no pnpm install): the pages are unstyled there.
  if [ -d "$src/dist-ui" ]; then cp -r "$src/dist-ui" "$CTX/bin/${pair%%:*}/"; else mkdir -p "$CTX/bin/${pair%%:*}/dist-ui"; fi
  [ -z "$RELEASE" ] || rm -rf "$src"
done
cp "$REPO/standalone/lib/"* "$CTX/lib/"
cp "$REPO/standalone/docker/entrypoint.sh" "$CTX/docker/"

docker buildx inspect "$BUILDER" >/dev/null 2>&1 || docker buildx create --name "$BUILDER" --driver docker-container >/dev/null
mkdir -p "$OUT"
docker buildx build --builder "$BUILDER" --platform linux/amd64,linux/arm64 \
  -f "$REPO/standalone/docker/Dockerfile" --output "type=oci,dest=$OUT/controlclaw-firewall.oci.tar" "$CTX"
for arch in amd64 arm64; do
  docker buildx build --builder "$BUILDER" --platform "linux/$arch" -q \
    -f "$REPO/standalone/docker/Dockerfile" -t "controlclaw-firewall:$TAG-$arch" --load "$CTX" >/dev/null
  echo "loaded controlclaw-firewall:$TAG-$arch"
done
echo "both platforms: $OUT/controlclaw-firewall.oci.tar"
