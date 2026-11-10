#!/bin/bash
# Build the box binaries: static musl, release, stripped. Writes them, the mitm-agent's
# page assets in dist-ui/ (build-ui.sh) and a SHA256SUMS file to
# rust/dist/<arch>-unknown-linux-musl/ (docs/plans/rust-rewrite.md §3, §5.1).
#
#   rust/scripts/build-box.sh            # natively when the musl cross toolchain is installed, else in Docker
#   rust/scripts/build-box.sh --docker   # always in the pinned build image (what releases use)
#   rust/scripts/build-box.sh --arch aarch64 [--docker]   # the arm build (x86_64 is the default)
#   rust/scripts/build-box.sh --prepare  # only build the pinned image (build-release.sh, before two builds at once)
#
# The firewall's page assets (dist-ui) need `pnpm install` first; CC_BUILD_NO_UI=1 builds the
# binaries without them.
# CC_BUILD_TARGET_DIR puts cargo's output elsewhere (release.sh builds twice to check the hashes).
# In Docker, the image is pinned (Dockerfile.build) and paths are remapped, Rust's and C's, so two
# builds of one commit give the same bytes; `verify-release.sh` checks that against a release.
set -euo pipefail

RUST_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DOCKER=0
PREPARE=0
ARCH=x86_64
while [ $# -gt 0 ]; do
  case "$1" in
    --docker) DOCKER=1 ;;
    --prepare) PREPARE=1 ;;
    --arch) ARCH="${2:-}"; [ $# -gt 1 ] && shift ;;
    *) echo "usage: build-box.sh [--docker] [--arch x86_64|aarch64] | --prepare" >&2; exit 2 ;;
  esac
  shift
done
case "$ARCH" in
  x86_64) ELF_MACHINE="Advanced Micro Devices X86-64" ;;
  aarch64) ELF_MACHINE="AArch64" ;;
  *) echo "build-box.sh: --arch is x86_64 or aarch64, not $ARCH" >&2; exit 2 ;;
esac
TARGET=$ARCH-unknown-linux-musl
# The target's names in cargo's and the cc crate's variables, and the cross toolchain's prefix.
T_ENV=${TARGET//-/_}
T_UPPER=${T_ENV^^}
CROSS=$ARCH-linux-musl
# Where Dockerfile.build installs the toolchain (musl-cross.sh install <dir> <arch>).
case "$ARCH" in x86_64) CROSS_DIR=/opt/musl-cross ;; aarch64) CROSS_DIR=/opt/musl-cross-aarch64 ;; esac
# bindgen (BoringSSL's bindings) parses C headers with libclang, which looks in /usr/include: the build
# machine's glibc headers. They do for x86_64, which is left as it is; for aarch64 it must read the
# cross toolchain's musl headers. Takes the toolchain folder; prints nothing for x86_64.
bindgen_env() { [ "$ARCH" = x86_64 ] || echo "BINDGEN_EXTRA_CLANG_ARGS_$T_ENV=--sysroot=$1/$CROSS"; }
OUT="${CC_BUILD_OUT:-$RUST_DIR/dist/$TARGET}"
TARGET_DIR="${CC_BUILD_TARGET_DIR:-$RUST_DIR/target}"
# The box binaries, one per line (shared by build-box.sh, release.sh and verify-release.sh).
mapfile -t BINS < "$(dirname "$0")/box-binaries"
PKGS=$(printf -- '-p %s ' "${BINS[@]}")
# The C code (mimalloc) stamps __DATE__/__TIME__; GCC takes them from this instead of the clock.
# The time of the last commit that touched rust/, so a commit elsewhere in the repo moves no hash.
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$RUST_DIR" log -1 --format=%ct -- . 2>/dev/null || echo 0)}"
export SOURCE_DATE_EPOCH
# The build stamp the vm-agent reports (`software.agent`, the console's agent version): taken from
# the last commit under rust/, as SOURCE_DATE_EPOCH is, so two builds of one commit still agree and
# a commit elsewhere moves nothing. A release passes its version; a dev build is 0.0.0-dev.<commit>.
CC_BUILD_COMMIT="${CC_BUILD_COMMIT:-$(git -C "$RUST_DIR" log -1 --format=%h --abbrev=7 -- . 2>/dev/null || echo unknown)}"
CC_BUILD_AT="${CC_BUILD_AT:-$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%S.000Z)}"
CC_BUILD_VERSION="${CC_BUILD_VERSION:-0.0.0-dev.$CC_BUILD_COMMIT}"
export CC_BUILD_COMMIT CC_BUILD_AT CC_BUILD_VERSION

# A native build is for trying things: it uses this machine's compiler and libraries, so its
# hashes are its own. Releases are built in Docker.
native() {
  export PATH="$HOME/.cargo/bin:$PATH"
  # From rust/, so rustup takes the toolchain rust-toolchain.toml pins (with its musl target), not
  # whatever the caller's folder would pick.
  cd "$RUST_DIR"
  # rust-toolchain.toml names the x86_64 target only; the arm one is added when it is asked for.
  [ "$ARCH" = x86_64 ] || rustup target add "$TARGET" >/dev/null
  local cargo_home="${CARGO_HOME:-$HOME/.cargo}" rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
  # ring and mimalloc compile C, and BoringSSL (cc-proxy's upstream TLS) C++: the musl cross
  # toolchain (musl.cc's x86_64-linux-musl-cross) has both and a static libstdc++; cmake and
  # libclang (bindgen) build BoringSSL. The caller's own RUSTFLAGS are kept, with the path remaps.
  local remap="-ffile-prefix-map=$RUST_DIR=/build -ffile-prefix-map=$cargo_home=/cargo"
  # shellcheck disable=SC2046 # bindgen_env is one word, or none for x86_64
  env PATH="$MUSL_CROSS:$PATH" \
    RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$RUST_DIR=/build --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$rustup_home=/rustup" \
    "CFLAGS_$T_ENV=$remap" "CXXFLAGS_$T_ENV=$remap" \
    "CC_$T_ENV=$CROSS-gcc" "CXX_$T_ENV=$CROSS-g++" \
    "AR_$T_ENV=$CROSS-ar" "CARGO_TARGET_${T_UPPER}_LINKER=$CROSS-gcc" \
    $(bindgen_env "$(dirname "$MUSL_CROSS")") \
    CARGO_TARGET_DIR="$TARGET_DIR" \
    cargo build --manifest-path "$RUST_DIR/Cargo.toml" --release --locked --target "$TARGET" $PKGS
}

IMAGE=controlclaw-rust-build:6
build_image() { docker build -q --platform linux/amd64 -t "$IMAGE" -f "$RUST_DIR/scripts/Dockerfile.build" "$RUST_DIR/scripts" >/dev/null; }
if [ "$PREPARE" = 1 ]; then build_image; exit 0; fi

in_docker() {
  local image=$IMAGE
  build_image
  # Fixed paths inside, whatever they are on this machine. The crate registry is kept between runs
  # (it is only downloads; Cargo.lock's checksums decide what is in it).
  local registry="${CC_BUILD_REGISTRY:-$RUST_DIR/target-cargo-registry}"
  mkdir -p "$TARGET_DIR" "$registry"
  # CC_BUILD_LABEL labels the container, so the caller can stop it (build-release.sh, when stopped).
  docker run --rm ${CC_BUILD_LABEL:+--label "cc-build=$CC_BUILD_LABEL"} --platform linux/amd64 -u "$(id -u):$(id -g)" -e HOME=/tmp -e SOURCE_DATE_EPOCH -e CC_BUILD_COMMIT -e CC_BUILD_AT -e CC_BUILD_VERSION \
    -v "$RUST_DIR:/src" -v "$TARGET_DIR:/target" -v "$registry:/opt/cargo/registry" -w /src "$image" \
    bash -c "RUSTFLAGS='--remap-path-prefix=/src=/build --remap-path-prefix=/opt/cargo=/cargo --remap-path-prefix=/opt/rustup=/rustup' \
      CFLAGS_$T_ENV='-ffile-prefix-map=/src=/build -ffile-prefix-map=/opt/cargo=/cargo' \
      CXXFLAGS_$T_ENV='-ffile-prefix-map=/src=/build -ffile-prefix-map=/opt/cargo=/cargo' \
      CC_$T_ENV=$CROSS-gcc CXX_$T_ENV=$CROSS-g++ \
      AR_$T_ENV=$CROSS-ar CARGO_TARGET_${T_UPPER}_LINKER=$CROSS-gcc \
      $(bindgen_env "$CROSS_DIR") \
      CARGO_TARGET_DIR=/target cargo build --release --locked --target $TARGET $PKGS"
}

# The musl cross toolchain: $CROSS_DIR (where Dockerfile.build puts it) or on PATH.
# A toolchain that is not the pinned one (musl-cross.sh check) is not used: the Docker build is.
MUSL_CROSS="$(dirname "$(readlink -f "$(PATH="$CROSS_DIR/bin:$PATH" command -v "$CROSS-g++" || echo "$CROSS_DIR/bin/x")")")"
# musl.cc's toolchains run on x86_64 only: any other build machine uses Docker.
if [ "$DOCKER" = 1 ] || [ "$(uname -m)" != x86_64 ] || [ ! -x "$MUSL_CROSS/$CROSS-g++" ] \
  || ! "$RUST_DIR/scripts/musl-cross.sh" check "$(dirname "$MUSL_CROSS")" "$ARCH" 2>/dev/null; then
  in_docker
else
  native
fi

rm -rf "$OUT"; mkdir -p "$OUT"
for b in "${BINS[@]}"; do cp "$TARGET_DIR/$TARGET/release/$b" "$OUT/"; done
# The mitm-agent's page assets, in dist-ui/ next to it as on a box (built with the repo's Node).
mapfile -t UI < "$(dirname "$0")/box-ui"
# They are built from apps/firewall-panel and packages/console-ui with Node (build-ui.sh), so they
# need the workspace's modules (`pnpm install`). A build without them stops: binaries with no
# dist-ui serve unstyled pages. CC_BUILD_NO_UI=1 builds the binaries alone, on purpose.
if [ "${CC_BUILD_NO_UI:-0}" = 1 ]; then
  echo "build-box: CC_BUILD_NO_UI=1, so no page assets (dist-ui): the firewall's pages will be unstyled" >&2
  UI=()
elif [ -d "$RUST_DIR/../node_modules" ]; then
  "$RUST_DIR/scripts/build-ui.sh" "$OUT/dist-ui"
else
  echo "build-box: no node_modules for the page assets (dist-ui): run pnpm install, or set CC_BUILD_NO_UI=1 to build the binaries alone" >&2
  exit 1
fi
(cd "$OUT" && sha256sum "${BINS[@]}" "${UI[@]/#/dist-ui/}" > SHA256SUMS)
# Static or nothing: a dynamically linked binary would depend on the box's glibc. And for the
# machine asked for: a wrong toolchain on PATH must not give an x86_64 file named aarch64.
for b in "${BINS[@]}"; do
  if readelf -l "$OUT/$b" | grep -q 'Requesting program interpreter'; then echo "$b is not static" >&2; exit 1; fi
  if ! readelf -h "$OUT/$b" | grep -q "Machine: *$ELF_MACHINE\$"; then echo "$b is not $ARCH" >&2; exit 1; fi
done
cat "$OUT/SHA256SUMS"
