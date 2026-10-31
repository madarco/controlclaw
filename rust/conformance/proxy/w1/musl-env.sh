# Sourced by run.sh and smoke/run.sh: the compilers a static musl cc-proxy needs. BoringSSL (the
# upstream TLS) is C++, which musl-gcc cannot build: the musl cross toolchain (musl.cc's
# x86_64-linux-musl-cross, installed by rust/scripts/musl-cross.sh to /opt/musl-cross or on PATH)
# has the C++ compiler and a static libstdc++. cmake and clang (libclang, for bindgen) must be
# installed too.
for d in /opt/musl-cross/bin; do
  [ -d "$d" ] && PATH="$d:$PATH"
done
export PATH
_musl_cross="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../scripts" && pwd)/musl-cross.sh"
if ! command -v x86_64-linux-musl-g++ >/dev/null; then
  echo "cc-proxy needs the musl cross toolchain for BoringSSL (x86_64-linux-musl-g++):" >&2
  echo "  sudo $_musl_cross install /opt/musl-cross" >&2
  exit 1
fi
# The toolchain found must be the pinned one (its tarball's hash, written when it was installed).
"$_musl_cross" check "$(dirname "$(dirname "$(readlink -f "$(command -v x86_64-linux-musl-g++)")")")" || exit 1
export CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc
export CXX_x86_64_unknown_linux_musl=x86_64-linux-musl-g++
export AR_x86_64_unknown_linux_musl=x86_64-linux-musl-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc
