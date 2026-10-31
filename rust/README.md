# rust/

The firewall and the agent side, in Rust:

- `bins/mitm-agent`: the firewall agent. It holds the encrypted stores, writes the proxy's rules and
  serves the firewall's pages.
- `bins/cc-proxy`: the proxy agents send their traffic through.
- `bins/vm-agent`: the agent on the machine that runs OpenClaw.
- `bins/cc-migrate`: moves the stores from older formats.
- `bins/cc-conformance`, `conformance/`: the conformance cases.
- `crates/cc-local`: a standalone firewall's own control plane.
- `crates/*`: the libraries they share.

## Build and test

```bash
../test.sh                                   # format, lints, tests, the control-plane cases on cc-local
scripts/build-box.sh --docker                # static x86_64 binaries and SHA256SUMS in dist/
scripts/build-box.sh --docker --arch aarch64 # the same for arm
```

The binaries come with the firewall's page assets in `dist-ui/` (its Logs, Doctor and Logins pages
and the local panel), built with Node: run `pnpm install` at the repo root first.
`CC_BUILD_NO_UI=1` builds the binaries without them.

Rust comes from `rustup`; `rust-toolchain.toml` pins the version. Building `cc-proxy` needs cmake and
libclang for BoringSSL (`apt install cmake clang libclang-dev`). `build-box.sh --docker` builds in the
pinned image `scripts/Dockerfile.build`, with the musl toolchains in it; without `--docker` it uses
the musl toolchains under `/opt/musl-cross` (or `/opt/musl-cross-aarch64`) when they are there.

The firewall's page styles are built in ControlClaw's own repo, so a build here has unstyled pages.

## Releases

Releases are built and signed in ControlClaw's own repo, not here: the page assets and the lockfile
come from there. Each release has a `SHA256SUMS` signed with minisign
([`standalone/release/SIGNING.md`](../standalone/release/SIGNING.md)).
