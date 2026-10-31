# The conformance rig: Ubuntu 24.04 with Node 24 from NodeSource, as the role installs it, the
# built TS bundles and the static Rust binaries. Running as root here lets the runner create the
# system paths the TS agents read (`/etc/controlclaw/pool-unclaimed`, a case's `system_bins`).
# openssh-client: the Doctor key store runs ssh-keygen at start (w5/fw-doctor-ts,
# w5/fw-doctor-installed). Built by conformance/run.sh from a staged context, never from the
# repository root.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg openssl openssh-client \
 && curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*
COPY repo /repo
ENV CC_RIG_SYSTEM_PATHS=1
WORKDIR /repo
ENTRYPOINT ["/repo/bin/cc-conformance", "--repo", "/repo", "--rust-bin-dir", "/repo/bin"]
CMD ["/repo/cases"]
