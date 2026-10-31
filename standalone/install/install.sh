#!/bin/bash
# Install the ControlClaw firewall on a plain Ubuntu VM (24.04, amd64 or arm64), without Ansible:
# the firewall agent (mitm-agent, in standalone mode: no control plane), cc-proxy and OpenConnector,
# as systemd units with the role's names, and DNS (dnsmasq) and time (chrony) for the agents, as the
# role gives them. See docs/standalone/standalone-mode.md.
#
#   sudo ./install.sh --version 0.2.0             # a release's binaries, checked against its signed SHA256SUMS
#   sudo ./install.sh --from rust/dist/aarch64-unknown-linux-musl   # a build-box.sh output
#   sudo ./install.sh --uninstall [--purge]       # remove the units and binaries (--purge: the state too)
#
#   --hostname N   the name a browser reaches the firewall's pages at, on 443 (behind Caddy, Tailscale
#                  Serve or an SSH tunnel), for the links `mitm-agent open <page>` prints: a name with
#                  a dot and no port
#   --base-url U   where the release assets are (default: $BASE_URL_DEFAULT/v<version>; also
#                  CC_RELEASE_URL). The signature is still checked against this script's key
#   --sums-sha256 H  the sha256 of the release's SHA256SUMS, from somewhere you trust, as a pin on top
#                  of the signature
#   --pubkey FILE  a minisign public key to check the release with instead of this script's own (a
#                  fork's releases, tests)
#   --listen ADDR  the address the proxy listens on (port 8080). Default: the VM's private address when
#                  it has one, else 127.0.0.1. Agents must reach it; nobody else should. DNS (53) and
#                  NTP (123) listen there too when it is a private address, else on loopback only.
#   --wireguard    also run WireGuard (cc-wg0) for agents on other machines (`controlclaw connect --mode
#                  remote`): each paired agent gets a peer and a tunnel address; the proxy and DNS
#                  listen on the firewall's tunnel address too. Open UDP 51820 to the agents.
#   --wg-endpoint H[:P]  the address agents reach this machine's WireGuard at (default: this machine's
#                  address toward the internet, port 51820)
#   --wg-address A/24    the firewall's tunnel address and network (default 10.77.0.1/24)
#
# The proxy starts with every request blocked (a rule in the firewall's local database) until you set
# your rules.
# It refuses a machine whose /opt/controlclaw it did not make (a box our Ansible role manages).
#
# Run it from a checkout (it reads ../lib) or with the lib files next to it.
set -euo pipefail

# The standalone releases (standalone/release/release.sh stamps both from release.conf and the
# signing key; from a checkout the key is read from ../release/controlclaw.pub).
BASE_URL_DEFAULT=https://github.com/madarco/controlclaw-oss/releases/download
RELEASE_PUBKEY=""
CONNECTOR_IMAGE=ghcr.io/oomol-lab/open-connector@sha256:f25207e6f71eabc70182c4f5db5c01db79091d0f4523a7495b35e649d5b6c006
ROOT=/opt/controlclaw
ETC=/etc/controlclaw
UNITS=(controlclaw-mitmproxy controlclaw-mitm-agent controlclaw-connector controlclaw-dns)
CHRONY_CONF=/etc/chrony/conf.d/controlclaw.conf
# Written by the first install: what tells this script's firewall from a box the role manages, which
# has the same unit names and folders.
MARKER=$ROOT/standalone/.installed
HERE="$(cd "$(dirname "$0")" && pwd)"
LIB="$HERE/../lib"; [ -f "$LIB/firstrun.sh" ] || LIB="$HERE"

die() { echo "install.sh: $*" >&2; exit 1; }
# The ufw rules --wireguard added (comment controlclaw-wg), newest number first.
cc_ufw_forget_wg() {
  command -v ufw >/dev/null || return 0
  ufw status numbered 2>/dev/null | sed -n 's/^\[ *\([0-9]*\)\].*controlclaw-wg.*/\1/p' | sort -rn |
    while read -r n; do ufw --force delete "$n" >/dev/null; done
}
UFW_WG=0

OTHER_NTP=""
VERSION="" FROM="" BASE_URL="${CC_RELEASE_URL:-}" SUMS_SHA256="" PUBKEY_FILE="" LISTEN="" PAGE_HOST="" UNINSTALL=0 PURGE=0
WG=0 WG_ENDPOINT="" WG_ADDRESS=10.77.0.1/24
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift ;;
    --from) FROM="${2:-}"; shift ;;
    --base-url) BASE_URL="${2:-}"; shift ;;
    --sums-sha256) SUMS_SHA256="${2:-}"; shift ;;
    --pubkey) PUBKEY_FILE="${2:-}"; shift ;;
    --listen) LISTEN="${2:-}"; shift ;;
    --hostname) PAGE_HOST="${2:-}"; shift ;;
    --wireguard) WG=1 ;;
    --wg-endpoint) WG_ENDPOINT="${2:-}"; shift ;;
    --wg-address) WG_ADDRESS="${2:-}"; shift ;;
    # From before standalone mode: the firewall agent always runs now.
    --with-agent) echo "install.sh: --with-agent is no longer needed: the firewall agent always runs" >&2 ;;
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1 ;;
    *) die "unknown option $1 (see the top of this file)" ;;
  esac
  shift
done
[ "$(id -u)" = 0 ] || die "run as root"

if [ "$UNINSTALL" = 1 ]; then
  [ -f "$MARKER" ] || die "$ROOT was not installed by this script (no $MARKER): nothing removed"
  for u in "${UNITS[@]}"; do systemctl disable --now "$u" 2>/dev/null || true; rm -f "/etc/systemd/system/$u.service"; done
  systemctl disable --now run-mitm-config.mount 2>/dev/null || true
  rm -rf /etc/systemd/system/run-mitm-config.mount /etc/systemd/system/controlclaw-mitmproxy.service.d
  rm -f /usr/local/bin/mitm-agent "$ETC/dnsmasq.conf"
  # WireGuard: the interface, its peers' sync and its rules go; its key stays with the state.
  systemctl disable --now controlclaw-wg-sync.path wg-quick@cc-wg0 2>/dev/null || true
  rm -f /etc/systemd/system/controlclaw-wg-sync.path /etc/systemd/system/controlclaw-wg-sync.service \
    /etc/wireguard/cc-wg0.conf "$ETC/wg.nft"
  cc_ufw_forget_wg
  if [ "$PURGE" = 1 ]; then rm -f /etc/wireguard/cc-wg0.key; fi
  systemctl disable --now controlclaw-ntp-guard.service 2>/dev/null || true
  rm -f /etc/systemd/system/controlclaw-ntp-guard.service "$ETC/ntp.nft"
  # chrony stays: it keeps this machine's clock. It stops serving the agents.
  if [ -f "$CHRONY_CONF" ]; then rm -f "$CHRONY_CONF"; systemctl restart chrony 2>/dev/null || true; fi
  systemctl daemon-reload
  # The marker stays with the state, so --purge can still remove it later.
  rm -rf "$ROOT/rust"; rm -f "$ROOT"/standalone/*.env "$ROOT/standalone/dnsmasq.conf"
  if [ "$PURGE" = 1 ]; then
    rm -rf "$ROOT" "$ETC/firewall.env"
    docker rm -f controlclaw-connector >/dev/null 2>&1 || true
    echo "removed, with the state (CA, keys, stores, connector data)"
  else
    echo "removed; the state in $ROOT stays (--purge removes it)"
  fi
  exit 0
fi

case "$(uname -m)" in
  x86_64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) die "no build for $(uname -m)" ;;
esac
[ -n "$VERSION" ] || [ -n "$FROM" ] || die "--version or --from is required"
[ -z "$VERSION" ] || [ -z "$FROM" ] || die "--version or --from, not both"
if [ -d "$ROOT" ] && [ ! -f "$MARKER" ]; then
  die "$ROOT exists and this script did not make it (no $MARKER): a box our Ansible role manages is updated by the role"
fi
for f in firstrun.sh cc-proxy.env mitm-agent.env connector.env dnsmasq.conf; do [ -f "$LIB/$f" ] || die "no $f in $LIB"; done
# shellcheck source=SCRIPTDIR/../lib/firstrun.sh
. "$LIB/firstrun.sh"
# The proxy's address: never all of them unless asked.
if [ -z "$LISTEN" ]; then
  for a in $(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1); do
    if cc_private_ipv4 "$a"; then LISTEN="$a"; break; fi
  done
  LISTEN="${LISTEN:-127.0.0.1}"
fi
[[ "$LISTEN" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "--listen is an IPv4 address, not $LISTEN"
# DNS and NTP follow the proxy onto a private address only: on a public one (or all of them) they
# would answer the whole internet, an open resolver.
PRIVATE=""
if cc_private_ipv4 "$LISTEN"; then PRIVATE="$LISTEN"; fi
# WireGuard: the firewall's tunnel address, and where agents reach it.
WG_IP=""
if [ "$WG" = 1 ]; then
  [[ "$WG_ADDRESS" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/24$ ]] || die "--wg-address is an IPv4 address with /24 (10.77.0.1/24), not $WG_ADDRESS"
  WG_IP="${WG_ADDRESS%/24}"
  if [ -z "$WG_ENDPOINT" ]; then
    WG_ENDPOINT="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
    [ -n "$WG_ENDPOINT" ] || die "cannot tell this machine's address: pass --wg-endpoint <host>"
  fi
  case "$WG_ENDPOINT" in *:*) ;; *) WG_ENDPOINT="$WG_ENDPOINT:51820" ;; esac
  [[ "$WG_ENDPOINT" =~ ^[A-Za-z0-9.-]+:[0-9]{1,5}$ ]] || die "--wg-endpoint is host[:port], not $WG_ENDPOINT"
fi
# Checked before anything changes: the link is https://<name>/, so a name with a dot and no port.
[ -z "$PAGE_HOST" ] || cc_valid_hostname "$PAGE_HOST" || die "--hostname takes a name with a dot and no port (the pages are served on 443), not $PAGE_HOST"

# --- the binaries: into a new folder, checked, then put in place ---
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
if [ -n "$FROM" ]; then
  [ -f "$FROM/SHA256SUMS" ] || die "no SHA256SUMS in $FROM (a build-box.sh output folder)"
  # Every file that is installed must have its line, and match it; only those files are copied.
  files=(mitm-agent cc-proxy)
  for f in "$FROM"/dist-ui/*; do
    [ -d "$f" ] && die "$FROM/dist-ui has a folder (${f##*/}): the page assets are files only"
    [ -f "$f" ] && files+=("dist-ui/${f##*/}")
  done
  [ "${#files[@]}" -gt 2 ] || die "no page assets in $FROM/dist-ui"
  for f in "${files[@]}"; do grep -q "  $f\$" "$FROM/SHA256SUMS" || die "$f has no line in $FROM/SHA256SUMS"; done
  (cd "$FROM" && for f in "${files[@]}"; do grep "  $f\$" SHA256SUMS; done | sha256sum -c --quiet -) \
    || die "$FROM does not match its SHA256SUMS"
  # The ELF header's machine field (od is in coreutils; readelf is not on a plain VM): 3e x86_64, b7 aarch64.
  machine="$(od -An -tx1 -j18 -N1 "$FROM/mitm-agent" | tr -d ' ')"
  [ "$machine" = "$( [ "$ARCH" = x86_64 ] && echo 3e || echo b7)" ] || die "$FROM is not a $ARCH build"
  mkdir -p "$STAGE/dist-ui"
  for f in "${files[@]}"; do cp "$FROM/$f" "$STAGE/$f"; done
  VERSION="local-$(sha256sum "$FROM/SHA256SUMS" | cut -c1-12)"
else
  [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "--version is major.minor.patch"
  # The key the release must be signed with: this script's own, a checkout's, or --pubkey.
  key="$RELEASE_PUBKEY"
  if [ -n "$PUBKEY_FILE" ]; then key="$(sed -n 2p "$PUBKEY_FILE" 2>/dev/null)"
  elif [ -z "$key" ] && [ -f "$HERE/../release/controlclaw.pub" ]; then key="$(sed -n 2p "$HERE/../release/controlclaw.pub")"; fi
  case "$key" in ""|*PLACEHOLDER*) die "this script has no release signing key yet (standalone/release/SIGNING.md): use --from, or --pubkey" ;; esac
  command -v openssl >/dev/null || { apt-get update -q >/dev/null; DEBIAN_FRONTEND=noninteractive apt-get install -y -q openssl >/dev/null; }
  url="${BASE_URL:-$BASE_URL_DEFAULT/v$VERSION}"
  curl -fsSLo "$STAGE/SHA256SUMS" "$url/SHA256SUMS" || die "no SHA256SUMS at $url"
  curl -fsSLo "$STAGE/SHA256SUMS.minisig" "$url/SHA256SUMS.minisig" || die "no SHA256SUMS.minisig at $url: the release is not signed"
  cc_minisign_verify "$key" "$STAGE/SHA256SUMS" "$STAGE/SHA256SUMS.minisig" || die "the release's SHA256SUMS is not signed by the release key: nothing installed"
  # Signed for this version, not an older release served under its name.
  [ "$(sed -n 3p "$STAGE/SHA256SUMS.minisig")" = "trusted comment: controlclaw $VERSION" ] \
    || die "the release's signature is for another version ($(sed -n 3p "$STAGE/SHA256SUMS.minisig")): nothing installed"
  if [ -n "$SUMS_SHA256" ]; then
    [ "$(sha256sum "$STAGE/SHA256SUMS" | cut -d' ' -f1)" = "$SUMS_SHA256" ] || die "the release's SHA256SUMS is not the one --sums-sha256 names"
  fi
  mkdir -p "$STAGE/dl" "$STAGE/dist-ui"
  assets=("mitm-agent-$ARCH-linux-musl" "cc-proxy-$ARCH-linux-musl")
  mapfile -t ui < <(sed -n 's/^[0-9a-f]\{64\}  mitm-agent-ui-//p' "$STAGE/SHA256SUMS")
  [ "${#ui[@]}" -gt 0 ] || die "the release has no page assets"
  for a in "${assets[@]}" "${ui[@]/#/mitm-agent-ui-}"; do
    grep -q "  $a\$" "$STAGE/SHA256SUMS" || die "the release has no $a"
    curl -fsSLo "$STAGE/dl/$a" "$url/$a" || die "could not download $a"
  done
  (cd "$STAGE/dl" && grep -E "  ($(IFS='|'; echo "${assets[*]}")|mitm-agent-ui-.*)\$" ../SHA256SUMS | sha256sum -c --quiet -) \
    || die "the downloads do not match the release's SHA256SUMS"
  mv "$STAGE/dl/mitm-agent-$ARCH-linux-musl" "$STAGE/mitm-agent"
  mv "$STAGE/dl/cc-proxy-$ARCH-linux-musl" "$STAGE/cc-proxy"
  for f in "${ui[@]}"; do mv "$STAGE/dl/mitm-agent-ui-$f" "$STAGE/dist-ui/$f"; done
fi
chmod 755 "$STAGE/mitm-agent" "$STAGE/cc-proxy"

# --- packages: openssl for the CA, Docker for OpenConnector, dnsmasq and chrony for the agents ---
# dnsmasq-base is the program without Ubuntu's dnsmasq service, which would take port 53 on every
# address (systemd-resolved has 127.0.0.53): controlclaw-dns runs it. chrony replaces
# systemd-timesyncd, as on a firewall the role manages, but not another time server the owner runs:
# apt would remove it without asking.
NTP=1
if ! command -v chronyd >/dev/null; then
  for d in ntpsec ntp openntpd; do
    if systemctl is-active --quiet "$d" 2>/dev/null; then NTP=0; OTHER_NTP="$d"; break; fi
  done
fi
need=()
command -v openssl >/dev/null || need+=(openssl)
command -v docker >/dev/null || need+=(docker.io)
[ -x /usr/sbin/dnsmasq ] || need+=(dnsmasq-base)
[ "$NTP" = 0 ] || command -v chronyd >/dev/null || need+=(chrony)
if [ "$WG" = 1 ]; then
  command -v wg >/dev/null || need+=(wireguard-tools)
  command -v nft >/dev/null || need+=(nftables)
fi
if [ "${#need[@]}" -gt 0 ]; then
  apt-get update -q >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${need[@]}" >/dev/null
fi
systemctl enable --now docker >/dev/null 2>&1 || true
DOCKER="$(command -v docker)" || die "docker is not installed"

# --- user, folders, first-start state ---
id controlclaw >/dev/null 2>&1 || useradd --system --home-dir "$ROOT" --shell /usr/sbin/nologin controlclaw
# dnsmasq drops root to this user once it has bound 53 (dnsmasq-base makes none).
id dnsmasq >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin dnsmasq
install -d -m 755 "$ROOT" "$ROOT/rust" "$ROOT/standalone" "$ETC"
touch "$MARKER"
install -d -m 750 -o controlclaw -g controlclaw "$ROOT/mitm" "$ROOT/mitm/logs" "$ROOT/mitm/ca"
install -d -m 700 -o controlclaw -g controlclaw "$ROOT/keys" "$ROOT/state"
install -d -m 700 -o root -g root "$ROOT/connector"
cc_make_ca "$ROOT/mitm/ca"
chown -R controlclaw:controlclaw "$ROOT/mitm/ca"
cc_make_connector_env "$ROOT/connector-keys.env"
chmod 600 "$ROOT/connector-keys.env"
if [ -n "$PAGE_HOST" ]; then
  cc_set_hostname "$ROOT/keys" "$PAGE_HOST"
  chown controlclaw:controlclaw "$ROOT/keys/vm_hostname"
fi

DEST="$ROOT/rust/$VERSION"
rm -rf "$DEST.new"; cp -r "$STAGE" "$DEST.new"; rm -f "$DEST.new/SHA256SUMS" "$DEST.new/SHA256SUMS.minisig"; rm -rf "$DEST.new/dl"
# mktemp made the folder 0700: the services run as controlclaw and must read it.
chmod -R u=rwX,go=rX "$DEST.new"
rm -rf "$DEST"; mv "$DEST.new" "$DEST"
install -m 644 "$LIB/cc-proxy.env" "$LIB/mitm-agent.env" "$LIB/connector.env" "$LIB/dnsmasq.conf" "$ROOT/standalone/"
install -m 755 "$LIB/wg-sync.sh" "$ROOT/standalone/wg-sync.sh"
[ -f "$ETC/firewall.env" ] || install -m 600 /dev/null "$ETC/firewall.env"
# An install from before standalone mode may point the agent at a console (STORE_URL=https://… from
# --with-agent): it stays that console's firewall, since standalone mode would stop at once on those.
# firewall.env is read after mitm-agent.env, so its MITM_MODE wins; one the owner wrote is kept.
if ! grep -q '^MITM_MODE=' "$ETC/firewall.env" && cc_has_control_plane < "$ETC/firewall.env"; then
  printf '# Written by install.sh: this firewall has a control plane (the URLs above). Remove them and this\n# line for standalone mode.\nMITM_MODE=saas\n' >> "$ETC/firewall.env"
  echo "install.sh: $ETC/firewall.env names a control plane: the firewall agent stays on MITM_MODE=saas (written there)" >&2
fi

# --- units ---
cat > /etc/systemd/system/run-mitm-config.mount <<EOF
[Unit]
Description=ControlClaw proxy secrets (in memory only)

[Mount]
What=tmpfs
Where=/run/mitm/config
Type=tmpfs
Options=rw,nosuid,nodev,mode=0700,uid=$(id -u controlclaw),gid=$(id -g controlclaw),size=16m

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/controlclaw-mitmproxy.service <<EOF
[Unit]
Description=ControlClaw egress proxy
After=network.target run-mitm-config.mount${WG_IP:+ wg-quick@cc-wg0.service}
RequiresMountsFor=/run/mitm/config

[Service]
Type=simple
User=controlclaw
LimitNOFILE=65536
MemoryMax=60%
EnvironmentFile=$ROOT/standalone/cc-proxy.env
EnvironmentFile=-$ETC/firewall.env
ExecStart=$DEST/cc-proxy --listen $LISTEN:8080$( [ -z "$WG_IP" ] || [ "$LISTEN" = 0.0.0.0 ] || echo " --listen $WG_IP:8080")
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# The firewall agent writes the proxy's rules now; an install from before standalone mode copied them.
rm -rf /etc/systemd/system/controlclaw-mitmproxy.service.d

# What pairing tells agents: the proxy's address, when it is one they reach (firewall.env, read
# after it, wins). On 0.0.0.0 or loopback it is left out, and agents use the firewall's own host.
case "$LISTEN" in
  0.0.0.0|127.*) PAIR_PROXY_LINE="" ;;
  *) PAIR_PROXY_LINE="Environment=PAIR_PROXY_ADDR=$LISTEN:8080
" ;;
esac
# And its DNS, when it serves the agents one; and its WireGuard, for remote agents.
[ -z "$PRIVATE" ] || PAIR_PROXY_LINE="${PAIR_PROXY_LINE}Environment=PAIR_DNS_ADDR=$PRIVATE
"
[ "$WG" = 0 ] || PAIR_PROXY_LINE="${PAIR_PROXY_LINE}Environment=WG_ENDPOINT=$WG_ENDPOINT
Environment=WG_ADDRESS=$WG_ADDRESS
Environment=WG_PROXY_PORT=8080
"
cat > /etc/systemd/system/controlclaw-mitm-agent.service <<EOF
[Unit]
Description=ControlClaw firewall agent
After=network.target run-mitm-config.mount controlclaw-connector.service
RequiresMountsFor=/run/mitm/config

[Service]
Type=simple
User=controlclaw
Environment=HOME=$ROOT
${PAIR_PROXY_LINE}EnvironmentFile=$ROOT/standalone/mitm-agent.env
EnvironmentFile=$ROOT/connector-keys.env
EnvironmentFile=-$ETC/firewall.env
ExecStart=$DEST/mitm-agent
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Where an app's OAuth sign-in comes back: the panel's /oauth/callback, worked out as the firewall
# agent does from the same LOCAL_PANEL_URL. One given to this install is the owner's (firewall.env,
# read after mitm-agent.env); every install writes the connector's from what is there now.
if [ -n "${LOCAL_PANEL_URL:-}" ]; then
  sed -i '/^LOCAL_PANEL_URL=/d' "$ETC/firewall.env"
  printf 'LOCAL_PANEL_URL=%s\n' "$LOCAL_PANEL_URL" >> "$ETC/firewall.env"
fi
panel_url="$(sed -n 's/^LOCAL_PANEL_URL=//p' "$ETC/firewall.env" | tail -1)"
panel_bind="$(sed -n 's/^LOCAL_PANEL_BIND=//p' "$ROOT/standalone/mitm-agent.env" "$ETC/firewall.env" | tail -1)"
cc_write_connector_origin "$ROOT/standalone/connector-origin.env" "$panel_url" "$panel_bind"

# As the role runs it: host network so its loopback is the VM's, a memory cap on the container.
cat > /etc/systemd/system/controlclaw-connector.service <<EOF
[Unit]
Description=ControlClaw app connector runtime (OpenConnector, loopback only)
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=simple
ExecStartPre=-$DOCKER rm -f controlclaw-connector
ExecStart=$DOCKER run --rm --name controlclaw-connector --network host \\
  --memory 512m --oom-score-adj 500 \\
  -v $ROOT/connector:$ROOT/connector \\
  --env-file $ROOT/standalone/connector.env --env-file $ROOT/connector-keys.env \\
  --env-file $ROOT/standalone/connector-origin.env \\
  $CONNECTOR_IMAGE
ExecStop=$DOCKER stop -t 10 controlclaw-connector
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# The agents' DNS: the role's settings, on the private address, else on loopback only (so it does
# not take 127.0.0.1:53 from a resolver of the owner's when it is not needed there). bind-dynamic
# binds an address that comes up after the service (a private network attached late) as well.
{
  echo "# Written by install.sh at every run. Settings: $ROOT/standalone/dnsmasq.conf"
  echo "conf-file=$ROOT/standalone/dnsmasq.conf"
  echo "user=dnsmasq"
  echo "bind-dynamic"
  echo "listen-address=${PRIVATE:-127.0.0.1}"
  [ -z "$WG_IP" ] || echo "listen-address=$WG_IP"
} > "$ETC/dnsmasq.conf"
chmod 644 "$ETC/dnsmasq.conf"

cat > /etc/systemd/system/controlclaw-dns.service <<EOF
[Unit]
Description=ControlClaw DNS for the agents (dnsmasq)
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/dnsmasq -k --conf-file=$ETC/dnsmasq.conf
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# --- WireGuard for remote agents ---
if [ "$WG" = 1 ]; then
  cc_wg_files "$WG_ADDRESS" "$WG_ENDPOINT" 8080 "$ETC/wg.nft" "$ROOT/standalone/wg-sync.sh" || die "WireGuard settings"
  [ -s /etc/wireguard/cc-wg0.key ] || (umask 077; wg genkey > /etc/wireguard/cc-wg0.key)
  # The public half, for pairing to hand out; the private one stays root's.
  wg pubkey < /etc/wireguard/cc-wg0.key > "$ROOT/keys/wg_public_key"
  chown controlclaw:controlclaw "$ROOT/keys/wg_public_key"; chmod 644 "$ROOT/keys/wg_public_key"
  cat > /etc/systemd/system/controlclaw-wg-sync.service <<EOF
[Unit]
Description=ControlClaw: apply the agents' WireGuard peers
After=wg-quick@cc-wg0.service
Requisite=wg-quick@cc-wg0.service

[Service]
Type=oneshot
ExecStart=$ROOT/standalone/wg-sync.sh
# It reads a file the firewall agent writes: bounded whatever that file is.
TimeoutStartSec=30
MemoryMax=64M
EOF
  cat > /etc/systemd/system/controlclaw-wg-sync.path <<EOF
[Unit]
Description=ControlClaw: watch the agents' WireGuard peers

[Path]
PathChanged=$ROOT/state/wg-peers.conf

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
if [ "$WG" = 1 ]; then
  systemctl enable wg-quick@cc-wg0 controlclaw-wg-sync.path >/dev/null
  systemctl restart wg-quick@cc-wg0 && systemctl restart controlclaw-wg-sync.path
  # ufw's own input chain drops what its rules do not allow, whatever ours accept: let the tunnel
  # reach the proxy and DNS, and agents reach WireGuard (which only answers keys it knows).
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow in on cc-wg0 to "$WG_IP" port 8080 proto tcp comment controlclaw-wg >/dev/null
    ufw allow in on cc-wg0 to "$WG_IP" port 53 comment controlclaw-wg >/dev/null
    ufw allow in on cc-wg0 to "$WG_IP" port 123 proto udp comment controlclaw-wg >/dev/null
    ufw allow in on cc-wg0 to "$WG_IP" port 3900,3940 proto tcp comment controlclaw-wg >/dev/null
    ufw allow "${WG_ENDPOINT##*:}/udp" comment controlclaw-wg >/dev/null
    UFW_WG=1
  fi
elif [ -f "$ROOT/keys/wg_public_key" ] || [ -f /etc/wireguard/cc-wg0.conf ]; then
  # Set up again without --wireguard: the tunnel goes (its key stays, for a later --wireguard).
  systemctl disable --now controlclaw-wg-sync.path wg-quick@cc-wg0 2>/dev/null || true
  rm -f "$ROOT/keys/wg_public_key" /etc/wireguard/cc-wg0.conf "$ETC/wg.nft" \
    /etc/systemd/system/controlclaw-wg-sync.path /etc/systemd/system/controlclaw-wg-sync.service
  systemctl daemon-reload
  cc_ufw_forget_wg
fi
systemctl enable --now run-mitm-config.mount controlclaw-connector controlclaw-mitmproxy controlclaw-dns >/dev/null
systemctl enable controlclaw-mitm-agent >/dev/null
# A reinstall with a new unit or image takes effect now.
systemctl restart controlclaw-connector controlclaw-mitm-agent controlclaw-mitmproxy controlclaw-dns
# dnsmasq stops at once when it cannot bind (port 53 taken by another resolver); a simple unit still
# reports the start as done, so look again.
sleep 2
DNS_OK=1; systemctl is-active --quiet controlclaw-dns || DNS_OK=0
# The agents' time: chrony answers NTP on the private address, from private addresses only. Without
# one it keeps this machine's clock and serves nobody. With WireGuard it answers on the tunnel
# address too: chrony takes one bindaddress per family, so then it binds none, and the nft rules
# (cc_wg_nft) and ufw decide who reaches 123; the allow lines hold it to private addresses still.
# chrony restarts only when that changed: a restart drops its sync for a while.
chrony_was="$(cat "$CHRONY_CONF" 2>/dev/null || true)"
if [ "$NTP" = 1 ] && { [ -n "$PRIVATE" ] || [ "$WG" = 1 ]; }; then
  mkdir -p "$(dirname "$CHRONY_CONF")"
  # chrony's allow lines are who may ask. On the private address: private addresses. On the tunnel
  # alone: its own /24. On both: no bindaddress (one per family), and the tunnel's rules drop NTP
  # on every other interface (cc_wg_nft).
  allow="allow 10.0.0.0/8
allow 172.16.0.0/12
allow 192.168.0.0/16
allow 100.64.0.0/10"
  if [ "$WG" = 1 ] && [ -z "$PRIVATE" ]; then
    bind_line="bindaddress $WG_IP"; allow="allow ${WG_IP%.*}.0/24"
  elif [ "$WG" = 1 ]; then bind_line="# no bindaddress: the private address and the tunnel's ($WG_IP); others dropped by controlclaw-ntp-guard"
  else bind_line="bindaddress $PRIVATE"; fi
  printf '# Written by install.sh: time for the agents, on the proxy'"'"'s private address (and the tunnel'"'"'s).
%s
%s
' "$bind_line" "$allow" > "$CHRONY_CONF"
else
  rm -f "$CHRONY_CONF"
fi
# With WireGuard chrony may bind no address: the guard drops NTP on every interface but loopback,
# the tunnel and the private one, from boot (before chrony), whether the tunnel is up or not.
if [ "$NTP" = 1 ] && [ "$WG" = 1 ]; then
  PRIVATE_IF=""
  [ -z "$PRIVATE" ] || PRIVATE_IF="$(ip -4 -o addr show | awk -v a="$PRIVATE" '{split($4, p, "/")} p[1] == a {print $2; exit}')"
  cc_ntp_nft "$PRIVATE_IF" > "$ETC/ntp.nft"
  cat > /etc/systemd/system/controlclaw-ntp-guard.service <<UNIT
[Unit]
Description=ControlClaw: NTP for the agents only (the tunnel and the private network)
Before=chrony.service
DefaultDependencies=no
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $ETC/ntp.nft
ExecStop=/usr/sbin/nft delete table inet controlclaw_ntp

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable controlclaw-ntp-guard.service >/dev/null 2>&1 || true
  systemctl restart controlclaw-ntp-guard.service || die "the NTP guard (journalctl -u controlclaw-ntp-guard)"
elif [ -f /etc/systemd/system/controlclaw-ntp-guard.service ]; then
  systemctl disable --now controlclaw-ntp-guard.service 2>/dev/null || true
  rm -f /etc/systemd/system/controlclaw-ntp-guard.service "$ETC/ntp.nft"
  systemctl daemon-reload
fi
if [ "$NTP" = 1 ]; then
  systemctl enable chrony >/dev/null 2>&1 || true
  if [ "$chrony_was" != "$(cat "$CHRONY_CONF" 2>/dev/null || true)" ] || ! systemctl is-active --quiet chrony; then
    systemctl restart chrony || { NTP=0; echo "install.sh: chrony did not start (journalctl -u chrony): no NTP for the agents" >&2; }
  fi
fi

# `mitm-agent open <page>` from a shell (as controlclaw, which reads the keys folder).
ln -sfn "$DEST/mitm-agent" /usr/local/bin/mitm-agent
# Older versions are removed once the new one runs.
find "$ROOT/rust" -mindepth 1 -maxdepth 1 ! -name "$VERSION" -exec rm -rf {} +

echo "installed $VERSION ($ARCH)"
echo "  proxy:  $LISTEN:8080 (agents connect through it)"
case "$LISTEN" in
  127.*) echo "          only this machine can use it: to open it to your agents, run again with --listen <an address they reach> and allow only them there" ;;
  0.0.0.0) echo "          on every address: allow 8080 only from your agents (a host firewall or your cloud's)" ;;
esac
if [ "$DNS_OK" = 0 ]; then
  echo "  DNS:    NOT RUNNING: controlclaw-dns stopped (another resolver on port 53?). See journalctl -u controlclaw-dns"
elif [ -n "$PRIVATE" ]; then
  echo "  DNS:    $PRIVATE:53 udp/tcp (for your agents; it answers every name, the proxy filters)"
elif [[ "$LISTEN" == 127.* ]]; then
  echo "  DNS:    127.0.0.1:53 only, no NTP for agents (the proxy is on loopback too): use --listen <a private"
  echo "          address> to serve your agents"
else
  echo "  DNS:    127.0.0.1:53 only, no NTP for agents: $LISTEN is not a private address, and a resolver there"
  echo "          would answer the whole internet. Use --listen <a private address> to serve your agents"
fi
if [ -n "$OTHER_NTP" ]; then
  echo "  NTP:    not served: $OTHER_NTP keeps this machine's time, and chrony would replace it. Point your agents at it, or remove it and run again"
elif [ "$NTP" = 1 ] && [ -n "$PRIVATE" ]; then
  echo "  NTP:    $PRIVATE:123 udp (for your agents)"
fi
echo "  CA:     $ROOT/mitm/ca/ca-cert.pem (agents must trust it)"
echo "  rules and agents: the firewall's local database ($ROOT/state/local.db), set through its API"
echo "          (PUT /api/egress-rules, /api/agents; see docs/standalone/standalone-mode.md)"
echo "  pages:  sudo -u controlclaw mitm-agent open logins$( [ -f "$ROOT/keys/vm_hostname" ] || echo "   (first: run again with --hostname <name>)")"
echo "  pair:   sudo -u controlclaw mitm-agent pair-code --name <agent>"
echo "          then on the agent's machine: controlclaw connect --firewall http://<this firewall>:8801 --mode <mode> (it asks for the code)"
if [ "$WG" = 1 ]; then
  echo "  WireGuard: cc-wg0 at $WG_ADDRESS, reached at $WG_ENDPOINT (open UDP ${WG_ENDPOINT##*:} to your agents$( [ "$UFW_WG" = 0 ] || echo "; ufw: opened, and the tunnel's proxy and DNS"))"
  echo "          remote agents: controlclaw connect --mode remote --firewall http://<this firewall>:8801"
  echo "          the proxy and DNS answer them on $WG_IP"
fi
echo "  close 8080, 53 and 123 to everything but your agents"
echo "  8801 (pairing) answers only a waiting one-time code; close it too when no agent is pairing"
openssl x509 -in "$ROOT/mitm/ca/ca-cert.pem" -noout -fingerprint -sha256
