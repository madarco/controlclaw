#!/bin/sh
# The firewall container: OpenConnector, cc-proxy, the firewall agent (mitm-agent) and dnsmasq (the
# agents' DNS), started under tini. First start makes the CA and the connector's keys on the /opt/controlclaw volume; a restart
# keeps them. When one program stops, the others are stopped and the container exits non-zero, so
# Docker's restart policy starts them all again.
#
# Runs as root to set up the volume, then starts each program as its own user (Dockerfile): cc-proxy
# and the firewall agent as controlclaw, OpenConnector as connector. The firewall agent runs in
# standalone mode (MITM_MODE in mitm-agent.env; docs/standalone/standalone-mode.md).
set -eu

LIB=/usr/local/lib/controlclaw
ROOT=/opt/controlclaw
# shellcheck source=SCRIPTDIR/../lib/firstrun.sh
. "$LIB/firstrun.sh"

if [ "$(id -u)" != 0 ]; then
  echo "[controlclaw] the entrypoint must run as root (it starts each program as its own user): do not set --user" >&2
  exit 1
fi

mkdir -p "$ROOT/keys" "$ROOT/state" "$ROOT/mitm/ca" "$ROOT/mitm/logs" "$ROOT/connector" /run/mitm/config
chown controlclaw:controlclaw "$ROOT/keys" "$ROOT/state" "$ROOT/mitm" "$ROOT/mitm/logs" /run/mitm/config
chown -R connector:connector "$ROOT/connector"
chmod 700 "$ROOT/keys" "$ROOT/state" "$ROOT/connector" /run/mitm/config
if ! grep -qs ' /run/mitm/config tmpfs ' /proc/mounts; then
  echo "[controlclaw] /run/mitm/config is not a tmpfs: the proxy's secrets are written to the container's disk (run with --tmpfs /run/mitm/config:uid=10001,mode=0700)"
fi
cc_make_ca "$ROOT/mitm/ca"
chown -R controlclaw:controlclaw "$ROOT/mitm/ca"
# Root's only: handed to the connector and the firewall agent in their environment, never readable
# on disk by the proxy.
cc_make_connector_env "$ROOT/connector-keys.env"
chown root:root "$ROOT/connector-keys.env"
chmod 600 "$ROOT/connector-keys.env"
echo "[controlclaw] CA: $(openssl x509 -in "$ROOT/mitm/ca/ca-cert.pem" -noout -fingerprint -sha256)"
export HOME="$ROOT"

# The name the page links use (CC_HOSTNAME).
if [ -n "${CC_HOSTNAME:-}" ]; then
  cc_set_hostname "$ROOT/keys" "$CC_HOSTNAME"
  chown controlclaw:controlclaw "$ROOT/keys/vm_hostname"
elif [ ! -f "$ROOT/keys/vm_hostname" ]; then
  echo "[controlclaw] pages: set CC_HOSTNAME to the name your browser reaches this firewall at (on 443), for the links 'mitm-agent open' prints"
fi

# A container given a console's settings (docker run -e STORE_URL=https://…) stays that console's
# firewall: standalone mode would stop at once on them. MITM_MODE set by the caller wins.
if [ -z "${MITM_MODE:-}" ] && env | cc_has_control_plane; then
  export MITM_MODE=saas
  echo "[controlclaw] a control plane is set (STORE_URL, FIREWALL_URL, …): the firewall agent runs with MITM_MODE=saas; set MITM_MODE=standalone and unset them for a firewall of your own"
fi

# Each program gets its own settings files and no others, read here as root, and runs as its own
# user. What the caller set (docker run -e) wins over the defaults.
pids=""
start() {
  name="$1"; user="$2"; envs="$3"; shift 3
  (
    for f in $envs; do cc_load_env_defaults "$f"; done
    exec su-exec "$user" "$@"
  ) &
  pids="$pids $!"
  echo "[controlclaw] started $name as $user (pid $!)"
}
stop() {
  for p in $pids; do kill -TERM "$p" 2>/dev/null || true; done
  for p in $pids; do wait "$p" 2>/dev/null || true; done
}
trap 'stop; exit 0' TERM INT

# WireGuard for remote agents (CC_WIREGUARD=1; needs --cap-add NET_ADMIN and the host's wireguard
# module): cc-wg0 on WG_ADDRESS (default 10.77.0.1/24), reached at WG_ENDPOINT (host:port, required).
# The key is kept on the volume, root's only; the public half is handed out by pairing.
if [ "${CC_WIREGUARD:-0}" = 1 ]; then
  [ -n "${WG_ENDPOINT:-}" ] || { echo "[controlclaw] CC_WIREGUARD=1 needs WG_ENDPOINT: the host:port agents reach this firewall's WireGuard at" >&2; exit 1; }
  export WG_ENDPOINT WG_ADDRESS="${WG_ADDRESS:-10.77.0.1/24}" WG_PROXY_PORT="${CC_PROXY_PORT:-8080}"
  cc_wg_files "$WG_ADDRESS" "$WG_ENDPOINT" "$WG_PROXY_PORT" /etc/wireguard/wg.nft "$LIB/wg-sync.sh"
  [ -s "$ROOT/wireguard.key" ] || (umask 077; wg genkey > "$ROOT/wireguard.key")
  chown root:root "$ROOT/wireguard.key"; chmod 600 "$ROOT/wireguard.key"
  install -d -m 700 /etc/wireguard
  install -m 600 "$ROOT/wireguard.key" /etc/wireguard/cc-wg0.key
  wg pubkey < "$ROOT/wireguard.key" > "$ROOT/keys/wg_public_key"
  chown controlclaw:controlclaw "$ROOT/keys/wg_public_key"
  wg-quick down cc-wg0 >/dev/null 2>&1 || true
  wg-quick up cc-wg0
  # The peers, applied when the firewall agent rewrites them.
  start wg-sync root "" sh -c 'last=""; while :; do f=/opt/controlclaw/state/wg-peers.conf; now=""; if [ -f "$f" ] && [ ! -L "$f" ]; then now="$(timeout 5 head -c 1048576 "$f" | cksum)"; fi; if [ "$now" != "$last" ]; then timeout 30 '"$LIB"'/wg-sync.sh && last="$now"; fi; sleep 3; done'
fi

# Without WireGuard, pairing hands out no tunnel (a volume from a CC_WIREGUARD=1 run keeps the key).
[ "${CC_WIREGUARD:-0}" = 1 ] || rm -f "$ROOT/keys/wg_public_key"

# Where an app's OAuth sign-in comes back: the panel (its /oauth/callback page), as the firewall
# agent's LOCAL_PANEL_URL says, at every start.
cc_write_connector_origin "$ROOT/connector-origin.env" "${LOCAL_PANEL_URL:-}" "${LOCAL_PANEL_BIND:-}"
# OpenConnector's own entry, from /app as in its image.
start open-connector connector "$LIB/connector.env $ROOT/connector-keys.env $ROOT/connector-origin.env" sh -c 'cd /app && exec node src/server/index.ts'
# The proxy's tenant is the agent's organization (local unless ORG_ID is set), unless set itself.
[ -n "${MITM_TENANT:-}" ] || [ -z "${ORG_ID:-}" ] || export MITM_TENANT="$ORG_ID"
start cc-proxy controlclaw "$LIB/cc-proxy.env" "$LIB/cc-proxy" --listen "0.0.0.0:${CC_PROXY_PORT:-8080}"
start mitm-agent controlclaw "$LIB/mitm-agent.env $ROOT/connector-keys.env" "$LIB/mitm-agent"
# The agents' DNS, on the container's addresses: who reaches it is the port publishing's choice, so
# with compose's CC_LISTEN on a public address (or all of them) it would answer the whole internet,
# and Docker's published ports go around a host firewall. Not started there unless CC_DNS_PUBLIC=1.
# It binds 53 as root, then runs as its own dnsmasq user; its log goes to the container's.
case "${CC_LISTEN:-}" in
  ""|127.*) dns_ok=1 ;;
  *) if cc_private_ipv4 "$CC_LISTEN" || [ "${CC_DNS_PUBLIC:-0}" = 1 ]; then dns_ok=1; else dns_ok=0; fi ;;
esac
if [ "$dns_ok" = 1 ]; then
  start dnsmasq root "" dnsmasq -k -C "$LIB/dnsmasq.conf" --log-facility=-
else
  echo "[controlclaw] DNS not started: CC_LISTEN=$CC_LISTEN is not a private address, and DNS there would answer the whole internet. Use a private address, or set CC_DNS_PUBLIC=1 if only your agents can reach it"
  # Remote agents still have theirs, on the tunnel only.
  if [ "${CC_WIREGUARD:-0}" = 1 ]; then
    start dnsmasq-wg root "" dnsmasq -k -C "$LIB/dnsmasq.conf" --log-facility=- --interface=cc-wg0 --bind-interfaces --pid-file=/run/dnsmasq-wg.pid
  fi
fi

# Ports of a container behind the firewall, published through it (`controlclaw up --local`: OpenClaw's
# gateway, on an internal network Docker publishes nothing from). CC_FORWARD is a list of
# <port>=<IPv4>:<port>, each a plain TCP relay run as controlclaw, listening on CC_FORWARD_BIND (an
# address of the firewall's; every one by default).
if ! printf '%s' "${CC_FORWARD_BIND:-0.0.0.0}" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
  echo "[controlclaw] CC_FORWARD_BIND: not an IPv4 address: $CC_FORWARD_BIND" >&2
  exit 1
fi
for f in $(printf '%s' "${CC_FORWARD:-}" | tr ',' ' '); do
  if ! printf '%s' "$f" | grep -Eq '^[0-9]{1,5}=([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$'; then
    echo "[controlclaw] CC_FORWARD: not <port>=<IPv4>:<port>: $f" >&2
    exit 1
  fi
  start "forward-${f%%=*}" controlclaw "" socat "TCP-LISTEN:${f%%=*},bind=${CC_FORWARD_BIND:-0.0.0.0},fork,reuseaddr" "TCP:${f#*=}"
done

while :; do
  for p in $pids; do
    if ! kill -0 "$p" 2>/dev/null; then
      code=0; wait "$p" || code=$?
      echo "[controlclaw] pid $p stopped (exit $code): stopping the others"
      stop
      exit 1
    fi
  done
  sleep 2
done
