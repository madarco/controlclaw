#!/bin/sh
# Applies the agents' WireGuard peers to cc-wg0: the firewall agent writes them (as controlclaw) to
# $ROOT/state/wg-peers.conf, root applies them here (`wg syncconf`), started by
# controlclaw-wg-sync.path when the file changes and by wg-quick when the interface comes up.
#
# The file is the firewall agent's, so only what a peer list needs gets through (peers() below): no
# [Interface], no Endpoint, no other keys or networks.
set -eu
ROOT=/opt/controlclaw
IFACE=cc-wg0
PEERS="$ROOT/state/wg-peers.conf"
KEY=/etc/wireguard/$IFACE.key
# The tunnel network's first three parts (10.77.0.) and the firewall's own address there, from the
# interface's own config.
FW="$(sed -n 's#^Address *= *\([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\)/24$#\1#p' /etc/wireguard/$IFACE.conf)"
[ -n "$FW" ] || { echo "wg-sync: no /24 Address in /etc/wireguard/$IFACE.conf" >&2; exit 1; }
NET="${FW%.*}."
PORT="$(sed -n 's/^ListenPort *= *\([0-9]*\)$/\1/p' /etc/wireguard/$IFACE.conf)"

# The peers, as the firewall agent wrote them: a regular file only (not a link, a FIFO or a device,
# which could hang this or never end), at most 1 MiB. Each [Peer] gets through with one PublicKey
# and one AllowedIPs, a /32 from .2 to .254 of the tunnel network and not the firewall's own; each
# key and each address once. Anything else drops the peer, or the line.
peers() {
  [ -f "$PEERS" ] && [ ! -L "$PEERS" ] || return 0
  timeout 10 head -c 1048576 "$PEERS" | awk -v net="$NET" -v fw="$FW" '
    function flush() {
      if (open && key != "" && ip != "" && !bad && !(key in keys) && !(ip in ips)) {
        keys[key] = 1; ips[ip] = 1
        printf "[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n", key, ip
      }
      open = 0; key = ""; ip = ""; bad = 0
    }
    $0 == "[Peer]" { flush(); open = 1; next }
    open && $1 == "PublicKey" && $2 == "=" && NF == 3 {
      if (key != "" || length($3) != 44 || $3 !~ /^[A-Za-z0-9+\/]+=$/) bad = 1; else key = $3
      next
    }
    open && $1 == "AllowedIPs" && $2 == "=" && NF == 3 {
      a = $3
      if (ip != "" || substr(a, length(a) - 2) != "/32") { bad = 1; next }
      a = substr(a, 1, length(a) - 3)
      host = substr(a, length(net) + 1)
      if (substr(a, 1, length(net)) != net || host !~ /^[0-9]+$/ || host ~ /^0/ || length(host) > 3 || host + 0 < 2 || host + 0 > 254 || a == fw) { bad = 1; next }
      ip = a
      next
    }
    /^\[/ { flush(); next }
    END { flush() }
  '
}

{
  printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n' "$(cat "$KEY")" "$PORT"
  peers
} | wg syncconf "$IFACE" /dev/stdin
echo "wg-sync: $(wg show "$IFACE" peers | wc -l) peer(s) on $IFACE"
