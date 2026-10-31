# First-start setup shared by the Docker image (docker/entrypoint.sh) and the VM install
# (install/install.sh): the interception CA and the connector's keys. Sourced, POSIX sh.
# Both are made once, behind an existence check: making either again would cut every agent off
# (a new CA) or lose every stored app credential (new connector keys).

# The CA, as the role's gen-ca.sh makes it: an RSA key and its certificate, in one PEM for the proxy
# (mitmproxy-ca.pem) and the public half alone for the agents (ca-cert.pem).
cc_make_ca() {
  dir="$1"
  if [ -f "$dir/mitmproxy-ca.pem" ]; then return 0; fi
  mkdir -p "$dir"
  (
    umask 077
    openssl genrsa -out "$dir/ca-key.pem" 4096 2>/dev/null
    openssl req -x509 -new -nodes -key "$dir/ca-key.pem" -sha256 -days 3650 \
      -subj "/CN=ControlClaw Egress CA/O=ControlClaw" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -out "$dir/ca-cert.pem" 2>/dev/null
    cat "$dir/ca-key.pem" "$dir/ca-cert.pem" > "$dir/mitmproxy-ca.pem.tmp"
    mv "$dir/mitmproxy-ca.pem.tmp" "$dir/mitmproxy-ca.pem"
  )
  chmod 644 "$dir/ca-cert.pem"
  echo "[controlclaw] made the CA in $dir"
}

# The connector's keys, as the role's connector.yml writes them. The admin token is there twice:
# under the runtime's name and under the firewall agent's.
cc_make_connector_env() {
  file="$1"
  if [ -f "$file" ]; then return 0; fi
  (
    umask 077
    admin="$(openssl rand -hex 32)"
    printf 'OOMOL_CONNECT_ENCRYPTION_KEY=%s\nOOMOL_CONNECT_ADMIN_TOKEN=%s\nCONNECTOR_ADMIN_TOKEN=%s\nOOMOL_CONNECT_RUNTIME_TOKEN=%s\n' \
      "$(openssl rand -base64 32)" "$admin" "$admin" "$(openssl rand -hex 32)" > "$file.tmp"
    mv "$file.tmp" "$file"
  )
  echo "[controlclaw] made the connector keys in $file"
}

# Where a browser reaches the panel, as the firewall agent works it out (cc_local::panel_origin): the
# origin of LOCAL_PANEL_URL (scheme, host, port; no path), else http://localhost:<port of
# LOCAL_PANEL_BIND, 8800>. OpenConnector's OAuth comes back to <this>/oauth/callback.
cc_panel_origin() {
  url="$1"; bind="${2:-127.0.0.1:8800}"
  if [ -n "$url" ]; then
    printf '%s\n' "$url" | sed -E 's#^([A-Za-z][A-Za-z0-9+.-]*://[^/?#]+).*#\1#'
  else
    printf 'http://localhost:%s\n' "${bind##*:}"
  fi
}
cc_write_connector_origin() {
  printf 'OOMOL_CONNECT_ORIGIN=%s\n' "$(cc_panel_origin "$2" "$3")" > "$1"
}

# The name a browser reaches this firewall's pages at, which `mitm-agent open` puts in its links
# (https://<name>/, so on port 443). The firewall agent takes a dotted name with no port only (its
# HOSTNAME check in core/access.rs); anything else is refused here rather than at the first link.
cc_valid_hostname() {
  # One line (grep reads line by line) and at most 253 characters, as the agent checks.
  case "$1" in *"
"*) return 1 ;; esac
  [ "${#1}" -le 253 ] || return 1
  printf '%s' "$1" | grep -Eqi '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
}
cc_set_hostname() {
  dir="$1"; name="$2"
  if ! cc_valid_hostname "$name"; then
    echo "[controlclaw] not a host name with a dot and no port: $name" >&2
    return 1
  fi
  printf '%s\n' "$name" > "$dir/vm_hostname"
}

# Whether KEY=value lines on stdin (an env file, or `env`) give the firewall agent a control plane:
# one of the variables standalone mode refuses (core::env::CONTROL_PLANE_VARS in mitm-agent), set
# to something other than a file: path. Such a firewall is a console's (MITM_MODE=saas); started as
# standalone it would stop at once on that variable, again and again.
cc_has_control_plane() {
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      FIREWALL_URL=*|STORE_URL=*|RULES_URL=*|IDENTITIES_URL=*|WEBHOOKS_URL=*|PERMISSION_URL=*|CA_URL=*|ACTIVITY_URL=*|MIGRATE_FROM_URL=*)
        value="${line#*=}"
        case "$value" in ''|file:*) ;; *) return 0 ;; esac
        ;;
    esac
  done
  return 1
}

# Export each KEY=value of an env file (the format systemd's EnvironmentFile reads) that is not set
# already, so what the caller set wins over the defaults.
cc_load_env_defaults() {
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    key="${line%%=*}"
    # A name only, before it reaches eval.
    case "$key" in
      ''|[!A-Za-z_]*|*[!A-Za-z0-9_]*) echo "[controlclaw] $1: not a setting name: $key" >&2; return 1 ;;
    esac
    eval "set_already=\${$key+x}"
    [ -n "$set_already" ] || export "$key=${line#*=}"
  done < "$1"
}

# Whether an IPv4 address is a private one: 10/8, 172.16/12, 192.168/16 or 100.64/10 (Tailscale).
# DNS and NTP for the agents go only there: on a public address they would answer the whole internet.
cc_private_ipv4() {
  printf '%s\n' "$1" | awk -F. '
    NF != 4 { exit 1 }
    { for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || $i + 0 > 255) exit 1 }
    ($1 == 10) || ($1 == 172 && $2 >= 16 && $2 <= 31) || ($1 == 192 && $2 == 168) || ($1 == 100 && $2 >= 64 && $2 <= 127) { ok = 1 }
    END { exit !ok }'
}

# WireGuard for remote agents (install.sh --wireguard, the image's CC_WIREGUARD=1). The rules for
# what comes in from the tunnel: the proxy (port $2), DNS, NTP and the gates (3900 app connections,
# 3940 MCP servers) on the firewall's tunnel address ($1), and answers to what the firewall started
# (its calls to the agents' vm-agent). Nothing is forwarded.
cc_wg_nft() {
  cat <<EOF
table inet controlclaw_wg
delete table inet controlclaw_wg
table inet controlclaw_wg {
  chain input {
    type filter hook input priority 0; policy accept;
    iifname "cc-wg0" ct state established,related accept
    iifname "cc-wg0" ip daddr $1 tcp dport $2 accept
    iifname "cc-wg0" ip daddr $1 meta l4proto { tcp, udp } th dport 53 accept
    iifname "cc-wg0" ip daddr $1 udp dport 123 accept
    iifname "cc-wg0" ip daddr $1 tcp dport { 3900, 3940 } accept
    iifname "cc-wg0" drop
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
    iifname "cc-wg0" drop
    oifname "cc-wg0" drop
  }
}
EOF
}

# NTP served by chrony with no bindaddress (install.sh --wireguard: the tunnel's address and the
# private one): every interface but loopback, the tunnel and $1 (the private address's, may be
# empty) drops it. Loaded at boot before chrony by its own unit, whether the tunnel is up or not.
cc_ntp_nft() {
  ifs="\"lo\", \"cc-wg0\""
  [ -z "${1:-}" ] || ifs="$ifs, \"$1\""
  cat <<EOF
table inet controlclaw_ntp
delete table inet controlclaw_ntp
table inet controlclaw_ntp {
  chain input {
    type filter hook input priority -1; policy accept;
    udp dport 123 iifname != { $ifs } drop
  }
}
EOF
}

# The interface's config: its address ($1, a /24), port ($2), the rules file ($3) and the peers'
# sync script ($4). The key is set from /etc/wireguard/cc-wg0.key; the peers come from the firewall
# agent.
cc_wg_conf() {
  cat <<EOF
# Written at every install or start. The peers come from the firewall agent (wg-sync).
[Interface]
Address = $1
ListenPort = $2
PostUp = wg set %i private-key /etc/wireguard/cc-wg0.key; nft -f $3; $4
PostDown = nft delete table inet controlclaw_wg
EOF
}

# Both files at once, for install.sh and the image: the address ($1) must be a /24 (wg-sync.sh reads
# it), the endpoint ($2) host:port, the proxy's own port ($3); the rules go to $4, the interface's
# config to /etc/wireguard/cc-wg0.conf, with the peers applied by $5.
cc_wg_files() {
  case "$1" in */24) ;; *) echo "[controlclaw] the WireGuard address is an IPv4 address with /24 (10.77.0.1/24), not $1" >&2; return 1 ;; esac
  printf '%s' "$2" | grep -Eq '^[A-Za-z0-9.-]+:[0-9]{1,5}$' || { echo "[controlclaw] the WireGuard endpoint is host:port, not $2" >&2; return 1; }
  install -d -m 700 /etc/wireguard
  cc_wg_nft "${1%/24}" "$3" > "$4"
  (umask 077; cc_wg_conf "$1" "${2##*:}" "$4" "$5" > /etc/wireguard/cc-wg0.conf)
}

# A minisign signature check with openssl only (standalone/release/SIGNING.md): <public key, the
# base64 line of a minisign .pub> <file> <file.minisig>. Takes the prehashed form minisign makes by
# default ("ED": Ed25519 over the file's BLAKE2b-512), checks the key id, the signature and the
# signature over the trusted comment. Exits non-zero, with a reason on stderr, on anything else.
cc_minisign_verify() {
  (
    set -e
    t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
    fail() { echo "signature: $*" >&2; exit 1; }
    # Ed25519 with -rawin needs OpenSSL 3: say so, not that the release is not signed.
    case "$(openssl version 2>/dev/null)" in
      "OpenSSL "[3-9].*) ;;
      *) fail "checking it needs OpenSSL 3 or newer (this machine has: $(openssl version 2>/dev/null || echo none))" ;;
    esac
    printf '%s' "$1" | base64 -d > "$t/pk" 2>/dev/null || fail "the public key is not base64"
    { [ "$(wc -c < "$t/pk")" -eq 42 ] && [ "$(head -c 2 "$t/pk")" = Ed ]; } || fail "not a minisign public key"
    [ -s "$3" ] || fail "no signature file $3"
    sed -n 2p "$3" | base64 -d > "$t/sig" 2>/dev/null || fail "the signature is not base64"
    { [ "$(wc -c < "$t/sig")" -eq 74 ] && [ "$(head -c 2 "$t/sig")" = ED ]; } || fail "not a prehashed minisign signature"
    head -c 10 "$t/pk" | tail -c 8 > "$t/pkid"; head -c 10 "$t/sig" | tail -c 8 > "$t/sigid"
    cmp -s "$t/pkid" "$t/sigid" || fail "signed with another key"
    # The public key as DER SubjectPublicKeyInfo: the fixed Ed25519 prefix, then its 32 bytes.
    { printf '\060\052\060\005\006\003\053\145\160\003\041\000'; tail -c 32 "$t/pk"; } > "$t/pk.der"
    tail -c 64 "$t/sig" > "$t/s"
    openssl dgst -blake2b512 -binary "$2" > "$t/h"
    openssl pkeyutl -verify -pubin -keyform DER -inkey "$t/pk.der" -rawin -in "$t/h" -sigfile "$t/s" >/dev/null 2>&1 \
      || fail "$2 does not match its signature"
    tc="$(sed -n 3p "$3")"
    case "$tc" in "trusted comment: "*) ;; *) fail "no trusted comment" ;; esac
    { cat "$t/s"; printf '%s' "${tc#trusted comment: }"; } > "$t/g"
    sed -n 4p "$3" | base64 -d > "$t/gs" 2>/dev/null || fail "the comment's signature is not base64"
    openssl pkeyutl -verify -pubin -keyform DER -inkey "$t/pk.der" -rawin -in "$t/g" -sigfile "$t/gs" >/dev/null 2>&1 \
      || fail "the trusted comment does not match its signature"
  )
}
