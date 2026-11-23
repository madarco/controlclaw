#!/usr/bin/env bash
# Generate the proxy CA used to terminate/inspect HTTPS.
#
# v1 emits a single custom CA (proves "our CA, not a public one"). Production uses an
# offline root that signs an on-box intermediate (backlog P10) — the agent trust store
# only ever gets the PUBLIC cert; the private key never leaves the mitm box's LUKS disk.
#
# Outputs (into $1, default ./ca):
#   mitmproxy-ca.pem  -> key+cert bundle the proxy serves as its signing CA
#   ca-cert.pem       -> PUBLIC cert only, installed into the agent box trust store
set -euo pipefail

OUT="${1:-./ca}"
DAYS="${CA_DAYS:-3650}"
CN="${CA_CN:-ControlClaw Egress CA}"
mkdir -p "$OUT"

if [[ -f "$OUT/mitmproxy-ca.pem" && "${FORCE:-0}" != "1" ]]; then
  echo "[gen-ca] $OUT/mitmproxy-ca.pem already exists (FORCE=1 to overwrite)"
  exit 0
fi

openssl genrsa -out "$OUT/ca-key.pem" 4096 2>/dev/null
openssl req -x509 -new -nodes -key "$OUT/ca-key.pem" -sha256 -days "$DAYS" \
  -subj "/CN=${CN}/O=ControlClaw" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$OUT/ca-cert.pem" 2>/dev/null

# mitmproxy wants a single PEM containing the private key followed by the cert.
cat "$OUT/ca-key.pem" "$OUT/ca-cert.pem" > "$OUT/mitmproxy-ca.pem"
chmod 600 "$OUT/ca-key.pem" "$OUT/mitmproxy-ca.pem"

echo "[gen-ca] wrote $OUT/{ca-key.pem,ca-cert.pem,mitmproxy-ca.pem}"
openssl x509 -in "$OUT/ca-cert.pem" -noout -subject -fingerprint -sha256
