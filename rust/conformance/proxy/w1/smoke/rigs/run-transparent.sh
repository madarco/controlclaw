#!/usr/bin/env bash
# Transparent-egress smoke. Validates the two production-critical, novel behaviors of the redsocks
# design — deterministically — by reproducing exactly what redsocks puts on the wire: an explicit
# proxy CONNECT to the destination *by IP* with the real SNI (redsocks only knows the IP; the host
# is in the TLS SNI). The redsocks daemon + nftables REDIRECT themselves are a standard mechanism,
# exercised here best-effort (Docker Desktop's netfilter is flaky for REDIRECT'd loopback) and
# validated natively on real Hetzner via scripts/mitm-e2e.ts.
#   TT1: CONNECT-by-IP + SNI=echo.test → INTERCEPTED + credential swapped (no HTTP_PROXY semantics).
#   TT2: CONNECT-by-IP + SNI=cp.test  → INSPECTED (our CA) and allowed whatever the rules say, sent
#        to the control plane by name (since 2026-10-28; it used to be passed through).
set -uo pipefail
cd "$(dirname "$0")"

COMPOSE="docker compose -f docker-compose.transparent.yml"
SECRET="REAL-SECRET-abc123"
PLACEHOLDER="__ECHO_TOKEN"
PROXY_IP="10.77.0.250"
ECHO_IP="10.88.0.10"
FAILS=0

pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; FAILS=$((FAILS+1)); }
warn() { echo "  ⚠️  $1"; }
agent() { $COMPOSE exec -T agent sh -c "$1"; }
# redsocks-style request: CONNECT to the IP, SNI from the URL host. $1=sni-host, rest=curl args.
# URLPATH (default /) is the path asked for: the control plane's allowance is only for a box's own paths.
cbyip() { local h="$1"; shift; agent "curl -s --max-time 8 --proxy http://$PROXY_IP:8080 --connect-to $h:443:$ECHO_IP:443 $* https://$h${URLPATH:-/}"; }

cleanup() { $COMPOSE down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== prep: CA + echo cert (echo.test + cp.test) + config =="
( cd .. && FORCE=1 bash gen-ca.sh "$PWD/smoke/ca" >/dev/null )
chmod -R a+rX ca; chmod a+rw ca ca/mitmproxy-ca.pem
mkdir -p echo-certs logs config; chmod 777 logs
# The log dir is shared by every suite in here and nothing else clears it, so a previous
# run's records would be counted as this one's.
rm -f logs/*.jsonl logs/*.jsonl.1 logs/*.log
openssl req -x509 -newkey rsa:2048 -nodes -keyout echo-certs/echo-key.pem \
  -out echo-certs/echo-cert.pem -days 365 -subj "/CN=echo.test" \
  -addext "subjectAltName=DNS:echo.test,DNS:cp.test,DNS:tunnel.test" 2>/dev/null
chmod a+r echo-certs/*
# rules: a `tunnel` rule for tunnel.test (uninspected passthrough) + the default allow.
cat > config/rules.json <<'EOF'
[
  { "name": "uninspected", "match_domain": "tunnel.test", "effect": "tunnel", "priority": 5 },
  { "name": "default-allow", "match_domain": "*", "effect": "allow", "priority": 1000 }
]
EOF
cp ../config/credentials.example.json config/credentials.json

echo "== build + up =="
$COMPOSE up -d --build >/dev/null 2>&1 || { echo "compose up failed"; $COMPOSE logs; exit 1; }

echo "== wait for proxy + install CA into the agent =="
ok=0
for i in $(seq 1 30); do
  if agent "curl -s -o /dev/null --max-time 3 --proxy http://$PROXY_IP:8080 -k https://$ECHO_IP/" 2>/dev/null; then ok=1; break; fi
  sleep 1
done
[ "$ok" = 1 ] && pass "proxy reachable from agent" || { fail "proxy never came up"; $COMPOSE logs proxy; exit 1; }
agent "cp /ca/ca-cert.pem /usr/local/share/ca-certificates/cc.crt && update-ca-certificates >/dev/null 2>&1 && echo ok" | grep -q ok \
  && pass "mitm CA installed in agent trust store" || fail "CA install failed"

echo "== TT1: redsocks-style CONNECT-by-IP (SNI=echo.test) is INTERCEPTED + credential-swapped =="
# Interception + swap happen in the request hook, BEFORE the upstream connect — so we assert via the
# proxy's redacted log (robust against this harness's flaky upstream DNS; swap-reaches-upstream is
# already proven deterministically by run-smoke.sh A1 over the explicit path).
# Quoted as one word on purpose: `cbyip` re-splits its arguments inside the container, so an
# unquoted header becomes three curl arguments and the extra two are read as URLs.
cbyip echo.test "-H 'Authorization: Bearer $PLACEHOLDER'" >/dev/null 2>&1 || true
if $COMPOSE exec -T proxy sh -c "grep echo.test /logs/mitm.jsonl 2>/dev/null | grep -q '$PLACEHOLDER'"; then
  pass "TT1 CONNECT-by-IP intercepted + credential swapped (placeholder logged; no proxy env)"
else
  fail "TT1 transparent-style intercept/swap not observed in proxy log"
fi
if $COMPOSE exec -T proxy sh -c "grep -q '$SECRET' /logs/mitm.jsonl" 2>/dev/null; then
  fail "TT1 real secret leaked into the proxy log"
else
  pass "TT1 proxy log redacted (real secret never logged)"
fi

echo "== TT2: control-plane host (SNI=cp.test) is INSPECTED and allowed =="
# echo.test (no -k) succeeds → intercepted, leaf signed by our trusted CA.
if cbyip echo.test >/dev/null 2>&1; then pass "TT2a echo.test trusted (intercepted by our CA)"; else fail "TT2a echo.test should be trusted"; fi
# cp.test (no -k) succeeds too → intercepted by our CA, and answered by the real upstream.
if URLPATH=/api/vm-agent/config cbyip cp.test >/dev/null 2>&1; then
  pass "TT2b cp.test intercepted by our CA and answered upstream"
else
  fail "TT2b cp.test should be inspected (our CA) and reach its upstream"
fi
# And logged like any other request, as the built-in control-plane allowance.
if $COMPOSE exec -T proxy sh -c "grep '\"host\": *\"cp.test\"' /logs/mitm.jsonl | grep -q '\"rule\": *\"control_plane\"'" 2>/dev/null; then
  pass "TT2c cp.test logged as rule control_plane"
else
  fail "TT2c cp.test missing from the proxy request log"
fi

echo "== TT5: a `tunnel` RULE (not the control-plane host) passes a host through uninspected =="
# tunnel.test has effect=tunnel → SNI passthrough → real upstream self-signed cert (untrusted).
if cbyip tunnel.test >/dev/null 2>&1; then
  fail "TT5 tunnel.test was intercepted (tunnel rule passthrough broken)"
else
  pass "TT5 tunnel.test passed through to real upstream (rule-driven uninspected egress works)"
fi
if $COMPOSE exec -T proxy sh -c "grep -q '\"host\": *\"tunnel.test\"' /logs/mitm.jsonl" 2>/dev/null; then
  fail "TT5 tunnel.test appeared in the proxy intercepted-request log"
else
  pass "TT5 tunnel.test absent from the proxy request log (not inspected, no swap)"
fi

echo "== TT6: a forged SNI cannot pick where a passthrough or a swap goes (docs/ops/t-sni-passthrough.md) =="
# CONNECT echo.test (by name), SNI = the control plane: refused, not passed through to echo.test.
OUT=$(agent "curl -sk --max-time 8 --proxy http://$PROXY_IP:8080 --connect-to tunnel.test:443:echo.test:443 https://tunnel.test/" 2>/dev/null)
if [ -z "$OUT" ] && $COMPOSE exec -T proxy sh -c "grep -q '\"rule\": *\"destination_mismatch\"' /logs/mitm.jsonl" 2>/dev/null; then
  pass "TT6a SNI=tunnel.test (a tunnel rule) to another name refused + logged as destination_mismatch"
else
  fail "TT6a SNI=tunnel.test to another name was not refused (got: ${OUT:0:120})"
fi
# SNI attacker.test, Host: echo.test with the placeholder: refused before the swap.
OUT=$(cbyip attacker.test -k -H "'Host: echo.test'" -H "'Authorization: Bearer $PLACEHOLDER'")
if echo "$OUT" | grep -q destination_mismatch && ! echo "$OUT" | grep -q "$SECRET"; then
  pass "TT6b Host: echo.test over SNI attacker.test refused, nothing swapped"
else
  fail "TT6b Host/SNI mismatch was not refused (got: ${OUT:0:160})"
fi

echo "== TT7: another site by Host over the control plane's name (T-sni's Vercel probe) =="
OUT=$(cbyip cp.test -k -H "'Host: nextjs.org'" -o /dev/null -w '%{http_code}')
if [ "$OUT" = "421" ] && $COMPOSE exec -T proxy sh -c "grep '\"host\": *\"nextjs.org\"' /logs/mitm.jsonl | grep -q destination_mismatch" 2>/dev/null; then
  pass "TT7 Host: nextjs.org over SNI cp.test refused (421) and logged"
else
  fail "TT7 Host: nextjs.org over SNI cp.test was not refused (got: $OUT)"
fi

echo "== TT3 (best-effort): real redsocks + nftables REDIRECT, NO HTTP_PROXY env =="
# The actual transparent daemon path. Standard on Linux; flaky under Docker Desktop's netfilter,
# so this is informational and does NOT fail the suite — it's validated on real hardware.
agent "printf '$ECHO_IP echo.test cp.test\n' >> /etc/hosts
cat > /etc/redsocks.conf <<EOF
base { log_debug = off; log_info = off; daemon = off; redirector = iptables; }
redsocks { local_ip = 127.0.0.1; local_port = 12345; ip = $PROXY_IP; port = 8080; type = http-connect; }
EOF
(redsocks -c /etc/redsocks.conf >/tmp/rs.log 2>&1 &); sleep 1
nft add table ip ccr; nft 'add chain ip ccr output { type nat hook output priority -100 ; policy accept ; }'
nft add rule ip ccr output ip daddr $PROXY_IP return
nft add rule ip ccr output ip daddr 127.0.0.0/8 return
nft add rule ip ccr output tcp dport {80,443} redirect to :12345
ip route replace default via 10.77.0.1 2>/dev/null" >/dev/null 2>&1
TOUT=$(agent "curl -s --max-time 8 -H 'Authorization: Bearer $PLACEHOLDER' https://echo.test/ 2>/dev/null")
if echo "$TOUT" | grep -q "$SECRET"; then
  pass "TT3 real redsocks transparent path intercepted + swapped (no proxy env)"
else
  warn "TT3 redsocks daemon relay did not complete under Docker Desktop (expected; validated on hardware via mitm-e2e)"
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "🎉 TRANSPARENT SMOKE PASSED (TT1/TT2 deterministic; TT3 best-effort)"; else echo "💥 $FAILS assertion(s) failed"; fi
exit "$FAILS"
