#!/usr/bin/env bash
# Residential-exit smoke (docs/plans/residential-exit.md). Hermetic: the "provider" is
# upstream-proxy.py, so this needs no account and no money.
#
#   R1  a residential rule reaches a host the firewall has NO route to → it really went through
#       the upstream, and it was CONNECTed by NAME (the provider resolved it, not us)
#   R2  the site's OWN certificate reaches the client → the TLS was relayed, not re-originated
#   R3  the firewall never opens its own connection to the destination (the `lazy` assertion)
#   R4  sticky: two agent boxes present two different sessions, each stable
#   R5  the traffic record carries host, port and bytes — and no path
#   R6  SOCKS5 works the same way
#   R7  fail closed: upstream down, wrong credential, cap used up, exit removed
#   R8  a credential is never swapped into a residential flow
#   R9  with `lazy` on, ordinary inspected traffic and the control-plane passthrough still work
#   R10 `exit: residential` cannot turn a block rule into an allow
#   R11 plain HTTP picks the exit per REQUEST, not per client connection
#   R12 a broad residential rule never walks past a narrower block
set -uo pipefail
cd "$(dirname "$0")"

COMPOSE="docker compose -f docker-compose.residential.yml"
SECRET="REAL-SECRET-abc123"
PLACEHOLDER="__ECHO_TOKEN"
PROXY_IP="10.77.0.250"
PROXY_EXT_IP="10.88.0.250"
UPSTREAM_IP="10.88.0.20"
ECHO_IP="10.88.0.10"
SHOP_IP="10.99.0.10"
FAILS=0

pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; FAILS=$((FAILS+1)); }
agent() { $COMPOSE exec -T "${2:-vma}" sh -c "$1"; }
# redsocks-style: CONNECT to the IP, the name only in the SNI. $1=name $2=ip, rest=curl args.
# Those args are re-split by the shell inside the container, so anything with a space in it has to
# arrive already quoted (`"-H 'A: b'"`). Getting that wrong is quiet: curl reads the stray words as
# extra URLs and the request still "works", against the wrong host.
# URLPATH (default /) is the path asked for: the control plane's allowance is only for a box's own paths.
res() { local h="$1" ip="$2"; shift 2; agent "curl -s --max-time 15 --proxy http://$PROXY_IP:8080 --connect-to $h:443:$ip:443 $* https://$h${URLPATH:-/}" "${AGENT:-vma}"; }
upstream_log() { $COMPOSE exec -T proxy sh -c "cat /logs/upstream.jsonl 2>/dev/null"; }
mitm_log() { $COMPOSE exec -T proxy sh -c "cat /logs/mitm.jsonl 2>/dev/null"; }
reset_logs() { $COMPOSE exec -T proxy sh -c ": > /logs/upstream.jsonl; : > /logs/echo-peers.log; : > /logs/mitm.jsonl"; }

exit_json() {  # $1=scheme $2=host $3=port $4=password $5=sticky $6=used_bytes
  cat > config/exit.json <<EOF
{ "enabled": true,
  "upstream": { "scheme": "$1", "host": "$2", "port": $3,
                "username": "acme", "password": "$4",
                "username_template": "{username}[-sessid-{session}]",
                "password_template": "{password}" },
  "sticky": $5, "sticky_salt": "0123456789abcdef0123456789abcdef",
  "cap_bytes": 5368709120, "used_bytes": $6 }
EOF
  sleep 1.5  # the addon reloads on mtime; give it a beat
}

cleanup() { $COMPOSE down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== prep: CA + certs + config =="
( cd .. && FORCE=1 bash gen-ca.sh "$PWD/smoke/ca" >/dev/null )
chmod -R a+rX ca; chmod a+rw ca ca/mitmproxy-ca.pem
mkdir -p echo-certs logs config; chmod 777 logs
# The log dir is shared by every suite in here and nothing else clears it, so a previous
# run's records would be counted as this one's.
rm -f logs/*.jsonl logs/*.jsonl.1 logs/*.log
openssl req -x509 -newkey rsa:2048 -nodes -keyout echo-certs/echo-key.pem \
  -out echo-certs/echo-cert.pem -days 365 -subj "/CN=echo.test" \
  -addext "subjectAltName=DNS:echo.test,DNS:cp.test,DNS:res.test,DNS:shop.test" 2>/dev/null
chmod a+r echo-certs/*

cat > config/rules.json <<'EOF'
[
  { "name": "shop-residential", "match_domain": "shop.test", "effect": "allow", "exit": "residential", "priority": 10 },
  { "name": "res-residential",  "match_domain": "res.test",  "effect": "allow", "exit": "residential", "priority": 20 },
  { "name": "default-allow",    "match_domain": "*",         "effect": "allow", "priority": 1000 }
]
EOF
cat > config/identities.json <<EOF
[ { "private_ip": "10.77.0.11", "vm_id": "vm-a", "cp_inspect": true }, { "private_ip": "10.77.0.12", "vm_id": "vm-b", "cp_inspect": true } ]
EOF
# A credential for res.test: R8 proves it is NOT swapped into a residential flow.
cat > config/credentials.json <<EOF
[ { "placeholder": "$PLACEHOLDER", "match_domain": "*.test", "secret": "$SECRET",
    "locations": ["header:authorization"] } ]
EOF
echo '{}' > config/grants.json
exit_json http "$UPSTREAM_IP" 8000 pw true 0

echo "== build + up =="
$COMPOSE up -d --build >/dev/null 2>&1 || { echo "compose up failed"; $COMPOSE logs; exit 1; }

ok=0
for i in $(seq 1 30); do
  if agent "curl -s -o /dev/null --max-time 3 --proxy http://$PROXY_IP:8080 -k https://$ECHO_IP/" 2>/dev/null; then ok=1; break; fi
  sleep 1
done
[ "$ok" = 1 ] && pass "proxy reachable from the agent" || { fail "proxy never came up"; $COMPOSE logs proxy; exit 1; }
agent "cp /ca/ca-cert.pem /usr/local/share/ca-certificates/cc.crt && update-ca-certificates >/dev/null 2>&1 && echo ok" | grep -q ok || fail "CA install failed"
agent "cp /ca/ca-cert.pem /usr/local/share/ca-certificates/cc.crt && update-ca-certificates >/dev/null 2>&1 && echo ok" vmb | grep -q ok || fail "CA install failed on vmb"

echo "== R1: a residential rule reaches a host the firewall cannot route to =="
reset_logs
# Sanity: the firewall really has no route to shop.test's network.
if $COMPOSE exec -T proxy sh -c "timeout 4 python3 -c \"import socket;socket.create_connection(('$SHOP_IP',443),3)\"" >/dev/null 2>&1; then
  fail "R1 precondition: the firewall CAN reach $SHOP_IP directly (the test would prove nothing)"
else
  pass "R1 precondition: the firewall has no route to the residential-only network"
fi
OUT=$(res shop.test "$SHOP_IP" -k)
if echo "$OUT" | grep -q '"method": *"GET"'; then
  pass "R1 the request arrived, so it went through the upstream"
else
  fail "R1 residential request did not complete: $OUT"
fi
if upstream_log | grep -q '"target": *"shop.test:443"'; then
  pass "R1 the firewall CONNECTed by name (shop.test:443), not by the IP redsocks gave it"
else
  fail "R1 upstream did not record a CONNECT to shop.test:443: $(upstream_log)"
fi

echo "== R2: the site's own certificate reaches the client (relayed, not re-originated) =="
if res shop.test "$SHOP_IP" --cacert /certs/echo-cert.pem | grep -q '"method"'; then
  pass "R2 the client verified the SITE's certificate through the residential exit"
else
  fail "R2 the site's own certificate did not reach the client"
fi
if res shop.test "$SHOP_IP" >/dev/null 2>&1; then
  fail "R2 the firewall's CA was accepted — the flow was intercepted, not relayed"
else
  pass "R2 the firewall's CA does NOT sign this flow (no interception)"
fi

echo "== R3: the firewall never opens its own connection to the destination =="
reset_logs
res res.test "$ECHO_IP" -k >/dev/null 2>&1
PEERS=$($COMPOSE exec -T proxy sh -c "cat /logs/echo-peers.log 2>/dev/null" | awk '{print $2}' | sort -u | tr '\n' ' ')
if echo "$PEERS" | grep -q "$UPSTREAM_IP"; then
  pass "R3 the destination saw the upstream proxy connect ($UPSTREAM_IP)"
else
  fail "R3 the destination never saw the upstream connect (peers: $PEERS)"
fi
if echo "$PEERS" | grep -q "$PROXY_EXT_IP"; then
  fail "R3 the destination ALSO saw the firewall connect directly ($PROXY_EXT_IP) — connection_strategy leak"
else
  pass "R3 the destination never saw the firewall's own address"
fi

echo "== R4: sticky sessions are per agent and stable =="
reset_logs
res res.test "$ECHO_IP" -k >/dev/null 2>&1
res res.test "$ECHO_IP" -k >/dev/null 2>&1
AGENT=vmb res res.test "$ECHO_IP" -k >/dev/null 2>&1
USERS=$(upstream_log | sed -n 's/.*"user": *"\([^"]*\)".*/\1/p')
UNIQ=$(echo "$USERS" | sort -u | wc -l)
VMA=$(echo "$USERS" | head -2 | sort -u | wc -l)
if [ "$UNIQ" = 2 ] && [ "$VMA" = 1 ]; then
  pass "R4 one session per agent box, stable across requests ($(echo "$USERS" | sort -u | tr '\n' ' '))"
else
  fail "R4 sessions wrong (expected 2 distinct, vma stable): $(echo "$USERS" | tr '\n' ' ')"
fi
if echo "$USERS" | grep -q "^acme-sessid-"; then
  pass "R4 the session rides the provider's username template"
else
  fail "R4 username template not applied: $USERS"
fi
# Sticky off → the bare username, no session.
exit_json http "$UPSTREAM_IP" 8000 pw false 0
reset_logs
res res.test "$ECHO_IP" -k >/dev/null 2>&1
if [ "$(upstream_log | sed -n 's/.*"user": *"\([^"]*\)".*/\1/p' | sort -u)" = "acme" ]; then
  pass "R4 sticky off sends the bare username"
else
  fail "R4 sticky off still sent a session: $(upstream_log)"
fi
exit_json http "$UPSTREAM_IP" 8000 pw true 0

echo "== R5: the traffic record has host, port and bytes — and no path =="
reset_logs
res res.test "$ECHO_IP" "-k -d $(head -c 3000 /dev/zero | tr '\0' 'x')" >/dev/null 2>&1
sleep 1
REC=$(mitm_log | grep '"effect": "residential"' | tail -1)
if [ -n "$REC" ]; then
  pass "R5 a residential record was written"
  echo "$REC" | grep -q '"host": "res.test"' && pass "R5 it names the host" || fail "R5 no host: $REC"
  echo "$REC" | grep -q '"exit": "residential"' && pass "R5 it says where it left from" || fail "R5 no exit marker"
  IN=$(echo "$REC" | sed -n 's/.*"bytes_in": *\([0-9]*\).*/\1/p')
  OUT=$(echo "$REC" | sed -n 's/.*"bytes_out": *\([0-9]*\).*/\1/p')
  if [ "${OUT:-0}" -gt 3000 ] && [ "${IN:-0}" -gt 0 ]; then
    pass "R5 bytes counted in both directions (in=$IN out=$OUT)"
  else
    fail "R5 byte counts look wrong (in=${IN:-} out=${OUT:-}): $REC"
  fi
  echo "$REC" | grep -q '"path"' && fail "R5 a relayed flow logged a path" || pass "R5 no path (there is none to have)"
else
  fail "R5 no residential record: $(mitm_log | tail -3)"
fi

echo "== R6: SOCKS5 =="
exit_json socks5 "$UPSTREAM_IP" 1080 pw true 0
reset_logs
if res shop.test "$SHOP_IP" -k | grep -q '"method"'; then
  pass "R6 the same flow works over SOCKS5"
else
  fail "R6 SOCKS5 relay failed: $($COMPOSE logs --tail 20 proxy 2>&1 | tail -5)"
fi
if upstream_log | grep -q '"proto": *"socks5".*"target": *"shop.test:443"'; then
  pass "R6 SOCKS5 resolved the NAME at the exit (ATYP=domain)"
else
  fail "R6 SOCKS5 did not record a domain CONNECT: $(upstream_log)"
fi
exit_json http "$UPSTREAM_IP" 8000 pw true 0

echo "== R7: fail closed, four ways =="
closed() {  # $1=label
  reset_logs
  if res shop.test "$SHOP_IP" -k 2>/dev/null | grep -q '"method"'; then
    fail "R7 $1: the request SUCCEEDED — it must not have"
  else
    pass "R7 $1: the request failed"
  fi
  if mitm_log | grep -q 'residential exit'; then
    pass "R7 $1: one record says why"
  else
    fail "R7 $1: no record explaining the failure: $(mitm_log | tail -2)"
  fi
}
exit_json http 10.88.0.99 8000 pw true 0;       closed "upstream unreachable"
exit_json http "$UPSTREAM_IP" 8000 wrong true 0; closed "wrong credential"
exit_json http "$UPSTREAM_IP" 8000 pw true 5368709120; closed "monthly cap used up"
echo '{ "enabled": false }' > config/exit.json; sleep 1.5; closed "no exit configured"
# ...and in none of those did anything reach the destination from this box.
if $COMPOSE exec -T proxy sh -c "cat /logs/echo-peers.log 2>/dev/null" | grep -q "$PROXY_EXT_IP"; then
  fail "R7 the firewall connected to the destination itself while failing closed"
else
  pass "R7 nothing left this box's address while the exit was down"
fi
exit_json http "$UPSTREAM_IP" 8000 pw true 0

echo "== R8: a credential is never swapped into a residential flow =="
reset_logs
res res.test "$ECHO_IP" "-k -H 'Authorization: Bearer $PLACEHOLDER'" >/dev/null 2>&1
if $COMPOSE exec -T upstream sh -c "grep -q '$SECRET' /logs/upstream.jsonl" 2>/dev/null; then
  fail "R8 the real secret reached the upstream provider"
else
  pass "R8 the real secret never reached the provider"
fi
if mitm_log | grep '"effect": "residential"' | grep -q "swapped"; then
  fail "R8 a swap was recorded on a residential flow"
else
  pass "R8 no credential swap on a relayed flow"
fi

echo "== R10: a block rule is still a block, even if it says residential =="
cat > config/rules.json <<'EOF'
[
  { "name": "shop-blocked",    "match_domain": "shop.test", "effect": "block", "exit": "residential", "priority": 5 },
  { "name": "res-residential", "match_domain": "res.test",  "effect": "allow", "exit": "residential", "priority": 20 },
  { "name": "default-allow",   "match_domain": "*",         "effect": "allow", "priority": 1000 }
]
EOF
sleep 1.5
reset_logs
if res shop.test "$SHOP_IP" -k 2>/dev/null | grep -q '"method"'; then
  fail "R10 a block rule marked residential let the request out"
else
  pass "R10 a block rule marked residential still blocks"
fi
if upstream_log | grep -q "shop.test"; then
  fail "R10 the blocked request was relayed through the upstream"
else
  pass "R10 nothing was relayed for a blocked rule"
fi
cat > config/rules.json <<'EOF'
[
  { "name": "shop-residential", "match_domain": "shop.test", "effect": "allow", "exit": "residential", "priority": 10 },
  { "name": "res-residential",  "match_domain": "res.test",  "effect": "allow", "exit": "residential", "priority": 20 },
  { "name": "default-allow",    "match_domain": "*",         "effect": "allow", "priority": 1000 }
]
EOF
sleep 1.5

echo "== R12: a broad residential rule does not walk past a narrower block =="
cat > config/rules.json <<'EOF'
[
  { "name": "no-shop",      "match_domain": "shop.test", "effect": "block", "priority": 5 },
  { "name": "scrape-all",   "match_domain": "*",         "effect": "allow", "exit": "residential", "priority": 500 },
  { "name": "default-allow","match_domain": "*",         "effect": "allow", "priority": 1000 }
]
EOF
sleep 1.5
reset_logs
if res shop.test "$SHOP_IP" -k 2>/dev/null | grep -q '"method"'; then
  fail "R12 the broad residential rule walked past the block"
else
  pass "R12 the narrower block still wins"
fi
if upstream_log | grep -q "shop.test"; then
  fail "R12 the blocked host was relayed through the exit"
else
  pass "R12 nothing reached the exit for a blocked host"
fi
# ...and the same broad rule still relays a host nothing else claims.
reset_logs
res res.test "$ECHO_IP" -k >/dev/null 2>&1
if upstream_log | grep -q '"target": *"res.test:443"'; then
  pass "R12 the broad rule still relays what it should, by name"
else
  fail "R12 the broad rule stopped working: $(upstream_log)"
fi
cat > config/rules.json <<'EOF'
[
  { "name": "shop-residential", "match_domain": "shop.test", "effect": "allow", "exit": "residential", "priority": 10 },
  { "name": "res-residential",  "match_domain": "res.test",  "effect": "allow", "exit": "residential", "priority": 20 },
  { "name": "default-allow",    "match_domain": "*",         "effect": "allow", "priority": 1000 }
]
EOF
sleep 1.5

echo "== R11: plain HTTP — the upstream is per request, not per connection =="
# Two requests down ONE proxy connection: a residential host, then an ordinary one. mitmproxy
# shares one server-connection object across the streams of a client connection, so a `via` set on
# it would carry over and bill the second request to the customer's residential account.
reset_logs
# `--connect-to` reproduces redsocks: addressed to the IP, the name only in the Host header. Two
# URLs on one command line means curl reuses the single proxy connection, which is the shape that
# exposes an upstream shared between streams.
agent "curl -s --max-time 15 --proxy http://$PROXY_IP:8080   --connect-to res.test:80:$ECHO_IP:80 --connect-to echo.test:80:$ECHO_IP:80   http://res.test/ http://echo.test/" >/dev/null 2>&1
sleep 1
if upstream_log | grep -q '"target": *"res.test:80"'; then
  pass "R11 the plain-HTTP residential request went out by NAME through the upstream"
else
  fail "R11 plain HTTP did not use the exit, or sent the IP redsocks gave it: $(upstream_log)"
fi
# Counted, not grepped by name: behind redsocks both requests are addressed to the same IP, so a
# leak would be invisible to a name match.
N=$(upstream_log | grep -c '"target"')
if [ "$N" = 1 ]; then
  pass "R11 exactly one request on that connection used the exit"
else
  fail "R11 $N requests went through the upstream; the second inherited the first's: $(upstream_log)"
fi

echo "== R9: with connection_strategy=lazy, ordinary traffic is unchanged =="
reset_logs
if res echo.test "$ECHO_IP" "-H 'Authorization: Bearer $PLACEHOLDER'" | grep -q "$SECRET"; then
  pass "R9 an inspected flow is still intercepted and credential-swapped"
else
  fail "R9 the inspected+swap path broke under lazy"
fi
if mitm_log | grep -q "$SECRET"; then fail "R9 the real secret was logged"; else pass "R9 the log is still redacted"; fi
# The control plane is inspected since 2026-10-28 (it used to be passed through): trusted via our CA,
# answered upstream, and allowed whatever the organisation's rules say.
if URLPATH=/api/vm-agent/config res cp.test "$ECHO_IP" >/dev/null 2>&1; then
  pass "R9 the control-plane host is inspected (our CA) and still reaches its upstream"
else
  fail "R9 the control-plane host did not get through under lazy"
fi
if upstream_log | grep -qE '"target": *"(echo|cp)\.test'; then
  fail "R9 ordinary traffic went through the residential upstream"
else
  pass "R9 ordinary traffic still leaves from the firewall itself"
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "🎉 RESIDENTIAL SMOKE PASSED"; else echo "💥 $FAILS assertion(s) failed"; fi
exit "$FAILS"
