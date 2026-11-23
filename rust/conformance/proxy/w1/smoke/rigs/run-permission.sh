#!/usr/bin/env bash
# Permission-gating smoke (Part 7a): require_permission -> 451 -> scoped, expiring grant.
set -uo pipefail
cd "$(dirname "$0")"
COMPOSE="docker compose -f docker-compose.smoke.yml"
SECRET="REAL-SECRET-abc123"; PLACEHOLDER="__ECHO_TOKEN"
FAILS=0
pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; FAILS=$((FAILS+1)); }
agent() { $COMPOSE exec -T agent sh -c "$1"; }
cleanup() { $COMPOSE down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== prep CA + echo cert + config (echo.test=require_permission, other.test=require_permission) =="
( cd .. && FORCE=1 bash gen-ca.sh "$PWD/smoke/ca" >/dev/null )
chmod -R a+rX ca; chmod a+rw ca ca/mitmproxy-ca.pem
mkdir -p echo-certs logs config; chmod 777 logs config
openssl req -x509 -newkey rsa:2048 -nodes -keyout echo-certs/echo-key.pem \
  -out echo-certs/echo-cert.pem -days 365 -subj "/CN=echo.test" \
  -addext "subjectAltName=DNS:echo.test,DNS:other.test,DNS:blocked.test" 2>/dev/null
chmod a+r echo-certs/*
cat > config/rules.json <<'JSON'
[ { "name": "ask-echo",  "match_domain": "echo.test",  "effect": "require_permission", "priority": 10 },
  { "name": "ask-other", "match_domain": "other.test", "effect": "require_permission", "priority": 20 },
  { "name": "allow",     "match_domain": "*",           "effect": "allow",              "priority": 1000 } ]
JSON
cp ../config/credentials.example.json config/credentials.json
echo '{}' > config/grants.json
rm -f logs/pending.jsonl

$COMPOSE up -d --build >/dev/null 2>&1 || { echo "up failed"; $COMPOSE logs; exit 1; }
for i in $(seq 1 30); do agent "curl -s -o /dev/null --max-time 3 --proxy http://proxy:8080 -k https://echo.test/" 2>/dev/null && break; sleep 1; done
agent "cp /ca/ca-cert.pem /usr/local/share/ca-certificates/cc.crt && update-ca-certificates >/dev/null 2>&1" || true

echo "== A1: require_permission -> 451, no secret upstream =="
RESP=$(agent "curl -s -w '\n%{http_code}' --proxy http://proxy:8080 -H 'Authorization: Bearer $PLACEHOLDER' https://echo.test/")
CODE=$(echo "$RESP" | tail -1); BODY=$(echo "$RESP" | sed '$d')
[ "$CODE" = "451" ] && pass "A1 returned 451" || fail "A1 expected 451, got $CODE"
echo "$BODY" | grep -q '"permission_id"' && pass "A1 challenge has permission_id" || fail "A1 no permission_id"
echo "$BODY" | grep -q "$SECRET" && fail "A1 secret leaked in 451 body" || pass "A1 no secret in challenge"
PID=$(echo "$BODY" | sed -E 's/.*"permission_id": *"([^"]+)".*/\1/')
echo "  permission_id=$PID"

echo "== A2: approve grant -> retry swaps secret =="
FUTURE=$(($(date +%s) + 300))
echo "{\"$PID\": {\"expires_at\": $FUTURE, \"scope\": \"GET echo.test/\"}}" > config/grants.json
sleep 1
OUT=$(agent "curl -s --proxy http://proxy:8080 -H 'Authorization: Bearer $PLACEHOLDER' https://echo.test/")
echo "$OUT" | grep -q "Bearer $SECRET" && pass "A2 approved request swaps secret upstream" || { fail "A2 swap did not happen"; echo "  got: $OUT"; }

echo "== A3: expired grant -> 451 again =="
PAST=$(($(date +%s) - 10))
echo "{\"$PID\": {\"expires_at\": $PAST, \"scope\": \"GET echo.test/\"}}" > config/grants.json
sleep 1
CODE=$(agent "curl -s -o /dev/null -w '%{http_code}' --proxy http://proxy:8080 -H 'Authorization: Bearer $PLACEHOLDER' https://echo.test/")
[ "$CODE" = "451" ] && pass "A3 expired grant re-challenges (451)" || fail "A3 expected 451, got $CODE"

echo "== A4: grant for echo.test does NOT unblock other.test =="
echo "{\"$PID\": {\"expires_at\": $FUTURE, \"scope\": \"GET echo.test/\"}}" > config/grants.json
sleep 1
CODE=$(agent "curl -s -o /dev/null -w '%{http_code}' --proxy http://proxy:8080 https://other.test/")
[ "$CODE" = "451" ] && pass "A4 different host still gated (scope isolation)" || fail "A4 expected 451, got $CODE"

echo "== A5: pending recorded for the agent to pick up =="
$COMPOSE exec -T proxy sh -c "grep -q '$PID' /logs/pending.jsonl" 2>/dev/null \
  && pass "A5 pending entry written" || fail "A5 no pending entry"

echo
if [ "$FAILS" -eq 0 ]; then echo "🎉 PERMISSION SMOKE PASSED"; else echo "💥 $FAILS failed"; fi
exit "$FAILS"
