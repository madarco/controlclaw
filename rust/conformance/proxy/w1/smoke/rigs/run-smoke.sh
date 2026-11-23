#!/usr/bin/env bash
# Hermetic Docker smoke test for the egress proxy core (Part 1).
# Exits non-zero if any assertion fails.
set -uo pipefail
cd "$(dirname "$0")"

COMPOSE="docker compose -f docker-compose.smoke.yml"
SECRET="REAL-SECRET-abc123"
PLACEHOLDER="__ECHO_TOKEN"
FAILS=0

pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; FAILS=$((FAILS+1)); }
agent() { $COMPOSE exec -T agent sh -c "$1"; }

cleanup() { $COMPOSE down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== prep: CA + echo cert + config =="
( cd .. && FORCE=1 bash gen-ca.sh "$PWD/smoke/ca" >/dev/null )
chmod -R a+rX ca; chmod a+rw ca ca/mitmproxy-ca.pem
mkdir -p echo-certs logs config; chmod 777 logs
# The log dir is shared by every suite in here and nothing else clears it, so a previous
# run's records would be counted as this one's.
rm -f logs/*.jsonl logs/*.jsonl.1 logs/*.log
openssl req -x509 -newkey rsa:2048 -nodes -keyout echo-certs/echo-key.pem \
  -out echo-certs/echo-cert.pem -days 365 -subj "/CN=echo.test" \
  -addext "subjectAltName=DNS:echo.test,DNS:other.test,DNS:blocked.test" 2>/dev/null
chmod a+r echo-certs/*
cp ../config/rules.example.json config/rules.json
cp ../config/credentials.example.json config/credentials.json

echo "== build + up =="
$COMPOSE up -d --build >/dev/null 2>&1 || { echo "compose up failed"; $COMPOSE logs; exit 1; }

echo "== wait for proxy =="
ok=0
for i in $(seq 1 30); do
  if agent "curl -s -o /dev/null --max-time 3 --proxy http://proxy:8080 -k https://echo.test/" 2>/dev/null; then ok=1; break; fi
  sleep 1
done
[ "$ok" = 1 ] && pass "proxy reachable from agent" || { fail "proxy never came up"; $COMPOSE logs proxy; exit 1; }

echo "== A4 (neg): HTTPS fails BEFORE installing our CA =="
if agent "curl -s -o /dev/null --max-time 5 --proxy http://proxy:8080 https://echo.test/" 2>/dev/null; then
  fail "A4 expected cert failure before CA install, but curl succeeded"
else
  pass "A4 HTTPS rejected without our CA (cert not yet trusted)"
fi

echo "== install our CA into agent trust store =="
agent "cp /ca/ca-cert.pem /usr/local/share/ca-certificates/cc.crt && update-ca-certificates >/dev/null 2>&1 && echo ok" | grep -q ok \
  && pass "CA installed in agent" || fail "CA install failed"

echo "== A1: credential swap reaches upstream =="
OUT=$(agent "curl -s --proxy http://proxy:8080 -H 'Authorization: Bearer $PLACEHOLDER' https://echo.test/")
echo "$OUT" | grep -q "$SECRET" && pass "A1 upstream received REAL secret (swap worked)" \
  || { fail "A1 secret not found upstream"; echo "    got: $OUT"; }
echo "$OUT" | grep -q "Bearer $SECRET" && pass "A1 swapped in Authorization header" || fail "A1 header not swapped"

echo "== A4 (pos): HTTPS now succeeds via our CA (no -k) =="
echo "$OUT" | grep -q '"method"' && pass "A4 HTTPS validated against our custom CA" || fail "A4 validated HTTPS failed"

echo "== A2: agent never held the real secret =="
if agent "env | grep -q '$SECRET'"; then fail "A2 secret leaked into agent env"; else pass "A2 secret absent from agent env"; fi

echo "== A3: domain scope — placeholder NOT swapped off-domain =="
OUT2=$(agent "curl -s --proxy http://proxy:8080 -H 'Authorization: Bearer $PLACEHOLDER' https://other.test/")
if echo "$OUT2" | grep -q "$SECRET"; then fail "A3 secret leaked to off-domain host!"; else pass "A3 no secret on off-domain host"; fi
echo "$OUT2" | grep -q "$PLACEHOLDER" && pass "A3 off-domain host saw bare placeholder" || fail "A3 placeholder missing off-domain"

echo "== A5: forced egress — no internet without the proxy =="
if agent "curl -s -o /dev/null --max-time 5 https://echo.test/" 2>/dev/null; then
  fail "A5 agent reached internet WITHOUT proxy (egress not forced)"
else
  pass "A5 agent has no egress except via the proxy"
fi

echo "== A6: block rule =="
CODE=$(agent "curl -s -o /dev/null -w '%{http_code}' --proxy http://proxy:8080 https://blocked.test/")
[ "$CODE" = "403" ] && pass "A6 blocked host returns 403" || fail "A6 expected 403, got $CODE"

echo "== A7: logs are redacted =="
if $COMPOSE exec -T proxy sh -c "grep -q '$SECRET' /logs/mitm.jsonl" 2>/dev/null; then
  fail "A7 real secret found in proxy log"
else
  pass "A7 proxy log redacted (placeholder only)"
fi
$COMPOSE exec -T proxy sh -c "grep -q '$PLACEHOLDER' /logs/mitm.jsonl" 2>/dev/null \
  && pass "A7 log shows placeholder" || fail "A7 placeholder missing from log"

echo "== A8: traffic record shape (one line per request, metadata only) =="
LOG=$($COMPOSE exec -T proxy sh -c "cat /logs/mitm.jsonl" 2>/dev/null)
ALLOW_LINE=$(echo "$LOG" | grep '"host": "echo.test"' | grep '"effect": "allow"' | head -1)
if echo "$ALLOW_LINE" | grep -q '"flow_id": "' && echo "$ALLOW_LINE" | grep -q '"status": 200' \
   && echo "$ALLOW_LINE" | grep -q '"rule": ' && echo "$ALLOW_LINE" | grep -q '"duration_ms": ' \
   && echo "$ALLOW_LINE" | grep -q '"bytes_in": '; then
  pass "A8 allow record carries flow_id, status, rule, duration_ms, bytes_in"
else
  fail "A8 allow record incomplete: $ALLOW_LINE"
fi
echo "$LOG" | grep -q '"authorization"' && fail "A8 authorization value present in log" || pass "A8 no header values in log"
N_ECHO=$(echo "$LOG" | grep -c '"host": "echo.test"')
# A4-pos and A1 each made one echo.test request: two records, not four (no request-time duplicates).
[ "$N_ECHO" = "2" ] && pass "A8 exactly one record per echo.test request" || fail "A8 expected 2 echo.test records, got $N_ECHO"
echo "$LOG" | grep '"host": "blocked.test"' | grep -q '"effect": "block"' && pass "A8 block record present" || fail "A8 block record missing"
echo "$LOG" | grep -q '?' && fail "A8 query string present in a logged path" || pass "A8 paths are query-stripped"

echo "== A9: size-based rotation (proxy-owned) =="
$COMPOSE exec -T proxy sh -c "rm -f /logs/rot.jsonl /logs/rot.jsonl.1" >/dev/null 2>&1
# Restart the proxy with a small cap (~20 records of ~290 bytes) on a fresh file, fire 30 requests:
# exactly one rotation, so live + .1 must hold all 30 with no torn lines.
MITM_LOG_FILE=/logs/rot.jsonl MITM_LOG_MAX_BYTES=6000 $COMPOSE up -d --force-recreate proxy >/dev/null 2>&1
for i in $(seq 1 30); do agent "curl -s -o /dev/null --max-time 3 --proxy http://proxy:8080 https://echo.test/" >/dev/null 2>&1 && break; sleep 1; done
$COMPOSE exec -T proxy sh -c "rm -f /logs/rot.jsonl /logs/rot.jsonl.1" >/dev/null 2>&1
for i in $(seq 1 30); do agent "curl -s -o /dev/null --max-time 5 --proxy http://proxy:8080 https://echo.test/?n=$i" >/dev/null 2>&1; done
sleep 1
ROT=$($COMPOSE exec -T proxy sh -c "cat /logs/rot.jsonl /logs/rot.jsonl.1 2>/dev/null | wc -l" | tr -d ' ')
$COMPOSE exec -T proxy sh -c "test -f /logs/rot.jsonl.1" 2>/dev/null && pass "A9 rotated file exists" || fail "A9 no rotated file"
[ "$ROT" = "30" ] && pass "A9 no records lost across rotation (30/30)" || fail "A9 expected 30 records across files, got $ROT"
if $COMPOSE exec -T proxy sh -c "cat /logs/rot.jsonl /logs/rot.jsonl.1" 2>/dev/null | python3 -c "import sys,json; [json.loads(l) for l in sys.stdin if l.strip()]" 2>/dev/null; then
  pass "A9 every line is complete JSON"
else
  fail "A9 torn line in rotated logs"
fi

echo "== A10: dev flags refused outside smoke =="
$COMPOSE down >/dev/null 2>&1
MITM_DEV_LOG_SECRETS=1 $COMPOSE up -d proxy >/dev/null 2>&1; sleep 3
if $COMPOSE logs proxy 2>/dev/null | grep -q "refusing to start with dev flags"; then
  pass "A10 proxy refuses MITM_DEV_LOG_SECRETS=1 without MITM_ALLOW_DEV_FLAGS"
else
  fail "A10 proxy started with a dev flag set"
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "🎉 ALL SMOKE ASSERTIONS PASSED"; else echo "💥 $FAILS assertion(s) failed"; fi
exit "$FAILS"
