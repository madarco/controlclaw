#!/usr/bin/env bash
# Inline AI review smoke: an `allow` rule with `ai_review` asks the judge before the request
# leaves; block -> 403, ask -> 451 + pending, allow -> through with the secret swapped; a slow or
# broken judge never changes the rule's decision; rules without ai_review never call it.
set -uo pipefail
cd "$(dirname "$0")"
COMPOSE="docker compose -f docker-compose.smoke.yml -f docker-compose.ai.yml"
SECRET="REAL-SECRET-abc123"; PLACEHOLDER="__ECHO_TOKEN"
FAILS=0
pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; FAILS=$((FAILS+1)); }
agent() { $COMPOSE exec -T agent sh -c "$1"; }
curl_code() { agent "curl -s -o /dev/null -w '%{http_code}' --max-time 15 --proxy http://proxy:8080 $1"; }
cleanup() { $COMPOSE down -v >/dev/null 2>&1 || true; rm -f logs/judge.jsonl logs/mitm.jsonl logs/pending.jsonl; }
trap cleanup EXIT

echo "== prep: echo.test = allow + ai_review, other.test = allow, blocked.test = block + ai_review (ignored) =="
( cd .. && FORCE=1 bash gen-ca.sh "$PWD/smoke/ca" >/dev/null )
chmod -R a+rX ca; chmod a+rw ca ca/mitmproxy-ca.pem
mkdir -p echo-certs logs config; chmod 777 logs config
openssl req -x509 -newkey rsa:2048 -nodes -keyout echo-certs/echo-key.pem \
  -out echo-certs/echo-cert.pem -days 365 -subj "/CN=echo.test" \
  -addext "subjectAltName=DNS:echo.test,DNS:other.test,DNS:blocked.test" 2>/dev/null
chmod a+r echo-certs/*
cat > config/rules.json <<'JSON'
[ { "name": "no-blocked", "match_domain": "blocked.test", "effect": "block", "ai_review": true, "priority": 5 },
  { "name": "ask-policy", "match_domain": "echo.test", "match_path": "/policy", "effect": "require_permission", "ai_review": true,
    "ai_policy": "Approve posting notes. Never approve deletes.", "priority": 6 },
  { "name": "ask-plain",  "match_domain": "other.test", "match_path": "/ask-plain", "effect": "require_permission", "ai_review": true, "priority": 7 },
  { "name": "echo-ai",    "match_domain": "echo.test",    "effect": "allow", "ai_review": true, "priority": 10 },
  { "name": "other",      "match_domain": "other.test",   "effect": "allow",                    "priority": 20 } ]
JSON
cp ../config/credentials.example.json config/credentials.json
echo '{}' > config/grants.json
rm -f logs/pending.jsonl logs/judge.jsonl logs/mitm.jsonl

$COMPOSE up -d --build >/dev/null 2>&1 || { echo "up failed"; $COMPOSE logs; exit 1; }
for i in $(seq 1 30); do agent "curl -s -o /dev/null --max-time 3 --proxy http://proxy:8080 -k https://other.test/" 2>/dev/null && break; sleep 1; done
agent "cp /ca/ca-cert.pem /usr/local/share/ca-certificates/cc.crt && update-ca-certificates >/dev/null 2>&1" || true
rm -f logs/judge.jsonl

echo "== B1: judge allows -> 200, secret swapped after the review =="
OUT=$(agent "curl -s --max-time 15 --proxy http://proxy:8080 -H 'Authorization: Bearer $PLACEHOLDER' 'https://echo.test/ok?token=abc&page=2'")
echo "$OUT" | grep -q "Bearer $SECRET" && pass "B1 allowed and swapped" || { fail "B1 not swapped"; echo "  got: $OUT"; }

echo "== B2: judge blocks -> 403 from the proxy, upstream never reached =="
RESP=$(agent "curl -s -w '\n%{http_code}' --max-time 15 --proxy http://proxy:8080 -X POST -H 'Content-Type: text/plain' -H 'Authorization: Bearer $PLACEHOLDER' --data-binary @/etc/services https://echo.test/exfil")
CODE=$(echo "$RESP" | tail -1); BODY=$(echo "$RESP" | sed '$d')
[ "$CODE" = "403" ] && pass "B2 blocked (403)" || fail "B2 expected 403, got $CODE"
echo "$BODY" | grep -q '"blocked_by_ai_review"' && echo "$BODY" | grep -q '"data_exfiltration"' && pass "B2 body names the AI review and category" || fail "B2 body: $BODY"
echo "$BODY" | grep -q "$SECRET" && fail "B2 secret leaked" || pass "B2 no secret in the response"

echo "== B3: judge asks -> 451, pending carries the AI category =="
RESP=$(agent "curl -s -w '\n%{http_code}' --max-time 15 --proxy http://proxy:8080 -X DELETE https://echo.test/ask/repo")
CODE=$(echo "$RESP" | tail -1); BODY=$(echo "$RESP" | sed '$d')
[ "$CODE" = "451" ] && pass "B3 held for a person (451)" || fail "B3 expected 451, got $CODE"
echo "$BODY" | grep -q '"reason": "ai_review"' && pass "B3 reason is ai_review" || fail "B3 body: $BODY"
grep -q '"ai_category": "destructive_change"' logs/pending.jsonl && pass "B3 pending has ai_category" || fail "B3 pending: $(cat logs/pending.jsonl)"
PID=$(echo "$BODY" | sed -E 's/.*"permission_id": *"([^"]+)".*/\1/')

echo "== B4: a human grant lets the retry through without asking the judge again =="
N_BEFORE=$(wc -l < logs/judge.jsonl)
echo "{\"$PID\": {\"expires_at\": $(($(date +%s) + 300)), \"scope\": \"DELETE echo.test/ask/repo\"}}" > config/grants.json
sleep 1
CODE=$(curl_code "-X DELETE https://echo.test/ask/repo")
[ "$CODE" = "200" ] && pass "B4 granted request passes" || fail "B4 expected 200, got $CODE"
[ "$(wc -l < logs/judge.jsonl)" = "$N_BEFORE" ] && pass "B4 judge not asked again" || fail "B4 judge was asked again"

echo "== B5: slow judge (5s, timeout 2s) -> the rule's allow stands =="
START=$(date +%s)
CODE=$(curl_code "https://echo.test/slow")
ELAPSED=$(($(date +%s) - START))
[ "$CODE" = "200" ] && pass "B5 allowed after the timeout" || fail "B5 expected 200, got $CODE"
[ "$ELAPSED" -le 5 ] && pass "B5 waited ${ELAPSED}s, not the judge's 5s" || fail "B5 waited ${ELAPSED}s"

echo "== B6: broken judge (HTTP 500) -> the rule's allow stands =="
CODE=$(curl_code "https://echo.test/boom")
[ "$CODE" = "200" ] && pass "B6 allowed" || fail "B6 expected 200, got $CODE"

echo "== B7: rules without ai_review, and block rules, never call the judge =="
N_BEFORE=$(wc -l < logs/judge.jsonl)
C1=$(curl_code "https://other.test/exfil"); C2=$(curl_code "https://blocked.test/")
[ "$C1" = "200" ] && [ "$C2" = "403" ] && pass "B7 other.test 200, blocked.test 403" || fail "B7 got $C1 / $C2"
[ "$(wc -l < logs/judge.jsonl)" = "$N_BEFORE" ] && pass "B7 judge not called" || fail "B7 judge was called"

echo "== B8: what the judge saw =="
python3 - <<'PY' && pass "B8 payloads: query names only, body <= 300 chars, placeholder not secret, history present" || fail "B8 payload check"
import json
rows = [json.loads(l) for l in open("logs/judge.jsonl")]
ok = next(r for r in rows if r["path"] == "/ok")
assert ok["query_keys"] == ["page", "token"], ok
assert "abc" not in json.dumps(ok), "query values must not reach the judge"
ex = next(r for r in rows if r["path"] == "/exfil")
assert ex["body_start"] and len(ex["body_start"]) <= 300, len(ex["body_start"] or "")
assert ex["content_type"] == "text/plain"
assert "REAL-SECRET" not in json.dumps(rows), "the judge runs before the swap"
assert any(e["host"] == "echo.test" for e in ex["recent"]), ex["recent"]
PY

echo "== B9: traffic log records the AI verdict =="
grep '"path": "/exfil"' logs/mitm.jsonl | grep -q '"ai": {"verdict": "block", "category": "data_exfiltration"' && pass "B9 block record has ai" || fail "B9 record: $(grep exfil logs/mitm.jsonl)"

echo "== B10: Ask rule + policy, judge approves -> 200 with the secret swapped, logged as the AI's approval =="
OUT=$(agent "curl -s --max-time 15 --proxy http://proxy:8080 -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer $PLACEHOLDER' --data '{\"note\":\"hi\"}' https://echo.test/policy/approve")
echo "$OUT" | grep -q "Bearer $SECRET" && pass "B10 approved and swapped" || { fail "B10 not approved"; echo "  got: $OUT"; }
grep '"path": "/policy/approve"' logs/mitm.jsonl | grep -q '"by": "ai"' && pass "B10 record says the AI approved" || fail "B10 record: $(grep policy/approve logs/mitm.jsonl)"
python3 - <<'PY' && pass "B10 judge got approve mode, the policy and the permission id" || fail "B10 payload"
import json
r = next(json.loads(l) for l in open("logs/judge.jsonl") if '"/policy/approve"' in l)
assert r["mode"] == "approve" and r["policy"].startswith("Approve posting notes") and r["permission_id"].startswith("perm_"), r
assert r["scope"] == "POST echo.test/policy/approve", r["scope"]
PY

echo "== B11: judge says no -> the usual 451, with the reason for the person =="
CODE=$(curl_code "-X DELETE https://echo.test/policy/deny")
[ "$CODE" = "451" ] && pass "B11 held for a person (451)" || fail "B11 expected 451, got $CODE"
grep '/policy/deny' logs/pending.jsonl | grep -q '"ai_category": "policy_mismatch"' && pass "B11 pending has the reason" || fail "B11 pending: $(grep policy/deny logs/pending.jsonl)"

echo "== B12: Ask rule with AI review but no policy -> 451, judge not called =="
N_BEFORE=$(wc -l < logs/judge.jsonl)
CODE=$(curl_code "https://other.test/ask-plain")
[ "$CODE" = "451" ] && pass "B12 451" || fail "B12 expected 451, got $CODE"
[ "$(wc -l < logs/judge.jsonl)" = "$N_BEFORE" ] && pass "B12 judge not called" || fail "B12 judge was called"

echo
if [ "$FAILS" -eq 0 ]; then echo "🎉 AI REVIEW SMOKE PASSED"; else echo "💥 $FAILS failed"; fi
exit "$FAILS"
