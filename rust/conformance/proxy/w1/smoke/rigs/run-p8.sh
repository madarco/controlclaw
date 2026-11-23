#!/usr/bin/env bash
# Per-VM identity smoke (P8.1): two boxes (vmA=10.66.0.11, vmB=10.66.0.12) share one proxy. The
# proxy resolves source IP → vm_id and applies VM-scoped rules + VM-scoped credentials (org fallback).
set -uo pipefail
cd "$(dirname "$0")"

COMPOSE="docker compose -f docker-compose.p8.yml"
FAILS=0
pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; FAILS=$((FAILS+1)); }
vma() { $COMPOSE exec -T vma sh -c "$1"; }
vmb() { $COMPOSE exec -T vmb sh -c "$1"; }
cleanup() { $COMPOSE down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== prep: CA + echo cert + per-VM config =="
( cd .. && FORCE=1 bash gen-ca.sh "$PWD/smoke/ca" >/dev/null )
chmod -R a+rX ca; chmod a+rw ca ca/mitmproxy-ca.pem
mkdir -p echo-certs logs config; chmod 777 logs
# The log dir is shared by every suite in here and nothing else clears it, so a previous
# run's records would be counted as this one's.
rm -f logs/*.jsonl logs/*.jsonl.1 logs/*.log
openssl req -x509 -newkey rsa:2048 -nodes -keyout echo-certs/echo-key.pem \
  -out echo-certs/echo-cert.pem -days 365 -subj "/CN=echo.test" \
  -addext "subjectAltName=DNS:echo.test,DNS:other.test" 2>/dev/null
chmod a+r echo-certs/*
cat > config/identities.json <<'EOF'
[ { "private_ip": "10.66.0.11", "vm_id": "vm-aaa" },
  { "private_ip": "10.66.0.12", "vm_id": "vm-bbb" } ]
EOF
# vm-aaa is blocked from echo.test; everything else allowed.
cat > config/rules.json <<'EOF'
[ { "name": "block-echo-vma", "match_domain": "echo.test", "effect": "block", "vm_id": "vm-aaa", "priority": 5 },
  { "name": "allow", "match_domain": "*", "effect": "allow", "priority": 1000 } ]
EOF
# org-wide credential for other.test, plus a vm-bbb override with a different secret.
cat > config/credentials.json <<'EOF'
[ { "match_domain": "other.test", "placeholder": "__TOK", "secret": "ORG-SECRET-xyz" },
  { "match_domain": "other.test", "placeholder": "__TOK", "secret": "VMB-SECRET-xyz", "vm_id": "vm-bbb" } ]
EOF

echo "== build + up =="
$COMPOSE up -d --build >/dev/null 2>&1 || { echo "compose up failed"; $COMPOSE logs; exit 1; }

echo "== wait for proxy + install CA into both boxes =="
ok=0
for i in $(seq 1 30); do
  if vma "curl -s -o /dev/null --max-time 3 --proxy http://proxy:8080 -k https://other.test/" 2>/dev/null; then ok=1; break; fi
  sleep 1
done
[ "$ok" = 1 ] && pass "proxy reachable" || { fail "proxy never came up"; $COMPOSE logs proxy; exit 1; }
for b in vma vmb; do
  $COMPOSE exec -T $b sh -c "cp /ca/ca-cert.pem /usr/local/share/ca-certificates/cc.crt && update-ca-certificates >/dev/null 2>&1 && echo ok" | grep -q ok \
    && pass "CA installed in $b" || fail "CA install failed in $b"
done

echo "== P8-1: VM-scoped rule applies only to the matching VM =="
CA=$(vma "curl -s -o /dev/null -w '%{http_code}' --max-time 6 --proxy http://proxy:8080 https://echo.test/")
[ "$CA" = "403" ] && pass "vmA blocked from echo.test (vm-scoped rule)" || fail "vmA expected 403, got $CA"
CB=$(vmb "curl -s -o /dev/null -w '%{http_code}' --max-time 6 --proxy http://proxy:8080 https://echo.test/")
[ "$CB" = "200" ] && pass "vmB NOT blocked from echo.test (rule doesn't apply to it)" || fail "vmB expected 200, got $CB"

echo "== P8-2: VM-scoped credential with org fallback =="
OA=$(vma "curl -s --max-time 6 --proxy http://proxy:8080 -H 'Authorization: Bearer __TOK' https://other.test/")
echo "$OA" | grep -q "ORG-SECRET-xyz" && pass "vmA got the ORG credential (fallback)" || { fail "vmA org secret missing"; echo "    $OA"; }
echo "$OA" | grep -q "VMB-SECRET" && fail "vmA leaked vmB's scoped secret!" || pass "vmA did NOT get vmB's scoped secret"
OB=$(vmb "curl -s --max-time 6 --proxy http://proxy:8080 -H 'Authorization: Bearer __TOK' https://other.test/")
echo "$OB" | grep -q "VMB-SECRET-xyz" && pass "vmB got its VM-scoped credential (override)" || { fail "vmB scoped secret missing"; echo "    $OB"; }
echo "$OB" | grep -q "ORG-SECRET" && fail "vmB got the org secret instead of its override" || pass "vmB override replaced the org secret"

echo "== P8-3: logs attribute the right vm_id =="
$COMPOSE exec -T proxy sh -c "grep -q '\"vm_id\": *\"vm-aaa\"' /logs/mitm.jsonl" 2>/dev/null \
  && pass "log carries vm_id=vm-aaa" || fail "vm_id not attributed in logs"

echo
if [ "$FAILS" -eq 0 ]; then echo "🎉 P8 PER-VM IDENTITY SMOKE PASSED"; else echo "💥 $FAILS assertion(s) failed"; fi
exit "$FAILS"
