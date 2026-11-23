import { createHash } from "node:crypto";
import { GATE_IMAGE } from "./capture/docker.js";

/**
 * The brain's machine on a standalone firewall (docs/standalone/brain.md): what `controlclaw brain
 * install` runs in Docker, and the root helpers `brain install` and `brain connect` give the
 * vm-agent's brain mode (rust/bins/vm-agent/src/gbrain/standalone.rs).
 *
 * GBrain is pinned by version and sha256, the twin of `gbrain_version` and `gbrain_sha256` in the
 * Ansible role (`roles/controlclaw/defaults/main.yml`): move them together. The helpers are the
 * role's own (`gbrain.yml`, `gbrain-pages.yml`, `gbrain-packages.yml`, at controlclaw-ansible
 * 35dfc74), with its paths as parameters, except `cc-gbrain-key`, which also takes the user's own
 * key's placeholder (a standalone brain has no included AI), and `cc-gbrain-svc`, the container's
 * stand-in for `systemctl try-restart gbrain`.
 */
export const GBRAIN_VERSION = "0.60.723.0";
export const GBRAIN_SHA256 = "283e1230d538f6faa3f2a5c3e03a1c9fab3bdc695f553f5a1bb7ae82713c9c9f";
export const GBRAIN_URL = `https://github.com/garrytan/gbrain/releases/download/v${GBRAIN_VERSION}/gbrain-linux-x64`;
/** Postgres 16 with pgvector, as the role's `postgresql-16-pgvector`. */
export const POSTGRES_IMAGE = "pgvector/pgvector:0.8.0-pg16";
export const BRAIN_MODELS = ["gpt-5.6-luna", "gpt-5.6-terra"] as const;

/** Where the helpers put things, and how they restart GBrain. */
export interface HelperOpts {
  /** GBrain's account. */
  user: string;
  /** Its home: `.gbrain/` (config, env), `content/`. */
  home: string;
  /** The file the helpers source before running GBrain's CLI (skipped when it is not there). */
  env: string;
  /**
   * Where `cc-gbrain-key` writes `OPENAI_API_KEY` and `OPENAI_BASE_URL`, its owner and mode. The
   * helpers source it after `env`, so what they run of GBrain has the brain's key (and, for a
   * connected GBrain, the firewall's proxy and CA, which `connect` writes there too).
   */
  keyFile: string;
  keyOwner: string;
  keyMode: string;
  /** The `gbrain` program. */
  gbrain: string;
  /** Where GBrain serves HTTP, as the helpers reach it: loopback, or its address in its container. */
  host: string;
  port: number;
  /** The vm-agent's hand-over folder for Export and Import, and who owns what lands there. */
  out: string;
  owner: string;
  /** A shell command that restarts GBrain so it reads its env and config again. */
  restart: string;
}

/** The helpers, by name under `/usr/local/bin` (`cc-gbrain-unzip.py` under `/usr/local/lib`). */
export function helpers(o: HelperOpts): Record<string, string> {
  const fill = (s: string) =>
    s
      .replaceAll("@ENV@", o.env)
      .replaceAll("@HOME@", o.home)
      .replaceAll("@USER@", o.user)
      .replaceAll("@OWNER@", o.owner)
      .replaceAll("@HOST@", o.host)
      .replaceAll("@PORT@", String(o.port))
      .replaceAll("@RESTART@", o.restart)
      .replaceAll("@OUT@", o.out)
      .replaceAll("@GBRAIN@", o.gbrain)
      .replaceAll("@KEYFILE@", o.keyFile)
      .replaceAll("@KEYOWNER@", o.keyOwner)
      .replaceAll("@KEYMODE@", o.keyMode);
  return {
    "cc-gbrain-key": fill(KEY),
    "cc-gbrain-token": fill(ROLE.token),
    "cc-gbrain-model": fill(ROLE.model),
    "cc-gbrain-login-link": fill(ROLE.loginLink),
    "cc-gbrain-pages": fill(ROLE.pages),
    "cc-gbrain-dream": fill(ROLE.dream),
    "cc-gbrain-unzip.py": fill(ROLE.unzip),
  };
}

/**
 * The brain's model key, as the firewall hands it to the vm-agent: `<placeholder> <base url>` on
 * stdin (or `-` to take it away). Only a placeholder, with its provider's own base URL: what lands in
 * GBrain's env is something the firewall swaps on that host and nowhere else, never a real key.
 */
const KEY = `#!/bin/bash
# Written by controlclaw brain. Usage: printf '%s\\n' '<placeholder> <base url>' | cc-gbrain-key   (or '-')
set -euo pipefail
KEY_FILE="@KEYFILE@"
NONE="vck-cc-included-none"
read -r value base || true
bad() { echo "cc-gbrain-key: not a placeholder with its provider's base URL" >&2; exit 2; }
case "$value" in
  -) value="$NONE"; base="https://ai-gateway.vercel.sh/v1" ;;
  sk-cc-openai-*) [[ "$value" =~ ^sk-cc-openai-[0-9a-f]{24}$ && "$\{base:-}" == "https://api.openai.com/v1" ]] || bad ;;
  vck-cc-included-*) bad ;;
  vck-cc-*) [[ "$value" =~ ^vck-cc-[0-9a-f]{24}$ && "$\{base:-}" == "https://ai-gateway.vercel.sh/v1" ]] || bad ;;
  *) bad ;;
esac
# The file's folder is made only when missing, never chmodded: it is also where other files live.
[ -d "$(dirname "$KEY_FILE")" ] || install -d -m 0700 "$(dirname "$KEY_FILE")"
touch "$KEY_FILE"
current="$(sed -n 's/^OPENAI_API_KEY=//p' "$KEY_FILE" | head -1) $(sed -n 's/^OPENAI_BASE_URL=//p' "$KEY_FILE" | head -1)"
if [ "$current" = "$value $base" ]; then
  echo unchanged
  exit 0
fi
tmp="$(mktemp "$KEY_FILE.XXXXXX")"
grep -v -e '^OPENAI_API_KEY=' -e '^OPENAI_BASE_URL=' "$KEY_FILE" > "$tmp" || true
printf 'OPENAI_BASE_URL=%s\\nOPENAI_API_KEY=%s\\n' "$base" "$value" >> "$tmp"
chown @KEYOWNER@ "$tmp"
chmod @KEYMODE@ "$tmp"
mv "$tmp" "$KEY_FILE"
@RESTART@
echo changed
`;

/** The role's helpers, its Jinja values as @NAME@ placeholders (`helpers` fills them). */
const ROLE = {
  model: `#!/bin/bash
# Written by controlclaw brain, from the Ansible role's (gbrain.yml). Usage: cc-gbrain-model gpt-5.6-luna|gpt-5.6-terra
set -euo pipefail
model="$\{1:-}"
case "$model" in gpt-5.6-luna|gpt-5.6-terra) ;; *) echo "cc-gbrain-model: not a brain model" >&2; exit 2 ;; esac
f=@HOME@/.gbrain/cc-model
[ -d @HOME@/.gbrain ] || { echo "cc-gbrain-model: no brain here yet" >&2; exit 3; }
if [ "$(cat "$f" 2>/dev/null || true)" = "$model" ]; then
  echo unchanged
  exit 0
fi
cd @HOME@
runuser -u @USER@ -- env HOME=@HOME@ M="$model" bash -c '
  set -eu; set -a; [ ! -f @ENV@ ] || . @ENV@; [ ! -r @KEYFILE@ ] || . @KEYFILE@; set +a
  for k in models.tier.utility models.tier.reasoning models.tier.subagent models.fence_repair models.content_repair; do
    @GBRAIN@ config set "$k" "openai:$M" >/dev/null
  done
  umask 077; printf "%s\\n" "$M" > @HOME@/.gbrain/cc-model'
@RESTART@
echo changed
`,
  token: `#!/bin/bash
# Written by controlclaw brain, from the Ansible role's (gbrain.yml).
# Usage: cc-gbrain-token create <vmId> <read|read_write>   prints the new token
#        cc-gbrain-token revoke <vmId>
set -euo pipefail
op="$\{1:-}"; vm="$\{2:-}"
[[ "$vm" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || { echo "cc-gbrain-token: bad vm id" >&2; exit 2; }
name="cc-$vm"
g() {
  cd @HOME@
  runuser -u @USER@ -- env HOME=@HOME@ bash -c \\
    'set -a; [ ! -f @ENV@ ] || . @ENV@; [ ! -r @KEYFILE@ ] || . @KEYFILE@; set +a; exec @GBRAIN@ "$@"' _ "$@"
}
# Every active token of that name. GBrain exits non-zero when there is none, which is fine:
# the gate has already dropped the agent, so a token it no longer holds reaches nothing.
revoke() {
  g auth revoke "$name" >/dev/null 2>&1 || true
}
case "$op" in
  create)
    case "$\{3:-}" in
      read) scopes=read ;;
      read_write) scopes=read,write ;;
      *) echo "cc-gbrain-token: scope must be read or read_write" >&2; exit 2 ;;
    esac
    revoke
    # Every connected agent reads the whole brain: that is what the brain is for
    # (apps/saas/docs/features/brain.md). GBrain 0.60.708 refuses a token bound to no member
    # on a brain with two or more members unless it says so (--reads-unscoped).
    out="$(g auth create "$name" --scopes "$scopes" --reads-unscoped --yes)"
    token="$(printf '%s\\n' "$out" | sed -nE 's/^[[:space:]]+([A-Za-z0-9_]{32,})[[:space:]]*$/\\1/p' | head -1)"
    [ -n "$token" ] || { echo "cc-gbrain-token: GBrain printed no token" >&2; exit 3; }
    printf '%s\\n' "$token"
    ;;
  revoke) revoke; echo revoked ;;
  *) echo "cc-gbrain-token: create or revoke" >&2; exit 2 ;;
esac
`,
  loginLink: `#!/bin/bash
# Written by controlclaw brain, from the Ansible role's (gbrain.yml). Usage: cc-gbrain-login-link   prints a single-use link
set -euo pipefail
cd @HOME@
out="$(runuser -u @USER@ -- env HOME=@HOME@ bash -c \\
  'set -a; [ ! -f @ENV@ ] || . @ENV@; [ ! -r @KEYFILE@ ] || . @KEYFILE@; set +a; exec @GBRAIN@ mcp admin login-link --url http://@HOST@:@PORT@/mcp --json' 2>/dev/null)"
url="$(printf '%s\\n' "$out" | tail -1 | python3 -I -c 'import sys,json; print(json.load(sys.stdin).get("url",""))' 2>/dev/null || true)"
[[ "$url" =~ ^https://[^/]+/admin/auth/[A-Za-z0-9_.~-]+$ ]] || { echo "cc-gbrain-login-link: GBrain gave no login link" >&2; exit 3; }
printf '%s\\n' "$url"
`,
  dream: `#!/bin/bash
# Written by controlclaw brain, from the Ansible role's (gbrain-packages.yml). Runs as gbrain with GBrain's env file.
#
# The night, in four steps inside one cost window (controlclaw apps/saas/docs/features/brain.md):
#   1. facts: GBrain queues one \`facts-absorb\` job per page an agent saves, and a Postgres brain runs
#      them only on its job worker. The worker runs here until the queue is empty, at most 30 minutes.
#   2. links: the typed links of pages agents saved (no model).
#   3. \`gbrain dream\`: GBrain's maintenance cycle, as configured by gbrain.yml.
#   4. long pages: \`extract_atoms\`, which cuts long pages into short ones, for at most 10 minutes.
# The summary for Activity is counts and a cost, nothing from any page.
set -uo pipefail
REPORT_DIR="$\{CC_GBRAIN_REPORT_DIR:-/var/lib/gbrain-report}"
G="$\{CC_GBRAIN_BIN:-@GBRAIN@}"
WORKER_SECONDS="$\{CC_GBRAIN_WORKER_SECONDS:-1800}"
ATOMS_SECONDS="$\{CC_GBRAIN_ATOMS_SECONDS:-600}"
sql() { psql "$GBRAIN_DATABASE_URL" -Atc "$1" 2>/dev/null; }
num() { case "$1" in ''|*[!0-9]*) echo 0 ;; *) echo "$1" ;; esac; }
started="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"

# 1. Facts. Jobs waiting, running, or due within two minutes (GBrain defers the whole queue for a
#    short while after a provider error); one deferred for longer is the next night's.
queued() { num "$(sql "select count(*) from minion_jobs where queue = 'default' and (status in ('waiting', 'active') or (status = 'delayed' and delay_until <= now() + interval '2 minutes'))")"; }
if [ "$(queued)" -gt 0 ]; then
  "$G" jobs work --concurrency 2 --nice 10 >/dev/null 2>&1 &
  worker=$!
  deadline=$((SECONDS + WORKER_SECONDS))
  while [ "$SECONDS" -lt "$deadline" ] && kill -0 "$worker" 2>/dev/null; do
    sleep 10
    [ "$(queued)" -eq 0 ] && break
  done
  # SIGTERM lets the job in flight finish (GBrain gives it 35 s) and puts nothing back half-done.
  kill -TERM "$worker" 2>/dev/null
  wait "$worker" 2>/dev/null
fi
pages_fact_checked="$(num "$(sql "select count(*) from minion_jobs where name = 'facts-absorb' and status = 'completed' and finished_at >= '$started'::timestamptz")")"
facts_waiting="$(queued)"

# 2. Links: an agent's page saved over MCP keeps its [[links]] as plain mentions; the typed ones
#    ("works at", "joined") are read here, with no model, so the cycle can judge them.
"$G" extract all --source db --json >/dev/null 2>&1

# 3. The maintenance cycle.
out="$("$G" dream --json)"
rc=$?

# 4. Long pages. Exit 11 means "more to do": the next night goes on.
atoms_out="$("$G" dream --phase extract_atoms --drain --window "$ATOMS_SECONDS" --json 2>/dev/null)"
atoms_rc=$?

finished="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
# What the night added and retired, by the rows' own times: not a difference of totals, which the
# cycle's own merging would eat into.
facts_new="$(num "$(sql "select count(*) from facts where created_at >= '$started'::timestamptz")")"
facts_retired="$(num "$(sql "select count(*) from facts where expired_at >= '$started'::timestamptz")")"
atoms_new="$(num "$(sql "select count(*) from pages where type = 'atom' and deleted_at is null and created_at >= '$started'::timestamptz")")"
usage="$(sql "select coalesce(sum(cost_usd),0)||' '||count(*) from chat_usage_log where created_at >= '$started'::timestamptz" || echo "")"
if [ -d "$REPORT_DIR" ]; then
  tmp="$(mktemp "$REPORT_DIR/.last-cycle.XXXXXX")"
  OUT="$out" RC="$rc" STARTED="$started" FINISHED="$finished" USAGE="$usage" ATOMS="$atoms_out" ATOMS_RC="$atoms_rc" \\
    FACTS_NEW="$facts_new" FACTS_RETIRED="$facts_retired" ATOMS_NEW="$atoms_new" CHECKED="$pages_fact_checked" WAITING="$facts_waiting" \\
    python3 - > "$tmp" <<'PY'
import json, os
def load(name):
    try:
        d = json.loads(os.environ.get(name, ""))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}
def n(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else 0
d = load("OUT")
usage = os.environ.get("USAGE", "").split()
totals = d.get("totals") if isinstance(d.get("totals"), dict) else {}
totals = {k: v for k, v in totals.items() if isinstance(v, (int, float)) and not isinstance(v, bool)}
phases = [p for p in d.get("phases", []) if isinstance(p, dict)]
def details(name):
    for p in phases:
        if p.get("phase") == name and isinstance(p.get("details"), dict):
            return p["details"]
    return {}
# What this run added to GBrain's own totals (counts only).
totals["facts_extracted"] = int(os.environ["FACTS_NEW"])
totals["pages_fact_checked"] = int(os.environ["CHECKED"])
totals["facts_waiting"] = int(os.environ["WAITING"])
edges = details("edge_contradictions")
totals["relationships_ended"] = n(edges.get("applied")) + n(edges.get("declared_applied"))
# Facts a newer one replaced, and relationships that ended: what the night retired.
totals["facts_retired"] = int(os.environ["FACTS_RETIRED"]) + totals["relationships_ended"]
atoms = load("ATOMS")
# Short pages cut from long ones, and the long pages still waiting for it.
totals["atoms_written"] = int(os.environ["ATOMS_NEW"])
totals["pages_to_split"] = n(atoms.get("remaining"))
print(json.dumps({
    "started_at": os.environ["STARTED"],
    "finished_at": os.environ["FINISHED"],
    "exit_code": int(os.environ["RC"]),
    "status": d.get("status") if isinstance(d.get("status"), str) else ("failed" if os.environ["RC"] != "0" else "unknown"),
    "duration_ms": d.get("duration_ms") if isinstance(d.get("duration_ms"), (int, float)) else None,
    "phases": [{"phase": p.get("phase"), "status": p.get("status")} for p in phases][:40],
    "totals": totals,
    "cost_usd": float(usage[0]) if len(usage) == 2 else None,
    "model_calls": int(usage[1]) if len(usage) == 2 else None,
}))
PY
  chmod 0640 "$tmp"
  mv "$tmp" "$REPORT_DIR/last-cycle.json"
fi
printf '%s\\n' "$out"
exit "$rc"
`,
  unzip: `# Written by controlclaw brain, from the Ansible role's (gbrain-pages.yml). Usage: python3 -I cc-gbrain-unzip.py <zip> <dir>
import json, os, posixpath, sys, zipfile

MAX_FILES = 20000
MAX_FILE = 20 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MARKDOWN = (".md", ".markdown")

def fail(code, message):
    print(json.dumps({"error": code, "message": message}))
    sys.exit(3)

src, dest = sys.argv[1], sys.argv[2]
try:
    z = zipfile.ZipFile(src)
except Exception:
    fail("not_zip", "The file is not a zip archive.")
names = []
skipped = 0
for info in z.infolist():
    if info.is_dir():
        continue
    name = info.filename.replace("\\\\", "/")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or name.startswith("/") or ".." in parts:
        fail("bad_path", "The archive has a file outside its own folder.")
    hidden = any(p.startswith(".") or p == "__MACOSX" for p in parts)
    if hidden or not parts[-1].lower().endswith(MARKDOWN):
        skipped += 1
        continue
    if info.file_size > MAX_FILE:
        fail("too_large", "A page in the archive is over 20 MB.")
    names.append((info, parts))
if not names:
    fail("no_markdown", "The archive has no Markdown files.")
if len(names) > MAX_FILES:
    fail("too_many", "The archive has more than 20,000 Markdown files.")
if sum(i.file_size for i, _ in names) > MAX_TOTAL:
    fail("too_large", "The archive holds more than 512 MB of Markdown.")
tops = {parts[0] for _, parts in names}
strip = len(tops) == 1 and all(len(parts) > 1 for _, parts in names)
total = 0
for info, parts in names:
    rel = posixpath.join(*(parts[1:] if strip else parts))
    out = os.path.join(dest, rel)
    if not os.path.realpath(out).startswith(os.path.realpath(dest) + os.sep):
        fail("bad_path", "The archive has a file outside its own folder.")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    written = 0
    with z.open(info) as r, open(out, "wb") as w:
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            written += len(chunk)
            total += len(chunk)
            # The sizes in the archive are what it says; this is what it holds.
            if written > MAX_FILE or total > MAX_TOTAL:
                fail("too_large", "The archive holds more than 512 MB of Markdown.")
            w.write(chunk)
print(json.dumps({"files": len(names), "skipped": skipped}))
`,
  pages: `#!/bin/bash
# Written by controlclaw brain, from the Ansible role's (gbrain-pages.yml).
# Usage: cc-gbrain-pages token          prints a new token for the vm-agent's pages
#        cc-gbrain-pages export         GBrain's export into OUT/export, the vm-agent's to zip and remove
#        cc-gbrain-pages import         imports OUT/import/upload.zip; progress in OUT/import/progress
#        cc-gbrain-pages cost <since>   what GBrain's model calls cost since an ISO time: "<usd> <calls>"
set -euo pipefail
OUT=@OUT@
NAME=controlclaw-pages
g() {
  cd @HOME@
  runuser -u @USER@ -- env HOME=@HOME@ bash -c \\
    'set -a; [ ! -f @ENV@ ] || . @ENV@; [ ! -r @KEYFILE@ ] || . @KEYFILE@; set +a; exec "$@"' _ "$@"
}
# A work directory of GBrain's own, inside the container, emptied first and removed at the end.
work() {
  WORK="@HOME@/.cc-pages-$1"
  rm -rf "$WORK"
  install -d -m 0700 -o @USER@ -g @USER@ "$WORK"
  trap 'rm -rf "$WORK"' EXIT
}
case "$\{1:-}" in
  token)
    # Read and write, like a Read and write agent, and every page: the pages show the whole
    # brain to an owner or admin. Not \`cc-\`, so Activity does not count it as an agent and the
    # agents' rescope leaves it alone. Earlier ones are revoked first (names are not unique).
    g @GBRAIN@ auth revoke "$NAME" >/dev/null 2>&1 || true
    out="$(g @GBRAIN@ auth create "$NAME" --scopes read,write --reads-unscoped --yes)"
    token="$(printf '%s\\n' "$out" | sed -nE 's/^[[:space:]]+([A-Za-z0-9_]{32,})[[:space:]]*$/\\1/p' | head -1)"
    [ -n "$token" ] || { echo "cc-gbrain-pages: GBrain printed no token" >&2; exit 3; }
    printf '%s\\n' "$token"
    ;;
  export)
    work export
    rm -rf "$OUT/export"
    g @GBRAIN@ export --dir "$WORK/out" >/dev/null 2>"$WORK/log" || {
      echo "cc-gbrain-pages: $(tail -1 "$WORK/log")" >&2; exit 3; }
    grep -q COMPLETE "$WORK/out/.gbrain-export-status" || {
      echo "cc-gbrain-pages: the export did not finish" >&2; exit 3; }
    rm -f "$WORK/out/.gbrain-export-status"
    mv "$WORK/out" "$OUT/export"
    chown -R @OWNER@:@OWNER@ "$OUT/export"
    chmod -R u+rwX,go-rwx "$OUT/export"
    echo exported
    ;;
  import)
    [ -s "$OUT/import/upload.zip" ] || { echo "cc-gbrain-pages: no upload" >&2; exit 3; }
    work import
    install -m 0600 -o @USER@ -g @USER@ "$OUT/import/upload.zip" "$WORK/upload.zip"
    rm -f "$OUT/import/upload.zip"
    install -d -m 0700 -o @USER@ -g @USER@ "$WORK/pages"
    if ! read_out="$(g python3 -I /usr/local/lib/cc-gbrain-unzip.py "$WORK/upload.zip" "$WORK/pages")"; then
      printf '%s\\n' "$read_out"
      exit 3
    fi
    rm -f "$WORK/upload.zip"
    printf 'read %s\\n' "$read_out" > "$OUT/import/progress"
    # GBrain prints "[import.files] 12/40 (30%) ..." on stderr; the last one is the progress.
    summary="$(g @GBRAIN@ import "$WORK/pages" --json --allow-noncanonical-root 2> >(
      while IFS= read -r line; do
        if [[ "$line" =~ ^\\[import\\.files\\]\\ ([0-9]+)/([0-9]+) ]]; then
          printf '%s %s\\n' "$\{BASH_REMATCH[1]}" "$\{BASH_REMATCH[2]}" > "$OUT/import/progress.tmp"
          mv -f "$OUT/import/progress.tmp" "$OUT/import/progress"
        fi
      done))" || { echo "cc-gbrain-pages: GBrain's import failed" >&2; exit 3; }
    # Links between the new pages ([[wikilinks]]) and their timelines are read by a pass of
    # their own. No AI. A failure here leaves the pages in, without those links yet.
    g @GBRAIN@ extract all --source db >/dev/null 2>&1 || echo "cc-gbrain-pages: link extraction failed" >&2
    printf '%s\\n' "$summary" | tail -1
    ;;
  cost)
    since="$\{2:-}"
    [[ "$since" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$ ]] || {
      echo "cc-gbrain-pages: bad time" >&2; exit 2; }
    # The time is checked above, so it can be part of the statement.
    sql="select coalesce(sum(cost_usd),0)||' '||count(*) from chat_usage_log where created_at >= '$since'::timestamptz"
    g bash -c 'exec psql "$GBRAIN_DATABASE_URL" -Atc "$1"' _ "$sql"
    ;;
  *) echo "cc-gbrain-pages: token, export, import or cost" >&2; exit 2 ;;
esac
`,
};

// ---- brain install: the containers ----

export const BRAIN_PROJECT = "controlclaw-brain";
/** GBrain's container, where the vm-agent runs the helpers (`docker exec`). */
export const BRAIN_CONTAINER = `${BRAIN_PROJECT}-gbrain-1`;
/** The brain's own network: GBrain, Postgres and the gate. Internal: no way out from it. */
export const BRAIN_SUBNET = "172.31.248.0/24";
export const BRAIN_GATE_IP = "172.31.248.2";
/**
 * With the firewall on this machine: the relay on the firewall's `agents` network that is GBrain's way
 * out (its proxy and DNS, nothing else). GBrain itself stays off that network, so it cannot reach an
 * OpenClaw there, and the gate that publishes GBrain stays off it, so no OpenClaw reaches GBrain.
 */
export const BRAIN_EGRESS_IP = "172.31.248.3";
export const BRAIN_GBRAIN_IP = "172.31.248.10";
export const BRAIN_POSTGRES_IP = "172.31.248.11";
/** GBrain's port in its container, published on this machine's loopback by the gate. */
export const GBRAIN_PORT = 3130;
/** GBrain's home in its container, on the `gbrain` volume. */
export const CONTAINER_HOME = "/var/lib/gbrain";
export const CONTAINER_CA = "/etc/controlclaw/ca.crt";
/** The vm-agent's hand-over folder for Export and Import, mounted at the same path inside. */
export const CONTAINER_OUT = "/opt/controlclaw/state/gbrain-pages";

/** The helpers as they run in GBrain's container: as root there, GBrain under `cc-brain-run`. */
export function containerHelpers(): Record<string, string> {
  return {
    ...helpers({
      user: "gbrain",
      home: CONTAINER_HOME,
      env: `${CONTAINER_HOME}/.gbrain/env`,
      keyFile: `${CONTAINER_HOME}/.gbrain/env`,
      keyOwner: "gbrain:gbrain",
      keyMode: "0600",
      gbrain: "/usr/local/bin/gbrain",
      // GBrain listens on its container's loopback; `cc-brain-run` relays the brain's network to it.
      host: "127.0.0.1",
      port: GBRAIN_PORT,
      out: CONTAINER_OUT,
      owner: "root",
      restart: "/usr/local/bin/cc-gbrain-svc restart",
    }),
    "cc-gbrain-svc": SVC,
    "cc-brain-run": RUN,
  };
}

/** `systemctl try-restart gbrain` in the container: `cc-brain-run` starts GBrain again. */
const SVC = `#!/bin/bash
# Written by controlclaw brain. Usage: cc-gbrain-svc restart
case "$\{1:-}" in
  restart) pkill -f '^/usr/local/bin/gbrain serve' || true ;;
  *) echo "cc-gbrain-svc: restart" >&2; exit 2 ;;
esac
`;

/**
 * GBrain's container: what the role's `gbrain.yml` does on a box, at every start (create or adopt),
 * then GBrain served on the brain's network only, started again when it stops, and the nightly run
 * once a night between 02:00 and 05:00 (the role's `gbrain-dream.timer`).
 */
const RUN = `#!/bin/bash
# Written by controlclaw brain: GBrain's container (the Ansible role's gbrain.yml, at every start).
set -uo pipefail
H=${CONTAINER_HOME}
ENV=$H/.gbrain/env
G=/usr/local/bin/gbrain
say() { echo "[brain] $*"; }
as_gbrain() {
  cd "$H"
  runuser -u gbrain -- env HOME="$H" bash -c 'set -a; . '"$ENV"'; set +a; exec "$@"' _ "$@"
}
install -d -o gbrain -g gbrain -m 0750 "$H"
install -d -o gbrain -g gbrain -m 0700 "$H/.gbrain"
install -d -o gbrain -g root -m 2750 /var/lib/gbrain-report
install -d -o root -g root -m 0750 ${CONTAINER_OUT}

# The env file: GBrain's owner credential is born here and never leaves; the database's address
# comes from Compose at each start; the model key is the firewall's (cc-gbrain-key).
if [ ! -s "$ENV" ]; then
  umask 077
  {
    echo "# Written by controlclaw brain. Made in this container; never sent anywhere."
    echo "GBRAIN_ADMIN_BOOTSTRAP_TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \\n')"
    echo "OPENAI_BASE_URL=https://ai-gateway.vercel.sh/v1"
    echo "OPENAI_API_KEY=vck-cc-included-none"
    echo "GBRAIN_NO_AUTOPILOT_INSTALL=1"
  } > "$ENV.tmp"
  chown gbrain:gbrain "$ENV.tmp"
  mv "$ENV.tmp" "$ENV"
fi
tmp="$(mktemp "$ENV.XXXXXX")"
grep -v '^GBRAIN_DATABASE_URL=' "$ENV" > "$tmp" || true
echo "GBRAIN_DATABASE_URL=$GBRAIN_DATABASE_URL" >> "$tmp"
chown gbrain:gbrain "$tmp"; chmod 0600 "$tmp"; mv "$tmp" "$ENV"

until psql "$GBRAIN_DATABASE_URL" -Atc 'select 1' >/dev/null 2>&1; do say "waiting for Postgres"; sleep 2; done
psql -q "$GBRAIN_DATABASE_URL" -v ON_ERROR_STOP=1 -c 'CREATE EXTENSION IF NOT EXISTS vector' || exit 1

if [ ! -f "$H/.gbrain/config.json" ]; then
  say "first start: gbrain init"
  as_gbrain "$G" init --non-interactive --content-root "$H/content" --embedding-model openai:text-embedding-3-small || exit 1
else
  # A new image under an existing brain: its schema first. Never a paid re-embedding.
  as_gbrain env GBRAIN_NO_REEMBED=1 "$G" apply-migrations --yes --no-autopilot-install || say "GBrain's migrations reported a problem"
fi

# The role's settings, every start: the brain's model (cc-model, Luna when there is none), Terra for
# deep answers, the gateway loop, and the nightly run learning by itself.
model="$(cat "$H/.gbrain/cc-model" 2>/dev/null || true)"
case "$model" in ${BRAIN_MODELS.join("|")}) ;; *) model=${BRAIN_MODELS[0]} ;; esac
for k in models.tier.utility models.tier.reasoning models.tier.subagent models.fence_repair models.content_repair; do
  as_gbrain "$G" config set "$k" "openai:$model" >/dev/null
done
as_gbrain "$G" config set models.tier.deep openai:${BRAIN_MODELS[1]} >/dev/null
as_gbrain "$G" config set agent.use_gateway_loop true >/dev/null
as_gbrain "$G" config set cycle.conversation_facts_backfill.enabled true >/dev/null
as_gbrain "$G" config set dream.edge_contradictions.mode apply >/dev/null
as_gbrain "$G" config set dream.single_value.mode apply >/dev/null
# Self-upgrade off, in the file GBrain reads it from (the role's reason): the version is the image's.
runuser -u gbrain -- python3 -I - "$H/.gbrain/config.json" <<'PY'
import json, os, sys
p = sys.argv[1]
d = json.load(open(p))
su = d.setdefault("self_upgrade", {})
if su.get("mode") != "off":
    su["mode"] = "off"
    tmp = p + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(d, fh, indent=2)
        fh.write("\\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)
PY

# The nightly run: once a night at a random minute between 02:00 and 05:00, this container's time.
(
  while true; do
    now=$(date +%s)
    at=$(date -d "tomorrow 02:00" +%s)
    [ "$(date +%H)" -lt 2 ] && at=$(date -d "today 02:00" +%s)
    sleep $(( at - now + RANDOM % 10800 ))
    say "nightly run"
    as_gbrain /usr/local/bin/cc-gbrain-dream >/dev/null || say "the nightly run failed"
  done
) &

# GBrain on this container's loopback only, as on a SaaS brain (it gives admin login links only
# there); the brain's network reaches it through this relay, which the gate publishes to the host.
(
  while true; do
    socat TCP-LISTEN:${GBRAIN_PORT},bind="$GBRAIN_BIND",fork,reuseaddr TCP:127.0.0.1:${GBRAIN_PORT}
    say "the relay to GBrain stopped; starting it again"
    sleep 2
  done
) &

while true; do
  as_gbrain "$G" serve --http --bind 127.0.0.1 --port ${GBRAIN_PORT} --public-url "$\{GBRAIN_PUBLIC_URL:-https://gbrain.invalid}"
  say "GBrain stopped ($?); starting it again"
  sleep 2
done
`;

/** GBrain's image: Ubuntu 24.04 (the role's), the pinned binary checked by sha256, the helpers. */
export const DOCKERFILE = `# Written by controlclaw brain install.
FROM ubuntu:24.04
RUN apt-get update \\
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl postgresql-client python3 procps socat tzdata \\
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL --retry 3 -o /usr/local/bin/gbrain-${GBRAIN_VERSION} ${GBRAIN_URL} \\
 && echo "${GBRAIN_SHA256}  /usr/local/bin/gbrain-${GBRAIN_VERSION}" | sha256sum -c - \\
 && chmod 0755 /usr/local/bin/gbrain-${GBRAIN_VERSION} \\
 && ln -s gbrain-${GBRAIN_VERSION} /usr/local/bin/gbrain \\
 && /usr/local/bin/gbrain --version | grep -q "${GBRAIN_VERSION}"
RUN useradd --system --home-dir ${CONTAINER_HOME} --no-create-home --shell /usr/sbin/nologin gbrain
COPY bin/ /usr/local/bin/
COPY cc-gbrain-unzip.py /usr/local/lib/cc-gbrain-unzip.py
RUN chmod 0755 /usr/local/bin/cc-* && chmod 0644 /usr/local/lib/cc-gbrain-unzip.py
ENTRYPOINT ["/usr/local/bin/cc-brain-run"]
`;

/** The build context's files: `Dockerfile`, `bin/<helper>`, `cc-gbrain-unzip.py`. */
export function imageFiles(): Record<string, string> {
  const files: Record<string, string> = { Dockerfile: DOCKERFILE };
  for (const [name, text] of Object.entries(containerHelpers())) {
    files[name.endsWith(".py") ? name : `bin/${name}`] = text;
  }
  return files;
}

/** The image's tag: GBrain's version and a hash of everything built into it. */
export function imageTag(files: Record<string, string> = imageFiles()): string {
  const h = createHash("sha256");
  for (const k of Object.keys(files).sort()) h.update(`${k}\0${files[k]}\0`);
  return `controlclaw-brain-gbrain:${GBRAIN_VERSION}-${h.digest("hex").slice(0, 12)}`;
}

/** How the brain's model calls leave: straight to the firewall (on its `agents` network), or through the gate. */
export type BrainEgress =
  | { kind: "firewall-net"; network: string; firewall: string; address: string }
  | { kind: "gate"; proxy: { host: string; port: number }; dns: string | null };

const q = (s: string) => JSON.stringify(s);

/** The Compose file. The database password is Compose's `GBRAIN_DB_PASSWORD`, from `.env` next to it. */
export function brainCompose(o: { image: string; egress: BrainEgress; out: string; ca: string; tz: string; gatewayIsolated: string[]; pagesName?: string }): string {
  const e = o.egress;
  const out = e.kind === "firewall-net" ? BRAIN_EGRESS_IP : BRAIN_GATE_IP;
  const proxy = `http://${out}:8080`;
  const dns = out;
  const direct = ["localhost", "127.0.0.1", BRAIN_GBRAIN_IP, BRAIN_POSTGRES_IP].join(",");
  const env: [string, string][] = [
    // Plain on the brain's own internal network, which only GBrain, Postgres and the gate are on:
    // GBrain asks for TLS to any Postgres that is not on its loopback.
    ["GBRAIN_DATABASE_URL", `postgres://gbrain:\${GBRAIN_DB_PASSWORD}@${BRAIN_POSTGRES_IP}:5432/gbrain?sslmode=disable`],
    ["GBRAIN_BIND", BRAIN_GBRAIN_IP],
    ["HTTP_PROXY", proxy],
    ["HTTPS_PROXY", proxy],
    ["http_proxy", proxy],
    ["https_proxy", proxy],
    ["NO_PROXY", direct],
    ["no_proxy", direct],
    ["NODE_EXTRA_CA_CERTS", CONTAINER_CA],
    ["TZ", o.tz],
    // GBrain builds its admin links and redirects on this: the name the firewall relays the pages under.
    ...(o.pagesName ? ([["GBRAIN_PUBLIC_URL", `https://${o.pagesName}`]] as [string, string][]) : []),
  ];
  // The gate: GBrain on this machine's loopback for the vm-agent, and in gate mode the brain's way
  // out, to the firewall's proxy and DNS. With the firewall here, the way out is `egress` on its
  // `agents` network instead. GBrain reaches nothing else, and nothing on `agents` reaches GBrain.
  const relays = [`socat TCP-LISTEN:${GBRAIN_PORT},fork,reuseaddr TCP:${BRAIN_GBRAIN_IP}:${GBRAIN_PORT}`];
  const outward = (host: string, port: number, dnsAt: string | null) => [
    `socat TCP-LISTEN:8080,fork,reuseaddr TCP:${host}:${port}`,
    ...(dnsAt ? [`socat UDP-LISTEN:53,fork,reuseaddr UDP:${dnsAt}:53`, `socat TCP-LISTEN:53,fork,reuseaddr TCP:${dnsAt}:53`] : []),
  ];
  if (e.kind === "gate") relays.push(...outward(e.proxy.host, e.proxy.port, e.dns));
  const script = (r: string[]) => q(`${r.map((x) => `${x} &`).join(" ")} wait`);
  return [
    "# Written by controlclaw brain install; removed by controlclaw brain disconnect (the volumes stay without --purge).",
    `name: ${BRAIN_PROJECT}`,
    "services:",
    "  postgres:",
    `    image: ${q(POSTGRES_IMAGE)}`,
    "    restart: unless-stopped",
    "    environment:",
    "      POSTGRES_USER: gbrain",
    "      POSTGRES_DB: gbrain",
    `      POSTGRES_PASSWORD: ${q("${GBRAIN_DB_PASSWORD}")}`,
    "    volumes:",
    "      - postgres:/var/lib/postgresql/data",
    "    networks:",
    "      brain:",
    `        ipv4_address: ${BRAIN_POSTGRES_IP}`,
    "  gbrain:",
    `    image: ${q(o.image)}`,
    "    restart: unless-stopped",
    "    depends_on: [postgres]",
    `    dns: [${q(dns)}]`,
    "    environment:",
    ...env.map(([k, v]) => `      ${k}: ${q(v)}`),
    "    volumes:",
    `      - gbrain:${CONTAINER_HOME}`,
    `      - ${q(`${o.ca}:${CONTAINER_CA}:ro`)}`,
    `      - ${q(`${o.out}:${CONTAINER_OUT}`)}`,
    "    networks:",
    "      brain:",
    `        ipv4_address: ${BRAIN_GBRAIN_IP}`,
    "  gate:",
    `    image: ${q(GATE_IMAGE)}`,
    "    restart: unless-stopped",
    `    entrypoint: ["/bin/sh", "-c"]`,
    `    command: [${script(relays)}]`,
    "    ports:",
    `      - ${q(`127.0.0.1:${GBRAIN_PORT}:${GBRAIN_PORT}`)} # GBrain, for the vm-agent on this machine`,
    "    networks:",
    "      default: {}",
    "      brain:",
    `        ipv4_address: ${BRAIN_GATE_IP}`,
    ...(e.kind === "firewall-net"
      ? [
          "  egress:",
          `    image: ${q(GATE_IMAGE)}`,
          "    restart: unless-stopped",
          `    entrypoint: ["/bin/sh", "-c"]`,
          `    command: [${script(outward(e.firewall, 8080, e.firewall))}]`,
          "    networks:",
          "      brain:",
          `        ipv4_address: ${BRAIN_EGRESS_IP}`,
          "      firewall:",
          `        ipv4_address: ${e.address}`,
        ]
      : []),
    "networks:",
    "  brain:",
    "    internal: true",
    ...o.gatewayIsolated,
    "    ipam:",
    `      config: [{ subnet: ${q(BRAIN_SUBNET)} }]`,
    ...(e.kind === "firewall-net" ? ["  firewall:", "    external: true", `    name: ${q(e.network)}`] : []),
    "volumes:",
    "  postgres:",
    "  gbrain:",
    "",
  ].join("\n");
}
