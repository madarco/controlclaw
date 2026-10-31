/**
 * The manifest's canonical form and hash, and the exclude list.
 * Run: npx tsx src/manifest.test.ts
 */
import assert from "node:assert/strict";
import { canonicalManifest, manifestHash, manifestMatches, parseManifest, type Manifest } from "./manifest";
import { assertArchivableRoot, shouldExclude } from "./paths";

let fails = 0;
const t = async (name: string, fn: () => void | Promise<void>) => {
  try {
    await fn();
    console.log(`  ✅ ${name}`);
  } catch (e) {
    fails++;
    console.log(`  ❌ ${name} — ${(e as Error).message}`);
  }
};

const base: Manifest = {
  version: 1,
  kind: "workspace",
  takenAt: "2026-09-21T10:00:00.000Z",
  root: "/home/controlclaw/.openclaw/workspace",
  entries: [
    { path: "notes/a.md", bytes: 12, mode: 0o644, kind: "file" },
    { path: "bin/run.sh", bytes: 40, mode: 0o755, kind: "file" },
    { path: "notes", bytes: 0, mode: 0o755, kind: "dir" },
  ],
  totalBytes: 52,
  excluded: [{ path: "node_modules", bytes: 900 }],
};

console.log("backup manifest");

await t("the hash does not depend on entry order or key order", async () => {
  const shuffled: Manifest = { ...base, entries: [base.entries[2]!, base.entries[0]!, base.entries[1]!] };
  assert.equal(canonicalManifest(shuffled), canonicalManifest(base));
  assert.equal(await manifestHash(shuffled), await manifestHash(base));
});

await t("the hash is 64 hex characters and stable", async () => {
  const h = await manifestHash(base);
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.equal(h, await manifestHash(JSON.parse(JSON.stringify(base)) as Manifest));
});

await t("changing a mode, a size or a path changes the hash", async () => {
  const h = await manifestHash(base);
  for (const m of [
    { ...base, entries: [{ ...base.entries[1]!, mode: 0o644 }, ...base.entries.slice(2)] },
    { ...base, entries: [{ ...base.entries[0]!, bytes: 13 }, ...base.entries.slice(1)] },
    { ...base, entries: [{ ...base.entries[0]!, path: "notes/b.md" }, ...base.entries.slice(1)] },
    { ...base, kind: "state" as const },
    { ...base, root: "/home/other" },
  ]) {
    assert.notEqual(await manifestHash(m), h, `hash unchanged for ${JSON.stringify(m).slice(0, 60)}`);
  }
});

await t("a manifest matches only its own hash", async () => {
  assert.equal(await manifestMatches(base, await manifestHash(base)), true);
  assert.equal(await manifestMatches(base, "0".repeat(64)), false);
});

await t("a manifest round-trips through JSON", () => {
  const m = parseManifest(JSON.stringify(base));
  assert.equal(m.entries.length, 3);
  assert.equal(m.excluded.length, 1);
  assert.throws(() => parseManifest(JSON.stringify({ version: 2 })), /not readable/);
});

console.log("excludes");

await t("caches, node_modules, logs and browser cache directories are left out", () => {
  for (const p of [
    "node_modules/left-pad/index.js",
    "app/node_modules/x",
    ".cache/thing",
    "browser/profile/Default/Cache/data_0",
    "browser/profile/Default/Code Cache/js/x",
    "browser/profile/Default/Service Worker/CacheStorage/y",
    "browser/profile/Crashpad/reports/z",
    "logs/agent.log",
    "openclaw.log",
    "run/agent.sock",
    "npm/_cacache/index-v5/aa",
    "tmp/half-written",
  ]) {
    assert.equal(shouldExclude(p, "workspace"), true, `${p} should be excluded`);
  }
});

await t("real content is kept, including dotfiles and git history", () => {
  for (const p of [
    "notes/a.md",
    ".git/objects/aa/bbcc",
    ".gitignore",
    "src/index.ts",
    "dist/bundle.js",
    "data/cached-report.csv",
    "sessions/2026-09-21.json",
    "agents/main/memory.md",
  ]) {
    assert.equal(shouldExclude(p, "workspace"), false, `${p} should be kept`);
  }
});

await t("a restore's own scratch directories are never archived", () => {
  // Left behind inside OpenClaw's home when a box dies mid-restore. Archiving them would put a
  // second copy of the workspace into the one archive that excludes the workspace.
  for (const p of [
    "workspace.cc-restoring/notes/a.md",
    "workspace.cc-previous-1758499200000/notes/a.md",
    "workspace.cc-previous-1/big.bin",
    "sub/thing.cc-restoring/x",
  ]) {
    assert.equal(shouldExclude(p, "state"), true, `${p} should be excluded from state`);
    assert.equal(shouldExclude(p, "workspace"), true, `${p} should be excluded from workspace too`);
  }
  // Not so eager that it eats real content that happens to look similar.
  for (const p of ["workspace-notes/a.md", "cc-previous/a.md", "notes.cc-previously/a.md"]) {
    assert.equal(shouldExclude(p, "workspace"), false, `${p} should be kept`);
  }
});

await t("the state archive skips the workspace, and vice versa", () => {
  assert.equal(shouldExclude("workspace/notes/a.md", "state"), true);
  assert.equal(shouldExclude("workspace", "state"), true);
  // A directory called `workspace` INSIDE the workspace archive is ordinary content.
  assert.equal(shouldExclude("workspace/notes/a.md", "workspace"), false);
  assert.equal(shouldExclude("config.json", "state"), false);
});

await t("this box's identity is never archived", () => {
  for (const p of ["openclaw_gateway_token", "keys/session_secret", "sub/vm_private_key.pem"]) {
    assert.equal(shouldExclude(p, "state"), true, `${p} should be excluded`);
  }
  for (const root of ["/opt/controlclaw/keys", "/opt/controlclaw/keys/", "/opt/controlclaw/mitm/ca", "/", "/root"]) {
    assert.throws(() => assertArchivableRoot(root), /refusing/, `${root} should be refused`);
  }
  assertArchivableRoot("/home/controlclaw/.openclaw");
});

console.log(fails ? `\n💥 ${fails} failed` : "\n✨ all passed");
process.exit(fails ? 1 : 0);
