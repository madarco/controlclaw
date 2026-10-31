// Backups across the two builds (W7 B3): the TS BackupService seals a tree into a fixture the Rust
// tests restore, and restores a fixture the Rust build sealed.
//
//   npx tsx rust/bins/vm-agent/src/boxside/fixtures/backup.mts seal <out-dir>
//   npx tsx rust/bins/vm-agent/src/boxside/fixtures/backup.mts restore <fixture-dir>
//
// A fixture is `blob.bin` (the ciphertext as PUT) and `meta.json` (key, binding, header, hash), with
// `tree.json` listing what the archive holds.
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, lstatSync, readlinkSync, symlinkSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BackupService } from "../../../../../../packages/vm-agent/src/backup.ts";

const META = { orgId: "org_1", vmId: "vm_1", backupId: "bk_1", kind: "workspace" as const, dataKey: Buffer.alloc(32, 7).toString("base64") };

/** The tree both builds archive: a nested file, an executable, a link, an empty folder. */
export function makeTree(home: string): void {
  const ws = join(home, "workspace");
  mkdirSync(join(ws, "notes", "deep"), { recursive: true });
  mkdirSync(join(ws, "empty"));
  writeFileSync(join(ws, "notes", "a.md"), "# hello\n");
  writeFileSync(join(ws, "notes", "deep", "b.txt"), "b".repeat(70_000));
  writeFileSync(join(ws, "run.sh"), "echo hi\n");
  chmodSync(join(ws, "run.sh"), 0o755);
  symlinkSync("notes/a.md", join(ws, "link.md"));
}

function list(root: string, rel = ""): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of readdirSync(join(root, rel)).sort()) {
    const r = rel ? `${rel}/${name}` : name;
    const st = lstatSync(join(root, r));
    if (st.isSymbolicLink()) out[r] = `link:${readlinkSync(join(root, r))}`;
    else if (st.isDirectory()) Object.assign(out, { [r]: `dir:${(st.mode & 0o777).toString(8)}` }, list(root, r));
    else out[r] = `file:${(st.mode & 0o777).toString(8)}:${readFileSync(join(root, r)).length}`;
  }
  return out;
}

const service = () => ({ ok: true });
const [mode, dir] = process.argv.slice(2);
if (mode === "seal") {
  const home = mkdtempSync(join(tmpdir(), "cc-bk-ts-"));
  makeTree(home);
  let blob = Buffer.alloc(0);
  const fetchImpl = (async (_url: string, init: { body: ReadableStream }) => {
    const chunks: Buffer[] = [];
    for await (const c of init.body as unknown as AsyncIterable<Uint8Array>) chunks.push(Buffer.from(c));
    blob = Buffer.concat(chunks);
    return new Response(null, { status: 200 });
  }) as unknown as typeof fetch;
  const svc = new BackupService({ home, spoolDir: home, service, fetchImpl, log: () => {} });
  const r = await svc.run({ ...META, uploadUrl: "https://store.example/put" });
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "blob.bin"), blob);
  writeFileSync(join(dir, "meta.json"), JSON.stringify({ ...META, header: r.header, manifestHash: r.manifestHash, entries: r.entries }, null, 2) + "\n");
  writeFileSync(join(dir, "tree.json"), JSON.stringify(list(join(home, "workspace")), null, 2) + "\n");
  console.log(`sealed ${r.entries} entries, ${r.cipherBytes} bytes`);
} else if (mode === "restore") {
  const meta = JSON.parse(readFileSync(join(dir, "meta.json"), "utf8"));
  const blob = readFileSync(join(dir, "blob.bin"));
  const home = mkdtempSync(join(tmpdir(), "cc-bk-ts-restore-"));
  const fetchImpl = (async () => new Response(blob, { status: 200 })) as unknown as typeof fetch;
  const svc = new BackupService({ home, spoolDir: home, service, fetchImpl, log: () => {}, sanitizeRestore: () => {} });
  const r = await svc.restore({ ...meta, downloadUrl: "https://store.example/get" });
  const want = JSON.parse(readFileSync(join(dir, "tree.json"), "utf8"));
  const got = list(join(home, "workspace"));
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    console.error("tree differs", { want, got });
    process.exit(1);
  }
  console.log(`restored ${r.entries} entries; tree matches`);
} else {
  console.error("usage: backup.mts seal|restore <dir>");
  process.exit(2);
}
