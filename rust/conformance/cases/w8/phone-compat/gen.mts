// Writes rust/bins/vm-agent/src/phone/compat.json: the reviewed voice-call plugin patches
// (`phonePatches()`: phone-compat.ts, phone-realtime-compat.ts, phone-reply-compat.ts and the
// admission stages) in the order patchPhonePlugin applies them, byte for byte, and the reviewed
// admission digests (phone-runtime.ts). The Rust build embeds
// the file; `--check` says whether it still matches the TS.
//   npx tsx rust/conformance/cases/w8/phone-compat/gen.mts [--check]
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { phonePatches } from "../../../../../packages/vm-agent/src/phone-compat.ts";
import { PHONE_NO_REPLY_TEXT } from "../../../../../packages/vm-agent/src/phone-reply-compat.ts";
import { PHONE_ADMISSION_DIGESTS } from "../../../../../packages/vm-agent/src/phone-runtime.ts";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "../../../../bins/vm-agent/src/phone/compat.json");
const patches = phonePatches();
// The TS applies each change with `String.replace(before, after)`, where `$$`, `$&`, `` $` `` and
// `$'` in `after` mean something; the Rust port inserts `after` as it is. Refuse a table where
// the two would differ.
for (const p of patches)
  for (const [, after] of p.changes)
    if (/\$[$&`']/.test(after)) throw new Error(`${p.file}: a replacement uses a $ pattern; the Rust port would differ`);
const text =
  JSON.stringify(
    {
      admissionDigests: [...PHONE_ADMISSION_DIGESTS],
      noReplyText: PHONE_NO_REPLY_TEXT,
      patches: patches.map((p) => ({ file: p.file, before: p.before, after: p.after, changes: p.changes.map(([a, b]) => [a, b]) })),
    },
    null,
    1,
  ) + "\n";
if (process.argv.includes("--check")) {
  if (readFileSync(out, "utf8") !== text) {
    console.error("compat.json is not what the TS has; run without --check");
    process.exit(1);
  }
  console.log("compat.json matches the TS patches");
} else writeFileSync(out, text);
