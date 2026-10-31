// Writes rust/bins/vm-agent/src/meetings/page_scripts.json: the JavaScript the vm-agent runs
// elsewhere: in the meeting browser's pages (the caption observer of meeting-captions.ts, the
// microphone settings of meeting-mic.ts) and in `node` (the notes program of meeting-summary.ts),
// as the TS builds them. The Rust build carries them unchanged; `--check` says
// whether the file still matches the TS.
//   npx tsx rust/conformance/cases/w8/page-scripts/gen.mts [--check]
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CAPTION_SCRIPT } from "../../../../../packages/vm-agent/src/meeting-captions.ts";
import { MIC_SCRIPT } from "../../../../../packages/vm-agent/src/meeting-mic.ts";
import { NOTES_PROGRAM } from "../../../../../packages/vm-agent/src/meeting-summary.ts";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "../../../../bins/vm-agent/src/meetings/page_scripts.json");
const text = JSON.stringify({ caption: CAPTION_SCRIPT, mic: MIC_SCRIPT, notes: NOTES_PROGRAM }, null, 1) + "\n";
if (process.argv.includes("--check")) {
  if (readFileSync(out, "utf8") !== text) {
    console.error("page_scripts.json is not what the TS builds; run without --check");
    process.exit(1);
  }
  console.log("page_scripts.json matches the TS page scripts");
} else writeFileSync(out, text);
