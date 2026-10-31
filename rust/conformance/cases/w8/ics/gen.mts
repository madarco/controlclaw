// Writes expected.json: what the TS build (ical.js) finds in each case of cases.json. The Rust
// test `meetings::ics::tests::parity` must find the same.
//   npx tsx rust/conformance/cases/w8/ics/gen.mts
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expandInvites, inviteUids } from "../../../../../packages/vm-agent/src/meeting-ics.ts";

const here = dirname(fileURLToPath(import.meta.url));
const cases = JSON.parse(readFileSync(join(here, "cases.json"), "utf8")) as Record<string, { uid: string; files: string[]; from: string; to: string }>;
const out: Record<string, unknown> = {};
// Where ical.js throws, `expandInvites` throws and the schedule gives up on that sync: the Rust
// port returns the same message as an error.
function occurrences(c: { uid: string; files: string[]; from: string; to: string }) {
  try {
    return expandInvites(c.uid, c.files, Date.parse(c.from), Date.parse(c.to)).map((o) => ({ ...o, start: new Date(o.start).toISOString(), end: new Date(o.end).toISOString() }));
  } catch (error) {
    return { error: (error as Error).message };
  }
}
// In name order, in one process: ical.js keeps the zones earlier files registered, and so does the
// Rust port, so both must see the files in the same order.
for (const name of Object.keys(cases).sort()) {
  const c = cases[name];
  out[name] = {
    uids: c.files.map((f) => inviteUids(f)),
    occurrences: occurrences(c),
  };
}
const check = process.argv.includes("--check");
const text = JSON.stringify(out, null, 1) + "\n";
if (check) {
  if (readFileSync(join(here, "expected.json"), "utf8") !== text) {
    console.error("expected.json is not what the TS build finds; run without --check to see the change");
    process.exit(1);
  }
  console.log("expected.json matches the TS build");
} else writeFileSync(join(here, "expected.json"), text);
