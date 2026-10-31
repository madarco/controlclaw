// Writes expected.json: what @controlclaw/meetings (index, consult-model, archive) answers for each
// call in cases.json. The Rust port (rust/bins/vm-agent/src/meetings/policy.rs and pages.rs) must give
// the same answers.
//   npx tsx gen.mts          write expected.json
//   npx tsx gen.mts --check  compare instead
import { readFileSync, writeFileSync } from "node:fs";
import * as m from "../../../../../packages/meetings/src/index.ts";
import * as c from "../../../../../packages/meetings/src/consult-model.ts";
import * as a from "../../../../../packages/meetings/src/archive.ts";

const fns: Record<string, (...a: unknown[]) => unknown> = { ...m, ...c, ...a } as never;
const here = new URL(".", import.meta.url);
const cases = JSON.parse(readFileSync(new URL("cases.json", here), "utf8")) as Array<{ fn: string; args: unknown[] }>;
const answers = cases.map(({ fn, args }) => {
  try {
    const out = fns[fn]!(...args);
    return out === undefined ? { undefined: true } : { ok: out };
  } catch (error) {
    return { error: (error as Error).message };
  }
});
const text = `${JSON.stringify(answers, null, 1)}\n`;
const path = new URL("expected.json", here);
if (process.argv.includes("--check")) {
  if (readFileSync(path, "utf8") !== text) {
    console.error("expected.json differs from the TS answers");
    process.exit(1);
  }
  console.log(`expected.json matches the TS (${answers.length} cases)`);
} else {
  writeFileSync(path, text);
  console.log(`wrote ${answers.length} answers`);
}
