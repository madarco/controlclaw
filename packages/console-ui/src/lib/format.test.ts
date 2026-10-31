/**
 * The console's server-rendered formatting must not move with the machine's locale or timezone:
 * that difference between the server's render and the browser's is hydration error #418.
 *
 * The test re-runs itself once under an Italian locale in Tokyo and compares the two outputs.
 * Run: pnpm --filter @controlclaw/console-ui test
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { countLabel, resetDayLabel } from "./format";

const SAMPLES = [
  countLabel(1234567),
  countLabel(0),
  // 23:30 UTC on the 30th: in Tokyo it is already the 1st, so an unpinned timezone shows here.
  resetDayLabel("2026-09-30T23:30:00.000Z"),
  resetDayLabel("2026-01-01T00:00:00.000Z"),
].join("\n");

if (process.env.FORMAT_TEST_CHILD) {
  process.stdout.write(SAMPLES);
  process.exit(0);
}

let fails = 0;
const t = (name: string, fn: () => void) => {
  try {
    fn();
    console.log(`  ✅ ${name}`);
  } catch (e) {
    fails++;
    console.log(`  ❌ ${name} — ${(e as Error).message}`);
  }
};

t("an Italian browser in Tokyo reads exactly what the server painted", () => {
  // Same runner as this process (tsx registers itself through execArgv), same file, other locale.
  const elsewhere = execFileSync(process.execPath, [...process.execArgv, fileURLToPath(import.meta.url)], {
    env: { ...process.env, FORMAT_TEST_CHILD: "1", LC_ALL: "it_IT.UTF-8", LANG: "it_IT.UTF-8", TZ: "Asia/Tokyo" },
    encoding: "utf8",
  });
  assert.equal(elsewhere, SAMPLES);
});

t("a count is grouped, and a reset day is its UTC day", () => {
  assert.equal(countLabel(1234567), "1,234,567");
  assert.equal(resetDayLabel("2026-09-30T23:30:00.000Z"), "September 30");
});

console.log(fails ? `\n💥 ${fails} failed` : "\n✨ all passed");
process.exit(fails ? 1 : 0);
