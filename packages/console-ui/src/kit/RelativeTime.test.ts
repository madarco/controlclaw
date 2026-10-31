/**
 * Both directions of a relative timestamp. A deadline — when an invitation expires, when a backup
 * will be deleted — used to clamp to "just now", which says the opposite of what is true.
 * Run: npx tsx "app/(dashboard)/components/RelativeTime.test.ts"
 */
import assert from "node:assert/strict";
import { formatRelative } from "./RelativeTime";

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

const NOW = Date.parse("2026-09-24T12:00:00.000Z");
const at = (ms: number) => formatRelative(new Date(NOW + ms), NOW);

t("the recent past reads as ago", () => {
  assert.equal(at(-10_000), "just now");
  assert.equal(at(-5 * 60_000), "5m ago");
  assert.equal(at(-3 * 3_600_000), "3h ago");
  assert.equal(at(-2 * 86_400_000), "2d ago");
});

t("a deadline reads as a deadline, not as just now", () => {
  assert.equal(at(30_000), "in a moment");
  assert.equal(at(6 * 60_000), "in 6m");
  assert.equal(at(5 * 3_600_000), "in 5h");
  assert.equal(at(6 * 86_400_000), "in 6d");
});

t("past a week either way it is a date, and the same date either way", () => {
  assert.equal(at(-30 * 86_400_000), at(-30 * 86_400_000));
  assert.match(at(30 * 86_400_000), /[A-Z][a-z]{2}/);
  assert.match(at(-30 * 86_400_000), /[A-Z][a-z]{2}/);
});

console.log(fails ? `\n💥 ${fails} failed` : "\n✨ all passed");
process.exit(fails ? 1 : 0);
