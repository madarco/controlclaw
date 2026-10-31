/**
 * The retention grid: 7 daily + 4 weekly.
 * Run: npx tsx src/retention.test.ts
 */
import assert from "node:assert/strict";
import { DAILY_KEEP, EXPIRY_GRACE_MS, WEEKLY_KEEP, dayKey, expiryFor, planRetention, weekKey } from "./retention";

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

const DAY = 24 * 60 * 60 * 1000;
const NOW = new Date("2026-09-21T09:00:00.000Z"); // a Monday
/** One backup per day at 02:00 UTC, `days` of them, newest today. */
const daily = (days: number) =>
  Array.from({ length: days }, (_, i) => ({
    id: `d${i}`,
    takenAt: new Date(Date.UTC(2026, 8, 21 - i, 2, 0, 0)),
  }));

console.log("retention");

t("fewer than a week of backups: nothing expires", () => {
  const p = planRetention(daily(5));
  assert.equal(p.expire.length, 0);
  assert.equal(p.keep.length, 5);
});

t("a month of daily backups keeps 7 dailies plus the weeklies", () => {
  const p = planRetention(daily(30));
  // d0 is Monday 2026-09-21, so the seven dailies (d0..d6) already cover this week and the last
  // one. Of the four weeks in the weekly window, only the two older ones still need a row of
  // their own: d8 (the newest of the week before last) and d15.
  assert.deepEqual(p.keep.map((b) => b.id), ["d0", "d1", "d2", "d3", "d4", "d5", "d6", "d8", "d15"]);
  assert.equal(p.keep.length + p.expire.length, 30);
  for (let i = 0; i < DAILY_KEEP; i++) assert.equal(p.reason.get(`d${i}`), "daily", `d${i} is a daily`);
  assert.ok(p.expire.some((b) => b.id === "d7"), "d7 falls out: same week as a kept daily, not the newest of it");
  assert.ok(p.expire.some((b) => b.id === "d22"), "d22 falls out: its week is past the four-week window");
});

t("the weeklies chosen are the newest backup of each of the last four weeks", () => {
  const p = planRetention(daily(30));
  const weeklies = p.keep.filter((b) => p.reason.get(b.id) === "weekly");
  // Two of the four weeks are already covered by a daily; a backup is never kept twice.
  assert.equal(weeklies.length, 2);
  const weeks = new Set(p.keep.map((b) => weekKey(b.takenAt)));
  assert.equal(weeks.size, WEEKLY_KEEP, "the kept rows span exactly the weekly window");
  for (const w of weeklies) {
    const sameWeek = daily(30).filter((b) => weekKey(b.takenAt) === weekKey(w.takenAt));
    const newest = sameWeek.reduce((a, b) => (b.takenAt > a.takenAt ? b : a));
    assert.equal(w.id, newest.id, `${w.id} is the newest of its week`);
  }
});

t("several backups on one day: only the newest of that day is a daily", () => {
  const p = planRetention([
    { id: "morning", takenAt: new Date("2026-09-21T02:00:00Z") },
    { id: "midday", takenAt: new Date("2026-09-21T12:00:00Z") },
    { id: "evening", takenAt: new Date("2026-09-21T22:00:00Z") },
  ]);
  assert.equal(p.reason.get("evening"), "daily");
  assert.equal(p.keep.length, 1);
  assert.deepEqual(p.expire.map((b) => b.id).sort(), ["midday", "morning"]);
});

t("one very old backup is still kept as the newest of its week, until the window passes it", () => {
  const p = planRetention([{ id: "ancient", takenAt: new Date("2020-01-01T00:00:00Z") }]);
  assert.equal(p.expire.length, 0, "the only backup there is never expires");
  assert.equal(p.keep.length, 1);
});

t("nothing ever expires everything", () => {
  for (const n of [1, 2, 7, 8, 40, 400]) {
    const p = planRetention(daily(n));
    assert.ok(p.keep.length >= 1, `${n} backups left nothing`);
    assert.ok(p.keep.length <= DAILY_KEEP + WEEKLY_KEEP, `${n} backups kept ${p.keep.length}`);
  }
});

t("the plan is stable: sweeping twice expires nothing new", () => {
  const first = planRetention(daily(40));
  const second = planRetention(first.keep);
  assert.equal(second.expire.length, 0, `second pass expired ${second.expire.map((b) => b.id).join(",")}`);
  assert.equal(second.keep.length, first.keep.length);
});

t("input order does not matter", () => {
  const rows = daily(20);
  const a = planRetention(rows);
  const b = planRetention([...rows].reverse());
  assert.deepEqual(
    a.keep.map((r) => r.id).sort(),
    b.keep.map((r) => r.id).sort(),
  );
});

t("day and week keys are UTC and anchored, not relative to now", () => {
  assert.equal(dayKey(new Date("2026-09-21T23:59:59Z")), "2026-09-21");
  assert.equal(dayKey(new Date("2026-09-22T00:00:01Z")), "2026-09-22");
  // Monday and the Sunday before it are different weeks; Monday and the Sunday after are the same.
  assert.equal(weekKey(new Date("2026-09-21T00:00:00Z")), weekKey(new Date("2026-09-27T23:59:59Z")));
  assert.notEqual(weekKey(new Date("2026-09-21T00:00:00Z")), weekKey(new Date("2026-09-20T23:59:59Z")));
});

t("expiry is a day of grace, not immediate deletion", () => {
  assert.equal(expiryFor(NOW).getTime() - NOW.getTime(), EXPIRY_GRACE_MS);
  assert.equal(expiryFor(NOW).getTime() - NOW.getTime(), DAY);
});

console.log(fails ? `\n💥 ${fails} failed` : "\n✨ all passed");
process.exit(fails ? 1 : 0);
