import assert from "node:assert/strict";
import { test } from "node:test";
import type { FwServiceState } from "./agent/fw-logs-types";
import { fwHistogram, fwPassesLevel, fwRecap, fwServiceTone } from "./firewall-logs";

const s = (over: Partial<FwServiceState>): FwServiceState => ({ id: "proxy", label: "Proxy", about: "", active: "active", sub: "running", result: "success", since: null, restarts: 0, exitStatus: 0, optional: false, ...over });

test("service tone: running, failed, crash loop, starting, stopped, optional off", () => {
  assert.deepEqual(fwServiceTone(s({})), { label: "Running", tone: "allow" });
  assert.equal(fwServiceTone(s({ active: "failed", result: "exit-code" })).label, "Failed");
  assert.deepEqual(fwServiceTone(s({ active: "activating", sub: "auto-restart", result: "exit-code" })), { label: "Restarting", tone: "block" });
  assert.equal(fwServiceTone(s({ active: "activating", sub: "start" })).label, "Starting");
  assert.deepEqual(fwServiceTone(s({ active: "inactive", sub: "dead" })), { label: "Stopped", tone: "ask" });
  assert.deepEqual(fwServiceTone(s({ active: "inactive", sub: "dead", optional: true })), { label: "Off", tone: "muted" });
});

test("level filter: systemd lines always pass", () => {
  const line = (level: "info" | "warn" | "error" | "unit") => ({ time: "", service: "proxy" as const, level, message: "" });
  assert.equal(fwPassesLevel(line("info"), "warn"), false);
  assert.equal(fwPassesLevel(line("warn"), "warn"), true);
  assert.equal(fwPassesLevel(line("warn"), "error"), false);
  assert.equal(fwPassesLevel(line("unit"), "error"), true);
});

test("histogram: lines land in their bucket by level, counts cover every line", () => {
  const end = Date.parse("2026-11-25T10:00:00Z");
  const at = (min: number, level: "info" | "warn" | "error" | "unit") => ({ time: new Date(end - min * 60_000).toISOString(), service: "proxy" as const, level, message: "" });
  const h = fwHistogram([at(1, "error"), at(2, "warn"), at(2, "unit"), at(59, "info"), at(90, "error")], "1h", end);
  assert.equal(h.buckets.length, 12);
  assert.deepEqual(h.buckets[11], { start: end - 5 * 60_000, info: 1, warn: 1, error: 1 });
  // The line from 90 minutes ago (a clock behind) goes in the first bucket, as the counts include it.
  assert.deepEqual(h.buckets[0], { start: end - 60 * 60_000, info: 1, warn: 0, error: 1 });
  assert.equal(h.errors, 2);
  assert.equal(h.warnings, 1);
});

test("recap: the PLAY RECAP counts, or null before the run got there", () => {
  assert.deepEqual(fwRecap(["TASK [x]", "localhost : ok=96   changed=4    unreachable=0    failed=1    skipped=21   rescued=0"]), { ok: 96, changed: 4, unreachable: 0, failed: 1, skipped: 21 });
  assert.equal(fwRecap(["TASK [x]", "ok: [localhost]"]), null);
});
