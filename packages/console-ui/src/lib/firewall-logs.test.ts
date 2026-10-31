import assert from "node:assert/strict";
import { test } from "node:test";
import type { FwServiceState } from "@controlclaw/console-ui/lib/agent/fw-logs-types";
import { fwPassesLevel, fwServiceTone } from "./firewall-logs";

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
