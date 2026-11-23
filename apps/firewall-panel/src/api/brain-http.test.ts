import { test } from "node:test";
import assert from "node:assert/strict";
import { toOverview, toPanelBrain } from "./brain-http";
import { pagesHostname } from "./brain";

test("no brain is a null brain", () => {
  assert.deepEqual(toPanelBrain(null), { brain: null });
});

test("the brain's read becomes the page's view, with no auto save and no waiting change", () => {
  const v = toPanelBrain({
    vmId: "br_1",
    name: "brain",
    address: "10.77.0.9:3100",
    origin: null,
    reachable: true,
    service: { active: true },
    locked: false,
    lockedByAdmin: false,
    stoppedAll: false,
    pages: true,
    pagesUrl: "https://brain.example.com",
    hostname: "brain.example.com",
    version: null,
    model: null,
    models: [{ id: "gpt-5.6-luna", label: "GPT-5.6 Luna", blurb: "Enough for most brains." }],
    needsKey: false,
    agents: [
      { vmId: "a1", name: "atlas", running: true, secured: true, stopped: false, connection: { scope: "read", since: "2026-11-23T10:00:00.000Z", autoCapture: false } },
      { vmId: "a2", name: "nova", running: false, secured: false, stopped: false, connection: null },
    ],
    change: null,
    gateUrl: "http://10.77.0.1:3940/brain/mcp",
    brainError: null,
    autoSave: { available: false, reason: "x" },
  });
  assert.equal(v.brain?.address, "10.77.0.9:3100");
  assert.equal(v.brain?.agents[0]?.connection?.scope, "read");
  assert.equal(v.brain?.agents[0]?.connection?.autoCapture, false);
  assert.equal(v.brain?.agents[1]?.connection, null);
  assert.equal(v.brain?.change, null);
  assert.deepEqual(v.brain?.service, { active: true });
  assert.equal(v.brain?.pagesUrl, "https://brain.example.com");
  assert.equal(v.brain?.error, null);
  assert.equal(v.brain?.autoSaveOff, "x");
  assert.equal(v.brain?.agents[0]?.stopped, false);
  assert.equal(v.brain?.lockedByAdmin, false);
});

test("the overview's kinds are named as people say them", () => {
  const o = toOverview({
    hours: [],
    searches: { today: 1, yesterday: 0, hourly: [] },
    saves: { today: 0, yesterday: 0, hourly: [] },
    answerMs: { today: null, hourly: [] },
    lastSavedAt: null,
    latest: null,
    feed: [{ kind: "changes", id: "c:1", at: "2026-11-23T10:00:00.000Z", changes: [{ key: "person", label: "person", delta: 2 }] }],
    growth: [{ day: "2026-11-23", pages: null, saves: 0 }],
    agents: [],
  });
  const f = o.feed[0];
  assert.equal(f?.kind, "changes");
  if (f?.kind === "changes") assert.equal(f.changes[0]?.label, "People");
});

test("a pasted address becomes the pages' name", () => {
  assert.equal(pagesHostname(" https://Brain.example.com/ "), "Brain.example.com");
  assert.equal(pagesHostname("brain.example.com."), "brain.example.com");
  assert.equal(pagesHostname("http://brain.example.com/__cc/brain?x=1"), "brain.example.com");
  assert.equal(pagesHostname("brain.example.com"), "brain.example.com");
});
