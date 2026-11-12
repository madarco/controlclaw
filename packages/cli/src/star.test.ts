import assert from "node:assert/strict";
import { test } from "node:test";
import type { Io } from "./commands.js";
import type { Ask } from "./menu.js";
import { STAR_URL, starPrompt, starStatePath } from "./star.js";
import { FakeSys } from "./sys.js";

function io(): Io & { lines: string[] } {
  const lines: string[] = [];
  return { lines, out: (l) => lines.push(l), err: (l) => lines.push(l) };
}

/** Answers each question with the next of `answers`; counts the questions. */
function answering(...answers: (string | null)[]): Ask & { asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    pick: async () => null,
    line: async (prompt) => {
      asked.push(prompt);
      return answers.length ? answers.shift()! : null;
    },
  };
}

const state = (sys: FakeSys) => JSON.parse(sys.read(starStatePath(sys)) ?? "null");

test("no terminal: no question, no file", async () => {
  const sys = new FakeSys();
  const ask = answering("y");
  await starPrompt(sys, io(), ask, false);
  assert.equal(ask.asked.length, 0);
  assert.equal(sys.read(starStatePath(sys)), null);
});

test("answered before: no question", async () => {
  const sys = new FakeSys();
  sys.write(starStatePath(sys), JSON.stringify({ version: 1, asked: 1, answered: true, starred: false }));
  const ask = answering("y");
  await starPrompt(sys, io(), ask, true);
  assert.equal(ask.asked.length, 0);
});

test("asked on two runs without an answer: not on the third", async () => {
  const sys = new FakeSys();
  const ask = answering(null, null, "y");
  for (let i = 0; i < 3; i++) await starPrompt(sys, io(), ask, true);
  assert.equal(ask.asked.length, 2);
  assert.deepEqual(state(sys), { version: 1, asked: 2, answered: false, starred: false });
  assert.deepEqual(sys.ran(), []);
});

test("no: settled, gh not run", async () => {
  const sys = new FakeSys();
  const out = io();
  await starPrompt(sys, out, answering("n"), true);
  assert.deepEqual(state(sys), { version: 1, asked: 1, answered: true, starred: false });
  assert.deepEqual(sys.ran(), []);
  assert.deepEqual(out.lines, []);
});

test("yes (the default) with gh signed in: stars it with gh", async () => {
  const sys = new FakeSys();
  const out = io();
  const ask = answering("maybe", "");
  await starPrompt(sys, out, ask, true);
  assert.equal(ask.asked.length, 2, "asked again after an answer that is neither");
  assert.deepEqual(sys.ran(), ["gh auth status --hostname github.com", "gh api --method PUT /user/starred/madarco/controlclaw"]);
  assert.deepEqual(out.lines, ["Starred madarco/controlclaw. Thank you!"]);
  assert.deepEqual(state(sys), { version: 1, asked: 1, answered: true, starred: true });
});

test("yes without gh: the URL, no star call", async () => {
  const sys = new FakeSys().on("gh auth status", { code: 1 });
  const out = io();
  await starPrompt(sys, out, answering("y"), true);
  assert.deepEqual(sys.ran(), ["gh auth status --hostname github.com"]);
  assert.deepEqual(out.lines, [`Star it at ${STAR_URL}`]);
  assert.equal(state(sys).starred, false);
});

test("yes, the gh call fails: the URL", async () => {
  const sys = new FakeSys().on("gh api", { code: 1, stderr: "HTTP 401" });
  const out = io();
  await starPrompt(sys, out, answering("yes"), true);
  assert.deepEqual(out.lines, [`Star it at ${STAR_URL}`]);
  assert.equal(state(sys).starred, false);
});

test("the state file cannot be written: no throw, the URL", async () => {
  const sys = new FakeSys();
  sys.write = () => {
    throw new Error("EACCES");
  };
  const out = io();
  await starPrompt(sys, out, answering("y"), true);
  assert.deepEqual(out.lines, [`Star it anytime at ${STAR_URL}`]);
});

test("under sudo: gh runs as SUDO_USER, the answer kept in their home, not in /etc/controlclaw", async () => {
  const sys = new FakeSys();
  sys.files.set("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nana:x:1000:1000::/home/ana:/bin/bash\n");
  sys.env = { SUDO_USER: "ana" };
  await starPrompt(sys, io(), answering("y"), true);
  const path = "/home/ana/.local/state/controlclaw/star-prompt.json";
  assert.equal(starStatePath(sys), path);
  assert.ok(sys.ran().includes(`as ana write ${path}`));
  assert.ok(sys.ran().includes("runuser -u ana -- env HOME=/home/ana XDG_RUNTIME_DIR=/run/user/1000 gh api --method PUT /user/starred/madarco/controlclaw"));
  assert.equal(sys.stat(path)?.uid, 1000);
  assert.ok(!sys.exists("/etc/controlclaw"));
});
