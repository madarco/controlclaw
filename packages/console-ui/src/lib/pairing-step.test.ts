import assert from "node:assert/strict";
import { test } from "node:test";
import {
  isUnreadable,
  lookupSlackApp,
  lookupTelegramBot,
  PAIRING_UNREADABLE_MS,
  PAIRING_WAIT_MS,
  pairingPhase,
  slackAppIdOf,
  startChatHref,
  startChatName,
} from "./pairing-step";

const t0 = 1_000_000;

test("a request wins over every other phase", () => {
  assert.equal(pairingPhase({ requests: 1, waitingSince: t0, unreadableSince: t0, now: t0 + PAIRING_WAIT_MS * 2 }), "request");
});

test("waiting, then slow after the wait, then unreadable when the agent stays silent", () => {
  assert.equal(pairingPhase({ requests: 0, waitingSince: t0, unreadableSince: null, now: t0 + 1000 }), "waiting");
  assert.equal(pairingPhase({ requests: 0, waitingSince: t0, unreadableSince: null, now: t0 + PAIRING_WAIT_MS }), "slow");
  assert.equal(pairingPhase({ requests: 0, waitingSince: t0, unreadableSince: t0, now: t0 + PAIRING_UNREADABLE_MS - 1 }), "waiting");
  assert.equal(pairingPhase({ requests: 0, waitingSince: t0, unreadableSince: t0, now: t0 + PAIRING_UNREADABLE_MS }), "unreadable");
});

test("a busy agent is not unreadable: it is restarting and will answer", () => {
  assert.equal(isUnreadable("ok", { busy: true, message: "busy" }), false);
  assert.equal(isUnreadable("ok", { busy: false, message: "pairing list failed" }), true);
  assert.equal(isUnreadable("unreachable", null), true);
  assert.equal(isUnreadable("deferred", null), false);
});

test("links per channel", () => {
  assert.equal(startChatHref({ type: "telegram", username: "marco_bot" }), "https://t.me/marco_bot");
  assert.equal(startChatName({ type: "telegram", username: "marco_bot" }), "@marco_bot");
  assert.equal(startChatHref({ type: "telegram", username: null }), null);
  assert.equal(startChatHref({ type: "slack", appId: "A012AB", teamId: "T01", appName: "ops" }), "https://slack.com/app_redirect?app=A012AB&team=T01");
  assert.equal(startChatHref({ type: "slack", appId: "A012AB", teamId: null, appName: null }), "https://slack.com/app_redirect?app=A012AB");
  assert.equal(startChatHref({ type: "slack", appId: null, teamId: "T01", appName: "ops" }), null);
  assert.equal(startChatHref({ type: "whatsapp", number: "+44 7700 900123" }), "https://wa.me/447700900123");
  assert.equal(startChatHref({ type: "whatsapp", number: null }), null);
});

test("the Slack app id comes out of the app-level token", () => {
  assert.equal(slackAppIdOf("xapp-1-A0123ABCD-1234567890-abcdef"), "A0123ABCD");
  assert.equal(slackAppIdOf("xoxb-123"), null);
});

test("Telegram lookup: a refused token is invalid, a network failure is unknown", async () => {
  assert.deepEqual(await lookupTelegramBot("1:x", async () => ({ status: 200, body: { ok: true, result: { username: "marco_bot" } } })), {
    kind: "ok",
    value: { username: "marco_bot" },
  });
  assert.deepEqual(await lookupTelegramBot("1:x", async () => ({ status: 401, body: { ok: false } })), { kind: "invalid" });
  assert.deepEqual(await lookupTelegramBot("1:x", async () => null), { kind: "unknown" });
  assert.deepEqual(await lookupTelegramBot("1:x", async () => ({ status: 500, body: {} })), { kind: "unknown" });
});

test("Slack lookup: invalid_auth is invalid, other errors are unknown", async () => {
  assert.deepEqual(await lookupSlackApp("xoxb-1", async () => ({ status: 200, body: { ok: true, team_id: "T1", team: "Acme", user: "ops" } })), {
    kind: "ok",
    value: { teamId: "T1", team: "Acme", appName: "ops" },
  });
  assert.deepEqual(await lookupSlackApp("xoxb-1", async () => ({ status: 200, body: { ok: false, error: "invalid_auth" } })), { kind: "invalid" });
  assert.deepEqual(await lookupSlackApp("xoxb-1", async () => ({ status: 200, body: { ok: false, error: "ratelimited" } })), { kind: "unknown" });
});
