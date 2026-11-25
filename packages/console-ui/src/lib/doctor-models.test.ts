import { test } from "node:test";
import assert from "node:assert/strict";
import { doctorDefaultChoice } from "./doctor-models";

const included = { id: "a-included", provider: "controlclaw_included", clis: ["claude", "codex", "pi"] as const };
const chatgpt = { id: "z-chatgpt", provider: "openai_codex", clis: ["codex", "pi"] as const };
const anthropic = { id: "m-anthropic", provider: "anthropic", clis: ["claude", "pi"] as const };
const openai = { id: "b-openai", provider: "openai", clis: ["codex", "pi"] as const };
const gateway = { id: "c-gateway", provider: "vercel_gateway", clis: ["claude", "codex", "pi"] as const };

test("a ChatGPT subscription wins over the included tokens, with Codex", () => {
  // The bug: the form started on Claude Code and took the first credential it could run, the included tokens.
  const pick = doctorDefaultChoice([included, chatgpt]);
  assert.equal(pick?.credential.id, "z-chatgpt");
  assert.equal(pick?.cli, "codex");
});

test("an API key before the AI Gateway before the included tokens", () => {
  assert.equal(doctorDefaultChoice([included, gateway, anthropic])?.credential.id, "m-anthropic");
  assert.equal(doctorDefaultChoice([included, gateway, anthropic])?.cli, "claude");
  assert.equal(doctorDefaultChoice([included, gateway])?.credential.id, "c-gateway");
  assert.equal(doctorDefaultChoice([included, gateway])?.cli, "claude");
  assert.equal(doctorDefaultChoice([gateway, openai])?.cli, "codex");
});

test("the same pick whatever the order, and none without credentials", () => {
  assert.equal(doctorDefaultChoice([anthropic, openai])?.credential.id, doctorDefaultChoice([openai, anthropic])?.credential.id);
  assert.equal(doctorDefaultChoice([]), null);
});

test("a form starts on the default and follows the person's choices", async () => {
  const { doctorFormPick } = await import("./doctor-models");
  const all = [included, chatgpt, anthropic];
  assert.equal(doctorFormPick(all, "", "").cli, "codex");
  assert.equal(doctorFormPick(all, "", "").credential?.id, "z-chatgpt");
  // Claude Code chosen: its best credential, the Anthropic key, not the included tokens.
  assert.equal(doctorFormPick(all, "claude", "").credential?.id, "m-anthropic");
  assert.equal(doctorFormPick(all, "claude", "a-included").credential?.id, "a-included");
  // A credential the coding agent cannot run is not kept.
  assert.equal(doctorFormPick(all, "claude", "z-chatgpt").credential?.id, "m-anthropic");
});
