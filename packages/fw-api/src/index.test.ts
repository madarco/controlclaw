import assert from "node:assert/strict";
import { test } from "node:test";
import { createFwApi, FwApiError } from "./index";

/** A fetch that answers from a list and keeps what it was asked. */
function fake(answers: Array<[number, unknown]>) {
  const seen: Array<{ url: string; init: RequestInit }> = [];
  const f = (async (url: string, init: RequestInit) => {
    seen.push({ url, init });
    const [status, body] = answers.shift() ?? [500, { error: "no answer" }];
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  return { f, seen };
}

test("a sign-in's CSRF token goes with every write, never with a read", async () => {
  const { f, seen } = fake([
    [200, { ok: true, csrf: "tok" }],
    [200, []],
    [200, { id: "r_1" }],
  ]);
  const api = createFwApi({ baseUrl: "http://fw:8800/", fetch: f });
  await api.post("/api/login", { body: { password: "a long password" } });
  assert.equal(api.csrf(), "tok");
  await api.get("/api/egress/rules");
  await api.patch("/api/egress/rules/{id}", { path: { id: "r 1" }, body: { enabled: false } });
  const headers = seen.map((s) => s.init.headers as Record<string, string>);
  assert.equal(headers[1]?.["x-csrf-token"], undefined);
  assert.equal(headers[2]?.["x-csrf-token"], "tok");
  assert.equal(seen[2]?.url, "http://fw:8800/api/egress/rules/r%201");
  assert.equal(seen[2]?.init.method, "PATCH");
  assert.equal(seen[2]?.init.credentials, "include");
});

test("a query is sent, and a refusal is an FwApiError with the API's message", async () => {
  const { f, seen } = fake([[409, { error: "OpenAI is already set up. Replace its key instead." }]]);
  const api = createFwApi({ fetch: f });
  await assert.rejects(
    api.get("/api/activity", { query: { verdict: "block", limit: 10 } }),
    (e: unknown) => e instanceof FwApiError && e.status === 409 && e.message.startsWith("OpenAI"),
  );
  assert.equal(seen[0]?.url, "/api/activity?verdict=block&limit=10");
});
