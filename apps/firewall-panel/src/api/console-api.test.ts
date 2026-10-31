import assert from "node:assert/strict";
import { test } from "node:test";
import { FwApiError } from "@controlclaw/fw-api";
import { errorText } from "./client";
import { panelApi } from "./console-api";

test("an area with no API refuses with a readable message", async () => {
  await assert.rejects(panelApi.vm.openAgentWhatsapp({ id: "a" }), /does not have agent pages yet/);
  await assert.rejects(panelApi.firewall.get(), /does not have firewall controls yet/);
});

test("errorText shows the API's own words", () => {
  assert.equal(errorText(new FwApiError(401, "Wrong password", { error: "Wrong password" })), "Wrong password");
  assert.match(errorText(new TypeError("fetch failed")), /did not answer/);
});
