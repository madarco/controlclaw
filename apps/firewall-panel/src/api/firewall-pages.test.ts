import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { FIREWALL_PAGES, firewallPageFromPath } from "./firewall-pages";

test("the panel's pages are the firewall's local_intent PAGES", () => {
  const rs = readFileSync(fileURLToPath(new URL("../../../../rust/bins/mitm-agent/src/core/local_intent.rs", import.meta.url)), "utf8");
  const block = rs.slice(rs.indexOf("pub const PAGES"), rs.indexOf("];", rs.indexOf("pub const PAGES")));
  const names = [...block.matchAll(/\("([a-z-]+)",/g)].map((m) => m[1]);
  assert.deepEqual(names, [...FIREWALL_PAGES]);
});

test("an /open/ path names a page, or nothing", () => {
  assert.equal(firewallPageFromPath("/open/logins"), "logins");
  assert.equal(firewallPageFromPath("/open/content-rules/"), "content-rules");
  assert.equal(firewallPageFromPath("/open/bogus"), null);
  // A bad escape would throw in decodeURIComponent.
  assert.equal(firewallPageFromPath("/open/%E0"), null);
});
