import assert from "node:assert/strict";
import { test } from "node:test";
import { setupTokenFrom } from "./setup-token";

test("the setup token from the link's fragment", () => {
  assert.equal(setupTokenFrom("#setup=0a1b2c"), "0a1b2c");
  assert.equal(setupTokenFrom("setup=0a1b2c&x=1"), "0a1b2c");
  assert.equal(setupTokenFrom("#token=0a1b2c"), "");
  assert.equal(setupTokenFrom("#setup=<script>"), "", "only a token's characters");
  assert.equal(setupTokenFrom(""), "");
});
