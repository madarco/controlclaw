import assert from "node:assert/strict";
import { test } from "node:test";
import { MIN_PASSWORD, passwordLength } from "./password";

test("characters are counted as the API counts them", () => {
  assert.equal(passwordLength("a long password"), 15);
  // Six emoji: 12 UTF-16 units, but six characters, which the API refuses.
  const six = "🔒".repeat(6);
  assert.equal(six.length, 12);
  assert.ok(passwordLength(six) < MIN_PASSWORD);
});
