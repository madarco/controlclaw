import test from "node:test";
import assert from "node:assert/strict";
import { hueFor, initialsOf, serviceForHost } from "./host-services";

test("the longest matching suffix wins", () => {
  assert.equal(serviceForHost("gmail.googleapis.com")?.name, "Gmail");
  assert.equal(serviceForHost("www.googleapis.com")?.name, "Google");
  assert.equal(serviceForHost("api.telegram.org")?.name, "Telegram");
});

test("a suffix matches whole labels only, and case, a port or a trailing dot do not matter", () => {
  assert.equal(serviceForHost("notgoogle.com"), null);
  assert.equal(serviceForHost("API.GitHub.com:443")?.name, "GitHub");
  assert.equal(serviceForHost("slack.com.")?.name, "Slack");
  assert.equal(serviceForHost("example.org"), null);
});

test("initials and hues", () => {
  assert.equal(initialsOf("Anna Rossi"), "AR");
  assert.equal(initialsOf("marcobot15"), "M");
  assert.equal(initialsOf("personal-ea"), "PE");
  assert.equal(initialsOf("  "), "?");
  assert.equal(hueFor("Anna"), hueFor("Anna"));
  assert.ok(hueFor("Anna") >= 0 && hueFor("Anna") < 360);
});
