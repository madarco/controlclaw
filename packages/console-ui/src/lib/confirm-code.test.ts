import assert from "node:assert/strict";
import { test } from "node:test";
import { extractCode } from "./confirm-code";

test("plain digits stay as they are", () => {
  assert.equal(extractCode("123456"), "123456");
  assert.equal(extractCode(""), "");
});

test("a space, a dash or an en dash between the halves is dropped", () => {
  assert.equal(extractCode("123 456"), "123456");
  assert.equal(extractCode("123-456"), "123456");
  assert.equal(extractCode("123–456"), "123456");
  assert.equal(extractCode("123 456"), "123456");
  assert.equal(extractCode(" 123  456 "), "123456");
});

test("the code is found in the whole message", () => {
  assert.equal(extractCode("Code: 123 456 — expires in 10 minutes"), "123456");
  assert.equal(
    extractCode(
      "ControlClaw: confirm this change to Marco's assistant?\nUpdate the firewall to 4f2a91c (mitm-agent 2026.9.30)\nCode: 482 913\nExpires in 10 minutes.",
    ),
    "482913",
  );
  assert.equal(extractCode("your code is 654-321, thanks"), "654321");
});

test("fewer than 6 digits keeps what is there", () => {
  assert.equal(extractCode("12"), "12");
  assert.equal(extractCode("123 45"), "12345");
  assert.equal(extractCode("1-2-3"), "123");
  assert.equal(extractCode("abc"), "");
});

test("more than 6 digits keeps the first 6", () => {
  assert.equal(extractCode("1234567"), "123456");
  assert.equal(extractCode("123 456 789"), "123456");
});
