import assert from "node:assert/strict";
import { test } from "node:test";
import { pairingUrl } from "./pairing";

test("the firewall's own address comes first", () => {
  assert.equal(pairingUrl({ open: true, port: 8801, url: "http://10.0.0.5:8801" }, "localhost"), "http://10.0.0.5:8801");
});

test("else the page's host, with the firewall's pairing port", () => {
  assert.equal(pairingUrl({ open: true, port: 9901, url: null }, "fw.lan"), "http://fw.lan:9901");
});

test("the placeholder only when nothing is known", () => {
  assert.equal(pairingUrl({ open: true, port: 8801, url: null }, "127.0.0.1"), "http://<firewall address>:8801");
  assert.equal(pairingUrl(undefined, "localhost"), "http://<firewall address>:8801");
});
