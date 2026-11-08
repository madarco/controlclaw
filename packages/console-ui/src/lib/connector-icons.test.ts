import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { CONNECTOR_CATALOG } from "./connector-catalog";
import { connectorIconUrl } from "./connector-icons";
import { CONNECTOR_VERSION } from "./connector-version";

const DIR = join(import.meta.dirname, "..", "..", "connector-icons");

test("a logo's URL has the version in its path, and only a service id gets one", () => {
  assert.equal(connectorIconUrl("google_sheets"), `/connector-icons/${CONNECTOR_VERSION}/google_sheets.webp`);
  assert.equal(connectorIconUrl("fusion-api"), `/connector-icons/${CONNECTOR_VERSION}/fusion-api.webp`);
  for (const bad of ["", "../x", "a/b", "A", "a.b", "-a", "x".repeat(65)]) assert.equal(connectorIconUrl(bad), null, bad);
});

test("the catalog's icon flags match the files, and every file is a 64x64 WebP", () => {
  const files = new Set(readdirSync(DIR).filter((f) => f.endsWith(".webp")).map((f) => f.slice(0, -5)));
  const flagged = new Set(CONNECTOR_CATALOG.filter((p) => p.icon).map((p) => p.service));
  // `agent_mail` is left out of CONNECTOR_CATALOG but is in the JSON, so it may have a file.
  assert.deepEqual([...flagged].filter((s) => !files.has(s)), []);
  assert.deepEqual([...files].filter((s) => !flagged.has(s) && s !== "agent_mail"), []);
  for (const s of flagged) assert.ok(connectorIconUrl(s), s);
  for (const s of files) {
    const b = readFileSync(join(DIR, `${s}.webp`));
    assert.equal(b.toString("latin1", 0, 4), "RIFF", s);
    assert.equal(b.toString("latin1", 8, 12), "WEBP", s);
    assert.ok(b.length < 16 * 1024, `${s}: ${b.length} bytes`);
    assert.deepEqual(webpSize(b), [64, 64], s);
  }
});

/** Width and height from a WebP's first chunk (VP8X, VP8L or VP8). */
function webpSize(b: Buffer): [number, number] {
  const chunk = b.toString("latin1", 12, 16);
  if (chunk === "VP8X") return [1 + b.readUIntLE(24, 3), 1 + b.readUIntLE(27, 3)];
  if (chunk === "VP8L") {
    const bits = b.readUInt32LE(21);
    return [1 + (bits & 0x3fff), 1 + ((bits >> 14) & 0x3fff)];
  }
  return [b.readUInt16LE(26) & 0x3fff, b.readUInt16LE(28) & 0x3fff];
}
