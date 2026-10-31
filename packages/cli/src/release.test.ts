import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { releaseVmAgent, verifyMinisign } from "./release.js";

/** A throwaway minisign key, and files signed with it the way `minisign -S` signs them. */
function minisignKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const id = Buffer.from("0123456789abcdef", "hex");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(12);
  const pub = Buffer.concat([Buffer.from("Ed"), id, raw]).toString("base64");
  const sig = (data: Buffer, comment = "controlclaw 1.2.3") => {
    const s = sign(null, createHash("blake2b512").update(data).digest(), privateKey);
    const g = sign(null, Buffer.concat([s, Buffer.from(comment)]), privateKey);
    return `untrusted comment: test\n${Buffer.concat([Buffer.from("ED"), id, s]).toString("base64")}\ntrusted comment: ${comment}\n${g.toString("base64")}\n`;
  };
  return { pub, sig };
}

test("a minisign signature is checked: the file, the key and the trusted comment", () => {
  const k = minisignKey();
  const data = Buffer.from("hello\n");
  verifyMinisign(k.pub, data, k.sig(data));
  assert.throws(() => verifyMinisign(k.pub, Buffer.from("hellO\n"), k.sig(data)), /does not match its signature/);
  assert.throws(() => verifyMinisign(minisignKey().pub, data, k.sig(data)), /does not match/);
  const other = { ...minisignKey() };
  const otherPub = Buffer.from(other.pub, "base64");
  otherPub.fill(1, 2, 10);
  assert.throws(() => verifyMinisign(otherPub.toString("base64"), data, k.sig(data)), /another key/);
  const forged = k.sig(data).replace("trusted comment: controlclaw 1.2.3", "trusted comment: controlclaw 1.2.4");
  assert.throws(() => verifyMinisign(k.pub, data, forged), /trusted comment/);
  assert.throws(() => verifyMinisign("bm90IGEga2V5", data, k.sig(data)), /not a minisign public key/);
});

/**
 * A fixed vector signed by the minisign tool itself (standalone/release/testdata/, whose shell test
 * checks the same one; its secret key was deleted).
 */
const VECTOR = {
  pub: "RWRmZrsat/g/R9H8xsW30FU5oVN03dYDe2mCSsj/50O5531Jmck9dWLe",
  text: "a fixed test vector for the minisign checks (standalone/release/SIGNING.md)\n",
  minisig: "untrusted comment: test vector, its secret key was deleted\nRURmZrsat/g/R+afLuqoiJ28A5HOapnIkVj9oL1LdVOEDiV9Ng2wjnSLSVuDNhQJt1GSfvz03AKD/y+RttlTQOqjhiszXMavLAg=\ntrusted comment: controlclaw 0.0.0-vector\noCo9k8tyCqxvypSnwPYsuvzpsE3/d2c5rJvuGUw2bywT/NKYKVLR27TSNFbkJmD1jjruIewYJRbxTs+ap2giDw==\n",
};

test("a signature made by the minisign tool is accepted, and nothing else", () => {
  const data = Buffer.from(VECTOR.text);
  assert.equal(verifyMinisign(VECTOR.pub, data, VECTOR.minisig), "controlclaw 0.0.0-vector");
  assert.throws(() => verifyMinisign(VECTOR.pub, Buffer.from(VECTOR.text.replace(")", ")!")), VECTOR.minisig), /does not match/);
  assert.throws(
    () => verifyMinisign(VECTOR.pub, data, VECTOR.minisig.replace("controlclaw 0.0.0-vector", "controlclaw 9.9.9")),
    /trusted comment/,
  );
  const lines = VECTOR.minisig.split("\n");
  const legacy = Buffer.from(lines[1], "base64");
  legacy.write("Ed", 0);
  lines[1] = legacy.toString("base64");
  assert.throws(() => verifyMinisign(VECTOR.pub, data, lines.join("\n")), /not a prehashed/);
});

function fakeRelease(files: Record<string, Buffer | string>) {
  const asked: string[] = [];
  const f = (async (url: string) => {
    asked.push(url);
    const name = url.split("/").pop() ?? "";
    const body = files[name];
    return body === undefined ? new Response("no", { status: 404 }) : new Response(body);
  }) as typeof fetch;
  return { f, asked };
}

test("the vm-agent is downloaded for this version and arch, and checked", async () => {
  const k = minisignKey();
  const bin = Buffer.from("\x7fELF vm-agent");
  const sums = Buffer.from(`${createHash("sha256").update(bin).digest("hex")}  vm-agent-aarch64-linux-musl\n`);
  const r = fakeRelease({ SHA256SUMS: sums, "SHA256SUMS.minisig": k.sig(sums), "vm-agent-aarch64-linux-musl": bin });
  const path = await releaseVmAgent({ url: "https://x/v{version}", pubkey: k.pub, version: "1.2.3", arch: "arm64", fetch: r.f });
  assert.ok(path);
  assert.deepEqual(readFileSync(path), bin);
  assert.equal(r.asked[0], "https://x/v1.2.3/SHA256SUMS");
});

test("a bad signature, a bad hash, no signature or another version's stops the download", async () => {
  const k = minisignKey();
  const bin = Buffer.from("vm-agent");
  const sums = Buffer.from(`${createHash("sha256").update(bin).digest("hex")}  vm-agent-x86_64-linux-musl\n`);
  const opts = { url: "https://x", pubkey: k.pub, version: "1.2.3", arch: "x64" };
  const tampered = Buffer.from(sums.toString().replace(/^./, "0"));
  await assert.rejects(
    releaseVmAgent({ ...opts, fetch: fakeRelease({ SHA256SUMS: tampered, "SHA256SUMS.minisig": k.sig(sums), "vm-agent-x86_64-linux-musl": bin }).f }),
    /not signed by the release key/,
  );
  await assert.rejects(
    releaseVmAgent({ ...opts, fetch: fakeRelease({ SHA256SUMS: sums, "SHA256SUMS.minisig": k.sig(sums), "vm-agent-x86_64-linux-musl": Buffer.from("evil") }).f }),
    /does not match the release's SHA256SUMS/,
  );
  await assert.rejects(releaseVmAgent({ ...opts, fetch: fakeRelease({ SHA256SUMS: sums }).f }), /SHA256SUMS.minisig/);
  const old = fakeRelease({ SHA256SUMS: sums, "SHA256SUMS.minisig": k.sig(sums, "controlclaw 1.2.2"), "vm-agent-x86_64-linux-musl": bin });
  await assert.rejects(releaseVmAgent({ ...opts, fetch: old.f }), /for another version \(controlclaw 1.2.2\)/);
});

test("a dev build has no release to download from", async () => {
  assert.equal(await releaseVmAgent({ url: "", pubkey: "" }), null);
});
