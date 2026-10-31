/**
 * The archive file container and the recovery key's second keypair.
 * Run: npx tsx src/recovery-identity.test.ts
 */
import assert from "node:assert/strict";
import { generateRecipientKeypair, fingerprint } from "./envelope";
import {
  ARCHIVE_FILE_MAGIC,
  archiveFileId,
  encodeArchivePrelude,
  parseArchivePrelude,
  readArchiveFileHead,
  type ArchivePrelude,
} from "./archive-file";
import {
  RECOVERY_REPLAY_WINDOW_MS,
  deriveRecoverySigningKeypair,
  recoveryKeyFingerprint,
  recoveryPublicKeys,
  createRecoveryBodyHasher,
  decodeRecoveryBody,
  encodeRecoveryBody,
  recoveryBodyDigest,
  signRecoveryRequest,
  verifyRecoveryRequest,
} from "./recovery-identity";
import { utf8 } from "./sodium";

let fails = 0;
const t = async (name: string, fn: () => void | Promise<void>) => {
  try {
    await fn();
    console.log(`  ✅ ${name}`);
  } catch (e) {
    fails++;
    console.log(`  ❌ ${name} — ${(e as Error).message}`);
  }
};

const prelude: ArchivePrelude = {
  version: 1,
  envelope: 1,
  kind: "workspace",
  backupId: "bk_1",
  orgId: "org_1",
  sourceBoxId: "vm_1",
  agentName: "Marco's assistant",
  takenAt: "2026-09-21T10:00:00.000Z",
  header: "h".repeat(32),
  manifestHash: "a".repeat(64),
  wraps: [
    { recipient: "firewall", fingerprint: "9c41-ab02-f7d1-e6b0", wrapped: "w".repeat(108) },
    { recipient: "recovery", fingerprint: "3ae7-1b94-c0d2-55f8", wrapped: "v".repeat(108) },
  ],
  plainBytes: 1024,
  cipherBytes: 1100,
  entries: 7,
};

console.log("backup archive file");

await t("a prelude round trips, and the stream that follows it is untouched", () => {
  const stream = Buffer.from("not really ciphertext, but it is opaque here");
  const file = Buffer.concat([Buffer.from(encodeArchivePrelude(prelude)), stream]);
  assert.equal(file.subarray(0, 8).toString("ascii"), ARCHIVE_FILE_MAGIC);
  const head = readArchiveFileHead(file);
  assert.equal(head.kind, "prelude");
  if (head.kind !== "prelude") return;
  assert.deepEqual(head.prelude, prelude);
  assert.deepEqual(file.subarray(head.streamOffset), stream);
});

await t("an archive with no prelude reads as raw rather than failing", () => {
  assert.equal(readArchiveFileHead(Buffer.from("\x00\x00\x01\x02some sealed bytes")).kind, "raw");
  // A short read that cannot yet be told apart is "raw" only when a byte already disagrees.
  assert.equal(readArchiveFileHead(Buffer.from("CCB")).kind, "incomplete");
  assert.equal(readArchiveFileHead(Buffer.from("CCX")).kind, "raw");
});

await t("a prelude that has not all arrived says how much is missing", () => {
  const whole = Buffer.from(encodeArchivePrelude(prelude));
  const head = readArchiveFileHead(whole.subarray(0, whole.length - 10));
  assert.equal(head.kind, "incomplete");
  if (head.kind === "incomplete") assert.equal(head.need, 10);
});

await t("a tampered prelude is refused rather than half-read", () => {
  const whole = Buffer.from(encodeArchivePrelude(prelude));
  // Break the JSON's own structure: the head is read before anything is verified, so it has to
  // fail with a sentence rather than throw a SyntaxError out of the CLI.
  const broken = Buffer.from(whole);
  broken[ARCHIVE_FILE_MAGIC.length + 4] = 0x5b; // `{` -> `[`
  assert.throws(() => readArchiveFileHead(broken), /not readable/);
  // A length that claims far more than the format allows is caught before anything is allocated.
  const huge = Buffer.from(whole);
  huge.writeUInt32BE(0xffffff, 8);
  assert.throws(() => readArchiveFileHead(huge), /wrong size/);
});

await t("a prelude with no wrap, or an unknown kind, is refused", () => {
  assert.throws(() => parseArchivePrelude(JSON.stringify({ ...prelude, wraps: [] })), /no sealed key/);
  assert.throws(() => parseArchivePrelude(JSON.stringify({ ...prelude, kind: "everything" })), /does not know/);
  assert.throws(() => parseArchivePrelude(JSON.stringify({ ...prelude, version: 2 })), /newer version/);
  assert.throws(() => parseArchivePrelude(JSON.stringify({ ...prelude, sourceBoxId: "" })), /no sourceBoxId/);
});

await t("the file id changes when any of the key material does", async () => {
  const id = await archiveFileId(prelude);
  assert.match(id, /^[0-9a-f]{4}(-[0-9a-f]{4}){2}$/);
  assert.equal(id, await archiveFileId({ ...prelude }));
  assert.notEqual(id, await archiveFileId({ ...prelude, sourceBoxId: "vm_2" }));
  assert.notEqual(id, await archiveFileId({ ...prelude, wraps: [prelude.wraps[0]!] }));
});

console.log("\nrecovery identity");

const recovery = await generateRecipientKeypair();

await t("the signing keypair is derived from the recovery key and nothing else", async () => {
  const a = await deriveRecoverySigningKeypair(recovery.secretKey);
  const b = await deriveRecoverySigningKeypair(recovery.secretKey);
  assert.equal(a.publicKey, b.publicKey);
  assert.equal(a.secretKey, b.secretKey);
  const other = await generateRecipientKeypair();
  assert.notEqual((await deriveRecoverySigningKeypair(other.secretKey)).publicKey, a.publicKey);
  // And it is not the X25519 half wearing a hat.
  assert.notEqual(a.publicKey, recovery.publicKey);
});

await t("both public halves come from the one secret the owner keeps", async () => {
  const pub = await recoveryPublicKeys(recovery.secretKey);
  assert.equal(pub.publicKey, recovery.publicKey);
  assert.equal(pub.signingPublicKey, (await deriveRecoverySigningKeypair(recovery.secretKey)).publicKey);
  assert.equal(await fingerprint(pub.publicKey), recovery.fingerprint);
});

await t("the fingerprint the owner compares covers BOTH halves", async () => {
  const pub = await recoveryPublicKeys(recovery.secretKey);
  const mine = await recoveryKeyFingerprint(pub);
  assert.match(mine, /^[0-9a-f]{4}(-[0-9a-f]{4}){3}$/);
  // A control plane that kept the wrap key honest and substituted only the signing key is exactly
  // what this has to catch, and the wrap key's own fingerprint would not.
  const impostor = await deriveRecoverySigningKeypair((await generateRecipientKeypair()).secretKey);
  assert.notEqual(await recoveryKeyFingerprint({ ...pub, signingPublicKey: impostor.publicKey }), mine);
  assert.equal(await fingerprint(pub.publicKey), recovery.fingerprint);
});

console.log("\nsigned recovery requests");

const signing = await deriveRecoverySigningKeypair(recovery.secretKey);
const NOW = 1_780_000_000_000;
const req = { method: "POST", path: "/recovery/firewall-restore", timestamp: NOW, body: utf8("the archive") };

await t("a request signed with the recovery key verifies", async () => {
  const sig = await signRecoveryRequest(signing.secretKey, req);
  assert.deepEqual(await verifyRecoveryRequest(signing.publicKey, sig, req, NOW), { ok: true });
});

await t("a different key, body, path or method does not", async () => {
  const sig = await signRecoveryRequest(signing.secretKey, req);
  const stranger = await deriveRecoverySigningKeypair((await generateRecipientKeypair()).secretKey);
  for (const [what, changed] of [
    ["key", null],
    ["body", { ...req, body: utf8("the archive.") }],
    ["path", { ...req, path: "/recovery/hello" }],
    ["method", { ...req, method: "GET" }],
  ] as const) {
    const v = changed
      ? await verifyRecoveryRequest(signing.publicKey, sig, changed, NOW)
      : await verifyRecoveryRequest(stranger.publicKey, sig, req, NOW);
    assert.equal(v.ok, false, `a changed ${what} still verified`);
    if (!v.ok) assert.equal(v.reason, "bad_signature");
  }
});

await t("a replayed request outside the window is refused, and says why", async () => {
  const sig = await signRecoveryRequest(signing.secretKey, req);
  const late = await verifyRecoveryRequest(signing.publicKey, sig, req, NOW + RECOVERY_REPLAY_WINDOW_MS + 1_000);
  assert.equal(late.ok, false);
  if (!late.ok) {
    assert.equal(late.reason, "stale");
    assert.match(late.message, /clock/);
  }
  // Just inside it is fine, in both directions: the owner's clock may be ahead of the box's.
  assert.equal((await verifyRecoveryRequest(signing.publicKey, sig, req, NOW + RECOVERY_REPLAY_WINDOW_MS - 1_000)).ok, true);
  assert.equal((await verifyRecoveryRequest(signing.publicKey, sig, req, NOW - RECOVERY_REPLAY_WINDOW_MS + 1_000)).ok, true);
});

await t("a body hashed as it streams past signs the same as one held whole", async () => {
  const hasher = await createRecoveryBodyHasher();
  hasher.update(utf8("the "));
  hasher.update(utf8("archive"));
  const streamed = { method: "POST", path: req.path, timestamp: NOW, bodyDigest: hasher.digest() };
  assert.equal(hasher.digest(), await recoveryBodyDigest(utf8("the archive")));
  const sig = await signRecoveryRequest(signing.secretKey, req);
  assert.equal((await verifyRecoveryRequest(signing.publicKey, sig, streamed, NOW)).ok, true);
});

await t("a framed body carries a head and an archive, and neither can be swapped for the other", () => {
  const tail = Buffer.from("sealed bytes");
  const framed = encodeRecoveryBody({ backupId: "bk_1", kind: "firewall" }, tail);
  const { head, tail: back } = decodeRecoveryBody(framed);
  assert.deepEqual(head, { backupId: "bk_1", kind: "firewall" });
  assert.deepEqual(Buffer.from(back), tail);
  assert.throws(() => decodeRecoveryBody(Buffer.from("not a recovery request at all")), /not a recovery request/);
  assert.throws(() => decodeRecoveryBody(framed.subarray(0, 6)), /too short/);
  const lying = Buffer.from(framed);
  lying.writeUInt32BE(0xffff, 8);
  assert.throws(() => decodeRecoveryBody(lying), /wrong size/);
});

await t("a garbled signature is a refusal, not a crash", async () => {
  assert.equal((await verifyRecoveryRequest(signing.publicKey, "not base64 at all!!", req, NOW)).ok, false);
  assert.equal((await verifyRecoveryRequest("also not a key", "AAAA", req, NOW)).ok, false);
});

console.log(fails ? `\n💥 ${fails} failed` : "\n✨ all passed");
process.exit(fails ? 1 : 0);
