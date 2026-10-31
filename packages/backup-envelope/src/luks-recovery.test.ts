/**
 * The disk passphrase seal, and the thing that stops it drifting from `cc-seal` on a box.
 * Run: npx tsx src/luks-recovery.test.ts
 */
import assert from "node:assert/strict";
import { LUKS_SEAL_VECTOR, openSealedPassphrase, RECOVERY_KEY_TAG, recoveryKeyTag, sealedTo, sealPassphrase, type SealedPassphrase, sealedToAnotherKey } from "./luks-recovery";
import { sodiumReady, toB64 } from "./sodium";

let fails = 0;
const t = async (name: string, fn: () => void | Promise<void>) => {
  try {
    await fn();
    console.log(`  ok  ${name}`);
  } catch (e) {
    fails++;
    console.error(`FAIL  ${name}\n      ${(e as Error).message}`);
  }
};

await t("a passphrase survives the round trip", async () => {
  const sodium = await sodiumReady();
  const secret = sodium.randombytes_buf(32);
  const pub = toB64(sodium.crypto_scalarmult_base(secret));
  const blob = await sealPassphrase("a-passphrase", pub);
  assert.equal(await openSealedPassphrase(blob, toB64(secret)), "a-passphrase");
});

await t("every seal is different, because the ephemeral key is", async () => {
  const a = await sealPassphrase("same", LUKS_SEAL_VECTOR.recoveryPublicKey);
  const b = await sealPassphrase("same", LUKS_SEAL_VECTOR.recoveryPublicKey);
  assert.notEqual(a.eph, b.eph);
  assert.notEqual(a.ct, b.ct);
});

await t("the checked-in vector still opens", async () => {
  const got = await openSealedPassphrase(LUKS_SEAL_VECTOR.sealed as SealedPassphrase, LUKS_SEAL_VECTOR.recoverySecretKey);
  assert.equal(got, LUKS_SEAL_VECTOR.passphrase);
});

// The one that matters. cc-seal is twenty lines of Node in the Ansible repo, written the way it is
// because it has to run before any package exists on a box. Nothing in CI executes it, so this blob
// — produced by it — is the only thing that notices if the two implementations part company.
await t("a blob produced by cc-seal on a box opens here", async () => {
  const got = await openSealedPassphrase(LUKS_SEAL_VECTOR.sealedByCcSeal as SealedPassphrase, LUKS_SEAL_VECTOR.recoverySecretKey);
  assert.equal(got, LUKS_SEAL_VECTOR.sealedByCcSealOpensTo);
});

await t("the wrong recovery key is refused, and says so in words an owner can act on", async () => {
  const sodium = await sodiumReady();
  const other = toB64(sodium.randombytes_buf(32));
  await assert.rejects(
    () => openSealedPassphrase(LUKS_SEAL_VECTOR.sealed as SealedPassphrase, other),
    /does not open this box's disk/,
  );
});

await t("a truncated ciphertext is refused rather than returning rubbish", async () => {
  const bad = { ...LUKS_SEAL_VECTOR.sealed, ct: LUKS_SEAL_VECTOR.sealed.ct.slice(0, 20) } as SealedPassphrase;
  await assert.rejects(() => openSealedPassphrase(bad, LUKS_SEAL_VECTOR.recoverySecretKey));
});

await t("a future version is refused instead of guessed at", async () => {
  await assert.rejects(
    () => openSealedPassphrase({ ...LUKS_SEAL_VECTOR.sealed, v: 2 } as unknown as SealedPassphrase, LUKS_SEAL_VECTOR.recoverySecretKey),
    /Unknown sealed-passphrase version/,
  );
});

await t("something that is not a recovery key at all is rejected early", async () => {
  await assert.rejects(() => openSealedPassphrase(LUKS_SEAL_VECTOR.sealed as SealedPassphrase, toB64(new Uint8Array(16))), /not a recovery key/);
  await assert.rejects(() => sealPassphrase("x", toB64(new Uint8Array(16))), /not a recovery public key/);
});

await t("the tag of a recovery key is the one the box writes into what it seals, and a blob without one says nothing", async () => {
  assert.equal(await recoveryKeyTag(LUKS_SEAL_VECTOR.recoveryPublicKey), LUKS_SEAL_VECTOR.recoveryKeyTag);
  assert.match(LUKS_SEAL_VECTOR.recoveryKeyTag, RECOVERY_KEY_TAG);
  // Another key has another tag.
  assert.notEqual(await recoveryKeyTag(LUKS_SEAL_VECTOR.recoverySecretKey), LUKS_SEAL_VECTOR.recoveryKeyTag);
  assert.equal(sealedTo({ ...LUKS_SEAL_VECTOR.sealed, to: LUKS_SEAL_VECTOR.recoveryKeyTag }), LUKS_SEAL_VECTOR.recoveryKeyTag);
  // Sealed before the field existed, or not a tag at all: not known.
  for (const blob of [LUKS_SEAL_VECTOR.sealed, { to: "your current key" }, { to: 7 }, null, "x"]) assert.equal(sealedTo(blob), null);
  // The field is not part of the crypto: a blob that carries it opens as before.
  assert.equal(await openSealedPassphrase({ ...LUKS_SEAL_VECTOR.sealed, to: LUKS_SEAL_VECTOR.recoveryKeyTag }, LUKS_SEAL_VECTOR.recoverySecretKey), LUKS_SEAL_VECTOR.passphrase);
});

await t("a key that did not open the blob is named as another key only when the blob names a different one", async () => {
  const named = { ...LUKS_SEAL_VECTOR.sealed, to: LUKS_SEAL_VECTOR.recoveryKeyTag };
  // The right key: nothing to say.
  assert.equal(await sealedToAnotherKey(named, LUKS_SEAL_VECTOR.recoverySecretKey), null);
  // Another key: both tags, for the sentence the owner reads.
  const other = Buffer.alloc(32, 7).toString("base64");
  const said = await sealedToAnotherKey(named, other);
  assert.equal(said?.sealedTo, LUKS_SEAL_VECTOR.recoveryKeyTag);
  assert.match(said?.key ?? "", RECOVERY_KEY_TAG);
  assert.notEqual(said?.key, said?.sealedTo);
  // A blob that names no key, or a key that is not one: not known, so the usual "wrong key" stands.
  assert.equal(await sealedToAnotherKey(LUKS_SEAL_VECTOR.sealed, other), null);
  assert.equal(await sealedToAnotherKey(named, "not base64 at all"), null);
});

if (fails) {
  console.error(`\n${fails} failed`);
  process.exit(1);
}
console.log("\nluks-recovery: all ok");
