/**
 * Confirming a change with the recovery key (T-99).
 * Run: npx tsx src/recovery-confirm.test.ts
 */
import assert from "node:assert/strict";
import { generateRecipientKeypair, randomDataKey, wrapDataKey } from "./envelope";
import { RECOVERY_ANSWER_LENGTH, RECOVERY_CONFIRM_CONTEXT, makeRecoveryAnswer, openRecoveryChallenge, sealRecoveryChallenge } from "./recovery-confirm";
import { fromB64, sodiumReady, toB64, utf8 } from "./sodium";

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

const owner = await generateRecipientKeypair();
const other = await generateRecipientKeypair();
const answer = await makeRecoveryAnswer();
const body = { changeId: "chg_1", subject: "your firewall", summary: "Update the software on your firewall", expiresAt: "2026-09-30T12:10:00.000Z", answer };

await t("an answer is 16 characters of the unambiguous alphabet, and fresh each time", async () => {
  assert.equal(answer.length, RECOVERY_ANSWER_LENGTH);
  assert.match(answer, /^[0-9a-hjkmnp-tv-z]{16}$/);
  assert.notEqual(answer, await makeRecoveryAnswer());
});

await t("the owner's key opens the challenge and reads back what the firewall sealed", async () => {
  const sealed = await sealRecoveryChallenge(body, owner.publicKey);
  assert.deepEqual(await openRecoveryChallenge(sealed, owner.secretKey, "chg_1"), body);
});

await t("another key cannot open it", async () => {
  const sealed = await sealRecoveryChallenge(body, owner.publicKey);
  await assert.rejects(() => openRecoveryChallenge(sealed, other.secretKey, "chg_1"), /cannot open/);
});

await t("a challenge for another change is refused, so the page cannot be pointed at a different one", async () => {
  const sealed = await sealRecoveryChallenge(body, owner.publicKey);
  await assert.rejects(() => openRecoveryChallenge(sealed, owner.secretKey, "chg_2"), /different change/);
});

await t("a wrapped backup data key is not an answer: the opener is not a decryption oracle", async () => {
  const wrapped = await wrapDataKey(await randomDataKey(), owner.publicKey);
  await assert.rejects(() => openRecoveryChallenge(wrapped, owner.secretKey, null), /not a confirmation/);
});

await t("a sealed plaintext without the context line, or with the wrong fields, is refused", async () => {
  const sodium = await sodiumReady();
  const seal = (s: string) => toB64(sodium.crypto_box_seal(utf8(s), fromB64(owner.publicKey)));
  await assert.rejects(() => openRecoveryChallenge(seal(JSON.stringify(body)), owner.secretKey, null), /not a confirmation/);
  await assert.rejects(() => openRecoveryChallenge(seal(`${RECOVERY_CONFIRM_CONTEXT}\n{"changeId":"chg_1"}`), owner.secretKey, null), /not a confirmation/);
  const long = { ...body, answer: `${answer}x` };
  await assert.rejects(() => openRecoveryChallenge(seal(`${RECOVERY_CONFIRM_CONTEXT}\n${JSON.stringify(long)}`), owner.secretKey, null), /not a confirmation/);
});

await t("garbage is a refusal, not a crash", async () => {
  await assert.rejects(() => openRecoveryChallenge("not base64!!", owner.secretKey, null), /cannot open/);
  await assert.rejects(() => openRecoveryChallenge(toB64(new Uint8Array(10)), owner.secretKey, null), /cannot open/);
});

console.log(fails ? `\n💥 ${fails} failed` : "\n✨ all passed");
process.exit(fails ? 1 : 0);
