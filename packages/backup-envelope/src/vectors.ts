import {
  bindingAad,
  generateRecipientKeypair,
  makeDecryptor,
  makeEncryptor,
  publicKeyOf,
  randomDataKey,
  rewrapDataKey,
  unwrapDataKey,
  wrapDataKey,
  type EnvelopeBinding,
} from "./envelope";
import { fromB64, toB64 } from "./sodium";

/**
 * The envelope's test vectors as a plain function, so the SAME assertions run under `tsx` in Node
 * and inside a real browser (`app/demo/backup-crypto` + `e2e/backups-crypto.spec.ts`). The rewrap
 * is the reason: it is the one operation that runs in the owner's browser and nowhere else, and a
 * WASM build that behaves differently there would be found by nothing else we have.
 */

export interface VectorResult {
  name: string;
  ok: boolean;
  error?: string;
}

const BINDING: EnvelopeBinding = { orgId: "org_1", vmId: "vm_1", backupId: "bk_1", kind: "workspace" };

function assert(cond: unknown, message: string): void {
  if (!cond) throw new Error(message);
}

async function sealed(dataKey: string, binding: EnvelopeBinding, plain: Uint8Array): Promise<{ header: string; blob: Uint8Array }> {
  const enc = await makeEncryptor(dataKey, binding);
  const parts: Uint8Array[] = [];
  for (let i = 0; i < plain.length; i += 1024) parts.push(enc.push(plain.subarray(i, Math.min(i + 1024, plain.length))));
  parts.push(enc.final());
  const total = parts.reduce((n, p) => n + p.length, 0);
  const blob = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    blob.set(p, at);
    at += p.length;
  }
  return { header: enc.header, blob };
}

async function opened(dataKey: string, header: string, binding: EnvelopeBinding, blob: Uint8Array, sliceAt = 7919): Promise<Uint8Array> {
  const dec = await makeDecryptor(dataKey, header, binding);
  const out: Uint8Array[] = [];
  // Deliberately ragged slices: a real download never hands over whole frames.
  for (let i = 0; i < blob.length; i += sliceAt) out.push(...dec.push(blob.subarray(i, Math.min(i + sliceAt, blob.length))));
  dec.end();
  const total = out.reduce((n, p) => n + p.length, 0);
  const joined = new Uint8Array(total);
  let at = 0;
  for (const p of out) {
    joined.set(p, at);
    at += p.length;
  }
  return joined;
}

async function refuses(name: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
  } catch {
    return;
  }
  throw new Error(`${name}: it was accepted`);
}

const CASES: { name: string; run: () => Promise<void> }[] = [
  {
    name: "a sealed archive round-trips byte for byte",
    run: async () => {
      const plain = new Uint8Array(40_000);
      for (let i = 0; i < plain.length; i++) plain[i] = (i * 31 + 7) & 0xff;
      const key = await randomDataKey();
      const { header, blob } = await sealed(key, BINDING, plain);
      assert(blob.length > plain.length, "the blob carries per-chunk overhead");
      assert(!toB64(blob).includes(toB64(plain).slice(8, 40)), "the plaintext is not in the blob");
      const back = await opened(key, header, BINDING, blob);
      assert(back.length === plain.length, `got ${back.length} of ${plain.length} bytes back`);
      for (let i = 0; i < plain.length; i++) assert(back[i] === plain[i], `byte ${i} differs`);
    },
  },
  {
    name: "an empty archive round-trips",
    run: async () => {
      const key = await randomDataKey();
      const { header, blob } = await sealed(key, BINDING, new Uint8Array(0));
      assert((await opened(key, header, BINDING, blob)).length === 0, "empty stayed empty");
    },
  },
  {
    name: "a blob bound to another backup is refused",
    run: async () => {
      const key = await randomDataKey();
      const { header, blob } = await sealed(key, BINDING, new Uint8Array([1, 2, 3]));
      for (const wrong of [
        { ...BINDING, backupId: "bk_2" },
        { ...BINDING, vmId: "vm_2" },
        { ...BINDING, orgId: "org_2" },
        { ...BINDING, kind: "state" as const },
      ]) {
        await refuses(`aad ${bindingAad(wrong).slice(-24)}`, () => opened(key, header, wrong, blob));
      }
    },
  },
  {
    name: "a truncated archive is refused, not half-restored",
    run: async () => {
      const key = await randomDataKey();
      const plain = new Uint8Array(9_000).fill(9);
      const { header, blob } = await sealed(key, BINDING, plain);
      // Every prefix short of the whole thing: mid-frame and (the dangerous one) exactly on a
      // frame boundary, where the bytes so far decrypt cleanly and only the FINAL tag is missing.
      await refuses("prefix without the final frame", () => opened(key, header, BINDING, blob.subarray(0, blob.length - 20)));
      await refuses("one byte short", () => opened(key, header, BINDING, blob.subarray(0, blob.length - 1)));
      await refuses("header only", () => opened(key, header, BINDING, new Uint8Array(0)));
    },
  },
  {
    name: "bytes appended after the end are refused",
    run: async () => {
      const key = await randomDataKey();
      const { header, blob } = await sealed(key, BINDING, new Uint8Array([4, 5, 6]));
      const extra = new Uint8Array(blob.length + blob.length);
      extra.set(blob);
      extra.set(blob, blob.length);
      await refuses("doubled blob", () => opened(key, header, BINDING, extra));
    },
  },
  {
    name: "a flipped bit anywhere is refused",
    run: async () => {
      const key = await randomDataKey();
      const { header, blob } = await sealed(key, BINDING, new Uint8Array(3_000).fill(2));
      for (const at of [4, 100, blob.length - 5]) {
        const tampered = new Uint8Array(blob);
        tampered[at] = tampered[at]! ^ 0x01;
        await refuses(`bit at ${at}`, () => opened(key, header, BINDING, tampered));
      }
    },
  },
  {
    name: "the wrong data key is refused",
    run: async () => {
      const key = await randomDataKey();
      const other = await randomDataKey();
      const { header, blob } = await sealed(key, BINDING, new Uint8Array([7]));
      await refuses("other data key", () => opened(other, header, BINDING, blob));
    },
  },
  {
    name: "each recipient can unwrap the data key; nobody else can",
    run: async () => {
      const firewall = await generateRecipientKeypair();
      const recovery = await generateRecipientKeypair();
      const stranger = await generateRecipientKeypair();
      const key = await randomDataKey();
      const forFirewall = await wrapDataKey(key, firewall.publicKey);
      const forRecovery = await wrapDataKey(key, recovery.publicKey);
      assert(forFirewall !== forRecovery, "sealed boxes are not deterministic across recipients");
      assert((await unwrapDataKey(forFirewall, firewall.secretKey)) === key, "the firewall unwraps its own");
      assert((await unwrapDataKey(forRecovery, recovery.secretKey)) === key, "the recovery key unwraps its own");
      await refuses("stranger", () => unwrapDataKey(forFirewall, stranger.secretKey));
      await refuses("crossed recipients", () => unwrapDataKey(forFirewall, recovery.secretKey));
    },
  },
  {
    name: "a recovery key's public half is derivable, so only the secret has to be saved",
    run: async () => {
      const kp = await generateRecipientKeypair();
      assert((await publicKeyOf(kp.secretKey)) === kp.publicKey, "derived public key matches");
    },
  },
  {
    name: "rewrapping to a rebuilt firewall opens the same archive",
    run: async () => {
      const oldFirewall = await generateRecipientKeypair();
      const recovery = await generateRecipientKeypair();
      const key = await randomDataKey();
      const plain = new Uint8Array(5_000).fill(3);
      const { header, blob } = await sealed(key, BINDING, plain);
      const wraps = {
        firewall: await wrapDataKey(key, oldFirewall.publicKey),
        recovery: await wrapDataKey(key, recovery.publicKey),
      };
      // The firewall was rebuilt: a brand-new keypair that has never seen this data key.
      const newFirewall = await generateRecipientKeypair();
      await refuses("the new firewall cannot unwrap the old wrap", () => unwrapDataKey(wraps.firewall, newFirewall.secretKey));
      // The owner pastes the recovery key; only this new wrap leaves the page.
      const rewrapped = await rewrapDataKey({ wrapped: wraps.recovery, secretKey: recovery.secretKey, toPublicKey: newFirewall.publicKey });
      assert(rewrapped !== wraps.recovery, "the rewrap is a new sealed box");
      assert((await unwrapDataKey(rewrapped, newFirewall.secretKey)) === key, "the new firewall now holds the data key");
      const back = await opened(await unwrapDataKey(rewrapped, newFirewall.secretKey), header, BINDING, blob);
      assert(back.length === plain.length, "and the archive opens");
    },
  },
  {
    name: "a rewrap with the wrong recovery key fails instead of producing a useless wrap",
    run: async () => {
      const recovery = await generateRecipientKeypair();
      const wrong = await generateRecipientKeypair();
      const target = await generateRecipientKeypair();
      const wrapped = await wrapDataKey(await randomDataKey(), recovery.publicKey);
      await refuses("wrong recovery key", () => rewrapDataKey({ wrapped, secretKey: wrong.secretKey, toPublicKey: target.publicKey }));
    },
  },
  {
    name: "corrupt input reads as corrupt input, not as the wrong key",
    run: async () => {
      const kp = await generateRecipientKeypair();
      const wrapped = await wrapDataKey(await randomDataKey(), kp.publicKey);
      // A caller that pre-flights an unwrap turns any throw into "you need your recovery key", so
      // every one of these has to be the envelope's own sentence rather than a raw sodium or base64
      // error escaping from outside the try.
      for (const [wrap, secret] of [
        ["not base64 at all!!", kp.secretKey],
        [wrapped, "not base64 at all!!"],
        [wrapped, toB64(new Uint8Array(16))],
        ["", kp.secretKey],
        [toB64(new Uint8Array(4)), kp.secretKey],
      ] as Array<[string, string]>) {
        let message = "";
        try {
          await unwrapDataKey(wrap, secret);
        } catch (e) {
          message = (e as Error).message;
        }
        assert(message === "This key cannot open that backup.", `got "${message}" for ${wrap.slice(0, 8)}/${secret.slice(0, 8)}`);
      }
    },
  },
  {
    name: "base64 helpers round-trip every byte value",
    run: async () => {
      const all = new Uint8Array(256);
      for (let i = 0; i < 256; i++) all[i] = i;
      const back = fromB64(toB64(all));
      for (let i = 0; i < 256; i++) assert(back[i] === i, `byte ${i}`);
    },
  },
];

export async function runEnvelopeVectors(): Promise<VectorResult[]> {
  const out: VectorResult[] = [];
  for (const c of CASES) {
    try {
      await c.run();
      out.push({ name: c.name, ok: true });
    } catch (e) {
      out.push({ name: c.name, ok: false, error: (e as Error).message });
    }
  }
  return out;
}
