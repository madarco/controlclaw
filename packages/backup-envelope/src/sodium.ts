import _sodium from "libsodium-wrappers";

/**
 * The one place libsodium is loaded. `libsodium-wrappers` compiles its WASM at import time and
 * resolves a promise when it is usable, so every entry point in this package awaits this first.
 * It bundles with esbuild and runs unchanged in Node and in a browser, which is the whole reason
 * the envelope lives in a package of its own: the same bytes are produced by an agent box, by the
 * firewall, and by the owner's browser holding the recovery key.
 */
export type Sodium = typeof _sodium;

let loaded: Promise<Sodium> | null = null;

export function sodiumReady(): Promise<Sodium> {
  loaded ??= _sodium.ready.then(() => _sodium);
  return loaded;
}

export function toB64(bytes: Uint8Array): string {
  // Not sodium's own base64: this must work before `ready()` in the tests' error paths, and the
  // strings travel through JSON and a Postgres text column, so plain standard base64 it is.
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return typeof btoa === "function" ? btoa(s) : Buffer.from(bytes).toString("base64");
}

export function fromB64(s: string): Uint8Array {
  if (typeof atob === "function") {
    const raw = atob(s);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }
  return new Uint8Array(Buffer.from(s, "base64"));
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
