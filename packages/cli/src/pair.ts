import { createHash, createHmac, generateKeyPairSync, randomBytes, timingSafeEqual, X509Certificate } from "node:crypto";
import { createSocket } from "node:dgram";
import { networkInterfaces } from "node:os";
import { isIPv4 } from "node:net";

/**
 * Pairing with a one-time code (cc-local's `pairing.rs` has the firewall's side and the reasoning).
 * The code never crosses the network: the request carries an HMAC made with it, and the firewall's
 * answer is taken only when its HMAC, made with the same code, checks and it echoes our nonce. So
 * the firewall's key and CA that the agent pins come from whoever made the code, even over plain HTTP.
 */

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export const REQUEST_TAG = "cc-pair-v1 request\n";
export const RESPONSE_TAG = "cc-pair-v1 response\n";

/** The code as the HMAC key, as the firewall reads it: upper case, no dashes, O as 0, I and L as 1. */
export function normalizeCode(code: string): string | null {
  const s = code
    .replace(/[-\s]/g, "")
    .toUpperCase()
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
  return s.length === 12 && [...s].every((c) => ALPHABET.includes(c)) ? s : null;
}

export function hmacHex(code: string, tag: string, text: string): string {
  return createHmac("sha256", code).update(tag).update(text).digest("hex");
}

/** A WireGuard key pair (X25519), base64 as `wg genkey` / `wg pubkey` print them. */
export function wgKeypair(): { privateKey: string; publicKey: string } {
  const { privateKey, publicKey } = generateKeyPairSync("x25519", {
    privateKeyEncoding: { type: "pkcs8", format: "der" },
    publicKeyEncoding: { type: "spki", format: "der" },
  });
  // The raw 32 bytes end both DER forms.
  return { privateKey: privateKey.subarray(-32).toString("base64"), publicKey: publicKey.subarray(-32).toString("base64") };
}

/** The vm-agent's own key pair, as `ensure_vm_keypair` writes it: PKCS#8 and SPKI PEM. */
export function agentKeypair(): { privatePem: string; publicPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return { privatePem: privateKey, publicPem: publicKey };
}

export interface PairRequest {
  publicKey: string;
  name?: string;
  /**
   * This machine's own address toward the firewall. Under the proof: the firewall refuses a request
   * that arrives from another address (a replay, or a NAT the admin did not name on the code).
   */
  source?: string;
  /** A secret kept on this machine; the firewall keeps its hash, and forgets the agent for it. */
  unpairSecret?: string;
  /** Remote mode: this machine's WireGuard public key; the firewall gives it a tunnel address. */
  wgPublicKey?: string;
  /** `ip:port` where the vm-agent listens for the firewall's calls (else the agent's address, 3100). */
  agentListen?: string;
}

/** The tunnel, when pairing was over WireGuard. */
export interface PairedTunnel {
  firewallPublicKey: string;
  endpoint: string;
  /** This machine's tunnel address: its identity at the proxy. */
  address: string;
  firewallAddress: string;
}

export interface Paired {
  agentId: string;
  name: string;
  address: string;
  firewallPublicKey: string;
  caPem: string;
  proxy: string | null;
  dns: string | null;
  /** Agents the firewall had at this address before: this one replaces them. */
  replaced: string[];
  /** The address the firewall calls the vm-agent from (its own toward `agent_listen`). */
  callsFrom?: string | null;
  wg: PairedTunnel | null;
}

export type Post = (url: string, body: unknown) => Promise<{ status: number; json: unknown }>;

export const httpPost: Post = async (url, body) => {
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
  return { status: r.status, json: await r.json().catch(() => null) };
};

/** The pairing endpoint: `pair` under the firewall's address (a path in it is kept, for a reverse proxy). */
export function pairUrl(firewall: string): string {
  const base = new URL(firewall);
  if (!base.pathname.endsWith("/")) base.pathname += "/";
  return new URL("pair", base).toString();
}

export async function pair(firewall: string, code: string, req: PairRequest, post: Post = httpPost): Promise<Paired> {
  const key = normalizeCode(code);
  if (!key) throw new Error("the code is 12 letters and digits, like 4F7K-92QD-XM3P");
  const nonce = randomBytes(32).toString("hex");
  if (!req.source) throw new Error("this machine's own address toward the firewall is not known");
  const unpairSha = req.unpairSecret ? createHash("sha256").update(req.unpairSecret).digest("hex") : null;
  const text = JSON.stringify({ v: 1, nonce, agent_public_key: req.publicKey, name: req.name ?? null, source: req.source, unpair_sha256: unpairSha, wg_public_key: req.wgPublicKey ?? null, agent_listen: req.agentListen ?? null });
  const url = pairUrl(firewall);
  let r: { status: number; json: unknown };
  try {
    r = await post(url, { request: text, proof: hmacHex(key, REQUEST_TAG, text) });
  } catch (e) {
    throw new Error(`could not reach ${url}: ${(e as Error).message}`, { cause: e });
  }
  const body = (r.json ?? {}) as { pairing?: unknown; mac?: unknown; error?: unknown };
  if (r.status !== 200) throw new Error(`the firewall refused: ${typeof body.error === "string" ? body.error : `HTTP ${r.status}`}`);
  if (typeof body.pairing !== "string" || typeof body.mac !== "string") throw new Error("the firewall's answer is not a pairing");
  const want = Buffer.from(hmacHex(key, RESPONSE_TAG, body.pairing), "hex");
  const got = Buffer.from(body.mac, "hex");
  if (got.length !== want.length || !timingSafeEqual(got, want)) {
    throw new Error("the answer was not made with this code: it did not come from your firewall. Nothing was installed.");
  }
  const p = JSON.parse(body.pairing) as Record<string, unknown>;
  if (p.nonce !== nonce) throw new Error("the answer is not for this request (another nonce). Nothing was installed.");
  const str = (k: string) => (typeof p[k] === "string" ? (p[k] as string) : null);
  const agentId = str("agent_id");
  const fwKey = str("firewall_public_key");
  const caPem = str("ca_pem");
  if (!agentId || !fwKey?.includes("BEGIN PUBLIC KEY") || !caPem) throw new Error("the firewall's answer misses its key, its CA or the agent id");
  return {
    agentId,
    name: str("name") ?? agentId,
    address: str("address") ?? "",
    firewallPublicKey: fwKey.trim(),
    caPem,
    proxy: str("proxy"),
    dns: str("dns"),
    replaced: Array.isArray(p.replaced) ? p.replaced.filter((x): x is string => typeof x === "string") : [],
    wg: tunnelOf(p.wg),
    // Only an IPv4 address goes into the vm-agent's config; anything else is dropped (then the
    // address connect dialled is used).
    callsFrom: isIPv4(str("calls_from") ?? "") ? str("calls_from") : null,
  };
}

const WG_KEY = /^[A-Za-z0-9+/]{43}=$/;
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

/** The tunnel in the answer, checked: these values end up in a WireGuard config and nft rules. */
function tunnelOf(v: unknown): PairedTunnel | null {
  if (!v || typeof v !== "object") return null;
  const w = v as Record<string, unknown>;
  const ok =
    typeof w.firewall_public_key === "string" && WG_KEY.test(w.firewall_public_key) &&
    typeof w.endpoint === "string" && /^[A-Za-z0-9.-]+:\d{1,5}$/.test(w.endpoint) &&
    typeof w.address === "string" && IPV4.test(w.address) &&
    typeof w.firewall_address === "string" && IPV4.test(w.firewall_address);
  if (!ok) throw new Error("the firewall's WireGuard settings are not valid");
  return { firewallPublicKey: w.firewall_public_key as string, endpoint: w.endpoint as string, address: w.address as string, firewallAddress: w.firewall_address as string };
}

/** Asks the firewall to forget the agent: null when it did, else why not. */
export async function unpair(firewall: string, agentId: string, secret: string, post: Post = httpPost): Promise<string | null> {
  const url = new URL("unpair", pairUrl(firewall)).toString();
  try {
    const r = await post(url, { agent_id: agentId, secret });
    if (r.status === 200) return null;
    const e = (r.json as { error?: unknown } | null)?.error;
    return typeof e === "string" ? e : `HTTP ${r.status}`;
  } catch (e) {
    return `could not reach ${url}: ${(e as Error).message}`;
  }
}

/** The address this machine sends from toward `ip` (no packet is sent: a UDP socket is only routed). */
export function sourceToward(ip: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = createSocket("udp4");
    s.on("error", (e) => {
      s.close();
      reject(e);
    });
    s.connect(9, ip, () => {
      const { address } = s.address();
      s.close();
      resolve(address);
    });
  });
}

/**
 * Whether the firewall at `ip` is on this machine, reached from `source` (`sourceToward`): `ip` is
 * one of this machine's addresses, or `source` is this machine's address on a Docker bridge
 * (`docker0`, `br-…`), so the firewall is a container here. Across a network it is neither.
 */
export function onThisMachine(ip: string, source: string, ifaces: ReturnType<typeof networkInterfaces> = networkInterfaces()): boolean {
  const all = Object.entries(ifaces).flatMap(([name, list]) => (list ?? []).filter((a) => a.family === "IPv4").map((a) => ({ name, address: a.address })));
  if (all.some((a) => a.address === ip)) return true;
  const via = all.find((a) => a.address === source);
  return !!via && /^(docker\d*|br-[0-9a-f]+)$/.test(via.name);
}

/** SHA-256 of the CA, as the firewall logs it at start, to compare by eye. */
export function caFingerprint(pem: string): string {
  try {
    return new X509Certificate(pem).fingerprint256;
  } catch {
    return "(not a certificate)";
  }
}
