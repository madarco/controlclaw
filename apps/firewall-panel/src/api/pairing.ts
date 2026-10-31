import type { Schemas } from "@controlclaw/fw-api";

export type PairAddress = Schemas["PairAddress"];

export const PAIR_ADDRESS_KEY = ["pairing-address"] as const;

function isLocal(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
}

/**
 * The address `controlclaw connect --firewall` takes. The firewall's own answer first (from
 * `PAIR_PROXY_ADDR`, which install.sh writes); else the page's host, unless the page is on
 * localhost (an SSH tunnel), which is not where the agent's machine finds the firewall.
 */
export function pairingUrl(addr: PairAddress | undefined, pageHost: string): string {
  if (addr?.url) return addr.url;
  return `http://${isLocal(pageHost) ? "<firewall address>" : pageHost}:${addr?.port ?? 8801}`;
}
