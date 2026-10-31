import { Resolver } from "node:dns/promises";
import { lookup } from "node:dns/promises";
import { isIPv4 } from "node:net";
import { connect } from "node:net";

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
}

/**
 * "host:port" with a default port. The host must be an IPv4 address or a hostname: it ends up in
 * nft rules, redsocks' config and the gate's shell command, so nothing else gets through.
 */
export function splitHostPort(raw: string, port: number): { host: string; port: number } {
  const m = /^([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(?::(\d{1,5}))?$/.exec(raw.trim());
  const p = m?.[2] ? Number(m[2]) : port;
  if (!m || p < 1 || p > 65535) throw new Error(`not a host:port (an IPv4 address or a hostname): ${raw}`);
  return { host: m[1]!, port: p };
}

export async function ipv4Of(host: string): Promise<string> {
  if (isIPv4(host)) return host;
  const { address } = await lookup(host, { family: 4 });
  return address;
}

/** Whether the firewall's DNS answers a query. */
export async function dnsAnswers(server: string, name = "example.com"): Promise<Check> {
  const r = new Resolver({ timeout: 3000, tries: 1 });
  r.setServers([server]);
  try {
    const a = await r.resolve4(name);
    return { name: "firewall DNS", ok: true, detail: `${server} answers (${name} → ${a[0]})` };
  } catch (e) {
    const code = (e as { code?: string }).code ?? String(e);
    return { name: "firewall DNS", ok: false, detail: `${server} does not answer (${code})` };
  }
}

/** Whether the proxy takes a CONNECT: it answers 200 even for a host its rules then block. */
export function proxyAnswers(proxy: string, target = "example.com:443"): Promise<Check> {
  const { host, port } = splitHostPort(proxy, 8080);
  return new Promise((resolve) => {
    const done = (ok: boolean, detail: string) => {
      sock.destroy();
      resolve({ name: "firewall proxy", ok, detail });
    };
    const sock = connect({ host, port, timeout: 5000 });
    sock.on("connect", () => sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    sock.once("data", (d: Buffer) => {
      const line = d.toString().split("\r\n")[0] ?? "";
      done(/^HTTP\/1\.[01] 200/.test(line), `${host}:${port} answered "${line}"`);
    });
    sock.on("timeout", () => done(false, `${host}:${port} did not answer`));
    sock.on("error", (e) => done(false, `${host}:${port}: ${e.message}`));
  });
}
