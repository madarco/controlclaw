import { randomBytes } from "node:crypto";
import { connect } from "node:net";
import { composeAtLeast, dockerTooOld } from "./capture/docker.js";
import type { Io, PairNet } from "./commands.js";
import { agentKeypair, type Paired, pair } from "./pair.js";
import type { Sys } from "./sys.js";

declare const __CC_CLI_VERSION__: string;
const VERSION = typeof __CC_CLI_VERSION__ === "string" ? __CC_CLI_VERSION__ : "0.0.0-dev";

/**
 * The firewall as a container on this machine: what `up` and `up --local` share. The image is the
 * release of the CLI's own version (standalone/release/release.conf's CC_IMAGE), pulled when missing.
 */
export const FIREWALL_IMAGE = "ghcr.io/madarco/controlclaw-firewall";

/** The image of this CLI's release; null in a dev build, which has none. */
export function releaseImage(version: string = VERSION): string | null {
  return /^\d+\.\d+\.\d+$/.test(version) ? `${FIREWALL_IMAGE}:${version}` : null;
}

/** `docker compose` for a project whose compose.yaml is in `dir`. */
export function composeIn(project: string, dir: string): (...args: string[]) => string[] {
  return (...args) => ["docker", "compose", "-p", project, "--project-directory", dir, "-f", `${dir}/compose.yaml`, ...args];
}

export async function hasImage(sys: Sys, image: string): Promise<boolean> {
  return (await sys.run(["docker", "image", "inspect", "--format", "{{.Id}}", image])).code === 0;
}

/** Pulls the image when it is not here. Throws with Docker's reason. */
export async function ensureImage(sys: Sys, io: Io, image: string): Promise<void> {
  if (await hasImage(sys, image)) return;
  io.out(`Pulling ${image}`);
  const p = await sys.run(["docker", "pull", "-q", image], { timeoutMs: 900_000 });
  if (p.code !== 0) throw new Error(`docker pull ${image}: ${p.stderr.trim().split("\n").pop()}`);
}

/** Why Docker here cannot run the firewall's networks; null when it can. `what` names the command. */
export async function dockerProblem(sys: Sys, what: string): Promise<string | null> {
  const v = await sys.run(["docker", "compose", "version", "--short"]);
  if (v.code !== 0 || !composeAtLeast(v.stdout.trim(), 2, 24, 4)) return `${what} needs Docker with Compose 2.24.4 or newer (found: ${v.stdout.trim() || "none"}).`;
  const server = await sys.run(["docker", "version", "--format", "{{.Server.Version}}"]);
  if (server.code !== 0) return `Docker does not answer: ${server.stderr.trim()}`;
  const old = dockerTooOld(server.stdout.trim());
  if (old) return `${what} ${old}.`;
  return null;
}

/**
 * Rootless Docker keeps its bridges in a namespace of its own: this machine has no address on the
 * firewall's network, so the vm-agent could not listen there for the firewall's calls.
 */
export async function rootlessDocker(sys: Sys): Promise<boolean> {
  const r = await sys.run(["docker", "info", "--format", "{{json .SecurityOptions}}"]);
  return r.code === 0 && r.stdout.includes("rootless");
}

/** Whether a container's healthcheck passes; `noCheck`: what a container without one counts as. */
export async function containerHealthy(sys: Sys, container: string, noCheck = false): Promise<boolean> {
  const r = await sys.run(["docker", "inspect", "-f", "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", container]);
  const s = r.stdout.trim();
  return s === "healthy" || (noCheck && (s === "none" || r.code !== 0));
}

export async function waitFor(sys: Sys, what: string, tries: number, test: () => Promise<boolean>): Promise<void> {
  for (let i = 0; i < tries; i++) {
    if (await test()) return;
    await sys.run(["sleep", "2"]);
  }
  throw new Error(`${what} did not come up`);
}

/** Until the firewall in `service` has its database and its key: then it can make a code. */
export function waitFirewall(sys: Sys, compose: (...a: string[]) => string[], service = "firewall"): Promise<void> {
  return waitFor(sys, "the firewall", 45, async () => {
    const r = await sys.run(compose("exec", "-T", "-u", "controlclaw", service, "sh", "-c", "test -s /opt/controlclaw/state/local.db && test -s /opt/controlclaw/keys/vm_public_key.pem"));
    return r.code === 0;
  });
}

export interface PairedHere {
  paired: Paired;
  keypair: { privatePem: string; publicPem: string };
  unpairSecret: string;
}

/**
 * Pairs with the firewall in a container here, with no typed code: one made inside the container,
 * with the address the proxy will see the agent at (`--replace`: a machine set up again keeps it),
 * then the pairing over this machine's loopback.
 */
export async function pairHere(
  sys: Sys,
  compose: (...a: string[]) => string[],
  o: { name: string; address: string; listen?: string; url: string },
  net: PairNet,
): Promise<PairedHere> {
  const made = await sys.run(compose("exec", "-T", "-u", "controlclaw", "firewall", "mitm-agent", "pair-code", "--name", o.name, "--address", o.address, "--replace"));
  const code = codeIn(made.stdout) ?? "";
  if (made.code !== 0 || !code) throw new Error(`mitm-agent pair-code: ${made.stderr.trim() || "no code"}`);
  const keypair = agentKeypair();
  const unpairSecret = randomBytes(32).toString("hex");
  // The pairing listener comes up a moment after the database: tried again while it cannot be reached.
  for (let i = 0; ; i++) {
    try {
      const paired = await pair(o.url, code, { publicKey: keypair.publicPem, name: o.name, source: "127.0.0.1", unpairSecret, agentListen: o.listen }, net.post);
      return { paired, keypair, unpairSecret };
    } catch (e) {
      if (i >= 15 || !(e as Error).message.startsWith("could not reach")) throw e;
      await sys.run(["sleep", "2"]);
    }
  }
}

/** The pairing code in `mitm-agent pair-code`'s output, whatever it prints around it. */
export function codeIn(out: string): string | null {
  return /\b[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}\b/.exec(out)?.[0] ?? null;
}

/** The newest setup token in a firewall's log (only the newest works), or null. */
export function setupTokenIn(log: string): string | null {
  const all = [...log.matchAll(/setup token \(POST \/api\/setup\): ([0-9a-f]+)/g)];
  return all.length ? all[all.length - 1]![1]! : null;
}

/** Whether something listens on host:port. */
export function listening(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = connect({ host, port, timeout: 2000 });
    const done = (v: boolean) => {
      s.destroy();
      resolve(v);
    };
    s.on("connect", () => done(true));
    s.on("timeout", () => done(false));
    s.on("error", () => done(false));
  });
}
