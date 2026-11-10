import { randomBytes } from "node:crypto";
import { basename, dirname, join } from "node:path";
import { q } from "./capture/docker.js";
import { connect, type Io } from "./commands.js";
import { composeIn, containerHealthy, dockerProblem, ensureImage, waitFor } from "./fwcontainer.js";
import { DEFAULT_OPENCLAW_IMAGE, GATEWAY_PORT, NODE_UID, OPENCLAW_ENV, setUpOpenClaw } from "./local.js";
import { gatherFacts } from "./doctor.js";
import { loadFirewall } from "./state.js";
import { type Sys, userByName } from "./sys.js";
import { connectHere, type HereNet } from "./up.js";
import { realNet } from "./commands.js";

/**
 * `controlclaw openclaw install`: a new OpenClaw on this machine, then connected to a firewall:
 * the one at `--firewall` (with a code), or the one `install` runs here (pairing by itself).
 * - `--docker` (default): a Compose project like OpenClaw's own (`/opt/openclaw`, or `~/openclaw`
 *   without root), OpenClaw's image, its Control UI on this machine's loopback;
 * - `--host`: OpenClaw's own installer, as its own user, run by systemd.
 * Not Ansible yet: the role needs the control plane.
 */
export const OPENCLAW_PROJECT = "openclaw";
export const OPENCLAW_SERVICE = "openclaw-gateway";

export interface OpenClawInstallOpts {
  host?: boolean;
  /** Connect it to this firewall (its pairing address); asks for the code. */
  firewall?: string;
  openclawImage?: string;
  dir?: string;
  name?: string;
  vmAgent?: string;
  /** `--host`: the user OpenClaw runs as (made when missing). */
  user?: string;
}

/** OpenClaw's compose file, as its own (one gateway service), with its ports on loopback only. */
export function openclawCompose(o: { image: string; dir: string }): string {
  const env = (k: string, v: string) => `      ${k}: ${q(v)}`;
  return [
    "# Written by controlclaw openclaw install: OpenClaw's gateway, as OpenClaw's own docker-compose.yml runs it.",
    `name: ${OPENCLAW_PROJECT}`,
    "services:",
    `  ${OPENCLAW_SERVICE}:`,
    `    image: ${q(o.image)}`,
    "    restart: unless-stopped",
    "    init: true",
    "    env_file: [.env]",
    "    environment:",
    ...OPENCLAW_ENV.map(([k, v]) => env(k, v)),
    "    volumes:",
    `      - ${q(`${join(o.dir, "config")}:/home/node/.openclaw`)}`,
    `      - ${q(`${join(o.dir, "secrets")}:/home/node/.config/openclaw`)}`,
    "    cap_drop: [NET_RAW, NET_ADMIN]",
    '    security_opt: ["no-new-privileges:true"]',
    "    ports:",
    `      - ${q(`127.0.0.1:${GATEWAY_PORT}:${GATEWAY_PORT}`)} # the gateway and its Control UI, on this machine only`,
    `    command: ["node", "dist/index.js", "gateway", "--bind", "lan", "--port", "${GATEWAY_PORT}"]`,
    "    healthcheck:",
    '      test: ["CMD", "node", "dist/docker-healthcheck.js"]',
    "      interval: 15s",
    "      start_period: 60s",
    "",
  ].join("\n");
}

export async function openclawInstall(sys: Sys, io: Io, o: OpenClawInstallOpts, net: HereNet = realNet): Promise<number> {
  const facts = await gatherFacts(sys, { vmAgent: o.vmAgent });
  if (facts.openclaw.install.runs.kind !== "not-found") {
    io.err("OpenClaw is on this machine already: connect it with controlclaw connect.");
    return 1;
  }
  const made = o.host ? await installOnHost(sys, io, o) : await installInDocker(sys, io, o);
  if (made !== 0) return made;
  io.out("");
  if (o.firewall) {
    io.out(`Connecting it to the firewall at ${o.firewall}`);
    return connect(sys, io, { firewall: o.firewall, mode: o.host ? "host" : "docker", name: o.name, vmAgent: o.vmAgent, user: o.host ? (o.user ?? "openclaw") : undefined }, net);
  }
  if (loadFirewall(sys)?.kind === "docker") {
    io.out("Connecting it to the firewall on this machine");
    return connectHere(sys, io, { mode: o.host ? "host" : "docker", name: o.name, vmAgent: o.vmAgent, user: o.host ? (o.user ?? "openclaw") : undefined }, net);
  }
  io.out("Next, connect it to a firewall: controlclaw connect --firewall http://<the firewall>:8801 (with a code from its panel), or install one here: controlclaw install, then controlclaw connect.");
  return 0;
}

function defaultDir(sys: Sys, o: OpenClawInstallOpts): string {
  return o.dir ?? (sys.euid === 0 ? "/opt/openclaw" : join(sys.env.HOME ?? "/tmp", "openclaw"));
}

async function installInDocker(sys: Sys, io: Io, o: OpenClawInstallOpts): Promise<number> {
  const problem = await dockerProblem(sys, "openclaw install");
  if (problem) {
    io.err(problem);
    return 1;
  }
  const dir = defaultDir(sys, o);
  if (sys.exists(dir)) {
    io.err(`${dir} is there already: remove it, or choose another folder with --dir.`);
    return 1;
  }
  const image = o.openclawImage ?? DEFAULT_OPENCLAW_IMAGE;
  const compose = composeIn(OPENCLAW_PROJECT, dir);
  try {
    await ensureImage(sys, io, image);
    io.out(`Writing ${dir}`);
    const token = randomBytes(24).toString("hex");
    sys.write(join(dir, "compose.yaml"), openclawCompose({ image, dir }));
    sys.write(join(dir, ".env"), `# Written by controlclaw openclaw install.\nOPENCLAW_GATEWAY_TOKEN=${token}\n`, { mode: 0o600 });
    // OpenClaw's state: its image's user's (uid 1000).
    for (const d of ["config", "config/workspace", "secrets"]) {
      const r = await sys.run(["install", "-d", "-m", "0700", ...(sys.euid === 0 ? ["-o", String(NODE_UID), "-g", String(NODE_UID)] : []), join(dir, d)]);
      if (r.code !== 0) throw new Error(`could not make ${join(dir, d)}: ${r.stderr.trim()}`);
    }
    if (sys.euid !== 0 && sys.euid !== NODE_UID) {
      // Without root, the folders are this user's: given to the image's user the way Docker can.
      const own = await sys.run(["docker", "run", "--rm", "--user", "0:0", "--network", "none", "--entrypoint", "chown", "-v", `${dir}:/oc`, image, "-R", `${NODE_UID}:${NODE_UID}`, "/oc/config", "/oc/secrets"]);
      if (own.code !== 0) throw new Error(`could not give ${dir}'s folders to OpenClaw's user (uid ${NODE_UID}): ${own.stderr.trim()}`);
    }
    io.out("Setting up OpenClaw");
    await setUpOpenClaw(sys, compose, OPENCLAW_SERVICE, true);
    io.out("Starting OpenClaw");
    const up = await sys.run(compose("up", "-d", OPENCLAW_SERVICE), { timeoutMs: 300_000 });
    if (up.code !== 0) throw new Error(`docker compose up: ${up.stderr.trim().split("\n").pop()}`);
    // A first start sets up its plugins: up to about four minutes.
    await waitFor(sys, "OpenClaw's gateway", 120, () => containerHealthy(sys, `${OPENCLAW_PROJECT}-${OPENCLAW_SERVICE}-1`));
    io.out(`OpenClaw runs in Docker (${image}), its files in ${dir}.`);
    io.out(`  Control UI: http://127.0.0.1:${GATEWAY_PORT}/#token=${token}`);
    io.out(`  From another machine: ssh -L ${GATEWAY_PORT}:127.0.0.1:${GATEWAY_PORT} <this machine>`);
    return 0;
  } catch (e) {
    io.err(`openclaw install failed: ${(e as Error).message}`);
    // What it made goes, so the next try starts over (the folder was not there before).
    await sys.run(compose("down"), { timeoutMs: 120_000 });
    const rm = await sys.run(["docker", "run", "--rm", "--user", "0:0", "--network", "none", "--entrypoint", "rm", "-v", `${dirname(dir)}:/p`, image, "-rf", `/p/${basename(dir)}`]);
    if (rm.code !== 0 || sys.exists(dir)) io.err(`Remove ${dir} to start over.`);
    return 1;
  }
}

/** OpenClaw's own installer: https://docs.openclaw.ai (install.sh). */
export const OPENCLAW_INSTALLER = "https://openclaw.ai/install.sh";

/**
 * OpenClaw's own installer, run as root: it needs root for Node 24 and the build tools, and puts
 * `openclaw` on every user's PATH. Then OpenClaw is set up as its own user (made when missing, never
 * root, never in the docker group), with its gateway as that user's systemd service, which outlives
 * a logout (lingering).
 */
async function installOnHost(sys: Sys, io: Io, o: OpenClawInstallOpts): Promise<number> {
  if (sys.euid !== 0) {
    io.err("openclaw install --host needs root (sudo): OpenClaw's installer installs Node and build tools, and OpenClaw gets a user of its own.");
    return 1;
  }
  const name = o.user ?? "openclaw";
  if (name === "root") {
    io.err("OpenClaw runs as its own user, not root: host mode would catch every root program.");
    return 2;
  }
  try {
    let user = userByName(sys, name);
    if (!user) {
      io.out(`Making the user ${name}`);
      const r = await sys.run(["useradd", "--create-home", "--shell", "/bin/bash", name]);
      if (r.code !== 0) throw new Error(`useradd ${name}: ${r.stderr.trim()}`);
      user = userByName(sys, name);
    }
    if (!user) throw new Error(`no user ${name} after useradd`);
    // Its systemd user service runs without a login, and starts at boot.
    const linger = await sys.run(["loginctl", "enable-linger", name]);
    if (linger.code !== 0) throw new Error(`loginctl enable-linger ${name}: ${linger.stderr.trim()}`);
    io.out("Running OpenClaw's installer (a few minutes)");
    const inst = await sys.run(["sh", "-c", `curl -fsSL --proto '=https' --tlsv1.2 ${OPENCLAW_INSTALLER} | bash -s -- --no-onboard --no-prompt`], { env: { OPENCLAW_NO_PROMPT: "1" }, timeoutMs: 1_800_000 });
    if (inst.code !== 0) throw new Error(`OpenClaw's installer: ${clean(inst.stderr || inst.stdout)}`);
    io.out(`Setting up OpenClaw as ${name}`);
    // From the user's home: the installer's checks run node in the working directory.
    const onboard = await sys.run(
      ["sh", "-c", 'cd "$HOME" && exec openclaw onboard --non-interactive --accept-risk --mode local --auth-choice skip --gateway-auth token --install-daemon --skip-channels'],
      { user, timeoutMs: 600_000 },
    );
    if (onboard.code !== 0) throw new Error(`openclaw onboard: ${clean(onboard.stderr || onboard.stdout)}`);
    await waitFor(sys, "OpenClaw's gateway", 60, async () => (await sys.run(["systemctl", "--user", "is-active", "openclaw-gateway.service"], { user })).stdout.trim() === "active");
    io.out(`OpenClaw runs as ${name}, its gateway a systemd user service (openclaw-gateway.service).`);
    io.out(`  Control UI: sudo -iu ${name} openclaw dashboard   (it prints the address with its token)`);
    return 0;
  } catch (e) {
    io.err(`openclaw install failed: ${(e as Error).message}`);
    return 1;
  }
}

/** The last line of a command's output, without its colours. */
function clean(out: string): string {
  // eslint-disable-next-line no-control-regex
  return out.replace(/\x1b\[[0-9;]*m/g, "").trim().split("\n").pop() ?? "";
}
