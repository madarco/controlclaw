import { join } from "node:path";
import { parsePasswd, type Sys, type User, userByName, userByUid, which } from "./sys.js";

/** `vm-agent discover`'s output (rust/bins/vm-agent/src/unmanaged/discover.rs, `Install`). */
export type Runs =
  | { kind: "systemd-user"; unit: string }
  | { kind: "systemd-system"; unit: string }
  | { kind: "docker"; container: string }
  | { kind: "pm2"; name: string }
  | { kind: "process"; pid: number | null }
  | { kind: "not-running" }
  | { kind: "not-found" };

export interface Install {
  cli: string | null;
  version: string | null;
  config_file: string | null;
  state_dir: string | null;
  runs: Runs;
  gateway_port: number;
}

export interface Found {
  install: Install;
  /** Who runs it on the host. Null for a container, or when nothing was found. */
  user: User | null;
  /** How it was found: `vm-agent discover`, or the CLI's own lighter look. */
  via: "vm-agent" | "light";
  /** Why `vm-agent discover` gave nothing, when a vm-agent was given. */
  discoverError?: string;
}

const NOT_FOUND: Install = {
  cli: null,
  version: null,
  config_file: null,
  state_dir: null,
  runs: { kind: "not-found" },
  gateway_port: 18789,
};

/** The vm-agent binary: `--vm-agent`, `$CC_VM_AGENT`, what `connect` installed, then PATH. */
export async function findVmAgent(sys: Sys, given?: string): Promise<string | null> {
  for (const p of [given, sys.env.CC_VM_AGENT, "/usr/local/bin/controlclaw-vm-agent"]) {
    if (p && sys.exists(p)) return p;
  }
  return which(sys, "controlclaw-vm-agent", "vm-agent");
}

/**
 * The user that runs OpenClaw's gateway: `--user`, else the owner of a gateway process on the host
 * (not one inside a container), else the one user with an OpenClaw config, else the user who ran
 * sudo, else whoever runs this.
 */
export async function findUser(sys: Sys, given?: string): Promise<User | null> {
  if (given) return userByName(sys, given);
  const ps = await sys.run(["ps", "-eo", "uid=,pid=,args="]);
  for (const line of ps.stdout.split("\n")) {
    const m = /^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(line);
    if (!m || !isGatewayProcess(m[3]!)) continue;
    const cgroup = sys.read(`/proc/${m[2]}/cgroup`) ?? "";
    if (/docker|containerd|libpod/.test(cgroup)) continue;
    const u = userByUid(sys, Number(m[1]));
    if (u) return u;
  }
  // Not running: the one user with an OpenClaw config in their home.
  const owners = parsePasswd(sys.read("/etc/passwd") ?? "").filter((u) => (u.uid === 0 || u.uid >= 1000) && sys.exists(join(u.home, ".openclaw/openclaw.json")));
  if (owners.length === 1) return owners[0]!;
  if (sys.env.SUDO_USER) return userByName(sys, sys.env.SUDO_USER);
  return userByUid(sys, sys.euid);
}

/**
 * A gateway process, by what it runs: OpenClaw's own program (`openclaw-gateway` is its process
 * title), or node/bun running OpenClaw with `gateway`. Not a shell, editor or `journalctl -u
 * openclaw-gateway` whose arguments only mention it.
 */
export function isGatewayProcess(args: string): boolean {
  const [exe = "", ...rest] = args.trim().split(/\s+/);
  const prog = exe.split("/").pop()!;
  if (prog === "openclaw-gateway") return true;
  if (prog === "openclaw") return rest.includes("gateway");
  if (prog === "bun" || /^node(js)?\d*$/.test(prog)) {
    return rest.some((a) => /openclaw/.test(a)) && rest.includes("gateway");
  }
  return false;
}

export function parseDiscover(raw: string): Install | null {
  try {
    const v = jsonFrom(raw) as Install;
    return v && typeof v === "object" && v.runs ? v : null;
  } catch {
    return null;
  }
}

/** What is installed, as `user` sees it. */
export async function findOpenClaw(sys: Sys, user: User | null, vmAgent: string | null): Promise<Found> {
  let discoverError: string | undefined;
  if (vmAgent) {
    const r = await discover(sys, vmAgent, user);
    const install = r.code === 0 ? parseDiscover(r.stdout) : null;
    if (install) return { install, user: install.runs.kind === "docker" ? null : user, via: "vm-agent" };
    discoverError = (r.stderr || r.stdout).trim().split("\n").pop() || `exit ${r.code}`;
  }
  return { install: await lightLook(sys, user), user, via: "light", ...(discoverError ? { discoverError } : {}) };
}

/**
 * `vm-agent discover` as OpenClaw's user. A binary that user cannot run (in root's home, say) runs
 * from a copy in a fresh folder it can read, removed after.
 */
async function discover(sys: Sys, vmAgent: string, user: User | null) {
  const r = await sys.run([vmAgent, "discover"], { user: user ?? undefined, timeoutMs: 60_000 });
  if (!(r.code === 126 || /permission denied/i.test(r.stderr)) || !user || sys.euid !== 0) return r;
  const dir = (await sys.run(["mktemp", "-d", "/tmp/controlclaw-discover.XXXXXX"])).stdout.trim();
  if (!dir) return r;
  try {
    await sys.run(["chmod", "0755", dir]);
    const copy = join(dir, "vm-agent");
    if ((await sys.run(["install", "-m", "0755", vmAgent, copy])).code !== 0) return r;
    return await sys.run([copy, "discover"], { user, timeoutMs: 60_000 });
  } finally {
    await sys.run(["rm", "-rf", dir]);
  }
}

/** Without the vm-agent: the CLI and its version only. Enough for doctor to say what is missing. */
async function lightLook(sys: Sys, user: User | null): Promise<Install> {
  const home = user?.home ?? sys.env.HOME ?? "/root";
  const places = [join(home, ".openclaw/bin/openclaw"), join(home, ".npm-global/bin/openclaw"), join(home, ".local/bin/openclaw"), "/usr/local/bin/openclaw", "/usr/bin/openclaw"];
  const cli = places.find((p) => sys.exists(p)) ?? null;
  if (!cli) return NOT_FOUND;
  const v = await sys.run([cli, "--version"], { user: user ?? undefined, timeoutMs: 30_000 });
  const version = /(\d{4}\.\d+\.\d+)/.exec(v.stdout)?.[1] ?? null;
  return { ...NOT_FOUND, cli, version, runs: { kind: "not-running" } };
}

/** The argv that runs an OpenClaw command, wherever OpenClaw is. */
export function cliArgv(install: Install, args: string[]): string[] {
  if (install.runs.kind === "docker") return ["docker", "exec", "-i", install.runs.container, "node", "dist/index.js", ...args];
  return [install.cli ?? "openclaw", ...args];
}

/** The command that restarts the gateway the way it runs. */
export function restartArgv(install: Install): string[] | null {
  switch (install.runs.kind) {
    case "systemd-system":
      return ["systemctl", "restart", "--", install.runs.unit];
    case "docker":
      return ["docker", "restart", "--", install.runs.container];
    case "pm2":
      return ["pm2", "restart", install.runs.name];
    // Not `openclaw gateway restart`: it refuses while the gateway restarts itself after a config
    // change (found on 2026.10.9), and a unit restart is what re-reads the drop-in's environment.
    case "systemd-user":
      return ["systemctl", "--user", "restart", "--", install.runs.unit];
    case "process":
      return cliArgv(install, ["gateway", "restart"]);
    default:
      return null;
  }
}

/** Who runs the restart: OpenClaw's user for its own service manager, else this process (root). */
export function restartUser(install: Install, user: User | null): User | undefined {
  return ["systemd-user", "process", "pm2"].includes(install.runs.kind) ? (user ?? undefined) : undefined;
}

/** The JSON object in a command's output, after any lines it prints first. */
export function jsonFrom(out: string): unknown {
  return JSON.parse(out.slice(out.indexOf("{")));
}

/** Restarts the gateway; the user's own commands run as that user. Null when it went fine. */
export async function restartOpenClaw(sys: Sys, install: Install, user: User | null): Promise<string | null> {
  const argv = restartArgv(install);
  if (!argv) return null;
  const r = await sys.run(argv, { user: restartUser(install, user), timeoutMs: 180_000 });
  if (r.code === 0) return null;
  return `OpenClaw did not restart (${(r.stderr || r.stdout).trim().split("\n").pop()}): restart it yourself so it reads the new settings.`;
}
