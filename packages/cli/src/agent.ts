import { join } from "node:path";
import type { Recorder } from "./state.js";
import type { Sys, User } from "./sys.js";

/**
 * The vm-agent in unmanaged mode (rust/bins/vm-agent/UNMANAGED.md): its binary, its one config
 * file and a unit that runs it as the OpenClaw user. Root installs a system unit with `User=`; a
 * user without root, a user unit.
 */
export const UNIT = "controlclaw-agent.service";
/**
 * Where the vm-agent listens for the firewall's calls. Not 3100, the firewall agent's own port (an
 * `up` firewall shares the machine), nor 3101 (the firewall's AI judge on loopback, and the
 * locked-disk listener on a secured box). Machines connected before keep the `listen` their config has.
 */
export const AGENT_PORT = 3102;
/** Remote mode's: the firewall calls a tunnel address on 3100, and pairing there takes no `agent_listen`. */
export const REMOTE_AGENT_PORT = 3100;

export interface AgentOpts {
  binary: string;
  /** Who it runs as: the OpenClaw user, or root for a container. */
  user: User;
  firewallUrl: string;
  firewallKey: string | null;
  container?: string;
  /** From pairing: the id the firewall's tokens name, and the agent's own key pair. */
  agentId?: string;
  keypair?: { privatePem: string; publicPem: string };
  /**
   * Where it listens: loopback by default. Paired, where the firewall calls it (pairing's
   * `agent_listen`): this machine's address toward the firewall, the tunnel's, or a Docker bridge's.
   */
  listen?: string;
  /** The only addresses that may connect to it: the firewall, as it reaches this machine. */
  allowFrom?: string[];
  /** The firewall's address as OpenClaw reaches it: where its MCP servers and app connections go. */
  gate?: string;
  /** A unit it starts after (remote mode: the tunnel). */
  after?: string;
}

export interface AgentPaths {
  bin: string;
  config: string;
  unit: string;
  state: string;
  system: boolean;
}

export function agentPaths(sys: Sys, user: User): AgentPaths {
  const system = sys.euid === 0;
  const home = sys.env.HOME ?? user.home;
  return {
    bin: system ? "/usr/local/bin/controlclaw-vm-agent" : join(home, ".local/bin/controlclaw-vm-agent"),
    config: system ? "/etc/controlclaw/agent.json" : join(home, ".config/controlclaw/agent.json"),
    unit: system ? join("/etc/systemd/system", UNIT) : join(home, ".config/systemd/user", UNIT),
    state: join(user.home, ".local/state/controlclaw"),
    system,
  };
}

export function agentConfig(o: AgentOpts, state: string): string {
  const file = {
    mode: "unmanaged",
    listen: o.listen ?? `127.0.0.1:${AGENT_PORT}`,
    state_dir: state,
    ...(o.agentId ? { agent_id: o.agentId } : {}),
    firewall: {
      url: o.firewallUrl,
      public_key: o.firewallKey,
      // The firewall signs its tokens for the address it dials (`h`): checked once there is one.
      ...(o.listen && o.agentId ? { hostnames: [hostOf(o.listen)] } : {}),
      ...(o.allowFrom?.length ? { allow_from: o.allowFrom } : {}),
      ...(o.gate ? { gate: o.gate } : {}),
    },
    openclaw: o.container ? { runs: "docker", container: o.container } : {},
  };
  return `${JSON.stringify(file, null, 2)}\n`;
}

/** The host of a `host:port`. */
function hostOf(listen: string): string {
  return listen.slice(0, listen.lastIndexOf(":"));
}

export function agentUnit(o: AgentOpts, p: AgentPaths): string {
  const lines = [
    "# Written by controlclaw connect; removed by controlclaw disconnect.",
    "[Unit]",
    "Description=ControlClaw agent (unmanaged)",
    `After=network-online.target${o.after ? ` ${o.after}` : ""}`,
    "",
    "[Service]",
  ];
  if (p.system) {
    lines.push(`User=${o.user.name}`, `Environment=HOME=${o.user.home}`, `Environment=XDG_RUNTIME_DIR=/run/user/${o.user.uid}`);
  }
  lines.push(
    `Environment=CC_AGENT_CONFIG=${p.config}`,
    `ExecStart=${p.bin}`,
    "Restart=always",
    "RestartSec=5",
    "",
    "[Install]",
    `WantedBy=${p.system ? "multi-user.target" : "default.target"}`,
    "",
  );
  return lines.join("\n");
}

export async function installAgent(sys: Sys, rec: Recorder, o: AgentOpts): Promise<AgentPaths> {
  const p = agentPaths(sys, o.user);
  const ctl = p.system ? ["systemctl"] : ["systemctl", "--user"];

  if (sys.realpath(o.binary) === sys.realpath(p.bin)) {
    // Already where it goes: used as it is, and left there by disconnect.
  } else {
    if (sys.exists(p.bin)) {
      // Someone else's binary at our path: set aside, and put back on disconnect.
      const aside = `${p.bin}.before-controlclaw`;
      // One left by an earlier connect (its record lost) is someone's binary too: never overwritten.
      if (sys.exists(aside)) throw new Error(`${aside} exists already: put it back or remove it, then connect again`);
      const mv = await sys.run(["mv", "-f", p.bin, aside]);
      if (mv.code !== 0) throw new Error(`could not set ${p.bin} aside: ${mv.stderr.trim()}`);
      // Recorded once it is aside: a failed move leaves nothing to put back.
      rec.onUndo("put back the vm-agent binary that was there", [["mv", "-f", aside, p.bin]]);
    }
    rec.onUndo("remove the vm-agent", [["rm", "-f", p.bin]]);
    const cp = await sys.run(["install", "-D", "-m", "0755", o.binary, p.bin]);
    if (cp.code !== 0) throw new Error(`could not install the vm-agent: ${cp.stderr.trim()}`);
  }

  // In the user's home: removed as that user, so a link planted there leads nowhere root can reach.
  rec.onUndo("remove the agent's state", [["rm", "-rf", "--", p.state]], sys.euid === 0 && o.user.uid !== 0 ? { user: o.user } : {});
  if (o.keypair) {
    // The key the firewall recorded at pairing; the agent keeps a pair it finds (ensure_vm_keypair).
    // In the user's home, so Recorder.file writes them as that user.
    await rec.file(join(p.state, "vm_private_key.pem"), o.keypair.privatePem, { mode: 0o600, owner: o.user });
    await rec.file(join(p.state, "vm_public_key.pem"), o.keypair.publicPem, { mode: 0o644, owner: o.user });
  }
  await rec.file(p.config, agentConfig(o, p.state));
  rec.onUndo("reload systemd", [[...ctl, "daemon-reload"]]);
  await rec.file(p.unit, agentUnit(o, p));
  rec.onUndo("stop the vm-agent", [[...ctl, "disable", "--now", UNIT]]);
  await sys.run([...ctl, "daemon-reload"]);
  const up = await sys.run([...ctl, "enable", "--now", UNIT]);
  if (up.code !== 0) throw new Error(`could not start the vm-agent: ${up.stderr.trim()}`);
  return p;
}

/**
 * A user service stops at logout unless the user lingers. Turned on when it was off (and off again
 * by disconnect); a note when it cannot be.
 */
export async function keepAfterLogout(sys: Sys, rec: Recorder, user: User): Promise<string | null> {
  const show = await sys.run(["loginctl", "show-user", user.name, "-p", "Linger", "--value"]);
  if (show.stdout.trim() === "yes") return null;
  const r = await sys.run(["loginctl", "enable-linger", user.name]);
  if (r.code !== 0) {
    return `Could not keep the vm-agent running after you log out (loginctl enable-linger: ${(r.stderr || r.stdout).trim() || `exit ${r.code}`}). Run: sudo loginctl enable-linger ${user.name}`;
  }
  rec.onUndo("stop keeping the user's services after logout", [["loginctl", "disable-linger", user.name]]);
  return null;
}
