import { docker } from "./capture/docker.js";
import { host } from "./capture/host.js";
import type { CaptureMode } from "./capture/mode.js";
import { proxy } from "./capture/proxy.js";
import { remote } from "./capture/remote.js";
import { local } from "./local.js";
import { cliArgv, type Found, findOpenClaw, findUser, findVmAgent, type Runs } from "./openclaw.js";
import { ESCAPE_GROUPS, escapeGroupMessage } from "./groups.js";
import { type Sys, userByName, which } from "./sys.js";

/** What this machine has, as `doctor` sees it. Every mode decides from these alone. */
export interface Facts {
  os: string | null;
  linux: boolean;
  systemd: boolean;
  root: boolean;
  nft: string | null;
  docker: { ok: boolean; version: string | null; compose: string | null } | null;
  redsocks: boolean;
  apt: boolean;
  resolved: boolean;
  nameservers: string[];
  chrome: string | null;
  certutil: string | null;
  wireguard: string | null;
  vmAgent: string | null;
  openclaw: Found;
  /** The OpenClaw user can use sudo, so it can undo host mode. */
  userSudo: boolean;
  /**
   * Groups of the OpenClaw user that let it start containers or VMs: their traffic is sent by
   * dockerd (or lxd, libvirt), not by the user, so host mode cannot catch it.
   */
  escapeGroups: string[];
  /** `id -nG` failed for the OpenClaw user: its groups, and so the two above, are not known. */
  groupsUnknown: boolean;
  /** systemd-resolved's uid (host mode limits it to the firewall's DNS); null when no such user. */
  resolveUid: number | null;
}

export const MODES: CaptureMode[] = [docker, host, proxy, remote, local];

export async function gatherFacts(sys: Sys, opts: { user?: string; vmAgent?: string } = {}): Promise<Facts> {
  const osRelease = sys.read("/etc/os-release") ?? "";
  const os = /^PRETTY_NAME="?([^"\n]*)"?/m.exec(osRelease)?.[1] ?? null;
  const [nft, apt, chrome, certutil, wireguard, vmAgent, user] = await Promise.all([
    which(sys, "nft").then((p) => p ?? (sys.exists("/usr/sbin/nft") ? "/usr/sbin/nft" : null)),
    which(sys, "apt-get"),
    which(sys, "google-chrome", "google-chrome-stable", "chromium", "chromium-browser"),
    which(sys, "certutil"),
    which(sys, "wg"),
    findVmAgent(sys, opts.vmAgent),
    findUser(sys, opts.user),
  ]);
  const [dockerV, composeV, resolved, openclaw] = await Promise.all([
    sys.run(["docker", "version", "--format", "{{.Server.Version}}"], { timeoutMs: 15_000 }),
    sys.run(["docker", "compose", "version", "--short"], { timeoutMs: 15_000 }),
    sys.run(["systemctl", "is-active", "systemd-resolved"], { timeoutMs: 15_000 }),
    findOpenClaw(sys, user, vmAgent),
  ]);
  const hasDocker = dockerV.code !== 127;
  const id = openclaw.user ? await sys.run(["id", "-nG", openclaw.user.name]) : null;
  const groups = id?.code === 0 ? id.stdout.split(/\s+/) : [];
  return {
    os,
    linux: process.platform === "linux",
    systemd: sys.exists("/run/systemd/system"),
    root: sys.euid === 0,
    nft,
    docker: hasDocker
      ? { ok: dockerV.code === 0, version: dockerV.stdout.trim() || null, compose: composeV.code === 0 ? composeV.stdout.trim() : null }
      : null,
    redsocks: sys.exists("/usr/sbin/redsocks"),
    apt: apt !== null,
    resolved: resolved.stdout.trim() === "active",
    nameservers: (sys.read("/etc/resolv.conf") ?? "").split("\n").flatMap((l) => /^nameserver\s+(\S+)/.exec(l)?.[1] ?? []),
    chrome,
    certutil,
    wireguard,
    vmAgent,
    openclaw,
    userSudo: groups.some((g) => ["sudo", "admin", "wheel"].includes(g)),
    escapeGroups: groups.filter((g) => ESCAPE_GROUPS.includes(g)),
    groupsUnknown: id !== null && id.code !== 0,
    resolveUid: userByName(sys, "systemd-resolve")?.uid ?? null,
  };
}

export interface ModeVerdict {
  name: string;
  ok: boolean;
  protects: string;
  blockers: string[];
}

export function verdicts(f: Facts): ModeVerdict[] {
  return MODES.map((m) => {
    const blockers = m.blockers(f);
    return { name: m.name, ok: blockers.length === 0, protects: m.protects, blockers };
  });
}

export function warnings(f: Facts): string[] {
  const out: string[] = [];
  const u = f.openclaw.user;
  if (u?.uid === 0 && f.openclaw.install.runs.kind !== "docker") {
    out.push("OpenClaw runs as root. Host mode needs it under its own user; proxy mode works but cannot stop shell commands.");
  }
  if (u && u.uid !== 0 && f.userSudo) out.push(`${u.name} can use sudo, so in host mode OpenClaw (or its agent) can remove the rules.`);
  if (u && u.uid !== 0 && f.escapeGroups.length) out.push(escapeGroupMessage(u, f.escapeGroups));
  if (f.resolved) {
    out.push("Host mode points this machine's DNS at the firewall. If the firewall stops, DNS stops for every program here, not only OpenClaw.");
  }
  if (!f.vmAgent) out.push("No vm-agent binary found: connect needs one (--vm-agent <path>).");
  return out;
}

export function runsText(r: Runs, user: string | null): string {
  const who = user ? `, user ${user}` : "";
  switch (r.kind) {
    case "systemd-user":
      return `systemd user unit ${r.unit}${who}`;
    case "systemd-system":
      return `systemd unit ${r.unit}${who}`;
    case "docker":
      return `Docker container ${r.container}`;
    case "pm2":
      return `pm2 process ${r.name}${who}`;
    case "process":
      return `a plain process${r.pid ? ` (pid ${r.pid})` : ""}${who}`;
    case "not-running":
      return `installed, not running${who}`;
    case "not-found":
      return "not found";
  }
}

export function renderDoctor(f: Facts): string {
  const row = (k: string, v: string) => `  ${k.padEnd(11)} ${v}`;
  const i = f.openclaw.install;
  const lines = [
    "This machine",
    row("OS", `${f.os ?? "unknown"}${f.systemd ? " (systemd)" : ""}`),
    row("Root", f.root ? "yes" : "no"),
    row("nftables", f.nft ?? "not found"),
    row("Docker", f.docker ? (f.docker.ok ? `${f.docker.version}, Compose ${f.docker.compose ?? "missing"}` : "installed, but this user cannot use it") : "not found"),
    row("redsocks", f.redsocks ? "installed" : f.apt ? "not installed (apt-get can install it)" : "not installed"),
    row("DNS", `${f.resolved ? "systemd-resolved" : "resolv.conf"} (${f.nameservers.join(", ") || "no nameserver"})`),
    row("Chrome", f.chrome ? `${f.chrome}${f.certutil ? "" : " (no certutil: the CA cannot be added to it)"}` : "not found"),
    row("WireGuard", f.wireguard ?? "not found"),
    row("vm-agent", f.vmAgent ?? "not found"),
    "",
    "OpenClaw",
  ];
  if (i.runs.kind === "not-found") {
    lines.push(row("Found", "no"));
  } else {
    lines.push(
      row("CLI", `${i.runs.kind === "docker" ? cliArgv(i, []).join(" ") : (i.cli ?? "?")}${i.version ? ` (${i.version})` : ""}`),
      row("Config", i.config_file ?? "unknown"),
      row("Runs as", runsText(i.runs, f.openclaw.user?.name ?? null)),
      row("Gateway", `port ${i.gateway_port}`),
    );
    if (f.openclaw.via === "light") lines.push(row("", "(a quick look: install the vm-agent for the full one)"));
  }
  lines.push("", "Modes");
  for (const v of verdicts(f)) {
    lines.push(`  ${v.ok ? "✓" : "✗"} ${v.name.padEnd(7)} ${v.ok ? v.protects : v.blockers.join("; ")}`);
  }
  const w = warnings(f);
  if (w.length) lines.push("", "Warnings", ...w.map((x) => `  ! ${x}`));
  return lines.join("\n");
}

export function doctorJson(f: Facts): object {
  return { facts: f, modes: verdicts(f), warnings: warnings(f) };
}
