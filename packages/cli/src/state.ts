import { dirname, join } from "node:path";
import { type Owner, type Sys, type User, userByName, userByUid } from "./sys.js";

/**
 * What `connect` did, step by step, in `connect.json`, so `disconnect` can undo exactly that and
 * nothing else. The record is saved after every step: a connect that fails half way is undone from
 * the same file.
 */
export type Mode = "docker" | "host" | "proxy" | "remote" | "local";

export type Step =
  /**
   * A file `connect` wrote. Undo puts back what was there, or removes it, and then the folders
   * `connect` created for it when they are empty.
   */
  | {
      kind: "file";
      path: string;
      previous: string | null;
      /** The previous file's mode and owner, put back with its content. */
      was?: { mode: number; uid: number; gid: number };
      dirs?: string[];
      /** Written as this user, because it owns a part of the path: undone as that user too. */
      user?: User;
    }
  /**
   * Commands that undo something. They run at this point of the reverse walk, so a step recorded
   * before a file runs after that file is put back (a reload after the restore).
   */
  | { kind: "run"; what: string; argv: string[][]; user?: User; input?: string };

export interface Firewall {
  url: string;
  /** host:port of the firewall's proxy. */
  proxy: string;
  /** The firewall's DNS address (host and docker modes). */
  dns: string | null;
  /** The id pairing gave this agent (none with --ca and --firewall-key). */
  agentId?: string;
  /** The secret that unpairs it (`POST /unpair`); the firewall keeps only its hash. */
  unpair?: string;
}

export interface ConnectRecord {
  version: 1;
  mode: Mode;
  at: string;
  /** The user OpenClaw runs as (none for a container). */
  user: User | null;
  firewall: Firewall;
  /** The OpenClaw container, in docker mode. */
  container?: string;
  /** The argv that runs OpenClaw's CLI (`cliArgv(install, [])`). */
  cli: string[];
  /** Where the CA was put for OpenClaw to read. */
  ca: string;
  /** Paired with the firewall `controlclaw install` runs on this machine (no code typed). */
  up?: UpFirewall;
  /** `--capture-only`: no vm-agent. */
  captureOnly?: boolean;
  /** OpenClaw's config as it was before connect, for `disconnect --restore-config`. */
  configBackup?: ConfigBackup;
  steps: Step[];
}

/** A copy of OpenClaw's config file, made before the vm-agent first writes to it. */
export interface ConfigBackup {
  /** OpenClaw's config file. */
  config: string;
  /** The copy (0600, in the state folder). */
  copy: string;
  /** How OpenClaw is restarted once the file is back, and as whom. */
  restart: string[] | null;
  restartAs?: User;
}

/** The firewall on this machine that connect paired with: its Compose project, and the gateway's network (docker mode). */
export interface UpFirewall {
  /** The folder of its compose.yaml. */
  dir: string;
  project: string;
  image?: string;
  /** Docker mode: the firewall's internal network, the gateway's only one. */
  network?: string;
  /** Set once connect finished: connect run again then checks it, and never pairs again. */
  done?: boolean;
}

/** Root keeps it in /etc; a user without root (proxy mode) in its own config folder. */
export function stateDir(sys: Sys): string {
  if (sys.euid === 0) return "/etc/controlclaw";
  const base = sys.env.XDG_CONFIG_HOME || join(sys.env.HOME ?? "/tmp", ".config");
  return join(base, "controlclaw");
}

export function recordPath(sys: Sys): string {
  return join(stateDir(sys), "connect.json");
}

/** What `controlclaw install` did: the firewall on this machine. Its own record, next to connect's. */
export function firewallRecordPath(sys: Sys): string {
  return join(stateDir(sys), "firewall.json");
}

/** The firewall `controlclaw install` put on this machine, and how to take it away. */
export interface FirewallRecord {
  version: 1;
  /** A container (`--docker`), or `install.sh`'s systemd units (`--host`). */
  kind: "docker" | "host";
  at: string;
  /** Its image (`--docker`), or the release install.sh installed (`--host`). */
  image: string;
  /** `--docker`: the folder of its compose.yaml, and its Compose project. */
  dir?: string;
  project?: string;
  /** The address other machines reach it at (`--listen`). */
  listen?: string;
  /** `--host`: install.sh, kept for `uninstall`. */
  installer?: string;
  steps: Step[];
}

export function loadFirewall(sys: Sys): FirewallRecord | null {
  const raw = sys.read(firewallRecordPath(sys));
  if (!raw) return null;
  try {
    const r = JSON.parse(raw) as FirewallRecord;
    return r.version === 1 ? r : null;
  } catch {
    return null;
  }
}

/** The record root keeps, when this user has none: then disconnect and status need sudo. */
export const ROOT_RECORD = "/etc/controlclaw/connect.json";
/** The firewall root installed. */
export const ROOT_FIREWALL = "/etc/controlclaw/firewall.json";

export function loadRecord(sys: Sys): ConnectRecord | null {
  const raw = sys.read(recordPath(sys));
  if (!raw) return null;
  try {
    const r = JSON.parse(raw) as ConnectRecord;
    return r.version === 1 ? r : null;
  } catch {
    return null;
  }
}

/**
 * As root under sudo, with no record of root's own: the record of the user who ran sudo, when that
 * user set this machine up without it (`up` by a user who can use Docker). Read as that user.
 */
export async function sudoUserRecord(sys: Sys): Promise<{ user: User; record: ConnectRecord } | null> {
  if (sys.euid !== 0 || sys.exists(ROOT_RECORD) || !sys.env.SUDO_USER) return null;
  const user = userByName(sys, sys.env.SUDO_USER);
  if (!user || user.uid === 0) return null;
  let raw: string | null = null;
  try {
    raw = await sys.readAs(user, join(user.home, ".config/controlclaw/connect.json"));
  } catch {
    return null;
  }
  try {
    const record = raw ? (JSON.parse(raw) as ConnectRecord) : null;
    return record?.version === 1 ? { user, record } : null;
  } catch {
    return null;
  }
}

/**
 * Who controls where `path` leads: the first owner other than root of a folder along it (from the
 * top), or of the file itself when it is a link, each looked at without following links. 0 when
 * root does. A regular file a user owns in root's folder is root's to write: it cannot become a
 * link there. Throws `SharedFolder` for a root folder the group or others may write to.
 */
export function pathOwner(sys: Sys, path: string): number {
  const parts = path.split("/").filter(Boolean);
  for (let i = 1; i <= parts.length; i++) {
    const p = `/${parts.slice(0, i).join("/")}`;
    const l = sys.lstat(p);
    if (!l) return 0;
    const last = i === parts.length;
    if (l.uid !== 0 && (!last || l.link)) return l.uid;
    // A root folder others may write to: anyone could put a link below it, and there is no one
    // user to write as. (A user's own folder is that user's, above.)
    if (!last && !l.link && l.mode & 0o022) throw new SharedFolder(p, l.mode);
  }
  return 0;
}

/** A folder on the path that the group or everyone may write to. */
export class SharedFolder extends Error {
  constructor(
    readonly dir: string,
    mode: number,
  ) {
    super(`${dir} can be written by other users (mode ${mode.toString(8)}): connect does not write through it. Remove their write access (chmod go-w ${dir}), then connect again`);
  }
}

/** Writes and records. Every change `connect` makes goes through one of these two methods. */
export class Recorder<R extends { steps: Step[] } = ConnectRecord> {
  constructor(
    private sys: Sys,
    readonly record: R,
    /** Where the record is kept: connect.json, or firewall.json for `install`. */
    private path: string = recordPath(sys),
  ) {}

  private save(): void {
    this.sys.write(this.path, `${JSON.stringify(this.record, null, 2)}\n`, { mode: 0o600 });
  }

  /**
   * Writes `path`, remembering what was there (content, mode, owner). A second write to the same
   * path keeps the first. A file that was there keeps its mode and owner unless `opts` says else.
   *
   * As root, a path that a user owns a part of (its home, a project folder) is written as that
   * user: root following a link the user planted there would write wherever it points.
   */
  async file(path: string, data: string, opts: { mode?: number; owner?: Owner } = {}): Promise<void> {
    const uid = this.sys.euid === 0 ? pathOwner(this.sys, path) : 0;
    if (uid !== 0) {
      const user = userByUid(this.sys, uid);
      if (!user) throw new Error(`${path} is owned by uid ${uid}, which has no user here: not written`);
      if (!this.record.steps.some((s) => s.kind === "file" && s.path === path)) {
        const dirs: string[] = [];
        for (let d = dirname(path); d !== "/" && !this.sys.exists(d); d = dirname(d)) dirs.push(d);
        const previous = await this.sys.readAs(user, path);
        this.record.steps.push({ kind: "file", path, previous, user, ...(dirs.length ? { dirs } : {}) });
        this.save();
      }
      await this.sys.writeAs(user, path, data, opts.mode);
      return;
    }
    const was = this.sys.stat(path) ?? undefined;
    if (!this.record.steps.some((s) => s.kind === "file" && s.path === path)) {
      const dirs: string[] = [];
      for (let d = dirname(path); d !== "/" && !this.sys.exists(d); d = dirname(d)) dirs.push(d);
      const previous = this.sys.read(path);
      this.record.steps.push({ kind: "file", path, previous, ...(previous !== null && was ? { was } : {}), ...(dirs.length ? { dirs } : {}) });
      this.save();
    }
    this.sys.write(path, data, { mode: opts.mode ?? was?.mode, owner: opts.owner ?? was });
  }

  /** Records how to undo what is about to be done. */
  onUndo(what: string, argv: string[][], opts: { user?: User; input?: string } = {}): void {
    this.record.steps.push({ kind: "run", what, argv, ...opts });
    this.save();
  }

  /** Saves the record as it is (also after a field of it changed). */
  start(): void {
    this.save();
  }
}

/**
 * Undo every step, newest first. A failed step is reported and the rest still run. The failed ones
 * stay in the record, so `disconnect` can be run again; the record goes only when all went well.
 */
export async function undoAll(sys: Sys, record: { steps: Step[] }, log: (line: string) => void, path: string = recordPath(sys)): Promise<number> {
  const left: Step[] = [];
  for (const step of [...record.steps].reverse()) {
    if (step.kind === "file") {
      try {
        if (step.user) {
          if (step.previous === null) await sys.removeAs(step.user, step.path, step.dirs ?? []);
          else await sys.writeAs(step.user, step.path, step.previous);
          continue;
        }
        if (step.previous === null) sys.remove(step.path);
        else sys.write(step.path, step.previous, { mode: step.was?.mode, owner: step.was });
        for (const d of step.dirs ?? []) sys.removeEmptyDir(d);
      } catch (e) {
        left.unshift(step);
        log(`  could not put back ${step.path}: ${(e as Error).message}`);
      }
      continue;
    }
    const failedArgv: string[][] = [];
    for (const argv of step.argv) {
      const r = await sys.run(argv, { user: step.user, input: step.input });
      if (r.code !== 0) {
        failedArgv.push(argv);
        log(`  could not ${step.what}: ${(r.stderr || r.stdout).trim().split("\n").pop() ?? ""}`);
      }
    }
    if (failedArgv.length) left.unshift({ ...step, argv: failedArgv });
  }
  if (left.length) {
    sys.write(path, `${JSON.stringify({ ...record, steps: left }, null, 2)}\n`, { mode: 0o600 });
  } else {
    sys.remove(path);
    sys.removeEmptyDir(stateDir(sys));
  }
  return left.length;
}
