import { spawn } from "node:child_process";
import { chmodSync, chownSync, existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, rmdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Everything the CLI does to the machine goes through this: commands (argv only, never a shell
 * string) and files. The tests swap in `FakeSys`, which records both.
 */
export interface Result {
  code: number;
  stdout: string;
  stderr: string;
}

export interface RunOpts {
  input?: string;
  /** Run as this user (root only; `runuser`), with its HOME and XDG_RUNTIME_DIR. */
  user?: User;
  env?: Record<string, string>;
  timeoutMs?: number;
}

export interface User {
  name: string;
  uid: number;
  gid: number;
  home: string;
}

/** Who owns a file. A `User` is one. */
export interface Owner {
  uid: number;
  gid: number;
}

export interface Sys {
  run(argv: string[], opts?: RunOpts): Promise<Result>;
  read(path: string): string | null;
  /** Writes the file, creating its folder. `owner` chowns both when running as root. */
  write(path: string, data: string, opts?: { mode?: number; owner?: Owner }): void;
  /** Mode bits and owner, or null when there is no such file. */
  stat(path: string): { mode: number; uid: number; gid: number } | null;
  /** The owner of the path itself (a link is not followed), and whether it is a link. */
  lstat(path: string): { uid: number; mode: number; link: boolean } | null;
  /**
   * The file as `user` reads it: null when there is none. Throws when it is there but the user
   * cannot read it. With `readAs`, `writeAs` and `removeAs` root never opens a path a user controls.
   */
  readAs(user: User, path: string): Promise<string | null>;
  /** Writes as `user`: new files and folders under umask 022, or 077 and then `mode` when one is given. */
  writeAs(user: User, path: string, data: string, mode?: number): Promise<void>;
  /** Removes the file as `user`, then each of `dirs` that is empty. */
  removeAs(user: User, path: string, dirs: string[]): Promise<void>;
  /** The file a path ends at, links followed; the path itself when it does not exist. */
  realpath(path: string): string;
  remove(path: string): void;
  /** Removes a folder only when it is empty. */
  removeEmptyDir(path: string): void;
  exists(path: string): boolean;
  euid: number;
  env: Record<string, string | undefined>;
}

const DEFAULT_TIMEOUT = 120_000;

/** The argv that runs `argv` as `user` with its own HOME and user bus. */
export function asUser(sys: Pick<Sys, "euid">, user: User | undefined, argv: string[], env: Record<string, string> = {}): string[] {
  const vars = { ...env };
  if (user) {
    vars.HOME = user.home;
    vars.XDG_RUNTIME_DIR = `/run/user/${user.uid}`;
  }
  const pairs = Object.entries(vars).map(([k, v]) => `${k}=${v}`);
  const withEnv = pairs.length ? ["env", ...pairs, ...argv] : argv;
  if (user && sys.euid === 0 && user.uid !== 0) return ["runuser", "-u", user.name, "--", ...withEnv];
  return withEnv;
}

export function realSys(): Sys {
  const euid = process.geteuid?.() ?? -1;
  const sys: Sys = {
    euid,
    env: process.env,
    run(argv, opts = {}) {
      const full = asUser(sys, opts.user, argv, opts.env);
      return new Promise((resolve) => {
        const [cmd, ...args] = full;
        const child = spawn(cmd!, args, { stdio: ["pipe", "pipe", "pipe"] });
        let stdout = "";
        let stderr = "";
        const timer = setTimeout(() => child.kill("SIGKILL"), opts.timeoutMs ?? DEFAULT_TIMEOUT);
        child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
        child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
        child.on("error", (e) => {
          clearTimeout(timer);
          resolve({ code: 127, stdout, stderr: stderr + e.message });
        });
        child.on("close", (code) => {
          clearTimeout(timer);
          resolve({ code: code ?? 1, stdout, stderr });
        });
        child.stdin.on("error", () => {});
        child.stdin.end(opts.input ?? "");
      });
    },
    read(path) {
      try {
        return readFileSync(path, "utf8");
      } catch {
        return null;
      }
    },
    write(path, data, opts = {}) {
      // Only folders made here get the owner: an existing one (a root-owned project) keeps its own.
      const made: string[] = [];
      for (let d = dirname(path); d !== "/" && !existsSync(d); d = dirname(d)) made.push(d);
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, data, { mode: opts.mode ?? 0o644 });
      chmodSync(path, opts.mode ?? 0o644);
      if (opts.owner && euid === 0) {
        for (const d of made) chownSync(d, opts.owner.uid, opts.owner.gid);
        chownSync(path, opts.owner.uid, opts.owner.gid);
      }
    },
    remove(path) {
      rmSync(path, { force: true, recursive: true });
    },
    stat(path) {
      try {
        const s = statSync(path);
        return { mode: s.mode & 0o7777, uid: s.uid, gid: s.gid };
      } catch {
        return null;
      }
    },
    lstat(path) {
      try {
        const s = lstatSync(path);
        return { uid: s.uid, mode: s.mode & 0o7777, link: s.isSymbolicLink() };
      } catch {
        return null;
      }
    },
    async readAs(user, path) {
      const r = await sys.run(["sh", "-c", 'if [ -e "$1" ] || [ -L "$1" ]; then cat -- "$1"; else exit 4; fi', "sh", path], { user });
      if (r.code === 4) return null;
      if (r.code !== 0) {
        throw new Error(`cannot read ${path} as ${user.name}, who owns its folder (${r.stderr.trim()}): give it to ${user.name} or remove it, then connect again`);
      }
      return r.stdout;
    },
    async writeAs(user, path, data, mode) {
      // With a mode, the file is made under umask 077, so a private key is never readable by others
      // before its chmod.
      const script = 'umask "$3"; mkdir -p -- "$(dirname -- "$1")" && cat > "$1" && if [ -n "$2" ]; then chmod "$2" -- "$1"; fi';
      const argv = ["sh", "-c", script, "sh", path, mode === undefined ? "" : mode.toString(8), mode === undefined ? "022" : "077"];
      const r = await sys.run(argv, { user, input: data });
      if (r.code !== 0) {
        throw new Error(`cannot write ${path} as ${user.name}, who owns its folder (${r.stderr.trim()}): give it to ${user.name} or remove it, then connect again`);
      }
    },
    async removeAs(user, path, dirs) {
      await sys.run(["sh", "-c", 'rm -f -- "$1"; shift; for d; do rmdir -- "$d" 2>/dev/null; done; true', "sh", path, ...dirs], { user });
    },
    realpath(path) {
      try {
        return realpathSync(path);
      } catch {
        return path;
      }
    },
    removeEmptyDir(path) {
      try {
        rmdirSync(path);
      } catch {
        /* not empty, or gone */
      }
    },
    exists(path) {
      return existsSync(path);
    },
  };
  return sys;
}

/** A recording stand-in: canned answers by command prefix, files in a map. */
export class FakeSys implements Sys {
  calls: { argv: string[]; opts: RunOpts }[] = [];
  files = new Map<string, string>();
  answers: [string, Partial<Result>][] = [];
  euid = 0;
  env: Record<string, string | undefined> = {};

  /** Answer every command whose argv, joined by spaces, contains `prefix`. Later ones win. */
  on(prefix: string, result: Partial<Result>): this {
    this.answers.unshift([prefix, result]);
    return this;
  }

  /** Records the argv as it would really run: wrapped in runuser and env, as `realSys` does. */
  async run(argv: string[], opts: RunOpts = {}): Promise<Result> {
    const full = asUser(this, opts.user, argv, opts.env);
    this.calls.push({ argv: full, opts });
    const line = full.join(" ");
    const hit = this.answers.find(([p]) => line.includes(p));
    return { code: 0, stdout: "", stderr: "", ...(hit?.[1] ?? {}) };
  }

  read(path: string): string | null {
    return this.files.get(path) ?? null;
  }

  /** Folders it creates are kept as "<dir>/" entries, so a leftover one shows in `files`. */
  write(path: string, data: string, opts: { mode?: number; owner?: Owner } = {}): void {
    for (let d = dirname(path); d !== "/" && !this.exists(d); d = dirname(d)) this.files.set(`${d}/`, "");
    this.files.set(path, data);
    this.modes.set(path, { mode: opts.mode ?? 0o644, uid: opts.owner?.uid ?? 0, gid: opts.owner?.gid ?? 0 });
  }

  remove(path: string): void {
    for (const k of [...this.files.keys()]) if (k === path || k.startsWith(`${path}/`)) this.files.delete(k);
  }

  modes = new Map<string, { mode: number; uid: number; gid: number }>();
  links = new Map<string, string>();

  stat(path: string): { mode: number; uid: number; gid: number } | null {
    return this.files.has(path) ? (this.modes.get(path) ?? { mode: 0o644, uid: 0, gid: 0 }) : null;
  }

  /** Owners of folders (and links), by path; root when not set. */
  owners = new Map<string, number>();

  lstat(path: string): { uid: number; mode: number; link: boolean } | null {
    if (this.links.has(path)) return { uid: this.owners.get(path) ?? 0, mode: 0o777, link: true };
    if (!this.exists(path)) return null;
    const m = this.modes.get(path);
    return { uid: this.owners.get(path) ?? m?.uid ?? 0, mode: m?.mode ?? 0o755, link: false };
  }

  async readAs(user: User, path: string): Promise<string | null> {
    this.calls.push({ argv: ["as", user.name, "read", path], opts: {} });
    return this.files.get(path) ?? null;
  }

  async writeAs(user: User, path: string, data: string, mode?: number): Promise<void> {
    this.calls.push({ argv: ["as", user.name, "write", path], opts: {} });
    const was = this.modes.get(path);
    this.write(path, data, { mode: mode ?? was?.mode ?? 0o600, owner: user });
  }

  async removeAs(user: User, path: string, dirs: string[]): Promise<void> {
    this.calls.push({ argv: ["as", user.name, "remove", path], opts: {} });
    this.remove(path);
    for (const d of dirs) this.removeEmptyDir(d);
  }

  realpath(path: string): string {
    return this.links.get(path) ?? path;
  }

  removeEmptyDir(path: string): void {
    const inside = [...this.files.keys()].filter((k) => k.startsWith(`${path}/`) && k !== `${path}/`);
    if (!inside.length) this.files.delete(`${path}/`);
  }

  exists(path: string): boolean {
    return this.files.has(path) || [...this.files.keys()].some((k) => k.startsWith(`${path}/`));
  }

  /** The commands run, one string each. */
  ran(): string[] {
    return this.calls.map((c) => c.argv.join(" "));
  }
}

/** Looks a user up in /etc/passwd. */
export function userByName(sys: Sys, name: string): User | null {
  return parsePasswd(sys.read("/etc/passwd") ?? "").find((u) => u.name === name) ?? null;
}

export function userByUid(sys: Sys, uid: number): User | null {
  return parsePasswd(sys.read("/etc/passwd") ?? "").find((u) => u.uid === uid) ?? null;
}

export function parsePasswd(raw: string): User[] {
  return raw
    .split("\n")
    .map((l) => l.split(":"))
    .filter((p) => p.length >= 6)
    .map(([name, , uid, gid, , home]) => ({ name: name!, uid: Number(uid), gid: Number(gid), home: home! }));
}

/** The first of `names` that is a program on PATH, or null. */
export async function which(sys: Sys, ...names: string[]): Promise<string | null> {
  for (const n of names) {
    const r = await sys.run(["sh", "-c", 'command -v "$1"', "sh", n]);
    if (r.code === 0 && r.stdout.trim()) return r.stdout.trim();
  }
  return null;
}
