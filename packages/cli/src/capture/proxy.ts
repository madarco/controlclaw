import { installNodeEnv, installSystemStore } from "../ca.js";
import type { Facts } from "../doctor.js";
import { cliArgv, jsonFrom, restartOpenClaw } from "../openclaw.js";
import type { Check } from "../probe.js";
import type { ConnectRecord } from "../state.js";
import type { Sys } from "../sys.js";
import type { CaptureMode, Ctx } from "./mode.js";

/**
 * Proxy only: OpenClaw's own managed proxy (`proxy.proxyUrl`), which routes the gateway's fetch,
 * node:http(s) and WebSocket clients through the firewall and fails closed when the proxy is down.
 * It is config, so it survives a reboot. Shell commands and other programs go around it.
 *
 * `proxy.tls.caFile` only verifies an `https://` proxy endpoint; trusting the firewall's CA for the
 * sites behind it takes NODE_EXTRA_CA_CERTS in the gateway's service environment.
 */
type Json = string | number | boolean | null | Json[] | { [k: string]: Json };

export function proxyPatch(proxy: string): { proxy: { [k: string]: Json } } {
  return { proxy: { enabled: true, proxyUrl: `http://${proxy}`, loopbackMode: "gateway-only" } };
}

/**
 * OpenClaw's current `proxy` block, read from its config file: `config get` redacts the URL, so a
 * value read that way could not be put back. Throws when the file cannot be read as JSON.
 */
export function currentProxy(path: string | null, raw: string | null): Json | undefined {
  if (!path || raw === null) throw new Error(`cannot read OpenClaw's config file${path ? ` (${path})` : ""}`);
  let cfg: { proxy?: Json };
  try {
    cfg = JSON.parse(raw) as { proxy?: Json };
  } catch {
    throw new Error(`${path} is not plain JSON, so its proxy setting cannot be saved: set proxy.proxyUrl by hand`);
  }
  return cfg.proxy;
}

export const proxy: CaptureMode = {
  name: "proxy",
  protects: "observability, plus enforcement for OpenClaw's own requests; shell commands and other programs go around it",
  blockers(f: Facts) {
    const runs = f.openclaw.install.runs.kind;
    if (runs === "not-found") return ["no OpenClaw found on this machine"];
    if (runs === "docker") return ["OpenClaw runs in Docker: use --mode docker"];
    return [];
  },
  async install(ctx: Ctx) {
    const { sys, rec, user, install } = ctx;
    const notes: string[] = [];
    const run = (args: string[], input?: string) => sys.run(cliArgv(install, args), { user: user ?? undefined, input, timeoutMs: 120_000 });

    // Only a machine with no proxy of its own: then undo is removing ours, and nothing is lost.
    const existing = currentProxy(install.config_file, install.config_file ? sys.read(install.config_file) : null);
    if (existing && typeof existing === "object" && Object.keys(existing).length) {
      throw new Error("OpenClaw already has a proxy setting. Proxy mode would replace it: remove it first, or use host mode");
    }
    const ours = proxyPatch(ctx.firewall.proxy);
    rec.onUndo("remove OpenClaw's proxy setting", [cliArgv(install, ["config", "patch", "--stdin"])], {
      user: user ?? undefined,
      input: JSON.stringify({ proxy: null }),
    });
    const patched = await run(["config", "patch", "--stdin"], JSON.stringify(ours));
    if (patched.code !== 0) throw new Error(`openclaw config patch failed: ${(patched.stderr || patched.stdout).trim()}`);
    ctx.log(`OpenClaw's proxy set to http://${ctx.firewall.proxy}`);

    if (sys.euid === 0) await installSystemStore(sys, rec, ctx.caPem);
    if (install.runs.kind === "systemd-system" && sys.euid !== 0) {
      notes.push(`OpenClaw runs as a system unit: run connect with sudo, or add NODE_EXTRA_CA_CERTS=${ctx.caPath} to its unit yourself.`);
    } else {
      const envNote = await installNodeEnv(sys, rec, install, user, ctx.caPath);
      if (envNote) notes.push(envNote);
    }

    ctx.log("Restarting OpenClaw");
    const restarted = await restartOpenClaw(sys, install, user);
    if (restarted) notes.push(restarted);
    notes.push("Only OpenClaw's own requests go through the firewall. Shell commands and other programs on this machine do not.");
    return notes;
  },
  async status(sys: Sys, record: ConnectRecord) {
    // `config get` redacts the URL; `proxy validate` shows it, and makes a request through it.
    // The CA is passed as the gateway gets it, so the request checks what the gateway sees.
    const r = await sys.run([...record.cli, "proxy", "validate", "--json"], {
      user: record.user ?? undefined,
      env: { NODE_EXTRA_CA_CERTS: record.ca },
      timeoutMs: 90_000,
    });
    return validateChecks(r.stdout, `http://${record.firewall.proxy}`);
  },
};

interface Validate {
  config?: { enabled?: boolean; proxyUrl?: string };
  checks?: { kind: string; url: string; ok: boolean; status?: number; error?: string }[];
}

/** `openclaw proxy validate --json` as two checks: the setting, and a request through it. */
export function validateChecks(stdout: string, want: string): Check[] {
  let v: Validate = {};
  try {
    v = jsonFrom(stdout) as Validate;
  } catch {
    return [{ name: "OpenClaw proxy setting", ok: false, detail: "openclaw proxy validate gave no answer" }];
  }
  const url = v.config?.proxyUrl?.replace(/\/$/, "");
  const setting: Check = {
    name: "OpenClaw proxy setting",
    ok: v.config?.enabled === true && url === want,
    detail: url ? `${v.config?.enabled ? "on" : "off"}, ${url}` : "not set",
  };
  const allowed = v.checks?.find((c) => c.kind === "allowed");
  // Any HTTP answer, also the firewall's 403, means the request went through and the CA is trusted.
  const request: Check = {
    name: "request through OpenClaw's proxy",
    ok: typeof allowed?.status === "number",
    detail: allowed ? `${allowed.url} ${allowed.status ?? allowed.error ?? "failed"}` : "not checked",
  };
  return [setting, request];
}
