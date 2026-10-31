import type { ConsoleApi } from "@controlclaw/console-ui/lib/api";
import type { ExitChangeKind, ExitChangeView, ExitView } from "@controlclaw/console-ui/lib/exit-schema";
import { presetById, templatesUseCountry } from "@controlclaw/console-ui/lib/exit-presets";
import { fw } from "./client";
import { send, settledChanges } from "./changes";
import { listRules } from "./egress";

/** `residential` in `GET /api/exit`: the exit store's status, snake_case (mitm-agent `core/exit.rs`). */
type Residential = {
  configured: boolean;
  provider?: string | null;
  sticky?: boolean;
  hint?: string | null;
  cap_bytes?: number | null;
  country?: string | null;
  last_check?: { at: number; ok: boolean; exit_ip?: string | null; exit_country?: string | null; error?: string | null } | null;
  usage?: { month?: string | null; bytes_in?: number; bytes_out?: number };
} | null;

export async function readExit(): Promise<Residential> {
  return ((await fw.get("/api/exit")) as { residential: Residential }).residential;
}

/** The exit as the Exit card reads it. The firewall keeps no templates in its status, so the preset's say whether a country can be asked for. */
export function toExitView(r: Residential, ruleCount: number): ExitView {
  const preset = presetById(r?.provider ?? "custom");
  const check = r?.last_check;
  return {
    configured: !!r?.configured,
    provider: r?.provider ?? "",
    providerName: preset.name,
    scheme: preset.scheme,
    host: preset.host,
    port: preset.port,
    usernameHint: r?.hint ?? null,
    sticky: !!r?.sticky,
    country: r?.country ?? null,
    // Another provider's templates are the owner's, which the status does not carry: the country is
    // offered, and the firewall uses it if the templates have a place for it.
    supportsCountry: r?.provider === "custom" || templatesUseCountry(preset.usernameTemplate, preset.passwordTemplate),
    state: r?.configured ? "active" : "none",
    lastError: null,
    capBytes: r?.cap_bytes ?? null,
    check: check ? { at: new Date(check.at * 1000).toISOString(), ok: check.ok, exitIp: check.exit_ip ?? null, exitCountry: check.exit_country ?? null, error: check.error ?? null } : null,
    usage: { month: r?.usage?.month ?? null, bytesIn: r?.usage?.bytes_in ?? 0, bytesOut: r?.usage?.bytes_out ?? 0 },
    ruleCount,
    canManage: true,
    hasFirewall: true,
  };
}

/** What Security rules' Websites tab needs of the exit. */
export function exitSummary(r: Residential): { configured: boolean; country: string | null; supportsCountry: boolean } {
  const v = toExitView(r, 0);
  return { configured: v.configured, country: v.country, supportsCountry: v.supportsCountry };
}

export async function exitView(): Promise<ExitView> {
  const [r, rules] = await Promise.all([readExit(), listRules()]);
  return toExitView(r, rules.filter((x) => x.enabled && x.exit === "residential").length);
}

const changes = settledChanges<ExitChangeView>((id) => ({
  id,
  kind: "settings",
  summary: "",
  status: "queued",
  sentVia: null,
  attemptsLeft: null,
  expiresAt: null,
  error: null,
  createdAt: new Date().toISOString(),
  tofu: false,
  stuck: false,
}));

const kindOf = async (): Promise<ExitChangeKind> => ((await readExit())?.configured ? "replace" : "add");

export const exit: ConsoleApi["exit"] = {
  getExit: exitView,
  async connectExit(input) {
    const kind = await kindOf();
    const ans = await send(() =>
      fw.put("/api/exit", {
        body: {
          provider: input.provider,
          providerName: presetById(input.provider).name,
          scheme: input.scheme ?? "http",
          host: input.host,
          port: input.port,
          username: input.username ?? "",
          password: input.password,
          usernameTemplate: input.usernameTemplate,
          passwordTemplate: input.passwordTemplate,
          sticky: input.sticky ?? false,
          capBytes: input.capBytes ?? null,
          country: input.country || null,
        },
      }),
    );
    return changes.record(ans, { kind, summary: kind === "add" ? "Connect the exit" : "Replace the exit" });
  },
  async updateExitSettings(input) {
    const body: Record<string, unknown> = {};
    if (input.sticky !== undefined) body.sticky = input.sticky;
    if (input.capBytes !== undefined) body.capBytes = input.capBytes;
    if (input.country !== undefined) body.country = input.country || null;
    return changes.record(await send(() => fw.patch("/api/exit", { body })), { kind: "settings", summary: "Change the exit's settings" });
  },
  async removeExit() {
    return changes.record(await send(() => fw.delete("/api/exit", { body: {} })), { kind: "remove", summary: "Remove the exit" });
  },
  checkExitNow: () => send(() => fw.post("/api/exit/check", { body: {} })),
  getExitChange: ({ changeId }) => changes.rpc.getChange({ changeId }),
  confirmExit: changes.rpc.confirm,
  cancelExit: changes.rpc.cancel,
};
