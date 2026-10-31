import type { Schemas } from "@controlclaw/fw-api";
import type { ConsoleApi } from "@controlclaw/console-ui/lib/api";
import type { EgressBoxOption, EgressRuleListItem } from "@controlclaw/console-ui/lib/egress-schema";
import type { AiReviewProvider, EgressAiView } from "@controlclaw/console-ui/lib/egress-ai-schema";
import { fw } from "./client";
import { listAgents, type AgentRow } from "./agents";

/** A site rule as the shared list holds it: the fields the API may leave out are null. */
export function toRule(r: Schemas["EgressRule"]): EgressRuleListItem {
  return {
    ...r,
    matchPath: r.matchPath ?? null,
    matchMethod: r.matchMethod ?? null,
    matchPort: r.matchPort ?? null,
    exitCountry: r.exitCountry ?? null,
    vmId: r.vmId ?? null,
    aiPolicy: r.aiPolicy ?? null,
  };
}

export async function listRules(): Promise<EgressRuleListItem[]> {
  return (await fw.get("/api/egress/rules")).map(toRule);
}

export function boxOptions(agents: AgentRow[]): EgressBoxOption[] {
  return agents.map((a) => ({ id: a.vm_id, name: a.name, kind: a.role === "gbrain" ? "brain" : "agent" }));
}

export const egressRules: ConsoleApi["egressRules"] = {
  create: async (input) => toRule(await fw.post("/api/egress/rules", { body: input as Schemas["NewEgressRule"] })),
  update: async ({ id, ...patch }) => toRule(await fw.patch("/api/egress/rules/{id}", { path: { id }, body: patch as Schemas["EgressRulePatch"] })),
  remove: ({ id }) => fw.delete("/api/egress/rules/{id}", { path: { id }, body: {} }),
  cycle: async ({ id }) => toRule(await fw.post("/api/egress/rules/{id}/cycle", { path: { id }, body: {} })),
};

/**
 * `/api/egress/ai` as the shared AI cards read it. The firewall's panel has no people to email and
 * no review history page (`local`), and no fixed question text to show.
 */
export function toAiView(v: Schemas["AiView"], agents: AgentRow[]): EgressAiView {
  const s = v.settings;
  // A key removed in Settings stays named in the saved settings; sending it back would be refused.
  const credentialId = v.credentials.some((c) => c.id === s.credentialId) ? (s.credentialId ?? null) : null;
  return {
    canManage: true,
    hasFirewall: true,
    splitSupported: true,
    historyAvailable: false,
    local: true,
    settings: {
      // The AI Firewall cannot run on a key that is gone, and the API refuses it on without one: shown
      // and sent back as off, so the other switch and the instructions can still be saved.
      enabled: s.enabled && credentialId !== null,
      logReviewEnabled: s.logReviewEnabled,
      logReviewNotify: "nobody",
      logReviewNotifyUserIds: [],
      logReviewNotifyMinSeverity: "medium",
      credentialId,
      model: s.model,
      dailyCallCap: s.dailyCallCap,
      scanIntervalHours: s.scanIntervalHours,
      autoApprovePerHour: s.autoApprovePerHour,
      requestInstructions: s.requestInstructions ?? null,
      reviewInstructions: s.reviewInstructions ?? null,
    },
    // The firewall lists the keys its review can use; the provider names are its own.
    credentials: v.credentials.map((c) => ({ ...c, provider: c.provider as AiReviewProvider })),
    questions: { request: "", review: "" },
    agents: agents.map((a) => ({ id: a.vm_id, name: a.name })),
    members: [],
    lastScan: null,
  };
}

async function aiView(): Promise<EgressAiView> {
  const [v, agents] = await Promise.all([fw.get("/api/egress/ai"), listAgents()]);
  return toAiView(v, agents);
}

type AiInput = Schemas["AiSettingsInput"];

/** The settings the API takes; the notify fields are the console's and are dropped. */
function aiInput(s: EgressAiView["settings"] | Parameters<ConsoleApi["egress"]["updateEgressAiSettings"]>[0]): AiInput {
  return {
    enabled: s.enabled,
    logReviewEnabled: s.logReviewEnabled,
    credentialId: s.credentialId,
    model: s.model,
    dailyCallCap: s.dailyCallCap,
    scanIntervalHours: s.scanIntervalHours,
    autoApprovePerHour: s.autoApprovePerHour,
    ...(s.requestInstructions !== undefined ? { requestInstructions: s.requestInstructions } : {}),
    ...(s.reviewInstructions !== undefined ? { reviewInstructions: s.reviewInstructions } : {}),
  };
}

export const egress: ConsoleApi["egress"] = {
  getEgressAiSettings: aiView,
  async updateEgressAiSettings(input) {
    await fw.put("/api/egress/ai", { body: aiInput(input) });
    return aiView();
  },
  // The API has no instructions-only call: the saved settings go back as they are, with the new words.
  async updateEgressAiInstructions(input) {
    const cur = toAiView(await fw.get("/api/egress/ai"), []);
    await fw.put("/api/egress/ai", { body: { ...aiInput({ ...cur.settings, requestInstructions: undefined, reviewInstructions: undefined }), ...input } });
    return aiView();
  },
  scanEgressNow: () => fw.post("/api/egress/scan", { body: {} }),
  openAiReviewHistory: () => Promise.reject(new Error("The review history is not on this firewall's panel yet")),
};
