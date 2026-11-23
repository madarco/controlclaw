import type { BrainOverviewView } from "@controlclaw/console-ui/lib/brain-stats";
import { categoryLabel } from "@controlclaw/console-ui/lib/brain-stats";
import type { BrainScopeId } from "@controlclaw/console-ui/lib/brain-view";
import type { Schemas } from "@controlclaw/fw-api";
import { fw } from "./client";
import { send } from "./changes";
import type { BrainSource, PanelBrainView } from "./brain";

type Detail = Schemas["BrainDetail"];
type Overview = Schemas["BrainOverview"];

/** `GET /api/brain` as the Brain page reads it (cc-local `api/brain.rs`, its twin). */
export function toPanelBrain(b: Detail | null | undefined): PanelBrainView {
  if (!b) return { brain: null };
  return {
    brain: {
      vmId: b.vmId,
      name: b.name,
      address: b.address ?? null,
      origin: b.origin === "install" || b.origin === "connect" ? b.origin : null,
      reachable: b.reachable,
      service: b.service ? { active: b.service.active } : null,
      locked: b.locked,
      lockedByAdmin: b.lockedByAdmin,
      stoppedAll: b.stoppedAll,
      pages: b.pages,
      pagesUrl: b.pagesUrl ?? null,
      error: b.brainError || null,
      autoSaveOff: b.autoSave.available ? null : b.autoSave.reason || null,
      version: b.version ?? null,
      model: b.model ?? null,
      models: b.models.map((m) => ({ id: m.id, label: m.label, blurb: m.blurb })),
      needsKey: b.needsKey,
      agents: b.agents.map((a) => ({
        vmId: a.vmId,
        name: a.name,
        running: a.running,
        secured: a.secured,
        connection: a.connection ? { scope: a.connection.scope as BrainScopeId, since: a.connection.since, autoCapture: false } : null,
        stopped: a.stopped,
      })),
      change: null,
    },
  };
}

/** `GET /api/brain/overview`: the same shape, with the kinds named as people say them. */
export function toOverview(o: Overview): BrainOverviewView {
  return {
    ...o,
    lastSavedAt: o.lastSavedAt ?? null,
    answerMs: { today: o.answerMs.today ?? null, hourly: o.answerMs.hourly },
    latest: o.latest
      ? { ...o.latest, diskUsedBytes: o.latest.diskUsedBytes ?? null, diskFreeBytes: o.latest.diskFreeBytes ?? null }
      : null,
    feed: o.feed.map((f) =>
      f.kind === "changes"
        ? { kind: "changes", id: f.id, at: f.at, changes: f.changes.map((c) => ({ ...c, label: categoryLabel(c.key) })) }
        : { kind: "saves", id: f.id, at: f.at, agentVmId: f.agentVmId ?? null, agentName: f.agentName ?? null, count: f.count },
    ),
    growth: o.growth.map((g) => ({ ...g, pages: g.pages ?? null })),
    agents: o.agents.map((a) => ({ ...a, lastAt: a.lastAt ?? null })),
  } as BrainOverviewView;
}

const noChange = (): Promise<never> => Promise.reject(new Error("No change is waiting: the firewall applies a change at once."));

/** The firewall's own brain routes (docs/standalone/panel-api.md, Brain). */
export const httpBrain: BrainSource = {
  get: async () => toPanelBrain((await fw.get("/api/brain")).brain),
  openPages: async ({ page }) => send(() => fw.post("/api/brain/open", { body: { page: page ?? "pages" } })),
  setLock: async ({ locked }) => {
    const ans = await send(() => fw.put("/api/brain/lock", { body: { locked } }));
    if (!ans.ok) throw new Error(ans.message || (locked ? "The firewall did not lock the brain" : "The firewall did not unlock the brain"));
    return ans;
  },
  setPagesName: async ({ hostname }) => send(() => fw.put("/api/brain/pages", { body: { hostname } })),
  area: {
    overview: async () => toOverview(await fw.get("/api/brain/overview")),
    connect: async ({ agentVmId, scope }) => {
      const ans = await send(() => fw.put("/api/brain/agents/{vmId}", { path: { vmId: agentVmId }, body: { scope } }));
      if (!ans.ok) throw new Error(ans.message || "The firewall did not connect the agent");
      return { changeId: null };
    },
    disconnect: async ({ agentVmId }) => send(() => fw.delete("/api/brain/agents/{vmId}", { path: { vmId: agentVmId }, body: {} })),
    setModel: async ({ model }) => send(() => fw.put("/api/brain/model", { body: { model } })),
    getChange: noChange,
    confirm: noChange,
    cancel: async () => ({ ok: true }),
  },
};
