import type { BrainOverviewView } from "@controlclaw/console-ui/lib/brain-stats";
import type { BrainAgentView } from "@controlclaw/console-ui/lib/brain-view";
import type { BrainSource, PanelBrainView } from "./brain";

/**
 * A brain held in memory, for `pnpm dev` with `VITE_FAKE_BRAIN=1` (never in a build). `?brain=`
 * picks a state for screenshots: `none`, `stopped`, `locked` (the emergency stop), `unreachable`,
 * `nokey`, `nopages` (its pages have no name yet) or, by default, a running brain. Changes apply at once, as on a standalone
 * firewall, and last until the page is reloaded.
 */

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

function state(): string {
  try {
    return new URLSearchParams(window.location.search).get("brain") ?? "running";
  } catch {
    return "running";
  }
}

function overview(running: boolean): BrainOverviewView {
  const now = Date.now();
  const start = Math.floor(now / HOUR) * HOUR - 23 * HOUR;
  const hours = Array.from({ length: 24 }, (_, i) => new Date(start + i * HOUR).toISOString());
  const wave = (scale: number) => hours.map((_, i) => Math.max(0, Math.round(scale * (0.4 + Math.sin(i / 3) * 0.35 + (i % 5) / 10))));
  const searches = wave(14);
  const saves = wave(4);
  const growth = Array.from({ length: 30 }, (_, i) => {
    const d = new Date(now - (29 - i) * DAY);
    return { day: d.toISOString().slice(0, 10), pages: i < 4 ? null : 220 + i * 31 + (i % 3) * 7, saves: (i * 7) % 23 };
  });
  return {
    hours,
    searches: { today: searches.reduce((a, b) => a + b, 0), yesterday: 141, hourly: searches },
    saves: { today: saves.reduce((a, b) => a + b, 0), yesterday: 38, hourly: saves },
    answerMs: { today: running ? 412 : null, hourly: hours.map((_, i) => 300 + ((i * 37) % 200)) },
    lastSavedAt: new Date(now - 4 * 60_000).toISOString(),
    latest: {
      at: new Date(now - 9 * 60_000).toISOString(),
      pageCount: 1_154,
      chunkCount: 6_310,
      byType: { person: 402, company: 188, meeting: 161, project: 120, note: 97, email: 84, concept: 51, deal: 31, atom: 9, other: 11 },
      diskUsedBytes: 1_300_000_000,
      diskFreeBytes: 37_700_000_000,
    },
    feed: [
      { kind: "saves", id: "s1", at: new Date(now - 4 * 60_000).toISOString(), agentVmId: "oc-1", agentName: "assistant", count: 3 },
      {
        kind: "changes",
        id: "c1",
        at: new Date(now - 9 * 60_000).toISOString(),
        changes: [
          { key: "meeting", label: "Meetings", delta: 4 },
          { key: "person", label: "People", delta: 2 },
        ],
      },
      { kind: "saves", id: "s2", at: new Date(now - 2 * HOUR).toISOString(), agentVmId: "oc-2", agentName: "research", count: 1 },
    ],
    growth,
    agents: [
      { vmId: "oc-1", searches: 412, saves: 96, lastAt: new Date(now - 4 * 60_000).toISOString() },
      { vmId: "oc-2", searches: 88, saves: 0, lastAt: new Date(now - 2 * HOUR).toISOString() },
    ],
  };
}

export function fakeBrain(): BrainSource {
  const s = state();
  const since = new Date(Date.now() - 6 * DAY).toISOString();
  let agents: BrainAgentView[] = [
    { vmId: "oc-1", name: "assistant", running: true, secured: true, connection: { scope: "read_write", since, autoCapture: false } },
    { vmId: "oc-2", name: "research", running: true, secured: true, connection: { scope: "read", since, autoCapture: false } },
    { vmId: "oc-3", name: "openclaw on the office mac mini, the one by the printer", running: true, secured: true, connection: null },
    { vmId: "oc-4", name: "laptop", running: false, secured: true, connection: null },
  ];
  let model = s === "nokey" ? null : "gpt-5.4-mini";
  let lockedByAdmin = false;
  let hostname: string | null = s === "nopages" ? null : "brain.example.com";
  if (s === "locked") agents = agents.map((a) => ({ ...a, stopped: true }));
  const delay = <T,>(v: T) => new Promise<T>((r) => setTimeout(() => r(v), 250));

  const view = (): PanelBrainView =>
    s === "none"
      ? { brain: null }
      : {
          brain: {
            vmId: "brain-1",
            name: "brain",
            address: "172.31.250.7",
            origin: s === "nopages" ? "connect" : "install",
            reachable: s !== "unreachable",
            service: s === "unreachable" ? null : { active: s !== "stopped" },
            locked: s === "locked" || lockedByAdmin,
            lockedByAdmin,
            stoppedAll: s === "locked",
            pages: hostname !== null,
            pagesUrl: hostname ? `https://${hostname}` : null,
            error: s === "unreachable" ? "the brain did not answer within 10 s" : null,
            autoSaveOff:
              "Not on a standalone firewall: it needs ControlClaw’s plugin on the agent, which `controlclaw connect` does not install. The agent saves when it decides to, or when you ask it.",
            version: "1.52.0",
            model,
            models:
              s === "nokey"
                ? []
                : [
                    { id: "gpt-5.4-mini", label: "GPT-5.4 mini", blurb: "Inexpensive. Enough for most brains." },
                    { id: "gpt-5.4", label: "GPT-5.4", blurb: "Better at reading long pages, about ten times the cost." },
                  ],
            needsKey: s === "nokey",
            agents,
            change: null,
          },
        };

  return {
    get: () => delay(view()),
    openPages: ({ page }) => delay({ url: page === "admin" ? "https://example.invalid/admin" : "https://example.invalid/__cc/brain" }),
    setLock: ({ locked }) => {
      lockedByAdmin = locked;
      return delay({ ok: true });
    },
    setPagesName: ({ hostname: h }) => {
      if (!h.includes(".")) return Promise.reject(new Error("hostname: a name with a dot and no port, such as brain.example.com"));
      hostname = h;
      return delay({ url: `https://${h}` });
    },
    area: {
      overview: () => delay(overview(s !== "stopped")),
      connect: ({ agentVmId, scope }) => {
        agents = agents.map((a) => (a.vmId === agentVmId ? { ...a, connection: { scope, since: a.connection?.since ?? new Date().toISOString(), autoCapture: false } } : a));
        return delay({ changeId: null });
      },
      disconnect: ({ agentVmId }) => {
        agents = agents.map((a) => (a.vmId === agentVmId ? { ...a, connection: null } : a));
        return delay({ ok: true });
      },
      setModel: ({ model: m }) => {
        model = m;
        return delay({ ok: true });
      },
      getChange: () => Promise.reject(new Error("No change is waiting.")),
      confirm: () => Promise.reject(new Error("No change is waiting.")),
      cancel: () => delay({ ok: true }),
    },
  };
}
