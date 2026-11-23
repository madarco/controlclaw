import type { ConsoleApi } from "@controlclaw/console-ui/lib/api";
import type { BrainAgentView, BrainChangeView, BrainModelChoice } from "@controlclaw/console-ui/lib/brain-view";
import { httpBrain } from "./brain-http";

/**
 * What `POST /api/brain/open` opens. `pages` lands on the brain's Pages, where Lately, Ask, Import
 * and Export are one click away (the sign-in link has no other landing); `admin` is GBrain's own
 * admin page.
 */
export type BrainPageId = "pages" | "admin";

/**
 * The Brain page's own read (docs/plans/standalone-brain.md part C): the brain paired with this
 * firewall, whether it answers, its model and the agents that may use it. Counts are the shared
 * Overview's (`ConsoleApi.brain.overview`).
 */
export interface PanelBrainView {
  brain: null | {
    vmId: string;
    name: string;
    /** Where the firewall reaches it. */
    address: string | null;
    /** `install`: `controlclaw brain install` set GBrain up; `connect`: a GBrain that was already there. */
    origin: "install" | "connect" | null;
    /** The vm-agent in brain mode answered. */
    reachable: boolean;
    /** GBrain's own service, when the vm-agent answered. */
    service: null | { active: boolean };
    /** No agent can search or save: the emergency stop for everyone, or the admin's lock. */
    locked: boolean;
    /** The admin's lock (`setLock`). */
    lockedByAdmin: boolean;
    /** The emergency stop for everyone. */
    stoppedAll: boolean;
    /** Its pages have a name, so they can be opened. */
    pages: boolean;
    /** `https://<name>` of its pages, when they have one. */
    pagesUrl: string | null;
    /** Why the firewall could not read the brain, when it could not. */
    error: string | null;
    /** Why "Save what it learns automatically" is off here. */
    autoSaveOff: string | null;
    version: string | null;
    /** The model for its own calls, on a model key of this firewall. Null: none chosen yet. */
    model: string | null;
    models: BrainModelChoice[];
    /** No model key on this firewall that the brain can use (OpenAI or Vercel AI Gateway). */
    needsKey: boolean;
    agents: BrainAgentView[];
    /** A connection still on its way, if any. */
    change: BrainChangeView | null;
  };
}

export interface BrainSource {
  get(): Promise<PanelBrainView>;
  /** A one-time link that opens one of the brain's pages, signed in. */
  openPages(input: { page?: BrainPageId }): Promise<{ url: string }>;
  /** Locks every agent out of the brain, or lets them back. Connections are kept. */
  setLock(input: { locked: boolean }): Promise<unknown>;
  /** The name the browser reaches the brain's pages at. Set once. */
  setPagesName(input: { hostname: string }): Promise<{ url: string }>;
  area: NonNullable<ConsoleApi["brain"]>;
}

let current: BrainSource = httpBrain;

/**
 * Puts another source in place of the firewall's routes (`brain-http.ts`), before the app renders:
 * `main.tsx` does it for `pnpm dev` with `VITE_FAKE_BRAIN=1` (a brain held in memory, `fake-brain.ts`), which a build leaves out.
 */
export function setBrainSource(source: BrainSource): void {
  current = source;
}

/** The current source, read at each call, so `setBrainSource` reaches the shared views too. */
export const brainSource: BrainSource = {
  get: () => current.get(),
  openPages: (input) => current.openPages(input),
  setLock: (input) => current.setLock(input),
  setPagesName: (input) => current.setPagesName(input),
  area: {
    overview: (input) => current.area.overview(input),
    connect: (input) => current.area.connect(input),
    disconnect: (input) => current.area.disconnect(input),
    setModel: (input) => current.area.setModel(input),
    getChange: (input) => current.area.getChange(input),
    confirm: (input) => current.area.confirm(input),
    cancel: (input) => current.area.cancel(input),
  },
};

export const BRAIN_KEY = ["brain"] as const;

/** The one read of the brain, shared by the page and the sidebar so both ask the same way. */
export const brainQuery = { queryKey: BRAIN_KEY, queryFn: () => brainSource.get(), refetchInterval: 20_000, retry: 2 };

/** What was typed as the pages' name, without a scheme, a path or a trailing dot. */
export const pagesHostname = (t: string) => t.trim().replace(/^https?:\/\//i, "").replace(/[/?#].*$/, "").replace(/\.$/, "");
