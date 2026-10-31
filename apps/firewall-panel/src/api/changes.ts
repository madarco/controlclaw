import type { Schemas } from "@controlclaw/fw-api";
import type { FirewallChangeLike, FirewallChangeRpc } from "@controlclaw/console-ui/firewall/change";
import { FwApiError } from "./client";

type CommandAnswer = Schemas["CommandAnswer"];

/**
 * What a person reads when the firewall refused a change. The routes say it three ways: `{error}`
 * (a bad request), `{ok: false, message}` (the firewall said no), and `{result: {message}}` (the
 * channel routes).
 */
export function refusalText(e: unknown): string {
  if (e instanceof FwApiError) {
    const b = e.body as { message?: unknown; error?: unknown; result?: { message?: unknown } } | null;
    for (const m of [b?.result?.message, b?.message, b?.error]) if (typeof m === "string" && m) return m;
  }
  return e instanceof Error ? e.message : "The firewall refused the change";
}

/** Calls the API; a refusal becomes an error with the firewall's own words. */
export async function send<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (e) {
    throw new Error(refusalText(e), { cause: e });
  }
}

const KEPT = new Set(["applied", "awaiting_authorization", "unconfirmed"]);
/** A change the firewall still holds: the panel's API confirms at once, so one left waiting did not apply. */
const WAITING = new Set(["awaiting_code", "queued", "sent"]);

/**
 * The console follows a change until the firewall confirms it with a code. The panel's API applies
 * it at once and answers with the outcome, so the change is handed to the view already settled,
 * and `getChange` answers from what was kept here. `awaiting_authorization` (an OAuth sign-in) stays
 * so until `settle` is told it finished.
 */
export function settledChanges<T extends FirewallChangeLike>(blank: (id: string) => T) {
  const views = new Map<string, T>();
  let n = 0;
  return {
    /** The change view for an answer, kept for `getChange`; a refusal throws. */
    record(ans: CommandAnswer, fields: Partial<T> = {}): T {
      const data = (ans.data ?? {}) as { changeId?: unknown; summary?: unknown; tofu?: unknown; sentVia?: unknown; expiresAt?: unknown };
      if (!ans.ok) throw new Error(ans.message || "The firewall refused the change");
      if (WAITING.has(ans.status)) throw new Error(ans.message || "The firewall did not apply the change: it is waiting for a code");
      const id = typeof data.changeId === "string" && data.changeId ? data.changeId : `local-${++n}`;
      const status = KEPT.has(ans.status) ? ans.status : "applied";
      const view = {
        ...blank(id),
        ...fields,
        id,
        status,
        summary: typeof data.summary === "string" && data.summary ? data.summary : (fields.summary ?? "The change"),
        tofu: data.tofu === true,
        sentVia: typeof data.sentVia === "string" ? data.sentVia : null,
        expiresAt: status === "awaiting_authorization" && typeof data.expiresAt === "string" ? data.expiresAt : null,
        createdAt: new Date().toISOString(),
      } as T;
      views.set(id, view);
      return view;
    },
    /** A sign-in finished (the callback page said so): the change is applied, or failed with `error`. */
    settle(id: string, error: string | null) {
      const v = views.get(id);
      if (v) views.set(id, { ...v, status: error ? "failed" : "applied", error, expiresAt: null });
    },
    get: (id: string) => views.get(id),
    rpc: {
      getChange: async ({ changeId }) => views.get(changeId) ?? { ...blank(changeId), status: "expired", error: "That change is no longer there." },
      confirm: () => Promise.reject(new Error("No code is needed on this firewall")),
      cancel: async ({ changeId }) => {
        const v = views.get(changeId);
        if (v) views.set(changeId, { ...v, status: "cancelled" });
        return { changeId };
      },
    } satisfies FirewallChangeRpc<T>,
  };
}
