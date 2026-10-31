"use client";

import { AppLink as Link } from "../../lib/link";
import { ExternalLink, Loader2, ShieldAlert } from "lucide-react";
import { ChangeList, Disclosure } from "../../kit/console-ui";
import type { ConnectorChangeView, ConnectorConnectionView, ConnectorFirewallView } from "../../lib/connectors-schema";
import { RelativeTime } from "../../kit/RelativeTime";

/** Pieces the Integrations page and an agent's Integrations tab draw the same way. */

export type Tone = "allow" | "ask" | "block" | "muted";

/** The line under a connection's name: our own state first, then the runtime's own word. */
export function statusLine(c: ConnectorConnectionView): { text: string; tone: Tone } {
  if (c.state === "pending") return { text: "Waiting for the firewall to connect it", tone: "ask" };
  if (c.state === "failed") return { text: c.lastError ?? "The app refused these credentials", tone: "block" };
  if (c.lastError) return { text: c.lastError, tone: "block" };
  if (c.runtimeState === "reauth_required") return { text: "Sign in again: the access token expired", tone: "block" };
  if (c.runtimeState && c.runtimeState !== "active") return { text: c.runtimeState.replace(/_/g, " "), tone: "ask" };
  if (c.agents.length === 0) return { text: "Connected, no agent uses it yet", tone: "muted" };
  const failed = c.agents.find((a) => a.state === "failed");
  if (failed) return { text: `${failed.name}: ${failed.lastError ?? "not applied"}`, tone: "block" };
  if (c.agents.some((a) => a.state === "pending")) return { text: "Adding it to the agents…", tone: "ask" };
  return { text: `Used by ${c.agents.map((a) => a.name).join(", ")}`, tone: "allow" };
}

/** What the history and the sign-in note read of a change: app connections and MCP servers alike. */
type ChangeLine = Pick<ConnectorChangeView, "summary" | "status" | "error" | "tofu" | "sentVia" | "createdAt"> & { kind: string };

const STATUS_LABEL: Record<ConnectorChangeView["status"], string> = {
  applied: "applied",
  failed: "failed",
  expired: "expired",
  cancelled: "cancelled",
  awaiting_code: "waiting for the code",
  awaiting_authorization: "waiting for the sign-in",
  queued: "queued",
};

/** "Recent changes", folded: what was asked for, whether it landed, how the code came. */
export function ChangeHistory({ recent, testId = "connectors-history" }: { recent: ChangeLine[]; testId?: string }) {
  if (recent.length === 0) return null;
  return (
    <Disclosure title="Recent changes" meta={recent.length} data-testid={testId}>
      <ChangeList
        items={recent.map((c) => ({
          ok: c.status === "applied" ? true : c.status === "failed" ? false : null,
          what: c.summary || c.kind,
          err: c.error,
          meta: (
            <>
              {STATUS_LABEL[c.status]}
              {c.status === "applied" ? (c.tofu ? " · first use" : c.sentVia ? ` · code via ${c.sentVia.split(":")[0]}` : "") : ""} ·{" "}
              <RelativeTime date={c.createdAt} />
            </>
          ),
        }))}
      />
    </Disclosure>
  );
}

/**
 * Why nothing can be changed right now. Three separate reasons, and they read differently: no
 * firewall at all, one that is not reporting, and one whose software predates the connector.
 */
export function FirewallNotice({ firewall, firewallHref }: { firewall: ConnectorFirewallView; firewallHref: string }) {
  if (firewall.reachable && firewall.supported) return null;
  if (firewall.note && firewall.reachable) {
    return (
      <div className="flex gap-3 rounded-xl border border-ask-border bg-ask-soft px-4 py-3 text-[13.5px] text-ask-fg" data-testid="connectors-no-firewall">
        <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
        <div>{firewall.note}</div>
      </div>
    );
  }
  return (
    <div className="flex gap-3 rounded-xl border border-ask-border bg-ask-soft px-4 py-3 text-[13.5px] text-ask-fg" data-testid="connectors-no-firewall">
      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
      <div>
        {firewall.state === "none" || firewall.state === "inactive"
          ? "Your organization has no firewall yet, so you can’t connect apps. Create a secured agent first: it comes with a firewall."
          : firewall.state === "starting"
            ? "Your firewall is still being set up. You can connect apps once it reports in."
            : !firewall.reachable
              ? "Your firewall hasn’t reported in recently. App connections go through it, so changes wait until it is back online."
              : "Your firewall doesn’t have the app connector yet. Update the firewall to use this page."}{" "}
        <Link href={firewallHref} className="font-medium underline">
          Open Firewall
        </Link>
      </div>
    </div>
  );
}

/** While a change is with the firewall and there is nothing for the person to do yet. */
export function PendingNote({ note }: { note: string | null }) {
  return (
    <div className="flex items-center gap-2 rounded-xl border border-line bg-surface px-4 py-3 text-[13.5px] text-ink-2" data-testid="connectors-change-pending">
      <Loader2 className="h-4 w-4 animate-spin" />
      {note ?? "Sending the change to your firewall…"}
    </div>
  );
}

/** The firewall started an OAuth authorization: send the person to the provider. */
export function AuthorizeNote({ change, onCancel, where = "the app" }: { change: Pick<ConnectorChangeView, "summary" | "authorizationUrl">; onCancel: () => void; where?: string }) {
  if (!change.authorizationUrl) return null;
  return (
    <div className="grid gap-2 rounded-xl border border-ask-border bg-ask-soft px-4 py-3 text-[13.5px] text-ask-fg" data-testid="connectors-authorize">
      <div className="font-medium">{change.summary}</div>
      <p>Sign in at {where} to finish. ControlClaw then brings you back to this tab and your firewall completes the connection.</p>
      <div className="flex items-center gap-3">
        <a
          href={change.authorizationUrl}
          target="_blank"
          rel="noreferrer"
          className="inline-flex h-[32px] items-center gap-1.5 rounded-[10px] bg-ink px-3 text-[13px] font-semibold text-surface"
          data-testid="connectors-authorize-link"
        >
          Sign in at {where} <ExternalLink className="h-3.5 w-3.5" />
        </a>
        <button type="button" onClick={onCancel} className="text-[13px] font-medium underline">
          Cancel
        </button>
      </div>
    </div>
  );
}
