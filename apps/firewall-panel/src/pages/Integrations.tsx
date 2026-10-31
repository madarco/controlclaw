import { useQuery } from "@tanstack/react-query";
import { IntegrationsPageView, OfficialCard } from "@controlclaw/console-ui/firewall/integrations";
import { agentMailStatusLine } from "@controlclaw/console-ui/lib/agentmail-words";
import type { StatusPillTone } from "@controlclaw/console-ui/kit/StatusPill";
import { GOOGLE_SERVICE_LABEL, readAgentMail, readGoogle, type AgentMailView, type GoogleView } from "../api/accounts";
import { listAgents, type AgentRow } from "../api/agents";
import { FwApiError, errorText } from "../api/client";
import { integrations, mcpServers } from "../api/integrations";
import { FormError } from "../auth/AuthFrame";

const SERVICE_LABEL = GOOGLE_SERVICE_LABEL;

/**
 * A card's read, which may fail on its own while the rest of the page shows: "not running" (a module
 * the firewall does not run answers 404), or that it could not be read.
 */
type Read<T> = { ok: true; value: T } | { ok: false; notRunning: boolean };
const settle = <T,>(p: Promise<T>): Promise<Read<T>> => p.then((value) => ({ ok: true as const, value }), (e) => ({ ok: false as const, notRunning: e instanceof FwApiError && e.status === 404 }));
const missing = (r: Read<unknown>) => (!r.ok && r.notRunning ? "Not running on this firewall" : "Couldn't read it: refresh the page");

/**
 * Integrations: Google and AgentMail first (their own pages), then connected apps (the pinned
 * OpenConnector catalog, searched here) and MCP servers, from the console's own view.
 */
export function IntegrationsPage() {
  const q = useQuery({
    queryKey: ["integrations"],
    queryFn: async () => {
      const [connectors, mcp, google, agentmail, agents] = await Promise.all([integrations.list(), mcpServers.list(), settle(readGoogle()), settle(readAgentMail()), listAgents().catch(() => [])]);
      return { connectors, mcp, google, agentmail, agents };
    },
    staleTime: Infinity,
    gcTime: 0,
  });
  if (q.isPending) return <div className="h-40 animate-pulse rounded-[14px] border border-line bg-bg-2" aria-busy="true" />;
  if (q.error) return <FormError>{errorText(q.error)}</FormError>;
  const source = new URLSearchParams(window.location.search).get("source");
  const { google, agentmail, agents } = q.data;
  return (
    <IntegrationsPageView
      connectors={q.data.connectors}
      mcp={q.data.mcp}
      panel={source === "mcp" ? { initialSource: "mcp" } : undefined}
      official={
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <GoogleCard google={google} agents={agents} />
          <AgentMailCard mail={agentmail} agents={agents} />
        </div>
      }
    />
  );
}

function names(ids: Array<string | null>, agents: AgentRow[]) {
  const by = new Map(agents.map((a) => [a.vm_id, a.name]));
  return [...new Set(ids.filter((x): x is string => !!x))].map((id) => ({ id, name: by.get(id) ?? id }));
}

function GoogleCard({ google: read, agents }: { google: Read<GoogleView>; agents: AgentRow[] }) {
  const google = read.ok ? read.value : null;
  const a = google?.account;
  const connected = !!a?.connected && !a.failed;
  const status: { text: string; tone: StatusPillTone } = !google
    ? { text: missing(read), tone: "muted" }
    : !a
      ? { text: "Not set up", tone: "muted" }
      : a.failed
        ? { text: a.failed, tone: "block" }
        : a.connected
          ? { text: "Connected", tone: "allow" }
          : { text: "Waiting for the sign-in", tone: "ask" };
  return (
    <OfficialCard
      href="/integrations/google"
      name="Google Workspace"
      tag="One Google account for your agents"
      mark="G"
      color="#1a73e8"
      setUp={!!a}
      connected={connected}
      can={a?.services.length ? a.services.slice(0, 3).map((s) => SERVICE_LABEL[s] ?? s) : ["Mail", "Calendar", "Drive"]}
      status={status}
      account={a?.accountLabel}
      agents={names((google?.agents ?? []).filter((x) => x.granted).map((x) => x.vmId), agents)}
      hint="Sign in with your own Google OAuth app. Every secret stays on your firewall."
      data-testid="google-card"
    />
  );
}

function AgentMailCard({ mail: read, agents }: { mail: Read<AgentMailView>; agents: AgentRow[] }) {
  const mail = read.ok ? read.value : null;
  const line = mail ? agentMailStatusLine({ account: { status: mail.status }, inboxes: mail.inboxes }) : { text: missing(read), tone: "muted" as const };
  const setUp = !!mail && mail.status !== "disconnected";
  return (
    <OfficialCard
      href="/integrations/agentmail"
      name="AgentMail"
      tag="An inbox per agent"
      mark="@"
      color="#7c4dff"
      setUp={setUp}
      connected={setUp && line.tone === "allow"}
      can={["Its own address", "Replies in the thread", "Rules for who it emails"]}
      status={line}
      account={mail?.humanEmail}
      agents={names((mail?.inboxes ?? []).map((i) => i.vmId), agents)}
      hint="Give each agent its own email address. It replies in the same thread."
      data-testid="agentmail-card"
    />
  );
}
