import { useQuery } from "@tanstack/react-query";
import { Bot } from "lucide-react";
import { PageHead } from "@controlclaw/console-ui/kit/PageHead";
import { Badge, Card, EmptyState, Sec } from "@controlclaw/console-ui/kit/console-ui";
import { AGENTS_KEY, listAgents } from "../api/agents";
import { errorText, fw } from "../api/client";
import { FormError } from "../auth/AuthFrame";
import { PairAgent, PendingCodes } from "./PairAgent";

export function AgentsPage() {
  const agents = useQuery({ queryKey: AGENTS_KEY, queryFn: listAgents, refetchInterval: 30_000 });
  const list = agents.data ?? [];
  // Each agent's last 24 hours, from the overview's per-agent rows.
  const traffic = useQuery({
    queryKey: ["agents-traffic"],
    queryFn: async () => new Map((await fw.get("/api/overview", { query: { range: "24h" } })).byAgent.flatMap((a) => (a.vmId ? [[a.vmId, a] as const] : []))),
    refetchInterval: 60_000,
  });
  return (
    <>
      <PageHead title="Agents" sub="The machines whose traffic goes through this firewall." />
      <Card data-testid="agents">
        {agents.isPending ? (
          <div className="px-4 py-6 text-[13.5px] text-ink-2">Loading…</div>
        ) : agents.error ? (
          <div className="px-4 py-4">
            <FormError>{errorText(agents.error)}</FormError>
          </div>
        ) : list.length === 0 ? (
          <EmptyState icon={Bot} title="No agents yet">
            Connect a machine that runs OpenClaw with a pairing code below.
          </EmptyState>
        ) : (
          <ul className="divide-y divide-line">
            {list.map((a) => (
              <li key={a.vm_id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3">
                <span className="min-w-0 flex-1 truncate text-[14px] font-medium text-ink">{a.name}</span>
                {a.role === "gbrain" ? <Badge tone="brand">Brain</Badge> : null}
                {a.private_ip ? <span className="font-mono text-[12.5px] text-ink-2">{a.private_ip}</span> : null}
                {a.hostname ? <span className="w-full truncate text-[12.5px] text-ink-2 sm:w-auto">{a.hostname}</span> : null}
                {traffic.data ? <Traffic row={traffic.data.get(a.vm_id)} /> : null}
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Sec title="Connect an agent" sub="Make a one-time code here, then run the command on the agent's machine.">
        <Card className="p-4 sm:p-5">
          <PairAgent />
        </Card>
        <PendingCodes />
      </Sec>
    </>
  );
}

/** "1,204 requests · 3 blocked" over the last 24 hours, or that it sent none. */
function Traffic({ row }: { row?: { total: number; blocked: number } }) {
  if (!row || row.total === 0) return <span className="w-full text-[12.5px] text-ink-2 sm:w-auto">No requests in 24h</span>;
  return (
    <span className="w-full text-[12.5px] text-ink-2 sm:w-auto" data-testid="agent-traffic">
      {row.total.toLocaleString()} {row.total === 1 ? "request" : "requests"}
      {row.blocked ? <span className="text-block-fg"> · {row.blocked.toLocaleString()} blocked</span> : null} in 24h
    </span>
  );
}
