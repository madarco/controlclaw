import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { ApiProvider, useApi } from "@controlclaw/console-ui/lib/api";
import { SecurityRulesView } from "@controlclaw/console-ui/firewall/rules";
import { isSecurityTab } from "@controlclaw/console-ui/lib/security-rules-list";
import { CONTENT_CHANNELS } from "@controlclaw/console-ui/lib/content-rules-schema";
import { listAgents } from "../api/agents";
import { errorText } from "../api/client";
import { boxOptions, egress, listRules } from "../api/egress";
import { exitSummary, readExit } from "../api/exit";
import { connectedApps } from "../api/integrations";
import { ruleMetrics } from "../api/rules";
import { FormError } from "../auth/AuthFrame";

/** No team chat or voice on a standalone firewall: their channels are not offered. */
const CHANNELS = CONTENT_CHANNELS.filter((c) => c !== "teamchat" && c !== "voice");

/**
 * Security rules: Messages, Email, Websites, Integrations, Auto approve and Settings (the AI cards),
 * from the console's own view. The Auto approve rules are on the firewall, with their counts. No
 * mailboxes until AgentMail and Google come to the panel, so Email says how to add one.
 */
export function SecurityPage() {
  const api = useApi();
  const withCounts = useMemo(() => ({ ...api, ruleMetrics }), [api]);
  const q = useQuery({
    queryKey: ["security"],
    queryFn: async () => {
      const [websites, agents, ai, exit, apps] = await Promise.all([listRules(), listAgents(), egress.getEgressAiSettings(), readExit(), connectedApps()]);
      return { websites, boxes: boxOptions(agents), ai, exit: exitSummary(exit), apps };
    },
    staleTime: Infinity,
    gcTime: 0,
  });
  const params = new URLSearchParams(window.location.search);
  const type = params.get("type");
  return (
    <>
      {q.isPending ? (
        <div className="h-40 animate-pulse rounded-[14px] border border-line bg-bg-2" aria-busy="true" />
      ) : q.error ? (
        <FormError>{errorText(q.error)}</FormError>
      ) : (
        <ApiProvider api={withCounts}>
        <SecurityRulesView
          auto={[]}
          autoKept="firewall"
          websites={q.data.websites}
          boxes={q.data.boxes}
          mailboxes={[]}
          apps={q.data.apps}
          canManage
          canManageWebsites
          exit={q.data.exit}
          ai={q.data.ai}
          initialType={isSecurityTab(type) ? type : null}
          initialAgent={params.get("agent")}
          initialRule={params.get("rule")}
          initialNew={params.get("new") === "1"}
          codes={false}
          contentChannels={CHANNELS}
        />
        </ApiProvider>
      )}
    </>
  );
}
