import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { EgressPageView } from "@controlclaw/console-ui/firewall/egress";
import { EgressAiSections } from "@controlclaw/console-ui/firewall/panel";
import { listAgents } from "../api/agents";
import { errorText } from "../api/client";
import { boxOptions, egress, listRules } from "../api/egress";
import { exitView } from "../api/exit";
import { FormError } from "../auth/AuthFrame";

/** Internet access: your own exit proxy, the site rules, then the firewall's AI review. */
export function InternetPage() {
  // Read once: the shared views keep their own state from here, as on the console.
  const q = useQuery({
    queryKey: ["internet"],
    queryFn: async () => {
      const [rules, agents, ai, exit] = await Promise.all([listRules(), listAgents(), egress.getEgressAiSettings(), exitView()]);
      return { rules, vmOptions: boxOptions(agents), ai, exit };
    },
    staleTime: Infinity,
    gcTime: 0,
  });
  // A link to a section (`#ai-review`) lands before the section exists: go to it once it does.
  const ready = !!q.data;
  useEffect(() => {
    const id = window.location.hash.slice(1);
    if (ready && id) document.getElementById(id)?.scrollIntoView({ block: "start" });
  }, [ready]);
  if (q.isPending) return <div className="h-40 animate-pulse rounded-[14px] border border-line bg-bg-2" aria-busy="true" />;
  if (q.error) return <FormError>{errorText(q.error)}</FormError>;
  return (
    <>
      <EgressPageView rules={q.data.rules} vmOptions={q.data.vmOptions} canManage exit={q.data.exit} exitChange={null} exitHomeText="Traffic leaves from your firewall's own address" />
      <EgressAiSections initial={q.data.ai} page="security" />
    </>
  );
}
