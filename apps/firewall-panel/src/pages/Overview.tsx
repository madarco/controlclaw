import { PageHead } from "@controlclaw/console-ui/kit/PageHead";
import { FirewallOverview } from "@controlclaw/console-ui/firewall/overview";

export function OverviewPage() {
  return (
    <>
      <PageHead title="Overview" sub="What went through this firewall: traffic, agents and the last requests." />
      <FirewallOverview canManage shields={false} />
    </>
  );
}
