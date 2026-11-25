import { ScrollText } from "lucide-react";
import { Button } from "@controlclaw/console-ui/ui/button";
import { PageHead } from "@controlclaw/console-ui/kit/PageHead";
import { FirewallOverview } from "@controlclaw/console-ui/firewall/overview";
import { PANEL_ROUTES } from "../routes";

export function OverviewPage() {
  return (
    <>
      <PageHead
        title="Overview"
        sub="What went through this firewall: traffic, agents and the last requests."
        actions={
          // The firewall's own Logs page, through the panel's door (OpenFirewallPage).
          <Button size="sm" variant="outline" asChild>
            <a href={PANEL_ROUTES.firewallLogs} data-testid="firewall-logs-link">
              <ScrollText className="h-3.5 w-3.5" aria-hidden="true" /> Logs
            </a>
          </Button>
        }
      />
      <FirewallOverview canManage shields={false} />
    </>
  );
}
