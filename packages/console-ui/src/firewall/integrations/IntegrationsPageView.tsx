import type { ReactNode } from "react";
import { PageHead } from "../../kit/PageHead";
import { Sec } from "../../kit/console-ui";
import type { ConnectorsView } from "../../lib/connectors-schema";
import type { McpServersView } from "../../lib/mcp-servers-schema";
import { IntegrationsPanel, type IntegrationsPanelProps } from "./IntegrationsPanel";
import { IntegrationsIntro } from "./OfficialCard";

/**
 * The body of `/dashboard/integrations`, apart from the loading, so the demo renders the same page
 * from fake data.
 */
export function IntegrationsPageView({
  connectors,
  mcp = null,
  panel,
  official,
}: {
  connectors: ConnectorsView;
  mcp?: McpServersView | null;
  /** Demo pages turn the panel's RPCs off and hand it a catalog. */
  panel?: Omit<IntegrationsPanelProps, "initial">;
  /** The control plane's own integrations, before the other apps (the console: Google, Drive, AgentMail, Phone). */
  official?: ReactNode;
}) {
  return (
    <>
      <PageHead title="Integrations" sub="Connect an app once for your organization, then choose which agents may use it." />
      <IntegrationsIntro />

      {official}

      <Sec
        title="Other apps"
        sub="GitHub, Notion, Slack, databases and more, through a connector on your firewall or any remote MCP server. You sign in once, and your firewall stores the credentials. Removing an app ends access at once, even when the agent is off."
      >
        <IntegrationsPanel initial={connectors} mcp={mcp} {...panel} />
      </Sec>
    </>
  );
}
