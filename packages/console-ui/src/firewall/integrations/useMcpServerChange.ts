"use client";

import { useApi } from "../../lib/api";
import { useFirewallChange } from "../change/useFirewallChange";
import type { McpServerChangeView } from "../../lib/mcp-servers-schema";

/** Follows one MCP server change from proposal to outcome (`useFirewallChange`, bound to the MCP servers RPC). */
export function useMcpServerChange(opts: { live: boolean; initial: McpServerChangeView | null; onSettled: () => void | Promise<unknown> }) {
  const api = useApi();
  return useFirewallChange<McpServerChangeView>({
    live: opts.live,
    initial: opts.initial,
    onSettled: opts.onSettled,
    rpc: { getChange: api.mcpServers.getChange, confirm: api.mcpServers.confirm, cancel: api.mcpServers.cancel },
    blank: (changeId) => ({
      id: changeId,
      vmId: null,
      serverId: null,
      name: "",
      kind: "add",
      summary: "",
      status: "queued",
      tofu: false,
      sentVia: null,
      attemptsLeft: null,
      expiresAt: null,
      authorizationUrl: null,
      error: null,
      createdAt: new Date().toISOString(),
      stuck: false,
    }),
  });
}
