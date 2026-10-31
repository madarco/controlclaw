import type { Schemas } from "@controlclaw/fw-api";
import type { ConsoleApi } from "@controlclaw/console-ui/lib/api";
import type { AgentChannelChangeView, AgentChannelsView, ConnectionView } from "@controlclaw/console-ui/lib/channels-schema";
import { fw } from "./client";
import { send, settledChanges } from "./changes";
import { listAgents, type AgentRow } from "./agents";

type Channel = Schemas["Channel"];
type ChannelChange = Schemas["ChannelChange"];

function toConnection(c: Channel, agents: AgentRow[]): ConnectionView {
  const agent = c.vmId ? agents.find((a) => a.vm_id === c.vmId) : undefined;
  return {
    id: c.id,
    type: c.type as ConnectionView["type"],
    label: c.label ?? null,
    secretHint: c.hint || null,
    state: "active",
    mode: "placeholder",
    assignedVm: c.vmId ? { vmId: c.vmId, name: agent?.name ?? c.agentName ?? c.vmId, displayName: null, status: "running" } : null,
    // The firewall's API does not carry what the agent last said about the channel.
    boxStatus: null,
    lastError: null,
    updatedAt: new Date().toISOString(),
  };
}

/**
 * One agent's channels as the console's panel reads them. The API has no live read of the agent
 * (its channel status, who is waiting to be approved), so `live` is empty and the panel is told not
 * to show the pairing list (`pairings={false}`).
 */
export function toAgentChannels(vmId: string, channels: Channel[], agents: AgentRow[]): AgentChannelsView {
  const agent = agents.find((a) => a.vm_id === vmId);
  const all = channels.map((c) => toConnection(c, agents));
  return {
    vm: { vmId, name: agent?.name ?? vmId, displayName: null, status: "running" },
    canManage: true,
    firewall: { state: "active", reachable: true },
    assigned: all.filter((c) => c.assignedVm?.vmId === vmId),
    available: all.filter((c) => !c.assignedVm),
    pending: null,
    recent: [],
    live: { boxRead: "ok", status: {}, pairings: [], pairingsError: null, whatsappLogin: null },
  };
}

const changes = settledChanges<AgentChannelChangeView>((id) => ({
  id, connectionId: null, vmId: null, channelType: "telegram", kind: "add", summary: "", status: "queued", tofu: false,
  sentVia: null, attemptsLeft: null, expiresAt: null, error: null, createdAt: new Date().toISOString(), stuck: false,
}));

/** The channel routes answer `{result, channels}`; the result is the change. */
function record(res: ChannelChange, fields: Partial<AgentChannelChangeView>): AgentChannelChangeView {
  const unconfirmed = (res.result.data as { unconfirmed?: unknown } | null)?.unconfirmed === true;
  const view = changes.record(res.result, fields);
  return unconfirmed ? { ...view, status: "unconfirmed" } : view;
}

export const channels: ConsoleApi["channels"] = {
  async listAgent({ vmId }) {
    const [res, agents] = await Promise.all([fw.get("/api/channels"), listAgents()]);
    return toAgentChannels(vmId, res.channels, agents);
  },
  async add(input) {
    const res = await send(() =>
      fw.post("/api/channels", {
        body: { type: input.type, botToken: input.botToken, appToken: input.type === "slack" ? input.appToken : null, label: input.label || null, vmId: input.vmId ?? null },
      }),
    );
    return record(res, { channelType: input.type, vmId: input.vmId ?? null, kind: "add", summary: `Add ${input.type === "slack" ? "Slack" : "Telegram"}` });
  },
  async replaceSecret({ connectionId, botToken, appToken, label }) {
    const res = await send(() => fw.put("/api/channels/{id}/token", { path: { id: connectionId }, body: { botToken, appToken: appToken ?? null, label: label || null } }));
    return record(res, { connectionId, kind: "replace", summary: "Replace the token" });
  },
  async assign({ connectionId, vmId }) {
    const res = await send(() => fw.post("/api/channels/{id}/assign", { path: { id: connectionId }, body: { vmId } }));
    return record(res, { connectionId, vmId, kind: "assign", summary: "Put it on the agent" });
  },
  async unassign({ connectionId }) {
    const res = await send(() => fw.post("/api/channels/{id}/unassign", { path: { id: connectionId }, body: {} }));
    return record(res, { connectionId, kind: "unassign", summary: "Take it off the agent" });
  },
  async approvePairing({ connectionId, code, senderId, label }) {
    const res = await send(() => fw.post("/api/channels/{id}/pairing", { path: { id: connectionId }, body: { code, senderId, label: label || null } }));
    return record(res, { connectionId, kind: "approve_pairing", summary: `Approve ${label || senderId}` });
  },
  whatsappLogin: () => Promise.reject(new Error("WhatsApp is not on this firewall's panel yet")),
  getChange: changes.rpc.getChange,
  confirm: changes.rpc.confirm,
  cancel: changes.rpc.cancel,
};
