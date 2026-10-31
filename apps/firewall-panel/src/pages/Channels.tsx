import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { MessageSquare } from "lucide-react";
import { PageHead } from "@controlclaw/console-ui/kit/PageHead";
import { Card, EmptyState, Field, Select } from "@controlclaw/console-ui/kit/console-ui";
import { ChannelsPanel } from "@controlclaw/console-ui/firewall/channels";
import type { AgentChannelsView } from "@controlclaw/console-ui/lib/channels-schema";
import { Button } from "@controlclaw/console-ui/ui/button";
import { Input } from "@controlclaw/console-ui/ui/input";
import { listAgents } from "../api/agents";
import { channels } from "../api/channels";
import { errorText } from "../api/client";
import { refusalText } from "../api/changes";
import { FormError } from "../auth/AuthFrame";
import { toast } from "sonner";

/**
 * Channels: Telegram and Slack bots, one agent at a time, from the console's own panel. The firewall
 * reads no list of people waiting for approval, so a person is approved with the code the bot sent
 * them (`Approve`, under the cards).
 */
export function ChannelsPage() {
  const agents = useQuery({ queryKey: ["agents"], queryFn: listAgents });
  const list = (agents.data ?? []).filter((a) => a.role !== "gbrain");
  const [picked, setPicked] = useState("");
  const vmId = picked || list[0]?.vm_id || "";
  const view = useQuery({ queryKey: ["channels", vmId], queryFn: () => channels.listAgent({ vmId }), enabled: !!vmId, staleTime: Infinity, gcTime: 0 });

  return (
    <>
      <PageHead
        title="Channels"
        sub="The Telegram and Slack bots your agents answer on. The firewall keeps their tokens; the agents get stand-ins."
        actions={
          list.length > 1 ? (
            <Select aria-label="Agent" value={vmId} onChange={(e) => setPicked(e.target.value)} className="w-auto min-w-[180px]">
              {list.map((a) => (
                <option key={a.vm_id} value={a.vm_id}>
                  {a.name}
                </option>
              ))}
            </Select>
          ) : null
        }
      />
      {agents.isPending || (vmId && view.isPending) ? (
        <div className="h-40 animate-pulse rounded-[14px] border border-line bg-bg-2" aria-busy="true" />
      ) : agents.error || view.error ? (
        <FormError>{errorText(agents.error ?? view.error)}</FormError>
      ) : !vmId ? (
        <Card>
          <EmptyState icon={MessageSquare} title="No agents yet">
            Connect an agent first (Agents), then give it a Telegram or Slack bot here.
          </EmptyState>
        </Card>
      ) : view.data ? (
        <ChannelsPanel key={vmId} initial={view.data} whatsapp={false} pairings={false} afterCards={(v) => <ApprovePerson view={v} />} />
      ) : null}
    </>
  );
}

/** Approve a person who messaged the bot, with the pairing code the bot sent them. */
function ApprovePerson({ view }: { view: AgentChannelsView }) {
  const live = view.assigned.filter((c) => c.type === "telegram" || c.type === "slack");
  const [connectionId, setConnectionId] = useState("");
  const [code, setCode] = useState("");
  const [senderId, setSenderId] = useState("");
  const [label, setLabel] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  if (!live.length) return null;
  // The channel picked last time may have been taken off this agent since.
  const connection = live.some((c) => c.id === connectionId) ? connectionId : live[0].id;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const who = label.trim() || senderId.trim();
      const res = await channels.approvePairing({ connectionId: connection, code: code.trim(), senderId: senderId.trim(), label: label.trim() || undefined });
      if ("status" in res && res.status === "unconfirmed") toast.info(`${who} is approved on the firewall; ${view.vm.name} has not confirmed it yet.`);
      else toast.success(`${who} can talk to ${view.vm.name} now.`);
      setCode("");
      setSenderId("");
      setLabel("");
    } catch (err) {
      setError(refusalText(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="p-4 sm:p-5" data-testid="channels-approve">
      <div className="mb-1 text-[14.5px] font-semibold text-ink">Approve a person</div>
      <p className="mb-4 text-[13px] text-ink-2">
        Someone who messages the bot gets a pairing code back. Approve them here with that code and their id on the channel (for Telegram, the number
        the bot shows).
      </p>
      <form onSubmit={submit} className="grid gap-3 sm:grid-cols-2">
        {live.length > 1 ? (
          <Field label="Channel" htmlFor="approve-channel" className="sm:col-span-2">
            <Select id="approve-channel" value={connection} onChange={(e) => setConnectionId(e.target.value)}>
              {live.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.label || (c.type === "slack" ? "Slack" : "Telegram")}
                </option>
              ))}
            </Select>
          </Field>
        ) : null}
        <Field label="Pairing code" htmlFor="approve-code">
          <Input id="approve-code" value={code} onChange={(e) => setCode(e.target.value)} maxLength={16} autoComplete="off" className="font-mono" />
        </Field>
        <Field label="Their id on the channel" htmlFor="approve-sender">
          <Input id="approve-sender" value={senderId} onChange={(e) => setSenderId(e.target.value)} maxLength={100} autoComplete="off" className="font-mono" />
        </Field>
        <Field label="Name (optional)" htmlFor="approve-label" className="sm:col-span-2">
          <Input id="approve-label" value={label} onChange={(e) => setLabel(e.target.value)} maxLength={80} />
        </Field>
        <div className="sm:col-span-2">
          <FormError>{error}</FormError>
          <Button type="submit" variant="brand" size="sm" disabled={busy || code.trim().length < 4 || !senderId.trim()} className="mt-1">
            {busy ? "Approving…" : "Approve"}
          </Button>
        </div>
      </form>
    </Card>
  );
}
