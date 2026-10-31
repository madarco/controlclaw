import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Inbox, RefreshCw, Trash2 } from "lucide-react";
import { PageHead } from "@controlclaw/console-ui/kit/PageHead";
import { Badge, Card, EmptyState, Field, FieldGrid, Sec, Segmented, Select } from "@controlclaw/console-ui/kit/console-ui";
import { agentMailStatusLine, agentmailError } from "@controlclaw/console-ui/lib/agentmail-words";
import { AppLink } from "@controlclaw/console-ui/lib/link";
import { Button } from "@controlclaw/console-ui/ui/button";
import { Input } from "@controlclaw/console-ui/ui/input";
import { agentMail, readAgentMail, type AgentMailAction, type AgentMailView } from "../api/accounts";
import { AGENTS_KEY, listAgents, type AgentRow } from "../api/agents";
import { errorText } from "../api/client";
import { FormError } from "../auth/AuthFrame";

const KEY = ["agentmail"] as const;

const INBOX_STATUS: Record<string, { label: string; tone: "allow" | "ask" | "block" | "neutral" }> = {
  active: { label: "Working", tone: "allow" },
  pending: { label: "Being set up", tone: "ask" },
  awaiting_claim: { label: "Waiting for the claim", tone: "ask" },
  unassigned: { label: "Not on an agent", tone: "neutral" },
  setup_failed: { label: "Setup failed", tone: "block" },
  needs_key: { label: "Needs a key", tone: "block" },
};

/**
 * AgentMail: email inboxes for the agents (`name@agentmail.to`). The firewall keeps the AgentMail key;
 * an agent gets its inbox through the address it was paired at, so only paired agents are offered.
 * Who may email an inbox is set in Security rules → Email.
 */
export function AgentMailPage() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: KEY, queryFn: readAgentMail });
  const agents = useQuery({ queryKey: AGENTS_KEY, queryFn: listAgents });
  const act = useMutation({
    mutationFn: ({ action, body }: { action: AgentMailAction; body: Record<string, unknown> }) => agentMail(action, body),
    onSuccess: (v) => qc.setQueryData(KEY, v),
  });
  /** True when AgentMail took it; a refusal shows above and leaves what was typed. */
  const run = (action: AgentMailAction, body: Record<string, unknown> = {}) => act.mutateAsync({ action, body }).then(() => true, () => false);

  const v = q.data;
  // An agent gets an inbox at the address pairing gave it (its hostname).
  const paired = (agents.data ?? []).filter((a) => a.role !== "gbrain" && a.hostname);
  const status = v ? agentMailStatusLine({ account: { status: v.status }, inboxes: v.inboxes }) : null;
  return (
    <>
      <PageHead
        title="AgentMail"
        sub="An email inbox for each agent. The firewall keeps the AgentMail key; the agents never see it."
        actions={
          v && v.status !== "disconnected" ? (
            <Button variant="outline" size="sm" disabled={act.isPending} onClick={() => void run("check")} aria-label="Check again">
              <RefreshCw />
            </Button>
          ) : null
        }
      />
      {q.isPending ? (
        <div className="h-40 animate-pulse rounded-[14px] border border-line bg-bg-2" aria-busy="true" />
      ) : q.error || !v ? (
        <FormError>{errorText(q.error)}</FormError>
      ) : (
        <>
          {status && v.status !== "disconnected" ? (
            <Card className="mb-4 flex flex-wrap items-center gap-2 px-4 py-3 text-[13.5px]" data-testid="agentmail-status">
              <span className="min-w-0 flex-1 text-ink">{status.text}</span>
              {v.humanEmail ? <span className="font-mono text-[12.5px] text-ink-2">{v.humanEmail}</span> : null}
            </Card>
          ) : null}
          {v.errorCode ? <FormError>{agentmailError(v.errorCode)}</FormError> : null}
          <FormError>{act.error ? act.error.message : ""}</FormError>
          {v.status === "disconnected" || v.status === "signup_uncertain" ? (
            <Start view={v} agents={paired} busy={act.isPending} run={run} />
          ) : v.status === "awaiting_claim" ? (
            <Claim view={v} busy={act.isPending} run={run} />
          ) : (
            <Inboxes view={v} agents={paired} all={agents.data ?? []} busy={act.isPending} run={run} />
          )}
        </>
      )}
    </>
  );
}

type Run = (action: AgentMailAction, body?: Record<string, unknown>) => Promise<boolean>;

function AgentSelect({ id, agents, value, onChange }: { id: string; agents: AgentRow[]; value: string; onChange: (v: string) => void }) {
  return (
    <Select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
      {agents.map((a) => (
        <option key={a.vm_id} value={a.vm_id}>
          {a.name}
        </option>
      ))}
    </Select>
  );
}

/** A new AgentMail account (AgentMail emails the owner a code), or an existing one's key. */
function Start({ view, agents, busy, run }: { view: AgentMailView; agents: AgentRow[]; busy: boolean; run: Run }) {
  const [how, setHow] = useState<"new" | "key">(view.status === "signup_uncertain" ? "key" : "new");
  const [email, setEmail] = useState(view.humanEmail ?? "");
  const [username, setUsername] = useState("");
  const [vmId, setVmId] = useState("");
  const [apiKey, setApiKey] = useState("");
  const agent = vmId || agents[0]?.vm_id || "";
  return (
    <Sec title="Set up AgentMail" sub={view.status === "signup_uncertain" ? agentmailError("signup_uncertain") ?? undefined : "Make a new AgentMail account, or connect one you have."} className="mt-0">
      <Card className="grid gap-4 p-4 sm:p-5">
        <Segmented<"new" | "key">
          size="sm"
          value={how}
          onChange={setHow}
          options={[
            { value: "new", label: "New account" },
            { value: "key", label: "I have a key" },
          ]}
        />
        <Field label="Your email" htmlFor="am-email" hint={how === "new" ? "AgentMail sends the account's code here." : "The account's owner."}>
          <Input id="am-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        </Field>
        {how === "new" ? (
          agents.length === 0 ? (
            <p className="text-[13px] text-ink-2">Pair an agent first (Agents): its inbox is set up at the address it was paired at.</p>
          ) : (
            <FieldGrid>
              <Field label="First inbox for" htmlFor="am-agent">
                <AgentSelect id="am-agent" agents={agents} value={agent} onChange={setVmId} />
              </Field>
              <Field label="Inbox name" htmlFor="am-user" hint="Becomes name@agentmail.to.">
                <Input id="am-user" value={username} onChange={(e) => setUsername(e.target.value.toLowerCase())} placeholder="atlas" />
              </Field>
            </FieldGrid>
          )
        ) : (
          <Field label="AgentMail key" htmlFor="am-key" hint="From the AgentMail console (am_…). Its inboxes start on no agent.">
            <Input id="am-key" type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} className="font-mono" autoComplete="off" />
          </Field>
        )}
        <div>
          <Button
            variant="brand"
            disabled={busy || !email.trim() || (how === "new" ? !agent || !username.trim() : !apiKey.trim())}
            onClick={() => void (how === "new" ? run("signup", { vmId: agent, humanEmail: email.trim(), username: username.trim() }) : run("import", { apiKey: apiKey.trim(), humanEmail: email.trim() }))}
            data-testid="agentmail-start"
          >
            {how === "new" ? "Create the account" : "Connect"}
          </Button>
        </div>
      </Card>
    </Sec>
  );
}

function Claim({ view, busy, run }: { view: AgentMailView; busy: boolean; run: Run }) {
  const [code, setCode] = useState("");
  return (
    <Sec title="Claim the account" sub={`AgentMail sent a code to ${view.humanEmail ?? "your email"}. The inboxes start once it is claimed.`} className="mt-0">
      <Card className="flex flex-wrap items-end gap-3 p-4 sm:p-5">
        <Field label="Code from AgentMail" htmlFor="am-otp" className="min-w-[180px] flex-1">
          <Input id="am-otp" inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} maxLength={10} className="font-mono" />
        </Field>
        <Button variant="brand" disabled={busy || code.length < 4} onClick={() => void run("claim", { otpCode: code })} data-testid="agentmail-claim">
          Claim
        </Button>
      </Card>
    </Sec>
  );
}

function Inboxes({ view, agents, all, busy, run }: { view: AgentMailView; agents: AgentRow[]; all: AgentRow[]; busy: boolean; run: Run }) {
  const names = new Map(all.map((a) => [a.vm_id, a.name]));
  const withInbox = new Set(view.inboxes.map((i) => i.vmId).filter(Boolean));
  const free = agents.filter((a) => !withInbox.has(a.vm_id));
  const [vmId, setVmId] = useState("");
  const [username, setUsername] = useState("");
  const [deleting, setDeleting] = useState<string | null>(null);
  const [confirm, setConfirm] = useState("");
  const agent = free.some((a) => a.vm_id === vmId) ? vmId : (free[0]?.vm_id ?? "");
  return (
    <>
      <Card data-testid="agentmail-inboxes">
        {view.inboxes.length === 0 ? (
          <EmptyState icon={Inbox} title="No inboxes yet" />
        ) : (
          <ul className="divide-y divide-line">
            {view.inboxes.map((i) => {
              const st = INBOX_STATUS[i.status] ?? { label: i.status, tone: "neutral" as const };
              return (
                <li key={i.inboxId} className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-4 py-3 sm:px-5">
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-[13.5px] text-ink">{i.inboxId}</div>
                    <div className="text-[12.5px] text-ink-2">{i.vmId ? (names.get(i.vmId) ?? i.vmId) : "Not on an agent"}</div>
                  </div>
                  <Badge tone={st.tone} dot>
                    {st.label}
                  </Badge>
                  {i.vmId ? (
                    <>
                      <Button size="sm" variant="ghost" disabled={busy} onClick={() => void run("push", { vmId: i.vmId })}>
                        Send again
                      </Button>
                      <Button size="sm" variant="ghost" disabled={busy} onClick={() => void run("forget", { vmId: i.vmId })}>
                        Take off agent
                      </Button>
                    </>
                  ) : free.length ? (
                    <GiveInbox inboxId={i.inboxId} free={free} busy={busy} run={run} />
                  ) : null}
                  <Button size="icon-sm" variant="ghost" aria-label={`Delete ${i.inboxId}`} onClick={() => (setDeleting(i.inboxId), setConfirm(""))}>
                    <Trash2 />
                  </Button>
                  {deleting === i.inboxId ? (
                    <div className="flex w-full flex-wrap items-center gap-2">
                      <span className="text-[12.5px] text-ink-2">Type the address to delete it at AgentMail:</span>
                      <Input value={confirm} onChange={(e) => setConfirm(e.target.value)} className="h-8 w-auto min-w-[220px] flex-1 font-mono" />
                      <Button size="sm" variant="destructive" disabled={busy || confirm !== i.inboxId} onClick={() => void run("delete", { inboxId: i.inboxId, confirmAddress: confirm }).then((ok) => ok && setDeleting(null))}>
                        Delete
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setDeleting(null)}>
                        Cancel
                      </Button>
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </Card>
      <p className="mt-2 text-[12.5px] text-ink-2">
        Who may email these inboxes, and whom the agents may email, is set in{" "}
        <AppLink href="/security?type=email" className="font-medium text-brand hover:underline">
          Security rules → Email
        </AppLink>
        .
      </p>
      {view.canCreate && free.length ? (
        <Sec title="New inbox">
          <Card className="flex flex-wrap items-end gap-3 p-4 sm:p-5">
            <Field label="For" htmlFor="am-new-agent" className="min-w-[160px]">
              <AgentSelect id="am-new-agent" agents={free} value={agent} onChange={setVmId} />
            </Field>
            <Field label="Inbox name" htmlFor="am-new-user" className="min-w-[180px] flex-1" hint="Becomes name@agentmail.to.">
              <Input id="am-new-user" value={username} onChange={(e) => setUsername(e.target.value.toLowerCase())} />
            </Field>
            <Button variant="brand" disabled={busy || !agent || !username.trim()} onClick={() => void run("create", { vmId: agent, username: username.trim() }).then((ok) => ok && setUsername(""))}>
              Create
            </Button>
          </Card>
        </Sec>
      ) : null}
    </>
  );
}

/** An inbox on no agent, given to the agent picked. */
function GiveInbox({ inboxId, free, busy, run }: { inboxId: string; free: AgentRow[]; busy: boolean; run: Run }) {
  const [vmId, setVmId] = useState(free[0].vm_id);
  const agent = free.some((a) => a.vm_id === vmId) ? vmId : free[0].vm_id;
  return (
    <span className="flex items-center gap-1.5">
      <AgentSelect id={`give-${inboxId}`} agents={free} value={agent} onChange={setVmId} />
      <Button size="sm" variant="outline" disabled={busy} onClick={() => void run("attach", { vmId: agent, inboxId })}>
        Give
      </Button>
    </span>
  );
}
