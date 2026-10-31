import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, KeyRound, Pencil, RefreshCw, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { PageHead } from "@controlclaw/console-ui/kit/PageHead";
import { Badge, Card, EmptyState, Field, Sec } from "@controlclaw/console-ui/kit/console-ui";
import { RelativeTime } from "@controlclaw/console-ui/kit/RelativeTime";
import { Button } from "@controlclaw/console-ui/ui/button";
import { Checkbox } from "@controlclaw/console-ui/ui/checkbox";
import { Input } from "@controlclaw/console-ui/ui/input";
import { Textarea } from "@controlclaw/console-ui/ui/textarea";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@controlclaw/console-ui/ui/dialog";
import { deleteLogin, disconnectOnePassword, openFirewallPage, readLogins, syncOnePassword, updateLogin, type LoginsView, type WebsiteLogin } from "../api/accounts";
import { AGENTS_KEY, listAgents, type AgentRow } from "../api/agents";
import { checkedUrl, openTabNow } from "../api/oauth";
import { ConfirmButton } from "../shell/ConfirmButton";
import { errorText } from "../api/client";
import { refusalText } from "../api/changes";
import { FormError } from "../auth/AuthFrame";

const KEY = ["logins"] as const;

/**
 * Website logins: the passwords the firewall types in for the agents, on the login's sites only. The
 * panel lists and edits them, never a password: a new login, and its password, are typed on the
 * firewall's own Logins page, which opens from here.
 */
export function LoginsPage() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: KEY, queryFn: readLogins });
  const agents = useQuery({ queryKey: AGENTS_KEY, queryFn: listAgents });
  // The brain box gets no website logins.
  const people = (agents.data ?? []).filter((a) => a.role !== "gbrain");
  const [editing, setEditing] = useState<WebsiteLogin | null>(null);
  const [opening, setOpening] = useState(false);
  const set = (v: LoginsView) => qc.setQueryData(KEY, v);

  async function openPage() {
    // The tab opens on the click: one opened after the call would be blocked.
    const tab = openTabNow();
    setOpening(true);
    try {
      const url = await openFirewallPage("logins");
      if (tab) tab.go(url);
      else {
        const safe = checkedUrl(url);
        if (!safe) throw new Error("The firewall answered with an address the panel does not open.");
        window.location.assign(safe);
      }
      toast.info("Add the login on the firewall's page, then come back and refresh.");
    } catch (e) {
      tab?.close();
      toast.error(refusalText(e));
    } finally {
      setOpening(false);
    }
  }

  const list = q.data?.logins ?? [];
  const names = new Map((agents.data ?? []).map((a) => [a.vm_id, a.name]));
  return (
    <>
      <PageHead
        title="Website logins"
        sub="Sign-ins your agents can use without seeing the password: the firewall puts it in, on the login's sites only."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => void q.refetch()} disabled={q.isFetching} aria-label="Refresh">
              <RefreshCw />
            </Button>
            <Button variant="brand" size="sm" onClick={() => void openPage()} disabled={opening} data-testid="logins-add">
              <ExternalLink />
              Add a login
            </Button>
          </>
        }
      />
      <Card data-testid="logins">
        {q.isPending ? (
          <div className="px-4 py-6 text-[13.5px] text-ink-2">Loading…</div>
        ) : q.error ? (
          <div className="px-4 py-4">
            <FormError>{errorText(q.error)}</FormError>
          </div>
        ) : list.length === 0 ? (
          <EmptyState icon={KeyRound} title="No website logins yet">
            Add one on the firewall&apos;s own page: you type the password there, so it never passes through this panel.
          </EmptyState>
        ) : (
          <ul className="divide-y divide-line">
            {list.map((l) => (
              <li key={l.id} className="flex flex-wrap items-start gap-x-3 gap-y-1 px-4 py-3 sm:px-5" data-testid="login">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2 text-[14px] font-medium text-ink">
                    {l.name}
                    {l.source === "1password" ? <Badge>1Password</Badge> : null}
                    {l.kind === "session" ? <Badge>Session</Badge> : null}
                    {l.needsSignInPage ? <Badge tone="ask">Needs its sign-in page</Badge> : null}
                  </div>
                  <div className="truncate text-[12.5px] text-ink-2">
                    {l.username ? <span className="font-mono">{l.username}</span> : null}
                    {l.username ? " · " : ""}
                    {l.sites.join(", ")}
                  </div>
                  <div className="text-[12.5px] text-ink-2">
                    {l.vmIds.length ? l.vmIds.map((v) => names.get(v) ?? v).join(", ") : "No agent yet"}
                    {l.lastUsedAt ? (
                      <>
                        {" "}
                        · used <RelativeTime date={l.lastUsedAt} />
                      </>
                    ) : null}
                  </div>
                </div>
                {l.source === "vault" && l.kind === "password" ? (
                  <Button variant="ghost" size="icon-sm" aria-label={`Edit ${l.name}`} onClick={() => setEditing(l)}>
                    <Pencil />
                  </Button>
                ) : null}
                {l.source === "vault" ? <DeleteLogin login={l} onDone={set} /> : null}
              </li>
            ))}
          </ul>
        )}
      </Card>
      {q.data?.onePassword ? <OnePasswordCard view={q.data} onChange={() => void q.refetch()} /> : null}
      {editing ? <EditLogin login={editing} agents={people} onClose={() => setEditing(null)} onDone={set} /> : null}
    </>
  );
}

/** The password lives only on the firewall: a delete asks once more. */
function DeleteLogin({ login, onDone }: { login: WebsiteLogin; onDone: (v: LoginsView) => void }) {
  const [asking, setAsking] = useState(false);
  const del = useMutation({ mutationFn: () => deleteLogin(login.id), onSuccess: onDone, onError: (e) => toast.error(refusalText(e)) });
  if (asking) {
    return (
      <span className="flex items-center gap-1.5">
        <Button variant="destructive" size="sm" disabled={del.isPending} onClick={() => del.mutate()} data-testid="login-delete-confirm">
          Delete
        </Button>
        <Button variant="ghost" size="sm" onClick={() => setAsking(false)}>
          Keep
        </Button>
      </span>
    );
  }
  return (
    <Button variant="ghost" size="icon-sm" aria-label={`Delete ${login.name}`} onClick={() => setAsking(true)}>
      <Trash2 />
    </Button>
  );
}

/** Name, sites, agents and how the password goes in; the password itself is changed on the firewall's page. */
function EditLogin({ login, agents, onClose, onDone }: { login: WebsiteLogin; agents: AgentRow[]; onClose: () => void; onDone: (v: LoginsView) => void }) {
  const [name, setName] = useState(login.name);
  const [sites, setSites] = useState(login.sites.join("\n"));
  const [vmIds, setVmIds] = useState<string[]>(login.vmIds);
  const [mode, setMode] = useState(login.mode);
  const save = useMutation({
    mutationFn: () => updateLogin({ id: login.id, name: name.trim(), sites: sites.split(/[\s,]+/).filter(Boolean), vmIds, mode }),
    onSuccess: (v) => {
      onDone(v);
      onClose();
    },
  });
  return (
    <Dialog open onOpenChange={(o) => (o ? null : onClose())}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit {login.name}</DialogTitle>
          <DialogDescription>The password stays on the firewall. To change it, open the firewall&apos;s Logins page.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <Field label="Name" htmlFor="login-name">
            <Input id="login-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={80} />
          </Field>
          <Field label="Sites" htmlFor="login-sites" hint="One per line: the sites the firewall may put this password in.">
            <Textarea id="login-sites" value={sites} onChange={(e) => setSites(e.target.value)} rows={3} className="font-mono" />
          </Field>
          <fieldset>
            <legend className="text-[12.5px] font-medium text-ink-2">Agents that may use it</legend>
            <div className="mt-1.5 grid gap-1.5 sm:grid-cols-2">
              {agents.map((a) => (
                <label key={a.vm_id} className="flex items-center gap-2 text-[13px] text-ink">
                  <Checkbox checked={vmIds.includes(a.vm_id)} onCheckedChange={(v) => setVmIds((p) => (v === true ? [...p, a.vm_id] : p.filter((x) => x !== a.vm_id)))} />
                  {a.name}
                </label>
              ))}
            </div>
          </fieldset>
          <label className="flex items-center gap-2 text-[13px] text-ink">
            <Checkbox checked={mode === "type"} onCheckedChange={(v) => setMode(v === true ? "type" : "swap")} />
            Type it into the page (for sites that check the password field) instead of swapping it in the request
          </label>
          <FormError>{save.error ? refusalText(save.error) : ""}</FormError>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="brand" disabled={save.isPending || !name.trim() || !sites.trim()} onClick={() => save.mutate()}>
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function OnePasswordCard({ view, onChange }: { view: LoginsView; onChange: () => void }) {
  const op = view.onePassword!;
  const sync = useMutation({ mutationFn: syncOnePassword, onSuccess: (m) => toast.info(m), onError: (e) => toast.error(refusalText(e)) });
  const disconnect = useMutation({ mutationFn: disconnectOnePassword, onSuccess: onChange, onError: (e) => toast.error(refusalText(e)) });
  return (
    <Sec title="1Password" sub={`Logins read from ${op.vaults.map((v) => v.name).join(", ") || "your vaults"}.`}>
      <Card className="flex flex-wrap items-center gap-3 px-4 py-3">
        <span className="min-w-0 flex-1 text-[13px] text-ink-2">
          {op.lastError ? <span className="text-block-fg">{op.lastError}</span> : op.lastSyncAt ? <>Read <RelativeTime date={op.lastSyncAt} /></> : "Not read yet"}
        </span>
        <Button size="sm" variant="outline" disabled={sync.isPending} onClick={() => sync.mutate()}>
          Read again
        </Button>
        <ConfirmButton label="Disconnect" confirm="Disconnect 1Password" busy={disconnect.isPending} onConfirm={() => disconnect.mutate()} />
      </Card>
    </Sec>
  );
}
