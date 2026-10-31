import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2 } from "lucide-react";
import { toast } from "sonner";
import { PageHead } from "@controlclaw/console-ui/kit/PageHead";
import { Card, Field, FieldGrid, Sec, Select } from "@controlclaw/console-ui/kit/console-ui";
import { JsonFileDrop, readFileText, UNREADABLE_FILE, type JsonFileNote } from "@controlclaw/console-ui/kit/JsonFileDrop";
import { Button } from "@controlclaw/console-ui/ui/button";
import { Checkbox } from "@controlclaw/console-ui/ui/checkbox";
import { CopyButton } from "@controlclaw/console-ui/ui/copy-button";
import { Input } from "@controlclaw/console-ui/ui/input";
import { Switch } from "@controlclaw/console-ui/ui/switch";
import { connectGoogle, forgetGoogle, GOOGLE_SERVICE_LABEL, parseGoogleClient, grantGoogle, GOOGLE_SERVICES, googleServices, pushGoogle, readGoogle, type GoogleView } from "../api/accounts";
import { AGENTS_KEY, listAgents, type AgentRow } from "../api/agents";
import { errorText } from "../api/client";
import { refusalText } from "../api/changes";
import { checkedUrl, onOauthDone, openTabNow } from "../api/oauth";
import { ConfirmButton } from "../shell/ConfirmButton";
import { FormError } from "../auth/AuthFrame";

const KEY = ["google"] as const;

const SERVICE_LABEL = GOOGLE_SERVICE_LABEL;

/**
 * Google: your own OAuth client, signed in once, then given to the agents you pick. The firewall keeps
 * the client and the tokens; an agent gets a stand-in the proxy swaps. Gmail push and Drive folders
 * are the console's (no API on a standalone firewall yet).
 */
export function GooglePage() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: KEY, queryFn: readGoogle });
  const agents = useQuery({ queryKey: AGENTS_KEY, queryFn: listAgents });
  const [reconnect, setReconnect] = useState(false);
  /** The sign-in this page started, so another one (an app's, in another tab) is not taken for it. */
  const [pending, setPending] = useState<string | null>(null);
  // The brain box gets no Google account.
  const people = (agents.data ?? []).filter((a) => a.role !== "gbrain");

  // The sign-in finishes in another tab (/oauth/callback): read the account again when it says so.
  useEffect(() => {
    if (!pending) return;
    return onOauthDone(({ changeId, error }) => {
      if (changeId !== pending) return;
      if (error) toast.error(error);
      else toast.success("Google is connected.");
      setPending(null);
      setReconnect(false);
      void qc.invalidateQueries({ queryKey: KEY });
    });
  }, [qc, pending]);

  const v = q.data;
  return (
    <>
      <PageHead title="Google" sub="Gmail, Calendar, Drive, Contacts, Sheets and Docs for your agents, with your own Google OAuth client." />
      {q.isPending ? (
        <div className="h-40 animate-pulse rounded-[14px] border border-line bg-bg-2" aria-busy="true" />
      ) : q.error || !v ? (
        <FormError>{errorText(q.error)}</FormError>
      ) : (
        <>
          <RedirectCard view={v} />
          {v.account?.connected && !reconnect ? (
            <Connected view={v} agents={people} onReconnect={() => setReconnect(true)} />
          ) : (
            <Setup view={v} agents={people} onStarted={setPending} onCancel={v.account?.connected ? () => setReconnect(false) : undefined} />
          )}
        </>
      )}
    </>
  );
}

/** The address to register in the OAuth client, or why Google would refuse it. */
function RedirectCard({ view }: { view: GoogleView }) {
  return (
    <Card className="mb-4 px-4 py-3" data-testid="google-redirect">
      <div className="text-[12.5px] font-medium text-ink-2">Authorized redirect URI (add it to your OAuth client)</div>
      <div className="mt-1 flex items-start gap-2">
        <code className="min-w-0 flex-1 break-all font-mono text-[13px] text-ink">{view.redirectUri}</code>
        <CopyButton value={view.redirectUri} className="shrink-0" />
      </div>
      {!view.redirectOk ? (
        <p className="mt-2 flex gap-2 text-[13px] text-ask-fg" data-testid="google-redirect-problem">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          {view.redirectProblem ?? "Google takes only an https address, or http on localhost."}
        </p>
      ) : null}
    </Card>
  );
}

function Setup({ view, agents, onStarted, onCancel }: { view: GoogleView; agents: AgentRow[]; onStarted: (changeId: string | null) => void; onCancel?: () => void }) {
  const a = view.account;
  const [clientId, setClientId] = useState(a?.clientId ?? "");
  const [clientSecret, setClientSecret] = useState("");
  const [projectId, setProjectId] = useState<string | null>(a?.projectId ?? null);
  const [note, setNote] = useState<JsonFileNote | null>(null);
  const [services, setServices] = useState<string[]>(a?.services.length ? a.services : ["gmail", "calendar", "drive", "contacts"]);
  const [gmailScope, setGmailScope] = useState(a?.gmailScope ?? "read-send");
  const [driveScope, setDriveScope] = useState(a?.driveScope ?? "full");
  const [audience, setAudience] = useState(a?.audience ?? "external_testing");
  const [vmIds, setVmIds] = useState<string[]>(view.agents.filter((x) => x.granted).map((x) => x.vmId));
  const [waiting, setWaiting] = useState(false);
  /** Where to sign in, when the browser blocked the tab. */
  const [link, setLink] = useState<string | null>(null);

  const start = useMutation({
    mutationFn: () => connectGoogle({ clientId: clientId.trim(), clientSecret: clientSecret.trim(), projectId, services, gmailScope, driveScope, audience, vmIds }),
    onSuccess: ({ changeId }) => {
      onStarted(changeId);
      setWaiting(true);
    },
  });

  async function onFile(file: File | null | undefined) {
    if (!file) return;
    const text = await readFileText(file);
    if (text === null) return setNote({ tone: "bad", text: UNREADABLE_FILE });
    const c = parseGoogleClient(text);
    if (!c) return setNote({ tone: "bad", text: "That is not an OAuth client file. Download the client's JSON from the Google Cloud console." });
    setClientId(c.clientId);
    setClientSecret(c.clientSecret);
    setProjectId(c.projectId);
    setNote(
      c.redirects.includes(view.redirectUri)
        ? { tone: "ok", text: "Read the client id and secret." }
        : { tone: "warn", text: "Read the client, but its redirect URIs do not include the address above: add it in the Google Cloud console, or Google refuses the sign-in." },
    );
  }

  return (
    <Sec title={a ? "Connect again" : "Connect your Google account"} sub="Your own OAuth client, from the Google Cloud console." className="mt-2">
      <Card className="p-4 sm:p-5">
        <ol className="mb-4 list-decimal space-y-1 pl-5 text-[13px] text-ink-2">
          <li>In the Google Cloud console, create a project and turn on the APIs you want (Gmail, Calendar, Drive, People, Sheets, Docs).</li>
          <li>Set up the OAuth consent screen: Internal for a Workspace, or External with yourself as a test user.</li>
          <li>Create an OAuth client of type &quot;Web application&quot; with the redirect URI above, and download its JSON.</li>
        </ol>
        <div className="grid gap-4">
          <JsonFileDrop title="Drop the client's JSON here" hint="Or choose the file. It fills the id and secret." note={note} onFile={(f) => void onFile(f)} testId="google-client-file" />
          <FieldGrid>
            <Field label="Client id" htmlFor="g-client-id">
              <Input id="g-client-id" value={clientId} onChange={(e) => setClientId(e.target.value)} className="font-mono" placeholder="….apps.googleusercontent.com" />
            </Field>
            <Field label="Client secret" htmlFor="g-client-secret">
              <Input id="g-client-secret" type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} className="font-mono" autoComplete="off" />
            </Field>
          </FieldGrid>
          <fieldset>
            <legend className="text-[12.5px] font-medium text-ink-2">Services</legend>
            <div className="mt-1.5 grid grid-cols-2 gap-1.5 sm:grid-cols-3">
              {GOOGLE_SERVICES.map((s) => (
                <label key={s} className="flex items-center gap-2 text-[13px] text-ink">
                  <Checkbox checked={services.includes(s)} onCheckedChange={(on) => setServices((p) => (on === true ? [...p, s] : p.filter((x) => x !== s)))} />
                  {SERVICE_LABEL[s]}
                </label>
              ))}
            </div>
          </fieldset>
          <FieldGrid>
            <Field label="Gmail" htmlFor="g-gmail">
              <Select id="g-gmail" value={gmailScope} onChange={(e) => setGmailScope(e.target.value)} disabled={!services.includes("gmail")}>
                <option value="read-send">Read and send</option>
                <option value="readonly">Read only</option>
                <option value="send">Send only</option>
                <option value="full">Everything (also delete)</option>
              </Select>
            </Field>
            <Field label="Drive" htmlFor="g-drive">
              <Select id="g-drive" value={driveScope} onChange={(e) => setDriveScope(e.target.value)} disabled={!services.includes("drive")}>
                <option value="full">Every file</option>
                <option value="readonly">Read every file</option>
                <option value="file">Only files it makes or you open with it</option>
              </Select>
            </Field>
            <Field label="Consent screen audience" htmlFor="g-audience" hint={audience === "external_testing" ? "Google signs a testing app out after 7 days: publish it to stay signed in." : undefined}>
              <Select id="g-audience" value={audience} onChange={(e) => setAudience(e.target.value)}>
                <option value="internal">Internal (Workspace)</option>
                <option value="external_testing">External, testing</option>
                <option value="external_production">External, published</option>
              </Select>
            </Field>
          </FieldGrid>
          {agents.length ? (
            <fieldset>
              <legend className="text-[12.5px] font-medium text-ink-2">Give it to</legend>
              <div className="mt-1.5 grid gap-1.5 sm:grid-cols-2">
                {agents.map((ag) => (
                  <label key={ag.vm_id} className="flex items-center gap-2 text-[13px] text-ink">
                    <Checkbox checked={vmIds.includes(ag.vm_id)} onCheckedChange={(on) => setVmIds((p) => (on === true ? [...p, ag.vm_id] : p.filter((x) => x !== ag.vm_id)))} />
                    {ag.name}
                  </label>
                ))}
              </div>
            </fieldset>
          ) : null}
          <FormError>{start.error ? refusalText(start.error) : ""}</FormError>
          {link ? (
            <p className="text-[13px] text-ink-2">
              The browser did not open a tab.{" "}
              <a href={link} target="_blank" rel="noopener noreferrer" className="font-medium text-brand hover:underline">
                Open the Google sign-in
              </a>
              .
            </p>
          ) : null}
          {waiting ? (
            <p className="text-[13px] text-ink-2" data-testid="google-waiting">
              Finish the sign-in in the tab that opened. Leave every box ticked on Google&apos;s page. This page updates when it is done.
            </p>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <Button
              variant="brand"
              disabled={start.isPending || !view.redirectOk || !clientId.trim() || !clientSecret.trim() || !services.length}
              onClick={() => {
                // The tab opens on the click: one opened after the call would be blocked.
                const tab = openTabNow();
                setLink(null);
                start.mutate(undefined, {
                  onSuccess: ({ authorizeUrl }) => {
                    if (tab) {
                      try {
                        tab.go(authorizeUrl);
                      } catch (e) {
                        toast.error(e instanceof Error ? e.message : String(e));
                      }
                    } else {
                      const safe = checkedUrl(authorizeUrl);
                      if (safe) setLink(safe);
                      else toast.error("The firewall answered with an address the panel does not open.");
                    }
                  },
                  onError: () => tab?.close(),
                });
              }}
              data-testid="google-connect"
            >
              {waiting ? "Open the sign-in again" : "Sign in with Google"}
            </Button>
            {onCancel ? (
              <Button variant="ghost" onClick={onCancel}>
                Cancel
              </Button>
            ) : null}
          </div>
        </div>
      </Card>
    </Sec>
  );
}

function Connected({ view, agents, onReconnect }: { view: GoogleView; agents: AgentRow[]; onReconnect: () => void }) {
  const qc = useQueryClient();
  const a = view.account!;
  const granted = new Set(view.agents.filter((x) => x.granted).map((x) => x.vmId));
  const refresh = () => void qc.invalidateQueries({ queryKey: KEY });
  const grant = useMutation({
    mutationFn: ({ vmId, on }: { vmId: string; on: boolean }) => grantGoogle(vmId, on),
    onSuccess: (problem) => (problem ? toast.error(`Saved on the firewall, but the agent did not take it: ${problem}`) : null),
    onError: (e) => toast.error(refusalText(e)),
    onSettled: refresh,
  });
  const push = useMutation({ mutationFn: pushGoogle, onSuccess: () => toast.success("Sent to the agent again."), onError: (e) => toast.error(refusalText(e)) });
  const services = useMutation({ mutationFn: googleServices, onError: (e) => toast.error(refusalText(e)), onSettled: refresh });
  const forget = useMutation({ mutationFn: forgetGoogle, onError: (e) => toast.error(refusalText(e)), onSettled: refresh });

  return (
    <>
      <Card className="mt-2 flex flex-wrap items-center gap-3 px-4 py-3" data-testid="google-account">
        <CheckCircle2 className="h-5 w-5 text-allow-fg" />
        <div className="min-w-0 flex-1">
          <div className="truncate font-mono text-[14px] text-ink">{a.accountLabel ?? "Google account"}</div>
          {a.failed ? <div className="text-[12.5px] text-block-fg">{a.failed}</div> : null}
        </div>
        <Button size="sm" variant="outline" onClick={onReconnect}>
          Connect again
        </Button>
        <ConfirmButton label="Disconnect" confirm="Disconnect Google" busy={forget.isPending} onConfirm={() => forget.mutate()} />
      </Card>
      <Sec title="Services" sub="Turning one off applies at once. Turning one on that Google was not asked for needs Connect again.">
        <Card className="grid gap-2 p-4 sm:grid-cols-3">
          {GOOGLE_SERVICES.map((s) => {
            const on = a.services.includes(s);
            return (
              <label key={s} className="flex items-center gap-2 text-[13px] text-ink">
                <Switch
                  checked={on}
                  disabled={services.isPending || (on && a.services.length === 1)}
                  onCheckedChange={(next) => services.mutate(next ? [...a.services, s] : a.services.filter((x) => x !== s))}
                  aria-label={SERVICE_LABEL[s]}
                />
                {SERVICE_LABEL[s]}
              </label>
            );
          })}
        </Card>
      </Sec>
      <Sec title="Agents" sub="Who may use this account. An agent gets a stand-in; the firewall puts the real token in.">
        <Card data-testid="google-agents">
          {agents.length === 0 ? (
            <div className="px-4 py-4 text-[13.5px] text-ink-2">No agents yet.</div>
          ) : (
            <ul className="divide-y divide-line">
              {agents.map((ag) => (
                <li key={ag.vm_id} className="flex items-center gap-3 px-4 py-2.5 text-[13.5px]">
                  <Switch checked={granted.has(ag.vm_id)} disabled={grant.isPending} onCheckedChange={(on) => grant.mutate({ vmId: ag.vm_id, on })} aria-label={`Google for ${ag.name}`} />
                  <span className="min-w-0 flex-1 truncate text-ink">{ag.name}</span>
                  {granted.has(ag.vm_id) ? (
                    <Button size="sm" variant="ghost" disabled={push.isPending} onClick={() => push.mutate(ag.vm_id)}>
                      Send again
                    </Button>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </Card>
      </Sec>
    </>
  );
}
