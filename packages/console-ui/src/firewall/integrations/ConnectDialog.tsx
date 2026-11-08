"use client";

import { useEffect, useMemo, useState } from "react";
import { ExternalLink, Loader2, ShieldCheck } from "lucide-react";
import { useApi } from "../../lib/api";
import { Button } from "../../ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "../../ui/dialog";
import { AppLogo } from "./AppLogo";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Checkbox } from "../../ui/checkbox";
import type { Busy } from "./useConnectorChange";
import type { CatalogProvider } from "../../lib/connectors-schema";
import { fieldsOf, secretKeysOf, type ConnectorAuthDescriptor, type ConnectorSetupView } from "../../lib/connectors-schema";
import { RedirectUri, SetupGuide } from "./SetupGuide";

/**
 * The connect dialog, rendered from the provider's own credential descriptor.
 *
 * Nothing here is provider-specific: the fields, their labels, which of them are secret and
 * which OAuth scope groups can be ticked all come from `integrations.getSetup`, which serves the
 * runtime's `GET /v1/providers/:service/setup` answer for the pinned version. A provider added
 * in a later OpenConnector release gets a working form here with no code change.
 *
 * The one thing the descriptor cannot do is tell somebody how to create the app in the first
 * place. That is `clientSetup` — the provider's own registration steps where it has them, ours
 * from `connector-guides.ts` where it does not — rendered as the "Before you start" block, with
 * the callback URL to register and per-field help under the fields it is about.
 */

export type ConnectSubmit =
  | { authType: "api_key" | "custom_credential"; label: string; secrets: Record<string, string>; extra: Record<string, string>; vmIds: string[] }
  /** The whole client form as typed; the server splits it by the provider's descriptor. */
  | { authType: "oauth2"; label: string; clientFields: Record<string, string>; authorizationOptionIds: string[]; vmIds: string[] };

export interface ConnectDialogProps {
  provider: CatalogProvider | null;
  agents: Array<{ vmId: string; name: string }>;
  state: Busy;
  onSubmit: (input: ConnectSubmit) => void;
  onClose: () => void;
  /** A replacement: only the credential fields, no label, no agents, no OAuth. */
  replacing?: boolean;
}

function StatusLine({ state }: { state: Busy }) {
  if (state.error) return <div className="text-[12.5px] text-block">{state.error}</div>;
  if (state.note) return <div className="text-[12.5px] text-ink-2">{state.note}</div>;
  return null;
}

/** Which credential type the dialog is collecting; a provider may offer more than one. */
function pickInitial(auth: ConnectorAuthDescriptor[]): ConnectorAuthDescriptor["type"] | null {
  for (const want of ["oauth2", "api_key", "custom_credential"] as const) {
    if (auth.some((a) => a.type === want)) return want;
  }
  return null;
}

export function ConnectDialog({ provider, agents, state, onSubmit, onClose, replacing = false }: ConnectDialogProps) {
  const api = useApi();
  const [setup, setSetup] = useState<ConnectorSetupView | null>(null);
  const [loading, setLoading] = useState(false);
  const [authType, setAuthType] = useState<ConnectorAuthDescriptor["type"] | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [label, setLabel] = useState("");
  const [options, setOptions] = useState<string[]>([]);
  const [vmIds, setVmIds] = useState<string[]>([]);

  useEffect(() => {
    if (!provider) {
      setSetup(null);
      return;
    }
    setValues({});
    setLabel("");
    setVmIds([]);
    setLoading(true);
    let stopped = false;
    void api.integrations
      .getSetup({ service: provider.service })
      .then((s) => {
        if (stopped) return;
        setSetup(s);
        const initial = replacing ? (s.auth.find((a) => a.type === "api_key" || a.type === "custom_credential")?.type ?? null) : pickInitial(s.auth);
        setAuthType(initial);
        const oauth = s.auth.find((a) => a.type === "oauth2");
        setOptions(oauth && oauth.type === "oauth2" ? (oauth.authorizationOptions ?? []).filter((o) => o.required || o.defaultSelected).map((o) => o.id) : []);
      })
      .catch((error) => {
        console.error("integrations.getSetup failed", error);
      })
      .finally(() => !stopped && setLoading(false));
    return () => {
      stopped = true;
    };
  }, [provider?.service, replacing]); // eslint-disable-line react-hooks/exhaustive-deps

  const descriptor = useMemo(() => setup?.auth.find((a) => a.type === authType) ?? null, [setup, authType]);
  const offered = useMemo(
    () => (setup?.auth ?? []).filter((a) => a.type !== "no_auth" && (!replacing || a.type !== "oauth2")).map((a) => a.type),
    [setup, replacing],
  );

  // Every field the descriptor declares, whichever kind it is. An OAuth client form is a form
  // too, and 14 of the catalog's OAuth providers require more than a client id and secret.
  const fields = descriptor ? fieldsOf(descriptor) : [];
  const oauth = descriptor?.type === "oauth2" ? descriptor : null;
  const ready = fields.filter((f) => f.required).every((f) => !!values[f.key]?.trim());
  // Registration steps for the credential type on screen: the provider's own, or ours merged
  // over them. An API-key provider can carry them too — "where do I make this token" is the
  // same question.
  const guide = descriptor && descriptor.type !== "no_auth" ? (descriptor.clientSetup ?? null) : null;
  const redirectUri = setup?.oauthClient?.expectedRedirectUri ?? null;

  const submit = () => {
    if (!descriptor) return;
    const known = new Set(fields.map((f) => f.key));
    const typed: Record<string, string> = {};
    for (const [k, v] of Object.entries(values)) if (v.trim() && known.has(k)) typed[k] = v.trim();
    if (oauth) {
      onSubmit({ authType: "oauth2", label: label.trim(), clientFields: typed, authorizationOptionIds: options, vmIds });
      return;
    }
    const secretKeys = new Set(secretKeysOf(descriptor));
    const secrets: Record<string, string> = {};
    const extra: Record<string, string> = {};
    for (const [k, v] of Object.entries(typed)) {
      if (secretKeys.has(k)) secrets[k] = v;
      else extra[k] = v;
    }
    onSubmit({ authType: descriptor.type as "api_key" | "custom_credential", label: label.trim(), secrets, extra, vmIds });
  };

  return (
    <Dialog open={!!provider} onOpenChange={(o) => !o && !state.busy && onClose()}>
      {/*
        Capped and scrollable, because a provider’s form is as long as the provider says. GitHub’s
        is ~1040px and GitLab’s ~885px (three client fields with long descriptions, five scope
        groups, the label, the agents, the note), and in a 720px window the Connect button sat
        below the fold with nothing to scroll.
      */}
      <DialogContent className="flex max-h-[85vh] flex-col sm:max-w-[520px]" data-testid="connector-dialog-connect">
        <DialogHeader>
          <DialogTitle className="flex min-w-0 items-center gap-2.5">
            {provider ? <AppLogo name={provider.name} home={provider.home} service={provider.service} icon={provider.icon} size={28} /> : null}
            <span className="min-w-0">{replacing ? `Replace ${provider?.name} credentials` : `Connect ${provider?.name}`}</span>
          </DialogTitle>
          <DialogDescription>
            {provider?.desc ??
              `${provider?.name ?? "This app"} has ${provider?.actions ?? 0} actions your agents can use. What you type here goes to your firewall and never to ControlClaw’s database.`}
          </DialogDescription>
        </DialogHeader>

        <div className="min-h-0 flex-1 overflow-y-auto px-0.5" data-testid="connector-dialog-body">
        {loading ? (
          <div className="flex items-center gap-2 py-6 text-[13.5px] text-ink-2">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading the app’s sign-in options…
          </div>
        ) : !descriptor ? (
          <div className="py-4 text-[13.5px] text-ink-2">You can’t connect this app from here yet.</div>
        ) : (
          <div className="grid gap-3">
            {offered.length > 1 && (
              <div className="flex gap-2" data-testid="connector-auth-types">
                {offered.map((t) => (
                  <Button key={t} size="sm" variant={t === authType ? "default" : "outline"} onClick={() => (setAuthType(t), setValues({}))}>
                    {t === "oauth2" ? "Sign in with OAuth" : t === "api_key" ? "API key" : "Credentials"}
                  </Button>
                ))}
              </div>
            )}

            {oauth ? (
              <>
                <div className="grid gap-2 rounded-xl border border-line bg-bg-2 px-3.5 py-3 text-[12.5px] text-ink-2">
                  <div className="font-medium text-ink">Use your own OAuth app</div>
                  <p>
                    {guide?.steps.length
                      ? `Create an OAuth app in ${provider?.name ?? "the app"} and paste its client ID and secret. The steps below show how and give you the callback URL to register. `
                      : `Create an OAuth app in ${provider?.name ?? "the app"} and register this exact callback URL, then paste its client ID and secret. `}
                    The secret is sent to your firewall. ControlClaw never stores it.
                  </p>
                  {/* With a guide, the URL lives inside "Before you start", next to the step
                      that says to register it, rather than twice on the same screen. The
                      condition has to be the one SetupGuide itself bails on, or a descriptor
                      with an empty steps[] would leave the dialog with no callback URL at all. */}
                  {guide?.steps.length ? null : <RedirectUri uri={redirectUri} tone="surface" />}
                  {provider?.home ? (
                    <a href={provider.home} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-medium underline">
                      {provider.name} <ExternalLink className="h-3 w-3" />
                    </a>
                  ) : null}
                </div>
                <SetupGuide guide={guide} providerName={provider?.name ?? "this app"} redirectUri={redirectUri} />
                {fields.map((f) => (
                  <Field key={f.key} field={f} help={guide?.help?.[f.key]} value={values[f.key] ?? ""} onChange={(v) => setValues((s) => ({ ...s, [f.key]: v }))} />
                ))}
                {(oauth.authorizationOptions ?? []).length > 0 && (
                  <div className="grid gap-1.5" data-testid="connector-scopes">
                    <Label>What the agents may do</Label>
                    {guide?.scopesNote ? (
                      <p className="text-[12px] text-ink-2" data-testid="connector-scopes-note">
                        {guide.scopesNote}
                      </p>
                    ) : null}
                    {(oauth.authorizationOptions ?? []).map((o) => (
                      <label key={o.id} className="flex items-start gap-2 text-[13px] text-ink">
                        <Checkbox
                          checked={options.includes(o.id)}
                          disabled={o.required}
                          onCheckedChange={(on) => setOptions((s) => (on ? [...new Set([...s, o.id])] : s.filter((x) => x !== o.id)))}
                        />
                        <span>
                          {o.label}
                          {o.risk === "destructive" ? <span className="ml-1 text-block">(destructive)</span> : o.risk === "sensitive" ? <span className="ml-1 text-ask">(sensitive)</span> : null}
                          {o.description ? <span className="block text-[12px] text-ink-2">{o.description}</span> : null}
                        </span>
                      </label>
                    ))}
                  </div>
                )}
                {/* A provider with no scope picker (Notion, Google) still has something to say. */}
                {guide?.scopesNote && (oauth.authorizationOptions ?? []).length === 0 ? (
                  <p className="text-[12px] text-ink-2" data-testid="connector-scopes-note">
                    {guide.scopesNote}
                  </p>
                ) : null}
              </>
            ) : (
              <>
                <SetupGuide guide={guide} providerName={provider?.name ?? "this app"} redirectUri={null} />
                {fields.map((f) => (
                  <Field key={f.key} field={f} help={guide?.help?.[f.key]} value={values[f.key] ?? ""} onChange={(v) => setValues((s) => ({ ...s, [f.key]: v }))} />
                ))}
                {guide?.scopesNote ? (
                  <p className="text-[12px] text-ink-2" data-testid="connector-scopes-note">
                    {guide.scopesNote}
                  </p>
                ) : null}
              </>
            )}

            {!replacing && (
              <>
                <div className="grid gap-1.5">
                  <Label htmlFor="connector-label">Name it (optional)</Label>
                  <Input id="connector-label" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Work account" data-testid="connector-label" />
                </div>
                {agents.length > 0 && (
                  <div className="grid gap-1.5" data-testid="connector-agents">
                    <Label>Which agents may use it</Label>
                    {agents.map((a) => (
                      <label key={a.vmId} className="flex items-center gap-2 text-[13px] text-ink">
                        <Checkbox
                          checked={vmIds.includes(a.vmId)}
                          onCheckedChange={(on) => setVmIds((s) => (on ? [...new Set([...s, a.vmId])] : s.filter((x) => x !== a.vmId)))}
                        />
                        {a.name}
                      </label>
                    ))}
                    <p className="text-[12px] text-ink-2">You can change this later, per agent.</p>
                  </div>
                )}
              </>
            )}

            <div className="flex gap-2 rounded-xl border border-line bg-bg-2 px-3.5 py-2.5 text-[12.5px] text-ink-2">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>
                The credentials are sent to your organization’s firewall, which stores them encrypted and makes the calls itself. The agents get
                permission to use this connection, never the credentials.
              </span>
            </div>
          </div>
        )}
        </div>

        <StatusLine state={state} />
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={state.busy}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!ready || state.busy || !descriptor} data-testid="connector-connect-submit">
            {state.busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            {oauth ? "Continue to sign-in" : replacing ? "Replace credentials" : "Connect"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Field({
  field,
  value,
  help,
  onChange,
}: {
  field: { key: string; label: string; inputType: string; required: boolean; secret: boolean; placeholder?: string; description?: string };
  value: string;
  /** One line from the guide about this exact field: where in the provider to find its value. */
  help?: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={`connector-field-${field.key}`}>
        {field.label}
        {field.required ? "" : " (optional)"}
      </Label>
      <Input
        id={`connector-field-${field.key}`}
        type={field.secret || field.inputType === "password" ? "password" : "text"}
        autoComplete="off"
        spellCheck={false}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={field.placeholder}
        data-testid={`connector-field-${field.key}`}
      />
      {field.description ? <p className="text-[12px] text-ink-2">{field.description}</p> : null}
      {help ? (
        <p className="text-[12px] text-ink-2" data-testid={`connector-field-help-${field.key}`}>
          {help}
        </p>
      ) : null}
    </div>
  );
}
