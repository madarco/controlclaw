"use client";

import { NativeSelect } from "../../ui/native-select";
import { useEffect, useState } from "react";
import { ExternalLink, Loader2 } from "lucide-react";
import { Button } from "../../ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "../../ui/dialog";
import { Input } from "../../ui/input";
import { Switch } from "../../ui/switch";
import { CONTROLCLAW_EXIT_PRESET_ID, EXIT_PRESETS, presetById, templatesUseCountry, templatesUseUsername } from "../../lib/exit-presets";
import { countryOptions } from "../../lib/countries";
import { NotInspectedNotice } from "./NotInspected";
import { DEFAULT_CAP_BYTES, type ExitScheme, type ExitView } from "../../lib/exit-schema";
import type { Busy } from "./useExitChange";

export interface ConnectDraft {
  provider: string;
  scheme: ExitScheme;
  host: string;
  port: number;
  username: string;
  password: string;
  usernameTemplate: string;
  passwordTemplate: string;
  sticky: boolean;
  capGb: string;
  /** "" is "any country"; otherwise an ISO 3166-1 alpha-2 code. */
  country: string;
}

export function draftFor(providerId: string, from?: ExitView): ConnectDraft {
  const p = presetById(providerId);
  return {
    provider: p.id,
    scheme: p.scheme,
    host: p.host,
    port: p.port,
    username: "",
    password: "",
    usernameTemplate: p.usernameTemplate,
    passwordTemplate: p.passwordTemplate,
    sticky: from?.sticky ?? false,
    country: from?.country ?? "",
    // `null` is a decision ("no ceiling"), not an absence. Folding it into the default put a 5 GB
    // stop back on an account whose owner had deliberately removed one, without saying so.
    capGb: from
      ? from.capBytes === null
        ? ""
        : String(Math.round((from.capBytes / 1024 ** 3) * 10) / 10)
      : String(DEFAULT_CAP_BYTES / 1024 ** 3),
  };
}

/**
 * Connecting a residential proxy account. Everything the provider gave the customer, and nothing
 * we invented: the preset fills the host, the port and the shape of the username, and every field
 * stays editable because providers change these without telling anyone.
 */
export function ConnectExitDialog({
  open,
  replace,
  state,
  onSubmit,
  onClose,
  managedAvailable = true,
}: {
  open: boolean;
  replace: ExitView | null;
  state: Busy;
  onSubmit: (draft: ConnectDraft) => void;
  onClose: () => void;
  /** Whether the control plane has its own exit to offer (the console: ControlClaw's relay). */
  managedAvailable?: boolean;
}) {
  const presets = managedAvailable ? EXIT_PRESETS : EXIT_PRESETS.filter((p) => p.id !== CONTROLCLAW_EXIT_PRESET_ID);
  const [draft, setDraft] = useState<ConnectDraft>(() => draftFor("oxylabs"));
  useEffect(() => {
    if (open) setDraft(draftFor(replace?.provider || "oxylabs", replace ?? undefined));
  }, [open, replace?.provider]); // eslint-disable-line react-hooks/exhaustive-deps
  const preset = presetById(draft.provider);
  // The included exit has no account to enter: the control plane mints the credential and the
  // bytes come out of a prepaid balance. Everything below the provider row is about a credential
  // the customer owns, so for this one it is hidden, and `ready` must not wait for a password
  // nobody can type, which is what left the button disabled with no way forward.
  const managed = preset.managed === true;
  // Asked of the live templates, not of the provider id: every field here is editable, so what
  // matters is what this credential would actually render.
  const needsUsername = !managed && templatesUseUsername(draft.usernameTemplate, draft.passwordTemplate);
  const takesCountry = templatesUseCountry(draft.usernameTemplate, draft.passwordTemplate);
  // An empty cap means "no ceiling"; anything else has to be a number, and saying so here beats a
  // schema rejection the person cannot read.
  const capError = !managed && draft.capGb.trim() && !(Number(draft.capGb) > 0) ? "Enter a number of gigabytes, or leave it empty for no limit." : null;
  const ready = managed || (draft.host.trim() && draft.port > 0 && (!needsUsername || draft.username.trim()) && draft.password.trim() && !capError);

  return (
    <Dialog open={open} onOpenChange={(o) => !o && !state.busy && onClose()}>
      <DialogContent className="sm:max-w-[560px]" data-testid="exit-dialog-connect">
        <DialogHeader>
          <DialogTitle>{replace ? "Replace the residential credential" : "Connect a residential proxy"}</DialogTitle>
          <DialogDescription>
            Your agents will reach the sites you choose from an ordinary home connection instead of your firewall’s address in Germany.{" "}
            {managed
              ? "This one is ControlClaw’s: the data counts against your plan’s allowance and there is no account to open."
              : "The account is yours: the provider bills you for the traffic that goes through it."}
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-3">
          <div className="flex flex-wrap gap-1.5" data-testid="exit-providers">
            {presets.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => setDraft((d) => ({ ...draftFor(p.id), username: d.username, password: d.password, sticky: d.sticky, capGb: d.capGb, country: d.country }))}
                className={`rounded-lg border px-2.5 py-1.5 text-[13px] ${draft.provider === p.id ? "border-brand-ink bg-brand-soft text-brand-ink" : "border-line text-ink-2 hover:bg-bg-2"}`}
              >
                {p.name}
              </button>
            ))}
          </div>

          {managed && (
            <p className="text-[13px] text-ink-2" data-testid="exit-managed-blurb">
              {preset.blurb} Your firewall gets its own credential, and the data counts against the balance below. Nothing to paste.
            </p>
          )}

          {!managed && (
          <div className="flex gap-2">
            <label className="flex flex-1 flex-col gap-1">
              <span className="text-xs text-ink-2">Host</span>
              <Input value={draft.host} onChange={(e) => setDraft((d) => ({ ...d, host: e.target.value }))} placeholder="pr.oxylabs.io" data-testid="exit-host" />
            </label>
            <label className="flex w-24 flex-col gap-1">
              <span className="text-xs text-ink-2">Port</span>
              <Input type="number" value={draft.port} onChange={(e) => setDraft((d) => ({ ...d, port: Number(e.target.value) }))} data-testid="exit-port" />
            </label>
            <label className="flex w-28 flex-col gap-1">
              <span className="text-xs text-ink-2">Protocol</span>
              <NativeSelect
                value={draft.scheme}
                onChange={(e) => setDraft((d) => ({ ...d, scheme: e.target.value as ExitScheme }))}
                className="h-9 rounded-md border bg-background px-2 text-sm"
                data-testid="exit-scheme"
              >
                <option value="http">HTTP</option>
                <option value="https">HTTPS</option>
                <option value="socks5">SOCKS5</option>
              </NativeSelect>
            </label>
          </div>
          )}

          {/*
            A provider whose templates never render `{username}` has no user name to give: Apify
            puts the group and the country there and identifies the account by the password alone.
            Asking anyway made a customer invent a value that was then thrown away, so the field
            goes and its help line stays to say why. The included exit has no form at all.
          */}
          {!managed && (needsUsername ? (
            <label className="flex flex-col gap-1">
              <span className="text-xs text-ink-2">Username</span>
              <Input value={draft.username} onChange={(e) => setDraft((d) => ({ ...d, username: e.target.value }))} autoComplete="off" data-testid="exit-username" />
              <span className="text-[12px] text-ink-2">{preset.usernameHelp}</span>
            </label>
          ) : (
            preset.usernameHelp && (
              <p className="text-[12px] text-ink-2" data-testid="exit-username-not-needed">
                {preset.usernameHelp}
              </p>
            )
          ))}

          {!managed && (
          <label className="flex flex-col gap-1">
            <span className="text-xs text-ink-2">Password</span>
            <Input type="password" value={draft.password} onChange={(e) => setDraft((d) => ({ ...d, password: e.target.value }))} autoComplete="new-password" data-testid="exit-password" />
          </label>
          )}

          {!managed && (
          <details className="rounded-lg border border-line px-3 py-2">
            <summary className="cursor-pointer text-[13px] text-ink-2">How this provider is addressed</summary>
            <div className="mt-2 grid gap-2">
              <label className="flex flex-col gap-1">
                <span className="text-xs text-ink-2">Username sent to the provider</span>
                <Input value={draft.usernameTemplate} onChange={(e) => setDraft((d) => ({ ...d, usernameTemplate: e.target.value }))} className="font-mono text-xs" />
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-xs text-ink-2">Password sent to the provider</span>
                <Input value={draft.passwordTemplate} onChange={(e) => setDraft((d) => ({ ...d, passwordTemplate: e.target.value }))} className="font-mono text-xs" />
              </label>
              <p className="text-[12px] text-ink-2">
                <code>{"{username}"}</code>, <code>{"{password}"}</code>, <code>{"{session}"}</code>, <code>{"{country}"}</code> and{" "}
                <code>{"{country_lc}"}</code> (lower case) are filled in. A part in <code>[square brackets]</code> is kept only when everything
                inside it has a value. The same template then works with or without a country, and with or without one IP per agent. Change these if
                your provider changes its format.
              </p>
            </div>
          </details>
          )}

          {takesCountry && (
            <label className="flex items-center justify-between gap-3 rounded-lg border border-line px-3 py-2">
              <span className="text-[13.5px]">
                Leave from
                <span className="block text-[12px] text-ink-2">
                  The default for every residential rule. A rule can ask for somewhere else.
                </span>
              </span>
              <NativeSelect
                value={draft.country}
                onChange={(e) => setDraft((d) => ({ ...d, country: e.target.value }))}
                className="h-9 rounded-md border bg-background px-2 text-sm"
                data-testid="exit-country"
              >
                <option value="">Any country</option>
                {countryOptions().map((c) => (
                  <option key={c.code} value={c.code}>
                    {c.name}
                  </option>
                ))}
              </NativeSelect>
            </label>
          )}

          <label className="flex items-center justify-between gap-3 rounded-lg border border-line px-3 py-2">
            <span className="text-[13.5px]">
              Give each agent its own IP
              <span className="block text-[12px] text-ink-2">Two agents working at once don’t look like the same person.</span>
            </span>
            <Switch checked={draft.sticky} onCheckedChange={(v) => setDraft((d) => ({ ...d, sticky: v }))} data-testid="exit-sticky" />
          </label>

          {!managed && (
          <label className="flex items-center justify-between gap-3 rounded-lg border border-line px-3 py-2">
            <span className="text-[13.5px]">
              Stop after
              <span className="block text-[12px] text-ink-2">Your provider bills you for residential data by the gigabyte. Leave empty for no limit.</span>
            </span>
            <span className="flex items-center gap-1.5">
              <Input value={draft.capGb} onChange={(e) => setDraft((d) => ({ ...d, capGb: e.target.value }))} className="h-9 w-20 text-right" data-testid="exit-cap" />
              <span className="text-[13px] text-ink-2">GB / month</span>
            </span>
          </label>
          )}
          {capError && <p className="text-[12.5px] text-block-fg">{capError}</p>}

          {!managed && preset.docsUrl && (
            <a href={preset.docsUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-[13px] text-brand-ink underline">
              {preset.name} setup docs <ExternalLink className="h-3 w-3" />
            </a>
          )}

          <NotInspectedNotice data-testid="exit-connect-not-inspected">
            Connecting an account changes nothing on its own. You choose which sites use it, one rule at a time. Those sites aren’t
            inspected: their traffic goes out encrypted, so AI review, content rules and website logins don’t apply to it.
          </NotInspectedNotice>

          {state.error && <p className="text-[13px] text-block-fg">{state.error}</p>}
          {state.busy && (
            <p className="flex items-center gap-2 text-[13px] text-ink-2">
              <Loader2 className="h-3.5 w-3.5 animate-spin" /> {state.note ?? "Working…"}
            </p>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={state.busy}>
            Cancel
          </Button>
          <Button
            // A username left over from another provider must not be stored against one that has
            // no use for it: the card would then show a hint for an account name nothing sends.
            onClick={() => onSubmit({ ...draft, username: needsUsername ? draft.username : "", country: takesCountry ? draft.country : "" })}
            disabled={!ready || state.busy}
            data-testid="exit-connect-submit"
          >
            {replace ? "Replace" : "Connect"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** Removing the exit. The rules that use it are what the person needs to be told about. */
export function RemoveExitDialog({
  open,
  ruleCount,
  state,
  onConfirm,
  onClose,
}: {
  open: boolean;
  ruleCount: number;
  state: Busy;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <Dialog open={open} onOpenChange={(o) => !o && !state.busy && onClose()}>
      <DialogContent className="sm:max-w-[480px]" data-testid="exit-dialog-remove">
        <DialogHeader>
          <DialogTitle>Remove the residential exit?</DialogTitle>
          <DialogDescription>
            Your firewall removes the account. {ruleCount > 0
              ? `The ${ruleCount} rule${ruleCount === 1 ? "" : "s"} using it go back to leaving from your firewall's own address. Those sites see a datacenter address again.`
              : "No rules are using it."}
          </DialogDescription>
        </DialogHeader>
        {state.error && <p className="text-[13px] text-block-fg">{state.error}</p>}
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={state.busy}>
            Keep it
          </Button>
          <Button variant="destructive" onClick={onConfirm} disabled={state.busy} data-testid="exit-remove-submit">
            Remove exit
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
