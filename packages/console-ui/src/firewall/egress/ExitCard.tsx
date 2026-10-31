"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { AlertTriangle, Globe2, Loader2, RefreshCw, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "../../ui/button";
import { Switch } from "../../ui/switch";
import { useApi } from "../../lib/api";
import { ConfirmCodeDialog } from "../channels/ChannelDialogs";
import { RelativeTime } from "../../kit/RelativeTime";
import {
  ActionMenu,
  Card,
  CardBody,
  Disclosure,
  Dot,
  Hint,
  IconBox,
  KV,
  Select,
  Stack,
} from "../../kit/console-ui";
import { bytesLabel, type ExitChangeView, type ExitView } from "../../lib/exit-schema";
import { CONTROLCLAW_EXIT_PRESET_ID } from "../../lib/exit-presets";
import { countryLabel, countryOptions } from "../../lib/countries";
import { ConnectExitDialog, RemoveExitDialog, type ConnectDraft } from "./ExitDialogs";
import { useExitChange } from "./useExitChange";
import { NotInspectedInfo } from "./NotInspected";

/**
 * The control plane's own prepaid exit (the console: ControlClaw's residential relay and its
 * included data). `card` is drawn in the Exit card's lower band and `buy` beside its title, when
 * `available` and the org uses that exit or has none yet.
 */
export type ExitAllowanceSlot = { available: boolean; buy: ReactNode; card: ReactNode };

/**
 * Where this organisation's traffic leaves from, at the top of Internet access — above the rules,
 * because it governs them.
 *
 * The card's job is to be honest about two things a person cannot see from a list of rules: that
 * the exit works (the address the world actually sees, checked by the firewall), and what it is
 * costing (bytes this month against the cap).
 *
 * Two features share it. An organisation can point the exit at **its own** provider account, or at
 * **ControlClaw residential**, where there is no account to enter and the thing to show is a
 * prepaid balance — that is `ExitAllowanceCard`, the card's lower band rather than a card of its
 * own, because "where does my traffic leave from" and "how much of it have I got left" are one
 * question to the person asking.
 *
 * The redesign puts one sentence and the two controls used often — the country and a re-check —
 * on the face of the card, and folds the rest (one address per agent, the address itself, the
 * month's bytes, replacing or removing the account) into **More options**. Nothing is dropped:
 * a state somebody has to act on, like a cap used up or a credential the firewall refused, stays
 * on the face where it cannot be missed.
 */
export function ExitCard({
  initial,
  initialChange,
  allowance,
  homeText = "Traffic leaves from your firewall in Germany",
}: {
  initial: ExitView;
  initialChange: ExitChangeView | null;
  allowance?: ExitAllowanceSlot;
  /** Where traffic leaves from with no exit set. The console's firewalls are all in Germany. */
  homeText?: string;
}) {
  const api = useApi();
  const [view, setView] = useState(initial);
  const [connecting, setConnecting] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [checking, setChecking] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setView(await api.exit.getExit({}));
    } catch (error) {
      console.error("getExit failed", error);
    }
  }, [api]);

  const { tracking, state, start, confirm, cancel } = useExitChange({ live: true, initial: initialChange, onSettled: refresh });
  // Once a code has been sent the change is the code dialog's. The Connect form is closed over it
  // rather than left underneath: two modal layers at once is how a click in the top one reads as
  // an outside click in the bottom one.
  const codeChange = tracking?.status === "awaiting_code" ? tracking : null;
  useEffect(() => {
    if (tracking?.status === "awaiting_code") {
      setConnecting(false);
      setRemoving(false);
    }
  }, [tracking?.status]);

  const onConnect = useCallback(
    (draft: ConnectDraft) => {
      // Empty is "no ceiling"; the dialog has already refused anything that is not a number.
      const capGb = draft.capGb.trim();
      const capBytes = capGb ? Math.round(Number(capGb) * 1024 ** 3) : null;
      // The included exit has no credential to send. It goes through its own procedure, which
      // mints the relay token server side, and comes back with the same `changeId` the code
      // dialog follows — so from here on the two paths are identical.
      if (draft.provider === CONTROLCLAW_EXIT_PRESET_ID && api.exitAllowance) {
        const managed = api.exitAllowance;
        void start(() => managed.connect({ sticky: draft.sticky }), "Sending the exit credential to your firewall…");
        setConnecting(false);
        return;
      }
      void start(
        () =>
          api.exit.connectExit({
            provider: draft.provider,
            scheme: draft.scheme,
            host: draft.host.trim(),
            port: Number(draft.port),
            username: draft.username.trim(),
            password: draft.password,
            usernameTemplate: draft.usernameTemplate.trim(),
            passwordTemplate: draft.passwordTemplate.trim(),
            sticky: draft.sticky,
            capBytes,
            country: draft.country,
          }),
        "Sending the account to your firewall…",
      );
      setConnecting(false);
    },
    [start, api],
  );

  const onSticky = useCallback(
    (sticky: boolean) => {
      setView((v) => ({ ...v, sticky }));
      void start(() => api.exit.updateExitSettings({ sticky }), sticky ? "Giving each agent its own address…" : "Going back to one shared address…");
    },
    [start, api],
  );

  const onCountry = useCallback(
    (country: string) => {
      setView((v) => ({ ...v, country: country || null }));
      void start(
        () => api.exit.updateExitSettings({ country }),
        country ? `Moving your residential traffic to ${countryLabel(country)}…` : "Letting the provider choose the country…",
      );
    },
    [start, api],
  );

  const onCheck = useCallback(async () => {
    setChecking(true);
    try {
      await api.exit.checkExitNow({});
      toast.success("Asked your firewall to try the exit. The result appears here in a few seconds.");
      setTimeout(() => void refresh(), 6000);
    } catch (error) {
      toast.error((error as Error).message || "Couldn’t reach your firewall. Try again.");
    } finally {
      setChecking(false);
    }
  }, [refresh, api]);

  const onRemove = useCallback(() => {
    void start(() => api.exit.removeExit({}), "Asking your firewall to remove the account…");
    setRemoving(false);
  }, [start, api]);

  const usage = view.usage.bytesIn + view.usage.bytesOut;
  const overCap = view.capBytes !== null && usage >= view.capBytes;
  // The managed relay bills against a prepaid balance, not against a monthly ceiling the customer
  // sets, so its own band answers "how much is left" and this one stops talking about caps.
  const managed = view.configured && view.provider === CONTROLCLAW_EXIT_PRESET_ID;
  const showAllowance = !!allowance?.available && (managed || !view.configured);
  // Buying sits in the action row, next to Connect, rather than in a block of its own.
  const buyButton = showAllowance ? allowance!.buy : null;

  /*
   * Deliberately narrower than the design's "Traffic comes out in Spain". The exit is per rule:
   * only the rules marked "via home internet" use it, and everything else still leaves from the
   * firewall's own address. On an organisation with an exit connected and no residential rules —
   * which is the state right after connecting one — the design's sentence is simply untrue, and
   * this is a page about where an agent's traffic can be seen.
   */
  const where = !view.configured
    ? homeText
    : view.country
      ? `Home-internet rules leave from ${countryLabel(view.country)}`
      : "Home-internet rules leave from wherever your provider chooses";

  return (
    <Card data-testid="exit-card">
      <CardBody>
        <Stack>
          <div className="flex flex-wrap items-start gap-3">
            <IconBox icon={Globe2} />
            <div className="min-w-0 flex-1 basis-[20rem]">
              <div className="text-[15px] font-semibold text-ink">{where}</div>
              <div className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[12.5px] text-ink-2">
                {view.configured ? (
                  <>
                    <span>
                      Through {managed ? "ControlClaw’s home-internet address (included)" : view.providerName}{" "}
                      <NotInspectedInfo data-testid="exit-not-inspected" />
                    </span>
                    {/* Only where the two share a line. On a phone they stack, and a separator
                        between them is then a lone "·" on a line of its own. */}
                    <span aria-hidden="true" className="hidden sm:inline">
                      ·
                    </span>
                    <ExitReachability view={view} />
                  </>
                ) : (
                  <span className="max-w-[62ch] text-pretty">
                    For sites that need a home connection, connect a residential proxy.
                  </span>
                )}
              </div>
            </div>

            {view.canManage ? (
              <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto sm:shrink-0">
                {view.configured ? (
                  <>
                    {view.supportsCountry ? (
                      <Select
                        aria-label="Exit country"
                        title="Where residential rules leave from, unless a rule says otherwise"
                        value={view.country ?? ""}
                        onChange={(e) => onCountry(e.target.value)}
                        disabled={state.busy}
                        className="w-full sm:w-[150px]"
                        data-testid="exit-card-country"
                      >
                        <option value="">Any country</option>
                        {countryOptions().map((c) => (
                          <option key={c.code} value={c.code}>
                            {c.name}
                          </option>
                        ))}
                      </Select>
                    ) : null}
                    <Button variant="ghost" size="sm" onClick={onCheck} disabled={checking || state.busy} data-testid="exit-check">
                      <RefreshCw className={`h-3.5 w-3.5 ${checking ? "animate-spin" : ""}`} /> Check
                    </Button>
                    {buyButton}
                    {/* Replacing the account and removing it are rare and destructive; they read
                        better as a menu than as two more buttons in a row that wraps on a phone. */}
                    <ActionMenu
                      data-testid="exit-menu"
                      items={[
                        { label: "Use my own proxy instead", icon: Globe2, onClick: () => setConnecting(true) },
                        "-",
                        { label: "Remove the exit", icon: Trash2, danger: true, onClick: () => setRemoving(true) },
                      ]}
                    />
                  </>
                ) : (
                  <>
                    <Button
                      variant="brand"
                      size="sm"
                      onClick={() => setConnecting(true)}
                      disabled={state.busy || !view.hasFirewall}
                      title={view.hasFirewall ? undefined : "Your organization has no firewall yet. Create a secured agent first."}
                      data-testid="exit-connect"
                    >
                      Connect a residential proxy
                    </Button>
                    {buyButton}
                  </>
                )}
              </div>
            ) : null}
          </div>

          {/* States somebody has to act on stay on the face of the card. Everything folded away
              below is a setting or a fact, never a problem. */}
          {overCap && !managed ? (
            <div className="flex items-start gap-2 rounded-[10px] border border-block-border bg-block-soft px-3.5 py-2.5 text-[12.5px] text-block-fg">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>This month’s limit is used up, so sites on residential rules are failing. Raise it, or wait for the 1st.</span>
            </div>
          ) : null}
          {view.lastError && !overCap ? (
            <div className="flex items-start gap-2 rounded-[10px] border border-block-border bg-block-soft px-3.5 py-2.5 text-[12.5px] text-block-fg">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" /> {view.lastError}
            </div>
          ) : null}
          {state.busy ? (
            <p className="flex items-center gap-2 text-[13px] text-ink-2">
              <Loader2 className="h-3.5 w-3.5 animate-spin" /> {state.note ?? "Working…"}
            </p>
          ) : null}
          {state.error ? <p className="text-[13px] text-block-fg">{state.error}</p> : null}

          {view.configured ? (
            <Disclosure flat title="More options" data-testid="exit-more">
              <Stack>
                <div className="flex flex-wrap items-center gap-3">
                  <div className="min-w-[14rem] flex-1">
                    <div className="text-[13.5px] font-semibold text-ink">A separate address for each agent</div>
                    <Hint>Otherwise all your agents share one.</Hint>
                  </div>
                  <Switch
                    checked={view.sticky}
                    onCheckedChange={onSticky}
                    disabled={!view.canManage || state.busy}
                    aria-label="One address per agent"
                    data-testid="exit-card-sticky"
                  />
                </div>

                <KV
                  rows={[
                    view.usernameHint ? ["Account", view.usernameHint, true] : null,
                    view.check?.exitIp ? ["Current address", view.check.exitIp, true] : null,
                    [
                      "Used this month",
                      `${bytesLabel(usage)}${!managed && view.capBytes !== null ? ` of ${bytesLabel(view.capBytes)}` : ""} · ${view.ruleCount} rule${view.ruleCount === 1 ? "" : "s"} use${view.ruleCount === 1 ? "s" : ""} it`,
                    ],
                  ]}
                  data-testid="exit-usage"
                />

              </Stack>
            </Disclosure>
          ) : null}
        </Stack>
      </CardBody>

      {showAllowance ? (
        <CardBody divided data-testid="exit-allowance">
          {allowance!.card}
        </CardBody>
      ) : null}

      <ConnectExitDialog
        open={connecting && !codeChange}
        replace={view.configured ? view : null}
        state={state}
        onSubmit={onConnect}
        onClose={() => setConnecting(false)}
        managedAvailable={!!api.exitAllowance}
      />
      <RemoveExitDialog open={removing && !codeChange} ruleCount={view.ruleCount} state={state} onConfirm={onRemove} onClose={() => setRemoving(false)} />
      <ConfirmCodeDialog
        change={codeChange}
        state={state}
        onSubmit={confirm}
        onCancel={() => void cancel()}
        sender="Your firewall"
        warning={
          tracking?.kind === "remove" ? (
            <span>Rules using the exit go back to leaving from your firewall’s own address.</span>
          ) : undefined
        }
      />
    </Card>
  );
}

/**
 * Whether the exit works, in one line. A provider that has no addresses in the country asked for
 * may refuse — which shows up as unreachable — or may quietly hand over one from somewhere else,
 * which looks exactly like success. This is the only place that tells the two apart, so it is said
 * out loud rather than left to be discovered from a site.
 */
function ExitReachability({ view }: { view: ExitView }) {
  if (!view.check) return <span data-testid="exit-status">Not checked yet</span>;
  const mismatch =
    !!view.country && !!view.check.ok && !!view.check.exitCountry && view.check.exitCountry !== view.country;
  if (!view.check.ok) {
    return (
      <span className="inline-flex items-center gap-1.5" data-testid="exit-status">
        <Dot tone="err">{view.check.error ?? "Not reachable"}</Dot>
        <RelativeTime date={view.check.at} />
      </span>
    );
  }
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5" data-testid="exit-status">
      <Dot tone="ok">
        Reachable
        {view.check.exitIp ? (
          <>
            {" "}
            from <span className="font-mono">{view.check.exitIp}</span>
            {view.check.exitCountry ? ` in ${countryLabel(view.check.exitCountry)}` : ""}
          </>
        ) : view.check.error ? (
          // The tunnel opened but the echo service would not say where from, usually because it
          // rate-limited us. Saying so beats an address that is simply missing with no reason.
          <span data-testid="exit-address-unknown"> · {view.check.error}</span>
        ) : null}
      </Dot>
      <RelativeTime date={view.check.at} />
      {mismatch ? (
        <span className="text-block-fg" data-testid="exit-country-mismatch">
          · you asked for {countryLabel(view.country!)}
        </span>
      ) : null}
    </span>
  );
}
