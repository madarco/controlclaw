"use client";

import { NativeSelect } from "../../ui/native-select";
import { useEffect, useReducer, useRef, useState } from "react";
import { ChevronDown, ExternalLink, Loader2, ShieldCheck } from "lucide-react";
import { Button } from "../../ui/button";
import { CopyButton } from "../../ui/copy-button";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "../../ui/collapsible";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../../ui/dialog";
import { InputOTP, InputOTPGroup, InputOTPSeparator, InputOTPSlot } from "../../ui/input-otp";
import { CODE_LENGTH, extractCode } from "../../lib/confirm-code";
import type { AgentChannelChangeView, AgentRefView, WhatsappLoginState } from "../../lib/channels-schema";
import { SLACK_APP_MANIFEST, SLACK_APP_NEW_URL, slackTokenProblem } from "../../lib/slack-app";
import {
  busyLine,
  canSubmit,
  CODE_DIALOG_IDLE,
  codeDialogReducer,
  failureOf,
  holdsOpen,
  isBusy,
  submitLabel,
  type CodeDialogPhase,
} from "../../lib/code-dialog";
import { RECOVERY_SENT_VIA } from "../../lib/recovery-confirm-schema";
import { RecoveryKeyConfirm, type LoadRecoveryChallenge } from "../change/RecoveryKeyConfirm";
import { useOptionalApi } from "../../lib/api";
import type { CodeTapView } from "../../lib/code-tap-schema";
import { lookupSlackApp, lookupTelegramBot, slackAppIdOf, type StartChat, type TokenLookup } from "../../lib/pairing-step";
import { PairingStep, type PairingStepProps } from "./PairingStep";

/** Where the dialog reads a change's Telegram buttons from; the demo pages pass fixtures. */
export type LoadCodeTap = (changeId: string) => Promise<CodeTapView | null>;
const CODE_TAP_POLL_MS = 2000;
/** Reads before deciding a change went out without buttons. */
const CODE_TAP_FIRST_READS = 3;

/**
 * The dialogs of the Channels page: token entry for Telegram and Slack, the WhatsApp QR, and
 * the confirmation code. They hold only form state; the panel owns the RPC calls.
 */

type Busy = { busy: boolean; error: string | null; note: string | null };

/**
 * The agent picker's value. It starts on `defaultAgent` (the organization's only agent) when that
 * agent is in the list, so a new channel goes straight to it and on to pairing; otherwise on "".
 */
function useAgentChoice(open: boolean, agents: AgentRefView[], defaultAgent: string | undefined) {
  const initial = defaultAgent && agents.some((a) => a.vmId === defaultAgent) ? defaultAgent : "";
  const [vmId, setVmId] = useState(initial);
  useEffect(() => setVmId(open ? initial : ""), [open, initial]);
  return [vmId, setVmId] as const;
}

/** Optional "enable it here straight away" picker. Absent when the caller already knows the agent. */
function AgentPicker({ agents, value, onChange }: { agents: AgentRefView[]; value: string; onChange: (v: string) => void }) {
  if (agents.length === 0) return null;
  return (
    <div className="grid gap-1.5">
      <Label htmlFor="ch-agent">Enable it on</Label>
      <NativeSelect
        id="ch-agent"
        className="h-9 rounded-md border border-line bg-bg px-2 text-[13px] text-ink"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        data-testid="channel-agent-select"
      >
        <option value="">Not yet: keep it in the organization</option>
        {agents.map((a) => (
          <option key={a.vmId} value={a.vmId}>
            {a.displayName || a.name}
          </option>
        ))}
      </NativeSelect>
    </div>
  );
}

export function TelegramDialog({
  open,
  replace,
  state,
  agents = [],
  defaultAgent,
  pairing,
  onClose,
  onSubmit,
}: {
  open: boolean;
  replace: boolean;
  state: Busy;
  /** Agents that could take the connection right away; empty hides the picker. */
  agents?: AgentRefView[];
  /** The organization's only agent: the picker starts on it instead of "Not yet". */
  defaultAgent?: string;
  /** Set once the bot is connected on an agent: the dialog walks the person through pairing. */
  pairing?: PairingStepProps | null;
  onClose: () => void;
  /** `start` is how to reach the bot, from Telegram itself; the panel keeps it for the pairing step. */
  onSubmit: (input: { botToken: string; label?: string; vmId?: string; start: StartChat }) => void;
}) {
  const [token, setToken] = useState("");
  const [label, setLabel] = useState("");
  const [vmId, setVmId] = useAgentChoice(open, agents, defaultAgent);
  const lookup = useTokenLookup(open);
  useEffect(() => {
    if (!open) {
      setToken("");
      setLabel("");
    }
  }, [open]);
  const valid = /^\d{6,}:[A-Za-z0-9_-]{20,}$/.test(token.trim());
  const busy = state.busy || lookup.checking;
  const submit = async () => {
    const botToken = token.trim();
    // Ask Telegram who the bot is, from this browser: a wrong token stops here, and the bot's
    // username gives the pairing step its t.me link (and the connection a name, when none was typed).
    const r = await lookup.run(() => lookupTelegramBot(botToken), "Telegram doesn’t accept this token. Copy it again from @BotFather.");
    if (!r) return;
    const username = r.kind === "ok" ? r.value.username : null;
    const typed = label.trim();
    onSubmit({
      botToken,
      label: typed || (!replace && username ? `@${username}` : undefined),
      vmId: vmId || undefined,
      start: { type: "telegram", username },
    });
  };
  if (pairing && open) {
    return (
      <Dialog open onOpenChange={(o) => !o && !pairing.approving && pairing.onClose()}>
        <DialogContent className="sm:max-w-[520px]" data-testid="channel-dialog-telegram" data-step="pairing">
          <PairingStep {...pairing} />
        </DialogContent>
      </Dialog>
    );
  }
  return (
    <Dialog open={open} onOpenChange={(o) => !o && !busy && onClose()}>
      <DialogContent className="sm:max-w-[520px]" data-testid="channel-dialog-telegram">
        <DialogHeader>
          <DialogTitle>{replace ? "Replace the Telegram token" : "Connect Telegram"}</DialogTitle>
          <DialogDescription>
            {replace
              ? "Paste the new token from @BotFather. The old token stops working once the change goes through."
              : "A Telegram bot is the agent’s number. People message the bot, and you approve who can talk to it."}
          </DialogDescription>
        </DialogHeader>
        {!replace && (
          <ol className="list-decimal space-y-1.5 pl-5 text-[13.5px] text-ink-2">
            <li>
              In Telegram, open <strong className="text-ink">@BotFather</strong> and send <code className="rounded bg-bg-2 px-1">/newbot</code>.
            </li>
            <li>Pick a name and a username ending in <code className="rounded bg-bg-2 px-1">bot</code>.</li>
            <li>Copy the token BotFather shows, like <code className="rounded bg-bg-2 px-1">123456789:AAF…</code>, and paste it here.</li>
          </ol>
        )}
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="tg-token">Bot token</Label>
            <Input
              id="tg-token"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="123456789:AAF…"
              autoComplete="off"
              spellCheck={false}
              data-testid="channel-telegram-token"
            />
          </div>
          {!replace && (
            <div className="grid gap-1.5">
              <Label htmlFor="tg-label">Bot name (optional)</Label>
              <Input id="tg-label" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="@marcobot" maxLength={80} />
            </div>
          )}
          {!replace && <AgentPicker agents={agents} value={vmId} onChange={setVmId} />}
        </div>
        <TokenNote />
        <StatusLine state={lookup.merge(state)} />
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={!valid || busy} data-testid="channel-telegram-submit">
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            {replace ? "Replace token" : "Connect Telegram"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function SlackDialog({
  open,
  replace,
  state,
  agents = [],
  defaultAgent,
  pairing,
  onClose,
  onSubmit,
}: {
  open: boolean;
  replace: boolean;
  state: Busy;
  /** Agents that could take the connection right away; empty hides the picker. */
  agents?: AgentRefView[];
  /** The organization's only agent: the picker starts on it instead of "Not yet". */
  defaultAgent?: string;
  /** Set once the app is connected on an agent: the dialog walks the person through pairing. */
  pairing?: PairingStepProps | null;
  onClose: () => void;
  /** `start` is how to open the app in Slack, from Slack itself; the panel keeps it for the pairing step. */
  onSubmit: (input: { botToken: string; appToken: string; label?: string; vmId?: string; start: StartChat }) => void;
}) {
  const [bot, setBot] = useState("");
  const [app, setApp] = useState("");
  const [label, setLabel] = useState("");
  const [vmId, setVmId] = useAgentChoice(open, agents, defaultAgent);
  useEffect(() => {
    if (!open) {
      setBot("");
      setApp("");
      setLabel("");
    }
  }, [open]);
  const lookup = useTokenLookup(open);
  const botProblem = slackTokenProblem("bot", bot);
  const appProblem = slackTokenProblem("app", app);
  const valid = bot.trim().startsWith("xoxb-") && app.trim().startsWith("xapp-");
  const busy = state.busy || lookup.checking;
  const submit = async () => {
    const botToken = bot.trim();
    const appToken = app.trim();
    // Ask Slack which workspace and app this is, from this browser: a wrong token stops here, and
    // the answer gives the pairing step a link that opens the app's messages.
    const r = await lookup.run(() => lookupSlackApp(botToken), "Slack doesn’t accept this bot token. Copy the Bot User OAuth Token again.");
    if (!r) return;
    const found = r.kind === "ok" ? r.value : null;
    const typed = label.trim();
    onSubmit({
      botToken,
      appToken,
      label: typed || (!replace && found?.team ? found.team : undefined),
      vmId: vmId || undefined,
      start: { type: "slack", appId: slackAppIdOf(appToken), teamId: found?.teamId ?? null, appName: found?.appName ?? null },
    });
  };
  if (pairing && open) {
    return (
      <Dialog open onOpenChange={(o) => !o && !pairing.approving && pairing.onClose()}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-[560px]" data-testid="channel-dialog-slack" data-step="pairing">
          <PairingStep {...pairing} />
        </DialogContent>
      </Dialog>
    );
  }
  return (
    <Dialog open={open} onOpenChange={(o) => !o && !busy && onClose()}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-[560px]" data-testid="channel-dialog-slack">
        <DialogHeader>
          <DialogTitle>{replace ? "Replace the Slack tokens" : "Connect Slack"}</DialogTitle>
          <DialogDescription>
            The agent joins your workspace as your own Slack app and answers direct messages and mentions.
          </DialogDescription>
        </DialogHeader>
        {!replace && <SlackSetupGuide />}
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="sl-bot">Bot token</Label>
            <Input id="sl-bot" value={bot} onChange={(e) => setBot(e.target.value)} placeholder="xoxb-…" autoComplete="off" spellCheck={false} data-testid="channel-slack-bot" />
            <FieldHint problem={botProblem} testId="channel-slack-bot-hint" />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="sl-app">App-level token</Label>
            <Input id="sl-app" value={app} onChange={(e) => setApp(e.target.value)} placeholder="xapp-…" autoComplete="off" spellCheck={false} data-testid="channel-slack-app" />
            <FieldHint problem={appProblem} testId="channel-slack-app-hint" />
          </div>
          {!replace && (
            <div className="grid gap-1.5">
              <Label htmlFor="sl-label">Workspace (optional)</Label>
              <Input id="sl-label" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Acme" maxLength={80} />
            </div>
          )}
          {!replace && <AgentPicker agents={agents} value={vmId} onChange={setVmId} />}
        </div>
        <TokenNote />
        <StatusLine state={lookup.merge(state)} />
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void submit()} disabled={!valid || busy} data-testid="channel-slack-submit">
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            {replace ? "Replace tokens" : "Connect Slack"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/**
 * How to build the Slack app. The manifest does the fiddly part — scopes, events, Socket Mode —
 * in one paste, so the steps left over are the two tokens Slack only shows in its own screens.
 */
function SlackSetupGuide() {
  const [showManifest, setShowManifest] = useState(false);
  return (
    // min-w-0 all the way down to the <pre>: it is a grid item, and the manifest's long lines
    // would otherwise set the track's min-content width and push the dialog past its max width.
    <div className="grid min-w-0 gap-2.5">
      <ol className="list-decimal space-y-1.5 pl-5 text-[13.5px] text-ink-2">
        <li>
          Open{" "}
          <a href={SLACK_APP_NEW_URL} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-link hover:underline">
            api.slack.com/apps <ExternalLink className="h-3 w-3" />
          </a>{" "}
          → <strong className="text-ink">Create New App</strong> → <strong className="text-ink">From a manifest</strong>, pick your workspace and paste the manifest below.
        </li>
        <li>
          <strong className="text-ink">Install App → Install to Workspace</strong>, then copy the <strong className="text-ink">Bot User OAuth Token</strong> (
          <code className="rounded bg-bg-2 px-1">xoxb-…</code>).
        </li>
        <li>
          <strong className="text-ink">Basic Information → App-Level Tokens → Generate Token and Scopes</strong>: add{" "}
          <code className="rounded bg-bg-2 px-1">connections:write</code>, save, and copy that token (<code className="rounded bg-bg-2 px-1">xapp-…</code>).
        </li>
        <li>Paste both tokens below. Then message the app in Slack. It replies with a pairing code, and you approve yourself.</li>
      </ol>

      <Collapsible open={showManifest} onOpenChange={setShowManifest} className="min-w-0">
        <div className="min-w-0 rounded-xl border border-line bg-bg-2">
          <div className="flex items-center gap-2 px-3 py-2">
            <CollapsibleTrigger className="flex flex-1 cursor-pointer items-center gap-1.5 text-left text-[13px] font-medium text-ink" data-testid="channel-slack-manifest-toggle">
              <ChevronDown className={`h-3.5 w-3.5 transition-transform ${showManifest ? "" : "-rotate-90"}`} />
              App manifest
            </CollapsibleTrigger>
            <CopyButton value={SLACK_APP_MANIFEST} size="xs" label="Copy manifest" data-testid="channel-slack-manifest-copy" />
          </div>
          <CollapsibleContent>
            <pre className="max-h-56 w-full min-w-0 overflow-auto border-t border-line px-3 py-2 font-mono text-[11.5px] leading-[1.5] text-ink-2" data-testid="channel-slack-manifest">
              {SLACK_APP_MANIFEST}
            </pre>
          </CollapsibleContent>
        </div>
      </Collapsible>

      <div className="rounded-xl border border-ask-border bg-ask-soft px-3 py-2 text-[12.5px] text-ask-fg">
        Don’t turn on <strong>token rotation</strong>. It makes Slack issue <code className="rounded bg-black/5 px-1">xoxe.</code> tokens that expire every 12 hours. Rotation can’t be
        turned off again, so you would have to create the app again.
      </div>
    </div>
  );
}

/** Why the token in this field is the wrong one. Shown while typing; the button stays disabled. */
function FieldHint({ problem, testId }: { problem: string | null; testId: string }) {
  if (!problem) return null;
  return (
    <span className="text-[12.5px] text-block-fg" data-testid={testId}>
      {problem}
    </span>
  );
}

export function WhatsappDialog({
  open,
  state,
  login,
  agents = [],
  defaultAgent,
  pairing,
  onShowCode,
  onClose,
  onStart,
}: {
  open: boolean;
  state: Busy;
  /**
   * A new dedicated number on an agent: once it is linked, the dialog walks the person through
   * pairing. Not shown for "my own number", where nobody else can message the agent.
   */
  pairing?: PairingStepProps | null;
  /** The live QR state from the box once the login started. */
  login: { state: WhatsappLoginState; qrDataUrl: string | null; message: string | null; onBox?: boolean } | null;
  /**
   * Opens the QR on the agent's own page, in a new tab: for a box that shows it there (`onBox`), the
   * console never has the image. The agent is the one the login is running on.
   */
  onShowCode?: () => void;
  /** Which agent to link the number on. Empty when the caller already knows (the agent page). */
  agents?: AgentRefView[];
  /** The organization's only agent: the picker starts on it instead of "Choose an agent…". */
  defaultAgent?: string;
  onClose: () => void;
  onStart: (personal: boolean, vmId?: string) => void;
}) {
  const [personal, setPersonal] = useState(false);
  const [vmId, setVmId] = useAgentChoice(open, agents, defaultAgent);
  const needsAgent = agents.length > 0 && !vmId;
  const started = login && login.state !== "idle";
  if (open && pairing && login?.state === "connected" && !personal) {
    return (
      <Dialog open onOpenChange={(o) => !o && !pairing.approving && pairing.onClose()}>
        <DialogContent className="sm:max-w-[520px]" data-testid="channel-dialog-whatsapp" data-step="pairing">
          <PairingStep {...pairing} />
        </DialogContent>
      </Dialog>
    );
  }
  return (
    <Dialog open={open} onOpenChange={(o) => !o && !state.busy && onClose()}>
      <DialogContent className="sm:max-w-[520px]" data-testid="channel-dialog-whatsapp">
        <DialogHeader>
          <DialogTitle>Connect WhatsApp</DialogTitle>
          <DialogDescription>
            The agent links to a WhatsApp number as a linked device, like WhatsApp Web. Only the agent’s box keeps the session.
          </DialogDescription>
        </DialogHeader>
        {!started ? (
          <div className="grid gap-2">
            {agents.length > 0 ? (
              <div className="grid gap-1.5">
                <Label htmlFor="wa-agent">Link it on</Label>
                <NativeSelect
                  id="wa-agent"
                  className="h-9 rounded-md border border-line bg-bg px-2 text-[13px] text-ink"
                  value={vmId}
                  onChange={(e) => setVmId(e.target.value)}
                  data-testid="channel-whatsapp-agent"
                >
                  <option value="">Choose an agent…</option>
                  {agents.map((a) => (
                    <option key={a.vmId} value={a.vmId}>
                      {a.displayName || a.name}
                    </option>
                  ))}
                </NativeSelect>
                <span className="text-[12.5px] text-ink-2">Only that agent’s box keeps the WhatsApp session. To move it later, you scan a new code.</span>
              </div>
            ) : null}
            <label className={`flex cursor-pointer gap-3 rounded-xl border p-3 ${!personal ? "border-brand bg-brand-soft/40" : "border-line"}`}>
              <input type="radio" name="wa-mode" checked={!personal} onChange={() => setPersonal(false)} className="mt-1" />
              <div className="text-[13.5px]">
                <div className="font-medium text-ink">A dedicated number (recommended)</div>
                <div className="text-ink-2">A second phone or SIM for the agent. People message that number, and you approve who can talk to it.</div>
              </div>
            </label>
            <label className={`flex cursor-pointer gap-3 rounded-xl border p-3 ${personal ? "border-brand bg-brand-soft/40" : "border-line"}`}>
              <input type="radio" name="wa-mode" checked={personal} onChange={() => setPersonal(true)} className="mt-1" />
              <div className="text-[13.5px]">
                <div className="font-medium text-ink">My own number</div>
                <div className="text-ink-2">Only you can talk to the agent, in the chat with yourself on WhatsApp. Nobody else can.</div>
              </div>
            </label>
          </div>
        ) : login?.state === "installing" ? (
          <div className="flex items-center gap-2 rounded-xl border border-ask-border bg-ask-soft px-3 py-2 text-[13.5px] text-ask-fg" data-testid="channel-whatsapp-installing">
            <Loader2 className="h-4 w-4 shrink-0 animate-spin" />
            Setting WhatsApp up on the agent. The first time takes a few minutes. The QR code appears when it is ready.
          </div>
        ) : login?.state === "qr" ? (
          <div className="flex flex-col items-center gap-3 text-center" data-testid="channel-whatsapp-qr-on-box">
            <div className="max-w-[46ch] text-[13px] text-ink-2">
              The QR code opens on your agent in a new tab, and only you can see it. Anyone who scans it links their WhatsApp to the agent, so scan it yourself: WhatsApp → Settings → Linked
              devices → Link a device.
            </div>
            <Button onClick={onShowCode} disabled={!onShowCode} data-testid="channel-whatsapp-show-code">
              <ExternalLink className="h-3.5 w-3.5" />
              Show QR code
            </Button>
          </div>
        ) : login?.state === "connected" ? (
          <div className="flex items-center gap-2 rounded-xl border border-allow-border bg-allow-soft px-3 py-2 text-[13.5px] text-allow-fg">
            <ShieldCheck className="h-4 w-4" /> {login.message || "Linked"}. {personal ? "Message yourself on WhatsApp to talk to the agent." : "Message the number, then approve yourself below."}
          </div>
        ) : (
          <div className="rounded-xl border border-block-border bg-block-soft px-3 py-2 text-[13.5px] text-block-fg">
            {login?.message || "Linking didn’t finish."} Press Start linking to get a new code.
          </div>
        )}
        <StatusLine state={state} />
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={state.busy}>
            {login?.state === "connected" ? "Done" : "Close"}
          </Button>
          {(!started || login?.state === "failed" || login?.state === "expired") && (
            <Button onClick={() => onStart(personal, vmId || undefined)} disabled={state.busy || needsAgent} data-testid="channel-whatsapp-start">
              {state.busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
              Start linking
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/**
 * What the code dialog needs of a change; channel and model changes both fit. `id` is only read when
 * the firewall sealed the code to the recovery key (T-99), to fetch that sealed challenge.
 */
export type CodeChange = Pick<AgentChannelChangeView, "summary" | "sentVia" | "expiresAt" | "attemptsLeft"> & { id?: string };

/**
 * Send the code. Return a promise that settles when the change is over for this dialog — landed and
 * on the page, or a long change started — and rejects when it did not go through (see
 * `CodeConfirmError`). Call `onApplying` once the code has been accepted. `useFirewallChange`'s
 * `confirm` is exactly this.
 */
export type CodeSubmit = (code: string, onApplying: () => void) => void | Promise<void>;

/** By value: a caller may build the change afresh on every render. */
function sameCodeChange(a: CodeChange, b: CodeChange | null): boolean {
  return !!b && a.id === b.id && a.summary === b.summary && a.sentVia === b.sentVia && a.expiresAt === b.expiresAt && a.attemptsLeft === b.attemptsLeft;
}

/**
 * The code step, shared by channels, model providers, agent updates and firewall updates. Who
 * sent the code and what the change costs differ per caller, so both are props: the firewall is
 * not an agent, and a firewall update takes the org's internet access down while it runs.
 *
 * From Confirm on it is busy and read-only, and it stays open until `onSubmit`'s promise settles —
 * even after the caller stops passing `change`, which happens as soon as the firewall answers. The
 * states are in `../lib/code-dialog.ts`.
 *
 * When no channel could deliver the code, the firewall says so with `sentVia: "recovery-key"` and
 * seals the answer to the organization's recovery key instead; the dialog then asks for that key
 * (`RecoveryKeyConfirm`) and sends the answer in the code's place. Same states, same Confirm.
 */
export function ConfirmCodeDialog({
  change,
  state,
  onSubmit,
  onCancel,
  sender = "Your agent",
  warning,
  initialPhase,
  initialCode = "",
  loadRecoveryChallenge,
  loadCodeTap: loadCodeTapProp,
}: {
  change: CodeChange | null;
  state: Busy;
  onSubmit: CodeSubmit;
  onCancel: () => void;
  /** Who the copy says sent the code. */
  sender?: string;
  /** Shown under the description: what confirming will cost. */
  warning?: React.ReactNode;
  /** Demo pages only: start in a given state. */
  initialPhase?: CodeDialogPhase;
  /** Demo pages only: the digits already typed. */
  initialCode?: string;
  /** Demo pages only: where the sealed challenge comes from instead of the firewall RPC. */
  loadRecoveryChallenge?: LoadRecoveryChallenge;
  /** Demo pages only: where the Telegram buttons' state comes from instead of the firewall RPC. */
  loadCodeTap?: LoadCodeTap;
}) {
  const api = useOptionalApi();
  // Without a loader or an app's API (the firewall's own pages) there are no buttons to read.
  const loadCodeTap: LoadCodeTap = loadCodeTapProp ?? (api ? (changeId) => api.firewall.codeTap({ changeId }) : async () => null);
  const [code, setCode] = useState(initialCode);
  const [answer, setAnswer] = useState<string | null>(null);
  const [left, setLeft] = useState("");
  const [phase, dispatch] = useReducer(codeDialogReducer, initialPhase ?? CODE_DIALOG_IDLE);
  // The last change the caller passed, shown while the dialog outlives it.
  const [held, setHeld] = useState(change);
  if (change && !sameCodeChange(change, held)) setHeld(change);
  const shown = change ?? (holdsOpen(phase) ? held : null);
  const open = !!shown;
  const byRecoveryKey = shown?.sentVia === RECOVERY_SENT_VIA;
  const busy = isBusy(phase);
  const final = phase.kind === "failed" && phase.final;
  // Approve with a button (docs/plans/channel-approval-buttons.md): a code sent to Telegram comes
  // with number buttons, and the firewall reports which number this dialog shows. Once the right
  // one is tapped it reports the change's code too, and the dialog sends it like a typed one.
  const tapId = !byRecoveryKey && shown?.id && shown.sentVia?.startsWith("telegram:") ? shown.id : null;
  // Keyed by change, so a number read for one change is never shown over the next one.
  const [tapRead, setTapRead] = useState<{ id: string; view: CodeTapView | null } | null>(null);
  const tap = tapRead && tapRead.id === tapId ? tapRead.view : null;
  const tapHandled = useRef<string | null>(null);
  const loadTap = useRef(loadCodeTap);
  loadTap.current = loadCodeTap;
  useEffect(() => {
    if (open) return;
    setCode("");
    setTapRead(null);
    tapHandled.current = null;
    dispatch({ type: "reset" });
  }, [open]);
  useEffect(() => {
    if (!open || !tapId) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    // Only while the firewall says this change went out with buttons. It reports that on the same
    // beat as the change itself, so a change it has not reported after a few reads had none (a
    // module without buttons, or Telegram refused them), and one it stopped reporting is over.
    let seen = false;
    let misses = 0;
    const poll = async () => {
      try {
        const t = await loadTap.current(tapId);
        if (stopped) return;
        setTapRead({ id: tapId, view: t });
        if (!t) {
          if (seen || ++misses >= CODE_TAP_FIRST_READS) return;
        } else {
          seen = true;
          // Nothing more can happen to an offer once it is decided.
          if (t.state !== "open") return;
        }
      } catch (error) {
        console.error("codeTap failed", error);
      }
      if (!stopped) timer = setTimeout(() => void poll(), CODE_TAP_POLL_MS);
    };
    void poll();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
  }, [open, tapId]);
  useEffect(() => {
    if (!shown?.expiresAt) return;
    const tick = () => {
      const ms = new Date(shown.expiresAt!).getTime() - Date.now();
      setLeft(ms <= 0 ? "expired" : `${Math.floor(ms / 60000)}:${String(Math.floor((ms % 60000) / 1000)).padStart(2, "0")}`);
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [shown?.expiresAt]);
  const value = byRecoveryKey ? answer : code.length === CODE_LENGTH ? code : null;
  const submit = async (given: string | null = value) => {
    if (!canSubmit(phase) || !given) return;
    dispatch({ type: "submit" });
    try {
      await onSubmit(given, () => dispatch({ type: "progress", step: "applying" }));
      dispatch({ type: "done" });
    } catch (error) {
      dispatch({ type: "failed", ...failureOf(error) });
      setCode("");
    }
  };
  // Each tap outcome is acted on once per change: the poll may report it again before it stops.
  useEffect(() => {
    if (!tap || !tapId || tapHandled.current === `${tapId}:${tap.state}`) return;
    if (tap.state === "approved" && tap.code && canSubmit(phase)) {
      tapHandled.current = `${tapId}:${tap.state}`;
      setCode(tap.code);
      void submit(tap.code);
    } else if (tap.state === "cancelled" && !busy) {
      tapHandled.current = `${tapId}:${tap.state}`;
      onCancel();
    }
    // `submit` and `onCancel` are new functions on every render; what decides is the tap and the phase.
  }, [tap, tapId, phase, busy]); // eslint-disable-line react-hooks/exhaustive-deps
  // A final failure keeps the dialog open on its own phase (`holdsOpen`), after the caller has
  // already dropped the change. Closing it must end that phase too, or Close does nothing.
  const close = () => {
    if (final) dispatch({ type: "reset" });
    onCancel();
  };
  const tapApproved = tap?.state === "approved";
  const via = shown?.sentVia ? shown.sentVia.replace(/^(\w+):/, (_, t: string) => `${t[0].toUpperCase()}${t.slice(1)} (`) + ")" : "your connected channel";
  const locked = busy || final || state.busy;
  const line = tapApproved && phase.kind === "confirming" ? "Approved in Telegram. Applying the change…" : busyLine(phase);
  return (
    <Dialog open={open} onOpenChange={(o) => !o && !busy && !state.busy && close()}>
      <DialogContent className="sm:max-w-[460px]" data-testid="channel-dialog-code" data-phase={phase.kind} aria-busy={busy}>
        {byRecoveryKey ? (
          <DialogHeader>
            <DialogTitle>Confirm with your recovery key</DialogTitle>
            <DialogDescription>
              None of your agents could send the code for <span className="text-ink">{shown?.summary}</span>, so your firewall locked it with your
              recovery key instead. Open it with the key to confirm the change. Once a channel works again, you’ll get a message that the key was used.
            </DialogDescription>
          </DialogHeader>
        ) : (
          <DialogHeader>
            <DialogTitle>Enter the confirmation code</DialogTitle>
            {tap ? (
              <DialogDescription>
                Your firewall sent a message to {via}. It says what it confirms: <span className="text-ink">{shown?.summary}</span>. If it says something
                else, tap Cancel there.
              </DialogDescription>
            ) : (
              <DialogDescription>
                {sender} sent a 6-digit code to {via}. The message says what it confirms: <span className="text-ink">{shown?.summary}</span>. If the message
                says something else, don’t enter the code.
              </DialogDescription>
            )}
          </DialogHeader>
        )}
        {tap && tap.state !== "refused" && !final ? (
          <div className="rounded-[12px] border border-line bg-bg-2 px-4 py-3 text-center" data-testid="channel-code-number" data-state={tap.state}>
            <div className="text-[12.5px] text-ink-2">{tapApproved ? "Approved in Telegram" : "In Telegram, tap"}</div>
            <div className="font-mono text-[34px] font-semibold leading-tight tracking-[0.08em] text-ink tabular-nums">{tap.number}</div>
            <div className="text-[12px] text-ink-2">{tapApproved ? "Applying the change." : "or type the 6-digit code from the message below."}</div>
          </div>
        ) : null}
        {tap?.state === "refused" && !final ? (
          <div className="rounded-xl border border-ask-border bg-ask-soft px-3 py-2 text-[12.5px] text-ask-fg" data-testid="channel-code-refused">
            The number tapped in Telegram didn’t match this one, so the buttons are off. Type the code from the message instead.
          </div>
        ) : null}
        {warning ? (
          <div className="rounded-[10px] border border-ask-border bg-ask-soft px-3.5 py-2.5 text-[12.5px] text-ask-fg" data-testid="channel-code-warning">
            {warning}
          </div>
        ) : null}
        {byRecoveryKey ? <RecoveryKeyConfirm key={shown?.id ?? "none"} changeId={shown?.id ?? null} locked={locked} onAnswer={setAnswer} load={loadRecoveryChallenge} /> : null}
        <form
          className="flex flex-col items-center gap-3 py-2"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          {byRecoveryKey ? null : (
          <InputOTP
            maxLength={CODE_LENGTH}
            value={code}
            onChange={(v) => setCode(extractCode(v))}
            pasteTransformer={extractCode}
            onPaste={(e) => {
              // A whole code replaces what was there, wherever the caret was.
              const pasted = extractCode(e.clipboardData.getData("text/plain"));
              if (pasted.length === CODE_LENGTH) setCode(pasted);
            }}
            disabled={locked}
            data-testid="channel-code-input"
            containerClassName="justify-center"
          >
            <InputOTPGroup>
              <InputOTPSlot index={0} />
              <InputOTPSlot index={1} />
              <InputOTPSlot index={2} />
            </InputOTPGroup>
            <InputOTPSeparator />
            <InputOTPGroup>
              <InputOTPSlot index={3} />
              <InputOTPSlot index={4} />
              <InputOTPSlot index={5} />
            </InputOTPGroup>
          </InputOTP>
          )}
          <div className="flex items-center gap-1.5 text-[12.5px] text-ink-2" data-testid="channel-code-line">
            {line ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                {line}
              </>
            ) : final ? null : (
              <>
                {left === "expired" ? "The code expired. Cancel and start the change again." : left ? `Expires in ${left}` : ""}
                {typeof shown?.attemptsLeft === "number" && shown.attemptsLeft < 5 ? ` · ${shown.attemptsLeft} ${shown.attemptsLeft === 1 ? "try" : "tries"} left` : ""}
              </>
            )}
          </div>
        </form>
        {phase.kind === "failed" ? (
          <div className="rounded-xl border border-block-border bg-block-soft px-3 py-2 text-[13px] text-block-fg" role="alert" data-testid="channel-dialog-error">
            {phase.message}
          </div>
        ) : busy ? null : (
          <StatusLine state={state} />
        )}
        <DialogFooter sticky>
          <Button variant="outline" onClick={close} disabled={busy || state.busy} data-testid="channel-code-cancel">
            {final ? "Close" : "Cancel change"}
          </Button>
          {final ? null : (
            <Button onClick={() => void submit()} disabled={!value || locked || left === "expired"} data-testid="channel-code-submit">
              {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
              {submitLabel(phase)}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/**
 * The token check a connect dialog runs before it hands the token on. `run` resolves to the lookup,
 * or to null when the service refused the token (the error then shows in the dialog).
 */
function useTokenLookup(open: boolean) {
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!open) setError(null);
  }, [open]);
  const run = async <T,>(look: () => Promise<TokenLookup<T>>, refused: string): Promise<TokenLookup<T> | null> => {
    setError(null);
    setChecking(true);
    try {
      const r = await look();
      if (r.kind === "invalid") {
        setError(refused);
        return null;
      }
      return r;
    } finally {
      setChecking(false);
    }
  };
  /** The dialog's status line: the panel's state, or this check's. */
  const merge = (state: Busy): Busy =>
    checking ? { busy: true, error: null, note: "Checking the token…" } : error && !state.error && !state.busy ? { ...state, error } : state;
  return { checking, run, merge };
}

function TokenNote() {
  return (
    <div className="flex gap-2 rounded-xl border border-line bg-bg-2 px-3 py-2 text-[12.5px] text-ink-2">
      <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <span>Your firewall encrypts the token and gives it to the agent. ControlClaw keeps only the last four characters.</span>
    </div>
  );
}

function StatusLine({ state }: { state: Busy }) {
  if (state.error) {
    return (
      <div className="rounded-xl border border-block-border bg-block-soft px-3 py-2 text-[13px] text-block-fg" data-testid="channel-dialog-error">
        {state.error}
      </div>
    );
  }
  if (state.note) {
    return (
      <div className="flex items-center gap-2 text-[13px] text-ink-2" data-testid="channel-dialog-note">
        {state.busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
        {state.note}
      </div>
    );
  }
  return null;
}
