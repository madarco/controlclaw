"use client";

import { useState } from "react";
import { AppLink as Link } from "../../lib/link";
import { History, ScanSearch, ShieldCheck, Sparkles } from "lucide-react";
import { toast } from "sonner";
import { Button } from "../../ui/button";
import { Checkbox } from "../../ui/checkbox";
import { Input } from "../../ui/input";
import { Textarea } from "../../ui/textarea";
import { Switch } from "../../ui/switch";
import { useApi } from "../../lib/api";
import { openInNewTab } from "../../lib/open-in-new-tab";
import { RelativeTime } from "../../kit/RelativeTime";
import {
  Disclosure,
  Field,
  FieldGrid,
  Hint,
  Sec,
  Select,
  Stack,
  StatusLine,
} from "../../kit/console-ui";
import { AI_INSTRUCTIONS_MAX, type EgressAiView, type LogReviewNotify, type LogReviewSeverity } from "../../lib/egress-ai-schema";
import { countLabel } from "../../lib/format";
import { useRoutes } from "../../lib/routes";

type Settings = EgressAiView["settings"];

const NOTIFY_LABEL: Record<LogReviewNotify, string> = {
  admins: "Owners and admins",
  members: "Specific people",
  nobody: "Nobody, Activity only",
};
/** Low findings are never emailed, so Notify from starts at medium. */
const SEVERITY_LABEL: Partial<Record<LogReviewSeverity, string>> = {
  medium: "Medium and high",
  high: "High only",
};

function errorMessage(err: unknown, fallback: string): string {
  const m = (err as { message?: string })?.message;
  return m && !m.startsWith("Internal") ? m : fallback;
}

/**
 * The firewall's two AIs (docs/features/ai-firewall-review.md, docs/plans/ai-log-review-split.md):
 * the **AI Firewall**, which checks requests on website rules marked AI review as they happen, and
 * **AI Log Review**, which reads the traffic afterwards and reports findings. They share one key,
 * model and daily limit, which are edited in one place per page:
 *
 * - `firewall` (the Firewall page's Settings tab): AI Log Review, with the shared fields.
 * - `security` (the Settings tab of Security rules): the AI Firewall with the shared fields, then AI Log
 *   Review without them.
 *
 * One state for both sections, so a save in one shows in the other.
 */
export function EgressAiSections({ initial, page }: { initial: EgressAiView; page: "firewall" | "security" }) {
  const ai = useEgressAi(initial);
  if (page === "firewall") return <AiLogReviewSection ai={ai} showModel />;
  return (
    <>
      <AiFirewallSection ai={ai} />
      <AiLogReviewSection ai={ai} showModel={false} />
    </>
  );
}

type EgressAi = ReturnType<typeof useEgressAi>;

function useEgressAi(initial: EgressAiView) {
  const api = useApi();
  const [view, setView] = useState(initial);
  const [draft, setDraft] = useState(initial.settings);
  const [saving, setSaving] = useState(false);

  const noKey = view.credentials.length === 0;
  const canAct = view.canManage && view.hasFirewall;
  const credential = view.credentials.find((c) => c.id === draft.credentialId) ?? null;

  /** Save every setting in `next`; with `only`, the draft's other fields keep their unsaved edits. */
  async function save(next: Settings, done: string, only?: Array<keyof Settings>) {
    setSaving(true);
    try {
      const v = await api.egress.updateEgressAiSettings(next);
      setView(v);
      setDraft((d) => (only ? { ...d, ...Object.fromEntries(only.map((k) => [k, v.settings[k]])) } : v.settings));
      toast.success(done);
      return true;
    } catch (err) {
      toast.error(errorMessage(err, "Couldn’t save the AI settings. Try again."));
      return false;
    } finally {
      setSaving(false);
    }
  }

  /** A switch saves only itself, on top of what is saved: edits elsewhere stay unsaved. */
  function toggle(key: "enabled" | "logReviewEnabled", on: boolean, label: string) {
    setDraft((d) => ({ ...d, [key]: on }));
    void save({ ...view.settings, [key]: on }, on ? `${label} is on. The firewall applies it within a minute.` : `${label} is off`, [key]).then((ok) => {
      if (!ok) setDraft((d) => ({ ...d, [key]: view.settings[key] }));
    });
  }

  // Only the texts, through their own RPC: saving words must never write a switch (a settings row
  // is the owner's answer to "should the AI run", `ensureAiReviewDefault`).
  async function saveInstructions(key: "requestInstructions" | "reviewInstructions") {
    setSaving(true);
    try {
      const v = await api.egress.updateEgressAiInstructions({ [key]: draft[key] });
      setView(v);
      setDraft((d) => ({ ...d, [key]: v.settings[key] }));
      toast.success("Instructions saved. The firewall applies them within a minute.");
    } catch (err) {
      toast.error(errorMessage(err, "Couldn’t save the instructions. Try again."));
    } finally {
      setSaving(false);
    }
  }

  function pickCredential(id: string) {
    const c = view.credentials.find((x) => x.id === id);
    setDraft((d) => ({ ...d, credentialId: id || null, model: c ? c.defaultModel : d.model }));
  }

  return { view, setView, draft, setDraft, saving, noKey, canAct, credential, save, toggle, saveInstructions, pickCredential };
}

/** Whether the fields in `keys` differ from what is saved. */
function changed(ai: EgressAi, keys: Array<keyof Settings>): boolean {
  return keys.some((k) => JSON.stringify(ai.draft[k]) !== JSON.stringify(ai.view.settings[k]));
}

const MODEL_KEYS: Array<keyof Settings> = ["credentialId", "model", "dailyCallCap"];

/** No firewall, or no key: the one line either section shows instead of its body. */
function Unavailable({ ai }: { ai: EgressAi }) {
  const routes = useRoutes();
  if (!ai.view.hasFirewall) return <StatusLine>This organization has no firewall yet.</StatusLine>;
  return (
    <StatusLine tone="warn" data-testid="egress-ai-no-key">
      Add a key in{" "}
      <Link href={routes.aiKeys} className="font-medium text-brand hover:underline">
        {ai.view.local ? "Settings" : "AI models"}
      </Link>{" "}
      {ai.view.local ? "(your own Google, Anthropic, OpenAI or Vercel AI Gateway key)" : "(the included tokens, or your own Google, Anthropic or OpenAI key)"} so the firewall’s AI can run.
    </StatusLine>
  );
}

/** The key, the model and the daily limit, which both AIs share. */
function ModelFields({ ai }: { ai: EgressAi }) {
  const { view, draft, setDraft, canAct, credential, pickCredential } = ai;
  return (
    <>
      <Field label="Model key">
        <Select value={draft.credentialId ?? ""} onChange={(e) => pickCredential(e.target.value)} disabled={!canAct} data-testid="egress-ai-credential">
          {view.credentials.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
              {c.hint ? ` · ${c.hint}` : ""}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="Model">
        <Input
          value={draft.model}
          onChange={(e) => setDraft((d) => ({ ...d, model: e.target.value }))}
          placeholder={credential?.defaultModel}
          disabled={!canAct}
          data-testid="egress-ai-model"
        />
      </Field>
      <Field label="Model calls a day">
        <Input
          type="number"
          min={100}
          max={100000}
          value={draft.dailyCallCap}
          onChange={(e) => setDraft((d) => ({ ...d, dailyCallCap: Number(e.target.value) }))}
          disabled={!canAct}
          data-testid="egress-ai-cap"
        />
      </Field>
    </>
  );
}

/**
 * The AI Firewall: the check before a request on a website rule marked AI review leaves, AI approval
 * on Ask rules with a policy, and the model the Messages rules judge their sentences with.
 */
export function AiFirewallSection({ ai }: { ai: EgressAi }) {
  const { view, draft, setDraft, saving, noKey, canAct, credential } = ai;
  const keys: Array<keyof Settings> = [...MODEL_KEYS, "autoApprovePerHour"];
  return (
    <Sec
      id="ai-firewall"
      icon={ShieldCheck}
      title="AI Firewall"
      data-testid="ai-firewall"
      sub={
        <>
          Checks each request on a Websites rule marked <b className="font-medium text-ink">AI review</b> before it leaves, and
          can block it or hold it for you. On Ask rules with a policy it can approve on your behalf. Your Messages rules use the
          same model to judge their sentences.
        </>
      }
      right={
        <Switch
          checked={draft.enabled}
          disabled={!canAct || saving || noKey}
          onCheckedChange={(on) => ai.toggle("enabled", on, "The AI Firewall")}
          aria-label="AI Firewall"
          data-testid="ai-firewall-toggle"
        />
      }
    >
      {!view.hasFirewall || noKey ? (
        <Unavailable ai={ai} />
      ) : (
        <>
          <StatusLine tone={view.settings.enabled ? "ok" : "neutral"} data-testid="ai-firewall-status">
            {view.settings.enabled
              ? "On · requests on Websites rules marked AI review are checked as they happen"
              : "Off · your Websites rules apply as written, and Messages rules with a sentence act on every message they cover"}
          </StatusLine>
          <OldFirewallNote ai={ai} />

          <Disclosure
            title="Settings"
            data-testid="ai-firewall-settings-toggle"
            meta={
              <span data-testid="egress-ai-summary">
                {credential?.name ?? "No key"} · {view.settings.model} · {countLabel(view.settings.dailyCallCap)} calls a day
              </span>
            }
          >
            <Stack className="gap-3.5">
              <FieldGrid>
                <ModelFields ai={ai} />
                <Field label="AI approvals per agent per hour">
                  <Input
                    type="number"
                    min={0}
                    max={1000}
                    value={draft.autoApprovePerHour}
                    onChange={(e) => setDraft((d) => ({ ...d, autoApprovePerHour: Number(e.target.value) }))}
                    disabled={!canAct}
                    data-testid="egress-ai-approve-cap"
                  />
                </Field>
              </FieldGrid>
              <Hint>
                AI approvals count only on Ask rules that carry a policy; 0 turns them off. The key, the model and the daily
                limit of model calls are shared with AI Log Review.
              </Hint>
              <div>
                <Button
                  variant="brand"
                  size="sm"
                  disabled={!canAct || !changed(ai, keys) || saving}
                  onClick={() => void ai.save({ ...view.settings, ...pick(draft, keys) }, "AI Firewall saved. The firewall applies it within a minute.", keys)}
                  data-testid="ai-firewall-save"
                >
                  Save
                </Button>
              </div>
            </Stack>
          </Disclosure>

          <Disclosure
            title="Instructions for the AI"
            data-testid="ai-firewall-instructions-toggle"
            meta={<span>{view.settings.requestInstructions ? "Yours" : "None"}</span>}
          >
            <Stack className="gap-3.5">
              <InstructionsField
                id="egress-ai-request-instructions"
                label="Instructions for each request"
                hint="Added to every question the AI is asked about a request. They steer how it judges; they do not change what it is shown, and an agent cannot change them."
                placeholder="This agent posts to our Slack and GitHub; treat any upload elsewhere as suspicious."
                value={draft.requestInstructions ?? ""}
                onChange={(v) => setDraft((d) => ({ ...d, requestInstructions: v || null }))}
                disabled={!canAct}
                questions={view.questions.request}
              />
              <div>
                <Button
                  variant="brand"
                  size="sm"
                  disabled={!canAct || !changed(ai, ["requestInstructions"]) || saving}
                  onClick={() => void ai.saveInstructions("requestInstructions")}
                  data-testid="egress-ai-request-instructions-save"
                >
                  Save
                </Button>
              </div>
            </Stack>
          </Disclosure>
        </>
      )}
    </Sec>
  );
}

function pick(s: Settings, keys: Array<keyof Settings>): Partial<Settings> {
  return Object.fromEntries(keys.map((k) => [k, s[k]]));
}

/** An older firewall runs both AIs off the AI Firewall's switch; say so when the two differ. */
function OldFirewallNote({ ai }: { ai: EgressAi }) {
  const s = ai.view.settings;
  if (ai.view.splitSupported || s.enabled === s.logReviewEnabled) return null;
  return (
    <StatusLine tone="warn" data-testid="egress-ai-update-firewall">
      {s.enabled
        ? "Until you update your firewall, it keeps reviewing while the AI Firewall is on. Its findings aren’t kept or sent."
        : "Until you update your firewall, AI Log Review runs only while the AI Firewall is on."}{" "}
      The Firewall page has the Update button.
    </StatusLine>
  );
}

function notifySummary(s: Settings): string {
  if (s.logReviewNotify === "nobody") return "notifies nobody";
  const who = s.logReviewNotify === "admins" ? "owners and admins" : `${s.logReviewNotifyUserIds.length} ${s.logReviewNotifyUserIds.length === 1 ? "person" : "people"}`;
  return `notifies ${who} from ${s.logReviewNotifyMinSeverity}`;
}

/** AI Log Review: the review every minute and the scan, with who is told about findings. */
export function AiLogReviewSection({ ai, showModel }: { ai: EgressAi; showModel: boolean }) {
  const api = useApi();
  const routes = useRoutes();
  const { view, draft, setDraft, saving, noKey, canAct, credential } = ai;
  const [scanning, setScanning] = useState(false);
  const [historyAgent, setHistoryAgent] = useState(view.agents[0]?.id ?? "");
  const [opening, setOpening] = useState(false);
  const keys: Array<keyof Settings> = [
    "scanIntervalHours",
    "logReviewNotify",
    "logReviewNotifyUserIds",
    "logReviewNotifyMinSeverity",
    ...(showModel ? MODEL_KEYS : []),
  ];

  async function scanNow() {
    setScanning(true);
    try {
      await api.egress.scanEgressNow();
      toast.success("Scan requested. Findings appear in Activity.");
      ai.setView(await api.egress.getEgressAiSettings());
    } catch (err) {
      toast.error(errorMessage(err, "Couldn’t start a scan. Try again."));
    } finally {
      setScanning(false);
    }
  }

  async function openHistory() {
    if (!historyAgent) return;
    setOpening(true);
    await openInNewTab(() => api.egress.openAiReviewHistory({ vmId: historyAgent }), "Couldn’t open the review history. Try again.");
    setOpening(false);
  }

  function togglePerson(userId: string, on: boolean) {
    setDraft((d) => ({
      ...d,
      logReviewNotifyUserIds: on ? [...new Set([...d.logReviewNotifyUserIds, userId])] : d.logReviewNotifyUserIds.filter((id) => id !== userId),
    }));
  }

  return (
    <Sec
      id="ai-review"
      icon={Sparkles}
      title="AI Log Review"
      data-testid="egress-ai"
      sub="Reviews your traffic and agents’ activities periodically, and reports any anomaly"
      right={
        <Switch
          checked={draft.logReviewEnabled}
          disabled={!canAct || saving || noKey}
          onCheckedChange={(on) => ai.toggle("logReviewEnabled", on, "AI Log Review")}
          aria-label="AI Log Review"
          data-testid="egress-ai-toggle"
        />
      }
    >
      {!view.hasFirewall || noKey ? (
        <Unavailable ai={ai} />
      ) : (
        <>
          <StatusLine tone={view.settings.logReviewEnabled ? "ok" : "neutral"} data-testid="egress-ai-status">
            {view.settings.logReviewEnabled
              ? `On · full scan every ${view.settings.scanIntervalHours}h${view.local ? "" : ` · ${notifySummary(view.settings)}`}`
              : "Off · nothing reviews your agents' traffic after the fact"}
          </StatusLine>
          {showModel ? <OldFirewallNote ai={ai} /> : null}

          <Disclosure
            title="Settings"
            data-testid="egress-ai-settings-toggle"
            meta={
              <span data-testid="egress-ai-log-summary">
                {showModel ? `${credential?.name ?? "No key"} · ${view.settings.model} · ` : ""}every {view.settings.scanIntervalHours}h
                {view.local ? "" : ` · ${NOTIFY_LABEL[view.settings.logReviewNotify].toLowerCase()}`}
              </span>
            }
          >
            <Stack className="gap-3.5">
              <FieldGrid>
                {view.local ? null : (
                  <>
                    <Field label="Notify">
                      <Select
                        value={draft.logReviewNotify}
                        onChange={(e) => setDraft((d) => ({ ...d, logReviewNotify: e.target.value as LogReviewNotify }))}
                        disabled={!canAct}
                        data-testid="egress-ai-notify"
                      >
                        {(Object.keys(NOTIFY_LABEL) as LogReviewNotify[]).map((k) => (
                          <option key={k} value={k}>
                            {NOTIFY_LABEL[k]}
                          </option>
                        ))}
                      </Select>
                    </Field>
                    <Field label="Notify from">
                      <Select
                        value={draft.logReviewNotifyMinSeverity}
                        onChange={(e) => setDraft((d) => ({ ...d, logReviewNotifyMinSeverity: e.target.value as LogReviewSeverity }))}
                        disabled={!canAct || draft.logReviewNotify === "nobody"}
                        data-testid="egress-ai-notify-from"
                      >
                        {(Object.keys(SEVERITY_LABEL) as LogReviewSeverity[]).map((k) => (
                          <option key={k} value={k}>
                            {SEVERITY_LABEL[k]}
                          </option>
                        ))}
                      </Select>
                    </Field>
                    {draft.logReviewNotify === "members" ? (
                      <div className="grid gap-1.5 sm:col-span-2" data-testid="egress-ai-notify-people">
                        <span className="text-[12.5px] font-medium text-ink-2">People to notify</span>
                        {view.members.length === 0 ? (
                          <Hint>
                            {draft.logReviewNotifyUserIds.length} {draft.logReviewNotifyUserIds.length === 1 ? "person" : "people"}. Owners and admins pick who.
                          </Hint>
                        ) : (
                          <div className="grid max-h-56 gap-1 overflow-auto rounded-lg border border-line p-2">
                            {view.members.map((m) => (
                              <label key={m.userId} className="flex min-w-0 items-center gap-2.5 rounded-md px-1.5 py-1 text-[13px] hover:bg-bg">
                                <Checkbox
                                  checked={draft.logReviewNotifyUserIds.includes(m.userId)}
                                  onCheckedChange={(on) => togglePerson(m.userId, on === true)}
                                  disabled={!canAct}
                                  aria-label={m.name}
                                />
                                <span className="flex min-w-0 flex-col sm:flex-row sm:gap-2.5">
                                  <span className="truncate text-ink">{m.name}</span>
                                  {m.email !== m.name ? <span className="truncate text-ink-2">{m.email}</span> : null}
                                </span>
                                <span className="ml-auto shrink-0 text-[11.5px] text-ink-2 capitalize">{m.role}</span>
                              </label>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : null}
                  </>
                )}
                <Field label="Full scan every (hours)">
                  <Input
                    type="number"
                    min={1}
                    max={168}
                    value={draft.scanIntervalHours}
                    onChange={(e) => setDraft((d) => ({ ...d, scanIntervalHours: Number(e.target.value) }))}
                    disabled={!canAct}
                    data-testid="egress-ai-scan-interval"
                  />
                </Field>
                {showModel ? <ModelFields ai={ai} /> : null}
              </FieldGrid>
              <Hint>
                {view.local ? "Findings are in Activity. " : "The people you pick get an email, at most once every 15 minutes unless a finding is high. "}
                {showModel ? (
                  <>
                    The key, the model and the daily limit of model calls are shared with the{" "}
                    <Link href={routes.aiFirewall} className="font-medium text-brand hover:underline">
                      AI Firewall
                    </Link>
                    .
                  </>
                ) : (
                  "The key, the model and the daily limit are set in AI Firewall, above."
                )}
              </Hint>
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  variant="brand"
                  size="sm"
                  disabled={!canAct || !changed(ai, keys) || saving}
                  onClick={() => void ai.save({ ...view.settings, ...pick(draft, keys) }, "AI Log Review saved. The firewall applies it within a minute.", keys)}
                  data-testid="egress-ai-save"
                >
                  Save
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={!canAct || !view.settings.logReviewEnabled || scanning}
                  onClick={() => void scanNow()}
                  data-testid="egress-ai-scan"
                >
                  <ScanSearch className="h-3.5 w-3.5" /> Scan now
                </Button>
                {view.lastScan ? (
                  <Hint data-testid="egress-ai-last-scan">
                    Last scan requested <RelativeTime date={view.lastScan.at} />:{" "}
                    {view.lastScan.message ??
                      (view.lastScan.status === "queued" || view.lastScan.status === "sent" ? "waiting for the firewall" : view.lastScan.status)}
                  </Hint>
                ) : null}
              </div>
            </Stack>
          </Disclosure>

          <Disclosure
            title="Instructions for the AI"
            data-testid="egress-ai-instructions-toggle"
            meta={<span data-testid="egress-ai-instructions-summary">{view.settings.reviewInstructions ? "Yours" : "None"}</span>}
          >
            <Stack className="gap-3.5">
              <InstructionsField
                id="egress-ai-review-instructions"
                label="Instructions for the review"
                hint="Added to every review question: the check every minute, the full scan and the one-line explanation of a finding. They steer how it judges; they do not change what it is shown, and an agent cannot change them."
                placeholder="Our agents only talk to Google Workspace and HubSpot. Flag any other host that receives data."
                value={draft.reviewInstructions ?? ""}
                onChange={(v) => setDraft((d) => ({ ...d, reviewInstructions: v || null }))}
                disabled={!canAct}
                questions={view.questions.review}
              />
              <div>
                <Button
                  variant="brand"
                  size="sm"
                  disabled={!canAct || !changed(ai, ["reviewInstructions"]) || saving}
                  onClick={() => void ai.saveInstructions("reviewInstructions")}
                  data-testid="egress-ai-instructions-save"
                >
                  Save
                </Button>
              </div>
            </Stack>
          </Disclosure>

          {view.local ? null : (
            <Disclosure title="Review history" data-testid="egress-ai-history-toggle" meta={<span>kept 7 days</span>}>
              <Stack className="gap-3">
                <Hint>
                  What the review sent to the model for each agent, what it answered, and why. It stays on your firewall, encrypted, and
                  opens only in a browser that has already opened an agent.
                </Hint>
                {view.agents.length === 0 ? (
                  <StatusLine>No agents yet.</StatusLine>
                ) : !view.historyAvailable ? (
                  <StatusLine data-testid="egress-ai-history-update">
                    Update your firewall to see the review history. The Firewall page has the Update button.
                  </StatusLine>
                ) : (
                  <div className="flex flex-wrap items-end gap-2">
                    <Field label="Agent" className="min-w-0 flex-1 sm:max-w-[280px]">
                      <Select value={historyAgent} onChange={(e) => setHistoryAgent(e.target.value)} data-testid="egress-ai-history-agent">
                        {view.agents.map((a) => (
                          <option key={a.id} value={a.id}>
                            {a.name}
                          </option>
                        ))}
                      </Select>
                    </Field>
                    <Button size="sm" variant="outline" disabled={!historyAgent || opening} onClick={() => void openHistory()} data-testid="egress-ai-history-open">
                      <History className="h-3.5 w-3.5" /> Open review history
                    </Button>
                  </div>
                )}
              </Stack>
            </Disclosure>
          )}
        </>
      )}
    </Sec>
  );
}

/** One instructions box: a counter under it, and the fixed questions it is added to, read-only. */
function InstructionsField({
  id,
  label,
  hint,
  placeholder,
  value,
  onChange,
  disabled,
  questions,
}: {
  id: string;
  label: string;
  hint: string;
  placeholder: string;
  value: string;
  onChange: (value: string) => void;
  disabled: boolean;
  questions: string;
}) {
  return (
    <div className="grid gap-1.5">
      <label htmlFor={id} className="text-[12.5px] font-medium text-ink-2">
        {label}
      </label>
      <Textarea
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        maxLength={AI_INSTRUCTIONS_MAX}
        rows={3}
        disabled={disabled}
        data-testid={id}
      />
      <div className="flex flex-wrap justify-between gap-2 text-[12px] text-ink-2">
        <span className="max-w-[60ch]">{hint}</span>
        <span data-testid={`${id}-count`}>
          {value.length} / {AI_INSTRUCTIONS_MAX}
        </span>
      </div>
      {questions ? (
        <Disclosure flat title={<span className="text-[12.5px] font-medium">What the AI is asked</span>}>
          <pre className="max-h-64 overflow-auto rounded-lg border border-line bg-bg p-3 font-mono text-[11.5px] leading-relaxed whitespace-pre-wrap text-ink-2">
            {questions}
          </pre>
        </Disclosure>
      ) : null}
    </div>
  );
}
