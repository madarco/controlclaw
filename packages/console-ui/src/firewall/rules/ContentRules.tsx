"use client";

import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Trash2 } from "lucide-react";
import { useRulesOptions } from "./rules-context";
import { Button } from "../../ui/button";
import { Checkbox } from "../../ui/checkbox";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Textarea } from "../../ui/textarea";
import { RadioGroup, RadioGroupItem } from "../../ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../../ui/select";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "../../ui/dialog";
import { useApi } from "../../lib/api";
import { cn } from "../../lib/utils";
import { CONTENT_IN_ONLY, CONTENT_OUT_ONLY } from "@controlclaw/console-ui/lib/agent/content-rules-schema";
import {
  CONTENT_CHANNELS,
  CONTENT_DETECTORS,
  CONTENT_POLICY_MAX,
  contentRule,
  type ContentChange,
  type ContentChannel,
  type ContentRule,
  type ContentRulesSnapshot,
  type ContentTryResult,
} from "../../lib/content-rules-schema";
import { ACTION_LABELS, CHANNEL_LABELS, CONTENT_TEMPLATES, DETECTOR_LABELS, DIRECTION_LABELS, contentRuleId } from "../../lib/content-rules-words";
import { useRulesChange, type RulesPending } from "./useRulesChange";
import { useRoutes } from "../../lib/routes";

/**
 * The Messages rules (content rules) on Security rules (docs/features/content-rules.md): reading
 * them, the editor, "Try a message" and the notices. The rules live on the firewall: this reads
 * them with `rules.read`, and every change, turning a rule off included, is held by the firewall
 * until the person types the code it sent. A rule is a sentence first (its policy, judged by the AI
 * on the firewall), with words and detectors as extras. "Try a message" is run by the firewall,
 * which holds the AI's key: nothing about the message is kept. The rows themselves are drawn by
 * `SecurityRulesView`.
 */

type Draft = Omit<ContentRule, "patterns" | "policy"> & { words: string; policy: string };

const FIELD_LABELS: Record<string, string> = {
  name: "Name",
  policy: "The rule",
  patterns: "Words",
  reason: "Reason",
  channels: "Channels",
  detectors: "Also match exactly",
};

/** The first thing the firewall would refuse, in words. */
function draftProblem(rule: unknown): string | null {
  const parsed = contentRule.safeParse(rule);
  if (parsed.success) return null;
  const issue = parsed.error.issues[0]!;
  const field = FIELD_LABELS[String(issue.path[0] ?? "")];
  if (issue.code === "too_small" && field) return `${field}: fill this in.`;
  if (issue.code === "too_big" && field) return `${field}: this is too long.`;
  return field ? `${field}: ${issue.message}.` : `${issue.message[0]!.toUpperCase()}${issue.message.slice(1)}.`;
}

function toDraft(rule: ContentRule): Draft {
  const { patterns, policy, ...rest } = rule;
  return { ...rest, policy: policy ?? "", words: patterns.join("\n") };
}

function fromDraft(draft: Draft): ContentRule {
  const { words, policy, ...rest } = draft;
  const sentence = policy.trim().replace(/\s+/g, " ");
  return {
    ...rest,
    name: rest.name.trim(),
    ...(sentence ? { policy: sentence } : {}),
    reason: rest.reason.trim(),
    patterns: [...new Set(words.split("\n").map((w) => w.trim().replace(/\s+/g, " ")).filter(Boolean))],
  };
}

function RuleEditor({
  initial,
  isNew,
  disabled,
  names,
  tryDemo,
  onSave,
  onCancel,
  onDelete,
}: {
  initial: ContentRule;
  isNew: boolean;
  disabled: boolean;
  names: Record<string, string>;
  tryDemo?: ContentTryResult;
  onSave: (rule: ContentRule) => void;
  onCancel: () => void;
  onDelete?: () => void;
}) {
  const { codes, channels } = useRulesOptions();
  const [draft, setDraft] = useState<Draft>(() => toDraft(initial));
  const [tried, setTried] = useState(false);
  const rule = fromDraft(draft);
  const problem = draftProblem(rule);
  const set = (patch: Partial<Draft>) => setDraft((d) => ({ ...d, ...patch }));
  const toggle = <T extends string>(list: T[], item: T, on: boolean): T[] => (on ? [...list, item] : list.filter((x) => x !== item));

  return (
    <form
      className="space-y-4"
      data-testid="content-rule-editor"
      onSubmit={(e) => {
        e.preventDefault();
        setTried(true);
        if (!problem) onSave(rule);
      }}
    >
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="min-w-0 space-y-4">
          <div>
            <Label htmlFor="content-name">Name</Label>
            <Input id="content-name" className="mt-2 h-9" maxLength={80} value={draft.name} onChange={(e) => set({ name: e.target.value })} disabled={disabled} />
          </div>
          <div>
            <Label htmlFor="content-policy">The rule, in one sentence</Label>
            <Textarea
              id="content-policy"
              className="mt-2 min-h-[72px] text-[13px]"
              maxLength={CONTENT_POLICY_MAX}
              placeholder="Don’t ask about or share anyone’s salary, pay or bonus."
              value={draft.policy}
              onChange={(e) => set({ policy: e.target.value.replace(/\n/g, " ") })}
              disabled={disabled}
            />
            <p className="mt-1 text-[12px] text-ink-2">Your firewall’s AI reads each message and decides whether it goes against this. It catches other wording too.</p>
          </div>
          <fieldset className="rounded-[10px] border border-line px-3 py-3">
            <legend className="px-1 text-[13px] font-medium text-ink">Also match exactly</legend>
            <Label htmlFor="content-words" className="text-[12.5px]">Words</Label>
            <Textarea
              id="content-words"
              className="mt-1.5 min-h-[72px] font-mono text-[12.5px]"
              placeholder={"customer list\nproject falcon"}
              value={draft.words}
              onChange={(e) => set({ words: e.target.value })}
              disabled={disabled}
            />
            <p className="mt-1 text-[12px] text-ink-2">One word or phrase per line. Case and accents are ignored; whole words only.</p>
            <div className="mt-3 space-y-2">
              {CONTENT_DETECTORS.filter((d) => d !== "secrets").map((d) => (
                <label key={d} className="flex cursor-pointer items-center gap-2.5 text-[13px] text-ink">
                  <Checkbox checked={draft.detectors.includes(d)} onCheckedChange={(v) => set({ detectors: toggle(draft.detectors, d, v === true) })} disabled={disabled} />
                  {DETECTOR_LABELS[d]}
                </label>
              ))}
            </div>
          </fieldset>
          <div>
            <Label htmlFor="content-reason">Reason</Label>
            <Input id="content-reason" className="mt-2 h-9" maxLength={200} value={draft.reason} onChange={(e) => set({ reason: e.target.value })} disabled={disabled} />
            <p className="mt-1 text-[12px] text-ink-2">The agent and the people in the chat see it when a message is stopped or held.</p>
          </div>
        </div>
        <div className="min-w-0 space-y-4">
          <div>
            <Label className="text-[13px]">Which way</Label>
            <Select
              value={draft.direction}
              onValueChange={(v) => set({ direction: v as Draft["direction"], action: v !== "out" && draft.action === "hold" ? "log" : draft.action })}
              disabled={disabled}
            >
              <SelectTrigger className="mt-2 h-9 w-full min-w-0" aria-label="Which way">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(["out", "in", "both"] as const).map((d) => (
                  <SelectItem key={d} value={d}>
                    {DIRECTION_LABELS[d]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <fieldset>
            <legend className="text-[13px] font-medium text-ink">Channels</legend>
            <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
              {channels.map((c) => {
                const never = (draft.direction === "out" && CONTENT_IN_ONLY.includes(c)) || (draft.direction === "in" && CONTENT_OUT_ONLY.includes(c));
                return (
                  <label key={c} className={cn("flex items-center gap-2.5 text-[13px] text-ink", never ? "opacity-55" : "cursor-pointer")}>
                    <Checkbox checked={draft.channels.includes(c)} onCheckedChange={(v) => set({ channels: toggle(draft.channels, c, v === true) })} disabled={disabled} />
                    {CHANNEL_LABELS[c]}
                  </label>
                );
              })}
            </div>
            <p className="mt-1 text-[12px] text-ink-2">Webhooks only come in; website requests only go out.</p>
          </fieldset>
          <div>
            <Label className="text-[13px]">What happens</Label>
            <RadioGroup className="mt-2 gap-2" value={draft.action} onValueChange={(v) => set({ action: v as Draft["action"] })} disabled={disabled}>
              {(["log", "hold", "block"] as const).map((a) => (
                <label key={a} className={cn("flex items-start gap-2.5", a === "hold" && draft.direction !== "out" ? "opacity-55" : "cursor-pointer")}>
                  <RadioGroupItem value={a} className="mt-0.5" disabled={a === "hold" && draft.direction !== "out"} />
                  <span className="min-w-0">
                    <span className="block text-[13px] text-ink">{ACTION_LABELS[a]}</span>
                    <span className="block text-[12px] text-ink-2">
                      {a === "log"
                        ? "The message goes through; Activity shows that the rule matched."
                        : a === "hold"
                          ? "Only for messages from your agents. Your approved people get Send and Don't send on Telegram; nothing is sent after 24 hours."
                          : "The message doesn’t go through, and the agent is told why."}
                    </span>
                  </span>
                </label>
              ))}
            </RadioGroup>
          </div>
        </div>
      </div>
      {tried && problem && (
        <p role="alert" className="text-[12.5px] text-destructive">
          {problem}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <Button type="submit" disabled={disabled}>
          {isNew ? "Add rule" : "Save rule"}
        </Button>
        <Button type="button" variant="outline" onClick={onCancel} disabled={disabled}>
          Cancel
        </Button>
        {onDelete && (
          <Button type="button" variant="ghost" className="ml-auto gap-1.5 text-destructive" onClick={onDelete} disabled={disabled}>
            <Trash2 className="h-3.5 w-3.5" />
            Delete rule
          </Button>
        )}
        {codes ? <p className="w-full text-[12px] text-ink-2">Your firewall sends a code to your approved people before it applies this.</p> : null}
      </div>
      <div className="border-t border-line pt-4">
        {problem ? (
          <p className="text-[12.5px] text-ink-2">Finish the rule to try it on a message.</p>
        ) : (
          <ContentTryBox names={names} draft={rule} demo={tryDemo} />
        )}
      </div>
    </form>
  );
}

const AI_FAILED: Record<string, string> = {
  off: "the AI Firewall is off",
  cap: "today’s limit of AI checks is used up",
  error: "the AI didn’t answer in time",
  model: "the AI Firewall’s model isn’t one content rules use (Jev)",
  unpinned: "the AI Firewall’s key or model isn’t the one your content rules accepted",
  too_long: "the message is too long for the AI to judge",
};

const AI_PROVIDER_WORDS: Record<string, string> = {
  vercel_gateway: "your Vercel AI Gateway key",
  controlclaw_included: "the included AI tokens",
};

/**
 * A message, which way and which channel, tried by the firewall: the rule that would act, every rule
 * that matches, and each policy's probability. With `draft`, the rule being edited counts as saved.
 */
export function ContentTryBox({
  names,
  draft,
  demo,
  inDialog,
}: {
  names: Record<string, string>;
  draft?: ContentRule | null;
  demo?: ContentTryResult;
  /** In the Try a message dialog, which has the heading: the box draws none of its own. */
  inDialog?: boolean;
}) {
  const { channels } = useRulesOptions();
  const api = useApi();
  const [text, setText] = useState("");
  const [direction, setDirection] = useState<"in" | "out">(draft?.direction === "in" ? "in" : "out");
  const [channel, setChannel] = useState<ContentChannel>(draft?.channels[0] ?? "telegram");
  const [result, setResult] = useState<ContentTryResult | null>(demo ?? null);
  const [trying, setTrying] = useState(false);
  const [error, setError] = useState("");
  const name = (id: string) => (draft?.id === id ? draft.name || "This rule" : (names[id] ?? id));

  async function tryIt() {
    if (demo || !text.trim()) return;
    setTrying(true);
    setError("");
    try {
      setResult(await api.contentRules.try({ text, direction, channel, ...(draft ? { draft } : {}) }));
    } catch (e) {
      setResult(null);
      setError(e instanceof Error && e.message ? e.message : "Your firewall didn’t answer. Try again.");
    } finally {
      setTrying(false);
    }
  }

  return (
    <div className={cn("space-y-3", draft === undefined && !inDialog && "px-5 py-4")} data-testid={draft === undefined ? "content-test" : "content-test-draft"}>
      {!inDialog && (
        <div>
          <p className="text-[13px] font-medium text-ink">{draft === undefined ? "Try a message" : "Try this rule"}</p>
          <p className="mt-0.5 text-[12.5px] text-ink-2">
            Your firewall checks it {draft === undefined ? "against your Messages rules" : "against this rule and your other Messages rules"}, with its AI. Nothing is sent or kept.
          </p>
        </div>
      )}
      <Textarea aria-label="Message to try" className="min-h-[72px] text-[13px]" placeholder="How much does Anna make?" value={text} onChange={(e) => setText(e.target.value)} />
      <div className="flex flex-wrap gap-2">
        <Select value={direction} onValueChange={(v) => setDirection(v as "in" | "out")}>
          <SelectTrigger className="h-9 min-w-0 flex-1 sm:w-64 sm:flex-none" aria-label="Which way">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="out">{DIRECTION_LABELS.out}</SelectItem>
            <SelectItem value="in">{DIRECTION_LABELS.in}</SelectItem>
          </SelectContent>
        </Select>
        <Select value={channel} onValueChange={(v) => setChannel(v as ContentChannel)}>
          <SelectTrigger className="h-9 min-w-0 flex-1 sm:w-52 sm:flex-none" aria-label="Channel">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {channels.map((c) => (
              <SelectItem key={c} value={c}>
                {CHANNEL_LABELS[c]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button type="button" variant="outline" className="h-9" onClick={() => void tryIt()} disabled={trying || !text.trim()}>
          {trying ? "Trying…" : "Try"}
        </Button>
      </div>
      {error && (
        <p role="alert" className="text-[12.5px] text-destructive">
          {error}
        </p>
      )}
      {result && (
        <div role="status" className="space-y-1 rounded-[10px] border border-line px-3 py-2.5 text-[12.5px] text-ink-2" data-testid="content-test-result">
          {result.rule ? (
            <p className="font-medium text-ink">
              {name(result.rule.id)}: {ACTION_LABELS[result.rule.action].toLowerCase()}
              {result.rule.by === "found" ? ", found by the AI" : result.rule.by === "failed" ? ", because the AI check couldn’t run" : ""}
            </p>
          ) : (
            <p className="font-medium text-ink">No rule acts on this message.</p>
          )}
          {result.hits.length > 1 && <p>Also matches: {result.hits.filter((h) => h.id !== result.rule?.id).map((h) => name(h.id)).join(", ")}</p>}
          {result.failed && <p>The AI couldn’t answer: {AI_FAILED[result.failed] ?? result.failed}. Rules that stop or hold act on every message their sentence covers until it can.</p>}
          {result.probabilities &&
            Object.entries(result.probabilities).map(([id, p]) => (
              <p key={id} className="tabular-nums">
                {name(id)}: {p >= 0.5 ? "goes against it" : "fine"} ({Math.round(p * 100)}%; the rule acts from 50%)
              </p>
            ))}
        </div>
      )}
    </div>
  );
}

/**
 * The Messages rules as Security rules reads them from the firewall: the rules,
 * whether the AI Firewall is on, and the change waiting for a code. With `demo`, a fixed snapshot.
 */
export interface ContentDemo {
  snapshot: ContentRulesSnapshot | null;
  counts?: Record<string, number>;
  pending?: RulesPending;
  error?: string;
  loading?: boolean;
  editing?: { rule: ContentRule; isNew: boolean };
  picking?: boolean;
  aiOn?: boolean;
  tried?: ContentTryResult;
}

export function useContentRules(demo?: ContentDemo, onSaved?: () => void) {
  const api = useApi();
  const [snapshot, setSnapshot] = useState<ContentRulesSnapshot | null>(demo?.snapshot ?? null);
  const [loading, setLoading] = useState(demo ? !!demo.loading : true);
  // Whether the AI Firewall is on, which judges the policies. Null until read.
  const [aiOn, setAiOn] = useState<boolean | null>(demo ? (demo.aiOn ?? true) : null);
  const change = useRulesChange<ContentChange, ContentRulesSnapshot>({ rpc: api.contentRules, demo, onSnapshot: setSnapshot, onSaved });
  const { setError } = change;

  const refresh = useCallback(async () => {
    if (demo) return;
    setLoading(true);
    setError("");
    try {
      // The rules' counts are read by Security rules itself, for every type (docs/plans/rule-metrics.md).
      const { aiOn: on, ...rest } = await api.contentRules.get();
      setSnapshot(rest);
      setAiOn(on);
    } catch (e) {
      setError(e instanceof Error && e.message ? e.message : "Your firewall didn’t answer. Start or update it, then reload.");
    } finally {
      setLoading(false);
    }
  }, [demo, setError, api]);
  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { snapshot, loading, aiOn, refresh, ...change };
}

/** Opens the firewall's own record of what was stopped, in a new tab. */
export function useOpenContentRecord(demo: boolean, onError: (message: string) => void) {
  const api = useApi();
  const [opening, setOpening] = useState(false);
  async function open() {
    if (demo) return;
    // Opened before the await, so the browser does not take it for a pop-up.
    const tab = window.open("about:blank", "_blank");
    setOpening(true);
    onError("");
    try {
      const { url } = await api.contentRules.open();
      if (tab) {
        tab.opener = null;
        tab.location.href = url;
      } else window.location.href = url;
    } catch (e) {
      tab?.close();
      onError(e instanceof Error && e.message ? e.message : "Couldn’t open your firewall’s record. Try again.");
    } finally {
      setOpening(false);
    }
  }
  return { opening, open };
}

const ALERT = "rounded-[10px] border border-destructive/30 p-3 text-[12.5px] text-destructive";

/** The AI Firewall on Security rules' Settings tab: switches tab in place when it can. */
function AiFirewallLink({ onOpen }: { onOpen?: () => void }) {
  const routes = useRoutes();
  return (
    <a
      href={routes.aiFirewall}
      className="font-medium underline"
      onClick={(e) => {
        if (!onOpen) return;
        e.preventDefault();
        onOpen();
      }}
    >
      Settings, under AI Firewall
    </a>
  );
}

/**
 * What the Messages rules need the person to know before the list: the rules could not be read,
 * the AI the sentences are judged by is not the one they accepted (with "Accept with a code"), the
 * AI Firewall is off, messages waiting for approval. The AI Firewall is on the Settings tab:
 * `onOpenAi` opens it.
 */
export function ContentNotices({
  snapshot,
  aiOn,
  canManage,
  disabled,
  onAcceptAi,
  onOpenAi,
}: {
  snapshot: ContentRulesSnapshot | null;
  aiOn: boolean | null;
  canManage: boolean;
  disabled: boolean;
  onAcceptAi: () => void;
  onOpenAi?: () => void;
}) {
  if (!snapshot) return null;
  const sentences = snapshot.rules.some((r) => r.enabled && r.policy);
  const ai = snapshot.ai;
  return (
    <>
      {snapshot.unreadable && (
        <p role="alert" className={ALERT}>
          Your firewall can’t read its Messages rules, so it stops every checked message. To repair them, save any change with a code.
        </p>
      )}
      {aiOn !== false && ai && sentences && !ai.matches && (
        <div role="alert" className={ALERT} data-testid="content-ai-pin">
          {ai.current && !ai.allowed ? (
            <p>
              Your AI Firewall uses {ai.current.model}, which Messages rules don’t use: they judge sentences only with Jev, on the AI Gateway or the
              included AI tokens. Until then, rules with a sentence stop or hold everything they cover. Change it in{" "}
              <AiFirewallLink onOpen={onOpenAi} />.
            </p>
          ) : (
            <>
              <p>
                {ai.pinned ? "Your AI Firewall now uses " : "Your Messages rules haven’t accepted an AI model and key yet. Your AI Firewall uses "}
                {ai.current ? `${ai.current.model} on ${AI_PROVIDER_WORDS[ai.current.provider] ?? ai.current.provider}` : "another key"}
                {ai.pinned ? ", not the model and key your Messages rules accepted." : "."} Until you accept it with a code, rules with a sentence stop or hold
                everything they cover.
              </p>
              {canManage && (
                <Button variant="outline" size="sm" className="mt-2 h-8" disabled={disabled} onClick={onAcceptAi}>
                  Accept with a code
                </Button>
              )}
            </>
          )}
        </div>
      )}
      {aiOn === false && sentences && (
        <p role="alert" className={ALERT}>
          The AI Firewall is off, so your firewall can’t judge your rules’ sentences. Messages rules that stop or hold act on every message they
          cover. Turn it on in <AiFirewallLink onOpen={onOpenAi} />.
        </p>
      )}
      {!!snapshot.held && (
        <p role="status" className="rounded-[10px] border border-line px-3 py-2.5 text-[12.5px] text-ink">
          {snapshot.held === 1 ? "1 message is" : `${snapshot.held} messages are`} waiting for approval on Telegram. What was stopped shows the text.
        </p>
      )}
    </>
  );
}

/** The always-on Leaking secrets rule as the firewall reports it. */
export const LEAKING_SECRETS_TEXT = "Passwords, keys and tokens in messages from your agents are stopped. The text isn’t kept.";

/**
 * Add or edit a Messages rule: the templates first for a new one, then the editor. The change waits
 * for a code; the code panel shows here while the dialog is open, and the dialog closes once the
 * firewall applied it.
 */
export function ContentRuleDialog({
  state,
  names,
  disabled,
  pendingPanel,
  error,
  tryDemo,
  onPick,
  onSave,
  onDelete,
  onClose,
}: {
  state: { picking: true } | { rule: ContentRule; isNew: boolean };
  names: Record<string, string>;
  disabled: boolean;
  pendingPanel: ReactNode;
  error: string;
  tryDemo?: ContentTryResult;
  onPick: (rule: ContentRule) => void;
  onSave: (rule: ContentRule) => void;
  onDelete: (id: string) => void;
  onClose: () => void;
}) {
  const { codes, channels } = useRulesOptions();
  const editing = "rule" in state ? state : null;
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-3xl" data-testid="content-rule-dialog">
        <DialogHeader>
          <DialogTitle>{editing ? (editing.isNew ? "New Messages rule" : `Edit ${editing.rule.name}`) : "New Messages rule"}</DialogTitle>
          <DialogDescription>
            Your firewall’s AI checks messages to and from your agents against the rule’s sentence.
            {codes ? " Every change needs a code sent to your approved people." : ""}
          </DialogDescription>
        </DialogHeader>
        {error && (
          <p role="alert" className={ALERT}>
            {error}
          </p>
        )}
        {pendingPanel}
        {editing ? (
          <RuleEditor
            key={editing.rule.id}
            initial={editing.rule}
            isNew={editing.isNew}
            disabled={disabled}
            names={names}
            tryDemo={tryDemo}
            onSave={onSave}
            onCancel={onClose}
            onDelete={editing.isNew ? undefined : () => onDelete(editing.rule.id)}
          />
        ) : (
          <div data-testid="content-templates">
            <p className="text-[13px] font-medium text-ink">Start from</p>
            <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2">
              {CONTENT_TEMPLATES.map((t) => (
                <button
                  key={t.key}
                  type="button"
                  className="rounded-[10px] border border-line px-3 py-2.5 text-left transition-colors hover:bg-bg-2"
                  onClick={() =>
                    onPick({ ...t.rule, channels: t.rule.channels.filter((c) => channels.includes(c)), patterns: [...t.rule.patterns], detectors: [...t.rule.detectors], id: contentRuleId(t.rule.name || "rule"), enabled: true })
                  }
                >
                  <span className="block text-[13px] font-medium text-ink">{t.label}</span>
                  <span className="block text-[12px] text-ink-2">{t.help}</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
