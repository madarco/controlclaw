"use client";

import { EgressAiSections } from "../panel/EgressAiCard";
import type { EgressAiView } from "../../lib/egress-ai-schema";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { AppLink as Link } from "../../lib/link";
import { ChevronRight, ExternalLink, Globe, Lock, Mail, MessageSquare, Pencil, Plug, Plus, RefreshCw, Settings2, Sparkles, Trash2, UserCheck, Wrench, X } from "lucide-react";
import { toast } from "sonner";
import { Button } from "../../ui/button";
import { Switch } from "../../ui/switch";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "../../ui/dialog";
import { PageHead } from "../../kit/PageHead";
import { ActionMenu, Card, Hint, Select } from "../../kit/console-ui";
import { useApi } from "../../lib/api";
import { cn } from "../../lib/utils";
import { EgressRuleDialog, draftOf } from "../egress/EgressRuleDialog";
import { useEgressRules } from "../egress/useEgressRules";
import { EveryOtherSiteSelect } from "../egress/EveryOtherSiteSelect";
import { managedEgressReason } from "../../lib/managed-egress";
import { NotInspectedBadge } from "../egress/NotInspected";
import type { EgressBoxOption, EgressRuleListItem } from "../../lib/egress-schema";
import { EMAIL_MODES, EmailEntryDialog, EmailSettingsPanel, useEmailRules, type EmailDemo } from "./EmailRules";
import { linkClass } from "../../lib/link-class";
import type { EmailMailbox, OutboundMode } from "../../lib/email-rules-schema";
import { CONTENT_CHANNELS, type ContentChannel, type ContentRule } from "../../lib/content-rules-schema";
import { RulesOptionsContext } from "./rules-context";
import type { AppOption, AppRule } from "../../lib/app-rules-schema";
import { AppRuleDialog, AppsTable, IntegrationsAiNotice, useAppRules, type AppsDemo } from "./AppRules";
import { NEXT_EFFECT, type SecurityRuleListItem } from "../../lib/security-schema";
import { SECURITY_TABS, SECURITY_TAB_LABELS, buildRows, channelsShort, filterRows, messagesExtras, tabCounts, type RuleRow, type RuleType, type SecurityTab } from "../../lib/security-rules-list";
import { ContentNotices, ContentRuleDialog, ContentTryBox, useContentRules, useOpenContentRecord, type ContentDemo } from "./ContentRules";
import { RulesCodePanel } from "./RulesCodePanel";
import { Acts, ActionPill, Cell, EmptyLine, Hits, Main, Ord, TRow } from "./RulesTable";
import { byRuleKey, foldNamedApps, outcomeLine, type RuleActivityItem } from "../../lib/rule-metrics";
import { SecurityRuleEditor } from "./SecurityRuleEditor";
import { useAutoRules, type AutoDemo, type AutoKept } from "./AutoRules";
import { patchAutoRule } from "../../lib/auto-approve-schema";
import { useRoutes } from "../../lib/routes";

/**
 * Security rules: every rule the firewall applies to the agents (docs/features/security-rules.md),
 * one tab per type, each kept where it always was and with its own code rules:
 *
 * - Messages (content rules, on the firewall): every change waits for a code.
 * - Email (senders and recipients, on the firewall): adding someone waits for a code.
 * - Websites (`egress_rule`, the Internet access rules): no code.
 * - Integrations (on the firewall, read on every app and MCP tool call): a change that lets more through waits for a code.
 * - Auto approve (answers the agents' permission requests): on a firewall that keeps them, a change
 *   that lets more through waits for a code; where ControlClaw keeps them (`security_rule`), no code.
 *
 * Then Settings: the AI Firewall and AI Log Review, which every type's AI checks use. It has no rows.
 *
 * Each tab is a table that ends in a grey row for what happens when no rule matches. The tab and
 * the agent filter (Websites and Auto approve) are kept in the address.
 */

const TYPE_ICON: Record<SecurityTab, typeof Globe> = { messages: MessageSquare, email: Mail, websites: Globe, apps: Plug, auto: UserCheck, settings: Settings2 };

/** The bar under the tabs: one line for the type, and when a change waits for a code. */
const TYPE_LINE: Record<SecurityTab, { line: string; code?: string; add?: string }> = {
  messages: { line: "Your firewall’s AI checks what your agents send and receive.", code: "Changes need a code", add: "New messages rule" },
  email: { line: "Mail from anyone not listed is held back.", code: "Adding someone needs a code" },
  websites: { line: "Read top to bottom. The first match decides.", add: "New site rule" },
  apps: { line: "What your agents may do in your connected apps and MCP servers, on sites the Websites rules allow. The first match decides.", code: "Loosening needs a code", add: "New integration rule" },
  auto: { line: "Answers your agents' permission requests for you. The first match decides.", code: "Loosening needs a code", add: "New rule" },
  settings: { line: "The AI that checks requests and messages as they happen, and the AI that reviews your agents' traffic afterwards." },
};

/** The table's short words for what a Messages rule does. */
const MESSAGE_ACTION: Record<ContentRule["action"], string> = { block: "Stop", hold: "Hold", log: "Record" };

const TYPE_PARAM = "type";
const AGENT_PARAM = "agent";
const RULE_PARAM = "rule";
const NEW_PARAM = "new";

/** Each table's row, by the rule's id: where `?rule=` scrolls to. */
const ROW_TESTID: Partial<Record<RuleType, string>> = { messages: "content-rule-", websites: "egress-rule-", apps: "app-rule-", auto: "auto-rule-" };

type Dialogs =
  | { kind: "messages"; state: { picking: true } | { rule: ContentRule; isNew: boolean } }
  | { kind: "email"; list: "senders" | "recipients" }
  | { kind: "websites"; rule: EgressRuleListItem | null }
  | { kind: "apps"; rule: AppRule | null }
  | { kind: "auto"; rule: SecurityRuleListItem | null }
  | { kind: "try" };

export interface SecurityRulesViewProps {
  /** The Auto approve rules ControlClaw keeps; empty where the firewall keeps them (read by the page). */
  auto: SecurityRuleListItem[];
  /** Where the Auto approve rules are kept (`console` when left out). */
  autoKept?: AutoKept;
  websites: EgressRuleListItem[];
  /** Every box a rule can be for: the agents, and the brain when there is one. */
  boxes: EgressBoxOption[];
  mailboxes: EmailMailbox[];
  /** The organization's connected apps, for the Integrations rules. */
  apps?: AppOption[];
  canManage: boolean;
  /** Website rules are Internet access's permission. */
  canManageWebsites: boolean;
  exit: { configured: boolean; country: string | null; supportsCountry: boolean };
  /** The AI Firewall and AI Log Review, on the Settings tab; null when there is no firewall to run them. */
  ai?: EgressAiView | null;
  /** The tab and the agent from the address (`?type=…&agent=…`), read by the server so the first render is the right one. */
  initialType?: SecurityTab | null;
  initialAgent?: string | null;
  /** A rule to open (`?rule=<id>`, the Firewall page's pencil), and `?new=1`: the tab's add dialog. */
  initialRule?: string | null;
  initialNew?: boolean;
  /** Changes wait for a confirmation code (the console). The firewall's own panel applies them at once, and says nothing about codes. */
  codes?: boolean;
  /** The channels a Messages rule can check; the firewall's own panel has no team chat or voice. Every channel when left out. */
  contentChannels?: readonly ContentChannel[];
  /** The demo page: fixed firewall answers, nothing sent. */
  demo?: {
    content?: ContentDemo;
    email?: EmailDemo;
    apps?: AppsDemo;
    /** Auto approve on a firewall that keeps them. */
    auto?: AutoDemo;
    /** What each rule matched in 7 days, in place of the RPC. */
    activity?: RuleActivityItem[];
    activityNow?: number;
    type?: SecurityTab;
    agent?: string;
    dialog?: Dialogs;
    emailSettingsOpen?: boolean;
  };
}

export function SecurityRulesView({ auto: initialAuto, autoKept = "console", websites, boxes, mailboxes, apps: appOptions = [], canManage, canManageWebsites, exit, ai, initialType, initialAgent, initialRule, initialNew, codes = true, contentChannels = CONTENT_CHANNELS, demo }: SecurityRulesViewProps) {
  const rulesOptions = useMemo(() => ({ codes, channels: contentChannels }), [codes, contentChannels]);
  const api = useApi();
  const routes = useRoutes();
  const [dialog, setDialog] = useState<Dialogs | null>(demo?.dialog ?? null);
  const closeDialog = useCallback(() => setDialog(null), []);
  // A change that settles closes its own type's dialog only: another one opened meanwhile stays.
  const closeMessages = useCallback(() => setDialog((d) => (d?.kind === "messages" ? null : d)), []);
  const closeEmail = useCallback(() => setDialog((d) => (d?.kind === "email" ? null : d)), []);
  const closeApps = useCallback(() => setDialog((d) => (d?.kind === "apps" ? null : d)), []);
  const closeAuto = useCallback(() => setDialog((d) => (d?.kind === "auto" ? null : d)), []);
  const autoOnFirewall = autoKept === "firewall" && !!api.autoApprove;
  const content = useContentRules(demo ? (demo.content ?? { snapshot: null, error: "The firewall didn’t answer." }) : undefined, closeMessages);
  const email = useEmailRules(mailboxes.length > 0, demo ? (demo.email ?? { snapshot: null }) : undefined, closeEmail);
  const web = useEgressRules(api.egressRules, websites, boxes, canManageWebsites, !!demo);

  const [consoleAutoRules, setAutoRules] = useState(initialAuto);
  // What each rule matched in the last 7 days (docs/plans/rule-metrics.md), every type, by `type:id`.
  const [activity, setActivity] = useState<{ items: Map<string, RuleActivityItem>; now: number }>({ items: byRuleKey(demo?.activity ?? []), now: demo?.activityNow ?? 0 });
  const record = useOpenContentRecord(!!demo, content.setError);
  const [emailSettingsOpen, setEmailSettingsOpen] = useState(!!demo?.emailSettingsOpen);

  // A control plane with no auto approve rules (the firewall's own panel) has no Auto approve tab.
  const tabs = useMemo(() => SECURITY_TABS.filter((t) => t !== "auto" || !!api.security || autoOnFirewall), [api, autoOnFirewall]);
  const [type, setTypeState] = useState<SecurityTab>(() => {
    const t = demo?.type ?? initialType ?? "messages";
    return tabs.includes(t) ? t : "messages";
  });
  const appRules = useAppRules(canManage && type === "apps", demo ? (demo.apps ?? { snapshot: null }) : undefined, closeApps);
  const autoFw = useAutoRules(autoOnFirewall && canManage && type === "auto", demo && autoOnFirewall ? (demo.auto ?? { snapshot: null }) : undefined, closeAuto);
  const autoRules = autoOnFirewall ? autoFw.items : consoleAutoRules;
  const [box, setBoxState] = useState<string>(demo?.agent ?? (initialAgent && boxes.some((b) => b.id === initialAgent) ? initialAgent : ""));
  const agents = useMemo(() => boxes.filter((b) => b.kind === "agent"), [boxes]);
  // The brain is a choice on Websites only: it sends no messages and asks for nothing.
  const boxOption = boxes.find((b) => b.id === box && (b.kind === "agent" || type === "websites")) ?? null;
  const filtered = type === "websites" || type === "apps" || type === "auto";

  const setParam = useCallback(
    (name: string, value: string) => {
      if (demo) return;
      const url = new URL(window.location.href);
      if (value) url.searchParams.set(name, value);
      else url.searchParams.delete(name);
      window.history.replaceState(window.history.state, "", url);
    },
    [demo],
  );
  const setType = (t: SecurityTab) => {
    setTypeState(t);
    setParam(TYPE_PARAM, t === "messages" ? "" : t);
    // The brain is a Websites choice: on another tab the filter goes back to every agent.
    if (t !== "websites" && boxes.find((b) => b.id === box)?.kind === "brain") setBox("");
  };
  const setBox = (id: string) => {
    setBoxState(id);
    setParam(AGENT_PARAM, id);
  };

  // Under the agent filter the counts are that agent's, as the rows are.
  const countsFor = filtered ? (boxOption?.id ?? null) : null;
  useEffect(() => {
    if (demo || !canManage || !api.ruleMetrics) return;
    api.ruleMetrics
      .list({ range: "7d", ...(countsFor ? { agentId: countsFor } : {}) })
      .then((r) => setActivity({ items: byRuleKey(r.items), now: new Date(r.generatedAt).getTime() }))
      .catch((err) => console.error("ruleMetrics.list failed", err));
  }, [canManage, demo, countsFor, api]);
  // Integrations counts kept by name fold into the rule that has the name now (the firewall's list).
  const foldedApps = useMemo(
    () => (appRules.snapshot ? byRuleKey(foldNamedApps([...activity.items.values()], appRules.snapshot.rules)) : activity.items),
    [activity.items, appRules.snapshot],
  );
  const hits = (t: RuleType, key: string) => (t === "apps" ? foldedApps : activity.items).get(`${t}:${key}`);

  // An old link to the email settings (`#email-settings`) opens them; one to the AI sections
  // (`#ai-firewall`, `#ai-review`, from before they had their own tab) opens Settings.
  useEffect(() => {
    if (demo) return;
    const hash = window.location.hash;
    if (hash !== "#email-settings" && hash !== "#ai-firewall" && hash !== "#ai-review") return;
    const frame = requestAnimationFrame(() => {
      if (hash === "#email-settings") {
        setTypeState("email");
        setEmailSettingsOpen(true);
      } else {
        setTypeState("settings");
        requestAnimationFrame(() => document.getElementById(hash.slice(1))?.scrollIntoView());
      }
    });
    return () => cancelAnimationFrame(frame);
  }, [demo]);

  /** A notice on another tab that says to change the AI: open Settings at the AI Firewall. */
  const openAiFirewall = () => {
    setType("settings");
    requestAnimationFrame(() => document.getElementById("ai-firewall")?.scrollIntoView({ behavior: "smooth", block: "start" }));
  };

  const rows = useMemo(
    () =>
      buildRows({
        content: content.snapshot?.rules ?? null,
        contentCounts: null,
        email: email.snapshot ? { senders: email.snapshot.rules.inbound.senders, recipients: email.snapshot.rules.outbound.recipients } : null,
        mailboxes,
        websites: web.items,
        apps: appRules.snapshot?.rules ?? null,
        appOptions,
        auto: autoRules,
        autoCounts: null,
        boxes,
      }),
    [content.snapshot, email.snapshot, mailboxes, web.items, appRules.snapshot, appOptions, autoRules, boxes],
  );
  const filter = { box: boxOption?.id ?? null, brain: boxOption?.kind === "brain" };
  const shown = filterRows(rows, { ...filter, type: type === "settings" ? null : type });
  const counts = tabCounts(rows, filter);

  const contentDisabled = !canManage || content.busy || !!content.pending;
  const emailDisabled = !canManage || email.busy || !!email.pending;
  const appsDisabled = !canManage || appRules.busy || !!appRules.pending;
  const autoFwDisabled = autoOnFirewall && (autoFw.busy || !!autoFw.pending || !autoFw.snapshot);
  // The always-on rules too: "Try a message" names the rule that would act, Leaking secrets included.
  const names = Object.fromEntries([...(content.snapshot?.core ?? []), ...(content.snapshot?.rules ?? [])].map((r) => [r.id, r.name]));

  // --- Auto approve ---
  const patchAuto = (id: string, patch: Partial<SecurityRuleListItem>) => setAutoRules((p) => p.map((r) => (r.id === id ? { ...r, ...patch } : r)));
  /** On a firewall that keeps the rules: the rule with a change, sent to it (it may want its code). */
  function sendAuto(rule: SecurityRuleListItem, patch: { effect?: SecurityRuleListItem["effect"]; enabled?: boolean }) {
    const held = autoFw.snapshot?.rules.find((r) => r.id === rule.id);
    if (!held || autoFwDisabled) return;
    void autoFw.send({ op: "put", rule: patchAutoRule(held, patch) });
  }
  async function cycleAuto(rule: SecurityRuleListItem) {
    if (autoOnFirewall) return sendAuto(rule, { effect: NEXT_EFFECT[rule.effect] });
    if (demo || rule.locked || !canManage || !api.security) return;
    patchAuto(rule.id, { effect: NEXT_EFFECT[rule.effect] });
    try {
      patchAuto(rule.id, await api.security.cycleSecurityRuleEffect({ id: rule.id }));
    } catch (err) {
      console.error("cycleSecurityRuleEffect failed", err);
      patchAuto(rule.id, { effect: rule.effect });
      toast.error("Couldn’t change the rule. Try again.");
    }
  }
  async function toggleAuto(rule: SecurityRuleListItem) {
    if (autoOnFirewall) return sendAuto(rule, { enabled: !rule.enabled });
    if (demo || rule.locked || !canManage || !api.security) return;
    patchAuto(rule.id, { enabled: !rule.enabled });
    try {
      patchAuto(rule.id, await api.security.updateSecurityRule({ id: rule.id, enabled: !rule.enabled }));
    } catch (err) {
      console.error("updateSecurityRule failed", err);
      patchAuto(rule.id, { enabled: rule.enabled });
      toast.error(`Couldn’t turn the rule ${rule.enabled ? "off" : "on"}. Try again.`);
    }
  }
  function savedAuto(rule: SecurityRuleListItem) {
    setAutoRules((prev) => {
      const next = prev.some((r) => r.id === rule.id) ? prev.map((r) => (r.id === rule.id ? rule : r)) : [...prev, rule];
      return next.sort((a, b) => a.priority - b.priority || a.createdAt.localeCompare(b.createdAt));
    });
    setDialog(null);
  }

  const codePanel = (which: "messages" | "email" | "apps" | "auto", where: "page" | "dialog") => {
    const c = which === "messages" ? content : which === "email" ? email : which === "apps" ? appRules : autoFw;
    if (!c.pending) return null;
    // While that type's dialog is open, the code is asked for there.
    if ((where === "page") === (dialog?.kind === which)) return null;
    return (
      <RulesCodePanel
        id={`${which === "messages" ? "content" : which}-code`}
        label={which === "messages" ? "Messages rules" : which === "email" ? "Email rules" : which === "apps" ? "Integrations rules" : "Auto approve rules"}
        className={where === "page" ? "mb-3" : ""}
        pending={c.pending}
        code={c.code}
        busy={c.busy}
        onCode={c.setCode}
        onConfirm={(cancel) => void c.confirm(cancel)}
      />
    );
  };

  // The add button for the tab, and why it is off when it is.
  const add: { onClick: () => void; off?: string } | null =
    type === "messages"
      ? canManage
        ? {
            onClick: () => setDialog({ kind: "messages", state: { picking: true } }),
            off: !content.snapshot ? "Your firewall must be running to hold Messages rules." : content.pending ? "A Messages change is waiting for its code." : undefined,
          }
        : null
      : type === "websites"
        ? canManageWebsites
          ? { onClick: () => setDialog({ kind: "websites", rule: null }) }
          : null
        : type === "apps"
          ? canManage
            ? {
                onClick: () => setDialog({ kind: "apps", rule: null }),
                off: !appRules.snapshot ? "Your firewall must be running to hold Integrations rules." : appRules.pending ? "An Integrations change is waiting for its code." : undefined,
              }
            : null
          : type === "auto" && canManage
            ? {
                onClick: () => setDialog({ kind: "auto", rule: null }),
                off: !autoOnFirewall ? undefined : !autoFw.snapshot ? "Your firewall must be running to hold Auto approve rules." : autoFw.pending ? "An Auto approve change is waiting for its code." : undefined,
              }
            : null;
  const T = TYPE_LINE[type];

  // `?rule=<id>` (the pencil on the Firewall page): once the rule is on the page, scroll to it, mark
  // it and open its editor. `?new=1`: the tab's add dialog, once it can open. Each happens once, and
  // the parameter leaves the address so a reload does not open it again.
  const [linkRule, setLinkRule] = useState<string | null>(demo ? null : (initialRule ?? null));
  const [linkNew, setLinkNew] = useState(!demo && !!initialNew);
  const linked = linkRule ? shown.find((r) => r.type !== "email" && r.rule.id === linkRule) : undefined;
  // The always-on rules are no row of the table but its grey one, with nothing to edit.
  const linkedCore = !!linkRule && type === "messages" && !!content.snapshot?.core.some((c) => c.id === linkRule);
  useEffect(() => {
    if (!linkedCore) return;
    const frame = requestAnimationFrame(() => {
      setLinkRule(null);
      setParam(RULE_PARAM, "");
      document.querySelector<HTMLElement>('[data-testid="security-core"]')?.scrollIntoView({ block: "center" });
    });
    return () => cancelAnimationFrame(frame);
  }, [linkedCore, setParam]);
  useEffect(() => {
    if (!linked || linked.type === "email") return;
    const frame = requestAnimationFrame(() => {
      setLinkRule(null);
      setParam(RULE_PARAM, "");
      const el = document.querySelector<HTMLElement>(`[data-testid="${ROW_TESTID[linked.type]}${linked.rule.id}"]`);
      if (el) {
        el.scrollIntoView({ block: "center" });
        el.classList.add("ring-2", "ring-brand", "ring-inset");
        setTimeout(() => el.classList.remove("ring-2", "ring-brand", "ring-inset"), 3000);
      }
      if (linked.type === "messages" && canManage && !contentDisabled) setDialog({ kind: "messages", state: { rule: linked.rule, isNew: false } });
      else if (linked.type === "websites" && canManageWebsites && !linked.managed) setDialog({ kind: "websites", rule: linked.rule });
      else if (linked.type === "apps" && canManage && !appsDisabled) setDialog({ kind: "apps", rule: linked.rule });
      else if (linked.type === "auto" && canManage && !linked.rule.locked) setDialog({ kind: "auto", rule: linked.rule });
    });
    return () => cancelAnimationFrame(frame);
  }, [linked, canManage, canManageWebsites, contentDisabled, appsDisabled, setParam]);
  const addable = add !== null && !add.off;
  useEffect(() => {
    if (!linkNew || !addable || type === "email" || type === "settings") return;
    const frame = requestAnimationFrame(() => {
      setLinkNew(false);
      setParam(NEW_PARAM, "");
      setDialog(type === "messages" ? { kind: "messages", state: { picking: true } } : { kind: type, rule: null });
    });
    return () => cancelAnimationFrame(frame);
  }, [linkNew, addable, type, setParam]);

  return (
    <RulesOptionsContext.Provider value={rulesOptions}>
      <>
        <PageHead
          title="Security rules"
          sub="What your firewall lets your agents send, receive, reach and do."
          actions={
            <ActionMenu
              icon={Wrench}
              ariaLabel="Tools"
              data-testid="security-tools"
              items={[
                {
                  label: "Try a message",
                  sub: "See which rule would act",
                  icon: MessageSquare,
                  disabled: !content.snapshot,
                  onClick: () => setDialog({ kind: "try" }),
                  "data-testid": "security-try",
                },
                ...(canManage ? [{ label: "What was stopped", icon: ExternalLink, disabled: record.opening, onClick: () => void record.open() }] : []),
                "-",
                {
                  label: "Reload rules from firewall",
                  icon: RefreshCw,
                  disabled: content.loading || email.loading || (type === "apps" && appRules.loading),
                  onClick: () => {
                    void content.refresh();
                    void email.refresh();
                    if (type === "apps") void appRules.refresh();
                  },
                },
              ]}
            />
          }
        />

        <TypeTabs tabs={tabs} type={type} counts={counts} onSelect={setType} />

        <div className="mb-3 flex flex-wrap items-center gap-2.5" data-testid="security-bar">
          <p className="m-0 flex min-w-[220px] flex-1 flex-wrap items-center gap-x-3 gap-y-1 text-[13.5px] text-ink-2">
            {T.line}
            {T.code && codes && (type !== "auto" || autoOnFirewall) ? (
              <span className="inline-flex items-center gap-[5px] text-[12px]" data-testid="needs-code" data-tour="needs-code">
                <Lock className="h-3 w-3" />
                {T.code}
              </span>
            ) : null}
            {type === "auto" && autoKept === "old" ? (
              <span className="text-[12px]" data-testid="auto-kept-console">
                Kept by ControlClaw until your firewall updates
              </span>
            ) : null}
            {(type === "messages" ? content.loading : type === "email" ? email.loading : type === "apps" ? appRules.loading : type === "auto" ? autoFw.loading : false) ? (
              <span className="inline-flex items-center gap-[5px] text-[12px]" role="status">
                <RefreshCw className="h-3 w-3 animate-spin" />
                Reading your firewall…
              </span>
            ) : null}
          </p>
          {filtered && boxes.length > 0 && (
            <Select className="h-[38px] w-full sm:w-[12rem]" aria-label="Agent" value={boxOption?.id ?? ""} onChange={(e) => setBox(e.target.value)} data-testid="security-agent-filter">
              <option value="">All agents</option>
              {agents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
              {type === "websites" &&
                boxes
                  .filter((b) => b.kind === "brain")
                  .map((b) => (
                    <option key={b.id} value={b.id}>
                      {b.name}
                    </option>
                  ))}
            </Select>
          )}
          {add && T.add && (
            <Button variant="brand" className="h-[38px] gap-[7px] rounded-[10px] px-[15px]" onClick={add.onClick} disabled={!!add.off} title={add.off} data-testid="security-new-rule" data-tour="new-rule">
              <Plus className="h-[15px] w-[15px]" />
              {T.add}
            </Button>
          )}
          {add?.off && (
            <Hint className="basis-full" data-testid="security-add-off">
              {add.off}
            </Hint>
          )}
          {filtered && boxOption && (
            <Hint className="basis-full" data-testid="security-agent-hint">
              {boxOption.kind === "brain"
                ? "Its first rules are managed by ControlClaw: the brain can reach only the AI Gateway and the certificate authorities."
                : `The rules your firewall applies to ${boxOption.name}: its own, and those for all agents.`}
            </Hint>
          )}
        </div>

        {/* What the firewall said, and a change waiting for its code, show on every tab: a wrong code,
            "Saved on your firewall" or a What was stopped error from the wrench menu would otherwise
            land on a tab nobody is looking at, and until a change is confirmed or cancelled that
            type's controls stay off. */}
        {content.error && dialog?.kind !== "messages" && dialog?.kind !== "try" && <Alert>{content.error}</Alert>}
        {email.error && dialog?.kind !== "email" && <Alert>{email.error}</Alert>}
        {/* The Integrations rules' own error stays on their tab: a firewall from before them says so on every load. */}
        {appRules.error && type === "apps" && dialog?.kind !== "apps" && <Alert>{appRules.error}</Alert>}
        {content.notice && <Notice>{content.notice}</Notice>}
        {email.notice && <Notice>{email.notice}</Notice>}
        {appRules.notice && type === "apps" && <Notice>{appRules.notice}</Notice>}
        {autoFw.error && type === "auto" && dialog?.kind !== "auto" && <Alert>{autoFw.error}</Alert>}
        {autoFw.notice && type === "auto" && <Notice>{autoFw.notice}</Notice>}
        {codePanel("messages", "page")}
        {codePanel("email", "page")}
        {codePanel("apps", "page")}
        {codePanel("auto", "page")}

        {type === "messages" && (
          <>
            <div className="space-y-3 [&:not(:empty)]:mb-3">
              <ContentNotices
                snapshot={content.snapshot}
                aiOn={content.aiOn}
                canManage={canManage}
                disabled={contentDisabled}
                onAcceptAi={() => void content.send({ op: "ai" })}
                onOpenAi={openAiFirewall}
              />
            </div>
            <MessagesTable
              rows={shown}
              content={content}
              hits={hits}
              now={activity.now}
              canManage={canManage}
              disabled={contentDisabled}
              onToggle={(rule, on) => void content.send({ op: "put", rule: { ...rule, enabled: on } })}
              onEdit={(rule) => setDialog({ kind: "messages", state: { rule, isNew: false } })}
            />
            {content.snapshot && (
              <Hint className="mt-2.5 block">These catch mistakes, not someone working around them. A message written to fool the AI, or a picture of the text, can get through. WhatsApp messages can’t be read, only allowed or not.</Hint>
            )}
          </>
        )}

        {type === "email" && (
          <section id="email" className="scroll-mt-20" data-testid="security-group-email">
            {mailboxes.length === 0 ? (
              <Card>
                <EmptyLine>
                  Email rules apply once you add an{" "}
                  <Link href={routes.agentMailIntegration} className={linkClass}>
                    AgentMail inbox
                  </Link>{" "}
                  or{" "}
                  <Link href={routes.googleIntegration} className={linkClass}>
                    connect Gmail
                  </Link>
                  .
                </EmptyLine>
              </Card>
            ) : !email.snapshot ? (
              <Card>
                <EmptyLine>{email.loading ? "Reading your firewall…" : "Can’t show Email rules: your firewall didn’t answer. Start or update it, then reload."}</EmptyLine>
              </Card>
            ) : (
              <>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  {(["senders", "recipients"] as const).map((list) => {
                    const entries = shown.filter((r): r is Extract<RuleRow, { type: "email" }> => r.type === "email" && r.list === list);
                    const snapshot = email.snapshot!;
                    const heldTotal = snapshot.held.reduce((n, h) => n + h.count, 0);
                    return (
                      <Card key={list} className="overflow-hidden" data-testid={`email-card-${list}`}>
                        <div className="flex items-start gap-3 border-b border-line px-4 py-3.5">
                          <div className="grid min-w-0 flex-1 gap-0.5">
                            <b className="text-[14px] font-semibold text-ink">{list === "senders" ? "Can email your agents" : "Your agents can email"}</b>
                            <small className="text-[12.5px] text-ink-2">{list === "senders" ? "Incoming" : "Outgoing"}</small>
                          </div>
                          {canManage && (
                            <Button variant="outline" size="sm" className="h-8 gap-1" disabled={emailDisabled} onClick={() => setDialog({ kind: "email", list })} data-testid={`email-add-${list}`}>
                              <Plus className="h-[13px] w-[13px]" /> Add
                            </Button>
                          )}
                        </div>
                        {entries.length === 0 && <EmptyLine>Nobody yet.</EmptyLine>}
                        {entries.map((r) => (
                          <TRow key={r.key} cols="email" data-testid={`email-${r.list}-${r.entry.value}-${r.entry.mailbox ?? "all"}`}>
                            <Main title={r.name} sub={r.scope} mono />
                            <Acts>
                              {canManage && (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-8 w-8 p-0"
                                  aria-label={`Remove ${r.name}`}
                                  disabled={emailDisabled}
                                  onClick={() => void email.send({ action: list === "senders" ? "remove_sender" : "remove_recipient", entry: r.entry })}
                                >
                                  <X className="h-3.5 w-3.5" />
                                </Button>
                              )}
                            </Acts>
                          </TRow>
                        ))}
                        {list === "senders" ? (
                          <TRow cols="email" builtin data-testid="email-builtin-senders">
                            <Main builtin title="Everyone else" sub={heldTotal ? `${heldTotal} held back this week` : "No mail held back this week"} />
                            <Acts>
                              <ActionPill tone="block">Held back</ActionPill>
                            </Acts>
                          </TRow>
                        ) : (
                          <TRow cols="email" builtin data-testid="email-builtin-recipients">
                            <Main
                              builtin
                              title="Everyone else"
                              sub={
                                <>
                                  {EMAIL_MODES.find((m) => m.value === snapshot.rules.outbound.mode)?.help}
                                  {hits("email", "out") ? <span className="block" data-testid="email-out-hits">{outcomeLine("email", hits("email", "out")!.counts)} in 7 days</span> : null}
                                </>
                              }
                            />
                            <Acts>
                              <Select
                                className="h-8 w-auto min-w-[9.5rem] text-[13px]"
                                aria-label="Someone new"
                                value={snapshot.rules.outbound.mode}
                                disabled={emailDisabled}
                                onChange={(e) => void email.send({ action: "set_outbound", mode: e.target.value as OutboundMode })}
                                data-testid="email-mode"
                              >
                                {EMAIL_MODES.map((m) => (
                                  <option key={m.value} value={m.value}>
                                    {m.label}
                                  </option>
                                ))}
                              </Select>
                            </Acts>
                          </TRow>
                        )}
                      </Card>
                    );
                  })}
                </div>
                <div id="email-settings" className="mt-4 scroll-mt-20">
                <Card className="overflow-hidden" data-testid="email-rules">
                  <button
                    type="button"
                    aria-expanded={emailSettingsOpen}
                    onClick={() => setEmailSettingsOpen((v) => !v)}
                    className={cn("flex w-full items-start gap-3 px-4 py-3.5 text-left", emailSettingsOpen && "border-b border-line")}
                  >
                    <ChevronRight className={cn("mt-0.5 h-4 w-4 shrink-0 text-ink-2 transition-transform", emailSettingsOpen && "rotate-90")} />
                    <span className="grid min-w-0 flex-1 gap-0.5">
                      <b className="text-[14px] font-semibold text-ink">Email settings</b>
                      <small className="text-[12.5px] text-ink-2">{codes ? "Apply to every mailbox. Loosening one needs a code; a stricter one applies at once." : "Apply to every mailbox."}</small>
                    </span>
                  </button>
                  {emailSettingsOpen && <EmailSettingsPanel snapshot={email.snapshot} disabled={emailDisabled} onChange={(c) => void email.send(c)} />}
                </Card>
                </div>
              </>
            )}
          </section>
        )}

        {type === "websites" && (
          <Card className="overflow-hidden" data-testid="security-group-websites">
            {!canManageWebsites ? (
              <EmptyLine>Only owners and admins can see website rules. They are on Internet access.</EmptyLine>
            ) : (
              <>
                <TRow cols="websites" head>
                  <span>#</span>
                  <span>Site</span>
                  <span>Agent</span>
                  <span>Then</span>
                  <span />
                </TRow>
                {shown.map((r, i) =>
                  r.type === "websites" ? (
                    <WebsiteRow
                      key={r.key}
                      row={r}
                      hits={<Hits item={hits("websites", r.rule.id)} now={activity.now} type="websites" testId={`egress-rule-hits-${r.rule.id}`} />}
                      order={i + 1}
                      canManage={canManageWebsites}
                      onCycle={() => void web.cycle(r.rule)}
                      onToggle={(on) => void web.toggle(r.rule, on)}
                      onEdit={() => setDialog({ kind: "websites", rule: r.rule })}
                      onDelete={() => void web.remove(r.rule)}
                    />
                  ) : null,
                )}
                {/* The brain's own last rule blocks everything else, so the default row is not its. */}
                {!filter.brain && (
                  <TRow cols="websites" builtin data-testid="security-builtin-websites">
                    <Ord />
                    <Main builtin title="Every other site" />
                    <Cell>{boxOption?.name ?? "All agents"}</Cell>
                    <Cell
                      sub={
                        <>
                          {web.otherSites === "block" ? "only the rules above" : web.otherSites === "unknown" ? "" : "and logged"}
                          <Hits item={hits("websites", "default")} now={activity.now} type="websites" block />
                        </>
                      }
                    >
                      {web.otherSites === null ? (
                        <ActionPill tone="allow">Allow</ActionPill>
                      ) : (
                        <EveryOtherSiteSelect value={web.otherSites} disabled={!canManageWebsites} onChange={(e) => void web.setOtherSites(e)} />
                      )}
                    </Cell>
                    <Acts />
                  </TRow>
                )}
              </>
            )}
          </Card>
        )}

        {type === "apps" && (
          <>
            <div className="space-y-3 [&:not(:empty)]:mb-3">
              <IntegrationsAiNotice
                rules={appRules.snapshot?.rules ?? []}
                ai={content.snapshot?.ai}
                aiOn={content.aiOn}
                canManage={canManage}
                disabled={contentDisabled}
                onAcceptAi={() => void content.send({ op: "ai" })}
              />
            </div>
            <AppsTable
              rows={shown}
              snapshot={appRules.snapshot}
              loading={appRules.loading}
              canManage={canManage}
              disabled={appsDisabled}
              agentName={boxOption?.name ?? null}
              hits={(key) => <Hits item={hits("apps", key)} now={activity.now} type="apps" block={key === "default"} testId={`app-rule-hits-${key}`} />}
              onSend={(change) => void appRules.send(change)}
              onEdit={(rule) => setDialog({ kind: "apps", rule })}
            />
            {appRules.snapshot && (
              <Hint className="mt-2.5 block">
                Your firewall reads every call your agents make to these apps and MCP servers. A blocked action or tool isn’t offered to the agent. To check what is sent or what comes back, tick Integration actions on a Messages rule.
              </Hint>
            )}
          </>
        )}

        {type === "auto" && (
          <Card className="overflow-hidden" data-testid="security-group-auto">
            <TRow cols="auto" head>
              <span>#</span>
              <span>Rule</span>
              <span>Matches</span>
              <span>Then</span>
              <span />
            </TRow>
            {shown.map((r, i) =>
              r.type === "auto" ? (
                <AutoRow key={r.key} row={r} order={i + 1} hits={<Hits item={hits("auto", r.rule.id)} now={activity.now} type="auto" testId={`auto-rule-hits-${r.rule.id}`} />} canManage={canManage} disabled={autoFwDisabled} onCycle={() => void cycleAuto(r.rule)} onToggle={() => void toggleAuto(r.rule)} onEdit={() => setDialog({ kind: "auto", rule: r.rule })} />
              ) : null,
            )}
            <TRow cols="auto" builtin data-testid="security-builtin-auto">
              <Ord />
              <Main builtin title="Every other request" />
              <Cell>Any request</Cell>
              <Cell sub={<>comes to you<Hits item={hits("auto", "default")} now={activity.now} type="auto" block /></>}>
                <ActionPill tone="ask">Ask</ActionPill>
              </Cell>
              <Acts />
            </TRow>
          </Card>
        )}

        {/* The firewall's two AIs, org-wide, on their own tab. */}
        {type === "settings" &&
          (ai ? (
            <div data-testid="security-settings">
              <EgressAiSections initial={ai} page="security" />
            </div>
          ) : (
            <Card className="p-4 text-[13px] text-ink-2" data-testid="security-settings-none">
              The AI Firewall and AI Log Review run on your firewall. They show here once your organization has one.
            </Card>
          ))}

        {dialog?.kind === "try" && (
          <Dialog open onOpenChange={(open) => !open && closeDialog()}>
            <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-[520px]" data-testid="security-try-dialog">
              <DialogHeader>
                <DialogTitle>Try a message</DialogTitle>
                <DialogDescription>See which Messages rule would act. Nothing is sent or kept.</DialogDescription>
              </DialogHeader>
              <ContentTryBox names={names} demo={demo?.content?.tried} inDialog />
            </DialogContent>
          </Dialog>
        )}
        {dialog?.kind === "messages" && (
          <ContentRuleDialog
            state={dialog.state}
            names={names}
            disabled={contentDisabled}
            pendingPanel={codePanel("messages", "dialog")}
            error={content.error}
            tryDemo={demo?.content?.tried}
            onPick={(rule) => setDialog({ kind: "messages", state: { rule, isNew: true } })}
            onSave={(rule) => void content.send({ op: "put", rule })}
            onDelete={(id) => void content.send({ op: "delete", id })}
            onClose={closeDialog}
          />
        )}
        {dialog?.kind === "apps" && (
          <AppRuleDialog
            rule={dialog.rule}
            apps={appOptions}
            agents={agents}
            disabled={appsDisabled}
            pendingPanel={codePanel("apps", "dialog")}
            error={appRules.error}
            demoActions={demo?.apps?.actions}
            onSave={(rule) => void appRules.send({ op: "put", rule })}
            onDelete={(id) => void appRules.send({ op: "delete", id })}
            onClose={closeDialog}
          />
        )}
        {dialog?.kind === "email" && (
          <EmailEntryDialog
            initialList={dialog.list}
            mailboxes={mailboxes}
            disabled={emailDisabled}
            pendingPanel={codePanel("email", "dialog")}
            error={email.error}
            onAdd={(list, entry) => void email.send({ action: list === "senders" ? "add_sender" : "add_recipient", entry })}
            onClose={closeDialog}
          />
        )}
        <EgressRuleDialog
          open={dialog?.kind === "websites"}
          initial={dialog?.kind === "websites" && dialog.rule ? draftOf(dialog.rule) : null}
          vmOptions={boxes}
          exitConfigured={exit.configured}
          exitCountry={exit.country}
          exitSupportsCountry={exit.supportsCountry}
          busy={web.busy}
          onClose={closeDialog}
          onSubmit={async (draft) => {
            if (await web.submit(draft, dialog?.kind === "websites" ? dialog.rule : null)) setDialog(null);
          }}
        />
        {dialog?.kind === "auto" && (
          <SecurityRuleEditor
            mode={dialog.rule ? "edit" : "create"}
            initial={dialog.rule}
            vmOptions={agents}
            onClose={closeDialog}
            demo={!!demo && !autoOnFirewall}
            {...(autoOnFirewall
              ? {
                  ruleCount: autoFw.items.length,
                  onPropose: (change) => {
                    setDialog(null);
                    void autoFw.send(change);
                  },
                }
              : {})}
            onSaved={savedAuto}
            onDeleted={(id) => {
              setAutoRules((p) => p.filter((r) => r.id !== id));
              setDialog(null);
            }}
          />
        )}
      </>
    </RulesOptionsContext.Provider>
  );
}

/**
 * The underlined tabs. Six do not fit a phone, so there they wrap in rows of two, each underlined,
 * rather than a strip that hides Settings off the edge. Settings has no rows, so no count.
 */
function TypeTabs({ tabs, type, counts, onSelect }: { tabs: readonly SecurityTab[]; type: SecurityTab; counts: Record<RuleType, number>; onSelect: (t: SecurityTab) => void }) {
  return (
    <div role="tablist" aria-label="Type" className="mb-4 grid grid-cols-2 sm:flex sm:gap-1 sm:border-b sm:border-line" data-testid="security-tabs" data-tour="rule-types">
      {tabs.map((t) => {
        const Icon = TYPE_ICON[t];
        return (
          <button
            key={t}
            type="button"
            role="tab"
            aria-selected={type === t}
            onClick={() => onSelect(t)}
            data-testid={`security-type-${t}`}
            className={cn(
              "inline-flex h-10 min-w-0 items-center gap-[7px] px-3 text-[13.5px] font-medium whitespace-nowrap sm:-mb-px sm:shrink-0 sm:border-b-2",
              type === t ? "border-b-2 border-ink text-ink" : "border-b border-line text-ink-2 hover:text-ink sm:border-transparent",
            )}
          >
            <Icon className="h-[15px] w-[15px] shrink-0" />
            <span className="truncate">{SECURITY_TAB_LABELS[t]}</span>
            {t === "settings" ? null : (
              <span className="inline-grid h-[18px] min-w-5 place-items-center rounded-full bg-bg-2 px-1.5 text-[11.5px] text-ink-2 tabular-nums">{counts[t]}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}

function Alert({ children }: { children: ReactNode }) {
  return (
    <p role="alert" className="mb-3 rounded-[10px] border border-destructive/30 p-3 text-[12.5px] text-destructive">
      {children}
    </p>
  );
}

function Notice({ children }: { children: ReactNode }) {
  return (
    <p role="status" className="mb-3 text-[12.5px] text-ink-2">
      {children}
    </p>
  );
}

function MessagesTable({
  rows,
  content,
  hits,
  now,
  canManage,
  disabled,
  onToggle,
  onEdit,
}: {
  rows: RuleRow[];
  content: ReturnType<typeof useContentRules>;
  hits: (type: RuleType, key: string) => RuleActivityItem | undefined;
  now: number;
  canManage: boolean;
  disabled: boolean;
  onToggle: (rule: ContentRule, on: boolean) => void;
  onEdit: (rule: ContentRule) => void;
}) {
  const core = content.snapshot?.core[0];
  const coreHits = core ? (hits("messages", core.id)?.total ?? 0) : null;
  return (
    <Card className="overflow-hidden" data-testid="security-group-messages">
      <TRow cols="messages" head>
        <span>Rule</span>
        <span>Checks</span>
        <span>Then</span>
        <span />
      </TRow>
      {!content.snapshot ? (
        <EmptyLine>{content.loading ? "Reading your firewall…" : "Can’t show Messages rules: your firewall didn’t answer. Start or update it, then reload."}</EmptyLine>
      ) : rows.length === 0 ? (
        <EmptyLine>No rules yet.</EmptyLine>
      ) : (
        rows.map((r) =>
          r.type === "messages" ? (
            <TRow key={r.key} cols="messages" off={!r.rule.enabled} data-testid={`content-rule-${r.rule.id}`}>
              <Main
                title={r.name}
                sub={
                  r.rule.policy ? (
                    <>
                      <Sparkles className="mr-1 inline h-3 w-3 align-[-2px] text-brand" aria-label="Checked by the AI" />
                      {r.rule.policy}
                      {messagesExtras(r.rule) ? <span className="block">{messagesExtras(r.rule)}</span> : null}
                    </>
                  ) : (
                    r.detail
                  )
                }
              />
              <Cell sub={channelsShort(r.rule.channels)}>{r.rule.direction === "both" ? "To and from agents" : r.rule.direction === "in" ? "To agents" : "From agents"}</Cell>
              <Cell sub={<Hits item={hits("messages", r.rule.id)} now={now} type="messages" testId={`content-rule-hits-${r.rule.id}`} />}>
                <ActionPill tone={r.action.tone}>{MESSAGE_ACTION[r.rule.action]}</ActionPill>
              </Cell>
              <Acts>
                {canManage && (
                  <Button variant="ghost" size="sm" className="h-8 w-8 p-0" aria-label={`Edit ${r.name}`} disabled={disabled} onClick={() => onEdit(r.rule)}>
                    <Pencil className="h-3.5 w-3.5" />
                  </Button>
                )}
                <Switch checked={r.rule.enabled} disabled={disabled} aria-label={`${r.rule.enabled ? "Turn off" : "Turn on"} ${r.name}`} onCheckedChange={(on) => onToggle(r.rule, on)} />
              </Acts>
            </TRow>
          ) : null,
        )
      )}
      <TRow cols="messages" builtin data-testid="security-core">
        <Main
          builtin
          title={
            <>
              <Lock className="h-[13px] w-[13px]" /> Always on
            </>
          }
          sub={`Hidden instructions, and leaking passwords, keys or tokens${coreHits ? ` · ${coreHits} stopped in 7 days` : ""}`}
        />
        <Cell>Everything</Cell>
        <Cell>
          <ActionPill tone="block">Stop</ActionPill>
        </Cell>
        <Acts />
      </TRow>
    </Card>
  );
}

function WebsiteRow({
  row,
  hits,
  order,
  canManage,
  onCycle,
  onToggle,
  onEdit,
  onDelete,
}: {
  row: Extract<RuleRow, { type: "websites" }>;
  /** How often it matched in 7 days. */
  hits: ReactNode;
  order: number;
  canManage: boolean;
  onCycle: () => void;
  onToggle: (on: boolean) => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const { rule, managed } = row;
  const editable = canManage && !managed;
  // Not inspected is not one of allow, ask and block: it changes only in the editor.
  const cyclable = editable && rule.effect !== "tunnel";
  const match = [rule.matchMethod ? `${rule.matchMethod} ` : "", rule.matchDomain, rule.matchPort != null ? `:${rule.matchPort}` : "", rule.matchPath ?? ""].join("");
  const sub = rule.managed ? (
    <span data-testid={`egress-rule-managed-${rule.id}`}>
      <Lock className="mr-1 inline h-[11px] w-[11px] align-[-1px]" />
      {managedEgressReason(rule.managed)} · <span className="font-mono text-[12px]">{match}</span>
    </span>
  ) : managed ? (
    <>
      <Lock className="mr-1 inline h-[11px] w-[11px] align-[-1px]" />
      Managed by ControlClaw
    </>
  ) : (
    <>
      <span className="font-mono text-[12px]">{match}</span>
      {[rule.exit === "residential" ? "via home internet" : "", row.detail ?? ""].filter(Boolean).map((t) => ` · ${t}`)}
    </>
  );
  return (
    <TRow cols="websites" off={!rule.enabled} data-testid={`egress-rule-${rule.id}`}>
      <Ord>{order}</Ord>
      <Main
        title={
          <>
            {rule.name}
            {rule.aiReview ? <Sparkles className="h-3 w-3 text-brand" aria-label="Checked by the AI" /> : null}
            {rule.exit === "residential" ? <NotInspectedBadge data-testid={`egress-rule-not-inspected-${rule.id}`} /> : null}
          </>
        }
        sub={sub}
      />
      <Cell>{row.scope}</Cell>
      <Cell sub={hits}>
        <ActionPill
          tone={row.action.tone}
          onClick={cyclable ? onCycle : undefined}
          title={cyclable ? "Tap to switch between allow, ask and block" : undefined}
          testId={`egress-rule-effect-${rule.id}`}
        >
          {row.action.label}
        </ActionPill>
      </Cell>
      <Acts>
        {editable && (
          <>
            <Switch checked={rule.enabled} onCheckedChange={onToggle} aria-label={`Turn ${rule.name} ${rule.enabled ? "off" : "on"}`} />
            <ActionMenu
              data-testid={`egress-rule-menu-${rule.id}`}
              items={[{ label: "Edit rule…", icon: Pencil, onClick: onEdit }, "-", { label: "Delete rule", icon: Trash2, danger: true, onClick: onDelete }]}
            />
          </>
        )}
      </Acts>
    </TRow>
  );
}

function AutoRow({
  row,
  order,
  hits,
  canManage,
  disabled,
  onCycle,
  onToggle,
  onEdit,
}: {
  row: Extract<RuleRow, { type: "auto" }>;
  order: number;
  /** How often it matched in 7 days. */
  hits: ReactNode;
  canManage: boolean;
  /** A change on the firewall is waiting, or its rules are not read yet. */
  disabled?: boolean;
  onCycle: () => void;
  onToggle: () => void;
  onEdit: () => void;
}) {
  const { rule } = row;
  const editable = canManage && !rule.locked && !disabled;
  return (
    <TRow cols="auto" off={!rule.enabled} data-testid={`auto-rule-${rule.id}`}>
      <Ord>{order}</Ord>
      <Main title={row.name} sub={row.detail} />
      <Cell sub={row.scope}>{row.match}</Cell>
      <Cell sub={hits}>
        <ActionPill tone={row.action.tone} onClick={editable ? onCycle : undefined} title={editable ? "Tap to switch between allow, ask and block" : undefined} testId={`auto-rule-effect-${rule.id}`}>
          {row.action.label}
        </ActionPill>
      </Cell>
      <Acts>
        {editable && (
          <>
            <Button variant="ghost" size="sm" className="h-8 w-8 p-0" aria-label={`Edit ${row.name}`} onClick={onEdit}>
              <Pencil className="h-3.5 w-3.5" />
            </Button>
            <Switch checked={rule.enabled} onCheckedChange={onToggle} aria-label={`Turn ${row.name} ${rule.enabled ? "off" : "on"}`} />
          </>
        )}
      </Acts>
    </TRow>
  );
}
