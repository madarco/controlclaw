"use client";

import { useRulesOptions } from "./rules-context";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ArrowDown, ArrowUp, Pencil, Search, Trash2 } from "lucide-react";
import { Button } from "../../ui/button";
import { Checkbox } from "../../ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "../../ui/dialog";
import { Input } from "../../ui/input";
import { Textarea } from "../../ui/textarea";
import { Label } from "../../ui/label";
import { RadioGroup, RadioGroupItem } from "../../ui/radio-group";
import { Switch } from "../../ui/switch";
import { ActionMenu, Card, Hint, Select } from "../../kit/console-ui";
import { AppLogo } from "../integrations/AppLogo";
import type { EgressBoxOption } from "../../lib/egress-schema";
import { useApi } from "../../lib/api";
import { cn } from "../../lib/utils";
import { APP_RULE_TOOLS_MAX, PROXY_METHODS, RULE_SENTENCE_MAX, appRuleId, integrationLabel, isMcpService, toolPattern, type AppActionOption, type AppEffect, type AppMatch, type AppOperation, type AppOption, type AppRule, type AppRulesChange, type AppRulesSnapshot } from "../../lib/app-rules-schema";
import type { RuleRow } from "../../lib/security-rules-list";
import { Acts, ActionPill, Cell, EmptyLine, Main, Ord, TRow } from "./RulesTable";
import { useRulesChange, type RulesPending } from "./useRulesChange";
import type { ContentRulesSnapshot } from "../../lib/content-rules-schema";

/**
 * The Integrations rules on Security rules (docs/plans/connector-inspection.md §3,
 * docs/plans/mcp-inspection.md): allow, ask or block what an agent does through the organization's
 * app connections and in any MCP server. The rules live on the firewall, which reads them on every
 * call; this reads them and sends each edit as one change. A change that lets more through needs
 * the code the firewall sends; one that only narrows applies at once.
 */

export interface AppsDemo {
  snapshot: AppRulesSnapshot | null;
  pending?: RulesPending;
  error?: string;
  loading?: boolean;
  /** The actions the dialog offers per app, as the server would answer. */
  actions?: Record<string, AppActionOption[]>;
}

/**
 * The apps rules as the firewall holds them, and the change waiting for a code. Read the first time
 * `enabled` is true (the Apps tab is open), not with the page: reading asks the firewall, and a
 * firewall from before Apps rules answers with an error that belongs on that tab only.
 */
export function useAppRules(enabled: boolean, demo?: AppsDemo, onSaved?: () => void) {
  const api = useApi();
  const [snapshot, setSnapshot] = useState<AppRulesSnapshot | null>(demo?.snapshot ?? null);
  const [loading, setLoading] = useState(demo ? !!demo.loading : false);
  const read = useRef(false);
  const change = useRulesChange<AppRulesChange, AppRulesSnapshot>({ rpc: api.appRules, demo, onSnapshot: setSnapshot, onSaved });
  const { setError } = change;
  const refresh = useCallback(async () => {
    if (demo || !enabled) return;
    setLoading(true);
    setError("");
    try {
      setSnapshot(await api.appRules.get());
    } catch (e) {
      setError(e instanceof Error && /update/i.test(e.message) ? e.message : "Your firewall didn’t answer. Start or update it, then reload.");
    } finally {
      setLoading(false);
    }
  }, [demo, enabled, setError, api]);
  useEffect(() => {
    if (!enabled || read.current || demo) return;
    read.current = true;
    void refresh();
  }, [enabled, demo, refresh]);
  return { snapshot, loading, refresh, ...change };
}

const NO_ACTIONS: AppActionOption[] = [];
const NEXT: Record<AppEffect, AppEffect> = { allow: "ask", ask: "block", block: "allow" };
const OPERATION_LABELS: Record<AppOperation, string> = { read: "Reads", write: "Changes something", destructive: "Deletes something" };
const THEN_HELP: Record<AppEffect, string> = {
  allow: "The call goes through, and is recorded.",
  ask: "The call waits until a person approves it on Permission requests. The approval is for that one call.",
  block: "The call isn’t made. A blocked action or tool isn’t offered to the agent either.",
};

/** The Apps tab: one row per rule, in the firewall's order, and the grey row for every other call. */
export function AppsTable({
  rows,
  snapshot,
  loading,
  canManage,
  disabled,
  agentName,
  hits,
  onSend,
  onEdit,
}: {
  rows: RuleRow[];
  snapshot: AppRulesSnapshot | null;
  loading: boolean;
  canManage: boolean;
  disabled: boolean;
  /** Under the agent filter, that agent's name for the grey row. */
  agentName: string | null;
  /** How often a rule (or "default") matched in 7 days. */
  hits?: (key: string) => ReactNode;
  onSend: (change: AppRulesChange) => void;
  onEdit: (rule: AppRule) => void;
}) {
  const { codes } = useRulesOptions();
  const all = snapshot?.rules ?? [];
  return (
    <Card className="overflow-hidden" data-testid="security-group-apps">
      <TRow cols="apps" head>
        <span>#</span>
        <span>Integration</span>
        <span>Matches</span>
        <span>Agent</span>
        <span>Then</span>
        <span />
      </TRow>
      {!snapshot ? (
        <EmptyLine>{loading ? "Reading your firewall…" : "Can’t show Integrations rules: your firewall didn’t answer. Start or update it, then reload."}</EmptyLine>
      ) : snapshot.unreadable ? (
        <EmptyLine>Your firewall can’t read its Integrations rules, so it refuses every app and MCP tool call. To repair them, save any change{codes ? " with a code" : ""}.</EmptyLine>
      ) : (
        rows.map((r) => {
          if (r.type !== "apps") return null;
          const at = all.findIndex((x) => x.id === r.rule.id);
          const editable = canManage && !disabled;
          return (
            <TRow key={r.key} cols="apps" off={!r.rule.enabled} data-testid={`app-rule-${r.rule.id}`}>
              <Ord>{at + 1}</Ord>
              <Main
                title={r.name}
                sub={
                  <span className="inline-flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
                    {r.app ? <AppLogo name={r.app.name} home={r.app.home ?? undefined} service={r.app.service} icon={r.app.icon} size={15} /> : null}
                    {[r.app?.name ?? (r.rule.service ? integrationLabel(r.rule.service) : "Any integration"), r.detail].filter(Boolean).join(" · ")}
                  </span>
                }
              />
              <Cell>{r.match}</Cell>
              <Cell>{r.scope}</Cell>
              <Cell sub={hits?.(r.rule.id)}>
                <ActionPill
                  tone={r.action.tone}
                  onClick={editable ? () => onSend({ op: "put", rule: { ...r.rule, then: NEXT[r.rule.then] } }) : undefined}
                  title={editable ? "Tap to switch between allow, ask and block" : undefined}
                  testId={`app-rule-effect-${r.rule.id}`}
                >
                  {r.action.label}
                </ActionPill>
              </Cell>
              <Acts>
                {canManage && (
                  <>
                    <Switch checked={r.rule.enabled} disabled={disabled} aria-label={`Turn ${r.name} ${r.rule.enabled ? "off" : "on"}`} onCheckedChange={(on) => onSend({ op: "put", rule: { ...r.rule, enabled: on } })} />
                    <ActionMenu
                      data-testid={`app-rule-menu-${r.rule.id}`}
                      items={[
                        { label: "Edit rule…", icon: Pencil, disabled, onClick: () => onEdit(r.rule) },
                        { label: "Move up", icon: ArrowUp, disabled: disabled || at <= 0, onClick: () => onSend({ op: "move", id: r.rule.id, to: at - 1 }) },
                        { label: "Move down", icon: ArrowDown, disabled: disabled || at >= all.length - 1, onClick: () => onSend({ op: "move", id: r.rule.id, to: at + 1 }) },
                        "-",
                        { label: "Delete rule", icon: Trash2, danger: true, disabled, onClick: () => onSend({ op: "delete", id: r.rule.id }) },
                      ]}
                    />
                  </>
                )}
              </Acts>
            </TRow>
          );
        })
      )}
      <TRow cols="apps" builtin data-testid="security-builtin-apps">
        <Ord />
        <Main builtin title="Every other app or MCP tool call" />
        <Cell>Any action or tool</Cell>
        <Cell>{agentName ?? "All agents"}</Cell>
        <Cell sub={<>and recorded{hits?.("default")}</>}>
          <ActionPill tone="allow">Allow</ActionPill>
        </Cell>
        <Acts />
      </TRow>
    </Card>
  );
}

/**
 * The AI the Integrations rules use is the one the Messages rules accepted with a code (the pin): a
 * rule's sentence and the labels of MCP tools that say nothing are asked of it alone. Until one is
 * accepted, or when the AI Firewall uses another, say what that means here and offer the same
 * Accept with a code. Shown only when a rule depends on it: a sentence, or what a tool does.
 */
export function IntegrationsAiNotice({
  rules,
  ai,
  aiOn,
  canManage,
  disabled,
  onAcceptAi,
}: {
  rules: AppRule[];
  ai: ContentRulesSnapshot["ai"] | undefined;
  aiOn: boolean | null;
  canManage: boolean;
  disabled: boolean;
  onAcceptAi: () => void;
}) {
  // Only rules that can meet an MCP tool call: an app's catalog says what its actions do, but a rule
  // for one app with a sentence still needs the AI.
  const forMcp = (r: AppRule) => r.enabled && (r.service === null || isMcpService(r.service));
  const sentences = rules.some((r) => r.enabled && r.sentence);
  const kinds = rules.some((r) => forMcp(r) && r.match.kind === "operation");
  if (!ai || ai.matches || (!sentences && !kinds)) return null;
  const what = [sentences ? "rules with a sentence ask a person (Block rules still block)" : null, kinds ? "MCP tools whose server doesn’t say what they do count as deleting something" : null]
    .filter(Boolean)
    .join(", and ");
  if (aiOn === false)
    return (
      <p role="alert" className="rounded-[10px] border border-line px-3 py-2.5 text-[12.5px] text-ink" data-testid="apps-ai-pin">
        The AI Firewall is off, so {what}.
      </p>
    );
  return (
    <div role="alert" className="rounded-[10px] border border-line px-3 py-2.5 text-[12.5px] text-ink" data-testid="apps-ai-pin">
      {ai.current && !ai.allowed ? (
        <p>
          Your AI Firewall uses {ai.current.model}, which these rules don’t use: they ask only Jev, on the AI Gateway or the included AI tokens. Until then, {what}.
        </p>
      ) : (
        <>
          <p>
            {ai.pinned ? "Your AI Firewall now uses a different model or key from the one your rules accepted." : "Your rules haven’t accepted your AI Firewall’s model and key yet."} Until you accept it
            with a code, {what}. The same acceptance covers Messages rules.
          </p>
          {canManage && (
            <Button variant="outline" size="sm" className="mt-2 h-8" disabled={disabled} onClick={onAcceptAi}>
              Accept with a code
            </Button>
          )}
        </>
      )}
    </div>
  );
}

type MatchKind = AppMatch["kind"];
type Draft = {
  name: string;
  service: string;
  connectionId: string;
  kind: MatchKind;
  actions: string[];
  pattern: string;
  /** An MCP server's tools, picked, and typed as patterns. */
  tools: string[];
  toolPattern: string;
  sentence: string;
  operations: AppOperation[];
  method: string;
  path: string;
  agents: string[] | null;
  then: AppEffect;
  enabled: boolean;
};

function draftOf(rule: AppRule | null): Draft {
  const m = rule?.match;
  return {
    name: rule?.name ?? "",
    service: rule?.service ?? "",
    connectionId: rule?.connectionId ?? "",
    // A new rule names no app yet, and Some actions needs one.
    kind: m?.kind ?? "operation",
    actions: m?.kind === "actions" ? m.actions.filter((a) => !a.includes("*")) : [],
    pattern: m?.kind === "actions" ? m.actions.filter((a) => a.includes("*")).join(", ") : "",
    tools: m?.kind === "tools" ? m.tools.filter((t) => !t.includes("*")) : [],
    toolPattern: m?.kind === "tools" ? m.tools.filter((t) => t.includes("*")).join(", ") : "",
    sentence: rule?.sentence ?? "",
    operations: m?.kind === "operation" ? m.operations : ["destructive"],
    method: m?.kind === "proxy" ? (m.method ?? "") : "",
    path: m?.kind === "proxy" ? (m.path ?? "") : "",
    agents: rule && rule.agents.length ? rule.agents : null,
    then: rule?.then ?? "ask",
    enabled: rule?.enabled ?? true,
  };
}

/** The rule a draft makes, or why it cannot be saved yet. */
export function ruleOf(draft: Draft, id: string): AppRule | string {
  const name = draft.name.trim().replace(/\s+/g, " ");
  if (!name) return "Give the rule a name.";
  let match: AppMatch;
  if (draft.kind === "actions") {
    const patterns = draft.pattern.split(/[\s,]+/).filter(Boolean);
    const bad = patterns.find((p) => !/^[a-z0-9_*]+\.[A-Za-z0-9_.*-]+$/.test(p) || (draft.service && !p.startsWith(`${draft.service}.`) && !p.startsWith("*.")));
    if (bad) return `${bad} is not a pattern of this app's actions. Start it with ${draft.service || "the app"}., as in ${draft.service || "github"}.delete_*.`;
    const actions = [...draft.actions, ...patterns];
    if (!actions.length) return "Pick at least one action, or type a pattern such as github.delete_*.";
    match = { kind: "actions", actions };
  } else if (draft.kind === "tools") {
    if (draft.service && !isMcpService(draft.service)) return "Tools are an MCP server’s: pick the server, or Any integration.";
    const patterns = draft.toolPattern.split(/[\s,]+/).filter(Boolean);
    const bad = patterns.find((p) => !toolPattern.safeParse(p).success);
    if (bad) return `${bad} is not a tool's name or a pattern such as delete_*.`;
    const tools = [...new Set([...draft.tools, ...patterns])];
    if (!tools.length) return draft.service ? "Pick at least one tool, or type a pattern such as delete_*." : "Type a tool’s name or a pattern such as delete_*.";
    if (tools.length > APP_RULE_TOOLS_MAX) return `A rule can name at most ${APP_RULE_TOOLS_MAX} tools. Use a pattern such as delete_* for many.`;
    match = { kind: "tools", tools };
  } else if (draft.kind === "operation") {
    if (!draft.operations.length) return "Pick what the actions do.";
    match = { kind: "operation", operations: draft.operations };
  } else if (draft.kind === "proxy") {
    if (!draft.service) return "Direct API calls are for one app: pick it.";
    const path = draft.path.trim();
    if (path && (!path.startsWith("/") || /[\s?#\\]/.test(path) || path.split("/").some((seg) => seg === "." || seg === ".."))) return "The path starts with / and has no query, spaces or . and .. parts, as in /repos/.";
    match = { kind: "proxy", method: (draft.method || null) as (typeof PROXY_METHODS)[number] | null, path: path || null };
  } else match = { kind: "any" };
  if (draft.agents !== null && draft.agents.length === 0) return "Pick at least one agent.";
  const sentence = draft.sentence.trim().replace(/\s+/g, " ");
  if (sentence && sentence.length < 3) return "Write the rule as a sentence, or leave it empty.";
  if (sentence.length > RULE_SENTENCE_MAX) return `The sentence can be at most ${RULE_SENTENCE_MAX} characters.`;
  return {
    id,
    name,
    enabled: draft.enabled,
    agents: draft.agents ?? [],
    service: draft.service || null,
    connectionId: draft.service && draft.connectionId ? draft.connectionId : null,
    match,
    then: draft.then,
    ...(sentence ? { sentence } : {}),
  };
}

/** New and edit, for one Integrations rule. Saving sends one change; a looser one waits for the code. */
export function AppRuleDialog({
  rule,
  apps,
  agents,
  disabled,
  pendingPanel,
  error,
  demoActions,
  onSave,
  onDelete,
  onClose,
}: {
  rule: AppRule | null;
  apps: AppOption[];
  agents: EgressBoxOption[];
  disabled: boolean;
  pendingPanel: ReactNode;
  error: string;
  demoActions?: Record<string, AppActionOption[]>;
  onSave: (rule: AppRule) => void;
  onDelete: (id: string) => void;
  onClose: () => void;
}) {
  const api = useApi();
  const [draft, setDraft] = useState<Draft>(() => draftOf(rule));
  const [invalid, setInvalid] = useState("");
  /** Each app's actions, as the server answered them, by app. */
  const [loaded, setLoaded] = useState<Record<string, AppActionOption[]>>({});
  const [query, setQuery] = useState("");
  const set = (patch: Partial<Draft>) => {
    setInvalid("");
    setDraft((d) => ({ ...d, ...patch }));
  };
  /** MCP servers the agents use, as the firewall learned them; read once, when the dialog opens. */
  const [servers, setServers] = useState<AppOption[] | null>(demoActions ? [] : null);
  useEffect(() => {
    if (demoActions) return;
    let live = true;
    api.appRules
      .mcpServers()
      .then((list) => live && setServers(list))
      .catch(() => live && setServers([]));
    return () => {
      live = false;
    };
  }, [demoActions, api]);
  const options = useMemo(() => {
    const by = new Map(apps.map((a) => [a.service, a]));
    for (const s of servers ?? []) by.set(s.service, { ...by.get(s.service), ...s });
    return [...by.values()];
  }, [apps, servers]);
  const appList = options.filter((a) => !a.mcp);
  const serverList = options.filter((a) => a.mcp);
  const app = options.find((a) => a.service === draft.service) ?? null;
  const isMcp = isMcpService(draft.service);
  const [toolQuery, setToolQuery] = useState("");
  const shownTools = useMemo(() => {
    const list = app?.mcp?.tools ?? [];
    const q = toolQuery.trim().toLowerCase();
    const picked = [...draft.tools.filter((t) => !list.some((x) => x.name === t)).map((name) => ({ name, description: null, kind: null, kindBy: null })), ...list.filter((t) => draft.tools.includes(t.name))];
    const hits = (q ? list.filter((t) => t.name.toLowerCase().includes(q) || (t.description ?? "").toLowerCase().includes(q)) : list).filter((t) => !draft.tools.includes(t.name));
    return [...picked, ...hits.slice(0, 60)];
  }, [app, toolQuery, draft.tools]);

  const actions = draft.service ? (demoActions?.[draft.service] ?? (demoActions ? NO_ACTIONS : (loaded[draft.service] ?? null))) : null;
  useEffect(() => {
    const service = draft.service;
    if (!service || draft.kind !== "actions" || demoActions || loaded[service]) return;
    let live = true;
    api.appRules
      .actions({ service })
      .then((list) => live && setLoaded((m) => ({ ...m, [service]: list })))
      .catch(() => live && setLoaded((m) => ({ ...m, [service]: [] })));
    return () => {
      live = false;
    };
  }, [draft.service, draft.kind, demoActions, loaded, api]);

  const shownActions = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = actions ?? [];
    const hits = q ? list.filter((a) => a.name.toLowerCase().includes(q)) : list;
    // The picked ones first, so a long list does not hide them, and picked ones the catalog no
    // longer has, so they can be unticked.
    const gone: AppActionOption[] = draft.actions.filter((id) => !list.some((a) => a.id === id)).map((id) => ({ id, name: id.slice(id.indexOf(".") + 1), operation: "destructive" }));
    const picked = [...gone, ...list.filter((a) => draft.actions.includes(a.id))];
    return [...picked, ...hits.filter((a) => !draft.actions.includes(a.id)).slice(0, 60)];
  }, [actions, query, draft.actions]);

  const save = () => {
    const made = ruleOf(draft, rule?.id ?? appRuleId(draft.name));
    if (typeof made === "string") return setInvalid(made);
    onSave(made);
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-[560px]" data-testid="app-rule-dialog">
        <DialogHeader>
          <DialogTitle>{rule ? "Edit integration rule" : "New integration rule"}</DialogTitle>
          <DialogDescription>
            Your firewall reads every call an agent makes to an app or an MCP server. The first rule that matches decides. A change that lets more through needs a code.
          </DialogDescription>
        </DialogHeader>
        {(error || invalid) && (
          <p role="alert" className="rounded-[10px] border border-destructive/30 p-3 text-[12.5px] text-destructive">
            {invalid || error}
          </p>
        )}
        {pendingPanel}
        <form
          className="space-y-4"
          onSubmit={(ev) => {
            ev.preventDefault();
            save();
          }}
        >
          <div>
            <Label htmlFor="app-rule-name">Name</Label>
            <Input id="app-rule-name" className="mt-2 h-9 w-full min-w-0" placeholder="No deleting repositories" maxLength={80} value={draft.name} onChange={(e) => set({ name: e.target.value })} disabled={disabled} />
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="min-w-0">
              <Label htmlFor="app-rule-app">Integration</Label>
              <Select
                id="app-rule-app"
                className="mt-2 h-9 w-full"
                value={draft.service}
                disabled={disabled}
                onChange={(e) => {
                  const next = e.target.value;
                  const mcp = isMcpService(next);
                  // A kind the new integration does not have falls back to what the action does.
                  const fits = draft.kind === "any" || draft.kind === "operation" || (draft.kind === "tools" ? mcp || !next : !mcp && !!next && (draft.kind === "actions" || draft.kind === "proxy"));
                  set({ service: next, connectionId: "", actions: [], pattern: "", tools: [], toolPattern: "", kind: fits ? draft.kind : "operation" });
                }}
                data-testid="app-rule-app"
              >
                <option value="">Any integration</option>
                {/* A rule's integration that is no longer offered stays choosable, so editing it does not change it. */}
                {draft.service && !app ? <option value={draft.service}>{isMcp ? integrationLabel(draft.service) : `${draft.service} (not connected)`}</option> : null}
                {appList.length ? (
                  <optgroup label="Apps">
                    {appList.map((a) => (
                      <option key={a.service} value={a.service}>
                        {a.name}
                      </option>
                    ))}
                  </optgroup>
                ) : null}
                {serverList.length ? (
                  <optgroup label="MCP servers">
                    {serverList.map((a) => (
                      <option key={a.service} value={a.service}>
                        {a.name}
                        {a.mcp?.agents.length ? ` · ${a.mcp.agents.length} agent${a.mcp.agents.length === 1 ? "" : "s"}` : ""}
                      </option>
                    ))}
                  </optgroup>
                ) : null}
              </Select>
              {servers === null ? <p className="mt-1 text-[12px] text-ink-2">Reading the MCP servers your agents use…</p> : null}
            </div>
            {app && app.connections.length > 1 && (
              <div className="min-w-0">
                <Label htmlFor="app-rule-connection">Connection</Label>
                <Select id="app-rule-connection" className="mt-2 h-9 w-full" value={draft.connectionId} disabled={disabled} onChange={(e) => set({ connectionId: e.target.value })}>
                  <option value="">Any connection</option>
                  {app.connections.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.label}
                    </option>
                  ))}
                </Select>
              </div>
            )}
          </div>

          <fieldset>
            <legend className="text-[13px] font-medium text-ink">Matches</legend>
            <RadioGroup className="mt-2 gap-2" value={draft.kind} onValueChange={(v) => set({ kind: v as MatchKind })} disabled={disabled}>
              {(
                isMcp
                  ? ([
                      ["tools", "Some tools", "Pick them from the server’s list, or type a pattern."],
                      ["operation", "What the tool does", "Reads, changes or deletes, as the server says. When the server says nothing, the AI judges it. A tool nobody could label counts as deleting."],
                      ["any", "Every call", "Everything an agent does with this server’s tools."],
                    ] as const)
                  : ([
                      ["actions", "Some actions", "Pick them from the app’s list, or type a pattern."],
                      ["operation", "What the action does", draft.service ? "Reads, changes or deletes, as the app’s catalog says." : "Reads, changes or deletes: as an app’s catalog says, or as an MCP server or the AI says of a tool."],
                      ["proxy", "Direct API calls", "By method and path. Agents can’t make these yet. A rule here applies once they can."],
                      ...(draft.service ? [] : ([["tools", "Some MCP tools", "On any MCP server, by the tool’s name or a pattern."]] as const)),
                      ["any", "Every call", draft.service ? "Everything an agent does in this app." : "Everything an agent does in any app or MCP server."],
                    ] as const)
              ).map(([v, label, help]) => {
                const off = !draft.service && (v === "proxy" || v === "actions");
                return (
                  <label key={v} className={cn("flex items-start gap-2.5", off ? "opacity-55" : "cursor-pointer")}>
                    <RadioGroupItem value={v} className="mt-0.5" disabled={off} />
                    <span className="min-w-0">
                      <span className="block text-[13px] text-ink">{label}</span>
                      <span className="block text-[12px] text-ink-2">{off ? "Pick an app first." : help}</span>
                    </span>
                  </label>
                );
              })}
            </RadioGroup>
          </fieldset>

          {draft.kind === "actions" && draft.service && (
            <div className="space-y-2" data-testid="app-rule-actions">
              <div className="relative">
                <Search className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-ink-2" />
                <Input className="h-9 w-full min-w-0 pl-8" placeholder={`Search ${app?.name ?? draft.service} actions`} value={query} onChange={(e) => setQuery(e.target.value)} disabled={disabled} aria-label="Search actions" />
              </div>
              <div className="max-h-[220px] overflow-y-auto rounded-[10px] border border-line">
                {actions === null ? (
                  <p className="m-0 p-3 text-[12.5px] text-ink-2">Loading the app’s actions…</p>
                ) : shownActions.length === 0 ? (
                  <p className="m-0 p-3 text-[12.5px] text-ink-2">No action matches.</p>
                ) : (
                  shownActions.map((a) => (
                    <label key={a.id} className="flex cursor-pointer items-center gap-2.5 border-b border-line px-3 py-2 last:border-b-0">
                      <Checkbox checked={draft.actions.includes(a.id)} disabled={disabled} onCheckedChange={(v) => set({ actions: v === true ? [...draft.actions, a.id] : draft.actions.filter((x) => x !== a.id) })} />
                      <span className="min-w-0 flex-1 truncate font-mono text-[12.5px] text-ink">{a.name}</span>
                      <span className={cn("shrink-0 text-[11.5px]", a.operation === "destructive" ? "text-block-fg" : "text-ink-2")}>{OPERATION_LABELS[a.operation]}</span>
                    </label>
                  ))
                )}
              </div>
              <div>
                <Label htmlFor="app-rule-pattern" className="text-[12.5px]">
                  Or a pattern
                </Label>
                <Input id="app-rule-pattern" className="mt-1.5 h-9 w-full min-w-0 font-mono text-[12.5px]" placeholder={`${draft.service}.delete_*`} value={draft.pattern} onChange={(e) => set({ pattern: e.target.value })} disabled={disabled} />
              </div>
            </div>
          )}
          {draft.kind === "tools" && !isMcp && !draft.service && (
            <div data-testid="app-rule-tools">
              <Label htmlFor="app-rule-tool-pattern" className="text-[12.5px]">
                Tool names or patterns
              </Label>
              <Input id="app-rule-tool-pattern" className="mt-1.5 h-9 w-full min-w-0 font-mono text-[12.5px]" placeholder="delete_*, drop_table" value={draft.toolPattern} onChange={(e) => set({ toolPattern: e.target.value })} disabled={disabled} />
            </div>
          )}
          {draft.kind === "tools" && isMcp && (
            <div className="space-y-2" data-testid="app-rule-tools">
              <div className="relative">
                <Search className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-ink-2" />
                <Input className="h-9 w-full min-w-0 pl-8" placeholder="Search the server’s tools" value={toolQuery} onChange={(e) => setToolQuery(e.target.value)} disabled={disabled} aria-label="Search tools" />
              </div>
              <div className="max-h-[220px] overflow-y-auto rounded-[10px] border border-line">
                {shownTools.length === 0 ? (
                  <p className="m-0 p-3 text-[12.5px] text-ink-2">{app?.mcp?.tools.length ? "No tool matches." : "No agent has listed this server’s tools yet. Type a tool’s name or a pattern below."}</p>
                ) : (
                  shownTools.map((t) => (
                    <label key={t.name} className="flex cursor-pointer items-start gap-2.5 border-b border-line px-3 py-2 last:border-b-0">
                      <Checkbox className="mt-0.5" checked={draft.tools.includes(t.name)} disabled={disabled} onCheckedChange={(v) => set({ tools: v === true ? [...draft.tools, t.name] : draft.tools.filter((x) => x !== t.name) })} />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate font-mono text-[12.5px] text-ink">{t.name}</span>
                        {t.description ? <span className="block truncate text-[11.5px] text-ink-2">{t.description}</span> : null}
                      </span>
                      <span className={cn("shrink-0 text-[11.5px]", t.kind === "destructive" || !t.kind ? "text-block-fg" : "text-ink-2")} title={t.kindBy === "ai" ? "As the AI read the tool: the server said nothing" : undefined}>
                        {t.kind ? `${OPERATION_LABELS[t.kind]}${t.kindBy === "ai" ? " (AI)" : ""}` : "Not said"}
                      </span>
                    </label>
                  ))
                )}
              </div>
              <div>
                <Label htmlFor="app-rule-tool-pattern" className="text-[12.5px]">
                  Or a pattern
                </Label>
                <Input id="app-rule-tool-pattern" className="mt-1.5 h-9 w-full min-w-0 font-mono text-[12.5px]" placeholder="delete_*" value={draft.toolPattern} onChange={(e) => set({ toolPattern: e.target.value })} disabled={disabled} />
              </div>
            </div>
          )}
          {draft.kind === "operation" && (
            <div className="flex flex-wrap gap-x-5 gap-y-2" data-testid="app-rule-operations">
              {(["read", "write", "destructive"] as const).map((o) => (
                <label key={o} className="flex cursor-pointer items-center gap-2 text-[13px] text-ink">
                  <Checkbox checked={draft.operations.includes(o)} disabled={disabled} onCheckedChange={(v) => set({ operations: v === true ? [...draft.operations, o] : draft.operations.filter((x) => x !== o) })} />
                  {OPERATION_LABELS[o]}
                </label>
              ))}
            </div>
          )}
          {draft.kind === "proxy" && (
            <div className="grid grid-cols-[7rem_minmax(0,1fr)] gap-2">
              <Select aria-label="Method" className="h-9" value={draft.method} disabled={disabled} onChange={(e) => set({ method: e.target.value })}>
                <option value="">Any method</option>
                {PROXY_METHODS.map((m) => (
                  <option key={m}>{m}</option>
                ))}
              </Select>
              <Input aria-label="Path starts with" className="h-9 min-w-0 font-mono text-[12.5px]" placeholder="/repos/" value={draft.path} onChange={(e) => set({ path: e.target.value })} disabled={disabled} />
            </div>
          )}

          <fieldset>
            <legend className="text-[13px] font-medium text-ink">Agents</legend>
            <RadioGroup className="mt-2 gap-2" value={draft.agents === null ? "all" : "some"} onValueChange={(v) => set({ agents: v === "all" ? null : (draft.agents ?? []) })} disabled={disabled}>
              <label className="flex cursor-pointer items-center gap-2.5 text-[13px] text-ink">
                <RadioGroupItem value="all" /> All agents
              </label>
              <label className="flex cursor-pointer items-center gap-2.5 text-[13px] text-ink">
                <RadioGroupItem value="some" /> Some agents
              </label>
            </RadioGroup>
            {draft.agents !== null && (
              <div className="mt-2 grid grid-cols-1 gap-2 pl-6 sm:grid-cols-2">
                {agents.map((a) => (
                  <label key={a.id} className="flex min-w-0 cursor-pointer items-center gap-2 text-[13px] text-ink">
                    <Checkbox checked={draft.agents!.includes(a.id)} disabled={disabled} onCheckedChange={(v) => set({ agents: v === true ? [...draft.agents!, a.id] : draft.agents!.filter((x) => x !== a.id) })} />
                    <span className="truncate">{a.name}</span>
                  </label>
                ))}
              </div>
            )}
          </fieldset>

          <fieldset>
            <legend className="text-[13px] font-medium text-ink">Then</legend>
            <RadioGroup className="mt-2 gap-2" value={draft.then} onValueChange={(v) => set({ then: v as AppEffect })} disabled={disabled}>
              {(["allow", "ask", "block"] as const).map((t) => (
                <label key={t} className="flex cursor-pointer items-start gap-2.5">
                  <RadioGroupItem value={t} className="mt-0.5" />
                  <span className="min-w-0">
                    <span className="block text-[13px] text-ink">{t === "allow" ? "Allow" : t === "ask" ? "Ask a person" : "Block"}</span>
                    <span className="block text-[12px] text-ink-2">{THEN_HELP[t]}</span>
                  </span>
                </label>
              ))}
            </RadioGroup>
          </fieldset>
          <div>
            <Label htmlFor="app-rule-sentence">The rule, in one sentence (optional)</Label>
            <Textarea
              id="app-rule-sentence"
              className="mt-2 min-h-[64px] w-full min-w-0 text-[13px]"
              placeholder="Only writes to repositories of the acme organization"
              maxLength={RULE_SENTENCE_MAX}
              value={draft.sentence}
              onChange={(e) => set({ sentence: e.target.value })}
              disabled={disabled}
              data-testid="app-rule-sentence"
            />
            <p className="mt-1.5 text-[12px] text-ink-2">
              With a sentence, the firewall’s AI reads each matching call and its arguments. The rule acts only on the calls that fit. Each check
              counts against the AI calls a day. When the AI can’t answer, an Allow rule asks a person instead, and a Block rule still blocks.
            </p>
          </div>
          {rule && (
            <label className="flex items-center gap-2.5 text-[13px] text-ink">
              <Switch checked={draft.enabled} onCheckedChange={(on) => set({ enabled: on })} disabled={disabled} /> On
            </label>
          )}
          <Hint className="block">
            To check what an agent sends to an app or MCP server, or what comes back, add a Messages rule. Tick Integration actions in it. A Websites rule still decides
            first whether the agent may reach a server at all.
          </Hint>
          <div className="flex flex-wrap gap-2">
            <Button type="submit" disabled={disabled} data-testid="app-rule-save">
              Save
            </Button>
            <Button type="button" variant="outline" onClick={onClose} disabled={disabled}>
              Cancel
            </Button>
            {rule && (
              <Button type="button" variant="ghost" className="ml-auto text-destructive" onClick={() => onDelete(rule.id)} disabled={disabled}>
                Delete
              </Button>
            )}
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
