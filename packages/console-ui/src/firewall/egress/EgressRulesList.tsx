"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Ban, Bot, Boxes, Brain, Check, Globe, Lock, Pencil, Server, ShieldQuestion, Sparkles, Trash2, Unlock } from "lucide-react";
import { Switch } from "../../ui/switch";
import {
  ActionMenu,
  Badge,
  Card,
  Chip,
  Chips,
  EmptyState,
  Hint,
  RuleRow,
  Sec,
  Select,
} from "../../kit/console-ui";
import { cn } from "../../lib/utils";
import type { EgressBoxOption, EgressEffect, EgressRuleListItem } from "../../lib/egress-schema";
import { countryLabel } from "../../lib/countries";
import { draftOf, EgressRuleDialog, type RuleDraft } from "./EgressRuleDialog";
import { useEgressRules, type EgressRuleSource } from "./useEgressRules";
import { NotInspectedBadge } from "./NotInspected";

const EFFECT_META: Record<EgressEffect, { label: string; icon: typeof Check; chip: string }> = {
  allow: { label: "Allow", icon: Check, chip: "border-allow-border bg-allow-soft text-allow-fg" },
  require_permission: { label: "Ask", icon: ShieldQuestion, chip: "border-ask-border bg-ask-soft text-ask-fg" },
  block: { label: "Block", icon: Ban, chip: "border-block-border bg-block-soft text-block-fg" },
  tunnel: { label: "Not inspected", icon: Unlock, chip: "border-line bg-bg text-ink-2" },
};

/** The query parameter that remembers which box the list is filtered to, so the view can be linked. */
const BOX_PARAM = "box";

interface Props {
  /** Where the rules are saved. */
  source: EgressRuleSource;
  /** A demo page: changes stay on the page. */
  demo?: boolean;
  initial: EgressRuleListItem[];
  /** The boxes a rule can be scoped to: every agent, and the brain if there is one. */
  vmOptions: EgressBoxOption[];
  canManage: boolean;
  /** Whether the org has a residential exit at all; without one the choice is not offered. */
  exitConfigured: boolean;
  /** The control plane has an exit at all; without one (the firewall's panel before its exit) there are no residential words. */
  exitAvailable?: boolean;
  /** The org default country, so a rule that does not override it can say what it inherits. */
  exitCountry?: string | null;
  /** False when the exit's credential has nowhere to put a country; the override is then hidden. */
  exitSupportsCountry?: boolean;
  /** Opens the new-rule dialog; the page header owns the button that sets it. */
  creating: boolean;
  onCreatingChange: (creating: boolean) => void;
}

/**
 * The site rules: a filter by box, a legend of counts, then one row per rule.
 *
 * Every row says which box it is for ("All boxes", or one agent or the brain). Filtered to one box,
 * the list shows what the firewall actually reads for it: that box's own rules and the ones for all
 * boxes, in the firewall's order. The brain's own rules show only when the list is filtered to the
 * brain. ControlClaw keeps them, so they are shown read-only.
 *
 * A row carries what the rule *is* — the site, what happens, and whether it is inspected — and
 * the two things done to it often: cycling the action, and turning it off. Everything else opens
 * the same dialog that created it, so there is one place a rule is written rather than six
 * controls squeezed into a row.
 */
export function EgressRulesList({
  source,
  demo = false,
  initial,
  vmOptions,
  canManage,
  exitConfigured,
  exitAvailable = true,
  exitCountry = null,
  exitSupportsCountry = false,
  creating,
  onCreatingChange,
}: Props) {
  const { items, busy, isManaged, cycle: handleCycle, toggle: handleToggle, remove: handleDelete, submit } = useEgressRules(source, initial, vmOptions, canManage, demo);
  const [editing, setEditing] = useState<EgressRuleListItem | null>(null);
  const [box, setBoxState] = useState("");
  const boxOption = vmOptions.find((v) => v.id === box) ?? null;

  // Read once on mount rather than through `useSearchParams`, which would need a Suspense boundary
  // around every page that renders this list. A box that is no longer listed falls back to all.
  useEffect(() => {
    const wanted = new URLSearchParams(window.location.search).get(BOX_PARAM);
    if (wanted && vmOptions.some((v) => v.id === wanted)) setBoxState(wanted);
  }, [vmOptions]);

  const setBox = useCallback((id: string) => {
    setBoxState(id);
    const url = new URL(window.location.href);
    if (id) url.searchParams.set(BOX_PARAM, id);
    else url.searchParams.delete(BOX_PARAM);
    window.history.replaceState(window.history.state, "", url);
  }, []);

  // Filtered: what the firewall reads for that box, in its order, the brain's own rules included.
  // Unfiltered: everything except the brain's own rules, which only show when the brain is picked.
  const main = useMemo(
    () => (box ? items.filter((r) => r.vmId === null || r.vmId === box) : items.filter((r) => !isManaged(r))),
    [box, items, isManaged],
  );

  const counts = useMemo(() => {
    const c = { allow: 0, require_permission: 0, block: 0, tunnel: 0, residential: 0 };
    for (const r of main) {
      if (!r.enabled) continue;
      c[r.effect] += 1;
      if (r.exit === "residential") c.residential += 1;
    }
    return c;
  }, [main]);

  /** One submit path for both the new-rule and the edit dialog. */
  const handleSubmit = useCallback(
    async (draft: RuleDraft) => {
      if (!(await submit(draft, editing))) return;
      if (editing) setEditing(null);
      else onCreatingChange(false);
    },
    [editing, onCreatingChange, submit],
  );

  return (
    <Sec
      id="site-rules"
      title="Site rules"
      sub={exitAvailable ? "Allow, ask or block sites, and route them through a residential IP" : "Allow, ask or block sites"}
    >
      {vmOptions.length > 0 ? (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
          <label htmlFor="egress-box-filter" className="text-[13px] font-medium text-ink">
            Show
          </label>
          <Select
            id="egress-box-filter"
            className="w-auto max-w-full min-w-[12rem]"
            value={box}
            onChange={(e) => setBox(e.target.value)}
            data-testid="egress-box-filter"
          >
            <option value="">All rules</option>
            {vmOptions.some((v) => v.kind === "agent") ? (
              <optgroup label="Agents">
                {vmOptions
                  .filter((v) => v.kind === "agent")
                  .map((v) => (
                    <option key={v.id} value={v.id}>
                      {v.name}
                    </option>
                  ))}
              </optgroup>
            ) : null}
            {vmOptions
              .filter((v) => v.kind === "brain")
              .map((v) => (
                <option key={v.id} value={v.id}>
                  {v.name}
                </option>
              ))}
          </Select>
          {boxOption ? (
            <Hint className="basis-full" data-testid="egress-box-filter-hint">
              {boxOption.kind === "brain"
                ? "The brain’s first rules are managed by ControlClaw: it can reach only the AI Gateway and the certificate authorities."
                : `What the firewall reads for ${boxOption.name}, in order: its own rules and the ones for all boxes.`}
            </Hint>
          ) : null}
        </div>
      ) : null}

      {/* Counts as chips rather than five stat cards: they are a legend for the list under them,
          not five numbers worth a card each. With no rules there is nothing to count. */}
      {main.length > 0 ? (
      <Chips>
        <Chip className="border-allow-border bg-allow-soft text-allow-fg">Allow {counts.allow}</Chip>
        <Chip className="border-ask-border bg-ask-soft text-ask-fg">Ask {counts.require_permission}</Chip>
        <Chip className="border-block-border bg-block-soft text-block-fg">Block {counts.block}</Chip>
        <Chip>Not inspected {counts.tunnel}</Chip>
        {exitAvailable ? <Chip className="border-brand-border bg-brand-soft text-brand-soft-fg">Via home internet {counts.residential}</Chip> : null}
      </Chips>
      ) : null}

      <Card data-testid="egress-rules">
        {main.length === 0 ? (
          <EmptyState icon={Globe}>
            {box ? "No rules for this box · every site is allowed and logged" : "No rules yet · every site is allowed and logged"}
          </EmptyState>
        ) : (
          main.map((rule) => (
            <Row
              key={rule.id}
              rule={rule}
              canManage={canManage}
              managed={isManaged(rule)}
              vmOptions={vmOptions}
              exitCountry={exitCountry}
              onCycle={handleCycle}
              onToggle={handleToggle}
              onDelete={handleDelete}
              onEdit={() => setEditing(rule)}
            />
          ))
        )}
      </Card>

      <EgressRuleDialog
        open={creating || editing !== null}
        initial={editing ? draftOf(editing) : null}
        vmOptions={vmOptions}
        exitConfigured={exitConfigured}
        exitCountry={exitCountry}
        exitSupportsCountry={exitSupportsCountry}
        busy={busy}
        onClose={() => {
          setEditing(null);
          onCreatingChange(false);
        }}
        onSubmit={handleSubmit}
      />
    </Sec>
  );
}

/** Which box a rule is for, as the chip on its row says it. */
function ScopeChip({ rule, vmOptions }: { rule: EgressRuleListItem; vmOptions: EgressBoxOption[] }) {
  const target = rule.vmId ? vmOptions.find((v) => v.id === rule.vmId) : null;
  // A scoped rule always names a box. One that is not offered any more still says it is scoped.
  const [Icon, label] = !rule.vmId
    ? [Boxes, "All boxes"]
    : target
      ? [target.kind === "brain" ? Brain : Bot, target.name]
      : [Server, "One box"];
  return (
    <Chip className="h-[22px] max-w-full gap-1 rounded-[6px] px-[7px] text-[11.5px] font-medium">
      <Icon className="h-[12px] w-[12px] shrink-0" />
      <span className="truncate" data-testid={`egress-rule-scope-${rule.id}`}>
        {label}
      </span>
    </Chip>
  );
}

function Row({
  rule,
  canManage,
  managed,
  vmOptions,
  exitCountry,
  onCycle,
  onToggle,
  onDelete,
  onEdit,
}: {
  rule: EgressRuleListItem;
  canManage: boolean;
  /** One of the brain's own rules: shown, never changed. */
  managed: boolean;
  vmOptions: EgressBoxOption[];
  exitCountry: string | null;
  onCycle: (r: EgressRuleListItem) => void;
  onToggle: (r: EgressRuleListItem, enabled: boolean) => void;
  onDelete: (r: EgressRuleListItem) => void;
  onEdit: () => void;
}) {
  const meta = EFFECT_META[rule.effect];
  const Icon = meta.icon;
  const editable = canManage && !managed;

  // What the rule matches, then what it gives up. One line: the row is a summary, and the dialog
  // behind it is where a rule is actually read.
  const match = [
    rule.matchMethod ? `${rule.matchMethod} ` : "",
    rule.matchDomain,
    rule.matchPort != null ? `:${rule.matchPort}` : "",
    rule.matchPath ?? "",
  ].join("");
  const facts = [
    rule.exit === "residential"
      ? `Via home internet${rule.exitCountry ? ` in ${countryLabel(rule.exitCountry)}` : exitCountry ? ` in ${countryLabel(exitCountry)}` : ""}`
      : rule.effect === "tunnel"
        ? "Not inspected"
        : "Inspected and logged",
    `Order ${rule.priority}`,
  ].filter(Boolean);

  return (
    <RuleRow
      faded={!rule.enabled}
      data-testid={`egress-rule-${rule.id}`}
      name={
        <>
          <span className="font-mono text-[13px] font-medium break-all">{rule.name}</span>
          <ScopeChip rule={rule} vmOptions={vmOptions} />
          {rule.exit === "residential" ? <NotInspectedBadge data-testid={`egress-rule-not-inspected-${rule.id}`} /> : null}
          {rule.aiReview ? (
            <Badge tone="brand" icon={Sparkles} data-testid={`egress-rule-ai-${rule.id}`}>
              {rule.effect === "require_permission" ? "AI approves" : "Checked by the AI"}
            </Badge>
          ) : null}
        </>
      }
      cond={
        <>
          <span className="font-mono break-all">{match}</span> · {facts.join(" · ")}
          {rule.aiReview && rule.aiPolicy ? (
            <span className="mt-0.5 block truncate text-brand-soft-fg" title={rule.aiPolicy} data-testid={`egress-rule-policy-${rule.id}`}>
              {rule.effect === "require_permission" ? "AI may approve" : "What the AI looks for"}: {rule.aiPolicy}
            </span>
          ) : null}
        </>
      }
    >
      {managed ? (
        <span
          className="inline-flex items-center gap-1 text-[12px] text-ink-2"
          title="Managed by ControlClaw"
          data-testid={`egress-rule-managed-${rule.id}`}
        >
          <Lock className="h-[12px] w-[12px]" />
          Managed
        </span>
      ) : null}
      <button
        type="button"
        onClick={() => onCycle(rule)}
        disabled={!editable}
        title={managed ? "Managed by ControlClaw" : canManage ? "Tap to switch between allow, ask and block" : "Read-only"}
        className={cn(
          "inline-flex h-[28px] items-center gap-1.5 rounded-full border px-3 text-[12px] font-semibold transition-colors",
          meta.chip,
          editable ? "cursor-pointer hover:opacity-80" : managed ? "cursor-default" : "cursor-not-allowed",
        )}
        data-testid={`egress-rule-effect-${rule.id}`}
      >
        <Icon className="h-[13px] w-[13px]" />
        {meta.label}
      </button>
      {editable ? (
        <>
          <Switch
            checked={rule.enabled}
            onCheckedChange={(v) => onToggle(rule, v)}
            aria-label={`Turn ${rule.name} ${rule.enabled ? "off" : "on"}`}
          />
          <ActionMenu
            data-testid={`egress-rule-menu-${rule.id}`}
            items={[
              { label: "Edit rule…", icon: Pencil, onClick: onEdit },
              "-",
              { label: "Delete rule", icon: Trash2, danger: true, onClick: () => onDelete(rule) },
            ]}
          />
        </>
      ) : null}
    </RuleRow>
  );
}
