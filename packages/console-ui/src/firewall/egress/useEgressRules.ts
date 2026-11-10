"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import type { z } from "zod";
import {
  aiReviewAllowed,
  NEXT_EGRESS_EFFECT,
  type createEgressRuleInputSchema,
  type EgressBoxOption,
  type EgressEffect,
  type EgressRuleListItem,
  type updateEgressRuleInputSchema,
} from "../../lib/egress-schema";
import { isBrainManagedRule } from "../../lib/brain-rules";
import type { RuleDraft } from "./EgressRuleDialog";

/**
 * Where the site rules are saved: the console passes its oRPC procedures, the firewall's own panel
 * its REST API. Each call returns the rule as stored, or throws with a message a person can read.
 */
export interface EgressRuleSource {
  create(input: z.input<typeof createEgressRuleInputSchema>): Promise<EgressRuleListItem>;
  update(input: z.input<typeof updateEgressRuleInputSchema>): Promise<EgressRuleListItem>;
  remove(input: { id: string }): Promise<unknown>;
  cycle(input: { id: string }): Promise<EgressRuleListItem>;
  /**
   * "Every other site", where a person can choose it (the firewall's own panel). Without it, every
   * other site is allowed and logged, and blocking them is a `*` rule of one's own.
   */
  everyOtherSite?: {
    get(): Promise<EveryOtherSite>;
    set(effect: EveryOtherSite): Promise<EveryOtherSite>;
  };
}

/** What happens to a site no rule names. */
export type EveryOtherSite = "allow" | "block";

/**
 * Effect when the quick-cycle chip is clicked. `tunnel` is never reached by cycling; clicking a
 * tunnel rule cycles it back to the safe default (mirrors the server).
 */
export function nextEffect(e: EgressEffect): EgressEffect {
  return e === "tunnel" ? "allow" : NEXT_EGRESS_EFFECT[e];
}

/** Rules are read in priority order, oldest first inside a priority — the same as the page's query. */
function byOrder(a: EgressRuleListItem, b: EgressRuleListItem) {
  return a.priority - b.priority || a.createdAt.localeCompare(b.createdAt);
}

/**
 * The site rules and what is done to them: cycling the action, turning one off, deleting, and the
 * one submit path of the new-rule and edit dialog. Internet access and Security rules both list
 * them through this.
 */
export function useEgressRules(
  source: EgressRuleSource,
  initial: EgressRuleListItem[],
  vmOptions: EgressBoxOption[],
  canManage: boolean,
  demo = false,
) {
  const [items, setItems] = useState(initial);
  const [busy, setBusy] = useState(false);
  const brainIds = useMemo(() => new Set(vmOptions.filter((v) => v.kind === "brain").map((v) => v.id)), [vmOptions]);
  /** One of the brain's own rules: listed only when the brain is picked. */
  const isBrain = useCallback((rule: EgressRuleListItem) => isBrainManagedRule(rule, brainIds), [brainIds]);
  /** Kept by ControlClaw (the brain's, or one added for a provider or a channel): shown, never changed. */
  const isManaged = useCallback((rule: EgressRuleListItem) => !!rule.managed || isBrain(rule), [isBrain]);

  // Unknown until the firewall says: a page that guessed Allow could hide a firewall that blocks.
  const [otherSites, setOtherSitesState] = useState<EveryOtherSite | "unknown">("unknown");
  const otherSitesSource = source.everyOtherSite;
  useEffect(() => {
    if (demo || !otherSitesSource) return;
    let live = true;
    otherSitesSource.get().then(
      (e) => live && setOtherSitesState(e),
      () => live && toast.error("Couldn’t read what happens to every other site. Reload to try again."),
    );
    return () => {
      live = false;
    };
  }, [otherSitesSource, demo]);
  const setOtherSites = useCallback(
    async (effect: EveryOtherSite) => {
      if (demo || !canManage || !otherSitesSource || otherSites === "unknown") return;
      const before = otherSites;
      setOtherSitesState(effect);
      try {
        setOtherSitesState(await otherSitesSource.set(effect));
      } catch {
        setOtherSitesState(before);
        toast.error("Couldn’t change what happens to every other site. Try again.");
      }
    },
    [demo, canManage, otherSitesSource, otherSites],
  );

  const cycle = useCallback(
    async (rule: EgressRuleListItem) => {
      if (demo || !canManage || isManaged(rule)) return;
      const next = nextEffect(rule.effect);
      setItems((p) => p.map((r) => (r.id === rule.id ? { ...r, effect: next } : r)));
      try {
        const row = await source.cycle({ id: rule.id });
        setItems((p) => p.map((r) => (r.id === rule.id ? row : r)));
      } catch {
        setItems((p) => p.map((r) => (r.id === rule.id ? { ...r, effect: rule.effect } : r)));
        toast.error("Couldn’t change what this rule does. Try again.");
      }
    },
    [source, canManage, isManaged, demo],
  );

  const toggle = useCallback(
    async (rule: EgressRuleListItem, enabled: boolean) => {
      if (demo || !canManage || isManaged(rule)) return;
      setItems((p) => p.map((r) => (r.id === rule.id ? { ...r, enabled } : r)));
      try {
        await source.update({ id: rule.id, enabled });
      } catch {
        setItems((p) => p.map((r) => (r.id === rule.id ? { ...r, enabled: !enabled } : r)));
        toast.error("Couldn’t turn the rule on or off. Try again.");
      }
    },
    [source, canManage, isManaged, demo],
  );

  const remove = useCallback(
    async (rule: EgressRuleListItem) => {
      if (demo || !canManage || isManaged(rule)) return;
      const prev = items;
      setItems((p) => p.filter((r) => r.id !== rule.id));
      try {
        await source.remove({ id: rule.id });
      } catch {
        setItems(prev);
        toast.error("Couldn’t delete the rule. Try again.");
      }
    },
    [source, canManage, isManaged, items, demo],
  );

  /** Creates the rule, or updates `editing`. True when it was saved. */
  const submit = useCallback(async (draft: RuleDraft, editing: EgressRuleListItem | null): Promise<boolean> => {
    if (demo) return true;
    setBusy(true);
    // The port only applies to tunnel rules (the field is hidden otherwise); never persist a
    // port the operator cannot see on a non-tunnel rule.
    const port = draft.effect === "tunnel" && draft.matchPort.trim() ? Number(draft.matchPort) : null;
    // `0` is a real priority — the first rule read — and so is an empty field, which
    // `Number("")` turns into 0. Neither may be guessed at: a cleared Order keeps the order the
    // rule already had, and a new rule falls back to the default.
    const typed = draft.priority.trim();
    const parsed = Number(typed);
    const priority = typed && Number.isFinite(parsed) ? parsed : (editing?.priority ?? 1000);
    const payload = {
      name: draft.name.trim(),
      matchDomain: draft.matchDomain.trim(),
      effect: draft.effect,
      matchPort: port,
      priority,
      vmId: draft.vmId || null,
      exit: draft.exit,
      // Only when the rule is actually residential. Sending `null` on a firewall rule would
      // clear a country the dialog never showed, so a rule put back on the firewall and later
      // sent residential again would have quietly lost where it was meant to come out.
      ...(draft.exit === "residential" ? { exitCountry: draft.exitCountry || null } : {}),
      aiReview:
        (draft.effect === "allow" && draft.aiReview) ||
        (draft.effect === "require_permission" && draft.aiReview && !!draft.aiPolicy.trim()),
      // The note for the AI: an approval policy on an Ask rule, extra instructions on an Allow rule.
      aiPolicy: aiReviewAllowed(draft.effect) && draft.exit === "firewall" && draft.aiReview ? draft.aiPolicy.trim() || null : null,
    };
    try {
      if (editing) {
        const row = await source.update({ id: editing.id, ...payload });
        setItems((p) => p.map((r) => (r.id === editing.id ? row : r)).sort(byOrder));
        toast.success("Rule saved");
      } else {
        const row = await source.create({
          ...payload,
          exitCountry: draft.exit === "residential" ? draft.exitCountry || null : null,
          enabled: true,
        });
        setItems((p) => [...p, row].sort(byOrder));
        toast.success("Rule created");
      }
      return true;
    } catch (error) {
      // The server refuses residential on a rule that blocks, or over a domain whose key it
      // swaps. Those refusals explain themselves, so show what it said rather than a shrug.
      toast.error((error as Error).message || "Couldn’t save the rule. Try again.");
      return false;
    } finally {
      setBusy(false);
    }
  }, [source, demo]);

  return {
    items,
    busy,
    isManaged,
    isBrain,
    cycle,
    toggle,
    remove,
    submit,
    /** Null where it is not a choice: every other site is allowed and logged. `unknown` until the firewall answers. */
    otherSites: otherSitesSource ? otherSites : null,
    setOtherSites,
  };
}
