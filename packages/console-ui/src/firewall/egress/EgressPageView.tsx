"use client";

import { useState, type ReactNode } from "react";
import { Plus } from "lucide-react";
import { Button } from "../../ui/button";
import { PageHead } from "../../kit/PageHead";
import type { EgressBoxOption, EgressRuleListItem } from "../../lib/egress-schema";
import type { ExitChangeView, ExitView } from "../../lib/exit-schema";
import { EgressRulesList } from "./EgressRulesList";
import { ExitCard, type ExitAllowanceSlot } from "./ExitCard";
import { useApi } from "../../lib/api";

/**
 * The Internet access page body.
 *
 * It is one client component rather than a server page of client islands because the page's
 * primary action — **New rule** — belongs at the top right of the page header, while the dialog
 * it opens belongs with the rules. One piece of state spans the two, and a client boundary around
 * the whole body is cheaper than a store for a single boolean. The data still loads on the server:
 * `EgressPage` fetches it and hands it over.
 */
export function EgressPageView({
  rules,
  vmOptions,
  canManage,
  exit,
  exitChange,
  allowance,
  webhooks,
  exitHomeText,
}: {
  rules: EgressRuleListItem[];
  vmOptions: EgressBoxOption[];
  canManage: boolean;
  /** The exit; left out where the control plane has none yet (the Exit card is not drawn). */
  exit?: ExitView;
  exitChange?: ExitChangeView | null;
  /** The control plane's own prepaid exit, drawn inside the Exit card. */
  allowance?: ExitAllowanceSlot;
  /** What the Exit card says when no exit is set: where traffic leaves from (the console: its firewalls' country). */
  exitHomeText?: string;
  /** Sections after the site rules (the console: incoming webhooks). */
  webhooks?: ReactNode;
}) {
  const api = useApi();
  const [creating, setCreating] = useState(false);

  return (
    <>
      <PageHead
        title="Internet access"
        sub="Which sites your agents can reach, and where their traffic comes from."
        actions={
          canManage ? (
            <Button
              variant="brand"
              className="h-[38px] gap-[7px] rounded-[10px] px-[15px]"
              onClick={() => setCreating(true)}
              data-testid="egress-new-rule"
            >
              <Plus className="h-[15px] w-[15px]" />
              New rule
            </Button>
          ) : null
        }
      />

      {/*
        The Exit card reads before the rules because it governs them, and the ControlClaw
        allowance sits inside it rather than in a border of its own: "which sites leave from
        somewhere else" and "how much of the included data is left" are one question to a person,
        even though they are two features underneath.
      */}
      {exit ? <ExitCard initial={exit} initialChange={exitChange ?? null} allowance={allowance} homeText={exitHomeText} /> : null}

      <EgressRulesList
        source={api.egressRules}
        initial={rules}
        vmOptions={vmOptions}
        canManage={canManage}
        exitConfigured={exit?.configured ?? false}
        exitAvailable={!!exit}
        exitCountry={exit?.country ?? null}
        exitSupportsCountry={exit?.supportsCountry ?? false}
        creating={creating}
        onCreatingChange={setCreating}
      />

      {/* Incoming webhooks live with the other traffic rules now, not on the Firewall page: every
          piece of state behind one is about what may reach an agent from outside. */}
      {webhooks}
    </>
  );
}
