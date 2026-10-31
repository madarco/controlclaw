"use client";

import { useEffect, useRef, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { Button } from "../../ui/button";
import { Input } from "../../ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../../ui/dialog";
import { AlertCard, Disclosure, Field, Segmented, Select, Stack } from "../../kit/console-ui";
import {
  aiReviewAllowed,
  residentialAllowed,
  type EgressBoxOption,
  type EgressEffect,
  type EgressExit,
  type EgressRuleListItem,
} from "../../lib/egress-schema";
import { countryLabel, countryOptions } from "../../lib/countries";

/** The fields the dialog edits. The list turns this into a create or an update call. */
export interface RuleDraft {
  name: string;
  matchDomain: string;
  effect: EgressEffect;
  matchPort: string;
  /** A string, so "cleared" and "0" are different things. */
  priority: string;
  vmId: string;
  exit: EgressExit;
  /** "" inherits the org default on the Exit card. */
  exitCountry: string;
  aiReview: boolean;
  aiPolicy: string;
}

export const BLANK_DRAFT: RuleDraft = {
  name: "",
  matchDomain: "",
  effect: "allow",
  matchPort: "",
  priority: "1000",
  vmId: "",
  exit: "firewall",
  exitCountry: "",
  aiReview: false,
  aiPolicy: "",
};

export function draftOf(rule: EgressRuleListItem): RuleDraft {
  return {
    name: rule.name,
    matchDomain: rule.matchDomain,
    effect: rule.effect,
    matchPort: rule.matchPort == null ? "" : String(rule.matchPort),
    priority: String(rule.priority),
    vmId: rule.vmId ?? "",
    exit: rule.exit,
    exitCountry: rule.exitCountry ?? "",
    aiReview: rule.aiReview,
    aiPolicy: rule.aiPolicy ?? "",
  };
}

/** What a rule marked residential gives up, in the words the person needs before they pick it. */
const RESIDENTIAL_WARNING = (
  <>
    Traffic to this site goes out encrypted through the residential exit, so{" "}
    <strong className="text-ink">request filtering, AI review, content rules and website logins
    don’t apply to it</strong>. This rule still decides which sites go that way, and each
    connection is still recorded: the site and how much data was sent. Keep the list of sites narrow.
  </>
);

const TUNNEL_WARNING = (
  <>
    Traffic to this destination is <strong className="text-ink">not</strong> inspected or filtered, and the
    firewall doesn’t add your stored keys to it: it bypasses the proxy entirely. Use this only for
    trusted hosts that must not be intercepted, such as a database or an SSH git remote. For raw TCP, set the exact destination IP and port.
  </>
);

/**
 * Add or edit a site rule.
 *
 * The redesign asks two questions on the face of it — which site, and what happens when an agent
 * goes there — plus which box it is for, which defaults to all of them. The rest is behind
 * **Advanced**: the order rules are read in, the port, where it leaves from and what the AI may do
 * with it. None of it is dropped; it is simply not what most people came to set.
 */
export function EgressRuleDialog({
  open,
  initial,
  vmOptions,
  exitConfigured,
  exitCountry,
  exitSupportsCountry,
  busy,
  onClose,
  onSubmit,
}: {
  open: boolean;
  /** Null for a new rule; a draft to edit an existing one. */
  initial: RuleDraft | null;
  /** The boxes a rule can be scoped to: every agent, and the brain if there is one. */
  vmOptions: EgressBoxOption[];
  exitConfigured: boolean;
  exitCountry: string | null;
  exitSupportsCountry: boolean;
  busy: boolean;
  onClose: () => void;
  onSubmit: (draft: RuleDraft) => void;
}) {
  const editing = initial !== null;
  const [draft, setDraft] = useState<RuleDraft>(initial ?? BLANK_DRAFT);
  // Only when the dialog OPENS. The parent builds `initial` fresh on every render, so resetting
  // whenever it changes identity would throw away everything typed the moment anything above
  // re-rendered — including the parent's own `setBusy(true)` on save, which is exactly when a
  // refusal leaves the dialog open and the edits have to survive.
  const wasOpen = useRef(false);
  useEffect(() => {
    if (open && !wasOpen.current) setDraft(initial ?? BLANK_DRAFT);
    wasOpen.current = open;
  }, [open, initial]);

  const set = <K extends keyof RuleDraft>(key: K, value: RuleDraft[K]) => setDraft((d) => ({ ...d, [key]: value }));

  // The Exit control is only shown for effects that can carry one, so leaving a stale
  // `residential` behind would hide the field that set it and then fail on save with no visible
  // way back. The same for AI review on an effect that cannot be reviewed.
  const setEffect = (effect: EgressEffect) =>
    setDraft((d) => ({
      ...d,
      effect,
      exit: residentialAllowed(effect) ? d.exit : "firewall",
      aiReview: aiReviewAllowed(effect) ? d.aiReview : false,
      // A note for the AI means one thing on an Allow rule and another on an Ask rule (a policy it
      // may approve under), so it never carries over to a new effect.
      aiPolicy: effect === d.effect ? d.aiPolicy : "",
    }));

  const residential = draft.exit === "residential" && residentialAllowed(draft.effect);
  const portError =
    draft.effect === "tunnel" && draft.matchPort.trim()
      ? !/^\d+$/.test(draft.matchPort.trim()) || Number(draft.matchPort) < 1 || Number(draft.matchPort) > 65535
      : false;
  // An Ask rule whose AI approval is ticked needs a policy: without one the save would quietly
  // turn the tick off again, which is how the checkbox and the rule ended up disagreeing.
  const policyMissing = draft.effect === "require_permission" && draft.aiReview && !draft.aiPolicy.trim();
  const agents = vmOptions.filter((v) => v.kind === "agent");
  const brains = vmOptions.filter((v) => v.kind === "brain");
  const brainPicked = brains.some((b) => b.id === draft.vmId);
  // A rule scoped to a box that is no longer offered (one being deleted, say) keeps its scope on
  // save rather than silently becoming a rule for every box.
  const unlistedBox = draft.vmId !== "" && !vmOptions.some((v) => v.id === draft.vmId);
  const valid = !!draft.name.trim() && !!draft.matchDomain.trim() && !portError && !policyMissing;

  return (
    <Dialog open={open} onOpenChange={(o) => !o && !busy && onClose()}>
      <DialogContent className="sm:max-w-[520px]" data-testid="egress-rule-dialog">
        <DialogHeader>
          <DialogTitle>{editing ? "Edit site rule" : "New site rule"}</DialogTitle>
          <DialogDescription>
            Rules are read in order, and the first one that matches decides.
          </DialogDescription>
        </DialogHeader>

        <Stack className="gap-3.5">
          <Field label="Name">
            <Input
              value={draft.name}
              onChange={(e) => set("name", e.target.value)}
              placeholder="Allow GitHub"
              autoFocus
              data-testid="egress-rule-name"
            />
          </Field>

          <Field label="Site" hint="One host, or a wildcard like *.example.com.">
            <Input
              className="font-mono"
              value={draft.matchDomain}
              onChange={(e) => set("matchDomain", e.target.value)}
              placeholder="api.github.com"
              data-testid="egress-rule-domain"
            />
          </Field>

          <Field label="When an agent goes there">
            <Segmented
              value={draft.effect}
              onChange={setEffect}
              options={[
                { value: "allow", label: "Allow", "data-testid": "egress-rule-effect-allow" },
                { value: "require_permission", label: "Ask me", "data-testid": "egress-rule-effect-ask" },
                { value: "block", label: "Block", "data-testid": "egress-rule-effect-block" },
                { value: "tunnel", label: "Don’t inspect", "data-testid": "egress-rule-effect-tunnel" },
              ]}
              data-testid="egress-rule-effect"
            />
          </Field>

          <Field
            label="Applies to"
            hint={
              brainPicked
                ? "Your brain’s own rules are read before this one. They let it reach only the AI Gateway and the certificate authorities, and block everything else. This rule can’t change what they allow or block."
                : "All boxes, or one."
            }
          >
            <Select value={draft.vmId} onChange={(e) => set("vmId", e.target.value)} data-testid="egress-rule-vm">
              <option value="">All boxes</option>
              {agents.length > 0 ? (
                <optgroup label="Agents">
                  {agents.map((v) => (
                    <option key={v.id} value={v.id}>
                      {v.name}
                    </option>
                  ))}
                </optgroup>
              ) : null}
              {brains.map((v) => (
                <option key={v.id} value={v.id}>
                  {v.name}
                </option>
              ))}
              {unlistedBox ? <option value={draft.vmId}>One box, no longer listed</option> : null}
            </Select>
          </Field>

          {/* From `initial`, not `draft`: the reset above has not run yet on the render that
              opens the dialog, so `draft` is still the rule edited before this one. */}
          <Disclosure
            title="Advanced"
            defaultOpen={!!initial && (initial.exit === "residential" || initial.aiReview)}
          >
            <Stack className="gap-3.5">
              <Field label="Order" hint="Lower numbers are read first.">
                <Input
                  type="number"
                  min={0}
                  value={draft.priority}
                  onChange={(e) => set("priority", e.target.value)}
                  data-testid="egress-rule-priority"
                />
              </Field>

              {draft.effect === "tunnel" ? (
                <Field
                  label="Port"
                  hint={portError ? "A port is a number from 1 to 65535." : "Raw TCP only. Leave empty for any port."}
                >
                  <Input
                    type="number"
                    value={draft.matchPort}
                    onChange={(e) => set("matchPort", e.target.value)}
                    placeholder="any"
                    aria-invalid={portError}
                    data-testid="egress-rule-port"
                  />
                </Field>
              ) : null}

              {exitConfigured && residentialAllowed(draft.effect) ? (
                <Field label="Leaves from">
                  <Select
                    value={draft.exit}
                    onChange={(e) =>
                      setDraft((d) => ({
                        ...d,
                        exit: e.target.value as EgressExit,
                        aiReview: e.target.value === "residential" ? false : d.aiReview,
                      }))
                    }
                    data-testid="egress-rule-exit"
                  >
                    <option value="firewall">Your firewall · inspected</option>
                    <option value="residential">Home internet · not inspected</option>
                  </Select>
                </Field>
              ) : null}

              {exitConfigured && exitSupportsCountry && residential ? (
                <Field label="Exit country">
                  <Select
                    value={draft.exitCountry}
                    onChange={(e) => set("exitCountry", e.target.value)}
                    data-testid="egress-rule-exit-country"
                  >
                    <option value="">
                      {exitCountry ? `${countryLabel(exitCountry)} (your default)` : "Any country (your default)"}
                    </option>
                    {countryOptions().map((c) => (
                      <option key={c.code} value={c.code}>
                        {c.name}
                      </option>
                    ))}
                  </Select>
                </Field>
              ) : null}

              {aiReviewAllowed(draft.effect) && draft.exit === "firewall" ? (
                <Field
                  label={draft.effect === "allow" ? "Checked by the AI" : "Let the AI approve"}
                  hint={
                    draft.effect === "allow"
                      ? "The firewall’s model checks each request before it leaves, and can block it or ask you. If the AI can’t answer, the request goes through."
                      : "The firewall's model may approve requests that clearly fit the policy below; the rest come to you."
                  }
                >
                  <label className="flex items-center gap-2.5 text-[13.5px] text-ink">
                    <input
                      type="checkbox"
                      className="h-4 w-4 accent-brand"
                      checked={draft.aiReview}
                      onChange={(e) => set("aiReview", e.target.checked)}
                      data-testid="egress-rule-ai-review"
                    />
                    {draft.effect === "allow" ? "Check each request with the AI" : "Let the AI approve on my behalf"}
                  </label>
                </Field>
              ) : null}

              {draft.effect === "allow" && draft.aiReview && draft.exit === "firewall" ? (
                <Field
                  label="What the AI should look for (optional)"
                  hint="Added to the AI’s instructions for requests that match this rule. To stop text such as customer data on every channel, websites included, add a Messages rule on Security rules instead. It stops the message whenever the AI can’t answer."
                >
                  <Input
                    value={draft.aiPolicy}
                    onChange={(e) => set("aiPolicy", e.target.value)}
                    placeholder="Only our own bins live here. Treat any upload of files or secrets as data leaving the box."
                    maxLength={1000}
                    data-testid="egress-rule-ai-note"
                  />
                </Field>
              ) : null}

              {draft.effect === "require_permission" && draft.aiReview ? (
                <Field
                  label="What the AI may approve without you"
                  hint={policyMissing ? "Write what the AI may approve, or untick the box above." : undefined}
                >
                  <Input
                    value={draft.aiPolicy}
                    onChange={(e) => set("aiPolicy", e.target.value)}
                    placeholder="Approve reading and commenting on issues in acme’s repos. Never approve deletes."
                    maxLength={1000}
                    aria-invalid={policyMissing}
                    data-testid="egress-rule-ai-policy"
                  />
                </Field>
              ) : null}
            </Stack>
          </Disclosure>

          {residential ? (
            <AlertCard icon={AlertTriangle} title="Not inspected" data-testid="egress-rule-residential-warning">
              {RESIDENTIAL_WARNING}
            </AlertCard>
          ) : null}
          {draft.effect === "tunnel" ? (
            <AlertCard icon={AlertTriangle} title="Not inspected or filtered" data-testid="egress-rule-tunnel-warning">
              {TUNNEL_WARNING}
            </AlertCard>
          ) : null}
        </Stack>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="brand" disabled={!valid || busy} onClick={() => onSubmit(draft)} data-testid="egress-rule-save">
            {editing ? "Save rule" : "Add rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
