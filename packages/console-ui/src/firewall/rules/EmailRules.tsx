"use client";

import { useRulesOptions } from "./rules-context";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Button } from "../../ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "../../ui/dialog";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Switch } from "../../ui/switch";
import { RadioGroup, RadioGroupItem } from "../../ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../../ui/select";
import { useApi } from "../../lib/api";
import { useRulesChange, type RulesPending } from "./useRulesChange";
import type { EmailChange, EmailMailbox, EmailRulesSnapshot, OutboundMode, RuleEntry } from "../../lib/email-rules-schema";

/**
 * The email rules on Security rules (docs/plans/email-rules.md §5). The rules live on the firewall;
 * this reads them, and sends each edit as one change. Adding somebody, or loosening a setting,
 * makes the firewall send a six-digit code to the approved people; removals and stricter settings
 * apply at once. The senders and recipients are rows of the page's one list (`SecurityRulesView`);
 * the settings that are not rules are the **Email settings** panel here.
 */

const ALL = "__all__";
const REASONS: Record<string, string> = {
  unauthenticated: "failed sender checks",
  not_allowed: "sender not listed",
  spam: "marked as spam",
  bad_from: "unreadable sender",
};
export const EMAIL_MODES: Array<{ value: OutboundMode; label: string; help: string }> = [
  { value: "listed", label: "Only listed", help: "Agents can email only the people listed." },
  { value: "ask", label: "Ask me", help: "Someone new needs your approval first." },
  { value: "anyone", label: "Send to anyone", help: "Agents can email anyone without asking, up to the sending limit." },
  { value: "block", label: "Block all email", help: "Agents send no email." },
];

export interface EmailDemo {
  snapshot: EmailRulesSnapshot | null;
  pending?: RulesPending;
  error?: string;
  loading?: boolean;
}

/** The email rules as the firewall holds them, and the change waiting for a code. */
export function useEmailRules(enabled: boolean, demo?: EmailDemo, onSaved?: () => void) {
  const api = useApi();
  const [snapshot, setSnapshot] = useState<EmailRulesSnapshot | null>(demo?.snapshot ?? null);
  const [loading, setLoading] = useState(demo ? !!demo.loading : enabled);
  const change = useRulesChange<EmailChange, EmailRulesSnapshot>({ rpc: api.emailRules, demo, onSnapshot: setSnapshot, onSaved });
  const { setError } = change;

  const refresh = useCallback(async () => {
    if (demo || !enabled) return;
    setLoading(true);
    setError("");
    try {
      setSnapshot(await api.emailRules.get());
    } catch {
      setError("Your firewall didn’t answer. Start or update it, then reload the page.");
    } finally {
      setLoading(false);
    }
  }, [demo, enabled, setError, api]);
  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { snapshot, loading, refresh, ...change };
}

/**
 * Add an address or a domain: someone who can email the agents, or someone they can email. The
 * firewall sends a code before it applies either.
 */
export function EmailEntryDialog({
  initialList = "senders",
  mailboxes,
  disabled,
  pendingPanel,
  error,
  onAdd,
  onClose,
}: {
  /** The card whose Add opened it. */
  initialList?: "senders" | "recipients";
  mailboxes: EmailMailbox[];
  disabled: boolean;
  pendingPanel: ReactNode;
  error: string;
  onAdd: (list: "senders" | "recipients", entry: RuleEntry) => void;
  onClose: () => void;
}) {
  const [list, setList] = useState<"senders" | "recipients">(initialList);
  const [value, setValue] = useState("");
  const { codes } = useRulesOptions();
  const [mailbox, setMailbox] = useState(ALL);
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-lg" data-testid="email-entry-dialog">
        <DialogHeader>
          <DialogTitle>New Email rule</DialogTitle>
          <DialogDescription>
            {codes ? "Your firewall sends a code to your approved people before it lets someone new in or out." : "Who may email your agents, and whom they may email."}
          </DialogDescription>
        </DialogHeader>
        {error && (
          <p role="alert" className="rounded-[10px] border border-destructive/30 p-3 text-[12.5px] text-destructive">
            {error}
          </p>
        )}
        {pendingPanel}
        <form
          className="space-y-4"
          onSubmit={(ev) => {
            ev.preventDefault();
            if (!value.trim()) return;
            onAdd(list, { value: value.trim().toLowerCase(), mailbox: mailbox === ALL ? null : mailbox });
          }}
        >
          <RadioGroup className="gap-2" value={list} onValueChange={(v) => setList(v as "senders" | "recipients")} disabled={disabled}>
            {(
              [
                ["senders", "Who can email your agents", "Your firewall holds back mail from anyone else, so it never reaches the agent."],
                ["recipients", "Whom your agents can email", "Agents can email them without asking."],
              ] as const
            ).map(([v, label, help]) => (
              <label key={v} className="flex cursor-pointer items-start gap-2.5">
                <RadioGroupItem value={v} className="mt-0.5" />
                <span className="min-w-0">
                  <span className="block text-[13px] text-ink">{label}</span>
                  <span className="block text-[12px] text-ink-2">{help}</span>
                </span>
              </label>
            ))}
          </RadioGroup>
          <div>
            <Label htmlFor="email-entry-value">Address or domain</Label>
            <Input
              id="email-entry-value"
              className="mt-2 h-9 w-full min-w-0 font-mono text-[12.5px]"
              placeholder="bob@example.com or @example.com"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              disabled={disabled}
            />
          </div>
          {mailboxes.length > 1 && (
            <div>
              <Label className="text-[13px]">Mailbox</Label>
              <Select value={mailbox} onValueChange={setMailbox} disabled={disabled}>
                <SelectTrigger className="mt-2 h-9 w-full min-w-0" aria-label="Mailbox">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={ALL}>All mailboxes</SelectItem>
                  {mailboxes.map((m) => (
                    <SelectItem key={m.ref} value={m.ref}>
                      {m.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          <div className="flex flex-wrap gap-2">
            <Button type="submit" disabled={disabled || !value.trim()}>
              Add address
            </Button>
            <Button type="button" variant="outline" onClick={onClose} disabled={disabled}>
              Cancel
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/**
 * The email settings that are not rules, one row each: the sender check, mail held back this week,
 * replies and the sending limit. What happens with someone new is the "Everyone else" row of the
 * recipients card. Each edit is one change; loosening ones need a code.
 */
export function EmailSettingsPanel({
  snapshot,
  disabled,
  onChange,
}: {
  snapshot: EmailRulesSnapshot;
  disabled: boolean;
  onChange: (change: EmailChange) => void;
}) {
  const rules = snapshot.rules;
  const [limits, setLimits] = useState({ perHour: String(rules.outbound.perHour), perDay: String(rules.outbound.perDay) });
  useEffect(() => {
    setLimits({ perHour: String(rules.outbound.perHour), perDay: String(rules.outbound.perDay) });
  }, [rules.outbound.perHour, rules.outbound.perDay]);
  const held = snapshot.held;
  const heldTotal = held.reduce((n, h) => n + h.count, 0);
  const limitsChanged = limits.perHour !== String(rules.outbound.perHour) || limits.perDay !== String(rules.outbound.perDay);

  return (
    <div data-testid="email-settings">
      <SettingRow title="Sender check" help="AgentMail inboxes always require DMARC.">
        <Select value={rules.inbound.requireAuth} onValueChange={(v) => onChange({ action: "set_inbound_auth", requireAuth: v as "aligned" | "dmarc" })} disabled={disabled}>
          <SelectTrigger className="h-9 w-full min-w-0 sm:w-[19rem] [&>span]:truncate" aria-label="Sender check">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="aligned">DMARC, or DKIM from the sender’s domain</SelectItem>
            <SelectItem value="dmarc">DMARC only</SelectItem>
          </SelectContent>
        </Select>
      </SettingRow>
      {heldTotal > 0 && (
        <SettingRow title={`${heldTotal} held back this week`} help="Mail from people who aren’t listed, or that failed the sender check." testId="email-held">
          <ul className="min-w-0 space-y-0.5 text-[12.5px] text-ink-2 sm:max-w-[19rem]">
            {held.slice(0, 6).map((h) => (
              <li key={`${h.mailbox}|${h.reason}|${h.domain}`} className="break-words">
                {h.count} from {h.domain ?? "unknown"} · {REASONS[h.reason] ?? h.reason}
              </li>
            ))}
          </ul>
        </SettingRow>
      )}
      <SettingRow title="Reply to people who can email them" help="Agents answer anyone allowed to write in, without asking.">
        <Switch
          checked={rules.outbound.repliesToSenders}
          onCheckedChange={(v) => onChange({ action: "set_outbound", repliesToSenders: v })}
          disabled={disabled}
          aria-label="Reply to people who can email the agents"
        />
      </SettingRow>
      <SettingRow title="Sending limit" help="Per mailbox. At most 20 recipients per message.">
        <form
          className="flex flex-wrap items-center gap-2.5"
          onSubmit={(e) => {
            e.preventDefault();
            // An emptied field is not a limit of 0: that would stop every mailbox at once.
            if (!limits.perHour || !limits.perDay) return;
            const perHour = Number(limits.perHour);
            const perDay = Number(limits.perDay);
            if (Number.isInteger(perHour) && Number.isInteger(perDay)) onChange({ action: "set_outbound", perHour, perDay });
          }}
        >
          <label className="inline-flex items-center gap-1.5 text-[13px] text-ink-2">
            <Input className="h-9 w-[72px] text-right tabular-nums" inputMode="numeric" aria-label="Per hour" value={limits.perHour} disabled={disabled}
              onChange={(e) => setLimits((l) => ({ ...l, perHour: e.target.value.replace(/\D/g, "") }))} />
            / hour
          </label>
          <label className="inline-flex items-center gap-1.5 text-[13px] text-ink-2">
            <Input className="h-9 w-[72px] text-right tabular-nums" inputMode="numeric" aria-label="Per day" value={limits.perDay} disabled={disabled}
              onChange={(e) => setLimits((l) => ({ ...l, perDay: e.target.value.replace(/\D/g, "") }))} />
            / day
          </label>
          {limitsChanged && (
            <Button type="submit" variant="outline" size="sm" className="h-8" disabled={disabled || !limits.perHour || !limits.perDay}>
              Save
            </Button>
          )}
        </form>
      </SettingRow>
    </div>
  );
}

function SettingRow({ title, help, testId, children }: { title: string; help: string; testId?: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-2.5 border-b border-line px-4 py-3.5 last:border-b-0" data-testid={testId}>
      <div className="min-w-[13rem] flex-1">
        <p className="text-[13.5px] font-medium text-ink">{title}</p>
        <p className="text-[12.5px] text-ink-2">{help}</p>
      </div>
      {children}
    </div>
  );
}
