import { z } from "zod";

/**
 * Email rules (docs/plans/email-rules.md). One set per organization, held on the firewall, applying
 * to every mailbox the org has. A mailbox is `agentmail:<inbox id>` or `gmail:<address>`; an entry
 * with `mailbox: null` applies to all of them.
 */

export const mailboxRef = z
  .string()
  .max(300)
  .regex(/^(?:agentmail|gmail):[^\s@]+@[^\s@]+$/)
  .transform((s) => s.toLowerCase());
export type MailboxRef = z.infer<typeof mailboxRef>;

const domainPart = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;

/** `bob@x.com` (one address) or `@x.com` (the whole domain). Lowercase, no plus-tag folding. */
export const addressPattern = z
  .string()
  .trim()
  .toLowerCase()
  .max(254)
  .refine((v) => {
    if (v.startsWith("@")) return domainPart.test(v.slice(1));
    const at = v.lastIndexOf("@");
    return at > 0 && /^[^\s@"<>(),;:\\[\]]{1,64}$/.test(v.slice(0, at)) && domainPart.test(v.slice(at + 1));
  }, "Use an address like bob@example.com or a domain like @example.com");

export const ruleEntry = z.object({
  value: addressPattern,
  mailbox: mailboxRef.nullable().default(null),
});
export type RuleEntry = z.infer<typeof ruleEntry>;

/** `anyone`: any address, with no list check and no request. The limits still apply. */
export const outboundMode = z.enum(["listed", "ask", "block", "anyone"]);
export type OutboundMode = z.infer<typeof outboundMode>;
export const requireAuth = z.enum(["aligned", "dmarc"]);
export type RequireAuth = z.infer<typeof requireAuth>;

export const LIMITS = { perHour: { min: 1, max: 200 }, perDay: { min: 1, max: 2000 } } as const;
export const MAX_RECIPIENTS = 20;
export const MAX_ENTRIES = 200;

export const emailRules = z.object({
  version: z.literal(1),
  inbound: z.object({
    requireAuth,
    senders: z.array(ruleEntry).max(MAX_ENTRIES),
  }),
  outbound: z.object({
    mode: outboundMode,
    /** Per-mailbox modes; only ever stricter than `mode` (enforced in `effectiveMode`). */
    mailboxModes: z.array(z.object({ mailbox: mailboxRef, mode: outboundMode })).max(MAX_ENTRIES),
    recipients: z.array(ruleEntry).max(MAX_ENTRIES),
    repliesToSenders: z.boolean(),
    perHour: z.number().int().min(LIMITS.perHour.min).max(LIMITS.perHour.max),
    perDay: z.number().int().min(LIMITS.perDay.min).max(LIMITS.perDay.max),
  }),
});
export type EmailRules = z.infer<typeof emailRules>;

export const DEFAULT_RULES: EmailRules = {
  version: 1,
  inbound: { requireAuth: "aligned", senders: [] },
  outbound: { mode: "ask", mailboxModes: [], recipients: [], repliesToSenders: true, perHour: 20, perDay: 100 },
};

/** One change, as the console (or a WebMCP tool) proposes it. */
export const emailChange = z.discriminatedUnion("action", [
  z.object({ action: z.literal("add_sender"), entry: ruleEntry }),
  z.object({ action: z.literal("remove_sender"), entry: ruleEntry }),
  z.object({ action: z.literal("add_recipient"), entry: ruleEntry }),
  z.object({ action: z.literal("remove_recipient"), entry: ruleEntry }),
  z.object({ action: z.literal("set_inbound_auth"), requireAuth }),
  z.object({
    action: z.literal("set_outbound"),
    mode: outboundMode.optional(),
    repliesToSenders: z.boolean().optional(),
    perHour: z.number().int().min(LIMITS.perHour.min).max(LIMITS.perHour.max).optional(),
    perDay: z.number().int().min(LIMITS.perDay.min).max(LIMITS.perDay.max).optional(),
  }),
  z.object({ action: z.literal("set_mailbox_mode"), mailbox: mailboxRef, mode: outboundMode.nullable() }),
]);
export type EmailChange = z.infer<typeof emailChange>;

const MODE_RANK: Record<OutboundMode, number> = { block: 0, listed: 1, ask: 2, anyone: 3 };
/** What agents will do in each mode, as the code message says it. */
const MODE_WORDS: Record<OutboundMode, string> = {
  listed: "send only to listed people",
  ask: "ask before emailing someone new",
  block: "send no email",
  anyone: "be able to email anyone, with no list and no request to you",
};
const sameEntry = (a: RuleEntry, b: RuleEntry) => a.value === b.value && a.mailbox === b.mailbox;

/** Approve once: how long one approved recipient may be emailed (docs/plans/email-rules.md §2.2). */
export const EMAIL_GRANT_SECONDS = 30 * 60;

/** Apply a change to a copy of the rules. Throws on a change that makes no sense. */
export function applyChange(rules: EmailRules, change: EmailChange): EmailRules {
  const next: EmailRules = structuredClone(rules);
  const add = (list: RuleEntry[], entry: RuleEntry) => {
    if (list.some((e) => sameEntry(e, entry))) throw new Error("Already listed");
    if (list.length >= MAX_ENTRIES) throw new Error("List is full");
    list.push(entry);
  };
  const remove = (list: RuleEntry[], entry: RuleEntry) => {
    const i = list.findIndex((e) => sameEntry(e, entry));
    if (i < 0) throw new Error("Not listed");
    list.splice(i, 1);
  };
  switch (change.action) {
    case "add_sender":
      add(next.inbound.senders, change.entry);
      break;
    case "remove_sender":
      remove(next.inbound.senders, change.entry);
      break;
    case "add_recipient":
      add(next.outbound.recipients, change.entry);
      break;
    case "remove_recipient":
      remove(next.outbound.recipients, change.entry);
      break;
    case "set_inbound_auth":
      next.inbound.requireAuth = change.requireAuth;
      break;
    case "set_outbound":
      if (change.mode) next.outbound.mode = change.mode;
      if (change.repliesToSenders !== undefined) next.outbound.repliesToSenders = change.repliesToSenders;
      if (change.perHour !== undefined) next.outbound.perHour = change.perHour;
      if (change.perDay !== undefined) next.outbound.perDay = change.perDay;
      break;
    case "set_mailbox_mode":
      next.outbound.mailboxModes = next.outbound.mailboxModes.filter((m) => m.mailbox !== change.mailbox);
      if (change.mode) next.outbound.mailboxModes.push({ mailbox: change.mailbox, mode: change.mode });
      break;
  }
  return emailRules.parse(next);
}

/**
 * Whether `next` lets anybody new instruct an agent or receive mail from one, compared with
 * `prev`. Those changes need a confirmation code (docs/plans/email-rules.md §3). Rate limits are
 * policy, not consent, and never count.
 */
export function widens(prev: EmailRules, next: EmailRules): boolean {
  const added = (a: RuleEntry[], b: RuleEntry[]) => b.some((e) => !a.some((o) => sameEntry(o, e)));
  if (added(prev.inbound.senders, next.inbound.senders)) return true;
  if (added(prev.outbound.recipients, next.outbound.recipients)) return true;
  if (prev.inbound.requireAuth === "dmarc" && next.inbound.requireAuth === "aligned") return true;
  if (!prev.outbound.repliesToSenders && next.outbound.repliesToSenders) return true;
  if (MODE_RANK[next.outbound.mode] > MODE_RANK[prev.outbound.mode]) return true;
  const mailboxes = new Set([...prev.outbound.mailboxModes, ...next.outbound.mailboxModes].map((m) => m.mailbox));
  for (const mb of mailboxes) if (MODE_RANK[effectiveMode(next, mb)] > MODE_RANK[effectiveMode(prev, mb)]) return true;
  return false;
}

/** The mode for one mailbox: the org mode, or the per-mailbox one when it is stricter. */
export function effectiveMode(rules: EmailRules, mailbox: MailboxRef): OutboundMode {
  const own = rules.outbound.mailboxModes.find((m) => m.mailbox === mailbox)?.mode;
  const org = rules.outbound.mode;
  return own && MODE_RANK[own] < MODE_RANK[org] ? own : org;
}

/** The domain part of an address, lowercased; null when there is none. */
export function domainOf(address: string): string | null {
  const at = address.lastIndexOf("@");
  if (at <= 0) return null;
  const d = address.slice(at + 1).toLowerCase();
  return domainPart.test(d) ? d : null;
}

/** Whether `address` is covered by one of `entries` for `mailbox`. */
export function listed(entries: RuleEntry[], address: string, mailbox: MailboxRef): boolean {
  const a = address.trim().toLowerCase();
  const d = domainOf(a);
  return entries.some(
    (e) => (e.mailbox === null || e.mailbox === mailbox) && (e.value === a || (d !== null && e.value === `@${d}`)),
  );
}

/**
 * One line a person reads on their phone next to the code. Written here, never by the console.
 * `next` is the rules as the change would leave them, so a mailbox's line says how it will really
 * send: a mode looser than the organization's does not apply, and "follow the organization" is
 * spelled out when the organization lets agents email anyone.
 */
export function describeChange(change: EmailChange, next?: EmailRules): string {
  const where = (e: RuleEntry) => (e.mailbox ? ` (${e.mailbox.replace(/^[a-z]+:/, "")} only)` : "");
  const who = (e: RuleEntry) => (e.value.startsWith("@") ? `anyone at ${e.value.slice(1)}` : e.value);
  switch (change.action) {
    case "add_sender":
      return `Let ${who(change.entry)} email your agents${where(change.entry)}`;
    case "remove_sender":
      return `Stop ${who(change.entry)} from emailing your agents${where(change.entry)}`;
    case "add_recipient":
      return `Let your agents send email to ${who(change.entry)}${where(change.entry)}`;
    case "remove_recipient":
      return `Stop your agents sending email to ${who(change.entry)}${where(change.entry)}`;
    case "set_inbound_auth":
      return change.requireAuth === "dmarc"
        ? "Only accept email that passes DMARC"
        : "Accept email that passes DMARC or has a DKIM signature from the sender's domain";
    case "set_outbound": {
      const parts: string[] = [];
      if (change.mode) parts.push(MODE_WORDS[change.mode]);
      if (change.repliesToSenders !== undefined) parts.push(change.repliesToSenders ? "reply to people allowed to email them" : "not reply unless the person is listed");
      if (change.perHour !== undefined || change.perDay !== undefined) parts.push(`send at most ${change.perHour ?? "the same"} an hour and ${change.perDay ?? "the same"} a day per mailbox`);
      return `Agents will ${parts.join(", ")}`;
    }
    case "set_mailbox_mode": {
      const mode = next ? effectiveMode(next, change.mailbox) : change.mode;
      const follows = mode === "anyone" ? `follow the organization setting and ${MODE_WORDS.anyone}` : "follow the organization setting";
      return `${change.mailbox.replace(/^[a-z]+:/, "")} will ${change.mode && mode ? MODE_WORDS[mode] : follows}`;
    }
  }
}
