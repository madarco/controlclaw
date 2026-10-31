import { AppLink as Link } from "../../lib/link";
import { AlertTriangle, Bot, Check, ChevronRight, Plug, ShieldCheck } from "lucide-react";
import { Button } from "../../ui/button";
import { StatusPill, type StatusPillTone } from "../../kit/StatusPill";
import { Badge } from "../../kit/console-ui";
import { Avatar, AvatarStack } from "../../kit/people";
import { cn } from "../../lib/utils";
import { AppLogo } from "./AppLogo";

/**
 * One of the four official integrations on the Integrations page (Google, Drive folders, AgentMail,
 * Phone), drawn the same way: a logo tile on a tint of the app's colour, Official or Connected,
 * what it can do, where it stands, the agents using it, and Manage or Set up.
 *
 * It owns nothing. The whole card is a link to the integration's own page, where every control
 * lives; each wrapper passes the status line its page uses, so the two cannot disagree.
 */
export function OfficialCard({
  href,
  name,
  tag,
  mark,
  color,
  setUp,
  connected,
  can,
  status,
  account,
  accountTestId,
  details,
  warn,
  hint,
  agents,
  held = setUp,
  "data-testid": testId,
}: {
  href: string;
  name: string;
  /** The short line under the name: "Mail · Calendar · Contacts". */
  tag: string;
  mark: string;
  color: string;
  /** Set up, in whatever state: Manage instead of Set up, and the footer lists the agents. */
  setUp: boolean;
  /** Set up and working (its status line is green): the Connected pill. Anything else says Official. */
  connected: boolean;
  /** "What it can do", three short chips. */
  can: string[];
  status: { text: string; tone: StatusPillTone };
  /** The account it is connected as, in mono, cut with an ellipsis. */
  account?: string | null;
  accountTestId?: string;
  /** Anything else the card says in its middle band: covered services, folders, a problem. */
  details?: React.ReactNode;
  /** An amber note that needs action. */
  warn?: React.ReactNode;
  /** What setting it up takes, shown until it is. */
  hint?: string;
  /** The agents that use it. */
  agents: Array<{ id: string; name: string }>;
  /** The firewall holds its credential: the "proxy-held" mark. Defaults to `setUp`. */
  held?: boolean;
  "data-testid": string;
}) {
  return (
    <Link
      href={href}
      data-testid={testId}
      style={{ "--c": color } as React.CSSProperties}
      className={cn(
        "relative flex min-w-0 flex-col gap-3.5 overflow-hidden rounded-xl border border-line bg-surface p-[18px] shadow-sm transition-colors hover:border-brand-border",
        "before:pointer-events-none before:absolute before:inset-x-0 before:top-0 before:h-[72px] before:content-['']",
        "before:bg-[linear-gradient(180deg,color-mix(in_oklch,var(--c)_12%,var(--surface)),var(--surface))]",
      )}
    >
      <div className="relative flex items-center gap-3">
        <AppLogo name={name} mark={mark} color={color} size={44} />
        <div className="min-w-0 flex-1">
          <div className="text-[16px] leading-tight font-semibold tracking-[-0.01em] text-ink">{name}</div>
          <div className="mt-0.5 text-[12.5px] leading-snug text-ink-2">{tag}</div>
        </div>
        {connected ? (
          <Badge tone="allow" dot>
            Connected
          </Badge>
        ) : (
          <Badge className="bg-surface">Official</Badge>
        )}
      </div>

      <ul className="relative flex flex-wrap gap-1.5">
        {can.map((c) => (
          <li key={c} className="inline-flex h-[26px] items-center gap-[5px] rounded-full bg-bg-2 px-2.5 text-[12.5px] text-ink-2">
            <Check className="h-3 w-3 text-allow" />
            {c}
          </li>
        ))}
      </ul>

      <div className="relative flex flex-1 flex-col gap-2 text-[12.5px]">
        <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1.5">
          <StatusPill tone={status.tone} data-testid={`${testId}-status`}>
            {status.text}
          </StatusPill>
          {account ? (
            <span title={account} className="min-w-0 max-w-full truncate font-mono text-[12px] text-ink-2" data-testid={accountTestId}>
              {account}
            </span>
          ) : null}
          {held ? (
            <span className="inline-flex items-center gap-1 whitespace-nowrap text-ink-2" title="The credential stays on your firewall. Agents only get a placeholder">
              <ShieldCheck className="h-3 w-3" /> proxy-held
            </span>
          ) : null}
        </div>
        {details}
        {warn ? (
          <div className="flex items-start gap-2 rounded-[8px] bg-ask-soft px-2.5 py-2 leading-snug text-ask-fg">
            <AlertTriangle className="mt-px h-[13px] w-[13px] shrink-0" />
            <span className="min-w-0">{warn}</span>
          </div>
        ) : null}
        {!setUp && hint ? <p className="text-ink-2">{hint}</p> : null}
      </div>

      <div className="relative flex items-center gap-2.5 border-t border-line pt-3">
        {setUp ? (
          <span className="flex min-w-0 flex-1 items-center gap-2" data-testid={`${testId}-agents`}>
            {agents.length ? (
              <AvatarStack items={agents.map((a) => <Avatar key={a.id} name={a.name} size={24} />)} label={agents.map((a) => a.name).join(", ")} />
            ) : (
              <Bot className="h-4 w-4 text-ink-2" />
            )}
            <span className="truncate text-[12.5px] text-ink-2">
              {agents.length ? `${agents.length} ${agents.length === 1 ? "agent" : "agents"}` : "No agents yet"}
            </span>
          </span>
        ) : (
          <span className="flex-1" />
        )}
        {/* Not a real button: the card is the link. `tabIndex` keeps it out of the tab order. */}
        <Button size="sm" variant={setUp ? "outline" : "default"} className="pointer-events-none shrink-0" tabIndex={-1} data-testid={`${testId}-open`}>
          {setUp ? "Manage" : "Set up"}
          <ChevronRight className="ml-1 h-3.5 w-3.5" />
        </Button>
      </div>
    </Link>
  );
}

/** The three steps above the official cards: you sign in, the firewall keeps it, agents get a stand-in. */
export function IntegrationsIntro() {
  const steps: Array<[React.ComponentType<{ className?: string }>, string, string]> = [
    [Plug, "You sign in once", "Google, a Twilio number, an API key…"],
    [ShieldCheck, "Your firewall stores the login", "Encrypted, on your firewall’s disk"],
    [Bot, "Agents get a placeholder", "The firewall adds the real key to each outgoing call"],
  ];
  return (
    <ol className="mt-1.5 grid grid-cols-1 gap-2.5 md:grid-cols-3" data-testid="integrations-intro">
      {steps.map(([Icon, title, sub], i) => (
        <li key={title} className="relative flex items-center gap-3 rounded-xl bg-bg-2 px-3.5 py-3">
          <span className="grid h-8 w-8 shrink-0 place-items-center rounded-[9px] bg-surface text-brand shadow-sm">
            <Icon className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <div className="text-[13.5px] font-semibold text-ink">{title}</div>
            <div className="text-[12.5px] text-ink-2">{sub}</div>
          </div>
          {i < steps.length - 1 ? (
            <span
              aria-hidden="true"
              className="absolute top-1/2 -right-[13px] z-[1] hidden h-5 w-5 -translate-y-1/2 place-items-center rounded-full border border-line bg-surface text-ink-2 md:grid"
            >
              <ChevronRight className="h-3.5 w-3.5" />
            </span>
          ) : null}
        </li>
      ))}
    </ol>
  );
}
