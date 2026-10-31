"use client";

import { BookOpen, ExternalLink, TriangleAlert } from "lucide-react";
import { CopyButton } from "../../ui/copy-button";
import { cn } from "../../lib/utils";
import type { ConnectorClientSetup } from "../../lib/connectors-schema";

/**
 * OpenConnector's own `clientSetup` steps call the host that shows them "OOMOL Connect" or
 * "this runtime", because upstream that host is its own console. Here it is this dialog, so the
 * name is swapped rather than left to send somebody looking for a product they do not have.
 * Only the prose names are touched — a JSON payload inside a step (ClickUp's and Granola's
 * dynamic client registration both have one) is an instruction to the provider and is left
 * exactly as it is.
 */
function hostedHere(step: string): string {
  return step
    .replace(/\bshown by OOMOL Connect\b/g, "shown here")
    .replace(/\bshown by this runtime\b/g, "shown here")
    .replace(/\binto OOMOL Connect\b/g, "into the fields here")
    .replace(/\bin this runtime\b/g, "here")
    .replace(/\bOOMOL Connect\b/g, "ControlClaw")
    // Whatever is left ("this runtime requests", "this runtime's exact URL") is the same host.
    .replace(/\bthis runtime\b/g, "ControlClaw");
}

/** The one callback URL of this deployment, selectable and copyable. Rendered exactly once. */
export function RedirectUri({ uri, tone }: { uri: string | null; tone: "surface" | "bg-2" }) {
  if (!uri) return null;
  return (
    <div className="flex items-start gap-2">
      <code
        className={`min-w-0 flex-1 select-all break-all rounded px-2 py-1 text-[12px] text-ink ${tone === "surface" ? "bg-surface" : "bg-bg-2"}`}
        data-testid="connector-redirect-uri"
      >
        {uri}
      </code>
      <CopyButton value={uri} className="h-[26px] shrink-0 px-2 text-[12px]" data-testid="connector-redirect-uri-copy" />
    </div>
  );
}

/**
 * "Before you start": how to create the app at the provider.
 *
 * Steps first, because that is the order somebody does them in, and the callback URL right under
 * them — the step that says to register it is the last place it is needed, and the form fields
 * follow. The pitfalls come last and deliberately quote the provider's own error text, because
 * that is the string somebody pastes into a search box.
 */
export function SetupGuide({
  guide,
  providerName,
  redirectUri,
  title = "Before you start",
  flat = false,
}: {
  guide: ConnectorClientSetup | null;
  providerName: string;
  redirectUri: string | null;
  /** Null where the guide sits under a heading of its own (the Google page's disclosure). */
  title?: string | null;
  /** No border or background, for a guide already inside a card. */
  flat?: boolean;
}) {
  if (!guide || guide.steps.length === 0) return null;
  const steps = guide.source === "controlclaw" ? guide.steps : guide.steps.map(hostedHere);
  // One Google guide serves five apps, so it names Google, not the app on screen.
  const writtenFor = guide.docsLabel ?? providerName;
  return (
    <div
      className={cn("grid grid-cols-[minmax(0,1fr)] gap-2 text-[12.5px] text-ink-2", !flat && "rounded-xl border border-line bg-surface px-3.5 py-3")}
      data-testid="connector-setup-guide"
    >
      {title ? (
        <div className="flex items-center gap-1.5 font-medium text-ink">
          <BookOpen className="h-3.5 w-3.5" />
          {title}
        </div>
      ) : null}
      <ol className="ml-4 grid list-decimal gap-1.5" data-testid="connector-setup-steps">
        {steps.map((step, i) => (
          <li key={i} className="pl-0.5 [overflow-wrap:anywhere]">
            {step}
          </li>
        ))}
      </ol>
      {redirectUri ? (
        <div className="grid gap-1">
          <span className="font-medium text-ink">Callback URL to register at the provider</span>
          <RedirectUri uri={redirectUri} tone="bg-2" />
        </div>
      ) : null}
      {(guide.screenshots ?? []).map((shot) => (
        // Plain <img>: these are static files the app serves, already the right size.
        <img key={shot.src} src={shot.src} alt={shot.alt} className="rounded-lg border border-line" loading="lazy" />
      ))}
      {(guide.pitfalls ?? []).length > 0 ? (
        <div className="grid gap-1" data-testid="connector-setup-pitfalls">
          <span className="flex items-center gap-1.5 font-medium text-ink">
            <TriangleAlert className="h-3.5 w-3.5" />
            If it doesn’t work
          </span>
          <ul className="ml-4 grid list-disc gap-1">
            {(guide.pitfalls ?? []).map((p, i) => (
              <li key={i}>{p}</li>
            ))}
          </ul>
        </div>
      ) : null}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        {guide.docsUrl ? (
          <a href={guide.docsUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-medium underline" data-testid="connector-setup-docs">
            {writtenFor}’s own documentation <ExternalLink className="h-3 w-3" />
          </a>
        ) : null}
        <span className="text-[11.5px]" data-testid={`connector-setup-source-${guide.source ?? "provider"}`}>
          {guide.source === "controlclaw"
            ? `Written by ControlClaw for ${writtenFor}, checked against its own documentation.`
            : `From the connector catalog’s notes for ${providerName}.`}
        </span>
      </div>
    </div>
  );
}
