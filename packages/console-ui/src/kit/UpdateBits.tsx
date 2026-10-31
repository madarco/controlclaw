"use client";

import { Download, Loader2 } from "lucide-react";
import { cn } from "../lib/utils";
import { Button } from "../ui/button";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "../ui/alert-dialog";
import type { VmUpdateProgress } from "../lib/vm-states";
import type { BoxSoftwareView } from "../lib/software-schema";
import type { ReleaseChanges } from "../lib/releases";
import type { UpdateAvailableView } from "../lib/update-available";
import { availableLine, clockTime, updateRunLine } from "../lib/update-lines";

/**
 * The three pieces of an update that both the agent's page and the firewall's page need: the
 * question before it starts, the line while it runs, and the line saying whether there is anything
 * to get.
 *
 * Shared because the two pages describe the same operation. Before this, one of them started a
 * multi-minute root-level reinstall on a single click with no dialog, no toast and no progress —
 * which is what T-81 is about.
 */

/** What the dialog says, per box kind. The agent's and the firewall's consequences differ. */
export type UpdateConfirmCopy = {
  title: string;
  /** The paragraphs of the body. Each is rendered as its own line. */
  lines: React.ReactNode[];
  /** The confirming button. */
  action: string;
};

/**
 * "1.2.0 → 1.4.0" and what changed in between, newest first, at most a few lines and then "and N
 * more". Draws nothing when there is neither a version pair nor a change to list, so a box on a
 * commit with no releases file gets the dialog it had before.
 */
export function ReleaseNotes({
  from,
  to,
  changes,
  className,
  testId = "release-notes",
}: {
  from: string | null;
  to: string | null;
  changes: ReleaseChanges;
  className?: string;
  testId?: string;
}) {
  const pair = to && from && from !== to ? `${from} → ${to}` : to;
  if (!pair && changes.lines.length === 0) return null;
  return (
    <div className={cn("rounded-[10px] border border-line px-3.5 py-2.5 text-left", className)} data-testid={testId}>
      {pair ? (
        <div className="font-mono text-[12.5px] font-semibold text-ink" data-testid={`${testId}-pair`}>
          {pair}
        </div>
      ) : null}
      {changes.lines.length > 0 ? (
        <ul className="mt-1.5 list-disc space-y-1 pl-4 text-[13px] text-ink-2">
          {changes.lines.map((line, i) => (
            <li key={i}>{line}</li>
          ))}
          {changes.more > 0 ? <li className="list-none -ml-4">and {changes.more} more</li> : null}
        </ul>
      ) : null}
    </div>
  );
}

export function UpdateConfirmDialog({
  open,
  copy,
  busy,
  onConfirm,
  onCancel,
  available,
  testId = "update-confirm",
}: {
  open: boolean;
  copy: UpdateConfirmCopy;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  /** The update on offer: its versions and changes go under the copy. */
  available?: UpdateAvailableView | null;
  testId?: string;
}) {
  return (
    <AlertDialog open={open} onOpenChange={(o) => !o && !busy && onCancel()}>
      <AlertDialogContent data-testid={testId}>
        <AlertDialogHeader>
          <AlertDialogTitle>{copy.title}</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-2.5 text-[13.5px]">
              {copy.lines.map((line, i) => (
                <p key={i}>{line}</p>
              ))}
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        {available?.state === "available" ? (
          <ReleaseNotes from={available.fromVersion} to={available.toVersion} changes={available.changes} testId={`${testId}-notes`} />
        ) : null}
        <AlertDialogFooter sticky>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          {/* Not AlertDialogAction: that closes on click, which would hide the spinner while the
              firewall is being asked to send a code. */}
          <Button disabled={busy} onClick={onConfirm} data-testid={`${testId}-submit`}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
            {copy.action}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

const TONE_CLASS = {
  busy: "text-ink-2",
  ok: "text-ink-2",
  err: "text-block-fg",
} as const;

/**
 * The line under the buttons: what the run is doing, when it started, and — once it is over — what
 * it installed or why it stopped.
 *
 * Renders nothing when no run has anything to say, so a page with no update history stays quiet.
 */
export function UpdateProgressLine({
  progress,
  startedAt,
  installed,
  available,
  failedFallback,
  updating = false,
  onRetry,
  className,
  testId,
}: {
  progress: VmUpdateProgress | null | undefined;
  startedAt: string | null | undefined;
  installed?: BoxSoftwareView | null;
  /** The update on offer, which names the version a run installs. */
  available?: UpdateAvailableView | null;
  failedFallback: string;
  /** A run is in flight on our side, even if the box has not reported yet. */
  updating?: boolean;
  /** Offered only on a failure. Absent for a reader who may not update this box. */
  onRetry?: () => void;
  className?: string;
  testId?: string;
}) {
  const line = updateRunLine(progress, { startedAt, installed, available, failedFallback, updating });
  if (!line) return null;
  const started = line.startedAt ? clockTime(line.startedAt) : null;
  return (
    <p className={cn("flex w-full flex-wrap items-center gap-x-2 gap-y-1 text-[13px]", TONE_CLASS[line.tone], className)} data-testid={testId}>
      {line.tone === "busy" ? <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" /> : null}
      <span>
        {line.tone === "busy" ? "Updating… " : null}
        {/* The clock is the reader's own, so server and browser render different text here on
            purpose. See `clockTime`. */}
        {started ? (
          <span suppressHydrationWarning data-testid={testId ? `${testId}-started` : undefined}>
            started {started}
          </span>
        ) : null}
        {started ? " · " : null}
        {line.text}
      </span>
      {line.tone === "err" && onRetry ? (
        <Button size="sm" variant="outline" onClick={onRetry} data-testid={testId ? `${testId}-retry` : undefined}>
          Retry
        </Button>
      ) : null}
    </p>
  );
}

/**
 * "Update available: 1.4.0", "Up to date", or why we cannot tell.
 *
 * Sits next to the Update button rather than under it: the button is the thing the sentence is
 * about, and someone scanning the section for "do I need to do anything" should not have to read
 * the version rows to find out.
 */
export function UpdateAvailableLine({
  available,
  running,
  className,
  testId,
}: {
  available: UpdateAvailableView | null | undefined;
  running: boolean;
  className?: string;
  testId?: string;
}) {
  const line = availableLine(available, { running });
  if (!line) return null;
  return (
    <span
      className={cn("text-[12.5px]", line.highlight ? "font-semibold text-ask-fg" : "text-ink-2", className)}
      data-testid={testId}
    >
      {line.text}
      {/* The version is the detail; at phone width the section heading, this line and the button
          share 375px, and the row they sit in cannot shrink (`Sec`'s `right` is shrink-0). The
          dialog the button opens names it again, with what changed. */}
      {line.detail ? <span className="hidden sm:inline">{line.detail}</span> : null}
    </span>
  );
}

/**
 * The availability line and the Update button, side by side: "Update available: 1.4.0" next to a
 * button that stands out, or "Up to date" next to a quiet one. The agent's Software section and the
 * firewall's status card both draw it, so the two pages cannot drift apart.
 *
 * It only draws. Whether pressing it may start anything, and what it opens, stays with the page.
 * Wraps the line above the button at phone width rather than squeezing the button.
 */
export function UpdateControl({
  available,
  running,
  spinning,
  disabled,
  onClick,
  className,
  testId,
  lineTestId,
}: {
  available: UpdateAvailableView | null | undefined;
  /** A run is in flight: the button says so and the availability answer is withheld. */
  running: boolean;
  /** Spinner on the button: a run in flight, or one being asked for. */
  spinning: boolean;
  disabled: boolean;
  onClick: () => void;
  className?: string;
  testId?: string;
  lineTestId?: string;
}) {
  return (
    <span className={cn("flex flex-wrap items-center justify-end gap-x-2.5 gap-y-1", className)}>
      <UpdateAvailableLine available={available} running={running} testId={lineTestId} />
      <Button
        size="sm"
        variant={available?.state === "available" && !running ? "default" : "outline"}
        disabled={disabled}
        onClick={onClick}
        data-testid={testId}
      >
        {spinning ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
        {running ? "Updating…" : "Update"}
      </Button>
    </span>
  );
}

/**
 * Why the console cannot say whether there is an update, in the section body rather than beside the
 * button.
 *
 * These are sentences — "could not reach GitHub", "checked too often just now" — and the row beside
 * the button is `shrink-0`, so a sentence there makes the page scroll sideways on a phone. Here it
 * has the width to wrap.
 */
export function UpdateUnknownReason({
  available,
  running,
  className,
  testId,
}: {
  available: UpdateAvailableView | null | undefined;
  running: boolean;
  className?: string;
  testId?: string;
}) {
  if (running || available?.state !== "unknown" || !available.reason) return null;
  return (
    <p className={cn("text-[12.5px] text-ink-2", className)} data-testid={testId}>
      {available.reason}
    </p>
  );
}

/**
 * The small marker an agent or firewall card carries when there is newer software. A card is a
 * glance, so it says only that much and links nowhere on its own — the card already links to the
 * page that explains it.
 */
export function UpdateAvailableBadge({ className, testId = "update-available-badge" }: { className?: string; testId?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-[20px] shrink-0 items-center gap-1 rounded-full border border-ask-border bg-ask-soft px-2 text-[11px] font-semibold text-ask-fg",
        className,
      )}
      data-testid={testId}
      title="Newer software is available for this box"
    >
      <Download className="h-[11px] w-[11px]" />
      Update
    </span>
  );
}
