import type { VmUpdateProgress } from "./vm-states";
import { type BoxSoftwareView, releaseLabel } from "./software-schema";
import { sameCommit, type UpdateAvailableView } from "./update-available";

/**
 * The words the console uses about an update in flight, shared by the agent's page and the
 * firewall's.
 *
 * Both had their own copy of this and the copies had already drifted — one said "Up to date." when
 * a run finished, the other named no commit at all, and neither said when the run started. One
 * module, because the two screens describe the same operation and a person who has seen one should
 * recognise the other.
 */

/** A full or abbreviated SHA. Anything else a box calls a `ref` is a branch name. */
const COMMITISH = /^[0-9a-f]{7,40}$/i;

/** The phases in which `cc-reprovision` is actually doing something. */
export const RUNNING_PHASES: ReadonlySet<VmUpdateProgress["phase"]> = new Set(["resolving", "installing", "running"]);

export function isRunningPhase(phase: VmUpdateProgress["phase"] | null | undefined): boolean {
  return !!phase && RUNNING_PHASES.has(phase);
}

/**
 * "14:32" in the reader's own timezone.
 *
 * Callers render this inside `suppressHydrationWarning`: the server and the browser are in
 * different timezones as a rule, so this is one of the few strings that is *meant* to differ
 * between the two renders. Showing UTC instead would be wrong for everyone rather than briefly
 * wrong for one paint.
 */
export function clockTime(iso: string): string | null {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleTimeString(undefined, { hour12: false, hour: "2-digit", minute: "2-digit" });
}

/**
 * A word in a box's detail that is a commit: "pinned to 8ae4a29406707fc8". It needs a digit and a
 * letter a–f, so "Downloaded 1048576 bytes" or "defaced" stays the box's own words.
 */
const COMMIT_WORD = /\b(?=[0-9a-f]*[a-f])(?=[0-9a-f]*\d)[0-9a-f]{7,40}\b/i;

/**
 * What the box is doing, in the person's terms. The box's own detail wins when it has one, unless
 * it names a commit: `cc-reprovision` writes "pinned to <commit>" and "ansible-pull <commit>", and
 * people see versions, never commits (releases.ts).
 */
function phaseLine(p: VmUpdateProgress, name: string | null): string {
  const detail = p.detail && !COMMIT_WORD.test(p.detail) ? p.detail : null;
  if (p.phase === "resolving") return detail ?? "Working out which version to install…";
  if (p.phase === "installing") return detail ?? "Fetching what it needs…";
  return detail ?? (name ? `Installing ${name}` : "Installing");
}

/**
 * The version a run's `ref` names, when we can tell: the offered update if that is the commit, else
 * what the box reports when it is on it. Null for a ref we cannot name — a branch, or a commit
 * neither side knows.
 */
function refName(ref: string | null | undefined, installed: BoxSoftwareView | null | undefined, available: UpdateAvailableView | null | undefined): string | null {
  if (!ref || !COMMITISH.test(ref)) return null;
  if (available?.toVersion && sameCommit(available.commit, ref)) return available.toVersion;
  if (installed?.release && sameCommit(installed.release.commit, ref)) return releaseLabel(installed);
  return null;
}

export type UpdateLine = {
  /** The sentence to show. */
  text: string;
  /** How it reads: a run in flight, a finished one, or one that failed. */
  tone: "busy" | "ok" | "err";
  /** Present while a run is in flight and we know when it began; render with suppressHydrationWarning. */
  startedAt: string | null;
};

/**
 * One line describing the run, or null when there is nothing to say (no run has ever happened, or
 * the last one predates the box's current state).
 *
 * `installed` is what the box reports running *now*. It is what turns "done" into a sentence worth
 * reading: the box's own detail for a finished run is usually a bare commit, and the date only
 * exists on our side.
 */
export function updateRunLine(
  progress: VmUpdateProgress | null | undefined,
  opts: {
    /** When the run began, from the change row — the box's own clock is not ours. */
    startedAt?: string | null;
    installed?: BoxSoftwareView | null;
    /** What to say when the box failed without saying why. Differs per box kind. */
    failedFallback: string;
    /**
     * A run is in flight as far as our own records go, whatever the box has said.
     *
     * There is a gap between the code being accepted and the box's first report — seconds on an
     * agent, up to a minute on a firewall, whose progress only arrives on a heartbeat. Without
     * this the page shows nothing at all for that gap, which is the same blankness this whole
     * change exists to remove, and lands right after the button press when someone is watching.
     */
    updating?: boolean;
    /** The update on offer, which names the version a run is installing. */
    available?: UpdateAvailableView | null;
  },
): UpdateLine | null {
  if (!progress || progress.phase === "idle") {
    if (!opts.updating) return null;
    return { text: "Waiting for the box to report in…", tone: "busy", startedAt: opts.startedAt ?? null };
  }

  if (progress.phase === "failed") {
    return { text: progress.detail ?? opts.failedFallback, tone: "err", startedAt: null };
  }

  if (progress.phase === "done") {
    const ref = progress.ref;
    const release = opts.installed?.release ?? null;
    // Named only when we know which version the commit is: the box confirms it is on it, or it is
    // the update on offer. A mismatch means the report has not caught up yet.
    const name = refName(ref, opts.installed, opts.available);
    if (name) return { text: `Updated to ${name}`, tone: "ok", startedAt: null };
    // A box running with the 24h rule relaxed tracks a branch, and reports the BRANCH as its ref —
    // which is the production path today. "Updated to main" names the thing it followed, not the
    // thing it installed, so say what the box is on instead. Phrased as a statement about now
    // rather than about the run, because the release report is what it is at the moment of
    // rendering: claiming this run installed it would be a guess, and a stale report would make it
    // a wrong one.
    if (release && opts.installed && !(ref && COMMITISH.test(ref))) {
      return { text: `Updated. Now on ${releaseLabel(opts.installed)}`, tone: "ok", startedAt: null };
    }
    const detail = progress.detail && !COMMIT_WORD.test(progress.detail) ? progress.detail : null;
    return { text: detail ?? "The update finished.", tone: "ok", startedAt: null };
  }

  return { text: phaseLine(progress, refName(progress.ref, opts.installed, opts.available)), tone: "busy", startedAt: opts.startedAt ?? null };
}

// ---- "update available" ----

export type AvailableLine = {
  /** The short half, which always fits: "Update available" or "Up to date". */
  text: string;
  /** The version on offer, ": 1.4.0". Dropped where there is no room. */
  detail: string | null;
  /** Whether to draw attention to the Update button. */
  highlight: boolean;
};

/**
 * The line above the Update button: whether pressing it would get anything.
 *
 * Null while a run is in flight — "Update available" next to "Updating…" reads as though the update
 * running is not the one on offer, and the answer is about to change anyway.
 */
export function availableLine(view: UpdateAvailableView | null | undefined, opts: { running: boolean }): AvailableLine | null {
  if (!view || opts.running) return null;
  if (view.state === "current") return { text: "Up to date", detail: null, highlight: false };
  if (view.state === "available") {
    const detail = view.toVersion ? `: ${view.toVersion}` : null;
    return { text: "Update available", detail, highlight: true };
  }
  // A reason is a sentence, and this line sits in a row that cannot shrink. `UpdateUnknownReason`
  // shows it in the section body instead, where it has the width to wrap.
  return null;
}
