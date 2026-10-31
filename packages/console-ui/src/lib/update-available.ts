import type { VmAnsibleSource } from "./vm-states";
import type { BoxSoftwareView } from "./software-schema";
import { changesSince, installedName, targetName, type Release, type ReleaseChanges } from "./releases";
import { sameCommit, shortCommit } from "./software-schema";

export { sameCommit };

/**
 * Whether a box has anything newer to install, decided the same way the box would decide it.
 *
 * The box never asks us what to pull — that is the point of `docs/features/agent-updates.md` — so
 * this file does not choose a version. It answers a different question: *if you pressed Update
 * now, would anything change?* To answer it honestly it has to apply the box's own rule, because
 * the newest commit on the branch and the newest commit the box will accept are usually not the
 * same commit.
 *
 * The rule (`cc-reprovision` in the Ansible repo): the newest commit on the pinned branch that is
 * at least 24 hours old, unless the box was provisioned with `update_allow_unverified`, in which
 * case plain branch HEAD. A console that skipped the 24h wait would promise an update that the box
 * then refuses with "no commit on main is at least 24h old yet" — the exact confusing pair this
 * feature exists to prevent.
 *
 * Everything here is display text and a boolean. Nothing decides what gets installed.
 */

/** The box installs nothing younger than this. Mirrors `cc-reprovision`. */
export const AGED_MS = 24 * 60 * 60 * 1000;

/** One upstream commit, as much of it as this feature needs. */
export type UpstreamCommit = {
  /** Full SHA, as GitHub gave it. */
  sha: string;
  /** When it was committed, ISO. The date the 24h rule is measured against. */
  date: string;
};

/**
 * What the console says about newer software, for one box.
 *
 * `unknown` is its own state rather than a silent fall back to "Up to date": the upstream lookup
 * goes over the internet and can rate-limit or fail, and a box shown as current because we could
 * not check is a box whose owner stops checking.
 */
export type UpdateAvailableView = {
  state: "available" | "current" | "unknown";
  /** The commit an Update would install, when we know it. */
  commit: string | null;
  shortCommit: string | null;
  /** That commit's date, ISO. */
  date: string | null;
  /** Why the answer is `unknown`, in the person's terms. Null otherwise. */
  reason: string | null;
  /**
   * What the box runs now, as people read it: "1.2.0", "before 1.0.0", "1 Oct build". Null when
   * the box has not reported a release. Display only, like everything below (releases.ts).
   */
  fromVersion: string | null;
  /** What an Update would install: "1.4.0", or "1 Oct build" when that commit has no releases file. */
  toVersion: string | null;
  /** The changes of every release in between, newest first. Empty when there is nothing to list. */
  changes: ReleaseChanges;
};

export const NO_CHANGES: ReleaseChanges = { lines: [], more: 0 };

export const UNKNOWN_AVAILABLE: UpdateAvailableView = {
  state: "unknown",
  commit: null,
  shortCommit: null,
  date: null,
  reason: null,
  fromVersion: null,
  toVersion: null,
  changes: NO_CHANGES,
};

/** `owner/repo` out of the clone URL a box was pinned to, or null if it is not a GitHub URL. */
export function parseGitHubRepo(repoUrl: string): { owner: string; repo: string } | null {
  const m = /^(?:https?:\/\/|git@)github\.com[/:]([^/]+)\/(.+?)(?:\.git)?\/*$/.exec(repoUrl.trim());
  if (!m) return null;
  const owner = m[1]!;
  const repo = m[2]!;
  // A path with more segments is not a repo URL; refusing beats asking GitHub about "a/b/c".
  if (!owner || !repo || repo.includes("/")) return null;
  return { owner, repo };
}

/**
 * The commit an Update would install, out of a branch's commits newest-first.
 *
 * Returns null when the branch has nothing the box would accept — which is a real answer, not a
 * failure: on a quiet branch every commit can be younger than a day.
 */
export function pickEligibleCommit(
  commits: readonly UpstreamCommit[],
  opts: { allowUnverified: boolean; now: Date },
): UpstreamCommit | null {
  if (commits.length === 0) return null;
  if (opts.allowUnverified) return commits[0]!;
  const cutoff = opts.now.getTime() - AGED_MS;
  // Newest-first, so the first one old enough is the newest one old enough. A commit with an
  // unparseable date is skipped rather than guessed at.
  for (const c of commits) {
    const at = Date.parse(c.date);
    if (Number.isFinite(at) && at <= cutoff) return c;
  }
  return null;
}

/**
 * The view for one box, from what it reports installed and what upstream offers.
 *
 * The date comparison is not redundant with the SHA one. A dev-secured box can be built from a
 * branch whose tip it already passed, and a box that reports a commit we cannot find upstream
 * would otherwise be told an older commit is "available" — an Update that moves it backwards.
 * Different SHA *and* strictly newer is the only combination that means "there is something to
 * get".
 *
 * NOTE: this compares a string the BOX reported, which `software.schema.ts` otherwise says is
 * never matched against anything the control plane holds. The exception is deliberate and worth
 * stating, because there is no second source: only the box knows what is installed on it. What it
 * buys a box that has been taken is the ability to suppress its own "Update available" marker by
 * reporting the current upstream SHA — it can hide a pending update from its owner, and nothing
 * more. It cannot cause an update, choose one, or stop one: the button still works, and what gets
 * installed is decided on the box from a pin the box cannot write.
 */
export function availableView(
  installed: BoxSoftwareView | null | undefined,
  upstream: UpstreamCommit | null,
  reason: string | null = null,
  /** releases.json at `upstream.sha`, when the console could read it. Names only; decides nothing. */
  releases: readonly Release[] | null = null,
): UpdateAvailableView {
  if (!upstream) return { ...UNKNOWN_AVAILABLE, reason };
  const release = installed?.release ?? null;
  const view = {
    commit: upstream.sha,
    shortCommit: shortCommit(upstream.sha),
    date: upstream.date,
    reason: null,
    fromVersion: release ? installedName(release, releases, { beforeFirst: true, targetSha: upstream.sha }) : null,
    toVersion: targetName(upstream, releases, release),
    changes: NO_CHANGES,
  };
  // Nothing to compare against: a box that has never reported its release cannot be called
  // current, and calling it stale would put an "Update available" badge on every old box.
  if (!release) return { ...view, state: "unknown", reason: "This box hasn’t reported which version it is on." };
  if (sameCommit(release.commit, upstream.sha)) return { ...view, state: "current" };
  const installedAt = Date.parse(release.commitDate);
  const upstreamAt = Date.parse(upstream.date);
  if (Number.isFinite(installedAt) && Number.isFinite(upstreamAt) && upstreamAt <= installedAt) {
    return { ...view, state: "current" };
  }
  return { ...view, state: "available", changes: changesSince(release, releases) };
}

/**
 * The 24h rule applies per box, and whether it applies at all was decided when the box was built.
 * Rows from before that was recorded fall back to the control plane's current setting, which is
 * the same value they were created with unless an operator changed it since — said plainly here
 * because it is the one guess in this file.
 */
export function allowsUnverified(source: VmAnsibleSource | null | undefined, envFlag: boolean): boolean {
  return source?.allowUnverified ?? envFlag;
}
