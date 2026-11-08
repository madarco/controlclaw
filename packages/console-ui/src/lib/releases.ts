/**
 * Release versions and their short changelogs (`docs/features/agent-updates.md`, "Versions").
 *
 * A release is a controlclaw-ansible commit promoted to production. The repo keeps a
 * `releases.json` at its root, newest first, which `scripts/release.sh` there adds to on every
 * promotion: `{version, commit?, date, changes}`. A box writes the newest version of its own
 * checkout into `/etc/controlclaw/release.json`; the console reads the same file at the commit an
 * Update would install. Everything here turns those two into the labels people see. Nothing in
 * this file decides whether a box is current: that is still the commit comparison in
 * `update-available.ts`.
 */
import { buildLabel, sameCommit } from "./software-schema";

export { buildLabel };

export type Release = {
  version: string;
  /** Set only on releases made before the file existed (1.0.0): a file cannot name its own commit. */
  commit?: string;
  /** YYYY-MM-DD. */
  date: string;
  changes: string[];
  /** Optional in the file; `releaseKind` derives it from the version when absent. */
  kind?: ReleaseKind;
};

export type ReleaseKind = "major" | "minor" | "patch";
const KINDS: readonly string[] = ["major", "minor", "patch"] satisfies ReleaseKind[];

/** The changes between two releases, ready to draw. `more` counts the lines left out. */
export type ReleaseChanges = { lines: string[]; more: number };

/** How many change lines a dialog shows before "and N more". */
export const MAX_CHANGE_LINES = 8;

const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;

export function isVersion(value: unknown): value is string {
  return typeof value === "string" && SEMVER.test(value);
}

/** Negative when `a` is older than `b`. Both must be versions. */
export function compareVersions(a: string, b: string): number {
  const x = a.split(".").map(Number);
  const y = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if (x[i] !== y[i]) return x[i]! - y[i]!;
  }
  return 0;
}

/**
 * `releases.json`, checked and sorted newest first. A malformed entry is skipped rather than
 * failing the file: the file is hand-edited, and one bad line should not hide every version.
 * Null when it is not a list at all.
 */
export function parseReleases(body: unknown): Release[] | null {
  if (!Array.isArray(body)) return null;
  const seen = new Set<string>();
  const out: Release[] = [];
  for (const row of body) {
    if (!row || typeof row !== "object") continue;
    const r = row as Record<string, unknown>;
    if (!isVersion(r.version) || seen.has(r.version)) continue;
    if (typeof r.date !== "string" || !DAY.test(r.date)) continue;
    const changes = Array.isArray(r.changes)
      ? r.changes.filter((c): c is string => typeof c === "string" && c.trim().length > 0).map((c) => c.trim().slice(0, 300))
      : [];
    seen.add(r.version);
    out.push({
      version: r.version,
      date: r.date,
      changes,
      ...(typeof r.commit === "string" && r.commit.length >= 7 ? { commit: r.commit } : {}),
      ...(typeof r.kind === "string" && KINDS.includes(r.kind) ? { kind: r.kind as ReleaseKind } : {}),
    });
  }
  return out.sort((a, b) => compareVersions(b.version, a.version));
}

/**
 * Major, minor or patch: what the entry says, else the step its version took (`release.sh`
 * bumps one part and zeroes the ones after it, so 1.4.0 is a minor and 2.0.0 a major).
 */
export function releaseKind(release: Pick<Release, "version" | "kind">): ReleaseKind {
  if (release.kind) return release.kind;
  const [, minor, patch] = release.version.split(".").map(Number);
  if (patch !== 0) return "patch";
  return minor !== 0 ? "minor" : "major";
}

/** What a box says it has installed, as far as naming it goes. */
export type InstalledRelease = { commit: string; commitDate: string; version?: string | null };

/**
 * The version a box is on: what it reported, else the release whose commit it is on, else null.
 * The second case is a box provisioned before release.json carried a version. `releases` is the
 * file at `targetSha`, so a box already on that commit is on its newest entry, even though only
 * 1.0.0 names a commit.
 */
export function installedVersion(
  installed: InstalledRelease,
  releases: readonly Release[] | null,
  targetSha?: string | null,
): string | null {
  if (isVersion(installed.version)) return installed.version;
  if (targetSha && releases?.[0] && sameCommit(installed.commit, targetSha)) return releases[0].version;
  const match = releases?.find((r) => r.commit && sameCommit(r.commit, installed.commit));
  return match?.version ?? null;
}

/**
 * The name for an installed release: "1.2.0", or "1 Oct build" when it has no version.
 * With `beforeFirst`, a build older than every release reads "before 1.0.0", which is what the
 * from→to pair of an update says.
 */
export function installedName(
  installed: InstalledRelease,
  releases: readonly Release[] | null,
  opts: { beforeFirst?: boolean; targetSha?: string | null } = {},
): string {
  const version = installedVersion(installed, releases, opts.targetSha);
  if (version) return version;
  const oldest = releases?.length ? releases[releases.length - 1]! : null;
  if (opts.beforeFirst && oldest && installed.commitDate.slice(0, 10) < oldest.date) return `before ${oldest.version}`;
  return buildLabel(installed.commitDate);
}

/**
 * The name for the commit an Update would install, from that commit's own releases.json.
 * The newest entry is its version. When the box already has that version but is on another
 * commit (an unreleased commit on a dev branch), the date says which build.
 */
export function targetName(
  target: { sha: string; date: string },
  releases: readonly Release[] | null,
  installed: InstalledRelease | null,
): string {
  const newest = releases?.[0];
  if (!newest) return buildLabel(target.date);
  if (installed && !sameCommit(installed.commit, target.sha) && installedVersion(installed, releases) === newest.version) {
    return `${newest.version} (${buildLabel(target.date)})`;
  }
  return newest.version;
}

/**
 * The changes an Update would bring, newest first: every release after the installed one, up to
 * the newest in the target's file. A box with no version counts releases dated after its commit.
 */
export function changesSince(
  installed: InstalledRelease | null,
  releases: readonly Release[] | null,
  max: number = MAX_CHANGE_LINES,
): ReleaseChanges {
  if (!releases?.length) return { lines: [], more: 0 };
  const from = installed ? installedVersion(installed, releases) : null;
  const day = installed?.commitDate.slice(0, 10) ?? null;
  // The date fallback is inclusive: a release's date is when it was promoted, not when its commit
  // was made, so a box built the same day may or may not have it. Listing a change it already has
  // is the smaller mistake than hiding one it does not.
  const newer = releases.filter((r) => (from ? compareVersions(r.version, from) > 0 : day ? r.date >= day : true));
  const all = newer.flatMap((r) => r.changes);
  return { lines: all.slice(0, max), more: Math.max(0, all.length - max) };
}
