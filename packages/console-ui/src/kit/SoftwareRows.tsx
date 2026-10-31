import { agentBuildLabel, hasReported, releaseLabel, releaseTitle, softwareDate, type BoxSoftwareView } from "../lib/software-schema";

/**
 * What one box is running, in plain words. Shared by the agent's settings page (which shows two
 * of these, the agent's and the organization's firewall) and by the Firewall page (which shows
 * its own). One component so the two pages cannot drift into describing the same thing
 * differently. See `apps/saas/docs/features/agent-settings.md`.
 *
 * Read-only by design: knowing what a box runs is a fact about it, so every role that can open
 * the page sees it, and there is no action here. Updating is the Update button's job and its
 * rules are unchanged.
 */

/** Copy for a box that has never reported. The Update button is what fixes it. */
export const NOT_REPORTED = "Not reported. This box was created before versions were tracked. Update it to see its version.";

/**
 * Label left, value right. The daemon build sits on its own line under the value rather than
 * beside it: in the two-column layout on the agent's page the pair is too long for one line, and
 * letting it wrap on its own put one row's value under its label while the others stayed beside
 * theirs.
 */
function Row({ label, value, sub, title }: { label: string; value: string; sub?: string | null; title?: string | null }) {
  return (
    <div className="flex items-baseline justify-between gap-x-4 py-1.5">
      <dt className="shrink-0 text-[13px] text-ink-2">{label}</dt>
      <dd className="min-w-0 text-right">
        <div className="truncate font-mono text-[12.5px] text-ink" title={title ?? value}>
          {value}
        </div>
        {sub ? <div className="truncate text-[12px] text-ink-2">{sub}</div> : null}
      </dd>
    </div>
  );
}

export function SoftwareRows({
  title,
  software,
  /** "Agent software" / "Firewall software" — the label on the version line. */
  versionLabel,
  /** Agent boxes run OpenClaw; firewall boxes do not, so the row is left out there. */
  showOpenClaw = false,
  version,
  testId,
  action,
}: {
  title: string;
  software: BoxSoftwareView | null;
  versionLabel: string;
  /**
   * The release's name when the console worked one out from the releases list
   * (`UpdateAvailableView.fromVersion`), for a box too old to report its own version.
   */
  version?: string | null;
  showOpenClaw?: boolean;
  testId: string;
  action?: React.ReactNode;
}) {
  return (
    <div data-testid={testId}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div className="text-[14px] font-semibold text-ink">{title}</div>
        {action}
      </div>
      {hasReported(software) ? (
        <dl className="mt-2 divide-y divide-line/60">
          <Row
            label={versionLabel}
            value={releaseLabel(software, version) ?? "Not reported"}
            title={releaseTitle(software)}
            sub={agentBuildLabel(software)}
          />
          {software.bootedAt ? <Row label="Last boot" value={new Date(software.bootedAt).toISOString().replace("T", " ").slice(0, 16) + " UTC"} /> : null}
          {software.rebootRequired !== undefined ? <Row label="Restart required" value={software.rebootRequired ? "Yes, at the next maintenance run" : "No"} /> : null}
          {showOpenClaw ? <Row label="OpenClaw" value={software.openclaw ?? "Not reported"} /> : null}
          <Row
            label="Installed on"
            value={software.release ? softwareDate(software.release.installedAt) : "Not reported"}
          />
        </dl>
      ) : (
        <p className="mt-2 max-w-[70ch] text-[13px] text-ink-2" data-testid={`${testId}-empty`}>
          {NOT_REPORTED}
        </p>
      )}
    </div>
  );
}
