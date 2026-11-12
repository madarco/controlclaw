import { z } from "zod";
import type { VmSoftware } from "./vm-states";

/**
 * What a box says it is running, on the way in and on the way out.
 * See `apps/saas/docs/features/agent-settings.md` ("Which version is my agent running").
 *
 * Everything in here arrives from a box. A box is the one thing in this system we assume can be
 * taken — that is the whole premise of the firewall — so these strings are treated as display
 * text and nothing else: capped hard, never parsed into a decision, never matched against
 * anything the control plane holds. The worst a lying box can do is show its owner a wrong
 * version number.
 */

/** Long enough for a full 40-char SHA and an ISO timestamp; short enough that a beat stays tiny. */
const FIELD = 64;
const field = z.string().min(1).max(FIELD);

/**
 * Every part is optional and nullable on purpose. A box provisioned before the release file
 * existed sends `release: null`; a firewall sends no `openclaw` at all; an older daemon sends
 * none of it. Unknown keys are dropped by zod, which is also what caps the payload.
 */
export const boxSoftwareSchema = z.object({
  rebootRequired: z.boolean().optional(),
  bootedAt: z.string().datetime().optional(),
  agent: z.object({ version: field, commit: field, builtAt: field }).nullish(),
  release: z
    .object({
      commit: field,
      commitDate: field,
      installedAt: field,
      // Optional: older boxes do not send it. Anything not shaped like 1.4.0 is dropped, not refused.
      version: z
        .string()
        .max(FIELD)
        .optional()
        .catch(undefined)
        .transform((v) => (v && /^\d+\.\d+\.\d+$/.test(v) ? v : undefined)),
    })
    .nullish(),
  openclaw: field.nullish(),
  // What the box can do (browser-enrollment.md §10). Only names this control plane knows are kept.
  // A long list is cut, never a reason to refuse the report: a box that gains a feature must not
  // lose its whole software report for it. (At 20 the list was full, and an agent that reported one
  // more was shown with the software it had before for good: found on a real pair, 12 October 2026.)
  features: z
    .array(z.unknown())
    .nullish()
    .transform((list) => (list ?? []).filter((f): f is string => typeof f === "string" && f.length <= 64).slice(0, 200)),
});

/**
 * The box features the control plane acts on, or keeps for operators. Anything else a box says is
 * dropped, so a feature the console reads and this list lacks is never seen, whatever the box
 * reports: a name is added here in the same change that first reads it. `software.test.ts` reads the
 * code for every such read and fails when one is missing. Four are kept with no reader yet, for
 * operators: `rust_runtime` (a Rust build), `runtime_fallback` (a Rust build crash-looped or could not
 * be switched to, and the Node build runs; docs/plans/rust-rewrite.md §5.1), and `agent_port_3102` (the
 * vm-agent runs on 3102: the count of boxes without it says when 3100 can be dropped,
 * docs/ops/t-vmagent-port-3102.md), and `approvals_via_firewall` (the vm-agent sends OpenClaw's
 * approvals to its firewall, whose Auto approve rules answer them; the count of boxes without it says
 * how many still ask the console directly).
 */
const KNOWN_FEATURES = new Set(["templates", "templates_apply", "templates_org", "templates_review", "templates_capture", "templates_steps2", "templates_bundles", "templates_check", "templates_repair", "templates_capture_ai", "open_v1", "logs_page", "whatsapp_page", "meetings_page", "phone_page", "doctor_v1", "console_mcp", "speech_realtime", "speech_live", "speech_wake", "speech_wake_local", "speech_always", "meeting_full_agent", "phone_voice_edit", "meeting_followup", "meetings_autojoin", "fw_tokens_bound", "skills_start", "skills_remove", "skills_capture", "notes_start", "disk_partners", "templates_code", "storage_grow", "skills_apply", "notes_apply", "llm_blocks", "meeting_present", "meeting_consult_model", "meeting_instructions", "rust_runtime", "runtime_fallback", "agent_port_3102", "approvals_via_firewall"]);

/** `null` when the box sent nothing usable — which reads as "not reported" everywhere. */
export function parseBoxSoftware(input: unknown): VmSoftware | null {
  const parsed = boxSoftwareSchema.safeParse(input);
  if (!parsed.success) return null;
  const { agent, release, openclaw } = parsed.data;
  // A payload with all three empty is a box saying nothing, not a version. Storing it would
  // replace "Not reported" with three blank lines.
  if (!agent && !release && !openclaw) return null;
  const features = (parsed.data.features ?? []).filter((f) => KNOWN_FEATURES.has(f));
  return { ...(parsed.data.rebootRequired !== undefined ? { rebootRequired: parsed.data.rebootRequired } : {}), ...(parsed.data.bootedAt ? { bootedAt: parsed.data.bootedAt } : {}), agent: agent ?? null, release: release ? withoutEmptyVersion(release) : null, openclaw: openclaw ?? null, ...(features.length ? { features } : {}) };
}

/** `{..., version: undefined}` would be stored as is; a release with no version has no key. */
function withoutEmptyVersion<T extends { version?: string }>(release: T): T {
  if (release.version !== undefined) return release;
  const { version: _drop, ...rest } = release;
  return rest as T;
}

/**
 * Whether a report differs from what is stored. Field by field rather than `JSON.stringify`:
 * key order is a property of whoever built the object, and a spurious "changed" here means a
 * database write on every heartbeat — one per box every five seconds.
 */
/** Whether what a box says it can do changed. Kept apart from the version: see `recordVmSoftware`. */
export function featuresChanged(prev: VmSoftware | null | undefined, next: VmSoftware): boolean {
  return [...(prev?.features ?? [])].sort().join(",") !== [...(next.features ?? [])].sort().join(",");
}

export function softwareChanged(prev: VmSoftware | null | undefined, next: VmSoftware): boolean {
  if (!prev) return true;
  if (prev.rebootRequired !== next.rebootRequired || prev.bootedAt !== next.bootedAt) return true;
  if (prev.openclaw !== next.openclaw) return true;
  if (
    prev.agent?.version !== next.agent?.version ||
    prev.agent?.commit !== next.agent?.commit ||
    prev.agent?.builtAt !== next.agent?.builtAt
  ) {
    return true;
  }
  return (
    prev.release?.commit !== next.release?.commit ||
    prev.release?.commitDate !== next.release?.commitDate ||
    prev.release?.installedAt !== next.release?.installedAt ||
    prev.release?.version !== next.release?.version
  );
}

// ---- what the console shows ----

export type BoxSoftwareView = {
  rebootRequired?: boolean;
  bootedAt?: string;
  /** Since when the box has been on this version — not when it last checked in. */
  reportedAt: string | null;
  release: { commit: string; shortCommit: string; commitDate: string; installedAt: string; version?: string } | null;
  agent: { version: string; commit: string; builtAt: string } | null;
  openclaw: string | null;
};

/**
 * Whether there is anything to show, i.e. whether the box has ever reported.
 *
 * Exactly the inverse of what `parseBoxSoftware` stores: it keeps a report with ANY of the three
 * parts, so a box that could name only its OpenClaw version — release file missing, build stamp
 * stripped — has reported, and telling it "created before versions were tracked, update it" would
 * be wrong twice over, since updating would not change what it says. One helper rather than a
 * condition in the component, so the two rules cannot drift apart again.
 */
export function hasReported(view: BoxSoftwareView | null | undefined): view is BoxSoftwareView {
  return !!view && (!!view.release || !!view.agent || !!view.openclaw);
}

/** Git short SHAs are seven characters. A box that sent something else gets shown what it sent. */
export function shortCommit(commit: string): string {
  return /^[0-9a-f]{8,40}$/i.test(commit) ? commit.slice(0, 7) : commit;
}

/** Whether two SHAs name the same commit, given either may be abbreviated. */
export function sameCommit(a: string | null | undefined, b: string | null | undefined): boolean {
  if (!a || !b) return false;
  const x = a.trim().toLowerCase();
  const y = b.trim().toLowerCase();
  const n = Math.min(x.length, y.length);
  // Seven is a short SHA; below that a prefix match is coincidence rather than identity.
  if (n < 7) return x === y;
  return x.slice(0, n) === y.slice(0, n);
}

export function softwareView(
  software: VmSoftware | null | undefined,
  reportedAt: Date | null | undefined,
): BoxSoftwareView | null {
  if (!software) return null;
  return {
    reportedAt: reportedAt?.toISOString() ?? null,
    rebootRequired: software.rebootRequired,
    bootedAt: software.bootedAt,
    release: software.release
      ? { ...software.release, shortCommit: shortCommit(software.release.commit) }
      : null,
    agent: software.agent,
    openclaw: software.openclaw,
  };
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/**
 * "19 Sep 2026" in UTC, from a string a box sent. Hand-built like `createdLabel`, for the same
 * reason (Node's and the browser's month abbreviations differ, which hydrates as a mismatch) —
 * and a date that will not parse is shown as sent rather than as "Invalid Date".
 */
export function softwareDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso.slice(0, 32);
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

/** "1 Oct build": how a release with no version is named. UTC, hand-built for the same reason as `softwareDate`. */
export function buildLabel(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "unknown build";
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} build`;
}

/**
 * "1.4.0", the one line that answers "which version is this box on". A box that did not report a
 * version gets `name` when the caller could work one out from the releases list
 * (`installedName` in releases.ts), else "1 Oct build". The commit is never the visible text: it
 * goes in a tooltip (`releaseTitle`).
 */
export function releaseLabel(view: BoxSoftwareView, name?: string | null): string | null {
  if (!view.release) return null;
  return view.release.version ?? name ?? buildLabel(view.release.commitDate);
}

/** "Build a1b2c3d, 19 Sep 2026": the tooltip under the version, for support. */
export function releaseTitle(view: BoxSoftwareView): string | null {
  if (!view.release) return null;
  return `Build ${view.release.shortCommit}, ${softwareDate(view.release.commitDate)}`;
}

/** "daemon 0.1.0" — the second line, for when the release alone does not explain things. */
export function agentBuildLabel(view: BoxSoftwareView): string | null {
  if (!view.agent) return null;
  return `daemon ${view.agent.version}`;
}
