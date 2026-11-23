/**
 * The Brain Overview's arithmetic, without the database (docs/plans/brain-overview-charts.md):
 * which GBrain operations are searches and which are saves, GBrain's page types under friendly
 * names, and the "+4 Meetings" lines from two readings of the counts. Browser-safe: the console's
 * Brain page, its demo, `brain-stats.server.ts` and the firewall panel's Brain page share it.
 */

import { kindLabel } from "./brain-kinds";

/**
 * Searches: what an agent asks the brain. GBrain's tool catalog (v0.60.723.0) names them; a rename
 * on an update shows up in `brain-stats.e2e.test.ts`, which fails on an operation in no list.
 * Twin: `SEARCH_OPS` and `SAVE_OPS` in `rust/crates/cc-local/src/api/brain.rs` (a standalone
 * firewall's Brain stats); change both together.
 */
export const SEARCH_OPS = [
  "search",
  "query",
  "search_by_image",
  "recall",
  "context_pack",
  "find_experts",
  "takes_search",
  "search_exact",
  "find_pages",
  "memory_recall",
  "assemble_evidence",
] as const;

/** Saves: what an agent writes into the brain. */
export const SAVE_OPS = [
  "put_page",
  "capture",
  "remember",
  "add_link",
  "add_tag",
  "add_timeline_entry",
  "put_raw_data",
  "takes_add",
  "takes_update",
  "takes_supersede",
  "file_upload",
  "append_page",
  "edit_page",
  "put_pages",
  "memory_write",
  "commit_page_upload",
  "memory_propose",
  "confirm_memory",
  "promote_guest_note",
  "ontology_propose",
  "log_ingest",
  "revert_version",
  "takes_resolve",
] as const;

/** Neither: reads of one page, lists, housekeeping. Counted nowhere, listed so the test knows them. */
export const OTHER_OPS = [
  "get_page",
  "list_pages",
  "fetch",
  "get_tags",
  "get_links",
  "get_backlinks",
  "get_timeline",
  "get_chunks",
  "get_raw_data",
  "traverse_graph",
  "resolve_slugs",
  "whoami",
  "get_brain_identity",
  "get_stats",
  "get_health",
  "get_versions",
  "takes_list",
  "think",
  "remove_tag",
  "remove_link",
  "delete_page",
  "restore_page",
  "forget",
  "forget_fact",
  "facts",
  "entity",
  "synthesize",
  "chronicle_day",
  "chronicle_since",
  "chronicle_on_this_day",
  "chronicle_last_seen",
  "open_loops",
  "list_skills",
  "get_skill",
  "get_recent_transcripts",
  "request_tools",
  "abort_page_upload",
  "begin_page_upload",
  "cancel_write_request",
  "code_blast",
  "code_callees",
  "code_callers",
  "code_def",
  "code_flow",
  "code_refs",
  "delta",
  "entity_identity_list",
  "extract_entities",
  "extract_facts",
  "extraction_pending",
  "find_anomalies",
  "find_contradictions",
  "find_orphans",
  "find_trajectory",
  "get_active_schema_pack",
  "get_brain_health",
  "get_calibration_profile",
  "get_ingest_log",
  "get_memory_settings",
  "get_page_upload",
  "get_recent_salience",
  "get_skill_asset",
  "get_write_request",
  "list_brain_skillpack",
  "list_link_sources",
  "list_schema_packs",
  "list_write_conflicts",
  "list_write_requests",
  "loops_close",
  "loops_mute",
  "loops_unmute",
  "memory_conversation_mode",
  "mute_notice",
  "ontology_conflicts",
  "ontology_dimensions",
  "ontology_get",
  "questions_list",
  "questions_pin",
  "questions_refresh",
  "questions_status",
  "questions_unpin",
  "rank_entities",
  "rate_answer",
  "schema_explain_type",
  "schema_graph",
  "schema_lint",
  "schema_review_orphans",
  "schema_stats",
  "search_modes",
  "sources_list",
  "sources_resolve_path",
  "sources_status",
  "storage_find",
  "storage_get",
  "storage_list",
  "takes_calibration",
  "takes_scorecard",
  "upload_page_part",
  "volunteer_chronicle",
  "volunteer_context",
  "wanted_pages",
  "whois",
] as const;

export type OpGroup = "search" | "save" | "other";

const GROUP = new Map<string, OpGroup>([
  ...SEARCH_OPS.map((o) => [o, "search"] as const),
  ...SAVE_OPS.map((o) => [o, "save"] as const),
  ...OTHER_OPS.map((o) => [o, "other"] as const),
]);

export function opGroup(operation: string): OpGroup {
  return GROUP.get(operation) ?? "other";
}

/** Whether a name is in one of the three lists. */
export function knownOp(operation: string): boolean {
  return GROUP.has(operation);
}

/**
 * The page types that may reach the console by name: GBrain's built-in `gbrain-base` schema pack
 * (v0.60.723.0). A type is frontmatter an agent wrote, so any other name could be brain text, which
 * never reaches the console (owner rule): the brain box sends every other type as `other`
 * (`rust/bins/vm-agent/src/gbrain/stats.rs`, the same list) and the sink folds any it still gets.
 */
export const BRAIN_PAGE_TYPES: readonly string[] = [
  "person", "company", "deal", "yc", "civic", "project", "concept", "source", "media", "writing", "analysis", "guide",
  "hardware", "architecture", "meeting", "note", "email", "slack", "calendar-event", "conversation", "atom", "event",
  "diary", "code", "image", "synthesis", "extract_receipt", "question",
];
const ALLOWED_TYPES = new Set(BRAIN_PAGE_TYPES);

/** Pages per allowed type, every other name summed into `other`. */
export function allowedTypeCounts(byType: Record<string, number>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [k, n] of Object.entries(byType)) {
    if (!(n > 0)) continue;
    const key = ALLOWED_TYPES.has(k) ? k : "other";
    out[key] = (out[key] ?? 0) + n;
  }
  return out;
}

/** A type's label for the tiles and the feed (`brain-kinds.ts`, shared with the brain's own pages). */
export function categoryLabel(type: string): string {
  return kindLabel(type);
}

export type CategoryItem = { key: string; label: string; count: number; pct: number };

/** Types under 1% of the pages are folded into Other, as the design draws it. */
const FOLD_UNDER = 0.01;

/** The tiles of "What it knows": biggest first, small ones in Other, which always comes last. */
export function foldCategories(byType: Record<string, number>): { total: number; items: CategoryItem[] } {
  const entries = Object.entries(byType).filter(([, n]) => Number.isFinite(n) && n > 0);
  const total = entries.reduce((s, [, n]) => s + n, 0);
  if (total === 0) return { total: 0, items: [] };
  let other = 0;
  const items: CategoryItem[] = [];
  for (const [key, n] of entries) {
    if (key === "other" || n / total < FOLD_UNDER) other += n;
    else items.push({ key, label: categoryLabel(key), count: n, pct: Math.round((n / total) * 100) });
  }
  items.sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
  if (other > 0) items.push({ key: "other", label: "Other", count: other, pct: Math.round((other / total) * 100) });
  return { total, items };
}

/** The key a type is shown under on the tiles: its own, or `other` when it was folded. */
export function categoryKeyOf(type: string, items: readonly CategoryItem[]): string {
  return items.some((i) => i.key === type) ? type : "other";
}

export type CategoryChange = { key: string; label: string; delta: number };

/**
 * What changed between two readings, by type, biggest first. A type that is gone counts as 0 in
 * the newer reading. Nothing when the readings are the same.
 */
export function typeChanges(before: Record<string, number>, after: Record<string, number>): CategoryChange[] {
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  const out: CategoryChange[] = [];
  for (const key of keys) {
    const delta = (after[key] ?? 0) - (before[key] ?? 0);
    if (delta !== 0) out.push({ key, label: categoryLabel(key), delta });
  }
  return out.sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta) || a.label.localeCompare(b.label));
}

/** "+4 Meetings, +2 People, −1 Notes". */
export function changesLine(changes: readonly CategoryChange[], max = 3): string {
  const shown = changes.slice(0, max).map((c) => `${c.delta > 0 ? "+" : "−"}${Math.abs(c.delta).toLocaleString("en-US")} ${c.label}`);
  const rest = changes.length - shown.length;
  return rest > 0 ? `${shown.join(", ")} and ${rest} more` : shown.join(", ");
}

/** The middle value, or the mean of the two middle ones. Null for an empty list. */
export function median(values: readonly number[]): number | null {
  const v = values.filter((n) => Number.isFinite(n)).sort((a, b) => a - b);
  if (v.length === 0) return null;
  const mid = Math.floor(v.length / 2);
  return v.length % 2 ? v[mid]! : (v[mid - 1]! + v[mid]!) / 2;
}

export type BrainCount = {
  today: number;
  /** Yesterday up to the same time of day. */
  yesterday: number;
  /** The last 24 hours, oldest first, matching `BrainOverviewView.hours`. */
  hourly: number[];
};

export type BrainFeedItem =
  | {
      kind: "saves";
      /** Stable across polls: agent and quarter hour. */
      id: string;
      /** The newest save in the group. */
      at: string;
      agentVmId: string | null;
      agentName: string | null;
      /** An outside app's saves (T-219): its name, when no agent made them. */
      clientName?: string | null;
      count: number;
    }
  | {
      kind: "changes";
      id: string;
      /** When the newer reading was taken. */
      at: string;
      changes: CategoryChange[];
    };

export type BrainGrowthDay = {
  /** The day, YYYY-MM-DD in the reader's time zone. */
  day: string;
  /** Pages at the day's last reading. Null before the first reading. */
  pages: number | null;
  saves: number;
};

/** One agent's calls over the last 30 days; `lastAt` is the newest (ISO), when it has one. */
export type BrainAgentUsage = { vmId: string; searches: number; saves: number; lastAt?: string | null };

/** What the Overview and the Agents tab read (`brain.overview`). Counts and type names only. */
export type BrainOverviewView = {
  /** ISO hour starts of the cards' 24 points. */
  hours: string[];
  searches: BrainCount;
  saves: BrainCount;
  /** Median duration of today's searches, and per hour (0 for an hour with none). */
  answerMs: { today: number | null; hourly: number[] };
  /** The newest save by any agent. */
  lastSavedAt: string | null;
  /** The newest reading of the counts, or null before the first one. */
  latest: null | {
    at: string;
    pageCount: number;
    chunkCount: number;
    byType: Record<string, number>;
    diskUsedBytes: number | null;
    diskFreeBytes: number | null;
  };
  feed: BrainFeedItem[];
  /** 30 days, oldest first, ending today. */
  growth: BrainGrowthDay[];
  /** Searches and saves per agent over the last 30 days, busiest first. */
  agents: BrainAgentUsage[];
};

export function emptyOverview(hours: string[] = []): BrainOverviewView {
  const zero = { today: 0, yesterday: 0, hourly: hours.map(() => 0) };
  return {
    hours,
    searches: zero,
    saves: { ...zero, hourly: [...zero.hourly] },
    answerMs: { today: null, hourly: hours.map(() => 0) },
    lastSavedAt: null,
    latest: null,
    feed: [],
    growth: [],
    agents: [],
  };
}

/**
 * The feed, newest first: save groups and count changes merged by time. With a category, only
 * the change lines that touch it, each cut to that category (saves are not tied to a type).
 */
export function filterFeed(feed: readonly BrainFeedItem[], category: string | null, items: readonly CategoryItem[]): BrainFeedItem[] {
  if (!category) return [...feed];
  const out: BrainFeedItem[] = [];
  for (const f of feed) {
    if (f.kind !== "changes") continue;
    const changes = f.changes.filter((c) => categoryKeyOf(c.key, items) === category);
    if (changes.length) out.push({ ...f, changes });
  }
  return out;
}
