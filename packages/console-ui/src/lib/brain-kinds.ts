/**
 * GBrain's page kinds as people see them, in one place: the label ("People"), one of them
 * ("Person"), and the colour a kind has everywhere, on the console's Brain overview and on the
 * brain's own pages. Browser-safe and pure, so the box bundle and the console share it.
 */

/**
 * GBrain's base schema pack types (v0.60.723.0), as people say them. A type that is not here (a
 * pack can add types, an update can rename one) shows its own name with a capital.
 */
const LABELS: Record<string, [many: string, one: string]> = {
  person: ["People", "Person"],
  company: ["Companies", "Company"],
  deal: ["Deals", "Deal"],
  project: ["Projects", "Project"],
  concept: ["Concepts", "Concept"],
  meeting: ["Meetings", "Meeting"],
  note: ["Notes", "Note"],
  email: ["Emails", "Email"],
  conversation: ["Conversations", "Conversation"],
  "calendar-event": ["Calendar events", "Calendar event"],
  source: ["Sources", "Source"],
  writing: ["Writing", "Writing"],
  analysis: ["Analyses", "Analysis"],
  guide: ["Guides", "Guide"],
  event: ["Events", "Event"],
  yc: ["YC", "YC"],
  civic: ["Civic", "Civic"],
  media: ["Media", "Media"],
  hardware: ["Hardware", "Hardware"],
  architecture: ["Architecture", "Architecture"],
  slack: ["Slack", "Slack"],
  atom: ["Facts", "Fact"],
  diary: ["Diary", "Diary"],
  code: ["Code", "Code"],
  image: ["Images", "Image"],
  synthesis: ["Summaries", "Summary"],
  extract_receipt: ["Extraction runs", "Extraction run"],
  question: ["Questions", "Question"],
  other: ["Other", "Page"],
};

function titleCase(kind: string): string | null {
  const words = kind.replace(/[-_]+/g, " ").trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : null;
}

/** "People", "Calendar events"; an unknown kind as its own name with a capital. */
export function kindLabel(kind: string): string {
  return LABELS[kind]?.[0] ?? titleCase(kind) ?? "Other";
}

/** One page of a kind: "Person", "Meeting"; an unknown kind as its own name, "Page" for none. */
export function kindOne(kind: string | null | undefined): string {
  if (!kind) return "Page";
  return LABELS[kind]?.[1] ?? titleCase(kind) ?? "Page";
}

/**
 * The colour of each common kind, as the design draws them. Each is mixed into the surface or the
 * ink where it is used, so dark mode gets the same hue on a dark ground.
 */
const COLOURS: Record<string, string> = {
  person: "oklch(0.62 0.13 250)",
  company: "var(--brand)",
  meeting: "oklch(0.6 0.12 180)",
  project: "oklch(0.6 0.12 300)",
  note: "oklch(0.68 0.13 60)",
  concept: "oklch(0.62 0.1 140)",
  deal: "oklch(0.58 0.1 20)",
  email: "oklch(0.55 0.05 250)",
  "calendar-event": "oklch(0.6 0.11 210)",
  conversation: "oklch(0.6 0.11 330)",
  source: "oklch(0.6 0.09 100)",
  analysis: "oklch(0.56 0.1 280)",
  event: "oklch(0.62 0.1 30)",
  writing: "oklch(0.58 0.09 160)",
};

/** Kinds with no colour of their own get one of these, always the same one for the same name. */
const SPARE = Array.from({ length: 12 }, (_, i) => `oklch(${i % 2 ? 0.56 : 0.64} 0.1 ${(i * 30 + 15) % 360})`);

export const OTHER_COLOUR = "var(--ink-2)";

/** A kind's colour: its own, a stable spare one for any other name, the ink's for `other` or none. */
export function kindColour(kind: string | null | undefined): string {
  if (!kind || kind === "other") return OTHER_COLOUR;
  const own = COLOURS[kind];
  if (own) return own;
  let h = 0;
  for (const ch of kind) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return SPARE[h % SPARE.length]!;
}

/**
 * The kind a slug's folder suggests (`people/ana` → person, `companies/acme` → company), for a link
 * whose page was not read. GBrain files pages by kind, but nothing makes it: an unknown folder is
 * `other`.
 */
export function kindOfSlug(slug: string): string {
  const folder = slug.split("/")[0]?.toLowerCase() ?? "";
  if (!slug.includes("/") || !folder) return "other";
  if (folder === "people") return "person";
  const candidates = [folder, folder.replace(/ies$/, "y"), folder.replace(/es$/, ""), folder.replace(/s$/, "")];
  return candidates.find((c) => c !== "other" && LABELS[c]) ?? "other";
}

/** Up to two initials of a name, for a person's badge: "Lucia Ferri" → "LF". */
export function initials(name: string): string {
  const words = name
    .replace(/,.*$/, "")
    .split(/[\s/_-]+/)
    .filter((w) => /\p{L}|\p{N}/u.test(w));
  return words
    .slice(0, 2)
    .map((w) => [...w.replace(/^[^\p{L}\p{N}]+/u, "")][0] ?? "")
    .join("")
    .toUpperCase();
}
