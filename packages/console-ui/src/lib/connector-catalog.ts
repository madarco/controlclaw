import catalogJson from "./connector-catalog.json";
import type { CatalogProvider, CatalogProviderView } from "./connectors-schema";

/**
 * The OpenConnector provider catalog, pinned with the runtime (`apps/saas/scripts/gen-connector-catalog.ts`
 * writes the JSON; the version it came from is `CONNECTOR_VERSION` in the console). Public data that
 * cannot change for a pinned version, so the console and the firewall's panel both search it here
 * rather than asking a firewall for 1500 providers.
 */
/** The OpenConnector release the catalog was generated from. */
export const CONNECTOR_VERSION = "v1.6.3";

export const CONNECTOR_CATALOG = (catalogJson as CatalogProvider[]).filter((p) => p.service !== "agent_mail");

const BY_SERVICE = new Map(CONNECTOR_CATALOG.map((p) => [p.service, p]));

export function catalogProvider(service: string): CatalogProvider | null {
  return BY_SERVICE.get(service) ?? null;
}

/** The display name for a provider, falling back to the id for one this build does not know. */
export function serviceName(service: string): string {
  return BY_SERVICE.get(service)?.name ?? service;
}

/** Every category in the catalog, by how many providers carry it. */
export function catalogCategories(): Array<{ name: string; count: number }> {
  const counts = new Map<string, number>();
  for (const p of CONNECTOR_CATALOG) for (const c of p.categories) counts.set(c, (counts.get(c) ?? 0) + 1);
  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

/** How many providers can be connected at all, for the search box's placeholder. Pinned, so counted once. */
let connectable: number | null = null;
export function connectableCount(): number {
  connectable ??= CONNECTOR_CATALOG.filter(isConnectable).length;
  return connectable;
}

/** Typing this lists the providers we wrote a setup guide for, whatever they are called. */
const GUIDE_NEEDLES = new Set(["guide", "guides", "guided"]);

/**
 * Providers matching a query. Name matches rank above id and description matches, so typing
 * "git" offers GitHub before the fifty providers whose blurb mentions git. "guide" is the one
 * query that is not about a name: it lists the apps in `guided` (the console's setup guides).
 */
export function searchCatalog(
  q: string,
  category: string,
  limit: number,
  keep: (p: CatalogProvider) => boolean = () => true,
  guided: ReadonlySet<string> = new Set(),
): CatalogProviderView[] {
  const needle = q.trim().toLowerCase();
  const wantsGuides = GUIDE_NEEDLES.has(needle);
  const scored: Array<{ p: CatalogProvider; score: number }> = [];
  for (const p of CONNECTOR_CATALOG) {
    if (category && !p.categories.includes(category)) continue;
    // Before the cut, so a page of `limit` is full whenever that many match.
    if (!keep(p)) continue;
    if (!needle) {
      scored.push({ p, score: 0 });
      continue;
    }
    if (wantsGuides) {
      if (guided.has(p.service)) scored.push({ p, score: 5 });
      continue;
    }
    const name = p.name.toLowerCase();
    const score = name === needle ? 5 : name.startsWith(needle) ? 4 : name.includes(needle) ? 3 : p.service.includes(needle) ? 2 : (p.desc ?? "").toLowerCase().includes(needle) ? 1 : 0;
    if (score > 0) scored.push({ p, score });
  }
  return scored
    .sort((a, b) => b.score - a.score || b.p.actions - a.p.actions || a.p.name.localeCompare(b.p.name))
    .slice(0, limit)
    .map((s) => ({ ...s.p, guide: guided.has(s.p.service) }));
}

/** Which providers a customer can connect at all: the ones that take a credential. */
export function isConnectable(p: CatalogProvider): boolean {
  return p.authTypes.some((t) => t === "api_key" || t === "custom_credential" || t === "oauth2");
}
