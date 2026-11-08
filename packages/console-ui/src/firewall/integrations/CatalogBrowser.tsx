"use client";

import { useEffect, useMemo, useState } from "react";
import { BookOpen, Loader2, Plus, Search } from "lucide-react";
import { useApi } from "../../lib/api";
import { cn } from "../../lib/utils";
import { Button } from "../../ui/button";
import { FilterChip } from "../../kit/console-ui";
import type { CatalogProvider, CatalogProviderView } from "../../lib/connectors-schema";
import { AppLogo } from "./AppLogo";

/** Browsing shows a dozen; a search shows as many as the old dialog did. */
const PAGE = 12;
const SEARCH_PAGE = 36;
/** The search RPC's own cap. */
const MAX = 60;

export type CatalogResult = {
  providers: CatalogProviderView[];
  categories: Array<{ name: string; count: number }>;
  total: number;
  version: string;
};

/**
 * The app catalog, inline on the Integrations page (it was a dialog). The catalog is ~1500 providers
 * pinned with the runtime, so it is searched on the server (`integrations.search`) and only the
 * matches come over the wire; with nothing typed it lists the apps with the most actions.
 *
 * A card marked "Guide" is one whose connect dialog shows a "Before you start" block: the steps
 * for creating the app at the provider. Typing "guide" lists exactly those — the one search term
 * here that is not a provider's name.
 *
 * `demo` replaces the RPC with a fixed list, filtered here, so the demo page needs no server.
 */
export function CatalogBrowser({
  canConnect,
  onPick,
  demo,
}: {
  canConnect: boolean;
  onPick: (p: CatalogProvider) => void;
  demo?: CatalogResult;
}) {
  const api = useApi();
  const [q, setQuery] = useState("");
  const [category, setCategoryState] = useState("");
  /** Rows "Show more" added on top of the page; a new search or category starts over. */
  const [extra, setExtra] = useState(0);
  const limit = Math.min(MAX, (q.trim() ? SEARCH_PAGE : PAGE) + extra);
  const setQ = (v: string) => (setQuery(v), setExtra(0));
  const setCategory = (v: string) => (setCategoryState(v), setExtra(0));
  const [fetched, setFetched] = useState<CatalogResult | null>(null);
  /** The key of a search that failed, and a counter that Retry bumps to run it again. */
  const [failed, setFailed] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  // Loading until the search for exactly what is on screen has come back.
  const key = `${q}\u0000${category}\u0000${limit}`;
  const [settled, setSettled] = useState<string | null>(null);
  const loading = !demo && settled !== key;

  // The demo filters its fixed list here, roughly as the server would.
  const demoResult = useMemo(() => {
    if (!demo) return null;
    const needle = q.trim().toLowerCase();
    return {
      ...demo,
      providers: demo.providers
        .filter((p) => (!category || p.categories.includes(category)) && (!needle || (needle === "guide" ? p.guide : p.name.toLowerCase().includes(needle))))
        .slice(0, limit),
    };
  }, [demo, q, category, limit]);
  const result = demoResult ?? fetched;

  useEffect(() => {
    if (demo) return;
    let stopped = false;
    const asked = `${q}\u0000${category}\u0000${limit}`;
    // Debounced so typing does not fire a request per keystroke.
    const t = setTimeout(() => {
      void api.integrations
        .search({ q, category, limit })
        .then((r) => {
          if (stopped) return;
          setFetched(r);
          setFailed(null);
        })
        .catch((error) => {
          console.error("integrations.search failed", error);
          if (!stopped) setFailed(asked);
        })
        .finally(() => !stopped && setSettled(asked));
    }, 200);
    return () => {
      stopped = true;
      clearTimeout(t);
    };
  }, [q, category, limit, demo, attempt, api]);

  const providers = result?.providers ?? [];
  const total = result?.total ?? 0;

  return (
    <div className="grid grid-cols-1 gap-3" data-testid="connector-catalog">
      <div className="flex flex-wrap items-center gap-2.5">
        <label className="flex h-[34px] min-w-[180px] flex-[0_1_280px] items-center gap-2 rounded-[9px] border border-input bg-surface px-3 text-ink-2 focus-within:ring-2 focus-within:ring-ring/50">
          <Search className="h-[15px] w-[15px] shrink-0" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={category ? `Search ${category}` : total ? `Search ${total.toLocaleString("en-US")} apps` : "GitHub, Notion, Postgres…"}
            aria-label="Search apps"
            className="min-w-0 flex-1 bg-transparent text-[13.5px] text-ink outline-none placeholder:text-ink-2"
            data-testid="connector-catalog-search"
          />
          {loading ? <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" /> : null}
        </label>
        <div className="flex min-w-0 flex-wrap gap-1.5">
          <FilterChip active={!category} onClick={() => setCategory("")}>
            All
          </FilterChip>
          {(result?.categories ?? []).slice(0, 7).map((c) => (
            <FilterChip key={c.name} active={category === c.name} onClick={() => setCategory(category === c.name ? "" : c.name)}>
              {c.name}
            </FilterChip>
          ))}
        </div>
      </div>

      <p className="text-[12.5px] text-ink-2">
        Search{" "}
        <button type="button" className="font-medium text-ink underline" onClick={() => setQ("guide")} data-testid="connector-catalog-guide-hint">
          guide
        </button>{" "}
        for the apps that come with setup steps.
        {result?.version ? ` Open Connector ${result.version}.` : ""}
      </p>

      <div data-testid="connector-catalog-results">
        {failed === key && !loading ? (
          <div className="flex flex-wrap items-center gap-3 py-4 text-[13.5px] text-block-fg" data-testid="connector-catalog-failed">
            Couldn’t load the app list.
            <Button size="sm" variant="outline" onClick={() => (setFailed(null), setSettled(null), setAttempt((n) => n + 1))}>
              Try again
            </Button>
          </div>
        ) : loading && providers.length === 0 ? (
          <div className="flex items-center gap-2 py-6 text-[13.5px] text-ink-2">
            <Loader2 className="h-4 w-4 animate-spin" /> Searching…
          </div>
        ) : providers.length === 0 ? (
          <p className="py-4 text-[13.5px] text-ink-2">{q.trim() ? `No app matches “${q.trim()}”.` : "No apps in this category."}</p>
        ) : (
          <ul className="grid grid-cols-[repeat(auto-fill,minmax(min(230px,100%),1fr))] gap-2.5">
            {providers.map((p) => (
              <li key={p.service} className="min-w-0">
                <button
                  type="button"
                  disabled={!canConnect}
                  onClick={() => onPick(p)}
                  className={cn(
                    "group flex h-full w-full min-w-0 flex-col gap-2.5 rounded-xl border border-line bg-surface p-3.5 text-left transition-[border-color,transform]",
                    canConnect ? "hover:-translate-y-px hover:border-brand" : "cursor-not-allowed opacity-70",
                  )}
                  data-testid={`connector-catalog-${p.service}`}
                >
                  <span className="flex min-w-0 items-center gap-2.5">
                    <AppLogo name={p.name} home={p.home} service={p.service} icon={p.icon} size={36} />
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-1.5">
                        <span className="truncate text-[14px] font-semibold text-ink">{p.name}</span>
                        {p.guide ? (
                          <span
                            className="inline-flex shrink-0 items-center gap-1 rounded-full border border-line px-1.5 py-px text-[10.5px] font-medium text-ink-2"
                            title="Comes with step-by-step instructions for creating the app at the provider"
                            data-testid={`connector-catalog-guide-${p.service}`}
                          >
                            <BookOpen className="h-[10px] w-[10px]" />
                            Guide
                          </span>
                        ) : null}
                      </span>
                      <span className="block truncate text-[12.5px] text-ink-2">
                        {p.actions} action{p.actions === 1 ? "" : "s"}
                        {p.categories[0] ? ` · ${p.categories[0]}` : ""}
                        {p.authTypes.includes("oauth2") ? " · OAuth" : p.authTypes.includes("api_key") ? " · API key" : ""}
                      </span>
                    </span>
                  </span>
                  {canConnect ? (
                    <span className="inline-flex items-center gap-1 text-[12.5px] font-semibold text-ink-2 group-hover:text-brand">
                      <Plus className="h-[13px] w-[13px]" /> Connect
                    </span>
                  ) : null}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      {providers.length >= limit && limit < MAX ? (
        <div>
          <Button size="sm" variant="outline" onClick={() => setExtra((n) => n + 24)} data-testid="connector-catalog-more">
            Show more
          </Button>
        </div>
      ) : null}
    </div>
  );
}
