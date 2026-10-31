"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { RefreshCw, Search } from "lucide-react";
import type { FwLogsResponse, FwServiceState } from "@controlclaw/console-ui/lib/agent/fw-logs-types";
import { cn } from "../../lib/utils";
import {
  FW_LEVEL_FILTERS,
  FW_RANGE_LABELS,
  READ_TIMEOUT_MS,
  REFRESH_MS,
  fwPassesLevel,
  fwServiceTone,
  type FwLevelFilter,
  type FwLogSource,
  type FwRange,
  type FwSelection,
} from "../../lib/firewall-logs";

const TONE_DOT = { allow: "bg-allow", ask: "bg-ask", block: "bg-block", muted: "bg-ink-2/50" } as const;
const TONE_TEXT = { allow: "text-allow", ask: "text-ask", block: "text-block", muted: "text-ink-2" } as const;

const LEVEL_CLASS: Record<string, string> = {
  error: "text-block",
  warn: "text-ask",
  unit: "text-brand-ink",
  debug: "text-ink-2",
};

function formatTime(iso: string, withDate: boolean): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const time = d.toLocaleTimeString(undefined, { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  return withDate ? `${d.toLocaleDateString(undefined, { month: "short", day: "numeric" })} ${time}` : time;
}

function formatWhen(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function serviceDetail(s: FwServiceState): string {
  const tone = fwServiceTone(s);
  const when = formatWhen(s.since);
  const parts = [tone.label];
  if (when) parts.push(`since ${when}`);
  if (s.restarts > 0) parts.push(`${s.restarts} restart${s.restarts === 1 ? "" : "s"}`);
  if (s.active !== "active" && s.exitStatus !== null && s.exitStatus !== 0) parts.push(`exit ${s.exitStatus}`);
  return parts.join(" · ");
}

/** A line of ansible output, coloured the way a person scans it: tasks, failures, changes. */
function runLineClass(line: string): string {
  if (/^(fatal|failed):|FAILED!|^ERROR!|\bfailed=[1-9]/.test(line)) return "text-block";
  if (/^TASK \[|^PLAY( RECAP)? \[/.test(line)) return "font-semibold text-ink";
  if (/^changed:|^\[WARNING\]/.test(line)) return "text-ask";
  if (/^ok:|^skipping:/.test(line)) return "text-ink-2";
  return "text-ink";
}

const UPDATE_PHASE: Record<string, string> = {
  idle: "No update running",
  resolving: "Update starting",
  installing: "Update installing",
  running: "Update running",
  done: "Last update finished",
  failed: "Last update failed",
};

function RetryButton({ onClick, disabled }: { onClick: () => void; disabled: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      data-testid="fw-logs-retry"
      className="inline-flex h-[30px] items-center gap-1.5 rounded-[8px] border border-line bg-surface px-3 font-sans text-[12.5px] font-medium text-ink hover:bg-bg-2 disabled:opacity-50"
    >
      <RefreshCw className={cn("h-[14px] w-[14px] text-ink-2", disabled && "animate-spin")} />
      {disabled ? "Trying again…" : "Try again"}
    </button>
  );
}

/**
 * The firewall's own logs. It knows nothing about where they come from, so the same component runs
 * on the firewall's page (`apps/firewall-panel/fw/fw-logs-main.tsx`) and in the demo (`/demo/firewall-logs`).
 */
export function FirewallLogs({ source, timeoutMs = READ_TIMEOUT_MS }: { source: FwLogSource; timeoutMs?: number }) {
  const [data, setData] = useState<FwLogsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [range, setRange] = useState<FwRange>("1h");
  const [selected, setSelected] = useState<FwSelection>("all");
  const [level, setLevel] = useState<FwLevelFilter>("all");
  const [qInput, setQInput] = useState("");
  const [q, setQ] = useState("");
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const inFlight = useRef<AbortController | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);
  const scrolledRun = useRef(false);

  // One read at a time. The timer only reads when nothing is out, so a firewall slower than
  // REFRESH_MS still gets to answer (it used to be asked again every 10 s and each answer was thrown
  // away for the newer request, leaving the page on "Loading…"). A new range or service, or the
  // refresh button, replaces the read that is out. A read that takes longer than `timeoutMs` ends
  // in an error with a retry, never in a spinner.
  const load = useCallback(
    async (mode: "poll" | "now") => {
      if (mode === "poll" && inFlight.current) return;
      inFlight.current?.abort();
      const ctrl = new AbortController();
      inFlight.current = ctrl;
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        ctrl.abort();
      }, timeoutMs);
      setLoading(true);
      try {
        const res = await source.read({ range, service: selected, signal: ctrl.signal });
        if (inFlight.current !== ctrl) return;
        setData(res);
        setError(null);
        setUpdatedAt(new Date());
      } catch (e) {
        if (inFlight.current !== ctrl) return;
        if (timedOut) setError(`The firewall did not answer within ${Math.round(timeoutMs / 1000)}s.`);
        else if (e instanceof TypeError) setError("Couldn’t reach the firewall. Check your connection and that the firewall is running.");
        else setError(e instanceof Error ? e.message : "Couldn’t load the logs. Try again.");
      } finally {
        clearTimeout(timer);
        if (inFlight.current === ctrl) {
          inFlight.current = null;
          setLoading(false);
        }
      }
    },
    [source, range, selected, timeoutMs],
  );

  useEffect(() => {
    void load("now");
    const t = setInterval(() => {
      if (document.visibilityState === "visible") void load("poll");
    }, REFRESH_MS);
    return () => {
      clearInterval(t);
      inFlight.current?.abort();
      inFlight.current = null;
    };
  }, [load]);

  useEffect(() => {
    const t = setTimeout(() => setQ(qInput.trim().toLowerCase()), 250);
    return () => clearTimeout(t);
  }, [qInput]);

  const services = useMemo(() => data?.services ?? [], [data]);
  // `update` (cc-reprovision's progress lines) has no status of its own, so no chip to take a label from.
  const labelOf = useMemo(() => new Map<string, string>([["update", "Updates"], ...services.map((s) => [s.id, s.label] as const)]), [services]);
  // Failed, crash-looping, or a core service stopped: each is something to look at.
  const failing = services.filter((s) => fwServiceTone(s).tone === "block" || (!s.optional && s.active === "inactive"));
  const isRun = selected === "run";
  const withDate = range === "24h";

  const visible = useMemo(() => {
    if (!data || isRun) return [];
    return data.lines.filter((line) => fwPassesLevel(line, level) && (!q || `${labelOf.get(line.service) ?? line.service} ${line.message}`.toLowerCase().includes(q)));
  }, [data, isRun, level, q, labelOf]);

  const runLines = useMemo(() => {
    if (!data?.run || !isRun) return [];
    return q ? data.run.filter((l) => l.toLowerCase().includes(q)) : data.run;
  }, [data, isRun, q]);

  // A run reads oldest first and ends with how it went: open it at the end, once per visit.
  useEffect(() => {
    if (!isRun) {
      scrolledRun.current = false;
      return;
    }
    if (scrolledRun.current || !data?.run || !listRef.current) return;
    listRef.current.scrollTop = listRef.current.scrollHeight;
    scrolledRun.current = true;
  }, [isRun, data]);

  const current = services.find((s) => s.id === selected) ?? null;
  const update = data?.update ?? null;

  const chip = (key: FwSelection, label: string, dot: keyof typeof TONE_DOT | null) => (
    <button
      key={key}
      type="button"
      onClick={() => setSelected(key)}
      aria-pressed={selected === key}
      data-testid={`fw-logs-service-${key}`}
      className={cn(
        "inline-flex h-[30px] shrink-0 items-center gap-1.5 rounded-full border px-3 text-[12.5px] font-medium",
        selected === key ? "border-line-2 bg-bg-2 font-semibold text-ink" : "border-line bg-surface text-ink-2 hover:text-ink",
      )}
    >
      {dot ? <span className={cn("h-1.5 w-1.5 rounded-full", TONE_DOT[dot])} /> : null}
      {label}
    </button>
  );

  return (
    <div className="flex flex-col gap-[18px]" data-testid="firewall-logs">
      <div className="rounded-[14px] border border-line bg-surface">
        <div className="flex flex-wrap gap-2 px-4 py-3" role="group" aria-label="Service">
          {chip("all", "All services", null)}
          {services.map((s) => chip(s.id, s.label, fwServiceTone(s).tone))}
          {chip("run", "Last update run", update?.phase === "failed" ? "block" : null)}
        </div>
        {failing.length > 0 ? (
          <div className="border-t border-line px-4 py-2.5 text-[12.5px] text-block" role="status" data-testid="fw-logs-failing">
            {failing.map((s) => `${s.label} ${fwServiceTone(s).label.toLowerCase()}`).join(" · ")}. Pick {failing.length === 1 ? "it" : "one"} above to see its last lines.
          </div>
        ) : null}
        {current ? (
          <div className="border-t border-line px-4 py-2.5 text-[12.5px] text-ink-2" data-testid="fw-logs-current">
            <span className={cn("font-medium", TONE_TEXT[fwServiceTone(current).tone])}>{current.label}</span>
            <span> · {current.about} · {serviceDetail(current)}</span>
          </div>
        ) : null}
        {isRun ? (
          <div className="border-t border-line px-4 py-2.5 text-[12.5px] text-ink-2" data-testid="fw-logs-run-state">
            {update ? (
              <>
                <span className={cn("font-medium", update.phase === "failed" ? "text-block" : "text-ink")}>{UPDATE_PHASE[update.phase] ?? update.phase}</span>
                {update.detail ? ` · ${update.detail}` : null}
                {formatWhen(update.at) ? ` · ${formatWhen(update.at)}` : null}
              </>
            ) : (
              "No update has run on this firewall yet. This is its first setup."
            )}
            <div className="mt-0.5">The output is shown as it was written, oldest line first.</div>
          </div>
        ) : null}
        {data?.warning ? <div className="border-t border-line px-4 py-2.5 text-[12.5px] text-ask">{data.warning}</div> : null}
      </div>

      <div className="rounded-[14px] border border-line bg-surface">
        <div className="flex flex-wrap items-center gap-2.5 px-4 py-3">
          <div className="relative w-[320px] max-w-full">
            <Search className="pointer-events-none absolute left-[11px] top-1/2 h-[14px] w-[14px] -translate-y-1/2 text-ink-2" />
            <input
              type="search"
              value={qInput}
              onChange={(e) => setQInput(e.target.value)}
              placeholder="Search the log…"
              aria-label="Search the log"
              data-testid="fw-logs-search"
              className="h-[34px] w-full rounded-[10px] border border-line bg-surface pl-[34px] pr-3 text-[13px] text-ink placeholder:text-ink-2 focus:border-line-2 focus:outline-none"
            />
          </div>
          <div className="flex-1" />
          {!isRun ? (
            <>
              <div className="inline-flex items-center gap-0.5 rounded-[9px] border border-line bg-surface p-0.5" role="group" aria-label="Time range">
                {(Object.keys(FW_RANGE_LABELS) as FwRange[]).map((key) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setRange(key)}
                    aria-pressed={range === key}
                    data-testid={`fw-logs-range-${key}`}
                    className={cn(
                      "inline-flex h-[30px] items-center rounded-[7px] px-3 text-[12.5px] font-medium",
                      range === key ? "bg-bg-2 font-semibold text-ink" : "text-ink-2 hover:text-ink",
                    )}
                  >
                    {FW_RANGE_LABELS[key]}
                  </button>
                ))}
              </div>
              <div className="inline-flex items-center gap-0.5 rounded-[9px] border border-line bg-surface p-0.5" role="group" aria-label="Level">
                {FW_LEVEL_FILTERS.map(({ key, label }) => (
                  <button
                    key={key}
                    type="button"
                    onClick={() => setLevel(key)}
                    aria-pressed={level === key}
                    data-testid={`fw-logs-level-${key}`}
                    className={cn(
                      "inline-flex h-[30px] items-center rounded-[7px] px-3 text-[12.5px] font-medium",
                      level === key ? "bg-bg-2 font-semibold text-ink" : "text-ink-2 hover:text-ink",
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </>
          ) : null}
          <span className="text-[12px] text-ink-2" aria-live="polite">
            {updatedAt ? `Updated ${formatTime(updatedAt.toISOString(), false)}` : null}
          </span>
          <button
            type="button"
            onClick={() => void load("now")}
            disabled={loading}
            aria-label="Refresh"
            data-testid="fw-logs-refresh"
            className="inline-flex h-[30px] w-[30px] items-center justify-center rounded-[8px] border border-line bg-surface text-ink-2 hover:text-ink disabled:opacity-50"
          >
            <RefreshCw className={cn("h-[15px] w-[15px]", loading && "animate-spin")} />
          </button>
        </div>

        {error && data ? (
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-t border-line px-4 py-2.5 text-[12.5px]" role="alert" data-testid="fw-logs-error">
            <span className="text-block">{error} The lines below are from the last read that worked.</span>
            <RetryButton onClick={() => void load("now")} disabled={loading} />
          </div>
        ) : null}
        <div className="border-t border-line">
          <div ref={listRef} className="h-[calc(100dvh-360px)] min-h-[360px] overflow-auto px-3 py-2 font-mono text-[12px] leading-[1.55]" data-testid="fw-logs-list">
            {error && !data ? (
              <div className="flex flex-col items-center gap-3 px-1 py-10 text-center font-sans text-[13px]" role="alert" data-testid="fw-logs-error">
                <span className="text-block">{error}</span>
                <RetryButton onClick={() => void load("now")} disabled={loading} />
              </div>
            ) : !data ? (
              <div className="px-1 py-10 text-center font-sans text-[13px] text-ink-2">Loading…</div>
            ) : isRun ? (
              runLines.length === 0 ? (
                <div className="px-1 py-10 text-center font-sans text-[13px] text-ink-2">{q ? "No lines match the search." : "No update or setup output on this firewall."}</div>
              ) : (
                runLines.map((line, i) => (
                  <div key={i} data-testid="fw-logs-run-line" className={cn("whitespace-pre-wrap break-words px-1 hover:bg-bg-2", runLineClass(line))}>
                    {line || " "}
                  </div>
                ))
              )
            ) : visible.length === 0 ? (
              <div className="px-1 py-10 text-center font-sans text-[13px] text-ink-2">
                {data.lines.length === 0 ? `Nothing logged in the last ${FW_RANGE_LABELS[range]}.` : "No lines match the current filters."}
              </div>
            ) : (
              <>
                {visible.map((line, i) => (
                  <div
                    key={`${line.time}-${i}`}
                    data-testid="fw-logs-line"
                    className="flex flex-wrap gap-x-3 whitespace-pre-wrap break-words px-1 hover:bg-bg-2 md:flex-nowrap"
                  >
                    <span className="shrink-0 text-ink-2">{formatTime(line.time, withDate)}</span>
                    {selected === "all" ? <span className="w-[112px] shrink-0 truncate text-ink-2">{labelOf.get(line.service) ?? line.service}</span> : null}
                    <span className={cn("w-[40px] shrink-0 uppercase", LEVEL_CLASS[line.level] ?? "text-ink-2")}>{line.level === "unit" ? "sys" : line.level}</span>
                    <span className={cn("min-w-0 basis-full md:basis-auto md:flex-1", LEVEL_CLASS[line.level] ?? "text-ink")}>{line.message}</span>
                  </div>
                ))}
                {data.truncated ? (
                  <div className="px-1 py-3 text-center font-sans text-[12.5px] text-ink-2">Only the newest {data.lines.length} lines are shown. Pick one service or a shorter range to see older ones.</div>
                ) : null}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
