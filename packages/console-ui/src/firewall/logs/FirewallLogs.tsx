"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { AlertTriangle, Check, ExternalLink, Info, Loader2, Lock, Package, Pause, Play, RefreshCw, Search, XCircle } from "lucide-react";
import type { FwLogLine, FwLogsResponse, FwServiceState, FwUpdateState } from "../../lib/agent/fw-logs-types";
import { cn } from "../../lib/utils";
import { BoxPageBody, BoxPageHead } from "../../kit/box-kit";
import {
  FW_LEVEL_FILTERS,
  FW_RANGE_LABELS,
  FW_RANGE_MS,
  FW_RANGE_SPAN,
  READ_TIMEOUT_MS,
  REFRESH_MS,
  fwHistogram,
  fwPassesLevel,
  fwRecap,
  fwServiceTone,
  type FwHistBucket,
  type FwLevelFilter,
  type FwLogSource,
  type FwRange,
  type FwSelection,
} from "../../lib/firewall-logs";

const FOCUS = "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand";
const CARD = "rounded-xl border border-line bg-surface";
const BTN =
  "inline-flex h-[30px] shrink-0 items-center gap-1.5 rounded-[8px] border border-line bg-surface px-3 text-[12.5px] font-medium whitespace-nowrap text-ink hover:bg-bg-2 disabled:opacity-50";

const TONE_DOT = { allow: "bg-allow", ask: "bg-ask", block: "bg-block", muted: "bg-ink-2/40" } as const;
const TONE_TEXT = { allow: "text-ink-2", ask: "text-ask-fg", block: "font-medium text-block-fg", muted: "text-ink-2" } as const;
const PILL = {
  allow: "bg-allow-soft text-allow-fg",
  ask: "bg-ask-soft text-ask-fg",
  block: "bg-block-soft text-block-fg",
  muted: "bg-bg-2 text-ink-2",
} as const;

/** The row's left border and light tint, by level, as on the agent's Logs page. */
const ROW_TONE: Record<string, string> = {
  error: "border-l-block bg-block-soft/50",
  warn: "border-l-ask bg-ask-soft/50",
};
const BADGE_TONE: Record<string, string> = {
  error: "font-semibold text-block-fg",
  warn: "font-semibold text-ask-fg",
  unit: "font-semibold text-brand-ink",
};

/** One colour per service, each 4.5:1 or better on the surface, light and dark. */
const SERVICE_TONE: Record<string, string> = {
  "mitm-agent": "text-[oklch(0.5_0.12_250)] dark:text-[oklch(0.8_0.09_250)]",
  proxy: "text-[oklch(0.48_0.09_180)] dark:text-[oklch(0.8_0.08_180)]",
  caddy: "text-[oklch(0.5_0.13_310)] dark:text-[oklch(0.8_0.09_310)]",
  dnsmasq: "text-[oklch(0.5_0.1_70)] dark:text-[oklch(0.82_0.1_80)]",
  tang: "text-[oklch(0.48_0.11_145)] dark:text-[oklch(0.8_0.1_145)]",
  disk: "text-[oklch(0.52_0.13_25)] dark:text-[oklch(0.8_0.09_25)]",
  "team-chat": "text-[oklch(0.5_0.12_280)] dark:text-[oklch(0.8_0.09_280)]",
  chrony: "text-[oklch(0.48_0.1_210)] dark:text-[oklch(0.8_0.08_210)]",
  tailscale: "text-[oklch(0.5_0.1_110)] dark:text-[oklch(0.82_0.09_110)]",
  update: "text-brand-ink",
};

function formatTime(iso: string | number, withDate = false): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const time = d.toLocaleTimeString(undefined, { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  return withDate ? `${d.toLocaleDateString(undefined, { month: "short", day: "numeric" })} ${time}` : time;
}

function clock(at: number): string {
  return new Date(at).toLocaleTimeString(undefined, { hour12: false, hour: "2-digit", minute: "2-digit" });
}

function formatWhen(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function formatDay(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

function serviceDetail(s: FwServiceState): string {
  const tone = fwServiceTone(s);
  const when = formatWhen(s.since);
  const parts = [tone.label];
  if (when) parts.push(`since ${when}`);
  if (s.restarts > 0) parts.push(plural(s.restarts, "restart", "restarts"));
  if (s.active !== "active" && s.exitStatus !== null && s.exitStatus !== 0) parts.push(`exit ${s.exitStatus}`);
  return parts.join(" · ");
}

/** "14 restarts since Nov 25, 09:12, exit code 1. Unlocks your agents' encrypted disks." */
function failingNote(s: FwServiceState): string {
  const parts: string[] = [];
  const since = s.since ? formatWhen(s.since) : null;
  if (s.restarts > 0) parts.push(`${plural(s.restarts, "restart", "restarts")}${since ? ` since ${since}` : ""}`);
  if (s.exitStatus) parts.push(`exit code ${s.exitStatus}`);
  const head = parts.join(", ");
  const text = [head ? `${head[0]!.toUpperCase()}${head.slice(1)}.` : "", s.about ? `${s.about}.` : ""].filter(Boolean).join(" ");
  return text;
}

/** Failed, crash-looping, or a core service stopped: each is something to look at. */
function isFailing(s: FwServiceState): boolean {
  return fwServiceTone(s).tone === "block" || (!s.optional && s.active === "inactive");
}

/** A line of ansible output, coloured the way a person scans it: tasks, failures, changes. */
function runLineClass(line: string): string {
  if (/^(fatal|failed):|FAILED!|^ERROR!|\bfailed=[1-9]/.test(line)) return "border-l-block bg-block-soft/50 text-block-fg";
  if (/^TASK \[|^PLAY( RECAP)? \[/.test(line)) return "mt-2 font-semibold text-ink first:mt-0";
  if (/^changed:|^\[WARNING\]/.test(line)) return "text-ask-fg";
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

/** What the rail says next to "Last update run": a version when the ref is one, else a short hash. */
function updateRef(u: FwUpdateState | null): string {
  if (!u) return "";
  if (u.phase === "failed") return "Failed";
  if (["resolving", "installing", "running"].includes(u.phase)) return "Running";
  const ref = u.ref ?? "";
  return /^v?\d+\.\d+/.test(ref) ? ref.replace(/^v/, "") : ref.slice(0, 7);
}

function RetryButton({ onClick, disabled }: { onClick: () => void; disabled: boolean }) {
  return (
    <button type="button" onClick={onClick} disabled={disabled} data-testid="fw-logs-retry" className={cn(BTN, FOCUS)}>
      <RefreshCw aria-hidden="true" className={cn("h-[13px] w-[13px] text-ink-2", disabled && "animate-spin")} />
      {disabled ? "Trying again…" : "Try again"}
    </button>
  );
}

function Banner({ tone, icon, children, actions, testId }: { tone: "block" | "ask"; icon: ReactNode; children: ReactNode; actions?: ReactNode; testId?: string }) {
  return (
    <div
      role={tone === "block" ? "alert" : "status"}
      data-testid={testId}
      className={cn(
        "flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border px-4 py-3 text-[13px] leading-5",
        tone === "block" ? "border-block-border bg-block-soft text-block-fg" : "border-ask-border bg-ask-soft text-ask-fg",
      )}
    >
      <span className="shrink-0 self-start pt-0.5">{icon}</span>
      <div className="min-w-0 flex-1 basis-[240px]">{children}</div>
      {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
    </div>
  );
}

function Empty({ icon, title, children, action, testId }: { icon: ReactNode; title: string; children: ReactNode; action?: ReactNode; testId?: string }) {
  return (
    <div className={cn(CARD, "flex flex-col items-center gap-2 px-6 py-12 text-center")} data-testid={testId} role="alert">
      <span className="mb-1 inline-grid h-10 w-10 place-items-center rounded-full bg-bg-2 text-ink-2">{icon}</span>
      <b className="text-[15px] font-semibold text-ink">{title}</b>
      <p className="m-0 max-w-[52ch] text-[13px] text-pretty text-ink-2">{children}</p>
      {action ? <div className="mt-2 flex flex-wrap justify-center gap-2">{action}</div> : null}
    </div>
  );
}

function bucketText(b: FwHistBucket, size: number): string {
  return `${clock(b.start)}–${clock(b.start + size)}: ${plural(b.info, "line", "lines")}, ${plural(b.warn, "warning", "warnings")}, ${plural(b.error, "error", "errors")}`;
}

/** Lines per bucket over the range, stacked by level. */
function LogChart({ buckets, range, errors, warnings, total }: { buckets: FwHistBucket[]; range: FwRange; errors: number; warnings: number; total: number }) {
  const max = Math.max(1, ...buckets.map((b) => b.info + b.warn + b.error));
  const size = FW_RANGE_MS[range] / buckets.length;
  const label = `Log lines over the last ${FW_RANGE_SPAN[range]}, by level: ${plural(total, "line", "lines")}, including ${plural(warnings, "warning", "warnings")} and ${plural(errors, "error", "errors")}.`;
  return (
    <div role="img" aria-label={label} data-testid="fw-logs-chart" className="flex h-[38px] min-w-0 items-end gap-[3px]">
      {buckets.map((b) => {
        const n = b.info + b.warn + b.error;
        return (
          <div key={b.start} title={bucketText(b, size)} className="flex min-h-[3px] flex-1 flex-col overflow-hidden rounded-[3px]" style={{ height: `${(n / max) * 100}%` }}>
            {b.error > 0 ? <i className="block bg-block" style={{ flex: b.error * 4 }} /> : null}
            {b.warn > 0 ? <i className="block bg-ask" style={{ flex: b.warn * 3 }} /> : null}
            <i className={cn("block", n ? "bg-brand/35" : "bg-line")} style={{ flex: b.info || 1 }} />
          </div>
        );
      })}
    </div>
  );
}

export interface FirewallLogsProps {
  source: FwLogSource;
  timeoutMs?: number;
  /** Doctor for this firewall, offered next to a failing service or update. Absent where there is none (a standalone firewall). */
  doctorHref?: string | null;
  /** The Firewall page, where Update is: in the console, or the standalone panel. */
  firewallHref?: string | null;
  /** Start on this service or the update run (the demo's states). */
  initialService?: FwSelection;
}

/**
 * The firewall's own logs. It knows nothing about where they come from, so the same component runs
 * on the firewall's page (`apps/firewall-panel/fw/fw-logs-main.tsx`) and in the demo (`/demo/firewall-logs`).
 */
export function FirewallLogs({ source, timeoutMs = READ_TIMEOUT_MS, doctorHref, firewallHref, initialService = "all" }: FirewallLogsProps) {
  const [data, setData] = useState<FwLogsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [range, setRange] = useState<FwRange>("1h");
  const [selected, setSelected] = useState<FwSelection>(initialService);
  const [level, setLevel] = useState<FwLevelFilter>("all");
  const [qInput, setQInput] = useState("");
  const [q, setQ] = useState("");
  const [paused, setPaused] = useState(false);
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
        if (timedOut) setError(`The firewall did not answer within ${Math.round(timeoutMs / 1000)} seconds.`);
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
    return () => {
      inFlight.current?.abort();
      inFlight.current = null;
    };
  }, [load]);

  // Paused stops the timer only: a new range, service or Refresh still reads.
  useEffect(() => {
    if (paused) return;
    const t = setInterval(() => {
      if (document.visibilityState === "visible") void load("poll");
    }, REFRESH_MS);
    return () => clearInterval(t);
  }, [load, paused]);

  useEffect(() => {
    const t = setTimeout(() => setQ(qInput.trim().toLowerCase()), 250);
    return () => clearTimeout(t);
  }, [qInput]);

  const services = useMemo(() => data?.services ?? [], [data]);
  // `update` (cc-reprovision's progress lines) has no status of its own, so no row to take a label from.
  const labelOf = useMemo(() => new Map<string, string>([["update", "Updates"], ...services.map((s) => [s.id, s.label] as const)]), [services]);
  const failing = services.filter(isFailing);
  const isRun = selected === "run";
  const withDate = range === "24h";
  const lines = useMemo(() => (data && !isRun ? data.lines : []), [data, isRun]);

  const hist = useMemo(() => fwHistogram(lines, range, updatedAt?.getTime() ?? Date.now()), [lines, range, updatedAt]);

  const visible = useMemo(
    () => lines.filter((line) => fwPassesLevel(line, level) && (!q || `${labelOf.get(line.service) ?? line.service} ${line.message}`.toLowerCase().includes(q))),
    [lines, level, q, labelOf],
  );

  const runLines = useMemo(() => {
    if (!data?.run || !isRun) return [];
    return q ? data.run.filter((l) => l.toLowerCase().includes(q)) : data.run;
  }, [data, isRun, q]);
  const recap = useMemo(() => (data?.run ? fwRecap(data.run) : null), [data]);

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
  const updateFailed = update?.phase === "failed" || (recap?.failed ?? 0) > 0;
  const oldBuild = !!data?.warning && /cannot read its logs yet/.test(data.warning);
  // A standalone firewall in Docker: no systemd, so no journal to read (fw_logs.rs says so).
  const inContainer = !!data?.warning && /runs in a container/.test(data.warning);

  const firewallLink = (label: string) =>
    firewallHref ? (
      <a href={firewallHref} target="_blank" rel="noreferrer" className={cn(BTN, FOCUS, "border-transparent bg-brand text-white hover:bg-brand/90")}>
        {label}
        <ExternalLink aria-hidden="true" className="h-[13px] w-[13px]" />
      </a>
    ) : null;

  // Nothing read yet, and the read failed: one card that says why, with a retry.
  if (error && !data) {
    const expired = /expired/i.test(error);
    return (
      <Empty
        testId="fw-logs-error"
        icon={expired ? <Lock aria-hidden="true" className="h-5 w-5" /> : <AlertTriangle aria-hidden="true" className="h-5 w-5" />}
        title={expired ? "Access to these logs has expired" : "Couldn’t read the logs"}
        action={<RetryButton onClick={() => void load("now")} disabled={loading} />}
      >
        {expired ? "Each page here has its own short pass from the console. Open the logs again from the Firewall page in your ControlClaw console." : error}
      </Empty>
    );
  }

  if (inContainer) {
    return (
      <Empty testId="fw-logs-container" icon={<Package aria-hidden="true" className="h-5 w-5" />} title="This firewall’s logs are in its container">
        It runs in a container, which has no system journal for this page to read. On the machine that runs it, use{" "}
        <code className="font-mono text-[12.5px]">docker compose logs firewall</code> in its folder, or{" "}
        <code className="font-mono text-[12.5px]">podman compose logs firewall</code> under Podman.
      </Empty>
    );
  }

  if (oldBuild) {
    return (
      <Empty testId="fw-logs-old" icon={<Package aria-hidden="true" className="h-5 w-5" />} title="This firewall can’t read its logs yet" action={firewallLink("Open the Firewall page")}>
        It is on a build from before this page. Press Update on the Firewall page, then open Logs again.
      </Empty>
    );
  }

  const running = services.filter((s) => s.active === "active").length;
  const off = services.filter((s) => s.optional && s.active !== "active");
  const upSince = formatDay(services.find((s) => s.id === "mitm-agent")?.since ?? null);
  const firstFailing = failing[0];
  const doctorLink = doctorHref ? (
    <a href={doctorHref} className={cn(BTN, FOCUS)}>
      Repair with Doctor
    </a>
  ) : null;

  const railButton = (key: FwSelection, body: ReactNode, testId = `fw-logs-service-${key}`) => (
    <button
      key={key}
      type="button"
      onClick={() => setSelected(key)}
      aria-pressed={selected === key}
      data-testid={testId}
      className={cn(
        "flex min-w-0 items-center gap-2 rounded-[8px] px-2.5 py-[7px] text-left text-[13px]",
        selected === key ? "bg-brand-soft font-semibold text-brand-ink" : "text-ink hover:bg-bg-2",
        FOCUS,
      )}
    >
      {body}
    </button>
  );

  return (
    <div className="flex flex-col gap-4" data-testid="firewall-logs">
      {failing.length > 0 && firstFailing ? (
        <Banner
          tone="block"
          testId="fw-logs-failing"
          icon={<XCircle aria-hidden="true" className="h-4 w-4" />}
          actions={
            <>
              {selected !== firstFailing.id ? (
                <button type="button" className={cn(BTN, FOCUS)} onClick={() => setSelected(firstFailing.id)}>
                  Show its lines
                </button>
              ) : null}
              {doctorLink}
            </>
          }
        >
          <b className="font-semibold">{failing.map((s) => `${s.label} ${fwServiceTone(s).label.toLowerCase()}`).join(" · ")}.</b> {failingNote(firstFailing)}
        </Banner>
      ) : null}
      {updateFailed ? (
        <Banner
          tone="block"
          testId="fw-logs-update-failed"
          icon={<XCircle aria-hidden="true" className="h-4 w-4" />}
          actions={
            <>
              {!isRun ? (
                <button type="button" className={cn(BTN, FOCUS)} onClick={() => setSelected("run")}>
                  Show the run
                </button>
              ) : null}
              {doctorLink}
            </>
          }
        >
          <b className="font-semibold">The last update failed</b>
          {update?.detail ? `: ${update.detail}.` : "."} Run it again from the Firewall page{doctorHref ? ", or let Doctor look" : ""}.
        </Banner>
      ) : null}
      {error && data ? (
        <Banner tone="ask" testId="fw-logs-error" icon={<AlertTriangle aria-hidden="true" className="h-4 w-4" />} actions={<RetryButton onClick={() => void load("now")} disabled={loading} />}>
          <b className="font-semibold">{error}</b> The lines below are from the last read that worked{updatedAt ? `, at ${formatTime(updatedAt.getTime())}` : ""}.
        </Banner>
      ) : null}
      {data?.warning ? (
        <Banner tone="ask" icon={<AlertTriangle aria-hidden="true" className="h-4 w-4" />}>
          {data.warning}
        </Banner>
      ) : null}

      {!isRun ? (
        <section aria-label="Summary" className={CARD}>
          <div className="grid items-center gap-x-5 gap-y-3 px-4 py-3 md:grid-cols-[auto_minmax(0,1fr)_auto]">
            <div className="grid min-w-0 gap-1">
              {!data ? (
                <span className="inline-flex w-fit items-center gap-1.5 rounded-full bg-bg-2 px-2.5 py-0.5 text-[12.5px] font-medium text-ink-2">
                  <Loader2 aria-hidden="true" className="h-3 w-3 animate-spin" />
                  Reading the firewall
                </span>
              ) : failing.length ? (
                <span className={cn("inline-flex w-fit items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[12.5px] font-medium", PILL.block)} data-testid="fw-logs-state">
                  <XCircle aria-hidden="true" className="h-3 w-3" />
                  {failing.map((s) => `${s.label} ${fwServiceTone(s).label.toLowerCase()}`).join(", ")}
                </span>
              ) : (
                <span className={cn("inline-flex w-fit items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[12.5px] font-medium", PILL.allow)} data-testid="fw-logs-state">
                  <span className="h-1.5 w-1.5 rounded-full bg-current motion-safe:animate-pulse" />
                  {plural(running, "service", "services")} running
                </span>
              )}
              {data ? (
                <span className="text-[12.5px] text-ink-2">
                  {off.length ? `${off.length} off: ${off.map((s) => s.label).join(", ")}` : null}
                  {off.length && upSince ? " · " : null}
                  {upSince ? `up since ${upSince}` : null}
                </span>
              ) : null}
            </div>
            <LogChart buckets={hist.buckets} range={range} errors={hist.errors} warnings={hist.warnings} total={lines.length} />
            <div className="flex flex-wrap items-center gap-1.5">
              <button
                type="button"
                onClick={() => setLevel(level === "error" ? "all" : "error")}
                aria-pressed={level === "error"}
                data-testid="fw-logs-count-error"
                className={cn(
                  "inline-flex h-[30px] items-center gap-1.5 rounded-full border px-3 text-[12.5px] text-ink",
                  level === "error" ? "border-block-border bg-block-soft" : "border-line bg-surface hover:bg-bg-2",
                  FOCUS,
                )}
              >
                <XCircle aria-hidden="true" className="h-[14px] w-[14px] text-block-fg" />
                <b className="font-semibold tabular-nums">{hist.errors}</b>
                {hist.errors === 1 ? "error" : "errors"}
              </button>
              <button
                type="button"
                onClick={() => setLevel(level === "warn" ? "all" : "warn")}
                aria-pressed={level === "warn"}
                data-testid="fw-logs-count-warn"
                className={cn(
                  "inline-flex h-[30px] items-center gap-1.5 rounded-full border px-3 text-[12.5px] text-ink",
                  level === "warn" ? "border-ask-border bg-ask-soft" : "border-line bg-surface hover:bg-bg-2",
                  FOCUS,
                )}
              >
                <AlertTriangle aria-hidden="true" className="h-[14px] w-[14px] text-ask-fg" />
                <b className="font-semibold tabular-nums">{hist.warnings}</b>
                {hist.warnings === 1 ? "warning" : "warnings"}
              </button>
              <span className="text-[12px] text-ink-2">in the last {FW_RANGE_SPAN[range]}</span>
            </div>
          </div>
        </section>
      ) : null}

      <div className="grid min-w-0 gap-4 lg:grid-cols-[220px_minmax(0,1fr)] lg:items-start">
        <nav aria-label="Service" className={cn(CARD, "min-w-0")}>
          <div className="border-b border-line px-4 py-3 text-[14px] font-semibold text-ink">Services</div>
          <div className="grid grid-cols-1 gap-0.5 p-1.5 sm:grid-cols-2 lg:grid-cols-1">
            {railButton(
              "all",
              <>
                <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-brand" />
                <span className="min-w-0 flex-1 truncate">All services</span>
                {data && !isRun ? <span className="text-[11.5px] font-normal text-ink-2 tabular-nums">{lines.length}</span> : null}
              </>,
            )}
            {services.map((s) => {
              const t = fwServiceTone(s);
              return railButton(
                s.id,
                <>
                  <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", TONE_DOT[t.tone])} />
                  <span className="min-w-0 flex-1 truncate">{s.label}</span>
                  <span className={cn("shrink-0 text-[11.5px] font-normal", TONE_TEXT[t.tone])}>{t.label}</span>
                </>,
              );
            })}
            <div className="mx-2 my-1 h-px bg-line sm:col-span-2 lg:col-span-1" aria-hidden="true" />
            {railButton(
              "run",
              <>
                <Package aria-hidden="true" className="h-[14px] w-[14px] shrink-0 text-ink-2" />
                <span className="min-w-0 flex-1 truncate">Last update run</span>
                <span className={cn("shrink-0 text-[11.5px] font-normal", updateFailed ? "font-medium text-block-fg" : "text-ink-2")}>{updateRef(update)}</span>
              </>,
            )}
          </div>
        </nav>

        <section aria-label="Log lines" className={cn(CARD, "min-w-0 overflow-hidden")}>
          {isRun ? (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-line px-4 py-3" data-testid="fw-logs-run-state">
              <div className="min-w-0 flex-1 basis-[240px]">
                <div className="flex flex-wrap items-center gap-2 text-[14px] font-semibold text-ink">
                  {update ? (
                    <span className={cn("inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11.5px] font-semibold", updateFailed ? PILL.block : update.phase === "done" ? PILL.allow : PILL.muted)}>
                      {updateFailed ? <XCircle aria-hidden="true" className="h-3 w-3" /> : update.phase === "done" ? <Check aria-hidden="true" className="h-3 w-3" /> : null}
                      {updateFailed ? "Failed" : update.phase === "done" ? "Finished" : update.phase === "idle" ? "Idle" : "Running"}
                    </span>
                  ) : null}
                  {update ? (UPDATE_PHASE[update.phase] ?? update.phase) : "No update has run on this firewall yet"}
                </div>
                <div className="mt-0.5 text-[12.5px] text-ink-2">
                  {update ? [update.detail, formatWhen(update.at)].filter(Boolean).join(" · ") : "This is its first setup."}
                  {update ? " · " : " "}as ansible wrote it, oldest line first
                </div>
              </div>
              {recap ? (
                <div className="flex flex-wrap gap-1.5 text-[12px] text-ink-2">
                  {(
                    [
                      ["ok", recap.ok],
                      ["changed", recap.changed],
                      ["failed", recap.failed],
                      ["skipped", recap.skipped],
                    ] as const
                  ).map(([k, n]) => (
                    <span key={k} className={cn("rounded-full bg-bg-2 px-2.5 py-1", k === "failed" && n > 0 && "bg-block-soft text-block-fg")}>
                      <b className="mr-1 font-semibold text-ink tabular-nums">{n}</b>
                      {k}
                    </span>
                  ))}
                </div>
              ) : null}
            </div>
          ) : current ? (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line px-4 py-3" data-testid="fw-logs-current">
              <span className={cn("h-2.5 w-2.5 shrink-0 rounded-full", TONE_DOT[fwServiceTone(current).tone])} />
              <div className="min-w-0 flex-1 basis-[200px]">
                <div className="text-[14px] font-semibold text-ink">
                  {current.label} <span className="text-[12.5px] font-normal text-ink-2">{current.about}</span>
                </div>
                <div className={cn("text-[12.5px]", isFailing(current) ? "text-block-fg" : "text-ink-2")}>{serviceDetail(current)}</div>
              </div>
              {isFailing(current) ? doctorLink : null}
            </div>
          ) : null}

          <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2.5">
            <label className="relative w-[300px] max-w-full min-w-0 flex-auto sm:flex-none">
              <span className="sr-only">Search the log</span>
              <Search aria-hidden="true" className="pointer-events-none absolute top-1/2 left-[11px] h-[14px] w-[14px] -translate-y-1/2 text-ink-2" />
              <input
                type="search"
                value={qInput}
                onChange={(e) => setQInput(e.target.value)}
                placeholder={isRun ? "Search the update run" : "Search messages and services"}
                data-testid="fw-logs-search"
                className="h-[34px] w-full rounded-[10px] border border-line bg-surface pr-3 pl-[34px] text-[13px] text-ink placeholder:text-ink-2 focus:border-line-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
              />
            </label>
            {!isRun ? (
              <>
                <div role="group" aria-label="Level" className="inline-flex max-w-full items-center gap-0.5 overflow-x-auto rounded-[9px] border border-line bg-surface p-0.5">
                  {FW_LEVEL_FILTERS.map(({ key, label }) => (
                    <button
                      key={key}
                      type="button"
                      onClick={() => setLevel(key)}
                      aria-pressed={level === key}
                      data-testid={`fw-logs-level-${key}`}
                      className={cn(
                        "inline-flex h-[30px] shrink-0 items-center rounded-[7px] px-3 text-[12.5px] font-medium whitespace-nowrap",
                        level === key ? "bg-bg-2 font-semibold text-ink" : "text-ink-2 hover:text-ink",
                        FOCUS,
                      )}
                    >
                      {label}
                    </button>
                  ))}
                </div>
                <div role="group" aria-label="Time range" className="inline-flex items-center gap-0.5 rounded-[9px] border border-line bg-surface p-0.5">
                  {(Object.keys(FW_RANGE_LABELS) as FwRange[]).map((key) => (
                    <button
                      key={key}
                      type="button"
                      onClick={() => setRange(key)}
                      aria-pressed={range === key}
                      data-testid={`fw-logs-range-${key}`}
                      className={cn(
                        "inline-flex h-[30px] shrink-0 items-center rounded-[7px] px-3 text-[12.5px] font-medium whitespace-nowrap",
                        range === key ? "bg-bg-2 font-semibold text-ink" : "text-ink-2 hover:text-ink",
                        FOCUS,
                      )}
                    >
                      {FW_RANGE_LABELS[key]}
                    </button>
                  ))}
                </div>
              </>
            ) : null}
            <div className="ml-auto flex flex-wrap items-center gap-2">
              <span className="text-[12px] whitespace-nowrap text-ink-2" aria-live="polite">
                {updatedAt ? `Updated ${formatTime(updatedAt.getTime())}` : null}
              </span>
              <button
                type="button"
                onClick={() => void load("now")}
                disabled={loading}
                aria-label="Refresh"
                title="Read again now"
                data-testid="fw-logs-refresh"
                className={cn("inline-flex h-[30px] w-[30px] items-center justify-center rounded-[8px] border border-line bg-surface text-ink-2 hover:text-ink disabled:opacity-50", FOCUS)}
              >
                <RefreshCw aria-hidden="true" className={cn("h-[15px] w-[15px]", loading && "animate-spin")} />
              </button>
              {!isRun ? (
                <>
                  <button
                    type="button"
                    onClick={() => setPaused((v) => !v)}
                    aria-label={paused ? "Resume reading every 10 seconds" : "Pause reading every 10 seconds"}
                    data-testid="fw-logs-pause"
                    className={cn(BTN, FOCUS, paused && "bg-bg-2")}
                  >
                    {paused ? <Play aria-hidden="true" className="h-[13px] w-[13px]" /> : <Pause aria-hidden="true" className="h-[13px] w-[13px]" />}
                    {paused ? "Resume" : "Pause"}
                  </button>
                  <span
                    role="status"
                    data-testid="fw-logs-live"
                    className={cn("inline-flex h-[26px] items-center gap-1.5 rounded-full px-2.5 text-[12px] font-medium whitespace-nowrap", paused ? PILL.muted : PILL.allow)}
                  >
                    <span className={cn("h-1.5 w-1.5 rounded-full bg-current", !paused && "motion-safe:animate-pulse")} />
                    {paused ? "Paused" : "Live"}
                  </span>
                </>
              ) : null}
            </div>
          </div>

          <div
            ref={listRef}
            role="log"
            aria-label={isRun ? "Last update run, oldest line first" : "Journal, newest first"}
            tabIndex={0}
            data-testid="fw-logs-list"
            className={cn("h-[calc(100dvh-380px)] min-h-[360px] overflow-auto py-1.5 font-mono text-[12px] leading-[1.6]", FOCUS, "focus-visible:-outline-offset-2")}
          >
            {!data ? (
              <div className="px-4 py-3">
                <p className="m-0 mb-3 flex items-center gap-2 font-sans text-[13px] text-ink-2">
                  <Loader2 aria-hidden="true" className="h-4 w-4 animate-spin" />
                  Reading the journal on the firewall…
                </p>
                {Array.from({ length: 7 }, (_, i) => (
                  <div key={i} className="mb-2.5 h-3 rounded bg-bg-2 motion-safe:animate-pulse" style={{ width: `${40 + ((i * 17) % 50)}%` }} />
                ))}
              </div>
            ) : isRun ? (
              runLines.length === 0 ? (
                <div className="px-4 py-12 text-center font-sans text-[13px] text-ink-2">{q ? `No line has “${qInput.trim()}”.` : "No update or setup output on this firewall."}</div>
              ) : (
                runLines.map((line, i) => (
                  <div key={i} data-testid="fw-logs-run-line" className={cn("border-l-[3px] border-l-transparent py-px pr-4 pl-3 break-words whitespace-pre-wrap", runLineClass(line))}>
                    {line || " "}
                  </div>
                ))
              )
            ) : visible.length === 0 ? (
              <div className="px-4 py-12 text-center font-sans text-[13px] text-ink-2" data-testid="fw-logs-empty">
                {lines.length === 0 ? (
                  current ? (
                    `${current.label} wrote nothing in the last ${FW_RANGE_SPAN[range]}.`
                  ) : (
                    `Nothing logged in the last ${FW_RANGE_SPAN[range]}.`
                  )
                ) : (
                  <>
                    No line matches.{" "}
                    <button
                      type="button"
                      onClick={() => {
                        setQInput("");
                        setQ("");
                        setLevel("all");
                      }}
                      className={cn("font-medium text-brand-ink underline-offset-2 hover:underline", FOCUS)}
                    >
                      Show everything
                    </button>
                  </>
                )}
              </div>
            ) : (
              <>
                {visible.map((line, i) => (
                  <LogRow key={`${line.time}-${i}`} line={line} withDate={withDate} service={selected === "all" ? (labelOf.get(line.service) ?? line.service) : null} />
                ))}
                {data.truncated ? (
                  <div className="px-4 py-3 text-center font-sans text-[12.5px] text-ink-2">
                    Only the newest {data.lines.length} lines are shown. Pick one service or a shorter range to see older ones.
                  </div>
                ) : null}
              </>
            )}
          </div>
        </section>
      </div>
      <p className="m-0 flex items-start gap-1.5 text-[12.5px] text-ink-2">
        <Info aria-hidden="true" className="mt-0.5 h-[13px] w-[13px] shrink-0" />
        The page reads again every 10 seconds while this tab is open. Lines marked sys are systemd’s own and pass every level filter.
      </p>
    </div>
  );
}

function LogRow({ line, withDate, service }: { line: FwLogLine; withDate: boolean; service: string | null }) {
  const Icon = line.level === "error" ? XCircle : line.level === "warn" ? AlertTriangle : null;
  return (
    <div
      data-testid="fw-logs-line"
      data-level={line.level}
      className={cn("flex flex-wrap gap-x-3 border-l-[3px] border-l-transparent py-[3px] pr-4 pl-3 break-words whitespace-pre-wrap hover:bg-bg-2", ROW_TONE[line.level])}
    >
      <span className="shrink-0 text-ink-2 tabular-nums">{formatTime(line.time, withDate)}</span>
      <span className={cn("inline-flex h-[19px] w-[52px] shrink-0 items-center gap-1 self-start text-[11px] text-ink-2", BADGE_TONE[line.level])}>
        {Icon ? <Icon aria-hidden="true" className="h-[11px] w-[11px] shrink-0" /> : null}
        {line.level === "unit" ? "sys" : line.level}
      </span>
      {service ? <span className={cn("shrink-0 sm:w-[118px] sm:truncate", SERVICE_TONE[line.service] ?? "text-ink-2")}>{service}</span> : null}
      <span className={cn("min-w-0 basis-full [overflow-wrap:anywhere] sm:flex-1 sm:basis-0", line.level === "unit" ? "text-brand-ink" : "text-ink")}>{line.message}</span>
    </div>
  );
}

/** The whole Logs page as the firewall serves it: title, line, and the viewer. */
export function FirewallLogsPage(props: FirewallLogsProps) {
  return (
    <BoxPageBody wide>
      <BoxPageHead
        title="Logs"
        sub="What each service on this firewall wrote, and its last update. Read on the firewall; secrets it holds are removed before a line reaches this page."
      />
      <FirewallLogs {...props} />
    </BoxPageBody>
  );
}
