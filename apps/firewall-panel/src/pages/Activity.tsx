import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Activity, Ban, Check, Globe, Play, Plug, RefreshCw, Search, Sparkles, UserCheck, Wrench } from "lucide-react";
import type { Schemas } from "@controlclaw/fw-api";
import { PageHead } from "@controlclaw/console-ui/kit/PageHead";
import { Card, EmptyState } from "@controlclaw/console-ui/kit/console-ui";
import { RoutineSwitch, useShowRoutine } from "@controlclaw/console-ui/kit/RoutineSwitch";
import { Button } from "@controlclaw/console-ui/ui/button";
import { cn } from "@controlclaw/console-ui/lib/utils";
import { errorText, fw } from "../api/client";
import { FormError } from "../auth/AuthFrame";

type Source = "network" | "tools" | "runs" | "findings" | "connectors";
type VerdictFilter = "all" | "allow" | "ask" | "block";
type Row = Schemas["ActivityRow"];

const PAGE = 50;

/** The console's Activity tabs, as this firewall keeps them. */
const SOURCES: Array<{ key: Source; label: string; Icon: typeof Globe; sub: string; empty: string }> = [
  {
    key: "network",
    label: "Network",
    Icon: Globe,
    sub: "Every request your agents made through the firewall: host, status, and the rule that decided it.",
    empty: "No network activity yet. Requests show up here once an agent sends one through the firewall.",
  },
  { key: "tools", label: "Tools", Icon: Wrench, sub: "Every tool your agents used.", empty: "No tool calls yet." },
  { key: "runs", label: "Runs", Icon: Play, sub: "Each turn your agents worked on, when it finished.", empty: "No runs yet." },
  {
    key: "findings",
    label: "Findings",
    Icon: Sparkles,
    sub: "What the firewall's AI review flagged in your agents' traffic.",
    empty: "No findings. Turn on AI Log Review in Internet access, and anything suspicious shows up here.",
  },
  { key: "connectors", label: "Integrations", Icon: Plug, sub: "Every call your agents made to a connected app or an MCP server.", empty: "No app calls yet." },
];

const VERDICTS: Array<{ key: VerdictFilter; label: string }> = [
  { key: "all", label: "All" },
  { key: "allow", label: "Allowed" },
  { key: "ask", label: "Asked" },
  { key: "block", label: "Blocked" },
];

const PILL: Record<Row["verdict"], { cls: string; Icon: typeof Check }> = {
  allowed: { cls: "bg-allow-soft text-allow-fg", Icon: Check },
  asked: { cls: "bg-ask-soft text-ask-fg", Icon: UserCheck },
  blocked: { cls: "bg-block-soft text-block-fg", Icon: Ban },
  recorded: { cls: "bg-bg-2 text-ink-2", Icon: Activity },
};

function time(iso: string): string {
  const d = new Date(iso);
  const today = new Date().toDateString() === d.toDateString();
  return d.toLocaleString(undefined, today ? { hour: "2-digit", minute: "2-digit", second: "2-digit" } : { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

/** Activity: the firewall's own log, by source, with the verdict counts, a search and pages. */
export function ActivityPage() {
  const [source, setSource] = useState<Source>("network");
  const [verdict, setVerdict] = useState<VerdictFilter>("all");
  const [qInput, setQInput] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(0);
  // Model calls and bot polling under the firewall's own rules: out of the list unless asked for.
  const [routine, setRoutine] = useShowRoutine();

  // Search as the person types, a moment after they stop.
  useEffect(() => {
    const t = setTimeout(() => {
      setQ(qInput.trim());
      setPage(0);
    }, 300);
    return () => clearTimeout(t);
  }, [qInput]);

  const data = useQuery({
    // Only Network has routine rows: the switch does not refetch the other views.
    queryKey: ["activity", source, verdict, q, page, source === "network" && routine],
    queryFn: () =>
      fw.get("/api/activity", { query: { source, verdict, q: q || undefined, routine: (source === "network" && routine) || undefined, limit: PAGE, offset: page * PAGE } }),
    // The last page stays up while the next one or a search loads, never under another tab.
    placeholderData: (prev, prevQuery) => (prevQuery?.queryKey[1] === source && prevQuery?.queryKey[2] === verdict ? prev : undefined),
    refetchInterval: 30_000,
  });
  const rows = data.data?.rows ?? [];
  const total = data.data?.total ?? 0;
  const counts = data.data?.counts;
  const current = SOURCES.find((s) => s.key === source)!;
  const pages = Math.max(1, Math.ceil(total / PAGE));

  return (
    <>
      <PageHead title="Activity" sub={current.sub} />
      <Card className="mb-4" data-testid="activity-filters">
        <div className="flex flex-wrap items-center gap-2.5 px-4 py-3">
          <div className="relative w-[320px] max-w-full">
            <Search className="pointer-events-none absolute top-1/2 left-[11px] h-[14px] w-[14px] -translate-y-1/2 text-ink-2" />
            <input
              type="search"
              aria-label="Search activity"
              maxLength={200}
              value={qInput}
              onChange={(e) => setQInput(e.target.value)}
              placeholder={source === "network" ? "Search hosts, rules, agents…" : "Search messages, agents…"}
              className="h-[34px] w-full rounded-[10px] border border-line bg-surface pr-3 pl-[34px] text-[13px] text-ink placeholder:text-ink-2 focus:border-line-2 focus:outline-none"
            />
          </div>
          {source === "network" ? (
            <RoutineSwitch
              on={routine}
              hidden={data.data?.routine ?? 0}
              onChange={(v) => {
                setRoutine(v);
                setPage(0);
              }}
            />
          ) : null}
          <div className="flex-1" />
          <div className="-mx-1 flex max-w-full items-center gap-0.5 overflow-x-auto rounded-[9px] border border-line bg-surface p-0.5 px-1 [scrollbar-width:none]">
            {SOURCES.map(({ key, label, Icon }) => (
              <button
                key={key}
                type="button"
                onClick={() => {
                  setSource(key);
                  setPage(0);
                }}
                className={cn(
                  "inline-flex h-[30px] shrink-0 items-center gap-1.5 rounded-[7px] px-3 text-[12.5px] font-medium whitespace-nowrap",
                  source === key ? "bg-bg-2 font-semibold text-ink" : "text-ink-2 hover:text-ink",
                )}
              >
                <Icon className="h-[13px] w-[13px]" />
                {label}
              </button>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-0.5 rounded-[9px] border border-line bg-surface p-0.5">
            {VERDICTS.map(({ key, label }) => (
              <button
                key={key}
                type="button"
                onClick={() => {
                  setVerdict(key);
                  setPage(0);
                }}
                className={cn(
                  "inline-flex h-[30px] items-center gap-1.5 rounded-[7px] px-3 text-[12.5px] font-medium whitespace-nowrap",
                  verdict === key ? "bg-bg-2 font-semibold text-ink" : "text-ink-2 hover:text-ink",
                )}
              >
                {label}
                {counts ? <span className="text-[11px] text-ink-2">{counts[key]}</span> : null}
              </button>
            ))}
          </div>
          <Button variant="outline" size="icon-sm" aria-label="Refresh" onClick={() => void data.refetch()} disabled={data.isFetching}>
            <RefreshCw className={cn(data.isFetching && "animate-spin")} />
          </Button>
        </div>
      </Card>

      <Card data-testid="activity">
        {data.error ? (
          <div className="px-4 py-4">
            <FormError>{errorText(data.error)}</FormError>
          </div>
        ) : data.isPending ? (
          <div className="px-4 py-6 text-[13.5px] text-ink-2">Loading…</div>
        ) : rows.length === 0 ? (
          <EmptyState icon={current.Icon}>{q ? "Nothing matches that search." : current.empty}</EmptyState>
        ) : (
          <div className="flex flex-col">
            {rows.map((r) => {
              const pill = PILL[r.verdict];
              return (
                <div
                  key={r.id}
                  data-testid="activity-row"
                  className="grid grid-cols-[auto_auto_1fr] items-center gap-x-3 gap-y-1 border-b border-line px-4 py-3 text-[13.5px] last:border-b-0 sm:grid-cols-[auto_auto_1fr_auto] sm:px-5"
                >
                  <span className="font-mono text-[11.5px] whitespace-nowrap text-ink-2">{time(r.createdAt)}</span>
                  <span className={cn("inline-flex h-[22px] items-center gap-1 rounded-[7px] px-2 text-[11.5px] font-semibold", pill.cls)}>
                    <pill.Icon className="h-3 w-3" />
                    {r.status || r.verdict}
                  </span>
                  <span className="col-span-3 min-w-0 break-words text-ink sm:col-span-1 sm:truncate" title={r.message}>
                    {r.statusCode != null ? <span className="mr-2 font-mono text-[11.5px] text-ink-2">{r.statusCode}</span> : null}
                    {r.message}
                    {r.rule ? <span className="ml-2 text-[12px] text-ink-2">· {r.rule}</span> : null}
                  </span>
                  <span className="hidden truncate text-[12px] text-ink-2 sm:block sm:max-w-[160px]">{r.agent ?? "Firewall"}</span>
                </div>
              );
            })}
          </div>
        )}
      </Card>
      {total > PAGE ? (
        <div className="mt-3 flex items-center justify-between text-[12.5px] text-ink-2">
          <span>
            {page * PAGE + 1}–{page * PAGE + rows.length} of {total}
          </span>
          <span className="flex gap-2">
            <Button size="sm" variant="outline" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
              Newer
            </Button>
            <Button size="sm" variant="outline" disabled={page + 1 >= pages} onClick={() => setPage((p) => p + 1)}>
              Older
            </Button>
          </span>
        </div>
      ) : null}
    </>
  );
}
