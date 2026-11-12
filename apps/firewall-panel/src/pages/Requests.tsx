import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Hand } from "lucide-react";
import { toast } from "sonner";
import type { Schemas } from "@controlclaw/fw-api";
import { Button } from "@controlclaw/console-ui/ui/button";
import { PageHead } from "@controlclaw/console-ui/kit/PageHead";
import { Badge, Card, EmptyState, Segmented } from "@controlclaw/console-ui/kit/console-ui";
import { RelativeTime } from "@controlclaw/console-ui/kit/RelativeTime";
import { errorText, fw } from "../api/client";
import { FormError } from "../auth/AuthFrame";

type Request = Schemas["PermissionRequest"];
type Shown = "pending" | "all";

const STATUS: Record<string, { label: string; tone: "ask" | "allow" | "block" | "neutral" }> = {
  pending: { label: "Waiting", tone: "ask" },
  approved: { label: "Approved", tone: "allow" },
  denied: { label: "Denied", tone: "block" },
  expired: { label: "Ran out", tone: "neutral" },
};

/** What the agents asked to do; a waiting one is answered here, and the agent's next poll gets it. */
export function RequestsPage() {
  const qc = useQueryClient();
  const [shown, setShown] = useState<Shown>("pending");
  const q = useQuery({
    queryKey: ["requests", shown],
    queryFn: () => fw.get("/api/requests", { query: shown === "pending" ? { status: "pending" } : {} }),
    refetchInterval: 10_000,
  });
  const [failed, setFailed] = useState<Record<string, string>>({});
  // Every row with an answer on its way, not only the last one clicked.
  const [sending, setSending] = useState<ReadonlySet<string>>(new Set());
  const answer = useMutation({
    mutationFn: ({ id, decision }: { id: string; decision: "approved" | "denied" }) => {
      setSending((s) => new Set(s).add(id));
      return fw.post("/api/requests/{id}/resolve", { path: { id }, body: { decision } });
    },
    onSettled: (_, __, { id }) =>
      setSending((s) => {
        const next = new Set(s);
        next.delete(id);
        return next;
      }),
    onSuccess: (_, { id }) => {
      setFailed(({ [id]: _gone, ...rest }) => rest);
      void qc.invalidateQueries({ queryKey: ["requests"] });
    },
    onError: (e, { id }) => {
      // Under Waiting the row may be gone on the next read (it ran out, or was answered elsewhere):
      // the reason is said where it stays.
      toast.error(`Not answered: ${errorText(e)}`);
      setFailed((f) => ({ ...f, [id]: errorText(e) }));
      void qc.invalidateQueries({ queryKey: ["requests"] });
    },
  });
  const list = q.data ?? [];

  return (
    <>
      <PageHead
        title="Permission requests"
        sub="What your agents asked to do. Approve or deny a waiting one; an answer reaches the agent within seconds."
        actions={
          <Segmented<Shown>
            size="sm"
            value={shown}
            onChange={setShown}
            options={[
              { value: "pending", label: "Waiting" },
              { value: "all", label: "All" },
            ]}
          />
        }
      />
      <Card data-testid="requests">
        {q.isPending ? (
          <div className="px-4 py-6 text-[13.5px] text-ink-2">Loading…</div>
        ) : q.error ? (
          <div className="px-4 py-4">
            <FormError>{errorText(q.error)}</FormError>
          </div>
        ) : list.length === 0 ? (
          <EmptyState icon={Hand} title={shown === "pending" ? "Nothing is waiting" : "No requests yet"}>
            When an agent asks to do something a rule holds for you, it shows up here.
          </EmptyState>
        ) : (
          <ul className="divide-y divide-line">
            {list.map((r) => (
              <RequestRow key={r.id} r={r} busy={sending.has(r.id)} error={failed[r.id]} onAnswer={(decision) => answer.mutate({ id: r.id, decision })} />
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}

function RequestRow({ r, busy, error, onAnswer }: { r: Request; busy: boolean; error?: string; onAnswer: (d: "approved" | "denied") => void }) {
  const status = STATUS[r.status] ?? { label: r.status, tone: "neutral" as const };
  return (
    <li className="px-4 py-3.5 sm:px-5" data-testid="request">
      <div className="flex flex-wrap items-start gap-x-3 gap-y-1">
        <div className="min-w-0 flex-1">
          <div className="text-[14px] font-medium text-ink">{r.title}</div>
          <div className="text-[12.5px] text-ink-2">
            {r.vmName ?? r.vmId} · <RelativeTime date={r.createdAt} />
            {r.status === "pending" && r.expiresAt ? (
              <>
                {" "}
                · runs out <RelativeTime date={r.expiresAt} />
              </>
            ) : null}
          </div>
        </div>
        <Badge tone={status.tone} dot>
          {status.label}
        </Badge>
      </div>
      {r.detail.length ? (
        <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5 text-[12.5px]">
          {r.detail.map(([k, v], i) => (
            <div key={i} className="contents">
              <dt className="text-ink-2">{k}</dt>
              <dd className="min-w-0 break-words text-ink">{v}</dd>
            </div>
          ))}
        </dl>
      ) : null}
      {r.ruleName ? (
        <p className="mt-2 text-[12.5px] text-ink-2" data-testid="request-rule">
          {r.resolvedBy === "rule" ? "Answered by the Auto approve rule" : "Asked by the Auto approve rule"} <span className="text-ink">{r.ruleName}</span>
        </p>
      ) : null}
      {error ? <p className="mt-2 text-[13px] text-block">{error}</p> : null}
      {r.status === "pending" ? (
        <div className="mt-3 flex gap-2">
          <Button size="sm" variant="brand" disabled={busy} onClick={() => onAnswer("approved")}>
            Approve
          </Button>
          <Button size="sm" variant="outline" disabled={busy} onClick={() => onAnswer("denied")}>
            Deny
          </Button>
        </div>
      ) : null}
    </li>
  );
}
