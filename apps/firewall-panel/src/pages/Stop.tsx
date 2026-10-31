import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { OctagonX } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@controlclaw/console-ui/ui/button";
import { Input } from "@controlclaw/console-ui/ui/input";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@controlclaw/console-ui/ui/dialog";
import { fw } from "../api/client";
import { refusalText } from "../api/rules";
import { FormError } from "../auth/AuthFrame";

/** `GET /api/kill` (cc-local `api/controls.rs`): untyped in the OpenAPI document, so typed here. */
type Kill = { org: { at: string } | null; agents: Array<{ vmId: string; name?: string | null; source?: string; at: string }> } | null;

const KEY = ["kill"] as const;

function useKill() {
  return useQuery({ queryKey: KEY, queryFn: async () => ((await fw.get("/api/kill")) as { kill: Kill }).kill, refetchInterval: 15_000 });
}

function stopped(k: Kill | undefined): boolean {
  return !!k && (!!k.org || k.agents.length > 0);
}

/** The emergency stop, in the header: every agent loses model calls, the web and its channels until started again. */
export function StopButton() {
  const qc = useQueryClient();
  const kill = useKill();
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  /** Every way the dialog closes clears what was typed: a STOP left there is one click from stopping everything. */
  const openChange = (o: boolean) => {
    setOpen(o);
    if (!o) {
      setTyped("");
      engage.reset();
    }
  };
  const engage = useMutation({
    mutationFn: () => fw.post("/api/kill/engage", { body: { confirm: "STOP" } }),
    onSuccess: () => {
      openChange(false);
      toast.success("Every agent is stopped.");
      void qc.invalidateQueries({ queryKey: KEY });
    },
  });
  // One agent stopped on its own leaves the others running: the button stays for them.
  if (kill.data?.org) return null;
  return (
    <>
      <Button variant="outline" size="sm" className="text-block-fg" onClick={() => setOpen(true)} data-testid="stop-open">
        <OctagonX />
        <span className="hidden sm:inline">Stop</span>
      </Button>
      <Dialog open={open} onOpenChange={openChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Stop every agent?</DialogTitle>
            <DialogDescription>
              The firewall refuses their model calls, the web and their channels at once, until you start them again here. Type STOP to go on.
            </DialogDescription>
          </DialogHeader>
          <Input value={typed} onChange={(e) => setTyped(e.target.value)} placeholder="STOP" autoComplete="off" aria-label="Type STOP" data-testid="stop-confirm" />
          <FormError>{engage.error ? refusalText(engage.error) : ""}</FormError>
          <DialogFooter>
            <Button variant="outline" onClick={() => openChange(false)}>
              Cancel
            </Button>
            <Button variant="destructive" disabled={typed !== "STOP" || engage.isPending} onClick={() => engage.mutate()} data-testid="stop-engage">
              Stop every agent
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

/** Across the top while anything is stopped, never dismissible, with Start again. */
export function StopBanner() {
  const qc = useQueryClient();
  const kill = useKill();
  const release = useMutation({
    // Everything that is stopped: the whole firewall, else each agent stopped on its own.
    mutationFn: async (k: NonNullable<Kill>) => {
      if (k.org) await fw.post("/api/kill/release", { body: { vmId: null } });
      for (const a of k.agents) await fw.post("/api/kill/release", { body: { vmId: a.vmId } });
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: KEY }),
    onError: (e) => toast.error(`Not started: ${refusalText(e)}`),
  });
  const k = kill.data;
  if (!stopped(k) || !k) return null;
  const text = k.org ? "Every agent is stopped" : `${k.agents.length === 1 ? (k.agents[0].name ?? "One agent") + " is" : `${k.agents.length} agents are`} stopped`;
  return (
    <div role="status" className="flex flex-wrap items-center gap-x-3 gap-y-1 bg-block px-4 py-[7px] text-[13px] font-medium text-white md:px-[18px]" data-testid="stop-banner">
      <OctagonX className="h-[15px] w-[15px] shrink-0" />
      <span className="min-w-0">
        {text}
        <span className="font-normal opacity-80"> · no model calls, no web, no channels</span>
      </span>
      <button
        type="button"
        className="ml-auto shrink-0 underline underline-offset-2 hover:opacity-80 disabled:opacity-60"
        disabled={release.isPending}
        onClick={() => release.mutate(k)}
        data-testid="stop-release"
      >
        {release.isPending ? "Starting…" : "Start again"}
      </button>
    </div>
  );
}
