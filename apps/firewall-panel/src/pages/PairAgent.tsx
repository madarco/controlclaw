import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@controlclaw/console-ui/ui/button";
import { Input } from "@controlclaw/console-ui/ui/input";
import { Checkbox } from "@controlclaw/console-ui/ui/checkbox";
import { CopyButton } from "@controlclaw/console-ui/ui/copy-button";
import { Card, Disclosure, Field } from "@controlclaw/console-ui/kit/console-ui";
import type { Schemas } from "@controlclaw/fw-api";
import { errorText, fw } from "../api/client";
import { FormError } from "../auth/AuthFrame";
import { AGENTS_KEY } from "../api/agents";
import { PAIR_ADDRESS_KEY, pairingUrl } from "../api/pairing";

const CODES_KEY = ["pairing-codes"] as const;

function untilText(expiresAt: number): string {
  return new Date(expiresAt * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/** A one-time code for one machine, and the command to run there with it. */
export function PairAgent({ compact }: { compact?: boolean }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [address, setAddress] = useState("");
  const [replace, setReplace] = useState(false);
  const [code, setCode] = useState<Schemas["NewCode"] | null>(null);
  const make = useMutation({
    mutationFn: () => fw.post("/api/pairing/codes", { body: { name: name.trim() || null, address: address.trim() || null, replace } }),
    onSuccess: (c) => {
      setCode(c);
      void qc.invalidateQueries({ queryKey: CODES_KEY });
    },
  });
  const addr = useQuery({ queryKey: PAIR_ADDRESS_KEY, queryFn: () => fw.get("/api/pairing/address"), staleTime: Infinity });
  const connect = (url: string) => `sudo controlclaw connect --mode host --firewall ${url}`;
  const command = connect(pairingUrl(addr.data, window.location.hostname));
  const remote = addr.data?.remoteUrl ? connect(addr.data.remoteUrl) : null;

  if (addr.data && !addr.data.open) {
    return (
      <p className="text-[13.5px] text-ink-2" data-testid="pairing-off">
        Pairing is off on this firewall (<code className="font-mono">PAIR_BIND=off</code>). Turn it on to connect agents from here.
      </p>
    );
  }

  if (code) {
    return (
      <div className="grid gap-4" data-testid="pairing-code">
        <div>
          <div className="text-[12.5px] font-medium text-ink-2">Pairing code{code.name ? ` for ${code.name}` : ""}</div>
          <div className="mt-1 flex items-center gap-2">
            <span className="font-mono text-[24px] font-semibold tracking-[0.06em] text-ink">{code.code}</span>
            <CopyButton value={code.code} />
          </div>
          <p className="mt-1 text-[12.5px] text-ink-2">It works once, until {untilText(code.expires_at)}. It is not shown again.</p>
        </div>
        <div>
          <div className="text-[12.5px] font-medium text-ink-2">On the agent&apos;s machine, run</div>
          <div className="mt-1 flex items-start gap-2 rounded-[9px] border border-line bg-bg px-3 py-2">
            <code className="min-w-0 flex-1 break-all font-mono text-[12.5px] text-ink">{command}</code>
            <CopyButton value={command} className="shrink-0" />
          </div>
          {remote ? (
            <>
              <div className="mt-3 text-[12.5px] font-medium text-ink-2">From another network, run</div>
              <div className="mt-1 flex items-start gap-2 rounded-[9px] border border-line bg-bg px-3 py-2">
                <code className="min-w-0 flex-1 break-all font-mono text-[12.5px] text-ink">{remote}</code>
                <CopyButton value={remote} className="shrink-0" />
              </div>
            </>
          ) : null}
          {remote ? (
            <p className="mt-1 text-[12.5px] text-ink-2">
              This is the firewall&apos;s public address (its <code className="font-mono">WG_ENDPOINT</code>): that machine needs TCP port {addr.data?.port}{" "}
              open to it, as well as WireGuard.
            </p>
          ) : null}
          <p className="mt-1 text-[12.5px] text-ink-2">
            It asks for the code. Use <code className="font-mono">--mode docker</code> when OpenClaw runs in Docker.
            {addr.data?.url ? null : (
              <>
                {" "}
                Put in the address the agent&apos;s machine reaches this firewall at (set <code className="font-mono">PAIR_PROXY_ADDR</code> and the
                firewall shows it here).
              </>
            )}{" "}
            The agent shows up in Agents within a minute.
          </p>
        </div>
        <Button variant="outline" onClick={() => setCode(null)}>
          Make another code
        </Button>
      </div>
    );
  }

  return (
    <form
      className="grid gap-4"
      data-testid="pairing-form"
      onSubmit={(e) => {
        e.preventDefault();
        make.mutate();
      }}
    >
      <Field label="Name (optional)" htmlFor="pair-name" hint="The agent's name here. The machine's own name when left empty.">
        <Input id="pair-name" value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      {compact ? null : (
        <Disclosure title="More options">
          <div className="grid gap-4 pt-2">
            <Field label="Address the proxy sees" htmlFor="pair-address" hint="Only when the machine's traffic comes from another address (a NAT, a container on this machine).">
              <Input id="pair-address" value={address} onChange={(e) => setAddress(e.target.value)} placeholder="10.0.0.5" className="font-mono" />
            </Field>
            <label className="flex items-center gap-2 text-[13px] text-ink-2">
              <Checkbox checked={replace} onCheckedChange={(v) => setReplace(v === true)} />
              It may take the place of an agent already at its address
            </label>
          </div>
        </Disclosure>
      )}
      <FormError>{make.error ? errorText(make.error) : ""}</FormError>
      <Button type="submit" variant="brand" disabled={make.isPending}>
        {make.isPending ? "Making a code…" : "Make a pairing code"}
      </Button>
    </form>
  );
}

/** The codes still waiting (never with the code), each with Revoke. */
export function PendingCodes() {
  const qc = useQueryClient();
  const codes = useQuery({ queryKey: CODES_KEY, queryFn: () => fw.get("/api/pairing/codes"), refetchInterval: 15_000 });
  const revoke = useMutation({
    mutationFn: (id: number) => fw.delete("/api/pairing/codes/{id}", { path: { id: String(id) }, body: {} }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: CODES_KEY });
      void qc.invalidateQueries({ queryKey: AGENTS_KEY });
    },
  });
  const list = codes.data?.codes ?? [];
  if (!list.length) return null;
  return (
    <Card className="mt-3" data-testid="pending-codes">
      <div className="border-b border-line px-4 py-2.5 text-[12.5px] font-medium text-ink-2">Codes waiting</div>
      <ul className="divide-y divide-line">
        {list.map((c) => (
          <li key={c.id} className="flex items-center gap-3 px-4 py-2.5 text-[13.5px]">
            <span className="min-w-0 flex-1 truncate text-ink">{c.name ?? "Any machine"}</span>
            <span className="text-ink-2">until {untilText(c.expires_at)}</span>
            <Button variant="ghost" size="sm" onClick={() => revoke.mutate(c.id)} disabled={revoke.isPending}>
              Revoke
            </Button>
          </li>
        ))}
      </ul>
    </Card>
  );
}
