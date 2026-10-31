"use client";

import { NativeSelect } from "../../ui/native-select";
import { useEffect, useState } from "react";
import { Loader2, Stethoscope } from "lucide-react";
import { Button } from "../../ui/button";
import { Textarea } from "../../ui/textarea";
import { ConfirmCodeDialog } from "../channels/ChannelDialogs";
import { CodeConfirmError } from "../../lib/code-dialog";
import type { DoctorStartCli, DoctorStartResult, DoctorStartState } from "@controlclaw/console-ui/lib/agent/doctor-start-types";
import { doctorModelsForCli, doctorSelectedModel } from "../../lib/doctor-models";

/**
 * Starting a Doctor repair on the firewall (docs/plans/doctor-rescue.md, Phase 1). Served by the
 * firewall at `/__cc/doctor/start/` and bundled into it by apps/firewall-panel/scripts/build-fw-files.mjs; the demo page drives it with a fake source.
 *
 * The problem is written here and stays on the firewall. The code is confirmed with the console's own
 * dialog, which also opens a challenge sealed to the recovery key.
 */
export interface DoctorStartSource {
  state: () => Promise<DoctorStartState>;
  propose: (input: { vmId: string; cli: DoctorStartCli; credentialId: string; model: string; problem: string }) => Promise<DoctorStartResult>;
  confirm: (input: { sessionId: string; code: string }) => Promise<DoctorStartResult>;
  /** Where to go once the repair runs: the firewall's chat. */
  go: (chat: string) => void;
}

const cliNames: Record<DoctorStartCli, string> = { claude: "Claude Code", codex: "Codex", pi: "Pi" };
const selectClass = "h-10 w-full min-w-0 rounded-md border border-line bg-surface px-3 text-sm text-ink";

export function DoctorStartPage({ source }: { source: DoctorStartSource }) {
  const [state, setState] = useState<DoctorStartState | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [vmId, setVmId] = useState("");
  const [cli, setCli] = useState<DoctorStartCli>("claude");
  const [credentialId, setCredentialId] = useState("");
  const [model, setModel] = useState("");
  const [problem, setProblem] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<DoctorStartResult | null>(null);

  useEffect(() => {
    source.state().then(setState, (e: unknown) => setLoadError(e instanceof Error ? e.message : "Couldn’t reach your firewall."));
  }, [source]);

  if (loadError) return <p className="rounded-xl border border-block-border bg-block-soft px-4 py-3 text-[13px] text-block-fg" role="alert">{loadError}</p>;
  if (!state) {
    return (
      <p className="flex items-center gap-2 text-[13px] text-ink-2">
        <Loader2 className="h-4 w-4 animate-spin" /> Reading your firewall…
      </p>
    );
  }

  const ready = state.agents.filter((a) => a.ready);
  // Opened from an agent's Doctor tab: that agent until the person picks another.
  const agent = ready.find((a) => a.vmId === (vmId || state.selected)) ?? ready[0];
  const choices = state.choices.filter((c) => c.clis.includes(cli));
  const credential = choices.find((c) => c.id === credentialId) ?? choices[0];
  const models = credential ? doctorModelsForCli(credential, cli) : [];
  const selectedModel = doctorSelectedModel(models, model);
  const canStart = !!agent && !!credential && !!selectedModel.trim() && !!problem.trim() && !busy;

  const propose = async () => {
    if (!agent || !credential) return;
    setBusy(true);
    setError(null);
    try {
      const out = await source.propose({ vmId: agent.vmId, cli, credentialId: credential.id, model: selectedModel, problem });
      if (out.ok && out.sessionId && out.sentVia) setPending(out);
      else setError(out.message ?? "Your firewall didn’t accept the repair.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn’t reach your firewall.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid gap-5">
      <div className="flex gap-3 rounded-[14px] border border-line bg-surface p-4 text-[13px] leading-6 text-ink-2">
        <Stethoscope className="mt-1 h-4 w-4 shrink-0" />
        <p className="m-0">
          Doctor runs on this firewall with root access for up to two hours. It connects to the agent over its private network, so it works even when the
          agent’s management service is down. Your problem description stays on this firewall. Your AI provider receives the repair context.
        </p>
      </div>
      {!ready.length && (
        <p className="rounded-xl border border-ask-border bg-ask-soft px-4 py-3 text-[13px] text-ask-fg" role="status">
          None of your agents has Doctor access yet. Update a working agent to install it. For an agent that broke before it had Doctor access, use Shell access.
        </p>
      )}
      {!state.choices.length && (
        <p className="rounded-xl border border-ask-border bg-ask-soft px-4 py-3 text-[13px] text-ask-fg" role="status">
          Doctor needs an AI provider. Add one or activate included AI tokens in the console, under Model providers.
        </p>
      )}
      <form
        className="grid gap-5 rounded-[14px] border border-line bg-surface p-5"
        onSubmit={(e) => {
          e.preventDefault();
          if (canStart) void propose();
        }}
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="space-y-2 text-sm text-ink">
            Agent
            <NativeSelect aria-label="Agent" className={selectClass} value={agent?.vmId ?? ""} onChange={(e) => setVmId(e.target.value)}>
              {!ready.length && <option value="">No agent with Doctor access</option>}
              {state.agents.map((a) => (
                <option key={a.vmId} value={a.vmId} disabled={!a.ready}>
                  {a.name}
                  {a.ready ? "" : " (Doctor access not installed)"}
                </option>
              ))}
            </NativeSelect>
          </label>
          <label className="space-y-2 text-sm text-ink">
            Coding agent
            <NativeSelect
              aria-label="Coding agent"
              className={selectClass}
              value={cli}
              onChange={(e) => {
                setCli(e.target.value as DoctorStartCli);
                setCredentialId("");
                setModel("");
              }}
            >
              {Object.entries(cliNames).map(([id, name]) => (
                <option key={id} value={id}>
                  {name}
                </option>
              ))}
            </NativeSelect>
          </label>
          <label className="space-y-2 text-sm text-ink">
            Pay with
            <NativeSelect
              aria-label="Pay with"
              className={selectClass}
              value={credential?.id ?? ""}
              onChange={(e) => {
                setCredentialId(e.target.value);
                setModel("");
              }}
            >
              {!choices.length && <option value="">No compatible key</option>}
              {choices.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.label}
                </option>
              ))}
            </NativeSelect>
          </label>
          <label className="space-y-2 text-sm text-ink">
            Model
            <NativeSelect aria-label="Model" className={selectClass} value={selectedModel} onChange={(e) => setModel(e.target.value)}>
              {!models.length && <option value="">No models available</option>}
              {models.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name}
                </option>
              ))}
            </NativeSelect>
          </label>
        </div>
        <label className="space-y-2 text-sm text-ink">
          What stopped working?
          <Textarea
            aria-label="Problem"
            value={problem}
            onChange={(e) => setProblem(e.target.value)}
            maxLength={8000}
            rows={5}
            placeholder="The agent stopped answering on Telegram after this morning’s update."
          />
        </label>
        {error && (
          <p className="rounded-xl border border-block-border bg-block-soft px-3 py-2 text-[13px] text-block-fg" role="alert">
            {error}
          </p>
        )}
        <div className="flex flex-wrap items-center justify-between gap-4">
          <p className="max-w-md text-xs leading-5 text-ink-2">
            One of your agents sends you a code to confirm. If none can, use your recovery key. Don’t paste secrets into the description.
          </p>
          <Button type="submit" disabled={!canStart} data-testid="doctor-start-submit">
            {busy && <Loader2 size={16} className="animate-spin" />}
            Start repair
          </Button>
        </div>
      </form>
      <ConfirmCodeDialog
        change={
          pending?.sessionId && pending.sentVia
            ? { id: pending.sessionId, summary: pending.summary ?? "", sentVia: pending.sentVia, expiresAt: pending.expiresAt ?? null, attemptsLeft: pending.attemptsLeft ?? null }
            : null
        }
        state={{ busy, error: null, note: null }}
        sender="Your firewall"
        warning="This allows Doctor to repair the agent with root access for up to two hours."
        loadRecoveryChallenge={async () => (pending?.challenge ? { challenge: pending.challenge, deliveryError: null, expiresAt: pending.expiresAt ?? null } : null)}
        onCancel={() => setPending(null)}
        onSubmit={async (code) => {
          const out = await source.confirm({ sessionId: pending!.sessionId!, code });
          if (out.ok && out.chat) {
            source.go(out.chat);
            return;
          }
          const final = out.status !== "invalid_code" || out.attemptsLeft === 0;
          if (final) setPending(null);
          throw new CodeConfirmError(
            out.status === "invalid_code"
              ? `That code is wrong.${out.attemptsLeft ? ` ${out.attemptsLeft} tries left.` : ""}`
              : (out.message ?? "The repair couldn’t start. Start a new one."),
            final,
          );
        }}
      />
    </div>
  );
}
