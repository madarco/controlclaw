"use client";

import { useEffect, useState } from "react";
import { Bot, Loader2, Lock, ShieldCheck, Shield, Sparkles, Stethoscope } from "lucide-react";
import { Button } from "../../ui/button";
import { Textarea } from "../../ui/textarea";
import { ConfirmCodeDialog } from "../channels/ChannelDialogs";
import { CodeConfirmError } from "../../lib/code-dialog";
import { cn } from "../../lib/utils";
import { BoxPageHead } from "../../kit/box-kit";
import type { DoctorStartChoice, DoctorStartCli, DoctorStartResult, DoctorStartState } from "../../lib/agent/doctor-start-types";
import { DOCTOR_CLI_NAMES } from "../../lib/doctor-models";
import { DoctorPickers, useDoctorChoice } from "./DoctorPickers";

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

const FOCUS = "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand";
const AGENT_PICKS = ["Stopped answering", "A channel stopped working", "Broke after an update", "Its pages don’t open"];
const FIREWALL_PICKS = ["Pages don’t load", "The proxy is down", "Disk is full", "Broke after an update"];

function costNote(c: DoctorStartChoice): string {
  if (c.provider === "openai_codex") return "your subscription’s allowance, no token cost";
  if (c.provider === "controlclaw_included") return "from your included AI";
  return "billed to your key";
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export function DoctorStartPage({ source }: { source: DoctorStartSource }) {
  const [state, setState] = useState<DoctorStartState | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [vmId, setVmId] = useState("");
  const [problem, setProblem] = useState("");
  const [change, setChange] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<DoctorStartResult | null>(null);
  // The form starts on the best credential the organization has, until the person picks.
  const choice = useDoctorChoice(state?.choices ?? null);

  useEffect(() => {
    source.state().then(setState, (e: unknown) => setLoadError(e instanceof Error ? e.message : "Couldn’t reach your firewall."));
  }, [source]);

  const head = <BoxPageHead title="Doctor" sub="A coding agent on this firewall that finds out what broke on an agent, or on the firewall itself, and fixes it." />;

  if (loadError) {
    return (
      <>
        {head}
        <p className="rounded-xl border border-block-border bg-block-soft px-4 py-3 text-[13px] text-block-fg" role="alert">
          {loadError}
        </p>
      </>
    );
  }
  if (!state) {
    return (
      <>
        {head}
        <p className="flex items-center gap-2 text-[13px] text-ink-2">
          <Loader2 className="h-4 w-4 animate-spin" /> Reading your firewall…
        </p>
      </>
    );
  }

  // This firewall first, then the agents.
  const targets = [...state.agents].sort((a, b) => Number(!!b.firewall) - Number(!!a.firewall));
  const ready = targets.filter((a) => a.ready);
  const readyAgents = ready.filter((a) => !a.firewall);
  // Opened from an agent's Doctor tab: that agent until the person picks another.
  const target = ready.find((a) => a.vmId === (vmId || state.selected)) ?? readyAgents[0] ?? ready[0];
  const fw = !!target?.firewall;
  // Until the person picks, the console's order decides the coding agent, the credential and the model.
  const { cli, credential, model: selectedModel, modelName } = choice;
  const canStart = !!target && !!credential && !!selectedModel.trim() && !!problem.trim() && !busy;

  const propose = async () => {
    if (!target || !credential) return;
    setBusy(true);
    setError(null);
    try {
      const out = await source.propose({ vmId: target.vmId, cli, credentialId: credential.id, model: selectedModel, problem });
      if (out.ok && out.sessionId && out.sentVia) setPending(out);
      else setError(out.message ?? "Your firewall didn’t accept the repair.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn’t reach your firewall.");
    } finally {
      setBusy(false);
    }
  };

  if (!ready.length) {
    return (
      <>
        {head}
        <div className="flex flex-col items-center gap-2 rounded-xl border border-line bg-surface px-6 py-12 text-center" role="status" data-testid="doctor-start-no-access">
          <span className="mb-1 inline-grid h-10 w-10 place-items-center rounded-full bg-bg-2 text-ink-2">
            <Stethoscope aria-hidden="true" className="h-5 w-5" />
          </span>
          <b className="text-[15px] font-semibold text-ink">None of your agents has Doctor access yet</b>
          <p className="m-0 max-w-[56ch] text-[13px] text-pretty text-ink-2">
            Doctor reaches an agent over its private network with access the agent installs when it updates. Update a working agent from the console, then
            come back. For an agent that broke before it had Doctor access, use Shell access.
          </p>
        </div>
      </>
    );
  }

  const picks = fw ? FIREWALL_PICKS : AGENT_PICKS;

  return (
    <>
      {head}
      {!readyAgents.length && (
        <p className="mb-4 rounded-xl border border-ask-border bg-ask-soft px-4 py-3 text-[13px] text-ask-fg" role="status">
          None of your agents has Doctor access yet. Update a working agent to install it. For an agent that broke before it had Doctor access, use Shell access.
        </p>
      )}
      {!state.choices.length && (
        <p className="mb-4 rounded-xl border border-ask-border bg-ask-soft px-4 py-3 text-[13px] text-ask-fg" role="status">
          Doctor needs an AI provider. Add one or activate included AI tokens in the console, under Model providers.
        </p>
      )}
      <form
        className="grid gap-5 rounded-xl border border-line bg-surface p-5"
        onSubmit={(e) => {
          e.preventDefault();
          if (canStart) void propose();
        }}
      >
        <fieldset className="m-0 grid min-w-0 gap-2.5 border-0 p-0">
          <legend className="mb-2.5 p-0 text-[13.5px] font-semibold text-ink">What needs repairing?</legend>
          <div className="grid gap-2 sm:grid-cols-2" role="radiogroup" aria-label="What needs repairing">
            {targets.map((a) => {
              const on = a.vmId === target?.vmId;
              return (
                <button
                  key={a.vmId}
                  type="button"
                  role="radio"
                  aria-checked={on}
                  disabled={!a.ready}
                  data-testid={`doctor-start-target-${a.vmId}`}
                  onClick={() => setVmId(a.vmId)}
                  className={cn(
                    "flex min-w-0 items-center gap-3 rounded-[10px] border px-3 py-2.5 text-left disabled:cursor-not-allowed disabled:opacity-55",
                    on ? "border-brand bg-brand-soft" : "border-line bg-surface hover:bg-bg-2",
                    FOCUS,
                  )}
                >
                  <span className={cn("inline-grid h-8 w-8 shrink-0 place-items-center rounded-lg", a.firewall ? "bg-brand text-white" : "bg-bg-2 text-ink-2")}>
                    {a.firewall ? <Shield aria-hidden="true" className="h-4 w-4" /> : <Bot aria-hidden="true" className="h-4 w-4" />}
                  </span>
                  <span className="grid min-w-0">
                    <b className={cn("truncate text-[13.5px] font-semibold", on ? "text-brand-ink" : "text-ink")}>{a.firewall ? "This firewall" : a.name}</b>
                    <small className="flex items-center gap-1.5 text-[12px] text-ink-2">
                      <i className={cn("h-1.5 w-1.5 shrink-0 rounded-full", a.ready ? "bg-allow" : "bg-ink-2/40")} />
                      {a.firewall ? "Its own repair commands only" : a.ready ? "Doctor access installed" : "Doctor access not installed"}
                    </small>
                  </span>
                </button>
              );
            })}
          </div>
        </fieldset>

        <fieldset className="m-0 grid min-w-0 gap-2.5 border-0 p-0">
          <legend className="mb-2.5 p-0 text-[13.5px] font-semibold text-ink">What’s wrong?</legend>
          <div className="flex flex-wrap gap-1.5">
            {picks.map((p) => (
              <button
                key={p}
                type="button"
                aria-pressed={problem.startsWith(p)}
                onClick={() => setProblem((cur) => (cur.startsWith(p) ? cur : `${p}. ${cur.replace(new RegExp(`^(${picks.map(escapeRe).join("|")})\\. ?`), "")}`))}
                className={cn(
                  "h-[30px] rounded-full border px-3 text-[12.5px] font-medium",
                  problem.startsWith(p) ? "border-brand bg-brand-soft text-brand-ink" : "border-line bg-surface text-ink-2 hover:text-ink",
                  FOCUS,
                )}
              >
                {p}
              </button>
            ))}
          </div>
          <Textarea
            aria-label="Problem"
            value={problem}
            onChange={(e) => setProblem(e.target.value)}
            maxLength={8000}
            rows={3}
            placeholder={fw ? "What happened, and since when? Doctor also starts with the firewall’s own checks." : "What happened, and since when? Don’t paste passwords."}
          />
        </fieldset>

        <div className="flex flex-wrap items-center gap-3 rounded-[10px] bg-bg-2 px-3.5 py-3 text-[13px] text-ink" data-testid="doctor-start-runs-with">
          <span className="inline-grid h-7 w-7 shrink-0 place-items-center rounded-full bg-surface text-brand-ink">
            <Sparkles aria-hidden="true" className="h-3.5 w-3.5" />
          </span>
          <div className="min-w-0 flex-1 basis-[220px]">
            <div className="text-[11.5px] font-medium tracking-[0.04em] text-ink-2 uppercase">Runs with</div>
            {credential ? (
              <div>
                {DOCTOR_CLI_NAMES[cli]} · {credential.label} · {modelName} <span className="text-ink-2">· {costNote(credential)}</span>
              </div>
            ) : (
              <div className="text-ask-fg">No credential can run {DOCTOR_CLI_NAMES[cli]}. Pick another coding agent.</div>
            )}
          </div>
          <button
            type="button"
            onClick={() => setChange((c) => !c)}
            aria-expanded={change}
            data-testid="doctor-start-change"
            className={cn("text-[13px] font-medium text-brand-ink underline-offset-2 hover:underline", FOCUS)}
          >
            {change ? "Done" : "Change"}
          </button>
        </div>
        {change || !credential ? (
          <div className="grid gap-4 sm:grid-cols-3">
            <DoctorPickers choice={choice} labelClassName="space-y-2 text-sm text-ink" selectClassName="h-10" />
          </div>
        ) : null}

        <ul className="m-0 grid list-none gap-1.5 p-0 text-[12.5px] text-ink-2">
          <li className="flex items-start gap-2">
            <Lock aria-hidden="true" className="mt-0.5 h-[13px] w-[13px] shrink-0" />
            {fw ? (
              <span>Only the firewall’s repair commands: logs, restarts, disk space, the update. No shell, no keys.</span>
            ) : (
              <span>
                Root access to <b className="font-semibold text-ink">{target?.name}</b>, up to 2 hours, over its private network: it works even when the
                agent’s management service is down.
              </span>
            )}
          </li>
          <li className="flex items-start gap-2">
            <ShieldCheck aria-hidden="true" className="mt-0.5 h-[13px] w-[13px] shrink-0" />
            <span>The chat stays on this firewall, encrypted, for 7 days. Your AI provider sees the repair context.</span>
          </li>
        </ul>

        {error && (
          <p className="m-0 rounded-xl border border-block-border bg-block-soft px-3 py-2 text-[13px] text-block-fg" role="alert">
            {error}
          </p>
        )}
        <div className="flex flex-wrap items-center justify-between gap-4 border-t border-line pt-4">
          <p className="m-0 max-w-md text-xs leading-5 text-ink-2">One of your agents sends you a code to confirm. No agent can? Your recovery key works too.</p>
          <Button type="submit" disabled={!canStart} data-testid="doctor-start-submit">
            {busy ? <Loader2 size={16} className="animate-spin" /> : <Stethoscope size={16} />}
            Send the code
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
        warning={fw ? "This allows Doctor to use the firewall’s repair commands for up to two hours." : "This allows Doctor to repair the agent with root access for up to two hours."}
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
    </>
  );
}
