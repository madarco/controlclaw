"use client";

import { useState, type ReactNode } from "react";
import { Loader2 } from "lucide-react";
import { useOptionalApi } from "../lib/api";
import { cn } from "../lib/utils";
import { Card } from "../kit/console-ui";
import type { BrainModelChoice } from "../lib/brain-view";

/**
 * The model for the brain's own calls: its nightly run and the rewording of searches (T-217). What
 * the choices are, and what they cost, is the caller's: the console's included AI, or the model key
 * of a standalone firewall. No code: it changes what the brain spends, not who reaches it.
 *
 * `live={false}` (the demo) renders the given state and never calls the server.
 */
export function BrainModelPicker({
  model,
  models,
  intro,
  canManage,
  running,
  live = true,
  onChanged,
}: {
  model: string;
  models: BrainModelChoice[];
  /** The line above the choices. */
  intro: ReactNode;
  canManage: boolean;
  /** The brain is running: the model is set on it. */
  running: boolean;
  live?: boolean;
  onChanged: () => void;
}) {
  const brain = useOptionalApi()?.brain;
  if (live && !brain) throw new Error("BrainModelPicker: the ConsoleApi has no brain area");
  // What was asked for, shown until the page's view says the brain has it (or the change failed).
  const [pending, setPending] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const current = pending && pending !== model ? pending : model;

  const choose = (id: string) => {
    if (id === current || busy) return;
    setPending(id);
    setError(null);
    if (!live || !brain) return;
    setBusy(true);
    void brain
      .setModel({ model: id })
      .then(() => onChanged())
      .catch((e: Error) => {
        setPending(null);
        setError(e.message || "Couldn’t change the model. Try again.");
      })
      .finally(() => setBusy(false));
  };

  const disabled = !canManage || !running || busy;
  return (
    <Card className="p-5" data-testid="brain-model">
      <p className="max-w-[70ch] text-pretty text-[13.5px] text-ink-2">{intro}</p>
      <div role="radiogroup" aria-label="Brain model" className="mt-3 grid gap-2 sm:grid-cols-2">
        {models.map((m) => {
          const on = m.id === current;
          return (
            <button
              key={m.id}
              type="button"
              role="radio"
              aria-checked={on}
              disabled={disabled}
              onClick={() => choose(m.id)}
              className={cn(
                "flex min-w-0 items-start justify-between gap-3 rounded-[12px] border px-4 py-3 text-left transition-colors",
                on ? "border-brand bg-brand/5" : "border-line hover:border-ink-3",
                disabled && !on ? "opacity-60" : null,
              )}
              data-testid={`brain-model-${m.id}`}
            >
              <span className="min-w-0">
                <span className="block text-[14px] font-medium text-ink">{m.label}</span>
                {m.blurb ? <span className="block text-[12.5px] text-ink-2">{m.blurb}</span> : null}
              </span>
              {m.cost !== undefined || (busy && pending === m.id) ? (
                <span className="shrink-0 whitespace-nowrap text-[12.5px] text-ink-2 tabular-nums" data-testid={`brain-model-cost-${m.id}`}>
                  {busy && pending === m.id ? <Loader2 className="h-4 w-4 animate-spin" /> : m.cost}
                </span>
              ) : null}
            </button>
          );
        })}
      </div>
      {!running ? <p className="mt-3 text-[13px] text-ink-2">Start the brain to change its model.</p> : null}
      {error ? (
        <p className="mt-3 text-[13px] text-block-fg" data-testid="brain-model-error">
          {error}
        </p>
      ) : null}
    </Card>
  );
}
