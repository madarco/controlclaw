"use client";

import { Loader2 } from "lucide-react";
import { Button } from "../../ui/button";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { CODE_LENGTH, extractCode } from "../../lib/confirm-code";
import { cn } from "../../lib/utils";
import type { RulesPending } from "./useRulesChange";

/** The pending change of a rules card: waiting for the firewall, or the code it sent. */
export function RulesCodePanel({
  id,
  pending,
  code,
  busy,
  onCode,
  onConfirm,
  label,
  className = "mx-5 mb-3",
}: {
  /** The code field's id, unique on the page. */
  id: string;
  pending: RulesPending;
  code: string;
  busy: boolean;
  onCode: (code: string) => void;
  onConfirm: (cancel?: boolean) => void;
  /** Which rules the change is to ("Messages rules"), when the page has more than one kind. */
  label?: string;
  className?: string;
}) {
  return (
    <div className={cn("rounded-[10px] border border-line p-4", className)} data-testid={`${id}-panel`}>
      <p className="text-[13px] font-medium text-ink break-words">
        {pending.status === "awaiting_code" ? "Confirm this change" : "Waiting for your firewall"}
        {label ? <span className="font-normal text-ink-2"> · {label}</span> : null}
      </p>
      {pending.status === "awaiting_code" ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            onConfirm();
          }}
          className="mt-3 flex flex-wrap items-end gap-3"
        >
          <div>
            <Label htmlFor={id}>6-digit code{pending.sentVia ? ` via ${pending.sentVia}` : ""}</Label>
            <Input
              id={id}
              className="mt-2 w-44 font-mono"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              value={code}
              onChange={(e) => onCode(extractCode(e.target.value))}
              required
            />
          </div>
          <Button type="submit" disabled={busy || code.length !== CODE_LENGTH}>
            Confirm
          </Button>
          <Button type="button" variant="outline" disabled={busy} onClick={() => onConfirm(true)}>
            Cancel change
          </Button>
          <p className="w-full text-[12.5px] text-ink-2">Read the change in the message before confirming. The code expires in 10 minutes.</p>
        </form>
      ) : (
        <Loader2 className="mt-3 h-4 w-4 animate-spin" />
      )}
    </div>
  );
}
