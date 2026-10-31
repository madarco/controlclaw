/**
 * The code dialog's state machine, away from React so it can be read and tested on its own. The
 * dialog is `ConfirmCodeDialog` in `app/(channels)/components/ChannelDialogs.tsx`; the hook whose
 * `confirm` drives it is `useFirewallChange`.
 *
 * From the moment the person presses Confirm the dialog is busy and read-only, and it stays open
 * until the change is over: it landed (close), or it failed (stay, say why). A change that takes
 * minutes — a firewall update, a whole-organization update — counts as over for the dialog once the
 * firewall has taken the code and started; the page shows the progress from there.
 */

import type { FirewallChangeStatus } from "./firewall-change";

export type CodeDialogPhase =
  | { kind: "idle" }
  /** The code is on its way to the firewall, or the firewall is checking it. */
  | { kind: "confirming" }
  /** The firewall took the code; the page is catching up with what it did. */
  | { kind: "applying" }
  /**
   * It did not go through. `final` means there is nothing left to retry — the change failed,
   * expired or ran out of tries — so the only way out is to close the dialog.
   */
  | { kind: "failed"; message: string; final: boolean };

export type CodeDialogEvent =
  | { type: "submit" }
  | { type: "progress"; step: "applying" }
  | { type: "failed"; message: string; final: boolean }
  | { type: "done" }
  | { type: "reset" };

export const CODE_DIALOG_IDLE: CodeDialogPhase = { kind: "idle" };

export function isBusy(phase: CodeDialogPhase): boolean {
  return phase.kind === "confirming" || phase.kind === "applying";
}

/**
 * Whether the dialog stays open after its change has left `awaiting_code`. The caller stops passing
 * a change the moment the firewall answers, which is before the page shows what happened; the
 * dialog keeps the last one on screen until the confirm promise settles.
 */
export function holdsOpen(phase: CodeDialogPhase): boolean {
  return isBusy(phase) || (phase.kind === "failed" && phase.final);
}

/** Whether the code can be typed and sent. */
export function canSubmit(phase: CodeDialogPhase): boolean {
  return phase.kind === "idle" || (phase.kind === "failed" && !phase.final);
}

export function codeDialogReducer(phase: CodeDialogPhase, event: CodeDialogEvent): CodeDialogPhase {
  switch (event.type) {
    case "submit":
      return canSubmit(phase) ? { kind: "confirming" } : phase;
    case "progress":
      return phase.kind === "confirming" ? { kind: "applying" } : phase;
    case "failed":
      // A late answer to a submit the person already walked away from changes nothing.
      return isBusy(phase) ? { kind: "failed", message: event.message, final: event.final } : phase;
    case "done":
      return isBusy(phase) ? CODE_DIALOG_IDLE : phase;
    case "reset":
      return CODE_DIALOG_IDLE;
  }
}

/** The Confirm button's label. */
export function submitLabel(phase: CodeDialogPhase): string {
  if (phase.kind === "confirming") return "Confirming…";
  if (phase.kind === "applying") return "Applying…";
  return "Confirm";
}

/** The line under the code while it is busy, in place of the countdown. */
export function busyLine(phase: CodeDialogPhase): string | null {
  if (phase.kind === "confirming") return "Checking the code with your firewall…";
  if (phase.kind === "applying") return "Code accepted. Applying the change…";
  return null;
}

/** What a confirm promise rejects with. `final`: the change is over, there is nothing to retry. */
export class CodeConfirmError extends Error {
  constructor(
    message: string,
    readonly final: boolean = false,
  ) {
    super(message);
    this.name = "CodeConfirmError";
  }
}

/** Reads whatever a confirm promise rejected with into the dialog's `failed` event. */
export function failureOf(error: unknown): { message: string; final: boolean } {
  const message = error instanceof Error && error.message ? error.message : "The change didn’t go through.";
  return { message, final: error instanceof CodeConfirmError ? error.final : false };
}

/** What the confirm step remembers while it waits for the firewall's answer. */
export type ConfirmWait = { attemptsBefore: number | null; startedAt: number };

/** How long the confirm step waits for the firewall to answer before telling the person. */
export const CONFIRM_ANSWER_TIMEOUT_MS = 30_000;

/**
 * What a fresh read of the change means to a confirm that is waiting, for a change that has not
 * ended (the terminal statuses are decided first, by the hook).
 *
 * - `wait`: the firewall has not answered yet.
 * - `wrong_code`: it answered, and the tries went down.
 * - `timeout`: it has not answered in `CONFIRM_ANSWER_TIMEOUT_MS`.
 * - `started`: it took the code and the change is under way in a state that is not the end — a
 *   whole-organization update's `running`, or a sign-in the page itself asks for. The dialog has
 *   nothing left to do; the page shows the progress.
 */
export function confirmVerdict(
  change: { status: FirewallChangeStatus; attemptsLeft: number | null },
  wait: ConfirmWait,
  now: number,
  timeoutMs: number = CONFIRM_ANSWER_TIMEOUT_MS,
): "wait" | "wrong_code" | "timeout" | "started" {
  if (change.status === "awaiting_code" || change.status === "queued") {
    if (change.status === "awaiting_code" && wait.attemptsBefore !== null && change.attemptsLeft !== null && change.attemptsLeft < wait.attemptsBefore) return "wrong_code";
    return now - wait.startedAt > timeoutMs ? "timeout" : "wait";
  }
  return "started";
}
