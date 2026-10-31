"use client";

import { useEffect, useMemo, useState } from "react";
import { KeyRound, Loader2 } from "lucide-react";
import { useOptionalApi } from "../../lib/api";
import { Button } from "../../ui/button";
import { CopyButton } from "../../ui/copy-button";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "../../ui/collapsible";
import { type JsonFileNote } from "../../kit/JsonFileDrop";
import { RecoveryKeyInput } from "../../kit/RecoveryKeyInput";
import type { RecoveryChallengeView } from "../../lib/recovery-confirm-schema";

/**
 * The code dialog's other half (T-99): no channel could deliver the code, so the firewall sealed an
 * answer to the organization's recovery key instead, and this is where the owner opens it.
 *
 * Two ways, and both end in the same 16-character answer going to the firewall in the field a code
 * would use:
 *
 *  - **In this page.** The key file is dropped or the key pasted, the challenge is opened here, and
 *    what the firewall sealed — its own summary of the change — is shown before anything is sent.
 *    The key goes nowhere; only the answer does.
 *  - **Without us.** `npx @controlclaw/recover answer <challenge>` opens it on the owner's machine,
 *    and they type the answer here. For anyone who does not want to paste their recovery key into a
 *    page we serve, which is the honest caveat of the first way.
 *
 * `onAnswer` hands the parent the answer when there is one to send, or null.
 */

const ANSWER_RE = /^[0-9a-hjkmnp-tv-z]{16}$/;

export type LoadRecoveryChallenge = (changeId: string) => Promise<RecoveryChallengeView | null>;

type Opened = { summary: string; subject: string; answer: string };

export function RecoveryKeyConfirm({
  changeId,
  locked,
  onAnswer,
  load: loadProp,
}: {
  changeId: string | null;
  locked: boolean;
  onAnswer: (answer: string | null) => void;
  load?: LoadRecoveryChallenge;
}) {
  const api = useOptionalApi();
  const load = useMemo<LoadRecoveryChallenge>(
    () => loadProp ?? (api ? (id) => api.firewall.recoveryChallenge({ changeId: id }) : async () => null),
    [loadProp, api],
  );
  const [challenge, setChallenge] = useState<RecoveryChallengeView | "loading" | "missing" | "unreachable">("loading");
  /** Bumped by Try again, after a read that failed rather than found nothing. */
  const [attempt, setAttempt] = useState(0);
  const [useKey, setUseKey] = useState(false);
  const [key, setKey] = useState("");
  const [note, setNote] = useState<JsonFileNote | null>(null);
  const [opening, setOpening] = useState(false);
  const [opened, setOpened] = useState<Opened | null>(null);
  const [openError, setOpenError] = useState<string | null>(null);
  const [typed, setTyped] = useState("");

  useEffect(() => {
    if (!changeId) {
      setChallenge("missing");
      return;
    }
    let stopped = false;
    setChallenge("loading");
    load(changeId)
      .then((c) => !stopped && setChallenge(c ?? "missing"))
      .catch((error) => {
        // A failed read is not "there is none": the change may be perfectly good, so the owner is
        // offered another try rather than told to start over.
        console.error("recoveryChallenge failed", error);
        if (!stopped) setChallenge("unreachable");
      });
    return () => {
      stopped = true;
    };
  }, [changeId, load, attempt]);

  const typedAnswer = typed.replace(/\s+/g, "").toLowerCase();
  const answer = opened?.answer ?? (ANSWER_RE.test(typedAnswer) ? typedAnswer : null);
  useEffect(() => {
    onAnswer(answer);
  }, [answer]); // eslint-disable-line react-hooks/exhaustive-deps

  const open = async () => {
    if (typeof challenge !== "object" || !changeId) return;
    setOpening(true);
    setOpenError(null);
    try {
      // Loaded on use: libsodium, which only this step needs.
      const { openRecoveryChallenge, parseRecoveryKey } = await import("@controlclaw/backup-envelope");
      const body = await openRecoveryChallenge(challenge.challenge, parseRecoveryKey(key), changeId);
      setOpened({ summary: body.summary, subject: body.subject, answer: body.answer });
      // The key has done its job; it does not stay in the page's state any longer than that.
      setKey("");
      setNote(null);
    } catch (error) {
      setOpenError(error instanceof Error && error.message ? error.message : "That key didn’t open the confirmation. Check that it’s your organization’s recovery key.");
    } finally {
      setOpening(false);
    }
  };

  if (challenge === "loading") {
    return (
      <div className="flex items-center gap-2 text-[13px] text-ink-2">
        <Loader2 className="h-3.5 w-3.5 animate-spin" /> Getting the confirmation from your firewall…
      </div>
    );
  }
  if (challenge === "unreachable") {
    return (
      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-block-border bg-block-soft px-3 py-2 text-[13px] text-block-fg" role="alert">
        <span className="min-w-0 flex-1">Couldn’t get the sealed confirmation from ControlClaw.</span>
        <Button type="button" size="sm" variant="outline" onClick={() => setAttempt((n) => n + 1)} data-testid="recovery-retry">
          Try again
        </Button>
      </div>
    );
  }
  if (challenge === "missing") {
    return (
      <div className="rounded-xl border border-block-border bg-block-soft px-3 py-2 text-[13px] text-block-fg" role="alert">
        Your firewall’s sealed confirmation isn’t here yet. Cancel this change and start it again.
      </div>
    );
  }

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-3" data-testid="recovery-confirm">
      <div className="rounded-xl border border-ask-border bg-ask-soft px-3 py-2 text-[12.5px] text-ask-fg" data-testid="recovery-delivery-error">
        {challenge.deliveryError ?? "None of your agents could send the code."}
      </div>

      {opened ? (
        <div className="rounded-xl border border-allow-border bg-allow-soft px-3 py-2.5 text-[13px] text-allow-fg" data-testid="recovery-opened">
          <div className="font-medium">Your firewall sealed this change:</div>
          <div className="mt-0.5 text-ink">{opened.summary}</div>
          <div className="mt-1 text-[12px]">Press Confirm if that’s what you asked for. If not, press Cancel change.</div>
        </div>
      ) : !useKey ? (
        <Button type="button" variant="outline" className="h-auto justify-self-start whitespace-normal py-2 text-left" onClick={() => setUseKey(true)} disabled={locked} data-testid="recovery-use-key">
          <KeyRound className="mr-1.5 h-3.5 w-3.5 shrink-0" />
          Can’t get the code? Use your recovery key
        </Button>
      ) : (
        <div className="grid grid-cols-[minmax(0,1fr)] gap-2">
          <Label htmlFor="confirm-recovery-key" className="text-[12px]">
            Your recovery key
          </Label>
          <RecoveryKeyInput
            id="confirm-recovery-key"
            testId="recovery-key-file"
            value={key}
            onChange={setKey}
            note={note}
            onNote={setNote}
            afterRead="Now press Open with key."
            disabled={locked || opening}
          />
          {openError ? (
            <div className="rounded-xl border border-block-border bg-block-soft px-3 py-2 text-[12.5px] text-block-fg" role="alert" data-testid="recovery-open-error">
              {openError}
            </div>
          ) : null}
          <Button type="button" size="sm" className="justify-self-start" onClick={() => void open()} disabled={locked || opening || key.trim().length === 0} data-testid="recovery-open">
            {opening ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : null}
            Open with key
          </Button>
          <p className="text-[12px] leading-relaxed text-ink-2">
            This page uses your key without sending it to ControlClaw. Only the answer inside goes to your firewall. But ControlClaw
            serves this page, so a compromised ControlClaw could serve one that keeps a copy. If that matters to you, use
            the command below instead.
          </p>
        </div>
      )}

      {opened ? null : (
        <Collapsible>
          <CollapsibleTrigger className="text-[12px] text-ink-2 underline underline-offset-2" data-testid="recovery-cli-toggle">
            Rather not paste your key here?
          </CollapsibleTrigger>
          <CollapsibleContent className="mt-2 grid grid-cols-[minmax(0,1fr)] gap-2 text-[12px] text-ink-2">
            <p>Run this on your own computer. It asks for your key there and prints a 16-letter answer.</p>
            <div className="flex items-start gap-2">
              <code className="min-w-0 flex-1 break-all rounded bg-surface-2 px-2 py-1 font-mono text-[11px]" data-testid="recovery-cli-command">
                npx @controlclaw/recover answer {challenge.challenge}
              </code>
              <CopyButton value={`npx @controlclaw/recover answer ${challenge.challenge}`} />
            </div>
            <Input
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              placeholder="The answer it printed"
              className="font-mono"
              maxLength={24}
              disabled={locked}
              autoComplete="off"
              spellCheck={false}
              data-testid="recovery-answer-input"
            />
          </CollapsibleContent>
        </Collapsible>
      )}
    </div>
  );
}
