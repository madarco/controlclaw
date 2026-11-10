"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { endsTheForm, type FirewallChangeStatus } from "../../lib/firewall-change";
import { CodeConfirmError, CONFIRM_ANSWER_TIMEOUT_MS, confirmVerdict, type ConfirmWait } from "../../lib/code-dialog";
import { boxErrorMessage } from "../../lib/box-error";
import { START_CHANGE_ERROR, startFirewallChange } from "../../lib/start-firewall-change";
import { RECOVERY_SENT_VIA, WRONG_RECOVERY_ANSWER } from "../../lib/recovery-confirm-schema";

/**
 * Follows one firewall change from proposal to outcome. Channel connections and model providers
 * both work the same way — the console proposes, the firewall answers through its heartbeat, and
 * a code step may come in between — so the polling, the confirm-and-wait dance and the cancel are
 * here once and the RPC methods are passed in.
 */

export type Busy = { busy: boolean; error: string | null; note: string | null };
export const IDLE: Busy = { busy: false, error: null, note: null };

export type { FirewallChangeStatus };

/** What the hook needs of a change; each feature's view is a superset. */
export type FirewallChangeLike = {
  id: string;
  summary: string;
  status: FirewallChangeStatus;
  tofu: boolean;
  sentVia: string | null;
  attemptsLeft: number | null;
  expiresAt: string | null;
  error: string | null;
  createdAt: string;
  stuck: boolean;
};

export type FirewallChangeRpc<T extends FirewallChangeLike> = {
  getChange: (input: { changeId: string }) => Promise<T>;
  confirm: (input: { changeId: string; code: string }) => Promise<unknown>;
  cancel: (input: { changeId: string }) => Promise<unknown>;
};

export interface UseFirewallChangeOptions<T extends FirewallChangeLike> {
  live: boolean;
  initial: T | null;
  rpc: FirewallChangeRpc<T>;
  /** A provisional row to show while the change is only queued. */
  blank: (changeId: string) => T;
  /**
   * The change is over, whichever way it went: re-read the page. Return the read's promise — the
   * code dialog waits for it before it closes, so the page already shows the result when it does.
   */
  onSettled: () => void | Promise<unknown>;
  /**
   * The change is over and there is nothing left for the person to do in the form that started it
   * — it applied, or the agent never confirmed it. A failure does NOT call this: the error belongs
   * in the dialog that collected the token, next to the field that has to change.
   *
   * It is handed the change, so a caller can tell which one ended (the Channels page keeps its
   * dialog open after an `add` to walk the person through pairing).
   */
  onDone?: (change: T) => void;
  /**
   * A feature whose change has states this hook does not know, consulted before anything else.
   *
   * It exists for one caller: a whole-organization update (T-100), whose statuses go `awaiting_code`
   * → `running` → `done`. `running` has to keep polling — the modal draws per-row progress off the
   * same rows for tens of minutes — and `running` is not in `FirewallChangeStatus`, so by default
   * this hook falls through every branch and keeps polling, which is exactly right. What it cannot
   * know is that `done` is the end, and without that the loop polls a finished batch for ever.
   *
   * Returning true stops the loop, clears the tracked change and calls `onSettled`. The default
   * behaviour is unchanged for every other caller, which is why this is a predicate here rather
   * than two more statuses in a union six features share.
   */
  isFinished?: (change: T) => boolean;
}

/** A confirm waiting for the firewall's answer: what it remembers, and the promise it settles. */
type Waiter = ConfirmWait & { changeId: string; resolve: () => void; reject: (error: Error) => void; onApplying?: () => void };

export function useFirewallChange<T extends FirewallChangeLike>(opts: UseFirewallChangeOptions<T>) {
  const [tracking, setTracking] = useState<T | null>(opts.initial);
  const [state, setState] = useState<Busy>(IDLE);
  const onSettled = useRef(opts.onSettled);
  onSettled.current = opts.onSettled;
  const rpc = useRef(opts.rpc);
  rpc.current = opts.rpc;
  const onDone = useRef(opts.onDone);
  onDone.current = opts.onDone;
  const blank = useRef(opts.blank);
  blank.current = opts.blank;
  const isFinished = useRef(opts.isFinished);
  isFinished.current = opts.isFinished;
  const waiter = useRef<Waiter | null>(null);
  /** The change whose end has been handled, so the two loops that read it do not handle it twice. */
  const settled = useRef<string | null>(null);
  /** A change that failed under the code dialog, kept until the dialog is closed. */
  const failure = useRef<{ error: string | null } | null>(null);

  /**
   * Re-read the page, but not for ever: the code dialog stays open until this is done, and a page
   * that never answers must not hold it open.
   */
  const refreshPage = async () => {
    try {
      await Promise.race([Promise.resolve(onSettled.current()), new Promise((r) => setTimeout(r, 15_000))]);
    } catch (error) {
      console.error("onSettled failed", error);
    }
  };

  /**
   * One read of the tracked change, from the poll loop or from a confirm waiting for its answer.
   * Returns true when the change is over and polling should stop.
   *
   * While a confirm waits, `tracking` keeps the change as it was when the code went in, so the
   * caller's `awaiting_code` test keeps the code dialog mounted and a form underneath it (a token
   * dialog that closes on `onDone`) does not come back for the seconds in between. It moves on when
   * the answer has been handled.
   */
  const observe = async (c: T): Promise<boolean> => {
    if (settled.current === c.id) return true;
    const w = waiter.current?.changeId === c.id ? waiter.current : null;
    if (!w) setTracking(c);
    // First, because a caller that owns its own end states owns them outright: a batch's
    // `done` must not fall through to `endsTheForm`, which would toast "confirmed and applied"
    // over a run where some boxes failed.
    if (isFinished.current?.(c)) {
      settled.current = c.id;
      waiter.current = null;
      w?.onApplying?.();
      await refreshPage();
      setState(IDLE);
      setTracking(null);
      w?.resolve();
      return true;
    }
    if (endsTheForm(c.status)) {
      settled.current = c.id;
      waiter.current = null;
      w?.onApplying?.();
      // The page is re-read before the code dialog closes and the toast shows, so the change is
      // already on it when they do.
      await refreshPage();
      setState(IDLE);
      setTracking(null);
      if (c.status === "unconfirmed") toast.info(boxErrorMessage(c.error) ?? "The agent has not confirmed this yet.");
      else toast.success(c.tofu ? `${c.summary}: done.` : `${c.summary}: confirmed and applied.`);
      onDone.current?.(c);
      w?.resolve();
      return true;
    }
    if (c.status === "failed" || c.status === "expired" || c.status === "cancelled" || c.status === "closed") {
      settled.current = c.id;
      waiter.current = null;
      const error = c.status === "cancelled" || c.status === "closed" ? null : (boxErrorMessage(c.error) ?? "The change didn’t go through. Try again.");
      if (w) {
        // The code dialog shows this and stays until it is closed; `cancel` then drops the change
        // and leaves the error for the form underneath, where it went before.
        failure.current = { error };
        setState(IDLE);
        w.reject(new CodeConfirmError(error ?? "The change was cancelled.", true));
        return true;
      }
      setState({ busy: false, error, note: null });
      setTracking(null);
      void refreshPage();
      return true;
    }
    if (w) {
      // A confirm is waiting, so the dialog is busy: nothing here may put the form back to idle
      // until the firewall has answered.
      const verdict = confirmVerdict(c, w, Date.now());
      if (verdict === "wait") return false;
      waiter.current = null;
      setState(IDLE);
      if (verdict === "wrong_code") {
        setTracking(c);
        w.reject(new CodeConfirmError(c.sentVia === RECOVERY_SENT_VIA ? WRONG_RECOVERY_ANSWER : "Wrong code. Check the message on your phone and try again."));
      } else if (verdict === "timeout") {
        w.reject(new CodeConfirmError("Your firewall didn’t answer yet. Try the code again in a moment."));
      } else {
        // The firewall took the code and a long change is under way; the page draws the rest.
        setTracking(c);
        w.resolve();
      }
      return false;
    }
    if (c.status === "awaiting_code" || c.status === "awaiting_login" || c.status === "awaiting_authorization") setState((s) => ({ busy: false, error: s.error, note: null }));
    else if (c.stuck) setState({ busy: true, error: null, note: "Your firewall hasn’t picked this up yet. Wait a few seconds." });
    return false;
  };
  const observeRef = useRef(observe);
  observeRef.current = observe;

  useEffect(() => {
    if (!opts.live || !tracking) return;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let stopped = false;
    const loop = async () => {
      if (stopped) return;
      try {
        const c = await rpc.current.getChange({ changeId: tracking.id });
        if (stopped) return;
        if (await observeRef.current(c)) return;
      } catch (error) {
        console.error("getChange failed", error);
      }
      if (!stopped) timer = setTimeout(loop, 2000);
    };
    void loop();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
  }, [opts.live, tracking?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  /** Start a change; `run` returns the change (or its id) from the RPC. */
  const start = useCallback(async (run: () => Promise<{ changeId: string } | T>, note: string, provisional: Partial<T> = {}) => {
    failure.current = null;
    setState({ busy: true, error: null, note });
    try {
      const r = await startFirewallChange(run);
      if ("changeId" in r && typeof r.changeId === "string") {
        setTracking({ ...blank.current(r.changeId), ...provisional });
      } else {
        setTracking(r as T);
        setState(IDLE);
      }
    } catch (error) {
      setTracking(null);
      setState({ busy: false, error: error instanceof Error && error.message ? error.message : START_CHANGE_ERROR, note: null });
    }
  }, []);

  /**
   * Adopt a change the caller has already started, by id. `start` covers the usual case — run the
   * RPC and follow whatever it returns — but a feature whose RPC can answer "there was nothing to
   * do" needs to decide that before anything is tracked: handing `start` an empty or null id leaves
   * this hook polling a change that does not exist, with the form stuck busy behind it.
   */
  const follow = useCallback((changeId: string, provisional: Partial<T> = {}) => {
    failure.current = null;
    setTracking({ ...blank.current(changeId), ...provisional });
    setState({ busy: false, error: null, note: null });
  }, []);

  /**
   * Send the code and settle when the change is over as far as the code dialog goes. Resolves once
   * the change has landed and the page has been re-read, or once a long change (a whole-organization
   * update) has started. Rejects with a `CodeConfirmError` on a wrong code, a failure, or a firewall
   * that does not answer. `ConfirmCodeDialog` stays busy until then; `onApplying` is called when
   * the firewall has taken the code and only the page is left to catch up.
   */
  const confirm = useCallback(
    async (code: string, onApplying?: () => void): Promise<void> => {
      if (!tracking) return;
      const changeId = tracking.id;
      setState({ busy: true, error: null, note: "Checking the code with your firewall…" });
      try {
        await rpc.current.confirm({ changeId, code });
      } catch (error) {
        setState(IDLE);
        throw new CodeConfirmError((error as Error).message || "Couldn’t send the code.");
      }
      await new Promise<void>((resolve, reject) => {
        const w: Waiter = { changeId, attemptsBefore: tracking.attemptsLeft, startedAt: Date.now(), resolve, reject, onApplying };
        waiter.current = w;
        // Read it sooner than the poll loop would. Both go through `observe`, which handles the
        // answer once, and both stop once it has.
        const wait = async () => {
          if (waiter.current !== w) return;
          try {
            await observeRef.current(await rpc.current.getChange({ changeId }));
          } catch (error) {
            console.error("getChange failed", error);
            if (waiter.current === w && Date.now() - w.startedAt > CONFIRM_ANSWER_TIMEOUT_MS) {
              waiter.current = null;
              setState(IDLE);
              reject(new CodeConfirmError("Your firewall didn’t answer yet. Try the code again in a moment."));
            }
          }
          if (waiter.current === w) setTimeout(() => void wait(), 1500);
        };
        setTimeout(() => void wait(), 1000);
      });
    },
    [tracking],
  );

  const cancel = useCallback(async () => {
    const failed = failure.current;
    failure.current = null;
    // The change already failed under the code dialog, and this is the dialog closing: nothing to
    // cancel, and the error goes back to the form that started it.
    if (failed) {
      setTracking(null);
      setState({ busy: false, error: failed.error, note: null });
      void onSettled.current();
      return;
    }
    // `live` off means fixtures (the demo pages): there is no change to cancel on the server.
    if (tracking && opts.live) {
      try {
        await rpc.current.cancel({ changeId: tracking.id });
      } catch (error) {
        console.error("cancel failed", error);
      }
    }
    waiter.current = null;
    setTracking(null);
    setState(IDLE);
    void onSettled.current();
  }, [tracking, opts.live]);

  return { tracking, setTracking, state, setState, start, follow, confirm, cancel };
}
