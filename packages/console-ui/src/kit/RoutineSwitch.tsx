"use client";

import { useCallback, useEffect, useState } from "react";
import { Switch } from "../ui/switch";

const KEY = "activity.showRoutine";

/**
 * Whether this viewer shows routine traffic on Activity: model calls and channel polling let through
 * by the rules ControlClaw adds for providers and channels. Off by default, kept in this browser.
 * Storage can be missing or refuse (a private window): then it is off and not kept.
 */
export function useShowRoutine(): [boolean, (on: boolean) => void] {
  const [on, setOn] = useState(false);
  useEffect(() => {
    try {
      setOn(window.localStorage.getItem(KEY) === "1");
    } catch {
      // Not kept: off.
    }
  }, []);
  const set = useCallback((v: boolean) => {
    setOn(v);
    try {
      window.localStorage.setItem(KEY, v ? "1" : "0");
    } catch {
      // Not kept, but this page still follows it.
    }
  }, []);
  return [on, set];
}

/** "Show routine traffic", with how many requests it leaves out when off. */
export function RoutineSwitch({ on, hidden, onChange }: { on: boolean; hidden: number; onChange: (on: boolean) => void }) {
  return (
    <label className="inline-flex shrink-0 cursor-pointer items-center gap-2 text-[12.5px] whitespace-nowrap text-ink-2" data-testid="routine-switch">
      <Switch checked={on} onCheckedChange={onChange} aria-label="Show routine traffic" />
      <span>
        Show routine traffic
        {!on && hidden > 0 ? <span className="ml-1 text-[11px]">({hidden.toLocaleString()} hidden)</span> : null}
      </span>
    </label>
  );
}
