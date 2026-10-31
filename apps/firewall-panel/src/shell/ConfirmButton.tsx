import { useState } from "react";
import { Button } from "@controlclaw/console-ui/ui/button";

/** A button for something hard to undo: the first click asks, the second does it. */
export function ConfirmButton({ label, confirm, busy, onConfirm }: { label: string; confirm: string; busy?: boolean; onConfirm: () => void }) {
  const [asking, setAsking] = useState(false);
  if (!asking) {
    return (
      <Button size="sm" variant="ghost" onClick={() => setAsking(true)}>
        {label}
      </Button>
    );
  }
  return (
    <span className="flex items-center gap-1.5">
      <Button size="sm" variant="destructive" disabled={busy} onClick={onConfirm}>
        {confirm}
      </Button>
      <Button size="sm" variant="ghost" onClick={() => setAsking(false)}>
        Keep
      </Button>
    </span>
  );
}
