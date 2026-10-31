"use client";

import { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";
import { toast } from "sonner";
import { Button } from "./button";
import { cn } from "../lib/utils";

/**
 * Copies a string to the clipboard and says so for a moment. Falls back to a hidden textarea
 * where `navigator.clipboard` is missing (an insecure origin, an old browser). With `toastMessage`
 * it also raises a toast, for a button whose own label is too small to notice.
 */
export function CopyButton({
  value,
  label = "Copy",
  copiedLabel = "Copied",
  className,
  size = "sm",
  variant = "outline-surface",
  toastMessage,
  ...rest
}: {
  value: string;
  toastMessage?: string;
  label?: string;
  copiedLabel?: string;
  className?: string;
  size?: React.ComponentProps<typeof Button>["size"];
  variant?: React.ComponentProps<typeof Button>["variant"];
  disabled?: boolean;
  "data-testid"?: string;
}) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => void (timer.current && clearTimeout(timer.current)), []);

  const copy = async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
      } else {
        const el = document.createElement("textarea");
        el.value = value;
        el.style.position = "fixed";
        el.style.opacity = "0";
        document.body.appendChild(el);
        el.select();
        document.execCommand("copy");
        el.remove();
      }
      setCopied(true);
      if (toastMessage) toast.success(toastMessage);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1600);
    } catch {
      // Nothing useful to say: the text is on screen and can be selected by hand.
    }
  };

  return (
    <Button type="button" variant={variant} size={size} className={cn("gap-1.5", className)} onClick={copy} {...rest}>
      {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? copiedLabel : label}
    </Button>
  );
}
