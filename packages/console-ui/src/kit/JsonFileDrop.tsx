"use client";

import { useRef, useState } from "react";
import { CheckCircle2, FileJson, ShieldAlert, Upload } from "lucide-react";
import { cn } from "../lib/utils";
import { Button } from "../ui/button";

/**
 * A drop zone for a JSON credential file, with a "Choose a file" button for anyone who would rather
 * not drag. It never uploads anything: the caller gets the File, reads it in the browser with
 * `readFileText`, and does what the paste would have done with the text.
 *
 * Used by the Google account's OAuth client file, the Drive folders service-account key and, with
 * `accept` and `icon` changed, the recovery key file on a locked disk (a `.txt`, not JSON).
 * `testId` prefixes the four ids: `-drop`, `-pick`, `-input` and `-note`.
 */

export type JsonFileNote = { tone: "ok" | "warn" | "bad"; text: React.ReactNode };

const NOTE_TONE = {
  ok: "border-allow-border bg-allow-soft text-allow-fg",
  warn: "border-ask-border bg-ask-soft text-ask-fg",
  bad: "border-block-border bg-block-soft text-block-fg",
} as const;

/**
 * The file's text, or null when the browser could not read it (a dropped directory, a file that
 * moved). Nothing above a drop handler awaits it, so a rejection would be silent and the drop would
 * seem to do nothing.
 */
export async function readFileText(file: File): Promise<string | null> {
  try {
    return await file.text();
  } catch {
    return null;
  }
}

export const UNREADABLE_FILE = "Couldn’t read that file. Choose it with the button instead of dropping it.";

export function JsonFileDrop({
  title,
  hint,
  note,
  onFile,
  testId,
  accept = "application/json,.json",
  icon: Icon = FileJson,
}: {
  title: string;
  hint: string;
  note: JsonFileNote | null;
  onFile: (file: File | null | undefined) => void;
  testId: string;
  /** The picker's filter. Dropping ignores it, so the caller still checks what it got. */
  accept?: string;
  icon?: React.ComponentType<{ className?: string }>;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-1.5">
      <div
        className={cn(
          "flex flex-wrap items-center gap-3 rounded-xl border border-dashed px-3 py-3 text-[13px]",
          over ? "border-brand bg-brand-soft" : "border-line bg-bg-2",
        )}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          onFile(e.dataTransfer.files?.[0]);
        }}
        data-testid={`${testId}-drop`}
      >
        <Icon className="h-5 w-5 shrink-0 text-ink-2" />
        <div className="min-w-[12rem] flex-1">
          <div className="font-medium text-ink">{title}</div>
          <div className="text-[11.5px] text-ink-2">{hint}</div>
        </div>
        <Button type="button" size="sm" variant="outline" className="shrink-0" onClick={() => input.current?.click()} data-testid={`${testId}-pick`}>
          <Upload className="mr-1.5 h-3.5 w-3.5" />
          Choose a file
        </Button>
        <input
          ref={input}
          type="file"
          accept={accept}
          className="hidden"
          data-testid={`${testId}-input`}
          onChange={(e) => {
            onFile(e.target.files?.[0]);
            e.target.value = "";
          }}
        />
      </div>
      {note ? (
        <div className={cn("flex gap-2 rounded-xl border px-3 py-2 text-[12.5px]", NOTE_TONE[note.tone])} data-testid={`${testId}-note`}>
          {note.tone === "ok" ? <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0" /> : <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />}
          <div className="min-w-0">{note.text}</div>
        </div>
      ) : null}
    </div>
  );
}
