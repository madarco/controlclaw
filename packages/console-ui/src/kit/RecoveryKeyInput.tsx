"use client";

import { FileKey } from "lucide-react";
import { Textarea } from "../ui/textarea";
import { JsonFileDrop, readFileText, UNREADABLE_FILE, type JsonFileNote } from "./JsonFileDrop";

/**
 * Where an owner gives the page their recovery key: drop the `controlclaw-recovery-key-….txt` file,
 * choose it, or paste the `ccrk1 …` string. The file is read in the page and only the key goes into
 * the paste box, so every caller reads that box either way. Nothing here is sent or kept.
 *
 * Used by a locked disk (`DiskEncryptionPanel`) and by the code dialog when no channel could deliver
 * a code (`ConfirmCodeDialog`, T-99). `testId` prefixes the drop zone's ids.
 */
export function RecoveryKeyInput({
  id,
  value,
  onChange,
  note,
  onNote,
  testId,
  afterRead,
  placeholder = "Or paste the recovery key you saved when you turned on backups",
  disabled = false,
}: {
  id: string;
  value: string;
  onChange: (key: string) => void;
  note: JsonFileNote | null;
  onNote: (note: JsonFileNote | null) => void;
  testId: string;
  /** What to do next, said once the key has been read from a file ("Now press Open this disk."). */
  afterRead: string;
  placeholder?: string;
  disabled?: boolean;
}) {
  const readKeyFile = async (file: File | null | undefined) => {
    if (!file) return;
    const text = await readFileText(file);
    if (text === null) {
      onNote({ tone: "bad", text: UNREADABLE_FILE });
      return;
    }
    // Loaded on use: the envelope package pulls in libsodium, and a page that never reads a key
    // should not pay for it.
    const { NO_KEY_IN_FILE, recoveryKeyFromFile } = await import("../lib/recovery-key-file");
    const found = recoveryKeyFromFile(text);
    if (found === null) {
      onChange("");
      onNote({ tone: "bad", text: `${file.name}: ${NO_KEY_IN_FILE}` });
      return;
    }
    onChange(found);
    onNote({ tone: "ok", text: `Read the key from ${file.name}. ${afterRead}` });
  };

  return (
    <>
      <JsonFileDrop
        testId={testId}
        title="Drop your recovery key file here"
        hint="The controlclaw-recovery-key-….txt you downloaded. Your browser reads it here. It isn’t uploaded."
        accept=".txt,text/plain"
        icon={FileKey}
        note={note}
        onFile={(file) => void (disabled ? undefined : readKeyFile(file))}
      />
      <Textarea
        id={id}
        value={value}
        onChange={(e) => {
          onNote(null);
          onChange(e.target.value);
        }}
        placeholder={placeholder}
        rows={2}
        className="font-mono text-[12px]"
        spellCheck={false}
        autoComplete="off"
        disabled={disabled}
        data-testid={`${testId}-paste`}
      />
    </>
  );
}
