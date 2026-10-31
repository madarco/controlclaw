import { formatRecoveryKey, parseRecoveryKey } from "@controlclaw/backup-envelope";

/**
 * The recovery key out of a dropped file, for the locked-disk card.
 *
 * The file is the one the "Download" button saves (`recoveryKeyFileText` in
 * `app/(backups)/lib/recovery-key.ts`): a few lines of explanation, then `Key: ccrk1 …`, a
 * fingerprint and a date. `parseRecoveryKey` already finds the `ccrk1 …` part anywhere in a text,
 * so this only re-formats what it found, so the paste box shows the key the way the owner saved it
 * and not the whole file. The unlock then parses that box as it would a paste.
 *
 * Null when the text holds nothing that looks like a key. Runs in the page; nothing here is sent or
 * kept.
 */
export function recoveryKeyFromFile(text: string): string | null {
  try {
    return formatRecoveryKey(parseRecoveryKey(text));
  } catch {
    return null;
  }
}

export const NO_KEY_IN_FILE =
  "There is no recovery key in that file. The one you downloaded is called controlclaw-recovery-key-….txt and has a line starting with ccrk1.";
