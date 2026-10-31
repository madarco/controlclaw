import { z } from "zod";

/** What `sentVia` says when the firewall sealed the answer to the recovery key instead of sending a code (T-99). */
export const RECOVERY_SENT_VIA = "recovery-key";

/** What the code dialog says when the firewall refused an answer; there is no phone message to check. */
export const WRONG_RECOVERY_ANSWER = "Your firewall didn’t accept that answer. Check you typed the one the command printed, or open it with your key again.";

export const recoveryChallengeInputSchema = z.object({ changeId: z.string().min(1).max(64) });

export type RecoveryChallengeView = {
  /** base64 sealed box; only the organization's recovery key opens it. */
  challenge: string;
  /** Why no channel could take the code, in the firewall's words. */
  deliveryError: string | null;
  expiresAt: string | null;
};
