import { z } from "zod";

export const codeTapInputSchema = z.object({ changeId: z.string().min(1).max(64) });

/**
 * One change's Telegram buttons, as the code dialog sees them (docs/plans/channel-approval-buttons.md).
 *
 * - `open`: show `number`; the person taps the button with it.
 * - `approved`: the right number was tapped; `code` is the change's code for the dialog to send.
 * - `refused`: a wrong number was tapped; the buttons are off and the code has to be typed.
 * - `cancelled`: Cancel was tapped; the change is gone.
 */
export type CodeTapView = {
  number: string;
  state: "open" | "approved" | "refused" | "cancelled";
  code: string | null;
};
