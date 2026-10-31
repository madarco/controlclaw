"use client";

import { toast } from "sonner";

/**
 * Open one of the box's own pages in a new tab, through a one-shot link the control plane mints.
 *
 * The tab has to be opened inside the click, before the link exists, or a popup blocker eats it;
 * the link then lands in it. It is blanked and cut loose from this page first (`opener = null`), so
 * the box's page cannot reach back into the console. Returns false when it did not open.
 *
 * On failure the reason is a toast, and `onError` gets it too, for a page that shows it in place: a
 * toast raised while the blank tab still has focus is easy to miss.
 */
export async function openInNewTab(mint: () => Promise<{ url: string }>, failure: string, onError?: (message: string) => void): Promise<boolean> {
  const tab = window.open("", "_blank");
  if (tab) tab.opener = null;
  try {
    const { url } = await mint();
    if (tab) tab.location.href = url;
    else window.open(url, "_blank", "noopener");
    return true;
  } catch (error) {
    tab?.close();
    console.error(failure, error);
    const message = error instanceof Error && error.message ? error.message : failure;
    toast.error(message);
    onError?.(message);
    return false;
  }
}
