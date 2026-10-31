/**
 * The OAuth sign-in's last step happens in another tab (`/oauth/callback`), which posts the
 * provider's answer to the firewall and says how it went here, so the tab that started the
 * sign-in can show it done.
 */
export const OAUTH_CHANNEL = "controlclaw-panel-oauth";

export type OauthDone = { changeId: string | null; error: string | null };

export function announceOauth(done: OauthDone): void {
  try {
    const ch = new BroadcastChannel(OAUTH_CHANNEL);
    ch.postMessage(done);
    ch.close();
  } catch {
    // No BroadcastChannel: the opener finds the new connection on its next read.
  }
}

/** Listens for the callback tab; the answer stops listening (a page's effect cleanup). */
export function onOauthDone(f: (done: OauthDone) => void): () => void {
  try {
    const ch = new BroadcastChannel(OAUTH_CHANNEL);
    ch.onmessage = (e: MessageEvent<OauthDone>) => f(e.data);
    // Node (the tests) keeps running while a channel is open; a browser tab does not care.
    (ch as { unref?: () => void }).unref?.();
    return () => ch.close();
  } catch {
    // As above.
    return () => {};
  }
}

/**
 * A tab for a page whose address comes from an API call. Opened on the click itself (a tab opened
 * after an awaited call is blocked as a pop-up), then sent on with `go`; `close` when the call failed.
 * Null when the browser blocked it anyway: show the link instead.
 */
export function openTabNow(): { go: (url: string) => void; close: () => void } | null {
  const w = window.open("", "_blank");
  if (!w) return null;
  w.opener = null;
  return {
    go: (url) => {
      const safe = checkedUrl(url);
      if (!safe) {
        w.close();
        throw new Error("The firewall answered with an address the panel does not open.");
      }
      w.location.replace(safe);
    },
    close: () => w.close(),
  };
}

/**
 * An address an API answer sends the browser to (a sign-in, a firewall page): https, or this
 * panel's own origin. Anything else (`javascript:`, `data:`, plain http elsewhere) is null.
 */
export function checkedUrl(url: string): string | null {
  try {
    const u = new URL(url, window.location.origin);
    return u.protocol === "https:" || u.origin === window.location.origin ? u.href : null;
  } catch {
    return null;
  }
}

/** Where providers send the person back: this panel's own callback page. */
export function redirectUri(): string {
  return `${typeof window === "undefined" ? "http://localhost:8800" : window.location.origin}/oauth/callback`;
}
