/**
 * A provider sends the person back to `/oauth/callback?code=…&state=…`. The page that hands this to
 * the firewall renders only for a signed-in admin, so with a session that ran out the code would
 * sit in the address bar and the history meanwhile. main.tsx calls `captureOauthParams` before
 * anything renders: the query is kept here and taken out of the address at once.
 */
let saved: URLSearchParams | null = null;

export function captureOauthParams(): void {
  if (window.location.pathname !== "/oauth/callback" || !window.location.search) return;
  saved = new URLSearchParams(window.location.search);
  window.history.replaceState(window.history.state, "", window.location.pathname);
}

/** What the provider sent back (empty when this page was opened another way). */
export function oauthParams(): URLSearchParams {
  return saved ?? new URLSearchParams();
}
