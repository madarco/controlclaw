/**
 * `controlclaw open` hands the first-run setup token in the link's fragment (`#setup=<token>`): a
 * browser never sends the fragment, so it is in no request and no server log. main.tsx calls
 * `captureSetupToken` before anything renders: the token is kept here and taken out of the address
 * bar and the history at once, and the setup form starts with it filled in.
 */
let saved = "";

/** The token in a fragment such as `#setup=abc`, or "" when there is none. */
export function setupTokenFrom(hash: string): string {
  const v = new URLSearchParams(hash.replace(/^#/, "")).get("setup") ?? "";
  return /^[0-9A-Za-z_-]{1,256}$/.test(v) ? v : "";
}

const listeners = new Set<(token: string) => void>();

/**
 * Takes the token out of the address. Also on `hashchange`: the link pasted into a tab that has the
 * panel open already changes only the fragment, and the page does not load again.
 */
export function captureSetupToken(): void {
  if (!window.location.hash) return;
  const token = setupTokenFrom(window.location.hash);
  if (!token) return;
  saved = token;
  window.history.replaceState(window.history.state, "", window.location.pathname + window.location.search);
  for (const l of listeners) l(token);
}

/** Called with a token that arrives after the page loaded; returns the unsubscribe. */
export function onSetupToken(l: (token: string) => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

/** The token the link carried, or "" (the person pastes it). */
export function setupToken(): string {
  return saved;
}
