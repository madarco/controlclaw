import { createFwApi, FwApiError } from "@controlclaw/fw-api";

/** Calls that answer 401 for a wrong token or password, not for an ended session. */
const SIGN_IN = ["/api/login", "/api/setup", "/api/session"];

let onSignedOut: () => void = () => {};

/** Called when the firewall answers 401 to a signed-in call: the session ended or was ended. */
export function watchSignedOut(f: () => void): void {
  onSignedOut = f;
}

const watched: typeof fetch = async (input, init) => {
  const res = await fetch(input, init);
  if (res.status === 401 && !SIGN_IN.some((p) => String(input).endsWith(p))) onSignedOut();
  return res;
};

/** The firewall's own API, on the page's origin (the firewall serves both). */
export const fw = createFwApi({ fetch: watched });

/** What a person reads when a call fails. */
export function errorText(e: unknown): string {
  if (e instanceof FwApiError) return e.message;
  if (e instanceof TypeError) return "The firewall did not answer. Check that it is running.";
  return e instanceof Error ? e.message : "Something went wrong";
}

export { FwApiError };
