import { useEffect, useState } from "react";
import { CheckCircle2, XCircle } from "lucide-react";
import { PageHead } from "@controlclaw/console-ui/kit/PageHead";
import { Card, EmptyState } from "@controlclaw/console-ui/kit/console-ui";
import { AppLink } from "@controlclaw/console-ui/lib/link";
import { FwApiError, fw } from "../api/client";
import { refusalText } from "../api/changes";
import { announceOauth } from "../api/oauth";
import { oauthParams } from "../oauth-params";

type Outcome = { state: "working" } | { state: "done"; summary: string | null } | { state: "failed"; message: string };

/** One post per sign-in, even when React runs the effect twice. */
const posted = new Map<string, Promise<Outcome>>();

async function finish(state: string, code: string | null, error: string | null): Promise<Outcome> {
  try {
    const ans = await fw.post("/api/oauth/callback", { body: { state, ...(code ? { code } : {}), ...(error ? { error } : {}) } });
    const data = (ans.data ?? {}) as { changeId?: unknown; summary?: unknown };
    const changeId = typeof data.changeId === "string" ? data.changeId : null;
    if (!ans.ok) {
      announceOauth({ changeId, error: ans.message || "The sign-in did not finish" });
      return { state: "failed", message: ans.message || "The sign-in did not finish" };
    }
    announceOauth({ changeId, error: null });
    return { state: "done", summary: typeof data.summary === "string" ? data.summary : null };
  } catch (e) {
    // A refused sign-in is a 409 that still names its change: the first tab is told why.
    const data = e instanceof FwApiError ? ((e.body as { data?: { changeId?: unknown } } | null)?.data ?? {}) : {};
    const message = refusalText(e);
    announceOauth({ changeId: typeof data.changeId === "string" ? data.changeId : null, error: message });
    return { state: "failed", message };
  }
}

/**
 * Where a provider sends the person back after an OAuth sign-in (the address registered as the
 * redirect URI). It hands the provider's answer to the firewall, takes it out of the address bar,
 * tells the tab that started the sign-in, and says how it went.
 */
export function OauthCallbackPage() {
  const [outcome, setOutcome] = useState<Outcome>({ state: "working" });
  // Kept by main.tsx before anything rendered, and already out of the address bar.
  const [q] = useState(oauthParams);

  useEffect(() => {
    const state = q.get("state");
    if (!state) {
      setOutcome({ state: "failed", message: "This page opens at the end of a sign-in, with the provider's answer. There is none here." });
      return;
    }
    let p = posted.get(state);
    if (!p) {
      p = finish(state, q.get("code"), q.get("error_description") ?? q.get("error"));
      posted.set(state, p);
    }
    void p.then(setOutcome);
  }, [q]);

  return (
    <>
      <PageHead title="Signing in" />
      <Card data-testid="oauth-callback">
        {outcome.state === "working" ? (
          <div className="px-4 py-10 text-center text-[13.5px] text-ink-2">Finishing the sign-in…</div>
        ) : outcome.state === "done" ? (
          <EmptyState icon={CheckCircle2} title="Signed in" action={<AppLink href="/integrations" className="font-medium text-brand hover:underline">Back to Integrations</AppLink>}>
            {outcome.summary ? `${outcome.summary}. ` : ""}You can close this tab.
          </EmptyState>
        ) : (
          <EmptyState icon={XCircle} title="The sign-in did not finish" action={<AppLink href="/integrations" className="font-medium text-brand hover:underline">Back to Integrations</AppLink>}>
            {outcome.message}
          </EmptyState>
        )}
      </Card>
    </>
  );
}
