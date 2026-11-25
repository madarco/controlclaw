import { useEffect, useState } from "react";
import { XCircle } from "lucide-react";
import { PageHead } from "@controlclaw/console-ui/kit/PageHead";
import { Card, EmptyState } from "@controlclaw/console-ui/kit/console-ui";
import { AppLink } from "@controlclaw/console-ui/lib/link";
import { refusalText } from "../api/changes";
import { openFirewallPage } from "../api/accounts";
import { firewallPageFromPath, type FirewallPageName } from "../api/firewall-pages";
import { checkedUrl } from "../api/oauth";

const TITLES: Record<FirewallPageName, string> = { "firewall-logs": "Logs", logins: "Website logins", "content-rules": "Content rules" };

/** One link per visit, even when React runs the effect twice. */
const asked = new Map<string, Promise<string>>();

/**
 * `/open/<page>`: where the firewall's own pages link to each other on a standalone firewall (their
 * sidebar, rust `core/fw_shell.rs`). Each of those pages needs its own one-time link, which only the
 * signed-in admin can ask for, so the sidebar comes here: the panel asks the firewall for the link
 * and goes on to it in the same tab.
 */
export function OpenFirewallPage() {
  const page = firewallPageFromPath(window.location.pathname);
  const [error, setError] = useState<string | null>(page ? null : "The firewall has no such page.");

  useEffect(() => {
    // The router can reuse this for another /open/<page>: start each one clean.
    setError(page ? null : "The firewall has no such page.");
    if (!page) return;
    let p = asked.get(page);
    if (!p) {
      p = openFirewallPage(page);
      asked.set(page, p);
    }
    p.then(
      (url) => {
        asked.delete(page);
        const safe = checkedUrl(url);
        if (safe) window.location.replace(safe);
        else setError("The firewall answered with an address the panel does not open.");
      },
      (e: unknown) => {
        asked.delete(page);
        setError(refusalText(e));
      },
    );
  }, [page]);

  return (
    <>
      <PageHead title={page ? TITLES[page] : "Not found"} />
      <Card data-testid="open-firewall-page">
        {error ? (
          <EmptyState icon={XCircle} title="This page did not open" action={<AppLink href="/" className="font-medium text-brand hover:underline">Back to Overview</AppLink>}>
            {error}
          </EmptyState>
        ) : (
          <div role="status" className="px-4 py-10 text-center text-[13.5px] text-ink-2">
            Opening the firewall’s {page ? TITLES[page] : ""} page…
          </div>
        )}
      </Card>
    </>
  );
}
