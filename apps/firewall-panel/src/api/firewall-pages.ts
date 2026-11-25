// Twin of rust/bins/mitm-agent/src/core/local_intent.rs (`PAGES`): change both together.
// firewall-pages.test.ts checks that the names match.

/** The firewall's own pages the panel can open: `/open/<page>` asks the firewall for a link. */
export const FIREWALL_PAGES = ["firewall-logs", "logins", "content-rules"] as const;
export type FirewallPageName = (typeof FIREWALL_PAGES)[number];

/** The page an `/open/<page>` path names, or null for any other path, a bad escape among them. */
export function firewallPageFromPath(pathname: string): FirewallPageName | null {
  let name: string;
  try {
    name = decodeURIComponent(pathname.replace(/^\/open\//, "").replace(/\/$/, ""));
  } catch {
    return null;
  }
  return (FIREWALL_PAGES as readonly string[]).includes(name) ? (name as FirewallPageName) : null;
}
