/**
 * Which tab a URL fragment opens on a tabbed console page. The pages that grew tabs in Console v3
 * (Firewall, Brain, Team chat, an agent) had sections that other pages, emails and docs link to
 * by id; those links keep working through the page's anchor map.
 */

/** Section id → the tab that holds it. */
export type TabAnchors = Record<string, string>;

export function tabForHash(hash: string, valid: readonly string[], anchors: TabAnchors, fallback: string): string {
  const h = hash.replace(/^#/, "");
  if (valid.includes(h)) return h;
  const viaAnchor = Object.hasOwn(anchors, h) ? anchors[h] : undefined;
  if (viaAnchor && valid.includes(viaAnchor)) return viaAnchor;
  return fallback;
}

/** An agent's page: sections linked to by id from elsewhere (the cards' "Disk locked" pill, older links), and the tab that holds each. */
export const AGENT_TAB_ANCHORS: TabAnchors = { disk: "home", software: "home", "shell-access": "support" };

/**
 * The Firewall page's old section links (docs, emails, the health check's fixes). Its tabs are
 * Overview, Settings and Confirmation codes (docs/plans/console-v3.md, unit 1).
 */
export const FIREWALL_TAB_ANCHORS: TabAnchors = {
  "ai-review": "settings",
  "agent-settings": "settings",
  "automatic-updates": "settings",
  doctor: "settings",
  disk: "settings",
  "code-recipients": "codes",
};
