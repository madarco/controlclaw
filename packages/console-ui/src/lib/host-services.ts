/**
 * Which service a host belongs to, for the round icons in front of a request (Live requests,
 * "Talking to", the Overview card, top sites). One map so every page draws Gmail the same way.
 * A host not in it gets a neutral icon with its first letter.
 */

export type HostService = {
  /** "Gmail". */
  name: string;
  /** One or two characters drawn on the icon. */
  mark: string;
  /** The icon's background; the mark is white on it. */
  color: string;
};

/** Suffix match on the host, longest first, so `mail.google.com` wins over `google.com`. */
const SERVICES = ([
  ["gmail.googleapis.com", { name: "Gmail", mark: "M", color: "#d93025" }],
  ["mail.google.com", { name: "Gmail", mark: "M", color: "#d93025" }],
  ["calendar.google.com", { name: "Calendar", mark: "31", color: "#1967d2" }],
  ["meet.google.com", { name: "Google Meet", mark: "▶", color: "#00897b" }],
  ["docs.google.com", { name: "Google Docs", mark: "D", color: "#4285f4" }],
  ["drive.google.com", { name: "Google Drive", mark: "▲", color: "#188038" }],
  ["googleapis.com", { name: "Google", mark: "G", color: "#1a73e8" }],
  ["google.com", { name: "Google", mark: "G", color: "#1a73e8" }],
  ["api.telegram.org", { name: "Telegram", mark: "✈", color: "#37aee2" }],
  ["telegram.org", { name: "Telegram", mark: "✈", color: "#37aee2" }],
  ["slack.com", { name: "Slack", mark: "#", color: "#4a154b" }],
  ["whatsapp.net", { name: "WhatsApp", mark: "W", color: "#25d366" }],
  ["whatsapp.com", { name: "WhatsApp", mark: "W", color: "#25d366" }],
  ["github.com", { name: "GitHub", mark: "GH", color: "#24292f" }],
  ["githubusercontent.com", { name: "GitHub", mark: "GH", color: "#24292f" }],
  ["agentmail.to", { name: "AgentMail", mark: "@", color: "#6d28d9" }],
  ["openai.com", { name: "OpenAI", mark: "AI", color: "#0d1117" }],
  ["chatgpt.com", { name: "ChatGPT", mark: "AI", color: "#0d1117" }],
  ["anthropic.com", { name: "Anthropic", mark: "AI", color: "#c96442" }],
  ["ai-gateway.vercel.sh", { name: "AI model", mark: "AI", color: "#0d1117" }],
  ["openrouter.ai", { name: "OpenRouter", mark: "AI", color: "#0d1117" }],
  ["skyscanner.net", { name: "Skyscanner", mark: "S", color: "#0770e3" }],
  ["twilio.com", { name: "Phone", mark: "☎", color: "#15803d" }],
] as Array<[suffix: string, service: HostService]>).sort((a, b) => b[0].length - a[0].length);

export function serviceForHost(host: string): HostService | null {
  const h = host.trim().toLowerCase().replace(/\.$/, "").replace(/:\d+$/, "");
  for (const [suffix, service] of SERVICES) {
    if (h === suffix || h.endsWith(`.${suffix}`)) return service;
  }
  return null;
}

/**
 * A stable hue for a name, so the same person or agent has the same avatar colour on every page
 * without anyone picking one.
 */
export function hueFor(name: string): number {
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.codePointAt(0)!) % 360;
  return h;
}

/** "Anna Rossi" → "AR", "marcobot15" → "M", "" → "?". */
export function initialsOf(name: string): string {
  const words = name.trim().split(/[\s._-]+/).filter(Boolean);
  if (words.length === 0) return "?";
  if (words.length === 1) return [...words[0]!][0]!.toUpperCase();
  return ([...words[0]!][0]! + [...words[words.length - 1]!][0]!).toUpperCase();
}
