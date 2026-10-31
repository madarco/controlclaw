/**
 * The look every page a box serves under `/__cc/` shares, on the agent and on the firewall
 * (apps/saas/docs/features/agent-pages.md): the console's header and sidebar, so the page reads as
 * part of ControlClaw. Strings only, no dependencies: each box bundles this into its one file.
 *
 * The markup uses the console's own Tailwind classes. The box stylesheets are built from the
 * console's theme by `apps/saas/scripts/build-box-files.mjs` (agent) and
 * `apps/firewall-panel/scripts/build-fw-files.mjs` (firewall), which both scan this file, so the tokens, the Inter font and
 * light/dark come from one place. A class used here that neither build scans has no CSS.
 *
 * Each box says where its stylesheet and theme script are (`ShellAssets`) and which pages it has:
 * `packages/vm-agent/src/routes/cc-shell.ts` and `packages/mitm-agent/src/fw-shell.ts`.
 */

export const ICONS = {
  meetings: '<path d="m16 13 5.223 3.482a.5.5 0 0 0 .777-.416V7.87a.5.5 0 0 0-.752-.432L16 10.5"/><rect x="2" y="6" width="14" height="12" rx="2"/>',
  phone:
    '<path d="M13.832 16.568a1 1 0 0 0 1.213-.303l.355-.465A2 2 0 0 1 17 15h3a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2A18 18 0 0 1 2 4a2 2 0 0 1 2-2h3a2 2 0 0 1 2 2v3a2 2 0 0 1-.8 1.6l-.468.351a1 1 0 0 0-.292 1.233 14 14 0 0 0 6.392 6.384"/>',
  files: '<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>',
  logs: '<path d="M15 12h-5"/><path d="M15 8h-5"/><path d="M19 17V5a2 2 0 0 0-2-2H4"/><path d="M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3"/>',
  whatsapp: '<path d="M7.9 20A9 9 0 1 0 4 16.1L2 22Z"/>',
  browser: '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
  doctor: '<path d="M11 2v2"/><path d="M5 2v2"/><path d="M5 3H4a2 2 0 0 0-2 2v4a6 6 0 0 0 12 0V5a2 2 0 0 0-2-2h-1"/><path d="M8 15a6 6 0 0 0 12 0v-3"/><circle cx="20" cy="10" r="2"/>',
  logins:
    '<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/>',
  content: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><path d="m14.5 7.5-5 5"/><path d="m9.5 7.5 5 5"/>',
  back: '<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>',
  mark: '<path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/>',
  shield:
    '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
} as const;

export type ShellIcon = keyof typeof ICONS;

export function icon(name: ShellIcon, cls: string): string {
  return `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name]}</svg>`;
}

/** The ControlClaw mark, as the console's header draws it (apps/saas `brand-mark.tsx`). */
export function brandMark(size: number): string {
  const claw = (d: string) => `<path d="${d}" stroke="white" stroke-width="2.4" stroke-linecap="round" fill="none" opacity="0.95"/>`;
  return (
    `<svg width="${size}" height="${size}" viewBox="0 0 48 48" fill="none" aria-hidden="true" class="shrink-0">` +
    `<defs><linearGradient id="cc-brand-mark" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="oklch(0.7 0.17 265)"/><stop offset="1" stop-color="oklch(0.34 0.17 265)"/></linearGradient></defs>` +
    `<path d="M24 3 L42 10 L42 24 C42 34 34 42 24 45 C14 42 6 34 6 24 L6 10 Z" fill="url(#cc-brand-mark)"/>` +
    claw("M15 18 C18 23 20 28 19 34") +
    claw("M22 15 C25 21 27 28 25 35") +
    claw("M29 16 C32 22 33 28 31 34") +
    `</svg>`
  );
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

/** `<` inside inline JSON would let a value close the script element; escape it. */
export function inlineJson(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

/** Light or dark from the system, set before the first paint; the console's tokens key off `.dark`. */
export const SHELL_JS = `(function(){var m=window.matchMedia("(prefers-color-scheme: dark)");var a=function(){document.documentElement.classList.toggle("dark",m.matches)};a();m.addEventListener("change",a)})();`;

/** Where this box serves the stylesheet and the theme script (`SHELL_JS`). Same origin, always. */
export interface ShellAssets {
  css: string;
  js: string;
}

/** The left of the header: whose pages these are. */
export interface ShellHeader {
  mark: ShellIcon;
  name: string;
  /** The box's address, under the name. */
  sub: string;
  /** Where "Back to console" goes; no button without it. */
  consoleUrl: string | null;
}

export interface ShellNavItem {
  label: string;
  /** Absent: the entry is shown but is not a link (there is nowhere it could go). */
  href?: string;
  icon: ShellIcon;
  /** The page being shown. */
  active?: boolean;
}

export function shellHead(title: string, assets: ShellAssets, extraHead = ""): string {
  return (
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">` +
    `<title>${escapeHtml(title)}</title><script src="${escapeHtml(assets.js)}"></script><link rel="stylesheet" href="${escapeHtml(assets.css)}">${extraHead}</head>`
  );
}

export function shellHeader(h: ShellHeader): string {
  const back = h.consoleUrl
    ? `<a href="${escapeHtml(h.consoleUrl)}" class="inline-flex h-9 shrink-0 items-center gap-1.5 rounded-lg border border-line bg-surface px-3 text-[13px] font-medium text-ink shadow-sm hover:bg-bg">` +
      `${icon("back", "h-4 w-4 text-ink-2")}<span class="hidden sm:inline">Back to console</span><span class="sm:hidden">Console</span></a>`
    : "";
  return (
    `<header class="flex h-full min-w-0 items-center gap-3 px-4 md:px-5">` +
    `<span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-brand-soft text-brand">${icon(h.mark, "h-[18px] w-[18px]")}</span>` +
    `<div class="min-w-0 leading-tight"><div class="truncate text-[14px] font-semibold text-ink">${escapeHtml(h.name)}</div>` +
    `<div class="truncate font-mono text-[11.5px] text-ink-2">${escapeHtml(h.sub)}</div></div>` +
    `<span class="flex-1"></span>` +
    back +
    `</header>`
  );
}

const BODY = `<body class="bg-bg-2 font-sans text-ink antialiased">`;

/**
 * A page with the header and the sidebar. `body` goes in the main panel, as the console puts a
 * page in its own. On a phone the sidebar is a row of tabs under the header.
 */
export function shellFrame(opts: { title: string; assets: ShellAssets; header: ShellHeader; navLabel: string; nav: ShellNavItem[]; body: string; head?: string; tail?: string }): string {
  const links = opts.nav
    .map((item) => {
      const tag = item.href === undefined ? "span" : "a";
      return (
        `<${tag}${item.href === undefined ? "" : ` href="${escapeHtml(item.href)}"`}${item.active ? ' aria-current="page"' : ""} class="flex shrink-0 items-center gap-[11px] rounded-lg px-[10px] py-2 text-[13.5px] ${item.active ? "bg-surface font-semibold text-ink shadow-sm" : "text-ink-2 hover:bg-bg"}">` +
        `${icon(item.icon, `h-4 w-4 shrink-0 ${item.active ? "text-brand" : "text-ink-2"}`)}<span>${escapeHtml(item.label)}</span></${tag}>`
      );
    })
    .join("");
  return (
    shellHead(opts.title, opts.assets, opts.head ?? "") +
    BODY +
    `<div class="grid min-h-dvh grid-rows-[58px_auto_1fr] md:h-dvh md:grid-cols-[220px_1fr] md:grid-rows-[58px_1fr] md:overflow-hidden">` +
    `<div class="min-w-0 md:col-span-2">${shellHeader(opts.header)}</div>` +
    `<nav aria-label="${escapeHtml(opts.navLabel)}" class="flex min-w-0 gap-0.5 overflow-x-auto px-3 pb-2 md:flex-col md:overflow-x-visible md:overflow-y-auto md:pb-4">${links}</nav>` +
    `<main class="min-w-0 border-t border-line bg-surface md:overflow-y-auto md:mr-2 md:mb-2 md:rounded-tl-2xl md:border shadow-sm">${opts.body}</main>` +
    `</div>${opts.tail ?? ""}</body></html>`
  );
}

/**
 * The header alone, over a centred card: pages that come before a session and so have no pages to
 * list. `head` and `tail` are the page's own pieces (a style element, its script).
 */
export function shellCardFrame(opts: { title: string; assets: ShellAssets; header: ShellHeader; body: string; head?: string; tail?: string }): string {
  return (
    shellHead(opts.title, opts.assets, opts.head ?? "") +
    BODY +
    `<div class="grid min-h-dvh grid-rows-[58px_1fr]">${shellHeader(opts.header)}` +
    `<div class="grid place-items-center px-4 py-8"><main class="w-full max-w-[26rem] rounded-2xl border border-line bg-surface p-6 shadow-sm sm:p-8">${opts.body}</main></div>` +
    `</div>${opts.tail ?? ""}</body></html>`
  );
}

/**
 * The ControlClaw mark over one card and nothing else: a page with a single purpose, reached from
 * a link (an agent asking for a login in a chat), usually on a phone. No header, no sidebar, no
 * way out to other pages.
 */
export function shellMinimalFrame(opts: { title: string; assets: ShellAssets; body: string; head?: string; tail?: string }): string {
  return (
    shellHead(opts.title, opts.assets, opts.head ?? "") +
    BODY +
    `<div class="mx-auto w-full max-w-[36rem] px-4 pt-6 pb-12 sm:pt-12">` +
    `<div class="mb-5 flex items-center gap-[9px]">${brandMark(26)}<span class="text-[15px] font-semibold tracking-[-0.01em] text-ink">ControlClaw</span></div>` +
    `<main class="min-w-0 rounded-2xl border border-line bg-surface p-5 shadow-sm sm:p-8">${opts.body}</main>` +
    `</div>${opts.tail ?? ""}</body></html>`
  );
}
