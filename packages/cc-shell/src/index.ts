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
 * `rust/bins/vm-agent/src/boxside/shell.rs` and `rust/bins/mitm-agent/src/core/fw_shell.rs`.
 */

export const ICONS = {
  meetings: '<path d="m16 13 5.223 3.482a.5.5 0 0 0 .777-.416V7.87a.5.5 0 0 0-.752-.432L16 10.5"/><rect x="2" y="6" width="14" height="12" rx="2"/>',
  phone:
    '<path d="M13.832 16.568a1 1 0 0 0 1.213-.303l.355-.465A2 2 0 0 1 17 15h3a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2A18 18 0 0 1 2 4a2 2 0 0 1 2-2h3a2 2 0 0 1 2 2v3a2 2 0 0 1-.8 1.6l-.468.351a1 1 0 0 0-.292 1.233 14 14 0 0 0 6.392 6.384"/>',
  files: '<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>',
  logs: '<path d="M15 12h-5"/><path d="M15 8h-5"/><path d="M19 17V5a2 2 0 0 0-2-2H4"/><path d="M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3"/>',
  whatsapp: '<path d="M7.9 20A9 9 0 1 0 4 16.1L2 22Z"/>',
  browser: '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
  screen: '<rect width="20" height="14" x="2" y="3" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/>',
  external: '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
  shieldCheck:
    '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>',
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

/** The card at the top of the sidebar: the box these pages are on. */
export interface ShellCard {
  mark: ShellIcon;
  name: string;
  sub: string;
  /** "Running · OpenClaw 2026.11.5", when the box knows it cheaply; no line without it. */
  status?: string | null;
}

export interface ShellNavItem {
  label: string;
  /** Absent: the entry is shown but is not a link (there is nowhere it could go). */
  href?: string;
  icon: ShellIcon;
  /** The page being shown. */
  active?: boolean;
  /** A short red note beside the label ("live"). */
  badge?: string | null;
  /** The link leaves this box (Doctor): an external-link mark. */
  external?: boolean;
  /** A label printed above the first entry of each group ("Waiting for you", "Help"). */
  group?: string | null;
}

const BODY = `<body class="bg-bg-2 font-sans text-ink antialiased">`;

export function shellHead(title: string, assets: ShellAssets, extraHead = ""): string {
  return (
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">` +
    `<title>${escapeHtml(title)}</title><script src="${escapeHtml(assets.js)}"></script><link rel="stylesheet" href="${escapeHtml(assets.css)}">${extraHead}</head>`
  );
}

function backLink(consoleUrl: string | null): string {
  return consoleUrl
    ? `<a href="${escapeHtml(consoleUrl)}" class="inline-flex h-9 shrink-0 items-center gap-1.5 rounded-lg border border-line bg-surface px-3 text-[13px] font-medium text-ink shadow-sm hover:bg-bg">` +
        `${icon("back", "h-4 w-4 text-ink-2")}<span class="hidden sm:inline">Back to console</span><span class="sm:hidden">Console</span></a>`
    : "";
}

/** The header of the pages before sign-in: the box's name and address, and Back to console. */
export function shellHeader(h: ShellHeader): string {
  return (
    `<header class="flex h-full min-w-0 items-center gap-3 px-4 md:px-5">` +
    `<span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-brand-soft text-brand">${icon(h.mark, "h-[18px] w-[18px]")}</span>` +
    `<div class="min-w-0 leading-tight"><div class="truncate text-[14px] font-semibold text-ink">${escapeHtml(h.name)}</div>` +
    `<div class="truncate font-mono text-[11.5px] text-ink-2">${escapeHtml(h.sub)}</div></div>` +
    `<span class="flex-1"></span>` +
    backLink(h.consoleUrl) +
    `</header>`
  );
}

/**
 * The header of the signed-in pages: ControlClaw, where you are (box › page), Back to console. On a
 * phone the box's name replaces the brand, since the sidebar card is not shown there.
 */
export function shellBrandHeader(h: ShellHeader, page: string): string {
  return (
    `<header class="flex h-full min-w-0 items-center gap-3 px-4 md:px-5">` +
    `<span class="flex min-w-0 items-center gap-[9px] md:w-[196px] md:shrink-0">${brandMark(26)}` +
    `<span class="hidden text-[15px] font-semibold tracking-[-0.01em] text-ink md:inline">ControlClaw</span>` +
    `<span class="truncate text-[14px] font-semibold text-ink md:hidden">${escapeHtml(h.name)}</span></span>` +
    `<nav aria-label="Breadcrumb" class="hidden min-w-0 items-center gap-2 text-[13.5px] text-ink-2 md:flex"><span class="truncate">${escapeHtml(h.name)}</span><span aria-hidden="true" class="text-muted-foreground">›</span>` +
    `<span aria-current="page" class="truncate font-medium text-ink">${escapeHtml(page)}</span></nav>` +
    `<span class="flex-1"></span>` +
    backLink(h.consoleUrl) +
    `</header>`
  );
}

function shellCard(c: ShellCard): string {
  const status = c.status
    ? `<div class="flex items-center gap-1.5 px-[10px] pt-2 text-[11.5px] text-ink-2"><span aria-hidden="true" class="h-[7px] w-[7px] shrink-0 rounded-full bg-allow"></span><span class="truncate">${escapeHtml(c.status)}</span></div>`
    : "";
  return (
    `<div class="hidden pb-3 md:block"><div class="flex min-w-0 items-center gap-2.5 rounded-xl border border-line bg-surface px-[10px] py-2.5 shadow-sm">` +
    `<span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-brand text-white">${icon(c.mark, "h-[17px] w-[17px]")}</span>` +
    `<div class="min-w-0 leading-tight"><div class="truncate text-[13.5px] font-semibold text-ink">${escapeHtml(c.name)}</div>` +
    `<div class="truncate font-mono text-[11px] text-ink-2">${escapeHtml(c.sub)}</div></div></div>${status}</div>`
  );
}

function navLink(item: ShellNavItem): string {
  const tag = item.href === undefined ? "span" : "a";
  const badge = item.badge
    ? `<span class="ml-auto inline-flex shrink-0 items-center gap-1 pl-1 text-[11px] font-medium text-block-fg"><span aria-hidden="true" class="h-1.5 w-1.5 rounded-full bg-block"></span>${escapeHtml(item.badge)}</span>`
    : "";
  const ext = item.external ? `${icon("external", "ml-auto hidden h-3.5 w-3.5 shrink-0 text-muted-foreground md:block")}<span class="sr-only"> (opens through the console)</span>` : "";
  return (
    `<${tag}${item.href === undefined ? "" : ` href="${escapeHtml(item.href)}"`}${item.active ? ' aria-current="page"' : ""} class="flex shrink-0 items-center gap-[11px] rounded-lg px-[10px] py-2 text-[13.5px] focus-visible:outline-2 focus-visible:outline-brand ${item.active ? "bg-surface font-semibold text-ink shadow-sm" : "text-ink-2 hover:bg-bg"}">` +
    `${icon(item.icon, `h-4 w-4 shrink-0 ${item.active ? "text-brand" : "text-ink-2"}`)}<span>${escapeHtml(item.label)}</span>${badge}${ext}</${tag}>`
  );
}

/** The note under the sidebar: where these pages come from. */
export function shellFoot(title: string, text: string): string {
  return (
    `<div class="mt-auto hidden pt-4 md:block"><div class="rounded-xl border border-line bg-surface p-3 shadow-sm">` +
    `<div class="flex items-center gap-1.5 text-[12.5px] font-semibold text-ink">${icon("shieldCheck", "h-3.5 w-3.5 shrink-0 text-brand")}${escapeHtml(title)}</div>` +
    `<p class="mt-1 text-[11.5px] leading-[1.45] text-ink-2">${escapeHtml(text)}</p></div></div>`
  );
}

/**
 * A page with the header and the sidebar. `body` goes in the main panel, as the console puts a
 * page in its own. On a phone the sidebar is a row of tabs under the header, which scrolls sideways
 * (a fade at the right edge says there is more).
 */
export function shellFrame(opts: {
  title: string;
  assets: ShellAssets;
  header: ShellHeader;
  /** The current page's name, for the breadcrumb. */
  page: string;
  card: ShellCard;
  navLabel: string;
  nav: ShellNavItem[];
  /** `shellFoot(...)`, or nothing. */
  foot?: string;
  body: string;
  head?: string;
  tail?: string;
}): string {
  let group: string | null | undefined;
  const links = opts.nav
    .map((item) => {
      const label = item.group && item.group !== group ? `<div class="hidden px-[10px] pt-4 pb-1 text-[11px] font-semibold tracking-[0.06em] text-muted-foreground uppercase md:block">${escapeHtml(item.group)}</div>` : "";
      group = item.group;
      return label + navLink(item);
    })
    .join("");
  return (
    shellHead(opts.title, opts.assets, opts.head ?? "") +
    BODY +
    `<div class="grid min-h-dvh grid-cols-[minmax(0,1fr)] grid-rows-[58px_auto_1fr] md:h-dvh md:grid-cols-[232px_minmax(0,1fr)] md:grid-rows-[58px_1fr] md:overflow-hidden">` +
    `<div class="min-w-0 md:col-span-2">${shellBrandHeader(opts.header, opts.page)}</div>` +
    `<div class="relative min-w-0 md:flex md:min-h-0 md:flex-col md:overflow-y-auto md:px-3 md:pb-3">${shellCard(opts.card)}` +
    `<nav aria-label="${escapeHtml(opts.navLabel)}" class="relative flex min-w-0 gap-0.5 overflow-x-auto px-3 pr-8 pb-2 md:flex-col md:overflow-x-visible md:px-0 md:pr-0 md:pb-0">${links}</nav>` +
    `<span aria-hidden="true" class="pointer-events-none absolute inset-y-0 right-0 w-10 bg-gradient-to-l from-bg-2 to-transparent md:hidden"></span>` +
    `${opts.foot ?? ""}</div>` +
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
