// The parts every page the firewall draws itself shares (Content rules, AI review history, Website
// logins, Doctor chat): page head, stat tiles, cards, pills, day headings, segmented buttons, empty
// states, banners and icons, in the classes of the agent pages' `box-kit` (apps/saas
// `app/(agents)/components/box-kit`), so the two read as one product. Served by the firewall at
// `/__cc/doctor/ui/kit-<hash>.js` (`core/fw_shell.rs`); each page loads it before its own script.
// Builds DOM nodes only, never HTML strings, so a value from the firewall is always text.
"use strict";
(function () {
  const SVG = "http://www.w3.org/2000/svg";
  // lucide 0.4xx, the console's icons.
  const ICONS = {
    alert: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    xCircle: '<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>',
    check: '<path d="M20 6 9 17l-5-5"/>',
    checkCircle: '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>',
    info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>',
    chevronRight: '<path d="m9 18 6-6-6-6"/>',
    arrowLeft: '<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>',
    chevronDown: '<path d="m6 9 6 6 6-6"/>',
    external: '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
    search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
    send: '<path d="M14.536 21.686a.5.5 0 0 0 .937-.024l6.5-19a.496.496 0 0 0-.635-.635l-19 6.5a.5.5 0 0 0-.024.937l7.93 3.18a2 2 0 0 1 1.112 1.11z"/><path d="m21.854 2.147-10.94 10.939"/>',
    bot: '<path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/>',
    globe: '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
    mail: '<rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/>',
    message: '<path d="M7.9 20A9 9 0 1 0 4 16.1L2 22Z"/>',
    webhook: '<path d="M18 16.98h-5.99c-1.1 0-1.95.94-2.48 1.9A4 4 0 0 1 2 17c.01-.7.2-1.4.57-2"/><path d="m6 17 3.13-5.78c.53-.97.1-2.18-.5-3.1a4 4 0 1 1 6.89-4.06"/><path d="m12 6 3.13 5.73C15.66 12.7 16.9 13 18 13a4 4 0 0 1 0 8"/>',
    phone: '<path d="M13.832 16.568a1 1 0 0 0 1.213-.303l.355-.465A2 2 0 0 1 17 15h3a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2A18 18 0 0 1 2 4a2 2 0 0 1 2-2h3a2 2 0 0 1 2 2v3a2 2 0 0 1-.8 1.6l-.468.351a1 1 0 0 0-.292 1.233 14 14 0 0 0 6.392 6.384"/>',
    app: '<rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/>',
    sparkles: '<path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z"/>',
    terminal: '<path d="m4 17 6-6-6-6"/><path d="M12 19h8"/>',
    file: '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/>',
    trash: '<path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>',
    more: '<circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/>',
    eye: '<path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/><circle cx="12" cy="12" r="3"/>',
    eyeOff: '<path d="M10.733 5.076a10.744 10.744 0 0 1 11.205 6.575 1 1 0 0 1 0 .696 10.747 10.747 0 0 1-1.444 2.49"/><path d="M14.084 14.158a3 3 0 0 1-4.242-4.242"/><path d="M17.479 17.499a10.75 10.75 0 0 1-15.417-5.151 1 1 0 0 1 0-.696 10.75 10.75 0 0 1 4.446-5.143"/><path d="m2 2 20 20"/>',
    key: '<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/>',
    upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5"/><path d="M12 3v12"/>',
    pencil: '<path d="M12 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.375 2.625a1 1 0 0 1 3 3l-9.013 9.014a2 2 0 0 1-.853.505l-2.873.84a.5.5 0 0 1-.62-.62l.84-2.873a2 2 0 0 1 .506-.852z"/>',
    lock: '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    shield: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
    shieldCheck: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>',
    square: '<rect width="14" height="14" x="5" y="5" rx="2"/>',
    doctor: '<path d="M11 2v2"/><path d="M5 2v2"/><path d="M5 3H4a2 2 0 0 0-2 2v4a6 6 0 0 0 12 0V5a2 2 0 0 0-2-2h-1"/><path d="M8 15a6 6 0 0 0 12 0v-3"/><circle cx="20" cy="10" r="2"/>',
    review: '<path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><circle cx="12" cy="12" r="1"/><path d="M18.944 12.33a1 1 0 0 0 0-.66 7.5 7.5 0 0 0-13.888 0 1 1 0 0 0 0 .66 7.5 7.5 0 0 0 13.888 0"/>',
    content: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><path d="m14.5 7.5-5 5"/><path d="m9.5 7.5 5 5"/>',
    arrowUpRight: '<path d="M7 7h10v10"/><path d="M7 17 17 7"/>',
    arrowDownLeft: '<path d="M17 7 7 17"/><path d="M17 17H7V7"/>',
    refresh: '<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>',
    copy: '<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
    diff: '<path d="M12 3v14"/><path d="M5 10h14"/><path d="M5 21h14"/>',
  };

  const FOCUS = "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand";

  /** An element: `h("div", {class, text, onclick, "aria-label": …}, …children)`. Strings are text. */
  function h(tag, props, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
      else if (k === "dataset") Object.assign(el.dataset, v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    append(el, children);
    return el;
  }

  function append(el, children) {
    for (const c of children.flat(Infinity)) {
      if (c === null || c === undefined || c === false || c === "") continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  /** A lucide icon, hidden from screen readers. Paths are this file's constants, never data. */
  function icon(name, cls) {
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("class", cls || "h-4 w-4 shrink-0");
    const tpl = document.createElementNS(SVG, "g");
    // Constant markup from ICONS above; parsed as SVG, never page data.
    tpl.innerHTML = ICONS[name] || "";
    while (tpl.firstChild) svg.append(tpl.firstChild);
    return svg;
  }

  const PILL_TONE = {
    allow: "bg-allow-soft text-allow-fg",
    ask: "bg-ask-soft text-ask-fg",
    block: "bg-block-soft text-block-fg",
    brand: "bg-brand-soft text-brand-ink",
    muted: "bg-bg-2 text-ink-2",
  };

  /** A rounded label in a tone: allow, ask, block, brand or muted. */
  function pill(text, tone, iconName) {
    return h(
      "span",
      { class: "inline-flex h-[22px] shrink-0 items-center gap-1 rounded-full px-2.5 text-[11.5px] font-semibold whitespace-nowrap " + (PILL_TONE[tone] || PILL_TONE.muted) },
      iconName ? icon(iconName, "h-3 w-3 shrink-0") : null,
      text,
    );
  }

  /** The page's title and line, its own buttons at the end (`BoxPageHead`). */
  function pageHead(title, sub, actions) {
    return h(
      "div",
      { class: "mb-5 flex flex-wrap items-end gap-x-4 gap-y-3" },
      h(
        "div",
        { class: "min-w-0 flex-1 basis-[280px]" },
        h("h1", { class: "text-[24px] font-semibold tracking-[-0.02em] text-ink" }, title),
        sub ? h("p", { class: "mt-1 max-w-[72ch] text-[13.5px] text-pretty text-ink-2" }, sub) : null,
      ),
      actions && actions.length ? h("div", { class: "flex flex-wrap items-center gap-2" }, actions) : null,
    );
  }

  const STAT_TONE = { brand: "text-brand", allow: "text-allow-fg", ask: "text-ask-fg", block: "text-block-fg" };

  /** Stat tiles in a bordered grid, two across on a phone, four from `sm` (`StatGrid`, `StatTile`). */
  function statGrid(tiles) {
    return h(
      "div",
      {
        class:
          "mb-5 grid grid-cols-2 overflow-hidden rounded-xl border border-line bg-surface [&>*]:border-line [&>*:nth-child(2n)]:border-l [&>*:nth-child(n+3)]:border-t sm:grid-cols-4 sm:[&>*]:border-t-0 sm:[&>*]:border-l sm:[&>*:first-child]:border-l-0",
      },
      tiles.map((t) =>
        h(
          "div",
          { class: "min-w-0 p-4" },
          h("div", { class: "text-[12.5px] text-ink-2" }, t.label),
          h("div", { class: "mt-1 text-[24px] leading-tight font-semibold tracking-[-0.02em] tabular-nums " + (STAT_TONE[t.tone] || "text-ink") }, String(t.value)),
          t.sub ? h("div", { class: "mt-0.5 text-[12px] text-ink-2" }, t.sub) : null,
        ),
      ),
    );
  }

  /** A bordered card (`section`), its rows inside. */
  function card(props, ...children) {
    const p = Object.assign({}, props);
    p.class = "overflow-hidden rounded-xl border border-line bg-surface " + (p.class || "");
    return h("section", p, ...children);
  }

  /** A card's title row: the title, a count, and what goes on the right. */
  function cardHead(title, count, right, id) {
    return h(
      "div",
      { class: "flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line px-4 py-3" },
      h("h2", { class: "text-[14.5px] font-semibold text-ink", id: id || null }, title),
      count !== undefined && count !== null ? h("span", { class: "text-[12.5px] text-ink-2 tabular-nums" }, String(count)) : null,
      right ? h("div", { class: "ml-auto flex flex-wrap items-center gap-2" }, right) : null,
    );
  }

  /** The heading of one day's rows ("Today 2"), as the agent pages' `DayHeading`. */
  function dayHeading(label, count) {
    return h(
      "div",
      { class: "border-y border-line bg-bg-2 px-4 py-1.5 text-[11.5px] font-semibold tracking-[0.06em] text-ink-2 uppercase" },
      label,
      count !== undefined ? h("span", { class: "ml-2 font-medium tabular-nums" }, String(count)) : null,
    );
  }

  const DAY = 86400000;
  function startOfDay(t) {
    const d = new Date(t);
    d.setHours(0, 0, 0, 0);
    return d.getTime();
  }

  /** "Today", "Yesterday", or "Sunday 22 Nov", in the browser's own time zone. */
  function dayLabel(at, now) {
    const diff = Math.round((startOfDay(now || Date.now()) - startOfDay(at)) / DAY);
    if (diff === 0) return "Today";
    if (diff === 1) return "Yesterday";
    return new Date(at).toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "short", ...(diff > 300 ? { year: "numeric" } : {}) });
  }

  /** Rows grouped by day, in the order given. */
  function groupByDay(rows, at, now) {
    const out = [];
    for (const row of rows) {
      const key = startOfDay(at(row));
      const last = out.find((g) => g.key === key);
      if (last) last.rows.push(row);
      else out.push({ key, label: dayLabel(at(row), now), rows: [row] });
    }
    return out;
  }

  /** "HH:MM" in the browser's time zone. */
  function clock(at) {
    return new Date(at).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }

  /** "09:38", "yesterday 22:40", or "Sunday 22 Nov, 05:01". */
  function when(at, now) {
    const d = dayLabel(at, now);
    if (d === "Today") return clock(at);
    if (d === "Yesterday") return "yesterday " + clock(at);
    return d + ", " + clock(at);
  }

  /**
   * Segmented buttons (`role="group"`, `aria-pressed`). `onChange(key)` runs on a press; the pressed
   * one moves at once.
   */
  function segmented(label, options, value, onChange) {
    const group = h("div", { role: "group", "aria-label": label, class: "inline-flex max-w-full items-center gap-0.5 overflow-x-auto rounded-[9px] border border-line bg-surface p-0.5" });
    const paint = (v) => {
      for (const b of group.children) {
        const on = b.dataset.key === v;
        b.setAttribute("aria-pressed", on ? "true" : "false");
        b.className = "inline-flex h-[30px] shrink-0 items-center gap-1.5 rounded-[7px] px-3 text-[12.5px] font-medium whitespace-nowrap " + (on ? "bg-bg-2 font-semibold text-ink " : "text-ink-2 hover:text-ink ") + FOCUS;
      }
    };
    for (const o of options) {
      group.append(
        h("button", { type: "button", dataset: { key: o.key }, onclick: () => { paint(o.key); onChange(o.key); } }, o.icon ? icon(o.icon, "h-[14px] w-[14px] shrink-0") : null, o.label),
      );
    }
    paint(value);
    return group;
  }

  const BUTTON = {
    outline: "border border-line bg-surface text-ink shadow-sm hover:bg-bg",
    brand: "bg-brand text-white shadow-sm hover:bg-brand/90",
    ghost: "text-ink-2 hover:bg-bg-2 hover:text-ink",
    danger: "border border-block-border bg-surface text-block-fg hover:bg-block-soft",
  };

  /** A button: `variant` outline (default), brand, ghost or danger; `size` sm (default) or md. */
  function button(label, opts) {
    const o = opts || {};
    const size = o.size === "md" ? "h-9 px-3.5 text-[13.5px]" : "h-[32px] px-3 text-[13px]";
    return h(
      o.href ? "a" : "button",
      {
        type: o.href ? null : o.type || "button",
        href: o.href || null,
        target: o.external ? "_blank" : null,
        rel: o.external ? "noopener noreferrer" : null,
        class: "inline-flex shrink-0 items-center justify-center gap-1.5 rounded-lg font-medium whitespace-nowrap disabled:pointer-events-none disabled:opacity-50 " + size + " " + (BUTTON[o.variant || "outline"]) + " " + FOCUS + (o.class ? " " + o.class : ""),
        onclick: o.onClick || null,
        disabled: o.disabled || null,
        "aria-label": o.ariaLabel || null,
        "aria-expanded": o.expanded === undefined ? null : String(o.expanded),
        id: o.id || null,
        form: o.form || null,
      },
      o.icon ? icon(o.icon, "h-[14px] w-[14px] shrink-0") : null,
      label,
      o.external ? icon("external", "h-3.5 w-3.5 shrink-0 " + (o.variant === "brand" ? "opacity-80" : "text-ink-2")) : null,
    );
  }

  /** A spinner; decorative unless a label is given. */
  function spinner(cls) {
    return h("span", { "aria-hidden": "true", class: "inline-block shrink-0 rounded-full border-2 border-current/25 border-t-current motion-safe:animate-spin " + (cls || "h-4 w-4") });
  }

  /** "Loading …" in a card's body. */
  function loading(text) {
    return h("div", { role: "status", class: "flex items-center justify-center gap-2 px-4 py-10 text-[13px] text-ink-2" }, spinner("h-4 w-4 text-brand"), text || "Loading…");
  }

  /** An empty state: an icon in a circle, a title, a line, a button. */
  function empty(opts) {
    return h(
      "div",
      { class: "flex flex-col items-center gap-2 px-6 py-10 text-center" },
      h("span", { class: "mb-1 grid h-10 w-10 place-items-center rounded-full bg-bg-2 text-ink-2" }, icon(opts.icon || "info", "h-[18px] w-[18px]")),
      opts.title ? h("div", { class: "text-[14.5px] font-semibold text-ink" }, opts.title) : null,
      opts.text ? h("p", { class: "max-w-[52ch] text-[13px] text-pretty text-ink-2" }, opts.text) : null,
      opts.action ? h("div", { class: "mt-2" }, opts.action) : null,
    );
  }

  const BANNER = {
    ask: ["border-ask-border bg-ask-soft text-ink", "text-ask-fg", "alert"],
    block: ["border-block-border bg-block-soft text-ink", "text-block-fg", "xCircle"],
    brand: ["border-brand/30 bg-brand-soft text-ink", "text-brand", "info"],
    allow: ["border-allow-border bg-allow-soft text-ink", "text-allow-fg", "checkCircle"],
  };

  /** A line across a card or page with an icon in its tone, and a button at the end. */
  function banner(tone, children, action) {
    const [cls, ic, name] = BANNER[tone] || BANNER.ask;
    return h(
      "div",
      { role: tone === "block" ? "alert" : "status", class: "flex flex-wrap items-start gap-x-3 gap-y-2 rounded-xl border px-4 py-3 text-[13px] " + cls },
      icon(name, "mt-0.5 h-4 w-4 shrink-0 " + ic),
      h("div", { class: "min-w-0 flex-1 basis-[220px]" }, children),
      action || null,
    );
  }

  /** The small note under a page, with an info icon. */
  function footNote(text) {
    return h("p", { class: "mt-4 flex items-start gap-1.5 text-[12px] text-ink-2" }, icon("info", "mt-px h-3.5 w-3.5 shrink-0"), h("span", {}, text));
  }

  /** A field's label and control, with an optional hint under it. */
  function field(label, control, hint, opts) {
    const o = opts || {};
    return h(
      "div",
      { class: "min-w-0" + (o.class ? " " + o.class : "") },
      h("label", { for: control.id || null, class: "mb-1.5 flex items-baseline gap-1.5 text-[13px] font-medium text-ink" }, label, o.optional ? h("span", { class: "font-normal text-ink-2" }, "optional") : null),
      control,
      hint ? h("p", { class: "mt-1.5 text-[12px] text-pretty text-ink-2", id: control.id ? control.id + "-hint" : null }, hint) : null,
    );
  }

  const INPUT = "h-[38px] w-full min-w-0 rounded-[10px] border border-line bg-surface px-3 text-[13.5px] text-ink placeholder:text-ink-2/70 focus:border-line-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand/40 disabled:opacity-60";
  const TEXTAREA = "min-h-[64px] w-full min-w-0 rounded-[10px] border border-line bg-surface px-3 py-2 text-[13.5px] text-ink placeholder:text-ink-2/70 focus:border-line-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand/40 disabled:opacity-60";

  window.ccKit = {
    h,
    append,
    icon,
    pill,
    pageHead,
    statGrid,
    card,
    cardHead,
    dayHeading,
    dayLabel,
    groupByDay,
    clock,
    when,
    segmented,
    button,
    spinner,
    loading,
    empty,
    banner,
    footNote,
    field,
    FOCUS,
    INPUT,
    TEXTAREA,
    MONO: "font-mono text-[12.5px]",
  };
})();
