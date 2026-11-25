/**
 * The shell is written twice: here, and in Rust (`rust/crates/cc-shell`), which every agent and every
 * firewall serves it from. Both render the same frames for the same inputs and compare them byte for
 * byte with the files in `fixtures/`; the Rust tests (`crates/cc-shell/src/tests.rs`) read the same
 * files, so neither can change alone. After a deliberate change to both, rewrite the files with
 * `CC_SHELL_WRITE_FIXTURE=1 pnpm --filter @controlclaw/cc-shell test` and check the Rust tests pass.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { shellFrame, shellFoot, shellMinimalFoot, shellMinimalFrame, type ShellNavItem } from "./index";

const FIXTURE = new URL("../fixtures/frame.html", import.meta.url);

function sameAs(file: string, html: string) {
  const url = new URL(`../fixtures/${file}`, import.meta.url);
  if (process.env.CC_SHELL_WRITE_FIXTURE === "1") writeFileSync(url, html);
  assert.equal(html, readFileSync(url, "utf8"));
}

// Keep in step with `frame_matches_the_ts_twin` in crates/cc-shell/src/tests.rs.
const header = { mark: "mark" as const, name: `a&b <x>`, sub: `a&b.example "q"`, consoleUrl: `https://console.example/agents/1?x=1&y="2"` };
const nav: ShellNavItem[] = [
  { label: "Meetings", href: "/__cc/meetings", icon: "meetings", active: true, badge: "live" },
  { label: "Screen", href: "/__cc/browser", icon: "screen" },
  { label: "Link <WhatsApp>", href: "/__cc/whatsapp?a=1&b=2", icon: "whatsapp", group: "Waiting for you" },
  { label: "Doctor", href: "https://console.example/doctor?vm=1&x=2", icon: "doctor", external: true, group: "Help & more" },
  { label: "Nowhere", icon: "logs", group: "Help & more" },
];

function frame(): string {
  return shellFrame({
    title: `Screen & <co>`,
    assets: { css: "/__cc/files-ui/tw.css", js: "/__cc/shell.js" },
    header,
    page: `Screen <1>`,
    card: { mark: "mark", name: `a&b <x>`, sub: `a&b.example "q"`, status: `Running · OpenClaw 2026.11.5 <b>` },
    navLabel: `Agent "pages"`,
    nav,
    foot: shellFoot(`Served by <this> agent`, `Read from a&b.example. It never passes through ControlClaw.`),
    body: `<p>body</p>`,
    head: `<meta name="x">`,
    tail: `<script src="/t.js"></script>`,
  });
}

test("the frame matches the fixture the Rust twin is checked against", () => {
  const html = frame();
  if (process.env.CC_SHELL_WRITE_FIXTURE === "1") writeFileSync(FIXTURE, html);
  assert.equal(html, readFileSync(FIXTURE, "utf8"));
});

// Keep in step with `tones_and_the_minimal_frame_match_the_ts_twin` in crates/cc-shell/src/tests.rs.
test("tones and the minimal frame match the fixtures the Rust twin is checked against", () => {
  const assets = { css: "/__cc/doctor/ui/shell-abc.css", js: "/__cc/doctor/ui/shell.js" };
  const header = { mark: "shield" as const, name: "Firewall", sub: "fw.example", consoleUrl: null };
  sameAs(
    "frame-tones.html",
    shellFrame({
      title: "Logs",
      assets,
      header,
      page: "Logs",
      card: { mark: "shield", name: "Firewall", sub: "fw.example", status: "1 service failing · 1.58.2", statusTone: "block" },
      navLabel: "Firewall pages",
      nav: [
        { label: "Logs", href: "/__cc/doctor/logs/", icon: "logs", active: true },
        { label: "Content rules", href: "https://c.example/x?a=1&b=2", icon: "content", badge: "2 <held>", badgeTone: "ask" },
        { label: "AI review", icon: "review" },
        { label: "Website logins", href: "/l", icon: "logins", group: "Set up" },
        { label: "Doctor", href: "/d", icon: "doctor", group: "Help" },
      ],
      foot: "",
      body: "<p>b</p>",
    }),
  );
  sameAs(
    "minimal.html",
    shellMinimalFrame({
      title: "A <login>",
      assets,
      body: "<p>card</p>",
      head: `<meta name="m">`,
      tail: `<script src="/m.js"></script>`,
      foot: shellMinimalFoot("Served by your firewall, ", "fw&.example", ". It never passes through ControlClaw."),
    }),
  );
});
