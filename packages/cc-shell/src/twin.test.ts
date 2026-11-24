/**
 * The shell is written twice: here, and in Rust (`rust/bins/vm-agent/src/boxside/shell.rs`), which
 * serves it on every agent. Both render the same frame for the same inputs and compare it byte for
 * byte with `fixtures/frame.html`; the Rust test (`frame_matches_the_ts_twin`) reads the same file,
 * so neither can change alone. After a deliberate change to both, rewrite the file with
 * `CC_SHELL_WRITE_FIXTURE=1 pnpm --filter @controlclaw/cc-shell test` and check the Rust test passes.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { shellFrame, shellFoot, type ShellNavItem } from "./index";

const FIXTURE = new URL("../fixtures/frame.html", import.meta.url);

// Keep in step with `frame_matches_the_ts_twin` in shell.rs.
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
