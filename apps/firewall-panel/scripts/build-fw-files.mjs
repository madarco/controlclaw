#!/usr/bin/env node
/**
 * Build the pages the firewall serves itself into <out> (its `dist-ui/`): the Logs page at
 * /__cc/doctor/logs/ (`app.js`, fw/fw-logs-main.tsx), the Doctor start page at /__cc/doctor/start/
 * (`doctor-start.js`, fw/doctor-start-main.tsx), and `app.css`, the one stylesheet every page of the
 * firewall links (the Logins, content rules, AI review history, Doctor chat and team chat pages the
 * agent draws itself), with Inter inlined, and `connector-icons.pack`, the app logos the local panel
 * serves.
 *
 *   node apps/firewall-panel/scripts/build-fw-files.mjs <out>
 *
 * Everything comes from this app, packages/console-ui and packages/cc-shell, so the public repo builds
 * it as the private one does. Tailwind scans what the pages use: the two bundles' components, the
 * shell, and the agent's page sources: all of the Rust agent's (`.rs`, and the `.html` and `.js` its
 * pages include) and, where they exist (the private repo), the TS ones. A page whose file is not in `SOURCES` below has no CSS for the classes only it uses.
 *
 * Callers: rust/scripts/build-ui.sh (the Rust agent reads `dist-ui/` next to its binary) and the TS
 * mitm-agent's build (`pnpm --filter @controlclaw/mitm-agent build`, which inlines the three files).
 */
import { build } from "esbuild";
import postcss from "postcss";
import tailwind from "@tailwindcss/postcss";
import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const APP = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO = resolve(APP, "../..");
const FW = join(APP, "fw");
if (!process.argv[2]) {
  console.error("usage: build-fw-files.mjs <out>");
  process.exit(2);
}
const OUT = resolve(process.argv[2]);

await rm(OUT, { recursive: true, force: true });
await mkdir(OUT, { recursive: true });

await build({
  entryPoints: { app: join(FW, "fw-logs-main.tsx"), "doctor-start": join(FW, "doctor-start-main.tsx") },
  outdir: OUT,
  bundle: true,
  format: "esm",
  platform: "browser",
  target: ["es2022"],
  minify: true,
  jsx: "automatic",
  legalComments: "none",
  plugins: [
    {
      // fw.css is Tailwind source, not plain CSS: it is built below and must not be bundled raw.
      name: "fw-css",
      setup(b) {
        b.onResolve({ filter: /fw\.css$/ }, () => ({ path: "fw.css", external: true, sideEffects: false }));
      },
    },
  ],
  define: { "process.env.NODE_ENV": '"production"' },
  logLevel: "warning",
});

const entry = join(OUT, "app.js");
for (const file of [entry, join(OUT, "doctor-start.js")]) await writeFile(file, (await readFile(file, "utf8")).replace(/import"fw\.css";?/g, ""));

// What Tailwind scans: the two bundles' components, then the shell and the firewall's own pages.
const UI = "packages/console-ui/src";
const RUST = "rust/bins/mitm-agent/src";
const TS = "packages/mitm-agent/src";
const SOURCES = [
  `${UI}/firewall/doctor`,
  `${UI}/firewall/channels/ChannelDialogs.tsx`,
  `${UI}/firewall/change/RecoveryKeyConfirm.tsx`,
  `${UI}/kit/RecoveryKeyInput.tsx`,
  `${UI}/kit/JsonFileDrop.tsx`,
  `${UI}/ui`,
  `${UI}/firewall/logs`,
  "packages/cc-shell/src/index.ts",
  // The pages the Rust agent draws: its HTML is in the .rs files and in the .html and .js files
  // they include (`include_str!`), so the whole source folder is scanned.
  RUST,
  // Their TS twins, in the private repo only.
  ...["fw-shell.ts", "logins-page.ts", "logins-web.ts", "doctor-chat-page.ts", "transcript-page.ts", "ai-review-history.ts", "teamchat-web.ts", "content-rules-page.ts"].map((f) => `${TS}/${f}`),
].filter((source) => existsSync(join(REPO, source)));
const from = join(FW, "fw.css");
const css = await postcss([tailwind({ base: FW, optimize: { minify: true } })]).process(
  `${SOURCES.map((source) => `@source "${join(REPO, source)}";`).join("\n")}\n${await readFile(from, "utf8")}`,
  { from },
);
// Inter, latin, one variable file for every weight, as a data URL: the page loads nothing else.
// The console's next/font variables are set here too.
const inter = await readFile(createRequire(import.meta.url).resolve("@fontsource-variable/inter/files/inter-latin-wght-normal.woff2"));
const fontFace = `@font-face{font-family:"Inter Variable";font-style:normal;font-display:swap;font-weight:100 900;src:url(data:font/woff2;base64,${inter.toString("base64")}) format("woff2")}:root{--font-inter:"Inter Variable";--font-jetbrains-mono:ui-monospace;--font-instrument-serif:Georgia}`;
await writeFile(join(OUT, "app.css"), fontFace + css.css);

// The app logos (packages/console-ui/connector-icons) as one file, `connector-icons.pack`, because the
// page assets are flat files, each one a release asset: `CCICONS1\n`, a JSON line
// `{"<service>": [offset, length]}`, then the WebP bytes. The panel serves it (cc-local `panel.rs`).
const ICONS = join(REPO, "packages/console-ui/connector-icons");
const iconFiles = (await readdir(ICONS)).filter((f) => f.endsWith(".webp")).sort();
const iconIndex = {};
const iconBytes = [];
let iconAt = 0;
for (const f of iconFiles) {
  const b = await readFile(join(ICONS, f));
  iconIndex[f.slice(0, -5)] = [iconAt, b.length];
  iconBytes.push(b);
  iconAt += b.length;
}
await writeFile(join(OUT, "connector-icons.pack"), Buffer.concat([Buffer.from(`CCICONS1\n${JSON.stringify(iconIndex)}\n`), ...iconBytes]));

const js = (await readFile(entry)).length;
const startJs = (await readFile(join(OUT, "doctor-start.js"))).length;
const cssSize = (await readFile(join(OUT, "app.css"))).length;
console.log(`fw-ui: app.js ${(js / 1024).toFixed(0)} KiB, doctor-start.js ${(startJs / 1024).toFixed(0)} KiB, app.css ${(cssSize / 1024).toFixed(0)} KiB, ${iconFiles.length} logos ${(iconAt / 1024).toFixed(0)} KiB → ${OUT}`);
