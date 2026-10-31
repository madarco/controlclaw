import { existsSync, renameSync } from "node:fs";
import { join } from "node:path";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

/**
 * The firewall's page assets are flat files (rust/scripts/box-ui): the build is `panel.html`,
 * `panel.js` and `panel.css`, with fixed names and everything else (the Inter font) inlined.
 * The firewall serves them on the API's own origin (cc-local `panel.rs`).
 */
function panelHtml(): Plugin {
  return {
    name: "panel-html",
    apply: "build",
    closeBundle() {
      // Only after a build that wrote the page: a failed one must show its own error.
      const page = join(import.meta.dirname, "dist/index.html");
      if (existsSync(page)) renameSync(page, join(import.meta.dirname, "dist/panel.html"));
    },
  };
}

export default defineConfig({
  plugins: [react(), tailwindcss(), panelHtml()],
  base: "/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsInlineLimit: 4 * 1024 * 1024,
    modulePreload: false,
    rollupOptions: {
      output: {
        entryFileNames: "panel.js",
        assetFileNames: "panel[extname]",
        codeSplitting: false,
      },
    },
  },
  // `pnpm dev`: the API of a firewall on this machine (or an SSH tunnel to one).
  server: { proxy: { "/api": process.env.PANEL_API ?? "http://127.0.0.1:8800" } },
});
