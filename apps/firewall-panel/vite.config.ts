import { existsSync, readFileSync, renameSync } from "node:fs";
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

/**
 * `pnpm dev`: the app logos from packages/console-ui/connector-icons, at the path the firewall
 * serves them from its `connector-icons.pack` (cc-local `panel.rs`).
 */
function connectorIcons(): Plugin {
  const dir = join(import.meta.dirname, "../../packages/console-ui/connector-icons");
  return {
    name: "connector-icons",
    apply: "serve",
    configureServer(server) {
      server.middlewares.use("/connector-icons/", (req, res, next) => {
        const service = /^\/[^/]+\/([a-z0-9][a-z0-9_-]{0,63})\.webp$/.exec(req.url?.split("?")[0] ?? "")?.[1];
        const file = service ? join(dir, `${service}.webp`) : null;
        if (!file || !existsSync(file)) return next();
        res.setHeader("Content-Type", "image/webp");
        res.end(readFileSync(file));
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), tailwindcss(), panelHtml(), connectorIcons()],
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
