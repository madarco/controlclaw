import { readFileSync } from "node:fs";
import { defineConfig } from "tsup";

const { version } = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")) as { version: string };

/** One file, no dependencies: `npx` on a machine that runs OpenClaw needs nothing but Node. */
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node22",
  clean: true,
  noExternal: [/.*/],
  splitting: false,
  banner: { js: "#!/usr/bin/env node" },
  define: { __CC_CLI_VERSION__: JSON.stringify(version) },
});
