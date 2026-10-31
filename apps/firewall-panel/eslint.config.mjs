import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

/**
 * The panel is open source and runs on the firewall, with no Next server, no database and no
 * ControlClaw account: the same rule as packages/console-ui.
 */
const FORBIDDEN = [
  { group: ["@/*", "**/apps/saas/**"], message: "The panel must not import from apps/saas." },
  { group: ["next", "next/*"], message: "The panel is not a Next app." },
  { group: ["drizzle-orm", "drizzle-orm/*", "**/lib/db/**"], message: "The panel has no database. Use the firewall's API." },
  { group: ["better-auth", "better-auth/*"], message: "The panel's sign-in is the firewall's own (/api/login)." },
  { group: ["@orpc/*", "**/orpc*"], message: "The panel calls the firewall's REST API through @controlclaw/fw-api." },
  { group: ["server-only"], message: "The panel is client code." },
];

export default tseslint.config(
  { ignores: ["node_modules/**", "dist/**"] },
  {
    files: ["**/*.{ts,tsx,mjs}"],
    extends: [tseslint.configs.base],
    plugins: { "react-hooks": reactHooks },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      "no-restricted-imports": ["error", { patterns: FORBIDDEN }],
    },
  },
);
