import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

/**
 * This package is shared with the open-source firewall panel, which has no Next server, no
 * database and no ControlClaw account. A view gets its data from a source passed in, never by
 * reaching into the SaaS.
 */
const FORBIDDEN = [
  { group: ["@/*", "**/apps/saas/**"], message: "console-ui must not import from apps/saas. Pass data or a slot in." },
  { group: ["next", "next/*"], message: "console-ui runs outside Next. Use AppLink (lib/link) or a prop." },
  { group: ["drizzle-orm", "drizzle-orm/*", "**/lib/db/**"], message: "console-ui must not depend on the database. Define the type here." },
  { group: ["better-auth", "better-auth/*"], message: "console-ui knows no session. Pass permissions as props." },
  { group: ["@orpc/*", "**/orpc*"], message: "console-ui must not call oRPC. Take a data source instead." },
  { group: ["server-only"], message: "console-ui is client code." },
];

export default tseslint.config(
  { ignores: ["node_modules/**"] },
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
