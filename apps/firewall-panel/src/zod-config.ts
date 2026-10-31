import { z } from "zod";

/**
 * zod checks whether it may compile its parsers with `Function`, and the panel's CSP (no
 * `unsafe-eval`) reports that check as a violation on every page. Without the compiler it parses the
 * same, a little slower. Imported first in main.tsx, before any schema parses.
 */
z.config({ jitless: true });
