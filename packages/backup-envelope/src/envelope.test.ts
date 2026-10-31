/**
 * The envelope's unit tests. The cases live in `vectors.ts` because the same ones run in a browser
 * (see `apps/saas/e2e/backups-crypto.spec.ts`).
 * Run: npx tsx src/envelope.test.ts
 */
import { runEnvelopeVectors } from "./vectors";

console.log("backup envelope");
const results = await runEnvelopeVectors();
for (const r of results) console.log(r.ok ? `  ✅ ${r.name}` : `  ❌ ${r.name} — ${r.error}`);
const fails = results.filter((r) => !r.ok).length;
console.log(fails ? `\n💥 ${fails} failed` : "\n✨ all passed");
process.exit(fails ? 1 : 0);
