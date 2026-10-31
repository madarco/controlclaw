import { run, terminalIo } from "./cli.js";

/** The entry point, and nothing else: `cli.ts` holds the commands so the tests can drive them. */
process.exitCode = await run(process.argv.slice(2), terminalIo());
