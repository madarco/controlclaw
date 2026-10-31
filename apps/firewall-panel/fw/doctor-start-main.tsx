/**
 * Starting a Doctor repair on the firewall, served by the firewall at `https://<firewall>/__cc/doctor/start/`
 * (packages/mitm-agent/src/doctor-start.ts, docs/plans/doctor-rescue.md).
 *
 * Why the firewall serves it: the problem description never passes through the console. The page
 * talks to the firewall same-origin, with the cookie the firewall gave this enrolled browser.
 *
 * The console's `DoctorStartPage` (packages/console-ui), bundled by `scripts/build-fw-files.mjs` into
 * the firewall's `dist-ui/doctor-start.js`.
 */
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { DoctorStartPage, type DoctorStartResult, type DoctorStartSource, type DoctorStartState } from "@controlclaw/console-ui/firewall/doctor";
import "./fw.css";

const EXPIRED = "Access to this page has expired. Start the repair again from your ControlClaw console.";

async function call<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, body === undefined ? { credentials: "same-origin" } : { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (res.status === 403) throw new Error(EXPIRED);
  if (res.status === 429) throw new Error("Your firewall is busy. Try again in a minute.");
  try {
    return (await res.json()) as T;
  } catch (error) {
    throw new Error(`Your firewall answered ${res.status}. Try again.`, { cause: error });
  }
}

const source: DoctorStartSource = {
  state: () => call<DoctorStartState>("state"),
  propose: (input) => call<DoctorStartResult>("propose", input),
  confirm: (input) => call<DoctorStartResult>("confirm", input),
  go: (chat) => location.assign(chat),
};

// The header and sidebar around `#root` are the firewall's own (packages/mitm-agent/src/fw-shell.ts).
const root = document.getElementById("root")!;

createRoot(root).render(
  <StrictMode>
    <div className="mx-auto w-full max-w-[860px] min-w-0 px-4 pt-6 pb-16 md:px-9">
      <h1 className="mb-1 text-[22px] font-semibold tracking-[-0.02em] text-ink">Doctor</h1>
      <p className="mb-5 max-w-[70ch] text-[13.5px] text-ink-2">Repair an agent that stopped answering, from your firewall.</p>
      <DoctorStartPage source={source} />
    </div>
  </StrictMode>,
);
