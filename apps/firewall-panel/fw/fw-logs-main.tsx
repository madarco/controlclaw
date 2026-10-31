/**
 * The firewall's own Logs page, served by the firewall at `https://<firewall>/__cc/doctor/logs/`
 * (packages/mitm-agent/src/fw-logs-page.ts, apps/saas/docs/features/firewall-logs.md).
 *
 * Why the firewall serves it: the console never reads these logs. The page reads them same-origin,
 * with the cookie the firewall gave this enrolled browser, and nothing else can.
 *
 * The console's `FirewallLogs` viewer (packages/console-ui), bundled by `scripts/build-fw-files.mjs`
 * into the firewall's `dist-ui/app.js`.
 */
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { FirewallLogs } from "@controlclaw/console-ui/firewall/logs";
import type { FwLogSource, FwLogsResponse } from "@controlclaw/console-ui/lib/firewall-logs";
import "./fw.css";

const source: FwLogSource = {
  read: async ({ range, service, signal }) => {
    const res = await fetch(`data?${new URLSearchParams({ range, service })}`, { credentials: "same-origin", signal });
    if (res.status === 403) throw new Error("Access to these logs has expired. Open them again from the Firewall page in your ControlClaw console.");
    if (!res.ok) throw new Error(`The firewall answered ${res.status}. Try again.`);
    try {
      return (await res.json()) as FwLogsResponse;
    } catch (error) {
      if (signal.aborted) throw error;
      throw new Error("The firewall’s answer was cut off or wasn’t a log. Try again.", { cause: error });
    }
  },
};

// The header and sidebar around `#root` are the firewall's own (packages/mitm-agent/src/fw-shell.ts).
const root = document.getElementById("root")!;

createRoot(root).render(
  <StrictMode>
    <div className="mx-auto w-full max-w-[1180px] min-w-0 px-4 pt-6 pb-16 md:px-9">
      <h1 className="mb-1 text-[22px] font-semibold tracking-[-0.02em] text-ink">Logs</h1>
      <p className="mb-5 max-w-[70ch] text-[13.5px] text-ink-2">
        What each service on your firewall wrote, read on the firewall itself. Secrets the firewall holds are removed before they reach this page, and
        nothing here passes through ControlClaw.
      </p>
      <FirewallLogs source={source} />
    </div>
  </StrictMode>,
);
