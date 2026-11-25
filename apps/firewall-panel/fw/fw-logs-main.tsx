/**
 * The firewall's own Logs page, served by the firewall at `https://<firewall>/__cc/doctor/logs/`
 * (rust/bins/mitm-agent/src/core/fw_logs.rs, apps/saas/docs/features/firewall-logs.md).
 *
 * Why the firewall serves it: the console never reads these logs. The page reads them same-origin,
 * with the cookie the firewall gave this enrolled browser, and nothing else can.
 *
 * The console's `FirewallLogs` viewer (packages/console-ui), bundled by `scripts/build-fw-files.mjs`
 * into the firewall's `dist-ui/app.js`.
 */
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { FirewallLogsPage } from "@controlclaw/console-ui/firewall/logs";
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

// The header and sidebar around `#root` are the firewall's own (rust/bins/mitm-agent/src/core/fw_shell.rs).
// `fw_logs.rs` puts on `#root` where the Firewall page (Back to console) and Doctor are, in the
// console or the standalone panel (empty when there is none); the page offers them next to a
// failing service and a failed update.
const root = document.getElementById("root")!;
const firewallHref = root.dataset.firewallUrl || null;
const doctorHref = root.dataset.doctorUrl || null;

createRoot(root).render(
  <StrictMode>
    <FirewallLogsPage source={source} firewallHref={firewallHref} doctorHref={doctorHref} />
  </StrictMode>,
);
