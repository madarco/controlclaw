import { createContext, useContext } from "react";
import { CONTENT_CHANNELS, type ContentChannel } from "@controlclaw/console-ui/lib/agent/content-rules-schema";

/**
 * What the rules views say and offer on this control plane. The console: changes wait for a code
 * and every channel can be checked. The firewall's own panel applies changes at once and has no team
 * chat or voice. `SecurityRulesView` provides it from its props; the editors read it.
 */
export type RulesOptions = { codes: boolean; channels: readonly ContentChannel[] };

export const RulesOptionsContext = createContext<RulesOptions>({ codes: true, channels: CONTENT_CHANNELS });

export function useRulesOptions(): RulesOptions {
  return useContext(RulesOptionsContext);
}
