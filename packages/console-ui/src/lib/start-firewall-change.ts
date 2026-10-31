import type { FirewallChangeLike } from "../firewall/change/useFirewallChange";
import { FIREWALL_CHANGE_STATUSES } from "./firewall-change";

export const START_CHANGE_TIMEOUT_MS = 30_000;
export const START_CHANGE_ERROR = "Couldn’t start the change. Please try again.";

const nonEmptyString = (value: unknown): value is string => typeof value === "string" && value.trim().length > 0;

/** Check before awaiting: a bound RPC function must never reach React's state setter. */
export async function startFirewallChange<T extends FirewallChangeLike>(run: () => Promise<{ changeId: string } | T>): Promise<{ changeId: string } | T> {
  const pending = run();
  if (!pending || typeof pending !== "object" || typeof pending.then !== "function") throw new Error(START_CHANGE_ERROR);

  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      pending,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("The change request timed out. Check recent changes before trying again.")), START_CHANGE_TIMEOUT_MS);
      }),
    ]);
    if (!result || typeof result !== "object") throw new Error(START_CHANGE_ERROR);
    if ("changeId" in result) {
      if (nonEmptyString(result.changeId)) return result;
    } else if (
      "id" in result && nonEmptyString(result.id) && FIREWALL_CHANGE_STATUSES.includes(result.status) &&
      typeof result.summary === "string" && typeof result.tofu === "boolean" && typeof result.stuck === "boolean" &&
      typeof result.createdAt === "string" && (result.sentVia === null || typeof result.sentVia === "string") &&
      (result.attemptsLeft === null || Number.isInteger(result.attemptsLeft)) &&
      (result.expiresAt === null || typeof result.expiresAt === "string") && (result.error === null || typeof result.error === "string")
    ) {
      return result;
    }
    throw new Error(START_CHANGE_ERROR);
  } finally {
    clearTimeout(timer);
  }
}
