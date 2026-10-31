/**
 * The contract between the firewall's Doctor start page (doctor-start.ts) and its viewer, which the
 * console builds (apps/firewall-panel/fw/doctor-start-main.tsx). Types only: both sides import it.
 */
export type DoctorStartCli = "claude" | "codex" | "pi";

/** One credential the console offered in the intent: what it can run and with which models. Never a secret. */
export interface DoctorStartChoice {
  id: string;
  label: string;
  provider: string;
  clis: DoctorStartCli[];
  models: { id: string; name: string }[];
}

/** `GET state`: the agents this firewall can repair and the console's credential choices. */
export interface DoctorStartState {
  /** The agents, and this firewall first when Firewall Doctor is installed (`firewall: true`). */
  agents: { vmId: string; name: string; ready: boolean; firewall?: boolean }[];
  choices: DoctorStartChoice[];
  /** The agent to select first: the one whose Doctor tab opened this page. Absent when it was opened elsewhere. */
  selected?: string;
}

/** `POST propose` and `POST confirm`: the firewall's answer, in the shape the page shows. */
export interface DoctorStartResult {
  ok: boolean;
  status: string;
  message?: string;
  sessionId?: string;
  summary?: string;
  /** Where the code went (`telegram:…`), or `recovery-key` when it was sealed to the owner's key. */
  sentVia?: string;
  /** The sealed challenge when `sentVia` is `recovery-key`. */
  challenge?: string;
  attemptsLeft?: number;
  /** When the code or challenge stops working (ISO). */
  expiresAt?: string;
  /** Where the browser goes once the repair runs. */
  chat?: string;
}
