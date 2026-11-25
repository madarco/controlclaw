/** The model the form starts on: the chosen one while it is still offered, else the first. */
export function doctorSelectedModel(models: { id: string }[], chosen: string): string {
  return models.some((m) => m.id === chosen) ? chosen : (models[0]?.id ?? "");
}

/** Gateway suggestions use the agent-setup catalog, restricted to the CLI's API. */
export function doctorModelsForCli<M extends { id: string }>(credential: { provider: string; models: M[] }, cli: "claude" | "codex" | "pi"): M[] {
  if (!["controlclaw_included", "vercel_gateway"].includes(credential.provider) || cli === "pi") return credential.models;
  const prefix = cli === "claude" ? "anthropic/" : "openai/";
  return credential.models.filter((model) => model.id.startsWith(prefix));
}

type DoctorCliId = "claude" | "codex" | "pi";

/**
 * How Doctor ranks a credential when nobody chose one: a subscription first (already paid for), then
 * the organization's own API keys, then its own AI Gateway key, and the included AI tokens last (they
 * count against the plan's allowance). Lower is better.
 */
export function doctorCredentialRank(provider: string): number {
  if (provider === "openai_codex") return 0;
  if (provider === "anthropic" || provider === "openai") return 1;
  if (provider === "vercel_gateway") return 2;
  if (provider === "controlclaw_included") return 3;
  return 4;
}

/** The coding agent made for a credential's provider: Codex for OpenAI and ChatGPT, else Claude Code. */
function preferredCli(provider: string, clis: readonly DoctorCliId[]): DoctorCliId | undefined {
  const made: DoctorCliId = provider === "openai_codex" || provider === "openai" ? "codex" : "claude";
  return clis.includes(made) ? made : clis[0];
}

/**
 * The coding agent and credential every Doctor form starts on (the agent's Doctor tab, Ask Doctor on a
 * finding, the firewall's own start page, and the MCP tools when they leave them out): the best
 * credential by `doctorCredentialRank`, ties broken by id so every surface picks the same one, with
 * the coding agent made for it. Null when there is no credential.
 */
/** Best credential first (`doctorCredentialRank`), then by id: the one order every Doctor surface lists and picks in. */
export function compareDoctorCredentials(a: { id: string; provider: string }, b: { id: string; provider: string }): number {
  return doctorCredentialRank(a.provider) - doctorCredentialRank(b.provider) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

/** The coding agents' names, as every Doctor form shows them. */
export const DOCTOR_CLI_NAMES: Record<DoctorCliId, string> = { claude: "Claude Code", codex: "Codex", pi: "Pi" };

export function doctorDefaultChoice<C extends { id: string; provider: string; clis: readonly DoctorCliId[] }>(choices: readonly C[]): { cli: DoctorCliId; credential: C } | null {
  const best = [...choices]
    .filter((c) => c.clis.length)
    .sort(compareDoctorCredentials)[0];
  const cli = best ? preferredCli(best.provider, best.clis) : undefined;
  return best && cli ? { cli, credential: best } : null;
}

/**
 * What a Doctor form shows from what the person chose so far (`cli` and `credentialId` empty until
 * they choose): the coding agent, the credentials it can run and the one selected. Until a choice,
 * the default (`doctorDefaultChoice`); after a coding agent is chosen, its best credential.
 */
export function doctorFormPick<C extends { id: string; provider: string; clis: readonly DoctorCliId[] }>(all: readonly C[], cli: DoctorCliId | "", credentialId: string): { cli: DoctorCliId; choices: C[]; credential: C | undefined } {
  const active: DoctorCliId = cli || (doctorDefaultChoice(all)?.cli ?? "claude");
  const choices = all.filter((c) => c.clis.includes(active));
  const credential = choices.find((c) => c.id === credentialId) ?? doctorDefaultChoice(choices)?.credential;
  return { cli: active, choices, credential };
}
