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
