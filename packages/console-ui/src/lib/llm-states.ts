/** The model providers a firewall can hold a key for (the `llm_provider` enum in the console's database). */
export const LLM_PROVIDERS = ["openai", "openai_codex", "anthropic", "google", "openrouter", "vercel_gateway", "controlclaw_included"] as const;
export type LlmProvider = (typeof LLM_PROVIDERS)[number];
