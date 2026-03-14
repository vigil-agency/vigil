/**
 * Provider Selection — per-agent / per-flow LLM provider routing
 * Port of arcline.pro lib/ai/provider-selection.ts
 */

export type ProviderSelectionMode = "inherit" | "provider" | "pinned";

export type ProviderSelectionState = {
  mode: ProviderSelectionMode;
  provider: string;
  model: string;
  fallbackChain: string[];
};

export const PROVIDER_OPTIONS = [
  { value: "ollama", label: "Ollama" },
  { value: "claude-api", label: "Claude API" },
  { value: "claude-cli", label: "Claude CLI" },
  { value: "claude-code", label: "Claude Code" },
  { value: "codex", label: "Codex CLI" },
] as const;

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .filter((entry): entry is string => typeof entry === "string")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function isProviderSelectionMode(
  value: unknown
): value is ProviderSelectionMode {
  return value === "inherit" || value === "provider" || value === "pinned";
}

function inferMode(provider: string, model: string): ProviderSelectionMode {
  if (!provider) {
    return "inherit";
  }

  return model ? "pinned" : "provider";
}

export function readProviderSelection(value: unknown): ProviderSelectionState {
  if (typeof value !== "object" || value === null) {
    return {
      mode: "inherit",
      provider: "",
      model: "",
      fallbackChain: [],
    };
  }

  const record = value as Record<string, unknown>;
  const provider = normalizeString(record.provider);
  const model = normalizeString(record.model);
  const fallbackChain = normalizeStringArray(
    record.fallbackChain ?? record.fallback_chain
  );
  const requestedMode = isProviderSelectionMode(record.mode)
    ? record.mode
    : inferMode(provider, model);

  if (requestedMode === "inherit" || !provider) {
    return {
      mode: "inherit",
      provider: "",
      model: "",
      fallbackChain,
    };
  }

  if (requestedMode === "provider" || !model) {
    return {
      mode: "provider",
      provider,
      model: "",
      fallbackChain,
    };
  }

  return {
    mode: "pinned",
    provider,
    model,
    fallbackChain,
  };
}

export function buildProviderSelectionConfig(
  value: Partial<ProviderSelectionState>
): Record<string, unknown> {
  const selection = readProviderSelection(value);
  const config: Record<string, unknown> = {
    mode: selection.mode,
  };

  if (selection.provider) {
    config.provider = selection.provider;
  }

  if (selection.model) {
    config.model = selection.model;
  }

  if (selection.fallbackChain.length > 0) {
    config.fallbackChain = selection.fallbackChain;
  }

  return config;
}

export function getProviderLabel(
  providerId: string | null | undefined
): string {
  return (
    PROVIDER_OPTIONS.find((option) => option.value === providerId)?.label ??
    providerId ??
    ""
  );
}
