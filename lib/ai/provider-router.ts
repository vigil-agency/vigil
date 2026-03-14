/**
 * Provider Router — resolves which AI provider to use for a given task
 * Port of arcline.pro lib/ai/providers/registry.ts
 */

import {
  type ProviderSelectionState,
  PROVIDER_OPTIONS,
  readProviderSelection,
} from "@/lib/ai/provider-selection";

/* ─── Route keys ─────────────────────────────────────────────────── */

const ROUTE_KEYS = ["scan", "analysis", "hunt", "default"] as const;
type RouteKey = (typeof ROUTE_KEYS)[number];

/* ─── Strategy fallback ordering ─────────────────────────────────── */

type Strategy = "balanced" | "premium" | "speed" | "economy";

const STRATEGY_FALLBACK_ORDER: Record<Strategy, string[]> = {
  balanced: ["ollama", "claude-api", "claude-cli", "codex"],
  premium: ["claude-api", "claude-cli", "ollama", "codex"],
  speed: ["ollama", "codex", "claude-cli", "claude-api"],
  economy: ["ollama", "codex", "claude-cli", "claude-api"],
};

/* ─── Default route assignments ──────────────────────────────────── */

const DEFAULT_ROUTES: Record<RouteKey, string> = {
  scan: "ollama",
  analysis: "claude-api",
  hunt: "ollama",
  default: "ollama",
};

/* ─── Resolved result ────────────────────────────────────────────── */

export interface ResolvedProvider {
  providerId: string;
  model: string;
  label: string;
  fallbackChain: string[];
}

/* ─── Category → route key mapping ───────────────────────────────── */

function categoryToRouteKey(category?: string | null): RouteKey {
  switch (category) {
    case "recon":
    case "scanner":
      return "scan";
    case "appsec":
    case "api-security":
    case "compliance":
    case "analyzer":
      return "analysis";
    case "runtime-detection":
    case "hunter":
      return "hunt";
    default:
      return "default";
  }
}

/* ─── Global provider fallback ───────────────────────────────────── */

let _getGlobalProvider: (() => string) | null = null;

/**
 * Register the global provider getter (called once from server.js).
 * This avoids circular requires with lib/ai.js.
 */
export function setGlobalProviderGetter(fn: () => string): void {
  _getGlobalProvider = fn;
}

function getGlobalProvider(): string {
  if (_getGlobalProvider) return _getGlobalProvider();
  return process.env.AI_PROVIDER || "ollama";
}

/* ─── Core resolver ──────────────────────────────────────────────── */

export interface ResolveArgs {
  surface?: string;
  category?: string | null;
  preferredProvider?: string | null;
  preferredModel?: string | null;
  fallbackChain?: string[] | null;
  strategy?: Strategy;
}

/**
 * Resolve which provider to use for a given task.
 * Priority: explicit config → route default → global default → fallback chain.
 */
export function resolveProviderSelection(
  args: ResolveArgs
): ResolvedProvider | null {
  const {
    category,
    preferredProvider,
    preferredModel,
    fallbackChain,
    strategy = "balanced",
  } = args;

  const routeKey = categoryToRouteKey(category);

  // 1. Explicit preferred provider
  if (preferredProvider) {
    return {
      providerId: preferredProvider,
      model: preferredModel || "",
      label: `${args.surface || "task"} → ${preferredProvider}`,
      fallbackChain: fallbackChain || STRATEGY_FALLBACK_ORDER[strategy],
    };
  }

  // 2. Global default
  const globalProvider = getGlobalProvider();
  if (globalProvider && globalProvider !== "none") {
    return {
      providerId: globalProvider,
      model: "",
      label: `${args.surface || "task"} → ${globalProvider} (global)`,
      fallbackChain: fallbackChain || STRATEGY_FALLBACK_ORDER[strategy],
    };
  }

  // 3. Route default
  const routeDefault = DEFAULT_ROUTES[routeKey];
  if (routeDefault) {
    return {
      providerId: routeDefault,
      model: "",
      label: `${args.surface || "task"} → ${routeDefault} (route: ${routeKey})`,
      fallbackChain: fallbackChain || STRATEGY_FALLBACK_ORDER[strategy],
    };
  }

  return null;
}

/* ─── Task-level resolver (convenience wrapper) ──────────────────── */

export function resolveTaskProvider(args: {
  config?: unknown;
  category?: string | null;
  surface?: string;
  strategy?: Strategy;
}): ResolvedProvider | null {
  const selection = readProviderSelection(args.config);

  return resolveProviderSelection({
    surface: args.surface || "agent",
    category: args.category,
    preferredProvider:
      selection.mode !== "inherit" ? selection.provider : null,
    preferredModel:
      selection.mode === "pinned" ? selection.model : null,
    fallbackChain:
      selection.fallbackChain.length > 0
        ? selection.fallbackChain
        : null,
    strategy: args.strategy,
  });
}

/* ─── Router snapshot (for settings UI) ──────────────────────────── */

export function getProviderRouterSnapshot(): {
  globalProvider: string;
  defaultRoutes: Record<string, string>;
  availableProviders: Array<{ value: string; label: string }>;
  strategies: Strategy[];
} {
  return {
    globalProvider: getGlobalProvider(),
    defaultRoutes: { ...DEFAULT_ROUTES },
    availableProviders: [...PROVIDER_OPTIONS],
    strategies: ["balanced", "premium", "speed", "economy"],
  };
}
