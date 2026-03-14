import type { ProviderSelectionState } from "@/lib/ai/provider-selection";

export type { ProviderSelectionState };

export interface AgentConfig {
  ai?: ProviderSelectionState;
  [key: string]: unknown;
}

export const AGENT_CATEGORIES = [
  "recon",
  "appsec",
  "api-security",
  "cloud-k8s",
  "iam",
  "data-security",
  "dependency-sbom",
  "runtime-detection",
  "compliance",
  "remediation",
] as const;

export type AgentCategory = (typeof AGENT_CATEGORIES)[number];

export type AgentRiskLevel = "critical" | "high" | "medium" | "low";
export type AgentModelProfile = "eco" | "auto" | "premium" | "agentic";
export type AgentMemoryPolicy = "none" | "session" | "persistent";
export type AgentAutonomyMode = "manual" | "assisted" | "autonomous";
export type AgentRunStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "blocked";

export interface AgentRecord {
  id: string;
  user_id: string;
  slug: string;
  name: string;
  description: string;
  category: AgentCategory;
  active: boolean;
  system_prompt: string;
  task_prompt: string;
  tools_allowed: string[];
  risk_level: AgentRiskLevel;
  model_profile: AgentModelProfile;
  memory_policy: AgentMemoryPolicy;
  budget_limit: number;
  autonomy_mode: AgentAutonomyMode;
  settings: Record<string, unknown>;
  config: AgentConfig;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface AgentRunRecord {
  id: string;
  agent_id: string;
  user_id: string;
  status: AgentRunStatus;
  input_text: string;
  output_text: string | null;
  error_text: string | null;
  evaluation_score: number | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface AgentRunStepRecord {
  id: string;
  run_id: string;
  step_index: number;
  phase: string;
  status: string;
  detail: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface AgentEvalResultRecord {
  id: string;
  agent_id: string;
  user_id: string;
  run_id: string | null;
  eval_suite: string;
  pass: boolean;
  score: number;
  results: Record<string, unknown>;
  created_at: string;
}

export interface AgentTemplate {
  slug: string;
  name: string;
  description: string;
  category: AgentCategory;
  system_prompt: string;
  task_prompt: string;
  tools_allowed: string[];
  risk_level: AgentRiskLevel;
  model_profile: AgentModelProfile;
  memory_policy: AgentMemoryPolicy;
  budget_limit: number;
  autonomy_mode: AgentAutonomyMode;
  settings: Record<string, unknown>;
  config?: AgentConfig;
}
