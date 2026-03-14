/**
 * Flow Types — port of arcline.pro flow type definitions
 */

import type { ProviderSelectionState } from "@/lib/ai/provider-selection";

export type FlowStatus = "draft" | "active" | "paused" | "archived" | "error";
export type FlowTriggerType = "manual" | "schedule" | "webhook" | "event" | "agent";
export type FlowCategory = "general" | "recon" | "appsec" | "compliance" | "remediation" | "ops";
export type FlowNodeType =
  | "start"
  | "end"
  | "llm"
  | "agent"
  | "tool"
  | "condition"
  | "loop"
  | "http"
  | "delay"
  | "human_input"
  | "notify";
export type FlowRunStatus =
  | "pending"
  | "running"
  | "waiting_input"
  | "paused"
  | "completed"
  | "failed"
  | "cancelled";

export interface FlowNodeData {
  label: string;
  config: Record<string, unknown>;
  description?: string;
}

export interface FlowNode {
  id: string;
  type: FlowNodeType;
  data: FlowNodeData;
  position: { x: number; y: number };
}

export interface FlowEdge {
  id: string;
  source: string;
  target: string;
  sourceHandle?: string;
  targetHandle?: string;
  label?: string;
}

export interface FlowMetadata {
  ai?: ProviderSelectionState;
  [key: string]: unknown;
}

export interface FlowRecord {
  id: string;
  user_id: string;
  name: string;
  slug: string;
  description: string;
  category: FlowCategory;
  status: FlowStatus;
  nodes: FlowNode[];
  edges: FlowEdge[];
  trigger_type: FlowTriggerType;
  trigger_config: Record<string, unknown>;
  variables: Record<string, unknown>;
  metadata: FlowMetadata;
  error_strategy: "stop" | "skip" | "retry";
  timeout_ms: number;
  max_retries: number;
  version: number;
  is_template: boolean;
  is_system: boolean;
  template_source_id: string | null;
  total_runs: number;
  success_rate: number;
  tags: string[];
  created_at: string;
  updated_at: string;
  deployed_at: string | null;
}

export interface FlowRunRecord {
  id: string;
  flow_id: string;
  user_id: string;
  status: FlowRunStatus;
  trigger_type: FlowTriggerType | null;
  trigger_payload: Record<string, unknown>;
  current_node_id: string | null;
  state: Record<string, unknown>;
  error_text: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface FlowVersionRecord {
  id: string;
  flow_id: string;
  version: number;
  nodes: FlowNode[];
  edges: FlowEdge[];
  variables: Record<string, unknown> | null;
  trigger_config: Record<string, unknown> | null;
  created_by: string | null;
  created_at: string;
}

export interface FlowCreateInput {
  name: string;
  slug: string;
  description?: string;
  category?: FlowCategory;
  nodes?: FlowNode[];
  edges?: FlowEdge[];
  trigger_type?: FlowTriggerType;
  trigger_config?: Record<string, unknown>;
  variables?: Record<string, unknown>;
  metadata?: FlowMetadata;
  error_strategy?: "stop" | "skip" | "retry";
  tags?: string[];
}

export interface FlowPatchInput {
  name?: string;
  slug?: string;
  description?: string;
  category?: FlowCategory;
  nodes?: FlowNode[];
  edges?: FlowEdge[];
  trigger_type?: FlowTriggerType;
  trigger_config?: Record<string, unknown>;
  variables?: Record<string, unknown>;
  metadata?: FlowMetadata;
  error_strategy?: "stop" | "skip" | "retry";
  timeout_ms?: number;
  max_retries?: number;
  status?: FlowStatus;
  tags?: string[];
}
