/**
 * Flow Executor — DAG walker for security workflow execution
 * Port of arcline.pro flow execution pattern
 */

import { readProviderSelection } from "@/lib/ai/provider-selection";
import { resolveTaskProvider } from "@/lib/ai/provider-router";
import {
  getFlowById,
  createFlowRun,
  updateFlowRun,
} from "@/lib/flows/store";
import type { FlowNode, FlowEdge, FlowRecord, FlowRunRecord } from "@/lib/flows/types";

interface ExecutionContext {
  askAI?: (prompt: string, opts?: Record<string, unknown>) => Promise<string>;
  io?: { emit: (event: string, data: unknown) => void };
  sendNotification?: (msg: string) => void;
}

/* ─── DAG helpers ────────────────────────────────────────────────── */

function buildAdjacency(
  edges: FlowEdge[]
): Map<string, Array<{ target: string; label?: string; sourceHandle?: string }>> {
  const adj = new Map<string, Array<{ target: string; label?: string; sourceHandle?: string }>>();
  for (const edge of edges) {
    if (!adj.has(edge.source)) adj.set(edge.source, []);
    adj.get(edge.source)!.push({
      target: edge.target,
      label: edge.label,
      sourceHandle: edge.sourceHandle,
    });
  }
  return adj;
}

function findStartNode(nodes: FlowNode[]): FlowNode | undefined {
  return nodes.find((n) => n.type === "start");
}

/* ─── Node executors ─────────────────────────────────────────────── */

async function executeNode(
  node: FlowNode,
  state: Record<string, unknown>,
  flow: FlowRecord,
  ctx: ExecutionContext
): Promise<unknown> {
  const config = node.data.config || {};

  switch (node.type) {
    case "start":
    case "end":
      return null;

    case "llm": {
      const prompt = (config.prompt as string) || "";
      if (!prompt || !ctx.askAI) return "No prompt or AI provider configured";

      // Resolve provider: node config → flow metadata → global
      const resolved = resolveTaskProvider({
        config: config.ai || flow.metadata?.ai,
        category: flow.category,
        surface: "flow-llm",
      });

      return ctx.askAI(prompt, {
        systemPrompt: config.systemPrompt as string || undefined,
        timeout: flow.timeout_ms || 120000,
      });
    }

    case "agent": {
      const agentSlug = config.agentSlug as string || config.agentId as string;
      const taskDescription = config.taskDescription as string || "";
      if (!agentSlug || !ctx.askAI) return "No agent or AI configured";

      const prompt = taskDescription
        ? `As the ${agentSlug} agent, execute: ${taskDescription}`
        : `Execute agent: ${agentSlug}`;

      return ctx.askAI(prompt, { timeout: flow.timeout_ms || 120000 });
    }

    case "condition": {
      const expression = config.expression as string || "false";
      try {
        // Simple expression evaluation against state
        const fn = new Function("state", `return !!(${expression})`);
        return fn(state);
      } catch {
        return false;
      }
    }

    case "http": {
      const url = config.url as string;
      const method = (config.method as string || "GET").toUpperCase();
      if (!url) return { error: "No URL configured" };

      try {
        const fetchOpts: RequestInit = { method };
        if (config.headers) {
          fetchOpts.headers = config.headers as Record<string, string>;
        }
        if (config.body && method !== "GET") {
          fetchOpts.body =
            typeof config.body === "string"
              ? config.body
              : JSON.stringify(config.body);
        }
        const resp = await fetch(url, fetchOpts);
        const text = await resp.text();
        try {
          return JSON.parse(text);
        } catch {
          return text;
        }
      } catch (err) {
        return { error: (err as Error).message };
      }
    }

    case "delay": {
      const ms = (config.ms as number) || 1000;
      await new Promise((resolve) => setTimeout(resolve, Math.min(ms, 60000)));
      return { delayed: ms };
    }

    case "notify": {
      const message = config.message as string || "Flow notification";
      if (ctx.sendNotification) ctx.sendNotification(message);
      return { notified: true, message };
    }

    case "human_input":
      return { waiting: true, prompt: config.prompt || "Waiting for input" };

    default:
      return { skipped: true, reason: `Unknown node type: ${node.type}` };
  }
}

/* ─── Main executor ──────────────────────────────────────────────── */

export async function executeFlow(
  flowId: string,
  userId: string,
  triggerPayload: Record<string, unknown>,
  ctx: ExecutionContext
): Promise<FlowRunRecord> {
  const flow = await getFlowById(flowId, userId);
  if (!flow) throw new Error("Flow not found");

  const run = await createFlowRun(flowId, userId, flow.trigger_type, triggerPayload);

  const nodes = (flow.nodes || []) as FlowNode[];
  const edges = (flow.edges || []) as FlowEdge[];
  const adj = buildAdjacency(edges);
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  const state: Record<string, unknown> = { trigger: triggerPayload };

  const startNode = findStartNode(nodes);
  if (!startNode) {
    await updateFlowRun(run.id, { status: "failed", error_text: "No start node found" });
    return { ...run, status: "failed", error_text: "No start node found" };
  }

  // BFS traversal
  const queue: string[] = [startNode.id];
  const visited = new Set<string>();

  try {
    while (queue.length > 0) {
      const nodeId = queue.shift()!;
      if (visited.has(nodeId)) continue;
      visited.add(nodeId);

      const node = nodeMap.get(nodeId);
      if (!node) continue;

      // Emit progress
      await updateFlowRun(run.id, { current_node_id: nodeId });
      if (ctx.io) {
        ctx.io.emit("flow:node_start", {
          runId: run.id,
          flowId,
          nodeId,
          nodeType: node.type,
          label: node.data.label,
        });
      }

      // Execute
      const result = await executeNode(node, state, flow, ctx);
      state[nodeId] = result;

      if (ctx.io) {
        ctx.io.emit("flow:node_complete", {
          runId: run.id,
          flowId,
          nodeId,
          nodeType: node.type,
          result: typeof result === "object" ? result : { value: result },
        });
      }

      // Handle human_input pause
      if (node.type === "human_input") {
        await updateFlowRun(run.id, {
          status: "waiting_input",
          state,
          current_node_id: nodeId,
        });
        return { ...run, status: "waiting_input", state };
      }

      // Get next nodes
      const outEdges = adj.get(nodeId) || [];
      if (node.type === "condition") {
        // Follow true/false handle
        const condResult = !!result;
        for (const edge of outEdges) {
          const handle = edge.sourceHandle || edge.label;
          if (
            (condResult && (handle === "true" || handle === "yes")) ||
            (!condResult && (handle === "false" || handle === "no")) ||
            !handle
          ) {
            queue.push(edge.target);
          }
        }
      } else {
        for (const edge of outEdges) {
          queue.push(edge.target);
        }
      }
    }

    // Mark complete
    await updateFlowRun(run.id, { status: "completed", state });
    if (ctx.io) {
      ctx.io.emit("flow:complete", { runId: run.id, flowId, state });
    }
    return { ...run, status: "completed", state };
  } catch (err) {
    const errorText = (err as Error).message || "Flow execution error";

    if (flow.error_strategy === "stop") {
      await updateFlowRun(run.id, { status: "failed", state, error_text: errorText });
      if (ctx.io) {
        ctx.io.emit("flow:error", { runId: run.id, flowId, error: errorText });
      }
      return { ...run, status: "failed", state, error_text: errorText };
    }

    // skip strategy: mark complete with error in state
    state._error = errorText;
    await updateFlowRun(run.id, { status: "completed", state });
    return { ...run, status: "completed", state };
  }
}
