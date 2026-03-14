/**
 * Flow Store — CRUD operations for flows, flow_runs, and flow_versions
 * Port of arcline.pro flow persistence pattern
 */

import { randomUUID } from "crypto";
import { execute, query, queryOne } from "@/lib/db/pool";
import type {
  FlowRecord,
  FlowRunRecord,
  FlowVersionRecord,
  FlowCreateInput,
  FlowPatchInput,
} from "@/lib/flows/types";

let ensured = false;

/* ─── Schema ─────────────────────────────────────────────────────── */

export async function ensureFlowTables(): Promise<void> {
  if (ensured) return;

  await execute(`
    CREATE TABLE IF NOT EXISTS flows (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name VARCHAR(160) NOT NULL,
      slug TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      category VARCHAR(60) NOT NULL DEFAULT 'general',
      status VARCHAR(20) NOT NULL DEFAULT 'draft',
      nodes JSONB NOT NULL DEFAULT '[]'::jsonb,
      edges JSONB NOT NULL DEFAULT '[]'::jsonb,
      trigger_type VARCHAR(20) NOT NULL DEFAULT 'manual',
      trigger_config JSONB NOT NULL DEFAULT '{}'::jsonb,
      variables JSONB NOT NULL DEFAULT '{}'::jsonb,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      error_strategy VARCHAR(16) NOT NULL DEFAULT 'stop',
      timeout_ms INTEGER NOT NULL DEFAULT 120000,
      max_retries INTEGER NOT NULL DEFAULT 0,
      version INTEGER NOT NULL DEFAULT 1,
      is_template BOOLEAN NOT NULL DEFAULT FALSE,
      is_system BOOLEAN NOT NULL DEFAULT FALSE,
      template_source_id UUID,
      total_runs INTEGER NOT NULL DEFAULT 0,
      success_rate REAL NOT NULL DEFAULT 0,
      tags TEXT[] NOT NULL DEFAULT '{}',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      deployed_at TIMESTAMPTZ,
      UNIQUE(user_id, slug)
    );

    CREATE TABLE IF NOT EXISTS flow_versions (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      flow_id UUID NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
      version INTEGER NOT NULL,
      nodes JSONB NOT NULL,
      edges JSONB NOT NULL,
      variables JSONB,
      trigger_config JSONB,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS flow_runs (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      flow_id UUID NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      trigger_type VARCHAR(20),
      trigger_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
      current_node_id TEXT,
      state JSONB NOT NULL DEFAULT '{}'::jsonb,
      error_text TEXT,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_flows_user_status ON flows(user_id, status);
    CREATE INDEX IF NOT EXISTS idx_flows_user_slug ON flows(user_id, slug);
    CREATE INDEX IF NOT EXISTS idx_flow_versions_flow ON flow_versions(flow_id, version DESC);
    CREATE INDEX IF NOT EXISTS idx_flow_runs_flow_created ON flow_runs(flow_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_flow_runs_user_created ON flow_runs(user_id, created_at DESC);
  `);

  ensured = true;
}

/* ─── Flows CRUD ─────────────────────────────────────────────────── */

export async function listFlows(
  userId: string,
  filters?: {
    status?: string;
    category?: string;
    trigger_type?: string;
    query?: string;
    templates_only?: boolean;
    limit?: number;
  }
): Promise<FlowRecord[]> {
  await ensureFlowTables();

  const conditions: string[] = ["user_id = $1"];
  const params: unknown[] = [userId];
  let idx = 2;

  if (filters?.status) {
    conditions.push(`status = $${idx}`);
    params.push(filters.status);
    idx++;
  }
  if (filters?.category) {
    conditions.push(`category = $${idx}`);
    params.push(filters.category);
    idx++;
  }
  if (filters?.trigger_type) {
    conditions.push(`trigger_type = $${idx}`);
    params.push(filters.trigger_type);
    idx++;
  }
  if (filters?.query) {
    conditions.push(`(name ILIKE $${idx} OR description ILIKE $${idx})`);
    params.push(`%${filters.query}%`);
    idx++;
  }
  if (filters?.templates_only) {
    conditions.push("is_template = true");
  }

  const limit = filters?.limit || 50;

  return query<FlowRecord>(
    `SELECT * FROM flows WHERE ${conditions.join(" AND ")}
     ORDER BY updated_at DESC
     LIMIT ${limit}`,
    params
  );
}

export async function getFlowById(
  flowId: string,
  userId: string
): Promise<FlowRecord | null> {
  await ensureFlowTables();
  return queryOne<FlowRecord>(
    `SELECT * FROM flows WHERE id = $1 AND user_id = $2`,
    [flowId, userId]
  );
}

export async function createFlow(
  userId: string,
  input: FlowCreateInput
): Promise<FlowRecord> {
  await ensureFlowTables();

  const row = await queryOne<FlowRecord>(
    `INSERT INTO flows (
       user_id, name, slug, description, category,
       nodes, edges, trigger_type, trigger_config,
       variables, metadata, error_strategy, tags
     ) VALUES (
       $1, $2, $3, $4, $5,
       $6::jsonb, $7::jsonb, $8, $9::jsonb,
       $10::jsonb, $11::jsonb, $12, $13::text[]
     ) RETURNING *`,
    [
      userId,
      input.name,
      input.slug,
      input.description || "",
      input.category || "general",
      JSON.stringify(input.nodes || []),
      JSON.stringify(input.edges || []),
      input.trigger_type || "manual",
      JSON.stringify(input.trigger_config || {}),
      JSON.stringify(input.variables || {}),
      JSON.stringify(input.metadata || {}),
      input.error_strategy || "stop",
      input.tags || [],
    ]
  );

  if (!row) throw new Error("Failed to create flow");
  return row;
}

export async function updateFlow(
  flowId: string,
  userId: string,
  patch: FlowPatchInput
): Promise<FlowRecord | null> {
  await ensureFlowTables();

  // Load current for version comparison
  const current = await queryOne<FlowRecord>(
    `SELECT id, nodes, edges, version FROM flows WHERE id = $1 AND user_id = $2`,
    [flowId, userId]
  );
  if (!current) return null;

  const jsonbFields = new Set([
    "trigger_config",
    "variables",
    "metadata",
    "nodes",
    "edges",
  ]);

  const sets: string[] = [];
  const vals: unknown[] = [flowId, userId];
  let idx = 3;

  const allowed = [
    "name",
    "slug",
    "description",
    "category",
    "nodes",
    "edges",
    "trigger_type",
    "trigger_config",
    "variables",
    "metadata",
    "error_strategy",
    "timeout_ms",
    "max_retries",
    "status",
    "tags",
  ] as const;

  const nodesChanged =
    patch.nodes !== undefined &&
    JSON.stringify(patch.nodes) !== JSON.stringify(current.nodes);
  const edgesChanged =
    patch.edges !== undefined &&
    JSON.stringify(patch.edges) !== JSON.stringify(current.edges);

  for (const key of allowed) {
    const val = (patch as Record<string, unknown>)[key];
    if (val !== undefined) {
      if (jsonbFields.has(key)) {
        sets.push(`${key} = $${idx++}::jsonb`);
        vals.push(JSON.stringify(val));
      } else if (key === "tags") {
        sets.push(`${key} = $${idx++}::text[]`);
        vals.push(val);
      } else {
        sets.push(`${key} = $${idx++}`);
        vals.push(val);
      }
    }
  }

  if (sets.length === 0) {
    return getFlowById(flowId, userId);
  }

  // Auto-increment version if graph changed
  if (nodesChanged || edgesChanged) {
    sets.push("version = version + 1");
    // Snapshot previous version
    await execute(
      `INSERT INTO flow_versions (flow_id, version, nodes, edges, variables, trigger_config, created_by)
       SELECT id, version, nodes, edges, variables, trigger_config, $1
       FROM flows WHERE id = $2`,
      [userId, flowId]
    );
  }

  if (patch.status === "active") {
    sets.push("deployed_at = NOW()");
  }

  sets.push("updated_at = NOW()");

  return queryOne<FlowRecord>(
    `UPDATE flows SET ${sets.join(", ")} WHERE id = $1 AND user_id = $2 RETURNING *`,
    vals
  );
}

export async function deleteFlow(
  flowId: string,
  userId: string
): Promise<boolean> {
  await ensureFlowTables();
  const deleted = await execute(
    `DELETE FROM flows WHERE id = $1 AND user_id = $2`,
    [flowId, userId]
  );
  return deleted > 0;
}

/* ─── Flow Runs ──────────────────────────────────────────────────── */

export async function createFlowRun(
  flowId: string,
  userId: string,
  triggerType: string | null,
  triggerPayload: Record<string, unknown>
): Promise<FlowRunRecord> {
  await ensureFlowTables();

  const row = await queryOne<FlowRunRecord>(
    `INSERT INTO flow_runs (flow_id, user_id, trigger_type, trigger_payload, status, started_at)
     VALUES ($1, $2, $3, $4::jsonb, 'running', NOW())
     RETURNING *`,
    [flowId, userId, triggerType, JSON.stringify(triggerPayload)]
  );

  if (!row) throw new Error("Failed to create flow run");

  // Increment total_runs
  await execute(
    `UPDATE flows SET total_runs = total_runs + 1 WHERE id = $1`,
    [flowId]
  );

  return row;
}

export async function updateFlowRun(
  runId: string,
  patch: {
    status?: string;
    current_node_id?: string | null;
    state?: Record<string, unknown>;
    error_text?: string | null;
  }
): Promise<void> {
  const sets: string[] = [];
  const params: unknown[] = [runId];
  let idx = 2;

  if (patch.status !== undefined) {
    sets.push(`status = $${idx++}`);
    params.push(patch.status);
    if (patch.status === "completed" || patch.status === "failed") {
      sets.push("completed_at = NOW()");
    }
  }
  if (patch.current_node_id !== undefined) {
    sets.push(`current_node_id = $${idx++}`);
    params.push(patch.current_node_id);
  }
  if (patch.state !== undefined) {
    sets.push(`state = $${idx++}::jsonb`);
    params.push(JSON.stringify(patch.state));
  }
  if (patch.error_text !== undefined) {
    sets.push(`error_text = $${idx++}`);
    params.push(patch.error_text);
  }

  if (sets.length > 0) {
    await execute(
      `UPDATE flow_runs SET ${sets.join(", ")} WHERE id = $1`,
      params
    );
  }
}

export async function listFlowRuns(
  flowId: string,
  limit = 20
): Promise<FlowRunRecord[]> {
  await ensureFlowTables();
  return query<FlowRunRecord>(
    `SELECT * FROM flow_runs WHERE flow_id = $1 ORDER BY created_at DESC LIMIT $2`,
    [flowId, limit]
  );
}

export async function getFlowRunById(
  runId: string
): Promise<FlowRunRecord | null> {
  return queryOne<FlowRunRecord>(
    `SELECT * FROM flow_runs WHERE id = $1`,
    [runId]
  );
}

/* ─── Flow Versions ──────────────────────────────────────────────── */

export async function listFlowVersions(
  flowId: string
): Promise<FlowVersionRecord[]> {
  return query<FlowVersionRecord>(
    `SELECT * FROM flow_versions WHERE flow_id = $1 ORDER BY version DESC`,
    [flowId]
  );
}
