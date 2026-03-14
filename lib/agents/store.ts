import { randomUUID } from "crypto";
import { getDefaultAgentTemplates } from "@/lib/agents/catalog";
import {
  AgentEvalResultRecord,
  AgentRecord,
  AgentRunRecord,
  AgentRunStepRecord,
} from "@/lib/agents/types";
import { execute, query, queryOne } from "@/lib/db/pool";

let ensured = false;

interface CountRow {
  count: string;
}

export interface AgentListItem extends AgentRecord {
  last_run_id: string | null;
  last_run_status: string | null;
  last_run_created_at: string | null;
  last_eval_score: number | null;
  last_eval_pass: boolean | null;
}

export interface AgentPatchInput {
  name?: string;
  description?: string;
  active?: boolean;
  system_prompt?: string;
  task_prompt?: string;
  tools_allowed?: string[];
  risk_level?: AgentRecord["risk_level"];
  model_profile?: AgentRecord["model_profile"];
  memory_policy?: AgentRecord["memory_policy"];
  budget_limit?: number;
  autonomy_mode?: AgentRecord["autonomy_mode"];
  settings?: Record<string, unknown>;
  config?: Record<string, unknown>;
}

export interface AgentCampaignRecord {
  id: string;
  user_id: string;
  goal: string;
  status: "queued" | "running" | "completed" | "failed";
  summary: string | null;
  created_at: string;
  updated_at: string;
}

export type AgentCampaignScheduleType = "once" | "interval" | "daily" | "weekly";

export interface AgentCampaignScheduleRecord {
  id: string;
  user_id: string;
  title: string;
  goal: string;
  max_agents: number;
  schedule_type: AgentCampaignScheduleType;
  schedule_config: Record<string, unknown>;
  timezone: string;
  enabled: boolean;
  web_agent_template: string | null;
  web_agent_config: Record<string, unknown>;
  next_run_at: string;
  last_run_at: string | null;
  last_campaign_id: string | null;
  last_status: string | null;
  last_error: string | null;
  run_count: number;
  created_at: string;
  updated_at: string;
}

export interface AgentCreateInput {
  slug: string;
  name: string;
  description: string;
  category: AgentRecord["category"];
  system_prompt: string;
  task_prompt: string;
  tools_allowed: string[];
  risk_level: AgentRecord["risk_level"];
  model_profile: AgentRecord["model_profile"];
  memory_policy: AgentRecord["memory_policy"];
  budget_limit: number;
  autonomy_mode: AgentRecord["autonomy_mode"];
  settings: Record<string, unknown>;
  config?: Record<string, unknown>;
}

export async function ensureAgentTables(): Promise<void> {
  if (ensured) return;

  await execute(`
    CREATE TABLE IF NOT EXISTS agents (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      slug TEXT NOT NULL,
      name VARCHAR(160) NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      category VARCHAR(60) NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      system_prompt TEXT NOT NULL,
      task_prompt TEXT NOT NULL,
      tools_allowed TEXT[] NOT NULL DEFAULT '{}',
      risk_level VARCHAR(16) NOT NULL DEFAULT 'medium',
      model_profile VARCHAR(16) NOT NULL DEFAULT 'auto',
      memory_policy VARCHAR(16) NOT NULL DEFAULT 'session',
      budget_limit INTEGER NOT NULL DEFAULT 10,
      autonomy_mode VARCHAR(16) NOT NULL DEFAULT 'assisted',
      settings JSONB NOT NULL DEFAULT '{}'::jsonb,
      version INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, slug)
    );

    CREATE TABLE IF NOT EXISTS agent_versions (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
      version INTEGER NOT NULL,
      system_prompt TEXT NOT NULL,
      task_prompt TEXT NOT NULL,
      settings JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS agent_runs (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status VARCHAR(16) NOT NULL DEFAULT 'queued',
      input_text TEXT NOT NULL,
      output_text TEXT,
      error_text TEXT,
      evaluation_score NUMERIC(5,2),
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS agent_run_steps (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      run_id UUID NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
      step_index INTEGER NOT NULL,
      phase VARCHAR(80) NOT NULL,
      status VARCHAR(24) NOT NULL,
      detail TEXT NOT NULL,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS agent_notes (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
      run_id UUID REFERENCES agent_runs(id) ON DELETE SET NULL,
      title VARCHAR(255) NOT NULL DEFAULT 'Agent Note',
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS agent_memories (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
      memory_key VARCHAR(120) NOT NULL,
      memory_value JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, agent_id, memory_key)
    );

    CREATE TABLE IF NOT EXISTS agent_artifacts (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      run_id UUID NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
      artifact_type VARCHAR(60) NOT NULL,
      title VARCHAR(255) NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS agent_policies (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      policy_name VARCHAR(120) NOT NULL,
      policy JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, policy_name)
    );

    CREATE TABLE IF NOT EXISTS agent_eval_results (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      run_id UUID REFERENCES agent_runs(id) ON DELETE SET NULL,
      eval_suite VARCHAR(120) NOT NULL,
      pass BOOLEAN NOT NULL DEFAULT FALSE,
      score NUMERIC(5,2) NOT NULL DEFAULT 0,
      results JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS audit_evidence (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      run_id UUID REFERENCES agent_runs(id) ON DELETE SET NULL,
      control_framework VARCHAR(80) NOT NULL,
      control_id VARCHAR(120) NOT NULL,
      title VARCHAR(255) NOT NULL,
      description TEXT NOT NULL,
      artifact_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
      status VARCHAR(20) NOT NULL DEFAULT 'open',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS agent_campaigns (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      goal TEXT NOT NULL,
      status VARCHAR(16) NOT NULL DEFAULT 'queued',
      summary TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS agent_campaign_runs (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      campaign_id UUID NOT NULL REFERENCES agent_campaigns(id) ON DELETE CASCADE,
      agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
      run_id UUID NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
      run_order INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS agent_campaign_schedules (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(160) NOT NULL DEFAULT 'Autonomous Campaign Schedule',
      goal TEXT NOT NULL,
      max_agents INTEGER NOT NULL DEFAULT 8,
      schedule_type VARCHAR(24) NOT NULL,
      schedule_config JSONB NOT NULL DEFAULT '{}'::jsonb,
      timezone VARCHAR(80) NOT NULL DEFAULT 'America/Chicago',
      enabled BOOLEAN NOT NULL DEFAULT TRUE,
      web_agent_template VARCHAR(80),
      web_agent_config JSONB NOT NULL DEFAULT '{}'::jsonb,
      next_run_at TIMESTAMPTZ NOT NULL,
      last_run_at TIMESTAMPTZ,
      last_campaign_id UUID REFERENCES agent_campaigns(id) ON DELETE SET NULL,
      last_status VARCHAR(20),
      last_error TEXT,
      run_count INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS scheduler_locks (
      name VARCHAR(120) PRIMARY KEY,
      locked_until TIMESTAMPTZ NOT NULL,
      holder VARCHAR(160) NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE agents ADD COLUMN IF NOT EXISTS config JSONB NOT NULL DEFAULT '{}'::jsonb;

    CREATE INDEX IF NOT EXISTS idx_agents_user_category ON agents(user_id, category);
    CREATE INDEX IF NOT EXISTS idx_agent_runs_user_created ON agent_runs(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_agent_runs_agent_created ON agent_runs(agent_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_agent_run_steps_run_idx ON agent_run_steps(run_id, step_index);
    CREATE INDEX IF NOT EXISTS idx_agent_eval_agent_created ON agent_eval_results(agent_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_agent_notes_user_updated ON agent_notes(user_id, updated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_evidence_user_created ON audit_evidence(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_agent_campaigns_user_created ON agent_campaigns(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_agent_campaign_runs_campaign_order ON agent_campaign_runs(campaign_id, run_order);
    CREATE INDEX IF NOT EXISTS idx_agent_campaign_schedules_user_created ON agent_campaign_schedules(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_agent_campaign_schedules_due ON agent_campaign_schedules(enabled, next_run_at);
  `);

  ensured = true;
}

export async function seedDefaultAgentsForUser(userId: string): Promise<void> {
  await ensureAgentTables();
  const countRow = await queryOne<CountRow>(
    `SELECT COUNT(*)::text AS count FROM agents WHERE user_id = $1`,
    [userId]
  );

  if (Number(countRow?.count || "0") > 0) return;

  const templates = getDefaultAgentTemplates();
  for (const template of templates) {
    const inserted = await queryOne<{ id: string; version: number }>(
      `INSERT INTO agents (
         user_id, slug, name, description, category, active, system_prompt, task_prompt,
         tools_allowed, risk_level, model_profile, memory_policy, budget_limit, autonomy_mode, settings
       ) VALUES (
         $1, $2, $3, $4, $5, TRUE, $6, $7, $8::text[], $9, $10, $11, $12, $13, $14::jsonb
       )
       ON CONFLICT (user_id, slug) DO NOTHING
       RETURNING id, version`,
      [
        userId,
        template.slug,
        template.name,
        template.description,
        template.category,
        template.system_prompt,
        template.task_prompt,
        template.tools_allowed,
        template.risk_level,
        template.model_profile,
        template.memory_policy,
        template.budget_limit,
        template.autonomy_mode,
        JSON.stringify(template.settings),
      ]
    );

    if (inserted) {
      await execute(
        `INSERT INTO agent_versions (
           agent_id, version, system_prompt, task_prompt, settings, created_by
         ) VALUES ($1, $2, $3, $4, $5::jsonb, $6)`,
        [
          inserted.id,
          inserted.version,
          template.system_prompt,
          template.task_prompt,
          JSON.stringify(template.settings),
          userId,
        ]
      );
    }
  }
}

export async function listAgents(userId: string): Promise<AgentListItem[]> {
  await ensureAgentTables();
  await seedDefaultAgentsForUser(userId);

  const rows = await query<AgentListItem>(
    `SELECT
       a.*,
       lr.id AS last_run_id,
       lr.status AS last_run_status,
       lr.created_at AS last_run_created_at,
       le.score::float AS last_eval_score,
       le.pass AS last_eval_pass
     FROM agents a
     LEFT JOIN LATERAL (
       SELECT r.id, r.status, r.created_at
       FROM agent_runs r
       WHERE r.agent_id = a.id
       ORDER BY r.created_at DESC
       LIMIT 1
     ) lr ON TRUE
     LEFT JOIN LATERAL (
       SELECT e.score, e.pass
       FROM agent_eval_results e
       WHERE e.agent_id = a.id
       ORDER BY e.created_at DESC
       LIMIT 1
     ) le ON TRUE
     WHERE a.user_id = $1
     ORDER BY a.category ASC, a.name ASC`,
    [userId]
  );

  return rows;
}

export async function listActiveAgents(userId: string): Promise<AgentListItem[]> {
  const agents = await listAgents(userId);
  return agents.filter((agent) => agent.active);
}

export async function getAgentById(
  userId: string,
  agentId: string
): Promise<AgentRecord | null> {
  await ensureAgentTables();
  return queryOne<AgentRecord>(
    `SELECT * FROM agents WHERE id = $1 AND user_id = $2`,
    [agentId, userId]
  );
}

export async function createAgent(
  userId: string,
  input: AgentCreateInput
): Promise<AgentRecord> {
  await ensureAgentTables();
  const created = await queryOne<AgentRecord>(
    `INSERT INTO agents (
       user_id, slug, name, description, category, active, system_prompt, task_prompt,
       tools_allowed, risk_level, model_profile, memory_policy, budget_limit, autonomy_mode, settings, config
     ) VALUES (
       $1, $2, $3, $4, $5, TRUE, $6, $7, $8::text[], $9, $10, $11, $12, $13, $14::jsonb, $15::jsonb
     )
     RETURNING *`,
    [
      userId,
      input.slug,
      input.name,
      input.description,
      input.category,
      input.system_prompt,
      input.task_prompt,
      input.tools_allowed,
      input.risk_level,
      input.model_profile,
      input.memory_policy,
      input.budget_limit,
      input.autonomy_mode,
      JSON.stringify(input.settings),
      JSON.stringify(input.config || {}),
    ]
  );

  if (!created) {
    throw new Error("Failed to create agent");
  }

  await execute(
    `INSERT INTO agent_versions (
       agent_id, version, system_prompt, task_prompt, settings, created_by
     ) VALUES ($1, $2, $3, $4, $5::jsonb, $6)`,
    [
      created.id,
      created.version,
      created.system_prompt,
      created.task_prompt,
      JSON.stringify(created.settings || {}),
      userId,
    ]
  );

  return created;
}

export async function updateAgent(
  userId: string,
  agentId: string,
  patch: AgentPatchInput
): Promise<AgentRecord | null> {
  await ensureAgentTables();

  const sets: string[] = [];
  const params: unknown[] = [];
  let idx = 1;
  let shouldVersion = false;

  if (patch.name !== undefined) {
    sets.push(`name = $${idx++}`);
    params.push(patch.name);
  }
  if (patch.description !== undefined) {
    sets.push(`description = $${idx++}`);
    params.push(patch.description);
  }
  if (patch.active !== undefined) {
    sets.push(`active = $${idx++}`);
    params.push(patch.active);
  }
  if (patch.system_prompt !== undefined) {
    sets.push(`system_prompt = $${idx++}`);
    params.push(patch.system_prompt);
    shouldVersion = true;
  }
  if (patch.task_prompt !== undefined) {
    sets.push(`task_prompt = $${idx++}`);
    params.push(patch.task_prompt);
    shouldVersion = true;
  }
  if (patch.tools_allowed !== undefined) {
    sets.push(`tools_allowed = $${idx++}::text[]`);
    params.push(patch.tools_allowed);
  }
  if (patch.risk_level !== undefined) {
    sets.push(`risk_level = $${idx++}`);
    params.push(patch.risk_level);
  }
  if (patch.model_profile !== undefined) {
    sets.push(`model_profile = $${idx++}`);
    params.push(patch.model_profile);
  }
  if (patch.memory_policy !== undefined) {
    sets.push(`memory_policy = $${idx++}`);
    params.push(patch.memory_policy);
  }
  if (patch.budget_limit !== undefined) {
    sets.push(`budget_limit = $${idx++}`);
    params.push(patch.budget_limit);
  }
  if (patch.autonomy_mode !== undefined) {
    sets.push(`autonomy_mode = $${idx++}`);
    params.push(patch.autonomy_mode);
  }
  if (patch.settings !== undefined) {
    sets.push(`settings = $${idx++}::jsonb`);
    params.push(JSON.stringify(patch.settings));
    shouldVersion = true;
  }
  if (patch.config !== undefined) {
    sets.push(`config = $${idx++}::jsonb`);
    params.push(JSON.stringify(patch.config));
  }

  if (sets.length === 0) {
    return getAgentById(userId, agentId);
  }

  if (shouldVersion) {
    sets.push("version = version + 1");
  }
  sets.push("updated_at = NOW()");

  params.push(agentId, userId);

  const updated = await queryOne<AgentRecord>(
    `UPDATE agents
     SET ${sets.join(", ")}
     WHERE id = $${idx++} AND user_id = $${idx}
     RETURNING *`,
    params
  );

  if (!updated) return null;

  if (shouldVersion) {
    await execute(
      `INSERT INTO agent_versions (
         agent_id, version, system_prompt, task_prompt, settings, created_by
       ) VALUES ($1, $2, $3, $4, $5::jsonb, $6)`,
      [
        updated.id,
        updated.version,
        updated.system_prompt,
        updated.task_prompt,
        JSON.stringify(updated.settings || {}),
        userId,
      ]
    );
  }

  return updated;
}

export async function deleteAgent(userId: string, agentId: string): Promise<boolean> {
  await ensureAgentTables();
  const deleted = await execute(
    `DELETE FROM agents WHERE id = $1 AND user_id = $2`,
    [agentId, userId]
  );
  return deleted > 0;
}

export async function createAgentRun(
  userId: string,
  agentId: string,
  inputText: string
): Promise<AgentRunRecord> {
  await ensureAgentTables();
  const run = await queryOne<AgentRunRecord>(
    `INSERT INTO agent_runs (agent_id, user_id, status, input_text)
     VALUES ($1, $2, 'queued', $3)
     RETURNING *`,
    [agentId, userId, inputText]
  );
  if (!run) {
    throw new Error("Failed to create run");
  }
  return run;
}

export async function listRecoverableRuns(
  limit = 100
): Promise<
  Array<{
    id: string;
    user_id: string;
    agent_id: string;
    input_text: string;
    status: string;
  }>
> {
  await ensureAgentTables();
  return query<
    {
      id: string;
      user_id: string;
      agent_id: string;
      input_text: string;
      status: string;
    }
  >(
    `SELECT id, user_id, agent_id, input_text, status
     FROM agent_runs
     WHERE status IN ('queued', 'running')
     ORDER BY created_at ASC
     LIMIT $1`,
    [Math.min(Math.max(limit, 1), 500)]
  );
}

export async function getRunById(
  userId: string,
  runId: string
): Promise<(AgentRunRecord & { agent_name: string; agent_slug: string }) | null> {
  await ensureAgentTables();
  return queryOne<AgentRunRecord & { agent_name: string; agent_slug: string }>(
    `SELECT r.*, a.name AS agent_name, a.slug AS agent_slug
     FROM agent_runs r
     JOIN agents a ON a.id = r.agent_id
     WHERE r.id = $1 AND r.user_id = $2`,
    [runId, userId]
  );
}

export async function listRunsForAgent(
  userId: string,
  agentId: string,
  limit = 25
): Promise<AgentRunRecord[]> {
  await ensureAgentTables();
  return query<AgentRunRecord>(
    `SELECT r.*
     FROM agent_runs r
     JOIN agents a ON a.id = r.agent_id
     WHERE r.user_id = $1 AND r.agent_id = $2 AND a.user_id = $1
     ORDER BY r.created_at DESC
     LIMIT $3`,
    [userId, agentId, Math.min(Math.max(limit, 1), 100)]
  );
}

export async function listStepsForRun(
  userId: string,
  runId: string
): Promise<AgentRunStepRecord[]> {
  await ensureAgentTables();
  return query<AgentRunStepRecord>(
    `SELECT s.*
     FROM agent_run_steps s
     JOIN agent_runs r ON r.id = s.run_id
     WHERE s.run_id = $1 AND r.user_id = $2
     ORDER BY s.step_index ASC, s.created_at ASC`,
    [runId, userId]
  );
}

export async function appendRunStep(
  runId: string,
  stepIndex: number,
  phase: string,
  status: string,
  detail: string,
  metadata: Record<string, unknown> = {}
): Promise<void> {
  await ensureAgentTables();
  await execute(
    `INSERT INTO agent_run_steps (
       id, run_id, step_index, phase, status, detail, metadata
     ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`,
    [
      randomUUID(),
      runId,
      stepIndex,
      phase,
      status,
      detail,
      JSON.stringify(metadata),
    ]
  );
}

export async function markRunRunning(runId: string): Promise<void> {
  await ensureAgentTables();
  await execute(
    `UPDATE agent_runs
     SET status = 'running', started_at = COALESCE(started_at, NOW())
     WHERE id = $1`,
    [runId]
  );
}

export async function markRunQueued(runId: string): Promise<void> {
  await ensureAgentTables();
  await execute(
    `UPDATE agent_runs
     SET status = 'queued',
         started_at = NULL,
         completed_at = NULL
     WHERE id = $1 AND status IN ('queued', 'running')`,
    [runId]
  );
}

export async function markRunCompleted(
  runId: string,
  outputText: string,
  evaluationScore?: number
): Promise<void> {
  await ensureAgentTables();
  await execute(
    `UPDATE agent_runs
     SET status = 'completed',
         output_text = $2,
         evaluation_score = $3,
         completed_at = NOW()
     WHERE id = $1`,
    [runId, outputText, evaluationScore ?? null]
  );
}

export async function markRunBlocked(runId: string, reason: string): Promise<void> {
  await ensureAgentTables();
  await execute(
    `UPDATE agent_runs
     SET status = 'blocked', error_text = $2, completed_at = NOW()
     WHERE id = $1`,
    [runId, reason]
  );
}

export async function markRunFailed(runId: string, errorText: string): Promise<void> {
  await ensureAgentTables();
  await execute(
    `UPDATE agent_runs
     SET status = 'failed', error_text = $2, completed_at = NOW()
     WHERE id = $1`,
    [runId, errorText]
  );
}

export async function addRunArtifact(
  runId: string,
  artifactType: string,
  title: string,
  content: string
): Promise<void> {
  await ensureAgentTables();
  await execute(
    `INSERT INTO agent_artifacts (run_id, artifact_type, title, content)
     VALUES ($1, $2, $3, $4)`,
    [runId, artifactType, title, content]
  );
}

export async function listRunArtifacts(
  userId: string,
  runId: string
): Promise<
  Array<{
    id: string;
    artifact_type: string;
    title: string;
    content: string;
    created_at: string;
  }>
> {
  await ensureAgentTables();
  return query(
    `SELECT ar.id, ar.artifact_type, ar.title, ar.content, ar.created_at
     FROM agent_artifacts ar
     JOIN agent_runs r ON r.id = ar.run_id
     WHERE ar.run_id = $1 AND r.user_id = $2
     ORDER BY ar.created_at ASC`,
    [runId, userId]
  );
}

export async function createRunNote(
  userId: string,
  runId: string,
  title: string,
  content: string
): Promise<{
  id: string;
  user_id: string;
  run_id: string;
  agent_id: string | null;
  title: string;
  content: string;
  created_at: string;
  updated_at: string;
}> {
  await ensureAgentTables();
  const note = await queryOne<{
    id: string;
    user_id: string;
    run_id: string;
    agent_id: string | null;
    title: string;
    content: string;
    created_at: string;
    updated_at: string;
  }>(
    `INSERT INTO agent_notes (user_id, run_id, agent_id, title, content)
     SELECT $1, r.id, r.agent_id, $3, $4
     FROM agent_runs r
     WHERE r.id = $2 AND r.user_id = $1
     RETURNING id, user_id, run_id, agent_id, title, content, created_at, updated_at`,
    [userId, runId, title, content]
  );

  if (!note) {
    throw new Error("Run not found");
  }
  return note;
}

export async function listRunNotes(
  userId: string,
  runId: string
): Promise<
  Array<{
    id: string;
    title: string;
    content: string;
    created_at: string;
    updated_at: string;
  }>
> {
  await ensureAgentTables();
  return query(
    `SELECT n.id, n.title, n.content, n.created_at, n.updated_at
     FROM agent_notes n
     JOIN agent_runs r ON r.id = n.run_id
     WHERE n.user_id = $1 AND n.run_id = $2 AND r.user_id = $1
     ORDER BY n.updated_at DESC`,
    [userId, runId]
  );
}

export async function upsertAgentMemory(
  userId: string,
  agentId: string,
  key: string,
  value: Record<string, unknown>
): Promise<void> {
  await ensureAgentTables();
  await execute(
    `INSERT INTO agent_memories (user_id, agent_id, memory_key, memory_value, updated_at)
     VALUES ($1, $2, $3, $4::jsonb, NOW())
     ON CONFLICT (user_id, agent_id, memory_key)
     DO UPDATE SET memory_value = EXCLUDED.memory_value, updated_at = NOW()`,
    [userId, agentId, key, JSON.stringify(value)]
  );
}

export async function createEvalResult(
  userId: string,
  agentId: string,
  runId: string | null,
  evalSuite: string,
  pass: boolean,
  score: number,
  results: Record<string, unknown>
): Promise<AgentEvalResultRecord> {
  await ensureAgentTables();
  const record = await queryOne<AgentEvalResultRecord>(
    `INSERT INTO agent_eval_results (
       agent_id, user_id, run_id, eval_suite, pass, score, results
     ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
     RETURNING *`,
    [agentId, userId, runId, evalSuite, pass, score, JSON.stringify(results)]
  );

  if (!record) {
    throw new Error("Failed to write eval result");
  }
  return record;
}

export async function addAuditEvidence(
  userId: string,
  runId: string | null,
  framework: string,
  controlId: string,
  title: string,
  description: string,
  artifactRefs: string[]
): Promise<void> {
  await ensureAgentTables();
  await execute(
    `INSERT INTO audit_evidence (
       user_id, run_id, control_framework, control_id, title, description, artifact_refs, status
     ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, 'open')`,
    [userId, runId, framework, controlId, title, description, JSON.stringify(artifactRefs)]
  );
}

export async function createCampaign(
  userId: string,
  goal: string
): Promise<AgentCampaignRecord> {
  await ensureAgentTables();
  const campaign = await queryOne<AgentCampaignRecord>(
    `INSERT INTO agent_campaigns (user_id, goal, status)
     VALUES ($1, $2, 'queued')
     RETURNING *`,
    [userId, goal]
  );
  if (!campaign) throw new Error("Failed to create campaign");
  return campaign;
}

export async function markCampaignStatus(
  campaignId: string,
  userId: string,
  status: AgentCampaignRecord["status"],
  summary?: string
): Promise<void> {
  await ensureAgentTables();
  await execute(
    `UPDATE agent_campaigns
     SET status = $3, summary = COALESCE($4, summary), updated_at = NOW()
     WHERE id = $1 AND user_id = $2`,
    [campaignId, userId, status, summary ?? null]
  );
}

export async function addCampaignRun(
  campaignId: string,
  agentId: string,
  runId: string,
  runOrder: number
): Promise<void> {
  await ensureAgentTables();
  await execute(
    `INSERT INTO agent_campaign_runs (campaign_id, agent_id, run_id, run_order)
     VALUES ($1, $2, $3, $4)`,
    [campaignId, agentId, runId, runOrder]
  );
}

export async function getCampaignById(
  userId: string,
  campaignId: string
): Promise<AgentCampaignRecord | null> {
  await ensureAgentTables();
  return queryOne<AgentCampaignRecord>(
    `SELECT * FROM agent_campaigns WHERE id = $1 AND user_id = $2`,
    [campaignId, userId]
  );
}

export async function listCampaignRuns(
  userId: string,
  campaignId: string
): Promise<
  Array<{
    run_order: number;
    run_id: string;
    agent_id: string;
    agent_name: string;
    run_status: string;
    created_at: string;
  }>
> {
  await ensureAgentTables();
  return query(
    `SELECT c.run_order, c.run_id, c.agent_id, a.name AS agent_name, r.status AS run_status, c.created_at
     FROM agent_campaign_runs c
     JOIN agent_campaigns cp ON cp.id = c.campaign_id
     JOIN agents a ON a.id = c.agent_id
     JOIN agent_runs r ON r.id = c.run_id
     WHERE c.campaign_id = $1 AND cp.user_id = $2
     ORDER BY c.run_order ASC`,
    [campaignId, userId]
  );
}

export async function createCampaignSchedule(
  userId: string,
  input: {
    title: string;
    goal: string;
    max_agents: number;
    schedule_type: AgentCampaignScheduleType;
    schedule_config: Record<string, unknown>;
    timezone: string;
    enabled: boolean;
    web_agent_template?: string | null;
    web_agent_config?: Record<string, unknown>;
    next_run_at: string;
  }
): Promise<AgentCampaignScheduleRecord> {
  await ensureAgentTables();
  const row = await queryOne<AgentCampaignScheduleRecord>(
    `INSERT INTO agent_campaign_schedules (
       user_id, title, goal, max_agents, schedule_type, schedule_config, timezone,
       enabled, web_agent_template, web_agent_config, next_run_at
     ) VALUES (
       $1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10::jsonb, $11::timestamptz
     )
     RETURNING *`,
    [
      userId,
      input.title,
      input.goal,
      input.max_agents,
      input.schedule_type,
      JSON.stringify(input.schedule_config || {}),
      input.timezone,
      input.enabled,
      input.web_agent_template || null,
      JSON.stringify(input.web_agent_config || {}),
      input.next_run_at,
    ]
  );
  if (!row) throw new Error("Failed to create campaign schedule");
  return row;
}

export async function listCampaignSchedules(
  userId: string
): Promise<AgentCampaignScheduleRecord[]> {
  await ensureAgentTables();
  return query<AgentCampaignScheduleRecord>(
    `SELECT * FROM agent_campaign_schedules
     WHERE user_id = $1
     ORDER BY created_at DESC`,
    [userId]
  );
}

export async function getCampaignScheduleById(
  userId: string,
  scheduleId: string
): Promise<AgentCampaignScheduleRecord | null> {
  await ensureAgentTables();
  return queryOne<AgentCampaignScheduleRecord>(
    `SELECT * FROM agent_campaign_schedules
     WHERE id = $1 AND user_id = $2`,
    [scheduleId, userId]
  );
}

export async function updateCampaignSchedule(
  userId: string,
  scheduleId: string,
  patch: Partial<{
    title: string;
    goal: string;
    max_agents: number;
    schedule_type: AgentCampaignScheduleType;
    schedule_config: Record<string, unknown>;
    timezone: string;
    enabled: boolean;
    web_agent_template: string | null;
    web_agent_config: Record<string, unknown>;
    next_run_at: string;
    last_run_at: string | null;
    last_campaign_id: string | null;
    last_status: string | null;
    last_error: string | null;
    run_count: number;
  }>
): Promise<AgentCampaignScheduleRecord | null> {
  await ensureAgentTables();
  const sets: string[] = [];
  const params: unknown[] = [];
  let idx = 1;

  if (patch.title !== undefined) {
    sets.push(`title = $${idx++}`);
    params.push(patch.title);
  }
  if (patch.goal !== undefined) {
    sets.push(`goal = $${idx++}`);
    params.push(patch.goal);
  }
  if (patch.max_agents !== undefined) {
    sets.push(`max_agents = $${idx++}`);
    params.push(patch.max_agents);
  }
  if (patch.schedule_type !== undefined) {
    sets.push(`schedule_type = $${idx++}`);
    params.push(patch.schedule_type);
  }
  if (patch.schedule_config !== undefined) {
    sets.push(`schedule_config = $${idx++}::jsonb`);
    params.push(JSON.stringify(patch.schedule_config || {}));
  }
  if (patch.timezone !== undefined) {
    sets.push(`timezone = $${idx++}`);
    params.push(patch.timezone);
  }
  if (patch.enabled !== undefined) {
    sets.push(`enabled = $${idx++}`);
    params.push(patch.enabled);
  }
  if (patch.web_agent_template !== undefined) {
    sets.push(`web_agent_template = $${idx++}`);
    params.push(patch.web_agent_template);
  }
  if (patch.web_agent_config !== undefined) {
    sets.push(`web_agent_config = $${idx++}::jsonb`);
    params.push(JSON.stringify(patch.web_agent_config || {}));
  }
  if (patch.next_run_at !== undefined) {
    sets.push(`next_run_at = $${idx++}::timestamptz`);
    params.push(patch.next_run_at);
  }
  if (patch.last_run_at !== undefined) {
    sets.push(`last_run_at = $${idx++}::timestamptz`);
    params.push(patch.last_run_at);
  }
  if (patch.last_campaign_id !== undefined) {
    sets.push(`last_campaign_id = $${idx++}`);
    params.push(patch.last_campaign_id);
  }
  if (patch.last_status !== undefined) {
    sets.push(`last_status = $${idx++}`);
    params.push(patch.last_status);
  }
  if (patch.last_error !== undefined) {
    sets.push(`last_error = $${idx++}`);
    params.push(patch.last_error);
  }
  if (patch.run_count !== undefined) {
    sets.push(`run_count = $${idx++}`);
    params.push(patch.run_count);
  }

  if (sets.length === 0) {
    return getCampaignScheduleById(userId, scheduleId);
  }

  sets.push("updated_at = NOW()");
  params.push(scheduleId, userId);
  return queryOne<AgentCampaignScheduleRecord>(
    `UPDATE agent_campaign_schedules
     SET ${sets.join(", ")}
     WHERE id = $${idx++} AND user_id = $${idx}
     RETURNING *`,
    params
  );
}

export async function deleteCampaignSchedule(
  userId: string,
  scheduleId: string
): Promise<boolean> {
  await ensureAgentTables();
  const count = await execute(
    `DELETE FROM agent_campaign_schedules
     WHERE id = $1 AND user_id = $2`,
    [scheduleId, userId]
  );
  return count > 0;
}

export async function listDueCampaignSchedules(
  nowIso: string,
  limit: number
): Promise<AgentCampaignScheduleRecord[]> {
  await ensureAgentTables();
  return query<AgentCampaignScheduleRecord>(
    `SELECT * FROM agent_campaign_schedules
     WHERE enabled = TRUE
       AND next_run_at <= $1::timestamptz
     ORDER BY next_run_at ASC
     LIMIT $2`,
    [nowIso, Math.min(Math.max(limit, 1), 100)]
  );
}

export async function tryAcquireSchedulerLease(
  name: string,
  holder: string,
  ttlSeconds: number
): Promise<boolean> {
  await ensureAgentTables();
  const row = await queryOne<{ acquired: boolean }>(
    `INSERT INTO scheduler_locks (name, locked_until, holder, updated_at)
     VALUES ($1, NOW() + ($2 * INTERVAL '1 second'), $3, NOW())
     ON CONFLICT (name) DO UPDATE
     SET
       locked_until = CASE
         WHEN scheduler_locks.locked_until < NOW()
         THEN NOW() + ($2 * INTERVAL '1 second')
         ELSE scheduler_locks.locked_until
       END,
       holder = CASE
         WHEN scheduler_locks.locked_until < NOW()
         THEN $3
         ELSE scheduler_locks.holder
       END,
       updated_at = NOW()
     RETURNING (holder = $3) AS acquired`,
    [name, Math.max(10, Math.min(ttlSeconds, 300)), holder]
  );
  return Boolean(row?.acquired);
}
