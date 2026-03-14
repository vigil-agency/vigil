import { chat, isOllamaAvailable, listModels } from "@/lib/ai/ollama-client";
import { readProviderSelection } from "@/lib/ai/provider-selection";
import { resolveTaskProvider } from "@/lib/ai/provider-router";
import { evaluateRunPolicy, redactSecrets } from "@/lib/agents/guardrails";
import { gatherTargetIntel } from "@/lib/agents/target-intel";
import {
  addAuditEvidence,
  addRunArtifact,
  appendRunStep,
  getAgentById,
  markRunBlocked,
  markRunCompleted,
  markRunFailed,
  markRunRunning,
  upsertAgentMemory,
} from "@/lib/agents/store";

export interface AgentRunJob {
  runId: string;
  userId: string;
  agentId: string;
  inputText: string;
}

function buildControlIds(category: string): string[] {
  switch (category) {
    case "appsec":
      return ["OWASP-ASVS-V5", "OWASP-LLM01"];
    case "api-security":
      return ["OWASP-API1", "OWASP-API4"];
    case "compliance":
      return ["SOC2-CC7", "NIST-AI-RMF-GV"];
    case "cloud-k8s":
      return ["CIS-K8S-5.2", "NIST-CSF-PR.AC"];
    default:
      return ["SOC2-CC6", "NIST-CSF-ID.RA"];
  }
}

function fallbackResponse(agentName: string, sanitizedInput: string): string {
  return `LLM runtime unavailable. ${agentName} executed in fallback mode.

Situation summary:
- Request received and sanitized for policy safety.
- No unsafe commands were executed.

Top findings:
- Verify scope and ownership for each target in this request.
- Prioritize critical internet-facing surfaces first.

Step-by-step action plan:
1. Convert the request into a scoped checklist with owners.
2. Execute low-risk discovery and validation tests.
3. Capture evidence (logs, screenshots, output snippets) for each step.
4. Record remediation tasks with due dates and retest criteria.

Validation checks:
- Confirm each finding can be reproduced.
- Confirm each remediation closes the exact issue.

Evidence to capture:
- Request context: ${sanitizedInput.slice(0, 220)}
- Commands used, outputs, and change approvals`;
}

/**
 * Run model using the resolved provider.
 * Supports: ollama, claude-api, claude-cli, claude-code, codex
 * Falls back to ollama if provider is not explicitly set.
 */
async function runModel(
  systemPrompt: string,
  taskPrompt: string,
  inputText: string,
  providerId?: string,
  model?: string
): Promise<string> {
  const prompt = taskPrompt.replace("{{input}}", inputText);
  const effectiveProvider = providerId || "ollama";

  // For non-ollama providers, delegate to lib/ai.js functions
  if (effectiveProvider !== "ollama") {
    try {
      // Dynamic require to avoid circular dependency issues
      const ai = require("@/lib/ai");
      if (effectiveProvider === "claude-api" && ai.callClaudeAPI) {
        return await ai.callClaudeAPI(prompt, {
          systemPrompt,
          model: model || undefined,
          timeout: 20000,
        });
      }
      if (effectiveProvider === "claude-cli" && ai.callClaudeCLI) {
        return await ai.callClaudeCLI(prompt, {
          systemPrompt,
          timeout: 20000,
        });
      }
      if (effectiveProvider === "claude-code" && ai.callClaudeCode) {
        return await ai.callClaudeCode(prompt, {
          systemPrompt,
          timeout: 20000,
        });
      }
      if (effectiveProvider === "codex" && ai.callCodex) {
        return await ai.callCodex(prompt, {
          systemPrompt,
          timeout: 20000,
        });
      }
      // askAI is the generic wrapper
      if (ai.askAI) {
        return await ai.askAI(prompt, { systemPrompt, timeout: 20000 });
      }
    } catch {
      // Fall through to ollama
    }
  }

  // Default: use ollama
  const available = await isOllamaAvailable();
  if (!available) {
    throw new Error("Ollama runtime unavailable");
  }

  const models = await listModels();
  if (models.length === 0) {
    throw new Error("No Ollama models available");
  }

  return Promise.race([
    chat(
      [
        { role: "system", content: systemPrompt },
        { role: "user", content: prompt },
      ],
      { temperature: 0.2, model: model || undefined }
    ),
    new Promise<string>((_, reject) =>
      setTimeout(() => reject(new Error("Model response timeout")), 20000)
    ),
  ]);
}

function toolEnabled(agentTools: string[], key: string): boolean {
  return agentTools.some((tool) => tool.toLowerCase() === key);
}

function buildTargetIntelContext(targetIntel: Awaited<ReturnType<typeof gatherTargetIntel>>): string {
  if (targetIntel.targets.domains.length === 0 && targetIntel.targets.ips.length === 0) {
    return "No explicit domain/IP target found in user input.";
  }

  const lines: string[] = [];
  if (targetIntel.targets.urls.length > 0) {
    lines.push(`URLs: ${targetIntel.targets.urls.join(", ")}`);
  }
  if (targetIntel.targets.domains.length > 0) {
    lines.push(`Domains: ${targetIntel.targets.domains.join(", ")}`);
  }
  if (targetIntel.targets.ips.length > 0) {
    lines.push(`IPs: ${targetIntel.targets.ips.join(", ")}`);
  }

  for (const entry of targetIntel.dns) {
    const local = entry.local.map((rec) => `${rec.type}:${rec.value}`).join("; ") || "none";
    const cloud = entry.cloud_checks
      .map((check) => {
        const answers = check.answers.map((a) => `${a.type}:${a.value}`).join(", ");
        return `${check.provider}=${check.ok ? answers || "ok/no-answers" : `error:${check.error || "unknown"}`}`;
      })
      .join(" | ");
    const providerZone = entry.provider_zone_matches
      .map((match) => {
        if (!match.ok) {
          return `${match.provider}=error:${match.error || "unknown"}`;
        }
        return `${match.provider}=zone:${match.zone_dns_name}`;
      })
      .join(" | ");
    lines.push(
      `DNS ${entry.domain} -> local[${local}] cloud[${cloud}] accountZones[${providerZone || "none"}]`
    );
  }

  if (targetIntel.provider_account_checks.length > 0) {
    lines.push(
      `Cloud account checks: ${targetIntel.provider_account_checks
        .map((item) => `${item.provider}:${item.ok ? "ready" : "not-ready"} (${item.detail})`)
        .join(" | ")}`
    );
  }

  return lines.join("\n");
}

export async function executeAgentRun(job: AgentRunJob): Promise<void> {
  let step = 0;
  try {
    const agent = await getAgentById(job.userId, job.agentId);
    if (!agent) {
      await markRunFailed(job.runId, "Agent not found or no longer accessible.");
      return;
    }

    await markRunRunning(job.runId);
    await appendRunStep(
      job.runId,
      ++step,
      "init",
      "ok",
      "Run started and agent configuration loaded.",
      { agent_slug: agent.slug, version: agent.version }
    );

    const policy = evaluateRunPolicy(agent, job.inputText);
    await appendRunStep(
      job.runId,
      ++step,
      "guardrails",
      policy.allowed ? "ok" : "blocked",
      policy.allowed
        ? "Input passed guardrail checks."
        : "Input blocked by policy safeguards.",
      { warnings: policy.warnings, blocks: policy.blocks }
    );

    if (!policy.allowed) {
      await markRunBlocked(job.runId, policy.blocks.join(" "));
      return;
    }

    const sanitizedInput = redactSecrets(policy.sanitizedInput);
    let targetIntelContext = "Target intel not requested for this run.";

    if (
      toolEnabled(agent.tools_allowed, "dns") ||
      toolEnabled(agent.tools_allowed, "osint")
    ) {
      await appendRunStep(
        job.runId,
        ++step,
        "target-intel",
        "running",
        "Resolving domains/IPs and performing cloud DNS cross-check.",
        {}
      );
      const intel = await gatherTargetIntel(sanitizedInput);
      targetIntelContext = buildTargetIntelContext(intel);
      await addRunArtifact(
        job.runId,
        "target-intel",
        "Target Intelligence",
        JSON.stringify(intel, null, 2)
      );
      await appendRunStep(
        job.runId,
        ++step,
        "target-intel",
        "ok",
        "Target intelligence artifact generated.",
        {
          domains: intel.targets.domains.length,
          ips: intel.targets.ips.length,
        }
      );
    }

    const systemPrompt = `${agent.system_prompt}

Operational constraints:
- Allowed tools: ${agent.tools_allowed.join(", ")}
- Risk level: ${agent.risk_level}
- Autonomy mode: ${agent.autonomy_mode}
- Budget limit: ${agent.budget_limit}
- Memory policy: ${agent.memory_policy}

Target intelligence:
${targetIntelContext}
`;

    let output = "";
    let usedFallback = false;

    // Resolve LLM provider from agent config (inherit → provider → pinned)
    const resolved = resolveTaskProvider({
      config: agent.config?.ai,
      category: agent.category,
      surface: "agent",
    });

    const resolvedProviderId = resolved?.providerId || "ollama";
    const resolvedModel = resolved?.model || "";

    await appendRunStep(
      job.runId,
      ++step,
      "reasoning",
      "running",
      "Generating agent response with model runtime.",
      {
        model_profile: agent.model_profile,
        provider: resolvedProviderId,
        model: resolvedModel || "(default)",
      }
    );

    try {
      output = await runModel(
        systemPrompt,
        agent.task_prompt,
        sanitizedInput,
        resolvedProviderId,
        resolvedModel
      );
    } catch (err) {
      usedFallback = true;
      output = fallbackResponse(agent.name, sanitizedInput);
      await appendRunStep(
        job.runId,
        ++step,
        "reasoning",
        "degraded",
        "Model runtime unavailable; fallback response generated.",
        { error: (err as Error).message }
      );
    }

    await addRunArtifact(
      job.runId,
      "analysis",
      "Agent Output",
      output
    );
    await appendRunStep(
      job.runId,
      ++step,
      "artifact",
      "ok",
      "Primary analysis artifact stored.",
      { fallback: usedFallback }
    );

    const controlIds = buildControlIds(agent.category);
    for (const controlId of controlIds) {
      await addAuditEvidence(
        job.userId,
        job.runId,
        controlId.startsWith("SOC2") ? "SOC2" : "NIST/OWASP",
        controlId,
        `${agent.name} evidence`,
        `Generated by ${agent.slug} run ${job.runId}.`,
        [job.runId]
      );
    }
    await appendRunStep(
      job.runId,
      ++step,
      "evidence",
      "ok",
      "Mapped output to baseline control evidence records.",
      { control_ids: controlIds }
    );

    await upsertAgentMemory(job.userId, job.agentId, "last_run", {
      run_id: job.runId,
      completed_at: new Date().toISOString(),
      input_excerpt: sanitizedInput.slice(0, 200),
      output_excerpt: output.slice(0, 300),
      used_fallback: usedFallback,
    });
    await appendRunStep(
      job.runId,
      ++step,
      "memory",
      "ok",
      "Updated persistent memory with last-run context."
    );

    await markRunCompleted(job.runId, output);
  } catch (err) {
    await markRunFailed(job.runId, (err as Error).message || "Unknown executor error");
  }
}
