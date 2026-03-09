/**
 * Vigil — P-E-R Engine (Planner-Executor-Reflector)
 * Inspired by LuaN1aoAgent's autonomous pentest architecture.
 *
 * Key innovations adapted:
 *   - Dual causal graph (task DAG + evidence reasoning chain)
 *   - L0-L5 failure attribution (structured failure analysis)
 *   - Scientific method loop (hypothesis -> experiment -> observation -> update)
 *   - Non-monotonic confidence propagation (logit/sigmoid)
 *   - Staged node review (executor proposes, reflector validates)
 */

const crypto = require('crypto');
const EventEmitter = require('events');

// ── Constants ─────────────────────────────────────────────────────────

const TASK_STATES = {
  PENDING: 'pending',
  READY: 'ready',
  RUNNING: 'running',
  COMPLETED: 'completed',
  FAILED: 'failed',
  DEPRECATED: 'deprecated',
  BLOCKED: 'blocked',
};

const HYPOTHESIS_STATES = {
  PENDING: 'pending',
  PLAUSIBLE: 'plausible',
  SUPPORTED: 'supported',
  CONFIRMED: 'confirmed',
  CONTRADICTED: 'contradicted',
  FALSIFIED: 'falsified',
};

const CAUSAL_TYPES = {
  EVIDENCE: 'evidence',
  HYPOTHESIS: 'hypothesis',
  POSSIBLE_VULN: 'possible_vuln',
  CONFIRMED_VULN: 'confirmed_vuln',
  KEY_FACT: 'key_fact',
};

const FAILURE_LEVELS = [
  { level: 0, name: 'Raw Observation', description: 'Uninterpreted tool output' },
  { level: 1, name: 'Tool Failure', description: 'Tool error — timeout, not found, permission denied' },
  { level: 2, name: 'Prerequisite Failure', description: 'Dependencies failed — auth expired, session invalid' },
  { level: 3, name: 'Environmental', description: 'External blocking — WAF, rate limiting, firewall' },
  { level: 4, name: 'Hypothesis Falsified', description: 'Attack vector proven wrong via evidence' },
  { level: 5, name: 'Strategy Flawed', description: 'Wrong attack path, fundamental replanning needed' },
];

const ENGINE_STATES = {
  INIT: 'init',
  PLANNING: 'planning',
  EXECUTING: 'executing',
  REFLECTING: 'reflecting',
  REPLANNING: 'replanning',
  COMPLETE: 'complete',
  HALTED: 'halted',
  ERROR: 'error',
};

// ── Task Graph (DAG) ──────────────────────────────────────────────────

class TaskGraph {
  constructor() {
    this.nodes = new Map();
    this.edges = [];
  }

  addTask(task) {
    const id = task.id || crypto.randomUUID();
    const node = {
      id, name: task.name,
      type: task.type || 'subtask',
      phase: task.phase || 'recon',
      tool: task.tool || null,
      params: task.params || {},
      dependencies: task.dependencies || [],
      priority: task.priority || 3,
      status: TASK_STATES.PENDING,
      result: null, error: null, failureLevel: null,
      startedAt: null, completedAt: null,
    };
    this.nodes.set(id, node);
    for (const dep of node.dependencies) {
      this.edges.push({ from: dep, to: id, type: 'depends_on' });
    }
    return node;
  }

  getReadyTasks() {
    const ready = [];
    for (const [, node] of this.nodes) {
      if (node.status !== TASK_STATES.PENDING) continue;
      const depsMet = node.dependencies.every(depId => {
        const dep = this.nodes.get(depId);
        return dep && dep.status === TASK_STATES.COMPLETED;
      });
      if (depsMet) {
        node.status = TASK_STATES.READY;
        ready.push(node);
      }
    }
    return ready.sort((a, b) => a.priority - b.priority);
  }

  completeTask(id, result) {
    const node = this.nodes.get(id);
    if (!node) return;
    node.status = TASK_STATES.COMPLETED;
    node.result = result;
    node.completedAt = new Date().toISOString();
  }

  failTask(id, error, failureLevel = 1) {
    const node = this.nodes.get(id);
    if (!node) return;
    node.status = TASK_STATES.FAILED;
    node.error = error;
    node.failureLevel = failureLevel;
    node.completedAt = new Date().toISOString();
  }

  getStats() {
    const s = { total: 0, pending: 0, ready: 0, running: 0, completed: 0, failed: 0, deprecated: 0, blocked: 0 };
    for (const [, node] of this.nodes) { s.total++; s[node.status] = (s[node.status] || 0) + 1; }
    return s;
  }

  toJSON() {
    return { nodes: Array.from(this.nodes.values()), edges: this.edges, stats: this.getStats() };
  }
}

// ── Causal Graph (Evidence Chain) ─────────────────────────────────────

class CausalGraph {
  constructor() {
    this.nodes = new Map();
    this.edges = [];
    this.staged = [];
  }

  addEvidence(data) {
    return this._addNode({ ...data, type: CAUSAL_TYPES.EVIDENCE, confidence: 1.0 });
  }

  addHypothesis(data) {
    return this._addNode({ ...data, type: CAUSAL_TYPES.HYPOTHESIS, status: HYPOTHESIS_STATES.PENDING, confidence: data.confidence || 0.5 });
  }

  addVulnerability(data) {
    const type = data.confirmed ? CAUSAL_TYPES.CONFIRMED_VULN : CAUSAL_TYPES.POSSIBLE_VULN;
    return this._addNode({ ...data, type, confidence: data.confidence || (data.confirmed ? 0.9 : 0.5) });
  }

  stageNode(data) {
    const node = { id: crypto.randomUUID(), stagedAt: new Date().toISOString(), ...data };
    this.staged.push(node);
    if (this.staged.length > 30) {
      this.staged.sort((a, b) => (b.priority || 0) - (a.priority || 0));
      this.staged = this.staged.slice(0, 30);
    }
    return node;
  }

  commitStagedNodes(ids) {
    const committed = [];
    for (const id of ids) {
      const idx = this.staged.findIndex(n => n.id === id);
      if (idx >= 0) {
        const node = this.staged.splice(idx, 1)[0];
        this._addNode(node);
        committed.push(node);
      }
    }
    return committed;
  }

  rejectStagedNodes(ids) {
    this.staged = this.staged.filter(n => !ids.includes(n.id));
  }

  addEdge(fromId, toId, type, strength = 'contingent') {
    this.edges.push({ from: fromId, to: toId, type, strength });
  }

  updateConfidence(nodeId, delta, strength = 'contingent') {
    const node = this.nodes.get(nodeId);
    if (!node) return;
    if (strength === 'necessary') {
      node.confidence = delta > 0 ? 1.0 : 0.0;
    } else {
      const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
      const p = clamp(node.confidence, 0.01, 0.99);
      const logit = Math.log(p / (1 - p));
      node.confidence = 1 / (1 + Math.exp(-(logit + delta)));
    }
    if (node.type === CAUSAL_TYPES.HYPOTHESIS) {
      if (node.confidence >= 0.9) node.status = HYPOTHESIS_STATES.CONFIRMED;
      else if (node.confidence >= 0.7) node.status = HYPOTHESIS_STATES.SUPPORTED;
      else if (node.confidence >= 0.3) node.status = HYPOTHESIS_STATES.PLAUSIBLE;
      else if (node.confidence >= 0.1) node.status = HYPOTHESIS_STATES.CONTRADICTED;
      else node.status = HYPOTHESIS_STATES.FALSIFIED;
    }
  }

  getFindings() {
    const findings = [];
    for (const [, node] of this.nodes) {
      if (node.type === CAUSAL_TYPES.CONFIRMED_VULN || (node.type === CAUSAL_TYPES.POSSIBLE_VULN && node.confidence >= 0.7)) {
        findings.push(node);
      }
    }
    return findings.sort((a, b) => b.confidence - a.confidence);
  }

  getStats() {
    const s = { evidence: 0, hypotheses: 0, possibleVulns: 0, confirmedVulns: 0, keyFacts: 0, edges: this.edges.length, staged: this.staged.length };
    for (const [, node] of this.nodes) {
      if (node.type === CAUSAL_TYPES.EVIDENCE) s.evidence++;
      else if (node.type === CAUSAL_TYPES.HYPOTHESIS) s.hypotheses++;
      else if (node.type === CAUSAL_TYPES.POSSIBLE_VULN) s.possibleVulns++;
      else if (node.type === CAUSAL_TYPES.CONFIRMED_VULN) s.confirmedVulns++;
      else if (node.type === CAUSAL_TYPES.KEY_FACT) s.keyFacts++;
    }
    return s;
  }

  _addNode(data) {
    const id = data.id || crypto.randomUUID();
    const node = { id, createdAt: new Date().toISOString(), ...data };
    this.nodes.set(id, node);
    return node;
  }

  toJSON() {
    return { nodes: Array.from(this.nodes.values()), edges: this.edges, staged: this.staged, stats: this.getStats() };
  }
}

// ── P-E-R Engine ──────────────────────────────────────────────────────

class PEREngine extends EventEmitter {
  constructor(opts = {}) {
    super();
    this.id = crypto.randomUUID();
    this.target = opts.target;
    this.scope = opts.scope || '';
    this.depth = opts.depth || 'standard';
    this.state = ENGINE_STATES.INIT;
    this.cycle = 0;
    this.maxCycles = opts.depth === 'quick' ? 3 : opts.depth === 'deep' ? 8 : 5;
    this.taskGraph = new TaskGraph();
    this.causalGraph = new CausalGraph();
    this.findings = [];
    this.report = null;
    this.timeline = [];
    this.halted = false;
    this.startedAt = null;
    this.completedAt = null;
    this.error = null;
    this.askAI = opts.askAI;
    this.askAIJSON = opts.askAIJSON;
    this.execFileSafe = opts.execFileSafe;
    this.execCommand = opts.execCommand;
  }

  async run() {
    this.startedAt = new Date().toISOString();
    this._log('Engine started', 'Target: ' + this.target + ', Depth: ' + this.depth);
    this.emit('progress', { phase: 'init', message: 'Autonomous pentest starting...' });

    try {
      await this._plan();

      while (this.cycle < this.maxCycles && !this.halted) {
        this.cycle++;
        this._log('Cycle ' + this.cycle, 'P-E-R cycle ' + this.cycle + '/' + this.maxCycles);

        await this._execute();
        if (this.halted) break;

        await this._reflect();
        if (this.halted) break;

        const stats = this.taskGraph.getStats();
        if (stats.pending === 0 && stats.ready === 0 && stats.running === 0) {
          this._log('All tasks complete', stats.completed + ' completed, ' + stats.failed + ' failed');
          break;
        }

        if (this.cycle < this.maxCycles) await this._replan();
      }

      await this._globalReflect();
      this.state = ENGINE_STATES.COMPLETE;
      this.completedAt = new Date().toISOString();
      this._log('Engine complete', this.findings.length + ' findings, ' + this.cycle + ' cycles');
      this.emit('complete', this.getResults());
    } catch (err) {
      this.state = ENGINE_STATES.ERROR;
      this.error = err.message;
      this.completedAt = new Date().toISOString();
      this._log('Engine error', err.message);
      this.emit('error', err);
    }
    return this.getResults();
  }

  halt() {
    this.halted = true;
    this.state = ENGINE_STATES.HALTED;
    this._log('Engine halted', 'Manual halt requested');
    this.emit('halted');
  }

  // ── PLANNER ────────────────────────────────────────────────────────

  async _plan() {
    this.state = ENGINE_STATES.PLANNING;
    this.emit('progress', { phase: 'planning', message: 'AI Planner decomposing target...' });

    const prompt = 'You are a penetration test planner using the Planner-Executor-Reflector framework.\n\n' +
      'Target: ' + this.target + '\nScope: ' + (this.scope || 'Full scope') + '\nDepth: ' + this.depth + '\n\n' +
      'Decompose this target into a DAG of security testing subtasks.\n' +
      'Each subtask should use one of these tools: nmap, nuclei, nikto, dig, whois, openssl, curl.\n\n' +
      'Rules:\n- Create 2-4 initial recon subtasks (no dependencies)\n' +
      '- Create scanning subtasks that depend on recon results\n' +
      '- Each task: name, phase (recon/scanning/exploitation), tool, params { target, flags }, dependencies (task indices), priority (1-5)\n' +
      (this.depth === 'quick' ? '- Keep it minimal: 3-5 total tasks\n' : this.depth === 'deep' ? '- Be thorough: 8-12 tasks covering all vectors\n' : '- Standard depth: 5-8 tasks\n') +
      '\nRespond with valid JSON:\n{\n  "strategy": "1-2 sentence strategy",\n  "tasks": [\n    { "name": "...", "phase": "recon", "tool": "nmap", "params": { "target": "' + this.target + '", "flags": "-Pn -sV -T4 --top-ports 1000" }, "dependencies": [], "priority": 1 }\n  ]\n}';

    let plan;
    if (this.askAIJSON) {
      try { plan = await this.askAIJSON(prompt, { timeout: 60000 }); } catch { /* fallback */ }
    }
    if (!plan || !plan.tasks || plan.tasks.length === 0) plan = this._defaultPlan();

    const taskIds = [];
    for (const t of plan.tasks) {
      const deps = (t.dependencies || []).map(i => taskIds[i]).filter(Boolean);
      const node = this.taskGraph.addTask({
        name: t.name, phase: t.phase || 'recon', tool: t.tool,
        params: t.params || {}, dependencies: deps, priority: t.priority || 3,
      });
      taskIds.push(node.id);
    }

    this._log('Plan created', plan.tasks.length + ' tasks — ' + (plan.strategy || 'default'));
    this.emit('progress', { phase: 'planning', message: 'Plan: ' + plan.tasks.length + ' tasks' });
  }

  _defaultPlan() {
    const t = this.target;
    return {
      strategy: 'Standard recon-scan pipeline',
      tasks: [
        { name: 'Port scan (top 1000)', phase: 'recon', tool: 'nmap', params: { target: t, flags: '-Pn -sV -T4 --top-ports 1000' }, dependencies: [], priority: 1 },
        { name: 'DNS reconnaissance', phase: 'recon', tool: 'dig', params: { target: t, flags: 'ANY +noall +answer' }, dependencies: [], priority: 2 },
        { name: 'SSL/TLS check', phase: 'recon', tool: 'openssl', params: { target: t }, dependencies: [], priority: 2 },
        { name: 'Vulnerability scan', phase: 'scanning', tool: 'nuclei', params: { target: t, flags: '-severity critical,high -silent' }, dependencies: [0], priority: 1 },
      ],
    };
  }

  // ── EXECUTOR ───────────────────────────────────────────────────────

  async _execute() {
    this.state = ENGINE_STATES.EXECUTING;
    const readyTasks = this.taskGraph.getReadyTasks();
    if (readyTasks.length === 0) return;

    this.emit('progress', { phase: 'executing', message: 'Executing ' + readyTasks.length + ' tasks...' });

    for (const task of readyTasks) {
      if (this.halted) break;
      task.status = TASK_STATES.RUNNING;
      task.startedAt = new Date().toISOString();
      this.emit('progress', { phase: 'executing', message: 'Running: ' + task.name + ' (' + task.tool + ')', taskId: task.id });

      try {
        const result = await this._executeTool(task);
        this.taskGraph.completeTask(task.id, result);

        const evidence = this.causalGraph.addEvidence({
          name: task.name + ' result', source: task.tool, taskId: task.id,
          summary: result.summary || '', raw: (result.raw || '').substring(0, 5000),
        });

        if (result.hypotheses) {
          for (const h of result.hypotheses) {
            this.causalGraph.stageNode({
              type: CAUSAL_TYPES.HYPOTHESIS, name: h.name, description: h.description,
              confidence: h.confidence || 0.5, status: HYPOTHESIS_STATES.PLAUSIBLE,
              evidenceId: evidence.id, priority: h.priority || 1,
            });
          }
        }
        this._log('Task completed', task.name + ': ' + (result.summary || 'done'));
      } catch (err) {
        const fl = this._classifyFailure(err);
        this.taskGraph.failTask(task.id, err.message, fl);
        this._log('Task failed', task.name + ': L' + fl + ' - ' + err.message);
      }
    }
  }

  async _executeTool(task) {
    const { tool, params } = task;
    const target = params.target || this.target;
    if (!/^[a-zA-Z0-9.\-:\/]+$/.test(target)) throw new Error('Invalid target format');

    let stdout = '', stderr = '';

    switch (tool) {
      case 'nmap': {
        const flags = (params.flags || '-Pn -T4 --top-ports 100').split(/\s+/).filter(Boolean);
        const r = await this.execFileSafe('nmap', [...flags, target], { timeout: 120000 });
        stdout = r.stdout || ''; stderr = r.stderr || '';
        break;
      }
      case 'nuclei': {
        const flags = (params.flags || '-severity critical,high -silent').split(/\s+/).filter(Boolean);
        const r = await this.execFileSafe('nuclei', ['-u', target, ...flags], { timeout: 300000 });
        stdout = r.stdout || ''; stderr = r.stderr || '';
        break;
      }
      case 'nikto': {
        const r = await this.execFileSafe('nikto', ['-h', target, '-Tuning', '123', '-maxtime', '120s'], { timeout: 180000 });
        stdout = r.stdout || ''; stderr = r.stderr || '';
        break;
      }
      case 'dig': {
        const safe = target.replace(/[^a-zA-Z0-9.\-]/g, '');
        const flags = (params.flags || 'ANY +noall +answer').split(/\s+/).filter(Boolean);
        const r = await this.execFileSafe('dig', [safe, ...flags], { timeout: 15000 });
        stdout = r.stdout || '';
        break;
      }
      case 'whois': {
        const safe = target.replace(/[^a-zA-Z0-9.\-]/g, '');
        const r = await this.execFileSafe('whois', [safe], { timeout: 15000 });
        stdout = r.stdout || '';
        break;
      }
      case 'openssl': {
        const safe = target.replace(/[^a-zA-Z0-9.\-]/g, '');
        const r = await this.execCommand(
          'echo | openssl s_client -servername ' + safe + ' -connect ' + safe + ':443 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null',
          { timeout: 15000 });
        stdout = r.stdout || '';
        break;
      }
      case 'curl': {
        const safe = target.replace(/[^a-zA-Z0-9.\-:\/\?&=_]/g, '');
        const r = await this.execFileSafe('curl', ['-sS', '-o', '/dev/null', '-w', '%{http_code} %{content_type} %{redirect_url}', '-D-', '--max-time', '10', safe], { timeout: 15000 });
        stdout = r.stdout || '';
        break;
      }
      default:
        throw new Error('Unknown tool: ' + tool);
    }

    // AI analysis of tool output
    let summary = '', hypotheses = [];
    if (this.askAIJSON && stdout.length > 10) {
      try {
        const analysis = await this.askAIJSON(
          'Analyze this ' + tool + ' output from a penetration test against ' + target + '.\n' +
          'Extract:\n1. Brief summary (1-2 sentences)\n2. Security hypotheses to investigate\n\n' +
          'Output:\n' + stdout.substring(0, 8000) + '\n\n' +
          'Respond with JSON:\n{ "summary": "...", "hypotheses": [{ "name": "...", "description": "...", "confidence": 0.5, "priority": 1 }] }',
          { timeout: 30000 });
        summary = analysis?.summary || '';
        hypotheses = analysis?.hypotheses || [];
      } catch { summary = stdout.substring(0, 200); }
    } else {
      summary = stdout.substring(0, 200);
    }

    return { summary, raw: stdout, stderr, hypotheses };
  }

  _classifyFailure(err) {
    const m = (err.message || '').toLowerCase();
    if (m.includes('timeout') || m.includes('enoent') || m.includes('not found')) return 1;
    if (m.includes('auth') || m.includes('permission') || m.includes('403')) return 2;
    if (m.includes('waf') || m.includes('rate limit') || m.includes('blocked') || m.includes('429')) return 3;
    if (m.includes('not vulnerable') || m.includes('no results')) return 4;
    return 1;
  }

  // ── REFLECTOR ──────────────────────────────────────────────────────

  async _reflect() {
    this.state = ENGINE_STATES.REFLECTING;
    this.emit('progress', { phase: 'reflecting', message: 'AI Reflector auditing results...' });

    const completed = Array.from(this.taskGraph.nodes.values()).filter(n => n.status === TASK_STATES.COMPLETED && n.completedAt);
    const failed = Array.from(this.taskGraph.nodes.values()).filter(n => n.status === TASK_STATES.FAILED);
    const staged = this.causalGraph.staged;

    if (completed.length === 0 && failed.length === 0) return;

    const taskSums = completed.map(t => '[DONE] ' + t.name + ': ' + (t.result?.summary || '').substring(0, 200)).join('\n');
    const failSums = failed.map(t => '[FAIL L' + t.failureLevel + '] ' + t.name + ': ' + t.error).join('\n');
    const stagedSums = staged.map(n => '[STAGED ' + n.type + '] ' + n.name + ': ' + (n.description || '') + ' (conf: ' + (n.confidence || 'N/A') + ')').join('\n');

    if (this.askAIJSON) {
      try {
        const reflection = await this.askAIJSON(
          'You are a security reflector auditing penetration test results.\n\n' +
          'Target: ' + this.target + '\nCycle: ' + this.cycle + '/' + this.maxCycles + '\n\n' +
          'Completed Tasks:\n' + (taskSums || 'None') + '\n\n' +
          'Failed Tasks:\n' + (failSums || 'None') + '\n\n' +
          'Staged Hypotheses (review each):\n' + (stagedSums || 'None') + '\n\n' +
          'Your job:\n1. Review staged hypotheses - approve (solid evidence) or reject (hallucinated/weak)\n' +
          '2. Identify confirmed or probable vulnerabilities from evidence\n' +
          '3. Classify failures using L0-L5 attribution (L0=raw, L1=tool, L2=prereq, L3=env, L4=falsified, L5=strategy)\n' +
          '4. Extract key security facts\n5. Determine if assessment is complete\n\n' +
          'Respond with JSON:\n{\n  "approvedNodes": [],\n  "rejectedNodes": [],\n' +
          '  "findings": [{ "title": "...", "severity": "critical|high|medium|low|info", "confidence": 0.9, "details": "...", "evidence": "...", "remediation": "..." }],\n' +
          '  "keyFacts": [],\n  "goalAchieved": false,\n  "nextSteps": []\n}',
          { timeout: 45000 });

        if (reflection) {
          if (reflection.approvedNodes?.length) this.causalGraph.commitStagedNodes(reflection.approvedNodes);
          if (reflection.rejectedNodes?.length) this.causalGraph.rejectStagedNodes(reflection.rejectedNodes);
          if (reflection.findings) {
            for (const f of reflection.findings) {
              this.causalGraph.addVulnerability({
                name: f.title, severity: f.severity, confidence: f.confidence || 0.8,
                details: f.details, evidence: f.evidence, remediation: f.remediation,
                confirmed: (f.confidence || 0) >= 0.9,
              });
              this.findings.push({ ...f, cycle: this.cycle, foundAt: new Date().toISOString() });
            }
          }
          if (reflection.keyFacts) {
            for (const fact of reflection.keyFacts) {
              this.causalGraph._addNode({ type: CAUSAL_TYPES.KEY_FACT, name: fact, confidence: 1.0 });
            }
          }
          if (reflection.goalAchieved) {
            this.halted = true;
            this._log('Goal achieved', 'Reflector determined assessment is complete');
          }
        }
      } catch (err) {
        this._log('Reflection error', err.message);
      }
    } else {
      // Without AI: auto-approve all staged nodes
      this.causalGraph.commitStagedNodes(staged.map(n => n.id));
    }

    this._log('Reflection complete', 'Cycle ' + this.cycle + ': ' + this.findings.length + ' total findings');
  }

  // ── REPLANNER ──────────────────────────────────────────────────────

  async _replan() {
    this.state = ENGINE_STATES.REPLANNING;
    const stats = this.taskGraph.getStats();
    if (stats.pending === 0 && stats.failed === 0) return;
    if (!this.askAIJSON) return;

    this.emit('progress', { phase: 'replanning', message: 'AI Planner adapting strategy...' });

    try {
      const findings = this.causalGraph.getFindings();
      const keyFacts = Array.from(this.causalGraph.nodes.values()).filter(n => n.type === CAUSAL_TYPES.KEY_FACT);
      const failedTasks = Array.from(this.taskGraph.nodes.values()).filter(n => n.status === 'failed');

      const replan = await this.askAIJSON(
        'You are a penetration test replanner.\n\n' +
        'Target: ' + this.target + '\nCycle: ' + this.cycle + '/' + this.maxCycles + '\n\n' +
        'Task Stats: ' + JSON.stringify(stats) + '\n\n' +
        'Key Findings:\n' + (findings.map(f => '- ' + f.name + ' (' + f.severity + ', conf: ' + ((f.confidence * 100).toFixed(0)) + '%)').join('\n') || 'None') + '\n\n' +
        'Key Facts:\n' + (keyFacts.map(f => '- ' + f.name).join('\n') || 'None') + '\n\n' +
        'Failed Tasks:\n' + (failedTasks.map(n => '- ' + n.name + ': L' + n.failureLevel + ' - ' + n.error).join('\n') || 'None') + '\n\n' +
        'Add new tasks that build on what we learned. Do NOT repeat completed tasks.\n' +
        'Tools: nmap, nuclei, nikto, dig, whois, openssl, curl\n\n' +
        'Respond with JSON:\n{ "addTasks": [{ "name": "...", "phase": "scanning|exploitation", "tool": "...", "params": { "target": "' + this.target + '", "flags": "..." }, "priority": 2 }], "reasoning": "why" }',
        { timeout: 30000 });

      if (replan?.addTasks?.length) {
        const completedIds = Array.from(this.taskGraph.nodes.values())
          .filter(n => n.status === TASK_STATES.COMPLETED).map(n => n.id);
        for (const t of replan.addTasks) {
          this.taskGraph.addTask({
            name: t.name, phase: t.phase || 'scanning', tool: t.tool,
            params: t.params || {}, priority: t.priority || 3,
            dependencies: completedIds.length > 0 ? [completedIds[completedIds.length - 1]] : [],
          });
        }
        this._log('Replan', 'Added ' + replan.addTasks.length + ' tasks: ' + (replan.reasoning || ''));
      }
    } catch (err) {
      this._log('Replan error', err.message);
    }
  }

  // ── GLOBAL REFLECTION ──────────────────────────────────────────────

  async _globalReflect() {
    this.emit('progress', { phase: 'reflecting', message: 'Final assessment...' });
    if (!this.askAIJSON) return;

    try {
      this.report = await this.askAIJSON(
        'Produce a final penetration test assessment.\n\n' +
        'Target: ' + this.target + '\nScope: ' + (this.scope || 'Full') + '\nCycles: ' + this.cycle + '\n' +
        'Tasks: ' + JSON.stringify(this.taskGraph.getStats()) + '\n' +
        'Causal Graph: ' + JSON.stringify(this.causalGraph.getStats()) + '\n\n' +
        'Findings:\n' + (this.findings.map(f => '- [' + f.severity + '] ' + f.title + ': ' + (f.details || '').substring(0, 200)).join('\n') || 'No findings') + '\n\n' +
        'Produce JSON:\n{\n  "summary": "executive summary",\n  "riskRating": "critical|high|medium|low",\n' +
        '  "attackPaths": ["path1"],\n  "recommendations": ["rec1", "rec2"],\n  "confidence": 0.8\n}',
        { timeout: 45000 });
    } catch (err) {
      this._log('Global reflection error', err.message);
    }
  }

  _log(event, detail) {
    this.timeline.push({ event, detail, timestamp: new Date().toISOString(), cycle: this.cycle, state: this.state });
  }

  getResults() {
    return {
      id: this.id, target: this.target, scope: this.scope, depth: this.depth,
      state: this.state, cycle: this.cycle, maxCycles: this.maxCycles,
      findings: this.findings, report: this.report || null,
      taskGraph: this.taskGraph.toJSON(), causalGraph: this.causalGraph.toJSON(),
      timeline: this.timeline,
      startedAt: this.startedAt, completedAt: this.completedAt, error: this.error,
      failureLevels: FAILURE_LEVELS,
    };
  }
}

// ── Factory ──────────────────────────────────────────────────────────

function createPEREngine(opts) { return new PEREngine(opts); }

module.exports = {
  createPEREngine, PEREngine, TaskGraph, CausalGraph,
  TASK_STATES, HYPOTHESIS_STATES, CAUSAL_TYPES, FAILURE_LEVELS, ENGINE_STATES,
};
