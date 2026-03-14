/**
 * Flows Routes — Security workflow automation with DAG execution
 * Port of arcline.pro flows API pattern
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DATA = path.join(__dirname, '..', 'data');
const FLOWS_PATH = path.join(DATA, 'flows.json');
const FLOW_RUNS_PATH = path.join(DATA, 'flow-runs.json');

function readJSON(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return fallback; }
}
function writeJSON(p, data) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + '.tmp.' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, p);
}

// Built-in security flow templates
const FLOW_TEMPLATES = [
  {
    slug: 'recon-pipeline', name: 'Recon Pipeline', category: 'recon',
    description: 'Automated recon: subdomain enum, port scan, critical finding alert',
    trigger_type: 'manual', difficulty: 'beginner', required_tools: ['dns', 'nmap'],
    nodes: [
      { id: 'start', type: 'start', data: { label: 'Start', config: {} }, position: { x: 250, y: 0 } },
      { id: 'subdomain', type: 'agent', data: { label: 'Subdomain Enum', config: { agentSlug: 'subdomain-enum' } }, position: { x: 250, y: 100 } },
      { id: 'portscan', type: 'agent', data: { label: 'Port Scan', config: { agentSlug: 'port-scanner' } }, position: { x: 250, y: 200 } },
      { id: 'check', type: 'condition', data: { label: 'Critical?', config: { expression: 'true' } }, position: { x: 250, y: 300 } },
      { id: 'notify', type: 'notify', data: { label: 'Alert', config: { message: 'Critical findings detected' } }, position: { x: 100, y: 400 } },
      { id: 'end', type: 'end', data: { label: 'End', config: {} }, position: { x: 250, y: 500 } },
    ],
    edges: [
      { id: 'e1', source: 'start', target: 'subdomain' },
      { id: 'e2', source: 'subdomain', target: 'portscan' },
      { id: 'e3', source: 'portscan', target: 'check' },
      { id: 'e4', source: 'check', target: 'notify', sourceHandle: 'true', label: 'true' },
      { id: 'e5', source: 'check', target: 'end', sourceHandle: 'false', label: 'false' },
      { id: 'e6', source: 'notify', target: 'end' },
    ],
  },
  {
    slug: 'compliance-check', name: 'Compliance Check', category: 'compliance',
    description: 'Sequential PCI DSS + HIPAA compliance analysis',
    trigger_type: 'manual', difficulty: 'beginner', required_tools: [],
    nodes: [
      { id: 'start', type: 'start', data: { label: 'Start', config: {} }, position: { x: 250, y: 0 } },
      { id: 'pci', type: 'agent', data: { label: 'PCI DSS', config: { agentSlug: 'pci-checker' } }, position: { x: 250, y: 100 } },
      { id: 'hipaa', type: 'agent', data: { label: 'HIPAA', config: { agentSlug: 'hipaa-checker' } }, position: { x: 250, y: 200 } },
      { id: 'end', type: 'end', data: { label: 'End', config: {} }, position: { x: 250, y: 300 } },
    ],
    edges: [
      { id: 'e1', source: 'start', target: 'pci' },
      { id: 'e2', source: 'pci', target: 'hipaa' },
      { id: 'e3', source: 'hipaa', target: 'end' },
    ],
  },
  {
    slug: 'incident-response', name: 'Incident Response', category: 'ops',
    description: 'Log analysis, malware detection, conditional escalation playbook',
    trigger_type: 'manual', difficulty: 'intermediate', required_tools: ['osint'],
    nodes: [
      { id: 'start', type: 'start', data: { label: 'Start', config: {} }, position: { x: 250, y: 0 } },
      { id: 'logs', type: 'agent', data: { label: 'Log Hunter', config: { agentSlug: 'log-hunter' } }, position: { x: 250, y: 100 } },
      { id: 'malware', type: 'agent', data: { label: 'Malware Analyzer', config: { agentSlug: 'malware-analyzer' } }, position: { x: 250, y: 200 } },
      { id: 'check', type: 'condition', data: { label: 'Malware?', config: { expression: 'true' } }, position: { x: 250, y: 300 } },
      { id: 'playbook', type: 'agent', data: { label: 'Playbook', config: { agentSlug: 'incident-playbook' } }, position: { x: 100, y: 400 } },
      { id: 'end', type: 'end', data: { label: 'End', config: {} }, position: { x: 250, y: 500 } },
    ],
    edges: [
      { id: 'e1', source: 'start', target: 'logs' },
      { id: 'e2', source: 'logs', target: 'malware' },
      { id: 'e3', source: 'malware', target: 'check' },
      { id: 'e4', source: 'check', target: 'playbook', sourceHandle: 'true', label: 'true' },
      { id: 'e5', source: 'check', target: 'end', sourceHandle: 'false', label: 'false' },
      { id: 'e6', source: 'playbook', target: 'end' },
    ],
  },
  {
    slug: 'vuln-triage', name: 'Vulnerability Triage', category: 'remediation',
    description: 'Scan, triage by severity, generate remediation plans for critical findings',
    trigger_type: 'manual', difficulty: 'intermediate', required_tools: [],
    nodes: [
      { id: 'start', type: 'start', data: { label: 'Start', config: {} }, position: { x: 250, y: 0 } },
      { id: 'headers', type: 'agent', data: { label: 'Header Audit', config: { agentSlug: 'header-auditor' } }, position: { x: 250, y: 100 } },
      { id: 'tls', type: 'agent', data: { label: 'TLS Analysis', config: { agentSlug: 'tls-analyzer' } }, position: { x: 250, y: 200 } },
      { id: 'end', type: 'end', data: { label: 'End', config: {} }, position: { x: 250, y: 300 } },
    ],
    edges: [
      { id: 'e1', source: 'start', target: 'headers' },
      { id: 'e2', source: 'headers', target: 'tls' },
      { id: 'e3', source: 'tls', target: 'end' },
    ],
  },
];

function seedFlows() {
  let flows = readJSON(FLOWS_PATH, null);
  if (!flows || flows.length === 0) {
    flows = FLOW_TEMPLATES.map(t => ({
      id: crypto.randomUUID(),
      ...t,
      status: 'draft',
      metadata: {},
      variables: {},
      error_strategy: 'stop',
      timeout_ms: 120000,
      max_retries: 0,
      version: 1,
      is_template: true,
      is_system: true,
      total_runs: 0,
      success_rate: 0,
      tags: [],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    }));
    writeJSON(FLOWS_PATH, flows);
  }

  // Append missing templates
  const existing = new Set(flows.map(f => f.slug));
  const missing = FLOW_TEMPLATES.filter(t => !existing.has(t.slug));
  if (missing.length > 0) {
    const newFlows = missing.map(t => ({
      id: crypto.randomUUID(),
      ...t,
      status: 'draft', metadata: {}, variables: {}, error_strategy: 'stop',
      timeout_ms: 120000, max_retries: 0, version: 1, is_template: true, is_system: true,
      total_runs: 0, success_rate: 0, tags: [], created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
    }));
    flows = [...flows, ...newFlows];
    writeJSON(FLOWS_PATH, flows);
  }

  return flows;
}

module.exports = function (app, ctx) {
  const { requireAuth, requireAdmin, requireRole, askAI, io } = ctx;

  // GET /api/flows — list flows
  app.get('/api/flows', requireAuth, (req, res) => {
    const flows = seedFlows();
    const runs = readJSON(FLOW_RUNS_PATH, []);
    const { status, category, trigger_type, query } = req.query;

    let result = flows.map(f => {
      const flowRuns = runs.filter(r => r.flowId === f.id);
      return { ...f, total_runs: flowRuns.length };
    });

    if (status) result = result.filter(f => f.status === status);
    if (category) result = result.filter(f => f.category === category);
    if (trigger_type) result = result.filter(f => f.trigger_type === trigger_type);
    if (query) {
      const q = query.toLowerCase();
      result = result.filter(f => (f.name || '').toLowerCase().includes(q) || (f.description || '').toLowerCase().includes(q));
    }

    res.json({ flows: result, total: result.length });
  });

  // POST /api/flows — create flow
  app.post('/api/flows', requireRole('analyst'), (req, res) => {
    const { name, slug, description, category, nodes, edges, trigger_type, metadata, variables, error_strategy, tags } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });

    const flows = readJSON(FLOWS_PATH, []);
    const autoSlug = slug || name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

    const flow = {
      id: crypto.randomUUID(),
      name, slug: autoSlug,
      description: description || '',
      category: category || 'general',
      status: 'draft',
      nodes: nodes || [
        { id: 'start', type: 'start', data: { label: 'Start', config: {} }, position: { x: 250, y: 0 } },
        { id: 'end', type: 'end', data: { label: 'End', config: {} }, position: { x: 250, y: 200 } },
      ],
      edges: edges || [{ id: 'e1', source: 'start', target: 'end' }],
      trigger_type: trigger_type || 'manual',
      trigger_config: {},
      metadata: metadata || {},
      variables: variables || {},
      error_strategy: error_strategy || 'stop',
      timeout_ms: 120000,
      max_retries: 0,
      version: 1,
      is_template: false,
      is_system: false,
      total_runs: 0,
      success_rate: 0,
      tags: tags || [],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    flows.push(flow);
    writeJSON(FLOWS_PATH, flows);
    res.json({ success: true, flow });
  });

  // GET /api/flows/templates
  app.get('/api/flows/templates', requireAuth, (req, res) => {
    res.json({ templates: FLOW_TEMPLATES });
  });

  // GET /api/flows/:id
  app.get('/api/flows/:id', requireAuth, (req, res) => {
    const flows = readJSON(FLOWS_PATH, []);
    const flow = flows.find(f => f.id === req.params.id || f.slug === req.params.id);
    if (!flow) return res.status(404).json({ error: 'Flow not found' });

    const runs = readJSON(FLOW_RUNS_PATH, []);
    flow.total_runs = runs.filter(r => r.flowId === flow.id).length;
    res.json(flow);
  });

  // PUT /api/flows/:id — update flow (with version bump on graph changes)
  app.put('/api/flows/:id', requireRole('analyst'), (req, res) => {
    const flows = readJSON(FLOWS_PATH, []);
    const flow = flows.find(f => f.id === req.params.id);
    if (!flow) return res.status(404).json({ error: 'Flow not found' });

    const { name, description, category, nodes, edges, trigger_type, trigger_config,
            metadata, variables, error_strategy, timeout_ms, max_retries, status, tags } = req.body;

    // Check if graph changed for version bump
    const nodesChanged = nodes !== undefined && JSON.stringify(nodes) !== JSON.stringify(flow.nodes);
    const edgesChanged = edges !== undefined && JSON.stringify(edges) !== JSON.stringify(flow.edges);

    if (name !== undefined) flow.name = name;
    if (description !== undefined) flow.description = description;
    if (category !== undefined) flow.category = category;
    if (nodes !== undefined) flow.nodes = nodes;
    if (edges !== undefined) flow.edges = edges;
    if (trigger_type !== undefined) flow.trigger_type = trigger_type;
    if (trigger_config !== undefined) flow.trigger_config = trigger_config;
    if (metadata !== undefined) flow.metadata = metadata;
    if (variables !== undefined) flow.variables = variables;
    if (error_strategy !== undefined) flow.error_strategy = error_strategy;
    if (timeout_ms !== undefined) flow.timeout_ms = timeout_ms;
    if (max_retries !== undefined) flow.max_retries = max_retries;
    if (status !== undefined) flow.status = status;
    if (tags !== undefined) flow.tags = tags;

    if (nodesChanged || edgesChanged) {
      flow.version = (flow.version || 1) + 1;
    }

    flow.updated_at = new Date().toISOString();
    writeJSON(FLOWS_PATH, flows);
    res.json({ success: true, flow });
  });

  // DELETE /api/flows/:id
  app.delete('/api/flows/:id', requireAdmin, (req, res) => {
    let flows = readJSON(FLOWS_PATH, []);
    const flow = flows.find(f => f.id === req.params.id);
    if (!flow) return res.status(404).json({ error: 'Flow not found' });
    if (flow.is_system) return res.status(400).json({ error: 'Cannot delete system template flows. Clone them instead.' });

    flows = flows.filter(f => f.id !== req.params.id);
    writeJSON(FLOWS_PATH, flows);
    res.json({ success: true });
  });

  // POST /api/flows/:id/execute — trigger flow execution
  app.post('/api/flows/:id/execute', requireRole('analyst'), async (req, res) => {
    try {
      const flows = readJSON(FLOWS_PATH, []);
      const flow = flows.find(f => f.id === req.params.id || f.slug === req.params.id);
      if (!flow) return res.status(404).json({ error: 'Flow not found' });

      const triggerPayload = req.body.trigger_payload || req.body.payload || {};

      // Simple sequential execution (no DAG library needed for JSON fallback)
      const run = {
        id: crypto.randomUUID(),
        flowId: flow.id,
        flowName: flow.name,
        status: 'running',
        trigger_type: flow.trigger_type,
        trigger_payload: triggerPayload,
        state: {},
        started_at: new Date().toISOString(),
        created_at: new Date().toISOString(),
      };

      const runs = readJSON(FLOW_RUNS_PATH, []);
      runs.push(run);
      writeJSON(FLOW_RUNS_PATH, runs);

      if (io) io.emit('flow:start', { runId: run.id, flowId: flow.id });

      // Execute nodes in order following edges
      const nodeMap = {};
      (flow.nodes || []).forEach(n => { nodeMap[n.id] = n; });

      const adj = {};
      (flow.edges || []).forEach(e => {
        if (!adj[e.source]) adj[e.source] = [];
        adj[e.source].push(e);
      });

      const startNode = (flow.nodes || []).find(n => n.type === 'start');
      if (!startNode) {
        run.status = 'failed';
        run.error_text = 'No start node';
        run.completed_at = new Date().toISOString();
        writeJSON(FLOW_RUNS_PATH, runs);
        return res.json({ run });
      }

      const visited = new Set();
      const queue = [startNode.id];
      const state = { trigger: triggerPayload };

      while (queue.length > 0) {
        const nodeId = queue.shift();
        if (visited.has(nodeId)) continue;
        visited.add(nodeId);

        const node = nodeMap[nodeId];
        if (!node) continue;

        run.current_node_id = nodeId;
        if (io) io.emit('flow:node_start', { runId: run.id, nodeId, label: node.data && node.data.label });

        // Execute by type
        let result = null;
        if (node.type === 'agent' && askAI) {
          const cfg = (node.data && node.data.config) || {};
          const prompt = 'As security agent ' + (cfg.agentSlug || 'unknown') + ', analyze: ' + JSON.stringify(triggerPayload).substring(0, 500);
          try {
            result = await askAI(prompt, { timeout: flow.timeout_ms || 120000 });
          } catch (e) {
            result = 'Agent execution failed: ' + e.message;
          }
        } else if (node.type === 'llm' && askAI) {
          const cfg = (node.data && node.data.config) || {};
          try {
            result = await askAI(cfg.prompt || 'Analyze', { timeout: flow.timeout_ms || 120000 });
          } catch (e) {
            result = 'LLM execution failed: ' + e.message;
          }
        } else if (node.type === 'condition') {
          result = true; // simplified - always true for now
        } else if (node.type === 'delay') {
          const ms = Math.min(((node.data && node.data.config && node.data.config.ms) || 1000), 30000);
          await new Promise(r => setTimeout(r, ms));
          result = { delayed: ms };
        } else if (node.type === 'notify') {
          const msg = (node.data && node.data.config && node.data.config.message) || 'Flow notification';
          if (ctx.sendNotification) ctx.sendNotification(msg);
          result = { notified: true };
        } else if (node.type === 'http') {
          const cfg = (node.data && node.data.config) || {};
          if (cfg.url) {
            try {
              const resp = await fetch(cfg.url, { method: cfg.method || 'GET' });
              result = await resp.text();
            } catch (e) {
              result = { error: e.message };
            }
          }
        }

        state[nodeId] = result;
        if (io) io.emit('flow:node_complete', { runId: run.id, nodeId, result: typeof result === 'string' ? result.substring(0, 200) : result });

        // Follow edges
        const outEdges = adj[nodeId] || [];
        for (const edge of outEdges) {
          queue.push(edge.target);
        }
      }

      run.status = 'completed';
      run.state = state;
      run.completed_at = new Date().toISOString();
      writeJSON(FLOW_RUNS_PATH, runs);

      if (io) io.emit('flow:complete', { runId: run.id, flowId: flow.id });

      res.json({ run });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/flows/:id/runs — run history
  app.get('/api/flows/:id/runs', requireAuth, (req, res) => {
    const runs = readJSON(FLOW_RUNS_PATH, []);
    const flowRuns = runs.filter(r => r.flowId === req.params.id).reverse();
    res.json({ runs: flowRuns.slice(0, 50) });
  });

  // GET /api/flows/runs/:runId — single run detail
  app.get('/api/flows/runs/:runId', requireAuth, (req, res) => {
    const runs = readJSON(FLOW_RUNS_PATH, []);
    const run = runs.find(r => r.id === req.params.runId);
    if (!run) return res.status(404).json({ error: 'Run not found' });
    res.json(run);
  });

  // POST /api/flows/:id/clone — clone a flow
  app.post('/api/flows/:id/clone', requireRole('analyst'), (req, res) => {
    const flows = readJSON(FLOWS_PATH, []);
    const source = flows.find(f => f.id === req.params.id);
    if (!source) return res.status(404).json({ error: 'Source flow not found' });

    const cloned = {
      ...JSON.parse(JSON.stringify(source)),
      id: crypto.randomUUID(),
      name: (req.body.name || source.name) + ' (Copy)',
      slug: source.slug + '-' + Date.now().toString(36),
      is_template: false,
      is_system: false,
      template_source_id: source.id,
      status: 'draft',
      version: 1,
      total_runs: 0,
      success_rate: 0,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    flows.push(cloned);
    writeJSON(FLOWS_PATH, flows);
    res.json({ success: true, flow: cloned });
  });
};
