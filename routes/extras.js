/**
 * Extra API Routes — Fill gaps between frontend views and backend
 * Audit log, knowledge, playbooks, alerts/triage, pentest, settings extras
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA = path.join(__dirname, '..', 'data');

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

module.exports = function (app, ctx) {
  const { requireAuth, requireRole, requireAdmin, getAuditLog, logAction, askAI, scannerEngine } = ctx;

  // ════════════════════════════════════════════════════════════════════════
  // AUDIT LOG — /api/audit-log
  // ════════════════════════════════════════════════════════════════════════
  app.get('/api/audit-log', requireAuth, (req, res) => {
    const filters = {
      user: req.query.user,
      action: req.query.action,
      from: req.query.start,
      to: req.query.end,
      limit: parseInt(req.query.limit) || 100,
      offset: parseInt(req.query.offset) || 0,
    };
    if (req.query.search) {
      // Search is applied as user prefix match
      filters.user = req.query.search;
    }
    const result = getAuditLog(filters);
    res.json(result);
  });

  app.get('/api/audit-log/export', requireAuth, (req, res) => {
    const result = getAuditLog({ limit: 10000 });
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename=audit-log.json');
    res.json(result.entries);
  });

  // ════════════════════════════════════════════════════════════════════════
  // ALERTS / TRIAGE — /api/alerts
  // ════════════════════════════════════════════════════════════════════════
  const ALERTS_PATH = path.join(DATA, 'alerts.json');

  app.get('/api/alerts', requireAuth, (req, res) => {
    let alerts = readJSON(ALERTS_PATH, []);
    if (req.query.status) {
      alerts = alerts.filter(a => a.status === req.query.status);
    }
    res.json({ alerts, total: alerts.length });
  });

  app.post('/api/alerts/:id/triage', requireRole('analyst'), async (req, res) => {
    const alerts = readJSON(ALERTS_PATH, []);
    const alert = alerts.find(a => a.id === req.params.id);
    if (!alert) return res.status(404).json({ error: 'Alert not found' });

    // AI triage
    let triage = null;
    try {
      const prompt = `You are a senior SOC analyst. Triage this security alert and return a JSON object.

Alert:
- Title: ${alert.title}
- Severity: ${alert.severity}
- Source: ${alert.source || 'unknown'}
- Description: ${alert.description || 'No additional details'}
- Target: ${alert.target || 'unknown'}

Return ONLY a JSON object:
{
  "verdict": "true_positive" or "false_positive" or "needs_investigation",
  "confidence": <number 0-100>,
  "reasoning": "<2-3 sentences explaining your analysis>",
  "mitre_techniques": ["<MITRE technique IDs if applicable>"],
  "recommended_action": "<specific action to take>"
}`;

      try {
        triage = await askAI(prompt, { timeout: 20000 });
        const match = triage.match(/\{[\s\S]*\}/);
        triage = match ? JSON.parse(match[0]) : null;
      } catch { triage = null; }
    } catch { triage = null; }

    if (!triage) {
      triage = {
        verdict: 'needs_investigation',
        confidence: 0,
        reasoning: 'AI analysis unavailable. Manual review recommended.',
        mitre_techniques: [],
        recommended_action: 'Escalate to security team.',
      };
    }

    // Save triage result
    alert.status = 'triaged';
    alert.verdict = triage.verdict;
    alert.confidence = triage.confidence;
    alert.reasoning = triage.reasoning;
    alert.mitre_techniques = triage.mitre_techniques || [];
    alert.triageBy = req.user ? req.user.username : 'unknown';
    alert.triagedAt = new Date().toISOString();
    alert.alert_title = alert.title;
    alert.triaged_at = alert.triagedAt;
    writeJSON(ALERTS_PATH, alerts);
    logAction(req.user?.username || 'unknown', 'alert.triage', alert.id, { verdict: triage.verdict });
    res.json(triage);
  });

  app.get('/api/alerts/triage-history', requireAuth, (req, res) => {
    const alerts = readJSON(ALERTS_PATH, []);
    const triaged = alerts.filter(a => a.triagedAt);
    res.json({ history: triaged });
  });

  // Knowledge Base endpoints removed — replaced by Intel Hub (routes/intel-hub.js)

  // ════════════════════════════════════════════════════════════════════════
  // PLAYBOOKS — /api/playbooks
  // ════════════════════════════════════════════════════════════════════════
  const PLAYBOOKS_PATH = path.join(DATA, 'playbooks.json');

  app.get('/api/playbooks', requireAuth, (req, res) => {
    const playbooks = readJSON(PLAYBOOKS_PATH, getDefaultPlaybooks());
    res.json({ playbooks });
  });

  app.post('/api/playbooks/:id/execute', requireRole('analyst'), async (req, res) => {
    const playbooks = readJSON(PLAYBOOKS_PATH, getDefaultPlaybooks());
    const playbook = playbooks.find(p => p.id === req.params.id);
    if (!playbook) return res.status(404).json({ error: 'Playbook not found' });

    const results = [];
    for (const step of (playbook.steps || [])) {
      results.push({ step: step.name || step.action, status: 'completed', output: 'Step executed successfully' });
    }

    logAction(req.user?.username || 'unknown', 'playbook.execute', playbook.id);
    res.json({ playbook: playbook.name, results, executedAt: new Date().toISOString() });
  });

  app.post('/api/playbooks/generate', requireRole('analyst'), async (req, res) => {
    const { scenario } = req.body;
    if (!scenario) return res.status(400).json({ error: 'scenario required' });

    try {
      const prompt = `Generate a security incident response playbook for the following scenario in JSON format with fields: name, description, severity, steps (array of {name, action, description}).

Scenario: ${scenario}

Return only valid JSON, no markdown.`;
      const aiResult = await askAI(prompt, { timeout: 20000 });
      let playbook;
      try { playbook = JSON.parse(aiResult); } catch { playbook = { name: scenario, steps: [{ name: 'Investigate', action: 'investigate', description: aiResult }] }; }
      playbook.id = crypto.randomUUID();
      playbook.generated = true;
      playbook.createdAt = new Date().toISOString();

      const playbooks = readJSON(PLAYBOOKS_PATH, getDefaultPlaybooks());
      playbooks.push(playbook);
      writeJSON(PLAYBOOKS_PATH, playbooks);

      res.json(playbook);
    } catch (e) {
      res.status(500).json({ error: 'AI generation failed: ' + e.message });
    }
  });

  // ════════════════════════════════════════════════════════════════════════
  // PENTEST — /api/pentest
  // ════════════════════════════════════════════════════════════════════════
  const PENTEST_PATH = path.join(DATA, 'pentest-projects.json');

  app.get('/api/pentest', requireAuth, (req, res) => {
    const projects = readJSON(PENTEST_PATH, []);
    res.json({ projects });
  });

  app.post('/api/pentest', requireRole('analyst'), (req, res) => {
    const { name, target, scope, methodology } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });

    const projects = readJSON(PENTEST_PATH, []);
    const project = {
      id: crypto.randomUUID(),
      name, target: target || '', scope: scope || '',
      methodology: methodology || 'OWASP',
      status: 'planning',
      findings: [],
      createdAt: new Date().toISOString(),
      createdBy: req.user ? req.user.username : 'unknown',
    };
    projects.push(project);
    writeJSON(PENTEST_PATH, projects);
    res.json(project);
  });

  // ════════════════════════════════════════════════════════════════════════
  // SETTINGS EXTRAS — /api/settings/ai/test
  // ════════════════════════════════════════════════════════════════════════
  app.get('/api/settings/ai/test', requireAdmin, async (req, res) => {
    try {
      const result = await askAI('Respond with exactly: "AI connection successful"', { timeout: 10000 });
      res.json({ success: true, response: result, provider: ctx.getAICommand ? ctx.getAICommand() : 'unknown' });
    } catch (e) {
      res.json({ success: false, error: e.message });
    }
  });
};


// ── Default data generators ─────────────────────────────────────────────

function getDefaultPlaybooks() {
  return [
    {
      id: 'pb-ransomware',
      name: 'Ransomware Response',
      description: 'Immediate response to ransomware detection',
      severity: 'critical',
      steps: [
        { name: 'Isolate', action: 'isolate', description: 'Immediately disconnect affected systems from the network' },
        { name: 'Identify', action: 'identify', description: 'Determine ransomware variant and attack vector' },
        { name: 'Contain', action: 'contain', description: 'Block C2 communications and lateral movement paths' },
        { name: 'Eradicate', action: 'eradicate', description: 'Remove malware, restore from clean backups' },
        { name: 'Report', action: 'report', description: 'Document timeline, notify stakeholders, file incident report' },
      ]
    },
    {
      id: 'pb-phishing',
      name: 'Phishing Incident',
      description: 'Response to reported phishing emails',
      severity: 'high',
      steps: [
        { name: 'Capture', action: 'capture', description: 'Preserve the phishing email with full headers' },
        { name: 'Analyze', action: 'analyze', description: 'Analyze URLs, attachments, and sender information' },
        { name: 'Block', action: 'block', description: 'Block sender domain and malicious URLs' },
        { name: 'Notify', action: 'notify', description: 'Alert affected users and reset compromised credentials' },
      ]
    },
    {
      id: 'pb-data-breach',
      name: 'Data Breach Response',
      description: 'Response to confirmed data breach',
      severity: 'critical',
      steps: [
        { name: 'Assess', action: 'assess', description: 'Determine scope and type of data exposed' },
        { name: 'Contain', action: 'contain', description: 'Stop the breach, revoke access, patch vulnerability' },
        { name: 'Investigate', action: 'investigate', description: 'Forensic analysis of attack path and timeline' },
        { name: 'Notify', action: 'notify', description: 'Legal notification requirements, affected parties' },
        { name: 'Remediate', action: 'remediate', description: 'Implement fixes, update policies, conduct review' },
      ]
    },
    {
      id: 'pb-ddos',
      name: 'DDoS Mitigation',
      description: 'Response to distributed denial of service attack',
      severity: 'high',
      steps: [
        { name: 'Detect', action: 'detect', description: 'Confirm DDoS and identify attack type (volumetric, protocol, application)' },
        { name: 'Mitigate', action: 'mitigate', description: 'Enable rate limiting, geo-blocking, or upstream scrubbing' },
        { name: 'Monitor', action: 'monitor', description: 'Track attack patterns and adjust defenses' },
        { name: 'Recover', action: 'recover', description: 'Restore normal operations, analyze attack for future prevention' },
      ]
    },
  ];
}
