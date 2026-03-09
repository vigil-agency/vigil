/**
 * Campaigns Routes — Multi-agent campaigns + Purple Team Simulator
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { MITRE_TACTICS, SCENARIO_TYPES, runSimulation } = require('../lib/purple-team');

const DATA = path.join(__dirname, '..', 'data');
const CAMPAIGNS_PATH = path.join(DATA, 'campaigns.json');
const AGENTS_PATH = path.join(DATA, 'agents.json');
const RUNS_PATH = path.join(DATA, 'agent-runs.json');
const PURPLE_PATH = path.join(DATA, 'purple-team.json');

function readJSON(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return fallback; }
}
function writeJSON(p, data) {
  // Atomic write: temp file + rename
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + '.tmp.' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, p);
}

function escapeHtml(s) { return String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }

// Track running campaigns to support stop
const runningCampaigns = new Map();

module.exports = function (app, ctx) {
  const { requireAuth, requireRole, askAI } = ctx;

  // Select relevant agents for a goal
  function selectAgents(goal, maxAgents) {
    const agents = readJSON(AGENTS_PATH, []);
    const enabled = agents.filter(a => a.enabled);
    const goalLower = goal.toLowerCase();

    // Keyword matching per category
    const categoryKeywords = {
      recon: ['scan', 'port', 'discover', 'enumerate', 'subdomain', 'reconnaissance', 'surface'],
      appsec: ['web', 'app', 'xss', 'sql', 'injection', 'header', 'api', 'application'],
      cloud: ['aws', 'gcp', 'azure', 'cloud', 's3', 'iam', 'bucket', 'container'],
      iam: ['user', 'password', 'auth', 'access', 'identity', 'permission', 'privilege'],
      compliance: ['comply', 'compliance', 'pci', 'hipaa', 'soc', 'audit', 'regulation'],
      'incident-response': ['incident', 'breach', 'respond', 'playbook', 'contain', 'recover'],
      'threat-hunting': ['hunt', 'threat', 'ioc', 'compromise', 'anomaly', 'suspicious', 'malware'],
      forensics: ['forensic', 'evidence', 'memory', 'disk', 'artifact', 'investigate'],
      network: ['network', 'firewall', 'tls', 'ssl', 'dns', 'port', 'connection'],
      'data-security': ['data', 'sensitive', 'pii', 'classify', 'encrypt', 'leak'],
    };

    // Score each agent
    const scored = enabled.map(agent => {
      let score = 0;
      const keywords = categoryKeywords[agent.category] || [];
      for (const kw of keywords) {
        if (goalLower.includes(kw)) score += 2;
      }
      // Name/description match
      if (goalLower.includes(agent.name.toLowerCase())) score += 5;
      const descWords = (agent.description || '').toLowerCase().split(/\s+/);
      for (const word of descWords) {
        if (word.length > 3 && goalLower.includes(word)) score += 1;
      }
      return { agent, score };
    });

    scored.sort((a, b) => b.score - a.score);
    return scored.slice(0, maxAgents).filter(s => s.score > 0).map(s => s.agent);
  }

  // POST /api/campaigns — launch campaign
  app.post('/api/campaigns', requireRole('analyst'), async (req, res) => {
    try {
      const { goal, max_agents } = req.body;
      if (!goal) return res.status(400).json({ error: 'goal required' });
      const maxAgents = Math.min(parseInt(max_agents) || 5, 10);

      const selectedAgents = selectAgents(goal, maxAgents);
      if (selectedAgents.length === 0) {
        return res.status(400).json({ error: 'No matching agents found for this goal. Try a more specific description.' });
      }

      const campaign = {
        id: crypto.randomUUID(),
        goal: escapeHtml(goal),
        maxAgents,
        status: 'running',
        agents: selectedAgents.map(a => ({ id: a.id, name: a.name, category: a.category, status: 'pending' })),
        runs: [],
        createdAt: new Date().toISOString(),
        createdBy: req.user ? req.user.user : 'unknown',
      };

      const campaigns = readJSON(CAMPAIGNS_PATH, []);
      campaigns.push(campaign);
      writeJSON(CAMPAIGNS_PATH, campaigns);

      // Run agents sequentially in background
      let stopped = false;
      runningCampaigns.set(campaign.id, { stop: () => { stopped = true; } });

      (async () => {
        for (let i = 0; i < selectedAgents.length; i++) {
          if (stopped) break;

          const agent = selectedAgents[i];
          campaign.agents[i].status = 'running';

          // Save progress
          const allCampaigns = readJSON(CAMPAIGNS_PATH, []);
          const idx = allCampaigns.findIndex(c => c.id === campaign.id);
          if (idx >= 0) allCampaigns[idx] = campaign;
          writeJSON(CAMPAIGNS_PATH, allCampaigns);

          try {
            const prompt = agent.system_prompt + '\n\n' + agent.task_prompt.replace(/\{\{input\}\}/g, goal);
            const output = await askAI(prompt, { timeout: 60000 });

            const run = {
              id: crypto.randomUUID(),
              agentId: agent.id,
              agentName: agent.name,
              campaignId: campaign.id,
              input: goal.substring(0, 500),
              output: output || 'No output',
              status: 'completed',
              createdAt: new Date().toISOString(),
            };
            campaign.runs.push(run);
            campaign.agents[i].status = 'completed';

            // Also save to global runs
            const runs = readJSON(RUNS_PATH, []);
            runs.push(run);
            if (runs.length > 1000) runs.splice(0, runs.length - 1000);
            writeJSON(RUNS_PATH, runs);
          } catch (e) {
            campaign.agents[i].status = 'failed';
            campaign.runs.push({
              id: crypto.randomUUID(),
              agentId: agent.id,
              agentName: agent.name,
              campaignId: campaign.id,
              input: goal.substring(0, 500),
              output: 'Error: ' + e.message,
              status: 'failed',
              createdAt: new Date().toISOString(),
            });
          }
        }

        campaign.status = stopped ? 'stopped' : 'completed';
        campaign.completedAt = new Date().toISOString();
        runningCampaigns.delete(campaign.id);

        const allCampaigns = readJSON(CAMPAIGNS_PATH, []);
        const idx = allCampaigns.findIndex(c => c.id === campaign.id);
        if (idx >= 0) allCampaigns[idx] = campaign;
        writeJSON(CAMPAIGNS_PATH, allCampaigns);

        if (ctx.io) ctx.io.emit('campaign_complete', { id: campaign.id, status: campaign.status });
      })();

      res.json({ campaign: { id: campaign.id, goal: campaign.goal, status: campaign.status, agentCount: selectedAgents.length } });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/campaigns
  app.get('/api/campaigns', requireAuth, (req, res) => {
    const campaigns = readJSON(CAMPAIGNS_PATH, []);
    res.json({
      campaigns: campaigns.map(c => ({
        id: c.id, goal: c.goal, status: c.status,
        agentCount: c.agents ? c.agents.length : 0,
        runCount: c.runs ? c.runs.length : 0,
        createdAt: c.createdAt, completedAt: c.completedAt,
      })).reverse(),
    });
  });

  // GET /api/campaigns/:id
  app.get('/api/campaigns/:id', requireAuth, (req, res) => {
    const campaigns = readJSON(CAMPAIGNS_PATH, []);
    const campaign = campaigns.find(c => c.id === req.params.id);
    if (!campaign) return res.status(404).json({ error: 'Campaign not found' });
    res.json(campaign);
  });

  // POST /api/campaigns/:id/stop
  app.post('/api/campaigns/:id/stop', requireRole('analyst'), (req, res) => {
    const running = runningCampaigns.get(req.params.id);
    if (!running) return res.status(400).json({ error: 'Campaign is not running' });
    running.stop();
    runningCampaigns.delete(req.params.id);
    res.json({ success: true, message: 'Campaign stop signal sent' });
  });

  // ════════════════════════════════════════════════════════════════════════
  // PURPLE TEAM SIMULATOR — /api/campaigns/purple-team
  // ════════════════════════════════════════════════════════════════════════

  // GET /api/campaigns/purple-team/scenarios — list scenario types + MITRE tactics
  app.get('/api/campaigns/purple-team/scenarios', requireAuth, (req, res) => {
    res.json({ scenarios: SCENARIO_TYPES, tactics: MITRE_TACTICS });
  });

  // POST /api/campaigns/purple-team — launch purple team simulation
  app.post('/api/campaigns/purple-team', requireRole('analyst'), async (req, res) => {
    const { target, scope, scenario, defenses } = req.body;
    if (!target) return res.status(400).json({ error: 'target required' });

    const { askAIJSON } = ctx;
    if (!askAIJSON) return res.status(503).json({ error: 'AI provider not configured' });

    const sim = {
      id: crypto.randomUUID(),
      type: 'purple-team',
      target: escapeHtml(target),
      scope: escapeHtml(scope || ''),
      scenario: scenario || 'external-attacker',
      defenses: escapeHtml(defenses || ''),
      status: 'running',
      createdAt: new Date().toISOString(),
      createdBy: req.user ? req.user.user : 'unknown',
    };

    const sims = readJSON(PURPLE_PATH, []);
    sims.push(sim);
    writeJSON(PURPLE_PATH, sims);

    // Return immediately
    res.json({ id: sim.id, status: 'running' });

    // Run in background
    try {
      console.log(`  [PURPLE] Starting simulation ${sim.id} — ${scenario || 'external-attacker'} vs ${target}`);

      if (ctx.io) {
        ctx.io.emit('purple_team_progress', { id: sim.id, phase: 'starting', message: 'Initializing purple team simulation...' });
      }

      const result = await runSimulation({
        target,
        scope,
        scenario: scenario || 'external-attacker',
        defenses,
        askAIJSON,
        timeout: 120000,
        onProgress: (progress) => {
          if (ctx.io) {
            ctx.io.emit('purple_team_progress', { id: sim.id, ...progress });
          }
        },
      });

      sim.status = 'completed';
      sim.completedAt = new Date().toISOString();
      sim.duration = result.duration;
      sim.result = result;

      console.log(`  [PURPLE] Simulation ${sim.id} completed: grade ${result.summary.grade}, ${result.tactics.length} tactics analyzed (${result.duration}ms)`);
    } catch (e) {
      console.error(`  [PURPLE] Simulation ${sim.id} failed:`, e.message);
      sim.status = 'failed';
      sim.error = e.message;
      sim.completedAt = new Date().toISOString();
    }

    // Save
    const allSims = readJSON(PURPLE_PATH, []);
    const idx = allSims.findIndex(s => s.id === sim.id);
    if (idx >= 0) allSims[idx] = sim;
    writeJSON(PURPLE_PATH, allSims);

    if (ctx.io) {
      ctx.io.emit('purple_team_complete', {
        id: sim.id,
        status: sim.status,
        grade: sim.result?.summary?.grade,
        tacticsCount: sim.result?.tactics?.length || 0,
      });
    }
  });

  // GET /api/campaigns/purple-team — list simulations
  app.get('/api/campaigns/purple-team', requireAuth, (req, res) => {
    const sims = readJSON(PURPLE_PATH, []);
    res.json({
      simulations: sims.map(s => ({
        id: s.id, target: s.target, scenario: s.scenario, status: s.status,
        grade: s.result?.summary?.grade, score: s.result?.summary?.defenseScore,
        duration: s.duration, createdAt: s.createdAt,
      })).reverse(),
    });
  });

  // GET /api/campaigns/purple-team/:id — get simulation details (cached for completed)
  app.get('/api/campaigns/purple-team/:id', requireAuth, (req, res) => {
    const neuralCache = require('../lib/neural-cache');
    const cacheKey = 'purple:' + req.params.id;
    const cached = neuralCache.get(cacheKey);
    if (cached) return res.json(cached);

    const sims = readJSON(PURPLE_PATH, []);
    const sim = sims.find(s => s.id === req.params.id);
    if (!sim) return res.status(404).json({ error: 'Simulation not found' });

    // Cache completed simulations (immutable) for 10 minutes
    if (sim.status === 'completed' || sim.status === 'failed') {
      neuralCache.set(cacheKey, sim, 600000);
    }
    res.json(sim);
  });
};
