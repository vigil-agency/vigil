/**
 * Ephemeral Infrastructure Routes — Disposable proxy node + tunnel management
 * Inspired by fluffy-barnacle (Codespace proxies) + pgrok (SSH tunnels + callback listeners).
 *
 * Manages: GitHub Codespace proxies, SSH tunnels (forward/reverse/dynamic),
 * and OOB callback listeners for vulnerability detection.
 */
const proxy = require('../lib/ephemeral-proxy');
const tunnelMgr = require('../lib/tunnel-manager');

module.exports = function (app, ctx) {
  const { requireAuth, requireRole, askAIJSON, io } = ctx;

  // ── Specific routes MUST come before :name param route ──

  // GET /api/proxy-nodes/health — prerequisites check
  app.get('/api/proxy-nodes/health', requireRole('analyst'), async (req, res) => {
    try {
      const gh = await proxy.checkGHInstalled();
      const auth = gh.installed ? await proxy.checkGHAuth() : { authenticated: false, user: null, detail: 'gh CLI not installed' };
      const proxyHealth = await proxy.checkProxyHealth();
      res.json({ gh, auth, proxyListening: proxyHealth });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/proxy-nodes/auth — authenticate gh CLI with a PAT (non-interactive)
  app.post('/api/proxy-nodes/auth', requireRole('admin'), async (req, res) => {
    const { token } = req.body;
    if (!token || typeof token !== 'string' || token.length < 10) {
      return res.status(400).json({ error: 'A valid GitHub Personal Access Token is required' });
    }
    try {
      await proxy.authenticateWithToken(token.trim());
      const auth = await proxy.checkGHAuth();
      require('../lib/neural-cache').invalidate('proxy:nodes');
      if (io) io.emit('proxy_node_update', { action: 'authenticated' });
      res.json({ success: true, auth });
    } catch (e) {
      res.status(500).json({ error: 'Authentication failed: ' + e.message });
    }
  });

  // POST /api/proxy-nodes/sync — sync with actual Codespace state
  app.post('/api/proxy-nodes/sync', requireRole('analyst'), async (req, res) => {
    try {
      const nodes = await proxy.syncNodes();
      res.json({ nodes, synced: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/proxy-nodes/ai-plan — AI infrastructure planner
  app.post('/api/proxy-nodes/ai-plan', requireRole('analyst'), async (req, res) => {
    const { engagement } = req.body;
    if (!engagement || typeof engagement !== 'string') {
      return res.status(400).json({ error: 'engagement description required' });
    }

    if (!askAIJSON) return res.status(503).json({ error: 'AI provider not configured' });

    try {
      const prompt = `You are an expert penetration testing infrastructure planner. Based on the engagement description, recommend disposable proxy infrastructure configuration using ephemeral GitHub Codespace nodes.

Engagement: ${engagement}

Consider:
- Number of disposable proxy nodes needed (each provides a unique exit IP)
- IP rotation frequency to avoid detection and blacklisting
- Whether scans should run sequential, parallel, or round-robin through proxies
- OPSEC level (low = speed over stealth, medium = balanced, high = maximum anonymity)
- Which scan phases need proxying vs which can run direct
- Risk assessment for the engagement scope

Respond with valid JSON only:
{
  "nodeCount": <number>,
  "rotationMinutes": <number>,
  "scanStrategy": "sequential|parallel|round-robin",
  "opsecLevel": "low|medium|high",
  "estimatedDuration": "<human-readable time estimate>",
  "recommendations": ["<recommendation 1>", "<recommendation 2>"],
  "risks": ["<risk 1>", "<risk 2>"],
  "scanPhases": [
    { "phase": "<name>", "scanType": "<nmap|nuclei|web|ssl|dns>", "useProxy": true, "reason": "<why>" }
  ]
}`;

      const result = await askAIJSON(prompt, { timeout: 60000 });
      res.json(result || { error: 'No AI response' });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ════════════════════════════════════════════════════════════════════════
  // SSH TUNNELS (pgrok-inspired)
  // ════════════════════════════════════════════════════════════════════════

  // GET /api/proxy-nodes/tunnels — list all SSH tunnels
  app.get('/api/proxy-nodes/tunnels', requireRole('analyst'), (req, res) => {
    const neuralCache = require('../lib/neural-cache');
    const cached = neuralCache.get('tunnels:list');
    if (cached) return res.json(cached);
    const data = tunnelMgr.listTunnels();
    neuralCache.set('tunnels:list', data, 30000); // 30s TTL
    res.json(data);
  });

  // POST /api/proxy-nodes/tunnels — create SSH tunnel
  app.post('/api/proxy-nodes/tunnels', requireRole('analyst'), async (req, res) => {
    const { type, sshTarget, localPort, remoteHost, remotePort, sshPort, sshKey, autoReconnect } = req.body;
    if (!type || !sshTarget || !localPort) {
      return res.status(400).json({ error: 'type, sshTarget, and localPort are required' });
    }
    try {
      const tunnel = await tunnelMgr.createTunnel({
        type, sshTarget, localPort: parseInt(localPort),
        remoteHost, remotePort: remotePort ? parseInt(remotePort) : undefined,
        sshPort: sshPort ? parseInt(sshPort) : 22,
        sshKey, autoReconnect,
      });
      require('../lib/neural-cache').invalidate('tunnels:list');
      if (io) io.emit('tunnel_update', { action: 'created', tunnel });
      res.json(tunnel);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // DELETE /api/proxy-nodes/tunnels/:id — stop a tunnel
  app.delete('/api/proxy-nodes/tunnels/:id', requireRole('analyst'), (req, res) => {
    try {
      const result = tunnelMgr.stopTunnel(req.params.id);
      require('../lib/neural-cache').invalidate('tunnels:list');
      if (io) io.emit('tunnel_update', { action: 'stopped', id: req.params.id });
      res.json(result);
    } catch (e) {
      res.status(404).json({ error: e.message });
    }
  });

  // POST /api/proxy-nodes/tunnels/:id/health — check tunnel health
  app.post('/api/proxy-nodes/tunnels/:id/health', requireRole('analyst'), async (req, res) => {
    try {
      const health = await tunnelMgr.checkTunnelHealth(req.params.id);
      res.json(health);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ════════════════════════════════════════════════════════════════════════
  // CALLBACK LISTENER — OOB vulnerability detection
  // ════════════════════════════════════════════════════════════════════════

  // GET /api/proxy-nodes/callback — get listener status
  app.get('/api/proxy-nodes/callback', requireRole('analyst'), (req, res) => {
    res.json(tunnelMgr.getCallbackStatus());
  });

  // POST /api/proxy-nodes/callback — start/stop listener
  app.post('/api/proxy-nodes/callback', requireRole('analyst'), (req, res) => {
    const { action, port } = req.body;
    try {
      if (action === 'stop') {
        res.json(tunnelMgr.stopCallbackListener());
      } else {
        const result = tunnelMgr.startCallbackListener(port ? parseInt(port) : 9999);
        if (io) io.emit('callback_update', { action: 'started', port: result.port });
        res.json(result);
      }
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/proxy-nodes/callback/log — get captured requests
  app.get('/api/proxy-nodes/callback/log', requireRole('analyst'), (req, res) => {
    const targetedOnly = req.query.targeted === 'true';
    const limit = parseInt(req.query.limit) || 50;
    const neuralCache = require('../lib/neural-cache');
    const cacheKey = 'callback:log:' + targetedOnly + ':' + limit;
    const cached = neuralCache.get(cacheKey);
    if (cached) return res.json(cached);
    const entries = tunnelMgr.getCallbackLog({ targetedOnly, limit });
    neuralCache.set(cacheKey, entries, 10000); // 10s TTL
    res.json(entries);
  });

  // DELETE /api/proxy-nodes/callback/log — clear log
  app.delete('/api/proxy-nodes/callback/log', requireRole('analyst'), (req, res) => {
    tunnelMgr.clearCallbackLog();
    require('../lib/neural-cache').invalidatePrefix('callback:log');
    res.json({ cleared: true });
  });

  // ════════════════════════════════════════════════════════════════════════
  // PROXY NODES (fluffy-barnacle-inspired)
  // ════════════════════════════════════════════════════════════════════════

  // GET /api/proxy-nodes — list all nodes + tunnel status
  app.get('/api/proxy-nodes', requireRole('analyst'), (req, res) => {
    // Short cache — state changes frequently (2 min TTL)
    const neuralCache = require('../lib/neural-cache');
    const cached = neuralCache.get('proxy:nodes');
    if (cached) return res.json(cached);

    const status = proxy.getStatus();
    neuralCache.set('proxy:nodes', status, 120000);
    res.json(status);
  });

  // POST /api/proxy-nodes — create new proxy node
  app.post('/api/proxy-nodes', requireRole('admin'), async (req, res) => {
    const { repo, machineType } = req.body;
    try {
      const node = await proxy.createCodespace(repo, machineType);
      require('../lib/neural-cache').invalidate('proxy:nodes');
      if (io) io.emit('proxy_node_update', { action: 'created', node });
      res.json(node);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── :name param routes MUST come last ──

  // POST /api/proxy-nodes/:name/start
  app.post('/api/proxy-nodes/:name/start', requireRole('analyst'), async (req, res) => {
    try {
      await proxy.startCodespace(req.params.name);
      if (io) io.emit('proxy_node_update', { action: 'started', name: req.params.name });
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/proxy-nodes/:name/stop
  app.post('/api/proxy-nodes/:name/stop', requireRole('analyst'), async (req, res) => {
    try {
      await proxy.stopCodespace(req.params.name);
      if (io) io.emit('proxy_node_update', { action: 'stopped', name: req.params.name });
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/proxy-nodes/:name/tunnel — start SOCKS5 tunnel
  app.post('/api/proxy-nodes/:name/tunnel', requireRole('analyst'), async (req, res) => {
    const port = req.body.port || proxy.DEFAULT_PORT;
    try {
      const result = await proxy.startTunnel(req.params.name, port);
      if (io) io.emit('proxy_node_update', { action: 'tunnel_started', name: req.params.name, ...result });
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // DELETE /api/proxy-nodes/:name/tunnel — stop SOCKS5 tunnel
  app.delete('/api/proxy-nodes/:name/tunnel', requireRole('analyst'), async (req, res) => {
    try {
      await proxy.stopTunnel(req.params.name);
      if (io) io.emit('proxy_node_update', { action: 'tunnel_stopped', name: req.params.name });
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // DELETE /api/proxy-nodes/:name — delete proxy node
  app.delete('/api/proxy-nodes/:name', requireRole('admin'), async (req, res) => {
    try {
      await proxy.deleteCodespace(req.params.name);
      if (io) io.emit('proxy_node_update', { action: 'deleted', name: req.params.name });
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
};
