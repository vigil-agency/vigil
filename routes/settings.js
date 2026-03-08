/**
 * Settings Routes — Configuration management
 */
const fs = require('fs');
const path = require('path');

const DATA = path.join(__dirname, '..', 'data');
const SETTINGS_PATH = path.join(DATA, 'settings.json');

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

module.exports = function (app, ctx) {
  const { requireAuth, requireAdmin, execCommand } = ctx;

  // GET /api/settings
  app.get('/api/settings', requireAdmin, (req, res) => {
    const settings = readJSON(SETTINGS_PATH, {
      aiProvider: 'claude-cli',
      theme: 'dark',
      autoScan: false,
      scanInterval: 24,
      notificationsEnabled: true,
      postureRefreshInterval: 60,
    });
    res.json(settings);
  });

  // POST /api/settings — update a setting
  app.post('/api/settings', requireAdmin, (req, res) => {
    const { key, value } = req.body;
    if (!key) return res.status(400).json({ error: 'key required' });

    // Whitelist of allowed settings
    const allowed = [
      'aiProvider', 'theme', 'autoScan', 'scanInterval',
      'notificationsEnabled', 'postureRefreshInterval',
      'companyName', 'contactEmail', 'slackWebhook', 'discordWebhook',
      'smtp', 'maxConcurrentScans', 'retentionDays',
    ];

    if (!allowed.includes(key)) {
      return res.status(400).json({ error: 'Setting not allowed: ' + escapeHtml(key) });
    }

    const settings = readJSON(SETTINGS_PATH, {});
    settings[key] = value;
    settings.updatedAt = new Date().toISOString();
    writeJSON(SETTINGS_PATH, settings);

    console.log(`[SETTINGS] ${key} updated by ${req.user ? req.user.user : 'unknown'}`);
    res.json({ success: true, key, value });
  });

  // GET /api/settings/ai — AI provider config
  app.get('/api/settings/ai', requireAdmin, (req, res) => {
    const settings = readJSON(SETTINGS_PATH, {});
    res.json({
      provider: settings.aiProvider || 'none',
      available: ['claude-api', 'claude-cli', 'codex', 'none'],
    });
  });

  // POST /api/settings/ai — update AI provider
  app.post('/api/settings/ai', requireAdmin, (req, res) => {
    const { provider } = req.body;
    if (!provider || !['claude-api', 'claude-cli', 'codex', 'none'].includes(provider)) {
      return res.status(400).json({ error: 'Invalid provider. Use: claude-api, claude-cli, codex, none' });
    }

    const settings = readJSON(SETTINGS_PATH, {});
    settings.aiProvider = provider;
    settings.updatedAt = new Date().toISOString();
    writeJSON(SETTINGS_PATH, settings);

    console.log(`[SETTINGS] AI provider changed to: ${provider}`);
    res.json({ success: true, provider });
  });

  // GET /api/settings/scanners — check which scanning tools are installed
  app.get('/api/settings/scanners', requireAdmin, async (req, res) => {
    const scanners = [
      { name: 'nmap', command: 'nmap --version', description: 'Network port scanner' },
      { name: 'nuclei', command: 'nuclei --version', description: 'Vulnerability scanner' },
      { name: 'trivy', command: 'trivy --version', description: 'Container/filesystem scanner' },
      { name: 'openssl', command: 'openssl version', description: 'SSL/TLS toolkit' },
      { name: 'curl', command: 'curl --version', description: 'HTTP client' },
      { name: 'dig', command: 'dig -v 2>&1 || echo "dig available"', description: 'DNS lookup utility' },
      { name: 'whois', command: 'whois --version 2>&1 || which whois', description: 'WHOIS lookup' },
      { name: 'docker', command: 'docker --version', description: 'Container runtime' },
    ];

    const results = await Promise.allSettled(
      scanners.map(async s => {
        try {
          const result = await execCommand(s.command + ' 2>&1 | head -1', { timeout: 5000 });
          const version = result.stdout.trim().split('\n')[0] || '';
          return { ...s, installed: true, version };
        } catch {
          return { ...s, installed: false, version: null };
        }
      })
    );

    const available = results.map(r => r.status === 'fulfilled' ? r.value : { name: 'unknown', installed: false });

    res.json({
      scanners: available,
      installed: available.filter(s => s.installed).length,
      total: available.length,
    });
  });
};
