/**
 * Code Audit Routes — LLM-driven source code vulnerability scanning
 * Vulnhuntr-inspired zero-shot vulnerability discovery
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { runCodeAudit, discoverFiles, VULN_TYPES, LANG_EXTENSIONS } = require('../lib/code-audit');

const DATA = path.join(__dirname, '..', 'data');
const SCANS_PATH = path.join(DATA, 'scans.json');

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
function escapeHtml(s) { return String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }

module.exports = function (app, ctx) {
  const { requireAuth, requireRole, askAIJSON } = ctx;

  // POST /api/code-audit — run LLM-driven code audit
  app.post('/api/code-audit', requireRole('analyst'), async (req, res) => {
    const { target, languages, vulnTypes } = req.body;

    if (!target || typeof target !== 'string') {
      return res.status(400).json({ error: 'target (directory path) is required' });
    }

    // Validate target path — must be absolute and exist
    const resolvedPath = path.resolve(target);
    if (!fs.existsSync(resolvedPath) || !fs.statSync(resolvedPath).isDirectory()) {
      return res.status(400).json({ error: 'Target directory does not exist: ' + target });
    }

    // Validate languages if provided
    const validLangs = languages && Array.isArray(languages)
      ? languages.filter(l => LANG_EXTENSIONS[l])
      : [];

    // Validate vuln types if provided
    const validVulnTypes = vulnTypes && Array.isArray(vulnTypes)
      ? vulnTypes.filter(v => VULN_TYPES[v])
      : Object.keys(VULN_TYPES);

    // Check AI provider is configured
    if (!askAIJSON) {
      return res.status(503).json({ error: 'AI provider not configured. Set up an AI provider in Settings.' });
    }

    // Create scan record
    const scan = {
      id: crypto.randomUUID(),
      type: 'code-audit',
      target: escapeHtml(resolvedPath),
      options: { languages: validLangs, vulnTypes: validVulnTypes },
      status: 'pending',
      findings: [],
      findingsCount: 0,
      createdAt: new Date().toISOString(),
      createdBy: req.user ? req.user.user : 'unknown',
    };

    const scans = readJSON(SCANS_PATH, []);
    scans.push(scan);
    writeJSON(SCANS_PATH, scans);

    // Return immediately, run scan in background
    res.json({ scan: { id: scan.id, type: scan.type, target: scan.target, status: 'running' } });

    // Execute code audit in background
    try {
      scan.status = 'running';
      scan.startedAt = new Date().toISOString();

      // Persist 'running' status to disk
      const runningScans = readJSON(SCANS_PATH, []);
      const runIdx = runningScans.findIndex(s => s.id === scan.id);
      if (runIdx >= 0) { runningScans[runIdx].status = 'running'; runningScans[runIdx].startedAt = scan.startedAt; }
      writeJSON(SCANS_PATH, runningScans);

      console.log(`  [CODE-AUDIT] Starting scan ${scan.id} on ${resolvedPath}`);

      const result = await runCodeAudit(resolvedPath, {
        askAIJSON,
        languages: validLangs,
        vulnTypes: validVulnTypes,
        timeout: 120000,
        onProgress: (progress) => {
          // Emit progress via Socket.IO
          if (ctx.io) {
            ctx.io.emit('code_audit_progress', {
              scanId: scan.id,
              phase: progress.phase,
              message: progress.message,
            });
          }
        },
      });

      // Convert code-audit findings to standard scan findings format
      scan.findings = result.findings.map(f => ({
        id: f.id,
        scanId: scan.id,
        type: 'code_vuln',
        title: `[${f.vulnType}] ${f.title}`,
        severity: f.severity,
        details: f.description,
        file: f.file,
        line: f.line,
        cwe: f.cwe,
        mitre: f.mitre,
        dataFlow: f.dataFlow,
        poc: f.poc,
        remediation: f.remediation,
        confidence: f.confidence,
        vulnType: f.vulnType,
        status: 'open',
      }));

      scan.findingsCount = scan.findings.length;
      scan.status = 'completed';
      scan.completedAt = new Date().toISOString();
      scan.duration = result.duration;
      scan.summary = result.summary;
      scan.filesAnalyzed = result.filesAnalyzed;
      scan.totalFiles = result.totalFiles;

    } catch (e) {
      console.error(`  [CODE-AUDIT] Scan ${scan.id} failed:`, e.message);
      scan.status = 'failed';
      scan.error = e.message;
      scan.completedAt = new Date().toISOString();
    }

    console.log(`  [CODE-AUDIT] Scan ${scan.id} ${scan.status}: ${scan.findingsCount} findings in ${scan.duration || 0}ms`);

    // Save updated scan
    const allScans = readJSON(SCANS_PATH, []);
    const idx = allScans.findIndex(s => s.id === scan.id);
    if (idx >= 0) allScans[idx] = scan;
    writeJSON(SCANS_PATH, allScans);

    // Notify via Socket.IO
    if (ctx.io) {
      ctx.io.emit('scan_complete', {
        id: scan.id,
        type: 'code-audit',
        status: scan.status,
        findingsCount: scan.findingsCount,
      });
    }
  });

  // GET /api/code-audit/vuln-types — list supported vulnerability types
  // MUST be before /:id route to avoid being caught as a param
  app.get('/api/code-audit/vuln-types', requireAuth, (req, res) => {
    res.json({ vulnTypes: VULN_TYPES, languages: LANG_EXTENSIONS });
  });

  // POST /api/code-audit/preview — preview files that would be scanned
  app.post('/api/code-audit/preview', requireRole('analyst'), (req, res) => {
    const { target, languages } = req.body;

    if (!target || typeof target !== 'string') {
      return res.status(400).json({ error: 'target (directory path) is required' });
    }

    const resolvedPath = path.resolve(target);
    if (!fs.existsSync(resolvedPath) || !fs.statSync(resolvedPath).isDirectory()) {
      return res.status(400).json({ error: 'Target directory does not exist' });
    }

    const validLangs = languages && Array.isArray(languages)
      ? languages.filter(l => LANG_EXTENSIONS[l])
      : [];

    const files = discoverFiles(resolvedPath, validLangs);
    res.json({
      path: resolvedPath,
      fileCount: files.length,
      files: files.map(f => ({ path: f.relPath, size: f.size })),
      languages: validLangs.length ? validLangs : Object.keys(LANG_EXTENSIONS),
    });
  });

  // GET /api/code-audit/:id — get code audit scan details (MUST be after specific routes)
  app.get('/api/code-audit/:id', requireAuth, (req, res) => {
    const scans = readJSON(SCANS_PATH, []);
    const scan = scans.find(s => s.id === req.params.id && s.type === 'code-audit');
    if (!scan) return res.status(404).json({ error: 'Code audit scan not found' });
    res.json(scan);
  });
};
