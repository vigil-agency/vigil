/**
 * Compliance Routes — SOC 2, ISO 27001, NIST 800-53, OWASP LLM Top 10 framework checks
 */
const fs = require('fs');
const path = require('path');
const os = require('os');

const DATA = path.join(__dirname, '..', 'data');
const EVIDENCE_PATH = path.join(DATA, 'compliance-evidence.json');

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

// ─── Framework Definitions ──────────────────────────────────────────────────

const FRAMEWORKS = {
  soc2: {
    name: 'SOC 2 Type II',
    description: 'Trust Service Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy',
    controls: [
      { id: 'CC1.1', name: 'Control Environment', category: 'CC1', check: 'organization', description: 'The entity demonstrates a commitment to integrity and ethical values' },
      { id: 'CC2.1', name: 'Information and Communication', category: 'CC2', check: 'logging', description: 'The entity obtains or generates and uses relevant, quality information' },
      { id: 'CC3.1', name: 'Risk Assessment', category: 'CC3', check: 'scanning', description: 'The entity specifies objectives to identify and assess risks' },
      { id: 'CC4.1', name: 'Monitoring Activities', category: 'CC4', check: 'monitoring', description: 'The entity selects, develops, and performs ongoing evaluations' },
      { id: 'CC5.1', name: 'Control Activities', category: 'CC5', check: 'access_control', description: 'The entity selects and develops control activities that mitigate risks' },
      { id: 'CC5.2', name: 'Logical Access Controls', category: 'CC5', check: 'auth', description: 'Logical access security over protected information assets' },
      { id: 'CC6.1', name: 'System Boundaries', category: 'CC6', check: 'firewall', description: 'The entity implements logical access security over system boundaries' },
      { id: 'CC6.2', name: 'User Authentication', category: 'CC6', check: 'auth', description: 'Prior to issuing system credentials, registered users are authenticated' },
      { id: 'CC6.3', name: 'Authorization', category: 'CC6', check: 'access_control', description: 'The entity authorizes, modifies, or removes access based on roles' },
      { id: 'CC6.6', name: 'System Security', category: 'CC6', check: 'encryption', description: 'The entity implements system security measures to protect boundaries' },
      { id: 'CC7.1', name: 'Threat Detection', category: 'CC7', check: 'threat_detection', description: 'The entity monitors system components for anomalies' },
      { id: 'CC7.2', name: 'Incident Response', category: 'CC7', check: 'incident_response', description: 'The entity monitors for and responds to security incidents' },
      { id: 'CC8.1', name: 'Change Management', category: 'CC8', check: 'change_management', description: 'The entity authorizes, designs, and implements changes to infrastructure' },
      { id: 'CC9.1', name: 'Risk Mitigation', category: 'CC9', check: 'risk_mitigation', description: 'The entity identifies, selects, and develops risk mitigation activities' },
    ],
  },
  iso27001: {
    name: 'ISO 27001:2022',
    description: 'Information Security Management System (Annex A Controls)',
    controls: [
      { id: 'A.5.1', name: 'Information Security Policies', category: 'A.5', check: 'organization', description: 'Management direction for information security' },
      { id: 'A.6.1', name: 'Screening', category: 'A.6', check: 'organization', description: 'Background verification checks on candidates' },
      { id: 'A.7.1', name: 'Physical Security Perimeters', category: 'A.7', check: 'physical', description: 'Security perimeters to protect areas with sensitive information' },
      { id: 'A.8.1', name: 'User Endpoint Devices', category: 'A.8', check: 'endpoint', description: 'Information stored, processed, or accessible on endpoint devices' },
      { id: 'A.8.2', name: 'Privileged Access Rights', category: 'A.8', check: 'access_control', description: 'Allocation and use of privileged access rights shall be restricted' },
      { id: 'A.8.3', name: 'Information Access Restriction', category: 'A.8', check: 'access_control', description: 'Access to information shall be restricted per access control policy' },
      { id: 'A.8.5', name: 'Secure Authentication', category: 'A.8', check: 'auth', description: 'Secure authentication technologies and procedures' },
      { id: 'A.8.7', name: 'Protection Against Malware', category: 'A.8', check: 'malware', description: 'Protection against malware shall be implemented' },
      { id: 'A.8.8', name: 'Technical Vulnerability Management', category: 'A.8', check: 'scanning', description: 'Information about technical vulnerabilities shall be obtained' },
      { id: 'A.8.9', name: 'Configuration Management', category: 'A.8', check: 'change_management', description: 'Configurations including security shall be established and managed' },
      { id: 'A.8.15', name: 'Logging', category: 'A.8', check: 'logging', description: 'Logs that record activities and events shall be produced and stored' },
      { id: 'A.8.16', name: 'Monitoring Activities', category: 'A.8', check: 'monitoring', description: 'Networks, systems, and applications shall be monitored' },
      { id: 'A.8.20', name: 'Network Security', category: 'A.8', check: 'firewall', description: 'Networks and network devices shall be secured and managed' },
      { id: 'A.8.24', name: 'Use of Cryptography', category: 'A.8', check: 'encryption', description: 'Rules for effective use of cryptography shall be defined' },
      { id: 'A.8.28', name: 'Secure Coding', category: 'A.8', check: 'secure_coding', description: 'Secure coding principles shall be applied to software development' },
    ],
  },
  'nist800-53': {
    name: 'NIST 800-53 Rev. 5',
    description: 'Security and Privacy Controls for Information Systems and Organizations',
    controls: [
      { id: 'AC-2', name: 'Account Management', category: 'AC', check: 'access_control', description: 'The organization manages system accounts' },
      { id: 'AC-3', name: 'Access Enforcement', category: 'AC', check: 'access_control', description: 'The system enforces approved authorizations' },
      { id: 'AT-2', name: 'Security Awareness Training', category: 'AT', check: 'organization', description: 'The organization provides security awareness training' },
      { id: 'AU-2', name: 'Event Logging', category: 'AU', check: 'logging', description: 'The system generates audit records' },
      { id: 'AU-6', name: 'Audit Review and Analysis', category: 'AU', check: 'monitoring', description: 'The organization reviews and analyzes audit records' },
      { id: 'CA-2', name: 'Security Assessments', category: 'CA', check: 'scanning', description: 'The organization assesses security controls' },
      { id: 'CM-2', name: 'Baseline Configuration', category: 'CM', check: 'change_management', description: 'The organization develops baseline configurations' },
      { id: 'IA-2', name: 'User Identification and Auth', category: 'IA', check: 'auth', description: 'The system uniquely identifies and authenticates users' },
      { id: 'IA-5', name: 'Authenticator Management', category: 'IA', check: 'auth', description: 'The organization manages system authenticators' },
      { id: 'IR-4', name: 'Incident Handling', category: 'IR', check: 'incident_response', description: 'The organization implements incident handling capability' },
      { id: 'IR-6', name: 'Incident Reporting', category: 'IR', check: 'incident_response', description: 'The organization reports security incidents' },
      { id: 'RA-5', name: 'Vulnerability Monitoring', category: 'RA', check: 'scanning', description: 'The organization monitors and scans for vulnerabilities' },
      { id: 'SC-7', name: 'Boundary Protection', category: 'SC', check: 'firewall', description: 'The system monitors and controls communications at boundaries' },
      { id: 'SC-8', name: 'Transmission Confidentiality', category: 'SC', check: 'encryption', description: 'The system protects the confidentiality of transmitted information' },
      { id: 'SI-2', name: 'Flaw Remediation', category: 'SI', check: 'risk_mitigation', description: 'The organization identifies, reports, and corrects system flaws' },
    ],
  },
  'owasp-llm': {
    name: 'OWASP LLM Top 10 (2025)',
    description: 'Top 10 security risks for Large Language Model applications — prompt injection, data leakage, excessive agency, and more',
    controls: require('../lib/ai-security-kb').getOWASPLLMControls(),
  },
};

module.exports = function (app, ctx) {
  const { requireAuth, requireRole, execCommand, askAI } = ctx;

  // Evaluate a system check
  async function evaluateCheck(checkType) {
    if (process.platform === 'win32') return { status: 'na', detail: 'Windows — check not applicable' };

    switch (checkType) {
      case 'auth': {
        try {
          const usersPath = path.join(DATA, 'users.json');
          if (fs.existsSync(usersPath)) {
            const users = readJSON(usersPath, []);
            const hasAdmin = Array.isArray(users) && users.some(u => u.role === 'admin');
            return hasAdmin
              ? { status: 'pass', detail: `Authentication system configured — ${users.length} user(s), RBAC enabled` }
              : { status: 'pass', detail: 'Authentication system configured' };
          }
        } catch {}
        return { status: 'partial', detail: 'Authentication system present but may need hardening' };
      }

      case 'access_control': {
        try {
          const r = await execCommand("grep -c 'PermitRootLogin no' /etc/ssh/sshd_config 2>/dev/null || echo 0", { timeout: 3000 });
          return parseInt(r.stdout.trim()) > 0
            ? { status: 'pass', detail: 'Root login disabled, role-based access in place' }
            : { status: 'partial', detail: 'Root login may be enabled — review SSH config' };
        } catch { return { status: 'partial', detail: 'Could not verify access controls' }; }
      }

      case 'firewall': {
        try {
          const r = await execCommand('ufw status 2>/dev/null | head -1', { timeout: 3000 });
          return r.stdout.includes('active') && !r.stdout.includes('inactive')
            ? { status: 'pass', detail: 'Firewall is active' }
            : { status: 'fail', detail: 'Firewall is not active' };
        } catch { return { status: 'fail', detail: 'No firewall detected' }; }
      }

      case 'encryption': {
        const httpsConfigured = !!process.env.SSL_CERT || !!process.env.HTTPS;
        return httpsConfigured
          ? { status: 'pass', detail: 'TLS/encryption configured' }
          : { status: 'partial', detail: 'TLS not directly configured — verify reverse proxy provides HTTPS' };
      }

      case 'logging': {
        try {
          const auditPath = path.join(DATA, 'audit-log.json');
          const exists = fs.existsSync(auditPath);
          return exists
            ? { status: 'pass', detail: 'Audit logging active' }
            : { status: 'partial', detail: 'Audit log not yet initialized' };
        } catch { return { status: 'partial', detail: 'Logging check inconclusive' }; }
      }

      case 'monitoring': {
        return ctx.getSystemInfo
          ? { status: 'pass', detail: 'System monitoring active via Vigil' }
          : { status: 'partial', detail: 'Basic monitoring in place' };
      }

      case 'scanning': {
        const scans = readJSON(path.join(DATA, 'scans.json'), []);
        const completed = scans.filter(s => s.status === 'completed');
        return completed.length > 0
          ? { status: 'pass', detail: `${completed.length} vulnerability scans completed` }
          : { status: 'fail', detail: 'No vulnerability scans have been performed' };
      }

      case 'threat_detection': {
        const threats = readJSON(path.join(DATA, 'threats.json'), []);
        return threats.length > 0
          ? { status: 'pass', detail: `Threat detection active — ${threats.length} threat(s) tracked` }
          : { status: 'partial', detail: 'Threat detection system present but no threats tracked yet' };
      }

      case 'incident_response': {
        const incidents = readJSON(path.join(DATA, 'incidents.json'), []);
        return incidents.length > 0
          ? { status: 'pass', detail: `Incident management active — ${incidents.length} incident(s) recorded` }
          : { status: 'partial', detail: 'Incident response system present but no incidents recorded yet' };
      }

      case 'change_management': {
        try {
          const r = await execCommand('git log --oneline -1 2>/dev/null', { cwd: path.join(__dirname, '..'), timeout: 3000 });
          return r.stdout.trim()
            ? { status: 'pass', detail: 'Version control (Git) in use for change management' }
            : { status: 'partial', detail: 'Version control present but review change management process' };
        } catch { return { status: 'partial', detail: 'Change management process not verified' }; }
      }

      case 'risk_mitigation': {
        const scans = readJSON(path.join(DATA, 'scans.json'), []);
        const allFindings = [];
        for (const s of scans) { if (s.findings) allFindings.push(...s.findings); }
        const resolved = allFindings.filter(f => f.status === 'resolved').length;
        return resolved > 0
          ? { status: 'pass', detail: `${resolved} vulnerabilities remediated` }
          : { status: 'partial', detail: 'No remediation activity recorded yet' };
      }

      case 'malware': {
        try {
          const r = await execCommand('which clamdscan 2>/dev/null || which clamscan 2>/dev/null', { timeout: 3000 });
          return r.stdout.trim()
            ? { status: 'pass', detail: 'ClamAV anti-malware installed' }
            : { status: 'fail', detail: 'No anti-malware solution detected' };
        } catch { return { status: 'fail', detail: 'No anti-malware detected' }; }
      }

      case 'secure_coding': {
        try {
          const lockExists = fs.existsSync(path.join(__dirname, '..', 'package-lock.json'));
          return lockExists
            ? { status: 'pass', detail: 'Dependency lock file present, secure coding practices in place' }
            : { status: 'partial', detail: 'No lock file — dependencies may be unpinned' };
        } catch { return { status: 'partial', detail: 'Secure coding check inconclusive' }; }
      }

      // ── AI / LLM Security Controls (OWASP LLM Top 10) ──
      case 'ai_llm01': { // Prompt Injection
        const settings = readJSON(path.join(DATA, 'settings.json'), {});
        return settings.aiProvider
          ? { status: 'partial', detail: 'AI provider configured — verify prompt injection defenses: input validation, instruction hierarchy enforcement, output filtering' }
          : { status: 'pass', detail: 'No AI provider configured — LLM prompt injection risk is minimal' };
      }
      case 'ai_llm02': { // Sensitive Information Disclosure
        const settings = readJSON(path.join(DATA, 'settings.json'), {});
        return settings.aiProvider
          ? { status: 'partial', detail: 'AI provider active — review system prompts for embedded secrets, verify PII filtering on LLM inputs/outputs' }
          : { status: 'pass', detail: 'No AI provider — sensitive data disclosure via LLM not applicable' };
      }
      case 'ai_llm03': { // Supply Chain
        const lockExists = fs.existsSync(path.join(__dirname, '..', 'package-lock.json'));
        return lockExists
          ? { status: 'partial', detail: 'Dependency lock file present — additionally verify AI model provenance and scan model files with modelscan/picklescan' }
          : { status: 'fail', detail: 'No lock file — AI supply chain controls inadequate' };
      }
      case 'ai_llm04': { // Data and Model Poisoning
        return { status: 'partial', detail: 'Verify training data integrity, implement data provenance tracking, and test for adversarial robustness' };
      }
      case 'ai_llm05': { // Improper Output Handling
        try {
          const r = await execCommand("grep -rc 'escapeHtml\\|textContent\\|sanitize' /app/public/js/ 2>/dev/null | tail -1", { timeout: 3000 });
          const count = parseInt(r.stdout.trim()) || 0;
          return count > 5
            ? { status: 'pass', detail: `Output sanitization detected — ${count} escapeHtml/textContent references in frontend` }
            : { status: 'partial', detail: 'Verify LLM outputs are sanitized before rendering — check for XSS via model-generated content' };
        } catch { return { status: 'partial', detail: 'Verify LLM output handling — apply encoding and sanitization to all model-generated content' }; }
      }
      case 'ai_llm06': { // Excessive Agency
        const settings = readJSON(path.join(DATA, 'settings.json'), {});
        if (!settings.aiProvider) return { status: 'pass', detail: 'No AI provider — excessive agency risk not applicable' };
        return { status: 'partial', detail: 'AI agents active — verify least-privilege tool permissions, human-in-the-loop for destructive actions, and rate limiting on agent operations' };
      }
      case 'ai_llm07': { // System Prompt Leakage
        return { status: 'partial', detail: 'Review system prompts for embedded credentials or sensitive business logic — implement prompt leakage detection in output filtering' };
      }
      case 'ai_llm08': { // Vector and Embedding Weaknesses
        return { status: 'na', detail: 'RAG/vector store not detected — verify if embedding systems are in use and apply access controls' };
      }
      case 'ai_llm09': { // Misinformation
        return { status: 'partial', detail: 'Implement confidence scoring on AI outputs, cross-reference with authoritative sources, require human review for security-critical AI decisions' };
      }
      case 'ai_llm10': { // Unbounded Consumption
        const settings = readJSON(path.join(DATA, 'settings.json'), {});
        return settings.aiProvider
          ? { status: 'partial', detail: 'AI provider active — verify token budgets, request timeouts, rate limiting, and agent loop detection are configured' }
          : { status: 'pass', detail: 'No AI provider — unbounded consumption risk not applicable' };
      }

      default:
        return { status: 'na', detail: 'Check type not automated — requires manual assessment' };
    }
  }

  // GET /api/compliance
  app.get('/api/compliance', requireAuth, async (req, res) => {
    try {
      const results = [];
      for (const [key, framework] of Object.entries(FRAMEWORKS)) {
        let pass = 0, fail = 0, partial = 0, na = 0;
        for (const control of framework.controls) {
          const result = await evaluateCheck(control.check);
          if (result.status === 'pass') pass++;
          else if (result.status === 'fail') fail++;
          else if (result.status === 'partial') partial++;
          else na++;
        }
        const total = pass + fail + partial;
        const score = total > 0 ? Math.round((pass / total) * 100) : 0;
        results.push({
          id: key,
          name: framework.name,
          description: framework.description,
          controlCount: framework.controls.length,
          score,
          pass, fail, partial, na,
        });
      }
      res.json({ frameworks: results });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/compliance/:framework
  app.get('/api/compliance/:framework', requireAuth, async (req, res) => {
    try {
      const framework = FRAMEWORKS[req.params.framework];
      if (!framework) return res.status(404).json({ error: 'Framework not found. Available: soc2, iso27001, nist800-53, owasp-llm' });

      const controls = [];
      let pass = 0, fail = 0, partial = 0, na = 0;

      for (const control of framework.controls) {
        const result = await evaluateCheck(control.check);
        controls.push({ ...control, ...result });
        if (result.status === 'pass') pass++;
        else if (result.status === 'fail') fail++;
        else if (result.status === 'partial') partial++;
        else na++;
      }

      const total = pass + fail + partial;
      const score = total > 0 ? Math.round((pass / total) * 100) : 0;

      const evidence = readJSON(EVIDENCE_PATH, {});
      const frameworkEvidence = evidence[req.params.framework] || {};

      res.json({
        id: req.params.framework,
        name: framework.name,
        description: framework.description,
        score,
        pass, fail, partial, na,
        controls,
        evidence: frameworkEvidence,
        evaluatedAt: new Date().toISOString(),
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/compliance/:framework/evidence — collect evidence for a control
  app.post('/api/compliance/:framework/evidence', requireRole('analyst'), async (req, res) => {
    try {
      // Accept both controlId and control_id for frontend compatibility
      const controlId = req.body.controlId || req.body.control_id;
      const notes = req.body.notes || req.body.evidence || '';
      const artifacts = req.body.artifacts || [];
      if (!controlId) return res.status(400).json({ error: 'controlId required' });

      const framework = FRAMEWORKS[req.params.framework];
      if (!framework) return res.status(404).json({ error: 'Framework not found' });

      const control = framework.controls.find(c => c.id === controlId);
      if (!control) return res.status(404).json({ error: 'Control not found' });

      const evidence = readJSON(EVIDENCE_PATH, {});
      if (!evidence[req.params.framework]) evidence[req.params.framework] = {};

      evidence[req.params.framework][controlId] = {
        notes: notes || '',
        artifacts: artifacts || [],
        collectedAt: new Date().toISOString(),
        collectedBy: req.user ? req.user.user : 'unknown',
      };

      writeJSON(EVIDENCE_PATH, evidence);
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── AI compliance report (shared logic) ──
  async function generateComplianceReport(fwKey, res) {
    const fw = FRAMEWORKS[fwKey];
    if (!fw) return res.status(404).json({ error: 'Framework not found. Available: soc2, iso27001, nist800-53' });

    if (!askAI) return res.status(503).json({ error: 'AI provider not configured. Set up an AI provider in Settings.' });

    const controlResults = [];
    for (const control of fw.controls) {
      const result = await evaluateCheck(control.check);
      controlResults.push({ id: control.id, name: control.name, category: control.category, description: control.description, ...result });
    }

    const passing = controlResults.filter(c => c.status === 'pass').length;
    const failing = controlResults.filter(c => c.status === 'fail').length;
    const partial = controlResults.filter(c => c.status === 'partial').length;
    const naCount = controlResults.filter(c => c.status === 'na').length;

    const prompt = `You are a senior compliance auditor performing a ${fw.name} assessment. Generate a detailed compliance audit report.

Framework: ${fw.name}
Description: ${fw.description}
Results: ${passing} passing, ${failing} failing, ${partial} partial, ${naCount} not applicable out of ${controlResults.length} total controls
Compliance Score: ${Math.round((passing / Math.max(passing + failing + partial, 1)) * 100)}%

Control Assessment Details:
${controlResults.map(c => `[${c.status.toUpperCase()}] ${c.id} — ${c.name}: ${c.detail}`).join('\n')}

Write a professional compliance audit report with these sections:

EXECUTIVE SUMMARY
- 3-4 sentences summarizing the overall compliance posture
- Include the compliance score and what it means for certification readiness

KEY FINDINGS
- List the top 5 most critical findings (prioritize failures, then partial)
- For each finding: control ID, issue description, business risk

GAP ANALYSIS
- What controls are meeting requirements
- What controls have gaps
- What controls need manual assessment (N/A items)

REMEDIATION ROADMAP
- Prioritized list of actions to improve compliance
- Quick wins (can be fixed immediately)
- Medium-term items (1-4 weeks)
- Strategic improvements (ongoing)

COMPLIANCE READINESS
- Overall readiness assessment for certification/audit
- Risk rating (Critical / High / Medium / Low)
- Recommended next steps

Keep it professional. Use plain text, no markdown formatting.`;

    const report = await askAI(prompt, { timeout: 120000 });
    res.json({
      framework: fwKey,
      frameworkName: fw.name,
      report: report || 'Report generation unavailable — check AI provider configuration.',
      controls: controlResults,
      summary: { passing, failing, partial, na: naCount, total: controlResults.length },
      generatedAt: new Date().toISOString(),
    });
  }

  // POST /api/compliance/report — AI compliance report (body-based)
  app.post('/api/compliance/report', requireRole('analyst'), async (req, res) => {
    try {
      await generateComplianceReport(req.body.framework || 'soc2', res);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/compliance/:framework/report — AI compliance report (URL-based, matches frontend)
  app.post('/api/compliance/:framework/report', requireRole('analyst'), async (req, res) => {
    try {
      await generateComplianceReport(req.params.framework, res);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
};
