/**
 * Agents Routes — 20+ built-in AI security agents + custom agents
 * Each agent is an AI specialist with a focused system prompt.
 * Users run agents by providing a target/input, and the AI analyzes it.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA = path.join(__dirname, '..', 'data');
const AGENTS_PATH = path.join(DATA, 'agents.json');
const RUNS_PATH = path.join(DATA, 'agent-runs.json');

function escapeHtml(s) { return String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }

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

// ═══════════════════════════════════════════════════════════════════════
// Built-in agent catalog — 20 specialized security AI agents
// Categories: scanner, analyzer, defender, hunter (match frontend tabs)
// ═══════════════════════════════════════════════════════════════════════
const AGENT_CATALOG = [
  // ── Scanners ─────────────────────────────────────────────────────
  {
    slug: 'port-scanner', name: 'Port Scanner', category: 'scanner',
    description: 'Analyzes open ports, services, and network attack surface for any target',
    system_prompt: 'You are a network reconnaissance expert and penetration tester. You analyze port scan results and identify attack vectors.',
    task_prompt: 'Analyze the security of this target: {{input}}\n\nFor each likely open port/service: identify the service, known vulnerabilities, attack vectors, and risk level. Provide a prioritized list of findings with specific remediation steps. Include CVSS scores where applicable.',
    risk_level: 'low', placeholder: 'IP address, hostname, or paste nmap output',
  },
  {
    slug: 'subdomain-enum', name: 'Subdomain Enumerator', category: 'scanner',
    description: 'Discovers subdomains and maps the external attack surface of a domain',
    system_prompt: 'You are a DNS and subdomain enumeration specialist focused on attack surface mapping.',
    task_prompt: 'Map the attack surface for domain: {{input}}\n\nList common subdomains to check (www, mail, api, dev, staging, admin, vpn, git, etc.), explain what each discovered subdomain reveals about infrastructure, and identify high-value targets. Assess the overall attack surface exposure.',
    risk_level: 'low', placeholder: 'example.com',
  },
  {
    slug: 'header-auditor', name: 'HTTP Header Auditor', category: 'scanner',
    description: 'Grades HTTP security headers and identifies missing protections',
    system_prompt: 'You are a web security expert specializing in HTTP security headers and browser security mechanisms.',
    task_prompt: 'Audit the HTTP security headers for: {{input}}\n\nCheck each header: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy. Grade each A-F. Provide exact header values to add for remediation.',
    risk_level: 'low', placeholder: 'URL or paste HTTP headers',
  },
  {
    slug: 'xss-scanner', name: 'XSS Scanner', category: 'scanner',
    description: 'Identifies cross-site scripting vulnerabilities and injection points',
    system_prompt: 'You are an application security tester specializing in XSS detection and exploitation.',
    task_prompt: 'Analyze for XSS vulnerabilities: {{input}}\n\nIdentify: reflected/stored/DOM-based injection points, bypass techniques for common filters, impact assessment, and secure coding fixes. Provide test payloads and explain each attack vector.',
    risk_level: 'medium', placeholder: 'URL, HTML snippet, or endpoint description',
  },
  {
    slug: 'sqli-detector', name: 'SQL Injection Detector', category: 'scanner',
    description: 'Detects SQL injection vulnerabilities and database exposure risks',
    system_prompt: 'You are a database security expert specializing in SQL injection detection and prevention.',
    task_prompt: 'Analyze for SQL injection: {{input}}\n\nIdentify vulnerable parameters, demonstrate attack vectors (UNION, blind, time-based, error-based), assess data exposure risk, and provide parameterized query remediation. Include WAF bypass considerations.',
    risk_level: 'medium', placeholder: 'URL with parameters, code snippet, or API endpoint',
  },
  {
    slug: 'tls-analyzer', name: 'TLS Configuration Analyzer', category: 'scanner',
    description: 'Grades TLS/SSL configuration, cipher suites, and certificate security',
    system_prompt: 'You are a cryptography expert specializing in TLS configuration and PKI.',
    task_prompt: 'Analyze TLS configuration for: {{input}}\n\nCheck: protocol versions (TLS 1.0-1.3), cipher suite strength, certificate chain validity, HSTS, OCSP stapling, certificate transparency, key size, and forward secrecy. Grade A+ to F with specific findings.',
    risk_level: 'low', placeholder: 'Domain name or paste SSL scan output',
  },

  // ── Analyzers ────────────────────────────────────────────────────
  {
    slug: 'aws-auditor', name: 'AWS Security Auditor', category: 'analyzer',
    description: 'Audits AWS configurations against CIS benchmarks and security best practices',
    system_prompt: 'You are an AWS security architect with deep expertise in CIS AWS Foundations Benchmark.',
    task_prompt: 'Audit this AWS configuration: {{input}}\n\nCheck: IAM policies (least privilege, MFA, key rotation), S3 (public access, encryption, versioning), security groups (open ports, CIDR ranges), CloudTrail, VPC flow logs, KMS. Map to CIS benchmark controls. Severity: Critical/High/Medium/Low.',
    risk_level: 'low', placeholder: 'AWS config, IAM policy, security group rules, or describe your setup',
  },
  {
    slug: 'iam-analyzer', name: 'IAM Policy Analyzer', category: 'analyzer',
    description: 'Identifies over-privileged access, unused permissions, and IAM risks',
    system_prompt: 'You are an identity and access management expert specializing in least-privilege analysis.',
    task_prompt: 'Analyze these IAM policies: {{input}}\n\nIdentify: over-privileged roles, wildcard permissions (*), unused permissions, privilege escalation paths, cross-account access risks, and service-linked role issues. Recommend specific least-privilege policies.',
    risk_level: 'low', placeholder: 'IAM policy JSON, role description, or permission set',
  },
  {
    slug: 'pci-checker', name: 'PCI DSS Checker', category: 'analyzer',
    description: 'Evaluates systems against PCI DSS v4.0 payment security requirements',
    system_prompt: 'You are a PCI DSS Qualified Security Assessor (QSA) with expertise in v4.0.',
    task_prompt: 'Evaluate against PCI DSS v4.0: {{input}}\n\nCheck: network segmentation (Req 1), cardholder data protection (Req 3-4), access control (Req 7-8), monitoring (Req 10), testing (Req 11). Status each requirement: Pass / Fail / Partial / N/A with specific gaps and remediation.',
    risk_level: 'low', placeholder: 'System architecture, network diagram, or security controls description',
  },
  {
    slug: 'hipaa-checker', name: 'HIPAA Compliance Checker', category: 'analyzer',
    description: 'Evaluates healthcare systems against HIPAA Security Rule requirements',
    system_prompt: 'You are a HIPAA compliance expert and healthcare security consultant.',
    task_prompt: 'Evaluate HIPAA compliance: {{input}}\n\nCheck: Administrative safeguards (risk analysis, workforce training), Physical safeguards (facility access, workstation security), Technical safeguards (access controls, audit controls, encryption, integrity). Map to specific HIPAA § references.',
    risk_level: 'low', placeholder: 'System description, security controls, or architecture',
  },
  {
    slug: 'data-classifier', name: 'Sensitive Data Classifier', category: 'analyzer',
    description: 'Identifies PII, PHI, PCI, credentials, and sensitive data exposure',
    system_prompt: 'You are a data classification and privacy expert. You identify sensitive data in any format.',
    task_prompt: 'Classify sensitive data in: {{input}}\n\nIdentify: PII (names, emails, SSNs, phone numbers), PHI (medical records, diagnoses), PCI (card numbers, CVVs), credentials (API keys, passwords, tokens), secrets (private keys, certificates). Rate exposure risk and recommend data protection (masking, encryption, tokenization).',
    risk_level: 'low', placeholder: 'Paste data, config file, log output, or code snippet',
  },
  {
    slug: 'password-auditor', name: 'Password Policy Auditor', category: 'analyzer',
    description: 'Audits authentication policies against NIST 800-63b guidelines',
    system_prompt: 'You are an authentication security expert with deep knowledge of NIST 800-63b.',
    task_prompt: 'Audit this authentication system: {{input}}\n\nCheck against NIST 800-63b: password length (min 8, prefer 15+), composition rules, breached password screening, MFA enforcement, session management, rate limiting, account lockout. Grade each control and provide specific fixes.',
    risk_level: 'low', placeholder: 'Auth policy description, login flow, or password requirements',
  },

  // ── Defenders ────────────────────────────────────────────────────
  {
    slug: 'incident-playbook', name: 'Incident Playbook Generator', category: 'defender',
    description: 'Creates tailored incident response playbooks with step-by-step procedures',
    system_prompt: 'You are an incident response commander with 15 years of experience handling security breaches.',
    task_prompt: 'Create an incident response playbook for: {{input}}\n\nInclude: DETECTION (triggers, indicators), TRIAGE (first 15 minutes — exact steps), CONTAINMENT (isolation procedures, commands), ERADICATION (removal steps), RECOVERY (restoration, validation), COMMUNICATION (stakeholder notification template), POST-INCIDENT (review checklist, metrics). Include specific commands for Linux/Windows.',
    risk_level: 'low', placeholder: 'Incident type: ransomware, data breach, DDoS, insider threat, phishing...',
  },
  {
    slug: 'firewall-auditor', name: 'Firewall Rule Auditor', category: 'defender',
    description: 'Audits firewall rules for overly permissive access and security gaps',
    system_prompt: 'You are a network security engineer specializing in firewall policy management and zero-trust architecture.',
    task_prompt: 'Audit these firewall rules: {{input}}\n\nIdentify: overly permissive rules (0.0.0.0/0), shadowed rules, unused rules, missing deny-all default, insecure protocols allowed, management access exposure. Recommend a hardened ruleset following zero-trust principles.',
    risk_level: 'low', placeholder: 'Paste iptables rules, security group config, or firewall policy',
  },
  {
    slug: 'malware-analyzer', name: 'Malware Behavior Analyzer', category: 'defender',
    description: 'Analyzes process behavior and IOCs for malware classification',
    system_prompt: 'You are a malware analyst specializing in behavioral analysis and threat classification.',
    task_prompt: 'Analyze for malware indicators: {{input}}\n\nCheck: persistence mechanisms (registry, cron, services), C2 communication (beaconing, DNS tunneling, encrypted channels), data exfiltration (encoding, staging), privilege escalation (exploits, misconfigs), lateral movement (pass-the-hash, RDP). Classify the threat family and provide IOCs.',
    risk_level: 'medium', placeholder: 'Process list, network connections, file hashes, or suspicious behavior description',
  },

  // ── Hunters ──────────────────────────────────────────────────────
  {
    slug: 'log-hunter', name: 'Log Threat Hunter', category: 'hunter',
    description: 'Hunts for indicators of compromise and attack patterns in log data',
    system_prompt: 'You are a threat hunter specializing in log analysis using MITRE ATT&CK framework.',
    task_prompt: 'Hunt for threats in these logs: {{input}}\n\nLook for: brute force (T1110), privilege escalation (T1068), lateral movement (T1021), data exfiltration (T1048), persistence (T1053), defense evasion (T1070), credential access (T1003). Map each finding to MITRE ATT&CK. Rate confidence: Confirmed / Likely / Possible.',
    risk_level: 'low', placeholder: 'Paste log entries, syslog output, or access logs',
  },
  {
    slug: 'network-anomaly', name: 'Network Anomaly Detector', category: 'hunter',
    description: 'Identifies anomalous network traffic, C2 beacons, and data exfiltration',
    system_prompt: 'You are a network security analyst specializing in traffic analysis and anomaly detection.',
    task_prompt: 'Analyze for network anomalies: {{input}}\n\nCheck: unusual outbound connections (known bad IPs, rare ports), DNS tunneling (long queries, high volume), beaconing patterns (regular intervals), data exfiltration (large uploads, encoded data), protocol anomalies (HTTP on non-standard ports). Provide IOCs and detection rules.',
    risk_level: 'low', placeholder: 'Paste netstat output, connection logs, or DNS queries',
  },
  {
    slug: 'memory-forensics', name: 'Memory Forensics Analyzer', category: 'hunter',
    description: 'Analyzes process memory for code injection, rootkits, and compromise indicators',
    system_prompt: 'You are a digital forensics expert specializing in memory analysis and volatile data examination.',
    task_prompt: 'Analyze for memory forensic indicators: {{input}}\n\nLook for: process injection (hollowing, DLL injection), suspicious memory regions (RWX permissions), rootkit indicators (hidden processes, hooked syscalls), credential dumping (lsass access), encrypted payloads. Provide Volatility commands for deeper analysis.',
    risk_level: 'medium', placeholder: 'Process list, memory dump info, or suspicious process details',
  },
  {
    slug: 'disk-forensics', name: 'Disk Forensics Analyzer', category: 'hunter',
    description: 'Analyzes filesystem artifacts for evidence of compromise and data tampering',
    system_prompt: 'You are a digital forensics examiner specializing in filesystem and timeline analysis.',
    task_prompt: 'Analyze for forensic evidence: {{input}}\n\nCheck: recently modified sensitive files, hidden/renamed files, timestomping (MACE inconsistencies), unusual setuid/setgid binaries, deleted file recovery opportunities, log tampering evidence, web shells, scheduled task modifications. Create a forensic timeline of events.',
    risk_level: 'low', placeholder: 'File listing, directory contents, or filesystem metadata',
  },
  // ── Raptor-Inspired Adversarial Agents ────────────────────────────────
  {
    slug: 'adversarial-analyst', name: 'Adversarial Analyst', category: 'hunter',
    description: 'MUST-GATE adversarial security analysis — assumes everything is exploitable until proven otherwise',
    system_prompt: 'You are an elite adversarial security analyst using the MUST-GATE reasoning framework.\n\nMUST-GATE CONSTRAINTS:\n[ASSUME-EXPLOIT] If you think something is not exploitable, investigate under the assumption it IS exploitable first.\n[NO-HEDGING] If your output includes "maybe", "uncertain", "could potentially" — immediately verify. No unverified hedging.\n[FULL-COVERAGE] Analyze the entire relevant code/attack path. No sampling or guessing.\n[PROOF] Always provide proof: vulnerable code, attack vector, and concrete PoC.\n[CONSISTENCY] Verify vuln_type, severity, and status all match your description and proof.\n\nPrioritize: Secrets > Input Validation > Auth/Authz > Crypto > Config.',
    task_prompt: 'Perform adversarial security analysis on: {{input}}\n\nFor each finding:\n1. Identify vulnerability class (CWE)\n2. Trace complete attack path (source → processing → sink)\n3. Assess exploitability (Source Control → Sanitizer → Reachability → Impact)\n4. Provide concrete proof-of-concept\n5. Verdict: EXPLOITABLE, LIKELY_EXPLOITABLE, NEEDS_INVESTIGATION, or FALSE_POSITIVE\n6. Specific remediation\n\nThink like an attacker. Communicate like a professional.',
    risk_level: 'medium', placeholder: 'Code snippet, URL, scan output, or vulnerability description',
    examples: [
      { label: 'Express login handler', input: 'app.post("/login", (req, res) => {\n  const { user, pass } = req.body;\n  const row = db.query("SELECT * FROM users WHERE name=\'" + user + "\' AND pass=\'" + pass + "\'");\n  if (row) res.cookie("session", row.id);\n});' },
      { label: 'File upload endpoint', input: 'app.post("/upload", multer({ dest: "/tmp" }).single("file"), (req, res) => {\n  const dest = path.join("/var/data", req.body.folder, req.file.originalname);\n  fs.renameSync(req.file.path, dest);\n  res.json({ url: "/files/" + req.body.folder + "/" + req.file.originalname });\n});' },
      { label: 'JWT verification', input: 'function verifyToken(token) {\n  const decoded = jwt.decode(token);\n  if (decoded.exp < Date.now() / 1000) throw new Error("expired");\n  return decoded;\n}' },
    ],
  },
  {
    slug: 'exploit-validator', name: 'Exploit Validator', category: 'hunter',
    description: '4-step exploitability validation — determines if a finding is truly exploitable',
    system_prompt: 'You are a senior penetration tester validating whether security findings are actually exploitable. You use a rigorous 4-step framework:\n\nStep 1 — Source Control: Who controls the input? Can an attacker provide or influence it?\nStep 2 — Sanitizer Effectiveness: Is there sanitization? Can it be bypassed (encoding, truncation, type juggling)?\nStep 3 — Reachability: Can an attacker actually trigger this code path via normal application flow?\nStep 4 — Impact Assessment: What is the worst-case outcome if exploited?\n\nVerdict rules:\n- EXPLOITABLE only if ALL 4 steps pass\n- FALSE_POSITIVE if ANY step definitively fails\n- NEEDS_INVESTIGATION if steps are inconclusive',
    task_prompt: 'Validate this finding for exploitability: {{input}}\n\nExecute each step in order. Do not skip steps. For each step provide:\n- Result: PASS / FAIL / INCONCLUSIVE\n- Evidence and reasoning\n- Specific code references if available\n\nThen provide final verdict with confidence score (1-10), attack vector, and remediation.',
    risk_level: 'medium', placeholder: 'Paste a vulnerability finding, code snippet, or scan result',
    examples: [
      { label: 'SQLi in search', input: 'Finding: SQL Injection in /api/search?q= parameter\nCode: db.query("SELECT * FROM products WHERE name LIKE \'%" + req.query.q + "%\'");\nContext: Express.js app behind Cloudflare WAF, parameterized queries used elsewhere' },
      { label: 'Stored XSS', input: 'Finding: Stored XSS in comment field\nCode: commentDiv.innerHTML = comment.body;\nContext: Comments sanitized with DOMPurify on input but rendered raw from database. Admin panel displays comments without sanitization.' },
      { label: 'SSRF in webhooks', input: 'Finding: SSRF via webhook URL parameter\nCode: const resp = await fetch(req.body.webhookUrl);\nContext: User-supplied webhook URL fetched server-side. No URL validation. App runs in AWS VPC with metadata endpoint at 169.254.169.254.' },
    ],
  },
  {
    slug: 'attack-path-mapper', name: 'Attack Path Mapper', category: 'hunter',
    description: 'Maps attack surfaces and reachability chains from entry point to critical asset',
    system_prompt: 'You are an attack surface specialist focused on mapping exploitation chains. You think in terms of: entry points → intermediate nodes → target assets. You identify every path an attacker could take from initial access to their objective, including lateral movement, privilege escalation, and data access paths.',
    task_prompt: 'Map the attack surface for: {{input}}\n\nIdentify:\n1. All entry points (HTTP endpoints, WebSocket, file uploads, APIs, auth flows)\n2. Intermediate nodes (services, databases, internal APIs, shared resources)\n3. Target assets (secrets, PII, admin access, infrastructure control)\n4. Attack chains connecting entry → intermediate → target\n5. Required prerequisites for each chain (auth level, timing, network position)\n6. Risk score per chain (likelihood × impact)\n\nPresent as a prioritized attack path map with the most viable chains first.',
    risk_level: 'low', placeholder: 'Application URL, architecture description, or codebase overview',
    examples: [
      { label: 'SaaS web app', input: 'Node.js SaaS app: Express API + React frontend. Auth: JWT in httpOnly cookies. Database: PostgreSQL. File storage: S3 with pre-signed URLs. Admin panel at /admin (same origin). User roles: free, pro, admin. Payments via Stripe webhooks.' },
      { label: 'Microservices in K8s', input: '3 microservices in Kubernetes: API gateway (public), auth service (internal), billing service (internal). Inter-service auth via shared JWT secret. Redis for session cache. PostgreSQL for each service. Ingress: nginx with rate limiting.' },
    ],
  },
  {
    slug: 'patch-reviewer', name: 'Patch Reviewer', category: 'defender',
    description: 'Reviews security patches from an attacker perspective — finds bypasses and incomplete fixes',
    system_prompt: 'You are a security patch reviewer who thinks like an attacker reviewing a defender\'s fix. Your job is to find bypasses, edge cases, and incomplete remediations. For every patch:\n1. Understand what vulnerability it fixes\n2. Identify the exact fix mechanism\n3. Try to bypass it (encoding, edge cases, race conditions, alternative paths)\n4. Check for regression (does the fix break other security controls?)\n5. Verify completeness (does it fix ALL variants or just the reported one?)',
    task_prompt: 'Review this security patch/fix from an attacker perspective: {{input}}\n\nFor the fix:\n- What vulnerability does it address?\n- What is the fix mechanism?\n- Can it be bypassed? How?\n- Does it fix ALL variants or just the reported case?\n- Does it introduce any new issues?\n- Are there alternative attack paths that still work?\n\nVerdict: COMPLETE_FIX, PARTIAL_FIX (with bypass details), or INEFFECTIVE_FIX.',
    risk_level: 'low', placeholder: 'Paste code diff, patch description, or before/after code',
    examples: [
      { label: 'XSS fix review', input: 'Before:\n  commentDiv.innerHTML = comment.text;\n\nAfter:\n  commentDiv.textContent = comment.text;\n\nContext: Fix for stored XSS in user comments. Comments support markdown formatting that is now broken by the fix.' },
      { label: 'SQLi fix review', input: 'Before:\n  db.query("SELECT * FROM users WHERE id=" + req.params.id);\n\nAfter:\n  db.query("SELECT * FROM users WHERE id=$1", [req.params.id]);\n\nContext: Only this one endpoint was fixed. 3 other endpoints in the same file use similar string concatenation.' },
    ],
  },
  {
    slug: 'red-team-planner', name: 'Red Team Planner', category: 'hunter',
    description: 'Plans multi-phase red team engagements with MITRE ATT&CK mapping',
    system_prompt: 'You are a red team operations planner who designs comprehensive adversary simulation plans. You map all activities to MITRE ATT&CK techniques, consider OPSEC at every stage, and plan for contingencies. You think in phases: Reconnaissance → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Lateral Movement → Collection → Exfiltration.',
    task_prompt: 'Plan a red team engagement for: {{input}}\n\nProvide:\n1. Scope and rules of engagement\n2. Phase-by-phase attack plan (mapped to MITRE ATT&CK)\n3. Tools and techniques per phase\n4. OPSEC considerations (detection avoidance)\n5. Contingency plans (if blocked at each phase)\n6. Success criteria and evidence collection plan\n7. Estimated timeline\n8. Required infrastructure (proxies, C2, domains)\n\nPresent as a professional red team operations plan.',
    risk_level: 'medium', placeholder: 'Target scope, objectives, and constraints',
    examples: [
      { label: 'E-commerce platform', input: 'Target: E-commerce platform (Ruby on Rails). Scope: *.shop.example.com. Objectives: access customer PII, test payment flow, assess admin panel. Constraints: no DoS, production environment, business hours only, 2-week engagement.' },
      { label: 'Corporate network', input: 'Target: Corporate network (500 employees). Scope: external perimeter + internal after initial access. Objectives: domain admin, access finance share, exfiltrate test data. Constraints: assume breach scenario (VPN credentials provided), no destructive actions, 3-week engagement.' },
    ],
  },
];

function seedAgents() {
  let agents = readJSON(AGENTS_PATH, null);

  // If empty or null, seed from catalog
  if (!agents || agents.length === 0) {
    agents = AGENT_CATALOG.map(a => ({
      id: crypto.randomUUID(),
      ...a,
      builtIn: true,
      enabled: true,
      createdAt: new Date().toISOString(),
    }));
    writeJSON(AGENTS_PATH, agents);
    return agents;
  }

  // Check if categories need updating (old categories → new categories)
  const oldCategories = new Set(['recon', 'appsec', 'cloud', 'iam', 'compliance', 'incident-response', 'threat-hunting', 'forensics', 'network', 'data-security']);
  const hasOldCategories = agents.some(a => a.builtIn && oldCategories.has(a.category));
  if (hasOldCategories) {
    // Re-seed built-in agents with new categories, preserve custom agents
    const customAgents = agents.filter(a => !a.builtIn);
    const newBuiltIn = AGENT_CATALOG.map(a => ({
      id: crypto.randomUUID(),
      ...a,
      builtIn: true,
      enabled: true,
      createdAt: new Date().toISOString(),
    }));
    agents = [...newBuiltIn, ...customAgents];
    writeJSON(AGENTS_PATH, agents);
    console.log('  Agents: re-seeded ' + newBuiltIn.length + ' built-in agents with updated categories');
  }

  return agents;
}

module.exports = function (app, ctx) {
  const { requireAuth, requireAdmin, requireRole, askAI } = ctx;

  // GET /api/agents
  app.get('/api/agents', requireAuth, (req, res) => {
    const agents = seedAgents();
    const runs = readJSON(RUNS_PATH, []);
    const category = req.query.category;

    // Compute run counts
    const runCounts = {};
    for (const r of runs) {
      runCounts[r.agentId] = (runCounts[r.agentId] || 0) + 1;
    }

    // Build examples lookup from catalog (merge even if agents.json lacks examples)
    const examplesMap = {};
    for (const cat of AGENT_CATALOG) {
      if (cat.examples) examplesMap[cat.slug] = cat.examples;
    }

    let result = agents.map(a => ({
      ...a,
      run_count: runCounts[a.id] || 0,
      examples: examplesMap[a.slug] || a.examples || undefined,
    }));

    if (category) result = result.filter(a => a.category === category);
    res.json({ agents: result, total: result.length });
  });

  // POST /api/agents — create custom agent
  app.post('/api/agents', requireRole('analyst'), (req, res) => {
    const { name, category, description, system_prompt, task_prompt } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });

    // Auto-generate prompts if not provided
    const sysPrompt = system_prompt || 'You are a security agent named ' + name + '. ' + (description || 'Analyze the input and provide security findings.');
    const taskPrompt = task_prompt || 'Analyze the following for security issues: {{input}}\n\nProvide detailed findings, severity ratings, and actionable remediation steps.';

    const agents = readJSON(AGENTS_PATH, []);
    const agent = {
      id: crypto.randomUUID(),
      slug: name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''),
      name: escapeHtml(name),
      category: category || 'custom',
      description: escapeHtml(description || ''),
      system_prompt: sysPrompt,
      task_prompt: taskPrompt,
      risk_level: 'medium',
      tools_allowed: [],
      builtIn: false,
      enabled: true,
      createdAt: new Date().toISOString(),
    };
    agents.push(agent);
    writeJSON(AGENTS_PATH, agents);
    res.json({ success: true, agent });
  });

  // GET /api/agents/:id
  app.get('/api/agents/:id', requireAuth, (req, res) => {
    const agents = readJSON(AGENTS_PATH, []);
    const agent = agents.find(a => a.id === req.params.id || a.slug === req.params.id);
    if (!agent) return res.status(404).json({ error: 'Agent not found' });

    const runs = readJSON(RUNS_PATH, []);
    agent.run_count = runs.filter(r => r.agentId === agent.id).length;
    res.json(agent);
  });

  // PATCH /api/agents/:id
  app.patch('/api/agents/:id', requireRole('analyst'), (req, res) => {
    const agents = readJSON(AGENTS_PATH, []);
    const agent = agents.find(a => a.id === req.params.id);
    if (!agent) return res.status(404).json({ error: 'Agent not found' });

    const { name, category, description, system_prompt, task_prompt, risk_level, enabled, tools_allowed } = req.body;
    if (name !== undefined) agent.name = escapeHtml(name);
    if (category !== undefined) agent.category = category;
    if (description !== undefined) agent.description = escapeHtml(description);
    if (system_prompt !== undefined) agent.system_prompt = system_prompt;
    if (task_prompt !== undefined) agent.task_prompt = task_prompt;
    if (risk_level !== undefined) agent.risk_level = risk_level;
    if (enabled !== undefined) agent.enabled = enabled;
    if (tools_allowed !== undefined) agent.tools_allowed = tools_allowed;
    agent.updatedAt = new Date().toISOString();

    writeJSON(AGENTS_PATH, agents);
    res.json({ success: true, agent });
  });

  // POST /api/agents/:id/run — execute agent
  app.post('/api/agents/:id/run', requireRole('analyst'), async (req, res) => {
    try {
      const agents = readJSON(AGENTS_PATH, []);
      const agent = agents.find(a => a.id === req.params.id || a.slug === req.params.id);
      if (!agent) return res.status(404).json({ error: 'Agent not found' });
      if (!agent.enabled) return res.status(400).json({ error: 'Agent is disabled' });

      const { input } = req.body;
      if (!input) return res.status(400).json({ error: 'input required — tell the agent what to analyze' });

      if (!askAI) return res.json({ run: { output: 'AI provider not configured. Go to Settings > AI Provider.', status: 'failed' } });

      const prompt = agent.system_prompt + '\n\n' + (agent.task_prompt || 'Analyze: {{input}}').replace(/\{\{input\}\}/g, input.substring(0, 2000));

      const startTime = Date.now();
      let output;
      try {
        output = await askAI(prompt, { timeout: 180000 });
      } catch (e) {
        output = null;
      }

      const run = {
        id: crypto.randomUUID(),
        agentId: agent.id,
        agentName: agent.name,
        input: input.substring(0, 1000),
        output: output || 'Agent could not produce output. Check AI provider configuration in Settings.',
        status: output ? 'completed' : 'failed',
        duration: Date.now() - startTime,
        createdAt: new Date().toISOString(),
        createdBy: req.user ? req.user.user : 'unknown',
      };

      const runs = readJSON(RUNS_PATH, []);
      runs.push(run);
      if (runs.length > 1000) runs.splice(0, runs.length - 1000);
      writeJSON(RUNS_PATH, runs);

      res.json({ run });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/agents/:id/runs — run history (also accept /history for frontend compat)
  app.get('/api/agents/:id/runs', requireAuth, (req, res) => {
    const runs = readJSON(RUNS_PATH, []);
    const agentRuns = runs.filter(r => r.agentId === req.params.id).reverse();
    res.json({ runs: agentRuns.slice(0, 50) });
  });
  app.get('/api/agents/:id/history', requireAuth, (req, res) => {
    const runs = readJSON(RUNS_PATH, []);
    const agentRuns = runs.filter(r => r.agentId === req.params.id).reverse();
    res.json({ runs: agentRuns.slice(0, 50) });
  });

  // DELETE /api/agents/:id
  app.delete('/api/agents/:id', requireAdmin, (req, res) => {
    let agents = readJSON(AGENTS_PATH, []);
    const agent = agents.find(a => a.id === req.params.id);
    if (!agent) return res.status(404).json({ error: 'Agent not found' });
    if (agent.builtIn) return res.status(400).json({ error: 'Cannot delete built-in agents. Disable them instead.' });
    agents = agents.filter(a => a.id !== req.params.id);
    writeJSON(AGENTS_PATH, agents);
    res.json({ success: true });
  });
};
