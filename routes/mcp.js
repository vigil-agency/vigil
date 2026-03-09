/**
 * MCP Server Route — Model Context Protocol (Streamable HTTP)
 * Vigil Security — 22 tools, 6 resources, 7 prompts
 *
 * SDK: @modelcontextprotocol/sdk v1.x
 * Transport: Streamable HTTP (stateless, one request = one connection)
 */
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { z } = require('zod');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA = path.join(__dirname, '..', 'data');

function readJSON(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return fallback; }
}

module.exports = function (app, ctx) {

  function createMcpServer() {
    const server = new McpServer({
      name: 'vigil-security',
      version: '1.0.0',
      instructions: 'Vigil Security — AI-powered security operations. Use tools to check security posture, scan for vulnerabilities, investigate threats, manage incidents, and generate reports.',
    });

    // ════════════════════════════════════════════════════════════════════════
    // TOOLS (22)
    // ════════════════════════════════════════════════════════════════════════

    // 1. check_posture
    server.tool('check_posture', 'Get current security posture score and breakdown', {},
      async () => {
        try {
          if (ctx.getPostureScore) {
            const posture = await ctx.getPostureScore();
            return { content: [{ type: 'text', text: JSON.stringify(posture, null, 2) }] };
          }
          return { content: [{ type: 'text', text: 'Posture scoring not available' }], isError: true };
        } catch (e) {
          return { content: [{ type: 'text', text: 'Error: ' + e.message }], isError: true };
        }
      }
    );

    // 2. scan_ports
    server.tool('scan_ports', 'Run an nmap port scan on a target', {
      target: z.string().describe('IP address or hostname to scan'),
      ports: z.string().default('1-1024').describe('Port range (e.g., 1-1024, 22,80,443)'),
    }, async ({ target, ports }) => {
      try {
        if (!/^[a-zA-Z0-9.\-:]+$/.test(target)) return { content: [{ type: 'text', text: 'Invalid target format' }], isError: true };
        if (!/^[\d,\-]+$/.test(ports)) return { content: [{ type: 'text', text: 'Invalid port range' }], isError: true };
        const result = await ctx.execFileSafe('nmap', ['-Pn', '-p', ports, '--open', '-T4', target], { timeout: 120000 });
        return { content: [{ type: 'text', text: result.stdout || result.stderr || 'No output' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'nmap error: ' + e.message }], isError: true };
      }
    });

    // 3. scan_vulnerabilities
    server.tool('scan_vulnerabilities', 'Run a nuclei vulnerability scan on a target', {
      target: z.string().describe('URL or hostname to scan'),
      severity: z.string().default('critical,high').describe('Severity filter'),
    }, async ({ target, severity }) => {
      try {
        if (!/^[a-zA-Z0-9.\-:\/]+$/.test(target)) return { content: [{ type: 'text', text: 'Invalid target format' }], isError: true };
        const validSev = severity.split(',').filter(s => ['critical','high','medium','low','info'].includes(s.trim())).join(',') || 'critical,high';
        const result = await ctx.execFileSafe('nuclei', ['-u', target, '-severity', validSev, '-silent'], { timeout: 300000 });
        return { content: [{ type: 'text', text: result.stdout || 'No vulnerabilities found (or nuclei not installed)' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'nuclei error: ' + e.message }], isError: true };
      }
    });

    // 4. check_ssl
    server.tool('check_ssl', 'Check SSL/TLS certificate for a domain', {
      domain: z.string().describe('Domain to check SSL certificate'),
    }, async ({ domain }) => {
      try {
        const safeDomain = domain.replace(/[^a-zA-Z0-9.\-]/g, '');
        if (!safeDomain || safeDomain.length > 253) return { content: [{ type: 'text', text: 'Invalid domain' }], isError: true };
        const result = await ctx.execCommand(
          `echo | openssl s_client -servername ${safeDomain} -connect ${safeDomain}:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null`,
          { timeout: 15000 }
        );
        return { content: [{ type: 'text', text: result.stdout || 'Could not retrieve certificate' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'SSL check error: ' + e.message }], isError: true };
      }
    });

    // 5. query_logs (cross-platform — uses Vigil security data stores)
    server.tool('query_logs', 'Search security logs and events using natural language', {
      query: z.string().describe('What to search for (e.g., "recent threats", "critical vulnerabilities", "scan results")'),
    }, async ({ query }) => {
      try {
        // Gather from Vigil data stores (works on all platforms)
        const stores = {
          'audit-log': readJSON(path.join(DATA, 'audit-log.json'), []),
          'threats': readJSON(path.join(DATA, 'threats.json'), []),
          'alerts': readJSON(path.join(DATA, 'alerts.json'), []),
          'incidents': readJSON(path.join(DATA, 'incidents.json'), []),
          'hunts': readJSON(path.join(DATA, 'hunts.json'), []),
        };
        const summary = Object.entries(stores)
          .filter(([, v]) => v.length > 0)
          .map(([k, v]) => `${k}: ${v.length} records\n${v.slice(-5).map(e => JSON.stringify(e)).join('\n')}`)
          .join('\n\n');

        if (!summary) return { content: [{ type: 'text', text: 'No security events found. Run scans or use other Vigil features to generate data.' }] };

        if (ctx.askAI) {
          const prompt = `User query: "${query}"\n\nSecurity data:\n${summary.substring(0, 4000)}\n\nAnswer the query using the data. Be concise (3-5 sentences). No markdown.`;
          const analysis = await ctx.askAI(prompt, { timeout: 20000 });
          return { content: [{ type: 'text', text: analysis || summary.substring(0, 2000) }] };
        }
        return { content: [{ type: 'text', text: summary.substring(0, 3000) }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Log query error: ' + e.message }], isError: true };
      }
    });

    // 6. osint_domain
    server.tool('osint_domain', 'Perform domain reconnaissance', {
      domain: z.string().describe('Domain to investigate'),
    }, async ({ domain }) => {
      try {
        const safeDomain = domain.replace(/[^a-zA-Z0-9.\-]/g, '');
        if (!safeDomain) return { content: [{ type: 'text', text: 'Invalid domain' }], isError: true };
        const results = {};
        try {
          const dig = await ctx.execFileSafe('dig', ['+short', 'A', safeDomain], { timeout: 10000 });
          results.A = dig.stdout.trim().split('\n').filter(Boolean);
        } catch {}
        try {
          const mx = await ctx.execFileSafe('dig', ['+short', 'MX', safeDomain], { timeout: 10000 });
          results.MX = mx.stdout.trim().split('\n').filter(Boolean);
        } catch {}
        try {
          const ns = await ctx.execFileSafe('dig', ['+short', 'NS', safeDomain], { timeout: 10000 });
          results.NS = ns.stdout.trim().split('\n').filter(Boolean);
        } catch {}
        return { content: [{ type: 'text', text: JSON.stringify({ domain: safeDomain, dns: results }, null, 2) }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'OSINT error: ' + e.message }], isError: true };
      }
    });

    // 7. osint_ip
    server.tool('osint_ip', 'Perform IP address lookup', {
      ip: z.string().describe('IP address to look up'),
    }, async ({ ip }) => {
      try {
        const http = require('http');
        const geo = await new Promise((resolve, reject) => {
          const r = http.get(`http://ip-api.com/json/${ip}`, { timeout: 10000 }, (resp) => {
            let d = '';
            resp.on('data', c => d += c);
            resp.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve({ error: 'parse failed' }); } });
          });
          r.on('error', reject);
          r.setTimeout(10000, () => { r.destroy(); reject(new Error('timeout')); });
        });
        return { content: [{ type: 'text', text: JSON.stringify(geo, null, 2) }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'IP lookup error: ' + e.message }], isError: true };
      }
    });

    // 8. triage_alert
    server.tool('triage_alert', 'AI triage of a security alert', {
      alertTitle: z.string().describe('Title of the alert'),
      alertDetails: z.string().describe('Alert details and context'),
      severity: z.string().default('medium').describe('Alert severity'),
    }, async ({ alertTitle, alertDetails, severity }) => {
      try {
        const prompt = `Triage this security alert. Respond with verdict (true_positive/false_positive/needs_investigation), confidence (0-100), and 2-3 sentence reasoning.\n\nAlert: ${alertTitle}\nSeverity: ${severity}\nDetails: ${alertDetails}`;
        const result = await ctx.askAI(prompt, { timeout: 20000 });
        return { content: [{ type: 'text', text: result || 'Triage unavailable' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Triage error: ' + e.message }], isError: true };
      }
    });

    // 9. hunt_threat
    server.tool('hunt_threat', 'Investigate a threat hypothesis', {
      hypothesis: z.string().describe('Threat hypothesis to investigate'),
    }, async ({ hypothesis }) => {
      try {
        if (process.platform === 'win32') {
          return { content: [{ type: 'text', text: 'Threat hunting requires Linux' }] };
        }
        // Gather quick evidence
        const cmds = {
          processes: 'ps aux --sort=-%cpu 2>/dev/null | head -15',
          connections: 'ss -tunapl 2>/dev/null | head -20',
          logins: 'last -10 2>/dev/null',
        };
        const evidence = {};
        for (const [key, cmd] of Object.entries(cmds)) {
          try {
            const r = await ctx.execCommand(cmd, { timeout: 10000 });
            evidence[key] = r.stdout.substring(0, 1000);
          } catch {}
        }
        const prompt = `Hypothesis: ${hypothesis}\n\nEvidence:\n${JSON.stringify(evidence, null, 2)}\n\nAnalyze the evidence. Is the hypothesis confirmed, not confirmed, or inconclusive? Explain in 3-5 sentences.`;
        const analysis = await ctx.askAI(prompt, { timeout: 30000 });
        return { content: [{ type: 'text', text: analysis || 'Analysis unavailable' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Hunt error: ' + e.message }], isError: true };
      }
    });

    // 10. run_agent
    server.tool('run_agent', 'Execute a security agent by name or slug', {
      agentSlug: z.string().describe('Agent slug or name (e.g., port-scanner, firewall-auditor)'),
      input: z.string().describe('Input data for the agent'),
    }, async ({ agentSlug, input }) => {
      try {
        const agents = readJSON(path.join(DATA, 'agents.json'), []);
        const agent = agents.find(a => a.slug === agentSlug || a.name.toLowerCase() === agentSlug.toLowerCase());
        if (!agent) return { content: [{ type: 'text', text: 'Agent not found: ' + agentSlug }], isError: true };
        const prompt = agent.system_prompt + '\n\n' + agent.task_prompt.replace(/\{\{input\}\}/g, input);
        const output = await ctx.askAI(prompt, { timeout: 60000 });
        return { content: [{ type: 'text', text: output || 'No output from agent' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Agent error: ' + e.message }], isError: true };
      }
    });

    // 11. launch_campaign
    server.tool('launch_campaign', 'Start a multi-agent security campaign', {
      goal: z.string().describe('Campaign goal (e.g., "full security audit of example.com")'),
      maxAgents: z.number().default(3).describe('Maximum number of agents to run'),
    }, async ({ goal, maxAgents }) => {
      try {
        const agents = readJSON(path.join(DATA, 'agents.json'), []);
        const goalLower = goal.toLowerCase();
        const selected = agents.filter(a => a.enabled).filter(a => {
          const text = (a.name + ' ' + a.description + ' ' + a.category).toLowerCase();
          return goalLower.split(/\s+/).some(word => word.length > 3 && text.includes(word));
        }).slice(0, maxAgents);

        if (selected.length === 0) return { content: [{ type: 'text', text: 'No matching agents for this goal' }] };

        const results = [];
        for (const agent of selected) {
          try {
            const prompt = agent.system_prompt + '\n\n' + agent.task_prompt.replace(/\{\{input\}\}/g, goal);
            const output = await ctx.askAI(prompt, { timeout: 60000 });
            results.push({ agent: agent.name, output: (output || 'No output').substring(0, 500) });
          } catch (e) {
            results.push({ agent: agent.name, error: e.message });
          }
        }
        return { content: [{ type: 'text', text: JSON.stringify({ goal, agentsRun: results.length, results }, null, 2) }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Campaign error: ' + e.message }], isError: true };
      }
    });

    // 12. generate_report
    server.tool('generate_report', 'Generate a security report', {
      type: z.enum(['security-audit', 'vulnerability', 'compliance', 'incident', 'executive']).describe('Report type'),
    }, async ({ type }) => {
      try {
        const scans = readJSON(path.join(DATA, 'scans.json'), []);
        const findings = [];
        for (const s of scans) { if (s.findings) findings.push(...s.findings); }
        const threats = readJSON(path.join(DATA, 'threats.json'), []);
        const incidents = readJSON(path.join(DATA, 'incidents.json'), []);

        const prompt = `Generate a brief ${type} security report.\n\nData:\n- Findings: ${findings.length} total (${findings.filter(f => f.severity === 'critical').length} critical)\n- Active threats: ${threats.filter(t => t.status === 'active').length}\n- Open incidents: ${incidents.filter(i => i.status !== 'closed').length}\n\nWrite a concise report with key findings, risks, and recommendations.`;
        const report = await ctx.askAI(prompt, { timeout: 30000 });
        return { content: [{ type: 'text', text: report || 'Report generation unavailable' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Report error: ' + e.message }], isError: true };
      }
    });

    // 13. compliance_check
    server.tool('compliance_check', 'Check compliance against a framework', {
      framework: z.enum(['soc2', 'iso27001', 'nist800-53']).describe('Compliance framework'),
    }, async ({ framework }) => {
      try {
        // Quick check summary
        const names = { soc2: 'SOC 2 Type II', iso27001: 'ISO 27001:2022', 'nist800-53': 'NIST 800-53 Rev. 5' };
        const prompt = `You are a compliance auditor. Give a brief (5-7 sentence) assessment of a server's likely compliance with ${names[framework] || framework}. Consider: access controls, encryption, logging, monitoring, incident response, vulnerability management. This is a Linux server running a Node.js security platform.`;
        const result = await ctx.askAI(prompt, { timeout: 20000 });
        return { content: [{ type: 'text', text: result || 'Compliance check unavailable' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Compliance error: ' + e.message }], isError: true };
      }
    });

    // 14. list_findings
    server.tool('list_findings', 'Get vulnerability findings', {
      severity: z.string().default('all').describe('Filter: critical, high, medium, low, or all'),
      limit: z.number().default(20).describe('Max findings to return'),
    }, async ({ severity, limit }) => {
      try {
        const scans = readJSON(path.join(DATA, 'scans.json'), []);
        let findings = [];
        for (const s of scans) { if (s.findings) findings.push(...s.findings); }
        if (severity !== 'all') findings = findings.filter(f => f.severity === severity);
        const result = findings.slice(0, limit).map(f => ({
          id: f.id, title: f.title, severity: f.severity, type: f.type, status: f.status,
        }));
        return { content: [{ type: 'text', text: JSON.stringify({ total: findings.length, findings: result }, null, 2) }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Error: ' + e.message }], isError: true };
      }
    });

    // 15. incident_create
    server.tool('incident_create', 'Create a security incident', {
      title: z.string().describe('Incident title'),
      severity: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
      description: z.string().describe('Incident description'),
      type: z.string().default('security').describe('Incident type'),
    }, async ({ title, severity, description, type }) => {
      try {
        const incidents = readJSON(path.join(DATA, 'incidents.json'), []);
        const incident = {
          id: crypto.randomUUID(),
          title, severity, description, type,
          status: 'open',
          timeline: [{ id: crypto.randomUUID(), event: 'Incident created via MCP', detail: description, timestamp: new Date().toISOString(), actor: 'mcp' }],
          createdAt: new Date().toISOString(),
          createdBy: 'mcp',
        };
        incidents.push(incident);
        fs.mkdirSync(DATA, { recursive: true });
        fs.writeFileSync(path.join(DATA, 'incidents.json'), JSON.stringify(incidents, null, 2));
        return { content: [{ type: 'text', text: 'Incident created: ' + incident.id + ' — ' + title }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Error: ' + e.message }], isError: true };
      }
    });

    // 16. run_code_audit
    server.tool('run_code_audit', 'Run AI-powered source code vulnerability scan on a directory', {
      target: z.string().describe('Directory path to scan (e.g., /app/routes)'),
      languages: z.array(z.string()).default([]).describe('Languages to scan: javascript, typescript, python, ruby, php, java, go, csharp'),
    }, async ({ target, languages }) => {
      try {
        const { runCodeAudit, discoverFiles, VULN_TYPES } = require('../lib/code-audit');
        const files = discoverFiles(target, languages);
        if (files.length === 0) return { content: [{ type: 'text', text: 'No source files found in ' + target }] };

        if (!ctx.askAIJSON) return { content: [{ type: 'text', text: 'AI provider not configured' }], isError: true };

        // Create scan record
        const scanId = crypto.randomUUID();
        const scan = {
          id: scanId, type: 'code-audit', scanType: 'code-audit', target,
          options: { languages, vulnTypes: Object.keys(VULN_TYPES) },
          status: 'running', findings: [], findingsCount: 0,
          createdAt: new Date().toISOString(), createdBy: 'mcp',
        };
        const scansPath = path.join(DATA, 'scans.json');
        const scans = readJSON(scansPath, []);
        scans.push(scan);
        fs.writeFileSync(scansPath, JSON.stringify(scans, null, 2));

        // Run in background — return immediately
        runCodeAudit(target, {
          askAIJSON: ctx.askAIJSON,
          languages,
          vulnTypes: Object.keys(VULN_TYPES),
          timeout: 120000,
          onProgress: (progress) => {
            if (ctx.io) ctx.io.emit('code_audit_progress', { scanId, phase: progress.phase, message: progress.message });
          },
        }).then(result => {
          scan.findings = result.findings.map(f => ({
            id: f.id, scanId, type: 'code_vuln', title: `[${f.vulnType}] ${f.title}`,
            severity: f.severity, details: f.description, file: f.file, line: f.line,
            cwe: f.cwe, mitre: f.mitre, confidence: f.confidence, vulnType: f.vulnType, status: 'open',
          }));
          scan.findingsCount = scan.findings.length;
          scan.status = 'completed';
          scan.completedAt = new Date().toISOString();
          scan.duration = result.duration;
          scan.summary = result.summary;
          scan.filesAnalyzed = result.filesAnalyzed;
          const allScans = readJSON(scansPath, []);
          const idx = allScans.findIndex(s => s.id === scanId);
          if (idx >= 0) allScans[idx] = scan;
          fs.writeFileSync(scansPath, JSON.stringify(allScans, null, 2));
          if (ctx.io) ctx.io.emit('scan_complete', { id: scanId, type: 'code-audit', status: 'completed', findingsCount: scan.findingsCount });
        }).catch(e => {
          scan.status = 'failed'; scan.error = e.message; scan.completedAt = new Date().toISOString();
          const allScans = readJSON(scansPath, []);
          const idx = allScans.findIndex(s => s.id === scanId);
          if (idx >= 0) allScans[idx] = scan;
          fs.writeFileSync(scansPath, JSON.stringify(allScans, null, 2));
        });

        return { content: [{ type: 'text', text: `Code audit started. ${files.length} files found.\nScan ID: ${scanId}\nCheck results with get_code_audit_results tool.` }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Code audit error: ' + e.message }], isError: true };
      }
    });

    // 17. get_code_audit_results
    server.tool('get_code_audit_results', 'Get results of a code audit scan', {
      scanId: z.string().default('latest').describe('Scan ID or "latest" for most recent code audit'),
    }, async ({ scanId }) => {
      try {
        const scans = readJSON(path.join(DATA, 'scans.json'), []);
        let scan;
        if (scanId === 'latest') {
          scan = scans.filter(s => s.scanType === 'code-audit').pop();
        } else {
          scan = scans.find(s => s.id === scanId);
        }
        if (!scan) return { content: [{ type: 'text', text: 'No code audit scan found' }] };
        const summary = {
          id: scan.id, status: scan.status, target: scan.target,
          findingCount: (scan.findings || []).length,
          findings: (scan.findings || []).slice(0, 10).map(f => ({
            title: f.title, severity: f.severity, confidence: f.confidence, file: f.file, vulnType: f.vulnType,
          })),
          summary: scan.summary,
        };
        return { content: [{ type: 'text', text: JSON.stringify(summary, null, 2) }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Error: ' + e.message }], isError: true };
      }
    });

    // 18. detect_waf
    server.tool('detect_waf', 'Detect WAF/CDN on a target URL', {
      target: z.string().describe('URL to scan (e.g., https://example.com)'),
      probeMode: z.enum(['passive', 'active']).default('passive').describe('passive=headers only, active=send probe payloads'),
    }, async ({ target, probeMode }) => {
      try {
        if (!/^https?:\/\//i.test(target)) target = 'https://' + target;
        const { detectWAF } = require('./scan-api');
        const result = await detectWAF(target, probeMode);

        if (result.detected) {
          return { content: [{ type: 'text', text: `WAF Detected: ${result.waf.name} (${result.waf.vendor})\nConfidence: ${result.confidence}%\nEvidence: ${(result.evidence || []).map(e => e.method + ': ' + e.detail).join(', ')}` }] };
        }
        return { content: [{ type: 'text', text: 'No WAF detected on ' + target }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'WAF detection error: ' + e.message }], isError: true };
      }
    });

    // 19. list_proxy_nodes
    server.tool('list_proxy_nodes', 'List ephemeral proxy nodes and tunnel status', {},
      async () => {
        try {
          const proxy = require('../lib/ephemeral-proxy');
          const status = proxy.getStatus();
          return { content: [{ type: 'text', text: JSON.stringify(status, null, 2) }] };
        } catch (e) {
          return { content: [{ type: 'text', text: 'Error: ' + e.message }], isError: true };
        }
      }
    );

    // 20. create_proxy_node
    server.tool('create_proxy_node', 'Create a disposable Codespace proxy node for anonymous scanning', {
      repo: z.string().default('github/codespaces-blank').describe('GitHub repo for the Codespace'),
      machineType: z.string().default('basicLinux32gb').describe('Machine type'),
    }, async ({ repo, machineType }) => {
      try {
        const proxy = require('../lib/ephemeral-proxy');
        const gh = await proxy.checkGHInstalled();
        if (!gh.installed) return { content: [{ type: 'text', text: 'gh CLI not installed. Install with: apt install gh && gh auth login' }], isError: true };
        const auth = await proxy.checkGHAuth();
        if (!auth.authenticated) return { content: [{ type: 'text', text: 'GitHub not authenticated. Run: gh auth login' }], isError: true };
        const node = await proxy.createCodespace(repo, machineType);
        return { content: [{ type: 'text', text: 'Proxy node created: ' + node.name + '\nUse start_proxy_tunnel to connect.' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Create error: ' + e.message }], isError: true };
      }
    });

    // 21. start_proxy_tunnel
    server.tool('start_proxy_tunnel', 'Start SOCKS5 tunnel through a proxy node', {
      name: z.string().describe('Codespace name'),
      port: z.number().default(1080).describe('Local SOCKS5 port'),
    }, async ({ name, port }) => {
      try {
        const proxy = require('../lib/ephemeral-proxy');
        const result = await proxy.startTunnel(name, port);
        return { content: [{ type: 'text', text: `Tunnel ${result.status}: SOCKS5 at 127.0.0.1:${result.port}\nExit IP: ${result.exitIP || 'detecting...'}` }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Tunnel error: ' + e.message }], isError: true };
      }
    });

    // 22. plan_proxy_infrastructure
    server.tool('plan_proxy_infrastructure', 'AI-plan disposable proxy infrastructure for an engagement', {
      engagement: z.string().describe('Engagement description (scope, targets, scan types, timeline)'),
    }, async ({ engagement }) => {
      try {
        if (!ctx.askAIJSON) return { content: [{ type: 'text', text: 'AI not configured' }], isError: true };
        const prompt = `You are a penetration testing infrastructure planner. Recommend disposable proxy infrastructure for:\n\n${engagement}\n\nRespond concisely: recommended node count, IP rotation frequency (minutes), scan strategy (sequential/parallel/round-robin), OPSEC level, and which scan phases need proxying.`;
        const result = await ctx.askAI(prompt, { timeout: 30000 });
        return { content: [{ type: 'text', text: result || 'No response' }] };
      } catch (e) {
        return { content: [{ type: 'text', text: 'Planning error: ' + e.message }], isError: true };
      }
    });

    // ════════════════════════════════════════════════════════════════════════
    // RESOURCES (6)
    // ════════════════════════════════════════════════════════════════════════

    server.resource('posture', 'vigil://posture', { description: 'Current security posture overview' },
      async (uri) => {
        let posture = { score: 'unknown', grade: 'N/A' };
        if (ctx.getPostureScore) {
          try { posture = await ctx.getPostureScore(); } catch {}
        }
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(posture, null, 2) }] };
      }
    );

    server.resource('threats', 'vigil://threats', { description: 'Active security threats' },
      async (uri) => {
        const threats = readJSON(path.join(DATA, 'threats.json'), []);
        const active = threats.filter(t => t.status === 'active').map(t => ({
          id: t.id, type: t.type, title: t.title, severity: t.severity, detectedAt: t.detectedAt,
        }));
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(active, null, 2) }] };
      }
    );

    server.resource('findings', 'vigil://findings', { description: 'Open vulnerability findings' },
      async (uri) => {
        const scans = readJSON(path.join(DATA, 'scans.json'), []);
        const findings = [];
        for (const s of scans) {
          if (s.findings) {
            for (const f of s.findings) {
              if (f.status === 'open') {
                findings.push({ id: f.id, title: f.title, severity: f.severity, type: f.type });
              }
            }
          }
        }
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(findings, null, 2) }] };
      }
    );

    server.resource('code-audit-findings', 'vigil://code-audit-findings', { description: 'Code audit vulnerability findings' },
      async (uri) => {
        const scans = readJSON(path.join(DATA, 'scans.json'), []);
        const codeScans = scans.filter(s => s.scanType === 'code-audit');
        const findings = [];
        for (const s of codeScans) {
          if (s.findings) findings.push(...s.findings.map(f => ({ ...f, scanId: s.id, target: s.target })));
        }
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(findings, null, 2) }] };
      }
    );

    server.resource('waf-signatures', 'vigil://waf-signatures', { description: 'WAF detection signature database' },
      async (uri) => {
        const sigs = ['Cloudflare', 'AWS WAF', 'AWS CloudFront', 'Akamai', 'Imperva/Incapsula', 'F5 BIG-IP ASM', 'FortiWeb', 'ModSecurity', 'Barracuda', 'Citrix NetScaler', 'Sucuri', 'Palo Alto', 'Google Cloud Armor', 'Fastly', 'DataDome', 'PerimeterX', 'Wordfence', 'Azure Front Door', 'DDoS-Guard', 'StackPath', 'KeyCDN', 'Edgecast/Verizon', 'Radware', 'SonicWall', 'Wallarm', 'Reblaze', 'Comodo/cWatch', 'Armor Defense', 'Alert Logic', 'Signal Sciences'];
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify({ count: sigs.length, signatures: sigs }, null, 2) }] };
      }
    );

    server.resource('proxy-nodes', 'vigil://proxy-nodes', { description: 'Ephemeral proxy node status' },
      async (uri) => {
        try {
          const proxy = require('../lib/ephemeral-proxy');
          const status = proxy.getStatus();
          return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(status, null, 2) }] };
        } catch {
          return { contents: [{ uri: uri.href, mimeType: 'application/json', text: '{"nodes":[],"activeTunnels":[]}' }] };
        }
      }
    );

    // ════════════════════════════════════════════════════════════════════════
    // PROMPTS (7)
    // ════════════════════════════════════════════════════════════════════════

    server.prompt('security_audit', 'Full security assessment of the system', {},
      () => ({
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Perform a full security audit. Use check_posture to get the security score, list_findings to see vulnerabilities, and scan_ports on localhost to check open ports. Then generate a security-audit report with generate_report. Provide a comprehensive assessment with prioritized recommendations.' },
        }],
      })
    );

    server.prompt('incident_response', 'Guided incident investigation', {
      incident: z.string().describe('Brief description of the security incident'),
    }, ({ incident }) => ({
      messages: [{
        role: 'user',
        content: { type: 'text', text: `Investigate this security incident: "${incident}". Use hunt_threat to gather evidence, query_logs to search for related activity, and check_posture for overall security state. Create an incident with incident_create if warranted. Provide a step-by-step investigation report.` },
      }],
    }));

    server.prompt('threat_briefing', 'Daily security threat summary', {},
      () => ({
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Generate a daily threat briefing. Use check_posture for the security score, list_findings for open vulnerabilities, and read the vigil://threats resource for active threats. Summarize the current threat landscape, highlight critical items, and recommend actions for today.' },
        }],
      })
    );

    server.prompt('compliance_report', 'Framework compliance assessment', {
      framework: z.enum(['soc2', 'iso27001', 'nist800-53']).default('soc2').describe('Compliance framework'),
    }, ({ framework }) => ({
      messages: [{
        role: 'user',
        content: { type: 'text', text: `Assess compliance with ${framework}. Use compliance_check to evaluate the framework, check_posture for security score, and list_findings for vulnerabilities. Generate a compliance report with findings, gaps, and a remediation roadmap.` },
      }],
    }));

    server.prompt('code_security_review', 'AI-powered source code security review', {
      target: z.string().default('/app/routes').describe('Directory path to audit'),
    }, ({ target }) => ({
      messages: [{
        role: 'user',
        content: { type: 'text', text: `Perform an AI-powered code security review of "${target}". Use run_code_audit to start the scan, then get_code_audit_results to retrieve findings. Read the vigil://code-audit-findings resource for context. Analyze each finding, assess exploitability, and provide prioritized remediation recommendations.` },
      }],
    }));

    server.prompt('waf_reconnaissance', 'WAF detection and analysis for a target', {
      target: z.string().describe('Target URL to fingerprint'),
    }, ({ target }) => ({
      messages: [{
        role: 'user',
        content: { type: 'text', text: `Perform WAF reconnaissance on "${target}". Use detect_waf with passive mode first, then active mode if needed. Read vigil://waf-signatures for the full signature database. Analyze the detected WAF, explain its capabilities and known bypass techniques, and recommend a penetration testing strategy that accounts for the WAF presence.` },
      }],
    }));

    server.prompt('anonymous_pentest_setup', 'Plan and provision anonymous scanning infrastructure', {
      engagement: z.string().describe('Engagement scope and requirements'),
    }, ({ engagement }) => ({
      messages: [{
        role: 'user',
        content: { type: 'text', text: `Plan anonymous scanning infrastructure for: "${engagement}". Use plan_proxy_infrastructure for AI recommendations. Check vigil://proxy-nodes for existing nodes. Use list_proxy_nodes to see current status. If nodes are needed, use create_proxy_node and start_proxy_tunnel. Provide a complete infrastructure setup plan with OPSEC considerations.` },
      }],
    }));

    return server;
  }

  // ── POST /mcp — Streamable HTTP MCP endpoint ──────────────────────────

  app.post('/mcp', ctx.requireAuth, async (req, res) => {
    try {
      const server = createMcpServer();
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on('close', () => { transport.close().catch(() => {}); server.close().catch(() => {}); });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (e) {
      if (!res.headersSent) {
        res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: e.message }, id: null });
      }
    }
  });

  // GET /mcp — SSE not supported in stateless mode
  app.get('/mcp', ctx.requireAuth, (req, res) => {
    res.writeHead(405).end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'SSE not supported in stateless mode. Use POST.' }, id: null }));
  });

  // DELETE /mcp — Session termination (no-op)
  app.delete('/mcp', ctx.requireAuth, (req, res) => {
    res.status(200).json({ success: true });
  });

  // ── POST /api/mcp/test — GUI test endpoint using InMemoryTransport ────

  app.post('/api/mcp/test', ctx.requireAuth, async (req, res) => {
    const { method, params } = req.body;
    if (!method) return res.status(400).json({ error: 'method required' });

    try {
      const server = createMcpServer();
      const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
      const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const client = new Client({ name: 'vigil-test', version: '1.0.0' });
      await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);

      let result;
      if (method === 'tools/list') {
        result = await client.listTools();
      } else if (method === 'resources/list') {
        result = await client.listResources();
      } else if (method === 'prompts/list') {
        result = await client.listPrompts();
      } else if (method === 'tools/call') {
        result = await client.callTool(params || {}, undefined, { timeout: 300000 });
      } else if (method === 'prompts/get') {
        result = await client.getPrompt({ name: (params || {}).name, arguments: (params || {}).arguments || {} }, undefined, { timeout: 300000 });
      } else if (method === 'resources/read') {
        result = await client.readResource(params || {});
      } else {
        result = { error: 'Unknown method: ' + method };
      }

      await client.close();
      await server.close();
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── MCP connection info ───────────────────────────────────────────────

  app.get('/api/mcp/info', ctx.requireAuth, (req, res) => {
    const host = req.headers.host || 'localhost:3001';
    const protocol = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
    const mcpUrl = protocol + '://' + host + '/mcp';
    res.json({
      url: mcpUrl,
      transport: 'streamable-http',
      version: '1.0.0',
      tools: 22,
      resources: 6,
      prompts: 7,
      instructions: {
        claudeDesktop: {
          config: {
            mcpServers: {
              vigil: {
                type: 'streamable-http',
                url: mcpUrl,
                headers: { Cookie: 'vigil_session=YOUR_SESSION_TOKEN' },
              },
            },
          },
          note: 'Replace YOUR_SESSION_TOKEN with your Vigil session cookie value',
        },
        claudeCode: 'claude mcp add --transport http vigil ' + mcpUrl,
        curl: 'curl -X POST ' + mcpUrl + ' -H "Content-Type: application/json" -b "vigil_session=TOKEN" -d \'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\'',
      },
    });
  });
};
