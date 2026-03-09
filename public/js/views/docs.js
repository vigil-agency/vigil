/* Vigil v1.0 — Documentation View */
Views.docs = {
  _activeSection: 'getting-started',

  init: function() {
    var el = document.getElementById('view-docs');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Documentation</div>' +
      '</div>' +

      '<div class="two-panel" style="height:calc(100vh - var(--topbar-height) - var(--statusbar-height) - 100px);">' +
        '<div class="two-panel-left glass-card" style="padding:12px;overflow-y:auto;">' +
          '<div style="font-weight:600;color:var(--text-primary);margin-bottom:12px;padding:0 8px;">Contents</div>' +
          '<div class="nav-item active doc-nav-item" data-doc="getting-started"><span class="nav-item-icon">&#9654;</span><span class="nav-item-label">Getting Started</span></div>' +
          '<div class="nav-item doc-nav-item" data-doc="overview"><span class="nav-item-icon">&#128200;</span><span class="nav-item-label">Overview Views</span></div>' +
          '<div class="nav-item doc-nav-item" data-doc="intelligence"><span class="nav-item-icon">&#128373;</span><span class="nav-item-label">Intelligence &amp; Hunting</span></div>' +
          '<div class="nav-item doc-nav-item" data-doc="scanning"><span class="nav-item-icon">&#128737;</span><span class="nav-item-label">Scanning &amp; Findings</span></div>' +
          '<div class="nav-item doc-nav-item" data-doc="agents"><span class="nav-item-icon">&#129302;</span><span class="nav-item-label">Agents &amp; Campaigns</span></div>' +
          '<div class="nav-item doc-nav-item" data-doc="incidents"><span class="nav-item-icon">&#128680;</span><span class="nav-item-label">Incidents &amp; Playbooks</span></div>' +
          '<div class="nav-item doc-nav-item" data-doc="compliance"><span class="nav-item-icon">&#9989;</span><span class="nav-item-label">Compliance &amp; Reports</span></div>' +
          '<div class="nav-item doc-nav-item" data-doc="tools"><span class="nav-item-icon">&#128295;</span><span class="nav-item-label">Terminal, OSINT &amp; MCP</span></div>' +
          '<div class="nav-item doc-nav-item" data-doc="system"><span class="nav-item-icon">&#9881;</span><span class="nav-item-label">Settings &amp; System</span></div>' +
          '<div class="nav-item doc-nav-item" data-doc="workspace"><span class="nav-item-icon">&#128736;</span><span class="nav-item-label">Workspace &amp; Git</span></div>' +
          '<div class="nav-item doc-nav-item" data-doc="api"><span class="nav-item-icon">&#128268;</span><span class="nav-item-label">API Reference</span></div>' +
          '<div class="nav-item doc-nav-item" data-doc="scanners"><span class="nav-item-icon">&#128187;</span><span class="nav-item-label">Scanner Setup</span></div>' +
          '<div class="nav-item doc-nav-item" data-doc="shortcuts"><span class="nav-item-icon">&#9000;</span><span class="nav-item-label">Keyboard Shortcuts</span></div>' +
        '</div>' +

        '<div class="two-panel-right glass-card" id="docs-content" style="line-height:1.8;color:var(--text-secondary);font-size:var(--font-size-sm);overflow-y:auto;">' +
        '</div>' +
      '</div>';

    var self = this;
    document.querySelectorAll('.doc-nav-item').forEach(function(item) {
      item.addEventListener('click', function() {
        document.querySelectorAll('.doc-nav-item').forEach(function(i) { i.classList.remove('active'); });
        item.classList.add('active');
        self._activeSection = item.getAttribute('data-doc');
        self.renderSection();
      });
    });
  },

  show: function() {
    this.renderSection();
  },

  hide: function() {},

  renderSection: function() {
    var container = document.getElementById('docs-content');
    var content = this._docs[this._activeSection] || '<p>Section not found.</p>';
    container.innerHTML = content;
    container.scrollTop = 0;
  },

  _img: function(src, alt) {
    return '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/' + src + '" alt="' + alt + '" style="width:100%;display:block;" loading="lazy"></div>';
  },

  _docs: {
    'getting-started':
      '<h2 style="color:var(--text-primary);font-size:var(--font-size-xl);margin-bottom:16px;">Getting Started with Vigil</h2>' +
      '<h3 style="color:var(--text-primary);font-size:var(--font-size-lg);margin:16px 0 8px;">Quick Start</h3>' +
      '<div class="code-block" style="margin-bottom:16px;">cd vigil && npm install && npm start\n# Access: http://localhost:4100\n# Default: admin / admin (change immediately)</div>' +
      '<h3 style="color:var(--text-primary);font-size:var(--font-size-lg);margin:16px 0 8px;">Requirements</h3>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li>Node.js 20+</li>' +
        '<li>Optional: nmap, nuclei, trivy, nikto, openssl (for scanning)</li>' +
        '<li>Optional: Claude CLI or Codex CLI (for AI features)</li>' +
        '<li>Optional: PostgreSQL 17 (falls back to JSON file stores)</li>' +
      '</ul>' +
      '<h3 style="color:var(--text-primary);font-size:var(--font-size-lg);margin:16px 0 8px;">First Steps</h3>' +
      '<ol style="padding-left:20px;list-style:decimal;">' +
        '<li style="margin-bottom:6px;">Log in with default credentials (<strong>admin / admin</strong>)</li>' +
        '<li style="margin-bottom:6px;">Go to <strong>Settings &gt; Account</strong> and change your password</li>' +
        '<li style="margin-bottom:6px;">Go to <strong>Settings &gt; AI Provider</strong> and select Claude CLI, Claude Code, or Codex CLI</li>' +
        '<li style="margin-bottom:6px;">Go to <strong>Settings &gt; Scanners</strong> to verify installed tools (nmap, nuclei, trivy)</li>' +
        '<li style="margin-bottom:6px;">Navigate to <strong>Dashboard</strong> to see your security posture score</li>' +
        '<li style="margin-bottom:6px;">Run your first scan from <strong>Port Scanner</strong> or <strong>Vuln Scanner</strong></li>' +
        '<li style="margin-bottom:6px;">Open <strong>Threat Hunt</strong> and enter a hypothesis to see AI investigation in action</li>' +
      '</ol>' +
      '<h3 style="color:var(--text-primary);font-size:var(--font-size-lg);margin:16px 0 8px;">BYOK AI Model</h3>' +
      '<p>Vigil uses a <strong>Bring Your Own Key</strong> model. All AI features shell out to locally-installed CLI tools (Claude CLI, Claude Code, Codex CLI). There is zero AI cost to the product itself &mdash; you use your own subscription. Without an AI CLI configured, all views still work but AI-powered features (triage, hunting, playbooks, analysis) degrade gracefully with placeholder messages.</p>' +
      '<h3 style="color:var(--text-primary);font-size:var(--font-size-lg);margin:16px 0 8px;">Architecture</h3>' +
      '<p>Express.js + Socket.IO with a vanilla JS frontend. No React, no build step, no bundler. ~35 route modules, ~27 libs, 37 views, 200+ API endpoints, only 6 npm dependencies. Data stored in JSON files under <code style="background:var(--well);padding:1px 4px;border-radius:3px;">data/</code> &mdash; works without any database. Optional PostgreSQL for production.</p>' +
      '<h3 style="color:var(--text-primary);font-size:var(--font-size-lg);margin:16px 0 8px;">RBAC Roles</h3>' +
      '<table class="data-table"><thead><tr><th>Role</th><th>Level</th><th>Permissions</th></tr></thead><tbody>' +
        '<tr><td style="color:var(--text-primary);">Admin</td><td>3</td><td>Full access: user management, settings, delete operations, all views</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Analyst</td><td>2</td><td>Run scans, triage alerts, create agents, execute hunts, manage incidents</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Viewer</td><td>1</td><td>Read-only: view dashboards, findings, reports, history</td></tr>' +
      '</tbody></table>',


    /* ===== OVERVIEW VIEWS ===== */
    'overview':
      '<h2 style="color:var(--text-primary);font-size:var(--font-size-xl);margin-bottom:16px;">Overview Views</h2>' +

      /* Dashboard */
      '<h3 style="color:var(--cyan);margin:20px 0 8px;font-size:var(--font-size-lg);">Dashboard</h3>' +
      '<p>The central security operations console. Everything you need to understand your security posture at a glance.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/Dashboard.png" alt="Vigil Dashboard" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">What you see:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Security Posture Score (0-100)</strong> &mdash; Animated circle with letter grade (A+ to F). Calculated from open vulnerabilities weighted by severity, compliance status, asset coverage, and scan recency. Color: cyan (&ge;80), purple (&ge;50), orange (&lt;50). Updates every 60 seconds via Socket.IO.</li>' +
        '<li><strong>Stat Cards</strong> &mdash; Active threats count, open findings count, last scan timestamp, compliance percentage. Each animates from 0 to current value on load.</li>' +
        '<li><strong>Threat Activity Chart</strong> &mdash; 24-hour line chart showing threat count per hour. Powered by Chart.js.</li>' +
        '<li><strong>Findings by Severity</strong> &mdash; Doughnut chart breaking down all findings into critical (orange), high, medium, and low.</li>' +
        '<li><strong>Recent Findings Table</strong> &mdash; Last 10 findings with severity badge, title, target hostname/IP, and relative time.</li>' +
        '<li><strong>AI Security Summary</strong> &mdash; AI-generated briefing with three sections: <span style="color:var(--cyan);">Highlights</span> (what\'s working), <span style="color:var(--orange);">Risks</span> (what needs attention), and Recommendations (next actions). Generated by calling <code style="background:var(--well);padding:1px 4px;border-radius:3px;">GET /api/briefing</code>.</li>' +
      '</ul>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Buttons:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Refresh</strong> &mdash; Reload all metrics, charts, and AI summary</li>' +
        '<li><strong>Run Scan</strong> &mdash; Jump to Vulnerability Scanner view</li>' +
        '<li><strong>Hunt Threat</strong> &mdash; Jump to Threat Hunt view</li>' +
        '<li><strong>Generate Report</strong> &mdash; Jump to Reports view</li>' +
      '</ul>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: Why is my score low?</strong><br>A: Run scans to establish a baseline. The score improves as you remediate vulnerabilities and pass compliance checks. A fresh install with no scan data shows a low score by design.</p>' +
      '<p><strong>Q: How often does the AI summary refresh?</strong><br>A: It regenerates each time you navigate to Dashboard or click Refresh. Takes 10-30 seconds depending on your AI provider speed.</p>' +
      '<p><strong>Q: Why do I see "AI summary unavailable"?</strong><br>A: Your AI CLI isn\'t configured. Go to Settings &gt; AI Provider and select Claude CLI, Claude Code, or Codex CLI. The dashboard works without AI &mdash; only the summary section is affected.</p>' +

      /* Attack Timeline */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Attack Timeline</h3>' +
      '<p>Chronological view of every security event across all data sources. Think of it as your security event stream &mdash; everything that happened, when it happened, correlated in one timeline.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/AttackTimeline.png" alt="Vigil Attack Timeline" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">What you see:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Stats Bar</strong> &mdash; Total events, critical count (orange), high count, event types count. All animated counters.</li>' +
        '<li><strong>Time Range Buttons</strong> &mdash; 1h, 24h (default), 7d, 30d. Changes scope of all events shown.</li>' +
        '<li><strong>AI Analysis Button</strong> &mdash; Sends all visible events to AI for pattern analysis, attack progression detection, and risk assessment. Opens modal with detailed narrative.</li>' +
        '<li><strong>Event Type Filters</strong> &mdash; All, Findings, Threats, Alerts, Scans, Incidents, Hunts, Auth, OSINT. Click to filter. Shows count badges per type.</li>' +
        '<li><strong>Type Count Tags</strong> &mdash; finding:137, scan:32, osint:8, threat:5, etc. Color-coded: orange for threats/findings/alerts/incidents, cyan for scans/osint, purple for hunts, gray for auth.</li>' +
        '<li><strong>Timeline Entries</strong> &mdash; Vertical timeline grouped by date. Each entry shows type badge, severity badge (CRITICAL/HIGH), event title, description, technical details (monospace), and source attribution.</li>' +
      '</ul>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: Where does timeline data come from?</strong><br>A: It aggregates from 9 data sources: findings, scans, threats, alerts, incidents, hunts, OSINT lookups, audit log (auth events), and agent runs. Every action across the platform feeds into this timeline.</p>' +
      '<p><strong>Q: What does AI Analysis do?</strong><br>A: It reads all events in the current view and generates a narrative identifying attack patterns, correlating events, and assessing risk progression. Useful for incident response &mdash; "what happened in the last 24 hours?"</p>' +
      '<p><strong>Q: Can I export the timeline?</strong><br>A: Not directly from the UI yet, but the raw data is available via <code style="background:var(--well);padding:1px 4px;border-radius:3px;">GET /api/timeline?range=24h</code>.</p>' +

      /* Intel Hub */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Intel Hub</h3>' +
      '<p>Security intelligence aggregator with 5 tabs: Security Feed, CVE Watch, CISA KEV, AI Briefing, and AI Threats. Replaces the old Knowledge Base view. Pulls from 15 RSS/Atom security feeds, NVD CVE API, and CISA KEV catalog.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Tabs:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Security Feed</strong> &mdash; Aggregates 15 security RSS feeds (CISA, SANS ISC, Krebs, BleepingComputer, Hacker News, Schneier, Exploit-DB, Talos, Rapid7, Dark Reading, ESET, SecurityWeek, CVE Feed). Click any article for full details in a modal. Auto-refreshes every 15 minutes.</li>' +
        '<li><strong>CVE Watch</strong> &mdash; NVD CVE API 2.0 search. Enter keywords to search the National Vulnerability Database. Shows CVSS scores, severity, description, and references. Add CVEs to your watchlist for monitoring.</li>' +
        '<li><strong>CISA KEV</strong> &mdash; CISA Known Exploited Vulnerabilities catalog. Table with CVE ID, vendor, product, vulnerability name, date added, due date, and required action. Click any row for full details modal.</li>' +
        '<li><strong>AI Briefing</strong> &mdash; AI-generated daily threat briefing analyzing the latest 50 feed items. Produces: executive summary, critical items, emerging threats, vulnerability highlights, and recommended actions. Takes ~30-60 seconds to generate.</li>' +
        '<li><strong>AI Threats</strong> &mdash; AI Security Knowledge Base with 5 sub-categories: OWASP LLM Top 10, MITRE ATLAS (15 adversarial ML techniques), Prompt Injection Patterns (8 types), AI Vulnerability Types (8 classes), and Defensive Tools (12 tools). Click any entry for detail modal with descriptions, attack examples, mitigations, and CWE/ATT&amp;CK references. AI analysis button for deeper assessment.</li>' +
      '</ul>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: How often are feeds updated?</strong><br>A: Every 15 minutes via background refresh + initial fetch 30 seconds after startup. NVD CVE API is rate-limited (7 seconds between requests).</p>' +
      '<p><strong>Q: Why do some feeds show errors?</strong><br>A: Some feeds (Packet Storm, Sophos) occasionally block server-side requests. 13/15 feeds consistently return results. Failed feeds are silently skipped.</p>' +
      '<p><strong>Q: What is the AI Threats tab for?</strong><br>A: It provides an in-memory knowledge base of AI/ML-specific security threats. Useful for teams building or deploying LLM applications. The OWASP LLM Top 10 is also available as a 4th compliance framework in the Compliance view.</p>',


    /* ===== INTELLIGENCE & HUNTING ===== */
    'intelligence':
      '<h2 style="color:var(--text-primary);font-size:var(--font-size-xl);margin-bottom:16px;">Intelligence &amp; Hunting</h2>' +

      /* Threat Feed */
      '<h3 style="color:var(--cyan);margin:20px 0 8px;font-size:var(--font-size-lg);">Threat Feed</h3>' +
      '<p>Real-time threat intelligence feed. Aggregates threats from scan results, local system detection (SSH brute force, suspicious processes, rogue cron jobs, world-writable files), and external feeds (CISA KEV catalog).</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/threatfeed.png" alt="Vigil Threat Feed" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">What you see:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Threat Level Badge</strong> &mdash; Large animated text: CRITICAL (orange), HIGH, MEDIUM, LOW (cyan). Calculated from the highest severity active threat.</li>' +
        '<li><strong>Summary Line</strong> &mdash; "X threats from Y sources" with source breakdown.</li>' +
        '<li><strong>Threat Sources Chart</strong> &mdash; Bar chart showing threat count by source type (native-container, native-vuln, auth.log, process_scan, cron_scan, file_scan).</li>' +
        '<li><strong>Threats Table</strong> &mdash; Columns: Severity (badge), Threat title, Source, Time (relative), Action (Triage button).</li>' +
      '</ul>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">AI Triage:</p>' +
      '<p>Click <strong>Triage</strong> on any threat. AI analyzes it as a senior SOC analyst and returns:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Verdict</strong> &mdash; true_positive (orange), false_positive (cyan), or needs_investigation (purple)</li>' +
        '<li><strong>Confidence %</strong> &mdash; 0-100 scale. Below 70% = manual review recommended.</li>' +
        '<li><strong>Reasoning</strong> &mdash; 2-3 sentence explanation of the verdict.</li>' +
        '<li><strong>MITRE ATT&CK Technique</strong> &mdash; e.g., T1110.001 (Brute Force: Password Guessing)</li>' +
        '<li><strong>Recommended Action</strong> &mdash; Specific remediation step.</li>' +
      '</ul>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: How does local threat detection work?</strong><br>A: On Linux, Vigil reads auth.log for failed SSH attempts (&gt;10 in 24h = threat), scans running processes for known miners (xmrig, cpuminer), checks cron jobs for suspicious curl/wget commands, and finds world-writable files in /etc and /usr/local/bin. On Windows, it relies on scan results and manual entries.</p>' +
      '<p><strong>Q: How often does the feed refresh?</strong><br>A: Every 30 seconds via Socket.IO auto-refresh when the view is active.</p>' +

      /* Alert Triage */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Alert Triage</h3>' +
      '<p>AI-powered alert classification. Instead of manually reviewing every alert, let AI sort the signal from the noise &mdash; identifying true positives, dismissing false positives, and flagging what needs human investigation.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/AlertTriage.png" alt="Vigil Alert Triage" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">What you see:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Pending Alerts Panel (left)</strong> &mdash; Cards showing severity badge, timestamp, title, description, source. Click any card to trigger AI triage.</li>' +
        '<li><strong>Triage Result Panel (right)</strong> &mdash; After AI analysis: large verdict label, confidence % with progress bar, analysis reasoning, recommended action, MITRE ATT&CK techniques (purple tags).</li>' +
        '<li><strong>Triage History</strong> &mdash; Table of past 20 verdicts: Alert name, Verdict (color-coded), Confidence %, Time.</li>' +
      '</ul>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Verdicts explained:</p>' +
      '<table class="data-table"><thead><tr><th>Verdict</th><th>Color</th><th>Meaning</th></tr></thead><tbody>' +
        '<tr><td style="color:var(--orange);font-weight:600;">TRUE POSITIVE</td><td>Orange</td><td>Real threat. Requires immediate action.</td></tr>' +
        '<tr><td style="color:var(--cyan);font-weight:600;">FALSE POSITIVE</td><td>Cyan</td><td>Not a real threat. Safe to dismiss.</td></tr>' +
        '<tr><td style="color:#a78bfa;font-weight:600;">NEEDS INVESTIGATION</td><td>Purple</td><td>Ambiguous. AI can\'t determine &mdash; human review needed.</td></tr>' +
      '</tbody></table>' +

      '<p><strong>Q: What confidence score should I trust?</strong><br>A: 85%+ is high confidence. 70-85% is moderate &mdash; review the reasoning. Below 70%, always manually verify.</p>' +

      /* Threat Hunt */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Threat Hunt</h3>' +
      '<p>Hypothesis-driven threat hunting powered by AI. You describe what you\'re looking for in plain English, and AI investigates across all your security data &mdash; gathering evidence, running analysis, and delivering a verdict.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/ThreatHunt.png" alt="Vigil Threat Hunt" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">How to use it:</p>' +
      '<ol style="padding-left:20px;list-style:decimal;">' +
        '<li style="margin-bottom:6px;">Type a hypothesis in the textarea: <em>"Check for unauthorized SSH access"</em>, <em>"Look for lateral movement indicators"</em>, <em>"Are there any data exfiltration attempts?"</em></li>' +
        '<li style="margin-bottom:6px;">Or click a <strong>Quick Hypothesis</strong> button: SSH Brute Force, C2 Communication, Privilege Escalation, Lateral Movement, DNS Exfiltration, Persistence Mechanisms.</li>' +
        '<li style="margin-bottom:6px;">Click <strong>Investigate</strong>. AI takes 15-30 seconds to research.</li>' +
        '<li style="margin-bottom:6px;">Review the results: Investigation Plan, Evidence Gathered (commands executed + output), AI Analysis, and final Verdict.</li>' +
      '</ol>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Results include:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Verdict Banner</strong> &mdash; Confirmed threat (orange), Clear (cyan), or Inconclusive (gray).</li>' +
        '<li><strong>Investigation Plan</strong> &mdash; AI\'s approach to investigating your hypothesis.</li>' +
        '<li><strong>Evidence</strong> &mdash; Each command executed with status (collected/skipped/failed) and raw output in code blocks.</li>' +
        '<li><strong>AI Analysis</strong> &mdash; Detailed prose explaining findings, patterns, and recommendations.</li>' +
      '</ul>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: What hypotheses work best?</strong><br>A: Be specific. <em>"Unauthorized SSH access in the last 24 hours"</em> works better than <em>"find threats"</em>. The AI searches audit logs, scan results, threat intel, findings, incidents, and OSINT data to build its analysis.</p>' +
      '<p><strong>Q: How is this different from Log Analysis?</strong><br>A: Threat Hunt is investigation-focused &mdash; it forms a plan, gathers evidence across multiple sources, and renders a verdict. Log Analysis is a single query-response for specific log searches.</p>' +
      '<p><strong>Q: Is the investigation history preserved?</strong><br>A: Yes. Last 20 investigations are shown in the History table at the bottom. Click any to review past results.</p>',


    /* ===== SCANNING & FINDINGS ===== */
    'scanning':
      '<h2 style="color:var(--text-primary);font-size:var(--font-size-xl);margin-bottom:16px;">Scanning &amp; Findings</h2>' +

      /* Findings */
      '<h3 style="color:var(--cyan);margin:20px 0 8px;font-size:var(--font-size-lg);">Vulnerability Findings</h3>' +
      '<p>Unified vulnerability management. Every finding from every scan type (nmap, nuclei, trivy, SSL) aggregated into one searchable, filterable, actionable table.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/Findings.png" alt="Vigil Vulnerability Findings" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">What you see:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Stats Cards</strong> &mdash; Total findings, Critical count (orange), High count (orange), Open count (purple). Animated counters.</li>' +
        '<li><strong>Filter Bar</strong> &mdash; Four dropdowns + search: Severity (all/critical/high/medium/low), Status (all/open/resolved/false_positive), Scan Type (all/nuclei/nmap/trivy/ssl), Search text (matches title + target).</li>' +
        '<li><strong>Findings Table</strong> &mdash; Checkbox, Severity badge, Title, Target (hostname/IP), Status tag, Scan Date. Click any row for detail panel.</li>' +
        '<li><strong>Detail Panel</strong> &mdash; Slides in showing: full title, severity, target, status, scan type, description, remediation guidance, CVE ID (if applicable), AI Analysis button.</li>' +
      '</ul>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Bulk Actions:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Mark Resolved</strong> &mdash; Select findings with checkboxes, click to mark as resolved.</li>' +
        '<li><strong>Mark False Positive</strong> &mdash; Dismiss false positives in bulk. Status tracked with who/when.</li>' +
      '</ul>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">AI Analysis (per finding):</p>' +
      '<p>Click <strong>AI Analysis</strong> in the detail panel. AI generates: Root Cause explanation, Impact assessment, step-by-step Remediation Steps, and Risk if Unpatched. Takes ~25 seconds.</p>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: What scan types generate findings?</strong><br>A: nmap (open ports, exposed services), nuclei (CVEs, misconfigurations, exposed panels), trivy (container vulnerabilities, secrets, misconfigurations), SSL (certificate issues, weak ciphers).</p>' +
      '<p><strong>Q: How do I reduce the finding count?</strong><br>A: Fix the underlying issues, then re-scan. Mark false positives to remove noise. Use bulk actions to manage large finding sets efficiently.</p>' +

      /* Port Scanner */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Port Scanner (Nmap)</h3>' +
      '<p>Network port scanning powered by nmap. Discover open ports, running services, and service versions on any target.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Scan Profiles:</p>' +
      '<table class="data-table"><thead><tr><th>Profile</th><th>Flags</th><th>Speed</th><th>Use Case</th></tr></thead><tbody>' +
        '<tr><td style="color:var(--text-primary);">Quick</td><td><code>-F -T4</code></td><td>~15s</td><td>Top 100 ports, fast check</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Standard</td><td><code>-sV -T3</code></td><td>~2min</td><td>Top 1000 ports + service detection</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Full</td><td><code>-sV -sC -O -p-</code></td><td>~15min</td><td>All 65535 ports, OS detection, scripts</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Stealth</td><td><code>-sS -T2</code></td><td>~5min</td><td>SYN scan, less detectable</td></tr>' +
      '</tbody></table>' +
      '<p><strong>Q: Can I scan internal networks?</strong><br>A: Yes. Scans run from the Vigil server. Ensure it has network access to the target. Custom port ranges and flags are supported in advanced options.</p>' +
      '<p><strong>Q: Does nmap need root?</strong><br>A: SYN scans do. Either run Vigil as root (not recommended) or set capabilities: <code style="background:var(--well);padding:1px 4px;border-radius:3px;">sudo setcap cap_net_raw+ep /usr/bin/nmap</code></p>' +

      /* Vuln Scanner */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Vulnerability Scanner (Nuclei)</h3>' +
      '<p>Template-based vulnerability scanning with 9000+ community templates. Finds CVEs, misconfigurations, exposed panels, default credentials, and more.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Features:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li>Severity filtering: critical, high, medium, low, info</li>' +
        '<li>Template categories: CVEs, vulnerabilities, misconfigurations, exposed-panels</li>' +
        '<li>Real-time results as findings are discovered</li>' +
        '<li>Each finding links to remediation references</li>' +
      '</ul>' +
      '<p><strong>Q: How do I update templates?</strong><br>A: Run <code style="background:var(--well);padding:1px 4px;border-radius:3px;">nuclei -update-templates</code> on the server. Templates are stored in <code>~/.nuclei-templates/</code>.</p>' +

      /* SSL Audit */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">SSL Audit (OpenSSL)</h3>' +
      '<p>Certificate chain analysis, cipher suite grading, protocol version testing (TLS 1.0-1.3), and expiry monitoring. Grades from A+ (perfect) to F.</p>' +
      '<p><strong>Q: What grades exist?</strong><br>A: A+ (HSTS + strong ciphers + TLS 1.2+), A, B (TLS 1.1), C (weak ciphers), D (TLS 1.0), F (expired/self-signed). Grade is based on protocol support, cipher strength, certificate validity, and HSTS.</p>' +

      /* DNS Recon */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">DNS Recon</h3>' +
      '<p>DNS enumeration: A, AAAA, MX, NS, TXT, SOA, CNAME records. WHOIS lookup and zone transfer testing.</p>' +
      '<p><strong>Q: What is a zone transfer test?</strong><br>A: Tests if the DNS server allows AXFR queries, which would expose all DNS records. A successful zone transfer is a misconfiguration finding that attackers exploit for reconnaissance.</p>' +

      /* Web Scanner + WAF Detection */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Web Scanner &amp; WAF Detection</h3>' +
      '<p>Web application scanning with integrated WAF (Web Application Firewall) detection. Two tabs: <strong>Findings</strong> for web vulnerabilities and <strong>WAF Detection</strong> for firewall fingerprinting.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">WAF Detection Features:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>30+ WAF Signatures</strong> &mdash; Cloudflare, AWS WAF/CloudFront, Akamai, Imperva, F5, FortiWeb, ModSecurity, Barracuda, Sucuri, Google Cloud Armor, Fastly, and more.</li>' +
        '<li><strong>4 Detection Vectors</strong> &mdash; Response headers, cookies, HTML body patterns, TLS certificate issuer analysis.</li>' +
        '<li><strong>Passive Mode</strong> &mdash; Analyzes headers from a single GET request. No payloads sent. Safe for initial recon.</li>' +
        '<li><strong>Active Mode</strong> &mdash; Sends benign probe payloads (XSS, SQLi, path traversal, RCE) to trigger WAF responses. Only use with authorization.</li>' +
      '</ul>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">How to use:</p>' +
      '<ol style="padding-left:20px;">' +
        '<li>Enter a target URL in the Web Scanner</li>' +
        '<li><strong>Full Scan</strong> runs web vuln scan + auto WAF detection (results in both tabs)</li>' +
        '<li><strong>WAF Scan</strong> runs WAF-only detection (~5 seconds, no vulnerability scanning)</li>' +
        '<li>Results show: detected WAF name/vendor, confidence %, evidence details, and findings</li>' +
      '</ol>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: Does WAF detection work without Nuclei installed?</strong><br>A: Yes. WAF detection is pure Node.js &mdash; no external scanner needed. It uses native HTTP/TLS modules to fingerprint WAFs.</p>' +
      '<p><strong>Q: Why does my full web scan take so long?</strong><br>A: Full scans run Nuclei with 9000+ templates, which can take 5+ minutes. Use the standalone WAF Scan button for quick (~5s) WAF-only detection.</p>' +

      /* Code Audit */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Code Audit (LLM-Powered)</h3>' +
      '<p>AI-driven source code vulnerability scanner inspired by Vulnhuntr. Analyzes source files for 7 vulnerability types using a 3-phase algorithm: file discovery, AI triage, and deep analysis with confidence scoring.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Vulnerability Types:</p>' +
      '<table class="data-table"><thead><tr><th>Type</th><th>Name</th><th>CWE</th></tr></thead><tbody>' +
        '<tr><td style="color:var(--text-primary);">RCE</td><td>Remote Code Execution</td><td>CWE-94</td></tr>' +
        '<tr><td style="color:var(--text-primary);">SQLi</td><td>SQL Injection</td><td>CWE-89</td></tr>' +
        '<tr><td style="color:var(--text-primary);">XSS</td><td>Cross-Site Scripting</td><td>CWE-79</td></tr>' +
        '<tr><td style="color:var(--text-primary);">SSRF</td><td>Server-Side Request Forgery</td><td>CWE-918</td></tr>' +
        '<tr><td style="color:var(--text-primary);">LFI</td><td>Local File Inclusion</td><td>CWE-98</td></tr>' +
        '<tr><td style="color:var(--text-primary);">AFO</td><td>Arbitrary File Overwrite</td><td>CWE-73</td></tr>' +
        '<tr><td style="color:var(--text-primary);">IDOR</td><td>Insecure Direct Object Ref</td><td>CWE-639</td></tr>' +
      '</tbody></table>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">How to use:</p>' +
      '<ol style="padding-left:20px;">' +
        '<li>Navigate to <strong>Scanning &gt; Code Audit</strong></li>' +
        '<li>Enter a target directory path (e.g., <code style="background:var(--well);padding:1px 4px;border-radius:3px;">/app/routes</code> in Docker)</li>' +
        '<li>Optionally select languages (JS, TS, Python, etc.) and vulnerability types to check</li>' +
        '<li>Click <strong>Preview Files</strong> to see what will be scanned before committing</li>' +
        '<li>Click <strong>Run Code Audit</strong> &mdash; runs in background with real-time progress</li>' +
        '<li>Results show severity, confidence (1-10), data flow traces, PoC exploits, and remediation</li>' +
        '<li>All findings auto-appear in the <strong>Findings</strong> view (filter by "Code Audit" type)</li>' +
      '</ol>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: What languages are supported?</strong><br>A: JavaScript, TypeScript, Python, Ruby, PHP, Java, Go, and C#. Supports .js, .mjs, .cjs, .ts, .tsx, .py, .rb, .php, .java, .go, .cs extensions.</p>' +
      '<p><strong>Q: How long does a scan take?</strong><br>A: Depends on file count. Preview first to check. Small projects (5-10 files): ~1 minute. Larger projects (30-50 files): 3-5 minutes. Each batch of files requires an AI call (~30-90 seconds).</p>' +
      '<p><strong>Q: Does this require AI to be configured?</strong><br>A: Yes. Code Audit uses the AI provider configured in Settings. It sends source code to the LLM for analysis. Ensure your AI provider is set up and working before running code audits.</p>' +
      '<p><strong>Q: What is the "Validate Exploitability" button?</strong><br>A: After a code audit completes, each finding has a <strong>Validate Exploitability</strong> button. Clicking it runs the Raptor 4-step MUST-GATE analysis on that specific finding: (1) Source Control &mdash; can an attacker control the input? (2) Sanitizer Effectiveness &mdash; can validation be bypassed? (3) Reachability &mdash; can the code path be triggered? (4) Impact &mdash; what is the worst case? The result shows a verdict badge (EXPLOITABLE in orange, FALSE_POSITIVE in cyan) with pass/fail for each step, attack vector, validated PoC, and reasoning. Takes ~60-90 seconds per finding.</p>' +
      '<p><strong>Q: How do I use Validate Exploitability?</strong><br>A: Sidebar &rarr; <strong>Scanning</strong> &rarr; <strong>Code Audit</strong>. (1) Enter a directory path and click <strong>Run Code Audit</strong>. (2) Wait for scan to finish (progress bar shows phases). (3) In the results table, click any finding row to expand its details. (4) Click the <strong>Validate Exploitability</strong> button (cyan border, bottom of finding details). (5) Wait ~60-90s &mdash; a spinner shows "Running MUST-GATE exploitability validation." (6) Review: verdict badge (orange = exploitable, cyan = false positive), 4-step table with pass/fail per step, attack vector, PoC, and reasoning. Use this to triage real vulnerabilities from noise before spending time on fixes.</p>' +

      /* Binary Analysis */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Binary Analysis</h3>' +
      '<p>Binary file inspection with deep analysis inspired by <strong>0xeb/vibe-re</strong> reverse engineering methodology. Uses standard Linux tools (<code style="background:var(--well);padding:1px 4px;border-radius:3px;">file</code>, <code style="background:var(--well);padding:1px 4px;border-radius:3px;">strings</code>, <code style="background:var(--well);padding:1px 4px;border-radius:3px;">readelf</code>, <code style="background:var(--well);padding:1px 4px;border-radius:3px;">objdump</code>) plus AI threat assessment. Analyzes ELF and PE binaries for malware indicators, suspicious imports, IOCs, structural anomalies, section entropy, disassembly patterns, import taint chains, and MITRE ATT&amp;CK mapping. Accessible as a tab within the Code Audit view.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">What it extracts:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>File identification</strong> &mdash; MIME type, format, architecture, endianness via <code style="background:var(--well);padding:1px 4px;border-radius:3px;">file</code> command</li>' +
        '<li><strong>Cryptographic hashes</strong> &mdash; MD5, SHA-1, SHA-256 for signature matching</li>' +
        '<li><strong>Entropy analysis</strong> &mdash; Shannon entropy to detect packing (&gt;7.0) or encryption (&gt;7.5)</li>' +
        '<li><strong>String extraction</strong> &mdash; URLs, IPv4 addresses, email addresses, domains, CVEs, registry keys, file paths, base64 blobs</li>' +
        '<li><strong>Suspicious imports</strong> &mdash; 60+ dangerous API calls (process injection, anti-debug, crypto, persistence, network)</li>' +
        '<li><strong>Binary structure</strong> &mdash; ELF/PE section headers, dynamic symbols, shared libraries, imports/exports</li>' +
        '<li><strong>Section entropy heatmap</strong> &mdash; Per-section Shannon entropy with anomaly detection + 15 packer signatures (UPX, ASPack, VMProtect, Themida, etc.) <em>(vibe-re)</em></li>' +
        '<li><strong>Disassembly patterns</strong> &mdash; ROP gadgets, syscalls, NOP sleds, PEB access, XOR decoders, call-pop PIC, stack pivots via objdump <em>(vibe-re)</em></li>' +
        '<li><strong>Import taint chains</strong> &mdash; 12 multi-step exploitation patterns: process injection, process hollowing, download &amp; execute, credential harvesting, keylogger pipeline, reverse shell, etc. <em>(vibe-re)</em></li>' +
        '<li><strong>MITRE ATT&amp;CK mapping</strong> &mdash; Auto-maps imports + IOCs + strings to ATT&amp;CK techniques (T1055, T1059, T1071, T1547, etc.) <em>(vibe-re)</em></li>' +
        '<li><strong>String obfuscation detection</strong> &mdash; Chi-squared byte distribution, XOR key brute-force, string density analysis, encrypted block detection <em>(vibe-re)</em></li>' +
        '<li><strong>AI threat assessment</strong> &mdash; LLM analyzes all extracted metadata including deep analysis and produces a structured malware analysis report</li>' +
      '</ul>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">How to use:</p>' +
      '<ol style="padding-left:20px;">' +
        '<li>Navigate to <strong>Scanning &gt; Code Audit</strong></li>' +
        '<li>Click the <strong>Binary Analysis</strong> tab (next to Source Code)</li>' +
        '<li>Enter the full path to a binary file (e.g., <code style="background:var(--well);padding:1px 4px;border-radius:3px;">/usr/bin/nmap</code> in Docker)</li>' +
        '<li>Click <strong>Analyze Binary</strong> &mdash; runs in background with real-time progress</li>' +
        '<li>Results show: file info, risk indicators, section entropy heatmap, MITRE ATT&amp;CK mapping, import taint chains, disassembly patterns, string obfuscation score, and AI threat assessment</li>' +
        '<li>Risk indicators auto-appear in the <strong>Findings</strong> view (filter by "Binary Analysis" type)</li>' +
      '</ol>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: What file types are supported?</strong><br>A: Any binary file up to 50MB. Best results with ELF (Linux) and PE (Windows) executables. Also works on shared libraries (.so, .dll), object files, and other binary formats.</p>' +
      '<p><strong>Q: Does it require AI?</strong><br>A: The AI threat assessment phase is optional. Without AI, you still get all deep analysis: section entropy, packer detection, disassembly patterns, import taint chains, MITRE mapping, and string obfuscation scoring.</p>' +
      '<p><strong>Q: What is deep analysis (vibe-re)?</strong><br>A: Inspired by the 0xeb/vibe-re reverse engineering methodology. It adds per-section entropy heatmaps with packer detection (15 signatures), objdump-based disassembly pattern scanning (ROP, shellcode, code caves), multi-step import taint chain detection (12 exploitation patterns), MITRE ATT&amp;CK technique mapping, and chi-squared string obfuscation scoring. All run automatically — no extra configuration needed.</p>' +
      '<p><strong>Q: What tools does it use?</strong><br>A: Standard Linux utilities already in the Docker container: <code style="background:var(--well);padding:1px 4px;border-radius:3px;">file</code> (identification), <code style="background:var(--well);padding:1px 4px;border-radius:3px;">strings</code> (text extraction), <code style="background:var(--well);padding:1px 4px;border-radius:3px;">readelf</code> (ELF structure), <code style="background:var(--well);padding:1px 4px;border-radius:3px;">objdump</code> (disassembly + patterns). No Ghidra, IDA Pro, or Java required.</p>' +
      '<p><strong>Q: How long does analysis take?</strong><br>A: Without AI: 2-10 seconds (deep analysis adds ~2-5s for disassembly scanning). With AI threat assessment: 15-45 seconds depending on binary complexity.</p>' +

      /* Proxy Nodes */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Proxy Nodes (Ephemeral Infrastructure)</h3>' +
      '<p>Disposable scanning infrastructure using GitHub Codespaces. Each node provides a unique exit IP via SOCKS5 proxy, enabling anonymous scanning during authorized penetration tests. Includes Proxy Pool &amp; Config Export for 6 tool formats, SSH Tunnels (forward/reverse/dynamic), OOB Callback Listener with Payload Hosting and 12 SSRF presets. Inspired by fluffy-barnacle + pgrok.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">How it works:</p>' +
      '<ol style="padding-left:20px;">' +
        '<li><strong>Create Node</strong> &mdash; Provisions a disposable GitHub Codespace (from <code style="background:var(--well);padding:1px 4px;border-radius:3px;">github/codespaces-blank</code>)</li>' +
        '<li><strong>Connect</strong> &mdash; Starts SOCKS5 tunnel via <code style="background:var(--well);padding:1px 4px;border-radius:3px;">gh codespace ssh -D 127.0.0.1:1080</code></li>' +
        '<li><strong>Scan</strong> &mdash; Route scanning tools through the SOCKS5 proxy for a different exit IP</li>' +
        '<li><strong>Rotate</strong> &mdash; Delete the node and create a new one for a fresh IP</li>' +
        '<li><strong>Teardown</strong> &mdash; Delete the Codespace when done. Zero traces.</li>' +
      '</ol>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Prerequisites:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>GitHub CLI (gh)</strong> &mdash; Must be installed and authenticated. See Scanner Setup section.</li>' +
        '<li><strong>GitHub Account</strong> &mdash; Free tier includes 120 core-hours/month of Codespaces.</li>' +
      '</ul>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">AI Infrastructure Planner:</p>' +
      '<p>Describe your engagement (target scope, testing window, scan types) and AI will recommend: number of proxy nodes, IP rotation frequency, OPSEC level, scan strategy (sequential/parallel/round-robin), and which scan phases should use proxying vs direct connection.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: How do I set up GitHub CLI?</strong><br>A: Install with <code style="background:var(--well);padding:1px 4px;border-radius:3px;">apt install gh</code>, then authenticate with <code style="background:var(--well);padding:1px 4px;border-radius:3px;">gh auth login</code>. Select GitHub.com, HTTPS, and "Login with a web browser." Open the device URL on any browser, enter the code, and authorize. See Scanner Setup for full instructions.</p>' +
      '<p><strong>Q: Is this free?</strong><br>A: GitHub free accounts include 120 core-hours/month of Codespaces. A basic node (2-core) costs 2 core-hours per hour. That gives ~60 hours of proxy time per month at no cost.</p>' +
      '<p><strong>Q: Do I need gh CLI in the Docker container?</strong><br>A: Yes. The Vigil Docker image includes gh CLI pre-installed. You just need to authenticate it once: <code style="background:var(--well);padding:1px 4px;border-radius:3px;">docker exec -it vigil gh auth login</code>. Or mount your host config: <code style="background:var(--well);padding:1px 4px;border-radius:3px;">~/.config/gh:/home/vigil/.config/gh:ro</code> in docker-compose.yml volumes.</p>' +
      '<p><strong>Q: What if gh CLI is not installed?</strong><br>A: The Proxy Nodes view shows a Prerequisites panel with setup instructions. All other Vigil features work normally without gh.</p>' +
      '<p><strong>Q: What is the Proxy Pool?</strong><br>A: The Proxy Pool tracks all active SOCKS5 tunnels and generates ready-to-paste configurations for 6 tools: proxychains, curl, ENV vars, Burp Suite, nmap, and nuclei. Click any format button to generate and copy the config.</p>' +
      '<p><strong>Q: What is Payload Hosting?</strong><br>A: You can host files or SSRF redirect payloads on the callback listener HTTP server. Use redirect payloads for SSRF testing (auto-redirects to internal metadata endpoints) or file payloads for XSS/XXE hosting. 12 one-click SSRF presets are available for common cloud metadata endpoints (AWS, GCP, Azure, K8s, Docker, Consul).</p>' +

      /* SSH Tunnels */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">SSH Tunnels (pgrok-inspired)</h3>' +
      '<p>Create and manage SSH tunnels for port forwarding, reverse tunnels, and SOCKS5 proxying. Accessible from the <strong>SSH Tunnels</strong> tab in Proxy Nodes. Inspired by the pgrok project.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Tunnel Types:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Forward (-L)</strong> &mdash; Access a remote service through a local port. Example: Forward local port 8080 to remote MySQL on port 3306.</li>' +
        '<li><strong>Reverse (-R)</strong> &mdash; Expose a local service to a remote server. Example: Make your local web server accessible via the remote host.</li>' +
        '<li><strong>Dynamic (-D)</strong> &mdash; SOCKS5 proxy through SSH. All traffic routed through the SSH server as exit point.</li>' +
      '</ul>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Features:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Auto-Reconnect</strong> &mdash; Exponential backoff (2s &rarr; 4s &rarr; 8s &rarr; 16s max). Resets after 60s stable connection.</li>' +
        '<li><strong>Health Check</strong> &mdash; Verifies tunnel is alive by checking if the local port is listening.</li>' +
        '<li><strong>SSH Key Support</strong> &mdash; Optional SSH key path for key-based authentication.</li>' +
      '</ul>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: Do SSH tunnels require gh CLI?</strong><br>A: No. SSH tunnels use standard <code style="background:var(--well);padding:1px 4px;border-radius:3px;">ssh</code> commands and work independently of GitHub Codespaces.</p>' +
      '<p><strong>Q: What happens if the SSH connection drops?</strong><br>A: With auto-reconnect enabled (default), the tunnel automatically reconnects with exponential backoff. The reconnect count is shown in the tunnels table.</p>' +

      /* Callback Listener */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">OOB Callback Listener</h3>' +
      '<p>Built-in HTTP callback listener for blind/out-of-band (OOB) vulnerability detection. Replaces the need for external services like interactsh or Burp Collaborator. Accessible from the <strong>Callback Listener</strong> tab in Proxy Nodes.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">How it works:</p>' +
      '<ol style="padding-left:20px;">' +
        '<li><strong>Start Listener</strong> &mdash; Launches an HTTP server on a configurable port (default 9999)</li>' +
        '<li><strong>Get Callback URL</strong> &mdash; A unique secret-based URL is generated (e.g., <code style="background:var(--well);padding:1px 4px;border-radius:3px;">http://YOUR_IP:9999/abc123</code>)</li>' +
        '<li><strong>Inject URL</strong> &mdash; Use the callback URL in scan payloads (SSRF, XXE, blind XSS, etc.)</li>' +
        '<li><strong>Monitor</strong> &mdash; Any request hitting the callback URL is captured with full details (method, headers, body, source IP)</li>' +
        '<li><strong>Detect</strong> &mdash; Requests matching the secret path are flagged as <span style="color:var(--orange);">TARGETED</span>, confirming the vulnerability triggered</li>' +
      '</ol>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: What is "targeted" vs non-targeted?</strong><br>A: Targeted requests hit the secret path (e.g., <code style="background:var(--well);padding:1px 4px;border-radius:3px;">/abc123</code>) — these confirm a vulnerability callback. Non-targeted requests hit any other path — could be scanners, bots, or background noise.</p>' +
      '<p><strong>Q: How do I use this for blind SSRF detection?</strong><br>A: Start the listener, copy the callback URL, inject it into SSRF-vulnerable parameters (e.g., <code style="background:var(--well);padding:1px 4px;border-radius:3px;">url=http://YOUR_IP:9999/secret</code>). If the server fetches the URL, you will see a targeted callback in the log.</p>' +
      '<p><strong>Q: Is the listener accessible from outside?</strong><br>A: The listener binds to 0.0.0.0 inside the container. You need to expose the port in docker-compose.yml (e.g., <code style="background:var(--well);padding:1px 4px;border-radius:3px;">- "9999:9999"</code>) for external targets to reach it.</p>' +

      /* Proxy Pool & Config Export */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Proxy Pool &amp; Config Export</h3>' +
      '<p>When you have active SOCKS5 tunnels (via Codespace nodes or SSH dynamic tunnels), the Proxy Pool section generates ready-to-use configuration for popular security tools:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>proxychains.conf</strong> &mdash; Full config file with round-robin chain for multiple proxies</li>' +
        '<li><strong>curl</strong> &mdash; Command-line flags (<code style="background:var(--well);padding:1px 4px;border-radius:3px;">--socks5-hostname</code>)</li>' +
        '<li><strong>ENV vars</strong> &mdash; Shell export commands (ALL_PROXY, HTTP_PROXY, HTTPS_PROXY)</li>' +
        '<li><strong>Burp Suite</strong> &mdash; Settings path for upstream SOCKS proxy configuration</li>' +
        '<li><strong>nmap</strong> &mdash; Proxy flag with TCP Connect scan requirement note</li>' +
        '<li><strong>nuclei</strong> &mdash; Proxy flag for HTTP request routing</li>' +
      '</ul>' +
      '<p>API: <code style="background:var(--well);padding:1px 4px;border-radius:3px;">GET /api/proxy-nodes/pool</code>, <code style="background:var(--well);padding:1px 4px;border-radius:3px;">POST /api/proxy-nodes/pool/config</code><br>MCP tool: <code style="background:var(--well);padding:1px 4px;border-radius:3px;">manage_proxy_pool</code> (action: status/config, format: proxychains/curl/env/burp/nmap/nuclei)<br>Neural cache: <code style="background:var(--well);padding:1px 4px;border-radius:3px;">proxy:pool</code> (30s TTL)</p>' +

      /* Payload Hosting */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Payload Hosting (cs-serve inspired)</h3>' +
      '<p>Host files or SSRF redirect payloads on the callback listener HTTP server. Inspired by fluffy-barnacle\'s cs-serve concept for serving payloads and redirects during authorized penetration tests.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Two payload types:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Redirect</strong> &mdash; Serves 302/301/307 redirects to a target URL. Use for SSRF testing: inject the payload URL, and when fetched, the server redirects to internal metadata endpoints.</li>' +
        '<li><strong>File</strong> &mdash; Serves custom content (HTML, JS, XML, etc.) at a specified path. Use for XSS payload hosting, XXE external entities, or exfiltration landing pages.</li>' +
      '</ul>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">SSRF Redirect Presets (12):</p>' +
      '<p>One-click deployment of common SSRF targets: AWS EC2 metadata (IMDSv1), AWS IAM credentials, GCP metadata, GCP service account tokens, Azure IMDS, Azure managed identity, DigitalOcean metadata, Kubernetes API, Kubernetes secrets, Docker socket API, Consul agent.</p>' +
      '<p>API: <code style="background:var(--well);padding:1px 4px;border-radius:3px;">GET/POST/DELETE /api/proxy-nodes/callback/payloads</code>, <code style="background:var(--well);padding:1px 4px;border-radius:3px;">GET /api/proxy-nodes/callback/ssrf-presets</code><br>Neural cache: <code style="background:var(--well);padding:1px 4px;border-radius:3px;">callback:payloads</code> (30s TTL)</p>',


    /* ===== AGENTS & CAMPAIGNS ===== */
    'agents':
      '<h2 style="color:var(--text-primary);font-size:var(--font-size-xl);margin-bottom:16px;">Security Agents &amp; Campaigns</h2>' +

      /* Security Agents */
      '<h3 style="color:var(--cyan);margin:20px 0 8px;font-size:var(--font-size-lg);">Security Agents</h3>' +
      '<p>27 built-in AI security agents, each a specialist with a focused system prompt. Includes 5 Raptor-inspired adversarial agents with MUST-GATE reasoning, plus AI Threat Analyst, Prompt Injection Tester, and Autonomous Pentester. Create unlimited custom agents. Run them against any target with natural language input.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/SecurityAgents.png" alt="Vigil Security Agents" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">What you see:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Stats Bar</strong> &mdash; Total Agents (27), Scanners (6), Analyzers (6), Total Runs (cumulative). Animated counters.</li>' +
        '<li><strong>Category Tabs</strong> &mdash; All, Scanners, Analyzers, Defenders, Hunters, Custom. Filter the grid.</li>' +
        '<li><strong>Agent Cards Grid</strong> &mdash; 3-column layout. Each card shows: category icon, agent name, category tag (colored), risk level (low/medium/high), run count, description, orange "Run Agent" button.</li>' +
      '</ul>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Built-in Agents (27):</p>' +
      '<table class="data-table" style="font-size:var(--font-size-xs);"><thead><tr><th>Agent</th><th>Category</th><th>Risk</th><th>What It Does</th></tr></thead><tbody>' +
        '<tr><td>Port Scanner</td><td>Scanner</td><td>Low</td><td>Analyzes open ports, services, and network attack surface</td></tr>' +
        '<tr><td>Subdomain Enumerator</td><td>Scanner</td><td>Low</td><td>Discovers subdomains and maps external attack surface</td></tr>' +
        '<tr><td>HTTP Header Auditor</td><td>Scanner</td><td>Low</td><td>Grades HTTP security headers, identifies missing protections</td></tr>' +
        '<tr><td>XSS Scanner</td><td>Scanner</td><td>Medium</td><td>Identifies cross-site scripting vulnerabilities and injection points</td></tr>' +
        '<tr><td>SQL Injection Detector</td><td>Scanner</td><td>Medium</td><td>Detects SQL injection vulnerabilities and database exposure</td></tr>' +
        '<tr><td>TLS Configuration Analyzer</td><td>Scanner</td><td>Low</td><td>Grades TLS/SSL configuration, cipher suites, and certificate security</td></tr>' +
        '<tr><td>AWS Security Auditor</td><td>Analyzer</td><td>Low</td><td>Audits AWS configurations against CIS benchmarks</td></tr>' +
        '<tr><td>IAM Policy Analyzer</td><td>Analyzer</td><td>Low</td><td>Identifies over-privileged access, unused permissions, and IAM risks</td></tr>' +
        '<tr><td>PCI DSS Checker</td><td>Analyzer</td><td>Low</td><td>Evaluates PCI DSS v4.0 payment security requirements</td></tr>' +
      '</tbody></table>' +
      '<p style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-top:4px;">Plus 18 more: HIPAA Checker, Data Classifier, Password Auditor, Incident Playbook, Firewall Auditor, Malware Analyzer, Log Hunter, Network Anomaly, Memory Forensics, Disk Forensics, 5 Raptor adversarial agents (Adversarial Analyst, Exploit Validator, Attack Path Mapper, Patch Reviewer, Red Team Planner), AI Threat Analyst (OWASP LLM/MITRE ATLAS mapping), Prompt Injection Tester (8 PI vectors), and Autonomous Pentester (P-E-R engine).</p>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Running an Agent:</p>' +
      '<ol style="padding-left:20px;list-style:decimal;">' +
        '<li style="margin-bottom:4px;">Click an agent card or its "Run Agent" button.</li>' +
        '<li style="margin-bottom:4px;">Enter target/input in the textarea (e.g., "192.168.1.0/24" for Port Scanner, or "Check our AWS S3 bucket policies" for AWS Auditor).</li>' +
        '<li style="margin-bottom:4px;">Click Run. AI executes with a 180-second timeout.</li>' +
        '<li style="margin-bottom:4px;">View output with color-coded border: cyan = success, orange = error.</li>' +
        '<li style="margin-bottom:4px;">View run history (last 50 runs per agent) with time, status, duration, input.</li>' +
      '</ol>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Creating Custom Agents:</p>' +
      '<p>Click <strong>Create Agent</strong>. Fill in: Name, Category (dropdown), Description, System Prompt (defines agent personality/expertise), Task Prompt (with <code style="background:var(--well);padding:1px 4px;border-radius:3px;">{{input}}</code> template variable). If you leave prompts blank, they\'re auto-generated from the name and category.</p>' +

      /* Campaigns */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Multi-Agent Campaigns</h3>' +
      '<p>Orchestrate multiple agents toward a single security goal. Define what you want done, set max agents, and Vigil coordinates the work.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/Campaigns.png" alt="Vigil Multi-Agent Campaigns" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">How it works:</p>' +
      '<ol style="padding-left:20px;list-style:decimal;">' +
        '<li style="margin-bottom:4px;">Click <strong>Launch Campaign</strong>.</li>' +
        '<li style="margin-bottom:4px;">Enter a goal: <em>"Full security assessment of production infrastructure"</em>, <em>"Audit all external-facing services for misconfigurations"</em>.</li>' +
        '<li style="margin-bottom:4px;">Set max agents (1-10, default 3) using the slider.</li>' +
        '<li style="margin-bottom:4px;">Campaign runs agents in sequence. Track progress in Active Campaigns panel with progress bar and agent completion count.</li>' +
        '<li style="margin-bottom:4px;">Click <strong>View Details</strong> to see each agent\'s status and summary in a modal.</li>' +
      '</ol>' +
      '<p><strong>Q: How does Vigil choose which agents to run?</strong><br>A: AI selects the most relevant agents based on your goal description and available agent capabilities. A "security assessment" might use Port Scanner + HTTP Header Auditor + TLS Analyzer.</p>' +

      /* Purple Team Simulator */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Purple Team Simulator (Decepticon-inspired)</h3>' +
      '<p>AI-driven attack-defense gap analysis through the MITRE ATT&amp;CK kill chain. Simulates realistic attack scenarios against your described infrastructure and evaluates defensive coverage across 10 ATT&amp;CK tactics. Produces defense grades, coverage heatmaps, critical gaps, and prioritized recommendations. Inspired by <a href="https://github.com/PurpleAILAB/Decepticon" style="color:var(--cyan);">Decepticon</a>\'s autonomous red team architecture.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Threat Scenarios:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>External Threat Actor</strong> &mdash; Sophisticated attacker from the internet</li>' +
        '<li><strong>Insider Threat</strong> &mdash; Malicious or compromised insider with legitimate access</li>' +
        '<li><strong>Ransomware Operator</strong> &mdash; Gang seeking to encrypt and exfiltrate data</li>' +
        '<li><strong>APT / Nation-State</strong> &mdash; Advanced persistent threat with long-term objectives</li>' +
        '<li><strong>Supply Chain Attack</strong> &mdash; Attacker compromising a third-party vendor</li>' +
      '</ul>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">How to use:</p>' +
      '<ol style="padding-left:20px;">' +
        '<li>Navigate to <strong>Agents &gt; Campaigns</strong></li>' +
        '<li>Click the <strong>Purple Team</strong> tab</li>' +
        '<li>Enter your target description (be specific &mdash; include tech stack, cloud provider, key services)</li>' +
        '<li>Optionally set scope, threat scenario, and known defenses</li>' +
        '<li>Click <strong>Run Simulation</strong> &mdash; AI analyzes 10 ATT&amp;CK tactics (~60-90 seconds)</li>' +
        '<li>Review: Defense Grade (A-F), ATT&amp;CK coverage heatmap, attack path narrative, critical gaps, prioritized recommendations</li>' +
        '<li>Click any tactic card for detailed attack scenario + defense evaluation</li>' +
      '</ol>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: Does this run actual attacks?</strong><br>A: No. The simulator uses AI reasoning to model attack scenarios and evaluate defenses &mdash; no actual scanning or exploitation occurs. It is safe to run against any target description.</p>' +
      '<p><strong>Q: How are scores calculated?</strong><br>A: Detection and Prevention scores (0-100%) are AI-estimated per tactic. Defense Score = average of detection + prevention. Grade: A (80%+), B (65%+), C (50%+), D (35%+), F (&lt;35%). Overall Risk = likelihood * (100 - prevention) / 100.</p>' +
      '<p><strong>Q: How specific should my target description be?</strong><br>A: The more specific, the better. Include: tech stack, cloud provider, authentication method, key services, data sensitivity. Vague descriptions produce generic results.</p>' +

      /* Raptor Adversarial Agents */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Raptor Adversarial Agents</h3>' +
      '<p>5 specialized agents powered by MUST-GATE adversarial reasoning. They think like attackers: assume everything is exploitable, trace full data flows, provide concrete proof-of-concepts, and never hedge without verification. These produce 3-14K chars of detailed professional-grade analysis.</p>' +

      '<table class="data-table" style="font-size:var(--font-size-xs);"><thead><tr><th>Agent</th><th>Category</th><th>What It Does</th><th>Takes ~</th></tr></thead><tbody>' +
        '<tr><td style="color:var(--text-primary);">Adversarial Analyst</td><td>Hunter</td><td>Full MUST-GATE adversarial analysis &mdash; assumes exploitability, traces attack paths, CWE-mapped findings with PoC</td><td>2-3 min</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Exploit Validator</td><td>Hunter</td><td>4-step validation of a specific finding: Source Control &rarr; Sanitizer &rarr; Reachability &rarr; Impact. Verdict: EXPLOITABLE / FALSE_POSITIVE</td><td>30-60s</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Attack Path Mapper</td><td>Hunter</td><td>Maps entry points &rarr; intermediate nodes &rarr; target assets. Produces ranked attack chains with prerequisites</td><td>1-2 min</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Patch Reviewer</td><td>Defender</td><td>Reviews security patches from attacker perspective &mdash; finds bypasses, edge cases, incomplete fixes. Verdict: COMPLETE / PARTIAL / INEFFECTIVE</td><td>30-60s</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Red Team Planner</td><td>Hunter</td><td>Multi-phase engagement plan mapped to MITRE ATT&amp;CK: Recon &rarr; Initial Access &rarr; Persistence &rarr; Exfil. OPSEC + contingency plans</td><td>1-2 min</td></tr>' +
      '</tbody></table>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">How to use:</p>' +
      '<ol style="padding-left:20px;list-style:decimal;">' +
        '<li style="margin-bottom:4px;">Open sidebar &rarr; <strong>Agents</strong> group &rarr; click <strong>Security Agents</strong></li>' +
        '<li style="margin-bottom:4px;">Click the <strong>Hunters</strong> tab to filter &mdash; all 5 Raptor agents are in this category</li>' +
        '<li style="margin-bottom:4px;">Click the orange <strong>Run Agent</strong> button on any Raptor agent card</li>' +
        '<li style="margin-bottom:4px;">Enter your target in the textarea &mdash; plain English describing code, app architecture, findings, or patches</li>' +
        '<li style="margin-bottom:4px;">Click <strong>Run</strong>. Wait 30s-3min. Output appears below with cyan border on success.</li>' +
        '<li style="margin-bottom:4px;">Scroll down to read the full analysis. Click <strong>History</strong> to see previous runs.</li>' +
      '</ol>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Example inputs for each agent:</p>' +
      '<div class="code-block" style="margin-bottom:8px;font-size:11px;">' +
        'Adversarial Analyst:\n' +
        '  "Express.js app with cookie-based auth, JSON file storage,\n   and shell command execution for security scanning"\n\n' +
        'Exploit Validator:\n' +
        '  "XSS in search results: user input from ?q= parameter is\n   reflected in HTML without encoding"\n\n' +
        'Attack Path Mapper:\n' +
        '  "Web app with: login page, REST API, Socket.IO, embedded\n   terminal, AI CLI integration, credential vault"\n\n' +
        'Patch Reviewer:\n' +
        '  "Fix: replaced execCommand(cmd) with execFileSafe(bin, args).\n   Before: execCommand(\\"nmap \\" + target).\n   After: execFileSafe(\\"nmap\\", [\\"-sV\\", target])"\n\n' +
        'Red Team Planner:\n' +
        '  "Internal web app with Express.js backend, cookie auth,\n   and security scanning capabilities. Internal network only."' +
      '</div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: What is MUST-GATE?</strong><br>A: 7 forced reasoning constraints that prevent the AI from cutting corners. ASSUME-EXPLOIT (assume exploitable until proven otherwise), NO-HEDGING (verify every "maybe"), FULL-COVERAGE (trace entire data flow), PROOF (concrete PoC required), STRICT-SEQUENCE (follow steps in order), CHECKLIST (pass/fail each check), CONSISTENCY (verdict must match evidence).</p>' +
      '<p><strong>Q: How is this different from regular agents?</strong><br>A: Regular agents give general security analysis. Raptor agents use adversarial thinking patterns &mdash; they assume the worst, trace full attack paths source-to-sink, provide concrete proof-of-concepts, and give definitive verdicts instead of vague warnings. The output is suitable for professional pentest reports.</p>' +
      '<p><strong>Q: I don\'t know what to type in the input box.</strong><br>A: Each Raptor agent has <strong>Try:</strong> buttons below the textarea with pre-built examples. Click any example to auto-fill the input with a realistic scenario (code snippet, finding, architecture description, etc.). Edit it to match your actual target, or just click Run to see how the agent works.</p>' +
      '<p><strong>Q: Why do Raptor agents take longer?</strong><br>A: They produce 3-14K chars of structured analysis with code references, CWE IDs, MITRE ATT&amp;CK mappings, PoC exploits, and step-by-step validation. The 180-second timeout accommodates this depth. Simpler agents return in 10-30 seconds.</p>' +

      /* Pentest Command Library (Reconmap-inspired) */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Pentest Command Library (Reconmap-inspired)</h3>' +
      '<p>18 pre-built parameterized security commands organized by engagement phase. Create projects from templates, execute commands against targets, track findings, and generate AI pentest reports. Inspired by <a href="https://github.com/reconmap/reconmap" style="color:var(--cyan);">Reconmap</a>\'s command database pattern.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Commands by Phase:</p>' +
      '<table class="data-table" style="font-size:var(--font-size-xs);"><thead><tr><th>Phase</th><th>Command</th><th>Tool</th><th>Description</th></tr></thead><tbody>' +
        '<tr><td style="color:var(--cyan);">Recon</td><td>Host Discovery</td><td>nmap</td><td>Ping sweep to find live hosts</td></tr>' +
        '<tr><td style="color:var(--cyan);">Recon</td><td>DNS Lookup</td><td>dig</td><td>Resolve A, MX, NS, TXT, SOA records</td></tr>' +
        '<tr><td style="color:var(--cyan);">Recon</td><td>WHOIS Lookup</td><td>whois</td><td>Domain/IP registration info</td></tr>' +
        '<tr><td style="color:var(--cyan);">Recon</td><td>SSL Certificate</td><td>openssl</td><td>Certificate details and chain</td></tr>' +
        '<tr><td style="color:var(--cyan);">Recon</td><td>Traceroute</td><td>traceroute</td><td>Network path trace</td></tr>' +
        '<tr><td style="color:var(--orange);">Scanning</td><td>Quick Port Scan</td><td>nmap</td><td>Top 1000 ports + service detection</td></tr>' +
        '<tr><td style="color:var(--orange);">Scanning</td><td>Full TCP Scan</td><td>nmap</td><td>All 65535 TCP ports</td></tr>' +
        '<tr><td style="color:var(--orange);">Scanning</td><td>Vulnerability Scan</td><td>nuclei</td><td>Template-based vuln scanning</td></tr>' +
        '<tr><td style="color:var(--orange);">Scanning</td><td>Web Server Scan</td><td>nikto</td><td>Web server misconfiguration</td></tr>' +
        '<tr><td style="color:var(--orange);">Scanning</td><td>SSL/TLS Audit</td><td>nmap</td><td>Cipher + protocol enumeration</td></tr>' +
        '<tr><td style="color:var(--orange);">Exploitation</td><td>Banner Grab</td><td>nmap</td><td>Service version fingerprinting</td></tr>' +
        '<tr><td style="color:var(--orange);">Exploitation</td><td>HTTP Methods</td><td>nmap</td><td>Test PUT, DELETE, etc.</td></tr>' +
        '<tr><td style="color:var(--orange);">Exploitation</td><td>Default Creds</td><td>nmap</td><td>Common credential testing</td></tr>' +
        '<tr><td style="color:var(--orange);">Exploitation</td><td>NSE Vuln Scripts</td><td>nmap</td><td>Nmap vuln detection scripts</td></tr>' +
      '</tbody></table>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Engagement Templates:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Web Application Pentest</strong> &mdash; OWASP WSTG methodology, full 4-phase workflow</li>' +
        '<li><strong>Network Penetration Test</strong> &mdash; PTES methodology, host-to-network assessment</li>' +
        '<li><strong>Quick Security Assessment</strong> &mdash; Rapid recon + port scan + vuln scan</li>' +
        '<li><strong>SSL/TLS Security Audit</strong> &mdash; Focused certificate and cipher analysis</li>' +
      '</ul>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">How to use:</p>' +
      '<ol style="padding-left:20px;">' +
        '<li>Navigate to <strong>Agents &gt; Pentest</strong></li>' +
        '<li>Click <strong>New Project</strong>, enter name + target, optionally select a template</li>' +
        '<li>Click the project card to open the <strong>Active Engagement</strong> view</li>' +
        '<li>Use phase tabs (Recon &rarr; Scanning &rarr; Exploitation &rarr; Reporting) to see available commands</li>' +
        '<li>Click a command button, fill in parameters (target auto-populated from project), click <strong>Execute</strong></li>' +
        '<li>Commands run in background &mdash; results appear automatically with parsed findings</li>' +
        '<li>Click execution rows to see raw output in a detail modal</li>' +
        '<li>Click <strong>Generate Report</strong> for an AI pentest report summarizing all phases and findings</li>' +
      '</ol>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: What tools are required?</strong><br>A: All tools (nmap, dig, whois, openssl, nuclei, nikto, traceroute) are pre-installed in the Docker container. No additional setup needed.</p>' +
      '<p><strong>Q: Can I browse commands without a project?</strong><br>A: Yes. The <strong>Command Library</strong> tab shows all 18 commands with phase filter and search. Click any command to see its parameters and execute it.</p>' +
      '<p><strong>Q: How does command execution work?</strong><br>A: Commands run in the Docker container using <code style="background:var(--well);padding:1px 4px;border-radius:3px;">execFileSafe()</code> (no shell injection). Parameters are validated against a safe character regex. Output is parsed to extract findings (open ports, vulnerabilities, etc.). Results are saved to the project and appear in the phase tabs.</p>' +
      '<p><strong>Q: Does the AI pentest report require AI?</strong><br>A: Yes. The report uses your configured AI provider to generate a professional penetration test report from project data (target, scope, commands executed, findings). Takes ~30-60 seconds. Without AI, use the raw execution data as your report basis.</p>' +

      /* Autonomous Pentest (P-E-R Engine) */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Autonomous Pentest (P-E-R Engine)</h3>' +
      '<p>AI-driven autonomous penetration testing with a Planner-Executor-Reflector cycle and dual causal graph reasoning. Inspired by <a href="https://github.com/LuaN1aoAgent" style="color:var(--cyan);">LuaN1aoAgent</a>. The engine decomposes targets into task DAGs, executes commands, and builds evidence chains to confirm or refute vulnerability hypotheses.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">How it works:</p>' +
      '<ol style="padding-left:20px;">' +
        '<li><strong>Planner</strong> &mdash; AI decomposes the target into a Task Graph (DAG) of subtasks with dependencies and priorities. Tools: nmap, nuclei, nikto, dig, whois, openssl, curl.</li>' +
        '<li><strong>Executor</strong> &mdash; Runs commands via <code style="background:var(--well);padding:1px 4px;border-radius:3px;">execFileSafe()</code>, parses output, proposes causal nodes (evidence, hypotheses, vulnerabilities) for the Causal Graph.</li>' +
        '<li><strong>Reflector</strong> &mdash; Audits executor output, validates causal nodes before committing, performs failure attribution (L0-L5), and decides whether to continue or halt.</li>' +
        '<li><strong>Replanner</strong> &mdash; Adapts the task graph based on reflector feedback, adding new tasks or adjusting priorities.</li>' +
      '</ol>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Depth Modes:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Quick</strong> &mdash; 3 P-E-R cycles, fast reconnaissance</li>' +
        '<li><strong>Standard</strong> &mdash; 5 cycles, balanced assessment</li>' +
        '<li><strong>Deep</strong> &mdash; 8 cycles, thorough testing with extended analysis</li>' +
      '</ul>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">How to use:</p>' +
      '<ol style="padding-left:20px;">' +
        '<li>Navigate to <strong>Agents &gt; Pentest</strong></li>' +
        '<li>Click the <strong>Autonomous</strong> tab</li>' +
        '<li>Click <strong>Launch Autonomous Pentest</strong></li>' +
        '<li>Enter target (URL, hostname, or IP), scope constraints, and depth</li>' +
        '<li>Monitor real-time progress: cycle count, task completion, evidence count, findings</li>' +
        '<li>When complete, click the result card for detailed view: task graph stats, causal graph stats, findings with severity, key facts, and AI-generated summary report</li>' +
      '</ol>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: What is the dual causal graph?</strong><br>A: Two graphs work together. The <strong>Task Graph</strong> is a DAG of subtasks (nmap scan, DNS lookup, etc.) with dependencies. The <strong>Causal Graph</strong> tracks evidence chains: Evidence &rarr; Hypothesis &rarr; Possible Vulnerability &rarr; Confirmed Vulnerability. Confidence propagates through the graph using logit/sigmoid updates.</p>' +
      '<p><strong>Q: What is L0-L5 failure attribution?</strong><br>A: When a task fails, the Reflector categorizes it: L0 (raw error), L1 (tool failure), L2 (missing prerequisite), L3 (environmental issue), L4 (hypothesis falsified by evidence), L5 (strategy-level problem requiring replanning).</p>' +
      '<p><strong>Q: How long does a scan take?</strong><br>A: Quick depth: ~1-3 minutes. Standard: ~3-8 minutes. Deep: ~8-15 minutes. Depends on target complexity and number of open services discovered.</p>',


    /* ===== INCIDENTS & PLAYBOOKS ===== */
    'incidents':
      '<h2 style="color:var(--text-primary);font-size:var(--font-size-xl);margin-bottom:16px;">Incidents &amp; Playbooks</h2>' +

      /* Playbooks */
      '<h3 style="color:var(--cyan);margin:20px 0 8px;font-size:var(--font-size-lg);">Incident Response Playbooks</h3>' +
      '<p>Pre-built and AI-generated incident response checklists. When an incident hits, you need a structured plan &mdash; not ad-hoc guessing.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/playbook.png" alt="Vigil Incident Response Playbooks" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Built-in Playbook Templates:</p>' +
      '<table class="data-table"><thead><tr><th>Playbook</th><th>Severity</th><th>Steps</th></tr></thead><tbody>' +
        '<tr><td style="color:var(--text-primary);">Ransomware Response</td><td><span style="color:var(--orange);">Critical</span></td><td>Isolate, contain, assess damage, eradicate, restore, post-mortem</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Phishing Incident</td><td><span style="color:var(--orange);">High</span></td><td>Identify scope, quarantine emails, reset credentials, scan endpoints</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Data Breach Response</td><td><span style="color:var(--orange);">Critical</span></td><td>Contain leak, forensics, notification, legal, remediation</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Account Compromise</td><td><span style="color:var(--orange);">High</span></td><td>Lock account, audit sessions, reset creds, check lateral movement</td></tr>' +
      '</tbody></table>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Create from Natural Language:</p>' +
      '<p>Click <strong>Create Playbook from Natural Language</strong>. Describe your incident scenario in the modal textarea, e.g.: <em>"Our web application is under a SQL injection attack and customer data may be exposed"</em>. Click <strong>Generate Playbook</strong>. AI creates a full step-by-step response plan with triage, containment, eradication, recovery, and post-incident phases.</p>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Using a Playbook:</p>' +
      '<p>Click any playbook template card to open it. Each step has a checkbox (toggle completion) and an <strong>Execute</strong> button for automated steps. Work through the checklist during an active incident.</p>' +

      '<p><strong>Q: Can I customize built-in playbooks?</strong><br>A: Built-in templates are read-only but you can create unlimited custom playbooks via natural language generation. Each generated playbook is editable.</p>' +

      /* Incidents */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Incidents</h3>' +
      '<p>Full incident lifecycle management. Create, investigate, contain, eradicate, recover, close. Each incident has a timeline of events and can generate an AI playbook.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Incident Status Flow:</p>' +
      '<div class="code-block" style="margin-bottom:12px;">Open → Investigating → Contained → Eradicated → Recovered → Closed</div>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">AI Response:</p>' +
      '<p>Click <strong>Generate Playbook</strong> on any open incident. AI reads the incident context + timeline and generates a structured IR guide with: Immediate Actions, Containment steps, Investigation approach, Eradication procedures, Recovery plan, and Lessons Learned. Takes ~30 seconds.</p>' +
      '<p><strong>Q: What severities exist?</strong><br>A: Critical (P1), High (P2), Medium (P3), Low (P4). Each has default SLA response times.</p>',


    /* ===== COMPLIANCE & REPORTS ===== */
    'compliance':
      '<h2 style="color:var(--text-primary);font-size:var(--font-size-xl);margin-bottom:16px;">Compliance &amp; Reports</h2>' +

      /* Compliance */
      '<h3 style="color:var(--cyan);margin:20px 0 8px;font-size:var(--font-size-lg);">Compliance Frameworks</h3>' +
      '<p>Track compliance against industry frameworks. Each control is automatically assessed with pass/fail/partial status. Collect evidence and generate compliance reports.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/complainace_framework.png" alt="Vigil Compliance Frameworks" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Supported Frameworks:</p>' +
      '<table class="data-table"><thead><tr><th>Framework</th><th>Controls</th><th>Automated Checks</th></tr></thead><tbody>' +
        '<tr><td style="color:var(--text-primary);">SOC 2 Type II</td><td>14 (CC1&ndash;CC9)</td><td>Auth, access control, firewall, encryption, logging, monitoring, scanning, threat detection, incident response, change mgmt</td></tr>' +
        '<tr><td style="color:var(--text-primary);">ISO 27001:2022</td><td>15 (A.5&ndash;A.8)</td><td>Same as SOC 2 plus malware detection, secure coding, physical/endpoint (manual)</td></tr>' +
        '<tr><td style="color:var(--text-primary);">NIST 800-53 Rev. 5</td><td>15 (AC,AT,AU,CA,CM,IA,IR,RA,SC,SI)</td><td>Account management, access enforcement, event logging, audit review, security assessments, baseline config, authenticator mgmt, incident handling, vulnerability monitoring, boundary protection, flaw remediation</td></tr>' +
        '<tr><td style="color:var(--text-primary);">OWASP LLM Top 10</td><td>10 (LLM01&ndash;LLM10)</td><td>Prompt injection detection, output sanitization, data poisoning, model DoS, supply chain, sensitive info disclosure, insecure plugins, excessive agency, overreliance, model theft. Baseline checks: AI provider config + output handling.</td></tr>' +
      '</tbody></table>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">What you see:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Framework Tabs</strong> &mdash; SOC 2, ISO 27001, NIST 800-53, OWASP LLM Top 10. Click to switch between frameworks.</li>' +
        '<li><strong>Stats Cards</strong> &mdash; Overall Compliance % (excludes N/A controls), Pass count (cyan), Fail count (orange), Partial count.</li>' +
        '<li><strong>Controls Table</strong> &mdash; ID, Control name, Check detail (what was tested), Status badge (Pass=cyan, Fail=orange, Partial=purple, N/A=info), Evidence button.</li>' +
        '<li><strong>Generate Report</strong> &mdash; AI-powered full audit report shown in a modal with executive summary, key findings, gap analysis, remediation roadmap, and compliance readiness.</li>' +
      '</ul>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">How It Works:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li>Controls are evaluated automatically: auth checks users.json, scanning checks completed scans, logging checks audit trail, firewall checks ufw, etc.</li>' +
        '<li>N/A controls (organization, physical, endpoint) require manual assessment and evidence collection.</li>' +
        '<li>Click <strong>Evidence</strong> on any control to attach notes or documentation.</li>' +
        '<li>AI reports use your configured AI provider (Settings &gt; AI Provider) to analyze all control results and generate professional audit reports.</li>' +
      '</ul>' +

      '<p><strong>Q: What does "Partial" mean?</strong><br>A: The control is partially implemented. The automated check found some evidence but full compliance requires additional configuration. Click Evidence to document what\'s in place.</p>' +
      '<p><strong>Q: Why is my score low?</strong><br>A: Score = Pass / (Pass+Fail+Partial) &times; 100. N/A controls are excluded. Run scans, create incidents, configure firewall, and enable TLS to improve scores.</p>' +
      '<p><strong>Q: How does Generate Report work?</strong><br>A: Click the button to invoke AI analysis of all controls in the active framework. A detailed report appears in a modal with scoring, gap analysis, remediation priorities, and certification readiness assessment. Takes 30-90 seconds depending on AI provider.</p>' +

      /* Reports */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Reports</h3>' +
      '<p>AI-generated security reports covering your entire security posture. Five report types with structured output.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/reports.png" alt="Vigil Security Reports" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Report Types:</p>' +
      '<table class="data-table"><thead><tr><th>Type</th><th>Content</th></tr></thead><tbody>' +
        '<tr><td style="color:var(--text-primary);">Security Audit</td><td>Full security assessment: posture score, findings, threats, compliance status, recommendations</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Vulnerability Report</td><td>All findings by severity, remediation priority, SLA tracking</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Compliance Report</td><td>Framework status, control pass/fail, evidence gaps, readiness %</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Incident Report</td><td>Incident history, timeline, response metrics, lessons learned</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Executive Summary</td><td>High-level briefing: key metrics, top risks, recommended actions</td></tr>' +
      '</tbody></table>' +
      '<p>Reports include an Executive Summary with a metrics table (posture score, total findings, open findings, active threats, open incidents), Current State assessment, Strengths, Risks, and Recommendations. The report shown in the screenshot is a Compliance Readiness Report with markdown formatting.</p>' +
      '<p><strong>Q: Can I export reports?</strong><br>A: Reports are generated as structured text/markdown. Copy from the modal or use the API: <code style="background:var(--well);padding:1px 4px;border-radius:3px;">POST /api/reports/generate {type}</code>.</p>',


    /* ===== TERMINAL, OSINT & MCP ===== */
    'tools':
      '<h2 style="color:var(--text-primary);font-size:var(--font-size-xl);margin-bottom:16px;">Terminal, OSINT &amp; MCP</h2>' +

      /* AI Terminal */
      '<h3 style="color:var(--cyan);margin:20px 0 8px;font-size:var(--font-size-lg);">AI Terminal</h3>' +
      '<p>Three-in-one command center: a real shell, an AI security assistant, and a credential vault browser &mdash; all in a floating drawer you can open from any page.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/AI_terminal.png" alt="Vigil AI Terminal — Shell tab" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Three Tabs:</p>' +
      '<table class="data-table"><thead><tr><th>Tab</th><th>What It Does</th></tr></thead><tbody>' +
        '<tr><td style="color:var(--text-primary);">Shell</td><td>Full interactive terminal (xterm.js + node-pty). Run any command: nmap, nuclei, docker, git, etc. Quick command buttons: clear, ls, ports, docker, auth log. Shows "Connected" status.</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Vigil AI</td><td>Natural language security assistant. Type questions like "Run a security posture check" or "Scan ports on localhost". Quick suggestion buttons: security posture check, scan ports, check SSL certificate, analyze auth log, list vulnerabilities, generate incident report. AI executes tools and returns results.</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Vault</td><td>Browse credentials stored in the encrypted vault (AES-256-GCM). Quick access without navigating to the Credentials view.</td></tr>' +
      '</tbody></table>' +

      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/vigial_ai.png" alt="Vigil AI Terminal — Vigil AI tab" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Controls:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Open Terminal (Ctrl+`)</strong> &mdash; Toggle the floating drawer from any page.</li>' +
        '<li><strong>Connect</strong> &mdash; Reconnect the terminal session if disconnected.</li>' +
        '<li><strong>Fullscreen</strong> &mdash; Expand terminal to full viewport.</li>' +
        '<li><strong>Minimize</strong> &mdash; Collapse to bottom bar.</li>' +
      '</ul>' +

      '<p><strong>Q: Does the terminal persist across page navigation?</strong><br>A: Yes. The terminal is a floating drawer that stays open when you switch views. Your shell session is maintained via Socket.IO.</p>' +

      /* OSINT */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">OSINT Reconnaissance</h3>' +
      '<p>Multi-tab intelligence platform with 7 tabs: Domain Intel, IP Lookup, Phone Intel, Email Intel, Username, Web Recon, and History. Enter any domain, IP, email, phone number, or username to get comprehensive reconnaissance with AI analysis.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/OSINT.png" alt="Vigil OSINT Reconnaissance" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Domain Intel Tab:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>AI Security Assessment</strong> &mdash; Top-level narrative analyzing the domain\'s security posture, risks, and recommendations. 6-8 sentences.</li>' +
        '<li><strong>Stats Cards</strong> &mdash; Subdomains found, Certificates discovered, Technologies detected, Missing security headers, Reputation score (0-100), Shared Hosts count.</li>' +
        '<li><strong>WHOIS Data</strong> &mdash; Registrar, creation/expiry dates, registrant, nameservers, status codes.</li>' +
        '<li><strong>SSL Certificate</strong> &mdash; CN, Issuer, Valid From/To, Protocol (TLS 1.3), SAN count.</li>' +
        '<li><strong>Technologies Detected</strong> &mdash; Tags showing discovered tech (CloudFlare, OpenSSL, etc.).</li>' +
        '<li><strong>HTTP Security Headers</strong> &mdash; Table checking 7 headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy) with Present (cyan) / Missing (orange) status and values.</li>' +
        '<li><strong>Reverse IP Lookup</strong> &mdash; (WebOSINT) All domains sharing the same IP address, shown as a tag cloud. Uses HackerTarget free API (no key needed). Helps identify shared hosting and co-located targets.</li>' +
        '<li><strong>Domain Reputation</strong> &mdash; (WebOSINT) Score out of 100 with individual test results (malware, phishing, spam). Requires WhoisXML API key stored in credential vault as <code style="background:var(--well);padding:1px 4px;border-radius:3px;">whoisxml_api_key</code> (500 free lookups). Shows helpful message when not configured.</li>' +
        '<li><strong>WHOIS History</strong> &mdash; (WebOSINT) Historical ownership table showing registrar, registrant org, creation date, and expiry across time. Requires WhoisFreaks API key stored as <code style="background:var(--well);padding:1px 4px;border-radius:3px;">whoisfreaks_api_key</code> (100 free).</li>' +
        '<li><strong>Subdomains</strong> &mdash; Discovered subdomains as tags.</li>' +
        '<li><strong>Certificates</strong> &mdash; CT log results table: CN, Issuer, Valid Until (top 25).</li>' +
        '<li><strong>DNS Records</strong> &mdash; MX, A, AAAA, TXT records grouped by type.</li>' +
      '</ul>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">IP Lookup Tab:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Dual-Source Geolocation</strong> &mdash; (WebOSINT) Cross-verifies location from ip-api.com and ipinfo.io. Shows VERIFIED badge (cyan) when both sources agree or MISMATCH badge (orange) when they disagree. Displays country, region, city, ISP, and org from both sources.</li>' +
        '<li><strong>Reverse IP Lookup</strong> &mdash; (WebOSINT) All domains hosted on the same IP, shown as a tag cloud. Same HackerTarget API as Domain Intel tab.</li>' +
        '<li><strong>Network Info</strong> &mdash; ISP, Organization, ASN, AS Name, Reverse DNS.</li>' +
        '<li><strong>Port Scan</strong> &mdash; Scans 10 common ports (22, 80, 443, 8080, 3389, 3306, 5432, 6379, 27017, 8443) with service identification.</li>' +
        '<li><strong>AI Security Assessment</strong> &mdash; Risk analysis based on open ports, geolocation, and network data.</li>' +
      '</ul>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Phone Intel Tab (GhostTrack-inspired):</p>' +
      '<p>Phone number intelligence using E.164 country code parsing. Enter a number with country code (e.g. +1 555 123 4567) to get:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Country &amp; Region</strong> &mdash; Identifies country from calling code (70+ countries supported).</li>' +
        '<li><strong>Line Type</strong> &mdash; Detects mobile vs fixed line vs toll-free for major countries (US, UK, India, Germany, France, Australia, Brazil, Japan, South Korea, China).</li>' +
        '<li><strong>Format Validation</strong> &mdash; Checks number length against expected format, outputs E.164, international, and national formats.</li>' +
        '<li><strong>AI Analysis</strong> &mdash; Carrier range identification, OSINT significance, and red flag detection.</li>' +
      '</ul>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Email Intel Tab (Holehe-inspired):</p>' +
      '<p>Check email registration across 12 online services and validate domain email security. Inspired by the Holehe OSINT tool and frishtik/osint-tools-mcp-server. Enter any email address to get:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Service Registration</strong> &mdash; Probes 12 services (Gravatar, GitHub, Firefox, Spotify, Pinterest, Adobe, WordPress, Duolingo, Twitter, Tumblr, Last.fm, Patreon) for email registration status: REGISTERED, Not Found, or Unknown.</li>' +
        '<li><strong>Email Validation</strong> &mdash; MX record check, SPF and DMARC analysis, disposable email detection (30+ throwaway domains), free vs custom/corporate provider classification.</li>' +
        '<li><strong>Disposable Detection</strong> &mdash; Flags known throwaway email providers (mailinator.com, guerrillamail.com, tempmail.com, etc.) as SUSPICIOUS in orange.</li>' +
        '<li><strong>AI Intelligence</strong> &mdash; Digital footprint analysis: user profiling from registration patterns, domain trustworthiness, OPSEC observations, recommended next investigation steps.</li>' +
      '</ul>' +
      '<p>API: <code style="background:var(--well);padding:1px 4px;border-radius:3px;">POST /api/osint/email</code> with <code>{email}</code>. MCP tool: <code>osint_email_check</code>. Neural cache: <code>osint:email:</code> key with 10min TTL.</p>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Username Tab (GhostTrack-inspired):</p>' +
      '<p>Enumerate a username across 26 social, developer, content, security, gaming, and design platforms. Uses stealth HTTP requests to check profile existence.</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Developer</strong> &mdash; GitHub, GitLab, Bitbucket, Dev.to, npm, PyPI, Docker Hub, Replit, Codepen, HackerNews.</li>' +
        '<li><strong>Security</strong> &mdash; HackerOne, Keybase.</li>' +
        '<li><strong>Social / Content</strong> &mdash; Reddit, Medium, Twitch, YouTube, Pinterest, SoundCloud, Flickr, Patreon, Gravatar, About.me, Linktree.</li>' +
        '<li><strong>Design / Gaming</strong> &mdash; Dribbble, Behance, Steam.</li>' +
      '</ul>' +
      '<p>Results show a table with found/not found status per platform, profile links for found accounts, and AI digital footprint analysis that assesses user type, platform distribution, and OPSEC observations.</p>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">History Tab:</p>' +
      '<p>Last 100 lookups (domain, IP, phone, email, username) with type, target, summary, and timestamp.</p>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Web Recon Tab (Scrapy + Scrapling inspired):</p>' +
      '<p>Lightweight web crawler for security reconnaissance with stealth capabilities. Four spider types:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Surface Scan</strong> &mdash; Crawl pages up to configurable depth, extract links (internal/external), emails, forms (login/file upload detection), technology stack, security headers, and IOCs (IP addresses, hashes, CVEs). Respects robots.txt.</li>' +
        '<li><strong>Exposed Files</strong> &mdash; Probe 50+ sensitive paths (.env, .git/config, backup.zip, wp-config.php, phpinfo.php, etc.) with risk assessment (critical/high/medium/low). Detects both exposed (200) and forbidden (403) paths.</li>' +
        '<li><strong>Tech Fingerprint</strong> &mdash; Deep technology detection from HTTP headers (Server, X-Powered-By, CDN), HTML patterns (CMS, JS frameworks), and known paths (WordPress, Joomla, security.txt). Identifies 20+ technologies + extracts IOCs.</li>' +
        '<li><strong>Threat Intel</strong> &mdash; Scrape 6 public threat intelligence feeds (CISA KEV, Feodo Tracker, URLhaus, ThreatFox, OpenPhish, IPsum). Extracts IOCs (IPs, MD5 hashes, CVEs) from all feeds. No API keys required.</li>' +
      '</ul>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Stealth Mode (Scrapling-inspired):</p>' +
      '<p>Enable the <strong>Stealth</strong> checkbox to activate anti-detection features: realistic browser User-Agent rotation (Chrome/Firefox/Safari profiles), Sec-Fetch headers, sec-ch-ua client hints, Google referer injection on first request, and randomized timing jitter (&plusmn;30% delay). Inspired by D4Vinci\'s Scrapling library and Apify\'s header-generator.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">IOC Extraction:</p>' +
      '<p>Surface and fingerprint scans automatically extract Indicators of Compromise from crawled pages: IPv4 addresses (excluding private ranges), MD5 and SHA256 hashes, and CVE identifiers. Threat Intel spider extracts IOCs from all feed data. IOC counts are shown in the results stat cards and listed in a dedicated section.</p>' +
      '<p>Results include stat cards (pages, emails, technologies, exposed paths, header score, IOCs, duration), technology badges, security header analysis, exposed path table, form detection, IOC listing, and AI analysis button.</p>' +

      '<p><strong>Q: Does OSINT make external API calls?</strong><br>A: Domain recon uses TLS connections (for SSL cert) and HTTP requests (for headers/technologies). IP lookup uses ip-api.com for geolocation. Web Recon crawls the target directly. Threat Intel fetches public feeds (CISA, abuse.ch, OpenPhish, IPsum). Username enumeration makes HTTP requests to 26 platform profile URLs. Email Intel probes 12 service endpoints (Gravatar, GitHub, Firefox, Spotify, etc.) and DNS for MX/SPF/DMARC. Phone Intel is local parsing only (no external calls). No paid APIs required.</p>' +
      '<p><strong>Q: What does Web Recon crawl?</strong><br>A: Only the target domain (internal links). External links are counted but not followed. Rate-limited to 500ms between requests by default (with jitter in stealth mode). Respects robots.txt. Max 30 pages per scan.</p>' +
      '<p><strong>Q: What threat intel feeds are scraped?</strong><br>A: CISA Known Exploited Vulnerabilities (JSON), Feodo Tracker botnet C2 IPs, URLhaus malware URLs, ThreatFox malware MD5s, OpenPhish phishing URLs, and IPsum threat IP aggregator. All public, no API keys needed.</p>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:16px 0 4px;">How to use Web Recon:</p>' +
      '<ol style="padding-left:20px;line-height:2;">' +
        '<li>Go to <strong>OSINT</strong> in the sidebar, click the <strong>Web Recon</strong> tab.</li>' +
        '<li>Enter a target URL (e.g. <code style="background:var(--well);padding:1px 4px;border-radius:3px;">https://example.com</code>). For Threat Intel, no URL needed.</li>' +
        '<li>Select a <strong>Spider Type</strong>:<br>' +
          '&bull; <em>Surface Scan</em> &mdash; crawl pages, find emails, tech stack, forms, security headers, IOCs.<br>' +
          '&bull; <em>Exposed Files</em> &mdash; check 50+ sensitive paths (.env, .git, backups, configs).<br>' +
          '&bull; <em>Tech Fingerprint</em> &mdash; identify server, CMS, JS frameworks, CDN + extract IOCs.<br>' +
          '&bull; <em>Threat Intel</em> &mdash; scrape public feeds (CISA KEV, abuse.ch, OpenPhish, IPsum).</li>' +
        '<li>Optionally enable <strong>Stealth</strong> mode for anti-detection (browser-like headers, timing jitter).</li>' +
        '<li>Set <strong>Depth</strong> (1-3) for surface scans. Higher depth follows more internal links but takes longer.</li>' +
        '<li>Click <strong>Crawl</strong>. Progress updates appear in real-time.</li>' +
        '<li>When complete, results show: stat cards, technology badges, security header audit, exposed paths with risk levels, forms detected, IOC listing, and a history of past scans.</li>' +
        '<li>Click <strong>AI Analysis</strong> on any result for a pentest-grade security assessment with risk rating, key findings, attack surface analysis, and prioritized recommendations.</li>' +
      '</ol>' +

      /* Log Analysis */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Log Analysis</h3>' +
      '<p>Natural language log querying. Type a question in plain English and AI searches Vigil\'s security data stores to generate analysis.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Data Sources Searched:</p>' +
      '<p>AI queries across 9 internal data stores: audit-log, scans, threats, alerts, findings, incidents, agent-runs, hunts, ssl-domains, osint-history. On Linux, it can also query system logs (syslog, auth.log, journal).</p>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Example Queries:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><em>"Show me failed login attempts in the last hour"</em></li>' +
        '<li><em>"What scans ran today?"</em></li>' +
        '<li><em>"List all critical findings"</em></li>' +
        '<li><em>"Show recent threat triage results"</em></li>' +
        '<li><em>"What incidents are open?"</em></li>' +
      '</ul>' +

      '<p><strong>Q: Does it only work on Linux?</strong><br>A: No. Vigil queries its own internal data stores cross-platform (Windows, macOS, Linux). On Linux, it can additionally query system logs (syslog, auth.log, systemd journal).</p>' +

      /* MCP Playground */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">MCP Playground</h3>' +
      '<p>Interactive testing interface for Vigil\'s built-in MCP (Model Context Protocol) server. Test all 37 tools, browse 7 resources, run 8 AI prompt workflows, and connect external AI assistants.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/MCP_Playground.png" alt="Vigil MCP Playground" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">5 Zones:</p>' +
      '<ol style="padding-left:20px;list-style:decimal;">' +
        '<li style="margin-bottom:6px;"><strong>Stats Bar</strong> &mdash; Tools (37), Resources (7), Prompts (8), MCP Calls counter.</li>' +
        '<li style="margin-bottom:6px;"><strong>AI Security Workflows</strong> &mdash; 4 clickable prompt cards: Security Audit (Multi-Tool), Threat Briefing (Daily), Incident Response (Interactive), Compliance Report (SOC2/ISO/NIST). Click to run the workflow with optional parameters. 4 additional prompts available via tool explorer: Code Security Review, WAF Reconnaissance, Anonymous Pentest Setup, AI Security Review.</li>' +
        '<li style="margin-bottom:6px;"><strong>Live Security Data</strong> &mdash; 3 MCP resource cards showing real-time data: Security Posture (score + grade from vigil://posture), Active Threats (count + critical badge + top 3 threats from vigil://threats), Open Findings (count + severity breakdown from vigil://findings). 4 additional resources: vigil://code-audit-findings, vigil://waf-signatures, vigil://proxy-nodes, vigil://ai-security-kb.</li>' +
        '<li style="margin-bottom:6px;"><strong>Tool Explorer</strong> &mdash; Two-panel layout. Left: search bar + 12 category tabs (All/Scanning/Intelligence/Compliance/Incident/System/Code Audit/Proxy/Adversarial/Pentest/Purple Team/AI Security) + tool list. Right: selected tool with description, auto-generated parameter form, Execute button, smart result rendering.</li>' +
        '<li style="margin-bottom:6px;"><strong>Request Log</strong> &mdash; Last 20 MCP calls with timestamp, status dot (cyan=success, orange=error), method, params, duration in ms.</li>' +
      '</ol>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">37 MCP Tools:</p>' +
      '<div class="code-block" style="margin-bottom:8px;font-size:11px;">check_posture         &mdash; Security posture score + breakdown\nscan_ports            &mdash; Nmap port scan (target, ports)\nscan_vulnerabilities  &mdash; Nuclei scan (target, severity)\ncheck_ssl             &mdash; SSL certificate check (domain)\nquery_logs            &mdash; Natural language log search\nosint_domain          &mdash; Domain DNS recon\nosint_ip              &mdash; IP geolocation lookup\nosint_reverse_ip      &mdash; Reverse IP lookup (WebOSINT, HackerTarget)\nosint_email_check     &mdash; Email registration check (Holehe-inspired)\ntriage_alert          &mdash; AI alert triage (title, details, severity)\nhunt_threat           &mdash; Threat hypothesis investigation\nrun_agent             &mdash; Execute security agent (slug, input)\nlaunch_campaign       &mdash; Multi-agent campaign (goal, maxAgents)\ngenerate_report       &mdash; Report generation (type)\ncompliance_check      &mdash; Framework compliance check\nlist_findings         &mdash; Get vulnerability findings\nincident_create       &mdash; Create security incident\nrun_code_audit        &mdash; AI code vulnerability scan (target, languages)\nget_code_audit_results&mdash; Get code audit findings (scanId)\ndetect_waf            &mdash; WAF/CDN fingerprinting (target, probeMode)\nlist_proxy_nodes      &mdash; List ephemeral proxy nodes\ncreate_proxy_node     &mdash; Create disposable Codespace proxy\nstart_proxy_tunnel    &mdash; Start SOCKS5 tunnel through proxy\nplan_proxy_infrastructure &mdash; AI proxy infrastructure planning\nvalidate_exploitability &mdash; MUST-GATE exploitability validation (Raptor)\nadversarial_analysis  &mdash; Deep adversarial security analysis (Raptor)\nrun_pentest_command   &mdash; Execute pentest command (commandId, params)\nget_pentest_results   &mdash; Get pentest project findings (projectId)\nrun_purple_team_sim   &mdash; Attack-defense gap analysis (target, scenario)\nget_purple_team_results &mdash; Get simulation results (simId)\nanalyze_binary        &mdash; Binary deep analysis + MITRE mapping (vibe-re inspired)\ncreate_tunnel         &mdash; SSH tunnel (forward/reverse/dynamic)\nmanage_callback_listener &mdash; OOB callback listener (start/stop/status)\ncheck_ai_security        &mdash; AI/LLM security posture (OWASP LLM Top 10)\nautonomous_pentest       &mdash; P-E-R autonomous pentest (dual causal graph)\ncheck_server_hardening   &mdash; Server hardening audit (SSH/firewall/IDS/kernel)\nmanage_proxy_pool        &mdash; Proxy pool status + config export (proxychains/curl/Burp/nmap/nuclei)</div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Connecting External AI:</p>' +
      '<p>Click <strong>Connect to Claude</strong> for setup instructions:</p>' +
      '<div class="code-block" style="margin-bottom:8px;"># Claude Code\nclaude mcp add vigil --transport http http://localhost:4100/mcp\n\n# Claude Desktop config:\n{ "mcpServers": { "vigil": { "url": "http://localhost:4100/mcp" } } }\n\n# cURL test:\ncurl -X POST http://localhost:4100/mcp -H "Content-Type: application/json" \\\n  -d \'{"jsonrpc":"2.0","method":"tools/list","id":1}\'</div>' +
      '<p><strong>Q: What is MCP?</strong><br>A: Model Context Protocol is a standard for AI assistants to interact with external tools. Vigil exposes 37 security tools, 7 live resources, and 8 prompt workflows via MCP. Claude (or any MCP-compatible AI) can run scans, check posture, triage alerts, hunt threats, audit code, detect WAFs, manage proxy infrastructure, validate exploitability, run adversarial analysis, autonomous pentests, server hardening audits, and generate reports.</p>' +
      '<p><strong>Q: Why do some MCP tools take a while?</strong><br>A: AI-powered tools (triage_alert, hunt_threat, generate_report, compliance_check, run_agent, launch_campaign, plan_proxy_infrastructure, validate_exploitability, adversarial_analysis) use the configured AI provider and may take 15-120 seconds. Scanner tools (scan_ports, scan_vulnerabilities) depend on scan complexity. The MCP test endpoint supports up to 5 minute timeouts.</p>' +
      '<p><strong>Q: Why does create_proxy_node fail?</strong><br>A: It requires the GitHub CLI (gh) to be authenticated with an account that has Codespaces access. Run <code>gh auth login</code> inside the container to configure.</p>' +
      '<p><strong>Q: How do I use the Adversarial MCP tools?</strong><br>A: Two Raptor-powered tools are in the <strong>Adversarial</strong> category tab:<br>' +
        '&bull; <strong>validate_exploitability</strong> &mdash; Paste a finding title, details, severity, and vuln type. Returns a 4-step MUST-GATE validation with verdict (EXPLOITABLE/FALSE_POSITIVE/NEEDS_INVESTIGATION). ~90 seconds.<br>' +
        '&bull; <strong>adversarial_analysis</strong> &mdash; Describe any target (app architecture, code snippet, URL, scan results). Returns adversarial findings with CWE IDs, attack paths, PoCs, and risk rating. ~2-5 minutes.<br>' +
        'Both work from the MCP Playground GUI (click Adversarial tab, select tool, fill params, click Execute) or via any MCP-connected AI assistant (Claude Desktop, Claude Code, etc.).</p>' +
      '<p><strong>Q: Can I use these tools from Claude Desktop?</strong><br>A: Yes. Connect Claude to Vigil via MCP: <code>claude mcp add vigil --transport http http://localhost:4100/mcp</code>. Then ask Claude things like "validate whether this SQL injection finding is exploitable" or "run an adversarial analysis on this Express.js API." Claude will call the Raptor tools automatically.</p>',


    /* ===== SETTINGS & SYSTEM ===== */
    'system':
      '<h2 style="color:var(--text-primary);font-size:var(--font-size-xl);margin-bottom:16px;">Settings &amp; System</h2>' +

      /* Settings */
      '<h3 style="color:var(--cyan);margin:20px 0 8px;font-size:var(--font-size-lg);">Settings</h3>' +
      '<p>Platform configuration with 5 tabs: Account, AI Provider, Scanners, Security, About.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/settings.png" alt="Vigil Settings" style="width:100%;display:block;" loading="lazy"></div>' +

      '<table class="data-table"><thead><tr><th>Tab</th><th>What You Configure</th></tr></thead><tbody>' +
        '<tr><td style="color:var(--text-primary);">Account</td><td>Username, password change, Two-Factor Authentication (TOTP 2FA with QR code + backup codes)</td></tr>' +
        '<tr><td style="color:var(--text-primary);">AI Provider</td><td>Select AI backend: Claude CLI, Claude Code, Codex CLI, or None. Tests connection on save.</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Scanners</td><td>Verify installed scanner paths: nmap, nuclei, trivy, nikto, openssl. Shows version and status.</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Security</td><td>Session timeout, password policy, IP allowlisting, audit log retention.</td></tr>' +
        '<tr><td style="color:var(--text-primary);">About</td><td>Vigil version, Node.js version, OS, uptime, license (AGPL-3.0).</td></tr>' +
      '</tbody></table>' +

      '<p><strong>Q: How do I enable 2FA?</strong><br>A: Settings &gt; Account &gt; Two-Factor Authentication &gt; Setup 2FA. Scan the QR code with any TOTP app (Google Authenticator, Authy, 1Password). Enter the 6-digit code to verify. Save backup codes securely.</p>' +
      '<p><strong>Q: What happens if I choose "None" for AI?</strong><br>A: All views still work. AI-powered features (triage, hunting, playbooks, analysis, summaries) degrade gracefully with "AI not configured" messages. Scanning, findings, compliance, reports, and all data views remain fully functional.</p>' +

      /* Credential Vault */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Credential Vault</h3>' +
      '<p>Encrypted credential storage using AES-256-GCM. Store API keys, tokens, passwords, and other secrets. Values are encrypted at rest and only decrypted when you click Reveal.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/credentials.png" alt="Vigil Credential Vault" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">What you see:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Credentials Table</strong> &mdash; Name, Type (api_key / token / password / secret), Last Updated, Actions (Reveal / Delete).</li>' +
        '<li><strong>Add Credential</strong> &mdash; Button opens modal: Name, Type dropdown, Value (password field). Stored encrypted immediately.</li>' +
        '<li><strong>Reveal</strong> &mdash; Decrypts and shows the value temporarily. Click again to hide.</li>' +
        '<li><strong>Delete</strong> &mdash; Permanently removes the credential (confirmation required).</li>' +
      '</ul>' +

      '<p><strong>Q: How secure is the vault?</strong><br>A: AES-256-GCM encryption with a unique IV per credential. The encryption key is in your .env file (ENCRYPTION_KEY). Without this key, credential values are unrecoverable.</p>' +

      /* Audit Log */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Audit Log</h3>' +
      '<p>Immutable audit trail of every action in the platform. Every login, scan, triage, agent run, setting change, and API call is logged.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/audit_log.png" alt="Vigil Audit Log" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">What you see:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Filter Bar</strong> &mdash; Date range pickers (from/to), search by user or action, Filter button.</li>' +
        '<li><strong>Log Table</strong> &mdash; Timestamp, User, Action (e.g., alert.triage, scan.start, auth.login), Resource (UUID of affected object), Details.</li>' +
        '<li><strong>Export</strong> &mdash; Download the filtered log as JSON.</li>' +
      '</ul>' +

      '<p><strong>Q: Is the audit log tamper-proof?</strong><br>A: Entries are append-only with cryptographic checksums. Each entry references the previous entry\'s hash, forming a chain. Tampering with any entry breaks the chain.</p>' +

      /* Notifications */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Notifications</h3>' +
      '<p>In-app notification center with real-time alerts via Socket.IO. Configure which events you want to be notified about.</p>' +
      '<div style="margin:12px 0;border:1px solid var(--border);border-radius:8px;overflow:hidden;"><img src="/img/notifications.png" alt="Vigil Notifications" style="width:100%;display:block;" loading="lazy"></div>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">What you see:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Notification Cards</strong> &mdash; Each shows severity tag (info/warning/critical), message, Mark Read and Dismiss buttons.</li>' +
        '<li><strong>Filter Dropdown</strong> &mdash; All, Unread, Info, Warning, Critical.</li>' +
        '<li><strong>Mark All Read</strong> &mdash; Bulk clear unread state.</li>' +
      '</ul>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Notification Preferences:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li>Critical findings (enabled by default)</li>' +
        '<li>Scan completions (enabled by default)</li>' +
        '<li>SSL certificate expiry warnings (enabled by default)</li>' +
        '<li>Daily security digest (optional)</li>' +
        '<li>Agent run completions (optional)</li>' +
      '</ul>' +

      /* Network & Infrastructure (ServerKit-inspired) */
      '<h3 style="color:var(--cyan);margin:28px 0 8px;font-size:var(--font-size-lg);">Network &amp; Infrastructure (ServerKit-inspired)</h3>' +
      '<p>Network monitoring with 3 tabs: Network (interfaces, ports, firewall), Services (systemd health), and Hardening (security audit). Inspired by <a href="https://github.com/jhd3197/ServerKit" style="color:var(--cyan);">ServerKit</a>.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Network Tab:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Network Interfaces</strong> &mdash; All interfaces with IP addresses, netmask, MAC, and CIDR notation.</li>' +
        '<li><strong>Listening Ports</strong> &mdash; Active connections and listening services via <code style="background:var(--well);padding:1px 4px;border-radius:3px;">ss</code> or <code style="background:var(--well);padding:1px 4px;border-radius:3px;">netstat</code>.</li>' +
        '<li><strong>Firewall Rules</strong> &mdash; UFW or iptables rules with status, action, direction, and source.</li>' +
      '</ul>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Services Tab:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Stat Cards</strong> &mdash; Total services detected, active (cyan), inactive (gray), failed (orange).</li>' +
        '<li><strong>Service Table</strong> &mdash; 27+ services checked: nginx, apache2, mysql, postgresql, redis, docker, sshd, fail2ban, cron, rsyslog, postfix, and more. Shows status icon, PID, and active-since timestamp.</li>' +
        '<li><strong>Requirements</strong> &mdash; Requires Linux with systemd. Docker containers without systemd show empty results (expected). On bare metal, all installed services are detected.</li>' +
      '</ul>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">Hardening Tab:</p>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>AI Assessment</strong> &mdash; AI-generated hardening analysis with prioritized remediation steps.</li>' +
        '<li><strong>Score &amp; Grade</strong> &mdash; 0-100 score with letter grade (A-F). Score = (earned points / total points) &times; 100.</li>' +
        '<li><strong>Grouped Checklist</strong> &mdash; 16 checks across 7 categories, each with pass/fail icon and severity:</li>' +
      '</ul>' +
      '<table class="data-table" style="font-size:var(--font-size-xs);"><thead><tr><th>Category</th><th>Checks</th></tr></thead><tbody>' +
        '<tr><td style="color:var(--text-primary);">SSH</td><td>Root login disabled, password auth disabled, non-default port, protocol 2</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Firewall</td><td>Firewall active (ufw or firewalld)</td></tr>' +
        '<tr><td style="color:var(--text-primary);">IDS</td><td>Fail2ban installed, fail2ban running</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Updates</td><td>Packages up to date, unattended-upgrades enabled</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Files</td><td>/etc/shadow perms, /etc/passwd perms, no world-writable in /etc</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Kernel</td><td>ASLR enabled (level 2), core dumps disabled</td></tr>' +
        '<tr><td style="color:var(--text-primary);">Accounts</td><td>No empty password accounts</td></tr>' +
      '</tbody></table>' +
      '<p style="margin-top:8px;">The <strong>Fail2ban</strong> section (within Hardening tab) shows jail list with ban stats, currently banned IPs, and recent failed login attempts.</p>' +
      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: Why is the Services tab empty in Docker?</strong><br>A: Docker containers typically don\'t use systemd as PID 1. Services run directly via the entrypoint. Deploy on bare metal or a VM with systemd for full service monitoring.</p>' +
      '<p><strong>Q: How is the hardening score calculated?</strong><br>A: Each check has a weight (4-10 points) based on security impact. Critical checks (firewall, empty passwords) have higher weight than informational ones (SSH port, core dumps). Score = earned / total &times; 100.</p>' +
      '<p><strong>Q: Can I improve my score?</strong><br>A: Yes. The AI assessment and each failed check include specific remediation steps. Common improvements: enable firewall (<code style="background:var(--well);padding:1px 4px;border-radius:3px;">ufw enable</code>), harden SSH (<code style="background:var(--well);padding:1px 4px;border-radius:3px;">PermitRootLogin no</code>), start fail2ban (<code style="background:var(--well);padding:1px 4px;border-radius:3px;">systemctl enable --now fail2ban</code>).</p>',


    /* ===== WORKSPACE & GIT ===== */
    'workspace':
      '<h2 style="color:var(--text-primary);font-size:var(--font-size-xl);margin-bottom:16px;">Workspace &amp; Git</h2>' +
      '<p style="margin-bottom:16px;">The Workspace section includes Git Intelligence Center, GitHub Hub, Calendar, and Notes. The Git view provides commit timeline, branch management, stash operations, AI-assisted commit messages, and multi-repo project management with encrypted credential support for private repositories.</p>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Connecting a GitHub Repository with a Personal Access Token</h3>' +
      '<p style="margin-bottom:8px;">To work with private repositories (push, pull, clone), you need a GitHub Personal Access Token (PAT) stored in the encrypted credential vault.</p>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:16px 0 4px;">Step 1: Create a GitHub Personal Access Token</p>' +
      '<ol style="padding-left:20px;list-style:decimal;">' +
        '<li>Go to <strong>github.com</strong> and sign in to your account.</li>' +
        '<li>Click your profile picture (top-right) &rarr; <strong>Settings</strong>.</li>' +
        '<li>Scroll down the left sidebar &rarr; <strong>Developer settings</strong> (at the very bottom).</li>' +
        '<li>Click <strong>Personal access tokens</strong> &rarr; <strong>Tokens (classic)</strong>.</li>' +
        '<li>Click <strong>Generate new token</strong> &rarr; <strong>Generate new token (classic)</strong>.</li>' +
        '<li>Give it a descriptive <strong>Note</strong> (e.g. "Vigil SOC").</li>' +
        '<li>Set an <strong>Expiration</strong> (90 days recommended, or custom).</li>' +
        '<li>Under <strong>Select scopes</strong>, check <code style="background:var(--well);padding:1px 4px;border-radius:3px;">repo</code> (Full control of private repositories). This grants read/write access to your repos.</li>' +
        '<li>Click <strong>Generate token</strong> at the bottom.</li>' +
        '<li><strong>Copy the token immediately</strong> &mdash; it starts with <code style="background:var(--well);padding:1px 4px;border-radius:3px;">ghp_</code> and is only shown once. If you lose it, you must generate a new one.</li>' +
      '</ol>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:16px 0 4px;">Step 2: Store the Token in the Credential Vault</p>' +
      '<ol style="padding-left:20px;list-style:decimal;">' +
        '<li>In Vigil, navigate to <strong>Credentials</strong> in the sidebar (under System).</li>' +
        '<li>Click <strong>Add Credential</strong>.</li>' +
        '<li>Fill in the fields:' +
          '<ul style="padding-left:20px;list-style:disc;margin:4px 0;">' +
            '<li><strong>Name:</strong> a descriptive name (e.g. <code style="background:var(--well);padding:1px 4px;border-radius:3px;">github-pat</code>)</li>' +
            '<li><strong>Type:</strong> select <code style="background:var(--well);padding:1px 4px;border-radius:3px;">api_token</code></li>' +
            '<li><strong>Value:</strong> paste your <code style="background:var(--well);padding:1px 4px;border-radius:3px;">ghp_...</code> token</li>' +
          '</ul>' +
        '</li>' +
        '<li>Click <strong>Save</strong>. The token is encrypted with AES-256-GCM and stored in the vault. It is never visible in plaintext again (you can reveal it from the Credentials view when needed).</li>' +
      '</ol>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:16px 0 4px;">Step 3: Add a Git Project and Link the Token</p>' +
      '<ol style="padding-left:20px;list-style:decimal;">' +
        '<li>Navigate to <strong>Git</strong> in the sidebar (under Workspace).</li>' +
        '<li>Click the <strong>gear icon</strong> next to the project selector to open project management.</li>' +
        '<li>Click <strong>Add Project</strong>.</li>' +
        '<li>Fill in the fields:' +
          '<ul style="padding-left:20px;list-style:disc;margin:4px 0;">' +
            '<li><strong>Name:</strong> a display name for the repo</li>' +
            '<li><strong>Remote URL:</strong> the HTTPS clone URL (e.g. <code style="background:var(--well);padding:1px 4px;border-radius:3px;">https://github.com/your-org/your-repo.git</code>)</li>' +
            '<li><strong>Local Path:</strong> leave empty to auto-clone into the container, or enter an existing path</li>' +
            '<li><strong>Credential:</strong> select the credential you created (e.g. <code style="background:var(--well);padding:1px 4px;border-radius:3px;">github-pat</code>)</li>' +
          '</ul>' +
        '</li>' +
        '<li>Click <strong>Save</strong>. If no local path was provided, Vigil clones the repo automatically using the encrypted token.</li>' +
        '<li>The project appears in the project selector dropdown. Click it to activate &mdash; all Git view panels (commits, branches, diff, stash) now operate on this repo.</li>' +
      '</ol>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:16px 0 4px;">How Authentication Works</p>' +
      '<p>When you push, pull, or clone, Vigil retrieves the token from the encrypted vault at runtime and injects it into the HTTPS URL: <code style="background:var(--well);padding:1px 4px;border-radius:3px;">https://TOKEN@github.com/...</code>. The token is never written to disk in plaintext or stored in git config. SSH keys are also supported &mdash; store as type <code style="background:var(--well);padding:1px 4px;border-radius:3px;">ssh_key</code> and Vigil writes a temporary key file with 0600 permissions for the git operation.</p>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Git Intelligence Center Features</h3>' +
      '<ul style="padding-left:20px;list-style:disc;">' +
        '<li><strong>Commit Timeline</strong> &mdash; Rich commit log with author, date, files changed, insertions/deletions.</li>' +
        '<li><strong>Branch Manager</strong> &mdash; View local and remote branches with last commit info. AI branch cleanup analysis.</li>' +
        '<li><strong>Diff Viewer</strong> &mdash; Staged and unstaged diffs with stat summary.</li>' +
        '<li><strong>Stash Manager</strong> &mdash; List, push, and pop stashes.</li>' +
        '<li><strong>AI Commit Assistant</strong> &mdash; Generate conventional commit messages from staged changes. AI code review before committing.</li>' +
        '<li><strong>AI PR Description</strong> &mdash; Generate pull request title, summary, and test plan from branch diff.</li>' +
        '<li><strong>AI Conflict Help</strong> &mdash; Analyze merge conflicts with resolution suggestions.</li>' +
        '<li><strong>Heatmap</strong> &mdash; GitHub-style contribution calendar (last 12 months).</li>' +
        '<li><strong>Contributors</strong> &mdash; Commit count by author.</li>' +
        '<li><strong>Repo Stats</strong> &mdash; Total commits, file count, repo size, first commit date.</li>' +
      '</ul>' +

      '<p style="color:var(--text-primary);font-weight:600;margin:12px 0 4px;">FAQ:</p>' +
      '<p><strong>Q: Do I need a PAT for public repos?</strong><br>A: No. Public repos can be cloned and read without a token. You only need a PAT for pushing to any repo or cloning/pulling private repos.</p>' +
      '<p><strong>Q: My token expired, what happens?</strong><br>A: Git operations will fail with a 401 error. Generate a new token on GitHub, then update the credential in Vigil\'s Credentials view (delete the old one, add a new one with the same name).</p>' +
      '<p><strong>Q: Can I use fine-grained tokens instead of classic?</strong><br>A: Yes. Fine-grained tokens work the same way &mdash; they also start with <code style="background:var(--well);padding:1px 4px;border-radius:3px;">github_pat_</code>. Select the specific repositories and permissions you need (Contents: read/write is the minimum for push/pull).</p>' +
      '<p><strong>Q: Is my token safe?</strong><br>A: Tokens are encrypted with AES-256-GCM in the credential vault. They are only decrypted in memory during git operations. Set <code style="background:var(--well);padding:1px 4px;border-radius:3px;">ENCRYPTION_KEY</code> in your .env file for persistent encryption across container restarts.</p>' +
      '<p><strong>Q: Can I manage multiple repos?</strong><br>A: Yes. Add multiple projects in the Git view, each with its own credential. Switch between them using the project selector dropdown.</p>' +
      '<p><strong>Q: The Git view shows empty data?</strong><br>A: The container needs a git repository to read from. Add a project with a remote URL to auto-clone, or specify a local path to an existing repo mount.</p>',


    /* ===== API REFERENCE ===== */
    'api':
      '<h2 style="color:var(--text-primary);font-size:var(--font-size-xl);margin-bottom:16px;">API Reference</h2>' +
      '<p style="margin-bottom:12px;">All endpoints require authentication via <code style="background:var(--well);padding:1px 4px;border-radius:3px;">vigil_session</code> cookie or <code style="background:var(--well);padding:1px 4px;border-radius:3px;">Authorization: Bearer TOKEN</code> header.</p>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Authentication</h3>' +
      '<div class="code-block" style="margin-bottom:8px;">POST /api/auth/login        { username, password }\nPOST /api/auth/logout\nGET  /api/auth/check\nPOST /api/auth/2fa/setup    (returns QR code)\nPOST /api/auth/2fa/verify   { code }</div>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Dashboard &amp; Posture</h3>' +
      '<div class="code-block" style="margin-bottom:8px;">GET  /api/posture              Security posture score (0-100)\nGET  /api/dashboard/stats      Threats, findings, scan time, compliance %\nGET  /api/dashboard/threat-activity   24h threat timeline\nGET  /api/dashboard/severity-breakdown  Findings by severity\nGET  /api/briefing             AI security summary\nGET  /api/timeline?range=24h&type=all  Attack timeline events</div>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Scanning</h3>' +
      '<div class="code-block" style="margin-bottom:8px;">POST /api/scans             { type: nmap|nuclei|trivy|ssl, target, options }\nGET  /api/scans              List all scans\nGET  /api/scans/:id          Scan details + findings\nPOST /api/scans/:id/rerun    Re-run scan\nDEL  /api/scans/:id          Delete scan (admin)</div>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Threats &amp; Findings</h3>' +
      '<div class="code-block" style="margin-bottom:8px;">GET  /api/threats             Active threats + level\nGET  /api/threats/feed        External threat feeds + CISA KEV\nPOST /api/threats/:id/triage  AI threat triage\nGET  /api/findings            All findings (filter: severity, status, type)\nGET  /api/findings/stats      Finding statistics\nPOST /api/findings/:id/analyze  AI vulnerability analysis\nPATCH /api/findings/:id       Update status {status}\nPOST /api/hunt               { hypothesis }  Threat hunting\nGET  /api/hunt/history        Past 20 investigations</div>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Alerts &amp; Triage</h3>' +
      '<div class="code-block" style="margin-bottom:8px;">GET  /api/alerts?status=pending  Pending alerts\nPOST /api/alerts/:id/triage     AI alert triage\nGET  /api/alerts/triage-history  Past 20 triage results</div>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Agents &amp; Campaigns</h3>' +
      '<div class="code-block" style="margin-bottom:8px;">GET  /api/agents              List all agents\nPOST /api/agents              { name, category, description, system_prompt }\nPOST /api/agents/:id/run     { input }  Execute agent (60s timeout)\nGET  /api/agents/:id/runs     Agent run history\nGET  /api/campaigns           List campaigns\nPOST /api/campaigns           { goal, max_agents }  Launch campaign</div>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">OSINT</h3>' +
      '<div class="code-block" style="margin-bottom:8px;">POST /api/osint/domain       { domain }  Full domain recon + reverse IP + reputation + AI\nPOST /api/osint/ip           { ip }  IP lookup + dual-source geo + reverse IP + AI\nPOST /api/osint/username     { username }  Username enumeration (26 platforms)\nPOST /api/osint/phone        { number }  Phone intel (E.164, 70+ countries)\nPOST /api/osint/email        { email }  Email registration check (Holehe, 12 services)\nPOST /api/osint/recon        { target, spiderType, stealth }  Web recon crawler\nGET  /api/osint/recon/:id    Get web recon results\nGET  /api/osint/history       Last 100 lookups</div>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Incidents &amp; Playbooks</h3>' +
      '<div class="code-block" style="margin-bottom:8px;">GET  /api/incidents           List incidents\nPOST /api/incidents           { title, severity, description, type }\nPATCH /api/incidents/:id      { status, severity, assignee }\nPOST /api/incidents/:id/respond  AI playbook generation (30s)\nPOST /api/incidents/:id/timeline  { event, detail }\nGET  /api/playbooks           Playbook templates\nPOST /api/playbooks/generate  { description }  AI generation</div>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Compliance &amp; Reports</h3>' +
      '<div class="code-block" style="margin-bottom:8px;">GET  /api/compliance              All frameworks summary (scores, pass/fail/partial)\nGET  /api/compliance/:framework   Framework details + controls (soc2|iso27001|nist800-53)\nPOST /api/compliance/:framework/report  AI compliance audit report\nPOST /api/compliance/:framework/evidence  { controlId, notes }  Attach evidence\nPOST /api/reports/generate       { type }  AI report generation</div>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Log Analysis</h3>' +
      '<div class="code-block" style="margin-bottom:8px;">POST /api/logs/query         { query, source }  NL log search + AI analysis\nGET  /api/logs/sources        Available log sources</div>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Network &amp; Infrastructure (ServerKit)</h3>' +
      '<div class="code-block" style="margin-bottom:8px;">GET  /api/network/interfaces   Network interfaces\nGET  /api/network/connections  Active connections (ss/netstat)\nGET  /api/network/firewall     Firewall rules (ufw/iptables)\nGET  /api/network/services     Service health (27+ systemd services)\nGET  /api/network/hardening    Hardening audit (16 checks, score/grade, AI)\nGET  /api/network/fail2ban     Fail2ban jails + failed logins\nGET  /api/network/dns?domain=  DNS lookup (A, AAAA, MX, NS, TXT, CNAME)</div>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">MCP Server (37 tools, 7 resources, 8 prompts)</h3>' +
      '<div class="code-block" style="margin-bottom:8px;">POST /mcp                    MCP JSON-RPC handler (Streamable HTTP)\nPOST /api/mcp/test           { method, params }  GUI test endpoint (5min timeout)\nGET  /api/mcp/info            Server metadata + connection instructions</div>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">System</h3>' +
      '<div class="code-block" style="margin-bottom:8px;">GET  /api/health              Health check\nGET  /api/system              CPU, memory, disk, processes\nGET  /api/audit-log           Audit trail (filter: date, user, action)\nGET  /api/credentials         List credentials (encrypted)\nPOST /api/credentials         { name, type, value }  Add credential\nGET  /api/notifications       User notifications\nPATCH /api/notifications/:id  { read }  Mark read</div>',


    /* ===== SCANNER SETUP ===== */
    'scanners':
      '<h2 style="color:var(--text-primary);font-size:var(--font-size-xl);margin-bottom:16px;">Scanner Setup</h2>' +
      '<p style="margin-bottom:16px;">Vigil works without any scanners installed &mdash; scanning views show "Scanner not found" but everything else (dashboard, agents, incidents, compliance, reports) works normally. Install scanners for full functionality.</p>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Nmap (Port Scanner)</h3>' +
      '<div class="code-block" style="margin-bottom:12px;"># Ubuntu/Debian\nsudo apt install nmap\n\n# macOS\nbrew install nmap\n\n# Windows\n# Download from https://nmap.org/download.html\n\n# Verify\nnmap --version</div>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Nuclei (Vulnerability Scanner)</h3>' +
      '<div class="code-block" style="margin-bottom:12px;"># Install via Go\ngo install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n\n# Or download binary from GitHub releases\n# https://github.com/projectdiscovery/nuclei/releases\n\n# Update templates (9000+ community templates)\nnuclei -update-templates\n\n# Verify\nnuclei --version</div>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Trivy (Container/Filesystem Scanner)</h3>' +
      '<div class="code-block" style="margin-bottom:12px;"># Ubuntu/Debian\ncurl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin\n\n# macOS\nbrew install trivy\n\n# Verify\ntrivy --version</div>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Nikto (Web Scanner)</h3>' +
      '<div class="code-block" style="margin-bottom:12px;"># Ubuntu/Debian\nsudo apt install nikto\n\n# macOS\nbrew install nikto\n\n# Verify\nnikto -Version</div>' +
      '<p style="color:var(--text-tertiary);font-size:var(--font-size-xs);">Note: Nikto is noisy and may trigger WAF/IDS alerts. Use against staging/test environments or with explicit authorization only.</p>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">OpenSSL (SSL Audit)</h3>' +
      '<div class="code-block" style="margin-bottom:12px;"># Usually pre-installed on Linux/macOS\nopenssl version\n\n# Ubuntu/Debian (if missing)\nsudo apt install openssl</div>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">AI CLI Tools (BYOK)</h3>' +
      '<div class="code-block" style="margin-bottom:12px;"># Claude Code (requires Anthropic subscription)\nnpm install -g @anthropic-ai/claude-code\n\n# Codex CLI (requires OpenAI API key)\nnpm install -g @openai/codex\n\n# Verify\nclaude --version\ncodex --version</div>' +
      '<p>After installing, go to <strong>Settings &gt; AI Provider</strong> and select your preferred CLI. All AI features (triage, hunting, playbooks, analysis, summaries) use your AI subscription through these CLI tools.</p>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">GitHub CLI (Proxy Nodes)</h3>' +
      '<div class="code-block" style="margin-bottom:12px;"># Ubuntu/Debian\ncurl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg\necho "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list\nsudo apt update && sudo apt install gh\n\n# macOS\nbrew install gh\n\n# Authenticate\ngh auth login\n# Select: GitHub.com > HTTPS > Login with web browser\n# Open the device URL in your browser, enter the code\n\n# Verify\ngh auth status</div>' +
      '<p>GitHub CLI is required for the <strong>Proxy Nodes</strong> feature (ephemeral Codespace infrastructure). Pre-installed in the Vigil Docker image. Authenticate inside the container with <code style="background:var(--well);padding:1px 4px;border-radius:3px;">docker exec -it vigil gh auth login</code>, or mount host credentials via volumes: <code style="background:var(--well);padding:1px 4px;border-radius:3px;">~/.config/gh:/home/vigil/.config/gh:ro</code></p>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Docker (Container Scanning)</h3>' +
      '<div class="code-block" style="margin-bottom:12px;"># Install Docker\ncurl -fsSL https://get.docker.com | sudo sh\n\n# Add user to docker group\nsudo usermod -aG docker $USER\n\n# Verify\ndocker --version</div>' +
      '<p>Docker is needed for container scanning (trivy image scans) and the Docker security view. Mount the Docker socket in docker-compose.yml or ensure the vigil user has group membership.</p>',

    'shortcuts':
      '<h2 style="color:var(--text-primary);font-size:var(--font-size-xl);margin-bottom:16px;">Keyboard Shortcuts</h2>' +
      '<p style="margin-bottom:16px;">Vigil supports keyboard shortcuts for fast navigation. Press <kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);">?</kbd> anywhere in the app to see the full shortcut list.</p>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Global Shortcuts</h3>' +
      '<table style="width:100%;border-collapse:collapse;margin-bottom:16px;">' +
        '<thead><tr style="border-bottom:1px solid var(--border);"><th style="text-align:left;padding:8px 0;color:var(--text-primary);">Key</th><th style="text-align:left;padding:8px 0;color:var(--text-primary);">Action</th></tr></thead>' +
        '<tbody>' +
          '<tr style="border-bottom:1px solid rgba(255,255,255,0.04);"><td style="padding:6px 0;"><kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);font-size:var(--font-size-xs);">Ctrl + K</kbd></td><td style="padding:6px 0;">Open command palette &mdash; fuzzy search across all views</td></tr>' +
          '<tr style="border-bottom:1px solid rgba(255,255,255,0.04);"><td style="padding:6px 0;"><kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);font-size:var(--font-size-xs);">Ctrl + B</kbd></td><td style="padding:6px 0;">Toggle sidebar visibility</td></tr>' +
          '<tr style="border-bottom:1px solid rgba(255,255,255,0.04);"><td style="padding:6px 0;"><kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);font-size:var(--font-size-xs);">Ctrl + Shift + R</kbd></td><td style="padding:6px 0;">Refresh current view (re-fetch data)</td></tr>' +
          '<tr style="border-bottom:1px solid rgba(255,255,255,0.04);"><td style="padding:6px 0;"><kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);font-size:var(--font-size-xs);">Ctrl + `</kbd></td><td style="padding:6px 0;">Toggle terminal drawer</td></tr>' +
          '<tr style="border-bottom:1px solid rgba(255,255,255,0.04);"><td style="padding:6px 0;"><kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);font-size:var(--font-size-xs);">Escape</kbd></td><td style="padding:6px 0;">Close modal, command palette, or overlay</td></tr>' +
          '<tr><td style="padding:6px 0;"><kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);font-size:var(--font-size-xs);">?</kbd></td><td style="padding:6px 0;">Show keyboard shortcut help overlay</td></tr>' +
        '</tbody>' +
      '</table>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Quick Navigation (number keys)</h3>' +
      '<p style="margin-bottom:8px;">When no input field is focused, number keys jump directly to common views:</p>' +
      '<table style="width:100%;border-collapse:collapse;margin-bottom:16px;">' +
        '<tbody>' +
          '<tr style="border-bottom:1px solid rgba(255,255,255,0.04);"><td style="padding:6px 0;width:80px;"><kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);font-size:var(--font-size-xs);">1</kbd></td><td style="padding:6px 0;">Dashboard</td></tr>' +
          '<tr style="border-bottom:1px solid rgba(255,255,255,0.04);"><td style="padding:6px 0;"><kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);font-size:var(--font-size-xs);">2</kbd></td><td style="padding:6px 0;">Findings</td></tr>' +
          '<tr style="border-bottom:1px solid rgba(255,255,255,0.04);"><td style="padding:6px 0;"><kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);font-size:var(--font-size-xs);">3</kbd></td><td style="padding:6px 0;">Port Scanner</td></tr>' +
          '<tr style="border-bottom:1px solid rgba(255,255,255,0.04);"><td style="padding:6px 0;"><kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);font-size:var(--font-size-xs);">4</kbd></td><td style="padding:6px 0;">Web Scanner</td></tr>' +
          '<tr style="border-bottom:1px solid rgba(255,255,255,0.04);"><td style="padding:6px 0;"><kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);font-size:var(--font-size-xs);">5</kbd></td><td style="padding:6px 0;">Security Agents</td></tr>' +
          '<tr style="border-bottom:1px solid rgba(255,255,255,0.04);"><td style="padding:6px 0;"><kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);font-size:var(--font-size-xs);">6</kbd></td><td style="padding:6px 0;">AI Chat</td></tr>' +
          '<tr><td style="padding:6px 0;"><kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);font-size:var(--font-size-xs);">7</kbd></td><td style="padding:6px 0;">Settings</td></tr>' +
        '</tbody>' +
      '</table>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Command Palette</h3>' +
      '<p style="margin-bottom:8px;">The command palette (<kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);">Ctrl+K</kbd>) provides fuzzy search across all 37 views. Type to filter, use arrow keys to navigate, and press Enter to jump to the selected view. The current view is highlighted in cyan.</p>' +

      '<h3 style="color:var(--cyan);margin:16px 0 8px;">Notes</h3>' +
      '<ul style="padding-left:20px;">' +
        '<li>Number key shortcuts are disabled when an input field, textarea, or dropdown is focused</li>' +
        '<li><kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);">Ctrl+K</kbd> and <kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);">Ctrl+B</kbd> work even when input fields are focused</li>' +
        '<li>On macOS, <kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);">Cmd</kbd> works as an alternative to <kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);">Ctrl</kbd></li>' +
      '</ul>'
  }
};
