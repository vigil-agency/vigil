# Vigil v1.0 — Developer Guide

## Overview
AI-powered security operations platform. Express.js + Socket.IO on port 4100.
Vanilla JS frontend — no React, no build step, no bundler.
~35 route modules | ~27 libs | 37 views | 200+ endpoints | 6 npm deps.
License: AGPL-3.0

## Quick Start
```bash
npm install && npm start
# Access: http://localhost:4100
# Default: admin / admin (change immediately)
```

## Bare Metal Install (Ubuntu/Debian)
```bash
# Node.js 22
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs build-essential

# Security scanners
sudo apt-get install -y nmap nikto dnsutils whois openssl

# Nuclei (vulnerability scanner)
GO_NUCLEI_VER=$(curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v)
curl -sL "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_${GO_NUCLEI_VER}_linux_amd64.zip" -o /tmp/nuclei.zip
sudo unzip -q /tmp/nuclei.zip -d /usr/local/bin/ && rm /tmp/nuclei.zip

# Trivy (container/filesystem scanner)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin

# Docker CLI (for container security scanning)
curl -fsSL https://get.docker.com | sudo sh

# AI CLIs (BYOK — optional)
sudo npm install -g @anthropic-ai/claude-code @openai/codex

# PostgreSQL 17 client (optional — works without DB)
sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/pgdg.gpg
sudo apt-get update && sudo apt-get install -y postgresql-client-17
```

## Architecture

### Server (orchestrator)
```
server.js                    -> Express + Socket.IO setup, auth middleware, intervals, .env loader
routes/                      -> ~35 route modules
lib/                         -> ~27 shared modules
data/                        -> Runtime JSON stores (scans, reports, notifications, agents,
                                settings, audit-log)
public/                      -> Vanilla JS frontend (ViewRegistry pattern)
docs/                        -> Documentation
```

### .env Loader (built-in, no dotenv dependency)
Custom parser in server.js reads `security/.env` at startup. Sets `process.env[key]` only for keys not already set. Supports `KEY=VALUE` format, ignores comments (#) and blank lines.

### Route Modules (~35)
```
auth.js                -> Login, logout, session, 2FA setup/verify
system.js              -> CPU, memory, disk, processes, server info
scans.js               -> Scan orchestration, scheduling, history
scan-api.js            -> Web/SSL/WAF scanning bridge, WAF detection engine (30+ signatures)
nmap.js                -> Nmap network scanning (ports, hosts, services)
nuclei.js              -> Nuclei vulnerability scanning (templates, severity)
trivy.js               -> Trivy container/filesystem/image scanning
openssl.js             -> SSL/TLS certificate analysis, chain validation
nikto.js               -> Nikto web server scanner
dns.js                 -> DNS reconnaissance (dig, whois, zone transfer)
docker.js              -> Docker container security auditing
docker-direct.js       -> Native Docker Engine API (container inspection)
vulnerabilities.js     -> CVE tracking, vulnerability database, CVSS scoring
compliance.js          -> Compliance frameworks (SOC2, PCI-DSS, HIPAA, ISO27001)
reports.js             -> Report generation (PDF, JSON, CSV), scheduling
alerts.js              -> Alert rules, thresholds, notification channels
incidents.js           -> Incident response workflow, timeline, postmortem
assets.js              -> Asset inventory, network map, service catalog
policies.js            -> Security policy management, enforcement
threats.js             -> Threat intelligence feeds, IOC matching
pentest.js             -> Pentest command library + engagement management (Reconmap-inspired)
credentials.js         -> AES-256-GCM credential vault
notifications.js       -> Notification system (email, webhook, Slack)
settings.js            -> Platform configuration, user preferences
mcp.js                 -> MCP server (Streamable HTTP, 37 tools, 7 resources, 8 prompts)
health.js              -> Health check endpoint, service status
code-audit.js          -> LLM-driven source code vulnerability scanning + binary analysis routes
ephemeral-infra.js     -> Disposable proxy nodes + SSH tunnels + OOB callback listener (fluffy-barnacle + pgrok inspired)
intel-hub.js           -> Intel Hub (RSS feeds, CVE Watch, CISA KEV, AI Briefings)
```

### Lib Modules (~27)
```
db.js                  -> PostgreSQL pool, dbQuery helper
exec.js                -> Shell command execution wrapper (timeout, sanitization)
ai.js                  -> AI provider wrapper (askAI, askAIJSON, getAICommand)
rbac.js                -> RBAC roles (admin/analyst/viewer), requireRole middleware
audit.js               -> Structured audit logging, auto-log middleware
users.js               -> PBKDF2 password hashing, user CRUD (users.json)
totp.js                -> TOTP 2FA generation + verification
sessions.js            -> Session token management (sessions.json)
scanner-nmap.js        -> Nmap CLI wrapper, XML parsing, port/service extraction
scanner-nuclei.js      -> Nuclei CLI wrapper, template management, result parsing
scanner-trivy.js       -> Trivy CLI wrapper, SBOM generation, vuln aggregation
scanner-openssl.js     -> OpenSSL CLI wrapper, cert chain analysis, expiry checks
scanner-nikto.js       -> Nikto CLI wrapper, web vuln parsing
docker-engine.js       -> Native Docker Engine API client
credential-vault.js    -> AES-256-GCM encrypted credential storage
notification-sender.js -> Push notifications via Socket.IO
neural-cache.js        -> Intelligent caching layer
code-audit.js          -> LLM-driven code vulnerability scanner (7 vuln types, confidence scoring)
ephemeral-proxy.js     -> Disposable Codespace proxy management (SOCKS5 tunnels, lifecycle)
tunnel-manager.js      -> SSH tunnel lifecycle (forward/reverse/dynamic) + OOB callback HTTP listener (pgrok-inspired)
web-recon.js           -> Scrapy-inspired web crawler (surface scan, exposed files, tech fingerprint)
osint-engine.js        -> OSINT reconnaissance engine (domain/IP/WHOIS/DNS, reverse IP, reputation, WHOIS history, cert transparency)
ghost-osint.js         -> Username enumeration (26 platforms) + phone number intelligence (70+ countries)
raptor-engine.js       -> Adversarial analysis engine (MUST-GATE reasoning, 4-step exploitability validation)
binary-analysis.js     -> Binary deep analysis (vibe-re): section entropy, disasm patterns, taint chains, MITRE mapping, obfuscation detection + AI
pentest-commands.js    -> Parameterized command catalog (18 commands, 4 templates) + execution engine
purple-team.js         -> MITRE ATT&CK kill chain simulator (14 tactics, 5 scenarios, gap analysis)
ai-security-kb.js      -> AI Security Knowledge Base (OWASP LLM Top 10, MITRE ATLAS, injection patterns, defensive tools)
per-engine.js          -> P-E-R Engine: Planner-Executor-Reflector cycle + dual causal graph (LuaN1aoAgent-inspired)
intel-feeds.js         -> RSS/Atom feed parser (15 feeds), CISA KEV, NVD CVE API, AI briefings
```

### Frontend (ViewRegistry pattern)
```
public/
  index.html                 -> Shell: head, sidebar, 37 view containers
  css/
    theme.css                -> Vigil Dark + CSS variables (glass treatment)
    layout.css               -> Glass sidebar, topbar, content grid, status bar
    components.css           -> Glass cards, badges, buttons, tables, forms, animations
    scanner.css              -> Scanner result views, severity badges
    terminal.css             -> xterm.js terminal
    modal.css                -> Glass modal system
  js/
    app.js                   -> State, Socket.IO, view registry, nav, cache, hotkeys, command palette
    charts.js                -> Chart.js wrappers (vulnerability trends, scan history)
    modal.js                 -> Modal.open/close/confirm/loading
    toast.js                 -> Toast notification system
    views/                   -> 37 self-registering view modules
```

## 37 Sidebar Views (ordered by sidebar position)

### Dashboard + Intel Hub (pinned at top, headerless group)
| View | File | Description |
|------|------|-------------|
| Dashboard | `views/dashboard.js` | Security posture score, active threats, recent scans |
| Intel Hub | `views/knowledge.js` | RSS feeds, CVE Watch, CISA KEV, AI Briefings, AI Threats (5 tabs) |

### AI & Intel
| View | File | Description |
|------|------|-------------|
| AI Terminal | `views/ai-terminal.js` | Claude CLI terminal for AI-powered security analysis |
| AI Chat | `views/ai-chat.js` | Conversational AI security assistant |
| MCP Playground | `views/mcp.js` | MCP tool testing, prompt library, 12 category tabs |

### Agents
| View | File | Description |
|------|------|-------------|
| Security Agents | `views/agents.js` | 27 security agents with "Try:" example buttons |
| Campaigns | `views/campaigns.js` | Multi-agent campaigns + Purple Team Simulator (Decepticon-inspired) |
| Pentest | `views/pentest.js` | Pentest command library, engagement phases, AI reports, Autonomous P-E-R tab (Reconmap + LuaN1aoAgent) |
| Playbooks | `views/playbooks.js` | Incident response playbook management |

### Workspace (third sidebar group)
| View | File | Description |
|------|------|-------------|
| Calendar | `views/calendar.js` | Security operations calendar |
| Notes | `views/notes.js` | Investigation notes and documentation |
| Git | `views/git.js` | Git repository management |
| GitHub Hub | `views/github-hub.js` | GitHub integration hub |

### Threat Operations
| View | File | Description |
|------|------|-------------|
| Threat Feed | `views/threat-intel.js` | Threat feeds, IOC matching, adversary profiles |
| Alert Triage | `views/alerts.js` | Alert rule configuration, notification channels |
| Threat Hunt | `views/threat-map.js` | Live threat visualization, geographic origins |

### Scanning
| View | File | Description |
|------|------|-------------|
| Port Scanner | `views/network-scan.js` | Nmap port scanning, host discovery, service detection |
| Vuln Scanner | `views/vuln-scan.js` | Nuclei vulnerability scanning with template selection |
| Web Scanner | `views/web-scanner.js` | Web scanning + WAF Detection tab (30+ WAF signatures) |
| Container Security | `views/container-scan.js` | Trivy image/filesystem scanning, SBOM generation |
| SSL Monitor | `views/ssl-audit.js` | OpenSSL certificate chain analysis, cipher suite grading |
| DNS Security | `views/dns-security.js` | DNS security analysis, DNSSEC validation |
| Code Audit | `views/code-audit.js` | LLM-driven source code vulnerability scanning + Binary Analysis tab |
| Proxy Nodes | `views/proxy-nodes.js` | Codespace proxies + Proxy Pool + SSH Tunnels + Callback Listener + Payload Hosting (3 tabs) |

### Intelligence
| View | File | Description |
|------|------|-------------|
| OSINT | `views/osint.js` | Domain, IP, Phone, Email Intel, Username, Web Recon tabs |
| Findings | `views/findings.js` | All vulnerability findings, filtering, severity |
| Attack Timeline | `views/timeline.js` | Incident timeline visualization, event correlation |

### Compliance
| View | File | Description |
|------|------|-------------|
| Frameworks | `views/compliance.js` | SOC2, ISO27001, NIST, OWASP LLM Top 10 (4 tabs) |
| Reports | `views/reports.js` | Report generation (PDF/JSON/CSV), scheduling |
| Audit Log | `views/audit-log.js` | Immutable audit trail, filtering, export |

### Infrastructure
| View | File | Description |
|------|------|-------------|
| Network | `views/network.js` | Network interfaces, ports, firewall + Services tab + Hardening audit (ServerKit) |
| Log Analysis | `views/log-analysis.js` | Log search and threat hunting |
| Credentials | `views/credentials.js` | AES-256-GCM credential vault |
| Notifications | `views/notifications.js` | Notification system management |

### System
| View | File | Description |
|------|------|-------------|
| Settings | `views/settings.js` | User management, AI provider, scanner paths, 2FA |
| Docs/FAQ | `views/docs.js` | Getting started guide, FAQ, troubleshooting |

## MCP Server (Built-In, Sandboxed)
- MCP server is **embedded inside Vigil** at `POST /mcp` (Streamable HTTP transport).
- Customers connect from Claude Desktop/Code/Cursor/VS Code on their local machine to Vigil's `/mcp` endpoint.
- Each customer's MCP server is isolated in their own container sandbox -- tenant-scoped, auth-gated.
- SDK: `@modelcontextprotocol/sdk` + Zod schemas

### Tools (37) — actual names from routes/mcp.js
```
# System & Posture
check_posture            -> Security posture score + grade breakdown
query_logs               -> Natural language log search with AI analysis

# Scanning
scan_ports               -> Nmap port scan (target, port range)
scan_vulnerabilities     -> Nuclei vuln scan (target, severity filter)
check_ssl                -> SSL/TLS certificate check (domain)

# Intelligence & OSINT
osint_domain             -> Domain DNS reconnaissance (A, MX, NS)
osint_ip                 -> IP geolocation lookup (ip-api.com)
osint_reverse_ip         -> Reverse IP lookup — find all domains on same IP (WebOSINT)
osint_email_check        -> Email registration check across 12 services (Holehe-inspired)
triage_alert             -> AI alert triage (title, details, severity)
hunt_threat              -> Threat hypothesis investigation (Linux evidence)

# Agents
run_agent                -> Execute security agent by slug (slug, input)
launch_campaign          -> Multi-agent campaign (goal, maxAgents)

# Compliance & Reports
generate_report          -> Security report (security-audit/vulnerability/compliance/incident/executive)
compliance_check         -> Framework compliance check (soc2/iso27001/nist800-53)
list_findings            -> Get vulnerability findings (severity filter, limit)

# Incidents
incident_create          -> Create security incident (title, severity, description)

# Code Audit
run_code_audit           -> AI source code vulnerability scan (target dir, languages)
get_code_audit_results   -> Get code audit findings (scanId or "latest")

# WAF Detection
detect_waf               -> WAF/CDN fingerprinting (target URL, passive/active)

# Proxy Nodes
list_proxy_nodes         -> List ephemeral proxy nodes + tunnel status
create_proxy_node        -> Create disposable Codespace proxy (requires gh auth)
start_proxy_tunnel       -> Start SOCKS5 tunnel through proxy node
plan_proxy_infrastructure -> AI proxy infrastructure planning

# Adversarial (Raptor-inspired)
validate_exploitability  -> 4-step MUST-GATE exploitability validation
adversarial_analysis     -> Deep adversarial security analysis with reasoning constraints

# Pentest (Reconmap-inspired)
run_pentest_command      -> Execute pentest command from library (commandId, params)
get_pentest_results      -> Get pentest project details and findings (projectId or "latest")

# Purple Team (Decepticon-inspired)
run_purple_team_sim      -> Run attack-defense gap analysis simulation (target, scenario)
get_purple_team_results  -> Get purple team simulation results (simId or "latest")

# Binary Analysis (vibe-re enhanced)
analyze_binary           -> Deep binary analysis + MITRE mapping (filePath, aiAnalysis, deepAnalysis)

# SSH Tunnels & Callback (pgrok-inspired)
create_tunnel            -> Create SSH tunnel (forward/reverse/dynamic, sshTarget, ports)
manage_callback_listener -> Start/stop/status OOB callback listener for blind vuln detection
manage_proxy_pool        -> Proxy pool status + config export (proxychains/curl/Burp/nmap/nuclei)

# AI Security (awesome-ai-security inspired)
check_ai_security        -> AI/LLM security posture assessment (OWASP LLM Top 10, MITRE ATLAS)

# Autonomous Pentest (LuaN1aoAgent-inspired)
autonomous_pentest       -> P-E-R autonomous pentest with dual causal graph reasoning

# Infrastructure (ServerKit-inspired)
check_server_hardening   -> Server hardening audit (SSH, firewall, IDS, kernel, files, score/grade)
```

### Resources
- `vigil://posture` -- Current security posture overview
- `vigil://threats` -- Active security threats
- `vigil://findings` -- Open vulnerability findings
- `vigil://code-audit-findings` -- Code audit vulnerability findings
- `vigil://waf-signatures` -- WAF detection signature database (30+)
- `vigil://proxy-nodes` -- Ephemeral proxy node status
- `vigil://ai-security-kb` -- AI Security Knowledge Base (OWASP LLM Top 10, MITRE ATLAS, injection patterns)

### Prompts
- `security_audit` -- Full security audit report generation
- `incident_response` -- Incident response playbook execution
- `threat_briefing` -- Daily threat intelligence briefing
- `compliance_report` -- Compliance gap analysis against framework
- `code_security_review` -- AI-powered source code security review
- `waf_reconnaissance` -- WAF detection and bypass analysis
- `anonymous_pentest_setup` -- Plan and provision anonymous scanning infra
- `ai_security_review` -- AI/LLM security posture assessment (OWASP LLM Top 10)

### GUI Test Endpoint
- `POST /api/mcp/test` uses InMemoryTransport (bypasses HTTP handshake, 5min tool timeout)
- GUI playground: search bar + 12 category tabs (All/Scanning/Intelligence/Compliance/Incident/System/Code Audit/Proxy/Adversarial/Pentest/Purple Team/AI Security), schema-driven param forms, 4 prompt workflow cards, request log
- MCP tools that need AI have 120s internal timeout; MCP client timeout is 300s to accommodate

## ViewRegistry Pattern
Each view JS file self-registers on `window.Views`:
```javascript
Views.myview = {
  init: function() { /* render HTML template into #view-myview */ },
  show: function() { /* fetch data, called on nav click */ },
  hide: function() { /* cleanup */ },
  update: function(data) { /* handle socket.io updates */ }
};
```

## Modal API
```javascript
// Open a custom modal
Modal.open({ title: 'My Modal', body: '<p>HTML content</p>', footer: '<button>OK</button>', size: 'lg' });

// Confirmation dialog (returns Promise<boolean>)
const confirmed = await Modal.confirm({
  title: 'Delete Scan',
  message: 'Are you sure?',
  confirmText: 'Delete',
  dangerous: true  // orange confirm button
});

// Loading state
Modal.loading('Scanning...');
Modal.close();
```

## Theme: Vigil Dark (Glass Treatment)

### CSS Variables (defined in theme.css)
- `--canvas: #0a0b10` -- deepest background
- `--surface-solid: #0e0e12` -- sidebar, topbar base
- `--surface: rgba(14,14,18,0.65)` -- glass cards
- `--text-primary: #e4e4e7`, `--text-secondary: #8b8b92`, `--text-tertiary: #52525a` (zinc scale)
- `--border: rgba(255,255,255,0.08)`, `--border-glass: rgba(255,255,255,0.10)`, `--border-top: rgba(255,255,255,0.14)`
- `--cyan: #22d3ee` -- secure, healthy, passing, active
- `--orange: #ff6b2b` -- threat, vulnerability, warning, critical

### Glass Treatment
- Sidebar: `rgba(10,10,14,0.70)` + `backdrop-filter: blur(40px) saturate(180%)`
- Topbar: `rgba(14,14,18,0.80)` + `backdrop-filter: blur(20px) saturate(180%)`
- Cards: `backdrop-filter: blur(20px) saturate(180%)` + border-top highlight + inset shadow
- Modals: `rgba(14,14,18,0.85)` + `blur(24px) saturate(180%)`

### Signal System (MANDATORY)
- **Cyan (#22d3ee)** = secure/passing/healthy/active/clean
- **Orange (#ff6b2b)** = threat/vulnerable/warning/critical/compromised
- **NEVER use green for success or red for error**

### Severity Badges
- Critical: orange bg, white text
- High: orange text, transparent bg
- Medium: `--text-secondary` with orange-tinted border
- Low: `--text-tertiary`
- Info: cyan text

### Fonts
- JetBrains Mono (monospace, primary for code + scanner output + status bar)
- System font stack for body text

## Socket.IO Events

### Server -> Client
| Event | Shape | Interval |
|-------|-------|----------|
| `init` | `{ system, scans, alerts, incidents }` | on connect |
| `metrics` | `{ system: {cpuPct, usedMemPct, usedMemMB, totalMemMB, ...}, ts }` | 3s |
| `scan_progress` | `{ scanId, type, progress, status }` | during scan |
| `scan_complete` | `{ scanId, type, results, summary }` | on scan finish |
| `code_audit_progress` | `{ scanId, phase, message }` | during code audit |
| `proxy_node_update` | `{ action, name, node? }` | on proxy node change |
| `tunnel_update` | `{ action, tunnel?, id? }` | on tunnel create/stop |
| `callback_update` | `{ action, port? }` | on callback listener start |
| `recon_progress` | `{ scanId, phase, url? }` | during web recon crawl |
| `recon_complete` | `{ scanId, spiderType, target, summary }` | on recon finish |
| `alert` | `{ id, severity, message, source, ts }` | on trigger |
| `threat_update` | `{ threats: [] }` | 30s |
| `posture_update` | `{ score, breakdown }` | 60s |
| `terminal_output` | string | on terminal activity |

### Client -> Server
| Event | Shape |
|-------|-------|
| `terminal_start` | `{ cols, rows }` |
| `terminal_input` | string |
| `terminal_resize` | `{ cols, rows }` |
| `start_scan` | `{ type, target, options }` |
| `cancel_scan` | `{ scanId }` |
| `refresh` | (empty) |

## AI Integration (BYOK + CLI Passthrough)

### Architecture
Users bring their own AI subscriptions. The app shells out to locally-installed CLI tools -- zero AI cost for the product.

### Supported Providers (Settings > AI Provider)
- **Claude API** (`claude-api`) -- direct Anthropic Messages API (requires ANTHROPIC_API_KEY)
- **Claude CLI** (`claude --print`) -- requires Anthropic subscription or Claude Max
- **Claude Code** (`claude`) -- requires Claude Max subscription
- **Codex CLI** (`codex`) -- OpenAI's open-source coding agent, requires OpenAI API key
- **None** -- AI features disabled, graceful degradation

### Docker AI Setup (Max Subscription)
- Claude CLI installed globally in container (`npm install -g @anthropic-ai/claude-code`)
- Host OAuth credentials mounted read-only: `~/.claude/.credentials.json:/home/vigil/.claude/.credentials.json:ro`
- `CLAUDECODE` env var stripped before spawning CLI (prevents nested-instance refusal)
- Uses `execFileSafe()` (not shell) to avoid backtick/pipe issues in prompts
- `child.stdin.end()` called after spawn to prevent CLI hanging
- Timeout: 120s default (complex prompts with README content need 60-90s)

### AI-Powered Features
- Vulnerability triage and prioritization
- Remediation guidance generation
- Incident response playbook creation
- Compliance gap analysis with recommendations
- Threat intelligence correlation
- Scan result summarization and risk scoring
- Postmortem report generation
- Security policy generation from description
- Daily threat briefing summaries
- Natural language to scanner command translation
- LLM-driven code vulnerability scanning (Vulnhuntr-inspired zero-shot analysis)
- AI finding analysis (per-finding deep-dive from Findings view)

## Scanner Integrations

### Nmap (Network Scanner)
- Port scanning (TCP/UDP/SYN)
- Host discovery (ping sweep, ARP)
- Service/version detection
- OS fingerprinting
- NSE script execution
- XML output parsing

### Nuclei (Vulnerability Scanner)
- Template-based scanning (9000+ templates)
- Severity filtering (critical, high, medium, low, info)
- Custom template support
- Rate limiting and threading control
- Authenticated scanning

### Trivy (Container/Filesystem Scanner)
- Docker image vulnerability scanning
- Filesystem scanning
- SBOM generation (CycloneDX, SPDX)
- Secret detection
- Misconfiguration scanning (Dockerfile, K8s, Terraform)
- License scanning

### OpenSSL (Certificate Analysis)
- Certificate chain validation
- Cipher suite enumeration and grading
- Protocol version testing (TLS 1.0-1.3)
- Certificate expiry monitoring
- OCSP/CRL checking
- Certificate transparency log lookup

### Nikto (Web Server Scanner)
- Web server misconfiguration detection
- Default file/CGI detection
- Outdated software identification
- HTTP method testing
- Server header analysis

### WAF Detection (evilwaf-inspired)
- 30+ WAF signature database (Cloudflare, AWS WAF, Akamai, Imperva, F5, ModSecurity, etc.)
- 4 detection vectors: response headers, cookies, body patterns, TLS cert issuer
- Passive mode (header analysis only) + Active mode (benign probe payloads)
- Auto-runs during full web scans; standalone via `POST /api/scan/waf`
- Integrated as tab within Web Scanner view (no new sidebar item)

### Code Audit (Vulnhuntr-inspired)
- LLM-driven zero-shot source code vulnerability discovery
- 7 vulnerability types: RCE, SQLi, XSS, SSRF, LFI, AFO, IDOR (CWE/MITRE mapped)
- 3-phase algorithm: file discovery → AI triage → deep analysis with confidence scoring
- Supports JS, TS, Python, Ruby, PHP, Java, Go, C#
- Findings normalized to standard scan format, visible in Findings view
- API: `POST /api/code-audit`, `GET /api/code-audit/:id`, `POST /api/code-audit/preview`
- Exploitability validation: `POST /api/code-audit/:id/validate/:findingIdx` (Raptor 4-step analysis)

### Purple Team Simulator (Decepticon-inspired)
- AI-driven attack-defense gap analysis through MITRE ATT&CK kill chain
- 14 ATT&CK tactics (TA0043-TA0040), 10 analyzed per simulation
- 5 threat scenarios: External Attacker, Insider Threat, Ransomware, APT, Supply Chain
- Per-tactic output: attack technique, scenario, likelihood, detection %, prevention %, controls, gaps
- Aggregate: Defense Grade (A-F), Defense Score, Overall Risk, coverage heatmap
- Produces: critical gaps list, prioritized recommendations with impact/effort
- No actual attacks — AI reasoning-only simulation
- API: `GET /api/campaigns/purple-team/scenarios`, `POST /api/campaigns/purple-team`, `GET /api/campaigns/purple-team/:id`
- Socket.IO events: `purple_team_progress`, `purple_team_complete`
- Lib: `lib/purple-team.js`, Routes: added to `routes/campaigns.js`
- Frontend: "Purple Team" tab in Campaigns view with ATT&CK heatmap + tactic detail modals

### Pentest Command Library (Reconmap-inspired)
- 18 pre-built parameterized security commands across 4 engagement phases
- Recon (5): Host Discovery, DNS Lookup, WHOIS, Reverse DNS, SSL Certificate, Traceroute
- Scanning (7): Quick/Full Port Scan, Vuln Scan, Web Server Scan, SSL Audit, DNS Zone Transfer, OS Detection, Script Scan
- Exploitation (4): Banner Grab, HTTP Methods, Default Creds, NSE Vuln Scripts
- 4 engagement templates: Web App (OWASP), Network (PTES), Quick Assessment, SSL Audit
- Parameter validation via safe char regex, `execFileSafe()` execution (no shell injection)
- Output parsers: nmap-hosts, nmap-ports, nuclei-jsonl, nikto, raw
- AI pentest report generation from project data (scope, methodology, commands, findings)
- API: `GET /api/pentest/commands`, `POST /api/pentest`, `GET /api/pentest/:id`, `POST /api/pentest/:id/exec`, `POST /api/pentest/:id/report`
- Socket.IO events: `pentest_progress`, `pentest_exec_complete`
- Lib: `lib/pentest-commands.js`, Routes: `routes/pentest.js` (standalone, moved from extras.js)

### Binary Analysis (integrated in Code Audit view, vibe-re enhanced)
- Binary inspection using `file`, `strings`, `readelf`, `objdump` (no Ghidra/Java)
- Extracts: file type, hashes (MD5/SHA1/SHA256), Shannon entropy, IOCs (URLs, IPs, emails, domains, CVEs)
- 60+ suspicious import detection (process injection, anti-debug, crypto, persistence, network APIs)
- ELF/PE structure: section headers, dynamic symbols, shared libraries, imports/exports
- Deep analysis (vibe-re inspired, 0xeb/vibe-re):
  - Per-section entropy heatmap with anomaly detection (encrypted data, code caves, packed sections)
  - 15 packer signatures: UPX, ASPack, VMProtect, Themida, Enigma, PECompact, MPRESS, Petite, NSPack, MEW
  - 9 disassembly patterns via objdump: ROP gadgets, syscalls, NOP sleds, PEB access, XOR decoders, call-pop PIC, stack pivots, self-modifying code, anti-disassembly
  - 12 import taint chains: process injection, process hollowing, reflective DLL, network exfiltration, HTTP C2, download & execute, credential harvesting, keylogger, anti-analysis, persistence, Unix reverse shell, shared library injection
  - MITRE ATT&CK mapping: auto-maps imports + IOCs + strings to ATT&CK techniques (70+ mappings)
  - String obfuscation detection: chi-squared distribution, XOR key brute-force, encrypted block detection, string density analysis (score 0-100)
- AI threat assessment: LLM produces malware analysis report with deep analysis context
- Max file size: 50MB
- API: `POST /api/code-audit/binary`, `GET /api/code-audit/binary/:id`
- Frontend: "Binary Analysis" tab in Code Audit view, results in Findings view (type='binary-analysis')
- Lib: `lib/binary-analysis.js` (exports: analyzeBinary, detectFileType, extractStrings, analyzeELF, analyzePE, computeEntropy, computeHashes, flagSuspiciousImports, analyzeEntropySections, detectDisassemblyPatterns, buildImportTaintChains, mapMITREAttackTactics, detectStringObfuscation)

### Raptor Engine (Adversarial Analysis)
- MUST-GATE reasoning framework: 7 forced constraints (ASSUME-EXPLOIT, STRICT-SEQUENCE, CHECKLIST, NO-HEDGING, FULL-COVERAGE, PROOF, CONSISTENCY)
- 4-step exploitability validation: Source Control → Sanitizer Effectiveness → Reachability → Impact Assessment
- Adversarial prioritization: Secrets > Input Validation > Auth/Authz > Crypto > Config
- 5 Raptor-inspired agents: Adversarial Analyst, Exploit Validator, Attack Path Mapper, Patch Reviewer, Red Team Planner
- 2 MCP tools: `validate_exploitability`, `adversarial_analysis`
- Code audit "Validate Exploitability" button runs per-finding 4-step analysis
- Lib: `lib/raptor-engine.js` (exports: adversarialAnalysis, validateExploitability, buildAdversarialPrompt, buildExploitabilityPrompt)
- Agent timeout: 180s (Raptor agents produce 3-14K chars of detailed analysis)

#### How to use Raptor features (3 sidebar paths):
1. **Sidebar > Agents > Security Agents > Hunters tab**: Run any of the 5 Raptor agents. Enter plain English describing code, app architecture, scan output, or vulnerability findings. Wait 30s-3min for detailed analysis.
2. **Sidebar > Scanning > Code Audit**: Run a code audit, then expand any finding row and click the "Validate Exploitability" button to run 4-step MUST-GATE analysis. Shows pass/fail per step with EXPLOITABLE/FALSE_POSITIVE verdict.
3. **Sidebar > System > MCP Server > Adversarial tab**: Test `validate_exploitability` or `adversarial_analysis` tools directly. Also available to any MCP-connected AI (Claude Desktop: `claude mcp add vigil --transport http http://localhost:4100/mcp`).

### Proxy Nodes (fluffy-barnacle + pgrok inspired)
- GitHub Codespaces as disposable SOCKS5 proxy nodes for anonymous scanning
- Full lifecycle: create, start, stop, delete Codespaces via `gh` CLI
- SSH dynamic port forwarding (`gh codespace ssh -D`) for SOCKS5 proxy
- Exit IP detection via ifconfig.me through the proxy
- AI infrastructure planner for engagement-based proxy recommendations
- Requires `gh` CLI installed and authenticated; graceful degradation when absent
- API: `GET /api/proxy-nodes`, `POST /api/proxy-nodes`, `POST /api/proxy-nodes/ai-plan`

### SSH Tunnels (pgrok-inspired)
- 3 tunnel types: Forward (-L local→remote), Reverse (-R remote←local), Dynamic (-D SOCKS5)
- Auto-reconnect with exponential backoff (2s → 4s → 8s → 16s max, reset after 60s stable)
- SSH keepalive (`ServerAliveInterval=15`), `ExitOnForwardFailure=yes`, strict host key disabled
- Health check via port listening verification
- Data persisted to `data/tunnels.json`, process cleanup on exit
- API: `GET/POST /api/proxy-nodes/tunnels`, `DELETE /api/proxy-nodes/tunnels/:id`, `POST /api/proxy-nodes/tunnels/:id/health`
- MCP tool: `create_tunnel` (type, sshTarget, localPort, remoteHost, remotePort)

### OOB Callback Listener (pgrok-inspired)
- Built-in HTTP server captures all incoming requests for blind vulnerability detection
- Replaces need for external services like interactsh/Burp Collaborator
- Secret-based targeting: generates unique token in URL path; requests matching secret are flagged as targeted callbacks
- Captures: method, URL, headers, body, source IP, user agent, content type
- Data persisted to `data/callback-log.json` (max 500 entries), auto-cleanup
- API: `GET/POST /api/proxy-nodes/callback`, `GET/DELETE /api/proxy-nodes/callback/log`
- MCP tool: `manage_callback_listener` (action: start/stop/status, port)
- Frontend: "Callback Listener" tab in Proxy Nodes view with status panel, captured requests table, detail modal

### Proxy Pool & Config Export (fluffy-barnacle enhanced)
- Proxy pool management: tracks all active SOCKS5 tunnels with exit IPs
- Config generation for 6 formats: proxychains.conf, curl, ENV vars, Burp Suite, nmap, nuclei
- Round-robin proxy chain support for multiple active proxies
- API: `GET /api/proxy-nodes/pool`, `POST /api/proxy-nodes/pool/config`
- MCP tool: `manage_proxy_pool` (action: status/config, format: proxychains/curl/env/burp/nmap/nuclei)
- Neural cache: `proxy:pool` (30s TTL)
- Frontend: "Proxy Pool & Config Export" card in Proxy Nodes tab with format buttons + copy

### Payload Hosting (fluffy-barnacle cs-serve inspired)
- Host files or SSRF redirect payloads on the callback listener HTTP server
- Two types: redirect (302/301/307/308 to target URL) and file (custom content + MIME type)
- 12 SSRF presets: AWS metadata/IAM/user-data, GCP metadata/token, Azure IMDS/identity, DigitalOcean, K8s API/secrets, Docker socket, Consul
- Payload requests are served automatically and logged as targeted callbacks
- Data persisted to `data/hosted-payloads.json`, hit counts tracked per payload
- API: `GET/POST/DELETE /api/proxy-nodes/callback/payloads`, `GET /api/proxy-nodes/callback/ssrf-presets`
- Neural cache: `callback:payloads` (30s TTL)
- Frontend: "Hosted Payloads" section in Callback Listener tab with SSRF Presets modal

### AI Security Knowledge Base (awesome-ai-security inspired)
- In-memory knowledge base of AI/ML security threats, frameworks, and defenses
- OWASP LLM Top 10 (2025): 10 entries with descriptions, attack examples, mitigations, CWE references
- MITRE ATLAS: 15 adversarial ML techniques with detection/mitigation guidance
- Prompt injection patterns: 8 types (direct, indirect, encoding, role-play, RAG, MCP, multi-turn, splitting)
- AI vulnerability types: 8 classes (model theft, data extraction, adversarial examples, agent manipulation, MCP compromise)
- Defensive tools reference: 12 tools (guardrails, scanners, red-team, detection)
- Compliance: OWASP LLM as 4th framework in Compliance view (alongside SOC2, ISO27001, NIST)
- Intel Hub: "AI Threats" tab with 5 sub-categories, detail modals, AI analysis
- MCP: `check_ai_security` tool, `vigil://ai-security-kb` resource, `ai_security_review` prompt
- Agents: `ai-threat-analyst` (maps to OWASP/ATLAS) and `prompt-injection-tester` (8 PI vectors)
- API: `GET /api/intel/ai-threats`, `POST /api/intel/ai-threats/analyze`
- Neural cache: `ai-kb:all` key with 10min TTL (static KB data)
- Lib: `lib/ai-security-kb.js`, Routes: modifications to intel-hub.js, compliance.js, agents.js, mcp.js

### P-E-R Engine (LuaN1aoAgent-inspired Autonomous Pentest)
- Planner-Executor-Reflector cycle for autonomous penetration testing
- Dual causal graph: Task Graph (DAG of subtasks with dependencies) + Causal Graph (evidence chain)
- Causal chain: Evidence -> Hypothesis -> Possible Vulnerability -> Confirmed Vulnerability
- L0-L5 failure attribution: L0=raw, L1=tool failure, L2=prerequisite, L3=environmental, L4=hypothesis falsified, L5=strategy flawed
- Non-monotonic confidence propagation: logit/sigmoid updates, necessary vs contingent evidence
- Staged node review: Executor proposes causal nodes, Reflector validates before committing
- Depth modes: quick (3 cycles), standard (5 cycles), deep (8 cycles)
- Tools: nmap, nuclei, nikto, dig, whois, openssl, curl (validated via execFileSafe)
- AI-driven: Planner decomposes target, Executor analyzes output, Reflector audits, Replanner adapts
- Results persisted to `data/per-results.json`, cached in neural cache (10min TTL)
- Socket.IO events: `per_progress` (phase updates), `per_complete`, `per_error`
- API: `POST /api/pentest/autonomous`, `GET /api/pentest/autonomous`, `GET /api/pentest/autonomous/:id`, `POST /api/pentest/autonomous/:id/halt`
- MCP tool: `autonomous_pentest` (target, scope, depth)
- Agent: `autonomous-pentester` with 3 example prompts
- Frontend: "Autonomous" tab in Pentest view with launch modal, live progress, detail modal with task/causal graph visualization
- Lib: `lib/per-engine.js` (exports: createPEREngine, PEREngine, TaskGraph, CausalGraph, constants)

### Web Recon (Scrapy + Scrapling inspired)
- Lightweight Node.js web crawler in `lib/web-recon.js` (Scrapy Spider→Pipeline architecture)
- 4 spider types: surface (crawl+extract+IOCs), exposed (50+ sensitive path check), fingerprint (deep tech+IOCs), threat-intel (public feed scraping)
- Extracts: links (internal/external), emails, forms (login/upload), technologies (20+ patterns), security headers (9 checks), IOCs (IPv4, MD5, SHA256, CVEs)
- Stealth mode (Scrapling-inspired): 5 browser profiles with UA rotation, Sec-Fetch headers, sec-ch-ua client hints, Google referer injection, timing jitter (±30%)
- Threat Intel spider scrapes 6 public feeds: CISA KEV, Feodo Tracker, URLhaus, ThreatFox, OpenPhish, IPsum (no API keys)
- Rate-limited (configurable delay with jitter in stealth), robots.txt-aware, depth-limited (max 3), URL deduplication
- Integrated as "Web Recon" tab in existing OSINT view (no new sidebar item)
- AI analysis endpoint generates pentest-grade security assessments
- API: `POST /api/osint/recon` (accepts `stealth:true`, `spiderType:"threat-intel"`), `GET /api/osint/recon/:id`, `GET /api/osint/recon`, `POST /api/osint/recon/:id/analyze`

### Ghost OSINT (GhostTrack-inspired)
- Username enumeration across 26 platforms (GitHub, GitLab, Reddit, HackerNews, Twitch, YouTube, Steam, npm, PyPI, etc.)
- Phone number intelligence with E.164 country code parsing (70+ countries), line type detection, format validation
- Integrated as "Phone Intel" and "Username" tabs in existing OSINT view (no new sidebar items)
- Username checks use stealth HTTP headers, run in parallel batches of 5, with rate limiting
- AI analysis for both: digital footprint assessment (username) and carrier/region analysis (phone)
- API: `POST /api/osint/username`, `POST /api/osint/phone`, `POST /api/osint/email`

### Email Intel (frishtik/osint-tools-mcp-server Holehe-inspired)
- Email registration check across 12 online services (Gravatar, GitHub, Firefox, Spotify, Pinterest, Adobe, WordPress, Duolingo, Twitter, Tumblr, Last.fm, Patreon)
- Email validation: MX records, SPF/DMARC analysis, disposable email detection (30+ throwaway domains), free vs custom/corporate provider classification
- Integrated as "Email Intel" tab in existing OSINT view (7 tabs total, no new sidebar items)
- Holehe-inspired HTTP probing: checks password-reset/signup/search endpoints per service
- Batched service checks (4 at a time, 400ms delay) with stealth headers
- Neural cache: `osint:email:` key with 10min TTL
- MCP tool: `osint_email_check`
- API: `POST /api/osint/email`
- Socket.IO event: `email_check_progress`

### WebOSINT (C3n7ral051nt4g3ncy/WebOSINT-inspired)
- Domain enrichment: reverse IP lookup (HackerTarget free API), domain reputation (WhoisXML), WHOIS history (WhoisFreaks)
- IP enrichment: dual-source geolocation (ip-api.com + ipinfo.io cross-verification), reverse IP lookup
- Integrated into existing Domain Intel + IP Lookup tabs in OSINT view (no new sidebar items)
- Optional API keys stored in credential vault: `whoisxml_api_key`, `whoisfreaks_api_key`, `hackertarget_api_key`
- Neural cache: `osint:reverse-ip:`, `osint:reputation:`, `osint:whois-history:`, `osint:ip-enhanced:` (10min TTL)
- MCP tool: `osint_reverse_ip` (HackerTarget reverse IP, no key needed for free tier)
- Lib: `lib/osint-engine.js` (reverseIPLookup, domainReputation, whoisHistory, ipLookupEnhanced, fetchText)

### Server Hardening (jhd3197/ServerKit-inspired)
- 3-tab Network view: Network (existing) | Services | Hardening
- Service health: checks 27+ systemd services via `systemctl is-active/show`, status/PID/since, sorted active→failed→inactive
- Hardening audit: 16 security checks across 7 categories (SSH, firewall, IDS, updates, files, kernel, accounts), score/100 with grade A-F
- Fail2ban status: jail list with ban stats, failed login attempts via `lastb`
- AI analysis: LLM generates hardening assessment with prioritized remediation
- Neural cache: `system:services` (30s), `system:hardening` (5min), `system:fail2ban` (1min)
- MCP tool: `check_server_hardening` (7 key checks, optional service status)
- API: `GET /api/network/services`, `GET /api/network/hardening`, `GET /api/network/fail2ban`
- Requires Linux/systemd for full results; graceful degradation on Windows/Docker

## Auth
- PBKDF2 password hashing (lib/users.js)
- Session tokens in cookies (`vigil_session`) or Bearer header
- Optional TOTP 2FA (lib/totp.js)
- Default admin created on first run (users.json)
- RBAC roles: admin, analyst, viewer

## Database
- PostgreSQL 17 via `lib/db.js`
- Tables: `scans`, `vulnerabilities`, `assets`, `incidents`, `alerts`, `compliance_checks`, `policies`
- Works without DB (graceful degradation -- uses JSON file stores)

## Shared Context (ctx)
Route modules receive `ctx` with: `pool`, `dbQuery`, `io`, `execCommand`, `requireAuth`, `requireAdmin`, `requireRole`, `getSystemInfo`, plus callbacks populated by routes (`getSecurityPosture`, `getRecentScans`, `getActiveAlerts`, `getAssetInventory`, `runScanner`, `sendNotification`, `sendAlert`).

## Key Conventions
- No npm deps beyond express, socket.io, pg, node-pty, multer, uuid
- All management actions use glass modals (Modal.open/confirm)
- Toast notifications for user feedback (Toast.success/error/info/warning)
- Client-side cache with TTL (`window.Cache`, `window.cachedFetch`)
- Animated number transitions (`window.animateValue`)
- `escapeHtml()` for all user-generated content in views
- Sidebar nav groups collapsible, state persisted in localStorage
- Status bar at bottom shows connection, security posture score, last scan time
- Scanner commands are sanitized -- user input is never interpolated into shell commands directly
- All scan results stored with timestamps for trend analysis
- Severity levels follow CVSS v3.1 scoring (Critical >= 9.0, High >= 7.0, Medium >= 4.0, Low >= 0.1)

## Keyboard Shortcuts (Browser GUI)
Implemented in `app.js` via `initHotkeys()`. All shortcuts work in the web browser.

### Global (always active)
| Key | Action |
|-----|--------|
| `Ctrl+K` | Command palette — fuzzy search all 37 views |
| `Ctrl+B` | Toggle sidebar |
| `Ctrl+Shift+R` | Refresh current view (re-fetch data) |
| `Ctrl+`` ` | Toggle terminal drawer |
| `Escape` | Close modal / palette / overlay |
| `?` | Keyboard shortcut help overlay |

### Quick Navigation (when no input focused)
| Key | View |
|-----|------|
| `1` | Dashboard |
| `2` | Findings |
| `3` | Port Scanner |
| `4` | Web Scanner |
| `5` | Security Agents |
| `6` | AI Chat |
| `7` | Settings |

### Command Palette
- Opened with `Ctrl+K`, fuzzy filters `viewNames` object
- Arrow keys navigate, Enter selects, Escape closes
- Current view highlighted in cyan
- `isInputFocused()` gates number key shortcuts (inputs/textareas/selects skip)

## Testing
```bash
# Start server
npm start

# Test endpoints (requires auth cookie)
curl -b "vigil_session=TOKEN" http://localhost:4100/api/health
curl -b "vigil_session=TOKEN" http://localhost:4100/api/system
curl -b "vigil_session=TOKEN" http://localhost:4100/api/scans
curl -b "vigil_session=TOKEN" http://localhost:4100/api/vulnerabilities
curl -b "vigil_session=TOKEN" http://localhost:4100/api/assets
```
