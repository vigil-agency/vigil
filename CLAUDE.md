# Vigil v1.0 — Developer Guide

## Overview
AI-powered security operations platform. Express.js + Socket.IO on port 4100.
Vanilla JS frontend — no React, no build step, no bundler.
~33 route modules | ~19 libs | 37 views | 200+ endpoints | 6 npm deps.
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
routes/                      -> ~33 route modules
lib/                         -> ~17 shared modules
data/                        -> Runtime JSON stores (scans, reports, notifications, agents,
                                settings, audit-log)
public/                      -> Vanilla JS frontend (ViewRegistry pattern)
docs/                        -> Documentation
```

### .env Loader (built-in, no dotenv dependency)
Custom parser in server.js reads `security/.env` at startup. Sets `process.env[key]` only for keys not already set. Supports `KEY=VALUE` format, ignores comments (#) and blank lines.

### Route Modules (~33)
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
pentest.js             -> Penetration test project management, findings
credentials.js         -> AES-256-GCM credential vault
notifications.js       -> Notification system (email, webhook, Slack)
settings.js            -> Platform configuration, user preferences
mcp.js                 -> MCP server (Streamable HTTP, 25+ tools, resources, prompts)
health.js              -> Health check endpoint, service status
code-audit.js          -> LLM-driven source code vulnerability scanning (Vulnhuntr-inspired)
ephemeral-infra.js     -> Disposable proxy node management (fluffy-barnacle-inspired)
```

### Lib Modules (~17)
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
web-recon.js           -> Scrapy-inspired web crawler (surface scan, exposed files, tech fingerprint)
ghost-osint.js         -> Username enumeration (26 platforms) + phone number intelligence (70+ countries)
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

## 37 Sidebar Views

### Overview
| View | File | Description |
|------|------|-------------|
| Dashboard | `views/dashboard.js` | Security posture score, active threats, recent scans, alert summary |
| Metrics | `views/metrics.js` | System resource metrics (CPU, memory, disk, network) |
| Threat Map | `views/threat-map.js` | Live threat visualization, geographic attack origins |

### Scanning
| View | File | Description |
|------|------|-------------|
| Network Scan | `views/network-scan.js` | Nmap port scanning, host discovery, service detection |
| Vuln Scan | `views/vuln-scan.js` | Nuclei vulnerability scanning with template selection |
| Container Scan | `views/container-scan.js` | Trivy image/filesystem scanning, SBOM generation |
| Web Scanner | `views/web-scanner.js` | Web scanning + WAF Detection tab (30+ WAF signatures) |
| SSL Audit | `views/ssl-audit.js` | OpenSSL certificate chain analysis, cipher suite grading |
| DNS Recon | `views/dns-recon.js` | DNS enumeration, zone transfer, WHOIS lookup |
| DNS Security | `views/dns-security.js` | DNS security analysis, DNSSEC validation |
| Code Audit | `views/code-audit.js` | LLM-driven source code vulnerability scanning |
| Proxy Nodes | `views/proxy-nodes.js` | Disposable Codespace proxies for anonymous scanning |
| Scan History | `views/scan-history.js` | All scan results, filtering, comparison, export |
| Scheduled Scans | `views/scheduled-scans.js` | Cron-based recurring scan configuration |

### Vulnerabilities
| View | File | Description |
|------|------|-------------|
| CVE Tracker | `views/cve-tracker.js` | CVE database search, affected assets, CVSS scoring |
| Vuln Dashboard | `views/vuln-dashboard.js` | Vulnerability trends, severity breakdown, SLA tracking |
| Remediation | `views/remediation.js` | Fix recommendations, patch tracking, AI-assisted guidance |

### Compliance
| View | File | Description |
|------|------|-------------|
| Compliance | `views/compliance.js` | Framework selection (SOC2, PCI-DSS, HIPAA, ISO27001) |
| Policy Editor | `views/policy-editor.js` | Security policy CRUD, enforcement rules |
| Audit Log | `views/audit-log.js` | Immutable audit trail, filtering, export |

### Incidents
| View | File | Description |
|------|------|-------------|
| Incidents | `views/incidents.js` | Incident response workflow, severity, assignment |
| Timeline | `views/timeline.js` | Incident timeline visualization, event correlation |
| Postmortem | `views/postmortem.js` | Post-incident review, lessons learned, AI summary |

### Assets
| View | File | Description |
|------|------|-------------|
| Assets | `views/assets.js` | Asset inventory, tags, risk scoring |
| Network Map | `views/network-map.js` | Visual network topology, service dependencies |
| Docker | `views/docker.js` | Container listing, security posture, image vulnerabilities |

### Intelligence
| View | File | Description |
|------|------|-------------|
| Threat Intel | `views/threat-intel.js` | Threat feeds, IOC matching, adversary profiles |
| Pentest | `views/pentest.js` | Pentest project management, findings, evidence |
| Reports | `views/reports.js` | Report generation (PDF/JSON/CSV), templates, scheduling |

### System
| View | File | Description |
|------|------|-------------|
| Terminal | `views/terminal.js` | Embedded terminal for manual scanner commands |
| Alerts | `views/alerts.js` | Alert rule configuration, notification channels |
| MCP Server | `views/mcp.js` | MCP playground, tool testing, prompt library |
| Settings | `views/settings.js` | User management, AI provider, scanner paths, 2FA |
| Docs/FAQ | `views/docs.js` | Getting started guide, FAQ, troubleshooting |

## MCP Server (Built-In, Sandboxed)
- MCP server is **embedded inside Vigil** at `POST /mcp` (Streamable HTTP transport).
- Customers connect from Claude Desktop/Code/Cursor/VS Code on their local machine to Vigil's `/mcp` endpoint.
- Each customer's MCP server is isolated in their own container sandbox -- tenant-scoped, auth-gated.
- SDK: `@modelcontextprotocol/sdk` + Zod schemas

### Tools (22)
```
# Scanning
run_nmap_scan            -> Execute nmap scan (ports, hosts, flags)
run_nuclei_scan          -> Execute nuclei scan (templates, severity filter)
run_trivy_scan           -> Execute trivy scan (image, filesystem, repo)
run_nikto_scan           -> Execute nikto web scan (target URL)
check_ssl_certificate    -> Analyze SSL/TLS certificate chain
run_dns_recon            -> DNS enumeration + WHOIS lookup

# Vulnerabilities
search_cve               -> Search CVE database by keyword/product/vendor
get_vulnerability        -> Get CVE details + CVSS score + references
list_vulnerabilities     -> List all tracked vulnerabilities (filter by severity)

# Assets
list_assets              -> List asset inventory with risk scores
get_asset_details        -> Get asset details + associated vulnerabilities
discover_hosts           -> Network host discovery (ping sweep)

# Docker
list_containers          -> List Docker containers with security status
inspect_container        -> Deep container inspection (config, mounts, network)
scan_image               -> Trivy scan a Docker image

# Compliance
check_compliance         -> Run compliance check against framework
get_policy_status        -> Get security policy enforcement status

# Incidents
create_incident          -> Create new security incident
update_incident          -> Update incident status/severity/assignee
get_incident_timeline    -> Get incident event timeline

# Reports
generate_report          -> Generate security report (PDF/JSON/CSV)
get_scan_results         -> Get results from a specific scan

# System
get_security_posture     -> Overall security posture score + breakdown
get_system_metrics       -> CPU, memory, disk, network metrics
get_alert_summary        -> Active alerts summary by severity

# Code Audit
run_code_audit           -> Start AI-powered source code vulnerability scan
get_code_audit_results   -> Get code audit findings (by ID or latest)

# WAF Detection
detect_waf               -> Fingerprint WAF/CDN on a target URL

# Proxy Nodes
list_proxy_nodes         -> List ephemeral proxy nodes + tunnel status
create_proxy_node        -> Create disposable Codespace proxy
start_proxy_tunnel       -> Start SOCKS5 tunnel through proxy node
plan_proxy_infrastructure -> AI-plan proxy infrastructure for engagement
```

### Tool Annotations
- `readOnlyHint: true` -- safe read operations (list, get, search)
- `destructiveHint: true` -- operations that modify state (create incident, run destructive scan)

### Resources
- `vigil://posture` -- Current security posture overview
- `vigil://threats` -- Active security threats
- `vigil://findings` -- Open vulnerability findings
- `vigil://code-audit-findings` -- Code audit vulnerability findings
- `vigil://waf-signatures` -- WAF detection signature database (30+)
- `vigil://proxy-nodes` -- Ephemeral proxy node status

### Prompts
- `security_audit` -- Full security audit report generation
- `incident_response` -- Incident response playbook execution
- `threat_briefing` -- Daily threat intelligence briefing
- `compliance_report` -- Compliance gap analysis against framework
- `code_security_review` -- AI-powered source code security review
- `waf_reconnaissance` -- WAF detection and bypass analysis
- `anonymous_pentest_setup` -- Plan and provision anonymous scanning infra

### GUI Test Endpoint
- `POST /api/mcp/test` uses InMemoryTransport (bypasses HTTP handshake)
- GUI playground: `/` command bar with fuzzy search, schema-driven param forms, prompt action cards, request log

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

### Proxy Nodes (fluffy-barnacle-inspired)
- GitHub Codespaces as disposable SOCKS5 proxy nodes for anonymous scanning
- Full lifecycle: create, start, stop, delete Codespaces via `gh` CLI
- SSH dynamic port forwarding (`gh codespace ssh -D`) for SOCKS5 proxy
- Exit IP detection via ifconfig.me through the proxy
- AI infrastructure planner for engagement-based proxy recommendations
- Requires `gh` CLI installed and authenticated; graceful degradation when absent
- API: `GET /api/proxy-nodes`, `POST /api/proxy-nodes`, `POST /api/proxy-nodes/ai-plan`

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
- API: `POST /api/osint/username`, `POST /api/osint/phone`

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
