/* Vigil v1.0 — MCP Playground (Model Context Protocol)
 * Interactive playground for 36 tools, 7 resources, 8 prompt workflows.
 * All calls go through POST /api/mcp/test with {method, params}.
 */
Views['mcp-playground'] = {
  _tools: [],
  _resources: [],
  _prompts: [],
  _selectedTool: null,
  _log: [],
  _activeCategory: 'all',
  _connInfo: null,

  // Tool category mapping (36 tools)
  _categories: {
    check_posture: 'system', scan_ports: 'scanning', scan_vulnerabilities: 'scanning',
    check_ssl: 'scanning', query_logs: 'scanning', osint_domain: 'intelligence',
    osint_ip: 'intelligence', osint_reverse_ip: 'intelligence', osint_email_check: 'intelligence',
    triage_alert: 'intelligence', hunt_threat: 'intelligence',
    run_agent: 'system', launch_campaign: 'system', generate_report: 'compliance',
    compliance_check: 'compliance', list_findings: 'compliance', incident_create: 'incident',
    run_code_audit: 'code-audit', get_code_audit_results: 'code-audit', detect_waf: 'scanning',
    list_proxy_nodes: 'proxy', create_proxy_node: 'proxy', start_proxy_tunnel: 'proxy',
    plan_proxy_infrastructure: 'proxy',
    validate_exploitability: 'adversarial', adversarial_analysis: 'adversarial',
    run_pentest_command: 'pentest', get_pentest_results: 'pentest',
    run_purple_team_sim: 'purple-team', get_purple_team_results: 'purple-team',
    analyze_binary: 'code-audit',
    create_tunnel: 'proxy', manage_callback_listener: 'proxy',
    check_ai_security: 'ai-security',
    autonomous_pentest: 'pentest',
    check_server_hardening: 'system',
  },
  _catLabels: { all: 'All', scanning: 'Scanning', intelligence: 'Intelligence', compliance: 'Compliance', incident: 'Incident', system: 'System', 'code-audit': 'Code Audit', proxy: 'Proxy', adversarial: 'Adversarial', pentest: 'Pentest', 'purple-team': 'Purple Team', 'ai-security': 'AI Security' },
  _catIcons: { scanning: '&#128269;', intelligence: '&#128373;', compliance: '&#9989;', incident: '&#128680;', system: '&#9881;', 'code-audit': '&#128187;', proxy: '&#128279;', adversarial: '&#9876;', pentest: '&#128296;', 'purple-team': '&#9760;', 'ai-security': '&#129302;' },

  // ── Helper: MCP API call ───────────────────────────────────────────────
  _mcpCall: function(method, params) {
    var start = Date.now();
    var self = this;
    return fetch('/api/mcp/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ method: method, params: params || {} })
    })
    .then(function(r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    })
    .then(function(data) {
      var entry = { time: new Date().toLocaleTimeString(), method: method, params: params, duration: Date.now() - start, status: 'success' };
      self._log.unshift(entry);
      if (self._log.length > 50) self._log.length = 50;
      return data;
    })
    .catch(function(err) {
      var entry = { time: new Date().toLocaleTimeString(), method: method, params: params, duration: Date.now() - start, status: 'error', error: err.message };
      self._log.unshift(entry);
      throw err;
    });
  },

  // ── Init ───────────────────────────────────────────────────────────────
  init: function() {
    var el = document.getElementById('view-mcp-playground');
    el.innerHTML =
      // ── Zone 1: Header + Stats ──────────────────────────────────────
      '<div class="section-header">' +
        '<div class="section-title">MCP Playground</div>' +
        '<div style="display:flex;gap:8px;">' +
          '<button class="btn btn-ghost btn-sm" id="mcp-connect-btn">&#128279; Connect to Claude</button>' +
          '<button class="btn btn-ghost btn-sm" id="mcp-refresh-btn">Refresh</button>' +
        '</div>' +
      '</div>' +

      '<div class="stat-grid" style="margin-bottom:16px;">' +
        '<div class="stat-card"><div class="stat-card-label">Tools</div><div class="stat-card-value" id="mcp-stat-tools" style="color:var(--cyan);">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Resources</div><div class="stat-card-value" id="mcp-stat-resources">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Prompts</div><div class="stat-card-value" id="mcp-stat-prompts">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">MCP Calls</div><div class="stat-card-value" id="mcp-stat-calls">0</div></div>' +
      '</div>' +

      // ── Zone 2: Quick Workflows (Prompt Cards) ─────────────────────
      '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">AI Security Workflows</div>' +
        '<div class="grid-2" id="mcp-workflows">' +

          '<div class="glass-card mcp-workflow-card" data-prompt="security_audit" style="cursor:pointer;border:1px solid rgba(34,211,238,0.15);">' +
            '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">' +
              '<span style="font-size:20px;">&#128737;</span>' +
              '<span style="color:var(--text-primary);font-weight:600;">Security Audit</span>' +
              '<span class="tag tag-cyan" style="margin-left:auto;font-size:10px;">Multi-Tool</span>' +
            '</div>' +
            '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);line-height:1.5;">Full security assessment — checks posture, scans ports, lists findings, generates report.</div>' +
          '</div>' +

          '<div class="glass-card mcp-workflow-card" data-prompt="threat_briefing" style="cursor:pointer;border:1px solid rgba(34,211,238,0.15);">' +
            '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">' +
              '<span style="font-size:20px;">&#128225;</span>' +
              '<span style="color:var(--text-primary);font-weight:600;">Threat Briefing</span>' +
              '<span class="tag tag-cyan" style="margin-left:auto;font-size:10px;">Daily</span>' +
            '</div>' +
            '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);line-height:1.5;">Daily threat summary — posture score, active threats, open vulnerabilities, recommended actions.</div>' +
          '</div>' +

          '<div class="glass-card mcp-workflow-card" data-prompt="incident_response" style="cursor:pointer;border:1px solid rgba(34,211,238,0.15);">' +
            '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">' +
              '<span style="font-size:20px;">&#128680;</span>' +
              '<span style="color:var(--text-primary);font-weight:600;">Incident Response</span>' +
              '<span class="tag" style="margin-left:auto;font-size:10px;color:var(--orange);">Interactive</span>' +
            '</div>' +
            '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);line-height:1.5;">Guided investigation — hunts threats, queries logs, checks posture, creates incidents.</div>' +
          '</div>' +

          '<div class="glass-card mcp-workflow-card" data-prompt="compliance_report" style="cursor:pointer;border:1px solid rgba(34,211,238,0.15);">' +
            '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">' +
              '<span style="font-size:20px;">&#128203;</span>' +
              '<span style="color:var(--text-primary);font-weight:600;">Compliance Report</span>' +
              '<span class="tag" style="margin-left:auto;font-size:10px;">SOC2 / ISO / NIST</span>' +
            '</div>' +
            '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);line-height:1.5;">Framework compliance gap analysis with findings, risks, and remediation roadmap.</div>' +
          '</div>' +

        '</div>' +
      '</div>' +

      // ── Zone 3: Live Security Resources ─────────────────────────────
      '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Live Security Data (MCP Resources)</div>' +
        '<div class="grid-3" id="mcp-resources">' +
          '<div class="glass-card" id="mcp-res-posture"><div class="loading-state"><div class="spinner spinner-sm"></div></div></div>' +
          '<div class="glass-card" id="mcp-res-threats"><div class="loading-state"><div class="spinner spinner-sm"></div></div></div>' +
          '<div class="glass-card" id="mcp-res-findings"><div class="loading-state"><div class="spinner spinner-sm"></div></div></div>' +
        '</div>' +
      '</div>' +

      // ── Zone 4: Tool Explorer (two-panel) ───────────────────────────
      '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Tool Explorer</div>' +
        '<div class="two-panel" style="min-height:400px;">' +
          '<div class="two-panel-left" style="overflow-y:auto;">' +
            '<input type="text" class="form-input" id="mcp-tool-search" placeholder="Search 36 tools..." style="margin-bottom:8px;">' +
            '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px;" id="mcp-cat-tabs"></div>' +
            '<div id="mcp-tool-list"><div class="loading-state"><div class="spinner spinner-sm"></div></div></div>' +
          '</div>' +
          '<div class="two-panel-right" style="display:flex;flex-direction:column;gap:12px;">' +
            '<div class="glass-card" style="flex:0 0 auto;" id="mcp-tool-form">' +
              '<div class="empty-state"><div class="empty-state-icon">&#128268;</div><div class="empty-state-title">Select a Tool</div><div class="empty-state-desc">Choose from the list to configure and execute</div></div>' +
            '</div>' +
            '<div class="glass-card" style="flex:1;overflow-y:auto;" id="mcp-tool-result">' +
              '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">Execute a tool to see results here</div>' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      // ── Zone 5: Request Log ─────────────────────────────────────────
      '<div class="glass-card">' +
        '<div class="glass-card-header">' +
          '<div class="glass-card-title">Request Log</div>' +
          '<button class="btn btn-ghost btn-sm" id="mcp-clear-log">Clear</button>' +
        '</div>' +
        '<div id="mcp-request-log" style="max-height:200px;overflow-y:auto;">' +
          '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">No MCP calls yet</div>' +
        '</div>' +
      '</div>';

    var self = this;

    // Wire events
    document.getElementById('mcp-connect-btn').addEventListener('click', function() { self.showConnectModal(); });
    document.getElementById('mcp-refresh-btn').addEventListener('click', function() { self.loadAll(); });
    document.getElementById('mcp-tool-search').addEventListener('input', function() { self.renderToolList(); });
    document.getElementById('mcp-clear-log').addEventListener('click', function() {
      self._log = [];
      document.getElementById('mcp-request-log').innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">Log cleared</div>';
    });

    // Workflow cards
    document.querySelectorAll('.mcp-workflow-card').forEach(function(card) {
      card.addEventListener('click', function() { self.executeWorkflow(card.getAttribute('data-prompt')); });
    });

    // Category tabs
    this.renderCatTabs();
  },

  show: function() { this.loadAll(); },
  hide: function() {},

  // ── Load everything ────────────────────────────────────────────────
  loadAll: function() {
    var self = this;
    // Parallel: tools, resources, connection info
    self._mcpCall('tools/list').then(function(data) {
      self._tools = data.tools || [];
      self.renderToolList();
      var el = document.getElementById('mcp-stat-tools');
      if (typeof animateValue === 'function') animateValue(el, 0, self._tools.length, 400);
      else el.textContent = self._tools.length;
    }).catch(function() {
      document.getElementById('mcp-tool-list').innerHTML = '<div style="color:var(--orange);font-size:var(--font-size-sm);">Failed to load tools</div>';
    });

    self._mcpCall('prompts/list').then(function(data) {
      self._prompts = data.prompts || [];
      var el = document.getElementById('mcp-stat-prompts');
      if (typeof animateValue === 'function') animateValue(el, 0, self._prompts.length, 400);
      else el.textContent = self._prompts.length;
    }).catch(function() {});

    self._mcpCall('resources/list').then(function(data) {
      self._resources = data.resources || [];
      var el = document.getElementById('mcp-stat-resources');
      if (typeof animateValue === 'function') animateValue(el, 0, self._resources.length, 400);
      else el.textContent = self._resources.length;
    }).catch(function() {});

    // Load live resource data
    self.loadResource('vigil://posture', 'mcp-res-posture', self.renderPosture);
    self.loadResource('vigil://threats', 'mcp-res-threats', self.renderThreats);
    self.loadResource('vigil://findings', 'mcp-res-findings', self.renderFindings);

    // Connection info
    fetch('/api/mcp/info', { credentials: 'same-origin' }).then(function(r) { return r.json(); }).then(function(d) { self._connInfo = d; }).catch(function() {});
  },

  // ── Load a resource into a card ────────────────────────────────────
  loadResource: function(uri, elementId, renderer) {
    var self = this;
    self._mcpCall('resources/read', { uri: uri }).then(function(data) {
      var el = document.getElementById(elementId);
      var contents = data.contents || [];
      var text = contents.length > 0 ? contents[0].text : '{}';
      try { var parsed = JSON.parse(text); renderer.call(self, el, parsed); }
      catch { el.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">Could not parse resource data</div>'; }
    }).catch(function() {
      var el = document.getElementById(elementId);
      el.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">Resource unavailable</div>';
    });
  },

  // ── Resource renderers ─────────────────────────────────────────────
  renderPosture: function(el, data) {
    var score = data.score || 0;
    var grade = data.grade || 'N/A';
    var color = score >= 80 ? 'var(--cyan)' : score >= 50 ? 'var(--text-secondary)' : 'var(--orange)';
    el.innerHTML =
      '<div style="text-align:center;padding:8px 0;">' +
        '<div style="font-size:10px;text-transform:uppercase;color:var(--text-tertiary);margin-bottom:4px;">Security Posture</div>' +
        '<div style="font-size:36px;font-weight:700;color:' + color + ';">' + score + '</div>' +
        '<div style="font-size:14px;color:' + color + ';font-weight:600;">Grade ' + escapeHtml(grade) + '</div>' +
        '<div style="font-size:var(--font-size-xs);color:var(--text-tertiary);margin-top:4px;">vigil://posture</div>' +
      '</div>';
  },

  renderThreats: function(el, data) {
    var threats = Array.isArray(data) ? data : [];
    var critical = threats.filter(function(t) { return t.severity === 'critical'; }).length;
    var color = critical > 0 ? 'var(--orange)' : threats.length > 0 ? 'var(--text-secondary)' : 'var(--cyan)';
    var html = '<div style="text-align:center;padding:8px 0;">' +
      '<div style="font-size:10px;text-transform:uppercase;color:var(--text-tertiary);margin-bottom:4px;">Active Threats</div>' +
      '<div style="font-size:36px;font-weight:700;color:' + color + ';">' + threats.length + '</div>';
    if (critical > 0) html += '<div style="font-size:var(--font-size-xs);color:var(--orange);font-weight:600;">' + critical + ' critical</div>';
    else if (threats.length === 0) html += '<div style="font-size:var(--font-size-xs);color:var(--cyan);">All clear</div>';
    html += '<div style="font-size:var(--font-size-xs);color:var(--text-tertiary);margin-top:4px;">vigil://threats</div></div>';
    if (threats.length > 0) {
      html += '<div style="margin-top:8px;border-top:1px solid var(--border);padding-top:8px;">';
      threats.slice(0, 3).forEach(function(t) {
        html += '<div style="font-size:var(--font-size-xs);color:var(--text-secondary);padding:2px 0;">' +
          '<span style="color:var(--orange);font-weight:600;">' + escapeHtml(t.severity || 'unknown') + '</span> ' +
          escapeHtml((t.title || t.type || '--').substring(0, 40)) + '</div>';
      });
      html += '</div>';
    }
    el.innerHTML = html;
  },

  renderFindings: function(el, data) {
    var findings = Array.isArray(data) ? data : [];
    var counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach(function(f) { if (counts[f.severity] !== undefined) counts[f.severity]++; });
    var color = counts.critical > 0 ? 'var(--orange)' : findings.length > 0 ? 'var(--text-secondary)' : 'var(--cyan)';
    el.innerHTML =
      '<div style="text-align:center;padding:8px 0;">' +
        '<div style="font-size:10px;text-transform:uppercase;color:var(--text-tertiary);margin-bottom:4px;">Open Findings</div>' +
        '<div style="font-size:36px;font-weight:700;color:' + color + ';">' + findings.length + '</div>' +
        '<div style="display:flex;gap:8px;justify-content:center;margin-top:4px;">' +
          (counts.critical > 0 ? '<span style="font-size:10px;color:var(--orange);font-weight:700;">' + counts.critical + ' crit</span>' : '') +
          (counts.high > 0 ? '<span style="font-size:10px;color:var(--orange);">' + counts.high + ' high</span>' : '') +
          (counts.medium > 0 ? '<span style="font-size:10px;color:var(--text-secondary);">' + counts.medium + ' med</span>' : '') +
          (counts.low > 0 ? '<span style="font-size:10px;color:var(--text-tertiary);">' + counts.low + ' low</span>' : '') +
        '</div>' +
        '<div style="font-size:var(--font-size-xs);color:var(--text-tertiary);margin-top:4px;">vigil://findings</div>' +
      '</div>';
  },

  // ── Category tabs ──────────────────────────────────────────────────
  renderCatTabs: function() {
    var self = this;
    var container = document.getElementById('mcp-cat-tabs');
    var html = '';
    Object.keys(self._catLabels).forEach(function(cat) {
      var isActive = self._activeCategory === cat;
      html += '<button class="btn btn-ghost btn-sm mcp-cat-btn' + (isActive ? ' active' : '') + '" data-cat="' + cat + '" style="font-size:11px;padding:3px 8px;">' + self._catLabels[cat] + '</button>';
    });
    container.innerHTML = html;
    container.querySelectorAll('.mcp-cat-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        self._activeCategory = btn.getAttribute('data-cat');
        container.querySelectorAll('.mcp-cat-btn').forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
        self.renderToolList();
      });
    });
  },

  // ── Tool list ──────────────────────────────────────────────────────
  renderToolList: function() {
    var container = document.getElementById('mcp-tool-list');
    var search = (document.getElementById('mcp-tool-search').value || '').toLowerCase();
    var cat = this._activeCategory;
    var self = this;

    var filtered = this._tools.filter(function(t) {
      var matchSearch = !search || (t.name || '').toLowerCase().indexOf(search) >= 0 || (t.description || '').toLowerCase().indexOf(search) >= 0;
      var matchCat = cat === 'all' || (self._categories[t.name] || 'system') === cat;
      return matchSearch && matchCat;
    });

    if (filtered.length === 0) {
      container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);padding:12px 0;">No tools match</div>';
      return;
    }

    var html = '';
    filtered.forEach(function(t) {
      var isSelected = self._selectedTool && self._selectedTool.name === t.name;
      var toolCat = self._categories[t.name] || 'system';
      var catIcon = self._catIcons[toolCat] || '&#9881;';
      html += '<div class="nav-item' + (isSelected ? ' active' : '') + ' mcp-tool-item" data-tool="' + escapeHtml(t.name) + '" style="margin-bottom:2px;cursor:pointer;">' +
        '<span class="nav-item-icon" style="font-size:14px;">' + catIcon + '</span>' +
        '<div style="flex:1;overflow:hidden;">' +
          '<div style="color:var(--text-primary);font-size:var(--font-size-xs);font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + escapeHtml(t.name) + '</div>' +
          '<div style="color:var(--text-tertiary);font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + escapeHtml((t.description || '').substring(0, 45)) + '</div>' +
        '</div>' +
      '</div>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.mcp-tool-item').forEach(function(item) {
      item.addEventListener('click', function() {
        var name = item.getAttribute('data-tool');
        var tool = self._tools.find(function(t) { return t.name === name; });
        if (tool) self.selectTool(tool);
      });
    });
  },

  // ── Select a tool → render params form ─────────────────────────────
  selectTool: function(tool) {
    this._selectedTool = tool;
    this.renderToolList(); // update active highlight

    var form = document.getElementById('mcp-tool-form');
    var schema = tool.inputSchema || {};
    var properties = schema.properties || {};
    var required = schema.required || [];
    var toolCat = this._categories[tool.name] || 'system';

    var html = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">' +
      '<span style="font-size:18px;">' + (this._catIcons[toolCat] || '&#9881;') + '</span>' +
      '<span style="color:var(--text-primary);font-weight:600;font-size:var(--font-size-sm);">' + escapeHtml(tool.name) + '</span>' +
      '<span class="tag" style="font-size:10px;margin-left:auto;">' + escapeHtml(toolCat) + '</span>' +
    '</div>';
    html += '<div style="color:var(--text-secondary);font-size:var(--font-size-xs);margin-bottom:12px;line-height:1.5;">' + escapeHtml(tool.description || '') + '</div>';

    var propKeys = Object.keys(properties);
    if (propKeys.length === 0) {
      html += '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-bottom:12px;">No parameters — click Execute to run</div>';
    } else {
      propKeys.forEach(function(key) {
        var prop = properties[key];
        var isReq = required.indexOf(key) >= 0;
        html += '<div class="form-group" style="margin-bottom:8px;">' +
          '<label class="form-label" style="font-size:var(--font-size-xs);">' + escapeHtml(key) + (isReq ? ' <span style="color:var(--orange);">*</span>' : '') + '</label>';

        if (prop.enum) {
          html += '<select class="form-select mcp-param" data-key="' + escapeHtml(key) + '" style="font-size:var(--font-size-xs);">';
          if (prop.default) {
            prop.enum.forEach(function(v) { html += '<option value="' + escapeHtml(v) + '"' + (v === prop.default ? ' selected' : '') + '>' + escapeHtml(v) + '</option>'; });
          } else {
            prop.enum.forEach(function(v) { html += '<option value="' + escapeHtml(v) + '">' + escapeHtml(v) + '</option>'; });
          }
          html += '</select>';
        } else if (prop.type === 'boolean') {
          html += '<select class="form-select mcp-param" data-key="' + escapeHtml(key) + '" style="font-size:var(--font-size-xs);"><option value="true">true</option><option value="false">false</option></select>';
        } else if (prop.type === 'number' || prop.type === 'integer') {
          html += '<input type="number" class="form-input mcp-param" data-key="' + escapeHtml(key) + '" value="' + (prop.default || '') + '" placeholder="' + escapeHtml(prop.description || key) + '" style="font-size:var(--font-size-xs);">';
        } else {
          html += '<input type="text" class="form-input mcp-param" data-key="' + escapeHtml(key) + '" value="' + escapeHtml(prop.default || '') + '" placeholder="' + escapeHtml(prop.description || key) + '" style="font-size:var(--font-size-xs);">';
        }
        html += '</div>';
      });
    }

    html += '<div style="display:flex;gap:8px;margin-top:12px;">' +
      '<button class="btn btn-primary btn-sm" id="mcp-exec-btn">Execute</button>' +
      '<button class="btn btn-ghost btn-sm" id="mcp-copy-json-btn">Copy JSON-RPC</button>' +
    '</div>';

    form.innerHTML = html;

    var self = this;
    document.getElementById('mcp-exec-btn').addEventListener('click', function() { self.executeTool(); });
    document.getElementById('mcp-copy-json-btn').addEventListener('click', function() { self.copyJsonRpc(); });
  },

  // ── Execute selected tool ──────────────────────────────────────────
  executeTool: function() {
    if (!this._selectedTool) return;
    var self = this;
    var toolName = this._selectedTool.name;

    // Gather params
    var args = {};
    document.querySelectorAll('.mcp-param').forEach(function(input) {
      var key = input.getAttribute('data-key');
      var val = input.value;
      if (val !== '' && val !== undefined) {
        if (input.type === 'number') val = Number(val);
        else if (val === 'true') val = true;
        else if (val === 'false') val = false;
        args[key] = val;
      }
    });

    var resultEl = document.getElementById('mcp-tool-result');
    var btn = document.getElementById('mcp-exec-btn');
    btn.disabled = true;
    btn.textContent = 'Executing...';
    resultEl.innerHTML = '<div class="loading-state"><div class="spinner spinner-sm"></div><div style="font-size:var(--font-size-xs);">Running ' + escapeHtml(toolName) + '...</div></div>';

    self._mcpCall('tools/call', { name: toolName, arguments: args })
      .then(function(data) {
        btn.disabled = false;
        btn.textContent = 'Execute';
        self.renderResult(resultEl, toolName, data);
        self.updateLog();
        self.updateCallCount();
        Toast.success(toolName + ' executed');
      })
      .catch(function(err) {
        btn.disabled = false;
        btn.textContent = 'Execute';
        resultEl.innerHTML = '<div style="color:var(--orange);font-size:var(--font-size-sm);padding:8px;border-left:3px solid var(--orange);">Execution failed: ' + escapeHtml(err.message) + '</div>';
        self.updateLog();
        Toast.error('Tool execution failed');
      });
  },

  // ── Smart result rendering ─────────────────────────────────────────
  renderResult: function(el, toolName, data) {
    var content = data.content || [];
    var isError = data.isError;
    var text = content.length > 0 && content[0].text ? content[0].text : JSON.stringify(data, null, 2);

    if (isError) {
      el.innerHTML = '<div style="padding:8px;border-left:3px solid var(--orange);color:var(--orange);font-size:var(--font-size-sm);">' +
        '<div style="font-weight:600;margin-bottom:4px;">Error</div>' + escapeHtml(text) + '</div>';
      return;
    }

    // Try parsing as JSON for structured rendering
    var parsed = null;
    try { parsed = JSON.parse(text); } catch {}

    var html = '';

    if (parsed) {
      // Structured JSON result
      if (parsed.score !== undefined && parsed.grade !== undefined) {
        // Posture data
        var color = parsed.score >= 80 ? 'var(--cyan)' : parsed.score >= 50 ? 'var(--text-secondary)' : 'var(--orange)';
        html += '<div style="text-align:center;margin-bottom:12px;"><span style="font-size:28px;font-weight:700;color:' + color + ';">' + parsed.score + '/100</span> <span style="color:' + color + ';font-weight:600;">Grade ' + escapeHtml(parsed.grade) + '</span></div>';
        if (parsed.categories) {
          html += '<table class="data-table" style="font-size:var(--font-size-xs);"><thead><tr><th>Category</th><th>Score</th><th>Max</th></tr></thead><tbody>';
          Object.entries(parsed.categories).forEach(function(pair) {
            var c = pair[1];
            html += '<tr><td>' + escapeHtml(pair[0]) + '</td><td style="color:var(--cyan);font-weight:600;">' + (c.score || 0) + '</td><td>' + (c.maxScore || 0) + '</td></tr>';
          });
          html += '</tbody></table>';
        }
      } else if (parsed.findings && Array.isArray(parsed.findings)) {
        // Findings list
        html += '<div style="margin-bottom:8px;color:var(--text-secondary);font-size:var(--font-size-xs);">Total: ' + parsed.total + ' findings</div>';
        html += '<table class="data-table" style="font-size:var(--font-size-xs);"><thead><tr><th>Title</th><th>Severity</th><th>Type</th></tr></thead><tbody>';
        parsed.findings.forEach(function(f) {
          var sc = f.severity === 'critical' || f.severity === 'high' ? 'var(--orange)' : 'var(--text-secondary)';
          html += '<tr><td>' + escapeHtml(f.title || '--') + '</td><td style="color:' + sc + ';font-weight:600;">' + escapeHtml(f.severity || '') + '</td><td>' + escapeHtml(f.type || '') + '</td></tr>';
        });
        html += '</tbody></table>';
      } else if (parsed.dns) {
        // DNS/OSINT result
        html += '<div style="font-weight:600;color:var(--text-primary);margin-bottom:8px;">' + escapeHtml(parsed.domain || '') + '</div>';
        Object.entries(parsed.dns).forEach(function(pair) {
          html += '<div style="margin-bottom:6px;"><span class="tag tag-cyan" style="font-size:10px;">' + escapeHtml(pair[0]) + '</span>';
          if (Array.isArray(pair[1])) {
            pair[1].forEach(function(v) { html += '<div style="font-size:var(--font-size-xs);color:var(--text-secondary);margin-left:8px;">' + escapeHtml(v) + '</div>'; });
          }
          html += '</div>';
        });
      } else if (Array.isArray(parsed)) {
        // Array of items
        html += '<div style="font-size:var(--font-size-xs);color:var(--text-secondary);margin-bottom:4px;">' + parsed.length + ' items</div>';
        html += '<div class="code-block" style="font-size:var(--font-size-xs);max-height:200px;overflow-y:auto;">' + escapeHtml(JSON.stringify(parsed, null, 2)) + '</div>';
      } else {
        // Generic object
        html += '<table class="data-table" style="font-size:var(--font-size-xs);"><tbody>';
        Object.entries(parsed).forEach(function(pair) {
          var val = typeof pair[1] === 'object' ? JSON.stringify(pair[1]) : String(pair[1]);
          html += '<tr><td style="color:var(--text-tertiary);font-weight:500;width:120px;">' + escapeHtml(pair[0]) + '</td><td>' + escapeHtml(val.substring(0, 200)) + '</td></tr>';
        });
        html += '</tbody></table>';
      }
    } else {
      // Plain text result (AI responses, CLI output)
      if (text.indexOf('PORT') >= 0 && text.indexOf('STATE') >= 0) {
        // nmap output
        html += '<div class="code-block" style="font-size:var(--font-size-xs);max-height:250px;overflow-y:auto;font-family:var(--font-mono);white-space:pre;">' + escapeHtml(text) + '</div>';
      } else {
        // AI prose (triage, hunt, report, compliance)
        html += '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;border-left:3px solid var(--cyan);padding-left:12px;">' +
          escapeHtml(text).replace(/\n/g, '<br>') + '</div>';
      }
    }

    // Copy raw button
    html += '<div style="margin-top:8px;text-align:right;"><button class="btn btn-ghost btn-sm mcp-copy-raw" style="font-size:10px;">Copy Raw</button></div>';
    el.innerHTML = html;
    el.querySelector('.mcp-copy-raw').addEventListener('click', function() {
      navigator.clipboard.writeText(text).then(function() { Toast.success('Copied to clipboard'); });
    });
  },

  // ── Execute prompt workflow ────────────────────────────────────────
  executeWorkflow: function(promptName) {
    var self = this;

    // For prompts with required args, show modal
    if (promptName === 'incident_response') {
      Modal.open({
        title: 'Incident Response Workflow',
        body: '<div class="form-group"><label class="form-label">Describe the incident</label>' +
          '<textarea class="form-textarea" id="mcp-incident-input" rows="3" placeholder="e.g., Suspicious outbound connections detected from web server at 2am"></textarea></div>',
        footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="mcp-incident-go">Run Investigation</button>'
      });
      document.getElementById('mcp-incident-go').addEventListener('click', function() {
        var input = document.getElementById('mcp-incident-input').value.trim();
        if (!input) { Toast.warning('Describe the incident'); return; }
        Modal.close();
        self._runPrompt(promptName, { incident: input });
      });
      return;
    }

    if (promptName === 'compliance_report') {
      Modal.open({
        title: 'Compliance Report',
        body: '<div class="form-group"><label class="form-label">Framework</label>' +
          '<select class="form-select" id="mcp-compliance-fw">' +
            '<option value="soc2">SOC 2 Type II</option>' +
            '<option value="iso27001">ISO 27001:2022</option>' +
            '<option value="nist800-53">NIST 800-53</option>' +
          '</select></div>',
        footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="mcp-compliance-go">Generate Report</button>'
      });
      document.getElementById('mcp-compliance-go').addEventListener('click', function() {
        var fw = document.getElementById('mcp-compliance-fw').value;
        Modal.close();
        self._runPrompt(promptName, { framework: fw });
      });
      return;
    }

    // No-arg prompts: security_audit, threat_briefing
    self._runPrompt(promptName, {});
  },

  _runPrompt: function(promptName, args) {
    var self = this;
    Modal.loading('Running ' + promptName.replace(/_/g, ' ') + ' workflow...');

    self._mcpCall('prompts/get', { name: promptName, arguments: args })
      .then(function(data) {
        Modal.close();
        var messages = data.messages || [];
        if (messages.length === 0) {
          Toast.warning('No prompt messages returned');
          return;
        }

        var promptText = '';
        messages.forEach(function(m) {
          if (m.content && m.content.text) promptText += m.content.text;
          else if (typeof m.content === 'string') promptText += m.content;
        });

        Modal.open({
          title: promptName.replace(/_/g, ' ').replace(/\b\w/g, function(l) { return l.toUpperCase(); }) + ' Workflow',
          body:
            '<div style="margin-bottom:12px;color:var(--text-tertiary);font-size:var(--font-size-xs);">This prompt chains multiple MCP tools. Copy it and use it with Claude Desktop/Code connected to Vigil\'s MCP server.</div>' +
            '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;border-left:3px solid var(--cyan);padding:12px;background:rgba(34,211,238,0.03);border-radius:4px;white-space:pre-wrap;">' +
              escapeHtml(promptText) +
            '</div>' +
            '<div style="margin-top:12px;display:flex;gap:8px;">' +
              '<button class="btn btn-primary btn-sm" id="mcp-copy-prompt">Copy Prompt</button>' +
              '<button class="btn btn-ghost btn-sm" id="mcp-run-first-tool">Run First Tool</button>' +
            '</div>',
          size: 'lg'
        });

        document.getElementById('mcp-copy-prompt').addEventListener('click', function() {
          navigator.clipboard.writeText(promptText).then(function() { Toast.success('Prompt copied'); });
        });

        // Run the first tool in the chain
        document.getElementById('mcp-run-first-tool').addEventListener('click', function() {
          Modal.close();
          // Auto-select and run the first tool mentioned
          var firstTool = null;
          var toolNames = self._tools.map(function(t) { return t.name; });
          for (var i = 0; i < toolNames.length; i++) {
            if (promptText.toLowerCase().indexOf(toolNames[i]) >= 0) {
              firstTool = self._tools.find(function(t) { return t.name === toolNames[i]; });
              break;
            }
          }
          if (firstTool) {
            self.selectTool(firstTool);
            Toast.info('Selected ' + firstTool.name + ' — configure params and execute');
            // Scroll to tool explorer
            document.getElementById('mcp-tool-form').scrollIntoView({ behavior: 'smooth' });
          } else {
            Toast.info('No matching tool found in prompt');
          }
        });

        self.updateLog();
        self.updateCallCount();
      })
      .catch(function(err) {
        Modal.close();
        Toast.error('Workflow failed: ' + err.message);
        self.updateLog();
      });
  },

  // ── Copy JSON-RPC for current tool ─────────────────────────────────
  copyJsonRpc: function() {
    if (!this._selectedTool) return;
    var args = {};
    document.querySelectorAll('.mcp-param').forEach(function(input) {
      var key = input.getAttribute('data-key');
      var val = input.value;
      if (val !== '') args[key] = val;
    });
    var rpc = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: this._selectedTool.name, arguments: args }
    };
    navigator.clipboard.writeText(JSON.stringify(rpc, null, 2)).then(function() { Toast.success('JSON-RPC copied'); });
  },

  // ── Connection instructions modal ──────────────────────────────────
  showConnectModal: function() {
    var info = this._connInfo || {};
    var inst = info.instructions || {};
    var url = info.url || 'http://localhost:4100/mcp';

    var desktopJson = inst.claudeDesktop ? JSON.stringify(inst.claudeDesktop.config, null, 2) : '{"mcpServers":{"vigil":{"type":"streamable-http","url":"' + url + '"}}}';
    var cliCmd = inst.claudeCode || 'claude mcp add --transport http vigil ' + url;
    var curlCmd = inst.curl || 'curl -X POST ' + url + ' -H "Content-Type: application/json" -d \'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\'';

    Modal.open({
      title: 'Connect to Vigil MCP Server',
      body:
        '<div style="margin-bottom:16px;color:var(--text-secondary);font-size:var(--font-size-sm);">' +
          'Connect Claude Desktop, Claude Code, or any MCP client to Vigil\'s built-in MCP server. ' +
          '<span style="color:var(--cyan);font-weight:600;">' + (info.tools || 35) + ' tools</span>, ' +
          '<span style="color:var(--cyan);">' + (info.resources || 3) + ' resources</span>, ' +
          '<span style="color:var(--cyan);">' + (info.prompts || 4) + ' prompts</span> available.' +
        '</div>' +

        '<div style="margin-bottom:16px;">' +
          '<div class="form-label" style="color:var(--cyan);">Claude Desktop</div>' +
          '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-bottom:4px;">Add to claude_desktop_config.json:</div>' +
          '<div class="code-block" style="font-size:var(--font-size-xs);max-height:120px;overflow-y:auto;">' + escapeHtml(desktopJson) + '</div>' +
          '<button class="btn btn-ghost btn-sm mcp-copy-config" data-text="desktop" style="margin-top:4px;font-size:10px;">Copy Config</button>' +
        '</div>' +

        '<div style="margin-bottom:16px;">' +
          '<div class="form-label" style="color:var(--cyan);">Claude Code (CLI)</div>' +
          '<div class="code-block" style="font-size:var(--font-size-xs);">' + escapeHtml(cliCmd) + '</div>' +
          '<button class="btn btn-ghost btn-sm mcp-copy-config" data-text="cli" style="margin-top:4px;font-size:10px;">Copy Command</button>' +
        '</div>' +

        '<div>' +
          '<div class="form-label" style="color:var(--cyan);">cURL (Test)</div>' +
          '<div class="code-block" style="font-size:var(--font-size-xs);word-break:break-all;">' + escapeHtml(curlCmd) + '</div>' +
          '<button class="btn btn-ghost btn-sm mcp-copy-config" data-text="curl" style="margin-top:4px;font-size:10px;">Copy cURL</button>' +
        '</div>',
      size: 'lg'
    });

    var texts = { desktop: desktopJson, cli: cliCmd, curl: curlCmd };
    document.querySelectorAll('.mcp-copy-config').forEach(function(btn) {
      btn.addEventListener('click', function() {
        navigator.clipboard.writeText(texts[btn.getAttribute('data-text')]).then(function() { Toast.success('Copied!'); });
      });
    });
  },

  // ── Request log ────────────────────────────────────────────────────
  updateLog: function() {
    var container = document.getElementById('mcp-request-log');
    if (this._log.length === 0) {
      container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">No MCP calls yet</div>';
      return;
    }
    var html = '';
    this._log.slice(0, 20).forEach(function(e) {
      var sc = e.status === 'success' ? 'var(--cyan)' : 'var(--orange)';
      html += '<div style="padding:4px 0;border-bottom:1px solid var(--border);font-size:var(--font-size-xs);display:flex;align-items:center;gap:6px;">' +
        '<span style="color:var(--text-tertiary);min-width:60px;">' + e.time + '</span>' +
        '<span style="width:6px;height:6px;border-radius:50%;background:' + sc + ';flex-shrink:0;"></span>' +
        '<span style="color:var(--text-primary);font-weight:500;">' + escapeHtml(e.method) + '</span>' +
        (e.params && e.params.name ? '<span style="color:var(--text-secondary);">' + escapeHtml(e.params.name) + '</span>' : '') +
        '<span style="color:var(--text-tertiary);margin-left:auto;">' + e.duration + 'ms</span>' +
      '</div>';
    });
    container.innerHTML = html;
  },

  updateCallCount: function() {
    var el = document.getElementById('mcp-stat-calls');
    el.textContent = this._log.length;
  }
};
