/* Vigil v1.1 — Security Agents View with LLM Provider Selection */
Views.agents = {
  _agents: [],
  _activeFilter: 'all',
  _selectedAgentId: null,
  _editMode: false,
  _dirty: false,

  init: function() {
    var el = document.getElementById('view-agents');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Security Agents</div>' +
        '<button class="btn btn-primary btn-sm" id="agents-create-btn">Create Agent</button>' +
      '</div>' +

      // Stats
      '<div class="stat-grid" style="margin-bottom:16px;">' +
        '<div class="stat-card"><div class="stat-card-label">Total Agents</div><div class="stat-card-value" id="agents-total">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Scanners</div><div class="stat-card-value" id="agents-scanners" style="color:var(--cyan);">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Analyzers</div><div class="stat-card-value" id="agents-analyzers" style="color:var(--purple);">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Total Runs</div><div class="stat-card-value" id="agents-runs">0</div></div>' +
      '</div>' +

      // Filter tabs
      '<div class="tab-bar" id="agents-filter-tabs">' +
        '<div class="tab-item active" data-filter="all">All</div>' +
        '<div class="tab-item" data-filter="scanner">Scanners</div>' +
        '<div class="tab-item" data-filter="analyzer">Analyzers</div>' +
        '<div class="tab-item" data-filter="defender">Defenders</div>' +
        '<div class="tab-item" data-filter="hunter">Hunters</div>' +
        '<div class="tab-item" data-filter="custom">Custom</div>' +
      '</div>' +

      // Agent grid
      '<div id="agents-grid" class="grid-3">' +
        '<div class="loading-state"><div class="spinner"></div><div>Loading agents...</div></div>' +
      '</div>' +

      // Detail / Editor panel
      '<div id="agents-detail" class="glass-card" style="display:none;margin-top:16px;">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">' +
          '<div>' +
            '<div style="font-size:var(--font-size-lg);font-weight:600;color:var(--text-primary);" id="agent-detail-name">--</div>' +
            '<div id="agent-detail-meta" style="margin-top:4px;"></div>' +
          '</div>' +
          '<div style="display:flex;gap:6px;">' +
            '<button class="btn btn-ghost btn-sm" id="agent-edit-toggle" style="color:var(--cyan);">Edit</button>' +
            '<button class="btn btn-primary btn-sm" id="agent-save-btn" style="display:none;">Save</button>' +
            '<button class="btn btn-ghost btn-sm" id="agent-discard-btn" style="display:none;color:var(--orange);">Discard</button>' +
            '<button class="btn btn-ghost btn-sm" id="agent-detail-close" style="color:var(--text-tertiary);">Close</button>' +
          '</div>' +
        '</div>' +
        '<div id="agent-detail-tabs" class="tab-bar" style="margin-bottom:12px;">' +
          '<div class="tab-item active" data-tab="config">Config</div>' +
          '<div class="tab-item" data-tab="run">Run</div>' +
          '<div class="tab-item" data-tab="history">History</div>' +
        '</div>' +
        '<div id="agent-detail-body"></div>' +
      '</div>';

    var self = this;
    document.getElementById('agents-create-btn').addEventListener('click', function() { self.showCreateModal(); });
    document.getElementById('agent-detail-close').addEventListener('click', function() {
      document.getElementById('agents-detail').style.display = 'none';
      self._editMode = false;
      self._dirty = false;
    });
    document.getElementById('agent-edit-toggle').addEventListener('click', function() {
      self._editMode = !self._editMode;
      this.textContent = self._editMode ? 'View' : 'Edit';
      self._showDetailTab('config');
    });
    document.getElementById('agent-save-btn').addEventListener('click', function() { self._saveAgent(); });
    document.getElementById('agent-discard-btn').addEventListener('click', function() {
      self._editMode = false;
      self._dirty = false;
      document.getElementById('agent-edit-toggle').textContent = 'Edit';
      self._showDetailTab('config');
    });

    document.querySelectorAll('#agents-filter-tabs .tab-item').forEach(function(tab) {
      tab.addEventListener('click', function() {
        document.querySelectorAll('#agents-filter-tabs .tab-item').forEach(function(t) { t.classList.remove('active'); });
        tab.classList.add('active');
        self._activeFilter = tab.getAttribute('data-filter');
        self.renderAgents();
      });
    });

    document.querySelectorAll('#agent-detail-tabs .tab-item').forEach(function(tab) {
      tab.addEventListener('click', function() {
        document.querySelectorAll('#agent-detail-tabs .tab-item').forEach(function(t) { t.classList.remove('active'); });
        tab.classList.add('active');
        self._showDetailTab(tab.getAttribute('data-tab'));
      });
    });
  },

  show: function() { this.loadAgents(); },
  hide: function() {},

  loadAgents: function() {
    var self = this;
    fetch('/api/agents', { credentials: 'same-origin' })
      .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function(data) {
        self._agents = data.agents || data || [];
        if (!Array.isArray(self._agents)) self._agents = [];
        var totalRuns = 0, scannerCount = 0, analyzerCount = 0;
        self._agents.forEach(function(a) {
          totalRuns += a.run_count || 0;
          if (a.category === 'scanner') scannerCount++;
          if (a.category === 'analyzer') analyzerCount++;
        });
        var set = typeof animateValue === 'function'
          ? function(id, v) { animateValue(document.getElementById(id), 0, v, 400); }
          : function(id, v) { document.getElementById(id).textContent = v; };
        set('agents-total', self._agents.length);
        set('agents-scanners', scannerCount);
        set('agents-analyzers', analyzerCount);
        set('agents-runs', totalRuns);
        self.renderAgents();
      })
      .catch(function() {
        document.getElementById('agents-grid').innerHTML = '<div class="empty-state" style="grid-column:1/-1;"><div class="empty-state-icon">&#129302;</div><div class="empty-state-title">Could Not Load Agents</div><div class="empty-state-desc">Check server connection</div></div>';
      });
  },

  renderAgents: function() {
    var container = document.getElementById('agents-grid');
    var filter = this._activeFilter;
    var agents = this._agents.filter(function(a) {
      if (filter === 'all') return true;
      return (a.category || '').toLowerCase() === filter;
    });

    if (agents.length === 0) {
      container.innerHTML = '<div class="empty-state" style="grid-column:1/-1;"><div class="empty-state-icon">&#129302;</div><div class="empty-state-title">No Agents</div><div class="empty-state-desc">' +
        (filter === 'custom' ? 'Click "Create Agent" to build your own security agent' : 'No agents in this category') + '</div></div>';
      return;
    }

    var catColors = {
      scanner: { tag: 'tag-cyan', color: 'var(--cyan)', icon: '&#128269;' },
      analyzer: { tag: 'tag-purple', color: 'var(--purple)', icon: '&#128202;' },
      defender: { tag: 'tag-cyan', color: 'var(--cyan)', icon: '&#128737;' },
      hunter: { tag: '', color: 'var(--orange)', icon: '&#127919;' },
      custom: { tag: '', color: 'var(--text-secondary)', icon: '&#9881;' },
    };

    var html = '';
    agents.forEach(function(a) {
      var cat = catColors[a.category] || catColors.custom;
      var riskColor = a.risk_level === 'high' ? 'var(--orange)' : a.risk_level === 'medium' ? 'var(--text-secondary)' : 'var(--cyan)';
      var providerTag = '';
      if (a.config && a.config.ai && a.config.ai.provider) {
        providerTag = '<span class="tag" style="font-size:10px;opacity:0.7;">' + escapeHtml(a.config.ai.provider) + '</span>';
      }

      html += '<div class="glass-card agent-card" data-id="' + escapeHtml(a.id || '') + '" style="cursor:pointer;transition:border-color 0.2s;" onmouseover="this.style.borderColor=\'rgba(34,211,238,0.3)\'" onmouseout="this.style.borderColor=\'\'">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">' +
          '<span style="font-size:18px;">' + cat.icon + '</span>' +
          '<span style="flex:1;color:var(--text-primary);font-weight:600;font-size:var(--font-size-sm);">' + escapeHtml(a.name || 'Unnamed') + '</span>' +
        '</div>' +
        '<div style="display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap;">' +
          '<span class="tag ' + cat.tag + '" style="font-size:10px;">' + escapeHtml(a.category || 'custom') + '</span>' +
          '<span style="font-size:10px;color:' + riskColor + ';">' + escapeHtml(a.risk_level || '') + ' risk</span>' +
          (a.run_count > 0 ? '<span style="font-size:10px;color:var(--text-tertiary);">' + a.run_count + ' runs</span>' : '') +
          providerTag +
        '</div>' +
        '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);line-height:1.5;margin-bottom:10px;">' + escapeHtml((a.description || '').substring(0, 100)) + '</div>' +
        '<button class="btn btn-primary btn-sm agent-quick-run" data-id="' + escapeHtml(a.id || '') + '" style="width:100%;" onclick="event.stopPropagation();">Run Agent</button>' +
      '</div>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.agent-card').forEach(function(card) {
      card.addEventListener('click', function(e) {
        if (e.target.classList.contains('agent-quick-run')) return;
        Views.agents.showAgentDetail(card.getAttribute('data-id'));
      });
    });
    container.querySelectorAll('.agent-quick-run').forEach(function(btn) {
      btn.addEventListener('click', function(e) {
        e.stopPropagation();
        Views.agents.runAgent(btn.getAttribute('data-id'));
      });
    });
  },

  // ── Config Editor Section Builder ──────────────────────────────
  _buildSection: function(title, color, fields, agent, editing) {
    var h = '<div style="margin-bottom:16px;border-left:3px solid ' + color + ';padding-left:12px;">' +
      '<div style="font-size:var(--font-size-xs);font-weight:600;color:' + color + ';margin-bottom:8px;text-transform:uppercase;letter-spacing:0.5px;">' + title + '</div>';
    fields.forEach(function(f) {
      var val = f.value !== undefined && f.value !== null ? f.value : '';
      h += '<div style="display:flex;align-items:' + (f.type === 'textarea' ? 'flex-start' : 'center') + ';margin-bottom:6px;gap:8px;">';
      h += '<span style="min-width:120px;color:var(--text-tertiary);font-size:var(--font-size-xs);">' + f.label + '</span>';
      if (editing && !f.readonly) {
        if (f.type === 'select') {
          h += '<select class="form-select" id="' + f.id + '" style="flex:1;font-size:var(--font-size-xs);padding:4px 8px;">';
          (f.options || []).forEach(function(opt) {
            var selected = (typeof opt === 'object' ? opt.value : opt) === String(val) ? ' selected' : '';
            h += '<option value="' + (typeof opt === 'object' ? opt.value : opt) + '"' + selected + '>' + (typeof opt === 'object' ? opt.label : opt) + '</option>';
          });
          h += '</select>';
        } else if (f.type === 'textarea') {
          h += '<textarea class="form-textarea" id="' + f.id + '" rows="' + (f.rows || 3) + '" style="flex:1;font-size:var(--font-size-xs);">' + escapeHtml(String(val)) + '</textarea>';
        } else if (f.type === 'number') {
          h += '<input type="number" class="form-input" id="' + f.id + '" value="' + escapeHtml(String(val)) + '" style="flex:1;font-size:var(--font-size-xs);padding:4px 8px;">';
        } else if (f.type === 'toggle') {
          h += '<label style="flex:1;cursor:pointer;"><input type="checkbox" id="' + f.id + '"' + (val ? ' checked' : '') + '> ' + (val ? 'Enabled' : 'Disabled') + '</label>';
        } else {
          h += '<input type="text" class="form-input" id="' + f.id + '" value="' + escapeHtml(String(val)) + '" placeholder="' + escapeHtml(f.placeholder || '') + '" style="flex:1;font-size:var(--font-size-xs);padding:4px 8px;">';
        }
      } else {
        // Read-only
        if (f.type === 'toggle') {
          h += '<span style="flex:1;color:' + (val ? 'var(--cyan)' : 'var(--text-tertiary)') + ';font-size:var(--font-size-xs);">' + (val ? 'Enabled' : 'Disabled') + '</span>';
        } else {
          var displayVal = String(val);
          if (displayVal.length > 200) displayVal = displayVal.substring(0, 200) + '...';
          h += '<span style="flex:1;color:var(--text-secondary);font-size:var(--font-size-xs);white-space:pre-wrap;max-height:80px;overflow:hidden;">' + escapeHtml(displayVal || '--') + '</span>';
        }
      }
      h += '</div>';
    });
    h += '</div>';
    return h;
  },

  _showDetailTab: function(tab) {
    var agent = this._agents.find(function(a) { return a.id === Views.agents._selectedAgentId; });
    if (!agent) return;
    var body = document.getElementById('agent-detail-body');
    var editing = this._editMode;
    var saveBtn = document.getElementById('agent-save-btn');
    var discardBtn = document.getElementById('agent-discard-btn');
    saveBtn.style.display = editing ? '' : 'none';
    discardBtn.style.display = editing ? '' : 'none';

    if (tab === 'config') {
      var aiConfig = (agent.config && agent.config.ai) || {};
      var llmMode = aiConfig.mode || 'inherit';
      var llmProvider = aiConfig.provider || '';
      var llmModel = aiConfig.model || '';

      var html = '';
      html += this._buildSection('Identity', 'var(--cyan)', [
        { label: 'name', id: 'ae-name', value: agent.name },
        { label: 'slug', id: 'ae-slug', value: agent.slug, readonly: !!agent.builtIn },
        { label: 'description', id: 'ae-desc', type: 'textarea', rows: 2, value: agent.description },
        { label: 'category', id: 'ae-category', type: 'select', value: agent.category, options: [
          {value:'scanner',label:'Scanner'},{value:'analyzer',label:'Analyzer'},{value:'defender',label:'Defender'},
          {value:'hunter',label:'Hunter'},{value:'custom',label:'Custom'}
        ]},
        { label: 'risk_level', id: 'ae-risk', type: 'select', value: agent.risk_level, options: [
          {value:'low',label:'Low'},{value:'medium',label:'Medium'},{value:'high',label:'High'},{value:'critical',label:'Critical'}
        ]},
      ], agent, editing);

      html += this._buildSection('Prompt', 'var(--purple)', [
        { label: 'system_prompt', id: 'ae-sysprompt', type: 'textarea', rows: 5, value: agent.system_prompt },
        { label: 'task_prompt', id: 'ae-taskprompt', type: 'textarea', rows: 3, value: agent.task_prompt },
      ], agent, editing);

      html += this._buildSection('LLM Assignment', '#22c55e', [
        { label: 'llm_mode', id: 'ae-llm-mode', type: 'select', value: llmMode, options: [
          {value:'inherit',label:'Inherit global default'},{value:'provider',label:'Use provider default'},{value:'pinned',label:'Pin provider + model'}
        ]},
        { label: 'llm_provider', id: 'ae-llm-provider', type: 'select', value: llmProvider, options: [
          {value:'',label:'(none)'},{value:'ollama',label:'Ollama'},{value:'claude-api',label:'Claude API'},
          {value:'claude-cli',label:'Claude CLI'},{value:'claude-code',label:'Claude Code'},{value:'codex',label:'Codex CLI'}
        ]},
        { label: 'llm_model', id: 'ae-llm-model', value: llmModel, placeholder: 'e.g., qwen3:8b or claude-sonnet-4-20250514' },
      ], agent, editing);

      html += this._buildSection('Tools & Capabilities', 'var(--orange)', [
        { label: 'tools_allowed', id: 'ae-tools', value: (agent.tools_allowed || []).join(', '), placeholder: 'dns, osint, nmap, ...' },
      ], agent, editing);

      html += this._buildSection('Behavior', '#3b82f6', [
        { label: 'autonomy_mode', id: 'ae-autonomy', type: 'select', value: agent.autonomy_mode || 'assisted', options: [
          {value:'manual',label:'Manual'},{value:'assisted',label:'Assisted'},{value:'autonomous',label:'Autonomous'}
        ]},
        { label: 'model_profile', id: 'ae-model-prof', type: 'select', value: agent.model_profile || 'auto', options: [
          {value:'eco',label:'Eco'},{value:'auto',label:'Auto'},{value:'premium',label:'Premium'},{value:'agentic',label:'Agentic'}
        ]},
        { label: 'memory_policy', id: 'ae-memory', type: 'select', value: agent.memory_policy || 'session', options: [
          {value:'none',label:'None'},{value:'session',label:'Session'},{value:'persistent',label:'Persistent'}
        ]},
        { label: 'budget_limit', id: 'ae-budget', type: 'number', value: agent.budget_limit || 10 },
      ], agent, editing);

      html += this._buildSection('Metadata', 'var(--text-tertiary)', [
        { label: 'version', value: agent.version || 1, readonly: true },
        { label: 'created', value: agent.createdAt || agent.created_at || '--', readonly: true },
        { label: 'updated', value: agent.updatedAt || agent.updated_at || '--', readonly: true },
      ], agent, false);

      html += this._buildSection('Stats', 'var(--text-tertiary)', [
        { label: 'total_runs', value: agent.run_count || 0, readonly: true },
        { label: 'active', id: 'ae-enabled', type: 'toggle', value: agent.enabled !== false },
      ], agent, editing);

      body.innerHTML = html;

      // Conditional visibility for LLM fields
      if (editing) {
        var self = this;
        var modeEl = document.getElementById('ae-llm-mode');
        var provGroup = document.getElementById('ae-llm-provider');
        var modelGroup = document.getElementById('ae-llm-model');
        function updateLLMVisibility() {
          var m = modeEl ? modeEl.value : 'inherit';
          if (provGroup) provGroup.closest('div[style]').style.display = m === 'inherit' ? 'none' : '';
          if (modelGroup) modelGroup.closest('div[style]').style.display = m === 'pinned' ? 'none' : 'none';
          // Show provider when not inherit, show model only when pinned
          if (provGroup && provGroup.parentElement) provGroup.parentElement.style.display = m !== 'inherit' ? '' : 'none';
          if (modelGroup && modelGroup.parentElement) modelGroup.parentElement.style.display = m === 'pinned' ? '' : 'none';
        }
        if (modeEl) {
          modeEl.addEventListener('change', updateLLMVisibility);
          updateLLMVisibility();
        }
      }
    } else if (tab === 'run') {
      this._renderRunTab(agent, body);
    } else if (tab === 'history') {
      body.innerHTML = '<div id="agent-history-list"><div class="loading-state"><div class="spinner spinner-sm"></div></div></div>';
      this.loadAgentHistory(agent.id);
    }
  },

  _renderRunTab: function(agent, body) {
    var html = '';
    html += '<div style="margin-bottom:16px;padding:12px;border-radius:8px;background:rgba(34,211,238,0.03);border:1px solid rgba(34,211,238,0.1);">' +
      '<div class="form-label" style="color:var(--cyan);">Run This Agent</div>' +
      '<textarea class="form-textarea" id="agent-inline-input" rows="3" placeholder="' + escapeHtml(agent.placeholder || 'Enter target or input for the agent...') + '" style="margin-bottom:8px;"></textarea>' +
      this._renderExampleButtons(agent, 'agent-inline-input') +
      '<button class="btn btn-primary btn-sm" id="agent-inline-run">Run ' + escapeHtml(agent.name) + '</button>' +
      '</div>';
    html += '<div id="agent-run-output" style="display:none;margin-bottom:16px;">' +
      '<div class="form-label">Agent Output</div>' +
      '<div id="agent-run-output-content" class="code-block" style="max-height:400px;overflow-y:auto;white-space:pre-wrap;color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;"></div>' +
      '</div>';
    body.innerHTML = html;
    this._bindExampleButtons(body, agent);
    var self = this;
    document.getElementById('agent-inline-run').addEventListener('click', function() { self.executeAgent(agent.id); });
    document.getElementById('agent-inline-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); self.executeAgent(agent.id); }
    });
  },

  _saveAgent: function() {
    var id = this._selectedAgentId;
    if (!id) return;
    var patch = {};

    var getVal = function(elId) { var el = document.getElementById(elId); return el ? el.value : undefined; };
    var getChecked = function(elId) { var el = document.getElementById(elId); return el ? el.checked : undefined; };

    if (getVal('ae-name') !== undefined) patch.name = getVal('ae-name');
    if (getVal('ae-desc') !== undefined) patch.description = getVal('ae-desc');
    if (getVal('ae-category') !== undefined) patch.category = getVal('ae-category');
    if (getVal('ae-risk') !== undefined) patch.risk_level = getVal('ae-risk');
    if (getVal('ae-sysprompt') !== undefined) patch.system_prompt = getVal('ae-sysprompt');
    if (getVal('ae-taskprompt') !== undefined) patch.task_prompt = getVal('ae-taskprompt');
    if (getVal('ae-autonomy') !== undefined) patch.autonomy_mode = getVal('ae-autonomy');
    if (getVal('ae-model-prof') !== undefined) patch.model_profile = getVal('ae-model-prof');
    if (getVal('ae-memory') !== undefined) patch.memory_policy = getVal('ae-memory');
    if (getVal('ae-budget') !== undefined) patch.budget_limit = parseInt(getVal('ae-budget'), 10) || 10;
    if (getChecked('ae-enabled') !== undefined) patch.enabled = getChecked('ae-enabled');

    // Tools
    var toolsVal = getVal('ae-tools');
    if (toolsVal !== undefined) {
      patch.tools_allowed = toolsVal.split(',').map(function(t) { return t.trim(); }).filter(Boolean);
    }

    // LLM config
    var llmMode = getVal('ae-llm-mode');
    if (llmMode !== undefined) {
      var config = { ai: { mode: llmMode } };
      if (llmMode !== 'inherit') {
        config.ai.provider = getVal('ae-llm-provider') || '';
      }
      if (llmMode === 'pinned') {
        config.ai.model = getVal('ae-llm-model') || '';
      }
      patch.config = config;
    }

    var self = this;
    fetch('/api/agents/' + id, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(patch)
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.error) { Toast.error(data.error); return; }
      Toast.success('Agent saved');
      self._editMode = false;
      self._dirty = false;
      document.getElementById('agent-edit-toggle').textContent = 'Edit';
      self.loadAgents();
      // Re-show detail after reload
      setTimeout(function() { self.showAgentDetail(id); }, 300);
    })
    .catch(function() { Toast.error('Failed to save agent'); });
  },

  showAgentDetail: function(id) {
    var agent = this._agents.find(function(a) { return a.id === id; });
    if (!agent) return;

    this._selectedAgentId = id;
    this._editMode = false;
    document.getElementById('agent-edit-toggle').textContent = 'Edit';
    var panel = document.getElementById('agents-detail');
    panel.style.display = 'block';
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    document.getElementById('agent-detail-name').textContent = agent.name || 'Unnamed';
    var catColors = { scanner: 'tag-cyan', analyzer: 'tag-purple', defender: 'tag-cyan', hunter: '', custom: '' };
    var providerLabel = (agent.config && agent.config.ai && agent.config.ai.provider) ? ' <span class="tag" style="font-size:10px;opacity:0.7;">' + escapeHtml(agent.config.ai.provider) + '</span>' : '';
    document.getElementById('agent-detail-meta').innerHTML =
      '<span class="tag ' + (catColors[agent.category] || '') + '">' + escapeHtml(agent.category || 'custom') + '</span>' +
      (agent.risk_level ? ' <span style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-left:6px;">' + escapeHtml(agent.risk_level) + ' risk</span>' : '') +
      (agent.run_count ? ' <span style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-left:6px;">' + agent.run_count + ' runs</span>' : '') +
      providerLabel;

    // Reset to config tab
    document.querySelectorAll('#agent-detail-tabs .tab-item').forEach(function(t, i) {
      t.classList.toggle('active', i === 0);
    });
    this._showDetailTab('config');
  },

  executeAgent: function(id) {
    var input = document.getElementById('agent-inline-input').value.trim();
    if (!input) { Toast.warning('Enter input for the agent'); return; }
    var agent = this._agents.find(function(a) { return a.id === id; });
    var btn = document.getElementById('agent-inline-run');
    var outputDiv = document.getElementById('agent-run-output');
    var outputContent = document.getElementById('agent-run-output-content');
    btn.disabled = true;
    btn.textContent = 'Executing...';
    outputDiv.style.display = 'block';
    outputContent.innerHTML = '<div class="loading-state"><div class="spinner"></div><div>' + escapeHtml(agent ? agent.name : 'Agent') + ' analyzing...</div></div>';
    var self = this;
    fetch('/api/agents/' + id + '/run', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin', body: JSON.stringify({ input: input })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      btn.disabled = false;
      btn.textContent = 'Run ' + escapeHtml(agent ? agent.name : 'Agent');
      if (data.error) { outputContent.textContent = 'Error: ' + data.error; outputContent.style.borderLeft = '3px solid var(--orange)'; Toast.error(data.error); return; }
      var output = data.run ? (data.run.output || 'No output') : (data.output || data.result || 'Agent completed.');
      var duration = data.run && data.run.duration ? ' (' + (data.run.duration / 1000).toFixed(1) + 's)' : '';
      var status = data.run ? data.run.status : 'completed';
      outputContent.style.borderLeft = status === 'completed' ? '3px solid var(--cyan)' : '3px solid var(--orange)';
      outputContent.style.paddingLeft = '12px';
      outputContent.textContent = output;
      Toast.success('Agent completed' + duration);
      self.loadAgentHistory(id);
      self.loadAgents();
    })
    .catch(function() {
      btn.disabled = false; btn.textContent = 'Run ' + escapeHtml(agent ? agent.name : 'Agent');
      outputContent.textContent = 'Agent execution failed.'; outputContent.style.borderLeft = '3px solid var(--orange)';
      Toast.error('Agent execution failed');
    });
  },

  runAgent: function(id) {
    var agent = this._agents.find(function(a) { return a.id === id; });
    if (!agent) return;
    // Open detail panel on Run tab
    this.showAgentDetail(id);
    document.querySelectorAll('#agent-detail-tabs .tab-item').forEach(function(t) {
      t.classList.toggle('active', t.getAttribute('data-tab') === 'run');
    });
    this._showDetailTab('run');
  },

  loadAgentHistory: function(agentId) {
    var container = document.getElementById('agent-history-list');
    if (!container) return;
    fetch('/api/agents/' + agentId + '/runs', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var runs = data.runs || data.history || [];
        if (!Array.isArray(runs) || runs.length === 0) {
          container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);">No run history yet</div>';
          return;
        }
        var h = '<table class="data-table"><thead><tr><th>Time</th><th>Status</th><th>Duration</th><th>Input</th></tr></thead><tbody>';
        runs.slice(0, 10).forEach(function(r) {
          var statusColor = r.status === 'completed' ? 'var(--cyan)' : 'var(--orange)';
          var dur = r.duration ? (r.duration / 1000).toFixed(1) + 's' : '--';
          h += '<tr><td>' + timeAgo(r.createdAt || r.created_at) + '</td>' +
            '<td><span style="color:' + statusColor + ';font-weight:600;font-size:var(--font-size-xs);">' + escapeHtml(r.status || 'complete') + '</span></td>' +
            '<td>' + dur + '</td>' +
            '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-tertiary);font-size:var(--font-size-xs);">' + escapeHtml((r.input || '--').substring(0, 60)) + '</td></tr>';
        });
        h += '</tbody></table>';
        container.innerHTML = h;
      })
      .catch(function() { container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);">Could not load history</div>'; });
  },

  _renderExampleButtons: function(agent, textareaId) {
    if (!agent.examples || !agent.examples.length) return '';
    var html = '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px;align-items:center;"><span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">Try:</span>';
    agent.examples.forEach(function(ex, i) {
      html += '<button class="btn btn-ghost btn-sm agent-example-btn" data-textarea="' + textareaId + '" data-example-idx="' + i + '" style="color:var(--cyan);border-color:rgba(34,211,238,0.2);font-size:10px;padding:2px 8px;">' + escapeHtml(ex.label) + '</button>';
    });
    html += '</div>';
    return html;
  },

  _bindExampleButtons: function(container, agent) {
    container.querySelectorAll('.agent-example-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var idx = parseInt(btn.getAttribute('data-example-idx'), 10);
        var textarea = document.getElementById(btn.getAttribute('data-textarea'));
        if (textarea && agent.examples && agent.examples[idx]) { textarea.value = agent.examples[idx].input; textarea.focus(); }
      });
    });
  },

  showCreateModal: function() {
    Modal.open({
      title: 'Create Security Agent',
      body:
        '<div class="form-group"><label class="form-label">Agent Name</label><input type="text" class="form-input" id="agent-new-name" placeholder="e.g., API Security Tester"></div>' +
        '<div class="form-group"><label class="form-label">Category</label><select class="form-select" id="agent-new-category"><option value="scanner">Scanner</option><option value="analyzer">Analyzer</option><option value="defender">Defender</option><option value="hunter">Hunter</option><option value="custom">Custom</option></select></div>' +
        '<div class="form-group"><label class="form-label">Description</label><textarea class="form-textarea" id="agent-new-desc" rows="2" placeholder="What does this agent do?"></textarea></div>' +
        '<div class="form-group"><label class="form-label">System Prompt <span style="color:var(--text-tertiary);font-weight:400;">(optional)</span></label><textarea class="form-textarea" id="agent-new-prompt" rows="3" placeholder="You are a security expert specializing in..."></textarea></div>' +
        '<div class="form-group"><label class="form-label">Task Prompt <span style="color:var(--text-tertiary);font-weight:400;">(use {{input}})</span></label><textarea class="form-textarea" id="agent-new-task" rows="3" placeholder="Analyze the following for security issues: {{input}}"></textarea></div>' +
        // LLM Assignment
        '<div style="border-top:1px solid var(--border);padding-top:12px;margin-top:12px;">' +
        '<div class="form-group"><label class="form-label" style="color:#22c55e;">LLM Assignment</label>' +
          '<select class="form-select" id="agent-new-llm-mode"><option value="inherit">Inherit global default</option><option value="provider">Use provider default</option><option value="pinned">Pin provider + model</option></select></div>' +
        '<div class="form-group" id="agent-new-llm-provider-group" style="display:none;"><label class="form-label">Provider</label>' +
          '<select class="form-select" id="agent-new-llm-provider"><option value="ollama">Ollama</option><option value="claude-api">Claude API</option><option value="claude-cli">Claude CLI</option><option value="claude-code">Claude Code</option><option value="codex">Codex CLI</option></select></div>' +
        '<div class="form-group" id="agent-new-llm-model-group" style="display:none;"><label class="form-label">Pinned Model</label>' +
          '<input type="text" class="form-input" id="agent-new-llm-model" placeholder="e.g., qwen3:8b"></div>' +
        '</div>',
      footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="agent-create-confirm">Create Agent</button>'
    });

    // LLM mode toggle
    var modeEl = document.getElementById('agent-new-llm-mode');
    modeEl.addEventListener('change', function() {
      document.getElementById('agent-new-llm-provider-group').style.display = modeEl.value !== 'inherit' ? '' : 'none';
      document.getElementById('agent-new-llm-model-group').style.display = modeEl.value === 'pinned' ? '' : 'none';
    });

    var self = this;
    document.getElementById('agent-create-confirm').addEventListener('click', function() {
      var name = document.getElementById('agent-new-name').value.trim();
      var category = document.getElementById('agent-new-category').value;
      var description = document.getElementById('agent-new-desc').value.trim();
      var systemPrompt = document.getElementById('agent-new-prompt').value.trim();
      var taskPrompt = document.getElementById('agent-new-task').value.trim();
      if (!name) { Toast.warning('Enter agent name'); return; }

      Modal.loading('Creating agent...');
      var body = { name: name, category: category, description: description };
      if (systemPrompt) body.system_prompt = systemPrompt;
      if (taskPrompt) body.task_prompt = taskPrompt;

      // LLM config
      var llmMode = document.getElementById('agent-new-llm-mode').value;
      if (llmMode !== 'inherit') {
        body.config = { ai: { mode: llmMode, provider: document.getElementById('agent-new-llm-provider').value } };
        if (llmMode === 'pinned') body.config.ai.model = document.getElementById('agent-new-llm-model').value;
      }

      fetch('/api/agents', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify(body) })
      .then(function(r) { return r.json(); })
      .then(function(data) { Modal.close(); if (data.error) { Toast.error(data.error); return; } Toast.success('Agent created: ' + name); self.loadAgents(); })
      .catch(function() { Modal.close(); Toast.error('Failed to create agent'); });
    });
  }
};
