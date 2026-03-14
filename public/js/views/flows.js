/* Vigil v1.1 — Security Flows View */
Views.flows = {
  _flows: [],
  _activeFilter: 'all',
  _selectedFlowId: null,
  _editMode: false,

  init: function() {
    var el = document.getElementById('view-flows');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Security Flows</div>' +
        '<button class="btn btn-primary btn-sm" id="flows-create-btn">Create Flow</button>' +
      '</div>' +

      '<div class="stat-grid" style="margin-bottom:16px;">' +
        '<div class="stat-card"><div class="stat-card-label">Total Flows</div><div class="stat-card-value" id="flows-total">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Active</div><div class="stat-card-value" id="flows-active" style="color:var(--cyan);">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Drafts</div><div class="stat-card-value" id="flows-drafts" style="color:var(--text-tertiary);">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Total Runs</div><div class="stat-card-value" id="flows-runs">0</div></div>' +
      '</div>' +

      '<div class="tab-bar" id="flows-filter-tabs">' +
        '<div class="tab-item active" data-filter="all">All</div>' +
        '<div class="tab-item" data-filter="active">Active</div>' +
        '<div class="tab-item" data-filter="draft">Drafts</div>' +
        '<div class="tab-item" data-filter="template">Templates</div>' +
      '</div>' +

      '<div id="flows-grid" class="grid-3">' +
        '<div class="loading-state"><div class="spinner"></div><div>Loading flows...</div></div>' +
      '</div>' +

      // Detail / Editor panel
      '<div id="flows-detail" class="glass-card" style="display:none;margin-top:16px;">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">' +
          '<div>' +
            '<div style="font-size:var(--font-size-lg);font-weight:600;color:var(--text-primary);" id="flow-detail-name">--</div>' +
            '<div id="flow-detail-meta" style="margin-top:4px;"></div>' +
          '</div>' +
          '<div style="display:flex;gap:6px;">' +
            '<button class="btn btn-ghost btn-sm" id="flow-edit-toggle" style="color:var(--cyan);">Edit</button>' +
            '<button class="btn btn-primary btn-sm" id="flow-save-btn" style="display:none;">Save</button>' +
            '<button class="btn btn-ghost btn-sm" id="flow-discard-btn" style="display:none;color:var(--orange);">Discard</button>' +
            '<button class="btn btn-ghost btn-sm" id="flow-detail-close" style="color:var(--text-tertiary);">Close</button>' +
          '</div>' +
        '</div>' +
        '<div id="flow-detail-tabs" class="tab-bar" style="margin-bottom:12px;">' +
          '<div class="tab-item active" data-tab="builder">Builder</div>' +
          '<div class="tab-item" data-tab="config">Config</div>' +
          '<div class="tab-item" data-tab="execute">Execute</div>' +
          '<div class="tab-item" data-tab="history">History</div>' +
        '</div>' +
        '<div id="flow-detail-body"></div>' +
      '</div>';

    var self = this;
    document.getElementById('flows-create-btn').addEventListener('click', function() { self.showCreateModal(); });
    document.getElementById('flow-detail-close').addEventListener('click', function() {
      document.getElementById('flows-detail').style.display = 'none';
      self._editMode = false;
    });
    document.getElementById('flow-edit-toggle').addEventListener('click', function() {
      self._editMode = !self._editMode;
      this.textContent = self._editMode ? 'View' : 'Edit';
      self._showDetailTab('builder');
    });
    document.getElementById('flow-save-btn').addEventListener('click', function() { self._saveFlow(); });
    document.getElementById('flow-discard-btn').addEventListener('click', function() {
      self._editMode = false;
      document.getElementById('flow-edit-toggle').textContent = 'Edit';
      self._showDetailTab('builder');
    });

    document.querySelectorAll('#flows-filter-tabs .tab-item').forEach(function(tab) {
      tab.addEventListener('click', function() {
        document.querySelectorAll('#flows-filter-tabs .tab-item').forEach(function(t) { t.classList.remove('active'); });
        tab.classList.add('active');
        self._activeFilter = tab.getAttribute('data-filter');
        self.renderFlows();
      });
    });

    document.querySelectorAll('#flow-detail-tabs .tab-item').forEach(function(tab) {
      tab.addEventListener('click', function() {
        document.querySelectorAll('#flow-detail-tabs .tab-item').forEach(function(t) { t.classList.remove('active'); });
        tab.classList.add('active');
        self._showDetailTab(tab.getAttribute('data-tab'));
      });
    });
  },

  show: function() { this.loadFlows(); },
  hide: function() {},

  loadFlows: function() {
    var self = this;
    fetch('/api/flows', { credentials: 'same-origin' })
      .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function(data) {
        self._flows = data.flows || [];
        var active = 0, drafts = 0, totalRuns = 0;
        self._flows.forEach(function(f) {
          if (f.status === 'active') active++;
          if (f.status === 'draft') drafts++;
          totalRuns += f.total_runs || 0;
        });
        var set = typeof animateValue === 'function'
          ? function(id, v) { animateValue(document.getElementById(id), 0, v, 400); }
          : function(id, v) { document.getElementById(id).textContent = v; };
        set('flows-total', self._flows.length);
        set('flows-active', active);
        set('flows-drafts', drafts);
        set('flows-runs', totalRuns);
        self.renderFlows();
      })
      .catch(function() {
        document.getElementById('flows-grid').innerHTML = '<div class="empty-state" style="grid-column:1/-1;"><div class="empty-state-icon">&#128260;</div><div class="empty-state-title">Could Not Load Flows</div><div class="empty-state-desc">Check server connection</div></div>';
      });
  },

  renderFlows: function() {
    var container = document.getElementById('flows-grid');
    var filter = this._activeFilter;
    var flows = this._flows.filter(function(f) {
      if (filter === 'all') return true;
      if (filter === 'template') return f.is_template;
      return f.status === filter;
    });

    if (flows.length === 0) {
      container.innerHTML = '<div class="empty-state" style="grid-column:1/-1;"><div class="empty-state-icon">&#128260;</div><div class="empty-state-title">No Flows</div><div class="empty-state-desc">Create a flow or clone a template</div></div>';
      return;
    }

    var triggerIcons = { manual: '&#9654;', schedule: '&#9200;', webhook: '&#128279;', event: '&#9889;', agent: '&#129302;' };
    var statusColors = { draft: 'var(--text-tertiary)', active: 'var(--cyan)', paused: 'var(--orange)', archived: 'var(--text-tertiary)', error: 'var(--orange)' };
    var catColors = { general: '', recon: 'tag-cyan', appsec: 'tag-purple', compliance: 'tag-cyan', remediation: '', ops: '' };

    var html = '';
    flows.forEach(function(f) {
      var icon = triggerIcons[f.trigger_type] || '&#9654;';
      var statusColor = statusColors[f.status] || 'var(--text-tertiary)';
      var catTag = catColors[f.category] || '';
      var nodeCount = (f.nodes || []).length;
      var providerTag = '';
      if (f.metadata && f.metadata.ai && f.metadata.ai.provider) {
        providerTag = '<span class="tag" style="font-size:10px;opacity:0.7;">' + escapeHtml(f.metadata.ai.provider) + '</span>';
      }

      html += '<div class="glass-card flow-card" data-id="' + escapeHtml(f.id) + '" style="cursor:pointer;transition:border-color 0.2s;" onmouseover="this.style.borderColor=\'rgba(34,211,238,0.3)\'" onmouseout="this.style.borderColor=\'\'">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">' +
          '<span style="font-size:18px;">' + icon + '</span>' +
          '<span style="flex:1;font-weight:600;color:var(--text-primary);font-size:var(--font-size-sm);">' + escapeHtml(f.name) + '</span>' +
          '<span style="font-size:10px;color:' + statusColor + ';font-weight:600;">' + escapeHtml(f.status) + '</span>' +
        '</div>' +
        '<div style="display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap;">' +
          '<span class="tag ' + catTag + '" style="font-size:10px;">' + escapeHtml(f.category || 'general') + '</span>' +
          '<span style="font-size:10px;color:var(--text-tertiary);">' + nodeCount + ' nodes</span>' +
          '<span style="font-size:10px;color:var(--text-tertiary);">' + (f.total_runs || 0) + ' runs</span>' +
          providerTag +
          (f.is_template ? '<span class="tag" style="font-size:10px;background:rgba(168,85,247,0.15);color:#a855f7;">template</span>' : '') +
        '</div>' +
        '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);line-height:1.5;margin-bottom:10px;">' + escapeHtml((f.description || '').substring(0, 100)) + '</div>' +
        '<div style="display:flex;gap:6px;">' +
          '<button class="btn btn-primary btn-sm flow-execute-btn" data-id="' + escapeHtml(f.id) + '" style="flex:1;" onclick="event.stopPropagation();">Execute</button>' +
          (f.is_template ? '<button class="btn btn-ghost btn-sm flow-clone-btn" data-id="' + escapeHtml(f.id) + '" style="color:var(--purple);" onclick="event.stopPropagation();">Clone</button>' : '') +
        '</div>' +
      '</div>';
    });
    container.innerHTML = html;

    container.querySelectorAll('.flow-card').forEach(function(card) {
      card.addEventListener('click', function(e) {
        if (e.target.classList.contains('flow-execute-btn') || e.target.classList.contains('flow-clone-btn')) return;
        Views.flows.showFlowDetail(card.getAttribute('data-id'));
      });
    });
    container.querySelectorAll('.flow-execute-btn').forEach(function(btn) {
      btn.addEventListener('click', function(e) { e.stopPropagation(); Views.flows.showFlowDetail(btn.getAttribute('data-id')); Views.flows._switchTab('execute'); });
    });
    container.querySelectorAll('.flow-clone-btn').forEach(function(btn) {
      btn.addEventListener('click', function(e) { e.stopPropagation(); Views.flows.cloneFlow(btn.getAttribute('data-id')); });
    });
  },

  _switchTab: function(tab) {
    document.querySelectorAll('#flow-detail-tabs .tab-item').forEach(function(t) {
      t.classList.toggle('active', t.getAttribute('data-tab') === tab);
    });
    this._showDetailTab(tab);
  },

  showFlowDetail: function(id) {
    var flow = this._flows.find(function(f) { return f.id === id; });
    if (!flow) return;
    this._selectedFlowId = id;
    this._editMode = false;
    document.getElementById('flow-edit-toggle').textContent = 'Edit';
    var panel = document.getElementById('flows-detail');
    panel.style.display = 'block';
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    document.getElementById('flow-detail-name').textContent = flow.name;

    var provLabel = (flow.metadata && flow.metadata.ai && flow.metadata.ai.provider) ? ' <span class="tag" style="font-size:10px;opacity:0.7;">' + escapeHtml(flow.metadata.ai.provider) + '</span>' : '';
    document.getElementById('flow-detail-meta').innerHTML =
      '<span class="tag">' + escapeHtml(flow.category || 'general') + '</span>' +
      ' <span style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-left:6px;">' + escapeHtml(flow.trigger_type) + ' trigger</span>' +
      ' <span style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-left:6px;">v' + (flow.version || 1) + '</span>' +
      provLabel;

    document.querySelectorAll('#flow-detail-tabs .tab-item').forEach(function(t, i) { t.classList.toggle('active', i === 0); });
    this._showDetailTab('builder');
  },

  _showDetailTab: function(tab) {
    var flow = this._flows.find(function(f) { return f.id === Views.flows._selectedFlowId; });
    if (!flow) return;
    var body = document.getElementById('flow-detail-body');
    var editing = this._editMode;
    document.getElementById('flow-save-btn').style.display = editing ? '' : 'none';
    document.getElementById('flow-discard-btn').style.display = editing ? '' : 'none';

    if (tab === 'builder') {
      this._renderBuilder(flow, body, editing);
    } else if (tab === 'config') {
      this._renderConfig(flow, body, editing);
    } else if (tab === 'execute') {
      this._renderExecute(flow, body);
    } else if (tab === 'history') {
      body.innerHTML = '<div id="flow-history-list"><div class="loading-state"><div class="spinner spinner-sm"></div></div></div>';
      this.loadFlowHistory(flow.id);
    }
  },

  _nodeIcon: function(type) {
    var icons = { start: '&#9654;', end: '&#9209;', llm: '&#129504;', agent: '&#129302;', tool: '&#128295;', condition: '&#9889;', loop: '&#128260;', http: '&#127760;', delay: '&#9201;', human_input: '&#128100;', notify: '&#128276;' };
    return icons[type] || '&#9679;';
  },

  _renderBuilder: function(flow, body, editing) {
    var self = this;
    var nodes = flow.nodes || [];
    var edges = flow.edges || [];

    var html = '<div style="border:1px solid var(--border);border-radius:8px;padding:12px;background:rgba(0,0,0,0.2);">';

    // Node list
    nodes.forEach(function(node, idx) {
      var cfg = (node.data && node.data.config) || {};
      var detail = '';
      if (node.type === 'agent') detail = cfg.agentSlug || '';
      else if (node.type === 'condition') detail = cfg.expression || '';
      else if (node.type === 'llm') detail = (cfg.prompt || '').substring(0, 40);
      else if (node.type === 'http') detail = (cfg.method || 'GET') + ' ' + (cfg.url || '');
      else if (node.type === 'delay') detail = (cfg.ms || 1000) + 'ms';
      else if (node.type === 'notify') detail = (cfg.message || '').substring(0, 40);

      html += '<div style="display:flex;align-items:center;gap:8px;padding:8px;border-radius:6px;background:rgba(255,255,255,0.03);margin-bottom:4px;">';
      html += '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);min-width:20px;">' + (idx + 1) + '.</span>';
      html += '<span style="font-size:16px;">' + self._nodeIcon(node.type) + '</span>';
      html += '<span style="flex:1;font-weight:500;color:var(--text-primary);font-size:var(--font-size-sm);">' + escapeHtml(node.data.label || node.type) + '</span>';
      if (detail) html += '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + escapeHtml(detail) + '</span>';
      html += '<span class="tag" style="font-size:9px;">' + node.type + '</span>';
      if (editing && node.type !== 'start' && node.type !== 'end') {
        html += '<button class="btn btn-ghost btn-sm flow-edit-node" data-idx="' + idx + '" style="padding:2px 6px;font-size:10px;color:var(--cyan);">edit</button>';
        html += '<button class="btn btn-ghost btn-sm flow-remove-node" data-idx="' + idx + '" style="padding:2px 6px;font-size:10px;color:var(--orange);">x</button>';
      }
      html += '</div>';

      // Draw edge arrow
      var outEdges = edges.filter(function(e) { return e.source === node.id; });
      if (outEdges.length > 0 && idx < nodes.length - 1) {
        if (node.type === 'condition') {
          html += '<div style="padding-left:36px;color:var(--text-tertiary);font-size:var(--font-size-xs);">';
          outEdges.forEach(function(e) {
            html += '<span style="margin-right:12px;">&#8595; ' + (e.label || e.sourceHandle || '') + '</span>';
          });
          html += '</div>';
        } else {
          html += '<div style="padding-left:36px;color:var(--text-tertiary);font-size:11px;">&#8595;</div>';
        }
      }
    });

    if (editing) {
      html += '<button class="btn btn-ghost btn-sm" id="flow-add-node" style="margin-top:8px;color:var(--cyan);width:100%;border:1px dashed rgba(34,211,238,0.3);">+ Add Node</button>';
    }

    html += '</div>';
    html += '<div style="margin-top:8px;color:var(--text-tertiary);font-size:var(--font-size-xs);">' + nodes.length + ' nodes &middot; ' + edges.length + ' edges &middot; version ' + (flow.version || 1) + '</div>';

    body.innerHTML = html;

    if (editing) {
      var addBtn = document.getElementById('flow-add-node');
      if (addBtn) addBtn.addEventListener('click', function() { self._showAddNodeModal(flow); });

      body.querySelectorAll('.flow-edit-node').forEach(function(btn) {
        btn.addEventListener('click', function() { self._showEditNodeModal(flow, parseInt(btn.getAttribute('data-idx'), 10)); });
      });
      body.querySelectorAll('.flow-remove-node').forEach(function(btn) {
        btn.addEventListener('click', function() { self._removeNode(flow, parseInt(btn.getAttribute('data-idx'), 10)); });
      });
    }
  },

  _renderConfig: function(flow, body, editing) {
    var self = this;
    var aiConfig = (flow.metadata && flow.metadata.ai) || {};
    var llmMode = aiConfig.mode || 'inherit';

    var html = '';
    html += self._buildSection('Identity', 'var(--cyan)', [
      { label: 'name', id: 'fe-name', value: flow.name },
      { label: 'slug', id: 'fe-slug', value: flow.slug },
      { label: 'description', id: 'fe-desc', type: 'textarea', rows: 2, value: flow.description },
      { label: 'category', id: 'fe-category', type: 'select', value: flow.category, options: [
        {value:'general',label:'General'},{value:'recon',label:'Recon'},{value:'appsec',label:'AppSec'},
        {value:'compliance',label:'Compliance'},{value:'remediation',label:'Remediation'},{value:'ops',label:'Ops'}
      ]},
    ], flow, editing);

    html += self._buildSection('Trigger', 'var(--purple)', [
      { label: 'trigger_type', id: 'fe-trigger', type: 'select', value: flow.trigger_type, options: [
        {value:'manual',label:'Manual'},{value:'schedule',label:'Schedule'},{value:'webhook',label:'Webhook'},
        {value:'event',label:'Event'},{value:'agent',label:'Agent'}
      ]},
    ], flow, editing);

    html += self._buildSection('LLM Assignment', '#22c55e', [
      { label: 'llm_mode', id: 'fe-llm-mode', type: 'select', value: llmMode, options: [
        {value:'inherit',label:'Inherit global default'},{value:'provider',label:'Use provider default'},{value:'pinned',label:'Pin provider + model'}
      ]},
      { label: 'llm_provider', id: 'fe-llm-provider', type: 'select', value: aiConfig.provider || '', options: [
        {value:'',label:'(none)'},{value:'ollama',label:'Ollama'},{value:'claude-api',label:'Claude API'},
        {value:'claude-cli',label:'Claude CLI'},{value:'claude-code',label:'Claude Code'},{value:'codex',label:'Codex CLI'}
      ]},
      { label: 'llm_model', id: 'fe-llm-model', value: aiConfig.model || '', placeholder: 'e.g., qwen3:8b' },
    ], flow, editing);

    html += self._buildSection('Execution', 'var(--orange)', [
      { label: 'error_strategy', id: 'fe-error', type: 'select', value: flow.error_strategy, options: ['stop','skip','retry'] },
      { label: 'timeout_ms', id: 'fe-timeout', type: 'number', value: flow.timeout_ms || 120000 },
      { label: 'max_retries', id: 'fe-retries', type: 'number', value: flow.max_retries || 0 },
    ], flow, editing);

    html += self._buildSection('Metadata', 'var(--text-tertiary)', [
      { label: 'version', value: flow.version || 1, readonly: true },
      { label: 'status', id: 'fe-status', type: 'select', value: flow.status, options: ['draft','active','paused'] },
      { label: 'created', value: flow.created_at || '--', readonly: true },
      { label: 'updated', value: flow.updated_at || '--', readonly: true },
    ], flow, editing);

    html += self._buildSection('Stats', 'var(--text-tertiary)', [
      { label: 'total_runs', value: flow.total_runs || 0, readonly: true },
      { label: 'node_count', value: (flow.nodes || []).length, readonly: true },
      { label: 'edge_count', value: (flow.edges || []).length, readonly: true },
    ], flow, false);

    body.innerHTML = html;

    if (editing) {
      var modeEl = document.getElementById('fe-llm-mode');
      if (modeEl) {
        function updateVis() {
          var m = modeEl.value;
          var prov = document.getElementById('fe-llm-provider');
          var model = document.getElementById('fe-llm-model');
          if (prov && prov.parentElement) prov.parentElement.style.display = m !== 'inherit' ? '' : 'none';
          if (model && model.parentElement) model.parentElement.style.display = m === 'pinned' ? '' : 'none';
        }
        modeEl.addEventListener('change', updateVis);
        updateVis();
      }
    }
  },

  _buildSection: function(title, color, fields, item, editing) {
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
            var ov = typeof opt === 'object' ? opt.value : opt;
            var ol = typeof opt === 'object' ? opt.label : opt;
            h += '<option value="' + ov + '"' + (ov === String(val) ? ' selected' : '') + '>' + ol + '</option>';
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

  _renderExecute: function(flow, body) {
    var html = '<div style="padding:12px;border-radius:8px;background:rgba(34,211,238,0.03);border:1px solid rgba(34,211,238,0.1);">' +
      '<div class="form-label" style="color:var(--cyan);">Execute Flow</div>' +
      '<textarea class="form-textarea" id="flow-trigger-payload" rows="3" placeholder=\'{"target": "example.com"}\' style="margin-bottom:8px;font-family:monospace;"></textarea>' +
      '<button class="btn btn-primary btn-sm" id="flow-execute-btn">Execute ' + escapeHtml(flow.name) + '</button>' +
      '</div>' +
      '<div id="flow-execute-output" style="display:none;margin-top:16px;">' +
        '<div class="form-label">Execution Results</div>' +
        '<div id="flow-execute-content" class="code-block" style="max-height:400px;overflow-y:auto;white-space:pre-wrap;color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;"></div>' +
      '</div>';
    body.innerHTML = html;

    var self = this;
    document.getElementById('flow-execute-btn').addEventListener('click', function() {
      var payloadStr = document.getElementById('flow-trigger-payload').value.trim();
      var payload = {};
      if (payloadStr) {
        try { payload = JSON.parse(payloadStr); } catch { Toast.warning('Invalid JSON payload'); return; }
      }

      var btn = document.getElementById('flow-execute-btn');
      var output = document.getElementById('flow-execute-output');
      var content = document.getElementById('flow-execute-content');
      btn.disabled = true;
      btn.textContent = 'Executing...';
      output.style.display = 'block';
      content.innerHTML = '<div class="loading-state"><div class="spinner"></div><div>Running flow...</div></div>';

      fetch('/api/flows/' + flow.id + '/execute', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin', body: JSON.stringify({ trigger_payload: payload })
      })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        btn.disabled = false;
        btn.textContent = 'Execute ' + escapeHtml(flow.name);
        if (data.error) { content.textContent = 'Error: ' + data.error; content.style.borderLeft = '3px solid var(--orange)'; Toast.error(data.error); return; }
        var run = data.run || data;
        content.style.borderLeft = run.status === 'completed' ? '3px solid var(--cyan)' : '3px solid var(--orange)';
        content.style.paddingLeft = '12px';
        content.textContent = JSON.stringify(run.state || run, null, 2);
        Toast.success('Flow ' + (run.status || 'completed'));
        self.loadFlows();
      })
      .catch(function() {
        btn.disabled = false; btn.textContent = 'Execute ' + escapeHtml(flow.name);
        content.textContent = 'Flow execution failed.'; content.style.borderLeft = '3px solid var(--orange)';
        Toast.error('Flow execution failed');
      });
    });
  },

  _saveFlow: function() {
    var id = this._selectedFlowId;
    if (!id) return;
    var getVal = function(elId) { var el = document.getElementById(elId); return el ? el.value : undefined; };
    var patch = {};

    if (getVal('fe-name') !== undefined) patch.name = getVal('fe-name');
    if (getVal('fe-desc') !== undefined) patch.description = getVal('fe-desc');
    if (getVal('fe-category') !== undefined) patch.category = getVal('fe-category');
    if (getVal('fe-trigger') !== undefined) patch.trigger_type = getVal('fe-trigger');
    if (getVal('fe-error') !== undefined) patch.error_strategy = getVal('fe-error');
    if (getVal('fe-timeout') !== undefined) patch.timeout_ms = parseInt(getVal('fe-timeout'), 10);
    if (getVal('fe-retries') !== undefined) patch.max_retries = parseInt(getVal('fe-retries'), 10);
    if (getVal('fe-status') !== undefined) patch.status = getVal('fe-status');

    var llmMode = getVal('fe-llm-mode');
    if (llmMode !== undefined) {
      patch.metadata = { ai: { mode: llmMode } };
      if (llmMode !== 'inherit') patch.metadata.ai.provider = getVal('fe-llm-provider') || '';
      if (llmMode === 'pinned') patch.metadata.ai.model = getVal('fe-llm-model') || '';
    }

    var self = this;
    fetch('/api/flows/' + id, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin', body: JSON.stringify(patch)
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.error) { Toast.error(data.error); return; }
      Toast.success('Flow saved');
      self._editMode = false;
      document.getElementById('flow-edit-toggle').textContent = 'Edit';
      self.loadFlows();
      setTimeout(function() { self.showFlowDetail(id); }, 300);
    })
    .catch(function() { Toast.error('Failed to save flow'); });
  },

  _showAddNodeModal: function(flow) {
    var nodeTypes = [
      { type: 'agent', label: 'Agent', icon: '&#129302;', desc: 'Run a security agent' },
      { type: 'llm', label: 'LLM', icon: '&#129504;', desc: 'Call LLM with prompt' },
      { type: 'condition', label: 'Condition', icon: '&#9889;', desc: 'Branch on expression' },
      { type: 'http', label: 'HTTP', icon: '&#127760;', desc: 'Make HTTP request' },
      { type: 'delay', label: 'Delay', icon: '&#9201;', desc: 'Wait for duration' },
      { type: 'notify', label: 'Notify', icon: '&#128276;', desc: 'Send notification' },
    ];

    var html = '<div class="grid-3" style="gap:8px;">';
    nodeTypes.forEach(function(nt) {
      html += '<div class="glass-card node-type-card" data-type="' + nt.type + '" style="cursor:pointer;text-align:center;padding:12px;" onmouseover="this.style.borderColor=\'rgba(34,211,238,0.3)\'" onmouseout="this.style.borderColor=\'\'">' +
        '<div style="font-size:24px;margin-bottom:4px;">' + nt.icon + '</div>' +
        '<div style="font-weight:600;font-size:var(--font-size-sm);color:var(--text-primary);">' + nt.label + '</div>' +
        '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + nt.desc + '</div>' +
      '</div>';
    });
    html += '</div>';

    Modal.open({ title: 'Add Node', body: html });

    var self = this;
    document.querySelectorAll('.node-type-card').forEach(function(card) {
      card.addEventListener('click', function() {
        var type = card.getAttribute('data-type');
        Modal.close();
        self._addNode(flow, type);
      });
    });
  },

  _addNode: function(flow, type) {
    var nodeId = type + '-' + Date.now().toString(36);
    var labels = { agent: 'New Agent Node', llm: 'LLM Node', condition: 'Condition', http: 'HTTP Request', delay: 'Delay', notify: 'Notify' };
    var newNode = {
      id: nodeId, type: type,
      data: { label: labels[type] || type, config: {} },
      position: { x: 250, y: (flow.nodes || []).length * 100 },
    };

    var nodes = JSON.parse(JSON.stringify(flow.nodes || []));
    var edges = JSON.parse(JSON.stringify(flow.edges || []));

    // Insert before end node
    var endIdx = nodes.findIndex(function(n) { return n.type === 'end'; });
    if (endIdx >= 0) {
      nodes.splice(endIdx, 0, newNode);
      // Reconnect: last node before end → new node → end
      var endNode = nodes[endIdx + 1];
      var prevEdge = edges.find(function(e) { return e.target === endNode.id; });
      if (prevEdge) {
        prevEdge.target = nodeId;
        edges.push({ id: 'e-' + Date.now(), source: nodeId, target: endNode.id });
      }
    } else {
      nodes.push(newNode);
    }

    var self = this;
    fetch('/api/flows/' + flow.id, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin', body: JSON.stringify({ nodes: nodes, edges: edges })
    })
    .then(function(r) { return r.json(); })
    .then(function() {
      Toast.success('Node added');
      self.loadFlows();
      setTimeout(function() { self.showFlowDetail(flow.id); }, 300);
    });
  },

  _removeNode: function(flow, idx) {
    var nodes = JSON.parse(JSON.stringify(flow.nodes || []));
    var edges = JSON.parse(JSON.stringify(flow.edges || []));
    var removedNode = nodes[idx];
    if (!removedNode) return;

    // Reconnect edges around removed node
    var inEdges = edges.filter(function(e) { return e.target === removedNode.id; });
    var outEdges = edges.filter(function(e) { return e.source === removedNode.id; });
    edges = edges.filter(function(e) { return e.source !== removedNode.id && e.target !== removedNode.id; });

    // Connect in-sources to out-targets
    inEdges.forEach(function(ie) {
      outEdges.forEach(function(oe) {
        edges.push({ id: 'e-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6), source: ie.source, target: oe.target });
      });
    });

    nodes.splice(idx, 1);

    var self = this;
    fetch('/api/flows/' + flow.id, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin', body: JSON.stringify({ nodes: nodes, edges: edges })
    })
    .then(function(r) { return r.json(); })
    .then(function() {
      Toast.success('Node removed');
      self.loadFlows();
      setTimeout(function() { self.showFlowDetail(flow.id); }, 300);
    });
  },

  _showEditNodeModal: function(flow, idx) {
    var node = flow.nodes[idx];
    if (!node) return;
    var cfg = (node.data && node.data.config) || {};
    var html = '<div class="form-group"><label class="form-label">Label</label><input type="text" class="form-input" id="ne-label" value="' + escapeHtml(node.data.label || '') + '"></div>';

    if (node.type === 'agent') {
      html += '<div class="form-group"><label class="form-label">Agent Slug</label><input type="text" class="form-input" id="ne-agent-slug" value="' + escapeHtml(cfg.agentSlug || '') + '" placeholder="e.g., port-scanner"></div>';
      html += '<div class="form-group"><label class="form-label">Task Description</label><textarea class="form-textarea" id="ne-task-desc" rows="2">' + escapeHtml(cfg.taskDescription || '') + '</textarea></div>';
    } else if (node.type === 'llm') {
      html += '<div class="form-group"><label class="form-label">Prompt</label><textarea class="form-textarea" id="ne-prompt" rows="3">' + escapeHtml(cfg.prompt || '') + '</textarea></div>';
    } else if (node.type === 'condition') {
      html += '<div class="form-group"><label class="form-label">Expression</label><input type="text" class="form-input" id="ne-expression" value="' + escapeHtml(cfg.expression || '') + '" placeholder="state.nodeId && ..."></div>';
    } else if (node.type === 'http') {
      html += '<div class="form-group"><label class="form-label">Method</label><select class="form-select" id="ne-method"><option' + (cfg.method === 'GET' || !cfg.method ? ' selected' : '') + '>GET</option><option' + (cfg.method === 'POST' ? ' selected' : '') + '>POST</option><option' + (cfg.method === 'PUT' ? ' selected' : '') + '>PUT</option><option' + (cfg.method === 'DELETE' ? ' selected' : '') + '>DELETE</option></select></div>';
      html += '<div class="form-group"><label class="form-label">URL</label><input type="text" class="form-input" id="ne-url" value="' + escapeHtml(cfg.url || '') + '"></div>';
    } else if (node.type === 'delay') {
      html += '<div class="form-group"><label class="form-label">Delay (ms)</label><input type="number" class="form-input" id="ne-delay-ms" value="' + (cfg.ms || 1000) + '"></div>';
    } else if (node.type === 'notify') {
      html += '<div class="form-group"><label class="form-label">Message</label><textarea class="form-textarea" id="ne-message" rows="2">' + escapeHtml(cfg.message || '') + '</textarea></div>';
    }

    // LLM override for agent/llm nodes
    if (node.type === 'agent' || node.type === 'llm') {
      var nodeAi = cfg.ai || {};
      html += '<details style="margin-top:12px;"><summary style="color:var(--text-tertiary);font-size:var(--font-size-xs);cursor:pointer;">LLM Override</summary>' +
        '<div class="form-group" style="margin-top:8px;"><label class="form-label">Mode</label><select class="form-select" id="ne-llm-mode"><option value="inherit"' + (nodeAi.mode !== 'provider' && nodeAi.mode !== 'pinned' ? ' selected' : '') + '>Inherit flow default</option><option value="provider"' + (nodeAi.mode === 'provider' ? ' selected' : '') + '>Use provider default</option><option value="pinned"' + (nodeAi.mode === 'pinned' ? ' selected' : '') + '>Pin provider + model</option></select></div>' +
        '<div class="form-group"><label class="form-label">Provider</label><select class="form-select" id="ne-llm-provider"><option value="">--</option><option value="ollama"' + (nodeAi.provider === 'ollama' ? ' selected' : '') + '>Ollama</option><option value="claude-api"' + (nodeAi.provider === 'claude-api' ? ' selected' : '') + '>Claude API</option><option value="claude-cli"' + (nodeAi.provider === 'claude-cli' ? ' selected' : '') + '>Claude CLI</option></select></div>' +
        '<div class="form-group"><label class="form-label">Model</label><input type="text" class="form-input" id="ne-llm-model" value="' + escapeHtml(nodeAi.model || '') + '"></div>' +
        '</details>';
    }

    Modal.open({
      title: 'Edit Node: ' + escapeHtml(node.data.label),
      body: html,
      footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="ne-save">Apply</button>'
    });

    var self = this;
    document.getElementById('ne-save').addEventListener('click', function() {
      var nodes = JSON.parse(JSON.stringify(flow.nodes));
      var n = nodes[idx];
      n.data.label = document.getElementById('ne-label').value;

      if (node.type === 'agent') {
        n.data.config.agentSlug = (document.getElementById('ne-agent-slug') || {}).value || '';
        n.data.config.taskDescription = (document.getElementById('ne-task-desc') || {}).value || '';
      } else if (node.type === 'llm') {
        n.data.config.prompt = (document.getElementById('ne-prompt') || {}).value || '';
      } else if (node.type === 'condition') {
        n.data.config.expression = (document.getElementById('ne-expression') || {}).value || '';
      } else if (node.type === 'http') {
        n.data.config.method = (document.getElementById('ne-method') || {}).value || 'GET';
        n.data.config.url = (document.getElementById('ne-url') || {}).value || '';
      } else if (node.type === 'delay') {
        n.data.config.ms = parseInt((document.getElementById('ne-delay-ms') || {}).value || '1000', 10);
      } else if (node.type === 'notify') {
        n.data.config.message = (document.getElementById('ne-message') || {}).value || '';
      }

      // LLM override
      var llmModeEl = document.getElementById('ne-llm-mode');
      if (llmModeEl) {
        var m = llmModeEl.value;
        if (m !== 'inherit') {
          n.data.config.ai = { mode: m, provider: (document.getElementById('ne-llm-provider') || {}).value || '' };
          if (m === 'pinned') n.data.config.ai.model = (document.getElementById('ne-llm-model') || {}).value || '';
        } else {
          delete n.data.config.ai;
        }
      }

      Modal.close();
      fetch('/api/flows/' + flow.id, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin', body: JSON.stringify({ nodes: nodes })
      })
      .then(function(r) { return r.json(); })
      .then(function() {
        Toast.success('Node updated');
        self.loadFlows();
        setTimeout(function() { self.showFlowDetail(flow.id); }, 300);
      });
    });
  },

  cloneFlow: function(id) {
    var self = this;
    fetch('/api/flows/' + id + '/clone', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin', body: '{}'
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.error) { Toast.error(data.error); return; }
      Toast.success('Flow cloned');
      self.loadFlows();
    })
    .catch(function() { Toast.error('Failed to clone flow'); });
  },

  loadFlowHistory: function(flowId) {
    var container = document.getElementById('flow-history-list');
    if (!container) return;
    fetch('/api/flows/' + flowId + '/runs', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var runs = data.runs || [];
        if (runs.length === 0) { container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);">No run history yet</div>'; return; }
        var h = '<table class="data-table"><thead><tr><th>Time</th><th>Status</th><th>Trigger</th><th>Nodes</th></tr></thead><tbody>';
        runs.slice(0, 20).forEach(function(r) {
          var sc = r.status === 'completed' ? 'var(--cyan)' : 'var(--orange)';
          var nodeCount = r.state ? Object.keys(r.state).length : 0;
          h += '<tr><td>' + timeAgo(r.created_at || r.started_at) + '</td>' +
            '<td><span style="color:' + sc + ';font-weight:600;font-size:var(--font-size-xs);">' + escapeHtml(r.status) + '</span></td>' +
            '<td style="font-size:var(--font-size-xs);">' + escapeHtml(r.trigger_type || '--') + '</td>' +
            '<td style="font-size:var(--font-size-xs);">' + nodeCount + ' executed</td></tr>';
        });
        h += '</tbody></table>';
        container.innerHTML = h;
      })
      .catch(function() { container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);">Could not load history</div>'; });
  },

  showCreateModal: function() {
    Modal.open({
      title: 'Create Security Flow',
      body:
        '<div class="form-group"><label class="form-label">Flow Name</label><input type="text" class="form-input" id="flow-new-name" placeholder="e.g., Recon Pipeline"></div>' +
        '<div class="form-group"><label class="form-label">Description</label><textarea class="form-textarea" id="flow-new-desc" rows="2" placeholder="What does this flow automate?"></textarea></div>' +
        '<div class="form-group"><label class="form-label">Category</label><select class="form-select" id="flow-new-category"><option value="general">General</option><option value="recon">Recon</option><option value="appsec">AppSec</option><option value="compliance">Compliance</option><option value="remediation">Remediation</option><option value="ops">Ops</option></select></div>' +
        '<div class="form-group"><label class="form-label">Trigger Type</label><select class="form-select" id="flow-new-trigger"><option value="manual">Manual</option><option value="schedule">Schedule</option><option value="webhook">Webhook</option></select></div>' +
        '<div style="border-top:1px solid var(--border);padding-top:12px;margin-top:12px;">' +
          '<div class="form-group"><label class="form-label" style="color:#22c55e;">LLM Assignment</label>' +
            '<select class="form-select" id="flow-new-llm-mode"><option value="inherit">Inherit global default</option><option value="provider">Use provider default</option><option value="pinned">Pin provider + model</option></select></div>' +
          '<div class="form-group" id="flow-new-llm-provider-group" style="display:none;"><label class="form-label">Provider</label>' +
            '<select class="form-select" id="flow-new-llm-provider"><option value="ollama">Ollama</option><option value="claude-api">Claude API</option><option value="claude-cli">Claude CLI</option><option value="claude-code">Claude Code</option><option value="codex">Codex CLI</option></select></div>' +
          '<div class="form-group" id="flow-new-llm-model-group" style="display:none;"><label class="form-label">Pinned Model</label>' +
            '<input type="text" class="form-input" id="flow-new-llm-model" placeholder="e.g., qwen3:8b"></div>' +
        '</div>',
      footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="flow-create-confirm">Create Flow</button>'
    });

    var modeEl = document.getElementById('flow-new-llm-mode');
    modeEl.addEventListener('change', function() {
      document.getElementById('flow-new-llm-provider-group').style.display = modeEl.value !== 'inherit' ? '' : 'none';
      document.getElementById('flow-new-llm-model-group').style.display = modeEl.value === 'pinned' ? '' : 'none';
    });

    var self = this;
    document.getElementById('flow-create-confirm').addEventListener('click', function() {
      var name = document.getElementById('flow-new-name').value.trim();
      if (!name) { Toast.warning('Enter flow name'); return; }

      Modal.loading('Creating flow...');
      var body = {
        name: name,
        description: document.getElementById('flow-new-desc').value.trim(),
        category: document.getElementById('flow-new-category').value,
        trigger_type: document.getElementById('flow-new-trigger').value,
      };

      var llmMode = document.getElementById('flow-new-llm-mode').value;
      if (llmMode !== 'inherit') {
        body.metadata = { ai: { mode: llmMode, provider: document.getElementById('flow-new-llm-provider').value } };
        if (llmMode === 'pinned') body.metadata.ai.model = document.getElementById('flow-new-llm-model').value;
      }

      fetch('/api/flows', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify(body) })
      .then(function(r) { return r.json(); })
      .then(function(data) { Modal.close(); if (data.error) { Toast.error(data.error); return; } Toast.success('Flow created'); self.loadFlows(); })
      .catch(function() { Modal.close(); Toast.error('Failed to create flow'); });
    });
  }
};
