/* Vigil v1.0 — Security Agents View */
Views.agents = {
  _agents: [],
  _activeFilter: 'all',

  init: function() {
    var el = document.getElementById('view-agents');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Security Agents</div>' +
        '<button class="btn btn-primary btn-sm" id="agents-create-btn">Create Agent</button>' +
      '</div>' +

      // ── Stats ────────────────────────────────────────────────────
      '<div class="stat-grid" style="margin-bottom:16px;">' +
        '<div class="stat-card">' +
          '<div class="stat-card-label">Total Agents</div>' +
          '<div class="stat-card-value" id="agents-total">0</div>' +
        '</div>' +
        '<div class="stat-card">' +
          '<div class="stat-card-label">Scanners</div>' +
          '<div class="stat-card-value" id="agents-scanners" style="color:var(--cyan);">0</div>' +
        '</div>' +
        '<div class="stat-card">' +
          '<div class="stat-card-label">Analyzers</div>' +
          '<div class="stat-card-value" id="agents-analyzers" style="color:var(--purple);">0</div>' +
        '</div>' +
        '<div class="stat-card">' +
          '<div class="stat-card-label">Total Runs</div>' +
          '<div class="stat-card-value" id="agents-runs">0</div>' +
        '</div>' +
      '</div>' +

      // ── Filter tabs ──────────────────────────────────────────────
      '<div class="tab-bar" id="agents-filter-tabs">' +
        '<div class="tab-item active" data-filter="all">All</div>' +
        '<div class="tab-item" data-filter="scanner">Scanners</div>' +
        '<div class="tab-item" data-filter="analyzer">Analyzers</div>' +
        '<div class="tab-item" data-filter="defender">Defenders</div>' +
        '<div class="tab-item" data-filter="hunter">Hunters</div>' +
        '<div class="tab-item" data-filter="custom">Custom</div>' +
      '</div>' +

      // ── Agent grid ───────────────────────────────────────────────
      '<div id="agents-grid" class="grid-3">' +
        '<div class="loading-state"><div class="spinner"></div><div>Loading agents...</div></div>' +
      '</div>' +

      // ── Detail / Run panel ───────────────────────────────────────
      '<div id="agents-detail" class="glass-card" style="display:none;margin-top:16px;">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">' +
          '<div>' +
            '<div style="font-size:var(--font-size-lg);font-weight:600;color:var(--text-primary);" id="agent-detail-name">--</div>' +
            '<div id="agent-detail-meta" style="margin-top:4px;"></div>' +
          '</div>' +
          '<button class="btn btn-ghost btn-sm" id="agent-detail-close" style="color:var(--text-tertiary);">Close</button>' +
        '</div>' +
        '<div id="agent-detail-body"></div>' +
      '</div>';

    var self = this;
    document.getElementById('agents-create-btn').addEventListener('click', function() { self.showCreateModal(); });
    document.getElementById('agent-detail-close').addEventListener('click', function() {
      document.getElementById('agents-detail').style.display = 'none';
    });

    document.querySelectorAll('#agents-filter-tabs .tab-item').forEach(function(tab) {
      tab.addEventListener('click', function() {
        document.querySelectorAll('#agents-filter-tabs .tab-item').forEach(function(t) { t.classList.remove('active'); });
        tab.classList.add('active');
        self._activeFilter = tab.getAttribute('data-filter');
        self.renderAgents();
      });
    });
  },

  show: function() {
    this.loadAgents();
  },

  hide: function() {},

  loadAgents: function() {
    var self = this;
    fetch('/api/agents', { credentials: 'same-origin' })
      .then(function(r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function(data) {
        self._agents = data.agents || data || [];
        if (!Array.isArray(self._agents)) self._agents = [];

        // Update stats
        var totalRuns = 0;
        var scannerCount = 0, analyzerCount = 0;
        self._agents.forEach(function(a) {
          totalRuns += a.run_count || 0;
          if (a.category === 'scanner') scannerCount++;
          if (a.category === 'analyzer') analyzerCount++;
        });
        var totalEl = document.getElementById('agents-total');
        var runsEl = document.getElementById('agents-runs');
        if (typeof animateValue === 'function') {
          animateValue(totalEl, 0, self._agents.length, 400);
          animateValue(document.getElementById('agents-scanners'), 0, scannerCount, 400);
          animateValue(document.getElementById('agents-analyzers'), 0, analyzerCount, 400);
          animateValue(runsEl, 0, totalRuns, 400);
        } else {
          totalEl.textContent = self._agents.length;
          document.getElementById('agents-scanners').textContent = scannerCount;
          document.getElementById('agents-analyzers').textContent = analyzerCount;
          runsEl.textContent = totalRuns;
        }

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

      html += '<div class="glass-card agent-card" data-id="' + escapeHtml(a.id || '') + '" style="cursor:pointer;transition:border-color 0.2s;" onmouseover="this.style.borderColor=\'rgba(34,211,238,0.3)\'" onmouseout="this.style.borderColor=\'\'">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">' +
          '<span style="font-size:18px;">' + cat.icon + '</span>' +
          '<span style="flex:1;color:var(--text-primary);font-weight:600;font-size:var(--font-size-sm);">' + escapeHtml(a.name || 'Unnamed') + '</span>' +
        '</div>' +
        '<div style="display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap;">' +
          '<span class="tag ' + cat.tag + '" style="font-size:10px;">' + escapeHtml(a.category || 'custom') + '</span>' +
          '<span style="font-size:10px;color:' + riskColor + ';">' + escapeHtml(a.risk_level || '') + ' risk</span>' +
          (a.run_count > 0 ? '<span style="font-size:10px;color:var(--text-tertiary);">' + a.run_count + ' runs</span>' : '') +
        '</div>' +
        '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);line-height:1.5;margin-bottom:10px;">' + escapeHtml((a.description || '').substring(0, 100)) + '</div>' +
        '<button class="btn btn-primary btn-sm agent-quick-run" data-id="' + escapeHtml(a.id || '') + '" style="width:100%;" onclick="event.stopPropagation();">Run Agent</button>' +
      '</div>';
    });
    container.innerHTML = html;

    // Card click → detail panel
    container.querySelectorAll('.agent-card').forEach(function(card) {
      card.addEventListener('click', function(e) {
        if (e.target.classList.contains('agent-quick-run')) return;
        Views.agents.showAgentDetail(card.getAttribute('data-id'));
      });
    });

    // Quick run buttons
    container.querySelectorAll('.agent-quick-run').forEach(function(btn) {
      btn.addEventListener('click', function(e) {
        e.stopPropagation();
        Views.agents.runAgent(btn.getAttribute('data-id'));
      });
    });
  },

  showAgentDetail: function(id) {
    var agent = this._agents.find(function(a) { return a.id === id; });
    if (!agent) return;

    this._selectedAgentId = id;
    var panel = document.getElementById('agents-detail');
    panel.style.display = 'block';
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    document.getElementById('agent-detail-name').textContent = agent.name || 'Unnamed';

    var catColors = { scanner: 'tag-cyan', analyzer: 'tag-purple', defender: 'tag-cyan', hunter: '', custom: '' };
    document.getElementById('agent-detail-meta').innerHTML =
      '<span class="tag ' + (catColors[agent.category] || '') + '">' + escapeHtml(agent.category || 'custom') + '</span>' +
      (agent.risk_level ? ' <span style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-left:6px;">' + escapeHtml(agent.risk_level) + ' risk</span>' : '') +
      (agent.run_count ? ' <span style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-left:6px;">' + agent.run_count + ' runs</span>' : '');

    var body = document.getElementById('agent-detail-body');
    var html = '';

    // Description
    html += '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);margin-bottom:16px;line-height:1.6;">' + escapeHtml(agent.description || 'No description') + '</div>';

    // Quick run form (inline, no modal needed)
    html += '<div style="margin-bottom:16px;padding:12px;border-radius:8px;background:rgba(34,211,238,0.03);border:1px solid rgba(34,211,238,0.1);">' +
      '<div class="form-label" style="color:var(--cyan);">Run This Agent</div>' +
      '<textarea class="form-textarea" id="agent-inline-input" rows="3" placeholder="' + escapeHtml(agent.placeholder || 'Enter target or input for the agent...') + '" style="margin-bottom:8px;"></textarea>' +
      this._renderExampleButtons(agent, 'agent-inline-input') +
      '<button class="btn btn-primary btn-sm" id="agent-inline-run">Run ' + escapeHtml(agent.name) + '</button>' +
      '</div>';

    // Run output area
    html += '<div id="agent-run-output" style="display:none;margin-bottom:16px;">' +
      '<div class="form-label">Agent Output</div>' +
      '<div id="agent-run-output-content" class="code-block" style="max-height:400px;overflow-y:auto;white-space:pre-wrap;color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;"></div>' +
      '</div>';

    // System prompt (collapsed)
    if (agent.system_prompt) {
      html += '<details style="margin-bottom:16px;">' +
        '<summary style="color:var(--text-tertiary);font-size:var(--font-size-xs);cursor:pointer;user-select:none;">System Prompt</summary>' +
        '<div class="code-block" style="margin-top:8px;max-height:150px;overflow-y:auto;font-size:var(--font-size-xs);">' + escapeHtml(agent.system_prompt) + '</div>' +
        '</details>';
    }

    // Run history
    html += '<div><div class="form-label">Run History</div><div id="agent-history-list"><div class="loading-state"><div class="spinner spinner-sm"></div></div></div></div>';

    body.innerHTML = html;

    // Example buttons fill textarea
    this._bindExampleButtons(body, agent);

    // Inline run button
    var self = this;
    document.getElementById('agent-inline-run').addEventListener('click', function() {
      self.executeAgent(id);
    });
    // Enter key in textarea (Ctrl+Enter to run)
    document.getElementById('agent-inline-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        self.executeAgent(id);
      }
    });

    // Load run history
    this.loadAgentHistory(id);
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
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ input: input })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      btn.disabled = false;
      btn.textContent = 'Run ' + escapeHtml(agent ? agent.name : 'Agent');

      if (data.error) {
        outputContent.textContent = 'Error: ' + data.error;
        outputContent.style.borderLeft = '3px solid var(--orange)';
        Toast.error(data.error);
        return;
      }

      // Handle response — run object is nested under data.run
      var output = '';
      if (data.run) {
        output = data.run.output || 'No output';
        var duration = data.run.duration ? ' (' + (data.run.duration / 1000).toFixed(1) + 's)' : '';
        var status = data.run.status || 'completed';
        outputContent.style.borderLeft = status === 'completed' ? '3px solid var(--cyan)' : '3px solid var(--orange)';
        outputContent.style.paddingLeft = '12px';
        outputContent.textContent = output;
        Toast.success('Agent completed' + duration);
      } else {
        output = data.output || data.result || 'Agent completed.';
        outputContent.textContent = output;
        outputContent.style.borderLeft = '3px solid var(--cyan)';
        outputContent.style.paddingLeft = '12px';
        Toast.success('Agent completed');
      }

      // Refresh history and run count
      self.loadAgentHistory(id);
      self.loadAgents();
    })
    .catch(function() {
      btn.disabled = false;
      btn.textContent = 'Run ' + escapeHtml(agent ? agent.name : 'Agent');
      outputContent.textContent = 'Agent execution failed. Check server connection and AI provider settings.';
      outputContent.style.borderLeft = '3px solid var(--orange)';
      Toast.error('Agent execution failed');
    });
  },

  runAgent: function(id) {
    var agent = this._agents.find(function(a) { return a.id === id; });
    if (!agent) return;

    var self = this;
    Modal.open({
      title: 'Run: ' + (agent.name || 'Agent'),
      body:
        '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);margin-bottom:12px;">' + escapeHtml(agent.description || '') + '</div>' +
        '<div class="form-group">' +
          '<label class="form-label">Input / Target</label>' +
          '<textarea class="form-textarea" id="agent-run-input" rows="4" placeholder="' + escapeHtml(agent.placeholder || 'Enter target, paste data, or describe what to analyze...') + '"></textarea>' +
          self._renderExampleButtons(agent, 'agent-run-input') +
        '</div>',
      footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="agent-run-confirm">Run Agent</button>'
    });

    // Example buttons in modal
    self._bindExampleButtons(document.querySelector('.modal-backdrop') || document.body, agent);

    document.getElementById('agent-run-confirm').addEventListener('click', function() {
      var input = document.getElementById('agent-run-input').value.trim();
      if (!input) { Toast.warning('Enter input for the agent'); return; }

      Modal.loading(agent.name + ' analyzing...');

      fetch('/api/agents/' + id + '/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ input: input })
      })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        Modal.close();

        if (data.error) { Toast.error(data.error); return; }

        var output = data.run ? data.run.output : (data.output || data.result || 'Agent completed.');
        var duration = data.run && data.run.duration ? ' (' + (data.run.duration / 1000).toFixed(1) + 's)' : '';
        var status = data.run ? data.run.status : 'completed';

        Modal.open({
          title: agent.name + ' Results' + duration,
          body: '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;white-space:pre-wrap;max-height:500px;overflow-y:auto;' +
            (status === 'completed' ? 'border-left:3px solid var(--cyan);padding-left:12px;' : 'border-left:3px solid var(--orange);padding-left:12px;') +
            '">' + escapeHtml(output) + '</div>',
          size: 'lg'
        });
        Toast.success('Agent completed' + duration);
        self.loadAgents(); // refresh run counts
      })
      .catch(function() { Modal.close(); Toast.error('Agent execution failed'); });
    });
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
          h += '<tr>' +
            '<td>' + timeAgo(r.createdAt || r.created_at) + '</td>' +
            '<td><span style="color:' + statusColor + ';font-weight:600;font-size:var(--font-size-xs);">' + escapeHtml(r.status || 'complete') + '</span></td>' +
            '<td>' + dur + '</td>' +
            '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-tertiary);font-size:var(--font-size-xs);">' + escapeHtml((r.input || '--').substring(0, 60)) + '</td>' +
            '</tr>';
        });
        h += '</tbody></table>';
        container.innerHTML = h;
      })
      .catch(function() {
        container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);">Could not load history</div>';
      });
  },

  _renderExampleButtons: function(agent, textareaId) {
    if (!agent.examples || !agent.examples.length) return '';
    var html = '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px;align-items:center;">' +
      '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">Try:</span>';
    agent.examples.forEach(function(ex, i) {
      html += '<button class="btn btn-ghost btn-sm agent-example-btn" ' +
        'data-textarea="' + textareaId + '" data-example-idx="' + i + '" ' +
        'style="color:var(--cyan);border-color:rgba(34,211,238,0.2);font-size:10px;padding:2px 8px;">' +
        escapeHtml(ex.label) + '</button>';
    });
    html += '</div>';
    return html;
  },

  _bindExampleButtons: function(container, agent) {
    container.querySelectorAll('.agent-example-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var idx = parseInt(btn.getAttribute('data-example-idx'), 10);
        var textarea = document.getElementById(btn.getAttribute('data-textarea'));
        if (textarea && agent.examples && agent.examples[idx]) {
          textarea.value = agent.examples[idx].input;
          textarea.focus();
        }
      });
    });
  },

  showCreateModal: function() {
    Modal.open({
      title: 'Create Security Agent',
      body:
        '<div class="form-group"><label class="form-label">Agent Name</label><input type="text" class="form-input" id="agent-new-name" placeholder="e.g., API Security Tester"></div>' +
        '<div class="form-group"><label class="form-label">Category</label><select class="form-select" id="agent-new-category"><option value="scanner">Scanner</option><option value="analyzer">Analyzer</option><option value="defender">Defender</option><option value="hunter">Hunter</option><option value="custom">Custom</option></select></div>' +
        '<div class="form-group"><label class="form-label">Description</label><textarea class="form-textarea" id="agent-new-desc" rows="2" placeholder="What does this agent do? What security problem does it solve?"></textarea></div>' +
        '<div class="form-group"><label class="form-label">System Prompt <span style="color:var(--text-tertiary);font-weight:400;">(optional — auto-generated if empty)</span></label><textarea class="form-textarea" id="agent-new-prompt" rows="3" placeholder="You are a security expert specializing in..."></textarea></div>' +
        '<div class="form-group"><label class="form-label">Task Prompt <span style="color:var(--text-tertiary);font-weight:400;">(optional — use {{input}} for user input)</span></label><textarea class="form-textarea" id="agent-new-task" rows="3" placeholder="Analyze the following for security issues: {{input}}"></textarea></div>',
      footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="agent-create-confirm">Create Agent</button>'
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

      fetch('/api/agents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(body)
      })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        Modal.close();
        if (data.error) { Toast.error(data.error); return; }
        Toast.success('Agent created: ' + name);
        self.loadAgents();
      })
      .catch(function() { Modal.close(); Toast.error('Failed to create agent'); });
    });
  }
};
