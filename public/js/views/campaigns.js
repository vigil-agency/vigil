/* Vigil v1.0 — Campaigns + Purple Team Simulator (Decepticon-inspired) */
Views.campaigns = {
  _tab: 'campaigns',
  _simulations: [],
  _activeSim: null,

  init: function() {
    var el = document.getElementById('view-campaigns');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Campaigns & Purple Team</div>' +
        '<div style="display:flex;gap:8px;">' +
          '<button class="btn btn-primary btn-sm" id="campaign-launch-btn">Launch Campaign</button>' +
          '<button class="btn btn-ghost btn-sm" id="campaign-refresh">Refresh</button>' +
        '</div>' +
      '</div>' +

      '<div class="tab-bar" id="camp-tabs">' +
        '<div class="tab-item active" data-tab="campaigns">Campaigns</div>' +
        '<div class="tab-item" data-tab="purple">Purple Team</div>' +
      '</div>' +

      /* ── Campaigns Tab ── */
      '<div id="camp-tab-campaigns">' +
        '<div class="glass-card" style="margin-bottom:20px;">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Active Campaigns</div>' +
          '<div id="campaigns-active"><div class="loading-state"><div class="spinner"></div><div>Loading...</div></div></div>' +
        '</div>' +
        '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Past Campaigns</div>' +
          '<div id="campaigns-past"><div class="empty-state"><div class="empty-state-icon">&#127919;</div><div class="empty-state-title">No Past Campaigns</div></div></div>' +
        '</div>' +
      '</div>' +

      /* ── Purple Team Tab ── */
      '<div id="camp-tab-purple" style="display:none;">' +
        '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Purple Team Simulator</div>' +
          '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);margin-bottom:16px;">AI-driven attack-defense gap analysis through MITRE ATT&CK kill chain. Simulates realistic attack scenarios and evaluates defensive coverage.</div>' +
          '<div class="form-group"><label class="form-label">Target Description</label><input type="text" class="form-input" id="pt-sim-target" placeholder="e.g., Production web application on AWS with React frontend and Node.js API"></div>' +
          '<div style="display:flex;gap:12px;">' +
            '<div class="form-group" style="flex:1;"><label class="form-label">Scope</label><input type="text" class="form-input" id="pt-sim-scope" placeholder="e.g., External-facing services only"></div>' +
            '<div class="form-group" style="flex:1;"><label class="form-label">Threat Scenario</label><select class="form-select" id="pt-sim-scenario">' +
              '<option value="external-attacker">External Threat Actor</option>' +
              '<option value="insider-threat">Insider Threat</option>' +
              '<option value="ransomware">Ransomware Operator</option>' +
              '<option value="apt">APT / Nation-State</option>' +
              '<option value="supply-chain">Supply Chain Attack</option>' +
            '</select></div>' +
          '</div>' +
          '<div class="form-group"><label class="form-label">Known Defenses (optional)</label><textarea class="form-textarea" id="pt-sim-defenses" rows="2" placeholder="e.g., WAF, EDR, SIEM, MFA enabled, network segmentation..."></textarea></div>' +
          '<button class="btn btn-danger btn-sm" id="pt-sim-launch">Run Simulation</button>' +
        '</div>' +

        '<div id="pt-sim-progress" style="display:none;" class="glass-card" style="margin-bottom:16px;">' +
          '<div style="display:flex;align-items:center;gap:12px;">' +
            '<div class="spinner"></div>' +
            '<div><div style="color:var(--text-primary);font-weight:600;">Simulation Running</div>' +
            '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);" id="pt-sim-status">Initializing...</div></div>' +
          '</div>' +
        '</div>' +

        '<div id="pt-sim-results"></div>' +

        '<div class="glass-card" style="margin-top:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Past Simulations</div>' +
          '<div id="pt-sim-history"><div class="empty-state"><div class="empty-state-icon">&#129302;</div><div class="empty-state-title">No Simulations Yet</div></div></div>' +
        '</div>' +
      '</div>';

    var self = this;

    // Tab switching
    document.querySelectorAll('#camp-tabs .tab-item').forEach(function(t) {
      t.addEventListener('click', function() {
        document.querySelectorAll('#camp-tabs .tab-item').forEach(function(x) { x.classList.remove('active'); });
        t.classList.add('active');
        self._tab = t.getAttribute('data-tab');
        document.getElementById('camp-tab-campaigns').style.display = self._tab === 'campaigns' ? 'block' : 'none';
        document.getElementById('camp-tab-purple').style.display = self._tab === 'purple' ? 'block' : 'none';
      });
    });

    document.getElementById('campaign-launch-btn').addEventListener('click', this.showLaunchModal.bind(this));
    document.getElementById('campaign-refresh').addEventListener('click', function() { self.show(); });
    document.getElementById('pt-sim-launch').addEventListener('click', function() { self._launchSimulation(); });

    // Socket.IO
    if (window.socket) {
      window.socket.on('purple_team_progress', function(data) {
        document.getElementById('pt-sim-status').textContent = data.message || data.phase || 'Running...';
      });
      window.socket.on('purple_team_complete', function(data) {
        document.getElementById('pt-sim-progress').style.display = 'none';
        if (data.status === 'completed') {
          Toast.success('Purple Team simulation complete — Grade: ' + (data.grade || '?'));
          self._loadSimulation(data.id);
          self._loadSimHistory();
        } else {
          Toast.error('Simulation failed');
        }
      });
    }
  },

  show: function() {
    this.loadCampaigns();
    this._loadSimHistory();
  },

  hide: function() {},

  // ═══════════════════════════════════════════════════════════════════════
  // CAMPAIGNS (existing)
  // ═══════════════════════════════════════════════════════════════════════

  loadCampaigns: function() {
    var activeContainer = document.getElementById('campaigns-active');
    var pastContainer = document.getElementById('campaigns-past');

    fetch('/api/campaigns', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var campaigns = data.campaigns || data || [];
        if (!Array.isArray(campaigns)) campaigns = [];

        var active = campaigns.filter(function(c) { return c.status === 'running' || c.status === 'active'; });
        var past = campaigns.filter(function(c) { return c.status !== 'running' && c.status !== 'active'; });

        if (active.length === 0) {
          activeContainer.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#127919;</div><div class="empty-state-title">No Active Campaigns</div><div class="empty-state-desc">Launch a campaign to begin multi-agent security operations</div></div>';
        } else {
          var html = '';
          active.forEach(function(c) {
            var progress = c.progress || 0;
            html += '<div class="glass-card" style="margin-bottom:8px;">' +
              '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">' +
                '<span style="color:var(--text-primary);font-weight:600;flex:1;">' + escapeHtml(c.goal || c.name || 'Campaign') + '</span>' +
                '<span class="badge badge-success">Running</span>' +
              '</div>' +
              '<div class="progress-bar"><div class="progress-bar-fill" style="width:' + progress + '%;"></div></div>' +
              '<div style="display:flex;justify-content:space-between;margin-top:6px;font-size:var(--font-size-xs);color:var(--text-tertiary);">' +
                '<span>' + (c.agents_complete || 0) + '/' + (c.agents_total || 0) + ' agents</span>' +
                '<span>' + progress + '%</span>' +
              '</div>' +
              '<div style="margin-top:8px;"><button class="btn btn-ghost btn-sm campaign-detail-btn" data-id="' + escapeHtml(c.id || '') + '">View Details</button></div>' +
            '</div>';
          });
          activeContainer.innerHTML = html;
        }

        if (past.length === 0) {
          pastContainer.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#127919;</div><div class="empty-state-title">No Past Campaigns</div></div>';
        } else {
          var html2 = '<table class="data-table"><thead><tr><th>Goal</th><th>Status</th><th>Agents</th><th>Time</th></tr></thead><tbody>';
          past.forEach(function(c) {
            html2 += '<tr class="clickable campaign-detail-btn" data-id="' + escapeHtml(c.id || '') + '">' +
              '<td style="color:var(--text-primary);">' + escapeHtml((c.goal || c.name || '--').substring(0, 60)) + '</td>' +
              '<td><span class="tag">' + escapeHtml(c.status || 'complete') + '</span></td>' +
              '<td>' + (c.agentCount || 0) + '</td>' +
              '<td>' + timeAgo(c.createdAt) + '</td>' +
              '</tr>';
          });
          html2 += '</tbody></table>';
          pastContainer.innerHTML = html2;
        }

        document.querySelectorAll('.campaign-detail-btn').forEach(function(btn) {
          btn.addEventListener('click', function() { Views.campaigns.showDetail(btn.getAttribute('data-id')); });
        });
      })
      .catch(function() {
        activeContainer.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#127919;</div><div class="empty-state-title">No Campaigns</div></div>';
      });
  },

  showLaunchModal: function() {
    Modal.open({
      title: 'Launch Campaign',
      body:
        '<div class="form-group"><label class="form-label">Campaign Goal</label><textarea class="form-textarea" id="campaign-goal" rows="3" placeholder="Describe the campaign goal..."></textarea></div>' +
        '<div class="form-group"><label class="form-label">Max Agents</label><input type="range" id="campaign-agents" min="1" max="10" value="3" style="width:100%;accent-color:var(--cyan);"><div style="display:flex;justify-content:space-between;font-size:var(--font-size-xs);color:var(--text-tertiary);"><span>1</span><span id="campaign-agents-val">3</span><span>10</span></div></div>',
      footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="campaign-launch-confirm">Launch</button>'
    });

    var slider = document.getElementById('campaign-agents');
    var valEl = document.getElementById('campaign-agents-val');
    slider.addEventListener('input', function() { valEl.textContent = slider.value; });

    document.getElementById('campaign-launch-confirm').addEventListener('click', function() {
      var goal = document.getElementById('campaign-goal').value.trim();
      if (!goal) { Toast.warning('Enter a campaign goal'); return; }
      var maxAgents = parseInt(document.getElementById('campaign-agents').value);

      Modal.loading('Launching campaign...');
      fetch('/api/campaigns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ goal: goal, max_agents: maxAgents })
      })
      .then(function() { Modal.close(); Toast.success('Campaign launched'); Views.campaigns.loadCampaigns(); })
      .catch(function() { Modal.close(); Toast.error('Failed to launch campaign'); });
    });
  },

  showDetail: function(id) {
    Modal.loading('Loading campaign details...');
    fetch('/api/campaigns/' + id, { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        Modal.close();
        var runs = data.runs || [];
        var runsHtml = '';
        if (Array.isArray(runs) && runs.length > 0) {
          runsHtml = '<table class="data-table"><thead><tr><th>Agent</th><th>Status</th><th>Summary</th></tr></thead><tbody>';
          runs.forEach(function(r) {
            runsHtml += '<tr><td style="color:var(--text-primary);">' + escapeHtml(r.agentName || '--') + '</td><td><span class="tag">' + escapeHtml(r.status || '--') + '</span></td><td>' + escapeHtml((r.output || '--').substring(0, 100)) + '</td></tr>';
          });
          runsHtml += '</tbody></table>';
        } else {
          runsHtml = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">No agent runs yet</div>';
        }

        Modal.open({
          title: 'Campaign Details',
          body:
            '<div class="detail-row"><div class="detail-label">Goal</div><div class="detail-value">' + escapeHtml(data.goal || '--') + '</div></div>' +
            '<div class="detail-row"><div class="detail-label">Status</div><div class="detail-value"><span class="tag">' + escapeHtml(data.status || '--') + '</span></div></div>' +
            '<div style="margin-top:16px;"><div class="form-label">Agent Runs</div>' + runsHtml + '</div>',
          size: 'lg'
        });
      })
      .catch(function() { Modal.close(); Toast.error('Failed to load campaign'); });
  },

  // ═══════════════════════════════════════════════════════════════════════
  // PURPLE TEAM SIMULATOR
  // ═══════════════════════════════════════════════════════════════════════

  _launchSimulation: function() {
    var target = document.getElementById('pt-sim-target').value.trim();
    if (!target) { Toast.warning('Enter a target description'); return; }

    var scope = document.getElementById('pt-sim-scope').value.trim();
    var scenario = document.getElementById('pt-sim-scenario').value;
    var defenses = document.getElementById('pt-sim-defenses').value.trim();

    var progressEl = document.getElementById('pt-sim-progress');
    progressEl.style.display = 'block';
    document.getElementById('pt-sim-status').textContent = 'Initializing...';
    document.getElementById('pt-sim-results').innerHTML = '';

    fetch('/api/campaigns/purple-team', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ target: target, scope: scope, scenario: scenario, defenses: defenses })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.error) { progressEl.style.display = 'none'; Toast.error(data.error); return; }
      Toast.info('Purple Team simulation started (ID: ' + (data.id || '').substring(0, 8) + ')');
    })
    .catch(function() { progressEl.style.display = 'none'; Toast.error('Failed to launch simulation'); });
  },

  _loadSimulation: function(id) {
    var self = this;
    fetch('/api/campaigns/purple-team/' + id, { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(sim) {
        if (sim.status === 'completed' && sim.result) {
          self._activeSim = sim;
          self._renderSimResults(sim);
        }
      })
      .catch(function() {});
  },

  _loadSimHistory: function() {
    var self = this;
    fetch('/api/campaigns/purple-team', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        self._simulations = data.simulations || [];
        self._renderSimHistory();
      })
      .catch(function() {});
  },

  _renderSimHistory: function() {
    var container = document.getElementById('pt-sim-history');
    if (this._simulations.length === 0) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#129302;</div><div class="empty-state-title">No Simulations Yet</div><div class="empty-state-desc">Run a purple team simulation above</div></div>';
      return;
    }

    var self = this;
    var html = '<table class="data-table"><thead><tr><th>Target</th><th>Scenario</th><th>Grade</th><th>Score</th><th>Status</th><th>Time</th></tr></thead><tbody>';
    this._simulations.forEach(function(s) {
      var gradeColor = (s.grade === 'A' || s.grade === 'B') ? 'var(--cyan)' : (s.grade === 'D' || s.grade === 'F') ? 'var(--orange)' : 'var(--text-secondary)';
      html += '<tr class="clickable pt-sim-row" data-id="' + escapeHtml(s.id) + '">' +
        '<td style="color:var(--text-primary);">' + escapeHtml((s.target || '--').substring(0, 40)) + '</td>' +
        '<td>' + escapeHtml(s.scenario || '--') + '</td>' +
        '<td style="color:' + gradeColor + ';font-weight:600;font-size:var(--font-size-lg);">' + escapeHtml(s.grade || '--') + '</td>' +
        '<td>' + (s.score || 0) + '%</td>' +
        '<td><span class="tag">' + escapeHtml(s.status || '--') + '</span></td>' +
        '<td>' + timeAgo(s.createdAt) + '</td>' +
        '</tr>';
    });
    html += '</tbody></table>';
    container.innerHTML = html;

    container.querySelectorAll('.pt-sim-row').forEach(function(row) {
      row.addEventListener('click', function() {
        self._loadSimulation(row.getAttribute('data-id'));
      });
    });
  },

  _renderSimResults: function(sim) {
    var r = sim.result;
    var container = document.getElementById('pt-sim-results');
    var s = r.summary;

    var gradeColor = (s.grade === 'A' || s.grade === 'B') ? 'var(--cyan)' : (s.grade === 'D' || s.grade === 'F') ? 'var(--orange)' : 'var(--text-secondary)';
    var riskColor = s.overallRisk >= 70 ? 'var(--orange)' : s.overallRisk >= 40 ? 'var(--text-secondary)' : 'var(--cyan)';

    var html =
      /* Score cards */
      '<div class="stat-grid" style="margin-bottom:16px;">' +
        '<div class="stat-card"><div class="stat-card-label">Defense Grade</div><div class="stat-card-value" style="color:' + gradeColor + ';font-size:32px;">' + escapeHtml(s.grade) + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Defense Score</div><div class="stat-card-value" style="color:' + gradeColor + ';">' + s.defenseScore + '%</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Overall Risk</div><div class="stat-card-value" style="color:' + riskColor + ';">' + s.overallRisk + '%</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Avg Detection</div><div class="stat-card-value">' + s.avgDetection + '%</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Avg Prevention</div><div class="stat-card-value">' + s.avgPrevention + '%</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Tactics Analyzed</div><div class="stat-card-value" style="color:var(--cyan);">' + s.tacticsAnalyzed + '</div></div>' +
      '</div>';

    /* ATT&CK Coverage Heatmap */
    html += '<div class="glass-card" style="margin-bottom:16px;">' +
      '<div class="glass-card-title" style="margin-bottom:12px;">MITRE ATT&CK Coverage Heatmap</div>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;">';

    (r.tactics || []).forEach(function(t) {
      var det = t.defense?.detection || 0;
      var prev = t.defense?.prevention || 0;
      var score = Math.round((det + prev) / 2);
      var bg = score >= 60 ? 'rgba(34,211,238,0.15)' : score >= 35 ? 'rgba(255,107,43,0.08)' : 'rgba(255,107,43,0.2)';
      var border = score >= 60 ? 'var(--cyan)' : score >= 35 ? 'var(--text-tertiary)' : 'var(--orange)';
      var riskBadge = t.risk === 'critical' ? 'badge-danger' : t.risk === 'high' ? 'badge-warning' : t.risk === 'medium' ? '' : 'badge-success';

      html += '<div style="background:' + bg + ';border:1px solid ' + border + ';border-radius:8px;padding:10px;cursor:pointer;" class="pt-tactic-card" data-id="' + escapeHtml(t.id) + '">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">' +
          '<div style="font-size:var(--font-size-xs);color:var(--text-tertiary);">' + escapeHtml(t.id) + '</div>' +
          '<span class="badge ' + riskBadge + '" style="font-size:10px;">' + escapeHtml(t.risk || 'medium') + '</span>' +
        '</div>' +
        '<div style="font-size:var(--font-size-sm);color:var(--text-primary);font-weight:600;margin-bottom:6px;">' + escapeHtml(t.name) + '</div>' +
        '<div style="display:flex;gap:8px;font-size:var(--font-size-xs);">' +
          '<span style="color:var(--cyan);">Det: ' + det + '%</span>' +
          '<span style="color:var(--orange);">Prev: ' + prev + '%</span>' +
        '</div>' +
      '</div>';
    });
    html += '</div></div>';

    /* Attack path */
    if (r.attackPath) {
      html += '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-title" style="margin-bottom:8px;">Most Likely Attack Path</div>' +
        '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.6;border-left:3px solid var(--orange);padding-left:12px;">' + escapeHtml(r.attackPath) + '</div>' +
      '</div>';
    }

    /* Critical gaps */
    if (r.criticalGaps && r.criticalGaps.length > 0) {
      html += '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-title" style="margin-bottom:8px;">Critical Gaps</div>';
      r.criticalGaps.forEach(function(gap, i) {
        html += '<div style="display:flex;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);">' +
          '<span style="color:var(--orange);font-weight:600;min-width:20px;">' + (i + 1) + '</span>' +
          '<span style="color:var(--text-secondary);font-size:var(--font-size-sm);">' + escapeHtml(gap) + '</span>' +
        '</div>';
      });
      html += '</div>';
    }

    /* Recommendations */
    if (r.recommendations && r.recommendations.length > 0) {
      html += '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-title" style="margin-bottom:8px;">Prioritized Recommendations</div>' +
        '<table class="data-table"><thead><tr><th>#</th><th>Action</th><th>Impact</th><th>Effort</th></tr></thead><tbody>';
      r.recommendations.forEach(function(rec) {
        var impactColor = rec.impact === 'high' ? 'var(--orange)' : rec.impact === 'medium' ? 'var(--text-secondary)' : 'var(--text-tertiary)';
        html += '<tr>' +
          '<td style="color:var(--cyan);font-weight:600;">' + (rec.priority || '-') + '</td>' +
          '<td style="color:var(--text-primary);">' + escapeHtml(rec.action || '--') + '</td>' +
          '<td style="color:' + impactColor + ';">' + escapeHtml(rec.impact || '--') + '</td>' +
          '<td>' + escapeHtml(rec.effort || '--') + '</td>' +
        '</tr>';
      });
      html += '</tbody></table></div>';
    }

    /* Detailed tactics table */
    html += '<div class="glass-card">' +
      '<div class="glass-card-title" style="margin-bottom:8px;">Detailed Tactic Analysis</div>' +
      '<table class="data-table"><thead><tr><th>Tactic</th><th>Technique</th><th>Likelihood</th><th>Detection</th><th>Prevention</th><th>Risk</th></tr></thead><tbody>';
    (r.tactics || []).forEach(function(t) {
      var riskColor = t.risk === 'critical' ? 'var(--orange)' : t.risk === 'high' ? 'var(--orange)' : t.risk === 'medium' ? 'var(--text-secondary)' : 'var(--cyan)';
      html += '<tr class="clickable pt-tactic-row" data-id="' + escapeHtml(t.id) + '">' +
        '<td style="color:var(--text-primary);">' + escapeHtml(t.name) + '</td>' +
        '<td style="font-size:var(--font-size-xs);">' + escapeHtml((t.attack?.technique || '--').substring(0, 50)) + '</td>' +
        '<td>' + (t.attack?.likelihood || 0) + '%</td>' +
        '<td style="color:var(--cyan);">' + (t.defense?.detection || 0) + '%</td>' +
        '<td style="color:var(--cyan);">' + (t.defense?.prevention || 0) + '%</td>' +
        '<td style="color:' + riskColor + ';font-weight:600;">' + escapeHtml(t.risk || '--') + '</td>' +
      '</tr>';
    });
    html += '</tbody></table></div>';

    container.innerHTML = html;

    // Tactic click -> detail modal
    var self = this;
    container.querySelectorAll('.pt-tactic-card, .pt-tactic-row').forEach(function(el) {
      el.addEventListener('click', function() {
        var tacticId = el.getAttribute('data-id');
        self._showTacticDetail(tacticId);
      });
    });
  },

  _showTacticDetail: function(tacticId) {
    if (!this._activeSim || !this._activeSim.result) return;
    var tactic = (this._activeSim.result.tactics || []).find(function(t) { return t.id === tacticId; });
    if (!tactic) return;

    var det = tactic.defense?.detection || 0;
    var prev = tactic.defense?.prevention || 0;

    var body = '<div class="detail-row"><div class="detail-label">MITRE ID</div><div class="detail-value" style="color:var(--cyan);">' + escapeHtml(tactic.id) + '</div></div>' +
      '<div class="detail-row"><div class="detail-label">Tactic</div><div class="detail-value">' + escapeHtml(tactic.name) + '</div></div>' +
      '<div class="detail-row"><div class="detail-label">Risk Level</div><div class="detail-value"><span class="badge ' + (tactic.risk === 'critical' || tactic.risk === 'high' ? 'badge-danger' : '') + '">' + escapeHtml(tactic.risk || '--') + '</span></div></div>';

    body += '<div style="margin-top:16px;color:var(--text-primary);font-weight:600;">Attack Scenario</div>' +
      '<div class="detail-row"><div class="detail-label">Technique</div><div class="detail-value" style="color:var(--orange);">' + escapeHtml(tactic.attack?.technique || '--') + '</div></div>' +
      '<div class="detail-row"><div class="detail-label">Scenario</div><div class="detail-value">' + escapeHtml(tactic.attack?.scenario || '--') + '</div></div>' +
      '<div class="detail-row"><div class="detail-label">Likelihood</div><div class="detail-value">' + (tactic.attack?.likelihood || 0) + '%</div></div>';

    body += '<div style="margin-top:16px;color:var(--text-primary);font-weight:600;">Defense Evaluation</div>' +
      '<div class="detail-row"><div class="detail-label">Detection</div><div class="detail-value" style="color:var(--cyan);">' + det + '%</div></div>' +
      '<div class="detail-row"><div class="detail-label">Prevention</div><div class="detail-value" style="color:var(--cyan);">' + prev + '%</div></div>';

    if (tactic.defense?.controls && tactic.defense.controls.length > 0) {
      body += '<div style="margin-top:8px;color:var(--text-primary);font-weight:600;font-size:var(--font-size-sm);">Existing Controls</div>';
      tactic.defense.controls.forEach(function(c) {
        body += '<div style="padding:3px 0;font-size:var(--font-size-sm);color:var(--cyan);">+ ' + escapeHtml(c) + '</div>';
      });
    }

    if (tactic.defense?.gaps && tactic.defense.gaps.length > 0) {
      body += '<div style="margin-top:8px;color:var(--text-primary);font-weight:600;font-size:var(--font-size-sm);">Gaps</div>';
      tactic.defense.gaps.forEach(function(g) {
        body += '<div style="padding:3px 0;font-size:var(--font-size-sm);color:var(--orange);">- ' + escapeHtml(g) + '</div>';
      });
    }

    Modal.open({ title: tactic.id + ' — ' + tactic.name, body: body, size: 'lg' });
  }
};
