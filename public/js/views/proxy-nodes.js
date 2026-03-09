/* Vigil v1.0 — Proxy Nodes View (Ephemeral Infrastructure) */
Views['proxy-nodes'] = {
  _status: null,
  _health: null,

  init: function() {
    var el = document.getElementById('view-proxy-nodes');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Proxy Nodes</div>' +
        '<div style="display:flex;gap:8px;">' +
          '<button class="btn btn-ghost btn-sm" id="proxy-sync-btn">Sync</button>' +
          '<button class="btn btn-ghost btn-sm" id="proxy-refresh-btn">Refresh</button>' +
        '</div>' +
      '</div>' +

      '<div class="stat-grid" style="margin-bottom:16px;">' +
        '<div class="stat-card"><div class="stat-card-label">Nodes</div><div class="stat-card-value" id="proxy-stat-nodes">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Active Tunnels</div><div class="stat-card-value" id="proxy-stat-tunnels" style="color:var(--cyan);">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Exit IP</div><div class="stat-card-value" id="proxy-stat-ip" style="font-size:var(--font-size-sm);">--</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">gh CLI</div><div class="stat-card-value" id="proxy-stat-gh" style="font-size:var(--font-size-sm);">--</div></div>' +
      '</div>' +

      '<div id="proxy-prereqs" class="glass-card" style="margin-bottom:16px;"></div>' +

      '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">' +
          '<div style="font-size:var(--font-size-base);font-weight:600;color:var(--text-primary);">Active Nodes</div>' +
          '<button class="btn btn-ghost btn-sm" id="proxy-create-btn" style="color:var(--cyan);">+ Create Node</button>' +
        '</div>' +
        '<div id="proxy-nodes-list">' +
          '<div class="loading-state"><div class="spinner"></div><div>Loading...</div></div>' +
        '</div>' +
      '</div>' +

      '<div class="glass-card">' +
        '<div style="font-size:var(--font-size-base);font-weight:600;color:var(--text-primary);margin-bottom:12px;">AI Infrastructure Planner</div>' +
        '<div style="margin-bottom:12px;">' +
          '<textarea class="form-input" id="proxy-ai-input" rows="3" placeholder="Describe your engagement... e.g. \'Web application pentest of 5 subdomains on example.com, authorized scope includes port scanning, vulnerability scanning, and web application testing\'" style="width:100%;resize:vertical;"></textarea>' +
        '</div>' +
        '<div style="display:flex;gap:8px;margin-bottom:12px;">' +
          '<button class="btn btn-ghost btn-sm" id="proxy-ai-plan-btn" style="color:var(--cyan);">Plan Infrastructure</button>' +
        '</div>' +
        '<div id="proxy-ai-result"></div>' +
      '</div>';

    var self = this;
    document.getElementById('proxy-refresh-btn').addEventListener('click', function() { self.show(); });
    document.getElementById('proxy-sync-btn').addEventListener('click', function() { self.syncNodes(); });
    document.getElementById('proxy-create-btn').addEventListener('click', function() { self.createNode(); });
    document.getElementById('proxy-ai-plan-btn').addEventListener('click', function() { self.aiPlan(); });

    // Socket.IO updates
    if (window.socket) {
      window.socket.on('proxy_node_update', function() { self.loadStatus(); });
    }
  },

  show: function() {
    this.checkHealth();
    this.loadStatus();
  },

  hide: function() {},

  checkHealth: function() {
    var self = this;
    fetch('/api/proxy-nodes/health', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        self._health = data;
        self.renderPrereqs(data);
        self.renderHealthStats(data);
      })
      .catch(function() {
        self.renderPrereqs({ gh: { installed: false }, auth: { authenticated: false }, proxyListening: false });
      });
  },

  loadStatus: function() {
    var self = this;
    fetch('/api/proxy-nodes', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        self._status = data;
        document.getElementById('proxy-stat-nodes').textContent = data.totalNodes || 0;
        document.getElementById('proxy-stat-tunnels').textContent = data.activeTunnelCount || 0;

        // Show exit IP from first tunneled node
        var tunneledNode = (data.nodes || []).find(function(n) { return n.exitIP; });
        document.getElementById('proxy-stat-ip').textContent = tunneledNode ? tunneledNode.exitIP : '--';

        self.renderNodes(data);
      })
      .catch(function() {
        document.getElementById('proxy-nodes-list').innerHTML =
          '<div class="empty-state"><div class="empty-state-icon">&#128752;</div><div class="empty-state-title">Unable to load</div></div>';
      });
  },

  renderHealthStats: function(data) {
    var ghEl = document.getElementById('proxy-stat-gh');
    if (data.gh && data.gh.installed) {
      ghEl.textContent = data.auth && data.auth.authenticated ? data.auth.user || 'Authenticated' : 'Not Authed';
      ghEl.style.color = data.auth && data.auth.authenticated ? 'var(--cyan)' : 'var(--orange)';
    } else {
      ghEl.textContent = 'Not Installed';
      ghEl.style.color = 'var(--text-tertiary)';
    }
  },

  renderPrereqs: function(data) {
    var el = document.getElementById('proxy-prereqs');
    var ghOk = data.gh && data.gh.installed;
    var authOk = data.auth && data.auth.authenticated;

    var html = '<div style="font-size:var(--font-size-base);font-weight:600;color:var(--text-primary);margin-bottom:10px;">Prerequisites</div>';

    // gh CLI
    html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">' +
      '<span style="color:' + (ghOk ? 'var(--cyan)' : 'var(--orange)') + ';">' + (ghOk ? '&#10003;' : '&#10007;') + '</span>' +
      '<span style="color:var(--text-secondary);">gh CLI: ' + (ghOk ? escapeHtml(data.gh.version) : 'Not installed') + '</span>' +
    '</div>';

    // Auth
    html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">' +
      '<span style="color:' + (authOk ? 'var(--cyan)' : 'var(--orange)') + ';">' + (authOk ? '&#10003;' : '&#10007;') + '</span>' +
      '<span style="color:var(--text-secondary);">GitHub Auth: ' + (authOk ? escapeHtml(data.auth.user || 'authenticated') : 'Not authenticated') + '</span>' +
    '</div>';

    // Proxy health
    html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">' +
      '<span style="color:' + (data.proxyListening ? 'var(--cyan)' : 'var(--text-tertiary)') + ';">' + (data.proxyListening ? '&#10003;' : '&#8226;') + '</span>' +
      '<span style="color:var(--text-secondary);">SOCKS5 Proxy: ' + (data.proxyListening ? 'Listening on :1080' : 'No active tunnel') + '</span>' +
    '</div>';

    if (!ghOk) {
      html += '<div style="margin-top:10px;padding:10px;border-radius:6px;background:rgba(255,107,43,0.08);border:1px solid rgba(255,107,43,0.15);color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.6;">' +
        '<strong style="color:var(--orange);">Setup Required</strong><br>' +
        '1. Install GitHub CLI: <code style="color:var(--cyan);">curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg</code><br>' +
        '2. Authenticate: <code style="color:var(--cyan);">gh auth login</code><br>' +
        '3. Verify: <code style="color:var(--cyan);">gh auth status</code><br>' +
        '<span style="color:var(--text-tertiary);">Codespaces use GitHub\'s free tier (120 core-hours/month). Each node provides a unique disposable exit IP for anonymous scanning.</span>' +
      '</div>';
    } else if (!authOk) {
      html += '<div style="margin-top:10px;padding:10px;border-radius:6px;background:rgba(255,107,43,0.08);border:1px solid rgba(255,107,43,0.15);color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.8;">' +
        '<strong style="color:var(--orange);">Authentication Required</strong><br>' +
        'Enter a GitHub Personal Access Token with <code style="color:var(--cyan);">codespace</code> scope.' +
        '<div style="display:flex;gap:8px;margin-top:8px;align-items:center;">' +
          '<input type="password" id="proxy-gh-token" class="form-input" placeholder="ghp_xxxxxxxxxxxxxxxxxxxx" style="flex:1;font-family:var(--font-mono);font-size:var(--font-size-xs);">' +
          '<button class="btn btn-primary btn-sm" id="proxy-auth-btn">Authenticate</button>' +
        '</div>' +
        '<div style="margin-top:6px;color:var(--text-tertiary);font-size:var(--font-size-xs);">Create a token at <a href="https://github.com/settings/tokens" target="_blank" rel="noopener" style="color:var(--cyan);">github.com/settings/tokens</a> &mdash; needs <strong>codespace</strong> scope (or classic token with <strong>codespace</strong> checkbox).</div>' +
      '</div>';
    }

    el.innerHTML = html;

    // Bind auth button if present
    var authBtn = document.getElementById('proxy-auth-btn');
    if (authBtn) {
      var self = this;
      authBtn.addEventListener('click', function() {
        var tokenInput = document.getElementById('proxy-gh-token');
        var token = tokenInput ? tokenInput.value.trim() : '';
        if (!token) { Toast.warning('Paste your GitHub token first'); return; }
        authBtn.disabled = true;
        authBtn.textContent = 'Authenticating...';
        fetch('/api/proxy-nodes/auth', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ token: token }),
        })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          if (data.error) {
            Toast.error(data.error);
            authBtn.disabled = false;
            authBtn.textContent = 'Authenticate';
          } else {
            Toast.success('Authenticated as ' + (data.auth && data.auth.user ? data.auth.user : 'GitHub user'));
            self.show();
          }
        })
        .catch(function(e) {
          Toast.error('Auth failed: ' + e.message);
          authBtn.disabled = false;
          authBtn.textContent = 'Authenticate';
        });
      });
    }
  },

  renderNodes: function(data) {
    var container = document.getElementById('proxy-nodes-list');
    var nodes = data.nodes || [];

    if (nodes.length === 0) {
      container.innerHTML =
        '<div class="empty-state">' +
          '<div class="empty-state-icon">&#128752;</div>' +
          '<div class="empty-state-title">No Proxy Nodes</div>' +
          '<div class="empty-state-desc">Create a disposable Codespace node to get an anonymous exit IP for scanning</div>' +
        '</div>';
      return;
    }

    var html = '<table class="data-table"><thead><tr>' +
      '<th>Name</th><th>State</th><th>Repository</th><th>Exit IP</th><th>Port</th><th>Actions</th>' +
    '</tr></thead><tbody>';

    nodes.forEach(function(n) {
      var stateColor = 'var(--text-tertiary)';
      if (n.state === 'Tunneled') stateColor = 'var(--cyan)';
      else if (n.state === 'Available') stateColor = 'var(--text-secondary)';
      else if (n.state === 'Connecting') stateColor = 'var(--orange)';

      html += '<tr>' +
        '<td style="color:var(--text-primary);font-family:var(--font-mono);">' + escapeHtml(n.name || '--') + '</td>' +
        '<td><span class="tag" style="color:' + stateColor + ';">' + escapeHtml(n.state || 'Unknown') + '</span></td>' +
        '<td style="color:var(--text-secondary);">' + escapeHtml(n.repository || '--') + '</td>' +
        '<td style="color:var(--cyan);font-family:var(--font-mono);">' + escapeHtml(n.exitIP || '--') + '</td>' +
        '<td>' + (n.tunnelPort ? ':' + n.tunnelPort : '--') + '</td>' +
        '<td style="display:flex;gap:4px;">';

      if (n.state === 'Tunneled' || n.state === 'Connecting') {
        html += '<button class="btn btn-ghost btn-sm proxy-action" data-action="stop-tunnel" data-name="' + escapeHtml(n.name) + '" style="color:var(--orange);">Disconnect</button>';
      } else if (n.state === 'Available') {
        html += '<button class="btn btn-ghost btn-sm proxy-action" data-action="tunnel" data-name="' + escapeHtml(n.name) + '" style="color:var(--cyan);">Connect</button>';
        html += '<button class="btn btn-ghost btn-sm proxy-action" data-action="stop" data-name="' + escapeHtml(n.name) + '">Stop</button>';
      } else if (n.state === 'Stopped' || n.state === 'Shutdown') {
        html += '<button class="btn btn-ghost btn-sm proxy-action" data-action="start" data-name="' + escapeHtml(n.name) + '" style="color:var(--cyan);">Start</button>';
      }
      html += '<button class="btn btn-ghost btn-sm proxy-action" data-action="delete" data-name="' + escapeHtml(n.name) + '" style="color:var(--orange);">&#128465;</button>';
      html += '</td></tr>';
    });

    html += '</tbody></table>';
    container.innerHTML = html;

    // Bind actions
    var self = this;
    container.querySelectorAll('.proxy-action').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var action = btn.getAttribute('data-action');
        var name = btn.getAttribute('data-name');
        self.nodeAction(action, name);
      });
    });
  },

  nodeAction: function(action, name) {
    var self = this;
    var method = 'POST';
    var url = '/api/proxy-nodes/' + encodeURIComponent(name);
    var body = null;

    switch (action) {
      case 'tunnel':
        url += '/tunnel';
        body = JSON.stringify({ port: 1080 });
        Modal.loading('Starting SOCKS5 tunnel...');
        break;
      case 'stop-tunnel':
        url += '/tunnel';
        method = 'DELETE';
        break;
      case 'start':
        url += '/start';
        Modal.loading('Starting Codespace...');
        break;
      case 'stop':
        url += '/stop';
        break;
      case 'delete':
        if (!confirm('Delete proxy node ' + name + '? This cannot be undone.')) return;
        method = 'DELETE';
        break;
    }

    fetch(url, {
      method: method,
      headers: body ? { 'Content-Type': 'application/json' } : {},
      credentials: 'same-origin',
      body: body,
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      Modal.close();
      if (data.error) {
        Toast.error(data.error);
      } else {
        Toast.success(action.replace(/-/g, ' ') + ' completed');
        self.loadStatus();
      }
    })
    .catch(function(e) {
      Modal.close();
      Toast.error('Action failed: ' + e.message);
    });
  },

  createNode: function() {
    var self = this;

    Modal.open({
      title: 'Create Proxy Node',
      body:
        '<div style="margin-bottom:12px;">' +
          '<label class="form-label">Repository (Codespace source)</label>' +
          '<input type="text" class="form-input" id="proxy-create-repo" value="github/codespaces-blank" placeholder="github/codespaces-blank">' +
        '</div>' +
        '<div style="margin-bottom:12px;">' +
          '<label class="form-label">Machine Type</label>' +
          '<select class="form-select" id="proxy-create-machine">' +
            '<option value="basicLinux32gb">Basic (2-core, 8GB RAM)</option>' +
            '<option value="standardLinux32gb">Standard (4-core, 16GB RAM)</option>' +
          '</select>' +
        '</div>' +
        '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);line-height:1.5;">' +
          'Creates a disposable GitHub Codespace with a unique exit IP. Uses your GitHub free-tier allocation (120 core-hours/month). Node is ephemeral — delete after use to rotate IP.' +
        '</div>',
      footer:
        '<button class="btn btn-ghost btn-sm" onclick="Modal.close()">Cancel</button>' +
        '<button class="btn btn-ghost btn-sm" id="proxy-create-confirm" style="color:var(--cyan);">Create Node</button>',
    });

    document.getElementById('proxy-create-confirm').addEventListener('click', function() {
      var repo = document.getElementById('proxy-create-repo').value.trim() || 'github/codespaces-blank';
      var machine = document.getElementById('proxy-create-machine').value;
      Modal.loading('Creating Codespace node... (may take 30-90s)');

      fetch('/api/proxy-nodes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ repo: repo, machineType: machine }),
      })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        Modal.close();
        if (data.error) {
          Toast.error(data.error);
        } else {
          Toast.success('Proxy node created: ' + (data.name || 'OK'));
          self.loadStatus();
        }
      })
      .catch(function(e) {
        Modal.close();
        Toast.error('Creation failed: ' + e.message);
      });
    });
  },

  syncNodes: function() {
    var self = this;
    Toast.info('Syncing with GitHub...');
    fetch('/api/proxy-nodes/sync', { method: 'POST', credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.error) {
          Toast.error(data.error);
        } else {
          Toast.success('Synced ' + (data.nodes || []).length + ' node(s)');
          self.loadStatus();
        }
      })
      .catch(function() { Toast.error('Sync failed'); });
  },

  aiPlan: function() {
    var engagement = document.getElementById('proxy-ai-input').value.trim();
    if (!engagement) { Toast.warning('Describe your engagement first'); return; }

    var resultEl = document.getElementById('proxy-ai-result');
    resultEl.innerHTML = '<div class="loading-state"><div class="spinner"></div><div>AI planning infrastructure...</div></div>';

    fetch('/api/proxy-nodes/ai-plan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ engagement: engagement }),
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.error) {
        resultEl.innerHTML = '<div style="color:var(--orange);">' + escapeHtml(data.error) + '</div>';
        return;
      }
      resultEl.innerHTML = Views['proxy-nodes'].renderAIPlan(data);
    })
    .catch(function(e) {
      resultEl.innerHTML = '<div style="color:var(--orange);">AI planning failed: ' + escapeHtml(e.message) + '</div>';
    });
  },

  renderAIPlan: function(plan) {
    var html = '<div style="border:1px solid var(--border);border-radius:8px;padding:16px;margin-top:8px;">';

    // Summary stats
    html += '<div style="display:flex;gap:16px;margin-bottom:16px;flex-wrap:wrap;">';
    if (plan.nodeCount) {
      html += '<div style="text-align:center;"><div style="font-size:var(--font-size-xl);color:var(--cyan);font-weight:700;">' + plan.nodeCount + '</div><div style="font-size:var(--font-size-xs);color:var(--text-tertiary);">Nodes</div></div>';
    }
    if (plan.rotationMinutes) {
      html += '<div style="text-align:center;"><div style="font-size:var(--font-size-xl);color:var(--cyan);font-weight:700;">' + plan.rotationMinutes + 'm</div><div style="font-size:var(--font-size-xs);color:var(--text-tertiary);">Rotation</div></div>';
    }
    if (plan.scanStrategy) {
      html += '<div style="text-align:center;"><div style="font-size:var(--font-size-xl);color:var(--text-primary);font-weight:700;">' + escapeHtml(plan.scanStrategy) + '</div><div style="font-size:var(--font-size-xs);color:var(--text-tertiary);">Strategy</div></div>';
    }
    if (plan.opsecLevel) {
      var opsecColor = plan.opsecLevel === 'high' ? 'var(--orange)' : plan.opsecLevel === 'medium' ? 'var(--cyan)' : 'var(--text-secondary)';
      html += '<div style="text-align:center;"><div style="font-size:var(--font-size-xl);font-weight:700;color:' + opsecColor + ';">' + escapeHtml(plan.opsecLevel) + '</div><div style="font-size:var(--font-size-xs);color:var(--text-tertiary);">OPSEC</div></div>';
    }
    if (plan.estimatedDuration) {
      html += '<div style="text-align:center;"><div style="font-size:var(--font-size-xl);color:var(--text-primary);font-weight:700;">' + escapeHtml(plan.estimatedDuration) + '</div><div style="font-size:var(--font-size-xs);color:var(--text-tertiary);">Duration</div></div>';
    }
    html += '</div>';

    // Scan phases
    if (plan.scanPhases && plan.scanPhases.length) {
      html += '<div style="margin-bottom:12px;"><div style="font-size:var(--font-size-sm);font-weight:600;color:var(--text-primary);margin-bottom:6px;">Scan Phases</div>';
      plan.scanPhases.forEach(function(phase, i) {
        var proxyBadge = phase.useProxy
          ? '<span class="tag" style="color:var(--cyan);font-size:var(--font-size-xs);">&#128752; via proxy</span>'
          : '<span class="tag" style="color:var(--text-tertiary);font-size:var(--font-size-xs);">direct</span>';
        html += '<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);">' +
          '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);width:20px;">' + (i + 1) + '</span>' +
          '<span style="color:var(--text-primary);min-width:100px;">' + escapeHtml(phase.phase || '') + '</span>' +
          '<span class="badge" style="font-size:var(--font-size-xs);">' + escapeHtml(phase.scanType || '') + '</span>' +
          proxyBadge +
          '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-left:auto;">' + escapeHtml(phase.reason || '') + '</span>' +
        '</div>';
      });
      html += '</div>';
    }

    // Recommendations
    if (plan.recommendations && plan.recommendations.length) {
      html += '<div style="margin-bottom:12px;"><div style="font-size:var(--font-size-sm);font-weight:600;color:var(--cyan);margin-bottom:4px;">Recommendations</div>';
      plan.recommendations.forEach(function(r) {
        html += '<div style="padding:3px 0;color:var(--text-secondary);font-size:var(--font-size-sm);">&#8226; ' + escapeHtml(r) + '</div>';
      });
      html += '</div>';
    }

    // Risks
    if (plan.risks && plan.risks.length) {
      html += '<div><div style="font-size:var(--font-size-sm);font-weight:600;color:var(--orange);margin-bottom:4px;">Risks</div>';
      plan.risks.forEach(function(r) {
        html += '<div style="padding:3px 0;color:var(--text-secondary);font-size:var(--font-size-sm);">&#9888; ' + escapeHtml(r) + '</div>';
      });
      html += '</div>';
    }

    html += '</div>';
    return html;
  }
};
