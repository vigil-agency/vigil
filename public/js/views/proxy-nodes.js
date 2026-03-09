/* Vigil v1.0 — Proxy Nodes View (Ephemeral Infrastructure)
 * 3 tabs: Proxy Nodes (Codespace SOCKS5) | Tunnels (pgrok-inspired SSH) | Callback Listener (OOB detection)
 */
Views['proxy-nodes'] = {
  _status: null,
  _health: null,
  _tab: 'nodes',
  _tunnels: null,
  _callbackStatus: null,
  _callbackLog: [],

  init: function() {
    var el = document.getElementById('view-proxy-nodes');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Proxy Nodes</div>' +
        '<div style="display:flex;gap:8px;">' +
          '<button class="btn btn-ghost btn-sm" id="proxy-refresh-btn">Refresh</button>' +
        '</div>' +
      '</div>' +

      // Stat grid
      '<div class="stat-grid" style="margin-bottom:16px;">' +
        '<div class="stat-card"><div class="stat-card-label">Proxy Nodes</div><div class="stat-card-value" id="proxy-stat-nodes">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">SSH Tunnels</div><div class="stat-card-value" id="proxy-stat-tunnels" style="color:var(--cyan);">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Callback</div><div class="stat-card-value" id="proxy-stat-callback" style="font-size:var(--font-size-sm);">Off</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">gh CLI</div><div class="stat-card-value" id="proxy-stat-gh" style="font-size:var(--font-size-sm);">--</div></div>' +
      '</div>' +

      // Tab bar
      '<div class="tab-bar" style="margin-bottom:16px;">' +
        '<button class="tab-btn active" data-tab="nodes">Proxy Nodes</button>' +
        '<button class="tab-btn" data-tab="tunnels">SSH Tunnels</button>' +
        '<button class="tab-btn" data-tab="callback">Callback Listener</button>' +
      '</div>' +

      // Tab content
      '<div id="proxy-tab-nodes"></div>' +
      '<div id="proxy-tab-tunnels" style="display:none;"></div>' +
      '<div id="proxy-tab-callback" style="display:none;"></div>';

    var self = this;
    document.getElementById('proxy-refresh-btn').addEventListener('click', function() { self.show(); });

    // Tab switching
    el.querySelectorAll('.tab-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        el.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
        self._tab = btn.getAttribute('data-tab');
        document.getElementById('proxy-tab-nodes').style.display = self._tab === 'nodes' ? '' : 'none';
        document.getElementById('proxy-tab-tunnels').style.display = self._tab === 'tunnels' ? '' : 'none';
        document.getElementById('proxy-tab-callback').style.display = self._tab === 'callback' ? '' : 'none';
        self._loadTab();
      });
    });

    // Socket.IO
    if (window.socket) {
      window.socket.on('proxy_node_update', function() { self._loadProxyNodes(); });
      window.socket.on('tunnel_update', function() { self._loadTunnels(); });
      window.socket.on('callback_update', function() { self._loadCallback(); });
    }
  },

  show: function() {
    this._checkHealth();
    this._loadTab();
  },
  hide: function() {},

  _loadTab: function() {
    if (this._tab === 'nodes') { this._initNodesTab(); this._loadProxyNodes(); }
    else if (this._tab === 'tunnels') { this._initTunnelsTab(); this._loadTunnels(); }
    else if (this._tab === 'callback') { this._initCallbackTab(); this._loadCallback(); }
  },

  _checkHealth: function() {
    var self = this;
    fetch('/api/proxy-nodes/health', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        self._health = data;
        var ghEl = document.getElementById('proxy-stat-gh');
        if (data.gh && data.gh.installed) {
          ghEl.textContent = data.auth && data.auth.authenticated ? data.auth.user || 'OK' : 'No Auth';
          ghEl.style.color = data.auth && data.auth.authenticated ? 'var(--cyan)' : 'var(--orange)';
        } else {
          ghEl.textContent = 'N/A';
          ghEl.style.color = 'var(--text-tertiary)';
        }
      }).catch(function() {});
  },

  // ════════════════════════════════════════════════════════════════════════
  // TAB 1: PROXY NODES (Codespace SOCKS5)
  // ════════════════════════════════════════════════════════════════════════

  _initNodesTab: function() {
    var container = document.getElementById('proxy-tab-nodes');
    if (container.getAttribute('data-init')) return;
    container.setAttribute('data-init', '1');

    container.innerHTML =
      '<div id="proxy-prereqs" class="glass-card" style="margin-bottom:16px;"></div>' +
      '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">' +
          '<div style="font-size:var(--font-size-base);font-weight:600;color:var(--text-primary);">Active Nodes</div>' +
          '<div style="display:flex;gap:8px;">' +
            '<button class="btn btn-ghost btn-sm" id="proxy-sync-btn">Sync</button>' +
            '<button class="btn btn-ghost btn-sm" id="proxy-create-btn" style="color:var(--cyan);">+ Create Node</button>' +
          '</div>' +
        '</div>' +
        '<div id="proxy-nodes-list"><div class="loading-state"><div class="spinner"></div></div></div>' +
      '</div>' +
      '<div class="glass-card">' +
        '<div style="font-size:var(--font-size-base);font-weight:600;color:var(--text-primary);margin-bottom:12px;">AI Infrastructure Planner</div>' +
        '<textarea class="form-input" id="proxy-ai-input" rows="3" placeholder="Describe your engagement..." style="width:100%;resize:vertical;margin-bottom:8px;"></textarea>' +
        '<button class="btn btn-ghost btn-sm" id="proxy-ai-plan-btn" style="color:var(--cyan);margin-bottom:8px;">Plan Infrastructure</button>' +
        '<div id="proxy-ai-result"></div>' +
      '</div>';

    var self = this;
    document.getElementById('proxy-sync-btn').addEventListener('click', function() { self._syncNodes(); });
    document.getElementById('proxy-create-btn').addEventListener('click', function() { self._createNode(); });
    document.getElementById('proxy-ai-plan-btn').addEventListener('click', function() { self._aiPlan(); });
  },

  _loadProxyNodes: function() {
    var self = this;
    fetch('/api/proxy-nodes', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        self._status = data;
        document.getElementById('proxy-stat-nodes').textContent = data.totalNodes || 0;
        self._renderNodes(data);
      }).catch(function() {});

    // Prereqs
    if (this._health) this._renderPrereqs(this._health);
    else this._checkHealth();
  },

  _renderPrereqs: function(data) {
    var el = document.getElementById('proxy-prereqs');
    if (!el) return;
    var ghOk = data.gh && data.gh.installed;
    var authOk = data.auth && data.auth.authenticated;
    var html = '<div style="font-size:var(--font-size-sm);font-weight:600;color:var(--text-primary);margin-bottom:8px;">Prerequisites</div>';
    html += '<div style="display:flex;gap:16px;flex-wrap:wrap;">';
    html += '<span style="color:' + (ghOk ? 'var(--cyan)' : 'var(--orange)') + ';font-size:var(--font-size-xs);">' + (ghOk ? '&#10003;' : '&#10007;') + ' gh CLI</span>';
    html += '<span style="color:' + (authOk ? 'var(--cyan)' : 'var(--orange)') + ';font-size:var(--font-size-xs);">' + (authOk ? '&#10003;' : '&#10007;') + ' GitHub Auth</span>';
    html += '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">&#8226; SSH client required for tunnels</span>';
    html += '</div>';

    if (!authOk && ghOk) {
      html += '<div style="margin-top:8px;display:flex;gap:8px;align-items:center;">' +
        '<input type="password" id="proxy-gh-token" class="form-input" placeholder="ghp_xxxxxxxxxxxxxxxxxxxx" style="flex:1;font-family:var(--font-mono);font-size:var(--font-size-xs);">' +
        '<button class="btn btn-primary btn-sm" id="proxy-auth-btn">Authenticate</button>' +
      '</div>';
    }
    el.innerHTML = html;

    var authBtn = document.getElementById('proxy-auth-btn');
    if (authBtn) {
      var self = this;
      authBtn.addEventListener('click', function() {
        var token = document.getElementById('proxy-gh-token').value.trim();
        if (!token) { Toast.warning('Paste your GitHub token first'); return; }
        authBtn.disabled = true; authBtn.textContent = 'Authenticating...';
        fetch('/api/proxy-nodes/auth', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ token: token }) })
          .then(function(r) { return r.json(); })
          .then(function(d) { if (d.error) { Toast.error(d.error); authBtn.disabled = false; authBtn.textContent = 'Authenticate'; } else { Toast.success('Authenticated'); self.show(); } })
          .catch(function() { authBtn.disabled = false; authBtn.textContent = 'Authenticate'; });
      });
    }
  },

  _renderNodes: function(data) {
    var container = document.getElementById('proxy-nodes-list');
    if (!container) return;
    var nodes = data.nodes || [];
    if (nodes.length === 0) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128752;</div><div class="empty-state-title">No Proxy Nodes</div><div class="empty-state-desc">Create a disposable Codespace for anonymous scanning</div></div>';
      return;
    }
    var html = '<table class="data-table"><thead><tr><th>Name</th><th>State</th><th>Exit IP</th><th>Port</th><th>Actions</th></tr></thead><tbody>';
    nodes.forEach(function(n) {
      var sc = n.state === 'Tunneled' ? 'var(--cyan)' : n.state === 'Available' ? 'var(--text-secondary)' : 'var(--text-tertiary)';
      html += '<tr><td style="font-family:var(--font-mono);">' + escapeHtml(n.name || '--') + '</td>' +
        '<td><span class="tag" style="color:' + sc + ';">' + escapeHtml(n.state || '?') + '</span></td>' +
        '<td style="color:var(--cyan);font-family:var(--font-mono);">' + escapeHtml(n.exitIP || '--') + '</td>' +
        '<td>' + (n.tunnelPort ? ':' + n.tunnelPort : '--') + '</td><td style="display:flex;gap:4px;">';
      if (n.state === 'Tunneled' || n.state === 'Connecting') html += '<button class="btn btn-ghost btn-sm proxy-action" data-action="stop-tunnel" data-name="' + escapeHtml(n.name) + '" style="color:var(--orange);">Disconnect</button>';
      else if (n.state === 'Available') html += '<button class="btn btn-ghost btn-sm proxy-action" data-action="tunnel" data-name="' + escapeHtml(n.name) + '" style="color:var(--cyan);">Connect</button><button class="btn btn-ghost btn-sm proxy-action" data-action="stop" data-name="' + escapeHtml(n.name) + '">Stop</button>';
      else if (n.state === 'Stopped' || n.state === 'Shutdown') html += '<button class="btn btn-ghost btn-sm proxy-action" data-action="start" data-name="' + escapeHtml(n.name) + '" style="color:var(--cyan);">Start</button>';
      html += '<button class="btn btn-ghost btn-sm proxy-action" data-action="delete" data-name="' + escapeHtml(n.name) + '" style="color:var(--orange);">&#128465;</button></td></tr>';
    });
    html += '</tbody></table>';
    container.innerHTML = html;
    var self = this;
    container.querySelectorAll('.proxy-action').forEach(function(btn) {
      btn.addEventListener('click', function() { self._nodeAction(btn.getAttribute('data-action'), btn.getAttribute('data-name')); });
    });
  },

  _nodeAction: function(action, name) {
    var self = this; var method = 'POST'; var url = '/api/proxy-nodes/' + encodeURIComponent(name); var body = null;
    if (action === 'tunnel') { url += '/tunnel'; body = JSON.stringify({ port: 1080 }); Modal.loading('Starting SOCKS5 tunnel...'); }
    else if (action === 'stop-tunnel') { url += '/tunnel'; method = 'DELETE'; }
    else if (action === 'start') { url += '/start'; Modal.loading('Starting Codespace...'); }
    else if (action === 'stop') { url += '/stop'; }
    else if (action === 'delete') { if (!confirm('Delete ' + name + '?')) return; method = 'DELETE'; }
    fetch(url, { method: method, headers: body ? { 'Content-Type': 'application/json' } : {}, credentials: 'same-origin', body: body })
      .then(function(r) { return r.json(); }).then(function(d) { Modal.close(); if (d.error) Toast.error(d.error); else { Toast.success(action.replace(/-/g, ' ') + ' done'); self._loadProxyNodes(); } })
      .catch(function(e) { Modal.close(); Toast.error(e.message); });
  },

  _createNode: function() {
    var self = this;
    Modal.open({ title: 'Create Proxy Node', body:
      '<div class="form-group"><label class="form-label">Repository</label><input type="text" class="form-input" id="proxy-create-repo" value="github/codespaces-blank"></div>' +
      '<div class="form-group"><label class="form-label">Machine</label><select class="form-select" id="proxy-create-machine"><option value="basicLinux32gb">Basic (2c/8GB)</option><option value="standardLinux32gb">Standard (4c/16GB)</option></select></div>',
      footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="proxy-create-go">Create</button>' });
    document.getElementById('proxy-create-go').addEventListener('click', function() {
      Modal.loading('Creating Codespace...');
      fetch('/api/proxy-nodes', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
        body: JSON.stringify({ repo: document.getElementById('proxy-create-repo').value.trim() || 'github/codespaces-blank', machineType: document.getElementById('proxy-create-machine').value }) })
        .then(function(r) { return r.json(); }).then(function(d) { Modal.close(); if (d.error) Toast.error(d.error); else { Toast.success('Created: ' + (d.name || 'OK')); self._loadProxyNodes(); } })
        .catch(function(e) { Modal.close(); Toast.error(e.message); });
    });
  },

  _syncNodes: function() {
    Toast.info('Syncing...');
    var self = this;
    fetch('/api/proxy-nodes/sync', { method: 'POST', credentials: 'same-origin' })
      .then(function(r) { return r.json(); }).then(function(d) { if (d.error) Toast.error(d.error); else { Toast.success('Synced ' + (d.nodes || []).length + ' node(s)'); self._loadProxyNodes(); } })
      .catch(function() { Toast.error('Sync failed'); });
  },

  _aiPlan: function() {
    var engagement = document.getElementById('proxy-ai-input').value.trim();
    if (!engagement) { Toast.warning('Describe your engagement'); return; }
    var el = document.getElementById('proxy-ai-result');
    el.innerHTML = '<div class="loading-state"><div class="spinner"></div><div>AI planning...</div></div>';
    fetch('/api/proxy-nodes/ai-plan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ engagement: engagement }) })
      .then(function(r) { return r.json(); }).then(function(d) { if (d.error) el.innerHTML = '<div style="color:var(--orange);">' + escapeHtml(d.error) + '</div>'; else el.innerHTML = Views['proxy-nodes']._renderAIPlan(d); })
      .catch(function(e) { el.innerHTML = '<div style="color:var(--orange);">' + escapeHtml(e.message) + '</div>'; });
  },

  _renderAIPlan: function(plan) {
    var html = '<div style="border:1px solid var(--border);border-radius:8px;padding:16px;margin-top:8px;">';
    html += '<div style="display:flex;gap:16px;margin-bottom:16px;flex-wrap:wrap;">';
    if (plan.nodeCount) html += '<div style="text-align:center;"><div style="font-size:var(--font-size-xl);color:var(--cyan);font-weight:700;">' + plan.nodeCount + '</div><div style="font-size:var(--font-size-xs);color:var(--text-tertiary);">Nodes</div></div>';
    if (plan.rotationMinutes) html += '<div style="text-align:center;"><div style="font-size:var(--font-size-xl);color:var(--cyan);font-weight:700;">' + plan.rotationMinutes + 'm</div><div style="font-size:var(--font-size-xs);color:var(--text-tertiary);">Rotation</div></div>';
    if (plan.scanStrategy) html += '<div style="text-align:center;"><div style="font-size:var(--font-size-xl);color:var(--text-primary);font-weight:700;">' + escapeHtml(plan.scanStrategy) + '</div><div style="font-size:var(--font-size-xs);color:var(--text-tertiary);">Strategy</div></div>';
    if (plan.opsecLevel) { var oc = plan.opsecLevel === 'high' ? 'var(--orange)' : 'var(--cyan)'; html += '<div style="text-align:center;"><div style="font-size:var(--font-size-xl);font-weight:700;color:' + oc + ';">' + escapeHtml(plan.opsecLevel) + '</div><div style="font-size:var(--font-size-xs);color:var(--text-tertiary);">OPSEC</div></div>'; }
    html += '</div>';
    if (plan.scanPhases && plan.scanPhases.length) { html += '<div style="margin-bottom:12px;"><div style="font-size:var(--font-size-sm);font-weight:600;color:var(--text-primary);margin-bottom:6px;">Phases</div>'; plan.scanPhases.forEach(function(p, i) { html += '<div style="display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid var(--border);font-size:var(--font-size-xs);"><span style="color:var(--text-tertiary);width:16px;">' + (i+1) + '</span><span style="color:var(--text-primary);min-width:80px;">' + escapeHtml(p.phase) + '</span><span class="badge">' + escapeHtml(p.scanType || '') + '</span><span style="color:' + (p.useProxy ? 'var(--cyan)' : 'var(--text-tertiary)') + ';">' + (p.useProxy ? 'proxy' : 'direct') + '</span><span style="color:var(--text-tertiary);margin-left:auto;">' + escapeHtml(p.reason || '') + '</span></div>'; }); html += '</div>'; }
    if (plan.recommendations && plan.recommendations.length) { html += '<div style="margin-bottom:8px;"><div style="font-size:var(--font-size-sm);font-weight:600;color:var(--cyan);margin-bottom:4px;">Recommendations</div>'; plan.recommendations.forEach(function(r) { html += '<div style="padding:2px 0;color:var(--text-secondary);font-size:var(--font-size-xs);">&#8226; ' + escapeHtml(r) + '</div>'; }); html += '</div>'; }
    if (plan.risks && plan.risks.length) { html += '<div><div style="font-size:var(--font-size-sm);font-weight:600;color:var(--orange);margin-bottom:4px;">Risks</div>'; plan.risks.forEach(function(r) { html += '<div style="padding:2px 0;color:var(--text-secondary);font-size:var(--font-size-xs);">&#9888; ' + escapeHtml(r) + '</div>'; }); html += '</div>'; }
    return html + '</div>';
  },

  // ════════════════════════════════════════════════════════════════════════
  // TAB 2: SSH TUNNELS (pgrok-inspired)
  // ════════════════════════════════════════════════════════════════════════

  _initTunnelsTab: function() {
    var container = document.getElementById('proxy-tab-tunnels');
    if (container.getAttribute('data-init')) return;
    container.setAttribute('data-init', '1');

    container.innerHTML =
      '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">' +
          '<div style="font-size:var(--font-size-base);font-weight:600;color:var(--text-primary);">SSH Tunnels</div>' +
          '<button class="btn btn-ghost btn-sm" id="tunnel-create-btn" style="color:var(--cyan);">+ New Tunnel</button>' +
        '</div>' +
        '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-bottom:12px;">Create SSH tunnels to expose services (reverse), access remote ports (forward), or create SOCKS5 proxies (dynamic). Auto-reconnects with exponential backoff.</div>' +
        '<div id="tunnel-list"><div class="loading-state"><div class="spinner spinner-sm"></div></div></div>' +
      '</div>' +

      '<div class="glass-card">' +
        '<div style="font-size:var(--font-size-sm);font-weight:600;color:var(--text-primary);margin-bottom:8px;">Tunnel Types</div>' +
        '<div style="display:flex;gap:12px;flex-wrap:wrap;">' +
          '<div style="flex:1;min-width:180px;padding:10px;border:1px solid var(--border);border-radius:6px;">' +
            '<div style="color:var(--cyan);font-weight:600;font-size:var(--font-size-xs);margin-bottom:4px;">Forward (-L)</div>' +
            '<div style="color:var(--text-tertiary);font-size:10px;line-height:1.5;">Access a remote service through a local port. E.g., reach internal DB at remote:5432 via localhost:5432.</div>' +
          '</div>' +
          '<div style="flex:1;min-width:180px;padding:10px;border:1px solid var(--border);border-radius:6px;">' +
            '<div style="color:var(--orange);font-weight:600;font-size:var(--font-size-xs);margin-bottom:4px;">Reverse (-R)</div>' +
            '<div style="color:var(--text-tertiary);font-size:10px;line-height:1.5;">Expose a local service through a remote server. E.g., make localhost:4100 reachable at vps:8080.</div>' +
          '</div>' +
          '<div style="flex:1;min-width:180px;padding:10px;border:1px solid var(--border);border-radius:6px;">' +
            '<div style="color:var(--text-primary);font-weight:600;font-size:var(--font-size-xs);margin-bottom:4px;">Dynamic (-D)</div>' +
            '<div style="color:var(--text-tertiary);font-size:10px;line-height:1.5;">Create a SOCKS5 proxy through a remote server for anonymous browsing and scanning.</div>' +
          '</div>' +
        '</div>' +
      '</div>';

    var self = this;
    document.getElementById('tunnel-create-btn').addEventListener('click', function() { self._createTunnel(); });
  },

  _loadTunnels: function() {
    var self = this;
    fetch('/api/proxy-nodes/tunnels', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        self._tunnels = data;
        var el = document.getElementById('proxy-stat-tunnels');
        el.textContent = data.connectedCount || 0;
        el.style.color = (data.connectedCount || 0) > 0 ? 'var(--cyan)' : 'var(--text-tertiary)';
        self._renderTunnels(data);
      }).catch(function() {});
  },

  _renderTunnels: function(data) {
    var container = document.getElementById('tunnel-list');
    if (!container) return;
    var tunnels = data.tunnels || [];
    if (tunnels.length === 0) {
      container.innerHTML = '<div class="empty-state" style="padding:24px 0;"><div class="empty-state-icon">&#128268;</div><div class="empty-state-title">No Active Tunnels</div><div class="empty-state-desc">Create an SSH tunnel to get started</div></div>';
      return;
    }
    var html = '<table class="data-table"><thead><tr><th>Type</th><th>Spec</th><th>SSH Target</th><th>Status</th><th>Reconnects</th><th>Actions</th></tr></thead><tbody>';
    tunnels.forEach(function(t) {
      var typeColor = t.type === 'reverse' ? 'var(--orange)' : t.type === 'forward' ? 'var(--cyan)' : 'var(--text-primary)';
      var statusColor = t.status === 'connected' ? 'var(--cyan)' : t.status === 'connecting' || t.status === 'reconnecting' ? 'var(--orange)' : 'var(--text-tertiary)';
      html += '<tr>' +
        '<td><span class="tag" style="color:' + typeColor + ';font-weight:600;">' + escapeHtml(t.type) + '</span></td>' +
        '<td style="font-family:var(--font-mono);font-size:var(--font-size-xs);color:var(--text-primary);">' + escapeHtml(t.spec) + '</td>' +
        '<td style="font-family:var(--font-mono);font-size:var(--font-size-xs);">' + escapeHtml(t.sshTarget) + '</td>' +
        '<td><span style="color:' + statusColor + ';font-weight:600;font-size:var(--font-size-xs);">' + escapeHtml(t.status) + '</span>' +
          (t.error ? '<div style="color:var(--orange);font-size:10px;">' + escapeHtml(t.error.substring(0, 60)) + '</div>' : '') + '</td>' +
        '<td style="text-align:center;">' + (t.reconnectCount || 0) + '</td>' +
        '<td><button class="btn btn-ghost btn-sm tunnel-stop" data-id="' + escapeHtml(t.id) + '" style="color:var(--orange);">Stop</button></td>' +
      '</tr>';
    });
    html += '</tbody></table>';
    container.innerHTML = html;
    var self = this;
    container.querySelectorAll('.tunnel-stop').forEach(function(btn) {
      btn.addEventListener('click', function() { self._stopTunnel(btn.getAttribute('data-id')); });
    });
  },

  _createTunnel: function() {
    var self = this;
    Modal.open({ title: 'Create SSH Tunnel', body:
      '<div class="form-group"><label class="form-label">Tunnel Type</label>' +
        '<select class="form-select" id="tunnel-type"><option value="forward">Forward (-L) — access remote port locally</option><option value="reverse">Reverse (-R) — expose local port remotely</option><option value="dynamic">Dynamic (-D) — SOCKS5 proxy</option></select></div>' +
      '<div class="form-group"><label class="form-label">SSH Target <span style="color:var(--orange);">*</span></label><input type="text" class="form-input" id="tunnel-ssh-target" placeholder="user@host (e.g., root@vps.example.com)"></div>' +
      '<div class="form-group"><label class="form-label">Local Port <span style="color:var(--orange);">*</span></label><input type="number" class="form-input" id="tunnel-local-port" placeholder="8080" value="8080"></div>' +
      '<div id="tunnel-remote-fields">' +
        '<div class="form-group"><label class="form-label">Remote Host</label><input type="text" class="form-input" id="tunnel-remote-host" placeholder="localhost" value="localhost"></div>' +
        '<div class="form-group"><label class="form-label">Remote Port</label><input type="number" class="form-input" id="tunnel-remote-port" placeholder="8080" value="8080"></div>' +
      '</div>' +
      '<div class="form-group"><label class="form-label">SSH Port</label><input type="number" class="form-input" id="tunnel-ssh-port" value="22"></div>' +
      '<div class="form-group"><label class="form-label">SSH Key (optional)</label><input type="text" class="form-input" id="tunnel-ssh-key" placeholder="/home/vigil/.ssh/id_rsa"></div>' +
      '<div class="form-group"><label style="display:flex;align-items:center;gap:6px;font-size:var(--font-size-xs);color:var(--text-secondary);"><input type="checkbox" id="tunnel-reconnect" checked> Auto-reconnect on disconnect</label></div>',
      footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="tunnel-create-go">Create Tunnel</button>',
      size: 'lg' });

    // Toggle remote fields for dynamic type
    document.getElementById('tunnel-type').addEventListener('change', function() {
      document.getElementById('tunnel-remote-fields').style.display = this.value === 'dynamic' ? 'none' : '';
    });

    document.getElementById('tunnel-create-go').addEventListener('click', function() {
      var type = document.getElementById('tunnel-type').value;
      var sshTarget = document.getElementById('tunnel-ssh-target').value.trim();
      var localPort = document.getElementById('tunnel-local-port').value;
      if (!sshTarget) { Toast.warning('SSH target required'); return; }
      if (!localPort) { Toast.warning('Local port required'); return; }

      var body = {
        type: type, sshTarget: sshTarget, localPort: parseInt(localPort),
        remoteHost: document.getElementById('tunnel-remote-host').value.trim() || 'localhost',
        remotePort: parseInt(document.getElementById('tunnel-remote-port').value) || parseInt(localPort),
        sshPort: parseInt(document.getElementById('tunnel-ssh-port').value) || 22,
        sshKey: document.getElementById('tunnel-ssh-key').value.trim() || undefined,
        autoReconnect: document.getElementById('tunnel-reconnect').checked,
      };

      Modal.loading('Creating tunnel...');
      fetch('/api/proxy-nodes/tunnels', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify(body) })
        .then(function(r) { return r.json(); }).then(function(d) {
          Modal.close();
          if (d.error) Toast.error(d.error);
          else { Toast.success('Tunnel created: ' + (d.spec || d.id)); self._loadTunnels(); }
        }).catch(function(e) { Modal.close(); Toast.error(e.message); });
    });
  },

  _stopTunnel: function(id) {
    var self = this;
    fetch('/api/proxy-nodes/tunnels/' + encodeURIComponent(id), { method: 'DELETE', credentials: 'same-origin' })
      .then(function(r) { return r.json(); }).then(function(d) { if (d.error) Toast.error(d.error); else { Toast.success('Tunnel stopped'); self._loadTunnels(); } })
      .catch(function(e) { Toast.error(e.message); });
  },

  // ════════════════════════════════════════════════════════════════════════
  // TAB 3: CALLBACK LISTENER (OOB detection)
  // ════════════════════════════════════════════════════════════════════════

  _initCallbackTab: function() {
    var container = document.getElementById('proxy-tab-callback');
    if (container.getAttribute('data-init')) return;
    container.setAttribute('data-init', '1');

    container.innerHTML =
      '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">' +
          '<div style="font-size:var(--font-size-base);font-weight:600;color:var(--text-primary);">OOB Callback Listener</div>' +
          '<div style="display:flex;gap:8px;">' +
            '<button class="btn btn-ghost btn-sm" id="cb-start-btn" style="color:var(--cyan);">Start Listener</button>' +
            '<button class="btn btn-ghost btn-sm" id="cb-stop-btn" style="color:var(--orange);display:none;">Stop</button>' +
          '</div>' +
        '</div>' +
        '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-bottom:12px;line-height:1.6;">' +
          'Starts an HTTP server that captures all incoming requests. Use the callback URL in scan payloads to detect blind vulnerabilities (blind XSS, SSRF, SQLi, RCE). ' +
          'Each listener gets a unique secret token — requests matching the secret are flagged as targeted callbacks from your payloads. ' +
          'Combine with a reverse SSH tunnel to make the listener internet-accessible.' +
        '</div>' +
        '<div id="cb-status"></div>' +
      '</div>' +

      '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">' +
          '<div style="font-size:var(--font-size-base);font-weight:600;color:var(--text-primary);">Captured Requests</div>' +
          '<div style="display:flex;gap:8px;">' +
            '<label style="display:flex;align-items:center;gap:4px;font-size:var(--font-size-xs);color:var(--text-secondary);"><input type="checkbox" id="cb-targeted-only"> Targeted only</label>' +
            '<button class="btn btn-ghost btn-sm" id="cb-refresh-log">Refresh</button>' +
            '<button class="btn btn-ghost btn-sm" id="cb-clear-log" style="color:var(--orange);">Clear</button>' +
          '</div>' +
        '</div>' +
        '<div id="cb-log"><div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">No captured requests</div></div>' +
      '</div>';

    var self = this;
    document.getElementById('cb-start-btn').addEventListener('click', function() { self._startCallback(); });
    document.getElementById('cb-stop-btn').addEventListener('click', function() { self._stopCallback(); });
    document.getElementById('cb-refresh-log').addEventListener('click', function() { self._loadCallbackLog(); });
    document.getElementById('cb-clear-log').addEventListener('click', function() { self._clearCallbackLog(); });
    document.getElementById('cb-targeted-only').addEventListener('change', function() { self._loadCallbackLog(); });
  },

  _loadCallback: function() {
    var self = this;
    fetch('/api/proxy-nodes/callback', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        self._callbackStatus = data;
        var statEl = document.getElementById('proxy-stat-callback');
        if (data.running) {
          statEl.textContent = ':' + data.port;
          statEl.style.color = 'var(--cyan)';
        } else {
          statEl.textContent = 'Off';
          statEl.style.color = 'var(--text-tertiary)';
        }
        self._renderCallbackStatus(data);
      }).catch(function() {});
    self._loadCallbackLog();
  },

  _renderCallbackStatus: function(data) {
    var el = document.getElementById('cb-status');
    if (!el) return;
    var startBtn = document.getElementById('cb-start-btn');
    var stopBtn = document.getElementById('cb-stop-btn');

    if (data.running) {
      startBtn.style.display = 'none';
      stopBtn.style.display = '';
      el.innerHTML =
        '<div style="padding:12px;border:1px solid rgba(34,211,238,0.2);border-radius:8px;background:rgba(34,211,238,0.03);">' +
          '<div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap;">' +
            '<div><div style="font-size:10px;color:var(--text-tertiary);text-transform:uppercase;">Status</div><div style="color:var(--cyan);font-weight:600;">Listening</div></div>' +
            '<div><div style="font-size:10px;color:var(--text-tertiary);text-transform:uppercase;">Port</div><div style="color:var(--cyan);font-weight:600;font-family:var(--font-mono);">' + data.port + '</div></div>' +
            '<div><div style="font-size:10px;color:var(--text-tertiary);text-transform:uppercase;">Total Requests</div><div style="color:var(--text-primary);font-weight:600;">' + (data.totalRequests || 0) + '</div></div>' +
            '<div><div style="font-size:10px;color:var(--text-tertiary);text-transform:uppercase;">Targeted</div><div style="color:var(--orange);font-weight:600;">' + (data.targetedRequests || 0) + '</div></div>' +
          '</div>' +
          '<div style="margin-top:10px;">' +
            '<div style="font-size:10px;color:var(--text-tertiary);text-transform:uppercase;margin-bottom:4px;">Callback URL (use in payloads)</div>' +
            '<div style="display:flex;gap:8px;align-items:center;">' +
              '<code style="color:var(--cyan);font-size:var(--font-size-xs);background:rgba(34,211,238,0.06);padding:6px 10px;border-radius:4px;flex:1;word-break:break-all;">' + escapeHtml(data.callbackURL || '--') + '</code>' +
              '<button class="btn btn-ghost btn-sm" id="cb-copy-url" style="font-size:10px;">Copy</button>' +
            '</div>' +
            '<div style="color:var(--text-tertiary);font-size:10px;margin-top:6px;">Replace VIGIL_IP with your server\'s actual IP/hostname. Combine with a reverse tunnel for internet access.</div>' +
          '</div>' +
        '</div>';
      var copyBtn = document.getElementById('cb-copy-url');
      if (copyBtn) {
        copyBtn.addEventListener('click', function() {
          navigator.clipboard.writeText(data.callbackURL || '').then(function() { Toast.success('Copied'); });
        });
      }
    } else {
      startBtn.style.display = '';
      stopBtn.style.display = 'none';
      el.innerHTML =
        '<div style="padding:12px;border:1px solid var(--border);border-radius:8px;">' +
          '<div style="display:flex;gap:8px;align-items:center;">' +
            '<label class="form-label" style="margin:0;font-size:var(--font-size-xs);">Port:</label>' +
            '<input type="number" class="form-input" id="cb-port" value="9999" style="width:100px;font-size:var(--font-size-xs);">' +
            '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">Listener not running</span>' +
          '</div>' +
        '</div>';
    }
  },

  _startCallback: function() {
    var self = this;
    var portInput = document.getElementById('cb-port');
    var port = portInput ? parseInt(portInput.value) || 9999 : 9999;
    fetch('/api/proxy-nodes/callback', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ action: 'start', port: port }) })
      .then(function(r) { return r.json(); }).then(function(d) { if (d.error) Toast.error(d.error); else { Toast.success('Callback listener started on :' + d.port); self._loadCallback(); } })
      .catch(function(e) { Toast.error(e.message); });
  },

  _stopCallback: function() {
    var self = this;
    fetch('/api/proxy-nodes/callback', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ action: 'stop' }) })
      .then(function(r) { return r.json(); }).then(function(d) { Toast.success('Listener stopped'); self._loadCallback(); })
      .catch(function(e) { Toast.error(e.message); });
  },

  _loadCallbackLog: function() {
    var self = this;
    var targeted = document.getElementById('cb-targeted-only');
    var targetedOnly = targeted && targeted.checked;
    fetch('/api/proxy-nodes/callback/log?targeted=' + targetedOnly + '&limit=50', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(entries) {
        self._callbackLog = entries;
        self._renderCallbackLog(entries);
      }).catch(function() {});
  },

  _renderCallbackLog: function(entries) {
    var el = document.getElementById('cb-log');
    if (!el) return;
    if (!entries || entries.length === 0) {
      el.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);padding:12px 0;">No captured requests</div>';
      return;
    }
    var html = '<table class="data-table" style="font-size:var(--font-size-xs);"><thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Source IP</th><th>User-Agent</th><th></th></tr></thead><tbody>';
    entries.forEach(function(e) {
      var rowColor = e.isTargeted ? 'background:rgba(255,107,43,0.04);' : '';
      var badge = e.isTargeted ? '<span class="tag" style="color:var(--orange);font-size:9px;">TARGETED</span> ' : '';
      html += '<tr style="' + rowColor + '">' +
        '<td style="white-space:nowrap;">' + escapeHtml((e.timestamp || '').substring(11, 19)) + '</td>' +
        '<td><span style="color:var(--cyan);font-weight:600;">' + escapeHtml(e.method) + '</span></td>' +
        '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + badge + escapeHtml(e.path || e.url || '') + '</td>' +
        '<td style="font-family:var(--font-mono);">' + escapeHtml(e.sourceIP || '--') + '</td>' +
        '<td style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-tertiary);">' + escapeHtml((e.userAgent || '--').substring(0, 50)) + '</td>' +
        '<td><button class="btn btn-ghost btn-sm cb-detail" data-id="' + escapeHtml(e.id) + '" style="font-size:10px;">Detail</button></td>' +
      '</tr>';
    });
    html += '</tbody></table>';
    el.innerHTML = html;

    var self = this;
    el.querySelectorAll('.cb-detail').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var id = btn.getAttribute('data-id');
        var entry = self._callbackLog.find(function(e) { return e.id === id; });
        if (entry) self._showCallbackDetail(entry);
      });
    });
  },

  _showCallbackDetail: function(entry) {
    var headersHtml = '';
    if (entry.headers) {
      Object.keys(entry.headers).forEach(function(k) {
        headersHtml += '<div style="padding:2px 0;"><span style="color:var(--cyan);font-weight:500;">' + escapeHtml(k) + ':</span> <span style="color:var(--text-secondary);">' + escapeHtml(entry.headers[k]) + '</span></div>';
      });
    }
    Modal.open({ title: 'Callback Request Detail', body:
      '<div style="display:flex;gap:12px;margin-bottom:12px;flex-wrap:wrap;">' +
        '<div><span style="font-size:10px;color:var(--text-tertiary);">Method</span><div style="color:var(--cyan);font-weight:600;">' + escapeHtml(entry.method) + '</div></div>' +
        '<div><span style="font-size:10px;color:var(--text-tertiary);">Path</span><div style="color:var(--text-primary);">' + escapeHtml(entry.url) + '</div></div>' +
        '<div><span style="font-size:10px;color:var(--text-tertiary);">Source</span><div style="font-family:var(--font-mono);">' + escapeHtml(entry.sourceIP) + ':' + (entry.sourcePort || '') + '</div></div>' +
        '<div><span style="font-size:10px;color:var(--text-tertiary);">Time</span><div>' + escapeHtml(entry.timestamp) + '</div></div>' +
        (entry.isTargeted ? '<div><span class="tag" style="color:var(--orange);">TARGETED CALLBACK</span></div>' : '') +
      '</div>' +
      '<div style="margin-bottom:12px;"><div style="font-size:var(--font-size-xs);font-weight:600;color:var(--text-primary);margin-bottom:4px;">Headers</div><div class="code-block" style="font-size:10px;max-height:200px;overflow-y:auto;">' + (headersHtml || 'None') + '</div></div>' +
      (entry.body ? '<div><div style="font-size:var(--font-size-xs);font-weight:600;color:var(--text-primary);margin-bottom:4px;">Body</div><div class="code-block" style="font-size:10px;max-height:150px;overflow-y:auto;white-space:pre-wrap;">' + escapeHtml(entry.body) + '</div></div>' : ''),
      size: 'lg' });
  },

  _clearCallbackLog: function() {
    var self = this;
    fetch('/api/proxy-nodes/callback/log', { method: 'DELETE', credentials: 'same-origin' })
      .then(function(r) { return r.json(); }).then(function() { Toast.success('Log cleared'); self._loadCallbackLog(); })
      .catch(function(e) { Toast.error(e.message); });
  }
};
