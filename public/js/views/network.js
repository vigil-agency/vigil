/* Vigil v1.0 — Network Overview View (ServerKit-inspired service + hardening tabs) */
Views.network = {
  init: function() {
    var el = document.getElementById('view-network');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Network & Infrastructure</div>' +
        '<div style="display:flex;gap:8px;">' +
          '<button class="btn btn-primary btn-sm" id="network-quick-scan">Quick Scan</button>' +
          '<button class="btn btn-ghost btn-sm" id="network-refresh">Refresh</button>' +
        '</div>' +
      '</div>' +

      '<div class="tab-bar" id="network-tabs">' +
        '<div class="tab-item active" data-tab="network-tab-net">Network</div>' +
        '<div class="tab-item" data-tab="network-tab-svc">Services</div>' +
        '<div class="tab-item" data-tab="network-tab-harden">Hardening</div>' +
      '</div>' +

      // ── Network Tab (existing) ─────────────────────────────────
      '<div class="tab-content active" id="network-tab-net">' +
        '<div class="grid-2" style="margin-bottom:20px;">' +
          '<div class="glass-card">' +
            '<div class="glass-card-title" style="margin-bottom:12px;">Network Interfaces</div>' +
            '<div id="network-interfaces">' +
              '<div class="loading-state"><div class="spinner"></div><div>Loading...</div></div>' +
            '</div>' +
          '</div>' +
          '<div class="glass-card">' +
            '<div class="glass-card-title" style="margin-bottom:12px;">Listening Ports</div>' +
            '<div id="network-ports">' +
              '<div class="loading-state"><div class="spinner"></div><div>Loading...</div></div>' +
            '</div>' +
          '</div>' +
        '</div>' +
        '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Firewall Rules</div>' +
          '<div id="network-firewall">' +
            '<div class="loading-state"><div class="spinner"></div><div>Loading...</div></div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      // ── Services Tab (ServerKit-inspired) ─────────────────────
      '<div class="tab-content" id="network-tab-svc">' +
        '<div id="network-services-content">' +
          '<div class="loading-state"><div class="spinner spinner-lg"></div><div>Checking services...<br><span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">Querying systemctl for nginx, postgresql, docker, sshd, fail2ban, and more</span></div></div>' +
        '</div>' +
      '</div>' +

      // ── Hardening Tab (ServerKit-inspired) ────────────────────
      '<div class="tab-content" id="network-tab-harden">' +
        '<div id="network-hardening-content">' +
          '<div class="loading-state"><div class="spinner spinner-lg"></div><div>Running hardening audit...<br><span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">SSH config, firewall, fail2ban, file permissions, kernel params, accounts, AI analysis</span></div></div>' +
        '</div>' +
      '</div>';

    var self = this;

    // Tabs
    document.querySelectorAll('#network-tabs .tab-item').forEach(function(tab) {
      tab.addEventListener('click', function() {
        document.querySelectorAll('#network-tabs .tab-item').forEach(function(t) { t.classList.remove('active'); });
        tab.classList.add('active');
        document.querySelectorAll('#view-network > .tab-content').forEach(function(c) { c.classList.remove('active'); });
        var target = document.getElementById(tab.getAttribute('data-tab'));
        if (target) target.classList.add('active');

        // Lazy load tabs
        var tabId = tab.getAttribute('data-tab');
        if (tabId === 'network-tab-svc' && !self._svcLoaded) self.loadServices();
        if (tabId === 'network-tab-harden' && !self._hardenLoaded) self.loadHardening();
      });
    });

    document.getElementById('network-refresh').addEventListener('click', function() {
      self._svcLoaded = false;
      self._hardenLoaded = false;
      self.show();
    });
    document.getElementById('network-quick-scan').addEventListener('click', function() { showView('port-scanner'); });
  },

  _svcLoaded: false,
  _hardenLoaded: false,

  show: function() {
    this.loadInterfaces();
    this.loadPorts();
    this.loadFirewall();
    // Load active tab if not network
    var activeTab = document.querySelector('#network-tabs .tab-item.active');
    if (activeTab) {
      var tabId = activeTab.getAttribute('data-tab');
      if (tabId === 'network-tab-svc') this.loadServices();
      if (tabId === 'network-tab-harden') this.loadHardening();
    }
  },

  hide: function() {},

  // ── Network Tab Loaders (existing) ────────────────────────────
  loadInterfaces: function() {
    var container = document.getElementById('network-interfaces');
    fetch('/api/network/interfaces', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var ifaces = data.interfaces || data || [];
        if (!Array.isArray(ifaces) || ifaces.length === 0) {
          container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">No interfaces found</div>';
          return;
        }
        var html = '<table class="data-table"><thead><tr><th>Interface</th><th>IP Address</th><th>MAC</th><th>Status</th></tr></thead><tbody>';
        ifaces.forEach(function(i) {
          var statusColor = i.status === 'up' ? 'var(--cyan)' : 'var(--text-tertiary)';
          html += '<tr>' +
            '<td style="color:var(--text-primary);font-weight:500;">' + escapeHtml(i.name || i.iface || '--') + '</td>' +
            '<td>' + escapeHtml(i.ip || i.address || '--') + '</td>' +
            '<td>' + escapeHtml(i.mac || '--') + '</td>' +
            '<td><span style="color:' + statusColor + ';">' + escapeHtml(i.status || 'unknown') + '</span></td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      })
      .catch(function() { container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">Could not load interfaces</div>'; });
  },

  loadPorts: function() {
    var container = document.getElementById('network-ports');
    fetch('/api/network/connections', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var conns = data.connections || [];
        var listening = conns.filter(function(c) { return (c.state || '').toUpperCase() === 'LISTENING'; });
        if (listening.length === 0) {
          container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">No listening ports detected</div>';
          return;
        }
        var html = '<table class="data-table"><thead><tr><th>Local Address</th><th>Protocol</th><th>State</th><th>Process</th></tr></thead><tbody>';
        listening.forEach(function(c) {
          html += '<tr>' +
            '<td style="color:var(--text-primary);font-weight:500;">' + escapeHtml(c.local || '') + '</td>' +
            '<td>' + escapeHtml(c.proto || 'tcp') + '</td>' +
            '<td><span style="color:var(--cyan);">' + escapeHtml(c.state || '') + '</span></td>' +
            '<td>' + escapeHtml(c.process || '--') + '</td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      })
      .catch(function() { container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">Could not load ports</div>'; });
  },

  loadFirewall: function() {
    var container = document.getElementById('network-firewall');
    fetch('/api/network/firewall', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var rules = data.rules || data || [];
        if (!Array.isArray(rules) || rules.length === 0) {
          container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">No firewall rules detected or firewall not configured</div>';
          return;
        }
        var html = '<table class="data-table"><thead><tr><th>Chain</th><th>Action</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Port</th></tr></thead><tbody>';
        rules.forEach(function(r) {
          var actionColor = r.action === 'ACCEPT' || r.action === 'allow' ? 'var(--cyan)' : 'var(--orange)';
          html += '<tr>' +
            '<td>' + escapeHtml(r.chain || '--') + '</td>' +
            '<td><span style="color:' + actionColor + ';font-weight:600;">' + escapeHtml(r.action || '--') + '</span></td>' +
            '<td>' + escapeHtml(r.protocol || 'any') + '</td>' +
            '<td>' + escapeHtml(r.source || 'any') + '</td>' +
            '<td>' + escapeHtml(r.destination || 'any') + '</td>' +
            '<td>' + escapeHtml(String(r.port || 'any')) + '</td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      })
      .catch(function() { container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">Could not load firewall rules</div>'; });
  },

  // ── Services Tab (ServerKit-inspired) ─────────────────────────
  loadServices: function() {
    var container = document.getElementById('network-services-content');
    var self = this;
    container.innerHTML = '<div class="loading-state"><div class="spinner spinner-lg"></div><div>Checking services...</div></div>';

    fetch('/api/network/services', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        self._svcLoaded = true;
        if (data.message && (!data.services || data.services.length === 0)) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#9881;</div><div class="empty-state-title">Service Monitoring</div><div class="empty-state-desc">' + escapeHtml(data.message) + '</div></div>';
          return;
        }

        var services = data.services || [];
        if (services.length === 0) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#9881;</div><div class="empty-state-title">No Services Detected</div><div class="empty-state-desc">No monitored services found on this system</div></div>';
          return;
        }

        var html = '';

        // Stat cards
        html += '<div class="stat-grid" style="margin-bottom:16px;">' +
          '<div class="stat-card"><div class="stat-card-label">Total Services</div><div class="stat-card-value">' + data.total + '</div></div>' +
          '<div class="stat-card"><div class="stat-card-label">Active</div><div class="stat-card-value" style="color:var(--cyan);">' + data.active + '</div></div>' +
          '<div class="stat-card"><div class="stat-card-label">Inactive</div><div class="stat-card-value" style="color:var(--text-tertiary);">' + data.inactive + '</div></div>' +
          '<div class="stat-card"><div class="stat-card-label">Failed</div><div class="stat-card-value" style="color:' + (data.failed > 0 ? 'var(--orange)' : 'var(--text-tertiary)') + ';">' + data.failed + '</div></div>' +
        '</div>';

        // Service table
        html += '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Service Health Monitor</div>' +
          '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-bottom:12px;">Monitors nginx, postgresql, mysql, redis, docker, sshd, fail2ban, and other critical services via systemctl</div>' +
          '<table class="data-table"><thead><tr><th>Service</th><th>Status</th><th>PID</th><th>Active Since</th></tr></thead><tbody>';

        services.forEach(function(s) {
          var statusColor = s.status === 'active' ? 'var(--cyan)' : s.status === 'failed' ? 'var(--orange)' : 'var(--text-tertiary)';
          var statusIcon = s.status === 'active' ? '&#9679;' : s.status === 'failed' ? '&#9888;' : '&#9675;';
          var since = s.since ? s.since.replace(/^\w+ /, '') : '--';

          html += '<tr>' +
            '<td style="color:var(--text-primary);font-weight:500;font-family:var(--font-mono);font-size:var(--font-size-xs);">' + escapeHtml(s.name) + '</td>' +
            '<td><span style="color:' + statusColor + ';font-weight:600;font-size:var(--font-size-xs);">' + statusIcon + ' ' + escapeHtml(s.status) + '</span></td>' +
            '<td style="color:var(--text-tertiary);font-family:var(--font-mono);font-size:var(--font-size-xs);">' + escapeHtml(s.pid && s.pid !== '0' ? s.pid : '--') + '</td>' +
            '<td style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + escapeHtml(since) + '</td>' +
            '</tr>';
        });
        html += '</tbody></table></div>';

        container.innerHTML = html;
      })
      .catch(function() {
        self._svcLoaded = false;
        container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#9881;</div><div class="empty-state-title">Service Check Failed</div><div class="empty-state-desc">Could not query service status. Ensure the server is running Linux with systemctl.</div></div>';
      });
  },

  // ── Hardening Tab (ServerKit-inspired) ────────────────────────
  loadHardening: function() {
    var container = document.getElementById('network-hardening-content');
    var self = this;
    container.innerHTML = '<div class="loading-state"><div class="spinner spinner-lg"></div><div>Running hardening audit...<br><span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">SSH, firewall, fail2ban, file permissions, kernel, accounts, AI analysis</span></div></div>';

    fetch('/api/network/hardening', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        self._hardenLoaded = true;
        if (data.message) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128274;</div><div class="empty-state-title">Hardening Audit</div><div class="empty-state-desc">' + escapeHtml(data.message) + '</div></div>';
          return;
        }

        var checks = data.checks || [];
        var html = '';

        // AI Analysis (top)
        if (data.analysis) {
          html += '<div class="glass-card" style="margin-bottom:16px;">' +
            '<div class="glass-card-title" style="margin-bottom:8px;color:var(--cyan);">AI Hardening Assessment</div>' +
            '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;white-space:pre-wrap;">' + escapeHtml(data.analysis) + '</div>' +
            '</div>';
        }

        // Score + stats
        var gradeColor = data.score >= 80 ? 'var(--cyan)' : data.score >= 50 ? 'var(--text-secondary)' : 'var(--orange)';
        html += '<div class="stat-grid" style="margin-bottom:16px;">' +
          '<div class="stat-card">' +
            '<div class="stat-card-label">Hardening Score</div>' +
            '<div class="stat-card-value" style="color:' + gradeColor + ';">' + data.score + '<span style="font-size:14px;color:var(--text-tertiary);">/100</span></div>' +
          '</div>' +
          '<div class="stat-card">' +
            '<div class="stat-card-label">Grade</div>' +
            '<div class="stat-card-value" style="color:' + gradeColor + ';">' + escapeHtml(data.grade || '?') + '</div>' +
          '</div>' +
          '<div class="stat-card">' +
            '<div class="stat-card-label">Passed</div>' +
            '<div class="stat-card-value" style="color:var(--cyan);">' + data.passed + '</div>' +
          '</div>' +
          '<div class="stat-card">' +
            '<div class="stat-card-label">Failed</div>' +
            '<div class="stat-card-value" style="color:' + (data.failed > 0 ? 'var(--orange)' : 'var(--text-tertiary)') + ';">' + data.failed + '</div>' +
          '</div>' +
        '</div>';

        // Group checks by category
        var categories = {};
        checks.forEach(function(c) {
          if (!categories[c.category]) categories[c.category] = [];
          categories[c.category].push(c);
        });

        var catLabels = { ssh: 'SSH Hardening', firewall: 'Firewall', ids: 'Intrusion Detection', updates: 'System Updates', files: 'File Permissions', kernel: 'Kernel Security', accounts: 'Account Security' };

        html += '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Security Hardening Checklist</div>' +
          '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-bottom:12px;">Checks SSH configuration, firewall status, fail2ban, system updates, file permissions, kernel parameters, and account security</div>';

        Object.keys(categories).forEach(function(cat) {
          var catChecks = categories[cat];
          var catPassed = catChecks.filter(function(c) { return c.passed; }).length;
          html += '<div style="margin-bottom:16px;">' +
            '<div style="font-weight:600;color:var(--text-primary);margin-bottom:8px;display:flex;align-items:center;gap:8px;">' +
              escapeHtml(catLabels[cat] || cat) +
              ' <span style="font-size:var(--font-size-xs);color:var(--text-tertiary);font-weight:400;">' + catPassed + '/' + catChecks.length + ' passed</span>' +
            '</div>';

          catChecks.forEach(function(c) {
            var icon = c.passed ? '<span style="color:var(--cyan);">&#10003;</span>' : '<span style="color:var(--orange);">&#10007;</span>';
            var sevColor = c.severity === 'critical' ? 'var(--orange)' : c.severity === 'high' ? 'var(--orange)' : 'var(--text-tertiary)';
            html += '<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);">' +
              '<div style="min-width:18px;text-align:center;">' + icon + '</div>' +
              '<div style="flex:1;">' +
                '<div style="color:var(--text-primary);font-size:var(--font-size-sm);">' + escapeHtml(c.name) + '</div>' +
                '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + escapeHtml(c.detail) + '</div>' +
              '</div>' +
              '<div style="min-width:60px;text-align:right;">' +
                '<span style="color:' + sevColor + ';font-size:var(--font-size-xs);text-transform:uppercase;font-weight:600;">' + escapeHtml(c.severity) + '</span>' +
              '</div>' +
            '</div>';
          });
          html += '</div>';
        });

        html += '</div>';

        // Fail2ban section
        html += '<div class="glass-card" style="margin-top:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Fail2ban Status</div>' +
          '<div id="network-fail2ban-content"><div class="loading-state"><div class="spinner"></div></div></div>' +
        '</div>';

        container.innerHTML = html;

        // Load fail2ban data
        self.loadFail2ban();
      })
      .catch(function() {
        self._hardenLoaded = false;
        container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128274;</div><div class="empty-state-title">Audit Failed</div><div class="empty-state-desc">Could not run hardening audit. Ensure the server is running Linux.</div></div>';
      });
  },

  loadFail2ban: function() {
    var container = document.getElementById('network-fail2ban-content');
    if (!container) return;

    fetch('/api/network/fail2ban', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (!data.installed) {
          container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">' + escapeHtml(data.message || 'fail2ban not installed') + '</div>';
          return;
        }

        var html = '';
        var jails = data.jails || [];

        if (jails.length > 0) {
          html += '<div style="margin-bottom:12px;">' +
            '<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;">' +
              '<div style="color:var(--cyan);font-size:var(--font-size-sm);font-weight:600;">' + jails.length + ' jails active</div>' +
              '<div style="color:' + (data.totalBanned > 0 ? 'var(--orange)' : 'var(--text-tertiary)') + ';font-size:var(--font-size-sm);font-weight:600;">' + data.totalBanned + ' IPs currently banned</div>' +
            '</div>';

          html += '<table class="data-table"><thead><tr><th>Jail</th><th>Failed</th><th>Total Banned</th><th>Currently Banned</th><th>Banned IPs</th></tr></thead><tbody>';
          jails.forEach(function(j) {
            html += '<tr>' +
              '<td style="color:var(--text-primary);font-weight:500;font-family:var(--font-mono);font-size:var(--font-size-xs);">' + escapeHtml(j.name) + '</td>' +
              '<td style="color:' + (j.totalFailed > 0 ? 'var(--orange)' : 'var(--text-tertiary)') + ';">' + j.totalFailed + '</td>' +
              '<td>' + j.totalBanned + '</td>' +
              '<td style="color:' + (j.currentBanned > 0 ? 'var(--orange)' : 'var(--cyan)') + ';font-weight:600;">' + j.currentBanned + '</td>' +
              '<td style="font-family:var(--font-mono);font-size:var(--font-size-xs);max-width:200px;overflow:hidden;text-overflow:ellipsis;">' + escapeHtml(j.bannedIPs.join(', ') || '--') + '</td>' +
              '</tr>';
          });
          html += '</tbody></table></div>';
        } else {
          html += '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">fail2ban is installed but no jails are configured</div>';
        }

        // Failed logins
        var logins = data.failedLogins || [];
        if (logins.length > 0) {
          html += '<div style="margin-top:12px;">' +
            '<div style="font-weight:600;color:var(--text-primary);margin-bottom:6px;">Recent Failed Login Attempts</div>' +
            '<table class="data-table"><thead><tr><th>User</th><th>Source</th><th>Terminal</th><th>Time</th></tr></thead><tbody>';
          logins.forEach(function(l) {
            html += '<tr>' +
              '<td style="color:var(--orange);font-weight:500;">' + escapeHtml(l.user) + '</td>' +
              '<td style="font-family:var(--font-mono);font-size:var(--font-size-xs);">' + escapeHtml(l.source) + '</td>' +
              '<td style="font-size:var(--font-size-xs);">' + escapeHtml(l.terminal) + '</td>' +
              '<td style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + escapeHtml(l.time) + '</td>' +
              '</tr>';
          });
          html += '</tbody></table></div>';
        }

        container.innerHTML = html || '<div style="color:var(--cyan);font-size:var(--font-size-sm);">fail2ban is installed — no activity to report</div>';
      })
      .catch(function() {
        container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">Could not query fail2ban status</div>';
      });
  }
};
