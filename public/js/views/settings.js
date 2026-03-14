/* Vigil v1.0 — Settings View */
Views.settings = {
  _activeTab: 'account',

  init: function() {
    var el = document.getElementById('view-settings');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Settings</div>' +
      '</div>' +

      '<div class="tab-bar" id="settings-tabs">' +
        '<div class="tab-item active" data-tab="settings-account">Account</div>' +
        '<div class="tab-item" data-tab="settings-ai">AI Provider</div>' +
        '<div class="tab-item" data-tab="settings-scanners">Scanners</div>' +
        '<div class="tab-item" data-tab="settings-security">Security</div>' +
        '<div class="tab-item" data-tab="settings-about">About</div>' +
      '</div>' +

      '<div class="tab-content active" id="settings-account">' +
        '<div class="glass-card" style="max-width:500px;">' +
          '<div class="glass-card-title" style="margin-bottom:16px;">Account</div>' +
          '<div class="form-group"><label class="form-label">Username</label><input type="text" class="form-input" id="settings-username" placeholder="Username"></div>' +
          '<div class="form-group"><label class="form-label">New Password</label><input type="password" class="form-input" id="settings-new-pass" placeholder="Leave blank to keep current"></div>' +
          '<div class="form-group"><label class="form-label">Confirm Password</label><input type="password" class="form-input" id="settings-confirm-pass" placeholder="Confirm new password"></div>' +
          '<button class="btn btn-primary" id="settings-save-account">Save Changes</button>' +
          '<div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--border);">' +
            '<div class="glass-card-title" style="margin-bottom:12px;">Two-Factor Authentication</div>' +
            '<div id="settings-2fa-status" style="color:var(--text-secondary);font-size:var(--font-size-sm);margin-bottom:12px;">Loading...</div>' +
            '<button class="btn btn-ghost btn-sm" id="settings-2fa-btn">Setup 2FA</button>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="tab-content" id="settings-ai">' +
        '<div class="glass-card" style="max-width:500px;">' +
          '<div class="glass-card-title" style="margin-bottom:16px;">AI Provider</div>' +
          '<div class="form-group"><label class="form-label">Provider</label><select class="form-select" id="settings-ai-provider"><option value="ollama">Ollama (Local — recommended)</option><option value="claude-api">Claude API</option><option value="claude-cli">Claude CLI</option><option value="codex">Codex CLI</option><option value="none">None (AI features disabled)</option></select></div>' +
          '<div id="settings-ollama-config" style="display:none;">' +
            '<div class="form-group"><label class="form-label">Ollama Base URL</label><input type="text" class="form-input" id="settings-ollama-url" placeholder="http://ollama:11434"></div>' +
            '<div class="form-group"><label class="form-label">Model</label><input type="text" class="form-input" id="settings-ollama-model" placeholder="qwen3:8b"></div>' +
          '</div>' +
          '<div id="settings-ai-status" style="margin-top:12px;"></div>' +
          '<div style="display:flex;gap:8px;margin-top:12px;">' +
            '<button class="btn btn-primary" id="settings-save-ai">Save</button>' +
            '<button class="btn btn-ghost" id="settings-test-ai">Test Connection</button>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="tab-content" id="settings-scanners">' +
        '<div class="glass-card" style="max-width:600px;">' +
          '<div class="glass-card-title" style="margin-bottom:16px;">Installed Scanners</div>' +
          '<div id="settings-scanner-list">' +
            '<div class="loading-state"><div class="spinner"></div><div>Checking scanners...</div></div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="tab-content" id="settings-security">' +
        '<div class="glass-card" style="max-width:500px;">' +
          '<div class="glass-card-title" style="margin-bottom:16px;">Security Settings</div>' +
          '<div class="form-group"><label class="form-label">Session Timeout (minutes)</label><input type="number" class="form-input" id="settings-session-timeout" value="60" min="5" max="1440"></div>' +
          '<div class="form-group"><label class="form-label">Max Login Attempts</label><input type="number" class="form-input" id="settings-max-attempts" value="5" min="3" max="20"></div>' +
          '<div class="form-group"><label class="form-label">Audit Log Retention (days)</label><input type="number" class="form-input" id="settings-audit-retention" value="90" min="7" max="365"></div>' +
          '<button class="btn btn-primary" id="settings-save-security">Save</button>' +
        '</div>' +
      '</div>' +

      '<div class="tab-content" id="settings-about">' +
        '<div class="glass-card" style="max-width:500px;">' +
          '<div style="text-align:center;margin-bottom:20px;">' +
            '<div style="font-size:36px;margin-bottom:8px;">&#128737;</div>' +
            '<div style="font-size:var(--font-size-2xl);font-weight:700;letter-spacing:2px;">VIGIL</div>' +
            '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">The Security Agency That Never Sleeps</div>' +
            '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-top:4px;">Version 1.0.0</div>' +
          '</div>' +
          '<div class="detail-row"><div class="detail-label">Platform</div><div class="detail-value" id="settings-platform">--</div></div>' +
          '<div class="detail-row"><div class="detail-label">Node.js</div><div class="detail-value" id="settings-node">--</div></div>' +
          '<div class="detail-row"><div class="detail-label">Uptime</div><div class="detail-value" id="settings-uptime">--</div></div>' +
          '<div class="detail-row"><div class="detail-label">License</div><div class="detail-value">AGPL-3.0</div></div>' +
        '</div>' +
      '</div>';

    var self = this;

    // Tab handling
    document.querySelectorAll('#settings-tabs .tab-item').forEach(function(tab) {
      tab.addEventListener('click', function() {
        document.querySelectorAll('#settings-tabs .tab-item').forEach(function(t) { t.classList.remove('active'); });
        tab.classList.add('active');
        var tabId = tab.getAttribute('data-tab');
        document.querySelectorAll('#view-settings > .tab-content').forEach(function(c) { c.classList.remove('active'); });
        document.getElementById(tabId).classList.add('active');
        self._activeTab = tabId.replace('settings-', '');
        self.loadTabData();
      });
    });

    // Account save
    document.getElementById('settings-save-account').addEventListener('click', function() {
      var username = document.getElementById('settings-username').value.trim();
      var newPass = document.getElementById('settings-new-pass').value;
      var confirmPass = document.getElementById('settings-confirm-pass').value;

      if (newPass && newPass !== confirmPass) {
        Toast.error('Passwords do not match');
        return;
      }

      var body = {};
      if (username) body.username = username;
      if (newPass) body.password = newPass;

      fetch('/api/auth/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(body)
      })
      .then(function() { Toast.success('Account updated'); })
      .catch(function() { Toast.error('Update failed'); });
    });

    // 2FA
    document.getElementById('settings-2fa-btn').addEventListener('click', function() {
      fetch('/api/auth/2fa/setup', { method: 'POST', credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          Modal.open({
            title: 'Setup 2FA',
            body: '<div style="text-align:center;"><div style="color:var(--text-secondary);font-size:var(--font-size-sm);margin-bottom:12px;">Scan this secret with your authenticator app:</div><div class="code-block" style="display:inline-block;margin-bottom:12px;">' + escapeHtml(data.secret || data.otpauth || '--') + '</div><div class="form-group"><label class="form-label">Verification Code</label><input type="text" class="form-input" id="settings-2fa-code" placeholder="Enter 6-digit code"></div></div>',
            footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="settings-2fa-verify">Verify & Enable</button>'
          });

          document.getElementById('settings-2fa-verify').addEventListener('click', function() {
            var code = document.getElementById('settings-2fa-code').value.trim();
            fetch('/api/auth/2fa/verify', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'same-origin',
              body: JSON.stringify({ code: code })
            })
            .then(function(r) { return r.json(); })
            .then(function(data) {
              if (data.success) { Modal.close(); Toast.success('2FA enabled'); Views.settings.load2FAStatus(); }
              else Toast.error(data.error || data.message || '2FA verification failed');
            })
            .catch(function() { Toast.error('2FA setup failed'); });
          });
        })
        .catch(function() { Toast.error('2FA setup failed'); });
    });

    // Toggle Ollama config fields based on provider selection
    document.getElementById('settings-ai-provider').addEventListener('change', function() {
      var ollamaCfg = document.getElementById('settings-ollama-config');
      ollamaCfg.style.display = this.value === 'ollama' ? '' : 'none';
    });

    // AI save
    document.getElementById('settings-save-ai').addEventListener('click', function() {
      var provider = document.getElementById('settings-ai-provider').value;
      var saves = [
        fetch('/api/settings/ai', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ provider: provider })
        })
      ];
      if (provider === 'ollama') {
        var url = document.getElementById('settings-ollama-url').value.trim();
        var model = document.getElementById('settings-ollama-model').value.trim();
        if (url) saves.push(fetch('/api/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ key: 'ollamaBaseUrl', value: url }) }));
        if (model) saves.push(fetch('/api/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ key: 'ollamaModel', value: model }) }));
      }
      Promise.all(saves)
        .then(function() { Toast.success('AI provider saved'); })
        .catch(function() { Toast.error('Save failed'); });
    });

    // AI test
    document.getElementById('settings-test-ai').addEventListener('click', function() {
      var statusEl = document.getElementById('settings-ai-status');
      statusEl.innerHTML = '<div class="spinner spinner-sm" style="display:inline-block;vertical-align:middle;margin-right:8px;"></div>Testing...';
      fetch('/api/settings/ai/test', { credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          if (data.success || data.available) {
            statusEl.innerHTML = '<span style="color:var(--cyan);">&#10003; Connected — ' + escapeHtml(data.provider || 'AI') + ' is available</span>';
          } else {
            statusEl.innerHTML = '<span style="color:var(--orange);">&#10007; ' + escapeHtml(data.message || 'Not available') + '</span>';
          }
        })
        .catch(function() {
          statusEl.innerHTML = '<span style="color:var(--orange);">&#10007; Connection failed</span>';
        });
    });

    // Security save
    document.getElementById('settings-save-security').addEventListener('click', function() {
      var timeout = document.getElementById('settings-session-timeout').value;
      var attempts = document.getElementById('settings-max-attempts').value;
      var retention = document.getElementById('settings-audit-retention').value;
      fetch('/api/settings/security', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ session_timeout: parseInt(timeout), max_login_attempts: parseInt(attempts), audit_retention_days: parseInt(retention) })
      })
      .then(function() { Toast.success('Security settings saved'); })
      .catch(function() { Toast.error('Save failed'); });
    });
  },

  show: function() {
    this.loadTabData();
    // Load username
    if (State.user) {
      document.getElementById('settings-username').value = State.user.username || '';
    }
    // Always load 2FA status on show
    this.load2FAStatus();
    // Load AI settings
    this.loadAISettings();
  },

  hide: function() {},

  loadTabData: function() {
    if (this._activeTab === 'scanners') this.loadScanners();
    if (this._activeTab === 'about') this.loadAbout();
  },

  loadAISettings: function() {
    fetch('/api/settings/ai', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var sel = document.getElementById('settings-ai-provider');
        if (sel && data.provider) sel.value = data.provider;
        var ollamaCfg = document.getElementById('settings-ollama-config');
        if (ollamaCfg) ollamaCfg.style.display = data.provider === 'ollama' ? '' : 'none';
        if (data.ollamaBaseUrl) {
          var urlEl = document.getElementById('settings-ollama-url');
          if (urlEl) urlEl.value = data.ollamaBaseUrl;
        }
        if (data.ollamaModel) {
          var modelEl = document.getElementById('settings-ollama-model');
          if (modelEl) modelEl.value = data.ollamaModel;
        }
      })
      .catch(function() {});
  },

  load2FAStatus: function() {
    var statusEl = document.getElementById('settings-2fa-status');
    var btnEl = document.getElementById('settings-2fa-btn');
    if (!statusEl) return;
    fetch('/api/auth/session', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.twoFactorEnabled) {
          statusEl.innerHTML = '<span style="color:var(--cyan);">&#10003; 2FA is enabled</span>';
          btnEl.textContent = 'Reconfigure 2FA';
        } else {
          statusEl.innerHTML = '<span style="color:var(--text-tertiary);">2FA is not enabled</span>';
          btnEl.textContent = 'Setup 2FA';
        }
      })
      .catch(function() {
        statusEl.textContent = '2FA status unavailable';
      });
  },

  loadScanners: function() {
    var container = document.getElementById('settings-scanner-list');
    fetch('/api/settings/scanners', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var scanners = data.scanners || [
          { name: 'nmap', description: 'Network port scanner' },
          { name: 'nuclei', description: 'Vulnerability scanner' },
          { name: 'trivy', description: 'Container vulnerability scanner' },
          { name: 'zap', description: 'Web application scanner' }
        ];

        var html = '<table class="data-table"><thead><tr><th>Scanner</th><th>Description</th><th>Status</th><th>Version</th></tr></thead><tbody>';
        scanners.forEach(function(s) {
          var statusColor = s.installed || s.available ? 'var(--cyan)' : 'var(--orange)';
          var statusText = s.installed || s.available ? 'Installed' : 'Not Found';
          html += '<tr>' +
            '<td style="color:var(--text-primary);font-weight:600;">' + escapeHtml(s.name || '--') + '</td>' +
            '<td>' + escapeHtml(s.description || '--') + '</td>' +
            '<td><span style="color:' + statusColor + ';">' + statusText + '</span></td>' +
            '<td>' + escapeHtml(s.version || '--') + '</td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      })
      .catch(function() {
        container.innerHTML = '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">Could not check scanner status</div>';
      });
  },

  loadAbout: function() {
    fetch('/api/system', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var sys = data.system || data || {};
        document.getElementById('settings-platform').textContent = (sys.platform || '--') + ' ' + (sys.arch || '');
        document.getElementById('settings-node').textContent = sys.nodeVersion || sys.node_version || '--';
        var uptime = sys.uptime || 0;
        var hours = Math.floor(uptime / 3600);
        var mins = Math.floor((uptime % 3600) / 60);
        document.getElementById('settings-uptime').textContent = hours + 'h ' + mins + 'm';
      })
      .catch(function() {});
  }
};
