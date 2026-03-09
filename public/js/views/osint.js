/* Vigil v1.0 — OSINT Reconnaissance View */
Views.osint = {
  _lastDomainData: null,

  init: function() {
    var el = document.getElementById('view-osint');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">OSINT Reconnaissance</div>' +
      '</div>' +

      '<div class="tab-bar" id="osint-tabs">' +
        '<div class="tab-item active" data-tab="osint-domain">Domain Intel</div>' +
        '<div class="tab-item" data-tab="osint-ip">IP Lookup</div>' +
        '<div class="tab-item" data-tab="osint-phone">Phone Intel</div>' +
        '<div class="tab-item" data-tab="osint-username">Username</div>' +
        '<div class="tab-item" data-tab="osint-recon">Web Recon</div>' +
        '<div class="tab-item" data-tab="osint-history">History</div>' +
      '</div>' +

      // ── Domain Tab ──────────────────────────────────────────────────
      '<div class="tab-content active" id="osint-domain">' +
        '<div class="glass-card" style="margin-bottom:20px;">' +
          '<div class="form-inline">' +
            '<div class="form-group" style="flex:1;">' +
              '<label class="form-label">Domain</label>' +
              '<input type="text" class="form-input" id="osint-domain-input" placeholder="example.com">' +
            '</div>' +
            '<div class="form-group" style="align-self:flex-end;">' +
              '<button class="btn btn-primary" id="osint-domain-btn">Investigate</button>' +
            '</div>' +
          '</div>' +
        '</div>' +
        '<div id="osint-domain-results">' +
          '<div class="empty-state"><div class="empty-state-icon">&#128065;</div><div class="empty-state-title">Domain Intelligence</div><div class="empty-state-desc">Enter a domain to gather WHOIS, DNS, SSL, subdomains, certificates, and AI security assessment</div></div>' +
        '</div>' +
      '</div>' +

      // ── IP Tab ──────────────────────────────────────────────────────
      '<div class="tab-content" id="osint-ip">' +
        '<div class="glass-card" style="margin-bottom:20px;">' +
          '<div class="form-inline">' +
            '<div class="form-group" style="flex:1;">' +
              '<label class="form-label">IP Address</label>' +
              '<input type="text" class="form-input" id="osint-ip-input" placeholder="8.8.8.8">' +
            '</div>' +
            '<div class="form-group" style="align-self:flex-end;">' +
              '<button class="btn btn-primary" id="osint-ip-btn">Investigate</button>' +
            '</div>' +
          '</div>' +
        '</div>' +
        '<div id="osint-ip-results">' +
          '<div class="empty-state"><div class="empty-state-icon">&#128065;</div><div class="empty-state-title">IP Intelligence</div><div class="empty-state-desc">Enter an IP address for geolocation, reverse DNS, port scan, and AI assessment</div></div>' +
        '</div>' +
      '</div>' +

      // ── History Tab ─────────────────────────────────────────────────
      '<div class="tab-content" id="osint-history">' +
        '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Past Lookups</div>' +
          '<div id="osint-history-list">' +
            '<div class="empty-state"><div class="empty-state-icon">&#128339;</div><div class="empty-state-title">No History</div><div class="empty-state-desc">Investigations will appear here</div></div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      // ── Phone Intel Tab ────────────────────────────────────────────
      '<div class="tab-content" id="osint-phone">' +
        '<div class="glass-card" style="margin-bottom:20px;">' +
          '<div class="form-inline">' +
            '<div class="form-group" style="flex:1;">' +
              '<label class="form-label">Phone Number</label>' +
              '<input type="text" class="form-input" id="osint-phone-input" placeholder="+1 555 123 4567">' +
            '</div>' +
            '<div class="form-group" style="align-self:flex-end;">' +
              '<button class="btn btn-primary" id="osint-phone-btn">Analyze</button>' +
            '</div>' +
          '</div>' +
          '<div style="margin-top:6px;color:var(--text-tertiary);font-size:var(--font-size-xs);">Include country code (e.g. +1 for US, +44 for UK, +91 for India). Supports 70+ countries.</div>' +
        '</div>' +
        '<div id="osint-phone-results">' +
          '<div class="empty-state"><div class="empty-state-icon">&#128222;</div><div class="empty-state-title">Phone Intelligence</div><div class="empty-state-desc">Enter a phone number to identify country, carrier type, format validation, and AI analysis</div></div>' +
        '</div>' +
      '</div>' +

      // ── Username Tab ────────────────────────────────────────────────
      '<div class="tab-content" id="osint-username">' +
        '<div class="glass-card" style="margin-bottom:20px;">' +
          '<div class="form-inline">' +
            '<div class="form-group" style="flex:1;">' +
              '<label class="form-label">Username</label>' +
              '<input type="text" class="form-input" id="osint-username-input" placeholder="johndoe">' +
            '</div>' +
            '<div class="form-group" style="align-self:flex-end;">' +
              '<button class="btn btn-primary" id="osint-username-btn">Enumerate</button>' +
            '</div>' +
          '</div>' +
          '<div style="margin-top:6px;color:var(--text-tertiary);font-size:var(--font-size-xs);">Checks 26 platforms: GitHub, GitLab, Reddit, HackerNews, Twitch, YouTube, Steam, npm, PyPI, Docker Hub, Medium, and more.</div>' +
        '</div>' +
        '<div id="osint-username-results">' +
          '<div class="empty-state"><div class="empty-state-icon">&#128100;</div><div class="empty-state-title">Username Enumeration</div><div class="empty-state-desc">Enter a username to search across 26 social, dev, gaming, and content platforms</div></div>' +
        '</div>' +
      '</div>' +

      // ── Web Recon Tab ──────────────────────────────────────────────
      '<div class="tab-content" id="osint-recon">' +
        '<div class="glass-card" style="margin-bottom:20px;">' +
          '<div class="form-inline" style="flex-wrap:wrap;gap:12px;">' +
            '<div class="form-group" style="flex:1;min-width:200px;">' +
              '<label class="form-label">Target URL</label>' +
              '<input type="text" class="form-input" id="recon-target" placeholder="https://example.com">' +
            '</div>' +
            '<div class="form-group" style="min-width:160px;">' +
              '<label class="form-label">Spider Type</label>' +
              '<select class="form-select" id="recon-type">' +
                '<option value="surface">Surface Scan</option>' +
                '<option value="exposed">Exposed Files</option>' +
                '<option value="fingerprint">Tech Fingerprint</option>' +
                '<option value="threat-intel">Threat Intel</option>' +
              '</select>' +
            '</div>' +
            '<div class="form-group" id="recon-depth-group" style="min-width:80px;">' +
              '<label class="form-label">Depth</label>' +
              '<select class="form-select" id="recon-depth">' +
                '<option value="1">1</option>' +
                '<option value="2" selected>2</option>' +
                '<option value="3">3</option>' +
              '</select>' +
            '</div>' +
            '<div class="form-group" style="align-self:flex-end;display:flex;align-items:center;gap:12px;">' +
              '<label style="display:flex;align-items:center;gap:6px;cursor:pointer;color:var(--text-secondary);font-size:var(--font-size-xs);" title="Stealth mode: rotates user agents, randomizes timing, adds browser-like headers (Scrapling-inspired)">' +
                '<input type="checkbox" id="recon-stealth" style="accent-color:var(--cyan);">' +
                'Stealth' +
              '</label>' +
              '<button class="btn btn-primary" id="recon-start-btn">Crawl</button>' +
            '</div>' +
          '</div>' +
          '<div style="margin-top:8px;color:var(--text-tertiary);font-size:var(--font-size-xs);line-height:1.5;">' +
            '<strong>Surface Scan</strong> — Crawl pages, extract links/emails/tech/IOCs/headers. ' +
            '<strong>Exposed Files</strong> — Check 50+ sensitive paths (.env, .git, backups, configs). ' +
            '<strong>Tech Fingerprint</strong> — Deep stack detection + IOC extraction. ' +
            '<strong>Threat Intel</strong> — Scrape public feeds (CISA KEV, abuse.ch, OpenPhish, IPsum).' +
          '</div>' +
        '</div>' +
        '<div id="recon-progress" style="display:none;margin-bottom:12px;" class="glass-card">' +
          '<div style="display:flex;align-items:center;gap:8px;"><div class="spinner"></div><span id="recon-progress-text">Starting...</span></div>' +
        '</div>' +
        '<div id="recon-results"></div>' +
        '<div class="glass-card" style="margin-top:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:12px;">Recent Scans</div>' +
          '<div id="recon-history"><div class="loading-state"><div class="spinner"></div></div></div>' +
        '</div>' +
      '</div>';

    var self = this;

    // Tabs
    document.querySelectorAll('#osint-tabs .tab-item').forEach(function(tab) {
      tab.addEventListener('click', function() {
        document.querySelectorAll('#osint-tabs .tab-item').forEach(function(t) { t.classList.remove('active'); });
        tab.classList.add('active');
        document.querySelectorAll('#view-osint > .tab-content').forEach(function(c) { c.classList.remove('active'); });
        document.getElementById(tab.getAttribute('data-tab')).classList.add('active');
      });
    });

    document.getElementById('osint-domain-btn').addEventListener('click', function() { self.lookupDomain(); });
    document.getElementById('osint-domain-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') self.lookupDomain();
    });
    document.getElementById('osint-ip-btn').addEventListener('click', function() { self.lookupIP(); });
    document.getElementById('osint-ip-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') self.lookupIP();
    });
    document.getElementById('osint-phone-btn').addEventListener('click', function() { self.lookupPhone(); });
    document.getElementById('osint-phone-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') self.lookupPhone();
    });
    document.getElementById('osint-username-btn').addEventListener('click', function() { self.lookupUsername(); });
    document.getElementById('osint-username-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') self.lookupUsername();
    });
    document.getElementById('recon-start-btn').addEventListener('click', function() { self.startRecon(); });
    document.getElementById('recon-target').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') self.startRecon();
    });
    // Toggle target/depth visibility for threat-intel mode
    document.getElementById('recon-type').addEventListener('change', function() {
      var isTI = this.value === 'threat-intel';
      document.getElementById('recon-target').parentElement.style.display = isTI ? 'none' : '';
      document.getElementById('recon-depth-group').style.display = isTI ? 'none' : '';
    });

    // Socket.IO progress for recon
    if (window.socket) {
      window.socket.on('recon_progress', function(data) {
        if (self._reconScanId && data.scanId === self._reconScanId) {
          var el = document.getElementById('recon-progress-text');
          if (el) el.textContent = data.phase + ': ' + (data.url || data.message || data.path || '');
        }
      });
      window.socket.on('recon_complete', function(data) {
        if (self._reconScanId && data.scanId === self._reconScanId) {
          self.loadReconResult(data.scanId);
        }
      });
    }
  },

  show: function() {
    this.loadHistory();
    this.loadReconHistory();
  },

  hide: function() {},

  // ── Domain Investigation ────────────────────────────────────────────
  lookupDomain: function() {
    var domain = document.getElementById('osint-domain-input').value.trim();
    if (!domain) { Toast.warning('Enter a domain'); return; }

    var btn = document.getElementById('osint-domain-btn');
    var results = document.getElementById('osint-domain-results');
    btn.disabled = true;
    btn.textContent = 'Investigating...';
    results.innerHTML = '<div class="loading-state"><div class="spinner spinner-lg"></div><div>Gathering intelligence on ' + escapeHtml(domain) + '...<br><span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">DNS, WHOIS, SSL, subdomains, cert transparency, HTTP headers, AI analysis</span></div></div>';

    fetch('/api/osint/domain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ domain: domain })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      btn.disabled = false;
      btn.textContent = 'Investigate';

      if (data.error) { results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Error</div><div class="empty-state-desc">' + escapeHtml(data.error) + '</div></div>'; Toast.error(data.error); return; }

      Views.osint._lastDomainData = data;
      var html = '';

      // ── AI Analysis (top, most valuable) ──────────────────────────
      if (data.analysis) {
        html += '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:8px;color:var(--cyan);">AI Security Assessment</div>' +
          '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;white-space:pre-wrap;">' + escapeHtml(data.analysis) + '</div>' +
          '</div>';
      }

      // ── Stat cards ────────────────────────────────────────────────
      html += '<div class="stat-grid" style="margin-bottom:16px;">' +
        '<div class="stat-card">' +
          '<div class="stat-card-label">Subdomains</div>' +
          '<div class="stat-card-value" style="color:var(--cyan);">' + (data.subdomains || []).length + '</div>' +
        '</div>' +
        '<div class="stat-card">' +
          '<div class="stat-card-label">Certificates</div>' +
          '<div class="stat-card-value">' + (data.certificates || []).length + '</div>' +
        '</div>' +
        '<div class="stat-card">' +
          '<div class="stat-card-label">Technologies</div>' +
          '<div class="stat-card-value">' + (data.technologies || []).length + '</div>' +
        '</div>' +
        '<div class="stat-card">' +
          '<div class="stat-card-label">Missing Headers</div>' +
          '<div class="stat-card-value" style="color:' + ((data.httpInfo && data.httpInfo.missingHeaders && data.httpInfo.missingHeaders.length > 0) ? 'var(--orange)' : 'var(--cyan)') + ';">' + (data.httpInfo && data.httpInfo.missingHeaders ? data.httpInfo.missingHeaders.length : '--') + '</div>' +
        '</div>' +
      '</div>';

      // ── WHOIS + SSL side by side ──────────────────────────────────
      html += '<div class="grid-2" style="margin-bottom:16px;">';

      // WHOIS
      var whois = data.whois || {};
      html += '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:8px;">WHOIS</div>';
      if (whois.registrar || whois.created) {
        html += Views.osint.detailRow('Registrar', whois.registrar) +
          Views.osint.detailRow('Created', whois.created) +
          Views.osint.detailRow('Expires', whois.expires) +
          Views.osint.detailRow('Registrant', whois.registrant) +
          Views.osint.detailRow('Nameservers', (whois.nameservers || []).join(', '));
        if (whois.status && whois.status.length > 0) {
          html += '<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:4px;">';
          whois.status.forEach(function(s) { html += '<span class="tag" style="font-size:10px;">' + escapeHtml(s.split(' ')[0]) + '</span>'; });
          html += '</div>';
        }
      } else {
        html += '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">WHOIS data unavailable — install whois for full data</div>';
      }
      html += '</div>';

      // SSL
      var ssl = data.ssl;
      html += '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:8px;">SSL Certificate</div>';
      if (ssl) {
        html += Views.osint.detailRow('Common Name', ssl.cn) +
          Views.osint.detailRow('Issuer', ssl.issuer) +
          Views.osint.detailRow('Valid From', ssl.valid_from) +
          Views.osint.detailRow('Valid To', ssl.valid_to) +
          Views.osint.detailRow('Protocol', ssl.protocol) +
          Views.osint.detailRow('SAN Count', ssl.san_count);
      } else {
        html += '<div style="color:var(--orange);font-size:var(--font-size-sm);">No SSL certificate — site may not support HTTPS</div>';
      }
      html += '</div></div>';

      // ── Technologies ──────────────────────────────────────────────
      var tech = data.technologies || [];
      if (tech.length > 0) {
        html += '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:8px;">Technologies Detected</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
        tech.forEach(function(t) { html += '<span class="tag tag-cyan">' + escapeHtml(t) + '</span>'; });
        html += '</div></div>';
      }

      // ── Security Headers ──────────────────────────────────────────
      var httpInfo = data.httpInfo;
      if (httpInfo) {
        html += '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:8px;">HTTP Security Headers</div>';
        var sh = httpInfo.securityHeaders || {};
        var headerNames = ['strict-transport-security', 'content-security-policy', 'x-frame-options', 'x-content-type-options', 'x-xss-protection', 'referrer-policy', 'permissions-policy'];
        html += '<table class="data-table"><thead><tr><th>Header</th><th>Status</th><th>Value</th></tr></thead><tbody>';
        headerNames.forEach(function(h) {
          var val = sh[h];
          var present = val ? true : false;
          html += '<tr>' +
            '<td style="color:var(--text-primary);font-family:var(--font-mono);font-size:var(--font-size-xs);">' + escapeHtml(h) + '</td>' +
            '<td><span style="color:' + (present ? 'var(--cyan)' : 'var(--orange)') + ';font-weight:600;">' + (present ? 'Present' : 'Missing') + '</span></td>' +
            '<td style="font-size:var(--font-size-xs);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + escapeHtml(val || '--') + '</td>' +
            '</tr>';
        });
        html += '</tbody></table></div>';
      }

      // ── Subdomains ────────────────────────────────────────────────
      var subs = data.subdomains || [];
      if (subs.length > 0) {
        html += '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:8px;">Subdomains (' + subs.length + ')</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
        subs.forEach(function(s) { html += '<span class="tag">' + escapeHtml(s) + '</span>'; });
        html += '</div></div>';
      }

      // ── Certificates ──────────────────────────────────────────────
      var certs = data.certificates || [];
      if (certs.length > 0) {
        html += '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:8px;">Certificates (' + certs.length + ')</div>' +
          '<table class="data-table"><thead><tr><th>Common Name</th><th>Issuer</th><th>Valid Until</th></tr></thead><tbody>';
        certs.slice(0, 25).forEach(function(c) {
          html += '<tr>' +
            '<td style="color:var(--text-primary);">' + escapeHtml(c.cn || '--') + '</td>' +
            '<td>' + escapeHtml(c.issuer || '--') + '</td>' +
            '<td>' + escapeHtml(c.valid_to || '--') + '</td>' +
            '</tr>';
        });
        html += '</tbody></table></div>';
      }

      // ── DNS Records (collapsed) ───────────────────────────────────
      var dnsData = data.dns || {};
      var dnsTypes = Object.keys(dnsData);
      if (dnsTypes.length > 0) {
        html += '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:8px;">DNS Records</div>';
        dnsTypes.forEach(function(type) {
          var records = dnsData[type];
          if (!records) return;
          var recordStr = '';
          if (Array.isArray(records)) {
            recordStr = records.map(function(r) {
              if (typeof r === 'string') return r;
              if (r.exchange) return r.priority + ' ' + r.exchange;
              if (r.value) return r.value;
              return JSON.stringify(r);
            }).join(', ');
          } else if (typeof records === 'object') {
            recordStr = records.nsname ? records.nsname + ' (serial: ' + records.serial + ')' : JSON.stringify(records);
          }
          if (recordStr) {
            html += '<div style="margin-bottom:6px;">' +
              '<span class="tag tag-cyan" style="min-width:40px;text-align:center;display:inline-block;">' + escapeHtml(type) + '</span> ' +
              '<span style="color:var(--text-secondary);font-size:var(--font-size-sm);font-family:var(--font-mono);">' + escapeHtml(recordStr) + '</span>' +
              '</div>';
          }
        });
        html += '</div>';
      }

      // ── Re-analyze button ─────────────────────────────────────────
      if (!data.analysis) {
        html += '<div style="text-align:center;margin-top:16px;">' +
          '<button class="btn btn-ghost" id="osint-ai-domain">Run AI Analysis</button>' +
          '</div>';
      }

      results.innerHTML = html;
      Toast.success('OSINT investigation complete');

      // AI Analysis button handler (only if no analysis was returned)
      var aiBtn = document.getElementById('osint-ai-domain');
      if (aiBtn) {
        aiBtn.addEventListener('click', function() {
          aiBtn.disabled = true;
          aiBtn.textContent = 'Analyzing...';
          fetch('/api/osint/domain/' + encodeURIComponent(domain) + '/analyze', { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(d) {
              if (d.analysis) {
                Modal.open({ title: 'AI OSINT Analysis: ' + domain, body: '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;white-space:pre-wrap;">' + escapeHtml(d.analysis) + '</div>', size: 'lg' });
              } else {
                Toast.warning('No analysis available — configure AI provider in Settings');
              }
              aiBtn.disabled = false;
              aiBtn.textContent = 'Run AI Analysis';
            })
            .catch(function() { aiBtn.disabled = false; aiBtn.textContent = 'Run AI Analysis'; Toast.error('AI analysis failed'); });
        });
      }

      Views.osint.loadHistory();
    })
    .catch(function() {
      btn.disabled = false;
      btn.textContent = 'Investigate';
      results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Investigation Failed</div><div class="empty-state-desc">Check server connection and try again</div></div>';
      Toast.error('OSINT lookup failed');
    });
  },

  // ── IP Investigation ────────────────────────────────────────────────
  lookupIP: function() {
    var ip = document.getElementById('osint-ip-input').value.trim();
    if (!ip) { Toast.warning('Enter an IP address'); return; }

    var btn = document.getElementById('osint-ip-btn');
    var results = document.getElementById('osint-ip-results');
    btn.disabled = true;
    btn.textContent = 'Investigating...';
    results.innerHTML = '<div class="loading-state"><div class="spinner spinner-lg"></div><div>Gathering intelligence on ' + escapeHtml(ip) + '...<br><span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">Reverse DNS, geolocation, port scan, AI analysis</span></div></div>';

    fetch('/api/osint/ip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ ip: ip })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      btn.disabled = false;
      btn.textContent = 'Investigate';

      if (data.error) { results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Error</div><div class="empty-state-desc">' + escapeHtml(data.error) + '</div></div>'; Toast.error(data.error); return; }

      var html = '';

      // ── AI Analysis ───────────────────────────────────────────────
      if (data.analysis) {
        html += '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:8px;color:var(--cyan);">AI Security Assessment</div>' +
          '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;white-space:pre-wrap;">' + escapeHtml(data.analysis) + '</div>' +
          '</div>';
      }

      // ── Geolocation + Network ─────────────────────────────────────
      html += '<div class="grid-2" style="margin-bottom:16px;">';

      html += '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:8px;">Geolocation</div>' +
        Views.osint.detailRow('IP Address', data.ip) +
        Views.osint.detailRow('Country', (data.country || '--') + (data.countryCode ? ' (' + data.countryCode + ')' : '')) +
        Views.osint.detailRow('Region', data.region) +
        Views.osint.detailRow('City', data.city) +
        Views.osint.detailRow('Timezone', data.timezone) +
        (data.lat && data.lon ? Views.osint.detailRow('Coordinates', data.lat + ', ' + data.lon) : '') +
        '</div>';

      html += '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:8px;">Network</div>' +
        Views.osint.detailRow('ISP', data.isp) +
        Views.osint.detailRow('Organization', data.org) +
        Views.osint.detailRow('ASN', data.asn) +
        Views.osint.detailRow('AS Name', data.asName) +
        Views.osint.detailRow('Reverse DNS', data.reverse_dns || data.hostname) +
        '</div>';

      html += '</div>';

      // ── Open Ports ────────────────────────────────────────────────
      var ports = data.openPorts || [];
      html += '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:8px;">Port Scan</div>';
      if (ports.length > 0) {
        html += '<div style="display:flex;flex-wrap:wrap;gap:8px;">';
        ports.forEach(function(p) {
          var portNum = p.port || p;
          var svcName = '';
          if (portNum === 22) svcName = 'SSH';
          else if (portNum === 80) svcName = 'HTTP';
          else if (portNum === 443) svcName = 'HTTPS';
          else if (portNum === 8080) svcName = 'HTTP-Alt';
          else if (portNum === 8443) svcName = 'HTTPS-Alt';
          else if (portNum === 3389) svcName = 'RDP';
          else if (portNum === 3306) svcName = 'MySQL';
          else if (portNum === 5432) svcName = 'PostgreSQL';
          else if (portNum === 6379) svcName = 'Redis';
          else if (portNum === 27017) svcName = 'MongoDB';
          html += '<div style="background:rgba(34,211,238,0.08);border:1px solid rgba(34,211,238,0.2);border-radius:6px;padding:8px 12px;text-align:center;">' +
            '<div style="color:var(--cyan);font-weight:600;font-size:var(--font-size-lg);">' + portNum + '</div>' +
            (svcName ? '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + svcName + '</div>' : '') +
            '</div>';
        });
        html += '</div>';
      } else {
        html += '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">No open ports detected on common ports (22, 80, 443, 8080, 8443, 3389, 3306, 5432, 6379, 27017)</div>';
      }
      html += '</div>';

      results.innerHTML = html;
      Toast.success('IP investigation complete');
      Views.osint.loadHistory();
    })
    .catch(function() {
      btn.disabled = false;
      btn.textContent = 'Investigate';
      results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Investigation Failed</div><div class="empty-state-desc">Check server connection and try again</div></div>';
      Toast.error('IP lookup failed');
    });
  },

  // ── Phone Intelligence ──────────────────────────────────────────────
  lookupPhone: function() {
    var phone = document.getElementById('osint-phone-input').value.trim();
    if (!phone) { Toast.warning('Enter a phone number'); return; }

    var btn = document.getElementById('osint-phone-btn');
    var results = document.getElementById('osint-phone-results');
    btn.disabled = true;
    btn.textContent = 'Analyzing...';
    results.innerHTML = '<div class="loading-state"><div class="spinner spinner-lg"></div><div>Analyzing ' + escapeHtml(phone) + '...</div></div>';

    fetch('/api/osint/phone', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ phone: phone })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      btn.disabled = false;
      btn.textContent = 'Analyze';
      if (data.error && !data.countryCode) {
        results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Error</div><div class="empty-state-desc">' + escapeHtml(data.error) + '</div></div>';
        Toast.error(data.error);
        return;
      }

      var html = '';

      // AI Analysis
      if (data.analysis) {
        html += '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:8px;color:var(--cyan);">AI Analysis</div>' +
          '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;white-space:pre-wrap;">' + escapeHtml(data.analysis) + '</div>' +
          '</div>';
      }

      // Stat cards
      var validColor = data.valid ? 'var(--cyan)' : 'var(--orange)';
      html += '<div class="stat-grid" style="margin-bottom:16px;">' +
        '<div class="stat-card"><div class="stat-card-label">Country</div><div class="stat-card-value" style="font-size:var(--font-size-sm);">' + escapeHtml(data.country || 'Unknown') + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Country Code</div><div class="stat-card-value" style="color:var(--cyan);">' + escapeHtml(data.countryCode || '?') + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Line Type</div><div class="stat-card-value" style="font-size:var(--font-size-sm);color:var(--cyan);">' + escapeHtml((data.lineType || 'unknown').replace(/_/g, ' ')) + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Valid Format</div><div class="stat-card-value" style="color:' + validColor + ';">' + (data.valid ? 'Yes' : 'No') + '</div></div>' +
      '</div>';

      // Details
      html += '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-title" style="margin-bottom:8px;">Number Details</div>' +
        Views.osint.detailRow('Input', data.input) +
        Views.osint.detailRow('E.164', data.e164) +
        Views.osint.detailRow('International', data.international) +
        Views.osint.detailRow('National', data.national) +
        Views.osint.detailRow('ISO Code', data.iso) +
        Views.osint.detailRow('Number Length', data.numberLength + (data.expectedLengths ? ' (expected: ' + data.expectedLengths.join(' or ') + ')' : '')) +
        '</div>';

      results.innerHTML = html;
      Toast.success('Phone analysis complete');
      Views.osint.loadHistory();
    })
    .catch(function() {
      btn.disabled = false;
      btn.textContent = 'Analyze';
      results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Analysis Failed</div><div class="empty-state-desc">Check server connection and try again</div></div>';
      Toast.error('Phone analysis failed');
    });
  },

  // ── Username Enumeration ───────────────────────────────────────────
  lookupUsername: function() {
    var username = document.getElementById('osint-username-input').value.trim();
    if (!username) { Toast.warning('Enter a username'); return; }

    var btn = document.getElementById('osint-username-btn');
    var results = document.getElementById('osint-username-results');
    btn.disabled = true;
    btn.textContent = 'Enumerating...';
    results.innerHTML = '<div class="loading-state"><div class="spinner spinner-lg"></div><div>Checking ' + escapeHtml(username) + ' across 26 platforms...<br><span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">This may take 10-15 seconds</span></div></div>';

    fetch('/api/osint/username', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ username: username })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      btn.disabled = false;
      btn.textContent = 'Enumerate';
      if (data.error) {
        results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Error</div><div class="empty-state-desc">' + escapeHtml(data.error) + '</div></div>';
        Toast.error(data.error);
        return;
      }

      var html = '';

      // AI Analysis
      if (data.analysis) {
        html += '<div class="glass-card" style="margin-bottom:16px;">' +
          '<div class="glass-card-title" style="margin-bottom:8px;color:var(--cyan);">AI Digital Footprint Analysis</div>' +
          '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;white-space:pre-wrap;">' + escapeHtml(data.analysis) + '</div>' +
          '</div>';
      }

      // Stat cards
      html += '<div class="stat-grid" style="margin-bottom:16px;">' +
        '<div class="stat-card"><div class="stat-card-label">Username</div><div class="stat-card-value" style="font-size:var(--font-size-sm);color:var(--cyan);">' + escapeHtml(data.username) + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Found</div><div class="stat-card-value" style="color:' + (data.found ? 'var(--orange)' : 'var(--text-tertiary)') + ';">' + data.found + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Not Found</div><div class="stat-card-value">' + data.notFound + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Errors</div><div class="stat-card-value" style="color:' + (data.errors ? 'var(--orange)' : 'var(--text-tertiary)') + ';">' + data.errors + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Duration</div><div class="stat-card-value" style="font-size:var(--font-size-sm);">' + ((data.duration || 0) / 1000).toFixed(1) + 's</div></div>' +
      '</div>';

      // Platform results table
      var platformResults = data.results || [];
      if (platformResults.length) {
        html += '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:8px;">Platform Results</div>' +
          '<table class="data-table"><thead><tr><th>Platform</th><th>Category</th><th>Status</th><th>Profile</th></tr></thead><tbody>';
        platformResults.forEach(function(r) {
          var statusColor = r.found ? 'var(--cyan)' : r.statusCode === 0 ? 'var(--text-tertiary)' : 'var(--text-secondary)';
          var statusText = r.found ? 'FOUND' : r.statusCode === 0 ? 'Error' : 'Not Found';
          html += '<tr>' +
            '<td style="color:var(--text-primary);font-weight:500;">' + escapeHtml(r.platform) + '</td>' +
            '<td><span class="tag" style="font-size:10px;">' + escapeHtml(r.category) + '</span></td>' +
            '<td style="color:' + statusColor + ';font-weight:600;font-size:var(--font-size-xs);">' + statusText + '</td>' +
            '<td>' + (r.found ? '<a href="' + escapeHtml(r.url) + '" target="_blank" rel="noopener" style="color:var(--cyan);font-size:var(--font-size-xs);text-decoration:none;">View Profile &rarr;</a>' : '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">--</span>') + '</td>' +
            '</tr>';
        });
        html += '</tbody></table></div>';
      }

      results.innerHTML = html;
      Toast.success('Username enumeration complete: ' + data.found + '/' + data.total + ' platforms');
      Views.osint.loadHistory();
    })
    .catch(function() {
      btn.disabled = false;
      btn.textContent = 'Enumerate';
      results.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#10007;</div><div class="empty-state-title">Enumeration Failed</div><div class="empty-state-desc">Check server connection and try again</div></div>';
      Toast.error('Username enumeration failed');
    });
  },

  // ── History ─────────────────────────────────────────────────────────
  loadHistory: function() {
    var container = document.getElementById('osint-history-list');
    fetch('/api/osint/history', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var history = data.history || data || [];
        if (!Array.isArray(history) || history.length === 0) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128339;</div><div class="empty-state-title">No History</div><div class="empty-state-desc">Investigations will appear here</div></div>';
          return;
        }
        var html = '<table class="data-table"><thead><tr><th>Type</th><th>Target</th><th>Summary</th><th>Time</th></tr></thead><tbody>';
        history.slice(0, 30).forEach(function(h) {
          html += '<tr>' +
            '<td><span class="tag tag-cyan">' + escapeHtml(h.type || '--') + '</span></td>' +
            '<td style="color:var(--text-primary);font-weight:500;">' + escapeHtml(h.target || h.query || '--') + '</td>' +
            '<td style="color:var(--text-tertiary);font-size:var(--font-size-xs);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + escapeHtml(h.summary || '--') + '</td>' +
            '<td>' + timeAgo(h.created_at || h.timestamp) + '</td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      })
      .catch(function() {});
  },

  // ── Helper: detail row ──────────────────────────────────────────────
  detailRow: function(label, value) {
    return '<div class="detail-row">' +
      '<div class="detail-label">' + escapeHtml(label) + '</div>' +
      '<div class="detail-value">' + escapeHtml(value || '--') + '</div>' +
      '</div>';
  },

  // ══════════════════════════════════════════════════════════════════════
  //  Web Recon (Scrapy-inspired)
  // ══════════════════════════════════════════════════════════════════════
  _reconScanId: null,

  startRecon: function() {
    var type = document.getElementById('recon-type').value;
    var target = document.getElementById('recon-target').value.trim();
    if (type !== 'threat-intel' && !target) { Toast.warning('Enter a target URL'); return; }

    var depth = parseInt(document.getElementById('recon-depth').value) || 2;
    var stealth = document.getElementById('recon-stealth').checked;
    var btn = document.getElementById('recon-start-btn');
    var progress = document.getElementById('recon-progress');
    var results = document.getElementById('recon-results');

    btn.disabled = true;
    btn.textContent = type === 'threat-intel' ? 'Fetching...' : 'Crawling...';
    progress.style.display = 'block';
    document.getElementById('recon-progress-text').textContent = 'Starting ' + type + ' scan...' + (stealth ? ' (stealth mode)' : '');
    results.innerHTML = '';

    var self = this;
    var payload = { spiderType: type, depth: depth, maxPages: 30, delay: 500, stealth: stealth };
    if (type !== 'threat-intel') payload.target = target;
    else payload.target = 'threat-feeds';

    fetch('/api/osint/recon', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.error) {
        Toast.error(data.error);
        btn.disabled = false;
        btn.textContent = 'Crawl';
        progress.style.display = 'none';
        return;
      }
      self._reconScanId = data.scanId;
      Toast.info('Recon started: ' + data.spiderType);

      // Poll for results (in case Socket.IO event is missed)
      self._pollRecon(data.scanId, btn, progress);
    })
    .catch(function(e) {
      Toast.error('Failed to start: ' + e.message);
      btn.disabled = false;
      btn.textContent = 'Crawl';
      progress.style.display = 'none';
    });
  },

  _pollRecon: function(scanId, btn, progress) {
    var self = this;
    var attempts = 0;
    var maxAttempts = 60; // 60 * 3s = 3 min max
    var poll = setInterval(function() {
      attempts++;
      fetch('/api/osint/recon/' + scanId, { credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          if (data.status === 'running' && attempts < maxAttempts) return;
          clearInterval(poll);
          btn.disabled = false;
          btn.textContent = 'Crawl';
          progress.style.display = 'none';
          if (data.error) { Toast.error(data.error); return; }
          if (data.summary) {
            Toast.success('Recon complete: ' + data.summary.pagesScanned + ' pages scanned');
            self.renderReconResult(data);
            self.loadReconHistory();
          }
        })
        .catch(function() {
          if (attempts >= maxAttempts) {
            clearInterval(poll);
            btn.disabled = false;
            btn.textContent = 'Crawl';
            progress.style.display = 'none';
          }
        });
    }, 3000);
  },

  loadReconResult: function(scanId) {
    var self = this;
    fetch('/api/osint/recon/' + scanId, { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.summary) {
          var btn = document.getElementById('recon-start-btn');
          var progress = document.getElementById('recon-progress');
          btn.disabled = false;
          btn.textContent = 'Crawl';
          progress.style.display = 'none';
          Toast.success('Recon complete');
          self.renderReconResult(data);
          self.loadReconHistory();
        }
      })
      .catch(function() {});
  },

  renderReconResult: function(data) {
    var container = document.getElementById('recon-results');

    // Threat Intel has a different result structure
    if (data.spiderType === 'threat-intel') {
      this.renderThreatIntelResult(data);
      return;
    }

    var s = data.summary || {};
    var headerScore = s.securityHeaderScore !== null ? s.securityHeaderScore : '--';
    var headerColor = headerScore >= 80 ? 'var(--cyan)' : headerScore >= 50 ? 'var(--purple)' : 'var(--orange)';
    var iocCount = s.iocsExtracted || 0;

    var html = '<div class="glass-card" style="margin-bottom:16px;">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">' +
        '<div class="glass-card-title">Results: ' + escapeHtml(data.target || '') +
          (data.stealth ? ' <span style="color:var(--cyan);font-size:var(--font-size-xs);font-weight:400;">STEALTH</span>' : '') +
        '</div>' +
        '<button class="btn btn-ghost btn-sm" id="recon-ai-btn" data-id="' + escapeHtml(data.id || '') + '" style="color:var(--cyan);">AI Analysis</button>' +
      '</div>' +

      '<div class="stat-grid" style="margin-bottom:16px;">' +
        '<div class="stat-card"><div class="stat-card-label">Pages</div><div class="stat-card-value">' + (s.pagesScanned || 0) + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Emails</div><div class="stat-card-value" style="color:' + (s.emailsFound ? 'var(--orange)' : 'var(--text-tertiary)') + ';">' + (s.emailsFound || 0) + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Technologies</div><div class="stat-card-value" style="color:var(--cyan);">' + (s.technologiesDetected || 0) + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Exposed Paths</div><div class="stat-card-value" style="color:' + (s.exposedPathsFound ? 'var(--orange)' : 'var(--cyan)') + ';">' + (s.exposedPathsFound || 0) + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Header Score</div><div class="stat-card-value" style="color:' + headerColor + ';">' + headerScore + '%</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">IOCs Found</div><div class="stat-card-value" style="color:' + (iocCount ? 'var(--orange)' : 'var(--text-tertiary)') + ';">' + iocCount + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Duration</div><div class="stat-card-value" style="font-size:var(--font-size-sm);">' + ((data.duration || 0) / 1000).toFixed(1) + 's</div></div>' +
      '</div>';

    // Technologies
    if (data.technologies && data.technologies.length) {
      html += '<div style="margin-bottom:12px;"><div style="font-weight:600;color:var(--text-primary);margin-bottom:6px;">Technologies Detected</div>' +
        '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
      data.technologies.forEach(function(t) {
        html += '<span class="badge" style="background:rgba(34,211,238,0.1);color:var(--cyan);border:1px solid rgba(34,211,238,0.2);padding:3px 10px;border-radius:12px;font-size:var(--font-size-xs);">' + escapeHtml(t) + '</span>';
      });
      html += '</div></div>';
    }

    // Emails
    if (data.emails && data.emails.length) {
      html += '<div style="margin-bottom:12px;"><div style="font-weight:600;color:var(--text-primary);margin-bottom:6px;">Emails Found</div>' +
        '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
      data.emails.forEach(function(e) {
        html += '<span style="color:var(--orange);font-family:var(--font-mono);font-size:var(--font-size-xs);">' + escapeHtml(e) + '</span>';
      });
      html += '</div></div>';
    }

    // Security Headers
    if (data.securityHeaders) {
      html += '<div style="margin-bottom:12px;"><div style="font-weight:600;color:var(--text-primary);margin-bottom:6px;">Security Headers (' + data.securityHeaders.score + '%)</div>';
      if (data.securityHeaders.missing.length) {
        html += '<div style="color:var(--orange);font-size:var(--font-size-xs);margin-bottom:4px;">Missing: ' + data.securityHeaders.missing.map(function(h) { return escapeHtml(h); }).join(', ') + '</div>';
      }
      if (data.securityHeaders.present.length) {
        html += '<div style="color:var(--cyan);font-size:var(--font-size-xs);">Present: ' + data.securityHeaders.present.map(function(h) { return escapeHtml(h.header); }).join(', ') + '</div>';
      }
      html += '</div>';
    }

    // Exposed Paths
    if (data.exposedPaths && data.exposedPaths.length) {
      html += '<div style="margin-bottom:12px;"><div style="font-weight:600;color:var(--text-primary);margin-bottom:6px;">Exposed / Notable Paths</div>' +
        '<table class="data-table"><thead><tr><th>Path</th><th>Status</th><th>Size</th><th>Risk</th></tr></thead><tbody>';
      data.exposedPaths.forEach(function(p) {
        var riskColor = p.risk === 'critical' ? 'var(--orange)' : p.risk === 'high' ? 'var(--orange)' : p.risk === 'medium' ? 'var(--purple)' : 'var(--text-tertiary)';
        html += '<tr>' +
          '<td style="font-family:var(--font-mono);font-size:var(--font-size-xs);">' + escapeHtml(p.path) + '</td>' +
          '<td>' + (p.exposed ? '<span style="color:var(--orange);">' + p.statusCode + ' exposed</span>' : '<span style="color:var(--text-tertiary);">' + p.statusCode + '</span>') + '</td>' +
          '<td style="color:var(--text-tertiary);">' + (p.size || '--') + 'B</td>' +
          '<td style="color:' + riskColor + ';text-transform:uppercase;font-size:var(--font-size-xs);font-weight:600;">' + escapeHtml(p.risk || '') + '</td>' +
          '</tr>';
      });
      html += '</tbody></table></div>';
    }

    // Forms
    if (data.forms && data.forms.length) {
      html += '<div style="margin-bottom:12px;"><div style="font-weight:600;color:var(--text-primary);margin-bottom:6px;">Forms Found (' + data.forms.length + ')</div>' +
        '<table class="data-table"><thead><tr><th>Page</th><th>Method</th><th>Inputs</th><th>Flags</th></tr></thead><tbody>';
      data.forms.forEach(function(f) {
        var flags = [];
        if (f.hasPassword) flags.push('<span style="color:var(--orange);">Login</span>');
        if (f.hasFile) flags.push('<span style="color:var(--orange);">File Upload</span>');
        html += '<tr>' +
          '<td style="font-size:var(--font-size-xs);max-width:200px;overflow:hidden;text-overflow:ellipsis;">' + escapeHtml(f.page || f.action || '') + '</td>' +
          '<td>' + escapeHtml(f.method) + '</td>' +
          '<td>' + f.inputCount + '</td>' +
          '<td>' + (flags.join(', ') || '--') + '</td>' +
          '</tr>';
      });
      html += '</tbody></table></div>';
    }

    // IOCs section
    var iocs = data.iocs || {};
    var hasIOCs = (iocs.ipv4 && iocs.ipv4.length) || (iocs.md5 && iocs.md5.length) || (iocs.sha256 && iocs.sha256.length) || (iocs.cves && iocs.cves.length);
    if (hasIOCs) {
      html += '<div style="margin-bottom:12px;"><div style="font-weight:600;color:var(--text-primary);margin-bottom:6px;">Indicators of Compromise (IOCs)</div>';
      if (iocs.cves && iocs.cves.length) {
        html += '<div style="margin-bottom:6px;"><span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">CVEs:</span> ';
        iocs.cves.forEach(function(c) { html += '<span class="badge" style="background:rgba(255,107,43,0.1);color:var(--orange);border:1px solid rgba(255,107,43,0.2);padding:2px 8px;border-radius:10px;font-size:var(--font-size-xs);margin:2px;">' + escapeHtml(c) + '</span>'; });
        html += '</div>';
      }
      if (iocs.ipv4 && iocs.ipv4.length) {
        html += '<div style="margin-bottom:6px;"><span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">IPs (' + iocs.ipv4.length + '):</span> ' +
          '<span style="font-family:var(--font-mono);font-size:var(--font-size-xs);color:var(--text-secondary);">' + iocs.ipv4.slice(0, 20).map(function(ip) { return escapeHtml(ip); }).join(', ') + (iocs.ipv4.length > 20 ? '...' : '') + '</span></div>';
      }
      if (iocs.md5 && iocs.md5.length) {
        html += '<div style="margin-bottom:6px;"><span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">MD5 (' + iocs.md5.length + '):</span> ' +
          '<span style="font-family:var(--font-mono);font-size:10px;color:var(--text-secondary);word-break:break-all;">' + iocs.md5.slice(0, 10).map(function(h) { return escapeHtml(h); }).join(', ') + (iocs.md5.length > 10 ? '...' : '') + '</span></div>';
      }
      if (iocs.sha256 && iocs.sha256.length) {
        html += '<div style="margin-bottom:6px;"><span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">SHA256 (' + iocs.sha256.length + '):</span> ' +
          '<span style="font-family:var(--font-mono);font-size:10px;color:var(--text-secondary);word-break:break-all;">' + iocs.sha256.slice(0, 5).map(function(h) { return escapeHtml(h); }).join(', ') + (iocs.sha256.length > 5 ? '...' : '') + '</span></div>';
      }
      html += '</div>';
    }

    html += '<div id="recon-ai-result"></div></div>';
    container.innerHTML = html;

    // Bind AI analysis button
    var aiBtn = document.getElementById('recon-ai-btn');
    if (aiBtn) {
      aiBtn.addEventListener('click', function() {
        var id = aiBtn.getAttribute('data-id');
        var resultEl = document.getElementById('recon-ai-result');
        resultEl.innerHTML = '<div class="loading-state"><div class="spinner"></div><div>AI analyzing reconnaissance data...</div></div>';
        fetch('/api/osint/recon/' + id + '/analyze', { method: 'POST', credentials: 'same-origin' })
          .then(function(r) { return r.json(); })
          .then(function(d) {
            if (d.error) { resultEl.innerHTML = '<div style="color:var(--orange);">' + escapeHtml(d.error) + '</div>'; return; }
            resultEl.innerHTML = '<div style="margin-top:12px;padding:12px;background:var(--well);border-radius:8px;border-left:3px solid var(--cyan);white-space:pre-wrap;font-size:var(--font-size-xs);line-height:1.7;color:var(--text-secondary);">' + escapeHtml(d.analysis) + '</div>';
          })
          .catch(function() { resultEl.innerHTML = '<div style="color:var(--orange);">AI analysis failed</div>'; });
      });
    }
  },

  renderThreatIntelResult: function(data) {
    var container = document.getElementById('recon-results');
    var s = data.summary || {};
    var iocs = data.iocs || {};
    var totalIOCs = (iocs.ipv4 || []).length + (iocs.md5 || []).length + (iocs.sha256 || []).length + (iocs.cves || []).length;

    var html = '<div class="glass-card" style="margin-bottom:16px;">' +
      '<div class="glass-card-title" style="margin-bottom:12px;">Threat Intelligence Collection</div>' +

      '<div class="stat-grid" style="margin-bottom:16px;">' +
        '<div class="stat-card"><div class="stat-card-label">Feeds Queried</div><div class="stat-card-value">' + (s.feedsQueried || 0) + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Feeds OK</div><div class="stat-card-value" style="color:var(--cyan);">' + (s.feedsSucceeded || 0) + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Total Entries</div><div class="stat-card-value">' + (s.totalEntries || 0) + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">IOCs Extracted</div><div class="stat-card-value" style="color:' + (totalIOCs ? 'var(--orange)' : 'var(--text-tertiary)') + ';">' + totalIOCs + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Duration</div><div class="stat-card-value" style="font-size:var(--font-size-sm);">' + ((data.duration || 0) / 1000).toFixed(1) + 's</div></div>' +
      '</div>';

    // Feed results table
    var feeds = data.feeds || [];
    if (feeds.length) {
      html += '<div style="margin-bottom:12px;"><div style="font-weight:600;color:var(--text-primary);margin-bottom:6px;">Feed Results</div>' +
        '<table class="data-table"><thead><tr><th>Feed</th><th>Status</th><th>Entries</th><th>Time</th></tr></thead><tbody>';
      feeds.forEach(function(f) {
        var statusColor = f.status === 'ok' ? 'var(--cyan)' : 'var(--orange)';
        html += '<tr>' +
          '<td style="color:var(--text-primary);font-size:var(--font-size-xs);">' + escapeHtml(f.name) + '</td>' +
          '<td style="color:' + statusColor + ';text-transform:uppercase;font-size:var(--font-size-xs);font-weight:600;">' + escapeHtml(f.status) + '</td>' +
          '<td>' + (f.entries || 0) + '</td>' +
          '<td style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + (f.fetchedAt ? new Date(f.fetchedAt).toLocaleTimeString() : '--') + '</td>' +
          '</tr>';
      });
      html += '</tbody></table></div>';
    }

    // CISA KEV entries (if present)
    var cisaFeed = feeds.find(function(f) { return f.feed === 'cisa_kev' && f.data && f.data.length; });
    if (cisaFeed) {
      html += '<div style="margin-bottom:12px;"><div style="font-weight:600;color:var(--text-primary);margin-bottom:6px;">CISA Known Exploited Vulnerabilities (Latest ' + Math.min(cisaFeed.data.length, 15) + ')</div>' +
        '<table class="data-table"><thead><tr><th>CVE</th><th>Vendor</th><th>Product</th><th>Due Date</th></tr></thead><tbody>';
      cisaFeed.data.slice(0, 15).forEach(function(v) {
        html += '<tr>' +
          '<td style="color:var(--orange);font-family:var(--font-mono);font-size:var(--font-size-xs);">' + escapeHtml(v.cve || '') + '</td>' +
          '<td style="font-size:var(--font-size-xs);">' + escapeHtml(v.vendor || '') + '</td>' +
          '<td style="font-size:var(--font-size-xs);">' + escapeHtml(v.product || '') + '</td>' +
          '<td style="font-size:var(--font-size-xs);color:var(--text-tertiary);">' + escapeHtml(v.dueDate || '') + '</td>' +
          '</tr>';
      });
      html += '</tbody></table></div>';
    }

    // Extracted IOCs
    if (totalIOCs > 0) {
      html += '<div style="margin-bottom:12px;"><div style="font-weight:600;color:var(--text-primary);margin-bottom:6px;">Extracted IOCs</div>';
      if (iocs.ipv4 && iocs.ipv4.length) {
        html += '<div style="margin-bottom:6px;"><span class="badge" style="background:rgba(255,107,43,0.1);color:var(--orange);padding:2px 8px;border-radius:10px;font-size:var(--font-size-xs);">IPs: ' + iocs.ipv4.length + '</span> ' +
          '<span style="font-family:var(--font-mono);font-size:10px;color:var(--text-secondary);">' + iocs.ipv4.slice(0, 30).map(function(ip) { return escapeHtml(ip); }).join(', ') + (iocs.ipv4.length > 30 ? '...' : '') + '</span></div>';
      }
      if (iocs.cves && iocs.cves.length) {
        html += '<div style="margin-bottom:6px;"><span class="badge" style="background:rgba(255,107,43,0.1);color:var(--orange);padding:2px 8px;border-radius:10px;font-size:var(--font-size-xs);">CVEs: ' + iocs.cves.length + '</span> ' +
          '<span style="font-family:var(--font-mono);font-size:10px;color:var(--text-secondary);">' + iocs.cves.slice(0, 20).map(function(c) { return escapeHtml(c); }).join(', ') + (iocs.cves.length > 20 ? '...' : '') + '</span></div>';
      }
      if (iocs.md5 && iocs.md5.length) {
        html += '<div style="margin-bottom:6px;"><span class="badge" style="background:rgba(255,107,43,0.1);color:var(--orange);padding:2px 8px;border-radius:10px;font-size:var(--font-size-xs);">MD5: ' + iocs.md5.length + '</span> ' +
          '<span style="font-family:var(--font-mono);font-size:10px;color:var(--text-secondary);word-break:break-all;">' + iocs.md5.slice(0, 10).map(function(h) { return escapeHtml(h); }).join(', ') + (iocs.md5.length > 10 ? '...' : '') + '</span></div>';
      }
      html += '</div>';
    }

    html += '</div>';
    container.innerHTML = html;
  },

  loadReconHistory: function() {
    var container = document.getElementById('recon-history');
    if (!container) return;
    fetch('/api/osint/recon', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (!data.length) {
          container.innerHTML = '<div class="empty-state" style="padding:24px;"><div class="empty-state-icon">&#128375;</div><div class="empty-state-title">No Recon Scans</div><div class="empty-state-desc">Run a web recon scan to discover attack surface, exposed files, and technologies</div></div>';
          return;
        }
        var html = '<table class="data-table"><thead><tr><th>Target</th><th>Type</th><th>Pages</th><th>Findings</th><th>Time</th></tr></thead><tbody>';
        data.slice(0, 20).forEach(function(r) {
          var s = r.summary || {};
          var findings = (s.exposedPathsFound || 0) + (s.emailsFound || 0);
          html += '<tr style="cursor:pointer;" onclick="Views.osint.loadReconResult(\'' + escapeHtml(r.id) + '\')">' +
            '<td style="font-family:var(--font-mono);font-size:var(--font-size-xs);color:var(--cyan);">' + escapeHtml(r.domain || r.target || '') + '</td>' +
            '<td>' + escapeHtml(r.spiderType || '') + '</td>' +
            '<td>' + (s.pagesScanned || 0) + '</td>' +
            '<td style="color:' + (findings ? 'var(--orange)' : 'var(--text-tertiary)') + ';">' + findings + '</td>' +
            '<td style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + ((r.duration || 0) / 1000).toFixed(1) + 's</td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
      })
      .catch(function() { container.innerHTML = ''; });
  }
};
