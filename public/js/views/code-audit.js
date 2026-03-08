/* Vigil v1.0 — Code Audit View (LLM-Driven Vulnerability Scanner) */
Views['code-audit'] = {
  _scanId: null,
  _pollTimer: null,

  init: function() {
    var el = document.getElementById('view-code-audit');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Code Audit</div>' +
        '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">AI-powered source code vulnerability scanner</div>' +
      '</div>' +

      // Config card
      '<div class="glass-card" style="margin-bottom:20px;">' +
        '<div class="form-inline" style="flex-wrap:wrap;gap:10px;">' +
          '<div class="form-group" style="flex:3;min-width:250px;">' +
            '<label class="form-label">Target Directory</label>' +
            '<input type="text" class="form-input" id="ca-target" placeholder="/path/to/project">' +
          '</div>' +
          '<div class="form-group" style="flex:1;min-width:140px;">' +
            '<label class="form-label">Languages</label>' +
            '<select class="form-select" id="ca-language">' +
              '<option value="all">All Supported</option>' +
              '<option value="javascript">JavaScript</option>' +
              '<option value="typescript">TypeScript</option>' +
              '<option value="python">Python</option>' +
              '<option value="php">PHP</option>' +
              '<option value="ruby">Ruby</option>' +
              '<option value="java">Java</option>' +
              '<option value="go">Go</option>' +
              '<option value="csharp">C#</option>' +
            '</select>' +
          '</div>' +
          '<div class="form-group" style="flex:1;min-width:140px;">' +
            '<label class="form-label">Vuln Types</label>' +
            '<select class="form-select" id="ca-vulntype">' +
              '<option value="all">All Types</option>' +
              '<option value="RCE">RCE</option>' +
              '<option value="SQLi">SQL Injection</option>' +
              '<option value="XSS">Cross-Site Scripting</option>' +
              '<option value="SSRF">SSRF</option>' +
              '<option value="LFI">Local File Inclusion</option>' +
              '<option value="AFO">Arbitrary File Overwrite</option>' +
              '<option value="IDOR">IDOR</option>' +
            '</select>' +
          '</div>' +
          '<div class="form-group" style="align-self:flex-end;display:flex;gap:8px;">' +
            '<button class="btn btn-ghost btn-sm" id="ca-preview-btn">Preview</button>' +
            '<button class="btn btn-primary" id="ca-scan-btn">Scan</button>' +
          '</div>' +
        '</div>' +
      '</div>' +

      // Progress card (hidden by default)
      '<div class="glass-card" id="ca-progress-card" style="display:none;margin-bottom:20px;">' +
        '<div style="display:flex;align-items:center;gap:12px;">' +
          '<div class="spinner"></div>' +
          '<div>' +
            '<div style="color:var(--text-primary);font-weight:500;" id="ca-progress-title">Running code audit...</div>' +
            '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);margin-top:4px;" id="ca-progress-detail">Initializing...</div>' +
          '</div>' +
        '</div>' +
        '<div style="margin-top:12px;height:4px;background:var(--border);border-radius:2px;overflow:hidden;">' +
          '<div id="ca-progress-bar" style="height:100%;width:0%;background:var(--cyan);border-radius:2px;transition:width 0.5s ease;"></div>' +
        '</div>' +
      '</div>' +

      // Results section
      '<div id="ca-results">' +
        '<div class="glass-card">' +
          '<div class="empty-state">' +
            '<div class="empty-state-icon">&#128269;</div>' +
            '<div class="empty-state-title">No Scan Results</div>' +
            '<div class="empty-state-desc">Enter a project directory path and click Scan to start AI-powered vulnerability analysis</div>' +
          '</div>' +
        '</div>' +
      '</div>';

    var self = this;
    document.getElementById('ca-scan-btn').addEventListener('click', function() { self.runScan(); });
    document.getElementById('ca-preview-btn').addEventListener('click', function() { self.previewFiles(); });

    // Listen for Socket.IO progress events
    if (window._socket) {
      window._socket.on('code_audit_progress', function(data) {
        if (data.scanId === self._scanId) {
          self.updateProgress(data);
        }
      });
      window._socket.on('scan_complete', function(data) {
        if (data.id === self._scanId && data.type === 'code-audit') {
          self.loadResults(data.id);
        }
      });
    }
  },

  show: function() {},
  hide: function() {
    if (this._pollTimer) { clearInterval(this._pollTimer); this._pollTimer = null; }
  },

  previewFiles: function() {
    var target = document.getElementById('ca-target').value.trim();
    if (!target) { Toast.warning('Enter a target directory path'); return; }

    var lang = document.getElementById('ca-language').value;
    var languages = lang === 'all' ? [] : [lang];

    Modal.loading('Discovering files...');

    fetch('/api/code-audit/preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ target: target, languages: languages })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      Modal.close();
      if (data.error) { Toast.error(data.error); return; }

      var html = '<div style="color:var(--text-secondary);margin-bottom:12px;">' +
        '<strong>' + data.fileCount + '</strong> files found in <code>' + escapeHtml(data.path) + '</code></div>';
      html += '<div style="max-height:400px;overflow-y:auto;font-family:var(--font-mono);font-size:var(--font-size-xs);">';
      (data.files || []).forEach(function(f) {
        html += '<div style="padding:3px 0;border-bottom:1px solid var(--border);">' +
          '<span style="color:var(--text-primary);">' + escapeHtml(f.path) + '</span>' +
          '<span style="color:var(--text-tertiary);margin-left:8px;">(' + (f.size / 1024).toFixed(1) + ' KB)</span></div>';
      });
      html += '</div>';

      Modal.open({ title: 'Files to Analyze', body: html, size: 'lg' });
    })
    .catch(function() { Modal.close(); Toast.error('Preview failed'); });
  },

  runScan: function() {
    var target = document.getElementById('ca-target').value.trim();
    if (!target) { Toast.warning('Enter a target directory path'); return; }

    var lang = document.getElementById('ca-language').value;
    var vulnType = document.getElementById('ca-vulntype').value;
    var languages = lang === 'all' ? [] : [lang];
    var vulnTypes = vulnType === 'all' ? [] : [vulnType];

    var scanBtn = document.getElementById('ca-scan-btn');
    var progressCard = document.getElementById('ca-progress-card');

    scanBtn.disabled = true;
    progressCard.style.display = 'block';
    this.updateProgress({ phase: 'starting', message: 'Initializing code audit...' });

    var self = this;

    fetch('/api/code-audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ target: target, languages: languages, vulnTypes: vulnTypes })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.error) {
        progressCard.style.display = 'none';
        scanBtn.disabled = false;
        Toast.error(data.error);
        return;
      }

      self._scanId = data.scan.id;
      self.updateProgress({ phase: 'running', message: 'AI analysis in progress...' });

      // Poll for results in case Socket.IO misses the event
      self._pollTimer = setInterval(function() {
        fetch('/api/code-audit/' + self._scanId, { credentials: 'same-origin' })
          .then(function(r) { return r.json(); })
          .then(function(scan) {
            if (scan.status === 'completed' || scan.status === 'failed') {
              clearInterval(self._pollTimer);
              self._pollTimer = null;
              self.renderResults(scan);
            }
          })
          .catch(function() {});
      }, 5000);
    })
    .catch(function() {
      progressCard.style.display = 'none';
      scanBtn.disabled = false;
      Toast.error('Failed to start code audit');
    });
  },

  updateProgress: function(data) {
    var progressTitle = document.getElementById('ca-progress-title');
    var progressDetail = document.getElementById('ca-progress-detail');
    var progressBar = document.getElementById('ca-progress-bar');

    if (progressDetail) progressDetail.textContent = data.message || '';

    var phaseProgress = { starting: 5, discovery: 15, triage: 35, analysis: 65, complete: 100 };
    var pct = phaseProgress[data.phase] || 50;
    if (progressBar) progressBar.style.width = pct + '%';

    var phaseTitles = {
      starting: 'Starting code audit...',
      discovery: 'Discovering source files...',
      triage: 'AI triaging entry points...',
      analysis: 'Deep vulnerability analysis...',
      complete: 'Analysis complete'
    };
    if (progressTitle && phaseTitles[data.phase]) progressTitle.textContent = phaseTitles[data.phase];
  },

  loadResults: function(scanId) {
    var self = this;
    fetch('/api/code-audit/' + scanId, { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(scan) { self.renderResults(scan); })
      .catch(function() { Toast.error('Failed to load results'); });
  },

  renderResults: function(scan) {
    var progressCard = document.getElementById('ca-progress-card');
    var scanBtn = document.getElementById('ca-scan-btn');
    var resultsEl = document.getElementById('ca-results');

    progressCard.style.display = 'none';
    scanBtn.disabled = false;

    if (this._pollTimer) { clearInterval(this._pollTimer); this._pollTimer = null; }

    if (scan.status === 'failed') {
      resultsEl.innerHTML =
        '<div class="glass-card">' +
          '<div class="empty-state">' +
            '<div class="empty-state-icon" style="color:var(--orange);">&#10007;</div>' +
            '<div class="empty-state-title">Scan Failed</div>' +
            '<div class="empty-state-desc">' + escapeHtml(scan.error || 'Unknown error') + '</div>' +
          '</div>' +
        '</div>';
      Toast.error('Code audit failed');
      return;
    }

    var findings = scan.findings || [];
    var duration = scan.duration ? (scan.duration / 1000).toFixed(1) + 's' : '--';

    // Summary stats
    var html =
      '<div class="stat-grid" style="margin-bottom:16px;">' +
        '<div class="stat-card"><div class="stat-card-label">Findings</div><div class="stat-card-value" style="color:' + (findings.length > 0 ? 'var(--orange)' : 'var(--cyan)') + ';">' + findings.length + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Files Analyzed</div><div class="stat-card-value">' + (scan.filesAnalyzed || 0) + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Total Files</div><div class="stat-card-value">' + (scan.totalFiles || 0) + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Duration</div><div class="stat-card-value">' + duration + '</div></div>' +
      '</div>';

    // Summary text
    if (scan.summary) {
      html += '<div class="glass-card" style="margin-bottom:16px;padding:12px;">' +
        '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);">' + escapeHtml(scan.summary) + '</div>' +
      '</div>';
    }

    if (findings.length === 0) {
      html += '<div class="glass-card">' +
        '<div class="empty-state">' +
          '<div class="empty-state-icon" style="color:var(--cyan);">&#10003;</div>' +
          '<div class="empty-state-title">No Vulnerabilities Found</div>' +
          '<div class="empty-state-desc">AI analysis did not identify any remotely exploitable vulnerabilities in the scanned code.</div>' +
        '</div>' +
      '</div>';
    } else {
      // Findings list
      html += '<div class="glass-card">' +
        '<div class="glass-card-header">' +
          '<div class="glass-card-title">Vulnerability Findings</div>' +
        '</div>';

      findings.forEach(function(f, idx) {
        var confColor = f.confidence >= 8 ? 'var(--orange)' : f.confidence >= 6 ? 'var(--purple, #a78bfa)' : 'var(--text-tertiary)';
        var confLabel = f.confidence >= 8 ? 'HIGH' : f.confidence >= 6 ? 'MED' : 'LOW';

        html += '<div class="glass-card" style="margin:8px 0;padding:14px;cursor:pointer;" onclick="Views[\'code-audit\'].toggleDetail(' + idx + ')">' +
          '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">' +
            '<span class="badge ' + severityBadge(f.severity) + '">' + escapeHtml(f.severity) + '</span>' +
            '<span style="color:' + confColor + ';font-size:var(--font-size-xs);font-weight:600;padding:2px 6px;border:1px solid ' + confColor + ';border-radius:4px;">' + confLabel + ' CONF ' + f.confidence + '/10</span>' +
            '<span style="color:var(--cyan);font-size:var(--font-size-xs);padding:2px 6px;border:1px solid var(--border);border-radius:4px;">' + escapeHtml(f.vulnType || '') + '</span>' +
            '<span style="color:var(--text-primary);font-weight:500;flex:1;">' + escapeHtml(f.title) + '</span>' +
          '</div>' +
          '<div style="margin-top:6px;color:var(--text-tertiary);font-size:var(--font-size-xs);">' +
            escapeHtml(f.file || '') + (f.line ? ':' + f.line : '') +
            (f.cwe ? ' | ' + escapeHtml(f.cwe) : '') +
            (f.mitre ? ' | ' + escapeHtml(f.mitre) : '') +
          '</div>' +

          // Expandable detail
          '<div id="ca-detail-' + idx + '" style="display:none;margin-top:14px;padding-top:14px;border-top:1px solid var(--border);">' +
            '<div class="detail-row"><div class="detail-label">Description</div><div class="detail-value" style="white-space:pre-wrap;">' + escapeHtml(f.description || '--') + '</div></div>' +
            (f.dataFlow ? '<div class="detail-row"><div class="detail-label">Data Flow</div><div class="detail-value" style="font-family:var(--font-mono);font-size:var(--font-size-xs);color:var(--cyan);">' + escapeHtml(f.dataFlow) + '</div></div>' : '') +
            (f.poc ? '<div class="detail-row"><div class="detail-label">Proof of Concept</div><div class="detail-value"><pre style="background:rgba(0,0,0,0.3);padding:10px;border-radius:6px;overflow-x:auto;font-size:var(--font-size-xs);color:var(--orange);margin:0;">' + escapeHtml(f.poc) + '</pre></div></div>' : '') +
            '<div class="detail-row"><div class="detail-label">Remediation</div><div class="detail-value" style="color:var(--cyan);white-space:pre-wrap;">' + escapeHtml(f.remediation || '--') + '</div></div>' +
          '</div>' +
        '</div>';
      });

      html += '</div>';
    }

    // Note about findings view
    if (findings.length > 0) {
      html += '<div style="margin-top:12px;padding:10px 14px;border-radius:6px;background:rgba(34,211,238,0.06);border:1px solid rgba(34,211,238,0.12);color:var(--text-tertiary);font-size:var(--font-size-xs);">' +
        'These findings are also available in the <a href="#" onclick="showView(\'findings\');return false;" style="color:var(--cyan);">Findings</a> view for tracking and triage.</div>';
    }

    resultsEl.innerHTML = html;
    Toast.success('Code audit complete — ' + findings.length + ' finding(s)');
  },

  toggleDetail: function(idx) {
    var detail = document.getElementById('ca-detail-' + idx);
    if (detail) {
      detail.style.display = detail.style.display === 'none' ? 'block' : 'none';
    }
  }
};
