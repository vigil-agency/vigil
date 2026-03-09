/* Vigil v1.0 — Code Audit View (LLM-Driven Vulnerability Scanner + Binary Analysis) */
Views['code-audit'] = {
  _scanId: null,
  _pollTimer: null,
  _tab: 'source',
  _binaryScanId: null,
  _binaryPollTimer: null,

  init: function() {
    var el = document.getElementById('view-code-audit');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Code Audit</div>' +
        '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);">AI-powered source code &amp; binary analysis</div>' +
      '</div>' +
      '<div class="tab-bar" id="ca-tabs">' +
        '<div class="tab-item active" data-tab="source">Source Code</div>' +
        '<div class="tab-item" data-tab="binary">Binary Analysis</div>' +
      '</div>' +

      // ─── SOURCE CODE TAB ───
      '<div id="ca-tab-source">' +

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
      '</div>' +
      '</div>' + // end ca-tab-source

      // ─── BINARY ANALYSIS TAB ───
      '<div id="ca-tab-binary" style="display:none;">' +
        '<div class="glass-card" style="margin-bottom:20px;">' +
          '<div class="form-inline" style="flex-wrap:wrap;gap:10px;">' +
            '<div class="form-group" style="flex:3;min-width:300px;">' +
              '<label class="form-label">Binary File Path</label>' +
              '<input type="text" class="form-input" id="ba-target" placeholder="/usr/bin/nmap or /path/to/suspicious.exe">' +
            '</div>' +
            '<div class="form-group" style="align-self:flex-end;">' +
              '<button class="btn btn-primary" id="ba-scan-btn">Analyze</button>' +
            '</div>' +
          '</div>' +
        '</div>' +
        '<div class="glass-card" id="ba-progress-card" style="display:none;margin-bottom:20px;">' +
          '<div style="display:flex;align-items:center;gap:12px;">' +
            '<div class="spinner"></div>' +
            '<div>' +
              '<div style="color:var(--text-primary);font-weight:500;" id="ba-progress-title">Analyzing binary...</div>' +
              '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);margin-top:4px;" id="ba-progress-detail">Initializing...</div>' +
            '</div>' +
          '</div>' +
          '<div style="margin-top:12px;height:4px;background:var(--border);border-radius:2px;overflow:hidden;">' +
            '<div id="ba-progress-bar" style="height:100%;width:0%;background:var(--cyan);border-radius:2px;transition:width 0.5s ease;"></div>' +
          '</div>' +
        '</div>' +
        '<div id="ba-results">' +
          '<div class="glass-card">' +
            '<div class="empty-state">' +
              '<div class="empty-state-icon">&#128190;</div>' +
              '<div class="empty-state-title">No Analysis Results</div>' +
              '<div class="empty-state-desc">Enter a binary file path (ELF, PE, Mach-O) to extract metadata, strings, IOCs, imports, and run AI threat assessment</div>' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>'; // end ca-tab-binary

    var self = this;
    document.getElementById('ca-scan-btn').addEventListener('click', function() { self.runScan(); });
    document.getElementById('ca-preview-btn').addEventListener('click', function() { self.previewFiles(); });
    document.getElementById('ba-scan-btn').addEventListener('click', function() { self.runBinaryScan(); });

    // Tab switching
    document.querySelectorAll('#ca-tabs .tab-item').forEach(function(t) {
      t.addEventListener('click', function() {
        document.querySelectorAll('#ca-tabs .tab-item').forEach(function(x) { x.classList.remove('active'); });
        t.classList.add('active');
        self._tab = t.getAttribute('data-tab');
        document.getElementById('ca-tab-source').style.display = self._tab === 'source' ? 'block' : 'none';
        document.getElementById('ca-tab-binary').style.display = self._tab === 'binary' ? 'block' : 'none';
      });
    });

    // Listen for Socket.IO progress events
    if (window._socket) {
      window._socket.on('code_audit_progress', function(data) {
        if (data.scanId === self._scanId) {
          self.updateProgress(data);
        }
        if (data.scanId === self._binaryScanId) {
          self.updateBinaryProgress(data);
        }
      });
      window._socket.on('scan_complete', function(data) {
        if (data.id === self._scanId && data.type === 'code-audit') {
          self.loadResults(data.id);
        }
        if (data.id === self._binaryScanId && data.type === 'binary-analysis') {
          self.loadBinaryResults(data.id);
        }
      });
    }
  },

  show: function() {},
  hide: function() {
    if (this._pollTimer) { clearInterval(this._pollTimer); this._pollTimer = null; }
    if (this._binaryPollTimer) { clearInterval(this._binaryPollTimer); this._binaryPollTimer = null; }
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
    this._lastScanId = scan.id;

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
            '<div style="margin-top:10px;display:flex;gap:8px;">' +
              '<button class="btn btn-ghost btn-sm ca-validate-btn" data-idx="' + idx + '" onclick="event.stopPropagation();Views[\'code-audit\'].validateFinding(' + idx + ')" style="font-size:11px;border-color:var(--cyan);">Validate Exploitability</button>' +
            '</div>' +
            '<div id="ca-validation-' + idx + '"></div>' +
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
  },

  validateFinding: function(idx) {
    if (!this._lastScanId) { Toast.error('No scan to validate'); return; }

    var btn = document.querySelector('.ca-validate-btn[data-idx="' + idx + '"]');
    var container = document.getElementById('ca-validation-' + idx);
    if (!container) return;

    if (btn) { btn.disabled = true; btn.textContent = 'Validating...'; }
    container.innerHTML = '<div class="loading-state" style="padding:12px;"><div class="spinner spinner-sm"></div><div style="font-size:var(--font-size-xs);margin-top:6px;">Running MUST-GATE exploitability validation...</div></div>';

    var scanId = this._lastScanId;
    fetch('/api/code-audit/' + scanId + '/validate/' + idx, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin'
    })
    .then(function(r) { return r.json(); })
    .then(function(result) {
      if (btn) { btn.disabled = false; btn.textContent = 'Validate Exploitability'; }

      if (result.error) {
        container.innerHTML = '<div style="color:var(--orange);font-size:var(--font-size-xs);margin-top:8px;">Validation error: ' + escapeHtml(result.error) + '</div>';
        return;
      }

      var verdictColors = { exploitable: 'var(--orange)', likely_exploitable: 'var(--orange)', needs_investigation: 'var(--text-secondary)', false_positive: 'var(--cyan)' };
      var verdictLabels = { exploitable: 'EXPLOITABLE', likely_exploitable: 'LIKELY EXPLOITABLE', needs_investigation: 'NEEDS INVESTIGATION', false_positive: 'FALSE POSITIVE' };
      var vc = verdictColors[result.verdict] || 'var(--text-secondary)';
      var vl = verdictLabels[result.verdict] || result.verdict;

      var html = '<div style="margin-top:12px;padding:14px;border-radius:8px;border:1px solid ' + vc + ';background:rgba(0,0,0,0.2);">' +
        '<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">' +
          '<span style="font-size:14px;font-weight:700;color:' + vc + ';padding:4px 10px;border:2px solid ' + vc + ';border-radius:6px;">' + vl + '</span>' +
          '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">Confidence: ' + (result.confidence || 0) + '/10</span>' +
          '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-left:auto;">MUST-GATE Validated</span>' +
        '</div>';

      // 4-step results
      if (result.steps && result.steps.length > 0) {
        html += '<div style="margin-bottom:10px;">';
        result.steps.forEach(function(s) {
          var stepColor = s.result === 'pass' || s.result === 'critical' || s.result === 'high' ? 'var(--orange)' : s.result === 'fail' ? 'var(--cyan)' : 'var(--text-tertiary)';
          var stepIcon = s.result === 'pass' || s.result === 'critical' || s.result === 'high' ? '&#9888;' : s.result === 'fail' ? '&#10003;' : '&#8943;';
          html += '<div style="padding:6px 0;border-bottom:1px solid var(--border);font-size:var(--font-size-xs);">' +
            '<div style="display:flex;align-items:center;gap:8px;">' +
              '<span style="color:' + stepColor + ';font-weight:600;">' + stepIcon + ' Step ' + s.step + '</span>' +
              '<span style="color:var(--text-primary);font-weight:500;">' + escapeHtml(s.name) + '</span>' +
              '<span style="color:' + stepColor + ';margin-left:auto;text-transform:uppercase;font-weight:600;">' + escapeHtml(s.result) + '</span>' +
            '</div>' +
            '<div style="color:var(--text-tertiary);margin-top:3px;padding-left:24px;line-height:1.5;">' + escapeHtml(s.analysis || '').substring(0, 300) + '</div>' +
          '</div>';
        });
        html += '</div>';
      }

      // Attack vector and PoC
      if (result.attack_vector) {
        html += '<div class="detail-row"><div class="detail-label" style="font-size:11px;">Attack Vector</div><div class="detail-value" style="font-size:var(--font-size-xs);color:var(--orange);">' + escapeHtml(result.attack_vector) + '</div></div>';
      }
      if (result.proof_of_concept) {
        html += '<div class="detail-row"><div class="detail-label" style="font-size:11px;">Validated PoC</div><div class="detail-value"><pre style="background:rgba(0,0,0,0.3);padding:8px;border-radius:4px;font-size:11px;color:var(--orange);margin:0;overflow-x:auto;">' + escapeHtml(result.proof_of_concept) + '</pre></div></div>';
      }
      if (result.reasoning) {
        html += '<div class="detail-row"><div class="detail-label" style="font-size:11px;">Reasoning</div><div class="detail-value" style="font-size:var(--font-size-xs);color:var(--text-secondary);line-height:1.6;">' + escapeHtml(result.reasoning) + '</div></div>';
      }

      html += '</div>';
      container.innerHTML = html;
      Toast.success('Exploitability validation complete: ' + vl);
    })
    .catch(function(err) {
      if (btn) { btn.disabled = false; btn.textContent = 'Validate Exploitability'; }
      container.innerHTML = '<div style="color:var(--orange);font-size:var(--font-size-xs);margin-top:8px;">Validation failed: ' + escapeHtml(err.message) + '</div>';
    });
  },

  /* ═══════════════════ BINARY ANALYSIS ═══════════════════ */
  _md: function(text) {
    if (!text) return '';
    var s = String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    s = s.replace(/^### (.+)$/gm, '<h4 style="color:var(--text-primary);font-size:var(--font-size-sm);font-weight:700;margin:14px 0 6px;">$1</h4>');
    s = s.replace(/^## (.+)$/gm, '<h3 style="color:var(--cyan);font-size:var(--font-size-base);font-weight:700;margin:18px 0 8px;border-bottom:1px solid var(--border);padding-bottom:6px;">$1</h3>');
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong style="color:var(--text-primary);">$1</strong>');
    s = s.replace(/^[\-\*] (.+)$/gm, '<div style="display:flex;gap:8px;margin:3px 0 3px 8px;"><span style="color:var(--cyan);">&#8226;</span><span>$1</span></div>');
    s = s.replace(/^(\d+)\. (.+)$/gm, '<div style="display:flex;gap:8px;margin:3px 0 3px 8px;"><span style="color:var(--cyan);font-weight:600;min-width:18px;">$1.</span><span>$2</span></div>');
    s = s.replace(/(CVE-\d{4}-\d{4,})/g, '<span style="color:var(--orange);font-weight:600;">$1</span>');
    s = s.replace(/\n\n/g, '</p><p style="margin:8px 0;">');
    s = s.replace(/\n/g, '<br>');
    return '<p style="margin:8px 0;">' + s + '</p>';
  },

  runBinaryScan: function() {
    var target = document.getElementById('ba-target').value.trim();
    if (!target) { Toast.warning('Enter a binary file path'); return; }

    var scanBtn = document.getElementById('ba-scan-btn');
    var progressCard = document.getElementById('ba-progress-card');

    scanBtn.disabled = true;
    progressCard.style.display = 'block';
    this.updateBinaryProgress({ phase: 'identify', message: 'Starting binary analysis...' });

    var self = this;

    fetch('/api/code-audit/binary', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ target: target })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.error) {
        progressCard.style.display = 'none';
        scanBtn.disabled = false;
        Toast.error(data.error);
        return;
      }

      self._binaryScanId = data.scan.id;
      self.updateBinaryProgress({ phase: 'strings', message: 'Analysis in progress...' });

      self._binaryPollTimer = setInterval(function() {
        fetch('/api/code-audit/binary/' + self._binaryScanId, { credentials: 'same-origin' })
          .then(function(r) { return r.json(); })
          .then(function(scan) {
            if (scan.status === 'completed' || scan.status === 'failed') {
              clearInterval(self._binaryPollTimer);
              self._binaryPollTimer = null;
              self.renderBinaryResults(scan);
            }
          })
          .catch(function() {});
      }, 3000);
    })
    .catch(function() {
      progressCard.style.display = 'none';
      scanBtn.disabled = false;
      Toast.error('Failed to start binary analysis');
    });
  },

  updateBinaryProgress: function(data) {
    var title = document.getElementById('ba-progress-title');
    var detail = document.getElementById('ba-progress-detail');
    var bar = document.getElementById('ba-progress-bar');

    if (detail) detail.textContent = data.message || '';

    var phaseProgress = { identify: 10, strings: 25, structure: 40, deep: 55, ai: 75, complete: 100 };
    var pct = phaseProgress[data.phase] || 50;
    if (bar) bar.style.width = pct + '%';

    var titles = {
      identify: 'Identifying file type...',
      strings: 'Extracting strings & IOCs...',
      structure: 'Analyzing binary structure...',
      deep: 'Deep analysis (entropy, disasm, taint chains)...',
      ai: 'Running AI threat assessment...',
      complete: 'Analysis complete'
    };
    if (title && titles[data.phase]) title.textContent = titles[data.phase];
  },

  loadBinaryResults: function(scanId) {
    var self = this;
    fetch('/api/code-audit/binary/' + scanId, { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(scan) { self.renderBinaryResults(scan); })
      .catch(function() { Toast.error('Failed to load binary results'); });
  },

  renderBinaryResults: function(scan) {
    var progressCard = document.getElementById('ba-progress-card');
    var scanBtn = document.getElementById('ba-scan-btn');
    var resultsEl = document.getElementById('ba-results');

    progressCard.style.display = 'none';
    scanBtn.disabled = false;

    if (this._binaryPollTimer) { clearInterval(this._binaryPollTimer); this._binaryPollTimer = null; }

    if (scan.status === 'failed') {
      resultsEl.innerHTML =
        '<div class="glass-card"><div class="empty-state">' +
          '<div class="empty-state-icon" style="color:var(--orange);">&#10007;</div>' +
          '<div class="empty-state-title">Analysis Failed</div>' +
          '<div class="empty-state-desc">' + escapeHtml(scan.error || 'Unknown error') + '</div>' +
        '</div></div>';
      Toast.error('Binary analysis failed');
      return;
    }

    var r = scan.result || {};
    var ft = r.fileType || {};
    var h = r.hashes || {};
    var ent = r.entropy || {};
    var str = r.strings || {};
    var iocs = r.iocs || {};
    var struct = r.structure || {};
    var duration = r.duration ? (r.duration / 1000).toFixed(1) + 's' : '--';
    var self = this;

    // Stats
    var riskCount = (r.riskIndicators || []).length;
    var iocCount = (iocs.urls || []).length + (iocs.ips || []).length + (iocs.emails || []).length + (iocs.domains || []).length;
    var mitreCount = (r.mitreTactics || []).length;
    var chainCount = (r.taintChains || []).length;
    var html =
      '<div class="stat-grid" style="margin-bottom:16px;">' +
        '<div class="stat-card"><div class="stat-card-label">Risk Indicators</div><div class="stat-card-value" style="color:' + (riskCount > 0 ? 'var(--orange)' : 'var(--cyan)') + ';">' + riskCount + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">IOCs Found</div><div class="stat-card-value" style="color:' + (iocCount > 0 ? 'var(--orange)' : 'var(--cyan)') + ';">' + iocCount + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">ATT&amp;CK Techniques</div><div class="stat-card-value" style="color:' + (mitreCount > 0 ? 'var(--orange)' : 'var(--cyan)') + ';">' + mitreCount + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Taint Chains</div><div class="stat-card-value" style="color:' + (chainCount > 0 ? 'var(--orange)' : 'var(--cyan)') + ';">' + chainCount + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Strings</div><div class="stat-card-value">' + (str.total || 0) + '</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Duration</div><div class="stat-card-value">' + duration + '</div></div>' +
      '</div>';

    // File info card
    html += '<div class="glass-card" style="margin-bottom:16px;">' +
      '<div class="glass-card-header"><div class="glass-card-title">File Information</div></div>' +
      '<table style="width:100%;border-collapse:collapse;font-size:var(--font-size-sm);">' +
        '<tr><td style="padding:6px 12px;color:var(--text-tertiary);width:140px;border-bottom:1px solid var(--border);">File</td>' +
          '<td style="padding:6px 12px;color:var(--text-primary);border-bottom:1px solid var(--border);font-weight:600;">' + escapeHtml(r.file || '') + '</td></tr>' +
        '<tr><td style="padding:6px 12px;color:var(--text-tertiary);border-bottom:1px solid var(--border);">Size</td>' +
          '<td style="padding:6px 12px;color:var(--text-secondary);border-bottom:1px solid var(--border);">' + ((r.size || 0) / 1024).toFixed(1) + ' KB (' + (r.size || 0).toLocaleString() + ' bytes)</td></tr>' +
        '<tr><td style="padding:6px 12px;color:var(--text-tertiary);border-bottom:1px solid var(--border);">Format</td>' +
          '<td style="padding:6px 12px;color:var(--cyan);font-weight:600;border-bottom:1px solid var(--border);">' + escapeHtml((ft.format || 'Unknown') + ' ' + (ft.bits || '') + '-bit ' + (ft.arch || '')) + '</td></tr>' +
        '<tr><td style="padding:6px 12px;color:var(--text-tertiary);border-bottom:1px solid var(--border);">Type</td>' +
          '<td style="padding:6px 12px;color:var(--text-secondary);border-bottom:1px solid var(--border);">' + escapeHtml(ft.detail || '') + '</td></tr>' +
        '<tr><td style="padding:6px 12px;color:var(--text-tertiary);border-bottom:1px solid var(--border);">Entropy</td>' +
          '<td style="padding:6px 12px;color:' + (ent.packed ? 'var(--orange)' : 'var(--text-secondary)') + ';border-bottom:1px solid var(--border);">' + (ent.value || 0) + ' — ' + escapeHtml(ent.assessment || '') + '</td></tr>' +
        '<tr><td style="padding:6px 12px;color:var(--text-tertiary);border-bottom:1px solid var(--border);">MD5</td>' +
          '<td style="padding:6px 12px;color:var(--text-secondary);font-family:var(--font-mono);font-size:11px;border-bottom:1px solid var(--border);">' + escapeHtml(h.md5 || '') + '</td></tr>' +
        '<tr><td style="padding:6px 12px;color:var(--text-tertiary);border-bottom:1px solid var(--border);">SHA256</td>' +
          '<td style="padding:6px 12px;color:var(--text-secondary);font-family:var(--font-mono);font-size:11px;border-bottom:1px solid var(--border);word-break:break-all;">' + escapeHtml(h.sha256 || '') + '</td></tr>' +
      '</table></div>';

    // Risk indicators
    if (r.riskIndicators && r.riskIndicators.length) {
      html += '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-header"><div class="glass-card-title" style="color:var(--orange);">Risk Indicators (' + r.riskIndicators.length + ')</div></div>';
      r.riskIndicators.forEach(function(ri) {
        html += '<div style="padding:8px 0;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;gap:10px;">' +
          '<span class="badge ' + severityBadge(ri.severity) + '" style="flex-shrink:0;">' + escapeHtml(ri.severity) + '</span>' +
          '<div><div style="color:var(--text-primary);font-weight:500;font-size:var(--font-size-sm);">' + escapeHtml(ri.indicator) + '</div>' +
          '<div style="color:var(--text-tertiary);font-size:11px;margin-top:2px;">' + escapeHtml(ri.detail) + '</div></div></div>';
      });
      html += '</div>';
    }

    // Suspicious imports
    if (r.suspiciousImports && r.suspiciousImports.length) {
      html += '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-header"><div class="glass-card-title" style="color:var(--orange);">Suspicious Imports (' + r.suspiciousImports.length + ')</div></div>' +
        '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
      r.suspiciousImports.forEach(function(imp) {
        html += '<span class="tag" style="color:var(--orange);border-color:var(--orange);font-family:var(--font-mono);font-size:11px;">' + escapeHtml(imp) + '</span>';
      });
      html += '</div></div>';
    }

    // IOCs
    if (iocCount > 0) {
      html += '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-header"><div class="glass-card-title">Indicators of Compromise (' + iocCount + ')</div></div>';

      if (iocs.urls && iocs.urls.length) {
        html += '<div style="margin-bottom:12px;"><div style="color:var(--text-tertiary);font-size:var(--font-size-xs);text-transform:uppercase;margin-bottom:6px;">URLs (' + iocs.urls.length + ')</div>';
        iocs.urls.forEach(function(u) {
          html += '<div style="font-family:var(--font-mono);font-size:11px;color:var(--orange);padding:2px 0;word-break:break-all;">' + escapeHtml(u) + '</div>';
        });
        html += '</div>';
      }
      if (iocs.ips && iocs.ips.length) {
        html += '<div style="margin-bottom:12px;"><div style="color:var(--text-tertiary);font-size:var(--font-size-xs);text-transform:uppercase;margin-bottom:6px;">IP Addresses (' + iocs.ips.length + ')</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
        iocs.ips.forEach(function(ip) { html += '<span class="tag" style="font-family:var(--font-mono);font-size:11px;">' + escapeHtml(ip) + '</span>'; });
        html += '</div></div>';
      }
      if (iocs.emails && iocs.emails.length) {
        html += '<div style="margin-bottom:12px;"><div style="color:var(--text-tertiary);font-size:var(--font-size-xs);text-transform:uppercase;margin-bottom:6px;">Email Addresses (' + iocs.emails.length + ')</div>';
        iocs.emails.forEach(function(e) { html += '<div style="font-size:11px;color:var(--text-secondary);padding:2px 0;">' + escapeHtml(e) + '</div>'; });
        html += '</div>';
      }
      if (iocs.domains && iocs.domains.length) {
        html += '<div style="margin-bottom:12px;"><div style="color:var(--text-tertiary);font-size:var(--font-size-xs);text-transform:uppercase;margin-bottom:6px;">Domains (' + iocs.domains.length + ')</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
        iocs.domains.forEach(function(d) { html += '<span class="tag" style="font-family:var(--font-mono);font-size:11px;">' + escapeHtml(d) + '</span>'; });
        html += '</div></div>';
      }
      html += '</div>';
    }

    // Libraries & Imports
    if ((struct.libraries && struct.libraries.length) || (struct.imports && struct.imports.length)) {
      html += '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-header"><div class="glass-card-title">Libraries & Imports</div></div>';

      if (struct.libraries && struct.libraries.length) {
        html += '<div style="margin-bottom:12px;"><div style="color:var(--text-tertiary);font-size:var(--font-size-xs);text-transform:uppercase;margin-bottom:6px;">Linked Libraries (' + struct.libraries.length + ')</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
        struct.libraries.forEach(function(lib) {
          html += '<span class="tag tag-cyan" style="font-family:var(--font-mono);font-size:11px;">' + escapeHtml(lib) + '</span>';
        });
        html += '</div></div>';
      }

      if (struct.imports && struct.imports.length) {
        html += '<div><div style="color:var(--text-tertiary);font-size:var(--font-size-xs);text-transform:uppercase;margin-bottom:6px;">Imports (' + struct.imports.length + ')</div>' +
          '<div style="max-height:200px;overflow-y:auto;font-family:var(--font-mono);font-size:11px;color:var(--text-secondary);">';
        struct.imports.slice(0, 100).forEach(function(imp) {
          var color = (r.suspiciousImports || []).indexOf(imp.name) >= 0 ? 'var(--orange)' : 'var(--text-secondary)';
          html += '<div style="padding:1px 0;color:' + color + ';">' + escapeHtml(imp.name || '') + '</div>';
        });
        if (struct.imports.length > 100) html += '<div style="color:var(--text-tertiary);padding-top:4px;">... and ' + (struct.imports.length - 100) + ' more</div>';
        html += '</div></div>';
      }
      html += '</div>';
    }

    // Section Entropy Heatmap (vibe-re)
    if (r.sectionEntropy && r.sectionEntropy.length) {
      html += '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-header"><div class="glass-card-title">Section Entropy Heatmap</div>' +
          (r.packers && r.packers.length ? '<div style="display:flex;gap:6px;">' + r.packers.map(function(p) { return '<span class="badge badge-orange">' + escapeHtml(p.name) + '</span>'; }).join('') + '</div>' : '') +
        '</div>' +
        '<table class="data-table"><thead><tr><th>Section</th><th>Size</th><th>Entropy</th><th style="width:200px;">Heatmap</th><th>Assessment</th></tr></thead><tbody>';
      r.sectionEntropy.forEach(function(se) {
        var pct = Math.round((se.entropy / 8) * 100);
        var barColor = se.entropy > 7.5 ? 'var(--orange)' : se.entropy > 7.0 ? '#e67e22' : se.entropy > 6.0 ? 'var(--cyan)' : 'var(--text-tertiary)';
        var rowStyle = se.anomaly ? 'background:rgba(255,107,43,0.08);' : '';
        html += '<tr style="' + rowStyle + '">' +
          '<td style="font-family:var(--font-mono);color:' + (se.executable ? 'var(--cyan)' : 'var(--text-secondary)') + ';">' + escapeHtml(se.name) + '</td>' +
          '<td>' + (se.size || 0).toLocaleString() + '</td>' +
          '<td style="font-family:var(--font-mono);color:' + barColor + ';">' + se.entropy + '</td>' +
          '<td><div style="background:var(--well);border-radius:4px;height:16px;overflow:hidden;"><div style="width:' + pct + '%;height:100%;background:' + barColor + ';border-radius:4px;transition:width .3s;"></div></div></td>' +
          '<td style="font-size:11px;color:' + (se.anomaly ? 'var(--orange)' : 'var(--text-tertiary)') + ';">' + escapeHtml(se.anomaly || se.assessment) + '</td></tr>';
      });
      html += '</tbody></table></div>';
    } else if (struct.sections && struct.sections.length) {
      // Fallback: basic sections table
      html += '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-header"><div class="glass-card-title">Sections (' + struct.sections.length + ')</div></div>' +
        '<table class="data-table"><thead><tr><th>Name</th><th>Type</th><th>Address</th><th>Size</th></tr></thead><tbody>';
      struct.sections.forEach(function(sec) {
        html += '<tr><td style="font-family:var(--font-mono);color:var(--cyan);">' + escapeHtml(sec.name || '') + '</td>' +
          '<td style="color:var(--text-tertiary);font-size:11px;">' + escapeHtml(sec.type || '') + '</td>' +
          '<td style="font-family:var(--font-mono);font-size:11px;">' + escapeHtml(sec.addr || '') + '</td>' +
          '<td>' + (sec.size || 0).toLocaleString() + '</td></tr>';
      });
      html += '</tbody></table></div>';
    }

    // MITRE ATT&CK Mapping (vibe-re)
    if (r.mitreTactics && r.mitreTactics.length) {
      html += '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-header"><div class="glass-card-title" style="color:var(--cyan);">MITRE ATT&amp;CK Mapping (' + r.mitreTactics.length + ' techniques)</div></div>' +
        '<table class="data-table"><thead><tr><th>Technique</th><th>Tactic</th><th>Name</th><th>Evidence</th></tr></thead><tbody>';
      r.mitreTactics.forEach(function(t) {
        html += '<tr><td style="font-family:var(--font-mono);color:var(--orange);font-weight:600;">' + escapeHtml(t.tid) + '</td>' +
          '<td style="color:var(--text-secondary);font-size:11px;">' + escapeHtml(t.tactic) + '</td>' +
          '<td style="color:var(--text-primary);">' + escapeHtml(t.name) + '</td>' +
          '<td style="font-size:11px;color:var(--text-tertiary);">' + t.evidence.slice(0, 3).map(function(e) { return escapeHtml(e); }).join(', ') + '</td></tr>';
      });
      html += '</tbody></table></div>';
    }

    // Import Taint Chains (vibe-re)
    if (r.taintChains && r.taintChains.length) {
      html += '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-header"><div class="glass-card-title" style="color:var(--orange);">Import Taint Chains (' + r.taintChains.length + ')</div></div>';
      r.taintChains.forEach(function(chain) {
        html += '<div style="padding:10px 0;border-bottom:1px solid var(--border);">' +
          '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">' +
            '<span class="badge ' + severityBadge(chain.severity) + '">' + escapeHtml(chain.severity) + '</span>' +
            '<span style="color:var(--text-primary);font-weight:600;">' + escapeHtml(chain.name) + '</span>' +
            '<span style="color:var(--text-tertiary);font-size:11px;">(' + chain.matchRatio + ' imports, confidence: ' + chain.confidence + ')</span>' +
          '</div>' +
          '<div style="color:var(--text-tertiary);font-size:var(--font-size-sm);margin-bottom:4px;">' + escapeHtml(chain.description) + '</div>' +
          '<div style="display:flex;align-items:center;gap:4px;flex-wrap:wrap;">';
        chain.matchedImports.forEach(function(imp, idx) {
          if (idx > 0) html += '<span style="color:var(--text-tertiary);font-size:10px;">&#x2192;</span>';
          html += '<span class="tag" style="color:var(--orange);border-color:var(--orange);font-family:var(--font-mono);font-size:11px;">' + escapeHtml(imp) + '</span>';
        });
        html += '</div></div>';
      });
      html += '</div>';
    }

    // Disassembly Patterns (vibe-re)
    if (r.disasmPatterns && r.disasmPatterns.length) {
      html += '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-header"><div class="glass-card-title" style="color:var(--orange);">Disassembly Patterns (' + r.disasmPatterns.length + ')</div></div>';
      r.disasmPatterns.forEach(function(pat) {
        html += '<div style="padding:8px 0;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;gap:10px;">' +
          '<span class="badge ' + severityBadge(pat.severity) + '" style="flex-shrink:0;">' + escapeHtml(pat.severity) + '</span>' +
          '<div><div style="display:flex;align-items:center;gap:8px;">' +
            '<span style="color:var(--text-primary);font-weight:500;font-size:var(--font-size-sm);">' + escapeHtml(pat.name) + '</span>' +
            '<span class="tag" style="font-size:10px;">' + escapeHtml(pat.category) + '</span>' +
            '<span style="color:var(--text-tertiary);font-size:11px;">' + pat.count + 'x</span>' +
          '</div>' +
          '<div style="color:var(--text-tertiary);font-size:11px;margin-top:2px;">' + escapeHtml(pat.description) + '</div></div></div>';
      });
      html += '</div>';
    }

    // String Obfuscation (vibe-re)
    if (r.obfuscation && r.obfuscation.techniques.length) {
      var obfColor = r.obfuscation.obfuscationScore > 60 ? 'var(--orange)' : r.obfuscation.obfuscationScore > 30 ? '#e67e22' : 'var(--text-secondary)';
      html += '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-header"><div class="glass-card-title">String Obfuscation Analysis</div>' +
          '<div style="color:' + obfColor + ';font-weight:600;font-size:var(--font-size-lg);">' + r.obfuscation.obfuscationScore + '/100</div></div>' +
        '<div style="margin-bottom:8px;"><div style="background:var(--well);border-radius:4px;height:8px;overflow:hidden;"><div style="width:' + r.obfuscation.obfuscationScore + '%;height:100%;background:' + obfColor + ';border-radius:4px;"></div></div></div>' +
        '<div style="display:flex;gap:16px;margin-bottom:12px;font-size:11px;color:var(--text-tertiary);">' +
          '<span>Plaintext Ratio: ' + (r.obfuscation.stats.plaintextRatio || 0) + '%</span>' +
          '<span>High-Entropy Blocks: ' + (r.obfuscation.stats.suspiciousBlocks || 0) + '</span>' +
          '<span>Total Strings: ' + (r.obfuscation.stats.totalStrings || 0) + '</span>' +
        '</div>';
      r.obfuscation.techniques.forEach(function(tech) {
        html += '<div style="padding:6px 0;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;gap:8px;">' +
          '<span class="badge ' + severityBadge(tech.severity) + '" style="flex-shrink:0;">' + escapeHtml(tech.severity) + '</span>' +
          '<div><div style="color:var(--text-primary);font-weight:500;font-size:var(--font-size-sm);">' + escapeHtml(tech.name) + '</div>' +
          '<div style="color:var(--text-tertiary);font-size:11px;">' + escapeHtml(tech.detail) + '</div></div></div>';
      });
      html += '</div>';
    }

    // Interesting strings
    if (str.interesting && str.interesting.length) {
      html += '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-header"><div class="glass-card-title">Interesting Strings (' + str.interesting.length + ')</div></div>' +
        '<div style="max-height:300px;overflow-y:auto;font-family:var(--font-mono);font-size:11px;color:var(--orange);">';
      str.interesting.forEach(function(s) {
        html += '<div style="padding:2px 0;border-bottom:1px solid var(--border);word-break:break-all;">' + escapeHtml(s) + '</div>';
      });
      html += '</div></div>';
    }

    // AI Assessment
    if (r.aiAssessment) {
      html += '<div class="glass-card" style="margin-bottom:16px;">' +
        '<div class="glass-card-header"><div class="glass-card-title" style="color:var(--cyan);">AI Threat Assessment</div></div>' +
        '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.8;">' +
          self._md(r.aiAssessment) + '</div></div>';
    }

    resultsEl.innerHTML = html;
    Toast.success('Binary analysis complete — ' + riskCount + ' risk indicator(s), ' + iocCount + ' IOC(s)');
  }
};
