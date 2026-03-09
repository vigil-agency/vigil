/* Vigil v1.0 — Compliance Frameworks View */
Views.compliance = {
  _activeFramework: 'soc2',

  init: function() {
    var el = document.getElementById('view-compliance');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Compliance Frameworks</div>' +
        '<button class="btn btn-primary btn-sm" id="compliance-report-btn">Generate Report</button>' +
      '</div>' +

      '<div class="tab-bar" id="compliance-tabs">' +
        '<div class="tab-item active" data-fw="soc2">SOC 2</div>' +
        '<div class="tab-item" data-fw="iso27001">ISO 27001</div>' +
        '<div class="tab-item" data-fw="nist800-53">NIST 800-53</div>' +
        '<div class="tab-item" data-fw="owasp-llm">OWASP LLM</div>' +
      '</div>' +

      '<div id="compliance-score-section" class="stat-grid" style="margin-bottom:20px;">' +
        '<div class="stat-card" style="text-align:center;">' +
          '<div class="stat-card-label">Overall Compliance</div>' +
          '<div class="stat-card-value" id="compliance-score-value" style="font-size:36px;">--%</div>' +
        '</div>' +
        '<div class="stat-card"><div class="stat-card-label">Passed</div><div class="stat-card-value" id="compliance-passed" style="color:var(--cyan);">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Failed</div><div class="stat-card-value" id="compliance-failed" style="color:var(--orange);">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Partial</div><div class="stat-card-value" id="compliance-partial" style="color:var(--purple);">0</div></div>' +
      '</div>' +

      '<div class="glass-card">' +
        '<div class="glass-card-title" style="margin-bottom:12px;">Controls</div>' +
        '<div id="compliance-controls">' +
          '<div class="loading-state"><div class="spinner"></div><div>Loading controls...</div></div>' +
        '</div>' +
      '</div>';

    var self = this;
    document.querySelectorAll('#compliance-tabs .tab-item').forEach(function(tab) {
      tab.addEventListener('click', function() {
        document.querySelectorAll('#compliance-tabs .tab-item').forEach(function(t) { t.classList.remove('active'); });
        tab.classList.add('active');
        self._activeFramework = tab.getAttribute('data-fw');
        self.loadControls();
      });
    });

    document.getElementById('compliance-report-btn').addEventListener('click', function() {
      Modal.loading('Generating AI compliance report... (this may take 30-90 seconds)');
      fetch('/api/compliance/' + self._activeFramework + '/report', { method: 'POST', credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          Modal.close();
          if (data.error) { Toast.error(data.error); return; }
          var s = data.summary || {};
          var scoreVal = s.passing && s.total ? Math.round((s.passing / Math.max(s.passing + s.failing + s.partial, 1)) * 100) : 0;
          var scoreColor = scoreVal >= 80 ? 'var(--cyan)' : scoreVal >= 50 ? 'var(--purple)' : 'var(--orange)';
          Modal.open({
            title: (data.frameworkName || 'Compliance') + ' — AI Audit Report',
            size: 'lg',
            body:
              '<div style="display:flex;gap:16px;margin-bottom:16px;flex-wrap:wrap;">' +
                '<div style="text-align:center;min-width:80px;"><div style="font-size:28px;font-weight:700;color:' + scoreColor + ';">' + scoreVal + '%</div><div style="font-size:var(--font-size-xs);color:var(--text-tertiary);">Score</div></div>' +
                '<div style="text-align:center;min-width:60px;"><div style="font-size:28px;font-weight:700;color:var(--cyan);">' + (s.passing || 0) + '</div><div style="font-size:var(--font-size-xs);color:var(--text-tertiary);">Pass</div></div>' +
                '<div style="text-align:center;min-width:60px;"><div style="font-size:28px;font-weight:700;color:var(--orange);">' + (s.failing || 0) + '</div><div style="font-size:var(--font-size-xs);color:var(--text-tertiary);">Fail</div></div>' +
                '<div style="text-align:center;min-width:60px;"><div style="font-size:28px;font-weight:700;color:var(--purple);">' + (s.partial || 0) + '</div><div style="font-size:var(--font-size-xs);color:var(--text-tertiary);">Partial</div></div>' +
                '<div style="text-align:center;min-width:60px;"><div style="font-size:28px;font-weight:700;color:var(--text-tertiary);">' + (s.na || 0) + '</div><div style="font-size:var(--font-size-xs);color:var(--text-tertiary);">N/A</div></div>' +
              '</div>' +
              '<div style="background:var(--well);border-radius:8px;padding:16px;max-height:50vh;overflow-y:auto;white-space:pre-wrap;font-family:var(--font-mono);font-size:var(--font-size-xs);line-height:1.7;color:var(--text-secondary);">' +
                escapeHtml(data.report || 'No report content.') +
              '</div>' +
              '<div style="margin-top:8px;color:var(--text-tertiary);font-size:var(--font-size-xs);">Generated: ' + (data.generatedAt || '--') + '</div>',
            footer: '<button class="btn btn-ghost btn-sm" onclick="Modal.close()">Close</button>'
          });
        })
        .catch(function() { Modal.close(); Toast.error('Report generation failed'); });
    });
  },

  show: function() {
    this.loadControls();
  },

  hide: function() {},

  loadControls: function() {
    var fw = this._activeFramework;
    var container = document.getElementById('compliance-controls');
    container.innerHTML = '<div class="loading-state"><div class="spinner"></div><div>Loading...</div></div>';

    fetch('/api/compliance/' + fw, { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var controls = data.controls || data || [];
        if (!Array.isArray(controls)) controls = [];

        var passed = 0, failed = 0, partial = 0, naCount = 0;
        controls.forEach(function(c) {
          var s = (c.status || '').toLowerCase();
          if (s === 'pass' || s === 'passed') passed++;
          else if (s === 'fail' || s === 'failed') failed++;
          else if (s === 'na' || s === 'not_applicable') naCount++;
          else partial++;
        });

        var scoreable = passed + failed + partial;
        var score = scoreable > 0 ? Math.round((passed / scoreable) * 100) : 0;
        document.getElementById('compliance-score-value').textContent = score + '%';
        document.getElementById('compliance-score-value').style.color = score >= 80 ? 'var(--cyan)' : score >= 50 ? 'var(--purple)' : 'var(--orange)';
        document.getElementById('compliance-passed').textContent = passed;
        document.getElementById('compliance-failed').textContent = failed;
        document.getElementById('compliance-partial').textContent = partial;

        if (controls.length === 0) {
          container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#9745;</div><div class="empty-state-title">No Controls</div><div class="empty-state-desc">No compliance data available for this framework</div></div>';
          return;
        }

        var html = '<table class="data-table"><thead><tr><th>ID</th><th>Control</th><th>Detail</th><th>Status</th><th>Actions</th></tr></thead><tbody>';
        controls.forEach(function(c) {
          var status = (c.status || 'partial').toLowerCase();
          var statusBadge = status === 'pass' || status === 'passed' ? 'badge-success' :
                           status === 'fail' || status === 'failed' ? 'badge-critical' :
                           status === 'na' ? 'badge-info' : 'badge-medium';
          var statusLabel = status === 'pass' || status === 'passed' ? 'Pass' :
                           status === 'fail' || status === 'failed' ? 'Fail' :
                           status === 'na' ? 'N/A' : 'Partial';

          html += '<tr>' +
            '<td style="color:var(--text-primary);font-weight:500;white-space:nowrap;">' + escapeHtml(c.id || c.control_id || '--') + '</td>' +
            '<td>' + escapeHtml(c.title || c.name || '--') + '</td>' +
            '<td style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + escapeHtml(c.detail || c.description || '--') + '</td>' +
            '<td><span class="badge ' + statusBadge + '">' + statusLabel + '</span></td>' +
            '<td><button class="btn btn-ghost btn-sm compliance-evidence-btn" data-id="' + escapeHtml(c.id || c.control_id || '') + '">Evidence</button></td>' +
            '</tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;

        container.querySelectorAll('.compliance-evidence-btn').forEach(function(btn) {
          btn.addEventListener('click', function() {
            var controlId = btn.getAttribute('data-id');
            Modal.open({
              title: 'Evidence: ' + controlId,
              body: '<div class="form-group"><label class="form-label">Upload or describe evidence</label><textarea class="form-textarea" id="evidence-text" rows="4" placeholder="Describe evidence for this control..."></textarea></div>',
              footer: '<button class="btn btn-ghost" onclick="Modal.close()">Cancel</button><button class="btn btn-primary" id="evidence-save-btn">Save Evidence</button>'
            });

            document.getElementById('evidence-save-btn').addEventListener('click', function() {
              var text = document.getElementById('evidence-text').value.trim();
              if (!text) { Toast.warning('Enter evidence'); return; }
              fetch('/api/compliance/' + fw + '/evidence', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ control_id: controlId, evidence: text })
              })
              .then(function() { Modal.close(); Toast.success('Evidence saved'); })
              .catch(function() { Toast.error('Failed to save evidence'); });
            });
          });
        });
      })
      .catch(function() {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#9745;</div><div class="empty-state-title">Framework Unavailable</div></div>';
      });
  }
};
