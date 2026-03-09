/* Vigil v1.0 — Vulnerability Findings View */
Views.findings = {
  _allFindings: [],

  init: function() {
    var el = document.getElementById('view-findings');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Vulnerability Findings</div>' +
        '<div style="display:flex;gap:8px;">' +
          '<button class="btn btn-ghost btn-sm" id="findings-bulk-resolve">Mark Resolved</button>' +
          '<button class="btn btn-ghost btn-sm" id="findings-bulk-fp">Mark False Positive</button>' +
          '<button class="btn btn-ghost btn-sm" id="findings-refresh">Refresh</button>' +
        '</div>' +
      '</div>' +

      '<div id="findings-stats" class="stat-grid" style="margin-bottom:16px;">' +
        '<div class="stat-card"><div class="stat-card-label">Total</div><div class="stat-card-value" id="findings-total">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Critical</div><div class="stat-card-value" id="findings-critical" style="color:var(--orange);">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">High</div><div class="stat-card-value" id="findings-high" style="color:var(--orange);">0</div></div>' +
        '<div class="stat-card"><div class="stat-card-label">Open</div><div class="stat-card-value" id="findings-open" style="color:var(--purple);">0</div></div>' +
      '</div>' +

      '<div class="filter-bar">' +
        '<select class="form-select" id="findings-sev-filter">' +
          '<option value="all">All Severities</option>' +
          '<option value="critical">Critical</option>' +
          '<option value="high">High</option>' +
          '<option value="medium">Medium</option>' +
          '<option value="low">Low</option>' +
        '</select>' +
        '<select class="form-select" id="findings-status-filter">' +
          '<option value="all">All Status</option>' +
          '<option value="open">Open</option>' +
          '<option value="resolved">Resolved</option>' +
          '<option value="false_positive">False Positive</option>' +
        '</select>' +
        '<select class="form-select" id="findings-type-filter">' +
          '<option value="all">All Scan Types</option>' +
          '<option value="nuclei">Nuclei</option>' +
          '<option value="nmap">Nmap</option>' +
          '<option value="zap">ZAP</option>' +
          '<option value="trivy">Trivy</option>' +
          '<option value="code-audit">Code Audit</option>' +
          '<option value="binary-analysis">Binary Analysis</option>' +
          '<option value="waf">WAF Detection</option>' +
        '</select>' +
        '<input type="text" class="form-input" id="findings-search" placeholder="Search findings..." style="max-width:200px;">' +
      '</div>' +

      '<div class="glass-card">' +
        '<div id="findings-table">' +
          '<div class="loading-state"><div class="spinner"></div><div>Loading findings...</div></div>' +
        '</div>' +
      '</div>' +

      '<div id="findings-detail" class="detail-panel" style="display:none;">' +
        '<div class="detail-panel-header">' +
          '<div>' +
            '<div style="font-size:var(--font-size-lg);font-weight:600;color:var(--text-primary);" id="finding-detail-title">--</div>' +
            '<div style="margin-top:4px;" id="finding-detail-badge"></div>' +
          '</div>' +
          '<button class="btn btn-ghost btn-sm" id="finding-detail-close">Close</button>' +
        '</div>' +
        '<div id="finding-detail-body"></div>' +
      '</div>';

    var self = this;
    document.getElementById('findings-refresh').addEventListener('click', function() { self.show(); });
    document.getElementById('findings-sev-filter').addEventListener('change', function() { self.filterAndRender(); });
    document.getElementById('findings-status-filter').addEventListener('change', function() { self.filterAndRender(); });
    document.getElementById('findings-type-filter').addEventListener('change', function() { self.filterAndRender(); });
    document.getElementById('findings-search').addEventListener('input', function() { self.filterAndRender(); });
    document.getElementById('finding-detail-close').addEventListener('click', function() {
      document.getElementById('findings-detail').style.display = 'none';
    });
    document.getElementById('findings-bulk-resolve').addEventListener('click', function() { self.bulkAction('resolved'); });
    document.getElementById('findings-bulk-fp').addEventListener('click', function() { self.bulkAction('false_positive'); });
  },

  show: function() {
    this.loadFindings();
  },

  hide: function() {},

  loadFindings: function() {
    var self = this;
    fetch('/api/findings', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        self._allFindings = data.findings || data || [];
        if (!Array.isArray(self._allFindings)) self._allFindings = [];

        // Stats
        var total = self._allFindings.length;
        var critical = self._allFindings.filter(function(f) { return (f.severity || '').toLowerCase() === 'critical'; }).length;
        var high = self._allFindings.filter(function(f) { return (f.severity || '').toLowerCase() === 'high'; }).length;
        var open = self._allFindings.filter(function(f) { return (f.status || 'open') === 'open'; }).length;

        document.getElementById('findings-total').textContent = total;
        document.getElementById('findings-critical').textContent = critical;
        document.getElementById('findings-high').textContent = high;
        document.getElementById('findings-open').textContent = open;

        self.filterAndRender();
      })
      .catch(function() {
        document.getElementById('findings-table').innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128196;</div><div class="empty-state-title">No Findings</div><div class="empty-state-desc">Run a scan to discover vulnerabilities</div></div>';
      });
  },

  filterAndRender: function() {
    var sev = document.getElementById('findings-sev-filter').value;
    var status = document.getElementById('findings-status-filter').value;
    var type = document.getElementById('findings-type-filter').value;
    var search = document.getElementById('findings-search').value.toLowerCase();

    var filtered = this._allFindings.filter(function(f) {
      if (sev !== 'all' && (f.severity || '').toLowerCase() !== sev) return false;
      if (status !== 'all' && (f.status || 'open') !== status) return false;
      if (type !== 'all' && (f.scanType || f.scan_type || '').toLowerCase() !== type) return false;
      if (search && !(f.title || '').toLowerCase().includes(search) && !(f.target || '').toLowerCase().includes(search)) return false;
      return true;
    });

    var container = document.getElementById('findings-table');
    if (filtered.length === 0) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#128196;</div><div class="empty-state-title">No Findings Match</div></div>';
      return;
    }

    var html = '<table class="data-table"><thead><tr><th style="width:30px;"><input type="checkbox" id="findings-select-all"></th><th>Severity</th><th>Title</th><th>Target</th><th>Status</th><th>Scan Date</th></tr></thead><tbody>';
    filtered.forEach(function(f) {
      html += '<tr class="clickable findings-row" data-id="' + escapeHtml(f.id || '') + '">' +
        '<td><input type="checkbox" class="finding-check" data-id="' + escapeHtml(f.id || '') + '" onclick="event.stopPropagation();"></td>' +
        '<td><span class="badge ' + severityBadge(f.severity) + '">' + escapeHtml(f.severity || 'info') + '</span></td>' +
        '<td style="color:var(--text-primary);">' + escapeHtml(f.title || f.name || '--') + '</td>' +
        '<td>' + escapeHtml(f.target || f.host || '--') + '</td>' +
        '<td><span class="tag">' + escapeHtml(f.status || 'open') + '</span></td>' +
        '<td>' + timeAgo(f.created_at || f.date) + '</td>' +
        '</tr>';
    });
    html += '</tbody></table>';
    container.innerHTML = html;

    // Select all
    document.getElementById('findings-select-all').addEventListener('change', function() {
      var checked = this.checked;
      container.querySelectorAll('.finding-check').forEach(function(cb) { cb.checked = checked; });
    });

    // Row click
    container.querySelectorAll('.findings-row').forEach(function(row) {
      row.addEventListener('click', function() {
        var id = row.getAttribute('data-id');
        Views.findings.showDetail(id);
      });
    });
  },

  showDetail: function(id) {
    var finding = this._allFindings.find(function(f) { return f.id == id; });
    if (!finding) return;

    document.getElementById('findings-detail').style.display = 'block';
    document.getElementById('finding-detail-title').textContent = finding.title || finding.name || '--';
    document.getElementById('finding-detail-badge').innerHTML = '<span class="badge ' + severityBadge(finding.severity) + '">' + escapeHtml(finding.severity || 'info') + '</span>';

    var body = document.getElementById('finding-detail-body');
    var html = '<div class="detail-row"><div class="detail-label">Target</div><div class="detail-value">' + escapeHtml(finding.target || '--') + '</div></div>';
    html += '<div class="detail-row"><div class="detail-label">Status</div><div class="detail-value">' + escapeHtml(finding.status || 'open') + '</div></div>';
    html += '<div class="detail-row"><div class="detail-label">Scan Type</div><div class="detail-value">' + escapeHtml(finding.scan_type || '--') + '</div></div>';
    html += '<div class="detail-row"><div class="detail-label">Description</div><div class="detail-value">' + escapeHtml(finding.description || '--') + '</div></div>';
    html += '<div class="detail-row"><div class="detail-label">Remediation</div><div class="detail-value">' + escapeHtml(finding.remediation || finding.solution || '--') + '</div></div>';
    if (finding.cve) {
      html += '<div class="detail-row"><div class="detail-label">CVE</div><div class="detail-value">' + escapeHtml(finding.cve) + '</div></div>';
    }
    html += '<div style="margin-top:16px;"><button class="btn btn-ghost btn-sm" id="finding-ai-analyze">AI Analysis</button></div>';
    body.innerHTML = html;

    document.getElementById('finding-ai-analyze').addEventListener('click', function() {
      Modal.loading('AI analyzing finding...');
      fetch('/api/findings/' + id + '/analyze', { method: 'POST', credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          Modal.close();
          Modal.open({ title: 'AI Analysis', body: '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;">' + escapeHtml(data.analysis || 'No analysis available').replace(/\n/g, '<br>') + '</div>', size: 'lg' });
        })
        .catch(function() { Modal.close(); Toast.error('AI analysis failed'); });
    });
  },

  bulkAction: function(status) {
    var checked = document.querySelectorAll('.finding-check:checked');
    if (checked.length === 0) { Toast.warning('Select findings first'); return; }

    var ids = [];
    checked.forEach(function(cb) { ids.push(cb.getAttribute('data-id')); });

    fetch('/api/findings/bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ ids: ids, status: status })
    })
    .then(function() {
      Toast.success(ids.length + ' finding(s) marked as ' + status.replace(/_/g, ' '));
      Views.findings.loadFindings();
    })
    .catch(function() { Toast.error('Bulk action failed'); });
  }
};
