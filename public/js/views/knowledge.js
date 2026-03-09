/* Vigil v1.0 — Intel Hub View (replaces Knowledge Base)
   Security RSS feeds, CVE Watch, AI Briefings, CISA KEV */
Views.knowledge = {
  _tab: 'feed',
  _items: [],
  _sources: [],
  _feedStatus: {},
  _lastRefresh: null,
  _filter: { source: '', category: '', search: '' },
  _kevData: null,
  _cveWatch: null,
  _briefings: [],

  /* ═══════════════════ Markdown Renderer ═══════════════════ */
  _md: function(text) {
    if (!text) return '';
    // Escape HTML first
    var s = String(text)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    // Code blocks ```...```
    s = s.replace(/```(\w*)\n([\s\S]*?)```/g, function(m, lang, code) {
      return '<pre style="background:var(--well);padding:12px;border-radius:var(--radius-sm);border:1px solid var(--border);overflow-x:auto;font-size:12px;line-height:1.6;margin:8px 0;">' +
        '<code>' + code.trim() + '</code></pre>';
    });

    // Inline code `...`
    s = s.replace(/`([^`]+)`/g, '<code style="background:var(--well);padding:1px 5px;border-radius:3px;font-size:12px;">$1</code>');

    // Headers ## and ###
    s = s.replace(/^### (.+)$/gm, '<h4 style="color:var(--text-primary);font-size:var(--font-size-sm);font-weight:700;margin:16px 0 6px;border-bottom:1px solid var(--border);padding-bottom:4px;">$1</h4>');
    s = s.replace(/^## (.+)$/gm, '<h3 style="color:var(--cyan);font-size:var(--font-size-base);font-weight:700;margin:20px 0 8px;border-bottom:1px solid var(--border);padding-bottom:6px;">$1</h3>');
    s = s.replace(/^# (.+)$/gm, '<h2 style="color:var(--text-primary);font-size:var(--font-size-lg);font-weight:700;margin:20px 0 10px;">$1</h2>');

    // Bold **text**
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong style="color:var(--text-primary);">$1</strong>');
    // Italic *text*
    s = s.replace(/(?<!\*)\*([^*]+)\*(?!\*)/g, '<em>$1</em>');

    // Numbered lists
    s = s.replace(/^(\d+)\. (.+)$/gm, '<div style="display:flex;gap:8px;margin:3px 0 3px 8px;"><span style="color:var(--cyan);font-weight:600;min-width:18px;">$1.</span><span>$2</span></div>');

    // Bullet lists  - and *
    s = s.replace(/^[\-\*] (.+)$/gm, '<div style="display:flex;gap:8px;margin:3px 0 3px 8px;"><span style="color:var(--cyan);">&#8226;</span><span>$1</span></div>');

    // Article references [N]
    s = s.replace(/\[(\d+)\]/g, '<span style="color:var(--cyan);font-weight:600;font-size:11px;">[$1]</span>');

    // CVE references
    s = s.replace(/(CVE-\d{4}-\d{4,})/g, '<span style="color:var(--orange);font-weight:600;">$1</span>');

    // Paragraphs (double newline)
    s = s.replace(/\n\n/g, '</p><p style="margin:8px 0;">');
    // Single newlines (within sections)
    s = s.replace(/\n/g, '<br>');

    return '<p style="margin:8px 0;">' + s + '</p>';
  },

  init: function() {
    var el = document.getElementById('view-knowledge');
    el.innerHTML =
      '<div class="section-header">' +
        '<div class="section-title">Intel Hub</div>' +
        '<div style="display:flex;gap:8px;align-items:center;">' +
          '<span id="intel-last-refresh" style="color:var(--text-tertiary);font-size:var(--font-size-xs);"></span>' +
          '<button class="btn btn-ghost btn-sm" id="intel-refresh-btn">Refresh Feeds</button>' +
        '</div>' +
      '</div>' +
      '<div class="tab-bar" id="intel-tabs">' +
        '<div class="tab-item active" data-tab="feed">Security Feed</div>' +
        '<div class="tab-item" data-tab="cve-watch">CVE Watch</div>' +
        '<div class="tab-item" data-tab="briefing">AI Briefing</div>' +
        '<div class="tab-item" data-tab="kev">CISA KEV</div>' +
      '</div>' +
      '<div id="intel-content"></div>';

    var self = this;
    document.querySelectorAll('#intel-tabs .tab-item').forEach(function(t) {
      t.addEventListener('click', function() {
        document.querySelectorAll('#intel-tabs .tab-item').forEach(function(x) { x.classList.remove('active'); });
        t.classList.add('active');
        self._tab = t.getAttribute('data-tab');
        self._renderTab();
      });
    });
    document.getElementById('intel-refresh-btn').addEventListener('click', function() { self._refreshFeeds(); });
  },

  show: function() {
    this._loadSources();
    this._renderTab();
  },

  hide: function() {},

  update: function(data) {
    if (data && data.newCount) {
      Toast.info(data.newCount + ' new intel items');
      if (this._tab === 'feed') this._loadFeed();
    }
  },

  /* ═══════════════════ Data Loading ═══════════════════ */
  _loadSources: function() {
    var self = this;
    fetch('/api/intel/sources', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(d) { self._sources = d.sources || []; })
      .catch(function() {});
  },

  _loadFeed: function() {
    var self = this;
    var c = document.getElementById('intel-content');
    if (!self._items.length) c.innerHTML = '<div class="loading-state"><div class="spinner"></div><div>Loading security feeds...</div></div>';

    var params = new URLSearchParams();
    if (self._filter.source) params.set('source', self._filter.source);
    if (self._filter.category) params.set('category', self._filter.category);
    if (self._filter.search) params.set('search', self._filter.search);
    params.set('limit', '80');
    fetch('/api/intel/feeds?' + params.toString(), { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        self._items = d.items || [];
        self._feedStatus = d.feedStatus || {};
        self._lastRefresh = d.lastRefresh;
        self._renderFeed();
        var ts = document.getElementById('intel-last-refresh');
        if (ts) ts.textContent = d.lastRefresh ? 'Updated ' + timeAgo(d.lastRefresh) : 'Not yet refreshed';
      })
      .catch(function() { self._renderMsg('Failed to load feeds. Try Refresh.'); });
  },

  _refreshFeeds: function() {
    var self = this;
    var btn = document.getElementById('intel-refresh-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Refreshing...'; }
    Toast.info('Fetching 15 security feeds...');

    fetch('/api/intel/feeds/refresh', { method: 'POST', credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        var ok = 0; var fail = 0;
        if (d.feedStatus) { for (var k in d.feedStatus) { if (d.feedStatus[k].status === 'ok') ok++; else fail++; } }
        Toast.success(d.newCount + ' new items from ' + ok + ' feeds' + (fail ? ' (' + fail + ' failed)' : ''));
        if (btn) { btn.disabled = false; btn.textContent = 'Refresh Feeds'; }
        if (self._tab === 'feed') self._loadFeed();
      })
      .catch(function() {
        Toast.error('Feed refresh failed');
        if (btn) { btn.disabled = false; btn.textContent = 'Refresh Feeds'; }
      });
  },

  _renderMsg: function(msg) {
    document.getElementById('intel-content').innerHTML =
      '<div class="empty-state"><div class="empty-state-icon">&#128161;</div>' +
      '<div class="empty-state-title">' + escapeHtml(msg) + '</div></div>';
  },

  /* ═══════════════════ Tab Routing ═══════════════════ */
  _renderTab: function() {
    var c = document.getElementById('intel-content');
    if (!c) return;
    c.innerHTML = '<div class="loading-state"><div class="spinner"></div><div>Loading...</div></div>';
    try {
      if (this._tab === 'feed') this._loadFeed();
      else if (this._tab === 'cve-watch') this._loadCVEWatch();
      else if (this._tab === 'briefing') this._loadBriefings();
      else if (this._tab === 'kev') this._loadKEV();
    } catch (e) {
      c.innerHTML = '<div class="empty-state"><div class="empty-state-title">Error loading tab</div><div class="empty-state-desc">' + escapeHtml(e.message) + '</div></div>';
    }
  },

  /* ═══════════════════ FEED TAB ═══════════════════ */
  _renderFeed: function() {
    var self = this;
    var c = document.getElementById('intel-content');

    // Build filter bar
    var sourceOpts = '<option value="">All Sources</option>';
    self._sources.forEach(function(s) {
      sourceOpts += '<option value="' + s.key + '"' + (self._filter.source === s.key ? ' selected' : '') + '>' + escapeHtml(s.name) + '</option>';
    });

    var catOpts = '<option value="">All Categories</option>' +
      '<option value="advisory"' + (self._filter.category === 'advisory' ? ' selected' : '') + '>Advisory</option>' +
      '<option value="news"' + (self._filter.category === 'news' ? ' selected' : '') + '>News</option>' +
      '<option value="analysis"' + (self._filter.category === 'analysis' ? ' selected' : '') + '>Analysis</option>' +
      '<option value="exploit"' + (self._filter.category === 'exploit' ? ' selected' : '') + '>Exploit</option>' +
      '<option value="vulnerability"' + (self._filter.category === 'vulnerability' ? ' selected' : '') + '>Vulnerability</option>';

    var filterHtml = '<div style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:center;">' +
      '<input type="text" class="form-input" id="intel-search" placeholder="Search articles..." value="' + escapeHtml(self._filter.search) + '" style="max-width:260px;flex:1;">' +
      '<select class="form-select" id="intel-source-filter" style="max-width:200px;">' + sourceOpts + '</select>' +
      '<select class="form-select" id="intel-cat-filter" style="max-width:160px;">' + catOpts + '</select>' +
      '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-left:auto;">' + self._items.length + ' items</span>' +
    '</div>';

    if (!self._items.length) {
      c.innerHTML = filterHtml +
        '<div class="empty-state"><div class="empty-state-icon">&#128225;</div>' +
        '<div class="empty-state-title">No Feed Items</div>' +
        '<div class="empty-state-desc">Click "Refresh Feeds" to fetch from 15 security sources</div></div>';
      self._bindFeedFilters();
      return;
    }

    var cardsHtml = '<div class="grid-2">';
    self._items.forEach(function(item, idx) {
      var catColors = { advisory: 'var(--orange)', news: 'var(--cyan)', analysis: 'var(--text-secondary)', exploit: 'var(--orange)', vulnerability: 'var(--orange)' };
      var catColor = catColors[item.category] || 'var(--cyan)';
      cardsHtml += '<div class="glass-card intel-card" data-idx="' + idx + '" style="cursor:pointer;transition:border-color 150ms;">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">' +
          '<span style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:' + catColor + ';">' + escapeHtml(item.sourceName) + '</span>' +
          '<span style="color:var(--text-tertiary);font-size:10px;margin-left:auto;">' + timeAgo(item.published) + '</span>' +
        '</div>' +
        '<div style="color:var(--text-primary);font-weight:600;font-size:var(--font-size-sm);margin-bottom:6px;line-height:1.4;">' + escapeHtml(item.title) + '</div>' +
        '<div style="color:var(--text-tertiary);font-size:11px;line-height:1.5;max-height:48px;overflow:hidden;">' + escapeHtml((item.summary || '').substring(0, 200)) + '</div>' +
      '</div>';
    });
    cardsHtml += '</div>';

    c.innerHTML = filterHtml + cardsHtml;
    self._bindFeedFilters();

    c.querySelectorAll('.intel-card').forEach(function(card) {
      card.addEventListener('click', function() {
        var idx = parseInt(card.getAttribute('data-idx'));
        self._showArticle(self._items[idx]);
      });
    });
  },

  _bindFeedFilters: function() {
    var self = this;
    var searchEl = document.getElementById('intel-search');
    var sourceEl = document.getElementById('intel-source-filter');
    var catEl = document.getElementById('intel-cat-filter');
    var debounce;
    if (searchEl) searchEl.addEventListener('input', function() {
      clearTimeout(debounce);
      debounce = setTimeout(function() { self._filter.search = searchEl.value; self._loadFeed(); }, 300);
    });
    if (sourceEl) sourceEl.addEventListener('change', function() { self._filter.source = sourceEl.value; self._loadFeed(); });
    if (catEl) catEl.addEventListener('change', function() { self._filter.category = catEl.value; self._loadFeed(); });
  },

  _showArticle: function(item) {
    if (!item) return;
    var self = this;
    var body = '<div style="margin-bottom:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;">' +
      '<span class="tag tag-cyan">' + escapeHtml(item.sourceName) + '</span>' +
      '<span class="tag" style="color:var(--text-tertiary);border-color:var(--border);">' + escapeHtml(item.category) + '</span>' +
      '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + timeAgo(item.published) + '</span>' +
    '</div>' +
    '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.8;margin-bottom:16px;">' +
      self._md(item.summary || 'No summary available') +
    '</div>';

    if (item.url) {
      body += '<div style="margin-bottom:16px;"><a href="' + escapeHtml(item.url) + '" target="_blank" rel="noopener" style="color:var(--cyan);font-size:var(--font-size-sm);">Open original article &#8599;</a></div>';
    }

    body += '<div style="border-top:1px solid var(--border);padding-top:12px;">' +
      '<button class="btn btn-primary btn-sm" id="intel-ai-analyze-btn">AI Analyze</button>' +
      '<div id="intel-ai-result" style="margin-top:12px;display:none;"></div>' +
    '</div>';

    Modal.open({ title: item.title, body: body, size: 'lg' });

    document.getElementById('intel-ai-analyze-btn').addEventListener('click', function() {
      var btn = this;
      btn.disabled = true; btn.textContent = 'Analyzing...';
      var result = document.getElementById('intel-ai-result');
      result.style.display = 'block';
      result.innerHTML = '<div class="loading-state" style="padding:16px;"><div class="spinner"></div><div>AI analyzing article...</div></div>';

      fetch('/api/intel/feeds/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ item: item })
      })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        result.innerHTML = '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.8;background:var(--well);padding:16px;border-radius:var(--radius);border:1px solid var(--border);">' +
          self._md(d.analysis || d.error || 'No analysis') + '</div>';
        btn.textContent = 'Analyzed';
      })
      .catch(function() {
        result.innerHTML = '<div style="color:var(--orange);">Analysis failed. Check AI provider.</div>';
        btn.disabled = false; btn.textContent = 'AI Analyze';
      });
    });
  },

  /* ═══════════════════ CVE WATCH TAB ═══════════════════ */
  _loadCVEWatch: function() {
    var self = this;
    fetch('/api/intel/cve-watch', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(d) { self._cveWatch = d; self._renderCVEWatch(); })
      .catch(function(e) {
        document.getElementById('intel-content').innerHTML =
          '<div class="empty-state"><div class="empty-state-icon">&#128270;</div>' +
          '<div class="empty-state-title">Failed to load CVE Watch</div>' +
          '<div class="empty-state-desc">' + escapeHtml(e.message || 'Network error') + '</div></div>';
      });
  },

  _renderCVEWatch: function() {
    var self = this;
    var d = self._cveWatch || { watchlist: [], results: [], lastCheck: null };
    var c = document.getElementById('intel-content');

    var html = '<div class="glass-card" style="margin-bottom:16px;">' +
      '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap;">' +
        '<div style="color:var(--text-primary);font-weight:600;">CVE Watchlist</div>' +
        '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' +
          (d.lastCheck ? 'Last checked ' + timeAgo(d.lastCheck) : 'Add keywords and click Check NVD') + '</span>' +
        '<button class="btn btn-ghost btn-sm" id="cve-refresh-btn" style="margin-left:auto;"' +
          (d.watchlist.length ? '' : ' disabled') + '>Check NVD</button>' +
      '</div>' +
      '<div style="display:flex;gap:8px;margin-bottom:12px;">' +
        '<input type="text" class="form-input" id="cve-add-input" placeholder="Add software to watch (e.g. nginx, nodejs, apache, postgresql)" style="flex:1;">' +
        '<button class="btn btn-primary btn-sm" id="cve-add-btn">Add</button>' +
      '</div>' +
      '<div style="display:flex;flex-wrap:wrap;gap:6px;" id="cve-watchlist-tags">';

    if (d.watchlist.length) {
      d.watchlist.forEach(function(kw) {
        html += '<span class="tag tag-cyan" style="cursor:pointer;" title="Click to remove" data-kw="' + escapeHtml(kw) + '">' +
          escapeHtml(kw) + ' &#10005;</span>';
      });
    } else {
      html += '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">No keywords watched yet. ' +
        'Add software names above to monitor for new CVEs from the NVD database.</span>';
    }
    html += '</div></div>';

    // Results
    if (d.results && d.results.length) {
      html += '<div class="glass-card"><div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">' +
        '<span style="color:var(--text-primary);font-weight:600;">' + d.results.length + ' CVEs Found</span>' +
      '</div>' +
      '<div style="max-height:500px;overflow-y:auto;">' +
      '<table class="data-table"><thead><tr>' +
        '<th>CVE ID</th><th>Severity</th><th>Score</th><th>Keyword</th><th>Description</th>' +
      '</tr></thead><tbody>';
      d.results.forEach(function(cve, idx) {
        var sevColor = (cve.severity === 'CRITICAL' || cve.severity === 'HIGH') ? 'var(--orange)' : 'var(--text-secondary)';
        html += '<tr class="cve-row" data-idx="' + idx + '" style="cursor:pointer;">' +
          '<td style="color:var(--cyan);white-space:nowrap;font-weight:600;">' + escapeHtml(cve.id || '') + '</td>' +
          '<td style="color:' + sevColor + ';font-weight:600;">' + escapeHtml(cve.severity || 'N/A') + '</td>' +
          '<td>' + (cve.score || '-') + '</td>' +
          '<td><span class="tag" style="font-size:10px;">' + escapeHtml(cve.keyword || '') + '</span></td>' +
          '<td style="font-size:11px;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' +
            escapeHtml((cve.description || '').substring(0, 300)) + '">' +
            escapeHtml((cve.description || '').substring(0, 150)) + '</td>' +
        '</tr>';
      });
      html += '</tbody></table></div></div>';
    } else if (d.watchlist.length && d.lastCheck) {
      html += '<div class="empty-state" style="padding:32px;"><div class="empty-state-icon">&#9989;</div>' +
        '<div class="empty-state-title">No CVEs found for your watchlist</div></div>';
    }

    c.innerHTML = html;

    // Bind add keyword
    var addBtn = document.getElementById('cve-add-btn');
    var addInput = document.getElementById('cve-add-input');
    if (addBtn) addBtn.addEventListener('click', function() { self._addCVEKeyword(); });
    if (addInput) addInput.addEventListener('keypress', function(e) { if (e.key === 'Enter') self._addCVEKeyword(); });

    // Bind check NVD
    var refreshBtn = document.getElementById('cve-refresh-btn');
    if (refreshBtn) refreshBtn.addEventListener('click', function() {
      refreshBtn.disabled = true; refreshBtn.textContent = 'Checking NVD...';
      Toast.info('Querying NVD for ' + d.watchlist.length + ' keywords (7s between requests)...');
      fetch('/api/intel/cve-watch', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin', body: JSON.stringify({ action: 'refresh' })
      })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        self._cveWatch = data;
        Toast.success((data.results ? data.results.length : 0) + ' CVEs found');
        self._renderCVEWatch();
      })
      .catch(function() {
        Toast.error('NVD query failed');
        refreshBtn.disabled = false; refreshBtn.textContent = 'Check NVD';
      });
    });

    // Bind CVE row click -> detail modal
    c.querySelectorAll('.cve-row').forEach(function(row) {
      row.addEventListener('click', function() {
        var idx = parseInt(row.getAttribute('data-idx'));
        var cve = (d.results || [])[idx];
        if (cve) self._showCVEDetail(cve);
      });
    });

    // Bind remove keyword tags
    c.querySelectorAll('#cve-watchlist-tags .tag[data-kw]').forEach(function(tag) {
      tag.addEventListener('click', function() {
        var kw = tag.getAttribute('data-kw');
        fetch('/api/intel/cve-watch', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin', body: JSON.stringify({ action: 'remove', keyword: kw })
        })
        .then(function(r) { return r.json(); })
        .then(function(data) { self._cveWatch = data; self._renderCVEWatch(); Toast.info('Removed "' + kw + '"'); })
        .catch(function() { Toast.error('Failed to remove keyword'); });
      });
    });
  },

  _addCVEKeyword: function() {
    var self = this;
    var input = document.getElementById('cve-add-input');
    var kw = (input.value || '').trim();
    if (!kw) return;
    input.value = '';
    fetch('/api/intel/cve-watch', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin', body: JSON.stringify({ action: 'add', keyword: kw })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) { self._cveWatch = data; self._renderCVEWatch(); Toast.success('Watching "' + kw + '"'); })
    .catch(function() { Toast.error('Failed to add keyword'); });
  },

  /* ═══════════════════ AI BRIEFING TAB ═══════════════════ */
  _loadBriefings: function() {
    var self = this;
    fetch('/api/intel/briefings', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(d) { self._briefings = d.briefings || []; self._renderBriefings(); })
      .catch(function() { self._briefings = []; self._renderBriefings(); });
  },

  _renderBriefings: function() {
    var self = this;
    var c = document.getElementById('intel-content');

    var sourceOpts = '<option value="">All Feeds</option>';
    self._sources.forEach(function(s) {
      sourceOpts += '<option value="' + s.key + '">' + escapeHtml(s.name) + '</option>';
    });

    var html = '<div class="glass-card" style="margin-bottom:16px;">' +
      '<div style="color:var(--text-primary);font-weight:600;margin-bottom:10px;">Generate AI Intelligence Briefing</div>' +
      '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-bottom:12px;">' +
        'AI analyzes the latest 50 feed items and produces a structured threat intelligence briefing with executive summary, critical items, notable threats, and recommended actions.' +
      '</div>' +
      '<div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">' +
        '<select class="form-select" id="briefing-scope" style="max-width:220px;">' + sourceOpts + '</select>' +
        '<button class="btn btn-primary btn-sm" id="briefing-gen-btn">Generate Briefing</button>' +
      '</div>' +
    '</div>' +
    '<div id="briefing-result"></div>';

    // Past briefings
    if (self._briefings.length) {
      html += '<div style="color:var(--text-primary);font-weight:600;margin:20px 0 12px;">Past Briefings (' + self._briefings.length + ')</div>';
      self._briefings.forEach(function(b, idx) {
        html += '<div class="glass-card briefing-card" data-idx="' + idx + '" style="cursor:pointer;margin-bottom:8px;transition:border-color 150ms;">' +
          '<div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">' +
            '<span style="color:var(--cyan);font-weight:600;">Intelligence Briefing</span>' +
            '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + timeAgo(b.generatedAt) + '</span>' +
            '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + b.itemCount + ' articles analyzed</span>' +
            '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);margin-left:auto;">' + escapeHtml(b.scope || 'all') + '</span>' +
          '</div>' +
        '</div>';
      });
    } else {
      html += '<div class="empty-state" style="padding:32px;">' +
        '<div class="empty-state-icon">&#129302;</div>' +
        '<div class="empty-state-title">No briefings yet</div>' +
        '<div class="empty-state-desc">Generate your first AI briefing to get a threat landscape summary</div></div>';
    }

    c.innerHTML = html;

    // Bind generate
    document.getElementById('briefing-gen-btn').addEventListener('click', function() {
      var btn = this;
      btn.disabled = true; btn.textContent = 'Generating...';
      var scopeEl = document.getElementById('briefing-scope');
      var feedKeys = scopeEl.value ? [scopeEl.value] : null;

      var resultEl = document.getElementById('briefing-result');
      resultEl.innerHTML = '<div class="glass-card"><div class="loading-state" style="padding:32px;">' +
        '<div class="spinner"></div><div>AI is analyzing feed items... this takes 1-2 minutes</div></div></div>';

      fetch('/api/intel/briefings/generate', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ scope: feedKeys ? 'selected' : 'all', feedKeys: feedKeys })
      })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        btn.disabled = false; btn.textContent = 'Generate Briefing';
        if (d.error) {
          resultEl.innerHTML = '<div class="glass-card" style="color:var(--orange);padding:16px;">' + escapeHtml(d.error) + '</div>';
          return;
        }
        resultEl.innerHTML = '<div class="glass-card" style="padding:20px;">' +
          '<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;border-bottom:1px solid var(--border);padding-bottom:12px;">' +
            '<span style="color:var(--cyan);font-weight:700;font-size:var(--font-size-lg);">Intelligence Briefing</span>' +
            '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + d.itemCount + ' articles</span>' +
            '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + timeAgo(d.generatedAt) + '</span>' +
          '</div>' +
          '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.8;">' +
            self._md(d.content) + '</div></div>';
        self._briefings.unshift(d);
      })
      .catch(function() {
        btn.disabled = false; btn.textContent = 'Generate Briefing';
        resultEl.innerHTML = '<div class="glass-card" style="color:var(--orange);padding:16px;">Briefing generation failed. Check AI provider.</div>';
      });
    });

    // Bind past briefing cards
    c.querySelectorAll('.briefing-card').forEach(function(card) {
      card.addEventListener('click', function() {
        var idx = parseInt(card.getAttribute('data-idx'));
        var b = self._briefings[idx];
        if (!b) return;
        Modal.open({
          title: 'Intelligence Briefing',
          body: '<div style="display:flex;gap:12px;margin-bottom:16px;align-items:center;border-bottom:1px solid var(--border);padding-bottom:12px;">' +
            '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + timeAgo(b.generatedAt) + '</span>' +
            '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + b.itemCount + ' articles</span>' +
            '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">' + escapeHtml(b.scope || 'all') + '</span>' +
          '</div>' +
          '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.8;">' +
            self._md(b.content) + '</div>',
          size: 'lg'
        });
      });
    });
  },

  /* ═══════════════════ CISA KEV TAB ═══════════════════ */
  _loadKEV: function() {
    var self = this;
    var c = document.getElementById('intel-content');

    // Use cached data if available
    if (self._kevData && self._kevData.vulnerabilities) {
      self._renderKEV();
      return;
    }

    c.innerHTML = '<div class="loading-state"><div class="spinner"></div><div>Loading CISA KEV catalog...</div></div>';
    fetch('/api/intel/kev?limit=100', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (d.error) {
          self._kevData = null;
          self._renderKEV();
        } else {
          self._kevData = d;
          self._renderKEV();
        }
      })
      .catch(function() {
        self._kevData = null;
        self._renderKEV();
      });
  },

  _renderKEV: function() {
    var self = this;
    var d = self._kevData;
    var c = document.getElementById('intel-content');

    if (!d || !d.vulnerabilities) {
      c.innerHTML = '<div class="glass-card" style="text-align:center;padding:40px;">' +
        '<div style="font-size:32px;margin-bottom:12px;">&#9888;</div>' +
        '<div style="color:var(--text-primary);font-weight:600;margin-bottom:8px;">CISA KEV Catalog</div>' +
        '<div style="color:var(--text-tertiary);margin-bottom:16px;">Fetch the Known Exploited Vulnerabilities catalog from CISA (1500+ actively exploited CVEs)</div>' +
        '<button class="btn btn-primary btn-sm" id="kev-fetch-btn">Fetch KEV Catalog</button></div>';

      document.getElementById('kev-fetch-btn').addEventListener('click', function() {
        var btn = this; btn.disabled = true; btn.textContent = 'Fetching from CISA...';
        fetch('/api/intel/kev/refresh', { method: 'POST', credentials: 'same-origin' })
          .then(function(r) { return r.json(); })
          .then(function(data) {
            if (data.error) { Toast.error(data.error); btn.disabled = false; btn.textContent = 'Fetch KEV Catalog'; return; }
            Toast.success(data.count + ' KEVs loaded');
            self._kevData = null; // Force reload
            self._loadKEV();
          })
          .catch(function() { Toast.error('KEV fetch failed'); btn.disabled = false; btn.textContent = 'Fetch KEV Catalog'; });
      });
      return;
    }

    var vulns = d.vulnerabilities || [];
    var html = '<div class="glass-card" style="margin-bottom:16px;">' +
      '<div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;">' +
        '<div style="color:var(--text-primary);font-weight:600;">CISA Known Exploited Vulnerabilities</div>' +
        '<span style="color:var(--orange);font-weight:600;">' + (d.count || 0) + ' total</span>' +
        '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);">Showing ' + vulns.length + ' of ' + (d.totalFiltered || d.count) + '</span>' +
        '<input type="text" class="form-input" id="kev-search" placeholder="Search CVE, vendor, product..." style="max-width:280px;margin-left:auto;">' +
        '<button class="btn btn-ghost btn-sm" id="kev-refresh-btn">Refresh</button>' +
      '</div>' +
    '</div>';

    if (vulns.length) {
      html += '<div class="glass-card" style="padding:0;"><div style="max-height:calc(100vh - 340px);overflow-y:auto;">' +
        '<table class="data-table"><thead><tr>' +
          '<th>CVE ID</th><th>Vendor</th><th>Product</th><th>Added</th><th>Due</th><th>Ransomware</th><th>Description</th>' +
        '</tr></thead><tbody>';
      vulns.forEach(function(v, idx) {
        var ransomColor = v.knownRansomware === 'Known' ? 'var(--orange)' : 'var(--text-tertiary)';
        html += '<tr class="kev-row" data-idx="' + idx + '" style="cursor:pointer;">' +
          '<td style="color:var(--cyan);white-space:nowrap;font-weight:600;">' + escapeHtml(v.cveID || '') + '</td>' +
          '<td>' + escapeHtml(v.vendor || '') + '</td>' +
          '<td>' + escapeHtml(v.product || '') + '</td>' +
          '<td style="white-space:nowrap;font-size:11px;">' + escapeHtml(v.dateAdded || '') + '</td>' +
          '<td style="white-space:nowrap;font-size:11px;">' + escapeHtml(v.dueDate || '') + '</td>' +
          '<td style="color:' + ransomColor + ';font-size:11px;">' + escapeHtml(v.knownRansomware || 'Unknown') + '</td>' +
          '<td style="font-size:11px;max-width:350px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' +
            escapeHtml((v.description || '').substring(0, 300)) + '">' + escapeHtml((v.description || '').substring(0, 200)) + '</td>' +
        '</tr>';
      });
      html += '</tbody></table></div></div>';
    } else {
      html += '<div class="empty-state" style="padding:32px;">' +
        '<div class="empty-state-title">No results matching search</div></div>';
    }

    c.innerHTML = html;

    // Bind KEV row click -> detail modal
    c.querySelectorAll('.kev-row').forEach(function(row) {
      row.addEventListener('click', function() {
        var idx = parseInt(row.getAttribute('data-idx'));
        var v = (vulns || [])[idx];
        if (v) self._showKEVDetail(v);
      });
    });

    // KEV search
    var kevDebounce;
    var kevSearch = document.getElementById('kev-search');
    if (kevSearch) kevSearch.addEventListener('input', function() {
      var q = this.value;
      clearTimeout(kevDebounce);
      kevDebounce = setTimeout(function() {
        fetch('/api/intel/kev?search=' + encodeURIComponent(q) + '&limit=100', { credentials: 'same-origin' })
          .then(function(r) { return r.json(); })
          .then(function(data) { self._kevData = data; self._renderKEV(); })
          .catch(function() {});
      }, 300);
    });

    var kevRefresh = document.getElementById('kev-refresh-btn');
    if (kevRefresh) kevRefresh.addEventListener('click', function() {
      kevRefresh.disabled = true; kevRefresh.textContent = 'Refreshing...';
      fetch('/api/intel/kev/refresh', { method: 'POST', credentials: 'same-origin' })
        .then(function() {
          self._kevData = null;
          Toast.success('KEV catalog refreshed');
          self._loadKEV();
        })
        .catch(function() { Toast.error('KEV refresh failed'); kevRefresh.disabled = false; kevRefresh.textContent = 'Refresh'; });
    });
  },

  /* ═══════════════════ DETAIL MODALS ═══════════════════ */
  _showKEVDetail: function(v) {
    var ransomColor = v.knownRansomware === 'Known' ? 'var(--orange)' : 'var(--text-tertiary)';
    var body = '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;">' +
      '<span class="tag tag-cyan" style="font-weight:600;">' + escapeHtml(v.cveID || '') + '</span>' +
      '<span class="tag" style="color:' + ransomColor + ';border-color:' + ransomColor + ';">Ransomware: ' + escapeHtml(v.knownRansomware || 'Unknown') + '</span>' +
    '</div>' +
    '<table style="width:100%;border-collapse:collapse;font-size:var(--font-size-sm);">' +
      '<tr><td style="padding:8px 12px;color:var(--text-tertiary);white-space:nowrap;border-bottom:1px solid var(--border);width:140px;">Vendor</td>' +
        '<td style="padding:8px 12px;color:var(--text-primary);border-bottom:1px solid var(--border);">' + escapeHtml(v.vendorProject || v.vendor || '') + '</td></tr>' +
      '<tr><td style="padding:8px 12px;color:var(--text-tertiary);white-space:nowrap;border-bottom:1px solid var(--border);">Product</td>' +
        '<td style="padding:8px 12px;color:var(--text-primary);border-bottom:1px solid var(--border);">' + escapeHtml(v.product || '') + '</td></tr>' +
      '<tr><td style="padding:8px 12px;color:var(--text-tertiary);white-space:nowrap;border-bottom:1px solid var(--border);">Vulnerability</td>' +
        '<td style="padding:8px 12px;color:var(--text-primary);border-bottom:1px solid var(--border);">' + escapeHtml(v.vulnerabilityName || '') + '</td></tr>' +
      '<tr><td style="padding:8px 12px;color:var(--text-tertiary);white-space:nowrap;border-bottom:1px solid var(--border);">Date Added</td>' +
        '<td style="padding:8px 12px;color:var(--text-primary);border-bottom:1px solid var(--border);">' + escapeHtml(v.dateAdded || '') + '</td></tr>' +
      '<tr><td style="padding:8px 12px;color:var(--text-tertiary);white-space:nowrap;border-bottom:1px solid var(--border);">Due Date</td>' +
        '<td style="padding:8px 12px;color:var(--orange);font-weight:600;border-bottom:1px solid var(--border);">' + escapeHtml(v.dueDate || '') + '</td></tr>' +
      '<tr><td style="padding:8px 12px;color:var(--text-tertiary);white-space:nowrap;border-bottom:1px solid var(--border);">Ransomware Use</td>' +
        '<td style="padding:8px 12px;color:' + ransomColor + ';font-weight:600;border-bottom:1px solid var(--border);">' + escapeHtml(v.knownRansomware || 'Unknown') + '</td></tr>' +
    '</table>' +
    '<div style="margin-top:16px;">' +
      '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Description</div>' +
      '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.8;background:var(--well);padding:14px;border-radius:var(--radius);border:1px solid var(--border);">' +
        this._md(v.shortDescription || v.description || 'No description available') +
      '</div>' +
    '</div>';

    if (v.requiredAction) {
      body += '<div style="margin-top:16px;">' +
        '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Required Action</div>' +
        '<div style="color:var(--orange);font-size:var(--font-size-sm);line-height:1.8;background:var(--well);padding:14px;border-radius:var(--radius);border:1px solid rgba(255,107,43,0.2);">' +
          this._md(v.requiredAction) +
        '</div>' +
      '</div>';
    }

    if (v.notes) {
      body += '<div style="margin-top:16px;">' +
        '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Notes</div>' +
        '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.8;">' +
          this._md(v.notes) +
        '</div>' +
      '</div>';
    }

    Modal.open({ title: v.cveID + ' — ' + escapeHtml(v.vendor || v.vendorProject || '') + ' ' + escapeHtml(v.product || ''), body: body, size: 'lg' });
  },

  _showCVEDetail: function(cve) {
    var sevColor = (cve.severity === 'CRITICAL' || cve.severity === 'HIGH') ? 'var(--orange)' : 'var(--text-secondary)';
    var body = '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;">' +
      '<span class="tag tag-cyan" style="font-weight:600;">' + escapeHtml(cve.id || '') + '</span>' +
      '<span class="tag" style="color:' + sevColor + ';border-color:' + sevColor + ';font-weight:600;">' + escapeHtml(cve.severity || 'N/A') + '</span>' +
      (cve.score ? '<span class="tag" style="color:var(--text-primary);font-weight:600;">CVSS ' + escapeHtml(String(cve.score)) + '</span>' : '') +
      (cve.keyword ? '<span class="tag" style="font-size:10px;">Matched: ' + escapeHtml(cve.keyword) + '</span>' : '') +
    '</div>' +
    '<table style="width:100%;border-collapse:collapse;font-size:var(--font-size-sm);">' +
      '<tr><td style="padding:8px 12px;color:var(--text-tertiary);white-space:nowrap;border-bottom:1px solid var(--border);width:140px;">CVE ID</td>' +
        '<td style="padding:8px 12px;color:var(--cyan);font-weight:600;border-bottom:1px solid var(--border);">' + escapeHtml(cve.id || '') + '</td></tr>' +
      '<tr><td style="padding:8px 12px;color:var(--text-tertiary);white-space:nowrap;border-bottom:1px solid var(--border);">Severity</td>' +
        '<td style="padding:8px 12px;color:' + sevColor + ';font-weight:600;border-bottom:1px solid var(--border);">' + escapeHtml(cve.severity || 'N/A') + '</td></tr>' +
      '<tr><td style="padding:8px 12px;color:var(--text-tertiary);white-space:nowrap;border-bottom:1px solid var(--border);">CVSS Score</td>' +
        '<td style="padding:8px 12px;color:var(--text-primary);font-weight:600;border-bottom:1px solid var(--border);">' + escapeHtml(cve.score ? String(cve.score) : 'N/A') + '</td></tr>' +
      (cve.vector ? '<tr><td style="padding:8px 12px;color:var(--text-tertiary);white-space:nowrap;border-bottom:1px solid var(--border);">Attack Vector</td>' +
        '<td style="padding:8px 12px;color:var(--text-secondary);border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:11px;">' + escapeHtml(cve.vector) + '</td></tr>' : '') +
      (cve.published ? '<tr><td style="padding:8px 12px;color:var(--text-tertiary);white-space:nowrap;border-bottom:1px solid var(--border);">Published</td>' +
        '<td style="padding:8px 12px;color:var(--text-secondary);border-bottom:1px solid var(--border);">' + escapeHtml(cve.published) + '</td></tr>' : '') +
      (cve.modified ? '<tr><td style="padding:8px 12px;color:var(--text-tertiary);white-space:nowrap;border-bottom:1px solid var(--border);">Modified</td>' +
        '<td style="padding:8px 12px;color:var(--text-secondary);border-bottom:1px solid var(--border);">' + escapeHtml(cve.modified) + '</td></tr>' : '') +
      (cve.keyword ? '<tr><td style="padding:8px 12px;color:var(--text-tertiary);white-space:nowrap;border-bottom:1px solid var(--border);">Watchlist Match</td>' +
        '<td style="padding:8px 12px;color:var(--cyan);border-bottom:1px solid var(--border);">' + escapeHtml(cve.keyword) + '</td></tr>' : '') +
    '</table>' +
    '<div style="margin-top:16px;">' +
      '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Description</div>' +
      '<div style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.8;background:var(--well);padding:14px;border-radius:var(--radius);border:1px solid var(--border);">' +
        this._md(cve.description || 'No description available') +
      '</div>' +
    '</div>';

    if (cve.references && cve.references.length) {
      body += '<div style="margin-top:16px;">' +
        '<div style="color:var(--text-tertiary);font-size:var(--font-size-xs);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">References</div>' +
        '<div style="display:flex;flex-direction:column;gap:4px;">';
      cve.references.forEach(function(ref) {
        var url = typeof ref === 'string' ? ref : (ref.url || ref);
        body += '<a href="' + escapeHtml(url) + '" target="_blank" rel="noopener" style="color:var(--cyan);font-size:var(--font-size-xs);word-break:break-all;">' + escapeHtml(url) + ' &#8599;</a>';
      });
      body += '</div></div>';
    }

    Modal.open({ title: cve.id + ' — ' + escapeHtml(cve.severity || 'N/A') + (cve.score ? ' (' + cve.score + ')' : ''), body: body, size: 'lg' });
  }
};
