/**
 * Vigil — Notes View
 * Notes with tags, pinning, archiving, charts, AI generation, full CRUD
 */
(function () {
  'use strict';

  var notes = [];
  var archived = [];
  var activeTab = 'all';
  var searchQuery = '';

  var TAG_COLORS = ['#ff6b2b', '#a78bfa', '#f59e0b', '#ef4444', '#3b82f6', '#10b981', '#ec4899', '#8b5cf6'];
  var NOTE_COLORS = {
    default: 'var(--surface)', cyan: 'rgba(255,107,43,0.06)', purple: 'rgba(167,139,250,0.06)',
    orange: 'rgba(239,68,68,0.06)', blue: 'rgba(59,130,246,0.06)', amber: 'rgba(245,158,11,0.06)'
  };

  function esc(s) { return typeof escapeHtml === 'function' ? escapeHtml(String(s || '')) : String(s || '').replace(/[&<>"']/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]; }); }
  function tagColor(tag) { var h = 0; for (var i = 0; i < tag.length; i++) h = ((h << 5) - h) + tag.charCodeAt(i); return TAG_COLORS[Math.abs(h) % TAG_COLORS.length]; }

  Views.notes = {
    init: function () {
      var c = document.getElementById('view-notes');
      if (!c) return;
      c.innerHTML =
        '<div class="section-header">' +
          '<div class="section-title">Notes</div>' +
          '<div style="display:flex;gap:8px;">' +
            '<button class="btn btn-ghost btn-sm" onclick="Views.notes.show()">Refresh</button>' +
            '<button class="btn btn-primary btn-sm" onclick="Views.notes.openEditor()">+ New Note</button>' +
          '</div>' +
        '</div>' +

        /* Stats */
        '<div class="stat-grid" style="margin-bottom:20px;">' +
          '<div class="stat-card"><div class="stat-card-label">Notes</div><div class="stat-card-value" id="notes-stat-total" style="color:var(--cyan);">0</div></div>' +
          '<div class="stat-card"><div class="stat-card-label">Pinned</div><div class="stat-card-value" id="notes-stat-pinned">0</div></div>' +
          '<div class="stat-card"><div class="stat-card-label">Tags</div><div class="stat-card-value" id="notes-stat-tags">0</div></div>' +
          '<div class="stat-card"><div class="stat-card-label">Archived</div><div class="stat-card-value" id="notes-stat-archived" style="color:var(--text-tertiary);">0</div></div>' +
        '</div>' +

        /* Charts row */
        '<div class="grid-2" style="margin-bottom:20px;">' +
          '<div class="glass-card">' +
            '<div class="glass-card-title" style="margin-bottom:12px;">Notes by Tag</div>' +
            '<div style="height:200px;"><canvas id="notes-chart-tags"></canvas></div>' +
          '</div>' +
          '<div class="glass-card">' +
            '<div class="glass-card-title" style="margin-bottom:12px;">AI Knowledge Summary</div>' +
            '<div style="display:flex;justify-content:flex-end;margin-bottom:8px;"><button class="btn btn-ghost btn-sm" onclick="Views.notes.loadSummary()">Refresh</button></div>' +
            '<div id="notes-ai-text" style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;min-height:100px;">' +
              '<div class="loading-state"><div class="spinner spinner-sm"></div></div>' +
            '</div>' +
          '</div>' +
        '</div>' +

        /* Tabs */
        '<div style="display:flex;gap:4px;margin-bottom:12px;border-bottom:1px solid var(--border);padding-bottom:0;">' +
          '<button class="btn btn-ghost btn-sm notes-vtab active" data-tab="all" onclick="Views.notes.switchTab(\'all\')" style="border-radius:8px 8px 0 0;">All Notes</button>' +
          '<button class="btn btn-ghost btn-sm notes-vtab" data-tab="pinned" onclick="Views.notes.switchTab(\'pinned\')" style="border-radius:8px 8px 0 0;">Pinned</button>' +
          '<button class="btn btn-ghost btn-sm notes-vtab" data-tab="tags" onclick="Views.notes.switchTab(\'tags\')" style="border-radius:8px 8px 0 0;">By Tags</button>' +
          '<button class="btn btn-ghost btn-sm notes-vtab" data-tab="archived" onclick="Views.notes.switchTab(\'archived\')" style="border-radius:8px 8px 0 0;">Archived</button>' +
          '<button class="btn btn-ghost btn-sm notes-vtab" data-tab="ai" onclick="Views.notes.switchTab(\'ai\')" style="border-radius:8px 8px 0 0;">AI Generate</button>' +
        '</div>' +

        /* Search bar */
        '<div style="margin-bottom:16px;">' +
          '<input class="form-input" id="notes-search" placeholder="Search notes..." oninput="Views.notes.search(this.value)" style="max-width:400px;"/>' +
        '</div>' +

        /* Content */
        '<div id="notes-content"></div>';
    },

    show: function () {
      this.loadNotes();
      this.loadSummary();
    },

    hide: function () {},
    update: function () {},

    loadNotes: function () {
      var q = searchQuery ? '?search=' + encodeURIComponent(searchQuery) : '';
      fetch('/api/notes' + q).then(function (r) { return r.json(); }).then(function (d) {
        notes = d.notes || [];
        archived = d.archived || [];
        Views.notes.renderStats();
        Views.notes.renderCharts();
        Views.notes.renderContent();
      }).catch(function () {});
    },

    loadSummary: function () {
      var el = document.getElementById('notes-ai-text');
      if (!el) return;
      el.innerHTML = '<div class="loading-state"><div class="spinner spinner-sm"></div></div>';
      fetch('/api/notes/ai-summary').then(function (r) { return r.json(); }).then(function (d) {
        el.textContent = d.summary || 'No summary available.';
      }).catch(function () { el.textContent = 'AI summary unavailable — configure an AI provider in Settings.'; });
    },

    renderStats: function () {
      var pinned = notes.filter(function (n) { return n.pinned; });
      var allTags = {};
      notes.forEach(function (n) { (n.tags || []).forEach(function (t) { allTags[t] = (allTags[t] || 0) + 1; }); });

      var els = {
        total: document.getElementById('notes-stat-total'),
        pinned: document.getElementById('notes-stat-pinned'),
        tags: document.getElementById('notes-stat-tags'),
        archived: document.getElementById('notes-stat-archived')
      };
      if (els.total) animateValue(els.total, 0, notes.length, 400);
      if (els.pinned) animateValue(els.pinned, 0, pinned.length, 400);
      if (els.tags) animateValue(els.tags, 0, Object.keys(allTags).length, 400);
      if (els.archived) animateValue(els.archived, 0, archived.length, 400);
    },

    renderCharts: function () {
      var allTags = {};
      notes.forEach(function (n) { (n.tags || []).forEach(function (t) { allTags[t] = (allTags[t] || 0) + 1; }); });
      var tagKeys = Object.keys(allTags).sort(function (a, b) { return allTags[b] - allTags[a]; }).slice(0, 8);
      var tagCounts = tagKeys.map(function (k) { return allTags[k]; });

      if (tagKeys.length) {
        createBarChart('notes-chart-tags', tagKeys, tagCounts);
      } else {
        var tc = document.getElementById('notes-chart-tags');
        if (tc) tc.parentElement.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:200px;color:var(--text-tertiary);">No tags yet</div>';
      }
    },

    renderContent: function () {
      var el = document.getElementById('notes-content');
      if (!el) return;

      var list = notes;
      if (activeTab === 'pinned') list = notes.filter(function (n) { return n.pinned; });
      if (activeTab === 'archived') list = archived;

      if (activeTab === 'tags') { this.renderTagsView(el); return; }
      if (activeTab === 'ai') { this.renderAIView(el); return; }

      if (!list.length) {
        el.innerHTML = '<div class="glass-card" style="text-align:center;padding:40px;color:var(--text-tertiary);">' +
          (activeTab === 'pinned' ? 'No pinned notes' : activeTab === 'archived' ? 'No archived notes' : 'No notes yet. Create your first note!') + '</div>';
        return;
      }

      el.innerHTML = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px;">' + list.map(function (n) {
        var bg = NOTE_COLORS[n.color] || NOTE_COLORS.default;
        return '<div class="glass-card" style="background:' + bg + ';padding:16px;">' +
          '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;">' +
            '<div style="font-weight:600;color:var(--text-primary);font-size:14px;">' + esc(n.title) + '</div>' +
            '<div style="display:flex;gap:2px;flex-shrink:0;">' +
              '<button class="btn btn-ghost btn-sm" onclick="Views.notes.togglePin(\'' + n.id + '\')" title="' + (n.pinned ? 'Unpin' : 'Pin') + '" style="padding:2px 6px;' + (n.pinned ? 'color:var(--cyan);' : '') + '">&#128204;</button>' +
              '<button class="btn btn-ghost btn-sm" onclick="Views.notes.openEditor(\'' + n.id + '\')" title="Edit" style="padding:2px 6px;">&#9998;</button>' +
              (activeTab !== 'archived' ? '<button class="btn btn-ghost btn-sm" onclick="Views.notes.archiveNote(\'' + n.id + '\')" title="Archive" style="padding:2px 6px;">&#128230;</button>' : '<button class="btn btn-ghost btn-sm" onclick="Views.notes.unarchiveNote(\'' + n.id + '\')" title="Unarchive" style="padding:2px 6px;">&#128194;</button>') +
              '<button class="btn btn-ghost btn-sm" onclick="Views.notes.deleteNote(\'' + n.id + '\')" title="Delete" style="padding:2px 6px;color:var(--orange);">&times;</button>' +
            '</div>' +
          '</div>' +
          '<div style="font-size:12px;color:var(--text-secondary);line-height:1.6;margin-bottom:8px;max-height:120px;overflow:hidden;">' + esc((n.content || '').substring(0, 300)) + (n.content && n.content.length > 300 ? '...' : '') + '</div>' +
          (n.tags && n.tags.length ? '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px;">' + n.tags.map(function (t) { return '<span style="font-size:11px;color:' + tagColor(t) + ';">#' + esc(t) + '</span>'; }).join('') + '</div>' : '') +
          '<div style="font-size:10px;color:var(--text-tertiary);">' + new Date(n.updated || n.created).toLocaleDateString() + '</div>' +
        '</div>';
      }).join('') + '</div>';
    },

    renderTagsView: function (el) {
      var allTags = {};
      notes.forEach(function (n) { (n.tags || []).forEach(function (t) { if (!allTags[t]) allTags[t] = []; allTags[t].push(n); }); });
      var tagKeys = Object.keys(allTags).sort(function (a, b) { return allTags[b].length - allTags[a].length; });

      if (!tagKeys.length) { el.innerHTML = '<div class="glass-card" style="text-align:center;padding:40px;color:var(--text-tertiary);">No tags yet. Add tags to your notes!</div>'; return; }

      el.innerHTML = tagKeys.map(function (tag) {
        return '<div class="glass-card" style="margin-bottom:12px;padding:14px;">' +
          '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">' +
            '<span style="font-size:14px;font-weight:600;color:' + tagColor(tag) + ';">#' + esc(tag) + '</span>' +
            '<span style="font-size:12px;color:var(--text-tertiary);">' + allTags[tag].length + ' note' + (allTags[tag].length > 1 ? 's' : '') + '</span>' +
          '</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px;">' + allTags[tag].map(function (n) {
            return '<span class="btn btn-ghost btn-sm" style="font-size:11px;padding:4px 8px;" onclick="Views.notes.openEditor(\'' + n.id + '\')">' + esc(n.title) + '</span>';
          }).join('') + '</div>' +
        '</div>';
      }).join('');
    },

    renderAIView: function (el) {
      el.innerHTML =
        '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:8px;">AI Note Generator</div>' +
          '<p style="color:var(--text-secondary);font-size:var(--font-size-sm);margin-bottom:12px;">Describe what you want to document and Vigil will generate a structured note.</p>' +
          '<div style="display:flex;gap:8px;margin-bottom:16px;">' +
            '<input id="notes-ai-prompt" class="form-input" placeholder="e.g. Document our API authentication flow and security measures..." style="flex:1"/>' +
            '<button class="btn btn-primary btn-sm" onclick="Views.notes.aiGenerate()">Generate</button>' +
          '</div>' +
          '<div id="notes-ai-result"></div>' +
        '</div>';
    },

    search: function (q) {
      searchQuery = q;
      this.loadNotes();
    },

    switchTab: function (tab) {
      activeTab = tab;
      document.querySelectorAll('.notes-vtab').forEach(function (b) {
        b.style.background = b.dataset.tab === tab ? 'var(--surface)' : '';
        b.style.color = b.dataset.tab === tab ? 'var(--cyan)' : '';
        b.style.borderBottom = b.dataset.tab === tab ? '2px solid var(--cyan)' : '';
      });
      this.renderContent();
    },

    openEditor: function (id) {
      var existing = null;
      if (id) {
        existing = notes.find(function (x) { return x.id === id; }) || archived.find(function (x) { return x.id === id; });
      }

      var body = '<div style="display:flex;flex-direction:column;gap:12px;">' +
        '<input id="note-edit-title" class="form-input" placeholder="Note title" value="' + (existing ? esc(existing.title) : '') + '"/>' +
        '<textarea id="note-edit-content" class="form-textarea" rows="10" placeholder="Write your note... (Markdown supported)" style="min-height:200px;font-family:\'JetBrains Mono\',monospace;font-size:13px;">' + (existing ? esc(existing.content || '') : '') + '</textarea>' +
        '<div style="display:flex;gap:8px;">' +
          '<input id="note-edit-tags" class="form-input" placeholder="Tags (comma-separated)" value="' + (existing ? esc((existing.tags || []).join(', ')) : '') + '" style="flex:1;"/>' +
          '<select id="note-edit-color" class="form-select" style="width:120px;">' +
            '<option value="default"' + (existing && existing.color === 'default' ? ' selected' : '') + '>Default</option>' +
            '<option value="cyan"' + (existing && existing.color === 'cyan' ? ' selected' : '') + '>Accent</option>' +
            '<option value="purple"' + (existing && existing.color === 'purple' ? ' selected' : '') + '>Purple</option>' +
            '<option value="orange"' + (existing && existing.color === 'orange' ? ' selected' : '') + '>Orange</option>' +
            '<option value="blue"' + (existing && existing.color === 'blue' ? ' selected' : '') + '>Blue</option>' +
            '<option value="amber"' + (existing && existing.color === 'amber' ? ' selected' : '') + '>Amber</option>' +
          '</select>' +
        '</div>' +
      '</div>';

      Modal.open({
        title: existing ? 'Edit Note' : 'New Note',
        body: body,
        size: 'lg',
        footer: '<button class="btn btn-ghost btn-sm" onclick="Modal.close()">Cancel</button><button class="btn btn-primary btn-sm" id="note-save-btn">' + (existing ? 'Save' : 'Create') + '</button>'
      });

      setTimeout(function () {
        var btn = document.getElementById('note-save-btn');
        if (btn) btn.onclick = function () {
          var title = document.getElementById('note-edit-title').value;
          if (!title) return Toast.error('Title required');

          var payload = {
            title: title,
            content: document.getElementById('note-edit-content').value,
            tags: document.getElementById('note-edit-tags').value.split(',').map(function (t) { return t.trim(); }).filter(Boolean),
            color: document.getElementById('note-edit-color').value
          };

          var url = id ? '/api/notes/' + id : '/api/notes';
          var method = id ? 'PUT' : 'POST';

          fetch(url, { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
            .then(function () {
              Modal.close();
              Views.notes.loadNotes();
              Toast.success(id ? 'Note updated' : 'Note created');
            });
        };
      }, 50);
    },

    togglePin: function (id) {
      var n = notes.find(function (x) { return x.id === id; });
      if (!n) return;
      fetch('/api/notes/' + id, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pinned: !n.pinned }) })
        .then(function () { Views.notes.loadNotes(); Toast.info(n.pinned ? 'Unpinned' : 'Pinned'); });
    },

    archiveNote: function (id) {
      fetch('/api/notes/' + id, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ archived: true }) })
        .then(function () { Views.notes.loadNotes(); Toast.info('Note archived'); });
    },

    unarchiveNote: function (id) {
      fetch('/api/notes/' + id, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ archived: false }) })
        .then(function () { Views.notes.loadNotes(); Toast.info('Note restored'); });
    },

    deleteNote: function (id) {
      Modal.confirm({ title: 'Delete Note', message: 'Delete this note permanently?', dangerous: true, confirmText: 'Delete' }).then(function (yes) {
        if (!yes) return;
        fetch('/api/notes/' + id, { method: 'DELETE', headers: { 'Content-Type': 'application/json' } }).then(function () {
          Views.notes.loadNotes();
          Toast.success('Note deleted');
        });
      });
    },

    aiGenerate: function () {
      var input = document.getElementById('notes-ai-prompt');
      var output = document.getElementById('notes-ai-result');
      if (!input || !input.value || !output) return;
      output.innerHTML = '<div class="loading-state"><div class="spinner spinner-sm"></div><div>Generating...</div></div>';
      fetch('/api/notes/ai-generate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ prompt: input.value }) })
        .then(function (r) { return r.json(); }).then(function (d) {
          if (d.note) {
            output.innerHTML = '<div class="glass-card" style="margin-top:12px;">' +
              '<div style="font-weight:600;font-size:14px;margin-bottom:8px;">' + esc(d.note.title) + '</div>' +
              '<div style="font-size:12px;color:var(--text-secondary);line-height:1.7;margin-bottom:8px;white-space:pre-wrap;">' + esc(d.note.content) + '</div>' +
              (d.note.tags ? '<div style="display:flex;gap:6px;margin-bottom:12px;">' + d.note.tags.map(function (t) { return '<span style="font-size:11px;color:' + tagColor(t) + ';">#' + esc(t) + '</span>'; }).join('') + '</div>' : '') +
              '<button class="btn btn-primary btn-sm" onclick="Views.notes.saveAINote()">Save as Note</button>' +
            '</div>';
            output._aiNote = d.note;
          } else output.innerHTML = '<div style="color:var(--text-tertiary);text-align:center;padding:20px;">Could not generate note.</div>';
        }).catch(function () { output.innerHTML = '<div style="color:var(--orange);text-align:center;padding:20px;">AI generation failed.</div>'; });
    },

    saveAINote: function () {
      var output = document.getElementById('notes-ai-result');
      if (!output || !output._aiNote) return;
      var n = output._aiNote;
      fetch('/api/notes', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title: n.title, content: n.content, tags: n.tags || [] }) })
        .then(function () { Views.notes.loadNotes(); Toast.success('AI note saved'); output.innerHTML = '<div style="color:var(--text-tertiary);text-align:center;padding:20px;">Note saved! Generate another?</div>'; });
    }
  };
})();
