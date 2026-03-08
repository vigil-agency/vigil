/**
 * Vigil — Calendar View
 * Full calendar with month/week/agenda, charts, AI briefing, CRUD
 */
(function () {
  'use strict';

  var currentMonth = new Date().getMonth();
  var currentYear = new Date().getFullYear();
  var events = [];
  var selectedDate = null;
  var activeTab = 'month';

  var CAT_COLORS = {
    meeting: '#a78bfa', deploy: '#ff6b2b', deadline: '#ef4444',
    reminder: '#f59e0b', general: '#8b8b92', maintenance: '#3b82f6'
  };

  function esc(s) { return typeof escapeHtml === 'function' ? escapeHtml(String(s || '')) : String(s || '').replace(/[&<>"']/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]; }); }

  Views.calendar = {
    init: function () {
      var c = document.getElementById('view-calendar');
      if (!c) return;
      c.innerHTML =
        '<div class="section-header">' +
          '<div class="section-title">Calendar</div>' +
          '<div style="display:flex;gap:8px;">' +
            '<button class="btn btn-ghost btn-sm" onclick="Views.calendar.show()">Refresh</button>' +
            '<button class="btn btn-primary btn-sm" onclick="Views.calendar.openAddModal()">+ Add Event</button>' +
          '</div>' +
        '</div>' +

        /* Stats */
        '<div class="stat-grid" style="margin-bottom:20px;">' +
          '<div class="stat-card"><div class="stat-card-label">Today</div><div class="stat-card-value" id="cal-stat-today" style="color:var(--cyan);">0</div></div>' +
          '<div class="stat-card"><div class="stat-card-label">This Week</div><div class="stat-card-value" id="cal-stat-week">0</div></div>' +
          '<div class="stat-card"><div class="stat-card-label">Total Events</div><div class="stat-card-value" id="cal-stat-total">0</div></div>' +
          '<div class="stat-card"><div class="stat-card-label">High Priority</div><div class="stat-card-value" id="cal-stat-high" style="color:var(--orange);">0</div></div>' +
        '</div>' +

        /* Charts row */
        '<div class="grid-2" style="margin-bottom:20px;">' +
          '<div class="glass-card">' +
            '<div class="glass-card-title" style="margin-bottom:12px;">Events by Category</div>' +
            '<div style="height:200px;"><canvas id="cal-chart-category"></canvas></div>' +
          '</div>' +
          '<div class="glass-card">' +
            '<div class="glass-card-title" style="margin-bottom:12px;">Priority Breakdown</div>' +
            '<div style="height:200px;"><canvas id="cal-chart-priority"></canvas></div>' +
          '</div>' +
        '</div>' +

        /* AI Briefing */
        '<div class="glass-card" style="margin-bottom:20px;">' +
          '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">' +
            '<div class="glass-card-title">AI Schedule Briefing</div>' +
            '<button class="btn btn-ghost btn-sm" onclick="Views.calendar.loadBriefing()">Refresh</button>' +
          '</div>' +
          '<div id="cal-ai-text" style="color:var(--text-secondary);font-size:var(--font-size-sm);line-height:1.7;min-height:40px;">' +
            '<div class="loading-state"><div class="spinner spinner-sm"></div></div>' +
          '</div>' +
        '</div>' +

        /* Tabs */
        '<div style="display:flex;gap:4px;margin-bottom:16px;border-bottom:1px solid var(--border);padding-bottom:0;">' +
          '<button class="btn btn-ghost btn-sm cal-vtab active" data-tab="month" onclick="Views.calendar.switchTab(\'month\')" style="border-radius:8px 8px 0 0;">Month</button>' +
          '<button class="btn btn-ghost btn-sm cal-vtab" data-tab="week" onclick="Views.calendar.switchTab(\'week\')" style="border-radius:8px 8px 0 0;">Week</button>' +
          '<button class="btn btn-ghost btn-sm cal-vtab" data-tab="agenda" onclick="Views.calendar.switchTab(\'agenda\')" style="border-radius:8px 8px 0 0;">Agenda</button>' +
          '<button class="btn btn-ghost btn-sm cal-vtab" data-tab="ai" onclick="Views.calendar.switchTab(\'ai\')" style="border-radius:8px 8px 0 0;">AI Planner</button>' +
        '</div>' +

        /* Month tab */
        '<div id="cal-tab-month">' +
          '<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">' +
            '<button class="btn btn-ghost btn-sm" onclick="Views.calendar.prevMonth()">&larr;</button>' +
            '<span id="cal-month-title" style="font-size:16px;font-weight:600;min-width:180px;text-align:center;"></span>' +
            '<button class="btn btn-ghost btn-sm" onclick="Views.calendar.nextMonth()">&rarr;</button>' +
            '<button class="btn btn-ghost btn-sm" onclick="Views.calendar.goToday()">Today</button>' +
          '</div>' +
          '<div id="cal-grid"></div>' +
        '</div>' +

        /* Week tab */
        '<div id="cal-tab-week" style="display:none"></div>' +

        /* Agenda tab */
        '<div id="cal-tab-agenda" style="display:none"></div>' +

        /* AI planner tab */
        '<div id="cal-tab-ai" style="display:none"></div>' +

        /* Day detail panel */
        '<div id="cal-day-detail" style="display:none;"></div>';
    },

    show: function () {
      this.loadEvents();
      this.loadBriefing();
    },

    hide: function () {},
    update: function () {},

    loadEvents: function () {
      fetch('/api/calendar/events').then(function (r) { return r.json(); }).then(function (d) {
        events = d.events || [];
        Views.calendar.renderStats();
        Views.calendar.renderCharts();
        Views.calendar.renderMonth();
        if (activeTab === 'week') Views.calendar.renderWeek();
        if (activeTab === 'agenda') Views.calendar.renderAgenda();
      }).catch(function () {});
    },

    loadBriefing: function () {
      var el = document.getElementById('cal-ai-text');
      if (!el) return;
      el.innerHTML = '<div class="loading-state"><div class="spinner spinner-sm"></div></div>';
      fetch('/api/calendar/ai-briefing').then(function (r) { return r.json(); }).then(function (d) {
        el.textContent = d.briefing || 'No briefing available.';
      }).catch(function () { el.textContent = 'AI briefing unavailable — configure an AI provider in Settings.'; });
    },

    renderStats: function () {
      var today = new Date().toISOString().slice(0, 10);
      var todayEv = events.filter(function (e) { return e.date === today; });
      var d = new Date(); d.setDate(d.getDate() + 7);
      var weekEnd = d.toISOString().slice(0, 10);
      var weekEv = events.filter(function (e) { return e.date >= today && e.date <= weekEnd; });
      var high = events.filter(function (e) { return e.priority === 'high' || e.priority === 'critical'; });

      var els = {
        today: document.getElementById('cal-stat-today'),
        week: document.getElementById('cal-stat-week'),
        total: document.getElementById('cal-stat-total'),
        high: document.getElementById('cal-stat-high')
      };
      if (els.today) animateValue(els.today, 0, todayEv.length, 400);
      if (els.week) animateValue(els.week, 0, weekEv.length, 400);
      if (els.total) animateValue(els.total, 0, events.length, 400);
      if (els.high) animateValue(els.high, 0, high.length, 400);
    },

    renderCharts: function () {
      // Category chart
      var cats = {};
      events.forEach(function (e) { cats[e.category || 'general'] = (cats[e.category || 'general'] || 0) + 1; });
      var catLabels = Object.keys(cats);
      var catData = catLabels.map(function (k) { return cats[k]; });
      if (catLabels.length) {
        createDoughnutChart('cal-chart-category', catLabels, catData, {
          plugins: {
            legend: { position: 'right', labels: { padding: 12 } }
          }
        });
      } else {
        var cc = document.getElementById('cal-chart-category');
        if (cc) cc.parentElement.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:200px;color:var(--text-tertiary);">No events yet</div>';
      }

      // Priority chart
      var pris = { low: 0, normal: 0, high: 0, critical: 0 };
      events.forEach(function (e) { if (pris[e.priority] !== undefined) pris[e.priority]++; else pris.normal++; });
      var priLabels = Object.keys(pris).filter(function (k) { return pris[k] > 0; });
      var priData = priLabels.map(function (k) { return pris[k]; });
      if (priLabels.length) {
        createDoughnutChart('cal-chart-priority', priLabels, priData, {
          plugins: {
            legend: { position: 'right', labels: { padding: 12 } }
          }
        });
      } else {
        var pc = document.getElementById('cal-chart-priority');
        if (pc) pc.parentElement.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:200px;color:var(--text-tertiary);">No events yet</div>';
      }
    },

    renderMonth: function () {
      var grid = document.getElementById('cal-grid');
      var title = document.getElementById('cal-month-title');
      if (!grid || !title) return;

      var months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
      title.textContent = months[currentMonth] + ' ' + currentYear;

      var firstDay = new Date(currentYear, currentMonth, 1).getDay();
      var daysInMonth = new Date(currentYear, currentMonth + 1, 0).getDate();
      var today = new Date().toISOString().slice(0, 10);

      var cellStyle = 'min-height:80px;padding:6px;cursor:pointer;border:1px solid var(--border);border-radius:6px;transition:background 0.15s;';
      var headerStyle = 'text-align:center;padding:8px 4px;font-size:11px;text-transform:uppercase;color:var(--text-tertiary);font-weight:600;';

      var html = '<div style="display:grid;grid-template-columns:repeat(7,1fr);gap:4px;">';
      ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].forEach(function (d) {
        html += '<div style="' + headerStyle + '">' + d + '</div>';
      });

      for (var i = 0; i < firstDay; i++) html += '<div style="' + cellStyle + 'opacity:0.2;"></div>';

      for (var d = 1; d <= daysInMonth; d++) {
        var dateStr = currentYear + '-' + String(currentMonth + 1).padStart(2, '0') + '-' + String(d).padStart(2, '0');
        var dayEvents = events.filter(function (e) { return e.date === dateStr; });
        var isToday = dateStr === today;
        var isSel = dateStr === selectedDate;

        var bg = 'background:' + (isSel ? 'rgba(255,107,43,0.15)' : isToday ? 'rgba(255,107,43,0.06)' : 'var(--surface)') + ';';
        var border = isToday ? 'border-color:var(--cyan);' : isSel ? 'border-color:var(--cyan);' : '';

        html += '<div style="' + cellStyle + bg + border + '" onclick="Views.calendar.selectDate(\'' + dateStr + '\')" onmouseover="this.style.background=\'rgba(255,255,255,0.04)\'" onmouseout="this.style.background=\'' + (isSel ? 'rgba(255,107,43,0.15)' : isToday ? 'rgba(255,107,43,0.06)' : 'var(--surface)') + '\'">';
        html += '<div style="font-size:12px;font-weight:' + (isToday ? '700' : '500') + ';color:' + (isToday ? 'var(--cyan)' : 'var(--text-primary)') + ';">' + d + '</div>';

        if (dayEvents.length > 0) {
          dayEvents.slice(0, 3).forEach(function (ev) {
            html += '<div style="font-size:10px;padding:1px 4px;margin-top:2px;border-radius:3px;background:' + (CAT_COLORS[ev.category] || '#8b8b92') + '22;color:' + (CAT_COLORS[ev.category] || '#8b8b92') + ';overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(ev.title) + '</div>';
          });
          if (dayEvents.length > 3) html += '<div style="font-size:9px;color:var(--text-tertiary);margin-top:2px;">+' + (dayEvents.length - 3) + ' more</div>';
        }
        html += '</div>';
      }
      html += '</div>';
      grid.innerHTML = html;
    },

    prevMonth: function () { currentMonth--; if (currentMonth < 0) { currentMonth = 11; currentYear--; } this.renderMonth(); },
    nextMonth: function () { currentMonth++; if (currentMonth > 11) { currentMonth = 0; currentYear++; } this.renderMonth(); },
    goToday: function () { var n = new Date(); currentMonth = n.getMonth(); currentYear = n.getFullYear(); selectedDate = n.toISOString().slice(0, 10); this.renderMonth(); this.showDayDetail(selectedDate); },

    selectDate: function (dateStr) {
      selectedDate = dateStr;
      this.renderMonth();
      this.showDayDetail(dateStr);
    },

    showDayDetail: function (dateStr) {
      var panel = document.getElementById('cal-day-detail');
      if (!panel) return;

      var dayEvents = events.filter(function (e) { return e.date === dateStr; });
      var dateLabel = new Date(dateStr + 'T12:00:00').toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' });

      var html = '<div class="glass-card" style="margin-top:16px;">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">' +
          '<div class="glass-card-title">' + esc(dateLabel) + '</div>' +
          '<div style="display:flex;gap:8px;">' +
            '<button class="btn btn-primary btn-sm" onclick="Views.calendar.openAddModal(\'' + dateStr + '\')">+ Add Event</button>' +
            '<button class="btn btn-ghost btn-sm" onclick="Views.calendar.closeDetail()">&times;</button>' +
          '</div>' +
        '</div>';

      if (!dayEvents.length) {
        html += '<div style="color:var(--text-tertiary);text-align:center;padding:20px;">No events scheduled</div>';
      } else {
        dayEvents.forEach(function (ev) {
          var catColor = CAT_COLORS[ev.category] || '#8b8b92';
          html += '<div style="display:flex;gap:12px;align-items:flex-start;padding:10px;border-left:3px solid ' + catColor + ';background:var(--surface);border-radius:0 8px 8px 0;margin-bottom:8px;">' +
            '<div style="flex:1;">' +
              '<div style="font-weight:600;color:var(--text-primary);">' + (ev.priority === 'high' || ev.priority === 'critical' ? '<span style="color:var(--orange);">!</span> ' : '') + esc(ev.title) + '</div>' +
              (ev.time ? '<div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">' + ev.time + (ev.endTime ? ' - ' + ev.endTime : '') + '</div>' : '') +
              (ev.description ? '<div style="font-size:12px;color:var(--text-tertiary);margin-top:4px;">' + esc(ev.description) + '</div>' : '') +
              '<div style="font-size:11px;margin-top:4px;"><span style="color:' + catColor + ';">' + esc(ev.category) + '</span> <span style="color:var(--text-tertiary);margin-left:8px;">' + (ev.priority || 'normal') + '</span></div>' +
            '</div>' +
            '<div style="display:flex;gap:4px;">' +
              '<button class="btn btn-ghost btn-sm" onclick="Views.calendar.editEvent(\'' + ev.id + '\')" title="Edit" style="padding:4px 8px;">&#9998;</button>' +
              '<button class="btn btn-ghost btn-sm" onclick="Views.calendar.deleteEvent(\'' + ev.id + '\')" title="Delete" style="padding:4px 8px;color:var(--orange);">&times;</button>' +
            '</div>' +
          '</div>';
        });
      }
      html += '</div>';
      panel.innerHTML = html;
      panel.style.display = 'block';
    },

    closeDetail: function () {
      var panel = document.getElementById('cal-day-detail');
      if (panel) { panel.style.display = 'none'; panel.innerHTML = ''; }
      selectedDate = null;
      this.renderMonth();
    },

    openAddModal: function (date) {
      date = date || selectedDate || new Date().toISOString().slice(0, 10);
      var body = '<div style="display:flex;flex-direction:column;gap:12px;">' +
        '<input id="cal-add-title" class="form-input" placeholder="Event title" autofocus/>' +
        '<div style="display:flex;gap:8px;">' +
          '<input id="cal-add-date" class="form-input" type="date" value="' + date + '" style="flex:1;"/>' +
          '<input id="cal-add-time" class="form-input" type="time" style="flex:1;"/>' +
          '<input id="cal-add-endtime" class="form-input" type="time" style="flex:1;" placeholder="End"/>' +
        '</div>' +
        '<div style="display:flex;gap:8px;">' +
          '<select id="cal-add-cat" class="form-select" style="flex:1;"><option value="general">General</option><option value="meeting">Meeting</option><option value="deploy">Deploy</option><option value="deadline">Deadline</option><option value="reminder">Reminder</option><option value="maintenance">Maintenance</option></select>' +
          '<select id="cal-add-pri" class="form-select" style="flex:1;"><option value="normal">Normal</option><option value="low">Low</option><option value="high">High</option><option value="critical">Critical</option></select>' +
        '</div>' +
        '<textarea id="cal-add-desc" class="form-textarea" rows="3" placeholder="Description (optional)"></textarea>' +
        '<div style="display:flex;gap:8px;">' +
          '<input id="cal-ai-input" class="form-input" placeholder="Or describe in natural language..." style="flex:1;"/>' +
          '<button class="btn btn-ghost btn-sm" onclick="Views.calendar.aiParse()">AI Parse</button>' +
        '</div>' +
      '</div>';

      Modal.open({
        title: 'Add Event',
        body: body,
        footer: '<button class="btn btn-ghost btn-sm" onclick="Modal.close()">Cancel</button><button class="btn btn-primary btn-sm" id="cal-add-submit">Add Event</button>'
      });

      setTimeout(function () {
        var btn = document.getElementById('cal-add-submit');
        if (btn) btn.onclick = function () {
          var title = document.getElementById('cal-add-title').value;
          if (!title) return Toast.error('Title required');
          fetch('/api/calendar/events', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              title: title,
              date: document.getElementById('cal-add-date').value,
              time: document.getElementById('cal-add-time').value,
              endTime: document.getElementById('cal-add-endtime').value,
              category: document.getElementById('cal-add-cat').value,
              priority: document.getElementById('cal-add-pri').value,
              description: document.getElementById('cal-add-desc').value
            })
          }).then(function () { Modal.close(); Views.calendar.loadEvents(); Toast.success('Event created'); });
        };
      }, 50);
    },

    aiParse: function () {
      var input = document.getElementById('cal-ai-input');
      if (!input || !input.value) return;
      Toast.info('AI parsing...');
      fetch('/api/calendar/ai-parse', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: input.value }) })
        .then(function (r) { return r.json(); }).then(function (d) {
          if (d.events && d.events.length > 0) {
            var ev = d.events[0];
            if (ev.title) document.getElementById('cal-add-title').value = ev.title;
            if (ev.date) document.getElementById('cal-add-date').value = ev.date;
            if (ev.time) document.getElementById('cal-add-time').value = ev.time;
            if (ev.category) document.getElementById('cal-add-cat').value = ev.category;
            if (ev.priority) document.getElementById('cal-add-pri').value = ev.priority;
            if (ev.description) document.getElementById('cal-add-desc').value = ev.description;
            Toast.success('AI filled ' + d.events.length + ' event(s)');
          } else Toast.warning('Could not parse');
        }).catch(function () { Toast.error('AI parse failed'); });
    },

    editEvent: function (id) {
      var ev = events.find(function (e) { return e.id === id; });
      if (!ev) return;

      var body = '<div style="display:flex;flex-direction:column;gap:12px;">' +
        '<input id="cal-edit-title" class="form-input" value="' + esc(ev.title) + '"/>' +
        '<div style="display:flex;gap:8px;">' +
          '<input id="cal-edit-date" class="form-input" type="date" value="' + ev.date + '" style="flex:1;"/>' +
          '<input id="cal-edit-time" class="form-input" type="time" value="' + (ev.time || '') + '" style="flex:1;"/>' +
          '<input id="cal-edit-endtime" class="form-input" type="time" value="' + (ev.endTime || '') + '" style="flex:1;"/>' +
        '</div>' +
        '<div style="display:flex;gap:8px;">' +
          '<select id="cal-edit-cat" class="form-select" style="flex:1;">' +
            ['general', 'meeting', 'deploy', 'deadline', 'reminder', 'maintenance'].map(function (c) { return '<option' + (c === ev.category ? ' selected' : '') + '>' + c + '</option>'; }).join('') +
          '</select>' +
          '<select id="cal-edit-pri" class="form-select" style="flex:1;">' +
            ['low', 'normal', 'high', 'critical'].map(function (p) { return '<option' + (p === ev.priority ? ' selected' : '') + '>' + p + '</option>'; }).join('') +
          '</select>' +
        '</div>' +
        '<textarea id="cal-edit-desc" class="form-textarea" rows="3">' + esc(ev.description || '') + '</textarea>' +
      '</div>';

      Modal.open({
        title: 'Edit Event',
        body: body,
        footer: '<button class="btn btn-ghost btn-sm" onclick="Modal.close()">Cancel</button><button class="btn btn-primary btn-sm" id="cal-edit-submit">Save</button>'
      });

      setTimeout(function () {
        var btn = document.getElementById('cal-edit-submit');
        if (btn) btn.onclick = function () {
          fetch('/api/calendar/events/' + id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              title: document.getElementById('cal-edit-title').value,
              date: document.getElementById('cal-edit-date').value,
              time: document.getElementById('cal-edit-time').value,
              endTime: document.getElementById('cal-edit-endtime').value,
              category: document.getElementById('cal-edit-cat').value,
              priority: document.getElementById('cal-edit-pri').value,
              description: document.getElementById('cal-edit-desc').value
            })
          }).then(function () {
            Modal.close();
            Views.calendar.loadEvents();
            if (selectedDate) Views.calendar.showDayDetail(selectedDate);
            Toast.success('Event updated');
          });
        };
      }, 50);
    },

    deleteEvent: function (id) {
      Modal.confirm({ title: 'Delete Event', message: 'Delete this event permanently?', dangerous: true, confirmText: 'Delete' }).then(function (yes) {
        if (!yes) return;
        fetch('/api/calendar/events/' + id, { method: 'DELETE', headers: { 'Content-Type': 'application/json' } }).then(function () {
          Views.calendar.loadEvents();
          if (selectedDate) Views.calendar.showDayDetail(selectedDate);
          Toast.success('Event deleted');
        });
      });
    },

    switchTab: function (tab) {
      activeTab = tab;
      document.querySelectorAll('.cal-vtab').forEach(function (b) {
        b.style.background = b.dataset.tab === tab ? 'var(--surface)' : '';
        b.style.color = b.dataset.tab === tab ? 'var(--cyan)' : '';
        b.style.borderBottom = b.dataset.tab === tab ? '2px solid var(--cyan)' : '';
      });
      ['month', 'week', 'agenda', 'ai'].forEach(function (t) {
        var el = document.getElementById('cal-tab-' + t);
        if (el) el.style.display = t === tab ? 'block' : 'none';
      });
      if (tab === 'week') this.renderWeek();
      if (tab === 'agenda') this.renderAgenda();
      if (tab === 'ai') this.renderAIPlanner();
    },

    renderWeek: function () {
      var el = document.getElementById('cal-tab-week');
      if (!el) return;
      var now = new Date();
      var startOfWeek = new Date(now);
      startOfWeek.setDate(now.getDate() - now.getDay());

      var html = '<div style="display:grid;grid-template-columns:repeat(7,1fr);gap:8px;">';
      var days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
      for (var i = 0; i < 7; i++) {
        var d = new Date(startOfWeek);
        d.setDate(startOfWeek.getDate() + i);
        var dateStr = d.toISOString().slice(0, 10);
        var dayEvents = events.filter(function (e) { return e.date === dateStr; });
        var isToday = dateStr === now.toISOString().slice(0, 10);

        html += '<div class="glass-card" style="min-height:200px;' + (isToday ? 'border-color:var(--cyan);' : '') + '">' +
          '<div style="text-align:center;margin-bottom:8px;"><span style="font-size:11px;color:var(--text-tertiary);">' + days[i] + '</span><br><span style="font-size:18px;font-weight:600;color:' + (isToday ? 'var(--cyan)' : 'var(--text-primary)') + ';">' + d.getDate() + '</span></div>';
        dayEvents.forEach(function (ev) {
          html += '<div style="font-size:11px;padding:4px 6px;margin-bottom:4px;border-radius:4px;border-left:2px solid ' + (CAT_COLORS[ev.category] || '#8b8b92') + ';background:var(--surface);cursor:pointer;" onclick="Views.calendar.selectDate(\'' + dateStr + '\')">' +
            (ev.time ? '<span style="color:var(--text-tertiary);">' + ev.time + '</span> ' : '') + esc(ev.title) + '</div>';
        });
        if (!dayEvents.length) html += '<div style="font-size:11px;color:var(--text-tertiary);text-align:center;padding:20px 0;">No events</div>';
        html += '</div>';
      }
      html += '</div>';
      el.innerHTML = html;
    },

    renderAgenda: function () {
      var el = document.getElementById('cal-tab-agenda');
      if (!el) return;
      var today = new Date().toISOString().slice(0, 10);
      var upcoming = events.filter(function (e) { return e.date >= today; }).sort(function (a, b) { return a.date.localeCompare(b.date) || (a.time || '').localeCompare(b.time || ''); });

      if (!upcoming.length) { el.innerHTML = '<div class="glass-card" style="text-align:center;padding:40px;color:var(--text-tertiary);">No upcoming events</div>'; return; }

      var grouped = {};
      upcoming.forEach(function (e) { if (!grouped[e.date]) grouped[e.date] = []; grouped[e.date].push(e); });

      var html = '';
      Object.keys(grouped).slice(0, 14).forEach(function (date) {
        var d = new Date(date + 'T12:00:00');
        var isToday = date === today;
        html += '<div style="margin-bottom:16px;">' +
          '<div style="font-size:12px;font-weight:600;color:' + (isToday ? 'var(--cyan)' : 'var(--text-secondary)') + ';margin-bottom:8px;padding-left:4px;">' +
            d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' }) +
            (isToday ? ' — TODAY' : '') +
          '</div>';
        grouped[date].forEach(function (ev) {
          html += '<div class="glass-card" style="padding:10px 14px;margin-bottom:4px;border-left:3px solid ' + (CAT_COLORS[ev.category] || '#8b8b92') + ';display:flex;justify-content:space-between;align-items:center;">' +
            '<div>' +
              '<span style="color:var(--text-primary);font-weight:500;">' + esc(ev.title) + '</span>' +
              '<span style="margin-left:12px;font-size:11px;color:var(--text-tertiary);">' + (ev.time || 'All day') + '</span>' +
              '<span style="margin-left:12px;font-size:11px;color:' + (CAT_COLORS[ev.category] || '#8b8b92') + ';">' + esc(ev.category) + '</span>' +
            '</div>' +
            '<div style="display:flex;gap:4px;">' +
              '<button class="btn btn-ghost btn-sm" style="padding:2px 6px;" onclick="Views.calendar.editEvent(\'' + ev.id + '\')">&#9998;</button>' +
              '<button class="btn btn-ghost btn-sm" style="padding:2px 6px;color:var(--orange);" onclick="Views.calendar.deleteEvent(\'' + ev.id + '\')">&times;</button>' +
            '</div>' +
          '</div>';
        });
        html += '</div>';
      });
      el.innerHTML = html;
    },

    renderAIPlanner: function () {
      var el = document.getElementById('cal-tab-ai');
      if (!el) return;
      el.innerHTML =
        '<div class="glass-card">' +
          '<div class="glass-card-title" style="margin-bottom:8px;">AI Schedule Assistant</div>' +
          '<p style="color:var(--text-secondary);font-size:var(--font-size-sm);margin-bottom:12px;">Describe what you need to schedule and Vigil will suggest events.</p>' +
          '<div style="display:flex;gap:8px;margin-bottom:16px;">' +
            '<input id="cal-ai-suggest-input" class="form-input" placeholder="e.g. Plan a deployment cycle for next week with testing and review..." style="flex:1"/>' +
            '<button class="btn btn-primary btn-sm" onclick="Views.calendar.aiSuggest()">Generate Plan</button>' +
          '</div>' +
          '<div id="cal-ai-suggestions"></div>' +
        '</div>';
    },

    aiSuggest: function () {
      var input = document.getElementById('cal-ai-suggest-input');
      var output = document.getElementById('cal-ai-suggestions');
      if (!input || !input.value || !output) return;
      output.innerHTML = '<div class="loading-state"><div class="spinner spinner-sm"></div><div>Generating...</div></div>';
      fetch('/api/calendar/ai-suggest', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ context: input.value }) })
        .then(function (r) { return r.json(); }).then(function (d) {
          var sugs = d.suggestions || [];
          if (!sugs.length) { output.innerHTML = '<div style="color:var(--text-tertiary);text-align:center;padding:20px;">No suggestions generated.</div>'; return; }
          output.innerHTML = sugs.map(function (s) {
            return '<div class="glass-card" style="padding:10px 14px;margin-bottom:6px;display:flex;justify-content:space-between;align-items:center;">' +
              '<div>' +
                '<span style="font-weight:500;">' + esc(s.title) + '</span>' +
                '<span style="margin-left:12px;font-size:11px;color:var(--text-tertiary);">' + (s.date || '') + (s.time ? ' ' + s.time : '') + '</span>' +
                '<span style="margin-left:12px;font-size:11px;color:' + (CAT_COLORS[s.category] || '#8b8b92') + ';">' + (s.category || '') + '</span>' +
              '</div>' +
              '<button class="btn btn-primary btn-sm" onclick="Views.calendar.addSuggestion(' + esc(JSON.stringify(JSON.stringify(s))) + ')">+ Add</button>' +
            '</div>';
          }).join('');
        }).catch(function () { output.innerHTML = '<div style="color:var(--orange);text-align:center;padding:20px;">AI suggestion failed.</div>'; });
    },

    addSuggestion: function (json) {
      var s = JSON.parse(json);
      fetch('/api/calendar/events', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(s) })
        .then(function () { Views.calendar.loadEvents(); Toast.success('Event added from AI suggestion'); });
    }
  };
})();
