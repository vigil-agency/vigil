/* Vigil v1.0 — Main Application */
(function() {
  'use strict';

  // ── State ──
  window.State = {
    user: null,
    posture: null,
    threats: [],
    connected: false,
    currentView: 'dashboard',
    riskScore: null
  };

  // ── View Registry ──
  window.Views = {};

  // ── Cache ──
  window.Cache = {
    _store: {},
    get: function(key) {
      var entry = this._store[key];
      if (!entry) return null;
      if (Date.now() > entry.expires) {
        delete this._store[key];
        return null;
      }
      return entry.data;
    },
    set: function(key, data, ttl) {
      this._store[key] = { data: data, expires: Date.now() + (ttl || 30000) };
    },
    clear: function(key) {
      if (key) delete this._store[key];
      else this._store = {};
    }
  };

  // ── Global fetch interceptor — CSRF header + 401 redirect on ALL API calls ──
  (function() {
    var _origFetch = window.fetch;
    var _redirecting = false;
    window.fetch = function(url, opts) {
      // Auto-add X-Requested-With on API calls to satisfy CSRF check
      if (typeof url === 'string' && url.indexOf('/api/') !== -1) {
        opts = Object.assign({}, opts);
        opts.headers = new Headers(opts.headers || {});
        if (!opts.headers.has('X-Requested-With')) {
          opts.headers.set('X-Requested-With', 'Vigil');
        }
      }
      return _origFetch.call(this, url, opts).then(function(response) {
        if (response.status === 401 && typeof url === 'string' && url.indexOf('/api/') !== -1 && url.indexOf('/api/auth/') === -1 && State.user && !_redirecting) {
          _redirecting = true;
          Toast.warning('Session expired — logging in again');
          setTimeout(function() { _redirecting = false; window.location.reload(); }, 1500);
        }
        return response;
      });
    };
  })();

  // ── Auth-aware Fetch (handles 401 + auto-parses JSON) ──
  window.apiFetch = function(url, opts) {
    var options = Object.assign({ credentials: 'same-origin' }, opts || {});
    return fetch(url, options).then(function(r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  };

  // ── Cached Fetch ──
  window.cachedFetch = function(url, ttl) {
    var cached = window.Cache.get(url);
    if (cached) return Promise.resolve(cached);
    return window.apiFetch(url).then(function(data) {
      window.Cache.set(url, data, ttl || 30000);
      return data;
    });
  };

  // ── Helpers ──
  window.escapeHtml = function(str) {
    if (!str) return '';
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
  };

  window.formatBytes = function(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    var k = 1024;
    var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  window.formatDate = function(dateStr) {
    if (!dateStr) return '--';
    var d = new Date(dateStr);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  window.timeAgo = function(dateStr) {
    if (!dateStr) return '--';
    var seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
    if (seconds < 60) return seconds + 's ago';
    var minutes = Math.floor(seconds / 60);
    if (minutes < 60) return minutes + 'm ago';
    var hours = Math.floor(minutes / 60);
    if (hours < 24) return hours + 'h ago';
    var days = Math.floor(hours / 24);
    return days + 'd ago';
  };

  window.animateValue = function(el, start, end, duration) {
    if (start === end) { el.textContent = end; return; }
    var range = end - start;
    var startTime = null;
    function step(ts) {
      if (!startTime) startTime = ts;
      var progress = Math.min((ts - startTime) / (duration || 600), 1);
      var current = Math.floor(start + range * progress);
      el.textContent = current;
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  };

  window.severityClass = function(sev) {
    if (!sev) return 'severity-info';
    var s = sev.toLowerCase();
    if (s === 'critical') return 'severity-critical';
    if (s === 'high') return 'severity-high';
    if (s === 'medium') return 'severity-medium';
    if (s === 'low') return 'severity-low';
    return 'severity-info';
  };

  window.severityBadge = function(sev) {
    if (!sev) return 'badge-info';
    var s = sev.toLowerCase();
    if (s === 'critical') return 'badge-critical';
    if (s === 'high') return 'badge-high';
    if (s === 'medium') return 'badge-medium';
    if (s === 'low') return 'badge-low';
    return 'badge-info';
  };

  window.scoreColor = function(score) {
    if (score >= 80) return 'score-good';
    if (score >= 50) return 'score-mid';
    return 'score-bad';
  };

  window.scoreGrade = function(score) {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  };

  // ── View Names ──
  var viewNames = {
    'dashboard': 'Dashboard',
    'threats': 'Threat Feed',
    'triage': 'Alert Triage',
    'hunt': 'Threat Hunt',
    'port-scanner': 'Port Scanner',
    'vuln-scanner': 'Vuln Scanner',
    'web-scanner': 'Web Scanner',
    'container-security': 'Container Security',
    'ssl-monitor': 'SSL Monitor',
    'dns-security': 'DNS Security',
    'code-audit': 'Code Audit',
    'proxy-nodes': 'Proxy Nodes',
    'osint': 'OSINT',
    'findings': 'Findings',
    'timeline': 'Attack Timeline',
    'agents': 'Security Agents',
    'campaigns': 'Campaigns',
    'pentest': 'Pentest',
    'playbooks': 'Playbooks',
    'compliance': 'Frameworks',
    'reports': 'Reports',
    'audit-log': 'Audit Log',
    'ai-terminal': 'AI Terminal',
    'ai-chat': 'AI Chat',
    'knowledge': 'Knowledge Base',
    'mcp-playground': 'MCP Playground',
    'network': 'Network',
    'log-analysis': 'Log Analysis',
    'credentials': 'Credentials',
    'notifications': 'Notifications',
    'settings': 'Settings',
    'docs': 'Docs'
  };

  // ── Navigation ──
  window.showView = function(name) {
    var prev = State.currentView;
    if (prev && Views[prev] && Views[prev].hide) {
      Views[prev].hide();
    }

    // Hide all views
    var containers = document.querySelectorAll('.view-container');
    containers.forEach(function(c) { c.style.display = 'none'; c.classList.remove('active'); });

    // Show target
    var target = document.getElementById('view-' + name);
    if (target) {
      target.style.display = 'block';
      target.classList.add('active');
    }

    // Update sidebar active
    document.querySelectorAll('.nav-item').forEach(function(item) {
      item.classList.toggle('active', item.getAttribute('data-view') === name);
    });

    // Update topbar
    var viewNameEl = document.getElementById('topbar-view-name');
    if (viewNameEl) viewNameEl.textContent = viewNames[name] || name;

    State.currentView = name;

    // Init view if needed, then show
    if (Views[name]) {
      if (!Views[name]._initialized) {
        Views[name].init();
        Views[name]._initialized = true;
      }
      if (Views[name].show) Views[name].show();
    }

    // Close mobile sidebar
    var sidebar = document.getElementById('sidebar');
    if (sidebar) sidebar.classList.remove('mobile-open');
  };

  // ── Sidebar ──
  var sidebarLeaveTimer = null;

  function initSidebar() {
    var sidebar = document.getElementById('sidebar');
    var navItems = document.querySelectorAll('.nav-item[data-view]');

    // Nav click
    navItems.forEach(function(item) {
      item.addEventListener('click', function(e) {
        if (e.target.classList.contains('nav-item-fav')) return;
        var view = item.getAttribute('data-view');
        if (view) showView(view);
      });
    });

    // Group collapse
    document.querySelectorAll('.nav-group-header').forEach(function(header) {
      header.addEventListener('click', function() {
        var group = header.parentElement;
        group.classList.toggle('collapsed');
        saveGroupState();
      });
    });

    // Favorites
    document.querySelectorAll('.nav-item-fav').forEach(function(star) {
      star.addEventListener('click', function(e) {
        e.stopPropagation();
        var view = star.getAttribute('data-fav');
        toggleFavorite(view);
      });
    });

    // Auto-collapse
    sidebar.addEventListener('mouseenter', function() {
      if (sidebarLeaveTimer) { clearTimeout(sidebarLeaveTimer); sidebarLeaveTimer = null; }
      sidebar.classList.remove('collapsed');
    });

    sidebar.addEventListener('mouseleave', function() {
      sidebarLeaveTimer = setTimeout(function() {
        if (window.innerWidth > 768) {
          sidebar.classList.add('collapsed');
        }
      }, 400);
    });

    // Mobile hamburger
    var hamburger = document.getElementById('topbar-hamburger');
    if (hamburger) {
      hamburger.addEventListener('click', function() {
        sidebar.classList.toggle('mobile-open');
      });
    }

    // Restore state
    restoreGroupState();
    restoreFavorites();

    // Start collapsed
    if (window.innerWidth > 768) {
      sidebar.classList.add('collapsed');
    }
  }

  // Favorites
  function getFavorites() {
    try { return JSON.parse(localStorage.getItem('vigil_favorites') || '[]'); }
    catch(e) { return []; }
  }

  function saveFavorites(favs) {
    localStorage.setItem('vigil_favorites', JSON.stringify(favs));
  }

  function toggleFavorite(view) {
    var favs = getFavorites();
    var idx = favs.indexOf(view);
    if (idx >= 0) favs.splice(idx, 1);
    else favs.push(view);
    saveFavorites(favs);
    renderFavorites();
  }

  function restoreFavorites() {
    var favs = getFavorites();
    document.querySelectorAll('.nav-item-fav').forEach(function(star) {
      var view = star.getAttribute('data-fav');
      if (favs.indexOf(view) >= 0) {
        star.classList.add('favorited');
        star.innerHTML = '&#9733;';
      } else {
        star.classList.remove('favorited');
        star.innerHTML = '&#9734;';
      }
    });
    renderFavorites();
  }

  function renderFavorites() {
    var favs = getFavorites();
    var container = document.getElementById('nav-favorites');
    var items = document.getElementById('nav-favorites-items');
    if (!container || !items) return;

    // Update star icons
    document.querySelectorAll('.nav-item-fav').forEach(function(star) {
      var view = star.getAttribute('data-fav');
      if (favs.indexOf(view) >= 0) {
        star.classList.add('favorited');
        star.innerHTML = '&#9733;';
      } else {
        star.classList.remove('favorited');
        star.innerHTML = '&#9734;';
      }
    });

    if (favs.length === 0) {
      container.style.display = 'none';
      return;
    }

    container.style.display = 'block';
    items.innerHTML = '';
    favs.forEach(function(view) {
      var source = document.querySelector('.nav-item[data-view="' + view + '"]');
      if (!source) return;
      var clone = source.cloneNode(true);
      clone.classList.remove('active');
      clone.addEventListener('click', function(e) {
        if (e.target.classList.contains('nav-item-fav')) {
          e.stopPropagation();
          toggleFavorite(view);
          return;
        }
        showView(view);
      });
      var cloneStar = clone.querySelector('.nav-item-fav');
      if (cloneStar) {
        cloneStar.addEventListener('click', function(e) {
          e.stopPropagation();
          toggleFavorite(view);
        });
      }
      items.appendChild(clone);
    });
  }

  // Group state
  function saveGroupState() {
    var state = {};
    document.querySelectorAll('.nav-group[data-group]').forEach(function(g) {
      state[g.getAttribute('data-group')] = g.classList.contains('collapsed');
    });
    localStorage.setItem('vigil_navGroups', JSON.stringify(state));
  }

  function restoreGroupState() {
    try {
      var state = JSON.parse(localStorage.getItem('vigil_navGroups') || '{}');
      Object.keys(state).forEach(function(key) {
        var g = document.querySelector('.nav-group[data-group="' + key + '"]');
        if (g && state[key]) g.classList.add('collapsed');
      });
    } catch(e) {}
  }

  // ── Auth ──
  function checkAuth() {
    return fetch('/api/auth/check', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.authenticated) {
          State.user = data.user;
          return true;
        }
        return false;
      })
      .catch(function() { return false; });
  }

  function showLogin() {
    document.getElementById('login-overlay').classList.remove('hidden');
    document.getElementById('app-layout').style.display = 'none';
  }

  function showApp() {
    document.getElementById('login-overlay').classList.add('hidden');
    document.getElementById('login-overlay').style.display = 'none';
    document.getElementById('app-layout').style.display = 'grid';

    // Update user display
    if (State.user) {
      var avatar = document.getElementById('user-avatar');
      var nameEl = document.getElementById('user-name');
      if (avatar) avatar.textContent = (State.user.username || 'A').charAt(0).toUpperCase();
      if (nameEl) nameEl.textContent = State.user.username || 'admin';
    }

    initSidebar();
    initSocket();
    initBell();
    showView('dashboard');
  }

  function initLoginForm() {
    var form = document.getElementById('login-form');
    if (!form) return;
    form.addEventListener('submit', function(e) {
      e.preventDefault();
      var btn = document.getElementById('login-btn');
      var errorEl = document.getElementById('login-error');
      var user = document.getElementById('login-username').value.trim();
      var pass = document.getElementById('login-password').value;

      if (!user || !pass) {
        errorEl.textContent = 'Enter username and password';
        return;
      }

      btn.disabled = true;
      btn.textContent = 'Signing in...';
      errorEl.textContent = '';

      fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ username: user, password: pass })
      })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.success) {
          State.user = data.user || { username: user };
          showApp();
        } else {
          errorEl.textContent = data.message || 'Invalid credentials';
        }
      })
      .catch(function() {
        errorEl.textContent = 'Connection failed';
      })
      .finally(function() {
        btn.disabled = false;
        btn.textContent = 'Sign In';
      });
    });
  }

  // ── User Dropdown ──
  function initUserMenu() {
    var userBtn = document.getElementById('topbar-user');
    var dropdown = document.getElementById('user-dropdown');
    var logoutBtn = document.getElementById('btn-logout');
    var profileBtn = document.getElementById('btn-profile');

    if (userBtn && dropdown) {
      userBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        dropdown.classList.toggle('open');
      });
      document.addEventListener('click', function() {
        dropdown.classList.remove('open');
      });
    }

    if (logoutBtn) {
      logoutBtn.addEventListener('click', function() {
        fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
          .finally(function() {
            State.user = null;
            window.Cache.clear();
            location.reload();
          });
      });
    }

    if (profileBtn) {
      profileBtn.addEventListener('click', function() {
        dropdown.classList.remove('open');
        showView('settings');
      });
    }
  }

  // ── Socket.IO ──
  function initSocket() {
    if (typeof io === 'undefined') {
      updateConnectionStatus(false);
      return;
    }

    var socket = io({ reconnection: true, reconnectionDelay: 2000 });
    window._socket = socket;

    socket.on('connect', function() {
      State.connected = true;
      updateConnectionStatus(true);
    });

    socket.on('disconnect', function() {
      State.connected = false;
      updateConnectionStatus(false);
    });

    socket.on('connect_error', function() {
      State.connected = false;
      updateConnectionStatus(false);
    });

    socket.on('init', function(data) {
      if (data && data.system) {
        State.posture = data.system;
        updateStatusBar(data.system);
      }
    });

    socket.on('metrics', function(data) {
      State.lastMetrics = data;
      updateLastUpdate();
      if (State.currentView === 'dashboard' && Views.dashboard && Views.dashboard.update) {
        Views.dashboard.update(data);
      }
    });

    socket.on('threats', function(data) {
      if (data && data.threats) {
        State.threats = data.threats;
        if (State.currentView === 'threats' && Views.threats && Views.threats.update) {
          Views.threats.update(data);
        }
      }
    });

    socket.on('posture', function(data) {
      if (data && data.score !== undefined) {
        State.riskScore = data.score;
        updateRiskScore(data.score);
      }
    });

    socket.on('claude_output', function(data) {
      if (Views['ai-terminal'] && Views['ai-terminal'].appendOutput) {
        Views['ai-terminal'].appendOutput(data);
      }
    });

    socket.on('claude_done', function(data) {
      if (Views['ai-terminal'] && Views['ai-terminal'].onDone) {
        Views['ai-terminal'].onDone(data);
      }
    });

    socket.on('notification', function(data) {
      updateBellCount();
      if (window.Toast && data && data.message) {
        var level = data.severity === 'critical' ? 'error' :
                    data.severity === 'high' ? 'warning' : 'info';
        Toast[level](data.message);
      }
    });
  }

  function updateConnectionStatus(connected) {
    var dot = document.getElementById('status-dot');
    var text = document.getElementById('status-conn-text');
    if (dot) {
      dot.className = 'status-dot ' + (connected ? 'connected' : 'disconnected');
    }
    if (text) {
      text.textContent = connected ? 'Connected' : 'Disconnected';
    }
  }

  function updateLastUpdate() {
    var el = document.getElementById('status-last-update');
    if (el) {
      el.textContent = 'Last update: ' + new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
  }

  function updateStatusBar(system) {
    var hostnameEl = document.getElementById('status-hostname');
    if (hostnameEl && system) {
      hostnameEl.textContent = system.hostname || '--';
    }
  }

  function updateRiskScore(score) {
    var textEl = document.getElementById('risk-score-text');
    var dotEl = document.getElementById('risk-score-dot');
    if (textEl) textEl.textContent = 'Score: ' + score;
    if (dotEl) {
      if (score >= 80) dotEl.style.background = 'var(--cyan)';
      else if (score >= 50) dotEl.style.background = 'var(--purple)';
      else dotEl.style.background = 'var(--orange)';
    }
  }

  // ── Notification Bell ──
  function updateBellCount() {
    fetch('/api/notifications/unread', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var count = data.count || 0;
        var badge = document.getElementById('bell-count');
        if (badge) {
          badge.textContent = count;
          badge.style.display = count > 0 ? 'flex' : 'none';
        }
      })
      .catch(function() {});
  }

  function initBell() {
    var bell = document.getElementById('topbar-bell');
    if (bell) {
      bell.addEventListener('click', function() {
        showView('notifications');
      });
    }
    // Poll every 60s
    updateBellCount();
    setInterval(updateBellCount, 60000);
  }

  // ── Init ──
  document.addEventListener('DOMContentLoaded', function() {
    initLoginForm();
    initUserMenu();

    checkAuth().then(function(authed) {
      if (authed) {
        showApp();
      } else {
        showLogin();
      }
    });
  });

  // ── Keyboard Shortcuts ──
  function isInputFocused() {
    var el = document.activeElement;
    if (!el) return false;
    var tag = el.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable;
  }

  function initHotkeys() {
    document.addEventListener('keydown', function(e) {
      var key = e.key;
      var ctrl = e.ctrlKey || e.metaKey;
      var shift = e.shiftKey;

      // ── Ctrl+K — Command Palette ──
      if (ctrl && key === 'k') {
        e.preventDefault();
        toggleCommandPalette();
        return;
      }

      // ── Ctrl+B — Toggle Sidebar ──
      if (ctrl && key === 'b' && !shift) {
        e.preventDefault();
        var sidebar = document.getElementById('sidebar');
        if (sidebar) sidebar.classList.toggle('collapsed');
        return;
      }

      // ── Ctrl+Shift+R — Refresh Current View ──
      if (ctrl && shift && key === 'R') {
        e.preventDefault();
        if (State.currentView && Views[State.currentView] && Views[State.currentView].show) {
          Views[State.currentView].show();
          Toast.info('View refreshed');
        }
        return;
      }

      // ── Escape — Close palette/overlays ──
      if (key === 'Escape') {
        var palette = document.getElementById('command-palette');
        if (palette && palette.style.display !== 'none') {
          palette.style.display = 'none';
          return;
        }
        var helpOverlay = document.getElementById('hotkey-help');
        if (helpOverlay && helpOverlay.style.display !== 'none') {
          helpOverlay.style.display = 'none';
          return;
        }
      }

      // Below here: skip if in input field
      if (isInputFocused()) return;

      // ── ? — Hotkey Help ──
      if (key === '?' && !ctrl) {
        e.preventDefault();
        toggleHotkeyHelp();
        return;
      }

      // ── Number keys — Quick Navigation ──
      if (!ctrl && !shift && !e.altKey) {
        switch (key) {
          case '1': showView('dashboard'); Toast.info('Dashboard'); return;
          case '2': showView('findings'); Toast.info('Findings'); return;
          case '3': showView('port-scanner'); Toast.info('Port Scanner'); return;
          case '4': showView('web-scanner'); Toast.info('Web Scanner'); return;
          case '5': showView('agents'); Toast.info('Security Agents'); return;
          case '6': showView('ai-chat'); Toast.info('AI Chat'); return;
          case '7': showView('settings'); Toast.info('Settings'); return;
        }
      }
    });
  }

  // ── Command Palette ──
  function toggleCommandPalette() {
    var palette = document.getElementById('command-palette');
    if (!palette) {
      palette = document.createElement('div');
      palette.id = 'command-palette';
      palette.style.cssText = 'display:none;position:fixed;top:0;left:0;right:0;bottom:0;z-index:10000;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);';
      palette.innerHTML =
        '<div style="max-width:520px;margin:80px auto;background:var(--surface-solid);border:1px solid var(--border-glass);border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,0.5);overflow:hidden;">' +
          '<div style="padding:12px 16px;border-bottom:1px solid var(--border);">' +
            '<input type="text" id="cmd-palette-input" placeholder="Type to search views..." style="width:100%;background:transparent;border:none;outline:none;color:var(--text-primary);font-size:var(--font-size-base);font-family:var(--font-mono);">' +
          '</div>' +
          '<div id="cmd-palette-results" style="max-height:360px;overflow-y:auto;padding:4px;"></div>' +
          '<div style="padding:8px 16px;border-top:1px solid var(--border);display:flex;gap:16px;color:var(--text-tertiary);font-size:var(--font-size-xs);">' +
            '<span><kbd style="background:var(--well);padding:1px 5px;border-radius:3px;font-family:var(--font-mono);">&#8593;&#8595;</kbd> Navigate</span>' +
            '<span><kbd style="background:var(--well);padding:1px 5px;border-radius:3px;font-family:var(--font-mono);">Enter</kbd> Go</span>' +
            '<span><kbd style="background:var(--well);padding:1px 5px;border-radius:3px;font-family:var(--font-mono);">Esc</kbd> Close</span>' +
          '</div>' +
        '</div>';
      document.body.appendChild(palette);

      palette.addEventListener('click', function(e) {
        if (e.target === palette) palette.style.display = 'none';
      });

      var input = document.getElementById('cmd-palette-input');
      input.addEventListener('input', function() { filterPalette(input.value); });
      input.addEventListener('keydown', function(e) {
        if (e.key === 'ArrowDown') { e.preventDefault(); movePaletteSelection(1); }
        else if (e.key === 'ArrowUp') { e.preventDefault(); movePaletteSelection(-1); }
        else if (e.key === 'Enter') {
          e.preventDefault();
          var active = document.querySelector('#cmd-palette-results .cmd-item.active');
          if (active) {
            palette.style.display = 'none';
            showView(active.getAttribute('data-view'));
          }
        }
      });
    }

    if (palette.style.display === 'none') {
      palette.style.display = 'block';
      var input = document.getElementById('cmd-palette-input');
      input.value = '';
      filterPalette('');
      input.focus();
    } else {
      palette.style.display = 'none';
    }
  }

  function filterPalette(query) {
    var results = document.getElementById('cmd-palette-results');
    var q = query.toLowerCase();
    var items = Object.keys(viewNames).filter(function(key) {
      if (!q) return true;
      return key.toLowerCase().indexOf(q) >= 0 || viewNames[key].toLowerCase().indexOf(q) >= 0;
    });

    var html = '';
    items.forEach(function(key, i) {
      var isActive = i === 0 ? ' active' : '';
      var isCurrent = key === State.currentView ? ' style="color:var(--cyan);"' : '';
      html += '<div class="cmd-item' + isActive + '" data-view="' + key + '" style="padding:8px 12px;cursor:pointer;border-radius:6px;display:flex;justify-content:space-between;align-items:center;">' +
        '<span' + isCurrent + '>' + escapeHtml(viewNames[key]) + '</span>' +
        '<span style="color:var(--text-tertiary);font-size:var(--font-size-xs);font-family:var(--font-mono);">' + escapeHtml(key) + '</span>' +
      '</div>';
    });
    results.innerHTML = html || '<div style="padding:16px;text-align:center;color:var(--text-tertiary);">No matching views</div>';

    results.querySelectorAll('.cmd-item').forEach(function(item) {
      item.addEventListener('mouseenter', function() {
        results.querySelectorAll('.cmd-item').forEach(function(i) { i.classList.remove('active'); });
        item.classList.add('active');
      });
      item.addEventListener('click', function() {
        document.getElementById('command-palette').style.display = 'none';
        showView(item.getAttribute('data-view'));
      });
    });
  }

  function movePaletteSelection(dir) {
    var items = document.querySelectorAll('#cmd-palette-results .cmd-item');
    if (items.length === 0) return;
    var idx = -1;
    items.forEach(function(item, i) { if (item.classList.contains('active')) idx = i; });
    items.forEach(function(item) { item.classList.remove('active'); });
    idx += dir;
    if (idx < 0) idx = items.length - 1;
    if (idx >= items.length) idx = 0;
    items[idx].classList.add('active');
    items[idx].scrollIntoView({ block: 'nearest' });
  }

  // ── Hotkey Help Overlay ──
  function toggleHotkeyHelp() {
    var overlay = document.getElementById('hotkey-help');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'hotkey-help';
      overlay.style.cssText = 'display:none;position:fixed;top:0;left:0;right:0;bottom:0;z-index:10000;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);';
      overlay.innerHTML =
        '<div style="max-width:500px;margin:60px auto;background:var(--surface-solid);border:1px solid var(--border-glass);border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,0.5);padding:24px;max-height:80vh;overflow-y:auto;">' +
          '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">' +
            '<div style="font-size:var(--font-size-lg);font-weight:600;color:var(--text-primary);">Keyboard Shortcuts</div>' +
            '<button class="btn btn-ghost btn-sm" onclick="document.getElementById(\'hotkey-help\').style.display=\'none\'">Close</button>' +
          '</div>' +
          '<table style="width:100%;border-collapse:collapse;">' +
            hotkeyRow('Ctrl + K', 'Command palette (search all views)', true) +
            hotkeyRow('Ctrl + B', 'Toggle sidebar') +
            hotkeyRow('Ctrl + Shift + R', 'Refresh current view') +
            hotkeyRow('Ctrl + `', 'Toggle terminal drawer') +
            hotkeyRow('Escape', 'Close modal / palette / overlay') +
            hotkeyRow('?', 'Show this help') +
            '<tr><td colspan="2" style="padding:12px 0 4px;color:var(--cyan);font-weight:600;font-size:var(--font-size-sm);border-bottom:1px solid var(--border);">Quick Navigation (when not typing)</td></tr>' +
            hotkeyRow('1', 'Dashboard') +
            hotkeyRow('2', 'Findings') +
            hotkeyRow('3', 'Port Scanner') +
            hotkeyRow('4', 'Web Scanner') +
            hotkeyRow('5', 'Security Agents') +
            hotkeyRow('6', 'AI Chat') +
            hotkeyRow('7', 'Settings') +
          '</table>' +
        '</div>';
      document.body.appendChild(overlay);
      overlay.addEventListener('click', function(e) {
        if (e.target === overlay) overlay.style.display = 'none';
      });
    }
    overlay.style.display = overlay.style.display === 'none' ? 'block' : 'none';
  }

  function hotkeyRow(key, desc, isFirst) {
    var border = isFirst ? '' : 'border-bottom:1px solid rgba(255,255,255,0.04);';
    return '<tr style="' + border + '">' +
      '<td style="padding:6px 0;width:150px;"><kbd style="background:var(--well);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);font-size:var(--font-size-xs);color:var(--text-primary);">' + key + '</kbd></td>' +
      '<td style="padding:6px 0;color:var(--text-secondary);font-size:var(--font-size-sm);">' + desc + '</td>' +
    '</tr>';
  }

  // Command palette active state CSS
  var hotkeyStyle = document.createElement('style');
  hotkeyStyle.textContent = '#cmd-palette-results .cmd-item.active{background:rgba(34,211,238,0.08)} #cmd-palette-results .cmd-item:hover{background:rgba(34,211,238,0.08)}';
  document.head.appendChild(hotkeyStyle);

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initHotkeys);
  } else {
    initHotkeys();
  }

})();
