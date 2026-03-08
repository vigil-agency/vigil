/**
 * Vigil Command Center — Floating Terminal Drawer
 * Overlays any page. Toggle with Ctrl+` or bottom bar button.
 * Tabs: Shell PTY, Vigil AI, Credential Vault
 * Persists across page switches. Session survives view changes.
 */
(function () {
  'use strict';

  // -- State --
  var term = null;
  var fitAddon = null;
  var termStarted = false;
  var drawerOpen = false;
  var drawerSize = 'half'; // 'half' | 'full' | 'mini'
  var activeTab = 'shell';
  var credentials = [];
  var vigilHistory = [];
  var cmdHistory = [];
  var historyIdx = -1;
  var drawerInited = false;

  // -- Inject Floating Drawer into DOM (once, persists forever) --
  function ensureDrawer() {
    if (drawerInited) return;
    drawerInited = true;

    var drawer = document.createElement('div');
    drawer.id = 'cmd-drawer';
    drawer.className = 'cmd-drawer';
    drawer.innerHTML =
      // Backdrop (click to minimize)
      '<div class="cmd-backdrop" id="cmd-backdrop" onclick="Views.terminal.toggleDrawer()"></div>' +
      // Drawer panel
      '<div class="cmd-drawer-panel" id="cmd-drawer-panel">' +
        // Drag handle + topbar
        '<div class="cmd-topbar" id="cmd-topbar">' +
          '<div class="cmd-topbar-left">' +
            '<div class="cmd-drag" onmousedown="Views.terminal.startResize(event)" title="Drag to resize">' +
              '<span></span><span></span><span></span>' +
            '</div>' +
            '<div class="cmd-tabs">' +
              cmdTab('shell', true) +
              cmdTab('vigil-ai', false) +
              cmdTab('vault', false) +
            '</div>' +
          '</div>' +
          '<div class="cmd-topbar-right">' +
            '<div class="cmd-status" id="cmd-status"><span class="cmd-status-dot" id="cmd-status-dot"></span><span id="cmd-status-label" class="cmd-status-label">Disconnected</span></div>' +
            '<button class="cmd-topbar-btn" onclick="Views.terminal.cycleSize()" title="Resize (Ctrl+Shift+`)">' +
              '<svg viewBox="0 0 14 14" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 5V2h3M12 5V2H9M2 9v3h3M12 9v3H9"/></svg>' +
            '</button>' +
            '<button class="cmd-topbar-btn" onclick="Views.terminal.toggleDrawer()" title="Minimize (Ctrl+`)">' +
              '<svg viewBox="0 0 14 14" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 10h10"/></svg>' +
            '</button>' +
          '</div>' +
        '</div>' +
        // Quick-command bar
        '<div class="cmd-quick-bar">' +
          '<div class="cmd-quick-left">' +
            '<button class="cmd-qbtn" onclick="Views.terminal.qcmd(\'clear\')">clear</button>' +
            '<button class="cmd-qbtn" onclick="Views.terminal.qcmd(\'ls -la\')">ls</button>' +
            '<button class="cmd-qbtn" onclick="Views.terminal.qcmd(\'ss -tunapl\')">ports</button>' +
            '<button class="cmd-qbtn" onclick="Views.terminal.qcmd(\'docker ps\')">docker</button>' +
            '<button class="cmd-qbtn" onclick="Views.terminal.qcmd(\'tail -50 /var/log/auth.log\')">auth log</button>' +
          '</div>' +
          '<div class="cmd-quick-right">' +
            '<button class="cmd-qbtn cmd-qbtn-connect" onclick="Views.terminal.showQuickConnect(this)">' +
              '<svg viewBox="0 0 12 12" width="10" height="10" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="6" cy="6" r="4"/><path d="M6 3v3h3"/></svg> Connect' +
            '</button>' +
          '</div>' +
        '</div>' +
        // Panel bodies
        '<div class="cmd-body">' +
          '<div class="cmd-panel" id="cmd-panel-shell"><div id="terminal-container" class="cmd-terminal-wrap"></div></div>' +
          '<div class="cmd-panel" id="cmd-panel-vigil-ai" style="display:none">' + buildVigilUI() + '</div>' +
          '<div class="cmd-panel" id="cmd-panel-vault" style="display:none">' + buildVaultUI() + '</div>' +
        '</div>' +
      '</div>';

    document.body.appendChild(drawer);

    // Keyboard shortcut: Ctrl+` toggle, Ctrl+Shift+` cycle size
    document.addEventListener('keydown', function (e) {
      if (e.ctrlKey && e.key === '`') {
        e.preventDefault();
        if (e.shiftKey) Views.terminal.cycleSize();
        else Views.terminal.toggleDrawer();
      }
    });
  }

  function cmdTab(id, active) {
    var icon = '';
    var label = '';
    if (id === 'shell') {
      icon = '<svg viewBox="0 0 14 14" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="3,3 7,7 3,11"/><line x1="8" y1="11" x2="12" y2="11"/></svg>';
      label = 'Shell';
    } else if (id === 'vigil-ai') {
      icon = '<svg viewBox="0 0 14 14" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="7" cy="7" r="5.5"/><path d="M5 6.5h0M9 6.5h0M6 9.5c.5.5 1.5.5 2 0"/></svg>';
      label = 'Vigil AI';
    } else if (id === 'vault') {
      icon = '<svg viewBox="0 0 14 14" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2.5" y="6" width="9" height="6" rx="1.5"/><path d="M4.5 6V4.5a2.5 2.5 0 0 1 5 0V6"/><circle cx="7" cy="9.5" r="1"/></svg>';
      label = 'Vault';
    }
    return '<button class="cmd-tab' + (active ? ' active' : '') + '" data-tab="' + id + '" onclick="Views.terminal.switchTab(\'' + id + '\')">' + icon + '<span>' + label + '</span></button>';
  }

  function buildVigilUI() {
    return '<div class="cht-panel">' +
      '<div class="cht-messages" id="cht-messages">' +
        '<div class="cht-welcome">' +
          '<div class="cht-welcome-icon"><svg viewBox="0 0 32 32" width="36" height="36" fill="none" stroke="var(--cyan)" stroke-width="1"><circle cx="16" cy="16" r="13"/><path d="M11 14h0M21 14h0M12 20c2 2.5 6 2.5 8 0"/><path d="M16 3v2M16 27v2M3 16h2M27 16h2" stroke-opacity="0.25"/></svg></div>' +
          '<div class="cht-welcome-title">Vigil Security AI</div>' +
          '<div class="cht-welcome-sub">Analyze threats, investigate incidents, audit configurations, scan vulnerabilities — just ask naturally.</div>' +
          '<div class="cht-suggestions">' +
            chtSug('Run a security posture check') +
            chtSug('Scan ports on localhost') +
            chtSug('Check SSL certificate') +
            chtSug('Analyze auth log for brute force') +
            chtSug('List open vulnerabilities') +
            chtSug('Generate incident report') +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="cht-input-wrap">' +
        '<input type="text" id="cht-input" class="cht-input" placeholder="Ask Vigil anything about security..." onkeydown="Views.terminal.chtKey(event)" />' +
        '<button class="cht-send-btn" id="cht-send-btn" onclick="Views.terminal.chtSend()">' +
          '<svg viewBox="0 0 14 14" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 7h12M9 3l4 4-4 4"/></svg>' +
        '</button>' +
      '</div>' +
    '</div>';
  }

  function chtSug(text) {
    return '<button class="cht-sug" onclick="Views.terminal.chtSend(\'' + h(text) + '\')">' + h(text) + '</button>';
  }

  function buildVaultUI() {
    return '<div class="vlt-panel">' +
      '<div class="vlt-toolbar">' +
        '<div class="vlt-toolbar-left">' +
          '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="var(--accent, #ff6b2b)" stroke-width="1.3"><rect x="3" y="7" width="10" height="7" rx="1.5"/><path d="M5 7V5a3 3 0 0 1 6 0v2"/><circle cx="8" cy="11" r="1"/></svg>' +
          '<span class="vlt-title">Credential Vault</span>' +
          '<span class="vlt-enc-badge">AES-256</span>' +
        '</div>' +
        '<button class="btn btn-sm" style="color:#ff6b2b;border-color:rgba(255,107,43,0.2);" onclick="Views.terminal.addCred()">+ Add</button>' +
      '</div>' +
      '<div class="vlt-search-row">' +
        '<input type="text" id="vlt-search" class="vlt-search" placeholder="Search credentials..." oninput="Views.terminal.filterCreds()" />' +
      '</div>' +
      '<div class="vlt-list" id="vlt-list"><div class="text-secondary" style="padding:20px;text-align:center">Loading...</div></div>' +
    '</div>';
  }

  // -- View Registry (clicking sidebar "AI Terminal" opens drawer) --
  Views['ai-terminal'] = {
    init: function () {
      ensureDrawer();
      var el = document.getElementById('view-ai-terminal');
      if (el) {
        el.innerHTML = '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:60vh;gap:16px">' +
          '<svg viewBox="0 0 48 48" width="56" height="56" fill="none" stroke="var(--cyan)" stroke-width="1"><polyline points="12,12 24,24 12,36"/><line x1="24" y1="36" x2="40" y2="36"/><rect x="4" y="4" width="40" height="40" rx="4" stroke-opacity="0.2"/></svg>' +
          '<div style="color:var(--text-primary);font-size:18px;font-weight:600">Command Center</div>' +
          '<div class="text-secondary" style="max-width:320px;text-align:center;line-height:1.5">The terminal is now a floating drawer. Open it from any page.</div>' +
          '<button class="btn btn-primary" onclick="Views.terminal.toggleDrawer()" style="margin-top:8px">Open Terminal (Ctrl+`)</button>' +
          '<div class="text-tertiary" style="font-size:11px;margin-top:4px">Keyboard: <kbd style="background:rgba(255,255,255,0.06);padding:2px 6px;border-radius:3px;font-size:10px">Ctrl + `</kbd> to toggle from anywhere</div>' +
        '</div>';
      }
    },
    show: function () {
      ensureDrawer();
      Views.terminal.openDrawer();
    },
    hide: function () {},
    update: function () {}
  };

  // Also redirect ai-chat sidebar click to the Vigil AI tab
  Views['ai-chat'] = {
    init: function () {
      ensureDrawer();
      var el = document.getElementById('view-ai-chat');
      if (el) {
        el.innerHTML = '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:60vh;gap:16px">' +
          '<svg viewBox="0 0 48 48" width="56" height="56" fill="none" stroke="var(--cyan)" stroke-width="1"><circle cx="24" cy="24" r="18"/><path d="M16 21h0M32 21h0M18 30c3 3.5 9 3.5 12 0"/></svg>' +
          '<div style="color:var(--text-primary);font-size:18px;font-weight:600">Vigil AI Chat</div>' +
          '<div class="text-secondary" style="max-width:320px;text-align:center;line-height:1.5">AI chat is integrated into the floating Command Center.</div>' +
          '<button class="btn btn-primary" onclick="Views.terminal.openDrawer();Views.terminal.switchTab(\'vigil-ai\')" style="margin-top:8px">Open AI Chat (Ctrl+`)</button>' +
        '</div>';
      }
    },
    show: function () {
      ensureDrawer();
      Views.terminal.openDrawer();
      Views.terminal.switchTab('vigil-ai');
    },
    hide: function () {},
    update: function () {}
  };

  // Also register as Views.terminal for direct access
  Views.terminal = {
    init: function () { ensureDrawer(); },
    show: function () { ensureDrawer(); Views.terminal.openDrawer(); },
    hide: function () {},
    update: function () {}
  };

  // -- Drawer Open / Close / Resize --
  Views.terminal.toggleDrawer = function () {
    ensureDrawer();
    if (drawerOpen) Views.terminal.closeDrawer();
    else Views.terminal.openDrawer();
  };

  Views.terminal.openDrawer = function () {
    ensureDrawer();
    var drawer = document.getElementById('cmd-drawer');
    if (!drawer) return;
    drawerOpen = true;
    drawer.classList.add('cmd-drawer-open');
    drawer.classList.remove('cmd-drawer-closed');
    applySize();
    if (activeTab === 'shell') {
      setTimeout(function () {
        ensureXterm();
        fitTerminal();
        if (!termStarted) startTerminalSession();
        if (term) term.focus();
      }, 100);
    }
    if (activeTab === 'vault') loadCredentials();
  };

  Views.terminal.closeDrawer = function () {
    var drawer = document.getElementById('cmd-drawer');
    if (!drawer) return;
    drawerOpen = false;
    drawer.classList.remove('cmd-drawer-open');
    drawer.classList.add('cmd-drawer-closed');
  };

  Views.terminal.cycleSize = function () {
    if (drawerSize === 'half') drawerSize = 'full';
    else if (drawerSize === 'full') drawerSize = 'mini';
    else drawerSize = 'half';
    applySize();
    setTimeout(fitTerminal, 100);
  };

  function applySize() {
    var panel = document.getElementById('cmd-drawer-panel');
    if (!panel) return;
    panel.className = 'cmd-drawer-panel cmd-size-' + drawerSize;
    var backdrop = document.getElementById('cmd-backdrop');
    if (backdrop) backdrop.style.display = drawerSize === 'full' ? '' : 'none';
  }

  Views.terminal.startResize = function (e) {
    e.preventDefault();
    var panel = document.getElementById('cmd-drawer-panel');
    if (!panel) return;
    var startY = e.clientY;
    var startH = panel.offsetHeight;
    function onMove(ev) {
      var newH = startH - (ev.clientY - startY);
      newH = Math.max(150, Math.min(window.innerHeight - 40, newH));
      panel.style.height = newH + 'px';
      panel.className = 'cmd-drawer-panel cmd-size-custom';
      drawerSize = 'custom';
    }
    function onUp() {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      setTimeout(fitTerminal, 50);
    }
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  };

  // -- Tab Switching --
  Views.terminal.switchTab = function (tab) {
    activeTab = tab;
    document.querySelectorAll('#cmd-drawer .cmd-tab').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-tab') === tab);
    });
    ['shell', 'vigil-ai', 'vault'].forEach(function (t) {
      var p = document.getElementById('cmd-panel-' + t);
      if (p) p.style.display = t === tab ? '' : 'none';
    });
    if (tab === 'shell') {
      setTimeout(function () { ensureXterm(); fitTerminal(); if (term) term.focus(); }, 50);
      if (!termStarted) setTimeout(startTerminalSession, 100);
    }
    if (tab === 'vault') loadCredentials();
    if (tab === 'vigil-ai') {
      var inp = document.getElementById('cht-input');
      if (inp) setTimeout(function () { inp.focus(); }, 50);
    }
  };

  // -- xterm.js Shell --
  function ensureXterm() {
    if (term) return;
    var container = document.getElementById('terminal-container');
    if (!container) return;
    if (typeof Terminal === 'undefined' || typeof FitAddon === 'undefined') {
      container.innerHTML = '<div style="padding:24px;color:var(--orange);font-family:monospace">[ERROR] xterm.js CDN not loaded.</div>';
      return;
    }
    term = new Terminal({
      theme: {
        background: '#0a0a0a',
        foreground: '#e2e8f0',
        cursor: '#ff6b2b',
        cursorAccent: '#0a0a0a',
        selectionBackground: 'rgba(255,107,43,0.18)',
        black: '#121212', brightBlack: '#2a2a2a',
        red: '#ef4444', brightRed: '#f87171',
        green: '#ff6b2b', brightGreen: '#ff8a57',
        yellow: '#eab308', brightYellow: '#fde047',
        blue: '#3b82f6', brightBlue: '#60a5fa',
        magenta: '#a855f7', brightMagenta: '#c084fc',
        cyan: '#ff6b2b', brightCyan: '#ff8a57',
        white: '#e2e8f0', brightWhite: '#f8fafc'
      },
      fontSize: 13,
      fontFamily: "'JetBrains Mono', 'Cascadia Code', 'Fira Code', monospace",
      cursorBlink: true, cursorStyle: 'bar',
      allowProposedApi: true, scrollback: 10000, convertEol: true,
      rightClickSelectsWord: true
    });
    fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(container);
    fitTerminal();

    // Copy: Ctrl+C copies when text selected, otherwise sends SIGINT
    term.attachCustomKeyEventHandler(function (e) {
      if (e.type !== 'keydown') return true;
      if (e.ctrlKey && e.key === 'c' && !e.shiftKey) {
        if (term.hasSelection()) {
          document.execCommand('copy');
          return false;
        }
        return true;
      }
      if (e.ctrlKey && e.shiftKey && (e.key === 'C' || e.key === 'c')) {
        if (term.hasSelection()) document.execCommand('copy');
        return false;
      }
      return true;
    });

    var sock = window._socket || window.socket;
    term.onData(function (data) { if (termStarted && sock) sock.emit('terminal_input', data); });
    window.addEventListener('resize', function () { if (drawerOpen && activeTab === 'shell') fitTerminal(); });
    if (sock) {
      sock.on('terminal_output', function (data) {
        if (!term) return;
        term.write(data);
      });
      // Replay buffered output on reattach (server sends full buffer)
      sock.on('terminal_replay', function (data) {
        if (!term) return;
        term.clear();
        term.write(data);
      });
      // PTY process exited (user typed exit, shell crashed)
      sock.on('terminal_exited', function () {
        termStarted = false;
        updateStatus(false);
      });
      // Successful reattach to existing PTY session
      sock.on('terminal_reattach_ok', function () {
        termStarted = true;
        updateStatus(true);
      });
      // No existing PTY to reattach — auto-start fresh session
      sock.on('terminal_reattach_fail', function () {
        termStarted = false;
        updateStatus(false);
        startTerminalSession();
      });
      // On socket reconnect: try to reattach to surviving PTY
      sock.on('connect', function () {
        if (termStarted) {
          // We thought we were connected — socket dropped, try reattach
          termStarted = false;
          updateStatus(false);
          if (term) term.write('\r\n\x1b[33m[Reconnecting...]\x1b[0m\r\n');
          sock.emit('terminal_reattach', { cols: term ? term.cols : 80, rows: term ? term.rows : 24 });
        }
      });
    }
    term.write('\x1b[36m  Vigil Command Center\x1b[0m\r\n\x1b[90m  Ctrl+` toggle | Ctrl+Shift+` resize | Session persists across reloads\x1b[0m\r\n\r\n');
  }

  function startTerminalSession() {
    if (termStarted) return;
    ensureXterm();
    if (!term) return;
    var sock = window._socket || window.socket;
    if (!sock) return;
    termStarted = true;
    updateStatus(true);
    term.focus();
    // terminal_start on server will reattach if a PTY already exists
    // for this user, or create a new one if not
    sock.emit('terminal_start', { cols: term.cols || 80, rows: term.rows || 24 });
  }

  function fitTerminal() {
    if (!fitAddon || !drawerOpen) return;
    var sock = window._socket || window.socket;
    try { fitAddon.fit(); if (termStarted && sock) sock.emit('terminal_resize', { cols: term.cols, rows: term.rows }); } catch {}
  }

  function updateStatus(on) {
    var dot = document.getElementById('cmd-status-dot');
    var label = document.getElementById('cmd-status-label');
    if (dot) dot.className = 'cmd-status-dot' + (on ? ' on' : '');
    if (label) { label.textContent = on ? 'Connected' : 'Disconnected'; label.className = 'cmd-status-label' + (on ? ' on' : ''); }
  }

  // -- Quick Commands --
  Views.terminal.qcmd = function (cmd) {
    if (activeTab !== 'shell') Views.terminal.switchTab('shell');
    var sock = window._socket || window.socket;
    if (!termStarted || !sock) { if (typeof Toast !== 'undefined') Toast.warning('Terminal not connected'); return; }
    sock.emit('terminal_input', cmd + '\r');
  };

  // -- Quick Connect Dropdown --
  Views.terminal.showQuickConnect = function (btn) {
    var existing = document.getElementById('qc-dropdown');
    if (existing) { existing.remove(); return; }

    fetch('/api/credentials').then(function (r) { return r.json(); }).then(function (d) {
      var creds = (d.credentials || []).filter(function (c) { return c.type === 'ssh_key' || c.type === 'password'; });
      var dd = document.createElement('div');
      dd.id = 'qc-dropdown';
      dd.className = 'qc-dropdown';
      if (creds.length === 0) {
        dd.innerHTML = '<div class="qc-empty">No SSH credentials in vault</div>';
      } else {
        dd.innerHTML = creds.map(function (c) {
          return '<button class="qc-item" onclick="Views.terminal.connectTo(\'' + c.id + '\');document.getElementById(\'qc-dropdown\').remove()">' +
            '<span class="qc-item-dot"></span>' +
            '<span class="qc-item-name">' + h(c.name) + '</span>' +
            (c.host ? '<span class="qc-item-host">' + h(c.host) + '</span>' : '') +
          '</button>';
        }).join('');
      }
      btn.parentNode.appendChild(dd);
      setTimeout(function () {
        document.addEventListener('click', function rmDD(e) {
          var d2 = document.getElementById('qc-dropdown');
          if (d2 && !d2.contains(e.target) && e.target !== btn) { d2.remove(); document.removeEventListener('click', rmDD); }
        });
      }, 10);
    });
  };

  Views.terminal.connectTo = function (id) {
    fetch('/api/credentials/' + id + '/inject', { method: 'POST' }).then(function (r) { return r.json(); }).then(function (d) {
      if (d.command) {
        Views.terminal.switchTab('shell');
        if (!termStarted) startTerminalSession();
        var sock = window._socket || window.socket;
        setTimeout(function () {
          if (sock) sock.emit('terminal_input', d.command + '\r');
          if (typeof Toast !== 'undefined') Toast.info('Connecting: ' + d.name);
        }, 200);
      }
    }).catch(function () { if (typeof Toast !== 'undefined') Toast.error('Connection failed'); });
  };

  // -- Vigil AI --
  Views.terminal.chtKey = function (e) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); Views.terminal.chtSend(); }
    if (e.key === 'ArrowUp' && cmdHistory.length > 0) { historyIdx = Math.min(historyIdx + 1, cmdHistory.length - 1); e.target.value = cmdHistory[historyIdx]; }
    if (e.key === 'ArrowDown') { historyIdx = Math.max(historyIdx - 1, -1); e.target.value = historyIdx >= 0 ? cmdHistory[historyIdx] : ''; }
  };

  Views.terminal.chtSend = function (preset) {
    var input = document.getElementById('cht-input');
    var msgs = document.getElementById('cht-messages');
    var btn = document.getElementById('cht-send-btn');
    var msg = preset || (input ? input.value.trim() : '');
    if (!msg || !msgs) return;
    if (input) input.value = '';
    historyIdx = -1;
    cmdHistory.unshift(msg);

    // Remove welcome
    var welcome = msgs.querySelector('.cht-welcome');
    if (welcome) welcome.remove();

    // User bubble
    msgs.innerHTML += '<div class="cht-msg cht-msg-user"><div class="cht-msg-text">' + h(msg) + '</div></div>';

    // Thinking
    var think = document.createElement('div');
    think.className = 'cht-msg cht-msg-ai';
    think.innerHTML = '<div class="cht-msg-avatar"><svg viewBox="0 0 14 14" width="12" height="12" fill="none" stroke="var(--cyan)" stroke-width="1.3"><circle cx="7" cy="7" r="5.5"/><path d="M5 6.5h0M9 6.5h0M6 9.5c.5.5 1.5.5 2 0"/></svg></div><div class="cht-msg-text"><span class="cht-thinking">Thinking...</span></div>';
    msgs.appendChild(think);
    msgs.scrollTop = msgs.scrollHeight;
    if (btn) btn.disabled = true;

    var histStr = vigilHistory.slice(-8).map(function (h) { return h.role + ': ' + h.text; }).join('\n');
    var prompt = 'You are Vigil, an AI security analyst in a floating terminal command center. The user is a security professional managing servers, running vulnerability scans, investigating threats, and handling incidents.\n\n' +
      (histStr ? 'Previous:\n' + histStr + '\n\n' : '') +
      'User: ' + msg + '\n\n' +
      'Rules:\n' +
      '- Be concise (2-5 sentences)\n' +
      '- For any executable command, wrap in [CMD]command[/CMD] so the UI shows a run button\n' +
      '- If the user asks to run something ambiguous, pick the best command\n' +
      '- Reference real tools: nmap, nuclei, trivy, openssl, ss, iptables, docker, journalctl\n' +
      '- No markdown. Plain text only.';

    vigilHistory.push({ role: 'user', text: msg });

    fetch('/api/claude/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt: prompt })
    }).then(function (r) { return r.json(); }).then(function (d) {
      var text = d.response || 'Couldn\'t process that. Try again.';
      vigilHistory.push({ role: 'vigil', text: text });

      // Parse [CMD]...[/CMD] into executable buttons
      var rendered = h(text).replace(/\[CMD\](.*?)\[\/CMD\]/g, function (_, cmd) {
        return '<button class="cht-exec-btn" onclick="Views.terminal.execCmd(\'' + cmd.replace(/'/g, "\\'").replace(/"/g, '&quot;') + '\')">' +
          '<svg viewBox="0 0 10 10" width="9" height="9" fill="none" stroke="currentColor" stroke-width="1.5"><polygon points="1,0 9,5 1,10"/></svg> ' + h(cmd) + '</button>';
      });

      think.innerHTML = '<div class="cht-msg-avatar"><svg viewBox="0 0 14 14" width="12" height="12" fill="none" stroke="var(--cyan)" stroke-width="1.3"><circle cx="7" cy="7" r="5.5"/><path d="M5 6.5h0M9 6.5h0M6 9.5c.5.5 1.5.5 2 0"/></svg></div><div class="cht-msg-text">' + rendered + '</div>';
      if (btn) btn.disabled = false;
      msgs.scrollTop = msgs.scrollHeight;
    }).catch(function (e) {
      think.querySelector('.cht-msg-text').innerHTML = '<span class="text-secondary">Connection error: ' + h(e.message || 'unknown') + '</span>';
      if (btn) btn.disabled = false;
    });
  };

  Views.terminal.execCmd = function (cmd) {
    Views.terminal.switchTab('shell');
    if (!termStarted) startTerminalSession();
    var sock = window._socket || window.socket;
    setTimeout(function () {
      if (sock) sock.emit('terminal_input', cmd + '\r');
      if (typeof Toast !== 'undefined') Toast.info('Running: ' + cmd.substring(0, 50));
    }, 200);
  };

  // -- Credential Vault --
  function loadCredentials() {
    fetch('/api/credentials').then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }).then(function (d) {
      credentials = d.credentials || [];
      renderVault();
    }).catch(function (e) {
      var el = document.getElementById('vlt-list');
      if (el) el.innerHTML = '<div class="text-secondary" style="padding:20px;text-align:center">Failed to load vault' +
        '<div class="text-tertiary" style="font-size:10px;margin-top:4px">' + (e.message || 'Unknown error') + '</div></div>';
    });
  }

  Views.terminal.filterCreds = function () {
    var q = (document.getElementById('vlt-search').value || '').toLowerCase();
    var items = document.querySelectorAll('.vlt-item');
    items.forEach(function (item) {
      var name = (item.getAttribute('data-name') || '').toLowerCase();
      item.style.display = !q || name.indexOf(q) >= 0 ? '' : 'none';
    });
  };

  function renderVault() {
    var el = document.getElementById('vlt-list');
    if (!el) return;
    if (credentials.length === 0) {
      el.innerHTML = '<div class="vlt-empty">' +
        '<svg viewBox="0 0 40 40" width="40" height="40" fill="none" stroke="var(--text-tertiary)" stroke-width="1"><rect x="8" y="16" width="24" height="18" rx="3"/><path d="M12 16v-4a8 8 0 0 1 16 0v4"/><circle cx="20" cy="26" r="2"/></svg>' +
        '<div style="margin-top:8px;color:var(--text-secondary)">No credentials yet</div>' +
        '<div class="text-tertiary" style="font-size:11px">Add SSH keys, API tokens, connection strings</div>' +
      '</div>';
      return;
    }
    var typeColors = { ssh_key: 'var(--cyan)', api_token: '#eab308', connection_string: '#a855f7', password: 'var(--orange)', custom: 'var(--text-secondary)' };
    el.innerHTML = credentials.map(function (c) {
      var color = typeColors[c.type] || typeColors.custom;
      return '<div class="vlt-item" data-name="' + h(c.name) + ' ' + h(c.host || '') + ' ' + h((c.tags || []).join(' ')) + '">' +
        '<div class="vlt-item-dot" style="background:' + color + '"></div>' +
        '<div class="vlt-item-info">' +
          '<div class="vlt-item-name">' + h(c.name) + '</div>' +
          '<div class="vlt-item-meta">' + h(c.type.replace(/_/g, ' ')) +
            (c.host ? ' &middot; ' + h(c.host) : '') +
            (c.username ? ' &middot; ' + h(c.username) : '') +
          '</div>' +
        '</div>' +
        '<div class="vlt-item-tags">' + (c.tags || []).map(function (t) { return '<span class="vlt-tag">' + h(t) + '</span>'; }).join('') + '</div>' +
        '<div class="vlt-item-actions">' +
          (c.type === 'ssh_key' || c.type === 'password' ? '<button class="vlt-act vlt-act-go" onclick="Views.terminal.connectTo(\'' + c.id + '\')" title="Connect"><svg viewBox="0 0 10 10" width="10" height="10" fill="none" stroke="currentColor" stroke-width="1.5"><polygon points="1,0 9,5 1,10"/></svg></button>' : '') +
          '<button class="vlt-act vlt-act-del" onclick="Views.terminal.delCred(\'' + c.id + '\',\'' + h(c.name).replace(/'/g, '') + '\')" title="Delete"><svg viewBox="0 0 10 10" width="10" height="10" fill="none" stroke="currentColor" stroke-width="1.3"><path d="M2 3h6M3 3v5a1 1 0 001 1h2a1 1 0 001-1V3M4 3V2h2v1"/></svg></button>' +
        '</div>' +
      '</div>';
    }).join('');
  }

  Views.terminal.addCred = function () {
    if (typeof Modal === 'undefined') return;
    Modal.open({ title: 'Add Credential', body: credForm(),
      footer: '<button class="btn btn-sm" onclick="Modal.close()">Cancel</button><button class="btn btn-sm btn-primary" onclick="Views.terminal.saveCred()">Save to Vault</button>'
    });
  };

  Views.terminal.delCred = function (id, name) {
    if (!confirm('Delete "' + name + '"?')) return;
    fetch('/api/credentials/' + id, { method: 'DELETE' }).then(function (r) { return r.json(); }).then(function (d) {
      if (d.success) { if (typeof Toast !== 'undefined') Toast.success('Deleted'); loadCredentials(); }
    });
  };

  function credForm(c) {
    c = c || {};
    return '<div class="cred-form">' +
      fRow('Name', '<input type="text" id="cf-name" class="form-input" value="' + h(c.name || '') + '" placeholder="My Server" />') +
      fRow('Type', '<select id="cf-type" class="form-input">' +
        opt('ssh_key', 'SSH Key', c.type) + opt('api_token', 'API Token', c.type) +
        opt('connection_string', 'Connection String', c.type) + opt('password', 'Password', c.type) + opt('custom', 'Custom', c.type) +
      '</select>') +
      fRow('Host', '<input type="text" id="cf-host" class="form-input" value="' + h(c.host || '') + '" placeholder="192.168.1.100" />') +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">' +
        fRow('Port', '<input type="number" id="cf-port" class="form-input" value="' + h(c.port || '') + '" placeholder="22" />') +
        fRow('Username', '<input type="text" id="cf-user" class="form-input" value="' + h(c.username || '') + '" placeholder="ubuntu" />') +
      '</div>' +
      fRow('Secret', '<textarea id="cf-secret" class="form-input" rows="4" placeholder="Paste secret...">' + h(c.secret || '') + '</textarea>') +
      fRow('Tags', '<input type="text" id="cf-tags" class="form-input" value="' + h((c.tags || []).join(', ')) + '" placeholder="production, aws" />') +
      '<div class="cred-form-note"><svg viewBox="0 0 12 12" width="11" height="11" fill="none" stroke="var(--cyan)" stroke-width="1.3"><rect x="2" y="5" width="8" height="5" rx="1"/><path d="M4 5V3.5a2 2 0 0 1 4 0V5"/></svg> Encrypted with AES-256-GCM. Never leaves server unencrypted.</div>' +
    '</div>';
  }

  function fRow(label, input) { return '<div class="cred-form-row"><label>' + label + '</label>' + input + '</div>'; }
  function opt(val, label, sel) { return '<option value="' + val + '"' + (sel === val ? ' selected' : '') + '>' + label + '</option>'; }

  Views.terminal.saveCred = function () {
    var name = (document.getElementById('cf-name').value || '').trim();
    var secret = (document.getElementById('cf-secret').value || '').trim();
    if (!name) { if (typeof Toast !== 'undefined') Toast.warning('Name required'); return; }
    if (!secret) { if (typeof Toast !== 'undefined') Toast.warning('Secret required'); return; }
    var data = {
      name: name,
      type: document.getElementById('cf-type').value,
      host: (document.getElementById('cf-host').value || '').trim() || null,
      port: parseInt(document.getElementById('cf-port').value) || null,
      username: (document.getElementById('cf-user').value || '').trim() || null,
      secret: secret,
      tags: (document.getElementById('cf-tags').value || '').split(',').map(function (t) { return t.trim(); }).filter(Boolean)
    };
    fetch('/api/credentials', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.success || d.id) { if (typeof Toast !== 'undefined') Toast.success('Saved'); if (typeof Modal !== 'undefined') Modal.close(); loadCredentials(); }
        else { if (typeof Toast !== 'undefined') Toast.error(d.error || 'Failed'); }
      }).catch(function () { if (typeof Toast !== 'undefined') Toast.error('Save failed'); });
  };

  // -- Helpers --
  function h(s) { return window.escapeHtml ? window.escapeHtml(String(s || '')) : String(s || '').replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }

  // -- Bottom Bar Terminal Toggle Button (inject into status bar) --
  function injectToggleButton() {
    var statusBar = document.getElementById('statusbar');
    if (!statusBar) { setTimeout(injectToggleButton, 500); return; }
    if (document.getElementById('cmd-toggle-btn')) return;
    var btn = document.createElement('button');
    btn.id = 'cmd-toggle-btn';
    btn.className = 'cmd-toggle-btn';
    btn.title = 'Terminal (Ctrl+`)';
    btn.innerHTML = '<svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="4,4 8,8 4,12"/><line x1="9" y1="12" x2="13" y2="12"/></svg>';
    btn.onclick = function () { Views.terminal.toggleDrawer(); };
    statusBar.insertBefore(btn, statusBar.firstChild);
  }

  // Init: inject toggle button and drawer
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { ensureDrawer(); injectToggleButton(); });
  } else {
    ensureDrawer();
    injectToggleButton();
  }
})();
