/**
 * Claude Routes — Claude CLI integration, AI terminal, prompt execution
 */
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

function getAIProvider() {
  try {
    const f = path.join(__dirname, '..', 'data', 'settings.json');
    if (fs.existsSync(f)) return JSON.parse(fs.readFileSync(f, 'utf8')).aiProvider || 'claude-cli';
  } catch {}
  return 'claude-cli';
}

function getAICommand(provider, prompt) {
  switch (provider) {
    case 'codex': return { cmd: 'codex', args: [prompt] };
    case 'claude-cli':
    default: return { cmd: 'claude', args: ['--print', prompt] };
  }
}

module.exports = function (app, ctx) {
  const { io, execCommand, requireAuth, requireRole, REPO_DIR } = ctx;
  let activeClaudeProc = null;

  // Expose for socket events
  ctx.activeClaudeProc = () => activeClaudeProc;

  function runClaude(prompt) {
    const provider = getAIProvider();
    if (provider === 'none') {
      io.emit('claude_output', '\r\n[INFO] AI provider is disabled. Configure in Settings > AI Provider.\r\n');
      return;
    }
    if (activeClaudeProc) {
      io.emit('claude_output', '\r\n[ERROR] AI already running.\r\n');
      return;
    }

    const { cmd, args } = getAICommand(provider, prompt);
    io.emit('claude_output', `\r\n[STARTING] ${cmd} "${prompt.substring(0, 80)}..."\r\n\r\n`);

    const child = spawn(cmd, args, { cwd: REPO_DIR, env: { ...process.env }, shell: true });
    activeClaudeProc = child;
    let output = '';

    child.stdout.on('data', (d) => {
      const t = d.toString();
      output += t;
      io.emit('claude_output', t);
    });

    child.stderr.on('data', (d) => {
      const t = d.toString();
      output += t;
      io.emit('claude_output', t);
    });

    child.on('close', (code) => {
      activeClaudeProc = null;
      io.emit('claude_done', { code, output, prompt });
    });

    child.on('error', (err) => {
      activeClaudeProc = null;
      io.emit('claude_output', `\r\n[ERROR] ${err.message}\r\n`);
      io.emit('claude_done', { code: 1, output: err.message, prompt });
    });
  }

  ctx.runClaude = runClaude;

  // askAI helper — runs AI CLI and returns text
  async function askAI(prompt, options) {
    const provider = getAIProvider();
    if (provider === 'none') return null;

    const timeout = (options && options.timeout) || 30000;
    const { cmd } = getAICommand(provider, prompt);
    const cleanEnv = { ...process.env };
    delete cleanEnv.CLAUDECODE;

    return new Promise((resolve, reject) => {
      const child = spawn(cmd, provider === 'codex' ? [] : ['--print'], {
        stdio: ['pipe', 'pipe', 'pipe'],
        shell: true,
        timeout,
        env: cleanEnv,
      });
      let stdout = '', stderr = '';

      child.stdout.on('data', d => { stdout += d; });
      child.stderr.on('data', d => { stderr += d; });
      child.on('close', code => {
        const result = stdout.trim() || stderr.trim();
        if (code === 0 && result) resolve(result);
        else resolve(result || null);
      });
      child.on('error', e => resolve(null));

      child.stdin.on('error', () => {});
      child.stdin.write(prompt);
      child.stdin.end();
    });
  }

  // askAIJSON helper — runs AI CLI and parses JSON from response
  async function askAIJSON(prompt, options) {
    const text = await askAI(prompt, options);
    if (!text) return null;
    try { return JSON.parse(text); }
    catch {
      // Try to extract JSON from response
      const match = text.match(/\{[\s\S]*\}/);
      if (match) {
        try { return JSON.parse(match[0]); }
        catch { return null; }
      }
      return null;
    }
  }

  // Expose AI helpers on ctx for other routes
  ctx.askAI = askAI;
  ctx.askAIJSON = askAIJSON;

  // POST /api/claude/run — run prompt through Claude CLI
  app.post('/api/claude/run', requireRole('analyst'), (req, res) => {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'prompt required' });
    if (activeClaudeProc) return res.status(409).json({ error: 'AI already running' });
    runClaude(prompt);
    res.json({ started: true });
  });

  // POST /api/claude/ask — one-shot AI query (returns response)
  app.post('/api/claude/ask', requireRole('analyst'), async (req, res) => {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'prompt required' });

    const provider = getAIProvider();
    if (provider === 'none') return res.json({ response: 'AI provider is disabled.', fallback: true });

    try {
      const response = await askAI(prompt, { timeout: 30000 });
      res.json({ response: response || 'No response from AI', cached: false });
    } catch (e) {
      res.json({ response: 'AI unavailable: ' + e.message, fallback: true });
    }
  });

  // POST /api/claude/stop — stop running AI process
  app.post('/api/claude/stop', requireRole('analyst'), (req, res) => {
    if (activeClaudeProc) {
      activeClaudeProc.kill('SIGTERM');
      activeClaudeProc = null;
      io.emit('claude_output', '\r\n[STOPPED]\r\n');
      res.json({ stopped: true });
    } else {
      res.json({ stopped: false });
    }
  });

  // GET /api/claude/status — check if AI is running
  app.get('/api/claude/status', requireAuth, (req, res) => {
    res.json({
      running: !!activeClaudeProc,
      provider: getAIProvider(),
    });
  });

  // ── Terminal Management (node-pty) — Persistent Sessions ─────────────
  //
  // PTY sessions are keyed by username (not socket.id) so they survive
  // page reloads & socket reconnections. On disconnect a grace period
  // keeps the PTY alive; on reconnect the client reattaches and replays
  // buffered output.

  const TERM_BUFFER_SIZE = 50000;      // chars to keep for replay
  const TERM_GRACE_PERIOD = 5 * 60000; // 5 min before orphan kill

  // Map<username, { term, sockets: Set<socket>, buffer: string, graceTimer }>
  let termSessions = new Map();

  function getTermSession(username) {
    return termSessions.get(username) || null;
  }

  function appendBuffer(sess, data) {
    sess.buffer += data;
    if (sess.buffer.length > TERM_BUFFER_SIZE) {
      sess.buffer = sess.buffer.slice(-TERM_BUFFER_SIZE);
    }
  }

  function emitToSession(sess, event, data) {
    for (const s of sess.sockets) {
      s.emit(event, data);
    }
  }

  function createTermSession(username, socket, cols, rows) {
    try {
      const pty = require('node-pty');
      const shell = process.platform === 'win32' ? 'powershell.exe' : (process.env.SHELL || '/bin/bash');

      // Filter sensitive env vars
      const safeEnv = { ...process.env };
      const sensitiveKeys = ['ENCRYPTION_KEY', 'DATABASE_URL', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'GITHUB_TOKEN', 'STRIPE_SECRET_KEY', 'JWT_SECRET', 'CLAUDECODE'];
      sensitiveKeys.forEach(k => delete safeEnv[k]);

      const term = pty.spawn(shell, [], {
        name: 'xterm-color',
        cols: cols || 80,
        rows: rows || 24,
        cwd: REPO_DIR,
        env: safeEnv,
      });

      const sess = {
        term,
        sockets: new Set([socket]),
        buffer: '',
        graceTimer: null,
      };

      term.onData((data) => {
        appendBuffer(sess, data);
        emitToSession(sess, 'terminal_output', data);
      });

      term.onExit(() => {
        // PTY process ended (user typed exit, shell crashed, etc.)
        emitToSession(sess, 'terminal_output', '\r\n\x1b[33m[Process exited]\x1b[0m\r\n');
        emitToSession(sess, 'terminal_exited', {});
        if (sess.graceTimer) clearTimeout(sess.graceTimer);
        termSessions.delete(username);
      });

      termSessions.set(username, sess);
      return sess;
    } catch (e) {
      socket.emit('terminal_output', '\r\n[ERROR] Terminal not available: ' + e.message + '\r\n');
      return null;
    }
  }

  function detachSocket(username, socket) {
    const sess = termSessions.get(username);
    if (!sess) return;
    sess.sockets.delete(socket);
    // If no more sockets connected, start grace period
    if (sess.sockets.size === 0) {
      sess.graceTimer = setTimeout(() => {
        // Grace expired — kill orphaned PTY
        try { sess.term.kill(); } catch {}
        termSessions.delete(username);
      }, TERM_GRACE_PERIOD);
    }
  }

  function attachSocket(username, socket) {
    const sess = termSessions.get(username);
    if (!sess) return false;
    // Cancel grace timer if running
    if (sess.graceTimer) {
      clearTimeout(sess.graceTimer);
      sess.graceTimer = null;
    }
    sess.sockets.add(socket);
    return true;
  }

  // Socket.IO events for terminal — verify auth on connection
  io.on('connection', (socket) => {
    // Authenticate socket connection via cookie or auth token
    const cookieHeader = socket.handshake.headers.cookie || '';
    const tokenMatch = cookieHeader.match(/vigil_session=([^;]+)/);
    const token = tokenMatch ? tokenMatch[1] : (socket.handshake.auth && socket.handshake.auth.token);
    const { getSession } = require('../lib/sessions');
    const session = token ? getSession(token) : null;
    if (!session) {
      socket.emit('terminal_output', '\r\n[ERROR] Authentication required for terminal access.\r\n');
      socket.disconnect();
      return;
    }
    socket.user = { username: session.username, role: session.role };

    // ── terminal_start: create new PTY or reattach to existing ──
    socket.on('terminal_start', (data) => {
      const username = socket.user.username;
      const cols = (data && data.cols) || 80;
      const rows = (data && data.rows) || 24;

      const existing = getTermSession(username);
      if (existing) {
        // Reattach to existing session
        attachSocket(username, socket);
        // Replay buffer so client sees previous output
        if (existing.buffer) socket.emit('terminal_replay', existing.buffer);
        socket.emit('terminal_reattach_ok', { reattached: true });
        // Resize to match new client
        try { existing.term.resize(cols, rows); } catch {}
        return;
      }

      // Create fresh PTY session
      createTermSession(username, socket, cols, rows);
    });

    // ── terminal_reattach: explicit reattach attempt (on reconnect) ──
    socket.on('terminal_reattach', (data) => {
      const username = socket.user.username;
      const existing = getTermSession(username);
      if (existing) {
        attachSocket(username, socket);
        if (existing.buffer) socket.emit('terminal_replay', existing.buffer);
        socket.emit('terminal_reattach_ok', { reattached: true });
        const cols = (data && data.cols) || 80;
        const rows = (data && data.rows) || 24;
        try { existing.term.resize(cols, rows); } catch {}
      } else {
        socket.emit('terminal_reattach_fail', {});
      }
    });

    socket.on('terminal_input', (data) => {
      const sess = getTermSession(socket.user.username);
      if (sess) sess.term.write(data);
    });

    socket.on('terminal_resize', (data) => {
      const sess = getTermSession(socket.user.username);
      if (sess && data && data.cols && data.rows) {
        try { sess.term.resize(data.cols, data.rows); } catch {}
      }
    });

    socket.on('claude_run', (data) => {
      // Only analyst+ roles can run AI commands
      if (socket.user && socket.user.role !== 'viewer' && data && data.prompt) {
        runClaude(data.prompt);
      }
    });

    socket.on('disconnect', () => {
      // Don't kill PTY — detach socket and start grace period
      detachSocket(socket.user.username, socket);
    });
  });
};
