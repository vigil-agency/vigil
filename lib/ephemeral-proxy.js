/**
 * Vigil — Ephemeral Proxy Infrastructure Manager
 * Inspired by fluffy-barnacle's Codespaces-as-infrastructure approach.
 *
 * Manages GitHub Codespaces as disposable SOCKS5 proxy nodes for
 * anonymous scanning during authorized penetration tests.
 *
 * Architecture:
 *   gh CLI -> Codespace lifecycle (create/start/stop/delete)
 *   gh codespace ssh -D -> SOCKS5 dynamic port forwarding
 *   curl --socks5-hostname -> health check + exit IP detection
 */
const { execFile, spawn } = require('child_process');
const net = require('net');
const path = require('path');
const fs = require('fs');

const DATA = path.join(__dirname, '..', 'data');
const NODES_PATH = path.join(DATA, 'proxy-nodes.json');

// In-memory tunnel tracking (not persisted — tunnels die with the process)
const activeTunnels = new Map();

const DEFAULT_REPO = 'github/codespaces-blank';
const DEFAULT_MACHINE = 'basicLinux32gb';
const DEFAULT_PORT = 1080;
const POLL_INTERVAL = 3000;
const POLL_TIMEOUT = 180000;

function readJSON(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return fallback; }
}
function writeJSON(p, data) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + '.tmp.' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, p);
}

/* ─── gh CLI wrappers ─── */

function runGH(args, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const child = execFile('gh', args, { timeout, env: { ...process.env } }, (err, stdout, stderr) => {
      if (err) reject(new Error(stderr || err.message));
      else resolve(stdout.trim());
    });
    child.stdin.end();
  });
}

/** Check if gh CLI is installed */
async function checkGHInstalled() {
  try {
    const version = await runGH(['--version'], 5000);
    return { installed: true, version: version.split('\n')[0] };
  } catch {
    return { installed: false, version: null };
  }
}

/** Check gh auth status */
async function checkGHAuth() {
  try {
    const status = await runGH(['auth', 'status'], 10000);
    const loggedIn = /Logged in/.test(status);
    const userMatch = status.match(/account\s+(\S+)/);
    return { authenticated: loggedIn, user: userMatch ? userMatch[1] : null, detail: status };
  } catch (e) {
    return { authenticated: false, user: null, detail: e.message };
  }
}

/** Authenticate gh CLI with a token (non-interactive) */
async function authenticateWithToken(token) {
  return new Promise((resolve, reject) => {
    const child = execFile('gh', ['auth', 'login', '--with-token'], {
      timeout: 15000,
      env: { ...process.env },
    }, (err, stdout, stderr) => {
      if (err) reject(new Error(stderr || err.message));
      else resolve(stdout.trim());
    });
    child.stdin.write(token);
    child.stdin.end();
  });
}

/* ─── Codespace lifecycle ─── */

/** List all Codespaces */
async function listCodespaces() {
  try {
    const raw = await runGH(
      ['codespace', 'list', '--json', 'name,state,repository,createdAt,machineDisplayName'],
      15000
    );
    return JSON.parse(raw || '[]');
  } catch {
    return [];
  }
}

/** Create a new Codespace */
async function createCodespace(repo, machineType) {
  repo = repo || DEFAULT_REPO;
  machineType = machineType || DEFAULT_MACHINE;

  const raw = await runGH([
    'codespace', 'create',
    '-R', repo,
    '-m', machineType,
  ], 120000);

  // gh codespace create returns the codespace name as plain text
  const name = raw.trim();
  const start = Date.now();
  while (Date.now() - start < POLL_TIMEOUT) {
    const list = await listCodespaces();
    const found = list.find(c => c.name === name);
    if (found && found.state === 'Available') break;
    await new Promise(r => setTimeout(r, POLL_INTERVAL));
  }

  // Persist node
  const nodes = readJSON(NODES_PATH, []);
  nodes.push({
    name: cs.name,
    state: 'Available',
    repository: repo,
    machineType,
    createdAt: cs.createdAt || new Date().toISOString(),
    tunnelPort: null,
    exitIP: null,
  });
  writeJSON(NODES_PATH, nodes);

  return { name: cs.name, state: 'Available', repository: repo, createdAt: cs.createdAt };
}

/** Start a stopped Codespace */
async function startCodespace(name) {
  await runGH(['codespace', 'start', '-c', name], 60000);

  const start = Date.now();
  while (Date.now() - start < POLL_TIMEOUT) {
    const list = await listCodespaces();
    const found = list.find(c => c.name === name);
    if (found && found.state === 'Available') break;
    await new Promise(r => setTimeout(r, POLL_INTERVAL));
  }

  updateNodeState(name, 'Available');
}

/** Stop a Codespace (preserves storage, stops billing) */
async function stopCodespace(name) {
  await stopTunnel(name);
  await runGH(['codespace', 'stop', '-c', name], 30000);
  updateNodeState(name, 'Stopped');
}

/** Delete a Codespace permanently */
async function deleteCodespace(name) {
  await stopTunnel(name);
  await runGH(['codespace', 'delete', '-c', name, '--force'], 30000);

  const nodes = readJSON(NODES_PATH, []);
  writeJSON(NODES_PATH, nodes.filter(n => n.name !== name));
}

/* ─── SOCKS5 tunnel management ─── */

/**
 * Start SSH dynamic-port-forward tunnel to Codespace.
 * Creates a local SOCKS5 proxy at 127.0.0.1:<port>.
 */
async function startTunnel(name, port) {
  port = port || DEFAULT_PORT;

  if (activeTunnels.has(name)) {
    throw new Error('Tunnel already active for ' + name);
  }

  // Check port not in use
  const portUsed = await isPortInUse(port);
  if (portUsed) {
    throw new Error('Port ' + port + ' is already in use');
  }

  const child = spawn('gh', [
    'codespace', 'ssh', '-c', name, '--', '-D', '127.0.0.1:' + port, '-N', '-o', 'StrictHostKeyChecking=no'
  ], {
    stdio: ['pipe', 'pipe', 'pipe'],
    detached: false,
  });

  child.stdin.end();

  const tunnelInfo = {
    pid: child.pid,
    port,
    startedAt: new Date().toISOString(),
    process: child,
  };

  activeTunnels.set(name, tunnelInfo);

  child.on('exit', (code) => {
    console.log('  [PROXY] Tunnel for ' + name + ' exited (code ' + code + ')');
    activeTunnels.delete(name);
    updateNodeState(name, 'Available', { tunnelPort: null, exitIP: null });
  });

  child.on('error', (err) => {
    console.error('  [PROXY] Tunnel error for ' + name + ':', err.message);
    activeTunnels.delete(name);
  });

  // Wait for SSH to establish
  await new Promise(r => setTimeout(r, 4000));

  const healthy = await checkProxyHealth(port);
  if (healthy) {
    const exitIP = await getExitIP(port);
    updateNodeState(name, 'Tunneled', { tunnelPort: port, exitIP });
    return { port, exitIP, pid: child.pid, status: 'connected' };
  }

  updateNodeState(name, 'Connecting', { tunnelPort: port });
  return { port, exitIP: null, pid: child.pid, status: 'connecting' };
}

/** Stop a tunnel */
async function stopTunnel(name) {
  const tunnel = activeTunnels.get(name);
  if (!tunnel) return;

  try {
    tunnel.process.kill('SIGTERM');
    await new Promise(r => setTimeout(r, 1000));
    if (!tunnel.process.killed) tunnel.process.kill('SIGKILL');
  } catch {}

  activeTunnels.delete(name);
  updateNodeState(name, 'Available', { tunnelPort: null, exitIP: null });
}

/** Check if SOCKS5 port is accepting connections */
function checkProxyHealth(port) {
  port = port || DEFAULT_PORT;
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(5000);
    socket.connect(port, '127.0.0.1', () => { socket.destroy(); resolve(true); });
    socket.on('error', () => { socket.destroy(); resolve(false); });
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
  });
}

/** Check if a port is already in use */
function isPortInUse(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', () => resolve(true));
    server.once('listening', () => { server.close(); resolve(false); });
    server.listen(port, '127.0.0.1');
  });
}

/** Get external IP through SOCKS5 proxy */
async function getExitIP(port) {
  port = port || DEFAULT_PORT;
  try {
    return await new Promise((resolve, reject) => {
      const child = execFile('curl', [
        '-s', '--max-time', '10',
        '--socks5-hostname', '127.0.0.1:' + port,
        'https://ifconfig.me'
      ], { timeout: 15000 }, (err, stdout) => {
        if (err) reject(err);
        else resolve(stdout.trim());
      });
      child.stdin.end();
    });
  } catch {
    return null;
  }
}

/* ─── State helpers ─── */

function updateNodeState(name, state, extra) {
  const nodes = readJSON(NODES_PATH, []);
  const idx = nodes.findIndex(n => n.name === name);
  if (idx >= 0) {
    nodes[idx].state = state;
    if (extra) Object.assign(nodes[idx], extra);
    writeJSON(NODES_PATH, nodes);
  }
}

/** Get full status (nodes + active tunnels) */
function getStatus() {
  const nodes = readJSON(NODES_PATH, []);
  const tunnels = [];

  for (const [name, info] of activeTunnels) {
    tunnels.push({ name, port: info.port, pid: info.pid, startedAt: info.startedAt });
  }

  return {
    nodes,
    activeTunnels: tunnels,
    totalNodes: nodes.length,
    activeTunnelCount: tunnels.length,
  };
}

/** Sync persisted nodes with actual Codespace state */
async function syncNodes() {
  const codespaces = await listCodespaces();
  const nodes = readJSON(NODES_PATH, []);

  // Update existing or add new
  for (const cs of codespaces) {
    const idx = nodes.findIndex(n => n.name === cs.name);
    const state = activeTunnels.has(cs.name) ? 'Tunneled' : (cs.state || 'Unknown');
    if (idx >= 0) {
      nodes[idx].state = state;
    } else {
      nodes.push({
        name: cs.name,
        state,
        repository: cs.repository || '',
        machineType: cs.machineDisplayName || 'unknown',
        createdAt: cs.createdAt || '',
        tunnelPort: null,
        exitIP: null,
      });
    }
  }

  // Remove nodes that no longer exist
  const csNames = new Set(codespaces.map(c => c.name));
  const synced = nodes.filter(n => csNames.has(n.name));
  writeJSON(NODES_PATH, synced);
  return synced;
}

module.exports = {
  checkGHInstalled,
  checkGHAuth,
  authenticateWithToken,
  listCodespaces,
  createCodespace,
  startCodespace,
  stopCodespace,
  deleteCodespace,
  startTunnel,
  stopTunnel,
  checkProxyHealth,
  getExitIP,
  getStatus,
  syncNodes,
  DEFAULT_PORT,
};
