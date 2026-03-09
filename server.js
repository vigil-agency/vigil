// Vigil v1.0 — The Security Agency That Never Sleeps
// .env loader (must be first — before any requires that read process.env)
const envPath = require('path').join(__dirname, '.env');
try {
  require('fs').readFileSync(envPath, 'utf8').split('\n').forEach(line => {
    line = line.trim();
    if (!line || line.startsWith('#')) return;
    const [key, ...val] = line.split('=');
    if (key && !process.env[key.trim()]) process.env[key.trim()] = val.join('=').trim();
  });
} catch {}

const express = require('express');
const http = require('http');
const { Server: SocketIO } = require('socket.io');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

// Lib modules
const { pool, dbQuery } = require('./lib/db');
const { execCommand, execFileSafe } = require('./lib/exec');
const { getUsers, getUser, createUser, verifyPassword } = require('./lib/users');
const { createSession, getSession, deleteSession, cleanExpired } = require('./lib/sessions');
const { requireRole, requireAction, ROLES } = require('./lib/rbac');
const { logAction, getAuditLog } = require('./lib/audit');
const { askAI, askAIJSON, getAICommand } = require('./lib/ai');
const { generateSecret, generateQRData, verifyToken: verifyTOTP } = require('./lib/totp');
const neuralCache = require('./lib/neural-cache');
const { storeCredential, getCredential, listCredentials, deleteCredential } = require('./lib/credential-vault');
const { calculatePosture } = require('./lib/posture-engine');
const threatIntel = require('./lib/threat-intel');
const { send: sendNotification, getUnread: getUnreadNotifs } = require('./lib/notification-sender');
const scannerEngine = require('./lib/scanner-engine');
const osintEngine = require('./lib/osint-engine');

// Ensure data directory exists
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// Express setup
const app = express();
const server = http.createServer(app);
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['http://localhost:4100', 'http://localhost:3001', 'http://127.0.0.1:4100'];
const io = new SocketIO(server, {
  cors: { origin: allowedOrigins, methods: ['GET', 'POST'], credentials: true },
  pingTimeout: 60000,
  pingInterval: 25000
});

app.disable('x-powered-by');

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// CSRF protection — require X-Requested-With header on state-changing requests
// Browsers block cross-origin custom headers without CORS preflight
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    // Allow requests with JSON content-type or custom header (not sent by simple CSRF forms)
    const ct = req.headers['content-type'] || '';
    const xhr = req.headers['x-requested-with'];
    if (ct.includes('application/json') || xhr) {
      return next();
    }
    // Allow MCP endpoint (uses JSON-RPC)
    if (req.path === '/mcp') return next();
    // Allow file uploads (multipart)
    if (ct.includes('multipart/form-data')) return next();
    return res.status(403).json({ error: 'Missing Content-Type or X-Requested-With header' });
  }
  next();
});

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Static files (no-cache for JS to prevent stale views)
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.js') || filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, must-revalidate');
    }
  }
}));

// Cookie parser (manual — no dependency)
app.use((req, res, next) => {
  req.cookies = {};
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    cookieHeader.split(';').forEach(cookie => {
      const parts = cookie.split('=');
      const name = parts[0] ? parts[0].trim() : '';
      const value = parts.slice(1).join('=').trim();
      if (name) req.cookies[name] = decodeURIComponent(value);
    });
  }
  next();
});

// Auth middleware
const requireAuth = (req, res, next) => {
  const token = req.cookies.vigil_session ||
    (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')
      ? req.headers.authorization.slice(7) : null);

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const session = getSession(token);
  if (!session) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }

  req.user = { username: session.username, role: session.role };
  next();
};

const requireAdmin = (req, res, next) => {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  });
};

// System info gathering
function getSystemInfo() {
  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const loadAvg = os.loadavg();

  // CPU usage calculation
  let totalIdle = 0, totalTick = 0;
  cpus.forEach(cpu => {
    for (const type in cpu.times) totalTick += cpu.times[type];
    totalIdle += cpu.times.idle;
  });
  const cpuPct = Math.round((1 - totalIdle / totalTick) * 100);

  return {
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    release: os.release(),
    uptime: os.uptime(),
    cpuPct,
    cpuCount: cpus.length,
    cpuModel: cpus[0] ? cpus[0].model : 'Unknown',
    loadAvg,
    totalMemMB: Math.round(totalMem / 1024 / 1024),
    usedMemMB: Math.round(usedMem / 1024 / 1024),
    freeMemMB: Math.round(freeMem / 1024 / 1024),
    usedMemPct: Math.round((usedMem / totalMem) * 100),
    nodeVersion: process.version,
    pid: process.pid
  };
}

// CPU usage tracking (per-interval delta)
let prevCpuInfo = null;
function getCpuUsage() {
  const cpus = os.cpus();
  let idle = 0, total = 0;
  cpus.forEach(cpu => {
    for (const type in cpu.times) total += cpu.times[type];
    idle += cpu.times.idle;
  });

  let cpuPct = 0;
  if (prevCpuInfo) {
    const idleDelta = idle - prevCpuInfo.idle;
    const totalDelta = total - prevCpuInfo.total;
    cpuPct = totalDelta > 0 ? Math.round((1 - idleDelta / totalDelta) * 100) : 0;
  }
  prevCpuInfo = { idle, total };
  return cpuPct;
}

// Disk usage (async)
async function getDiskUsage() {
  return new Promise(resolve => {
    const platform = os.platform();
    if (platform === 'win32') {
      exec('wmic logicaldisk get size,freespace,caption', { timeout: 5000 }, (err, stdout) => {
        if (err) return resolve([]);
        const lines = stdout.trim().split('\n').slice(1);
        const disks = [];
        lines.forEach(line => {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 3) {
            const caption = parts[0];
            const free = parseInt(parts[1]) || 0;
            const size = parseInt(parts[2]) || 0;
            if (size > 0) {
              disks.push({
                filesystem: caption,
                mount: caption,
                size: Math.round(size / 1024 / 1024 / 1024),
                used: Math.round((size - free) / 1024 / 1024 / 1024),
                available: Math.round(free / 1024 / 1024 / 1024),
                usePct: Math.round(((size - free) / size) * 100)
              });
            }
          }
        });
        resolve(disks);
      });
    } else {
      exec('df -h --output=source,size,used,avail,pcent,target 2>/dev/null || df -h', { timeout: 5000 }, (err, stdout) => {
        if (err) return resolve([]);
        const lines = stdout.trim().split('\n').slice(1);
        const disks = [];
        lines.forEach(line => {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 6 && !parts[0].startsWith('tmpfs') && !parts[0].startsWith('devtmpfs')) {
            disks.push({
              filesystem: parts[0],
              size: parts[1],
              used: parts[2],
              available: parts[3],
              usePct: parseInt(parts[4]) || 0,
              mount: parts[5]
            });
          }
        });
        resolve(disks);
      });
    }
  });
}

// Shared context object
const REPO_DIR = process.env.REPO_DIR || __dirname;
const ctx = {
  pool,
  dbQuery,
  io,
  execCommand,
  execFileSafe,
  REPO_DIR,
  requireAuth,
  requireAdmin,
  requireRole,
  requireAction,
  askAI,
  askAIJSON,
  getAICommand,
  getSystemInfo,
  sendNotification: (type, title, message, severity) => {
    const notif = sendNotification(type, title, message, severity);
    io.emit('notification', notif);
    return notif;
  },
  neuralCache,
  scannerEngine,
  osintEngine,
  threatIntel,
  logAction,
  getAuditLog,
  generateSecret,
  generateQRData,
  verifyTOTP,
  storeCredential,
  getCredential,
  listCredentials,
  deleteCredential,
  calculatePosture,

  // Callbacks populated by route modules
  getPostureScore: null,
  getRecentThreats: null,
  runClaude: null
};

// Health endpoint (minimal — don't leak version/internals to unauthenticated users)
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', ts: new Date().toISOString() });
});

// Load all route modules
console.log('\n  Vigil v1.0 — Loading routes...');
const routesDir = path.join(__dirname, 'routes');
if (fs.existsSync(routesDir)) {
  const routeFiles = fs.readdirSync(routesDir).filter(f => f.endsWith('.js'));
  routeFiles.forEach(file => {
    try {
      require('./routes/' + file)(app, ctx);
      console.log('  \u2713 routes/' + file);
    } catch (e) {
      console.error('  \u2717 routes/' + file + ':', e.message);
    }
  });
  console.log('  ' + routeFiles.length + ' route modules loaded\n');
} else {
  console.log('  No routes/ directory found\n');
}

// SPA fallback — serve index.html for non-API routes
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api/')) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    res.status(404).json({ error: 'Not found' });
  }
});

// Error handler
app.use((err, req, res, _next) => {
  console.error('Server error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// Socket.IO
io.on('connection', async (socket) => {
  console.log('  Socket connected:', socket.id);

  // Emit initial data
  const systemInfo = getSystemInfo();
  const postureScore = ctx.getPostureScore ? await ctx.getPostureScore() : { score: 0, grade: 'N/A' };
  const recentThreats = ctx.getRecentThreats ? ctx.getRecentThreats() : [];

  socket.emit('init', {
    system: systemInfo,
    posture: postureScore,
    threats: recentThreats,
    version: '1.0.0'
  });

  // Terminal + Claude events are handled by routes/claude.js (per-socket pty tracking)

  socket.on('refresh', () => {
    socket.emit('init', {
      system: getSystemInfo(),
      posture: ctx.getPostureScore ? ctx.getPostureScore() : { score: 0, grade: 'N/A' },
      threats: ctx.getRecentThreats ? ctx.getRecentThreats() : [],
      version: '1.0.0'
    });
  });

  socket.on('disconnect', () => {
    console.log('  Socket disconnected:', socket.id);
  });
});

// Intervals — metrics every 3s
const metricsInterval = setInterval(async () => {
  const cpuPct = getCpuUsage();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;

  io.emit('metrics', {
    system: {
      cpuPct,
      usedMemPct: Math.round((usedMem / totalMem) * 100),
      usedMemMB: Math.round(usedMem / 1024 / 1024),
      totalMemMB: Math.round(totalMem / 1024 / 1024),
      freeMemMB: Math.round(freeMem / 1024 / 1024),
      loadAvg: os.loadavg()
    },
    ts: new Date().toISOString()
  });
}, 3000);

// Threats every 10s
const threatsInterval = setInterval(() => {
  if (ctx.getRecentThreats) {
    io.emit('threats', { threats: ctx.getRecentThreats() });
  }
}, 10000);

// Posture every 30s
const postureInterval = setInterval(async () => {
  if (ctx.getPostureScore) {
    try {
      const posture = await ctx.getPostureScore();
      io.emit('posture', posture);
    } catch {}
  }
}, 30000);

// Clean expired sessions every 5 minutes
const sessionCleanInterval = setInterval(() => {
  cleanExpired();
}, 300000);

// Intel feed refresh every 15 minutes
const intelFeedsInterval = setInterval(async () => {
  try {
    const intel = require('./lib/intel-feeds');
    await intel.refreshAllFeeds(io);
  } catch {}
}, 900000);
// Initial feed refresh 30s after startup
setTimeout(async () => {
  try {
    const intel = require('./lib/intel-feeds');
    await intel.refreshAllFeeds(io);
    console.log('  Intel feeds: initial refresh complete');
  } catch {}
}, 30000);

// Graceful shutdown
function shutdown(signal) {
  console.log('\n  Vigil shutting down (' + signal + ')...');
  clearInterval(metricsInterval);
  clearInterval(threatsInterval);
  clearInterval(postureInterval);
  clearInterval(sessionCleanInterval);
  clearInterval(intelFeedsInterval);

  io.close();
  server.close(() => {
    if (pool) {
      pool.end().then(() => {
        console.log('  Database pool closed');
        process.exit(0);
      }).catch(() => process.exit(0));
    } else {
      process.exit(0);
    }
  });

  // Force exit after 10s
  setTimeout(() => {
    console.error('  Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Start server
const PORT = parseInt(process.env.VIGIL_PORT || '4100', 10);
server.listen(PORT, () => {
  console.log('  ========================================');
  console.log('  Vigil v1.0 — Security Operations Center');
  console.log('  ========================================');
  console.log('  Port:     ' + PORT);
  console.log('  Database: ' + (pool ? 'connected' : 'unavailable'));
  console.log('  AI:       ' + (getAICommand() || 'none'));
  console.log('  PID:      ' + process.pid);
  console.log('  ========================================');
  console.log('  http://localhost:' + PORT);
  console.log('');
});

module.exports = { app, server, io, ctx };
