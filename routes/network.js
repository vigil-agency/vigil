/**
 * Network Routes — Interfaces, connections, firewall, port scanning, DNS
 */
const fs = require('fs');
const path = require('path');
const dns = require('dns');

module.exports = function (app, ctx) {
  const { requireAuth, requireRole, requireAdmin, execCommand } = ctx;

  // GET /api/network/interfaces
  app.get('/api/network/interfaces', requireAuth, async (req, res) => {
    try {
      const os = require('os');
      const ifaces = os.networkInterfaces();
      const interfaces = [];

      for (const [name, addrs] of Object.entries(ifaces)) {
        for (const addr of addrs) {
          interfaces.push({
            name,
            address: addr.address,
            netmask: addr.netmask,
            family: addr.family,
            mac: addr.mac,
            internal: addr.internal,
            cidr: addr.cidr,
          });
        }
      }

      // Try to get more detail on Linux
      if (process.platform !== 'win32') {
        try {
          const result = await execCommand('ip -br addr 2>/dev/null || ifconfig 2>/dev/null | head -50', { timeout: 5000 });
          if (result.stdout.trim()) {
            res.json({ interfaces, raw: result.stdout.trim() });
            return;
          }
        } catch {}
      }

      res.json({ interfaces });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/network/connections
  app.get('/api/network/connections', requireAuth, async (req, res) => {
    try {
      if (process.platform === 'win32') {
        try {
          const result = await execCommand('netstat -an | findstr "ESTABLISHED LISTENING" 2>NUL', { timeout: 10000 });
          const lines = (result.stdout || '').trim().split('\n').filter(Boolean);
          const connections = lines.map(line => {
            const parts = line.trim().split(/\s+/);
            return { proto: parts[0], local: parts[1], foreign: parts[2], state: parts[3] || '' };
          });
          return res.json({ connections, total: connections.length });
        } catch {
          return res.json({ connections: [], error: 'Could not retrieve connections' });
        }
      }

      const result = await execCommand('ss -tunapl 2>/dev/null || netstat -tunapl 2>/dev/null', { timeout: 10000 });
      const lines = (result.stdout || '').trim().split('\n');
      const header = lines.shift();
      const connections = lines.filter(Boolean).map(line => {
        const parts = line.trim().split(/\s+/);
        return {
          proto: parts[0] || '',
          state: parts[1] || '',
          recvQ: parts[2] || '',
          sendQ: parts[3] || '',
          local: parts[4] || '',
          peer: parts[5] || '',
          process: parts[6] || '',
        };
      });

      res.json({ connections, total: connections.length });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/network/firewall
  app.get('/api/network/firewall', requireAuth, async (req, res) => {
    try {
      if (process.platform === 'win32') {
        return res.json({
          tool: 'windows',
          status: 'Check Windows Firewall via Control Panel',
          rules: [],
          message: 'Windows Firewall management is done through Windows Security settings.',
        });
      }

      // Try ufw first
      try {
        const ufwResult = await execCommand('ufw status verbose 2>/dev/null', { timeout: 5000 });
        const output = ufwResult.stdout.trim();
        if (output.includes('Status:')) {
          const active = output.includes('active') && !output.includes('inactive');
          const rules = [];
          const lines = output.split('\n');
          for (const line of lines) {
            const match = line.match(/^(.*?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT)?\s*(.*)/i);
            if (match) {
              rules.push({ to: match[1].trim(), action: match[2], direction: match[3] || '', from: match[4].trim() });
            }
          }
          return res.json({ tool: 'ufw', status: active ? 'active' : 'inactive', rules, raw: output });
        }
      } catch {}

      // Try iptables
      try {
        const iptResult = await execCommand('iptables -L -n --line-numbers 2>/dev/null', { timeout: 5000 });
        if (iptResult.stdout.trim()) {
          const rules = [];
          const lines = iptResult.stdout.trim().split('\n');
          for (const line of lines) {
            const match = line.match(/^(\d+)\s+(\w+)\s+(\w+)\s+--\s+(\S+)\s+(\S+)\s*(.*)/);
            if (match) {
              rules.push({ num: match[1], action: match[2], proto: match[3], source: match[4], dest: match[5], extra: match[6].trim() });
            }
          }
          return res.json({ tool: 'iptables', status: 'active', rules, raw: iptResult.stdout.trim().substring(0, 3000) });
        }
      } catch {}

      res.json({ tool: 'none', status: 'no firewall detected', rules: [] });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/network/scan — port scan
  app.post('/api/network/scan', requireRole('analyst'), async (req, res) => {
    try {
      const { target, ports } = req.body;
      if (!target) return res.status(400).json({ error: 'target required' });
      if (!/^[a-zA-Z0-9._\-:]+$/.test(target)) return res.status(400).json({ error: 'Invalid target format' });

      const portRange = ports || '1-1024';
      const cmd = `nmap -Pn -p ${portRange} --open -T4 ${target} 2>&1`;

      try {
        const result = await execCommand(cmd, { timeout: 120000 });
        const output = result.stdout || '';

        // Parse open ports
        const openPorts = [];
        const lines = output.split('\n');
        for (const line of lines) {
          const match = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/);
          if (match) {
            openPorts.push({
              port: parseInt(match[1]),
              protocol: match[2],
              service: match[3],
              version: match[4].trim() || '',
            });
          }
        }

        res.json({
          target,
          portRange,
          openPorts,
          total: openPorts.length,
          raw: output.substring(0, 5000),
          scannedAt: new Date().toISOString(),
        });
      } catch (e) {
        res.json({
          target,
          openPorts: [],
          error: 'nmap not available: ' + e.message,
          note: 'Install nmap: sudo apt install nmap',
        });
      }
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  //  ServerKit-inspired: Service Health, Hardening Audit, Fail2ban
  // ═══════════════════════════════════════════════════════════════════════
  const neuralCache = require('../lib/neural-cache');

  // GET /api/network/services — Service health monitoring
  app.get('/api/network/services', requireAuth, async (req, res) => {
    try {
      const cached = neuralCache.get('system:services');
      if (cached) return res.json(cached);

      if (process.platform === 'win32') {
        return res.json({ services: [], message: 'Service monitoring requires Linux (systemctl)' });
      }

      const serviceNames = [
        'nginx', 'apache2', 'httpd',
        'mysql', 'mysqld', 'mariadb', 'postgresql', 'postgres', 'redis', 'redis-server', 'mongod',
        'docker', 'containerd',
        'sshd', 'ssh',
        'fail2ban',
        'ufw',
        'clamav-daemon', 'clamav-freshclam',
        'cron', 'crond',
        'rsyslog', 'systemd-journald',
        'postfix', 'dovecot',
        'named', 'bind9', 'unbound',
      ];

      const services = [];
      const { execFileSafe } = ctx;

      // Check which services exist and their status (parallel, batched)
      const checks = serviceNames.map(async (name) => {
        try {
          const result = await execFileSafe('systemctl', ['is-active', name], { timeout: 3000 });
          const status = (result.stdout || '').trim();
          if (status === 'active' || status === 'inactive' || status === 'failed') {
            // Get more detail for active/failed
            let uptime = null;
            try {
              const info = await execFileSafe('systemctl', ['show', name, '--property=ActiveEnterTimestamp,MainPID,MemoryCurrent'], { timeout: 3000 });
              const props = {};
              (info.stdout || '').trim().split('\n').forEach(line => {
                const [k, ...v] = line.split('=');
                if (k) props[k.trim()] = v.join('=').trim();
              });
              if (props.ActiveEnterTimestamp && props.ActiveEnterTimestamp !== '') {
                uptime = props.ActiveEnterTimestamp;
              }
              return { name, status, pid: props.MainPID || null, since: uptime, memory: props.MemoryCurrent || null };
            } catch {}
            return { name, status };
          }
        } catch (e) {
          // Exit code 3 = inactive, 4 = not found
          const stderr = (e.stderr || '').toLowerCase();
          const stdout = (e.stdout || '').trim();
          if (stdout === 'inactive') return { name, status: 'inactive' };
          if (stdout === 'failed') return { name, status: 'failed' };
          // Not found / not installed — skip
        }
        return null;
      });

      const results = await Promise.allSettled(checks);
      results.forEach(r => {
        if (r.status === 'fulfilled' && r.value) services.push(r.value);
      });

      // Sort: active first, then failed, then inactive
      const order = { active: 0, failed: 1, inactive: 2 };
      services.sort((a, b) => (order[a.status] || 3) - (order[b.status] || 3));

      const result = {
        services,
        active: services.filter(s => s.status === 'active').length,
        inactive: services.filter(s => s.status === 'inactive').length,
        failed: services.filter(s => s.status === 'failed').length,
        total: services.length,
      };

      neuralCache.set('system:services', result, 30000); // 30s cache
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/network/hardening — Security hardening audit (ServerKit-inspired)
  app.get('/api/network/hardening', requireRole('analyst'), async (req, res) => {
    try {
      const cached = neuralCache.get('system:hardening');
      if (cached) return res.json(cached);

      if (process.platform === 'win32') {
        return res.json({ checks: [], score: 0, message: 'Hardening audit requires Linux' });
      }

      const checks = [];
      let totalPoints = 0;
      let earnedPoints = 0;

      async function check(name, category, weight, testFn) {
        totalPoints += weight;
        try {
          const result = await testFn();
          const passed = !!result.passed;
          if (passed) earnedPoints += weight;
          checks.push({ name, category, weight, passed, detail: result.detail || '', severity: result.severity || 'medium' });
        } catch (e) {
          checks.push({ name, category, weight, passed: false, detail: 'Check failed: ' + e.message, severity: 'low' });
        }
      }

      // ── SSH Hardening ──────────────────────────────────────────
      await check('SSH root login disabled', 'ssh', 10, async () => {
        const r = await execCommand('grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null', { timeout: 3000 });
        const val = (r.stdout || '').trim().split(/\s+/)[1] || '';
        return { passed: val.toLowerCase() === 'no', detail: val ? 'PermitRootLogin=' + val : 'Not configured (defaults vary)', severity: 'high' };
      });

      await check('SSH password auth disabled', 'ssh', 8, async () => {
        const r = await execCommand('grep -i "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null', { timeout: 3000 });
        const val = (r.stdout || '').trim().split(/\s+/)[1] || '';
        return { passed: val.toLowerCase() === 'no', detail: val ? 'PasswordAuthentication=' + val : 'Not configured', severity: 'high' };
      });

      await check('SSH port non-default', 'ssh', 5, async () => {
        const r = await execCommand('grep -i "^Port" /etc/ssh/sshd_config 2>/dev/null', { timeout: 3000 });
        const val = (r.stdout || '').trim().split(/\s+/)[1] || '22';
        return { passed: val !== '22', detail: 'SSH port: ' + val, severity: 'low' };
      });

      await check('SSH protocol 2 only', 'ssh', 5, async () => {
        const r = await execCommand('grep -i "^Protocol" /etc/ssh/sshd_config 2>/dev/null', { timeout: 3000 });
        const val = (r.stdout || '').trim().split(/\s+/)[1] || '2';
        return { passed: val === '2' || val === '', detail: val ? 'Protocol ' + val : 'Default (2)', severity: 'medium' };
      });

      // ── Firewall ──────────────────────────────────────────────
      await check('Firewall active', 'firewall', 10, async () => {
        try {
          const r = await execCommand('ufw status 2>/dev/null || firewall-cmd --state 2>/dev/null', { timeout: 5000 });
          const out = (r.stdout || '').toLowerCase();
          const active = out.includes('status: active') || out.includes('running');
          return { passed: active, detail: active ? 'Firewall is active' : 'Firewall is inactive', severity: 'critical' };
        } catch { return { passed: false, detail: 'No firewall detected', severity: 'critical' }; }
      });

      // ── Fail2ban ──────────────────────────────────────────────
      await check('Fail2ban installed', 'ids', 8, async () => {
        try {
          const r = await execCommand('fail2ban-client --version 2>/dev/null', { timeout: 3000 });
          return { passed: r.code === 0, detail: (r.stdout || '').trim().split('\n')[0] || 'installed', severity: 'medium' };
        } catch { return { passed: false, detail: 'fail2ban not installed', severity: 'medium' }; }
      });

      await check('Fail2ban service running', 'ids', 7, async () => {
        try {
          const r = await execCommand('systemctl is-active fail2ban 2>/dev/null', { timeout: 3000 });
          const active = (r.stdout || '').trim() === 'active';
          return { passed: active, detail: active ? 'fail2ban is running' : 'fail2ban is not running', severity: 'medium' };
        } catch { return { passed: false, detail: 'Cannot check fail2ban status', severity: 'low' }; }
      });

      // ── System Updates ────────────────────────────────────────
      await check('System packages up to date', 'updates', 8, async () => {
        try {
          const r = await execCommand('apt list --upgradable 2>/dev/null | grep -c upgradable || echo 0', { timeout: 10000 });
          const count = parseInt((r.stdout || '0').trim()) || 0;
          return { passed: count <= 5, detail: count + ' packages upgradable', severity: count > 20 ? 'high' : 'medium' };
        } catch { return { passed: true, detail: 'Cannot check (non-apt system)', severity: 'low' }; }
      });

      await check('Unattended upgrades enabled', 'updates', 6, async () => {
        try {
          const r = await execCommand('dpkg -l unattended-upgrades 2>/dev/null | grep -c "^ii" || echo 0', { timeout: 3000 });
          const installed = parseInt((r.stdout || '0').trim()) > 0;
          return { passed: installed, detail: installed ? 'unattended-upgrades installed' : 'Not installed', severity: 'low' };
        } catch { return { passed: false, detail: 'Cannot check', severity: 'low' }; }
      });

      // ── File Permissions ──────────────────────────────────────
      await check('/etc/shadow permissions', 'files', 7, async () => {
        const r = await execCommand('stat -c "%a" /etc/shadow 2>/dev/null', { timeout: 3000 });
        const perms = (r.stdout || '').trim();
        const ok = perms === '640' || perms === '600' || perms === '000';
        return { passed: ok, detail: 'Permissions: ' + (perms || 'unknown'), severity: 'high' };
      });

      await check('/etc/passwd permissions', 'files', 5, async () => {
        const r = await execCommand('stat -c "%a" /etc/passwd 2>/dev/null', { timeout: 3000 });
        const perms = (r.stdout || '').trim();
        const ok = perms === '644';
        return { passed: ok, detail: 'Permissions: ' + (perms || 'unknown'), severity: 'medium' };
      });

      // ── Kernel / System ───────────────────────────────────────
      await check('Address space layout randomization (ASLR)', 'kernel', 6, async () => {
        const r = await execCommand('cat /proc/sys/kernel/randomize_va_space 2>/dev/null', { timeout: 3000 });
        const val = (r.stdout || '').trim();
        return { passed: val === '2', detail: 'ASLR level: ' + (val || 'unknown') + ' (2=full)', severity: 'medium' };
      });

      await check('Core dumps disabled', 'kernel', 4, async () => {
        const r = await execCommand('ulimit -c 2>/dev/null', { timeout: 3000 });
        const val = (r.stdout || '').trim();
        return { passed: val === '0', detail: 'Core dump limit: ' + (val || 'unknown'), severity: 'low' };
      });

      await check('No world-writable files in /etc', 'files', 5, async () => {
        const r = await execCommand('find /etc -maxdepth 2 -perm -o+w -type f 2>/dev/null | head -5', { timeout: 5000 });
        const files = (r.stdout || '').trim().split('\n').filter(Boolean);
        return { passed: files.length === 0, detail: files.length ? files.length + ' world-writable files: ' + files.slice(0, 3).join(', ') : 'None found', severity: 'medium' };
      });

      await check('No empty password accounts', 'accounts', 8, async () => {
        const r = await execCommand('awk -F: \'($2 == "") {print $1}\' /etc/shadow 2>/dev/null', { timeout: 3000 });
        const accounts = (r.stdout || '').trim().split('\n').filter(Boolean);
        return { passed: accounts.length === 0, detail: accounts.length ? 'Empty password: ' + accounts.join(', ') : 'No accounts with empty passwords', severity: 'critical' };
      });

      // Score calculation
      const score = totalPoints > 0 ? Math.round((earnedPoints / totalPoints) * 100) : 0;
      const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 50 ? 'D' : 'F';
      const passed = checks.filter(c => c.passed).length;
      const failed = checks.filter(c => !c.passed).length;

      const result = { checks, score, grade, passed, failed, total: checks.length, earnedPoints, totalPoints };

      // AI analysis if available
      if (ctx.askAI) {
        try {
          const failedChecks = checks.filter(c => !c.passed).map(c => c.name + ' (' + c.severity + '): ' + c.detail).join('\n');
          const prompt = `You are a Linux server hardening specialist. Give a concise assessment (4-6 sentences) of this server's security posture.

Score: ${score}/100 (Grade ${grade})
Passed: ${passed}/${checks.length} checks
Failed checks:
${failedChecks || 'None'}

Assess: overall hardening level, most critical gaps, and top 3 prioritized remediation steps. Be specific.`;
          result.analysis = await ctx.askAI(prompt, { timeout: 20000 });
        } catch {}
      }

      neuralCache.set('system:hardening', result, 300000); // 5min cache
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/network/fail2ban — Fail2ban status (ServerKit-inspired)
  app.get('/api/network/fail2ban', requireAuth, async (req, res) => {
    try {
      const cached = neuralCache.get('system:fail2ban');
      if (cached) return res.json(cached);

      if (process.platform === 'win32') {
        return res.json({ installed: false, message: 'Fail2ban requires Linux' });
      }

      // Check if fail2ban is installed
      try {
        await execCommand('which fail2ban-client 2>/dev/null', { timeout: 3000 });
      } catch {
        return res.json({ installed: false, message: 'fail2ban is not installed. Install with: apt install fail2ban' });
      }

      const result = { installed: true, jails: [], totalBanned: 0 };

      // Get jail list
      try {
        const r = await execCommand('fail2ban-client status 2>/dev/null', { timeout: 5000 });
        const jailMatch = (r.stdout || '').match(/Jail list:\s*(.+)/);
        if (jailMatch) {
          const jailNames = jailMatch[1].split(',').map(j => j.trim()).filter(Boolean);

          // Get status of each jail
          for (const jail of jailNames.slice(0, 10)) {
            try {
              const jr = await execCommand(`fail2ban-client status ${jail} 2>/dev/null`, { timeout: 3000 });
              const output = jr.stdout || '';
              const totalFailed = (output.match(/Total failed:\s*(\d+)/) || [])[1] || '0';
              const totalBanned = (output.match(/Total banned:\s*(\d+)/) || [])[1] || '0';
              const currentBanned = (output.match(/Currently banned:\s*(\d+)/) || [])[1] || '0';
              const bannedIPs = (output.match(/Banned IP list:\s*(.+)/) || [])[1] || '';

              result.jails.push({
                name: jail,
                totalFailed: parseInt(totalFailed),
                totalBanned: parseInt(totalBanned),
                currentBanned: parseInt(currentBanned),
                bannedIPs: bannedIPs.trim().split(/\s+/).filter(Boolean),
              });
              result.totalBanned += parseInt(currentBanned);
            } catch {}
          }
        }
      } catch {}

      // Get recent failed login attempts
      try {
        const r = await execCommand('lastb -n 20 2>/dev/null | head -20', { timeout: 5000 });
        result.failedLogins = (r.stdout || '').trim().split('\n').filter(l => l.trim() && !l.includes('btmp begins')).map(line => {
          const parts = line.trim().split(/\s+/);
          return { user: parts[0] || '', terminal: parts[1] || '', source: parts[2] || '', time: parts.slice(3).join(' ') };
        }).slice(0, 15);
      } catch {
        result.failedLogins = [];
      }

      neuralCache.set('system:fail2ban', result, 60000); // 1min cache
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/network/dns — DNS lookup
  app.get('/api/network/dns', requireAuth, (req, res) => {
    const domain = req.query.domain;
    if (!domain) return res.status(400).json({ error: 'domain query parameter required' });
    if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
      return res.status(400).json({ error: 'Invalid domain format' });
    }

    const results = {};
    const lookups = [
      new Promise(resolve => {
        dns.resolve4(domain, (err, addrs) => { results.A = err ? [] : addrs; resolve(); });
      }),
      new Promise(resolve => {
        dns.resolve6(domain, (err, addrs) => { results.AAAA = err ? [] : addrs; resolve(); });
      }),
      new Promise(resolve => {
        dns.resolveMx(domain, (err, addrs) => { results.MX = err ? [] : addrs; resolve(); });
      }),
      new Promise(resolve => {
        dns.resolveNs(domain, (err, addrs) => { results.NS = err ? [] : addrs; resolve(); });
      }),
      new Promise(resolve => {
        dns.resolveTxt(domain, (err, addrs) => { results.TXT = err ? [] : addrs.map(r => r.join('')); resolve(); });
      }),
      new Promise(resolve => {
        dns.resolveCname(domain, (err, addrs) => { results.CNAME = err ? [] : addrs; resolve(); });
      }),
    ];

    Promise.all(lookups).then(() => {
      res.json({ domain, records: results });
    });
  });
};
