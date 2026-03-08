/**
 * Scan API Routes — Bridge between frontend views and scanner-engine
 * Maps the URLs the frontend calls to the actual scanner implementations.
 * Provides Node.js native fallbacks when CLI tools aren't installed.
 */
const net = require('net');
const dns = require('dns');
const tls = require('tls');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DATA = path.join(__dirname, '..', 'data');
const SCANS_PATH = path.join(DATA, 'scans.json');
const SSL_DOMAINS_PATH = path.join(DATA, 'ssl-domains.json');

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

// ── Node.js native port scanner (no nmap needed) ────────────────────────
function scanPort(host, port, timeout) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    socket.on('connect', () => { socket.destroy(); resolve({ port, state: 'open' }); });
    socket.on('timeout', () => { socket.destroy(); resolve(null); });
    socket.on('error', () => { socket.destroy(); resolve(null); });
    socket.connect(port, host);
  });
}

async function nativeScanPorts(host, ports, concurrency = 100) {
  const results = [];
  for (let i = 0; i < ports.length; i += concurrency) {
    const batch = ports.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(p => scanPort(host, p, 1500))
    );
    results.push(...batchResults.filter(Boolean));
  }
  return results;
}

// Well-known services
const SERVICES = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain', 80: 'http',
  110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn', 143: 'imap',
  443: 'https', 445: 'microsoft-ds', 993: 'imaps', 995: 'pop3s', 1433: 'ms-sql',
  1521: 'oracle', 3306: 'mysql', 3389: 'ms-wbt-server', 5432: 'postgresql',
  5900: 'vnc', 6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt',
  9200: 'elasticsearch', 27017: 'mongodb',
};

// ── Node.js native SSL checker (no openssl needed) ──────────────────────
function nativeSSLCheck(domain, port = 443) {
  return new Promise(resolve => {
    const socket = tls.connect({ host: domain, port, servername: domain, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate(true);
      socket.end();
      if (!cert || !cert.subject) {
        return resolve({ error: 'No certificate returned' });
      }
      const now = new Date();
      const validFrom = new Date(cert.valid_from);
      const validTo = new Date(cert.valid_to);
      const daysLeft = Math.ceil((validTo - now) / 86400000);
      const expired = daysLeft < 0;

      let grade = 'A';
      if (expired) grade = 'F';
      else if (daysLeft < 7) grade = 'D';
      else if (daysLeft < 30) grade = 'C';
      else if (daysLeft < 90) grade = 'B';

      const san = cert.subjectaltname
        ? cert.subjectaltname.split(',').map(s => s.trim().replace('DNS:', '')).filter(Boolean)
        : [];

      resolve({
        domain,
        checked: true,
        subject: cert.subject.CN || Object.values(cert.subject).join(', '),
        issuer: cert.issuer ? (cert.issuer.O || cert.issuer.CN || Object.values(cert.issuer).join(', ')) : 'unknown',
        validFrom: validFrom.toISOString(),
        expiry: validTo.toISOString(),
        daysLeft,
        expired,
        grade,
        san,
        serialNumber: cert.serialNumber || null,
        fingerprint: cert.fingerprint256 || cert.fingerprint || null,
        protocol: socket.getProtocol ? socket.getProtocol() : null,
        cipher: socket.getCipher ? socket.getCipher() : null,
      });
    });
    socket.setTimeout(10000);
    socket.on('timeout', () => { socket.destroy(); resolve({ domain, error: 'Connection timed out', grade: 'F' }); });
    socket.on('error', (e) => { resolve({ domain, error: e.message, grade: 'F' }); });
  });
}

// ── Validate target ─────────────────────────────────────────────────────
function isValidTarget(target) {
  if (!target || typeof target !== 'string' || target.length > 253) return false;
  // IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(target))
    return target.split('.').every(p => { const n = parseInt(p); return n >= 0 && n <= 255; });
  // IPv4 CIDR
  if (/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(target)) return true;
  // Hostname
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(target)) return true;
  return false;
}

function isValidDomain(d) {
  return d && typeof d === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(d);
}

function isValidURL(u) {
  if (!u || typeof u !== 'string') return false;
  try { const url = new URL(u); return ['http:', 'https:'].includes(url.protocol); }
  catch { return false; }
}

function expandPorts(scanType, customRange) {
  const TOP_100 = [7,20,21,22,23,25,43,53,67,68,69,79,80,88,110,111,113,119,123,135,137,139,143,161,179,194,201,311,389,427,443,445,465,500,513,514,515,543,544,548,554,587,631,636,646,873,990,993,995,1025,1026,1027,1028,1029,1080,1110,1433,1434,1521,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3001,3128,3306,3389,3986,4100,4899,5000,5001,5060,5100,5190,5357,5432,5631,5666,5800,5900,5901,6000,6001,6379,6646,7070,8000,8008,8080,8443,8888,9090,9100,9200,10000,27017,32768,49152,49153,49154];
  switch (scanType) {
    case 'full': {
      const ports = [];
      for (let i = 1; i <= 65535; i++) ports.push(i);
      return ports;
    }
    case 'stealth':
    case 'quick':
    default:
      if (customRange) {
        const ports = [];
        customRange.split(',').forEach(part => {
          part = part.trim();
          if (part.includes('-')) {
            const [s, e] = part.split('-').map(Number);
            if (s && e) for (let i = s; i <= Math.min(e, 65535); i++) ports.push(i);
          } else {
            const p = parseInt(part);
            if (p >= 1 && p <= 65535) ports.push(p);
          }
        });
        return ports.length > 0 ? ports : TOP_100;
      }
      return TOP_100;
  }
}


module.exports = function (app, ctx) {
  const { requireAuth, requireRole, scannerEngine } = ctx;

  // ════════════════════════════════════════════════════════════════════════
  // POST /api/scan/ports — Port Scanner view
  // ════════════════════════════════════════════════════════════════════════
  app.post('/api/scan/ports', requireAuth, async (req, res) => {
    try {
      const { target, scan_type, port_range } = req.body;
      if (!target) return res.status(400).json({ error: 'target required' });
      if (!isValidTarget(target)) return res.status(400).json({ error: 'Invalid target format' });

      const ports = expandPorts(scan_type, port_range);

      // Try nmap first via scanner-engine
      const nmapResult = await scannerEngine.runNmap(target, {
        ports: port_range || (scan_type === 'full' ? '1-65535' : '1-1000'),
        serviceVersion: true,
        timing: scan_type === 'stealth' ? 'T2' : 'T4',
      });

      if (nmapResult.available && !nmapResult.error) {
        const openPorts = nmapResult.findings.map(f => {
          const portMatch = f.title.match(/port (\d+)\/(tcp|udp) \((\w+)\)/);
          return {
            port: portMatch ? parseInt(portMatch[1]) : 0,
            protocol: portMatch ? portMatch[2] : 'tcp',
            state: 'open',
            service: portMatch ? portMatch[3] : f.title,
            version: f.description || '',
          };
        });
        saveScanResult('nmap', target, openPorts);
        return res.json({ target, ports: openPorts, total: openPorts.length, scanner: 'nmap', scannedAt: new Date().toISOString() });
      }

      // Fallback: Node.js native TCP scan
      const openPorts = await nativeScanPorts(target, ports.length > 1000 ? ports.slice(0, 1000) : ports);
      const results = openPorts.map(p => ({
        port: p.port,
        protocol: 'tcp',
        state: 'open',
        service: SERVICES[p.port] || 'unknown',
        version: '',
      }));

      saveScanResult('native-tcp', target, results);
      res.json({
        target,
        ports: results,
        total: results.length,
        scanner: 'native-tcp',
        note: nmapResult.error || 'nmap not available — using Node.js TCP scanner',
        scannedAt: new Date().toISOString(),
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ════════════════════════════════════════════════════════════════════════
  // POST /api/scan/nuclei — Vulnerability Scanner view
  // ════════════════════════════════════════════════════════════════════════
  app.post('/api/scan/nuclei', requireAuth, async (req, res) => {
    try {
      const { target, severity, category } = req.body;
      if (!target) return res.status(400).json({ error: 'target required' });

      const sevMap = { critical: 'critical', high: 'critical,high', medium: 'critical,high,medium', low: 'critical,high,medium,low', info: 'critical,high,medium,low,info' };
      const nucleiResult = await scannerEngine.runNuclei(target, {
        severity: sevMap[severity] || 'critical,high,medium',
        tags: category !== 'all' ? category : undefined,
      });

      if (nucleiResult.available && !nucleiResult.error) {
        const findings = nucleiResult.findings.map(f => ({
          severity: f.severity,
          title: f.title,
          name: f.title,
          template_id: f.templateId || '',
          description: f.description,
          matched_at: f.target,
          target: f.target,
          reference: f.remediation || '',
          cve: f.cve || null,
        }));
        saveScanResult('nuclei', target, findings);
        return res.json({ target, findings, total: findings.length, scanner: 'nuclei' });
      }

      // Nuclei not installed — run native vulnerability assessment
      // NOTE: Web Scanner (/api/scan/web) already covers headers + exposed paths.
      // This scanner focuses on: SSL/TLS vulns, CORS, HTTP methods, cookies,
      // tech fingerprinting, port services, and info leakage.
      const nativeFindings = [];
      const resolvedUrl = isValidURL(target) ? target : 'https://' + target;
      const hostname = isValidURL(target) ? new URL(target).hostname : target;

      // Run checks in parallel where possible
      await Promise.all([
        // 1. SSL/TLS vulnerability assessment
        nativeSSLCheck(hostname).then(ssl => {
          if (!ssl || ssl.error) {
            nativeFindings.push(mkFinding('medium', 'SSL Connection Failed', 'native-ssl', `Could not establish TLS connection to ${hostname}: ${ssl?.error || 'unknown error'}.\n\nRemediation: Verify the server has a valid TLS certificate and is accepting connections on port 443.`, target));
            return;
          }
          if (ssl.expired) {
            nativeFindings.push(mkFinding('critical', 'SSL Certificate Expired', 'native-ssl-expiry', `Certificate for ${hostname} expired on ${ssl.expiry}.\n\nRemediation: Renew the SSL certificate immediately.`, target));
          } else if (ssl.daysLeft < 30) {
            nativeFindings.push(mkFinding('high', 'SSL Certificate Expiring Soon', 'native-ssl-expiry', `Certificate expires in ${ssl.daysLeft} days (${ssl.expiry}).\n\nRemediation: Renew before expiration.`, target));
          }
          const proto = typeof ssl.protocol === 'string' ? ssl.protocol : (ssl.protocol?.name || '');
          if (proto && /TLSv1\.[01]|SSLv3/.test(proto)) {
            nativeFindings.push(mkFinding('high', 'Weak TLS Protocol: ' + proto, 'native-ssl-protocol', `Server negotiated deprecated protocol ${proto}.\n\nRemediation: Disable TLS 1.0, TLS 1.1, and SSLv3. Require TLS 1.2+.`, target));
          }
          const cipher = typeof ssl.cipher === 'string' ? ssl.cipher : (ssl.cipher?.name || '');
          if (cipher && /RC4|DES|MD5|NULL|EXPORT|anon/i.test(cipher)) {
            nativeFindings.push(mkFinding('high', 'Weak Cipher Suite: ' + cipher, 'native-ssl-cipher', `Server uses weak cipher ${cipher}.\n\nRemediation: Disable weak ciphers. Use AEAD suites (AES-GCM, ChaCha20).`, target));
          }
          if (ssl.san && ssl.san.length === 0) {
            nativeFindings.push(mkFinding('medium', 'No Subject Alternative Names', 'native-ssl-san', `Certificate has no SANs. Modern browsers require SAN for validation.\n\nRemediation: Reissue certificate with proper SAN entries.`, target));
          }
          if (!isValidURL(target) || new URL(target).protocol === 'http:') {
            nativeFindings.push(mkFinding('high', 'No HTTPS — Unencrypted Transport', 'native-no-tls', 'Target uses plain HTTP. All traffic is in cleartext.\n\nRemediation: Configure HTTPS with a valid TLS certificate.', target));
          }
        }).catch(() => {}),

        // 2. CORS, HTTP methods, cookies, tech fingerprint (single request)
        httpVulnCheck(resolvedUrl, target, nativeFindings).catch(() => {}),

        // 3. Quick port scan for risky services (top 20 dangerous ports)
        portVulnCheck(hostname, target, nativeFindings).catch(() => {}),
      ]);

      // Sort by severity
      const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      nativeFindings.sort((a, b) => (sevOrder[a.severity] || 4) - (sevOrder[b.severity] || 4));

      saveScanResult('native-vuln', target, nativeFindings);
      res.json({
        target,
        findings: nativeFindings,
        total: nativeFindings.length,
        scanner: 'native',
        note: 'Scanned with built-in vulnerability checks (SSL/TLS, CORS, HTTP methods, cookies, open services, tech fingerprint). Install nuclei for CVE-level scanning.',
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ════════════════════════════════════════════════════════════════════════
  // POST /api/scan/web — Web Application Scanner view
  // ════════════════════════════════════════════════════════════════════════
  app.post('/api/scan/web', requireAuth, async (req, res) => {
    try {
      const { target, scan_type } = req.body;
      if (!target) return res.status(400).json({ error: 'target required' });
      if (!isValidURL(target)) return res.status(400).json({ error: 'Invalid URL format. Use http:// or https://' });

      // Web scanner using built-in HTTP checks
      const url = new URL(target);
      const findings = [];

      // Check security headers
      const headerChecks = await checkSecurityHeaders(target);
      findings.push(...headerChecks);

      // Check for common exposed paths
      if (scan_type === 'active' || scan_type === 'spider') {
        const pathChecks = await checkExposedPaths(target);
        findings.push(...pathChecks);
      }

      // WAF detection (passive by default, active if scan_type is active)
      const wafProbeMode = scan_type === 'active' ? 'active' : 'passive';
      const wafResult = await detectWAF(target, wafProbeMode);

      // Also try nuclei if available
      const nucleiResult = await scannerEngine.runNuclei(target, { severity: 'critical,high,medium' });
      if (nucleiResult.available && nucleiResult.findings.length > 0) {
        nucleiResult.findings.forEach(f => {
          findings.push({
            risk: f.severity,
            severity: f.severity,
            name: f.title,
            title: f.title,
            description: f.description,
            url: f.target || target,
            solution: f.remediation || '',
            reference: f.cve || '',
          });
        });
      }

      saveScanResult('web', target, findings.concat(wafResult.findings));
      res.json({
        target,
        alerts: findings,
        findings,
        wafDetection: wafResult,
        total: findings.length,
        scanner: nucleiResult.available ? 'nuclei+headers+waf' : 'headers+waf',
        scannedAt: new Date().toISOString(),
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ════════════════════════════════════════════════════════════════════════
  // POST /api/scan/container — Container Security view
  // Trivy if available, else native analysis + AI
  // ════════════════════════════════════════════════════════════════════════
  app.post('/api/scan/container', requireAuth, async (req, res) => {
    try {
      const { image } = req.body;
      if (!image) return res.status(400).json({ error: 'image required' });

      // Try Trivy first
      const trivyResult = await scannerEngine.runTrivy(image, 'image');

      if (trivyResult.available && !trivyResult.error) {
        const vulnerabilities = trivyResult.findings.map(f => ({
          severity: f.severity,
          cve_id: f.cve,
          vulnerability_id: f.cve,
          pkg_name: f.title.split(':')[0]?.trim() || '',
          package: f.title.split(':')[0]?.trim() || '',
          installed_version: '',
          fixed_version: f.remediation ? f.remediation.replace(/^Update .+ to /, '') : 'N/A',
          description: f.description,
        }));
        saveScanResult('trivy', image, vulnerabilities.map(v => ({ id: crypto.randomUUID(), title: v.cve_id || 'Container vulnerability', severity: v.severity, type: 'container', status: 'open', description: v.description || '' })));
        return res.json({ image, vulnerabilities, total: vulnerabilities.length, scanner: 'trivy' });
      }

      // Fallback: native analysis + AI
      if (ctx.nativeContainerScan) {
        const native = await ctx.nativeContainerScan(image);
        saveScanResult('native-container', image, native.findings.map(f => ({ id: crypto.randomUUID(), title: f.title, severity: f.severity, type: 'container', status: 'open', description: f.description || '' })));
        return res.json({ image, vulnerabilities: native.findings, total: native.findings.length, scanner: 'native', analysis: native.analysis, metadata: native.metadata });
      }

      res.json({ image, vulnerabilities: [], total: 0, scanner: 'none', error: 'No scanner available', note: 'Install trivy for deep container scanning' });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ════════════════════════════════════════════════════════════════════════
  // POST /api/scan/ports/save — Save port scan results
  // ════════════════════════════════════════════════════════════════════════
  app.post('/api/scan/ports/save', requireAuth, (req, res) => {
    saveScanResult('nmap', req.body.target || 'unknown', req.body.ports || req.body.results || []);
    res.json({ success: true });
  });

  // ════════════════════════════════════════════════════════════════════════
  // POST /api/dns/lookup — DNS Security view
  // ════════════════════════════════════════════════════════════════════════

  // Check DNSSEC using dig +dnssec (falls back to DNSKEY query via Node.js)
  async function checkDNSSEC(domain) {
    // Try dig +dnssec first (most accurate)
    if (ctx.execCommand) {
      const cmd = process.platform === 'win32'
        ? `nslookup -type=DNSKEY ${domain} 2>nul`
        : `dig +dnssec +short ${domain} DNSKEY 2>/dev/null`;
      const { stdout, code } = await ctx.execCommand(cmd, { timeout: 8000 });
      if (code === 0 && stdout.trim()) {
        // dig: presence of DNSKEY records + RRSIG means DNSSEC is configured
        const hasKeys = stdout.includes('256 3') || stdout.includes('257 3') || stdout.toLowerCase().includes('dnskey');
        if (hasKeys) return { enabled: true, status: 'valid', detail: 'DNSKEY records found — domain is DNSSEC-signed' };
      }
      // Try checking for RRSIG on A records
      if (process.platform !== 'win32') {
        const rrsig = await ctx.execCommand(`dig +dnssec +short ${domain} A 2>/dev/null`, { timeout: 8000 });
        if (rrsig.code === 0 && rrsig.stdout.includes('RRSIG')) {
          return { enabled: true, status: 'valid', detail: 'RRSIG signatures present on A records' };
        }
      }
    }

    // Fallback: no dig available and Node.js dns doesn't support DNSKEY rrtype
    return { enabled: false, status: 'unknown', detail: 'Install dig (dnsutils) for DNSSEC verification' };
  }

  // Resolve CAA records
  function resolveCAA(domain) {
    return new Promise(resolve => {
      dns.resolveCaa(domain, (err, records) => {
        if (err || !records || records.length === 0) {
          resolve([]);
        } else {
          resolve(records.map(r => ({
            critical: r.critical || 0,
            tag: r.issue ? 'issue' : r.issuewild ? 'issuewild' : r.iodef ? 'iodef' : (r.tag || 'unknown'),
            value: r.issue || r.issuewild || r.iodef || r.value || JSON.stringify(r),
          })));
        }
      });
    });
  }

  // Check for DMARC record at _dmarc subdomain
  function checkDMARC(domain) {
    return new Promise(resolve => {
      dns.resolveTxt('_dmarc.' + domain, (err, records) => {
        if (err || !records) { resolve(null); return; }
        const flat = records.map(r => Array.isArray(r) ? r.join('') : String(r));
        const dmarc = flat.find(r => r.startsWith('v=DMARC1'));
        resolve(dmarc || null);
      });
    });
  }

  app.post('/api/dns/lookup', requireAuth, async (req, res) => {
    try {
      const { domain } = req.body;
      if (!domain) return res.status(400).json({ error: 'domain required' });
      if (!isValidDomain(domain)) return res.status(400).json({ error: 'Invalid domain format' });

      const records = {};

      // Resolve all record types + DNSSEC + CAA + DMARC in parallel
      const [dnssecResult, caaRecords, dmarcRecord] = await Promise.all([
        checkDNSSEC(domain),
        resolveCAA(domain),
        checkDMARC(domain),
        new Promise(resolve => {
          dns.resolve4(domain, { ttl: true }, (err, addrs) => {
            records.A = err ? [] : addrs.map(a => typeof a === 'object' ? { type: 'A', value: a.address, address: a.address, ttl: a.ttl } : { type: 'A', value: a, address: a, ttl: '--' });
            resolve();
          });
        }),
        new Promise(resolve => {
          dns.resolve6(domain, { ttl: true }, (err, addrs) => {
            records.AAAA = err ? [] : addrs.map(a => typeof a === 'object' ? { type: 'AAAA', value: a.address, address: a.address, ttl: a.ttl } : { type: 'AAAA', value: a, address: a, ttl: '--' });
            resolve();
          });
        }),
        new Promise(resolve => {
          dns.resolveMx(domain, (err, addrs) => {
            records.MX = err ? [] : addrs.map(a => ({ priority: a.priority, exchange: a.exchange, value: a.exchange, ttl: '--' }));
            resolve();
          });
        }),
        new Promise(resolve => {
          dns.resolveNs(domain, (err, addrs) => {
            records.NS = err ? [] : addrs.map(a => ({ value: a, ttl: '--' }));
            resolve();
          });
        }),
        new Promise(resolve => {
          dns.resolveTxt(domain, (err, addrs) => {
            records.TXT = err ? [] : addrs.map(r => ({ value: Array.isArray(r) ? r.join('') : String(r) }));
            resolve();
          });
        }),
        new Promise(resolve => {
          dns.resolveCname(domain, (err, addrs) => {
            records.CNAME = err ? [] : addrs.map(a => ({ name: domain, value: a, ttl: '--' }));
            resolve();
          });
        }),
        new Promise(resolve => {
          dns.resolveSoa(domain, (err, soa) => {
            records.SOA = err || !soa ? [] : [{
              nsname: soa.nsname, primary: soa.nsname,
              hostmaster: soa.hostmaster, admin: soa.hostmaster,
              serial: soa.serial, refresh: soa.refresh, retry: soa.retry,
              expire: soa.expire, minttl: soa.minttl,
            }];
            resolve();
          });
        }),
      ]);

      // Add CAA to records
      records.CAA = caaRecords;

      // Security scoring
      const totalRecords = Object.values(records).reduce((sum, arr) => sum + arr.length, 0);
      let score = 30; // baseline for resolving
      const issues = [];
      const strengths = [];

      // SPF check (in TXT records)
      const hasSPF = (records.TXT || []).some(r => (r.value || '').includes('v=spf1'));
      if (hasSPF) { score += 10; strengths.push('SPF record configured'); }
      else { issues.push('No SPF record — vulnerable to email spoofing'); }

      // DMARC check (dedicated _dmarc subdomain query)
      if (dmarcRecord) {
        score += 10;
        strengths.push('DMARC policy configured');
        // Check DMARC policy strength
        if (dmarcRecord.includes('p=reject')) { score += 5; strengths.push('DMARC policy set to reject (strongest)'); }
        else if (dmarcRecord.includes('p=quarantine')) { score += 3; strengths.push('DMARC policy set to quarantine'); }
        else if (dmarcRecord.includes('p=none')) { issues.push('DMARC policy is "none" (monitoring only) — upgrade to quarantine or reject'); }
      } else {
        issues.push('No DMARC record at _dmarc.' + domain + ' — email authentication incomplete');
      }

      // DKIM hint (may not appear at apex, but check TXT)
      const hasDKIM = (records.TXT || []).some(r => (r.value || '').includes('v=DKIM1'));
      if (hasDKIM) { score += 5; strengths.push('DKIM record found'); }

      // MX exists
      if (records.MX && records.MX.length > 0) { score += 5; strengths.push('MX records configured (' + records.MX.length + ')'); }

      // NS redundancy
      if (records.NS && records.NS.length >= 2) { score += 5; strengths.push('Multiple nameservers (' + records.NS.length + ')'); }
      else if (records.NS && records.NS.length === 1) { issues.push('Single nameserver — no DNS redundancy'); }

      // CAA records
      if (caaRecords.length > 0) {
        score += 10;
        strengths.push('CAA records restrict certificate issuance (' + caaRecords.length + ' rules)');
      } else {
        issues.push('No CAA records — any CA can issue certificates for this domain');
      }

      // DNSSEC
      if (dnssecResult.enabled) {
        score += 15;
        strengths.push('DNSSEC is enabled — DNS responses are cryptographically signed');
      } else if (dnssecResult.status === 'unknown') {
        // Can't verify — don't penalize, but note it
        issues.push('DNSSEC status unknown — install dig (dnsutils) for verification');
      } else {
        issues.push('DNSSEC not configured — DNS responses are not cryptographically verified');
      }

      // IPv6
      if (records.AAAA && records.AAAA.length > 0) { score += 5; strengths.push('IPv6 (AAAA) records present'); }

      if (score > 100) score = 100;

      // Build structured assessment (data-driven)
      const dataAssessment = {
        score,
        strengths,
        issues,
        summary: `DNS Security Score: ${score}/100 for ${domain}. ${strengths.length} strengths, ${issues.length} issues found.`,
      };

      // Try AI-powered assessment
      let aiAssessment = null;
      if (ctx.askAI) {
        try {
          const prompt = `Analyze DNS security for ${domain}. Give a concise assessment (4-6 sentences).

DNS Records: ${Object.entries(records).map(([k, v]) => k + ': ' + v.length).join(', ')}
DNSSEC: ${dnssecResult.enabled ? 'Enabled' : 'Not configured'}
CAA Records: ${caaRecords.length > 0 ? caaRecords.map(r => r.tag + '=' + r.value).join(', ') : 'None'}
SPF: ${hasSPF ? 'Yes' : 'No'}
DMARC: ${dmarcRecord ? dmarcRecord.substring(0, 80) : 'Not found'}
Score: ${score}/100

Strengths: ${strengths.join('; ') || 'None'}
Issues: ${issues.join('; ') || 'None'}

Focus on: attack surface, email security posture, DNS hijacking risk, certificate security. Be specific and actionable.`;
          aiAssessment = await ctx.askAI(prompt, { timeout: 15000 });
        } catch { /* AI optional */ }
      }

      // Build final assessment text
      let assessment = '';
      if (aiAssessment) {
        assessment = aiAssessment;
      } else {
        // Structured fallback
        const parts = [`DNS Security Score: ${score}/100 for ${domain}\n`];
        if (strengths.length > 0) parts.push('Strengths:\n' + strengths.map(s => '+ ' + s).join('\n'));
        if (issues.length > 0) parts.push('\nIssues:\n' + issues.map(i => '- ' + i).join('\n'));
        parts.push('\nRecommendations:');
        if (!hasSPF) parts.push('- Add SPF record (v=spf1) to prevent email spoofing');
        if (!dmarcRecord) parts.push('- Add DMARC record at _dmarc.' + domain + ' with p=quarantine or p=reject');
        if (caaRecords.length === 0) parts.push('- Add CAA records to restrict which CAs can issue certificates');
        if (!dnssecResult.enabled) parts.push('- Enable DNSSEC to cryptographically sign DNS responses');
        if (records.NS && records.NS.length < 2) parts.push('- Add additional nameservers for redundancy');
        assessment = parts.join('\n');
      }

      // DNSSEC status for frontend
      const dnssec = dnssecResult.enabled ? 'valid' : 'not_configured';

      res.json({
        domain,
        records,
        dnssec,
        dnssecDetail: dnssecResult.detail,
        caa: caaRecords,
        dmarc: dmarcRecord || null,
        security_score: score,
        score,
        assessment,
        strengths,
        issues,
        totalRecords,
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ════════════════════════════════════════════════════════════════════════
  // GET /api/ssl/domains — SSL Monitor view (list monitored domains)
  // ════════════════════════════════════════════════════════════════════════
  app.get('/api/ssl/domains', requireAuth, (req, res) => {
    const domains = readJSON(SSL_DOMAINS_PATH, []);
    res.json({ domains });
  });

  // ════════════════════════════════════════════════════════════════════════
  // GET /api/ssl/:domain/analyze — SSL AI analysis
  // ════════════════════════════════════════════════════════════════════════
  app.get('/api/ssl/:domain/analyze', requireAuth, async (req, res) => {
    try {
      const domain = req.params.domain;
      if (!isValidDomain(domain)) return res.status(400).json({ error: 'Invalid domain' });

      const sslData = await nativeSSLCheck(domain);

      const analysis = [
        `SSL Analysis for ${domain}:`,
        `Grade: ${sslData.grade || 'N/A'}`,
        sslData.expiry ? `Certificate expires ${sslData.expiry.split('T')[0]} (${sslData.daysLeft} days remaining)` : 'Could not retrieve certificate',
        sslData.issuer ? `Issuer: ${sslData.issuer}` : '',
        sslData.protocol ? `Protocol: ${typeof sslData.protocol === 'string' ? sslData.protocol : sslData.protocol.name || 'unknown'}` : '',
        sslData.cipher ? `Cipher: ${typeof sslData.cipher === 'string' ? sslData.cipher : sslData.cipher.name || 'unknown'}` : '',
        sslData.san && sslData.san.length > 0 ? `SANs: ${sslData.san.join(', ')}` : '',
        '',
        sslData.daysLeft < 30 ? 'WARNING: Certificate expires soon. Renew immediately.' : 'Certificate is valid and properly configured.',
      ].filter(Boolean).join('\n');

      // Try AI analysis if available
      let aiAnalysis = null;
      try {
        aiAnalysis = await ctx.askAI(`Analyze this SSL certificate for ${domain} in 3-4 sentences. Grade: ${sslData.grade}, Days left: ${sslData.daysLeft}, Issuer: ${sslData.issuer}. Assess security and recommend improvements.`, { timeout: 10000 });
      } catch {}

      res.json({ domain, analysis: aiAnalysis || analysis, summary: analysis, ...sslData });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // Override POST /api/ssl/check to also save to domains list
  const origSslCheck = app._router.stack.find(r => r.route && r.route.path === '/api/ssl/check' && r.route.methods.post);
  if (!origSslCheck) {
    // If ssl.js didn't register it, add our own
    app.post('/api/ssl/check', requireAuth, async (req, res) => {
      try {
        const { domain } = req.body;
        if (!domain) return res.status(400).json({ error: 'domain required' });
        if (!isValidDomain(domain)) return res.status(400).json({ error: 'Invalid domain format' });

        const result = await nativeSSLCheck(domain);

        // Save to domains list
        const domains = readJSON(SSL_DOMAINS_PATH, []);
        const existing = domains.findIndex(d => d.domain === domain);
        const entry = {
          domain,
          grade: result.grade,
          issuer: result.issuer,
          expiry: result.expiry,
          daysLeft: result.daysLeft,
          days_until_expiry: result.daysLeft,
          lastCheck: new Date().toISOString(),
          ...result,
        };
        if (existing >= 0) {
          domains[existing] = { ...domains[existing], ...entry };
        } else {
          domains.push(entry);
        }
        writeJSON(SSL_DOMAINS_PATH, domains);

        res.json(result);
      } catch (e) {
        res.status(500).json({ error: e.message });
      }
    });
  }

  // ════════════════════════════════════════════════════════════════════════
  // GET /api/scan/availability — Check which scanners are installed
  // ════════════════════════════════════════════════════════════════════════
  app.get('/api/scan/availability', requireAuth, async (req, res) => {
    const availability = await scannerEngine.checkAvailability();
    res.json(availability);
  });

  // ── Helper: save scan result to history ────────────────────────────────
  // POST /api/scan/waf — WAF Detection endpoint
  // ════════════════════════════════════════════════════════════════════════
  app.post('/api/scan/waf', requireAuth, async (req, res) => {
    try {
      const { target, probe_mode } = req.body;
      if (!target) return res.status(400).json({ error: 'target required' });
      if (!isValidURL(target)) return res.status(400).json({ error: 'Invalid URL format. Use http:// or https://' });

      const mode = probe_mode === 'active' ? 'active' : 'passive';

      // Check cache (WAF rarely changes — 1 hour TTL)
      const neuralCache = require('../lib/neural-cache');
      const cacheKey = 'waf:' + target + ':' + mode;
      const cached = neuralCache.get(cacheKey);
      if (cached) { return res.json(cached); }

      const result = await detectWAF(target, mode);
      neuralCache.set(cacheKey, result, 3600000); // 1 hour

      saveScanResult('waf', target, result.findings.map(f => ({
        id: crypto.randomUUID(),
        title: f.title,
        severity: f.severity,
        type: 'waf_detection',
        status: 'open',
        details: f.description,
      })));

      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  function saveScanResult(type, target, findings) {
    const scans = readJSON(SCANS_PATH, []);
    scans.push({
      id: crypto.randomUUID(),
      type,
      target,
      status: 'completed',
      findingsCount: findings.length,
      findings,
      createdAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
    });
    // Keep last 100 scans
    if (scans.length > 100) scans.splice(0, scans.length - 100);
    writeJSON(SCANS_PATH, scans);

    // Auto-generate alerts/threats from critical/high findings
    if (ctx.syncFindingsToAlertsAndThreats) {
      try { ctx.syncFindingsToAlertsAndThreats(); } catch {}
    }
  }
};


// ── Security header checks (Node.js native HTTP) ─────────────────────
async function checkSecurityHeaders(targetUrl) {
  const findings = [];
  try {
    const url = new URL(targetUrl);
    const protocol = url.protocol === 'https:' ? require('https') : require('http');

    const headers = await new Promise((resolve, reject) => {
      const req = protocol.get(targetUrl, { timeout: 10000, rejectUnauthorized: false }, (res) => {
        resolve(res.headers);
        res.destroy();
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    });

    const checks = [
      { header: 'strict-transport-security', name: 'HSTS', risk: 'medium', desc: 'No Strict-Transport-Security header — susceptible to downgrade attacks', solution: 'Add Strict-Transport-Security header with max-age' },
      { header: 'x-content-type-options', name: 'X-Content-Type-Options', risk: 'low', desc: 'No X-Content-Type-Options header — MIME sniffing possible', solution: 'Add X-Content-Type-Options: nosniff' },
      { header: 'x-frame-options', name: 'X-Frame-Options', risk: 'medium', desc: 'No X-Frame-Options header — clickjacking risk', solution: 'Add X-Frame-Options: DENY or SAMEORIGIN' },
      { header: 'content-security-policy', name: 'CSP', risk: 'medium', desc: 'No Content-Security-Policy header — XSS risk increased', solution: 'Add a Content-Security-Policy header' },
      { header: 'referrer-policy', name: 'Referrer-Policy', risk: 'low', desc: 'No Referrer-Policy header', solution: 'Add Referrer-Policy: strict-origin-when-cross-origin' },
      { header: 'permissions-policy', name: 'Permissions-Policy', risk: 'low', desc: 'No Permissions-Policy header', solution: 'Add Permissions-Policy to restrict browser features' },
    ];

    for (const check of checks) {
      if (!headers[check.header]) {
        findings.push({
          risk: check.risk,
          severity: check.risk,
          name: `Missing ${check.name} Header`,
          title: `Missing ${check.name} Header`,
          description: check.desc,
          url: targetUrl,
          solution: check.solution,
          reference: '',
        });
      }
    }

    // Check server header (information disclosure)
    if (headers['server']) {
      findings.push({
        risk: 'info',
        severity: 'info',
        name: 'Server Header Disclosure',
        title: 'Server Header Disclosure',
        description: `Server header reveals: ${headers['server']}`,
        url: targetUrl,
        solution: 'Remove or mask the Server header to prevent information disclosure',
        reference: '',
      });
    }

    // Check for X-Powered-By
    if (headers['x-powered-by']) {
      findings.push({
        risk: 'low',
        severity: 'low',
        name: 'X-Powered-By Header Disclosure',
        title: 'X-Powered-By Header Disclosure',
        description: `X-Powered-By header reveals: ${headers['x-powered-by']}`,
        url: targetUrl,
        solution: 'Remove X-Powered-By header',
        reference: '',
      });
    }

  } catch (e) {
    findings.push({
      risk: 'info',
      severity: 'info',
      name: 'Connection Error',
      title: 'Could not connect to target',
      description: e.message,
      url: targetUrl,
      solution: 'Verify the target URL is accessible',
      reference: '',
    });
  }
  return findings;
}

// ── Vuln scanner helpers (distinct from web scanner) ──────────────────
function mkFinding(severity, title, templateId, description, target) {
  return { severity, title, name: title, template_id: templateId, description, matched_at: target, target, reference: '', cve: null };
}

async function httpVulnCheck(targetUrl, originalTarget, findings) {
  const url = new URL(targetUrl);
  const proto = url.protocol === 'https:' ? require('https') : require('http');

  const { headers, statusCode } = await new Promise((resolve, reject) => {
    const req = proto.get(targetUrl, { timeout: 8000, rejectUnauthorized: false }, (res) => {
      resolve({ headers: res.headers, statusCode: res.statusCode });
      res.destroy();
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });

  // CORS misconfiguration — send Origin and check response
  try {
    const corsHeaders = await new Promise((resolve, reject) => {
      const opts = { hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80), path: url.pathname, method: 'OPTIONS', headers: { 'Origin': 'https://evil.example.com', 'Access-Control-Request-Method': 'GET' }, timeout: 5000, rejectUnauthorized: false };
      const req = (url.protocol === 'https:' ? require('https') : require('http')).request(opts, (res) => { resolve(res.headers); res.destroy(); });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
      req.end();
    });
    const acao = corsHeaders['access-control-allow-origin'];
    if (acao === '*') {
      findings.push(mkFinding('medium', 'CORS Wildcard: Access-Control-Allow-Origin: *', 'native-cors', 'Server allows requests from any origin. If credentials are also allowed, this enables cross-site data theft.\n\nRemediation: Restrict CORS to specific trusted origins.', originalTarget));
    } else if (acao === 'https://evil.example.com') {
      findings.push(mkFinding('high', 'CORS Origin Reflection — Arbitrary Origin Accepted', 'native-cors', 'Server reflects back any Origin header, allowing any website to make authenticated requests.\n\nRemediation: Validate Origin against a whitelist of trusted domains.', originalTarget));
    }
    if (corsHeaders['access-control-allow-credentials'] === 'true' && (acao === '*' || acao === 'https://evil.example.com')) {
      findings.push(mkFinding('high', 'CORS with Credentials — Cross-Origin Cookie Theft', 'native-cors-creds', 'Server allows credentials with a permissive origin policy. Attackers can steal session cookies cross-site.\n\nRemediation: Never combine Access-Control-Allow-Credentials: true with wildcard or reflected origins.', originalTarget));
    }
  } catch {}

  // Dangerous HTTP methods
  const allow = headers['allow'] || '';
  try {
    const optRes = await new Promise((resolve, reject) => {
      const opts = { hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80), path: url.pathname, method: 'OPTIONS', timeout: 5000, rejectUnauthorized: false };
      const req = (url.protocol === 'https:' ? require('https') : require('http')).request(opts, (res) => { resolve(res.headers['allow'] || ''); res.destroy(); });
      req.on('error', () => resolve(allow));
      req.on('timeout', () => { req.destroy(); resolve(allow); });
      req.end();
    });
    const methods = (optRes || allow).toUpperCase();
    if (methods.includes('TRACE')) {
      findings.push(mkFinding('medium', 'HTTP TRACE Method Enabled', 'native-http-method', 'TRACE method is enabled, which can be exploited for Cross-Site Tracing (XST) attacks to steal credentials.\n\nRemediation: Disable TRACE method on the web server.', originalTarget));
    }
    if (methods.includes('PUT') || methods.includes('DELETE')) {
      findings.push(mkFinding('medium', 'Dangerous HTTP Methods Enabled: ' + methods, 'native-http-method', 'PUT and/or DELETE methods are advertised. If not properly restricted, attackers can modify or delete resources.\n\nRemediation: Disable unused HTTP methods or restrict with authentication.', originalTarget));
    }
  } catch {}

  // Cookie security
  const cookies = headers['set-cookie'];
  if (cookies) {
    const cookieArr = Array.isArray(cookies) ? cookies : [cookies];
    for (const c of cookieArr) {
      const lower = c.toLowerCase();
      const issues = [];
      if (!lower.includes('httponly')) issues.push('HttpOnly');
      if (!lower.includes('secure')) issues.push('Secure');
      if (!lower.includes('samesite')) issues.push('SameSite');
      if (issues.length > 0) {
        const cookieName = c.split('=')[0].trim();
        findings.push(mkFinding('medium', `Insecure Cookie "${cookieName}" — Missing: ${issues.join(', ')}`, 'native-cookie', `Cookie "${cookieName}" lacks ${issues.join(', ')} flag(s), increasing risk of session hijacking or CSRF.\n\nRemediation: Set ${issues.join(', ')} flags on all session cookies.`, originalTarget));
        break;
      }
    }
  }

  // Technology fingerprinting
  const techFindings = [];
  if (headers['server']) techFindings.push('Server: ' + headers['server']);
  if (headers['x-powered-by']) techFindings.push('X-Powered-By: ' + headers['x-powered-by']);
  if (headers['x-aspnet-version']) techFindings.push('ASP.NET: ' + headers['x-aspnet-version']);
  if (headers['x-generator']) techFindings.push('Generator: ' + headers['x-generator']);
  if (techFindings.length > 1) {
    findings.push(mkFinding('low', 'Technology Stack Disclosed', 'native-tech-fingerprint', `Multiple technology headers expose server internals:\n${techFindings.map(t => '  - ' + t).join('\n')}\n\nRemediation: Remove or mask technology-identifying headers.`, originalTarget));
  }

  // Information leakage via error-like status codes
  if (statusCode === 500 || statusCode === 503) {
    findings.push(mkFinding('low', `Server Error Response (HTTP ${statusCode})`, 'native-error-leak', `Server returned HTTP ${statusCode} which may expose stack traces or internal details in the response body.\n\nRemediation: Configure custom error pages that don't reveal internals.`, originalTarget));
  }
}

// Risky open services — scan ports that indicate vulnerable/dangerous services
const RISKY_PORTS = [
  { port: 21, service: 'FTP', risk: 'high', reason: 'FTP transmits credentials in cleartext' },
  { port: 23, service: 'Telnet', risk: 'critical', reason: 'Telnet is unencrypted remote access — trivially sniffable' },
  { port: 25, service: 'SMTP', risk: 'low', reason: 'Open SMTP relay check — may allow email spoofing' },
  { port: 445, service: 'SMB', risk: 'high', reason: 'SMB exposed to internet — EternalBlue, WannaCry attack vector' },
  { port: 1433, service: 'MSSQL', risk: 'high', reason: 'Database port open to internet — brute-force and injection risk' },
  { port: 3306, service: 'MySQL', risk: 'high', reason: 'Database port open to internet — brute-force and injection risk' },
  { port: 5432, service: 'PostgreSQL', risk: 'high', reason: 'Database port open to internet — brute-force and injection risk' },
  { port: 6379, service: 'Redis', risk: 'critical', reason: 'Redis has no auth by default — unauthenticated data access and RCE' },
  { port: 27017, service: 'MongoDB', risk: 'critical', reason: 'MongoDB has no auth by default — full database exposure' },
  { port: 9200, service: 'Elasticsearch', risk: 'high', reason: 'Elasticsearch API exposed — data theft and cluster manipulation' },
  { port: 2375, service: 'Docker API', risk: 'critical', reason: 'Unencrypted Docker API — full host RCE via container escape' },
  { port: 5900, service: 'VNC', risk: 'high', reason: 'VNC remote desktop exposed — screenshot/keylog risk' },
  { port: 11211, service: 'Memcached', risk: 'high', reason: 'Memcached exposed — data leakage and DDoS amplification' },
  { port: 3389, service: 'RDP', risk: 'medium', reason: 'RDP exposed — BlueKeep and brute-force target' },
  { port: 8080, service: 'HTTP-Proxy', risk: 'low', reason: 'Alternate HTTP port — may expose admin panels or dev servers' },
];

async function portVulnCheck(hostname, originalTarget, findings) {
  const results = await Promise.all(
    RISKY_PORTS.map(p => scanPort(hostname, p.port, 2000).then(r => r ? p : null))
  );
  for (const hit of results.filter(Boolean)) {
    findings.push(mkFinding(hit.risk, `Open ${hit.service} (port ${hit.port})`, 'native-port-risk', `${hit.reason}.\n\nRemediation: Block port ${hit.port} at the firewall or restrict to trusted IPs only.`, originalTarget));
  }
}


async function checkExposedPaths(targetUrl) {
  const findings = [];
  const protocol = targetUrl.startsWith('https') ? require('https') : require('http');

  const paths = [
    { path: '/.env', name: 'Environment file exposed', risk: 'critical' },
    { path: '/.git/config', name: 'Git configuration exposed', risk: 'critical' },
    { path: '/wp-admin/', name: 'WordPress admin panel', risk: 'medium' },
    { path: '/phpmyadmin/', name: 'phpMyAdmin exposed', risk: 'high' },
    { path: '/server-status', name: 'Apache server-status', risk: 'medium' },
    { path: '/robots.txt', name: 'Robots.txt', risk: 'info' },
    { path: '/.well-known/security.txt', name: 'Security.txt', risk: 'info' },
    { path: '/api/docs', name: 'API documentation exposed', risk: 'low' },
    { path: '/debug', name: 'Debug endpoint', risk: 'high' },
    { path: '/actuator', name: 'Spring Boot Actuator', risk: 'high' },
  ];

  const checkPath = (p) => new Promise(resolve => {
    const url = targetUrl.replace(/\/$/, '') + p.path;
    const req = protocol.get(url, { timeout: 5000, rejectUnauthorized: false }, (res) => {
      res.destroy();
      if (res.statusCode === 200) {
        resolve({
          risk: p.risk,
          severity: p.risk,
          name: p.name,
          title: p.name,
          description: `${p.path} returned HTTP 200 — may be exposed`,
          url: url,
          solution: `Restrict access to ${p.path} or remove it`,
          reference: '',
        });
      } else {
        resolve(null);
      }
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });

  const results = await Promise.all(paths.map(checkPath));
  findings.push(...results.filter(Boolean));
  return findings;
}


// ── WAF Detection Engine (evilwaf-inspired) ────────────────────────────
// Fingerprints 30+ WAF solutions via headers, cookies, response body, and status codes.
// Pure Node.js — no external dependencies.

const WAF_SIGNATURES = [
  // CDN / Cloud WAFs
  { name: 'Cloudflare', vendor: 'Cloudflare', headers: { 'server': /cloudflare/i, 'cf-ray': /.+/, 'cf-cache-status': /.+/ }, cookies: ['__cfduid', '__cf_bm', 'cf_clearance'], body: [/cloudflare/i, /attention required/i, /cf-error-details/i, /ray ID/i], codes: [403, 429, 503, 520, 521, 522, 523, 524, 525, 526] },
  { name: 'AWS WAF', vendor: 'Amazon', headers: { 'x-amzn-requestid': /.+/, 'x-amz-cf-id': /.+/ }, cookies: ['awsalb', 'awsalbcors'], body: [/aws/i, /request blocked/i], codes: [403, 429] },
  { name: 'AWS CloudFront', vendor: 'Amazon', headers: { 'x-amz-cf-id': /.+/, 'x-amz-cf-pop': /.+/, 'via': /CloudFront/i }, cookies: [], body: [/cloudfront/i], codes: [403] },
  { name: 'Akamai', vendor: 'Akamai', headers: { 'server': /AkamaiGHost/i, 'x-akamai-transformed': /.+/ }, cookies: ['ak_bmsc', '_abck', 'bm_sv', 'bm_mi', 'akamai_g'], body: [/akamai/i, /reference.*#/i], codes: [403] },
  { name: 'Google Cloud Armor', vendor: 'Google', headers: { 'server': /gws/i, 'x-goog-': /.+/ }, cookies: [], body: [/google cloud armor/i, /blocked by security policy/i], codes: [403, 429] },
  { name: 'Azure WAF', vendor: 'Microsoft', headers: { 'server': /Microsoft-Azure/i, 'x-azure-ref': /.+/ }, cookies: [], body: [/azure/i, /web application firewall/i], codes: [403] },
  { name: 'Fastly', vendor: 'Fastly', headers: { 'x-served-by': /cache-/i, 'x-fastly-request-id': /.+/, 'via': /varnish/i }, cookies: [], body: [/fastly/i], codes: [403, 429, 503] },
  { name: 'Sucuri', vendor: 'GoDaddy', headers: { 'x-sucuri-id': /.+/, 'server': /Sucuri/i, 'x-sucuri-cache': /.+/ }, cookies: ['sucuri_cloudproxy_uuid'], body: [/sucuri/i, /access denied.*sucuri/i, /sucuri website firewall/i], codes: [403] },
  // Traditional WAFs
  { name: 'Imperva / Incapsula', vendor: 'Imperva', headers: { 'x-iinfo': /.+/, 'x-cdn': /Incapsula/i }, cookies: ['visid_incap_', 'incap_ses_', 'nlbi_'], body: [/incapsula/i, /imperva/i, /powered by incapsula/i], codes: [403] },
  { name: 'F5 BIG-IP ASM', vendor: 'F5', headers: { 'server': /BIG-IP/i, 'x-cnection': /.+/, 'x-wa-info': /.+/ }, cookies: ['BIGipServer', 'TS0', 'f5_cspm', 'f5avraaaaaaa'], body: [/BIG-IP/i, /the requested URL was rejected/i, /support id/i], codes: [403] },
  { name: 'FortiWeb', vendor: 'Fortinet', headers: { 'server': /FortiWeb/i, 'x-fortiweb-': /.+/ }, cookies: ['FORTIWAFSID'], body: [/fortiweb/i, /fortinet/i, /fortigate/i], codes: [403] },
  { name: 'ModSecurity', vendor: 'Trustwave', headers: { 'server': /mod_security/i }, cookies: [], body: [/mod_security/i, /modsecurity/i, /not acceptable/i, /NOYB/i], codes: [403, 406] },
  { name: 'Barracuda', vendor: 'Barracuda', headers: { 'server': /barracuda/i }, cookies: ['barra_counter_session', 'BNI__BARRACUDA_LB_COOKIE'], body: [/barracuda/i], codes: [403] },
  { name: 'Citrix NetScaler', vendor: 'Citrix', headers: { 'via': /NS-CACHE/i, 'cneonction': /.+/, 'x-ns-': /.+/ }, cookies: ['NSC_', 'citrix_ns_id'], body: [/netscaler/i, /ns_af/i], codes: [403, 302] },
  { name: 'Palo Alto', vendor: 'Palo Alto', headers: { 'x-pan-': /.+/ }, cookies: [], body: [/has been blocked/i, /palo alto/i], codes: [403] },
  { name: 'DenyAll', vendor: 'DenyAll', headers: { 'server': /DenyAll/i }, cookies: ['sessioncookie'], body: [/denyall/i, /conditionblocked/i], codes: [403] },
  { name: 'Wallarm', vendor: 'Wallarm', headers: { 'server': /wallarm/i, 'x-wallarm-': /.+/ }, cookies: [], body: [/wallarm/i], codes: [403] },
  // Open-source / Nginx / Apache
  { name: 'NAXSI', vendor: 'Open Source', headers: { 'server': /naxsi/i, 'x-naxsi-sig': /.+/ }, cookies: [], body: [/naxsi/i, /blocked by naxsi/i], codes: [403] },
  { name: 'Comodo WAF', vendor: 'Comodo', headers: { 'server': /Comodo/i }, cookies: [], body: [/comodo/i, /protected by comodo/i], codes: [403] },
  { name: 'StackPath', vendor: 'StackPath', headers: { 'x-sp-': /.+/, 'server': /StackPath/i }, cookies: [], body: [/stackpath/i, /secureedge/i], codes: [403] },
  { name: 'Reblaze', vendor: 'Reblaze', headers: { 'server': /Reblaze/i, 'x-rb-': /.+/ }, cookies: ['rbzid'], body: [/reblaze/i, /access denied.*reblaze/i], codes: [403] },
  { name: 'Edgecast / Verizon', vendor: 'Edgecast', headers: { 'server': /ECAcc/i, 'x-ec-': /.+/ }, cookies: [], body: [/edgecast/i], codes: [403] },
  { name: 'KeyCDN', vendor: 'KeyCDN', headers: { 'server': /keycdn/i, 'x-edge-': /.+/ }, cookies: [], body: [/keycdn/i], codes: [403] },
  { name: 'DataDome', vendor: 'DataDome', headers: { 'x-datadome': /.+/, 'server': /DataDome/i }, cookies: ['datadome'], body: [/datadome/i], codes: [403, 429] },
  { name: 'PerimeterX / HUMAN', vendor: 'HUMAN', headers: { 'x-px-': /.+/ }, cookies: ['_px', '_pxhd', '_pxvid'], body: [/perimeterx/i, /human challenge/i, /px-captcha/i], codes: [403, 429] },
  { name: 'Wordfence', vendor: 'Defiant', headers: {}, cookies: ['wfwaf-authcookie'], body: [/wordfence/i, /generated by wordfence/i, /a]potentially unsafe operation/i], codes: [403, 503] },
  { name: 'AWS Shield', vendor: 'Amazon', headers: { 'x-amz-apigw-id': /.+/ }, cookies: [], body: [/aws shield/i], codes: [403, 429] },
  { name: 'Radware', vendor: 'Radware', headers: { 'x-sl-compstate': /.+/ }, cookies: [], body: [/radware/i, /unauthorized activity/i], codes: [403] },
  { name: 'Squarespace', vendor: 'Squarespace', headers: { 'x-servedby': /squarespace/i, 'server': /Squarespace/i }, cookies: [], body: [/squarespace/i], codes: [403] },
];

// Benign payloads that trigger WAF but are safe — used for active probing
const WAF_PROBE_PAYLOADS = [
  { name: 'XSS probe', param: 'q', value: '<script>alert(1)</script>' },
  { name: 'SQLi probe', param: 'id', value: "' OR '1'='1" },
  { name: 'Path traversal', param: 'file', value: '../../../../etc/passwd' },
  { name: 'RCE probe', param: 'cmd', value: '; cat /etc/passwd' },
];

// Status codes that typically indicate WAF blocking
const WAF_BLOCK_CODES = new Set([403, 406, 407, 409, 418, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524, 525, 526]);

/**
 * Detect WAF presence on a target URL
 * @param {string} targetUrl - URL to probe
 * @param {string} probeMode - 'passive' (headers only) or 'active' (send payloads)
 * @returns {Promise<object>} - { detected, waf, confidence, evidence, findings }
 */
async function detectWAF(targetUrl, probeMode = 'passive') {
  const url = new URL(targetUrl);
  const proto = url.protocol === 'https:' ? require('https') : require('http');
  const evidence = [];
  const wafScores = {}; // waf name -> cumulative score
  let responseHeaders = {};
  let responseCookies = [];
  let responseBody = '';
  let statusCode = 0;
  let tlsInfo = null;

  // ── Phase 1: Fetch target and analyze response ──
  try {
    const result = await new Promise((resolve, reject) => {
      const req = proto.get(targetUrl, { timeout: 10000, rejectUnauthorized: false }, (res) => {
        let body = '';
        res.on('data', chunk => { body += chunk.toString(); if (body.length > 50000) res.destroy(); });
        res.on('end', () => resolve({ headers: res.headers, statusCode: res.statusCode, body, rawHeaders: res.rawHeaders, socket: res.socket }));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    });

    responseHeaders = result.headers;
    statusCode = result.statusCode;
    responseBody = result.body.substring(0, 50000);
    responseCookies = (responseHeaders['set-cookie'] || []);
    if (typeof responseCookies === 'string') responseCookies = [responseCookies];

    // Extract TLS info if HTTPS
    if (url.protocol === 'https:' && result.socket && result.socket.getPeerCertificate) {
      try {
        const cert = result.socket.getPeerCertificate();
        if (cert && cert.issuer) {
          tlsInfo = { issuer: cert.issuer.O || cert.issuer.CN || '', subject: cert.subject?.CN || '' };
        }
      } catch {}
    }
  } catch (e) {
    return { detected: false, waf: null, confidence: 0, evidence: [{ method: 'error', detail: e.message }], findings: [] };
  }

  // ── Phase 2: Match against WAF signatures ──
  for (const sig of WAF_SIGNATURES) {
    let score = 0;

    // Check response headers
    for (const [headerName, pattern] of Object.entries(sig.headers)) {
      // Check exact header names
      const headerVal = responseHeaders[headerName.toLowerCase()];
      if (headerVal && pattern.test(headerVal)) {
        score += 30;
        evidence.push({ waf: sig.name, method: 'header', detail: `${headerName}: ${headerVal}` });
      }
    }

    // Check all response headers for partial matches (some WAFs add custom headers)
    for (const [key, val] of Object.entries(responseHeaders)) {
      if (key.toLowerCase().includes(sig.name.toLowerCase().split(' ')[0].toLowerCase()) && !evidence.find(e => e.waf === sig.name && e.detail.startsWith(key))) {
        score += 15;
        evidence.push({ waf: sig.name, method: 'header', detail: `${key}: ${val}` });
      }
    }

    // Check cookies
    const cookieStr = responseCookies.join(' ');
    for (const cookieName of sig.cookies) {
      if (cookieStr.toLowerCase().includes(cookieName.toLowerCase())) {
        score += 25;
        evidence.push({ waf: sig.name, method: 'cookie', detail: `Cookie: ${cookieName}` });
      }
    }

    // Check response body
    for (const pattern of sig.body) {
      if (pattern.test(responseBody)) {
        score += 20;
        evidence.push({ waf: sig.name, method: 'body', detail: `Body matches: ${pattern.source}` });
        break; // one body match is enough
      }
    }

    // Check TLS certificate issuer
    if (tlsInfo && tlsInfo.issuer) {
      const issuerLower = tlsInfo.issuer.toLowerCase();
      if (issuerLower.includes(sig.name.toLowerCase().split(' ')[0].toLowerCase())) {
        score += 15;
        evidence.push({ waf: sig.name, method: 'certificate', detail: `Cert issuer: ${tlsInfo.issuer}` });
      }
    }

    if (score > 0) wafScores[sig.name] = (wafScores[sig.name] || 0) + score;
  }

  // ── Phase 3: Active probing (if enabled) ──
  if (probeMode === 'active') {
    for (const payload of WAF_PROBE_PAYLOADS) {
      try {
        const probeUrl = new URL(targetUrl);
        probeUrl.searchParams.set(payload.param, payload.value);

        const probeResult = await new Promise((resolve, reject) => {
          const req = proto.get(probeUrl.href, { timeout: 8000, rejectUnauthorized: false }, (res) => {
            let body = '';
            res.on('data', chunk => { body += chunk.toString(); if (body.length > 10000) res.destroy(); });
            res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
          });
          req.on('error', reject);
          req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
        });

        if (WAF_BLOCK_CODES.has(probeResult.statusCode) && probeResult.statusCode !== statusCode) {
          // WAF blocked the probe — boost all existing scores or add generic detection
          evidence.push({ waf: 'Active Probe', method: 'probe', detail: `${payload.name}: HTTP ${probeResult.statusCode} (normal: ${statusCode})` });

          // Try to identify which WAF from the error response
          for (const sig of WAF_SIGNATURES) {
            for (const pattern of sig.body) {
              if (pattern.test(probeResult.body)) {
                wafScores[sig.name] = (wafScores[sig.name] || 0) + 35;
                evidence.push({ waf: sig.name, method: 'probe_body', detail: `${payload.name} error page matches ${sig.name}` });
                break;
              }
            }
          }

          // If no specific WAF matched, still record the block
          if (!Object.keys(wafScores).length) {
            wafScores['Unknown WAF'] = (wafScores['Unknown WAF'] || 0) + 25;
          } else {
            // Boost all matched WAFs
            for (const waf of Object.keys(wafScores)) {
              wafScores[waf] += 10;
            }
          }
        }
      } catch {}
    }
  }

  // ── Phase 4: Score and rank results ──
  const sortedWAFs = Object.entries(wafScores)
    .map(([name, score]) => ({ name, score: Math.min(100, score), vendor: WAF_SIGNATURES.find(s => s.name === name)?.vendor || 'Unknown' }))
    .sort((a, b) => b.score - a.score);

  const primaryWAF = sortedWAFs.length > 0 ? sortedWAFs[0] : null;
  const detected = primaryWAF && primaryWAF.score >= 15;

  // Build findings array in Vigil schema
  const findings = [];
  if (detected) {
    findings.push({
      risk: 'info',
      severity: 'info',
      name: `WAF Detected: ${primaryWAF.name}`,
      title: `WAF Detected: ${primaryWAF.name}`,
      description: `${primaryWAF.name} (${primaryWAF.vendor}) detected with ${primaryWAF.score}% confidence. ` +
        `Detection methods: ${[...new Set(evidence.filter(e => e.waf === primaryWAF.name).map(e => e.method))].join(', ')}`,
      url: targetUrl,
      solution: `WAF presence affects penetration testing strategy. Consider WAF-specific bypass techniques and ensure testing authorization covers WAF evasion. ` +
        `Verify WAF rules are up-to-date and cover OWASP Top 10.`,
      reference: '',
    });

    // Additional WAFs
    sortedWAFs.slice(1).filter(w => w.score >= 15).forEach(waf => {
      findings.push({
        risk: 'info',
        severity: 'info',
        name: `Additional WAF/CDN: ${waf.name}`,
        title: `Additional WAF/CDN: ${waf.name}`,
        description: `${waf.name} (${waf.vendor}) detected with ${waf.score}% confidence`,
        url: targetUrl,
        solution: 'Multiple security layers detected — review WAF stack configuration',
        reference: '',
      });
    });

    // WAF bypass risk assessment
    if (probeMode === 'active') {
      const blockedProbes = evidence.filter(e => e.method === 'probe');
      const totalProbes = WAF_PROBE_PAYLOADS.length;
      const blockRate = blockedProbes.length / totalProbes;

      if (blockRate >= 0.75) {
        findings.push({
          risk: 'info',
          severity: 'info',
          name: 'WAF Block Rate: Strong',
          title: `WAF blocks ${Math.round(blockRate * 100)}% of test payloads`,
          description: `${blockedProbes.length}/${totalProbes} attack probes were blocked. WAF appears to be effectively filtering common attack vectors.`,
          url: targetUrl,
          solution: 'WAF protection is active. Test with more advanced evasion techniques if authorized.',
          reference: '',
        });
      } else if (blockRate > 0) {
        findings.push({
          risk: 'medium',
          severity: 'medium',
          name: 'WAF Block Rate: Partial',
          title: `WAF blocks only ${Math.round(blockRate * 100)}% of test payloads`,
          description: `Only ${blockedProbes.length}/${totalProbes} attack probes were blocked. Some common attack vectors may bypass the WAF.`,
          url: targetUrl,
          solution: 'Review WAF rule configuration — some attack patterns are not being caught.',
          reference: '',
        });
      } else if (detected) {
        findings.push({
          risk: 'high',
          severity: 'high',
          name: 'WAF Detected but Not Blocking',
          title: 'WAF present but not blocking attack payloads',
          description: 'A WAF was detected via fingerprinting but none of the test payloads were blocked. The WAF may be in detection-only mode or misconfigured.',
          url: targetUrl,
          solution: 'Verify WAF is in active blocking mode. Review security rules and ensure OWASP CRS or equivalent rules are enabled.',
          reference: '',
        });
      }
    }
  }

  if (!detected) {
    findings.push({
      risk: 'medium',
      severity: 'medium',
      name: 'No WAF Detected',
      title: 'No Web Application Firewall detected',
      description: 'No WAF/CDN fingerprints found. The application may be directly exposed to the internet without WAF protection.',
      url: targetUrl,
      solution: 'Consider deploying a WAF (Cloudflare, AWS WAF, ModSecurity) to protect against common web attacks (SQLi, XSS, RCE).',
      reference: '',
    });
  }

  return {
    detected,
    waf: primaryWAF ? { name: primaryWAF.name, vendor: primaryWAF.vendor, confidence: primaryWAF.score } : null,
    allWAFs: sortedWAFs.filter(w => w.score >= 15),
    confidence: primaryWAF ? primaryWAF.score : 0,
    evidence: evidence,
    probeMode,
    findings,
    statusCode,
    tlsInfo,
    target: targetUrl,
  };
}
