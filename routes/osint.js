/**
 * OSINT Routes — Domain recon, IP lookup, email lookup, AI analysis, history
 * Uses osint-engine.js for all lookups (pure Node.js, no CLI deps needed)
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const tls = require('tls');

const DATA = path.join(__dirname, '..', 'data');
const HISTORY_PATH = path.join(DATA, 'osint-history.json');

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

module.exports = function (app, ctx) {
  const { requireAuth, requireRole, askAI, osintEngine } = ctx;

  function saveToHistory(type, target, summary) {
    const history = readJSON(HISTORY_PATH, []);
    history.push({
      id: crypto.randomUUID(),
      type,
      target,
      summary: summary || null,
      created_at: new Date().toISOString(),
    });
    if (history.length > 200) history.splice(0, history.length - 200);
    writeJSON(HISTORY_PATH, history);
  }

  // ── SSL certificate check via Node.js TLS (no openssl needed) ──────
  function getSSLCert(domain) {
    return new Promise(resolve => {
      try {
        const socket = tls.connect(443, domain, { servername: domain, timeout: 8000 }, () => {
          try {
            const cert = socket.getPeerCertificate();
            const protocol = socket.getProtocol ? socket.getProtocol() : '';
            socket.destroy();
            if (!cert || !cert.subject) { resolve(null); return; }
            resolve({
              cn: cert.subject.CN || '',
              issuer: cert.issuer ? (cert.issuer.O || cert.issuer.CN || '') : '',
              valid_from: cert.valid_from || '',
              valid_to: cert.valid_to || '',
              serial: cert.serialNumber || '',
              fingerprint: cert.fingerprint256 || cert.fingerprint || '',
              san: cert.subjectaltname ? cert.subjectaltname.split(',').map(s => s.trim().replace('DNS:', '')) : [],
              protocol: protocol || '',
            });
          } catch { socket.destroy(); resolve(null); }
        });
        socket.on('error', () => resolve(null));
        socket.setTimeout(8000, () => { socket.destroy(); resolve(null); });
      } catch { resolve(null); }
    });
  }

  // ── HTTP headers check via Node.js https (no curl needed) ──────────
  function getHTTPHeaders(domain) {
    return new Promise(resolve => {
      try {
        const https = require('https');
        const req = https.request({ hostname: domain, port: 443, method: 'HEAD', timeout: 8000 }, res => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            server: res.headers['server'] || null,
            poweredBy: res.headers['x-powered-by'] || null,
            securityHeaders: {
              'strict-transport-security': res.headers['strict-transport-security'] || null,
              'content-security-policy': res.headers['content-security-policy'] || null,
              'x-frame-options': res.headers['x-frame-options'] || null,
              'x-content-type-options': res.headers['x-content-type-options'] || null,
              'x-xss-protection': res.headers['x-xss-protection'] || null,
              'referrer-policy': res.headers['referrer-policy'] || null,
              'permissions-policy': res.headers['permissions-policy'] || null,
            },
          });
        });
        req.on('error', () => resolve(null));
        req.setTimeout(8000, () => { req.destroy(); resolve(null); });
        req.end();
      } catch { resolve(null); }
    });
  }

  // Detect technologies from HTTP headers
  function detectTechnologies(httpInfo, ssl) {
    const tech = [];
    if (!httpInfo) return tech;
    const h = httpInfo.headers || {};
    const server = (h['server'] || '').toLowerCase();
    const powered = (h['x-powered-by'] || '').toLowerCase();

    if (server.includes('nginx')) tech.push('Nginx');
    if (server.includes('apache')) tech.push('Apache');
    if (server.includes('cloudflare')) tech.push('Cloudflare');
    if (server.includes('microsoft')) tech.push('IIS');
    if (server.includes('litespeed')) tech.push('LiteSpeed');
    if (powered.includes('express')) tech.push('Express.js');
    if (powered.includes('php')) tech.push('PHP');
    if (powered.includes('asp.net')) tech.push('ASP.NET');
    if (powered.includes('next')) tech.push('Next.js');
    if (h['x-vercel-id']) tech.push('Vercel');
    if (h['x-amz-cf-id'] || h['x-amz-request-id']) tech.push('AWS');
    if (h['x-github-request-id']) tech.push('GitHub Pages');
    if (h['cf-ray']) tech.push('Cloudflare CDN');
    if (h['x-cache'] && h['x-cache'].includes('HIT')) tech.push('CDN Cache');
    if (ssl && ssl.protocol) tech.push(ssl.protocol);
    if (ssl && ssl.issuer) {
      if (ssl.issuer.toLowerCase().includes('encrypt')) tech.push("Let's Encrypt");
      else if (ssl.issuer.toLowerCase().includes('cloudflare')) tech.push('Cloudflare SSL');
      else if (ssl.issuer.toLowerCase().includes('digicert')) tech.push('DigiCert');
    }
    // Security headers present
    const sh = httpInfo.securityHeaders || {};
    if (sh['strict-transport-security']) tech.push('HSTS');
    if (sh['content-security-policy']) tech.push('CSP');

    return [...new Set(tech)];
  }

  // ═══════════════════════════════════════════════════════════════════════
  // POST /api/osint/domain — Full domain reconnaissance
  // ═══════════════════════════════════════════════════════════════════════
  app.post('/api/osint/domain', requireRole('analyst'), async (req, res) => {
    try {
      const { domain } = req.body;
      if (!domain) return res.status(400).json({ error: 'domain required' });
      if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(domain)) {
        return res.status(400).json({ error: 'Invalid domain format' });
      }

      // Run osint-engine + SSL + HTTP + AI all in parallel
      const [reconResult, sslResult, httpResult] = await Promise.allSettled([
        osintEngine ? osintEngine.domainRecon(domain) : Promise.resolve({}),
        getSSLCert(domain),
        getHTTPHeaders(domain),
      ]);

      const recon = reconResult.status === 'fulfilled' ? reconResult.value : {};
      const ssl = sslResult.status === 'fulfilled' ? sslResult.value : null;
      const httpInfo = httpResult.status === 'fulfilled' ? httpResult.value : null;

      // Build technologies list
      const technologies = detectTechnologies(httpInfo, ssl);

      // Build certificates array
      const certificates = [];
      if (ssl) {
        certificates.push({
          cn: ssl.cn,
          issuer: ssl.issuer,
          valid_from: ssl.valid_from,
          valid_to: ssl.valid_to,
          serial: ssl.serial,
          san: ssl.san,
          protocol: ssl.protocol,
        });
      }
      // Add cert transparency results
      const ctCerts = recon.certTransparency || [];
      ctCerts.slice(0, 20).forEach(c => {
        certificates.push({
          cn: c.name,
          issuer: c.issuer,
          valid_from: c.notBefore,
          valid_to: c.notAfter,
        });
      });

      // Build subdomains array
      const subdomains = (recon.subdomains || []).map(s =>
        typeof s === 'string' ? s : (s.subdomain || '')
      ).filter(Boolean);

      // WHOIS data
      const whois = recon.whois || {};

      // DNS records
      const dnsRecords = recon.dns || {};

      // Security headers assessment
      const secHeaders = httpInfo ? httpInfo.securityHeaders : {};
      const missingHeaders = [];
      if (secHeaders) {
        if (!secHeaders['strict-transport-security']) missingHeaders.push('Strict-Transport-Security (HSTS)');
        if (!secHeaders['content-security-policy']) missingHeaders.push('Content-Security-Policy (CSP)');
        if (!secHeaders['x-frame-options']) missingHeaders.push('X-Frame-Options');
        if (!secHeaders['x-content-type-options']) missingHeaders.push('X-Content-Type-Options');
        if (!secHeaders['referrer-policy']) missingHeaders.push('Referrer-Policy');
      }

      // Build the response
      const result = {
        domain,
        whois: {
          registrar: whois.registrar || null,
          created: whois.created || null,
          expires: whois.expires || null,
          updated: whois.updated || null,
          nameservers: whois.nameServers || [],
          registrant: whois.registrant || null,
          status: whois.status || [],
          available: whois.available !== false,
          raw: whois.raw || null,
        },
        dns: dnsRecords,
        subdomains,
        certificates,
        technologies,
        httpInfo: httpInfo ? {
          status: httpInfo.status,
          server: httpInfo.server,
          poweredBy: httpInfo.poweredBy,
          securityHeaders: secHeaders,
          missingHeaders,
        } : null,
        ssl: ssl ? {
          cn: ssl.cn,
          issuer: ssl.issuer,
          valid_from: ssl.valid_from,
          valid_to: ssl.valid_to,
          protocol: ssl.protocol,
          san_count: ssl.san ? ssl.san.length : 0,
        } : null,
      };

      // AI assessment (runs after data is ready, non-blocking for response)
      let aiAnalysis = null;
      if (askAI) {
        try {
          const prompt = `You are an OSINT analyst. Give a concise security assessment (6-8 sentences) of ${domain}.

WHOIS: Registrar=${whois.registrar || 'unknown'}, Created=${whois.created || 'unknown'}, Expires=${whois.expires || 'unknown'}
DNS: ${Object.entries(dnsRecords).map(([k, v]) => k + ':' + (Array.isArray(v) ? v.length : v ? 1 : 0)).join(', ')}
Subdomains found: ${subdomains.length} (${subdomains.slice(0, 5).join(', ')})
SSL: ${ssl ? ssl.issuer + ', ' + ssl.protocol + ', valid until ' + ssl.valid_to : 'No SSL'}
Tech: ${technologies.join(', ') || 'None detected'}
Missing security headers: ${missingHeaders.join(', ') || 'None — all present'}
Cert transparency entries: ${ctCerts.length}

Assess: attack surface, exposure, security posture, notable risks. Be specific and actionable.`;
          aiAnalysis = await askAI(prompt, { timeout: 20000 });
        } catch { /* AI optional */ }
      }

      result.analysis = aiAnalysis;

      saveToHistory('domain', domain, (aiAnalysis || '').substring(0, 200));
      res.json(result);
    } catch (e) {
      console.error('[OSINT] Domain error:', e.message);
      res.status(500).json({ error: 'Domain reconnaissance failed: ' + e.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // POST /api/osint/ip — IP address lookup
  // ═══════════════════════════════════════════════════════════════════════
  app.post('/api/osint/ip', requireRole('analyst'), async (req, res) => {
    try {
      const { ip } = req.body;
      if (!ip) return res.status(400).json({ error: 'ip required' });
      // Validate IPv4 or IPv6
      if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && !/^[a-fA-F0-9:]+$/.test(ip)) {
        return res.status(400).json({ error: 'Invalid IP format' });
      }

      // Use osint-engine for core lookup
      const engineResult = osintEngine ? await osintEngine.ipLookup(ip) : {};

      const geo = engineResult.geolocation || {};
      const reverseDNS = engineResult.reverseDNS || [];

      // Quick port check via native Node.js (no nmap needed)
      const openPorts = [];
      const commonPorts = [22, 80, 443, 8080, 8443, 3389, 3306, 5432, 6379, 27017];
      const portChecks = commonPorts.map(port => {
        return new Promise(resolve => {
          const net = require('net');
          const socket = new net.Socket();
          socket.setTimeout(2000);
          socket.on('connect', () => {
            openPorts.push({ port, state: 'open' });
            socket.destroy();
            resolve();
          });
          socket.on('timeout', () => { socket.destroy(); resolve(); });
          socket.on('error', () => { socket.destroy(); resolve(); });
          socket.connect(port, ip);
        });
      });
      await Promise.allSettled(portChecks);

      const result = {
        ip,
        reverse_dns: Array.isArray(reverseDNS) ? reverseDNS.join(', ') : (reverseDNS || ''),
        hostname: Array.isArray(reverseDNS) && reverseDNS.length > 0 ? reverseDNS[0] : null,
        country: geo.country || null,
        countryCode: geo.countryCode || null,
        region: geo.region || null,
        city: geo.city || null,
        lat: geo.lat || null,
        lon: geo.lon || null,
        timezone: geo.timezone || null,
        isp: geo.isp || null,
        org: geo.org || null,
        asn: geo.as || null,
        asName: geo.asName || null,
        openPorts,
      };

      // AI assessment
      let aiAnalysis = null;
      if (askAI) {
        try {
          const prompt = `Assess this IP address as a security analyst (3-4 sentences):
IP: ${ip}
Location: ${geo.city || '?'}, ${geo.region || '?'}, ${geo.country || '?'}
ISP: ${geo.isp || '?'} | Org: ${geo.org || '?'} | ASN: ${geo.as || '?'}
Reverse DNS: ${result.reverse_dns || 'none'}
Open ports: ${openPorts.map(p => p.port).join(', ') || 'none detected'}

Assess: Is this a hosting provider, residential, corporate? Any notable risks from open ports? Reputation concerns?`;
          aiAnalysis = await askAI(prompt, { timeout: 15000 });
        } catch { /* AI optional */ }
      }
      result.analysis = aiAnalysis;

      saveToHistory('ip', ip, `${geo.city || '?'}, ${geo.country || '?'} — ${geo.isp || '?'}`);
      res.json(result);
    } catch (e) {
      console.error('[OSINT] IP error:', e.message);
      res.status(500).json({ error: 'IP lookup failed: ' + e.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════
  // GET /api/osint/history — Past lookups
  // ═══════════════════════════════════════════════════════════════════════
  app.get('/api/osint/history', requireAuth, (req, res) => {
    const history = readJSON(HISTORY_PATH, []);
    res.json({ history: history.reverse().slice(0, 100) });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // POST /api/osint/analyze — Standalone AI analysis of OSINT data
  // Also handles GET /api/osint/domain/:domain/analyze for frontend compat
  // ═══════════════════════════════════════════════════════════════════════
  app.post('/api/osint/analyze', requireRole('analyst'), async (req, res) => {
    try {
      const { data, type } = req.body;
      if (!data) return res.status(400).json({ error: 'data required' });
      if (!askAI) return res.json({ analysis: 'AI provider not configured. Go to Settings > AI Provider.' });

      const prompt = `You are an OSINT analyst. Analyze these reconnaissance results and provide a security assessment.

Type: ${type || 'unknown'}
Data: ${JSON.stringify(data, null, 2).substring(0, 3000)}

Provide:
1. Summary of what was found (2-3 sentences)
2. Attack surface assessment (what is exposed)
3. Security concerns (specific issues found)
4. Recommendations (actionable steps to reduce exposure)

Keep it concise and actionable.`;

      const analysis = await askAI(prompt, { timeout: 25000 });
      res.json({ analysis: analysis || 'Analysis unavailable.' });
    } catch (e) {
      console.error('[OSINT] AI error:', e.message);
      res.status(500).json({ error: 'AI analysis failed' });
    }
  });

  // GET compat endpoint for frontend "AI Analysis" button
  app.get('/api/osint/domain/:domain/analyze', requireRole('analyst'), async (req, res) => {
    try {
      const domain = req.params.domain;
      if (!askAI) return res.json({ analysis: 'AI provider not configured. Go to Settings > AI Provider.' });

      // Look up history for this domain
      const history = readJSON(HISTORY_PATH, []);
      const past = history.reverse().find(h => h.target === domain && h.type === 'domain');

      const prompt = `You are a security OSINT analyst. Provide a thorough security assessment for the domain: ${domain}
${past ? '\nPrevious lookup summary: ' + (past.summary || 'N/A') : ''}

Assess: domain reputation, attack surface, potential risks, email security, hosting information, and recommendations. 5-8 sentences, specific and actionable.`;

      const analysis = await askAI(prompt, { timeout: 25000 });
      res.json({ analysis: analysis || 'Analysis unavailable.' });
    } catch (e) {
      res.status(500).json({ error: 'AI analysis failed' });
    }
  });

  // ══════════════════════════════════════════════════════════════════════
  //  Web Recon — Scrapy-inspired crawling/reconnaissance
  // ══════════════════════════════════════════════════════════════════════
  const { WebRecon } = require('../lib/web-recon');
  const RECON_PATH = path.join(DATA, 'recon-results.json');
  const activeRecons = new Map();

  // POST /api/osint/recon — start a web recon scan
  app.post('/api/osint/recon', requireRole('analyst'), async (req, res) => {
    const { target, spiderType, depth, maxPages, delay, stealth, feeds } = req.body;

    const validTypes = ['surface', 'exposed', 'fingerprint', 'threat-intel'];
    const type = validTypes.includes(spiderType) ? spiderType : 'surface';

    // threat-intel doesn't need a target URL
    if (type !== 'threat-intel' && (!target || typeof target !== 'string')) {
      return res.status(400).json({ error: 'target URL required' });
    }

    let targetUrl;
    if (type !== 'threat-intel') {
      try {
        targetUrl = new URL(target.startsWith('http') ? target : 'https://' + target);
      } catch {
        return res.status(400).json({ error: 'Invalid URL' });
      }
    }

    const scanId = crypto.randomUUID();
    const recon = new WebRecon({
      depth: Math.min(depth || 2, 3),
      maxPages: Math.min(maxPages || 30, 50),
      delay: Math.max(delay || 500, 200),
      respectRobots: true,
      timeout: 10000,
      stealth: stealth === true,
    });

    activeRecons.set(scanId, { status: 'running', startedAt: new Date().toISOString() });

    const targetLabel = type === 'threat-intel' ? 'threat-feeds' : targetUrl.href;
    res.json({ scanId, spiderType: type, target: targetLabel, status: 'running', stealth: stealth === true });

    // Execute in background
    try {
      if (ctx.io) {
        recon.on('progress', (p) => {
          ctx.io.emit('recon_progress', { scanId, ...p });
        });
      }

      let result;
      if (type === 'surface') result = await recon.surface(targetUrl.href);
      else if (type === 'exposed') result = await recon.exposed(targetUrl.href);
      else if (type === 'threat-intel') result = await recon.threatIntel(feeds);
      else result = await recon.fingerprint(targetUrl.href);

      result.id = scanId;
      result.createdAt = new Date().toISOString();
      result.createdBy = req.user ? req.user.user : 'unknown';

      // Persist
      const results = readJSON(RECON_PATH, []);
      results.push(result);
      if (results.length > 50) results.splice(0, results.length - 50);
      writeJSON(RECON_PATH, results);

      // Save to OSINT history
      const summaryText = type === 'threat-intel'
        ? `threat-intel: ${result.summary.feedsSucceeded}/${result.summary.feedsQueried} feeds, ${result.summary.totalEntries} entries, ${result.summary.iocsExtracted} IOCs`
        : `${type}: ${result.summary.pagesScanned} pages, ${result.summary.emailsFound} emails, ${result.summary.technologiesDetected} techs, ${(result.summary.iocsExtracted || 0)} IOCs`;
      saveToHistory('recon-' + type, targetLabel, summaryText);

      activeRecons.set(scanId, { status: 'completed', result });

      if (ctx.io) {
        ctx.io.emit('recon_complete', { scanId, spiderType: type, target: targetLabel, summary: result.summary });
      }

      console.log(`  [WEB-RECON] ${type} scan ${scanId} completed in ${result.duration}ms`);
    } catch (e) {
      console.error(`  [WEB-RECON] Scan ${scanId} failed:`, e.message);
      activeRecons.set(scanId, { status: 'failed', error: e.message });
      if (ctx.io) ctx.io.emit('recon_complete', { scanId, status: 'failed', error: e.message });
    }
  });

  // GET /api/osint/recon/:id — get recon results
  app.get('/api/osint/recon/:id', requireAuth, (req, res) => {
    // Check in-memory first (active/recent scans)
    const active = activeRecons.get(req.params.id);
    if (active) {
      if (active.status === 'completed') return res.json(active.result);
      if (active.status === 'failed') return res.status(500).json({ error: active.error });
      return res.json({ status: 'running' });
    }

    // Check persisted results
    const results = readJSON(RECON_PATH, []);
    const result = results.find(r => r.id === req.params.id);
    if (!result) return res.status(404).json({ error: 'Recon scan not found' });
    res.json(result);
  });

  // GET /api/osint/recon — list recent recon results
  app.get('/api/osint/recon', requireAuth, (req, res) => {
    const results = readJSON(RECON_PATH, []);
    // Return summary only (not full page data)
    res.json(results.map(r => ({
      id: r.id,
      spiderType: r.spiderType,
      target: r.target,
      domain: r.domain,
      duration: r.duration,
      summary: r.summary,
      createdAt: r.createdAt,
    })).reverse());
  });

  // POST /api/osint/recon/:id/analyze — AI analysis of recon results
  app.post('/api/osint/recon/:id/analyze', requireRole('analyst'), async (req, res) => {
    if (!askAI) return res.status(503).json({ error: 'AI provider not configured' });

    const results = readJSON(RECON_PATH, []);
    const result = results.find(r => r.id === req.params.id);
    if (!result) return res.status(404).json({ error: 'Recon scan not found' });

    try {
      const s = result.summary;
      const prompt = `You are a senior penetration tester analyzing web reconnaissance results. Provide a security assessment.

Target: ${result.target} (${result.domain})
Spider Type: ${result.spiderType}
Pages Scanned: ${s.pagesScanned}
Emails Found: ${s.emailsFound}${result.emails.length ? ' (' + result.emails.slice(0, 5).join(', ') + ')' : ''}
Technologies: ${result.technologies.join(', ') || 'none detected'}
Forms: ${s.formsFound} (${s.loginForms} login forms, ${s.fileUploads} file uploads)
Exposed Paths: ${s.exposedPathsFound} exposed, ${s.forbiddenPaths} forbidden
Security Header Score: ${s.securityHeaderScore !== null ? s.securityHeaderScore + '%' : 'N/A'}
${result.securityHeaders ? 'Missing Headers: ' + result.securityHeaders.missing.join(', ') : ''}
${result.exposedPaths.length ? 'Exposed Files:\n' + result.exposedPaths.filter(p => p.exposed).map(p => `  ${p.path} (${p.risk}) — ${p.statusCode}, ${p.size}B`).join('\n') : ''}

Provide:
1. Risk Assessment (Critical/High/Medium/Low) with justification
2. Key findings (top 5 security concerns)
3. Attack surface analysis
4. Recommendations (prioritized)
Keep it professional and actionable. 8-12 sentences.`;

      const analysis = await askAI(prompt, { timeout: 60000 });
      res.json({ analysis: analysis || 'Analysis unavailable.', scanId: result.id });
    } catch (e) {
      res.status(500).json({ error: 'AI analysis failed: ' + e.message });
    }
  });
};
