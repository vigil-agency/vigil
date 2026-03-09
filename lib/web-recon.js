/**
 * Vigil — Web Reconnaissance Engine (Scrapy + Scrapling inspired)
 *
 * Lightweight Node.js web crawler for security reconnaissance.
 * Architecture: Spider → Middleware → Pipeline (Scrapy pattern)
 * Stealth features inspired by D4Vinci's Scrapling (browserforge/header-generator)
 *
 * Spider types:
 *   surface     — Crawl domain, extract links/emails/tech/headers + IOC extraction
 *   exposed     — Check common sensitive paths (.env, .git, backups)
 *   fingerprint — Deep tech stack detection from headers + HTML patterns + IOCs
 *   threat-intel — Scrape public threat intelligence feeds (CISA KEV, abuse.ch, etc.)
 */
const https = require('https');
const http = require('http');
const { URL } = require('url');
const EventEmitter = require('events');

// ── Stealth: Realistic browser profiles (Scrapling/browserforge inspired) ──
const BROWSER_PROFILES = [
  {
    ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    acceptLang: 'en-US,en;q=0.9',
    secFetchDest: 'document', secFetchMode: 'navigate', secFetchSite: 'none', secFetchUser: '?1',
    headerOrder: ['host','connection','sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform','upgrade-insecure-requests','user-agent','accept','sec-fetch-site','sec-fetch-mode','sec-fetch-user','sec-fetch-dest','accept-encoding','accept-language'],
  },
  {
    ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    acceptLang: 'en-US,en;q=0.9',
    secFetchDest: 'document', secFetchMode: 'navigate', secFetchSite: 'none', secFetchUser: '?1',
    headerOrder: ['host','connection','sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform','upgrade-insecure-requests','user-agent','accept','sec-fetch-site','sec-fetch-mode','sec-fetch-user','sec-fetch-dest','accept-encoding','accept-language'],
  },
  {
    ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    acceptLang: 'en-US,en;q=0.5',
    secFetchDest: 'document', secFetchMode: 'navigate', secFetchSite: 'none', secFetchUser: '?1',
    headerOrder: ['host','user-agent','accept','accept-language','accept-encoding','connection','upgrade-insecure-requests','sec-fetch-dest','sec-fetch-mode','sec-fetch-site','sec-fetch-user'],
  },
  {
    ua: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    acceptLang: 'en-US,en;q=0.9',
    secFetchDest: 'document', secFetchMode: 'navigate', secFetchSite: 'none', secFetchUser: '?1',
    headerOrder: ['host','connection','sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform','upgrade-insecure-requests','user-agent','accept','sec-fetch-site','sec-fetch-mode','sec-fetch-user','sec-fetch-dest','accept-encoding','accept-language'],
  },
  {
    ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    acceptLang: 'en-US,en;q=0.9',
    secFetchDest: 'document', secFetchMode: 'navigate', secFetchSite: 'none',
    headerOrder: ['host','accept','sec-fetch-site','sec-fetch-dest','sec-fetch-mode','accept-language','user-agent','accept-encoding','connection'],
  },
];

// ── IOC (Indicator of Compromise) regex patterns (InQuest/iocextract inspired) ──
const IOC_PATTERNS = {
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
  ipv6: /\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b/g,
  md5: /(?:[^a-fA-F\d]|\b)([a-fA-F\d]{32})(?:[^a-fA-F\d]|\b)/g,
  sha1: /(?:[^a-fA-F\d]|\b)([a-fA-F\d]{40})(?:[^a-fA-F\d]|\b)/g,
  sha256: /(?:[^a-fA-F\d]|\b)([a-fA-F\d]{64})(?:[^a-fA-F\d]|\b)/g,
  cve: /\bCVE-(1999|2\d{3})-(\d{4,})\b/gi,
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|co|us|uk|de|fr|ru|cn|info|biz|xyz|top|onion)\b/gi,
  url: /https?:\/\/[^\s<>"')\]]+/gi,
  defangedUrl: /hxxps?:\/\/[^\s<>"')\]]+/gi,
  defangedDot: /\[\.\]/g,
};

// ── Public threat intelligence feed URLs (no API key required) ──
const THREAT_FEEDS = {
  cisa_kev: {
    name: 'CISA Known Exploited Vulnerabilities',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    type: 'json',
  },
  feodo: {
    name: 'Feodo Tracker (Botnet C2)',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
    type: 'csv',
  },
  urlhaus: {
    name: 'URLhaus (Malware URLs)',
    url: 'https://urlhaus.abuse.ch/downloads/csv_recent/',
    type: 'csv',
  },
  threatfox_md5: {
    name: 'ThreatFox (Malware MD5)',
    url: 'https://threatfox.abuse.ch/export/csv/md5/recent/',
    type: 'csv',
  },
  openphish: {
    name: 'OpenPhish (Phishing URLs)',
    url: 'https://openphish.com/feed.txt',
    type: 'text',
  },
  ipsum: {
    name: 'IPsum (Threat IP Aggregator)',
    url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt',
    type: 'text',
  },
};

// ── Exposed/Sensitive paths to check ──
const SENSITIVE_PATHS = [
  '/.env', '/.git/config', '/.git/HEAD', '/.gitignore',
  '/.htaccess', '/.htpasswd', '/web.config', '/wp-config.php',
  '/wp-config.php.bak', '/wp-login.php', '/administrator/',
  '/backup.zip', '/backup.tar.gz', '/backup.sql', '/db.sql',
  '/dump.sql', '/database.sql', '/config.php', '/config.yml',
  '/config.json', '/package.json', '/composer.json',
  '/Dockerfile', '/docker-compose.yml', '/.dockerignore',
  '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
  '/.well-known/security.txt', '/server-status', '/server-info',
  '/phpinfo.php', '/info.php', '/test.php', '/debug/',
  '/api/', '/api/v1/', '/api/swagger.json', '/swagger-ui/',
  '/graphql', '/.DS_Store', '/Thumbs.db',
  '/error_log', '/access.log', '/debug.log',
  '/.ssh/authorized_keys', '/id_rsa', '/id_rsa.pub',
  '/credentials.json', '/secrets.yml', '/token.json',
];

// ── Tech fingerprint patterns ──
const TECH_PATTERNS = {
  // Headers
  headers: {
    'x-powered-by': { regex: /(.+)/, field: 'poweredBy' },
    'server': { regex: /(.+)/, field: 'server' },
    'x-aspnet-version': { regex: /(.+)/, field: 'aspnet' },
    'x-drupal-cache': { regex: /.+/, value: 'Drupal' },
    'x-generator': { regex: /(.+)/, field: 'generator' },
    'x-varnish': { regex: /.+/, value: 'Varnish' },
    'x-cache': { regex: /HIT|MISS/, value: 'CDN Cache' },
    'cf-ray': { regex: /.+/, value: 'Cloudflare' },
    'x-amz-cf-id': { regex: /.+/, value: 'AWS CloudFront' },
    'x-vercel-id': { regex: /.+/, value: 'Vercel' },
    'x-netlify-request-id': { regex: /.+/, value: 'Netlify' },
  },
  // HTML body patterns
  body: [
    { regex: /<meta\s+name=["']generator["']\s+content=["']([^"']+)/i, field: 'generator' },
    { regex: /wp-content|wp-includes/i, value: 'WordPress' },
    { regex: /\/sites\/default\/files/i, value: 'Drupal' },
    { regex: /Joomla!/i, value: 'Joomla' },
    { regex: /shopify\.com/i, value: 'Shopify' },
    { regex: /react/i, value: 'React (possible)' },
    { regex: /ng-app|angular/i, value: 'Angular (possible)' },
    { regex: /vue\.js|__vue__/i, value: 'Vue.js (possible)' },
    { regex: /jquery[./\-](\d[\d.]+)/i, field: 'jQuery' },
    { regex: /bootstrap[./\-](\d[\d.]+)/i, field: 'Bootstrap' },
    { regex: /next\.js|__NEXT_DATA__/i, value: 'Next.js' },
    { regex: /nuxt/i, value: 'Nuxt.js' },
    { regex: /laravel/i, value: 'Laravel' },
    { regex: /django/i, value: 'Django' },
    { regex: /express/i, value: 'Express.js (possible)' },
    { regex: /phpmyadmin/i, value: 'phpMyAdmin' },
    { regex: /grafana/i, value: 'Grafana' },
    { regex: /kibana/i, value: 'Kibana' },
    { regex: /gitlab/i, value: 'GitLab' },
    { regex: /jenkins/i, value: 'Jenkins' },
  ],
};

// ── Security headers to check ──
const SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'x-xss-protection',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
];

/** Build stealth headers for a browser profile */
function buildStealthHeaders(profile, referer) {
  const headers = {
    'User-Agent': profile.ua,
    'Accept': profile.accept,
    'Accept-Language': profile.acceptLang,
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': profile.secFetchDest || 'document',
    'Sec-Fetch-Mode': profile.secFetchMode || 'navigate',
    'Sec-Fetch-Site': profile.secFetchSite || 'none',
  };
  if (profile.secFetchUser) headers['Sec-Fetch-User'] = profile.secFetchUser;
  if (referer) {
    headers['Referer'] = referer;
    headers['Sec-Fetch-Site'] = 'cross-site';
  }
  // Chrome-specific sec-ch-ua
  if (profile.ua.includes('Chrome/')) {
    const ver = profile.ua.match(/Chrome\/(\d+)/);
    if (ver) {
      headers['sec-ch-ua'] = `"Chromium";v="${ver[1]}", "Google Chrome";v="${ver[1]}", "Not-A.Brand";v="99"`;
      headers['sec-ch-ua-mobile'] = '?0';
      headers['sec-ch-ua-platform'] = profile.ua.includes('Windows') ? '"Windows"' :
        profile.ua.includes('Macintosh') ? '"macOS"' : '"Linux"';
    }
  }
  return headers;
}

/** Fetch a URL with timeout, redirect following, response metadata, and optional stealth */
function fetchURL(url, timeout = 10000, opts = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;

    // Build headers (stealth or basic)
    let headers;
    if (opts.stealth && opts.profile) {
      headers = buildStealthHeaders(opts.profile, opts.referer);
    } else {
      headers = {
        'User-Agent': 'Vigil-SecurityScanner/1.0 (+https://vigil.agency)',
        'Accept': 'text/html,application/xhtml+xml,*/*',
      };
    }

    const req = mod.request(parsed, {
      method: 'GET',
      timeout,
      headers,
      rejectUnauthorized: false,
    }, (res) => {
      // Follow redirects (up to 3)
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        try {
          const redirectUrl = new URL(res.headers.location, url).href;
          res.resume();
          return fetchURL(redirectUrl, timeout, opts).then(resolve).catch(reject);
        } catch { /* fall through */ }
      }
      let body = '';
      const maxSize = opts.maxBodySize || 500000;
      res.setEncoding('utf8');
      res.on('data', chunk => { if (body.length < maxSize) body += chunk; }); // configurable limit
      res.on('end', () => {
        resolve({
          url,
          statusCode: res.statusCode,
          headers: res.headers,
          body,
          contentType: res.headers['content-type'] || '',
        });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.end();
  });
}

/** Add jitter to a delay (±30%, Scrapling-style) */
function jitterDelay(baseMs) {
  const jitter = baseMs * 0.3;
  return Math.round(baseMs + (Math.random() * 2 - 1) * jitter);
}

/** Extract IOCs (Indicators of Compromise) from text */
function extractIOCs(text) {
  const iocs = { ipv4: [], ipv6: [], md5: [], sha1: [], sha256: [], cves: [], domains: [], urls: [] };
  if (!text || text.length < 10) return iocs;

  // Limit text to avoid regex DoS on huge pages
  const limited = text.substring(0, 200000);

  // IPv4
  const ipv4Set = new Set();
  let m;
  while ((m = IOC_PATTERNS.ipv4.exec(limited)) !== null) {
    const ip = m[0];
    if (!/^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|255\.)/.test(ip) && !/\.\d+\./.test(ip) === false) {
      ipv4Set.add(ip);
    }
  }
  iocs.ipv4 = [...ipv4Set].slice(0, 100);

  // MD5
  const md5Set = new Set();
  IOC_PATTERNS.md5.lastIndex = 0;
  while ((m = IOC_PATTERNS.md5.exec(limited)) !== null) {
    if (m[1] && !/^0+$/.test(m[1]) && !/^f+$/i.test(m[1])) md5Set.add(m[1].toLowerCase());
  }
  iocs.md5 = [...md5Set].slice(0, 50);

  // SHA256
  const sha256Set = new Set();
  IOC_PATTERNS.sha256.lastIndex = 0;
  while ((m = IOC_PATTERNS.sha256.exec(limited)) !== null) {
    if (m[1] && !/^0+$/.test(m[1]) && !/^f+$/i.test(m[1])) sha256Set.add(m[1].toLowerCase());
  }
  iocs.sha256 = [...sha256Set].slice(0, 50);

  // CVEs
  const cveSet = new Set();
  IOC_PATTERNS.cve.lastIndex = 0;
  while ((m = IOC_PATTERNS.cve.exec(limited)) !== null) {
    cveSet.add(m[0].toUpperCase());
  }
  iocs.cves = [...cveSet].slice(0, 100);

  return iocs;
}

/** Parse robots.txt and return disallowed paths */
function parseRobotsTxt(body) {
  const disallowed = [];
  let inWildcard = false;
  for (const line of body.split('\n')) {
    const trimmed = line.trim();
    if (/^user-agent:\s*\*/i.test(trimmed)) inWildcard = true;
    else if (/^user-agent:/i.test(trimmed)) inWildcard = false;
    else if (inWildcard && /^disallow:\s*(.+)/i.test(trimmed)) {
      disallowed.push(RegExp.$1.trim());
    }
  }
  return disallowed;
}

/** Extract links from HTML */
function extractLinks(html, baseUrl) {
  const links = new Set();
  const regex = /(?:href|src|action)=["']([^"'#]+)/gi;
  let match;
  while ((match = regex.exec(html)) !== null) {
    try {
      const resolved = new URL(match[1], baseUrl).href;
      if (resolved.startsWith('http')) links.add(resolved);
    } catch { /* skip invalid URLs */ }
  }
  return [...links];
}

/** Extract emails from HTML */
function extractEmails(html) {
  const emails = new Set();
  const regex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  let match;
  while ((match = regex.exec(html)) !== null) {
    const email = match[0].toLowerCase();
    if (!email.endsWith('.png') && !email.endsWith('.jpg') && !email.endsWith('.gif')) {
      emails.add(email);
    }
  }
  return [...emails];
}

/** Extract forms from HTML */
function extractForms(html, baseUrl) {
  const forms = [];
  const formRegex = /<form[^>]*>([\s\S]*?)<\/form>/gi;
  let match;
  while ((match = formRegex.exec(html)) !== null) {
    const tag = match[0];
    const actionMatch = tag.match(/action=["']([^"']*)/i);
    const methodMatch = tag.match(/method=["']([^"']*)/i);
    const hasPassword = /type=["']password/i.test(match[1]);
    const hasFile = /type=["']file/i.test(match[1]);
    const inputCount = (match[1].match(/<input/gi) || []).length;
    forms.push({
      action: actionMatch ? actionMatch[1] : '',
      method: (methodMatch ? methodMatch[1] : 'GET').toUpperCase(),
      hasPassword,
      hasFile,
      inputCount,
    });
  }
  return forms;
}

/** Detect technologies from headers and body */
function detectTech(headers, body) {
  const techs = new Set();
  const details = {};

  // Header-based detection
  for (const [header, pattern] of Object.entries(TECH_PATTERNS.headers)) {
    const val = headers[header];
    if (val) {
      if (pattern.value) techs.add(pattern.value);
      if (pattern.field) { details[pattern.field] = val; techs.add(val); }
    }
  }

  // Body-based detection
  for (const pattern of TECH_PATTERNS.body) {
    const match = body.match(pattern.regex);
    if (match) {
      if (pattern.value) techs.add(pattern.value);
      if (pattern.field) { details[pattern.field] = match[1] || 'detected'; techs.add(`${pattern.field} ${match[1] || ''}`); }
    }
  }

  return { technologies: [...techs], details };
}

/** Analyze security headers */
function analyzeSecurityHeaders(headers) {
  const present = [];
  const missing = [];
  for (const h of SECURITY_HEADERS) {
    if (headers[h]) present.push({ header: h, value: headers[h] });
    else missing.push(h);
  }
  const score = Math.round((present.length / SECURITY_HEADERS.length) * 100);
  return { present, missing, score, total: SECURITY_HEADERS.length };
}


// ═══════════════════════════════════════════════════════════════════════
//  WebRecon — Main crawler engine
// ═══════════════════════════════════════════════════════════════════════

class WebRecon extends EventEmitter {
  constructor(options = {}) {
    super();
    this.maxDepth = options.depth || 2;
    this.maxPages = options.maxPages || 30;
    this.delay = options.delay || 500; // ms between requests
    this.respectRobots = options.respectRobots !== false;
    this.timeout = options.timeout || 10000;
    this.stealth = options.stealth || false;

    // Stealth: pick a random browser profile for this session
    this._profile = BROWSER_PROFILES[Math.floor(Math.random() * BROWSER_PROFILES.length)];
    // Stealth: inject Google referer on first request (Scrapling stealthy_headers pattern)
    this._initialReferer = this.stealth ? 'https://www.google.com/' : null;

    // Scheduler state
    this._visited = new Set();
    this._queue = [];
    this._results = { pages: [], emails: new Set(), technologies: new Set(), forms: [], exposedPaths: [], securityHeaders: null, iocs: { ipv4: [], md5: [], sha256: [], cves: [] } };
    this._pageCount = 0;
    this._running = false;
    this._disallowed = [];
    this._targetDomain = null;
  }

  /** Fetch options for stealth/normal mode */
  _fetchOpts(referer) {
    if (!this.stealth) return {};
    return { stealth: true, profile: this._profile, referer: referer || undefined };
  }

  /** Delay with jitter in stealth mode, flat delay otherwise */
  async _rateLimit(baseMs) {
    const ms = this.stealth ? jitterDelay(baseMs || this.delay) : (baseMs || this.delay);
    if (ms > 0) await this._sleep(ms);
  }

  /** Merge extracted IOCs into cumulative results */
  _mergeIOCs(iocs) {
    const r = this._results.iocs;
    for (const ip of iocs.ipv4) { if (!r.ipv4.includes(ip) && r.ipv4.length < 200) r.ipv4.push(ip); }
    for (const h of iocs.md5) { if (!r.md5.includes(h) && r.md5.length < 100) r.md5.push(h); }
    for (const h of iocs.sha256) { if (!r.sha256.includes(h) && r.sha256.length < 100) r.sha256.push(h); }
    for (const c of iocs.cves) { if (!r.cves.includes(c) && r.cves.length < 200) r.cves.push(c); }
  }

  /** Run a surface scan — crawl and extract everything + IOCs */
  async surface(targetUrl) {
    const start = Date.now();
    const parsed = new URL(targetUrl);
    this._targetDomain = parsed.hostname;

    // Check robots.txt
    if (this.respectRobots) {
      try {
        const robotsUrl = `${parsed.protocol}//${parsed.host}/robots.txt`;
        const r = await fetchURL(robotsUrl, 5000, this._fetchOpts());
        if (r.statusCode === 200) this._disallowed = parseRobotsTxt(r.body);
      } catch { /* no robots.txt */ }
    }

    // Seed the queue
    this._queue.push({ url: targetUrl, depth: 0 });

    // Crawl loop
    let firstRequest = true;
    while (this._queue.length > 0 && this._pageCount < this.maxPages) {
      const { url, depth } = this._queue.shift();
      if (this._visited.has(url)) continue;
      if (depth > this.maxDepth) continue;
      if (this._isDisallowed(url)) continue;

      this._visited.add(url);
      this.emit('progress', { phase: 'crawling', url, pageCount: this._pageCount, queueSize: this._queue.length });

      try {
        const referer = firstRequest ? this._initialReferer : targetUrl;
        firstRequest = false;
        const response = await fetchURL(url, this.timeout, this._fetchOpts(referer));
        this._pageCount++;

        const isHTML = response.contentType.includes('text/html');
        const page = {
          url: response.url,
          statusCode: response.statusCode,
          contentType: response.contentType,
          size: response.body.length,
        };

        if (isHTML) {
          // Extract links
          const links = extractLinks(response.body, url);
          const internal = links.filter(l => this._isInternal(l));
          const external = links.filter(l => !this._isInternal(l));
          page.internalLinks = internal.length;
          page.externalLinks = external.length;

          // Queue internal links for crawling
          for (const link of internal) {
            if (!this._visited.has(link)) {
              this._queue.push({ url: link, depth: depth + 1 });
            }
          }

          // Extract emails
          const emails = extractEmails(response.body);
          emails.forEach(e => this._results.emails.add(e));

          // Extract forms
          const forms = extractForms(response.body, url);
          if (forms.length) {
            this._results.forms.push(...forms.map(f => ({ ...f, page: url })));
          }

          // Tech detection
          const tech = detectTech(response.headers, response.body);
          tech.technologies.forEach(t => this._results.technologies.add(t));

          // IOC extraction
          const iocs = extractIOCs(response.body);
          this._mergeIOCs(iocs);
        }

        // Security headers (first page only)
        if (!this._results.securityHeaders) {
          this._results.securityHeaders = analyzeSecurityHeaders(response.headers);
        }

        this._results.pages.push(page);

        // Rate limiting (with jitter in stealth mode)
        await this._rateLimit();
      } catch (e) {
        this._results.pages.push({ url, statusCode: 0, error: e.message });
      }
    }

    return this._buildResult('surface', targetUrl, Date.now() - start);
  }

  /** Run exposed files check — probe sensitive paths */
  async exposed(targetUrl) {
    const start = Date.now();
    const parsed = new URL(targetUrl);
    const baseUrl = `${parsed.protocol}//${parsed.host}`;
    this._targetDomain = parsed.hostname;

    this.emit('progress', { phase: 'scanning', message: `Checking ${SENSITIVE_PATHS.length} paths...` });

    const results = [];
    for (const p of SENSITIVE_PATHS) {
      const url = baseUrl + p;
      try {
        const response = await fetchURL(url, this.timeout, this._fetchOpts(targetUrl));
        const isExposed = response.statusCode === 200 && response.body.length > 0;
        const isForbidden = response.statusCode === 403;
        if (isExposed || isForbidden) {
          const risk = isExposed ? this._assessPathRisk(p) : 'info';
          results.push({
            path: p,
            url,
            statusCode: response.statusCode,
            size: response.body.length,
            contentType: response.contentType,
            risk,
            exposed: isExposed,
          });
          this.emit('progress', { phase: 'found', path: p, status: response.statusCode, risk });
        }
      } catch { /* timeout/error = not reachable */ }

      await this._rateLimit(Math.max(this.delay, 200));
    }

    this._results.exposedPaths = results;
    return this._buildResult('exposed', targetUrl, Date.now() - start);
  }

  /** Run tech fingerprinting — deep analysis of target + IOCs */
  async fingerprint(targetUrl) {
    const start = Date.now();
    const parsed = new URL(targetUrl);
    this._targetDomain = parsed.hostname;

    this.emit('progress', { phase: 'fingerprinting', url: targetUrl });

    // Fetch main page
    try {
      const response = await fetchURL(targetUrl, this.timeout, this._fetchOpts(this._initialReferer));
      const tech = detectTech(response.headers, response.body);
      tech.technologies.forEach(t => this._results.technologies.add(t));

      this._results.securityHeaders = analyzeSecurityHeaders(response.headers);
      this._results.pages.push({
        url: response.url,
        statusCode: response.statusCode,
        size: response.body.length,
      });

      // Extract forms
      const forms = extractForms(response.body, targetUrl);
      this._results.forms = forms.map(f => ({ ...f, page: targetUrl }));

      // IOC extraction
      const iocs = extractIOCs(response.body);
      this._mergeIOCs(iocs);

      // Check a few key paths for more tech clues
      const techPaths = ['/robots.txt', '/sitemap.xml', '/favicon.ico', '/wp-login.php', '/administrator/', '/api/', '/.well-known/security.txt'];
      for (const p of techPaths) {
        try {
          const r = await fetchURL(`${parsed.protocol}//${parsed.host}${p}`, 5000, this._fetchOpts(targetUrl));
          if (r.statusCode === 200) {
            if (p === '/wp-login.php') this._results.technologies.add('WordPress');
            if (p === '/administrator/') this._results.technologies.add('Joomla');
            if (p === '/.well-known/security.txt') this._results.technologies.add('security.txt present');
            if (p === '/robots.txt') {
              const sitemaps = r.body.match(/Sitemap:\s*(.+)/gi) || [];
              if (sitemaps.length) this._results.technologies.add(`${sitemaps.length} sitemap(s)`);
            }
          }
        } catch { /* skip */ }
        await this._rateLimit(200);
      }
    } catch (e) {
      this._results.pages.push({ url: targetUrl, statusCode: 0, error: e.message });
    }

    return this._buildResult('fingerprint', targetUrl, Date.now() - start);
  }

  /** Run threat intel collection — scrape public feeds for IOCs */
  async threatIntel(feedKeys) {
    const start = Date.now();
    const feeds = feedKeys && feedKeys.length
      ? feedKeys.filter(k => THREAT_FEEDS[k]).map(k => ({ key: k, ...THREAT_FEEDS[k] }))
      : Object.entries(THREAT_FEEDS).map(([key, feed]) => ({ key, ...feed }));

    const feedResults = [];

    for (const feed of feeds) {
      this.emit('progress', { phase: 'fetching', message: `Fetching ${feed.name}...` });
      try {
        const fetchOpts = { ...this._fetchOpts(), maxBodySize: 5000000 }; // 5MB for feeds
        const response = await fetchURL(feed.url, 30000, fetchOpts);
        if (response.statusCode !== 200) {
          feedResults.push({ feed: feed.key, name: feed.name, status: 'error', statusCode: response.statusCode, entries: 0 });
          continue;
        }

        let entries = [];
        if (feed.type === 'json') {
          try {
            const data = JSON.parse(response.body);
            // CISA KEV format
            if (data.vulnerabilities) {
              entries = data.vulnerabilities.slice(0, 100).map(v => ({
                cve: v.cveID,
                vendor: v.vendorProject,
                product: v.product,
                name: v.vulnerabilityName,
                dateAdded: v.dateAdded,
                dueDate: v.dueDate,
                shortDescription: (v.shortDescription || '').substring(0, 200),
              }));
            }
          } catch { /* parse error */ }
        } else if (feed.type === 'csv') {
          const lines = response.body.split('\n').filter(l => l.trim() && !l.startsWith('#'));
          entries = lines.slice(0, 200).map(l => {
            const cols = l.split(',').map(c => c.replace(/^"|"$/g, '').trim());
            return { raw: cols.slice(0, 5).join(' | ') };
          });
          // Extract IOCs from CSV text
          const iocs = extractIOCs(response.body);
          this._mergeIOCs(iocs);
        } else if (feed.type === 'text') {
          const lines = response.body.split('\n').filter(l => l.trim() && !l.startsWith('#'));
          entries = lines.slice(0, 200).map(l => ({ value: l.trim() }));
          const iocs = extractIOCs(response.body);
          this._mergeIOCs(iocs);
        }

        feedResults.push({
          feed: feed.key,
          name: feed.name,
          status: 'ok',
          entries: entries.length,
          data: entries.slice(0, 50),
          fetchedAt: new Date().toISOString(),
        });

        await this._rateLimit(1000);
      } catch (e) {
        feedResults.push({ feed: feed.key, name: feed.name, status: 'error', error: e.message, entries: 0 });
      }
    }

    const result = {
      spiderType: 'threat-intel',
      target: 'threat-feeds',
      domain: null,
      duration: Date.now() - start,
      feeds: feedResults,
      iocs: { ...this._results.iocs },
      summary: {
        feedsQueried: feeds.length,
        feedsSucceeded: feedResults.filter(f => f.status === 'ok').length,
        totalEntries: feedResults.reduce((sum, f) => sum + f.entries, 0),
        iocsExtracted: this._results.iocs.ipv4.length + this._results.iocs.md5.length + this._results.iocs.sha256.length + this._results.iocs.cves.length,
      },
    };
    return result;
  }

  _isInternal(url) {
    try {
      return new URL(url).hostname === this._targetDomain;
    } catch { return false; }
  }

  _isDisallowed(url) {
    if (!this._disallowed.length) return false;
    try {
      const p = new URL(url).pathname;
      return this._disallowed.some(d => p.startsWith(d));
    } catch { return false; }
  }

  _assessPathRisk(path) {
    if (/\.env|credentials|secret|token|id_rsa|\.ssh/i.test(path)) return 'critical';
    if (/\.git|\.htpasswd|wp-config|config\.(php|yml|json)|\.sql|dump/i.test(path)) return 'high';
    if (/backup|phpinfo|debug|server-(status|info)/i.test(path)) return 'medium';
    return 'low';
  }

  _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  _buildResult(spiderType, target, duration) {
    const iocCount = this._results.iocs.ipv4.length + this._results.iocs.md5.length +
      this._results.iocs.sha256.length + this._results.iocs.cves.length;
    return {
      spiderType,
      target,
      domain: this._targetDomain,
      duration,
      stealth: this.stealth,
      pagesScanned: this._results.pages.length,
      pages: this._results.pages,
      emails: [...this._results.emails],
      technologies: [...this._results.technologies],
      forms: this._results.forms,
      exposedPaths: this._results.exposedPaths,
      securityHeaders: this._results.securityHeaders,
      iocs: { ...this._results.iocs },
      summary: {
        pagesScanned: this._results.pages.length,
        emailsFound: this._results.emails.size,
        technologiesDetected: this._results.technologies.size,
        formsFound: this._results.forms.length,
        exposedPathsFound: this._results.exposedPaths.filter(p => p.exposed).length,
        forbiddenPaths: this._results.exposedPaths.filter(p => p.statusCode === 403).length,
        securityHeaderScore: this._results.securityHeaders ? this._results.securityHeaders.score : null,
        loginForms: this._results.forms.filter(f => f.hasPassword).length,
        fileUploads: this._results.forms.filter(f => f.hasFile).length,
        iocsExtracted: iocCount,
      },
    };
  }
}

module.exports = { WebRecon, fetchURL, extractIOCs, SENSITIVE_PATHS, SECURITY_HEADERS, THREAT_FEEDS, IOC_PATTERNS };
