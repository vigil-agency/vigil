'use strict';
/**
 * Intel Feeds — Security RSS aggregation, CISA KEV, NVD CVE Watch, AI Briefings
 * Zero new npm deps — uses Node 22 native fetch + regex XML parsing
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, '..', 'data');
const FEEDS_PATH = path.join(DATA_DIR, 'intel-feeds.json');
const KEV_PATH = path.join(DATA_DIR, 'intel-kev.json');
const CVE_WATCH_PATH = path.join(DATA_DIR, 'cve-watchlist.json');
const BRIEFINGS_PATH = path.join(DATA_DIR, 'intel-briefings.json');

const MAX_ITEMS = 500;
const FETCH_TIMEOUT = 15000;

/* ═══════════════════════════════════════════════════════════════════════════
   Feed Registry — 15 curated security RSS/Atom feeds (no API keys needed)
   ═══════════════════════════════════════════════════════════════════════════ */
const FEEDS = {
  'cisa-alerts':   { name: 'CISA Advisories',     url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml',   category: 'advisory' },
  'sans-isc':      { name: 'SANS ISC',             url: 'https://isc.sans.edu/rssfeed.xml',                      category: 'analysis' },
  'krebs':         { name: 'Krebs on Security',    url: 'https://krebsonsecurity.com/feed/',                     category: 'news' },
  'bleeping':      { name: 'BleepingComputer',     url: 'https://www.bleepingcomputer.com/feed/',                category: 'news' },
  'hackernews':    { name: 'The Hacker News',      url: 'https://feeds.feedburner.com/TheHackersNews',           category: 'news' },
  'schneier':      { name: 'Schneier on Security', url: 'https://www.schneier.com/feed/atom/',                   category: 'analysis' },
  'packet-storm':  { name: 'Packet Storm',         url: 'https://rss.packetstormsecurity.com/',                  category: 'exploit' },
  'exploit-db':    { name: 'Exploit-DB',            url: 'https://www.exploit-db.com/rss.xml',                    category: 'exploit' },
  'talos':         { name: 'Cisco Talos',           url: 'https://feeds.feedburner.com/feedburner/Talos',         category: 'analysis' },
  'rapid7':        { name: 'Rapid7 Blog',           url: 'https://blog.rapid7.com/rss/',                         category: 'analysis' },
  'dark-reading':  { name: 'Dark Reading',          url: 'https://www.darkreading.com/rss.xml',                   category: 'news' },
  'sophos':        { name: 'Sophos News',           url: 'https://news.sophos.com/en-us/feed/',                   category: 'analysis' },
  'eset':          { name: 'WeLiveSecurity',        url: 'https://www.welivesecurity.com/feed/',                  category: 'analysis' },
  'securityweek':  { name: 'SecurityWeek',          url: 'https://feeds.feedburner.com/securityweek',             category: 'news' },
  'cvefeed':       { name: 'CVE Feed',              url: 'https://cvefeed.io/rssfeed/latest.xml',                 category: 'vulnerability' },
};

/* ═══════════════════════════════════════════════════════════════════════════
   JSON helpers
   ═══════════════════════════════════════════════════════════════════════════ */
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

/* ═══════════════════════════════════════════════════════════════════════════
   XML / RSS / Atom Parsing (zero deps — regex-based)
   ═══════════════════════════════════════════════════════════════════════════ */
function getTag(xml, tag) {
  const re = new RegExp('<' + tag + '[^>]*>(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?</' + tag + '>', 'i');
  const m = xml.match(re);
  return m ? m[1].trim() : '';
}

function getAttr(xml, tag, attr) {
  const re = new RegExp('<' + tag + '[^>]*?' + attr + '=["\']([^"\']*)["\']', 'i');
  const m = xml.match(re);
  return m ? m[1] : '';
}

function stripHTML(s) {
  return s
    .replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ').trim();
}

function parseXMLFeed(xml) {
  const items = [];

  // Try RSS 2.0 first
  const rssBlocks = xml.match(/<item[\s>][\s\S]*?<\/item>/gi) || [];
  for (const raw of rssBlocks) {
    const title = stripHTML(getTag(raw, 'title'));
    const link = getTag(raw, 'link') || getAttr(raw, 'link', 'href');
    const summary = stripHTML(getTag(raw, 'description') || getTag(raw, 'content:encoded') || '').slice(0, 600);
    const published = getTag(raw, 'pubDate') || getTag(raw, 'dc:date') || '';
    const category = stripHTML(getTag(raw, 'category'));
    if (title) items.push({ title, link, summary, published, category });
  }
  if (items.length) return items;

  // Try Atom
  const atomBlocks = xml.match(/<entry[\s>][\s\S]*?<\/entry>/gi) || [];
  for (const raw of atomBlocks) {
    const title = stripHTML(getTag(raw, 'title'));
    const link = getAttr(raw, 'link', 'href');
    const summary = stripHTML(getTag(raw, 'summary') || getTag(raw, 'content') || '').slice(0, 600);
    const published = getTag(raw, 'updated') || getTag(raw, 'published') || '';
    const category = getAttr(raw, 'category', 'term');
    if (title) items.push({ title, link, summary, published, category });
  }
  return items;
}

/* ═══════════════════════════════════════════════════════════════════════════
   Feed Fetching
   ═══════════════════════════════════════════════════════════════════════════ */
async function fetchSingleFeed(key, feed) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT);
    const res = await fetch(feed.url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Vigil/1.0 SecurityFeedAggregator',
        'Accept': 'application/rss+xml, application/atom+xml, application/xml, text/xml, */*',
      },
    });
    clearTimeout(timer);
    if (!res.ok) return { key, status: 'error', code: res.status, items: [] };

    const xml = await res.text();
    const parsed = parseXMLFeed(xml);
    const items = parsed.slice(0, 30).map(item => {
      let pubISO;
      try { pubISO = item.published ? new Date(item.published).toISOString() : new Date().toISOString(); }
      catch { pubISO = new Date().toISOString(); }
      return {
        id: crypto.createHash('md5').update(item.link || item.title).digest('hex').slice(0, 12),
        source: key,
        sourceName: feed.name,
        category: feed.category,
        title: item.title,
        summary: item.summary,
        url: item.link,
        published: pubISO,
        feedCategory: item.category,
      };
    });
    return { key, status: 'ok', items };
  } catch (e) {
    return { key, status: 'error', error: e.message, items: [] };
  }
}

async function refreshAllFeeds(io) {
  const data = readJSON(FEEDS_PATH, { items: [], feedStatus: {}, lastRefresh: null });
  const existingIds = new Set(data.items.map(i => i.id));
  const feedStatus = {};
  let newCount = 0;
  const newItems = [];

  const keys = Object.keys(FEEDS);
  // Fetch in parallel batches of 5
  for (let i = 0; i < keys.length; i += 5) {
    const batch = keys.slice(i, i + 5);
    const results = await Promise.allSettled(
      batch.map(k => fetchSingleFeed(k, FEEDS[k]))
    );
    for (const r of results) {
      if (r.status !== 'fulfilled') continue;
      const { key, status, items, code, error } = r.value;
      feedStatus[key] = {
        status,
        lastFetch: new Date().toISOString(),
        itemCount: items.length,
        error: error || (code ? 'HTTP ' + code : undefined),
      };
      for (const item of items) {
        if (!existingIds.has(item.id)) {
          newItems.push(item);
          existingIds.add(item.id);
          newCount++;
        }
      }
    }
  }

  // Prepend new items, trim to MAX
  data.items = [...newItems, ...data.items].slice(0, MAX_ITEMS);
  data.feedStatus = { ...data.feedStatus, ...feedStatus };
  data.lastRefresh = new Date().toISOString();
  writeJSON(FEEDS_PATH, data);

  if (io && newCount > 0) {
    io.emit('intel_update', { newCount, lastRefresh: data.lastRefresh });
  }
  return { newCount, total: data.items.length, feedStatus };
}

/* ═══════════════════════════════════════════════════════════════════════════
   CISA KEV (Known Exploited Vulnerabilities)
   ═══════════════════════════════════════════════════════════════════════════ */
async function fetchKEV() {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    const res = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
      signal: controller.signal,
      headers: { 'User-Agent': 'Vigil/1.0' },
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    const json = await res.json();
    const data = {
      lastFetch: new Date().toISOString(),
      title: json.title,
      catalogVersion: json.catalogVersion,
      count: json.count,
      vulnerabilities: (json.vulnerabilities || []).map(v => ({
        cveID: v.cveID,
        vendor: v.vendorProject,
        product: v.product,
        name: v.vulnerabilityName,
        description: v.shortDescription,
        dateAdded: v.dateAdded,
        dueDate: v.dueDate,
        action: v.requiredAction,
        knownRansomware: v.knownRansomwareCampaignUse,
        notes: v.notes,
      })),
    };
    writeJSON(KEV_PATH, data);
    return data;
  } catch (e) {
    return readJSON(KEV_PATH, null);
  }
}

function getKEV() {
  return readJSON(KEV_PATH, null);
}

/* ═══════════════════════════════════════════════════════════════════════════
   NVD CVE Search (rate-limited: 5 req/30s without API key)
   ═══════════════════════════════════════════════════════════════════════════ */
async function searchNVD(keyword, limit) {
  limit = limit || 20;
  try {
    const url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch='
      + encodeURIComponent(keyword) + '&resultsPerPage=' + limit;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'Vigil/1.0' },
    });
    clearTimeout(timer);
    if (!res.ok) return { error: 'NVD API returned ' + res.status };
    const json = await res.json();
    return {
      totalResults: json.totalResults,
      results: (json.vulnerabilities || []).map(v => {
        const cve = v.cve;
        const metrics = cve.metrics && (cve.metrics.cvssMetricV31 && cve.metrics.cvssMetricV31[0])
          || (cve.metrics && cve.metrics.cvssMetricV30 && cve.metrics.cvssMetricV30[0]) || {};
        return {
          id: cve.id,
          description: (cve.descriptions || []).find(d => d.lang === 'en')?.value || '',
          published: cve.published,
          modified: cve.lastModified,
          score: metrics.cvssData && metrics.cvssData.baseScore,
          severity: metrics.cvssData && metrics.cvssData.baseSeverity,
          vector: metrics.cvssData && metrics.cvssData.vectorString,
        };
      }),
    };
  } catch (e) {
    return { error: e.message };
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   CVE Watchlist
   ═══════════════════════════════════════════════════════════════════════════ */
function getCVEWatch() {
  return readJSON(CVE_WATCH_PATH, { watchlist: [], results: [], lastCheck: null });
}

function saveCVEWatch(data) {
  writeJSON(CVE_WATCH_PATH, data);
}

async function refreshCVEWatch() {
  const data = getCVEWatch();
  if (!data.watchlist.length) return data;

  const results = [];
  for (const keyword of data.watchlist) {
    const r = await searchNVD(keyword, 10);
    if (r.results) {
      for (const cve of r.results) {
        results.push({ ...cve, keyword });
      }
    }
    // Rate limit: 7s between requests (NVD: 5 req/30s without key)
    await new Promise(ok => setTimeout(ok, 7000));
  }

  // Dedup by CVE ID, keep highest severity
  const seen = new Map();
  for (const r of results) {
    if (!seen.has(r.id) || (r.score || 0) > (seen.get(r.id).score || 0)) {
      seen.set(r.id, r);
    }
  }

  data.results = [...seen.values()].sort((a, b) => (b.score || 0) - (a.score || 0));
  data.lastCheck = new Date().toISOString();
  saveCVEWatch(data);
  return data;
}

/* ═══════════════════════════════════════════════════════════════════════════
   Feed Data Access
   ═══════════════════════════════════════════════════════════════════════════ */
function getItems(filters) {
  filters = filters || {};
  const data = readJSON(FEEDS_PATH, { items: [], feedStatus: {}, lastRefresh: null });
  let items = data.items;

  if (filters.source) items = items.filter(i => i.source === filters.source);
  if (filters.category) items = items.filter(i => i.category === filters.category);
  if (filters.search) {
    const q = filters.search.toLowerCase();
    items = items.filter(i =>
      (i.title && i.title.toLowerCase().includes(q)) ||
      (i.summary && i.summary.toLowerCase().includes(q))
    );
  }

  const limit = filters.limit || 100;
  const offset = filters.offset || 0;

  return {
    items: items.slice(offset, offset + limit),
    total: items.length,
    feedStatus: data.feedStatus,
    lastRefresh: data.lastRefresh,
  };
}

/* ═══════════════════════════════════════════════════════════════════════════
   AI Briefings — LLM analysis of feed items
   ═══════════════════════════════════════════════════════════════════════════ */
function getBriefings() {
  return readJSON(BRIEFINGS_PATH, []);
}

async function generateBriefing(askAI, scope, feedKeys) {
  scope = scope || 'all';
  const data = readJSON(FEEDS_PATH, { items: [] });
  let items = data.items;

  if (feedKeys && feedKeys.length) {
    items = items.filter(i => feedKeys.includes(i.source));
  }

  items = items.slice(0, 50);
  if (!items.length) return { error: 'No feed items available. Refresh feeds first.' };

  const articleList = items.map(function(item, i) {
    return '[' + (i + 1) + '] ' + item.sourceName + ' | ' + item.title +
      '\n' + (item.summary || 'No summary') +
      '\nURL: ' + (item.url || 'N/A') +
      '\nPublished: ' + (item.published || 'Unknown');
  }).join('\n\n');

  const prompt = 'You are a senior security intelligence analyst producing a threat intelligence briefing for a SOC team.\n\n' +
    'Analyze these ' + items.length + ' recent security articles/advisories:\n\n' + articleList + '\n\n' +
    'Produce a structured intelligence briefing with these sections:\n\n' +
    '## EXECUTIVE SUMMARY\n3-4 sentences summarizing the current threat landscape based on these articles.\n\n' +
    '## CRITICAL ITEMS\nMust-act items: active exploits, critical CVEs, major breaches, urgent advisories. Include CVE IDs where applicable.\n\n' +
    '## NOTABLE THREATS\nNew malware campaigns, APT activity, ransomware trends, emerging attack techniques.\n\n' +
    '## VULNERABILITY SPOTLIGHT\nSignificant vulnerabilities disclosed, affected software/versions, CVSS scores if mentioned.\n\n' +
    '## RECOMMENDED ACTIONS\n5-7 concrete defensive steps a SOC team should take based on this intelligence.\n\n' +
    'Be specific, cite article numbers [N], and prioritize by impact.';

  const briefingText = await askAI(prompt, { timeout: 120000 });
  if (!briefingText) return { error: 'AI analysis failed. Check AI provider configuration.' };

  const briefing = {
    id: crypto.randomUUID(),
    generatedAt: new Date().toISOString(),
    scope: scope,
    feedKeys: feedKeys || Object.keys(FEEDS),
    itemCount: items.length,
    content: briefingText,
  };

  const briefings = getBriefings();
  briefings.unshift(briefing);
  writeJSON(BRIEFINGS_PATH, briefings.slice(0, 20));

  return briefing;
}

async function analyzeItem(askAI, item) {
  const prompt = 'You are a security analyst. Analyze this security article for SOC relevance:\n\n' +
    'Title: ' + item.title + '\n' +
    'Source: ' + item.sourceName + '\n' +
    'Published: ' + item.published + '\n' +
    'Summary: ' + item.summary + '\n' +
    'URL: ' + item.url + '\n\n' +
    'Provide:\n' +
    '1. THREAT LEVEL: Critical/High/Medium/Low/Informational\n' +
    '2. RELEVANCE: Who is affected and why this matters\n' +
    '3. KEY TAKEAWAYS: 2-3 bullet points\n' +
    '4. MITRE ATT&CK: Relevant technique IDs if applicable (e.g., T1566)\n' +
    '5. RECOMMENDED ACTIONS: Specific steps to detect or mitigate\n\n' +
    'Be concise and actionable.';

  return await askAI(prompt, { timeout: 60000 });
}

module.exports = {
  FEEDS,
  refreshAllFeeds,
  fetchKEV,
  searchNVD,
  getItems,
  getKEV,
  getCVEWatch,
  saveCVEWatch,
  refreshCVEWatch,
  getBriefings,
  generateBriefing,
  analyzeItem,
};
