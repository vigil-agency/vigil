'use strict';
/**
 * Intel Hub — Security feed aggregation, CVE watch, AI briefings, CISA KEV
 */
const intel = require('../lib/intel-feeds');

module.exports = function(app, ctx) {
  const { requireAuth, requireRole, askAI } = ctx;

  /* ── Feed items ── */
  app.get('/api/intel/feeds', requireAuth, (req, res) => {
    const { source, category, search, limit, offset } = req.query;
    const result = intel.getItems({
      source, category, search,
      limit: parseInt(limit) || 100,
      offset: parseInt(offset) || 0,
    });
    res.json(result);
  });

  /* ── Refresh feeds (manual trigger) ── */
  app.post('/api/intel/feeds/refresh', requireRole('analyst'), async (req, res) => {
    try {
      const result = await intel.refreshAllFeeds(ctx.io);
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  /* ── AI analyze single article ── */
  app.post('/api/intel/feeds/analyze', requireRole('analyst'), async (req, res) => {
    const { item } = req.body;
    if (!item) return res.status(400).json({ error: 'item required' });
    try {
      const analysis = await intel.analyzeItem(askAI, item);
      res.json({ analysis });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  /* ── CISA KEV ── */
  app.get('/api/intel/kev', requireAuth, async (req, res) => {
    let data = intel.getKEV();
    if (!data) data = await intel.fetchKEV();
    if (!data) return res.status(503).json({ error: 'KEV data unavailable' });

    const { search, limit } = req.query;
    let vulns = data.vulnerabilities || [];
    if (search) {
      const q = search.toLowerCase();
      vulns = vulns.filter(v =>
        v.cveID.toLowerCase().includes(q) ||
        v.vendor.toLowerCase().includes(q) ||
        v.product.toLowerCase().includes(q) ||
        (v.description || '').toLowerCase().includes(q)
      );
    }
    const lim = parseInt(limit) || 50;
    res.json({
      lastFetch: data.lastFetch,
      title: data.title,
      catalogVersion: data.catalogVersion,
      count: data.count,
      vulnerabilities: vulns.slice(0, lim),
      totalFiltered: vulns.length,
    });
  });

  app.post('/api/intel/kev/refresh', requireRole('analyst'), async (req, res) => {
    const data = await intel.fetchKEV();
    if (!data) return res.status(503).json({ error: 'Failed to fetch KEV' });
    res.json({ count: data.count, lastFetch: data.lastFetch });
  });

  /* ── CVE Watch ── */
  app.get('/api/intel/cve-watch', requireAuth, (req, res) => {
    res.json(intel.getCVEWatch());
  });

  app.post('/api/intel/cve-watch', requireRole('analyst'), async (req, res) => {
    const { action, keyword } = req.body;
    const data = intel.getCVEWatch();

    if (action === 'add' && keyword) {
      const kw = keyword.toLowerCase().trim();
      if (kw && !data.watchlist.includes(kw)) {
        data.watchlist.push(kw);
        intel.saveCVEWatch(data);
      }
      res.json(data);
    } else if (action === 'remove' && keyword) {
      data.watchlist = data.watchlist.filter(k => k !== keyword.toLowerCase().trim());
      intel.saveCVEWatch(data);
      res.json(data);
    } else if (action === 'refresh') {
      try {
        const updated = await intel.refreshCVEWatch();
        res.json(updated);
      } catch (e) {
        res.status(500).json({ error: e.message });
      }
    } else {
      res.status(400).json({ error: 'action (add/remove/refresh) required' });
    }
  });

  /* ── NVD ad-hoc search ── */
  app.get('/api/intel/nvd', requireAuth, async (req, res) => {
    const { keyword } = req.query;
    if (!keyword) return res.status(400).json({ error: 'keyword required' });
    const result = await intel.searchNVD(keyword);
    res.json(result);
  });

  /* ── AI Briefings ── */
  app.get('/api/intel/briefings', requireAuth, (req, res) => {
    res.json({ briefings: intel.getBriefings() });
  });

  app.post('/api/intel/briefings/generate', requireRole('analyst'), async (req, res) => {
    const { scope, feedKeys } = req.body;
    try {
      const briefing = await intel.generateBriefing(askAI, scope, feedKeys);
      if (briefing.error) return res.status(400).json(briefing);
      res.json(briefing);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  /* ── Feed registry (for frontend dropdowns) ── */
  app.get('/api/intel/sources', requireAuth, (req, res) => {
    const sources = Object.entries(intel.FEEDS).map(function(entry) {
      return { key: entry[0], name: entry[1].name, category: entry[1].category };
    });
    res.json({ sources });
  });
};
