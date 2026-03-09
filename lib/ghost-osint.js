/**
 * Vigil — Ghost OSINT Module (GhostTrack-inspired)
 *
 * Username enumeration across 25+ social platforms + phone number intelligence.
 * Pure Node.js — no external dependencies.
 */
const https = require('https');
const http = require('http');
const { URL } = require('url');
const crypto = require('crypto');
const neuralCache = require('./neural-cache');

// ── Stealth headers for platform checks ──
const STEALTH_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
  'Accept-Encoding': 'identity',
  'Connection': 'keep-alive',
  'Sec-Fetch-Dest': 'document',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'none',
  'Sec-Fetch-User': '?1',
  'Upgrade-Insecure-Requests': '1',
};

// ── Disposable/throwaway email domains ──
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com', 'guerrillamail.com', 'tempmail.com', 'throwaway.email',
  'yopmail.com', 'sharklasers.com', 'guerrillamailblock.com', 'grr.la',
  'dispostable.com', 'maildrop.cc', 'temp-mail.org', 'fakeinbox.com',
  'emailondeck.com', 'getnada.com', 'trashmail.com', 'mohmal.com',
  '10minutemail.com', 'temp-mail.io', 'tempail.com', 'harakirimail.com',
  'mailnesia.com', 'jetable.org', 'mytrashmail.com', 'trashinbox.com',
  'getairmail.com', 'crazymailing.com', 'trbvn.com', 'mailforspam.com',
  'spambox.us', 'spamfree24.org', 'mintemail.com', 'mt2015.com',
]);

// ── Free email providers ──
const FREE_PROVIDERS = new Set([
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
  'icloud.com', 'me.com', 'protonmail.com', 'proton.me', 'zoho.com',
  'mail.com', 'gmx.com', 'gmx.net', 'yandex.com', 'yandex.ru',
  'live.com', 'msn.com', 'tutanota.com', 'tuta.com', 'fastmail.com',
  'hey.com', 'mail.ru', 'inbox.com', 'rocketmail.com', 'att.net',
]);

// ── Platforms for username enumeration ──
// method: 'status' = 200 means found, 404 = not found
// method: 'json'   = parse JSON and check for key
const PLATFORMS = [
  // Developer
  { name: 'GitHub', category: 'dev', url: 'https://github.com/{user}', method: 'status' },
  { name: 'GitLab', category: 'dev', url: 'https://gitlab.com/{user}', method: 'status' },
  { name: 'Bitbucket', category: 'dev', url: 'https://bitbucket.org/{user}/', method: 'status' },
  { name: 'Dev.to', category: 'dev', url: 'https://dev.to/{user}', method: 'status' },
  { name: 'npm', category: 'dev', url: 'https://www.npmjs.com/~{user}', method: 'status' },
  { name: 'PyPI', category: 'dev', url: 'https://pypi.org/user/{user}/', method: 'status' },
  { name: 'Docker Hub', category: 'dev', url: 'https://hub.docker.com/u/{user}/', method: 'status' },
  { name: 'Replit', category: 'dev', url: 'https://replit.com/@{user}', method: 'status' },
  { name: 'Codepen', category: 'dev', url: 'https://codepen.io/{user}', method: 'status' },
  // Security
  { name: 'HackerOne', category: 'security', url: 'https://hackerone.com/{user}', method: 'status' },
  { name: 'Keybase', category: 'security', url: 'https://keybase.io/{user}', method: 'status' },
  // Social / Content
  { name: 'Reddit', category: 'social', url: 'https://www.reddit.com/user/{user}/about.json', method: 'json', foundKey: 'data' },
  { name: 'HackerNews', category: 'dev', url: 'https://hacker-news.firebaseio.com/v0/user/{user}.json', method: 'json', foundKey: 'id' },
  { name: 'Medium', category: 'content', url: 'https://medium.com/@{user}', method: 'status' },
  { name: 'Twitch', category: 'content', url: 'https://www.twitch.tv/{user}', method: 'status' },
  { name: 'YouTube', category: 'content', url: 'https://www.youtube.com/@{user}', method: 'status' },
  { name: 'Pinterest', category: 'social', url: 'https://www.pinterest.com/{user}/', method: 'status' },
  { name: 'SoundCloud', category: 'content', url: 'https://soundcloud.com/{user}', method: 'status' },
  { name: 'Flickr', category: 'content', url: 'https://www.flickr.com/people/{user}/', method: 'status' },
  { name: 'Patreon', category: 'content', url: 'https://www.patreon.com/{user}', method: 'status' },
  { name: 'Gravatar', category: 'social', url: 'https://en.gravatar.com/{user}.json', method: 'json', foundKey: 'entry' },
  { name: 'About.me', category: 'social', url: 'https://about.me/{user}', method: 'status' },
  { name: 'Linktree', category: 'social', url: 'https://linktr.ee/{user}', method: 'status' },
  // Design / Creative
  { name: 'Dribbble', category: 'design', url: 'https://dribbble.com/{user}', method: 'status' },
  { name: 'Behance', category: 'design', url: 'https://www.behance.net/{user}', method: 'status' },
  // Gaming
  { name: 'Steam', category: 'gaming', url: 'https://steamcommunity.com/id/{user}', method: 'status' },
];

// ── Country calling codes (E.164) ──
const COUNTRY_CODES = {
  '1': { country: 'United States / Canada', iso: 'US', lengths: [10] },
  '7': { country: 'Russia / Kazakhstan', iso: 'RU', lengths: [10] },
  '20': { country: 'Egypt', iso: 'EG', lengths: [10] },
  '27': { country: 'South Africa', iso: 'ZA', lengths: [9] },
  '30': { country: 'Greece', iso: 'GR', lengths: [10] },
  '31': { country: 'Netherlands', iso: 'NL', lengths: [9] },
  '32': { country: 'Belgium', iso: 'BE', lengths: [8, 9] },
  '33': { country: 'France', iso: 'FR', lengths: [9] },
  '34': { country: 'Spain', iso: 'ES', lengths: [9] },
  '36': { country: 'Hungary', iso: 'HU', lengths: [8, 9] },
  '39': { country: 'Italy', iso: 'IT', lengths: [9, 10] },
  '40': { country: 'Romania', iso: 'RO', lengths: [9] },
  '41': { country: 'Switzerland', iso: 'CH', lengths: [9] },
  '43': { country: 'Austria', iso: 'AT', lengths: [10, 11] },
  '44': { country: 'United Kingdom', iso: 'GB', lengths: [10] },
  '45': { country: 'Denmark', iso: 'DK', lengths: [8] },
  '46': { country: 'Sweden', iso: 'SE', lengths: [9] },
  '47': { country: 'Norway', iso: 'NO', lengths: [8] },
  '48': { country: 'Poland', iso: 'PL', lengths: [9] },
  '49': { country: 'Germany', iso: 'DE', lengths: [10, 11] },
  '51': { country: 'Peru', iso: 'PE', lengths: [9] },
  '52': { country: 'Mexico', iso: 'MX', lengths: [10] },
  '54': { country: 'Argentina', iso: 'AR', lengths: [10] },
  '55': { country: 'Brazil', iso: 'BR', lengths: [10, 11] },
  '56': { country: 'Chile', iso: 'CL', lengths: [9] },
  '57': { country: 'Colombia', iso: 'CO', lengths: [10] },
  '60': { country: 'Malaysia', iso: 'MY', lengths: [9, 10] },
  '61': { country: 'Australia', iso: 'AU', lengths: [9] },
  '62': { country: 'Indonesia', iso: 'ID', lengths: [10, 11, 12] },
  '63': { country: 'Philippines', iso: 'PH', lengths: [10] },
  '64': { country: 'New Zealand', iso: 'NZ', lengths: [8, 9] },
  '65': { country: 'Singapore', iso: 'SG', lengths: [8] },
  '66': { country: 'Thailand', iso: 'TH', lengths: [9] },
  '81': { country: 'Japan', iso: 'JP', lengths: [10] },
  '82': { country: 'South Korea', iso: 'KR', lengths: [9, 10] },
  '84': { country: 'Vietnam', iso: 'VN', lengths: [9, 10] },
  '86': { country: 'China', iso: 'CN', lengths: [11] },
  '90': { country: 'Turkey', iso: 'TR', lengths: [10] },
  '91': { country: 'India', iso: 'IN', lengths: [10] },
  '92': { country: 'Pakistan', iso: 'PK', lengths: [10] },
  '93': { country: 'Afghanistan', iso: 'AF', lengths: [9] },
  '94': { country: 'Sri Lanka', iso: 'LK', lengths: [9] },
  '98': { country: 'Iran', iso: 'IR', lengths: [10] },
  '212': { country: 'Morocco', iso: 'MA', lengths: [9] },
  '213': { country: 'Algeria', iso: 'DZ', lengths: [9] },
  '216': { country: 'Tunisia', iso: 'TN', lengths: [8] },
  '234': { country: 'Nigeria', iso: 'NG', lengths: [10] },
  '254': { country: 'Kenya', iso: 'KE', lengths: [9] },
  '255': { country: 'Tanzania', iso: 'TZ', lengths: [9] },
  '256': { country: 'Uganda', iso: 'UG', lengths: [9] },
  '351': { country: 'Portugal', iso: 'PT', lengths: [9] },
  '353': { country: 'Ireland', iso: 'IE', lengths: [9] },
  '358': { country: 'Finland', iso: 'FI', lengths: [9, 10] },
  '380': { country: 'Ukraine', iso: 'UA', lengths: [9] },
  '420': { country: 'Czech Republic', iso: 'CZ', lengths: [9] },
  '852': { country: 'Hong Kong', iso: 'HK', lengths: [8] },
  '880': { country: 'Bangladesh', iso: 'BD', lengths: [10] },
  '886': { country: 'Taiwan', iso: 'TW', lengths: [9] },
  '961': { country: 'Lebanon', iso: 'LB', lengths: [7, 8] },
  '962': { country: 'Jordan', iso: 'JO', lengths: [8, 9] },
  '964': { country: 'Iraq', iso: 'IQ', lengths: [10] },
  '966': { country: 'Saudi Arabia', iso: 'SA', lengths: [9] },
  '971': { country: 'UAE', iso: 'AE', lengths: [9] },
  '972': { country: 'Israel', iso: 'IL', lengths: [9] },
  '974': { country: 'Qatar', iso: 'QA', lengths: [8] },
  '977': { country: 'Nepal', iso: 'NP', lengths: [10] },
};

// ── HTTP check for a single URL ──
function checkURL(url, timeout = 8000) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const mod = parsed.protocol === 'https:' ? https : http;
      const req = mod.request(parsed, {
        method: 'GET',
        timeout,
        headers: STEALTH_HEADERS,
        rejectUnauthorized: false,
      }, (res) => {
        // Follow one redirect
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
          const loc = res.headers.location;
          res.resume();
          if (/login|signin|sign_in|accounts|error|404|not.?found/i.test(loc)) {
            resolve({ statusCode: 404, redirect: loc });
            return;
          }
          try {
            checkURL(new URL(loc, url).href, timeout).then(resolve);
          } catch { resolve({ statusCode: res.statusCode }); }
          return;
        }
        let body = '';
        res.setEncoding('utf8');
        res.on('data', chunk => { if (body.length < 5000) body += chunk; });
        res.on('end', () => resolve({ statusCode: res.statusCode, body: body.substring(0, 3000) }));
      });
      req.on('error', () => resolve({ statusCode: 0, error: 'connection_error' }));
      req.on('timeout', () => { req.destroy(); resolve({ statusCode: 0, error: 'timeout' }); });
      req.end();
    } catch (e) {
      resolve({ statusCode: 0, error: e.message });
    }
  });
}

// ── HTTP POST helper for email service checks ──
function httpPost(url, body, contentType, timeout = 6000) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(url);
      const data = typeof body === 'string' ? body : JSON.stringify(body);
      const mod = parsed.protocol === 'https:' ? https : http;
      const req = mod.request(parsed, {
        method: 'POST',
        timeout,
        headers: {
          ...STEALTH_HEADERS,
          'Content-Type': contentType || 'application/json',
          'Content-Length': Buffer.byteLength(data),
        },
        rejectUnauthorized: false,
      }, (res) => {
        let respBody = '';
        res.setEncoding('utf8');
        res.on('data', chunk => { if (respBody.length < 5000) respBody += chunk; });
        res.on('end', () => resolve({ statusCode: res.statusCode, body: respBody }));
      });
      req.on('error', () => resolve({ statusCode: 0, error: 'connection_error' }));
      req.on('timeout', () => { req.destroy(); resolve({ statusCode: 0, error: 'timeout' }); });
      req.write(data);
      req.end();
    } catch (e) {
      resolve({ statusCode: 0, error: e.message });
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════
//  Username Enumeration
// ═══════════════════════════════════════════════════════════════════════

async function enumerateUsername(username, onProgress) {
  const start = Date.now();
  const results = [];

  // Validate username
  if (!username || !/^[a-zA-Z0-9_.\-]{1,40}$/.test(username)) {
    return { error: 'Invalid username. Use alphanumeric, underscore, dash, dot (1-40 chars).' };
  }

  // Run in batches of 5
  for (let i = 0; i < PLATFORMS.length; i += 5) {
    const batch = PLATFORMS.slice(i, i + 5);
    const checks = batch.map(async (platform) => {
      const url = platform.url.replace('{user}', encodeURIComponent(username));
      if (onProgress) onProgress({ platform: platform.name, url, checked: i + batch.indexOf(platform) + 1, total: PLATFORMS.length });

      const response = await checkURL(url);
      let found = false;

      if (platform.method === 'status') {
        found = response.statusCode === 200;
      } else if (platform.method === 'json') {
        try {
          if (response.statusCode === 200 && response.body) {
            const data = JSON.parse(response.body);
            found = platform.foundKey ? !!data[platform.foundKey] : !!data;
          }
        } catch { found = false; }
      }

      // False positive check: some sites return 200 with "not found" content
      if (found && response.body) {
        const snippet = response.body.substring(0, 1000).toLowerCase();
        if (/page not found|user not found|profile.*not found|doesn.t exist|does not exist|no such user|this account|suspended|deactivated/.test(snippet)) {
          found = false;
        }
      }

      results.push({
        platform: platform.name,
        category: platform.category,
        url: url,
        found,
        statusCode: response.statusCode,
      });
    });

    await Promise.allSettled(checks);
    // Rate limit between batches
    await new Promise(r => setTimeout(r, 300));
  }

  // Sort: found first, then alphabetical
  results.sort((a, b) => {
    if (a.found !== b.found) return b.found ? 1 : -1;
    return a.platform.localeCompare(b.platform);
  });

  return {
    username,
    duration: Date.now() - start,
    total: PLATFORMS.length,
    found: results.filter(r => r.found).length,
    notFound: results.filter(r => !r.found && r.statusCode !== 0).length,
    errors: results.filter(r => r.statusCode === 0).length,
    results,
  };
}

// ═══════════════════════════════════════════════════════════════════════
//  Phone Number Intelligence
// ═══════════════════════════════════════════════════════════════════════

function parsePhoneNumber(input) {
  if (!input || typeof input !== 'string') {
    return { valid: false, input, error: 'No phone number provided' };
  }

  // Normalize
  let raw = input.trim();
  let number = raw.replace(/[\s\-\(\)\.]/g, '');

  // Handle + prefix
  if (number.startsWith('+')) number = number.substring(1);
  // Handle 00 international prefix
  else if (number.startsWith('00')) number = number.substring(2);

  // Must be all digits now
  if (!/^\d{7,15}$/.test(number)) {
    return { valid: false, input: raw, error: 'Invalid format. Use digits with optional + prefix.' };
  }

  // Match country code (try 3-digit, 2-digit, 1-digit)
  let countryCode = null;
  let countryInfo = null;
  let nationalNumber = null;

  for (const len of [3, 2, 1]) {
    const prefix = number.substring(0, len);
    if (COUNTRY_CODES[prefix]) {
      countryCode = prefix;
      countryInfo = COUNTRY_CODES[prefix];
      nationalNumber = number.substring(len);
      break;
    }
  }

  if (!countryInfo) {
    return {
      valid: false,
      input: raw,
      digits: number,
      error: 'Country code not recognized. Include country code (e.g. +1 for US, +44 for UK).',
    };
  }

  const validLength = countryInfo.lengths.includes(nationalNumber.length);

  // Line type heuristic (basic, country-specific)
  let lineType = 'unknown';
  if (countryCode === '1') {
    lineType = 'fixed_or_mobile'; // NANP doesn't distinguish
  } else if (countryCode === '44') {
    if (/^7[1-9]/.test(nationalNumber)) lineType = 'mobile';
    else if (/^[1-3]/.test(nationalNumber)) lineType = 'fixed_line';
    else if (/^8/.test(nationalNumber)) lineType = 'toll_free_or_premium';
  } else if (countryCode === '91') {
    if (/^[6-9]/.test(nationalNumber)) lineType = 'mobile';
    else lineType = 'fixed_line';
  } else if (countryCode === '86') {
    if (/^1[3-9]/.test(nationalNumber)) lineType = 'mobile';
    else lineType = 'fixed_line';
  } else if (countryCode === '49') {
    if (/^1[5-7]/.test(nationalNumber)) lineType = 'mobile';
    else lineType = 'fixed_line';
  } else if (countryCode === '33') {
    if (/^[67]/.test(nationalNumber)) lineType = 'mobile';
    else lineType = 'fixed_line';
  } else if (countryCode === '61') {
    if (/^4/.test(nationalNumber)) lineType = 'mobile';
    else lineType = 'fixed_line';
  } else if (countryCode === '55') {
    if (/^\d{2}9/.test(nationalNumber)) lineType = 'mobile';
    else lineType = 'fixed_line';
  } else if (countryCode === '81') {
    if (/^[789]0/.test(nationalNumber)) lineType = 'mobile';
    else lineType = 'fixed_line';
  } else if (countryCode === '82') {
    if (/^1[0-9]/.test(nationalNumber)) lineType = 'mobile';
    else lineType = 'fixed_line';
  }

  // Format the number
  const e164 = '+' + countryCode + nationalNumber;
  let national = nationalNumber;
  // Add common formatting for major countries
  if (countryCode === '1' && nationalNumber.length === 10) {
    national = '(' + nationalNumber.substring(0, 3) + ') ' + nationalNumber.substring(3, 6) + '-' + nationalNumber.substring(6);
  } else if (countryCode === '44' && nationalNumber.length === 10) {
    national = '0' + nationalNumber.substring(0, 4) + ' ' + nationalNumber.substring(4);
  }

  return {
    valid: validLength,
    input: raw,
    countryCode: '+' + countryCode,
    country: countryInfo.country,
    iso: countryInfo.iso,
    nationalNumber,
    national,
    e164,
    international: '+' + countryCode + ' ' + nationalNumber,
    lineType,
    numberLength: nationalNumber.length,
    expectedLengths: countryInfo.lengths,
  };
}

// ═══════════════════════════════════════════════════════════════════════
//  Email Registration Check (Holehe-inspired)
// ═══════════════════════════════════════════════════════════════════════

// Services to probe for email registration
const EMAIL_CHECK_SERVICES = [
  { name: 'Gravatar', category: 'social' },
  { name: 'GitHub', category: 'dev' },
  { name: 'Firefox', category: 'browser' },
  { name: 'Spotify', category: 'music' },
  { name: 'Pinterest', category: 'social' },
  { name: 'Adobe', category: 'creative' },
  { name: 'WordPress', category: 'cms' },
  { name: 'Duolingo', category: 'education' },
  { name: 'Twitter', category: 'social' },
  { name: 'Tumblr', category: 'social' },
  { name: 'Last.fm', category: 'music' },
  { name: 'Patreon', category: 'content' },
];

/**
 * Probe a single service for email registration (Holehe-inspired)
 * Returns: true = registered, false = not found, null = unknown/error
 */
async function probeEmailService(name, email) {
  switch (name) {
    case 'Gravatar': {
      const hash = crypto.createHash('md5').update(email).digest('hex');
      const res = await checkURL('https://en.gravatar.com/' + hash + '.json', 6000);
      if (res.statusCode === 200) return true;
      if (res.statusCode === 404) return false;
      return null;
    }
    case 'GitHub': {
      const res = await checkURL('https://api.github.com/search/users?q=' + encodeURIComponent(email) + '+in:email', 8000);
      if (res.statusCode === 200 && res.body) {
        try { return JSON.parse(res.body).total_count > 0; } catch {}
      }
      return null;
    }
    case 'Firefox': {
      const res = await httpPost('https://api.accounts.firefox.com/v1/account/status',
        JSON.stringify({ email: email }), 'application/json', 6000);
      if (res.statusCode === 200 && res.body) {
        try { return JSON.parse(res.body).exists === true; } catch {}
      }
      if (res.statusCode === 400) return false;
      return null;
    }
    case 'Spotify': {
      const res = await checkURL('https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email=' + encodeURIComponent(email), 6000);
      if (res.statusCode === 200 && res.body) {
        try {
          var d = JSON.parse(res.body);
          if (d.status === 20) return true;
          if (d.status === 1) return false;
        } catch {}
      }
      return null;
    }
    case 'Pinterest': {
      var pData = JSON.stringify({ options: { email: email } });
      var res = await checkURL('https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/?source_url=/&data=' + encodeURIComponent(pData), 6000);
      if (res.statusCode === 200 && res.body) {
        try {
          var pd = JSON.parse(res.body);
          if (pd.resource_response && pd.resource_response.data !== undefined) {
            return pd.resource_response.data === true;
          }
        } catch {}
      }
      return null;
    }
    case 'Adobe': {
      var res2 = await httpPost('https://auth.services.adobe.com/signin/v2/users/accounts',
        JSON.stringify({ username: email, includeTenants: false }), 'application/json', 6000);
      if (res2.statusCode === 200 && res2.body) {
        try {
          var ad = JSON.parse(res2.body);
          if (Array.isArray(ad)) return ad.length > 0;
        } catch {}
      }
      return null;
    }
    case 'WordPress': {
      var res3 = await httpPost('https://wordpress.com/wp-login.php?action=lostpassword',
        'user_login=' + encodeURIComponent(email), 'application/x-www-form-urlencoded', 6000);
      if (res3.statusCode === 200 && res3.body) {
        var wb = res3.body.toLowerCase();
        if (wb.includes('check your e-mail') || wb.includes('check your email')) return true;
        if (wb.includes('no account') || wb.includes('not found') || wb.includes('no user')) return false;
      }
      if (res3.statusCode === 302) return true;
      return null;
    }
    case 'Duolingo': {
      var res4 = await checkURL('https://www.duolingo.com/2017-06-30/users?email=' + encodeURIComponent(email), 6000);
      if (res4.statusCode === 200 && res4.body) {
        try {
          var dd = JSON.parse(res4.body);
          if (dd.users) return dd.users.length > 0;
        } catch {}
      }
      return null;
    }
    case 'Twitter': {
      var res5 = await checkURL('https://api.twitter.com/i/users/email_available.json?email=' + encodeURIComponent(email), 6000);
      if (res5.statusCode === 200 && res5.body) {
        try { return JSON.parse(res5.body).taken === true; } catch {}
      }
      return null;
    }
    case 'Tumblr': {
      var res6 = await httpPost('https://www.tumblr.com/svc/account/register',
        JSON.stringify({ action: 'signup_account', determine_email: email, user_age: 25 }),
        'application/json', 6000);
      if (res6.statusCode === 200 && res6.body) {
        try {
          var td = JSON.parse(res6.body);
          if (td.errors && Array.isArray(td.errors)) {
            return td.errors.some(function(e) { return /taken|use/i.test(typeof e === 'string' ? e : ''); });
          }
          if (td.usernames) return false;
        } catch {}
      }
      return null;
    }
    case 'Last.fm': {
      var res7 = await checkURL('https://www.last.fm/join/partial/validate?email=' + encodeURIComponent(email), 6000);
      if (res7.statusCode === 200 && res7.body) {
        try {
          var ld = JSON.parse(res7.body);
          if (ld.errors && ld.errors.email) return true;
          return false;
        } catch {}
      }
      return null;
    }
    case 'Patreon': {
      var res8 = await httpPost('https://www.patreon.com/api/auth?include=user_location',
        JSON.stringify({ data: { type: 'user', attributes: { email: email } } }),
        'application/vnd.api+json', 6000);
      if (res8.statusCode === 401) return true;
      if (res8.statusCode === 422) return false;
      return null;
    }
    default:
      return null;
  }
}

/**
 * Check email registration across multiple services (Holehe-inspired)
 * @param {string} email — email address to check
 * @param {function} [onProgress] — optional progress callback
 * @returns {Promise<object>}
 */
async function checkEmailRegistration(email, onProgress) {
  const start = Date.now();

  if (!email || typeof email !== 'string') {
    return { error: 'No email provided' };
  }
  email = email.toLowerCase().trim();
  if (!/^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(email)) {
    return { error: 'Invalid email format. Use name@domain.com' };
  }

  // Check cache
  const cacheKey = 'osint:email:' + email;
  const cached = neuralCache.get(cacheKey);
  if (cached) return cached;

  const parts = email.split('@');
  const localPart = parts[0];
  const domain = parts[1];

  // Email metadata
  const meta = {
    email: email,
    localPart: localPart,
    domain: domain,
    isDisposable: DISPOSABLE_DOMAINS.has(domain),
    isFreeProvider: FREE_PROVIDERS.has(domain),
    providerType: DISPOSABLE_DOMAINS.has(domain) ? 'disposable' : FREE_PROVIDERS.has(domain) ? 'free' : 'custom/corporate',
    mxRecords: [],
    hasMX: false,
    hasSPF: false,
    hasDMARC: false,
  };

  // DNS checks (MX, SPF, DMARC) — parallel
  const dns = require('dns');
  const [mxResult, txtResult, dmarcResult] = await Promise.allSettled([
    new Promise(function(resolve, reject) { dns.resolveMx(domain, function(err, r) { err ? reject(err) : resolve(r); }); }),
    new Promise(function(resolve, reject) { dns.resolveTxt(domain, function(err, r) { err ? reject(err) : resolve(r); }); }),
    new Promise(function(resolve, reject) { dns.resolveTxt('_dmarc.' + domain, function(err, r) { err ? reject(err) : resolve(r); }); }),
  ]);

  if (mxResult.status === 'fulfilled' && mxResult.value) {
    meta.mxRecords = mxResult.value.sort(function(a, b) { return a.priority - b.priority; }).map(function(r) { return r.exchange; });
    meta.hasMX = meta.mxRecords.length > 0;
  }
  if (txtResult.status === 'fulfilled' && txtResult.value) {
    var flat = txtResult.value.map(function(r) { return r.join(''); });
    meta.spf = flat.find(function(r) { return r.startsWith('v=spf1'); }) || null;
    meta.hasSPF = !!meta.spf;
  }
  if (dmarcResult.status === 'fulfilled' && dmarcResult.value) {
    var dmarcFlat = dmarcResult.value.map(function(r) { return r.join(''); });
    meta.dmarc = dmarcFlat.find(function(r) { return r.startsWith('v=DMARC1'); }) || null;
    meta.hasDMARC = !!meta.dmarc;
  }

  // Service registration checks — batches of 4
  const results = [];
  for (let i = 0; i < EMAIL_CHECK_SERVICES.length; i += 4) {
    const batch = EMAIL_CHECK_SERVICES.slice(i, i + 4);
    const checks = batch.map(async function(svc, idx) {
      if (onProgress) onProgress({ service: svc.name, checked: i + idx + 1, total: EMAIL_CHECK_SERVICES.length });
      let registered = null;
      try { registered = await probeEmailService(svc.name, email); }
      catch { registered = null; }
      results.push({ service: svc.name, category: svc.category, registered: registered });
    });
    await Promise.allSettled(checks);
    await new Promise(function(r) { setTimeout(r, 400); });
  }

  // Sort: registered first, then not found, then unknown
  results.sort(function(a, b) {
    function order(v) { return v === true ? 0 : v === false ? 1 : 2; }
    if (order(a.registered) !== order(b.registered)) return order(a.registered) - order(b.registered);
    return a.service.localeCompare(b.service);
  });

  const result = {
    email: email,
    meta: meta,
    duration: Date.now() - start,
    totalServices: EMAIL_CHECK_SERVICES.length,
    registered: results.filter(function(r) { return r.registered === true; }).length,
    notRegistered: results.filter(function(r) { return r.registered === false; }).length,
    unknown: results.filter(function(r) { return r.registered === null; }).length,
    results: results,
  };

  neuralCache.set(cacheKey, result, 10 * 60 * 1000);
  return result;
}

module.exports = { enumerateUsername, parsePhoneNumber, checkEmailRegistration, PLATFORMS, COUNTRY_CODES, EMAIL_CHECK_SERVICES, DISPOSABLE_DOMAINS, FREE_PROVIDERS };
