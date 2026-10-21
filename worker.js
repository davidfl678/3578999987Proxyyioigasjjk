/**
 * Cloudflare Worker - Public CORS Proxy with IP-based Rate Limiting
 * 
 * Rate limits:
 * - 15 requests per IP per hour
 * - 89 requests per IP per day
 * 
 * KV Binding: RATE_LIMIT_KV (Namespace ID: fa973f0ae1114355a327b3ecf2b6006a)
 */

const LIMIT_PER_HOUR = 15;
const LIMIT_PER_DAY = 89;
const KV_EXPIRATION_TTL = 26 * 60 * 60; // Exactly 26 hours (93,600 seconds) TTL for KV keys

// In-memory fallback cache for development or if KV binding is not yet configured
const memoryStore = new Map();

export default {
  async fetch(request, env, ctx) {
    const requestUrl = new URL(request.url);

    // 1. Handle CORS Preflight (OPTIONS request) immediately
    // Browsers send OPTIONS before complex requests - DO NOT rate-limit these!
    if (request.method === 'OPTIONS') {
      return handlePreflight(request);
    }

    const clientIp = getClientIp(request);

    // 2. Quota check endpoint (read-only, does not count against rate limit)
    if (requestUrl.pathname === '/quota' || requestUrl.pathname === '/api/quota') {
      const quota = await getQuotaStatus(env, clientIp);
      return new Response(JSON.stringify(quota, null, 2), {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'no-store',
          ...getRateLimitHeaders(quota, clientIp),
        },
      });
    }

    // 3. Extract target URL from request
    const targetUrlString = extractTargetUrl(requestUrl);

    // If no target URL provided and root accessed, serve the Documentation & Tester UI
    if (!targetUrlString) {
      if (requestUrl.pathname === '/' || requestUrl.pathname === '') {
        const quota = await getQuotaStatus(env, clientIp);
        return serveLandingPage(requestUrl, clientIp, quota);
      }
      return jsonError(400, 'Bad Request', 'No target URL provided. Usage: ?url=https://example.com or /https://example.com');
    }

    // 4. Validate Target URL & Check for SSRF / Loop attacks
    const safetyCheck = isSafeUrl(targetUrlString, requestUrl.hostname);
    if (!safetyCheck.safe) {
      return jsonError(403, 'Forbidden', `Target URL rejected: ${safetyCheck.reason}`);
    }

    // 5. Check and Apply Rate Limiting (Cloudflare KV)
    const rateLimit = await checkAndIncrementRateLimit(env, clientIp);
    if (!rateLimit.allowed) {
      return new Response(
        JSON.stringify({
          error: 'Too Many Requests',
          message: rateLimit.reason === 'hourly'
            ? `Hourly rate limit exceeded (${LIMIT_PER_HOUR} requests/hour). Please try again in ${rateLimit.retryAfter} seconds.`
            : `Daily rate limit exceeded (${LIMIT_PER_DAY} requests/day). Please try again in ${rateLimit.retryAfter} seconds.`,
          clientIp: clientIp,
          limit: rateLimit.limit,
          period: rateLimit.reason,
          remainingHour: rateLimit.remainingHour,
          remainingDay: rateLimit.remainingDay,
          retryAfterSeconds: rateLimit.retryAfter,
        }, null, 2),
        {
          status: 429,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD',
            'Access-Control-Allow-Headers': '*',
            'Retry-After': String(rateLimit.retryAfter),
            ...getRateLimitHeaders(rateLimit, clientIp),
          },
        }
      );
    }

    // 6. Forward Request to Target
    try {
      const response = await forwardProxyRequest(request, safetyCheck.url, rateLimit, clientIp);
      return response;
    } catch (err) {
      return jsonError(502, 'Bad Gateway', `Failed to fetch target URL: ${err.message}`, {
        targetUrl: targetUrlString,
        ...getRateLimitHeaders(rateLimit, clientIp),
      });
    }
  },
};

/**
 * Handle CORS Preflight requests
 */
function handlePreflight(request) {
  const reqHeaders = request.headers.get('Access-Control-Request-Headers') || '*';
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD',
      'Access-Control-Allow-Headers': reqHeaders,
      'Access-Control-Max-Age': '86400',
      'Content-Length': '0',
    },
  });
}

/**
 * Extract Target URL from Query or Path
 */
function extractTargetUrl(requestUrl) {
  // Case A: Query string "?url="
  const search = requestUrl.search;
  const urlParamIndex = search.indexOf('url=');
  if (urlParamIndex !== -1) {
    let target = search.substring(urlParamIndex + 4);
    try {
      if (target.startsWith('http%3A') || target.startsWith('https%3A')) {
        target = decodeURIComponent(target);
      }
    } catch (e) {}
    return target;
  }

  // Case B: Path prefix /http... or /https...
  let path = requestUrl.pathname.slice(1);
  if (requestUrl.search && !search.includes('url=')) {
    path += requestUrl.search;
  }

  // Handle single slash after protocol (e.g. https:/example.com)
  if (path.startsWith('http:/') && !path.startsWith('http://')) {
    path = 'http://' + path.slice(6);
  } else if (path.startsWith('https:/') && !path.startsWith('https://')) {
    path = 'https://' + path.slice(7);
  }

  if (path.startsWith('http://') || path.startsWith('https://')) {
    return path;
  }

  return null;
}

/**
 * Validate URL and Prevent SSRF / Loops
 */
function isSafeUrl(targetUrlString, workerHost) {
  let url;
  try {
    url = new URL(targetUrlString);
  } catch (e) {
    return { safe: false, reason: 'Invalid URL syntax' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { safe: false, reason: 'Only HTTP and HTTPS protocols are permitted' };
  }

  const hostname = url.hostname.toLowerCase();

  // Prevent proxy looping into itself
  if (workerHost && (hostname === workerHost.toLowerCase() || hostname === 'localhost')) {
    return { safe: false, reason: 'Proxying to self or localhost is prohibited' };
  }

  // Local/Internal domain filters
  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.lan')
  ) {
    return { safe: false, reason: 'Internal/local hostnames are prohibited' };
  }

  // IPv4 Private & Reserved Ranges check
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = hostname.match(ipv4Regex);
  if (match) {
    const [_, o1, o2, o3, o4] = match.map(Number);
    if (o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255) {
      return { safe: false, reason: 'Malformed IP address' };
    }
    // 0.0.0.0
    if (o1 === 0) return { safe: false, reason: 'Zero IP (0.0.0.0) is blocked' };
    // 127.0.0.0/8 (Loopback)
    if (o1 === 127) return { safe: false, reason: 'Loopback IP addresses (127.0.0.0/8) are blocked' };
    // 10.0.0.0/8 (Private)
    if (o1 === 10) return { safe: false, reason: 'Private IP addresses (10.0.0.0/8) are blocked' };
    // 172.16.0.0/12 (Private)
    if (o1 === 172 && o2 >= 16 && o2 <= 31) return { safe: false, reason: 'Private IP addresses (172.16.0.0/12) are blocked' };
    // 192.168.0.0/16 (Private)
    if (o1 === 192 && o2 === 168) return { safe: false, reason: 'Private IP addresses (192.168.0.0/16) are blocked' };
    // 169.254.0.0/16 (Link-local & Cloud Metadata e.g. AWS/GCP 169.254.169.254)
    if (o1 === 169 && o2 === 254) return { safe: false, reason: 'Link-local/Cloud Metadata IP addresses (169.254.0.0/16) are blocked' };
    // 224.0.0.0/4 (Multicast / Reserved)
    if (o1 >= 224) return { safe: false, reason: 'Multicast or reserved IP addresses are blocked' };
  }

  // IPv6 checks (::1, fe80:: link local, fc00:: / fd00:: unique local)
  if (
    hostname === '::1' ||
    hostname.startsWith('fe80:') ||
    hostname.startsWith('fc') ||
    hostname.startsWith('fd') ||
    hostname.includes('::ffff:127.') ||
    hostname.includes('::ffff:10.') ||
    hostname.includes('::ffff:192.168.') ||
    hostname.includes('::ffff:169.254.')
  ) {
    return { safe: false, reason: 'IPv6 local/private addresses are blocked' };
  }

  return { safe: true, url };
}

/**
 * Extract Client IP reliably from Cloudflare headers
 */
function getClientIp(request) {
  return (
    request.headers.get('cf-connecting-ip') ||
    request.headers.get('x-real-ip') ||
    request.headers.get('x-forwarded-for')?.split(',')[0].trim() ||
    '127.0.0.1'
  );
}

/**
 * Check Rate Limit in Cloudflare KV
 */
async function checkAndIncrementRateLimit(env, clientIp) {
  const now = Date.now();
  const hourWindow = Math.floor(now / (60 * 60 * 1000));
  const dayWindow = Math.floor(now / (24 * 60 * 60 * 1000));
  const key = `ratelimit:${clientIp}`;

  let stored = null;

  if (env && env.RATE_LIMIT_KV) {
    try {
      stored = await env.RATE_LIMIT_KV.get(key, 'json');
    } catch (e) {
      console.error('KV read error:', e);
    }
  } else {
    // In-memory fallback
    const entry = memoryStore.get(key);
    if (entry && entry.expiresAt && entry.expiresAt < now) {
      memoryStore.delete(key);
      stored = null;
    } else {
      stored = entry || null;
    }
  }

  stored = stored || {};

  let hourCount = stored.hourWindow === hourWindow ? (stored.hourCount || 0) : 0;
  let dayCount = stored.dayWindow === dayWindow ? (stored.dayCount || 0) : 0;

  // 1. Check Hourly Limit
  if (hourCount >= LIMIT_PER_HOUR) {
    const retryAfter = Math.max(1, Math.ceil(((hourWindow + 1) * 3600000 - now) / 1000));
    return {
      allowed: false,
      reason: 'hourly',
      limit: LIMIT_PER_HOUR,
      hourCount,
      dayCount,
      remainingHour: 0,
      remainingDay: Math.max(0, LIMIT_PER_DAY - dayCount),
      retryAfter,
    };
  }

  // 2. Check Daily Limit
  if (dayCount >= LIMIT_PER_DAY) {
    const retryAfter = Math.max(1, Math.ceil(((dayWindow + 1) * 86400000 - now) / 1000));
    return {
      allowed: false,
      reason: 'daily',
      limit: LIMIT_PER_DAY,
      hourCount,
      dayCount,
      remainingHour: Math.max(0, LIMIT_PER_HOUR - hourCount),
      remainingDay: 0,
      retryAfter,
    };
  }

  // Increment counters
  hourCount += 1;
  dayCount += 1;

  const dataToSave = {
    hourWindow,
    hourCount,
    dayWindow,
    dayCount,
    lastUpdated: now,
  };

  if (env && env.RATE_LIMIT_KV) {
    try {
      // Exactly 26 hours TTL (93,600 seconds) so inactive IP keys automatically purge from KV
      await env.RATE_LIMIT_KV.put(key, JSON.stringify(dataToSave), { expirationTtl: KV_EXPIRATION_TTL });
    } catch (e) {
      console.error('KV write error:', e);
    }
  } else {
    memoryStore.set(key, { ...dataToSave, expiresAt: now + (KV_EXPIRATION_TTL * 1000) });
  }

  return {
    allowed: true,
    hourCount,
    dayCount,
    remainingHour: Math.max(0, LIMIT_PER_HOUR - hourCount),
    remainingDay: Math.max(0, LIMIT_PER_DAY - dayCount),
  };
}

/**
 * Get read-only quota status (without incrementing)
 */
async function getQuotaStatus(env, clientIp) {
  const now = Date.now();
  const hourWindow = Math.floor(now / (60 * 60 * 1000));
  const dayWindow = Math.floor(now / (24 * 60 * 60 * 1000));
  const key = `ratelimit:${clientIp}`;

  let stored = null;
  if (env && env.RATE_LIMIT_KV) {
    try {
      stored = await env.RATE_LIMIT_KV.get(key, 'json');
    } catch (e) {}
  } else {
    const entry = memoryStore.get(key);
    if (entry && entry.expiresAt && entry.expiresAt < now) {
      memoryStore.delete(key);
      stored = null;
    } else {
      stored = entry || null;
    }
  }
  stored = stored || {};

  const hourCount = stored.hourWindow === hourWindow ? (stored.hourCount || 0) : 0;
  const dayCount = stored.dayWindow === dayWindow ? (stored.dayCount || 0) : 0;

  return {
    clientIp,
    hourLimit: LIMIT_PER_HOUR,
    hourUsed: hourCount,
    remainingHour: Math.max(0, LIMIT_PER_HOUR - hourCount),
    dayLimit: LIMIT_PER_DAY,
    dayUsed: dayCount,
    remainingDay: Math.max(0, LIMIT_PER_DAY - dayCount),
    resetHourSeconds: Math.max(1, Math.ceil(((hourWindow + 1) * 3600000 - now) / 1000)),
    resetDaySeconds: Math.max(1, Math.ceil(((dayWindow + 1) * 86400000 - now) / 1000)),
    kvBound: !!(env && env.RATE_LIMIT_KV),
  };
}

/**
 * Helper to build Rate Limit Headers
 */
function getRateLimitHeaders(rateLimit, clientIp) {
  return {
    'X-RateLimit-Limit-Hour': String(LIMIT_PER_HOUR),
    'X-RateLimit-Remaining-Hour': String(rateLimit.remainingHour ?? 0),
    'X-RateLimit-Limit-Day': String(LIMIT_PER_DAY),
    'X-RateLimit-Remaining-Day': String(rateLimit.remainingDay ?? 0),
    'X-RateLimit-Client-IP': clientIp,
  };
}

/**
 * Forward request to target server and attach CORS headers
 */
async function forwardProxyRequest(request, targetUrl, rateLimit, clientIp) {
  // Strip hop-by-hop and Cloudflare specific headers
  const newHeaders = new Headers();
  const hopByHopHeaders = new Set([
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailers',
    'transfer-encoding',
    'upgrade',
    'host',
    'cf-ray',
    'cf-connecting-ip',
    'cf-visitor',
    'cf-ipcountry',
    'x-real-ip',
    'x-forwarded-proto',
    'cdn-loop',
  ]);

  for (const [key, value] of request.headers.entries()) {
    const lowerKey = key.toLowerCase();
    if (!hopByHopHeaders.has(lowerKey)) {
      newHeaders.set(key, value);
    }
  }

  // Remove accept-encoding to ensure target returns uncompressed plain data,
  // preventing double-compression or missing encoding header issues in edge proxy
  newHeaders.delete('accept-encoding');

  // Set standard User-Agent if none provided
  if (!newHeaders.has('user-agent')) {
    newHeaders.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Corsly/1.0');
  }

  // Prepare body (GET and HEAD must not have a body in Fetch API)
  const isBodyAllowed = !['GET', 'HEAD'].includes(request.method);
  const body = isBodyAllowed ? request.body : undefined;

  const fetchOptions = {
    method: request.method,
    headers: newHeaders,
    body: body,
    redirect: 'follow',
  };

  const targetResponse = await fetch(targetUrl.toString(), fetchOptions);

  // Clone headers from target response
  const responseHeaders = new Headers();

  for (const [key, value] of targetResponse.headers.entries()) {
    const lowerKey = key.toLowerCase();
    // Exclude target CORS and conflicting compression headers
    if (
      !lowerKey.startsWith('access-control-') &&
      lowerKey !== 'content-encoding' &&
      lowerKey !== 'content-length' &&
      lowerKey !== 'connection' &&
      lowerKey !== 'transfer-encoding'
    ) {
      responseHeaders.set(key, value);
    }
  }

  // Set permissive CORS headers
  responseHeaders.set('Access-Control-Allow-Origin', '*');
  responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD');
  responseHeaders.set('Access-Control-Allow-Headers', '*');
  responseHeaders.set('Access-Control-Expose-Headers', '*');
  responseHeaders.set('Access-Control-Max-Age', '86400');

  // Set Rate Limit and Proxy Info headers
  responseHeaders.set('X-RateLimit-Limit-Hour', String(LIMIT_PER_HOUR));
  responseHeaders.set('X-RateLimit-Remaining-Hour', String(rateLimit.remainingHour));
  responseHeaders.set('X-RateLimit-Limit-Day', String(LIMIT_PER_DAY));
  responseHeaders.set('X-RateLimit-Remaining-Day', String(rateLimit.remainingDay));
  responseHeaders.set('X-RateLimit-Client-IP', clientIp);
  responseHeaders.set('X-Proxied-By', 'Corsly');

  return new Response(targetResponse.body, {
    status: targetResponse.status,
    statusText: targetResponse.statusText,
    headers: responseHeaders,
  });
}

/**
 * Return JSON error with CORS headers
 */
function jsonError(status, title, message, extra = {}) {
  return new Response(
    JSON.stringify({
      status,
      error: title,
      message,
      ...extra,
    }, null, 2),
    {
      status,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD',
        'Access-Control-Allow-Headers': '*',
        'Access-Control-Expose-Headers': '*',
      },
    }
  );
}

/**
 * HTML Landing Page & Interactive Tester
 */
function serveLandingPage(requestUrl, clientIp, quota) {
  const origin = requestUrl.origin;
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Corsly - Fast & Secure CORS Proxy</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #121826;
      --card-border: #1f293d;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --accent: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --code-bg: #070a12;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.6;
      padding: 24px 16px;
      display: flex;
      flex-direction: column;
      align-items: center;
      min-height: 100vh;
    }
    .container {
      max-width: 960px;
      width: 100%;
      margin: 0 auto;
    }
    header {
      text-align: center;
      margin-bottom: 32px;
    }
    .badge-status {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
      padding: 4px 12px;
      border-radius: 9999px;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 12px;
      border: 1px solid rgba(16, 185, 129, 0.3);
    }
    .badge-status .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #34d399;
      box-shadow: 0 0 8px #34d399;
    }
    h1 {
      font-size: 32px;
      font-weight: 800;
      letter-spacing: -0.5px;
      margin-bottom: 8px;
      background: linear-gradient(135deg, #60a5fa, #a855f7);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    p.subtitle {
      color: var(--text-muted);
      font-size: 15px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
    }
    .card h2 {
      font-size: 16px;
      font-weight: 700;
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
      color: #e5e7eb;
    }
    .stat-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      font-size: 14px;
    }
    .stat-row:last-child { border-bottom: none; }
    .stat-label { color: var(--text-muted); }
    .stat-val { font-weight: 700; font-family: monospace; }
    .stat-val.highlight { color: #60a5fa; }
    .stat-val.good { color: #34d399; }
    .stat-val.warn { color: var(--warning); }
    .progress-bar-container {
      width: 100%;
      height: 6px;
      background: #1f293d;
      border-radius: 3px;
      overflow: hidden;
      margin-top: 4px;
      margin-bottom: 10px;
    }
    .progress-bar {
      height: 100%;
      background: linear-gradient(90deg, #3b82f6, #10b981);
      border-radius: 3px;
    }
    .progress-bar.danger {
      background: var(--danger);
    }
    .url-box {
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 12px;
      font-family: monospace;
      font-size: 13px;
      color: #93c5fd;
      word-break: break-all;
      margin-bottom: 12px;
    }
    .input-group {
      display: flex;
      gap: 8px;
      margin-bottom: 12px;
    }
    select, input[type="text"] {
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 14px;
      outline: none;
      transition: border 0.2s;
    }
    select:focus, input[type="text"]:focus {
      border-color: var(--primary);
    }
    input[type="text"] { flex: 1; }
    select { width: 105px; cursor: pointer; }
    button {
      background: var(--primary);
      color: white;
      border: none;
      border-radius: 8px;
      padding: 10px 18px;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      transition: background 0.2s;
    }
    button:hover { background: var(--primary-hover); }
    button:disabled { opacity: 0.6; cursor: not-allowed; }
    .response-area {
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 12px;
      font-family: monospace;
      font-size: 12px;
      max-height: 280px;
      overflow-y: auto;
      white-space: pre-wrap;
      color: #a7f3d0;
      display: none;
    }
    .tabs {
      display: flex;
      gap: 8px;
      margin-bottom: 12px;
    }
    .tab-btn {
      background: transparent;
      color: var(--text-muted);
      border: 1px solid var(--card-border);
      border-radius: 6px;
      padding: 6px 12px;
      font-size: 12px;
      cursor: pointer;
    }
    .tab-btn.active {
      background: var(--card-border);
      color: var(--text);
      font-weight: 600;
    }
    pre {
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 14px;
      overflow-x: auto;
      font-family: monospace;
      font-size: 12px;
      color: #cbd5e1;
    }
    footer {
      margin-top: 32px;
      text-align: center;
      font-size: 13px;
      color: var(--text-muted);
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="badge-status">
        <span class="dot"></span> Active & Ready
      </div>
      <h1>⚡ Corsly</h1>
      <p class="subtitle">Fast, secure, and open CORS proxy with smart IP rate limiting.</p>
    </header>

    <div class="grid">
      <!-- Rate Limit & IP Card -->
      <div class="card">
        <h2>📊 Your IP & Quota</h2>
        <div class="stat-row">
          <span class="stat-label">Client IP</span>
          <span class="stat-val highlight" id="clientIp">${clientIp}</span>
        </div>
        
        <div class="stat-row">
          <span class="stat-label">Hourly Limit</span>
          <span class="stat-val" id="hourStatus">${quota.remainingHour} / ${quota.hourLimit} left</span>
        </div>
        <div class="progress-bar-container">
          <div class="progress-bar" id="hourBar" style="width: ${(quota.remainingHour / quota.hourLimit) * 100}%"></div>
        </div>

        <div class="stat-row">
          <span class="stat-label">Daily Limit</span>
          <span class="stat-val" id="dayStatus">${quota.remainingDay} / ${quota.dayLimit} left</span>
        </div>
        <div class="progress-bar-container">
          <div class="progress-bar" id="dayBar" style="width: ${(quota.remainingDay / quota.dayLimit) * 100}%"></div>
        </div>

        <div class="stat-row">
          <span class="stat-label">Storage TTL</span>
          <span class="stat-val">26 Hours (Auto-purge)</span>
        </div>
      </div>

      <!-- Quick Usage Card -->
      <div class="card">
        <h2>🚀 Quick Usage</h2>
        <div style="font-size: 13px; color: var(--text-muted); margin-bottom: 8px;">Method 1: Query Parameter (Recommended)</div>
        <div class="url-box">${origin}/?url=https://api.github.com/users/octocat</div>
        <div style="font-size: 13px; color: var(--text-muted); margin-bottom: 8px;">Method 2: Path Prefix</div>
        <div class="url-box">${origin}/https://api.github.com/users/octocat</div>
      </div>
    </div>

    <!-- Live Tester Card -->
    <div class="card" style="margin-bottom: 24px;">
      <h2>🧪 Test Target URL</h2>
      <div class="input-group">
        <select id="reqMethod">
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="DELETE">DELETE</option>
          <option value="HEAD">HEAD</option>
        </select>
        <input type="text" id="targetUrlInput" placeholder="https://api.github.com/users/octocat" value="https://api.github.com/users/octocat">
        <button id="sendBtn" onclick="sendTestRequest()">Send Request</button>
      </div>
      <div id="statusInfo" style="font-size: 13px; margin-bottom: 8px; display: none;"></div>
      <div class="response-area" id="resArea"></div>
    </div>

    <!-- Code Examples Card -->
    <div class="card">
      <h2>💻 Integration Snippets</h2>
      <div class="tabs">
        <button class="tab-btn active" onclick="showSnippet('js')">JavaScript (Fetch)</button>
        <button class="tab-btn" onclick="showSnippet('curl')">cURL</button>
        <button class="tab-btn" onclick="showSnippet('python')">Python</button>
      </div>

      <pre id="codeJs"><code>// Fetch through Corsly
const targetUrl = 'https://api.github.com/users/octocat';
const proxyUrl = '${origin}/?url=' + encodeURIComponent(targetUrl);

fetch(proxyUrl)
  .then(res => res.json())
  .then(data => console.log(data))
  .catch(err => console.error(err));</code></pre>

      <pre id="codeCurl" style="display: none;"><code># cURL request through Corsly
curl -i "${origin}/?url=https://api.github.com/users/octocat"</code></pre>

      <pre id="codePython" style="display: none;"><code># Python request through Corsly
import requests

target_url = "https://api.github.com/users/octocat"
proxy_url = f"${origin}/?url={target_url}"

response = requests.get(proxy_url)
print(response.status_code)
print(response.json())</code></pre>
    </div>

    <footer>
      Powered by Corsly &bull; 15 req/hr &bull; 89 req/day &bull; 26h TTL
    </footer>
  </div>

  <script>
    async function updateQuota() {
      try {
        const res = await fetch('/quota');
        if (res.ok) {
          const data = await res.json();
          document.getElementById('hourStatus').innerText = data.remainingHour + ' / ' + data.hourLimit + ' left';
          document.getElementById('dayStatus').innerText = data.remainingDay + ' / ' + data.dayLimit + ' left';
          document.getElementById('hourBar').style.width = ((data.remainingHour / data.hourLimit) * 100) + '%';
          document.getElementById('dayBar').style.width = ((data.remainingDay / data.dayLimit) * 100) + '%';
        }
      } catch (e) {}
    }

    async function sendTestRequest() {
      const btn = document.getElementById('sendBtn');
      const method = document.getElementById('reqMethod').value;
      const target = document.getElementById('targetUrlInput').value.trim();
      const statusInfo = document.getElementById('statusInfo');
      const resArea = document.getElementById('resArea');

      if (!target) return alert('Please enter a target URL');

      btn.disabled = true;
      btn.innerText = 'Sending...';
      statusInfo.style.display = 'block';
      statusInfo.innerText = 'Connecting via proxy...';
      resArea.style.display = 'none';

      try {
        const proxyUrl = '/?url=' + encodeURIComponent(target);
        const startTime = performance.now();
        const res = await fetch(proxyUrl, { method });
        const duration = Math.round(performance.now() - startTime);

        const statusColor = res.ok ? '#34d399' : (res.status === 429 ? '#f59e0b' : '#ef4444');
        statusInfo.innerHTML = 'Status: <strong style="color:' + statusColor + '">' + res.status + ' ' + res.statusText + '</strong> (' + duration + ' ms)';

        const text = await res.text();
        let formatted = text;
        try {
          formatted = JSON.stringify(JSON.parse(text), null, 2);
        } catch (e) {}

        resArea.innerText = formatted;
        resArea.style.display = 'block';

        // Refresh quota display
        await updateQuota();
      } catch (err) {
        statusInfo.innerHTML = '<span style="color:#ef4444">Error: ' + err.message + '</span>';
      } finally {
        btn.disabled = false;
        btn.innerText = 'Send Request';
      }
    }

    function showSnippet(type) {
      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
      event.target.classList.add('active');

      document.getElementById('codeJs').style.display = type === 'js' ? 'block' : 'none';
      document.getElementById('codeCurl').style.display = type === 'curl' ? 'block' : 'none';
      document.getElementById('codePython').style.display = type === 'python' ? 'block' : 'none';
    }
  </script>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache',
    },
  });
}
