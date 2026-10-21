// Test script for CORS proxy logic
import assert from 'node:assert';

// 1. URL extraction test
function extractTargetUrl(requestUrlString) {
  const requestUrl = new URL(requestUrlString);
  
  // Case 1: Query param "?url="
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
  
  // Case 2: Path-based
  let path = requestUrl.pathname.slice(1);
  if (requestUrl.search && !search.includes('url=')) {
    path += requestUrl.search;
  }
  
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

// 2. SSRF check
function isSafeUrl(targetUrlString, workerHost) {
  let url;
  try {
    url = new URL(targetUrlString);
  } catch (e) {
    return { safe: false, reason: 'Invalid URL format' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { safe: false, reason: 'Only HTTP and HTTPS protocols are allowed' };
  }

  const hostname = url.hostname.toLowerCase();

  if (workerHost && (hostname === workerHost.toLowerCase() || hostname === 'localhost')) {
    return { safe: false, reason: 'Requests to proxy host or localhost are prohibited' };
  }

  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal')
  ) {
    return { safe: false, reason: 'Requests to local domains are prohibited' };
  }

  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = hostname.match(ipv4Regex);
  if (match) {
    const [_, o1, o2, o3, o4] = match.map(Number);
    if (o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255) {
      return { safe: false, reason: 'Invalid IP address' };
    }
    if (o1 === 127) return { safe: false, reason: 'Loopback IP addresses (127.x.x.x) are blocked' };
    if (o1 === 0) return { safe: false, reason: '0.0.0.0 IP address is blocked' };
    if (o1 === 10) return { safe: false, reason: 'Private IP addresses (10.x.x.x) are blocked' };
    if (o1 === 172 && o2 >= 16 && o2 <= 31) return { safe: false, reason: 'Private IP addresses (172.16-31.x.x) are blocked' };
    if (o1 === 192 && o2 === 168) return { safe: false, reason: 'Private IP addresses (192.168.x.x) are blocked' };
    if (o1 === 169 && o2 === 254) return { safe: false, reason: 'Link-local/Cloud metadata IP addresses (169.254.x.x) are blocked' };
    if (o1 >= 224 && o1 <= 239) return { safe: false, reason: 'Multicast IP addresses are blocked' };
  }

  if (
    hostname === '::1' ||
    hostname.startsWith('fe80:') ||
    hostname.startsWith('fc') ||
    hostname.startsWith('fd') ||
    hostname.includes('::ffff:127.') ||
    hostname.includes('::ffff:10.') ||
    hostname.includes('::ffff:192.168.')
  ) {
    return { safe: false, reason: 'IPv6 local/private addresses are blocked' };
  }

  return { safe: true, url };
}

// 3. Mock KV rate limiter test
class MockKV {
  constructor() {
    this.store = new Map();
  }
  async get(key, type) {
    const val = this.store.get(key);
    if (!val) return null;
    if (type === 'json') return JSON.parse(val);
    return val;
  }
  async put(key, val, options) {
    this.store.set(key, typeof val === 'string' ? val : JSON.stringify(val));
  }
}

const LIMIT_PER_HOUR = 15;
const LIMIT_PER_DAY = 89;

async function checkAndIncrementRateLimit(kv, clientIp, now = Date.now()) {
  const hourWindow = Math.floor(now / (60 * 60 * 1000));
  const dayWindow = Math.floor(now / (24 * 60 * 60 * 1000));
  const key = `ratelimit:${clientIp}`;

  const stored = await kv.get(key, 'json') || {};

  let hourCount = stored.hourWindow === hourWindow ? (stored.hourCount || 0) : 0;
  let dayCount = stored.dayWindow === dayWindow ? (stored.dayCount || 0) : 0;

  if (hourCount >= LIMIT_PER_HOUR) {
    const retryAfter = Math.ceil(((hourWindow + 1) * 3600000 - now) / 1000);
    return {
      allowed: false,
      reason: 'hourly',
      limit: LIMIT_PER_HOUR,
      current: hourCount,
      remainingHour: 0,
      remainingDay: Math.max(0, LIMIT_PER_DAY - dayCount),
      retryAfter
    };
  }

  if (dayCount >= LIMIT_PER_DAY) {
    const retryAfter = Math.ceil(((dayWindow + 1) * 86400000 - now) / 1000);
    return {
      allowed: false,
      reason: 'daily',
      limit: LIMIT_PER_DAY,
      current: dayCount,
      remainingHour: Math.max(0, LIMIT_PER_HOUR - hourCount),
      remainingDay: 0,
      retryAfter
    };
  }

  hourCount += 1;
  dayCount += 1;

  await kv.put(key, JSON.stringify({
    hourWindow,
    hourCount,
    dayWindow,
    dayCount,
    lastUpdated: now
  }), { expirationTtl: 172800 });

  return {
    allowed: true,
    hourCount,
    dayCount,
    remainingHour: LIMIT_PER_HOUR - hourCount,
    remainingDay: LIMIT_PER_DAY - dayCount
  };
}

// Run Tests
async function runTests() {
  console.log('Testing URL Extraction...');
  assert.strictEqual(extractTargetUrl('https://proxy.dev/?url=https://api.github.com/users'), 'https://api.github.com/users');
  assert.strictEqual(extractTargetUrl('https://proxy.dev/https://api.github.com/users'), 'https://api.github.com/users');
  assert.strictEqual(extractTargetUrl('https://proxy.dev/https://api.github.com/search?q=test&page=1'), 'https://api.github.com/search?q=test&page=1');
  assert.strictEqual(extractTargetUrl('https://proxy.dev/?url=https%3A%2F%2Fapi.github.com%2Fusers'), 'https://api.github.com/users');
  assert.strictEqual(extractTargetUrl('https://proxy.dev/'), null);
  console.log('✓ URL extraction passed');

  console.log('Testing SSRF protection...');
  assert.strictEqual(isSafeUrl('http://localhost:8080', 'proxy.dev').safe, false);
  assert.strictEqual(isSafeUrl('http://127.0.0.1/test', 'proxy.dev').safe, false);
  assert.strictEqual(isSafeUrl('http://169.254.169.254/latest/meta-data', 'proxy.dev').safe, false);
  assert.strictEqual(isSafeUrl('http://10.0.0.5/', 'proxy.dev').safe, false);
  assert.strictEqual(isSafeUrl('http://192.168.1.1/admin', 'proxy.dev').safe, false);
  assert.strictEqual(isSafeUrl('http://172.20.0.1/', 'proxy.dev').safe, false);
  assert.strictEqual(isSafeUrl('https://proxy.dev/test', 'proxy.dev').safe, false); // self-loop
  assert.strictEqual(isSafeUrl('https://api.github.com/users', 'proxy.dev').safe, true);
  console.log('✓ SSRF checks passed');

  console.log('Testing Rate Limiting...');
  const kv = new MockKV();
  const ip = '1.2.3.4';
  let now = 1000000000;

  // Make 15 requests in the same hour
  for (let i = 1; i <= 15; i++) {
    const res = await checkAndIncrementRateLimit(kv, ip, now);
    assert.strictEqual(res.allowed, true);
    assert.strictEqual(res.hourCount, i);
    assert.strictEqual(res.dayCount, i);
    assert.strictEqual(res.remainingHour, 15 - i);
    assert.strictEqual(res.remainingDay, 89 - i);
  }

  // 16th request should fail with hourly limit
  const res16 = await checkAndIncrementRateLimit(kv, ip, now);
  assert.strictEqual(res16.allowed, false);
  assert.strictEqual(res16.reason, 'hourly');
  assert.strictEqual(res16.remainingHour, 0);
  assert(res16.retryAfter > 0);
  console.log('✓ Hourly limit 15 triggered properly');

  // Move time forward 1 hour (3,600,000 ms)
  now += 3600000;
  const resHourNext = await checkAndIncrementRateLimit(kv, ip, now);
  assert.strictEqual(resHourNext.allowed, true);
  assert.strictEqual(resHourNext.hourCount, 1);
  assert.strictEqual(resHourNext.dayCount, 16); // Day continues!
  console.log('✓ Hourly limit reset in new hour, daily count persisted');

  // Test daily limit: IP '5.6.7.8'
  const ip2 = '5.6.7.8';
  for (let h = 0; h < 6; h++) {
    const hTime = now + (h * 3600000);
    const countInHour = (h === 5) ? 14 : 15; // 5 * 15 = 75, + 14 = 89
    for (let i = 1; i <= countInHour; i++) {
      const res = await checkAndIncrementRateLimit(kv, ip2, hTime);
      assert.strictEqual(res.allowed, true);
    }
  }

  // 90th request of the day should fail with daily limit!
  const res90 = await checkAndIncrementRateLimit(kv, ip2, now + (5 * 3600000));
  assert.strictEqual(res90.allowed, false);
  assert.strictEqual(res90.reason, 'daily');
  assert.strictEqual(res90.remainingDay, 0);
  console.log('✓ Daily limit 89 triggered properly');

  console.log('All tests passed successfully! 🎉');
}

runTests();
