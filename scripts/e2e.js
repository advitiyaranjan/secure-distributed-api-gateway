// End-to-end checks against a running stack (docker compose or `npm run dev`).
// Usage: GATEWAY_URL=https://localhost:8443 ADMIN_PASSWORD=... node scripts/e2e.js
//
// Note: the auth tier allows 20 token/login/register calls per minute per IP, and
// this suite uses ~13 of them plus a deliberate burst at the end. Wait a minute
// between consecutive runs.
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import https from 'node:https';

// The local gateway uses a self-signed certificate. Never do this against real hosts.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
process.removeAllListeners('warning');

const envFile = new URL('../.env', import.meta.url);
const dotenv = existsSync(envFile)
  ? Object.fromEntries(readFileSync(envFile, 'utf8').split('\n').filter((l) => l.includes('=')).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1).trim()]))
  : {};
const BASE = process.env.GATEWAY_URL || 'https://localhost:8443';
const HTTP_BASE = process.env.GATEWAY_HTTP_URL || 'http://localhost:8080';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || dotenv.ADMIN_PASSWORD || 'admin-dev-password';
const REPORTING_SECRET = process.env.REPORTING_CLIENT_SECRET || dotenv.REPORTING_CLIENT_SECRET || 'reporting-dev-secret';
const DIRECT_BACKEND = process.env.DIRECT_BACKEND_URL || 'http://127.0.0.1:4002';

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  \x1b[32m✔\x1b[0m ${name}`);
  } catch (err) {
    failed += 1;
    console.log(`  \x1b[31m✘ ${name}\x1b[0m\n      ${err.message}`);
  }
}
function expect(cond, msg) {
  if (!cond) throw new Error(msg);
}

async function call(method, path, { token, body, form, headers = {}, base = BASE } = {}) {
  const h = { ...headers };
  if (token) h.authorization = `Bearer ${token}`;
  let payload;
  if (form) {
    h['content-type'] = 'application/x-www-form-urlencoded';
    payload = new URLSearchParams(form).toString();
  } else if (body !== undefined) {
    h['content-type'] ??= 'application/json';
    payload = typeof body === 'string' ? body : JSON.stringify(body);
  }
  const res = await fetch(base + path, { method, headers: h, body: payload, redirect: 'manual' });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, headers: res.headers, body: json };
}

const passwordLogin = (username, password, scope) => call('POST', '/auth/oauth/token', {
  form: { grant_type: 'password', client_id: 'web-app', username, password, ...(scope ? { scope } : {}) },
});

const ctx = {};
const user2 = `bob_${randomBytes(3).toString('hex')}`;
const user3 = `eve_${randomBytes(3).toString('hex')}`;
const pw = `pw-${randomBytes(8).toString('hex')}`;

console.log(`\nE2E against ${BASE}\n`);

console.log('Transport & headers');
await test('HTTP redirects to HTTPS with 308', async () => {
  const r = await call('GET', '/api/products', { base: HTTP_BASE });
  expect(r.status === 308 && r.headers.get('location')?.startsWith('https://'), `got ${r.status} ${r.headers.get('location')}`);
});
await test('security headers (HSTS, nosniff, CSP, no x-powered-by)', async () => {
  const r = await call('GET', '/health');
  expect(r.headers.get('strict-transport-security')?.includes('max-age=31536000'), 'missing HSTS');
  expect(r.headers.get('x-content-type-options') === 'nosniff', 'missing nosniff');
  expect(r.headers.get('content-security-policy')?.includes("default-src 'none'"), 'missing CSP');
  expect(!r.headers.has('x-powered-by'), 'x-powered-by leaked');
  expect(r.headers.get('x-request-id'), 'missing request id');
});

console.log('Authentication (OAuth 2.0 / JWT)');
await test('protected route without token → 401 + WWW-Authenticate', async () => {
  const r = await call('GET', '/api/products');
  expect(r.status === 401 && r.headers.get('www-authenticate')?.startsWith('Bearer'), `got ${r.status}`);
});
await test('register a user (always gets role "user")', async () => {
  const r = await call('POST', '/auth/register', { body: { username: user2, password: pw } });
  expect(r.status === 201 && r.body.roles.join() === 'user', `got ${r.status} ${JSON.stringify(r.body)}`);
});
await test('register rejects weak password and mass-assigned roles', async () => {
  const weak = await call('POST', '/auth/register', { body: { username: user3, password: 'short' } });
  const mass = await call('POST', '/auth/register', { body: { username: user3, password: pw, roles: ['admin'] } });
  expect(weak.status === 400 && mass.status === 400, `got ${weak.status} / ${mass.status}`);
});
await test('password grant issues RS256 JWT + refresh token', async () => {
  const r = await passwordLogin(user2, pw);
  expect(r.status === 200 && r.body.access_token && r.body.refresh_token, `got ${r.status} ${JSON.stringify(r.body)}`);
  const header = JSON.parse(Buffer.from(r.body.access_token.split('.')[0], 'base64url'));
  expect(header.alg === 'RS256' && header.typ === 'at+jwt' && header.kid, `header ${JSON.stringify(header)}`);
  expect(r.headers.get('cache-control') === 'no-store', 'token response must be no-store');
  ctx.user = r.body;
});
await test('admin login', async () => {
  const r = await passwordLogin('admin', ADMIN_PASSWORD);
  expect(r.status === 200, `got ${r.status} ${JSON.stringify(r.body)}`);
  ctx.admin = r.body;
});
await test('wrong password → invalid_grant (generic message)', async () => {
  const r = await passwordLogin(user2, 'definitely-wrong');
  expect(r.status === 400 && r.body.error === 'invalid_grant', `got ${r.status}`);
});
await test('tampered JWT signature → 401', async () => {
  const [h, p] = ctx.user.access_token.split('.');
  const r = await call('GET', '/api/products', { token: `${h}.${p}.${randomBytes(256).toString('base64url')}` });
  expect(r.status === 401, `got ${r.status}`);
});
await test('alg=none token → 401', async () => {
  const p = ctx.user.access_token.split('.')[1];
  const none = `${Buffer.from('{"alg":"none","typ":"at+jwt"}').toString('base64url')}.${p}.`;
  const r = await call('GET', '/api/products', { token: none });
  expect(r.status === 401, `got ${r.status}`);
});
await test('GET /auth/me returns own profile', async () => {
  const r = await call('GET', '/auth/me', { token: ctx.user.access_token });
  expect(r.status === 200 && r.body.username === user2, `got ${r.status}`);
});

console.log('OAuth 2.0 authorization code + PKCE');
await test('code flow with S256 PKCE, then code replay is rejected', async () => {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const redirectUri = 'http://localhost:3000/callback';
  const a = await call('POST', '/auth/oauth/authorize', {
    body: {
      response_type: 'code', client_id: 'web-app', redirect_uri: redirectUri, scope: 'products:read orders:read',
      state: 'xyz', code_challenge: challenge, code_challenge_method: 'S256', username: user2, password: pw,
    },
  });
  expect(a.status === 200 && a.body.code, `authorize ${a.status} ${JSON.stringify(a.body)}`);
  const exchange = (v) => call('POST', '/auth/oauth/token', {
    form: { grant_type: 'authorization_code', client_id: 'web-app', code: a.body.code, redirect_uri: redirectUri, code_verifier: v },
  });
  const t = await exchange(verifier);
  expect(t.status === 200 && t.body.scope === 'orders:read products:read', `token ${t.status} ${JSON.stringify(t.body)}`);
  const replay = await exchange(verifier);
  expect(replay.status === 400 && replay.body.error === 'invalid_grant', `replay ${replay.status}`);
  ctx.narrow = t.body;
});
await test('narrow-scoped token cannot create orders (least privilege)', async () => {
  const r = await call('POST', '/api/orders', { token: ctx.narrow.access_token, body: { items: [{ productId: 1, quantity: 1 }], shippingAddress: '1 Test Street' } });
  expect(r.status === 403 && r.headers.get('www-authenticate')?.includes('insufficient_scope'), `got ${r.status}`);
});
await test('unregistered redirect_uri is refused', async () => {
  const r = await call('POST', '/auth/oauth/authorize', {
    body: { response_type: 'code', client_id: 'web-app', redirect_uri: 'https://evil.example/cb', code_challenge: 'x'.repeat(43), code_challenge_method: 'S256', username: user2, password: pw },
  });
  expect(r.status === 400, `got ${r.status}`);
});

console.log('Refresh token rotation & revocation');
await test('refresh rotates; reusing the old refresh token revokes the whole family', async () => {
  const first = ctx.user.refresh_token;
  const r1 = await call('POST', '/auth/oauth/token', { form: { grant_type: 'refresh_token', client_id: 'web-app', refresh_token: first } });
  expect(r1.status === 200 && r1.body.refresh_token !== first, `refresh ${r1.status}`);
  const reuse = await call('POST', '/auth/oauth/token', { form: { grant_type: 'refresh_token', client_id: 'web-app', refresh_token: first } });
  expect(reuse.status === 400, `reuse ${reuse.status}`);
  const r2 = await call('POST', '/auth/oauth/token', { form: { grant_type: 'refresh_token', client_id: 'web-app', refresh_token: r1.body.refresh_token } });
  expect(r2.status === 400, `family member still valid: ${r2.status}`);
  ctx.user = { ...ctx.user, access_token: r1.body.access_token };
});
await test('revoked access token is rejected immediately', async () => {
  const t = await passwordLogin(user2, pw);
  const before = await call('GET', '/api/orders', { token: t.body.access_token });
  const rev = await call('POST', '/auth/oauth/revoke', { form: { client_id: 'web-app', token: t.body.access_token } });
  const after = await call('GET', '/api/orders', { token: t.body.access_token });
  expect(before.status === 200 && rev.status === 200 && after.status === 401, `${before.status} → ${rev.status} → ${after.status}`);
});

console.log('RBAC');
await test('user can read products but not write them', async () => {
  const read = await call('GET', '/api/products', { token: ctx.user.access_token });
  const write = await call('POST', '/api/products', { token: ctx.user.access_token, body: { sku: 'HACK-1', name: 'x', priceCents: 1, stock: 1 } });
  expect(read.status === 200 && write.status === 403, `read ${read.status}, write ${write.status}`);
});
await test('user cannot reach admin endpoints', async () => {
  const statuses = await Promise.all(['/admin/users', '/admin/logs', '/admin/metrics', '/health/services'].map(async (p) => (await call('GET', p, { token: ctx.user.access_token })).status));
  expect(statuses.every((s) => s === 403), `got ${statuses}`);
});
await test('spoofed identity headers are ignored', async () => {
  const r = await call('GET', '/admin/users', {
    token: ctx.user.access_token,
    headers: { 'x-user-roles': 'admin', 'x-user-scopes': 'users:read', 'x-user-id': 'someone' },
  });
  expect(r.status === 403, `got ${r.status}`);
});
await test('admin can list users', async () => {
  const r = await call('GET', '/admin/users', { token: ctx.admin.access_token });
  expect(r.status === 200 && r.body.items.length >= 2, `got ${r.status}`);
});

console.log('Caching');
await test('GET is cached (MISS → HIT), admin write invalidates it', async () => {
  const path = `/api/products?limit=5&q=${randomBytes(2).toString('hex')}`;
  const a = await call('GET', path, { token: ctx.user.access_token });
  const b = await call('GET', path, { token: ctx.user.access_token });
  expect(a.headers.get('x-cache') === 'MISS' && b.headers.get('x-cache') === 'HIT', `${a.headers.get('x-cache')} → ${b.headers.get('x-cache')}`);
  const sku = `E2E-${randomBytes(3).toString('hex').toUpperCase()}`;
  const created = await call('POST', '/api/products', { token: ctx.admin.access_token, body: { sku, name: 'E2E product', priceCents: 1234, stock: 5 } });
  expect(created.status === 201, `create ${created.status} ${JSON.stringify(created.body)}`);
  ctx.productId = created.body.id;
  const c = await call('GET', path, { token: ctx.user.access_token });
  expect(c.headers.get('x-cache') === 'MISS', `after write: ${c.headers.get('x-cache')}`);
});
await test('Cache-Control: no-cache bypasses the cache', async () => {
  const r = await call('GET', '/api/products', { token: ctx.user.access_token, headers: { 'cache-control': 'no-cache' } });
  expect(r.headers.get('x-cache') === 'BYPASS', `got ${r.headers.get('x-cache')}`);
});

console.log('Orders, service-to-service calls & encryption');
await test('user creates an order (prices come from product-service)', async () => {
  const r = await call('POST', '/api/orders', {
    token: ctx.user.access_token,
    body: { items: [{ productId: ctx.productId, quantity: 2 }, { productId: 1, quantity: 1 }], shippingAddress: '221B Baker Street' },
  });
  expect(r.status === 201 && r.body.totalCents > 2468 && r.body.shippingAddress === '221B Baker Street', `got ${r.status} ${JSON.stringify(r.body)}`);
  ctx.orderId = r.body.id;
});
await test('client-supplied price fields are rejected', async () => {
  const r = await call('POST', '/api/orders', {
    token: ctx.user.access_token, body: { items: [{ productId: 1, quantity: 1, unitPriceCents: 1 }], shippingAddress: 'Somewhere 1' },
  });
  expect(r.status === 400, `got ${r.status}`);
});
await test("another user cannot read someone else's order (404, not 403)", async () => {
  await call('POST', '/auth/register', { body: { username: user3, password: pw } });
  const other = await passwordLogin(user3, pw);
  const r = await call('GET', `/api/orders/${ctx.orderId}`, { token: other.body.access_token });
  expect(r.status === 404, `got ${r.status}`);
});
await test('client_credentials: reporting-service reads all orders, cannot write products', async () => {
  const basic = Buffer.from(`reporting-service:${REPORTING_SECRET}`).toString('base64');
  const t = await call('POST', '/auth/oauth/token', { form: { grant_type: 'client_credentials' }, headers: { authorization: `Basic ${basic}` } });
  expect(t.status === 200 && !t.body.refresh_token, `token ${t.status} ${JSON.stringify(t.body)}`);
  const all = await call('GET', '/api/orders?all=true', { token: t.body.access_token });
  expect(all.status === 200 && all.body.items.some((o) => o.id === ctx.orderId), `orders ${all.status}`);
  expect(all.body.items.every((o) => o.shippingAddress === undefined), 'bulk listing leaked PII');
  const write = await call('POST', '/api/products', { token: t.body.access_token, body: { sku: 'SVC-1', name: 'x', priceCents: 1, stock: 1 } });
  expect(write.status === 403, `write ${write.status}`);
});

console.log('Input & path hardening');
// fetch() normalises "../" away client-side, so send these raw.
const rawStatus = (path, token) => new Promise((resolve, reject) => {
  const u = new URL(BASE);
  https.get({ host: u.hostname, port: u.port, path, rejectUnauthorized: false, headers: { authorization: `Bearer ${token}` } }, (res) => {
    res.resume();
    resolve(res.statusCode);
  }).on('error', reject);
});
await test('path traversal is blocked', async () => {
  const statuses = await Promise.all(['/api/products/../orders', '/api/products/..%2F..%2Fusers', '/api/products/%2e%2e/x', '/api//products', '/admin/../api/orders']
    .map((p) => rawStatus(p, ctx.admin.access_token)));
  expect(statuses.every((s) => s === 400), `got ${statuses}`);
});
await test('non-JSON body → 415, oversized body → 413', async () => {
  const xml = await call('POST', '/api/orders', { token: ctx.user.access_token, headers: { 'content-type': 'text/xml' }, body: '<a/>' });
  const big = await call('POST', '/api/orders', { token: ctx.user.access_token, body: { shippingAddress: 'x'.repeat(200_000), items: [] } });
  expect(xml.status === 415 && big.status === 413, `got ${xml.status} / ${big.status}`);
});
await test('unknown route → 404, disallowed method → 403 (default deny)', async () => {
  const a = await call('GET', '/nope', { token: ctx.admin.access_token });
  const b = await call('DELETE', '/api/orders/x', { token: ctx.admin.access_token });
  expect(a.status === 404 && b.status === 403, `got ${a.status} / ${b.status}`);
});
await test('backend rejects requests that bypass the gateway (unsigned)', async () => {
  let r;
  try {
    r = await fetch(`${DIRECT_BACKEND}/products`, { headers: { 'x-user-id': 'x', 'x-user-scopes': 'products:read' }, signal: AbortSignal.timeout(2000) });
  } catch {
    console.log('      (backend not reachable from host, as intended in docker compose; skipped)');
    return;
  }
  expect(r.status === 401, `got ${r.status}`);
});
await test('CORS: allowed origin gets headers, unknown origin preflight is refused', async () => {
  const ok = await call('OPTIONS', '/api/products', { headers: { origin: 'http://localhost:3000', 'access-control-request-method': 'GET' } });
  const bad = await call('OPTIONS', '/api/products', { headers: { origin: 'https://evil.example', 'access-control-request-method': 'GET' } });
  expect(ok.status === 204 && ok.headers.get('access-control-allow-origin') === 'http://localhost:3000' && bad.status === 403, `got ${ok.status} / ${bad.status}`);
});

console.log('Observability');
await test('health: liveness, readiness and aggregated backend status', async () => {
  const live = await call('GET', '/health');
  const ready = await call('GET', '/ready');
  const all = await call('GET', '/health/services', { token: ctx.admin.access_token });
  expect(live.status === 200 && ready.status === 200, `live ${live.status} ready ${ready.status}`);
  expect(all.status === 200 && ['auth', 'products', 'orders', 'logs'].every((s) => all.body.checks[s]?.status === 'ok'), JSON.stringify(all.body));
});
await test('centralized logs: one request id traced across gateway, order- and product-service', async () => {
  const r = await call('POST', '/api/orders', { token: ctx.user.access_token, body: { items: [{ productId: 2, quantity: 1 }], shippingAddress: '1 Trace Lane' } });
  const rid = r.headers.get('x-request-id');
  await new Promise((res) => setTimeout(res, 3000)); // loggers ship every 2s
  const logs = await call('GET', `/admin/logs?requestId=${rid}`, { token: ctx.admin.access_token });
  const services = new Set(logs.body.items?.map((l) => l.service));
  expect(['gateway', 'order-service', 'product-service'].every((s) => services.has(s)), `services seen: ${[...services]}`);
  expect(!JSON.stringify(logs.body).includes('1 Trace Lane'), 'PII leaked into logs');
});
await test('metrics endpoint (admin)', async () => {
  const m = await call('GET', '/admin/metrics', { token: ctx.admin.access_token });
  expect(m.status === 200 && m.body.requests > 0 && m.body.cache.hit > 0, `got ${m.status}`);
});

console.log('Rate limiting');
await test('brute-force on the token endpoint is throttled with 429 + Retry-After', async () => {
  const results = [];
  for (let i = 0; i < 25; i += 1) results.push(await passwordLogin(`ghost_${i}`, 'wrong-password'));
  const limited = results.filter((r) => r.status === 429);
  expect(limited.length > 0, `no 429 in ${results.map((r) => r.status)}`);
  expect(limited[0].headers.get('retry-after') && limited[0].headers.get('ratelimit-limit'), 'missing rate limit headers');
});

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
