// Load test: latency, throughput and behaviour under concurrency.
//
//   GATEWAY_URL=https://localhost:8443 ADMIN_PASSWORD=... node loadtest/run.js
//   options (env): DURATION=10 (seconds per scenario), CONNECTIONS=10,50,100
//
// Run the stack with docker-compose.loadtest.yml (or `RATE_LIMIT_MULTIPLIER=1000
// npm run dev`) so the per-user limiter doesn't cap throughput. Writes a Markdown
// report and raw JSON to loadtest/results/.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import autocannon from 'autocannon';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // local self-signed cert only
process.removeAllListeners('warning');

const envFile = new URL('../.env', import.meta.url);
const dotenv = existsSync(envFile)
  ? Object.fromEntries(readFileSync(envFile, 'utf8').split('\n').filter((l) => l.includes('=')).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1).trim()]))
  : {};
const BASE = process.env.GATEWAY_URL || 'https://localhost:8443';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || dotenv.ADMIN_PASSWORD || 'admin-dev-password';
const DURATION = Number(process.env.DURATION || 10);
const SWEEP = (process.env.CONNECTIONS || '10,50,100').split(',').map(Number);

async function getJson(path, init = {}) {
  const res = await fetch(BASE + path, init);
  return { status: res.status, body: await res.json().catch(() => null) };
}

const login = await getJson('/auth/oauth/token', {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ grant_type: 'password', client_id: 'web-app', username: 'admin', password: ADMIN_PASSWORD }),
});
if (login.status !== 200) {
  console.error('Login failed:', login.status, login.body);
  process.exit(1);
}
const auth = { authorization: `Bearer ${login.body.access_token}` };
const metrics = () => getJson('/admin/metrics', { headers: auth }).then((r) => r.body);
const dbQueries = () => getJson('/api/products/_stats', { headers: auth }).then((r) => r.body?.dbQueries ?? null);

function run(title, { path, ...opts }) {
  return new Promise((resolve, reject) => {
    const instance = autocannon({ url: BASE + path, duration: DURATION, connections: 50, ...opts }, (err, result) => (err ? reject(err) : resolve(result)));
    process.stdout.write(`  ${title} … `);
    instance.on('done', () => process.stdout.write('done\n'));
  });
}

function summarize(name, connections, r, extra = {}) {
  const statuses = Object.fromEntries(Object.entries(r.statusCodeStats ?? {}).map(([code, v]) => [code, v.count]));
  return {
    scenario: name,
    connections,
    requests: r.requests.total,
    rps: Math.round(r.requests.average),
    p50: r.latency.p50,
    p90: r.latency.p90,
    p99: r.latency.p99,
    max: r.latency.max,
    errors: r.errors + r.timeouts,
    statuses,
    ...extra,
  };
}

const results = [];
const productsPath = '/api/products?limit=20';
console.log(`\nLoad testing ${BASE} (${DURATION}s per run)\n`);

// 1. Baseline: TLS + gateway overhead only, no auth/upstream.
results.push(summarize('GET /health (baseline)', 50, await run('baseline /health', { path: '/health' })));

// 2. Cache effect at fixed concurrency, measuring DB queries hitting product-service.
let q0 = await dbQueries();
results.push(summarize('GET /api/products (cache bypass)', 50,
  await run('products, cache bypassed', { path: productsPath, headers: { ...auth, 'cache-control': 'no-cache' } }),
  { dbQueries: q0 === null ? null : (await dbQueries()) - q0 }));
q0 = await dbQueries();
results.push(summarize('GET /api/products (cached)', 50,
  await run('products, cached', { path: productsPath, headers: auth }),
  { dbQueries: q0 === null ? null : (await dbQueries()) - q0 }));

// 3. Concurrency sweep on the hot read path.
for (const c of SWEEP) {
  results.push(summarize(`GET /api/products (cached) @${c}`, c, await run(`products cached, ${c} connections`, { path: productsPath, headers: auth, connections: c })));
}

// 4. Write path: JWT + RBAC + body validation + order→product service call + AES-GCM + SQLite write.
results.push(summarize('POST /api/orders', 50, await run('create orders', {
  path: '/api/orders',
  method: 'POST',
  headers: { ...auth, 'content-type': 'application/json' },
  body: JSON.stringify({ items: [{ productId: 1, quantity: 1 }, { productId: 2, quantity: 2 }], shippingAddress: '1 Load Test Way' }),
})));

// 5. Abuse: credential stuffing on the token endpoint. The auth tier is NOT multiplied,
//    so nearly everything should be shed with 429 before reaching auth-service.
results.push(summarize('POST /auth/oauth/token (brute force)', 20, await run('token endpoint brute force', {
  path: '/auth/oauth/token',
  method: 'POST',
  connections: 20,
  duration: Math.min(DURATION, 5),
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: 'grant_type=password&client_id=web-app&username=attacker&password=guess',
})));

const m = await metrics();

// ---- report -----------------------------------------------------------------
const fmt = (v) => (v === null || v === undefined ? '–' : v);
const rows = results.map((r) => `| ${r.scenario} | ${r.connections} | ${r.requests} | ${r.rps} | ${r.p50} | ${r.p90} | ${r.p99} | ${r.max} | ${Object.entries(r.statuses).map(([k, v]) => `${k}:${v}`).join(' ')} | ${r.errors} | ${fmt(r.dbQueries)} |`);
const bypass = results[1];
const cached = results[2];
const brute = results.at(-1);
const shed = brute.statuses['429'] ?? 0;
const suspicious = results.filter((r) => r !== brute && Object.entries(r.statuses).some(([code, n]) => !code.startsWith('2') && n / r.requests > 0.01));
const warnings = suspicious.length
  ? `\n> **Warning:** unexpected non-2xx responses in: ${suspicious.map((r) => r.scenario).join('; ')}. Check rate limits (RATE_LIMIT_MULTIPLIER) and service health before trusting these numbers.\n`
  : '';

const report = `# Load test report

- Target: \`${BASE}\`
- Date: ${new Date().toISOString()}
- Duration per run: ${DURATION}s, Node ${process.version}

| Scenario | Conns | Requests | Req/s | p50 ms | p90 ms | p99 ms | max ms | Status codes | Errors | DB queries |
|---|---|---|---|---|---|---|---|---|---|---|
${rows.join('\n')}
${warnings}
## Findings

- **Caching:** cached reads served ${cached.rps} req/s at p99 ${cached.p99} ms vs ${bypass.rps} req/s at p99 ${bypass.p99} ms with the cache bypassed${bypass.dbQueries ? `; the cached run issued ${cached.dbQueries} product DB queries for ${cached.requests} requests (vs ${bypass.dbQueries} for ${bypass.requests} uncached)` : ''}.
- **Rate limiting:** ${shed} of ${brute.requests} brute-force token requests (${brute.requests ? Math.round((shed / brute.requests) * 100) : 0}%) were rejected with 429 at the gateway.
- **Gateway counters:** cache hit ratio ${fmt(m?.cacheHitRatio)}, rate-limited ${fmt(m?.rateLimited)}, upstream errors ${fmt(m?.upstreamErrors)}, gateway-side p99 ${fmt(m?.latencyMs?.p99)} ms over the last ${fmt(m?.latencyMs?.sampleSize)} requests.
`;

mkdirSync(new URL('./results/', import.meta.url), { recursive: true });
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
writeFileSync(new URL(`./results/report-${stamp}.md`, import.meta.url), report);
writeFileSync(new URL(`./results/raw-${stamp}.json`, import.meta.url), JSON.stringify({ results, gatewayMetrics: m }, null, 2));
console.log(`\n${report}\nSaved to loadtest/results/report-${stamp}.md`);
