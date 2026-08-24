// In-process counters and a latency histogram, exposed to admins at /admin/metrics.
const BUCKETS_MS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];

export function createMetrics() {
  const startedAt = new Date().toISOString();
  const counters = {
    requests: 0,
    byStatusClass: { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 },
    byRoute: {},
    cache: { hit: 0, miss: 0, bypass: 0, invalidations: 0 },
    rateLimited: 0,
    authFailures: 0,
    forbidden: 0,
    upstreamErrors: 0,
    circuitOpenRejections: 0,
  };
  const histogram = new Array(BUCKETS_MS.length + 1).fill(0);
  const samples = [];

  return {
    counters,
    observe(route, status, durationMs) {
      counters.requests += 1;
      counters.byStatusClass[`${Math.floor(status / 100)}xx`] = (counters.byStatusClass[`${Math.floor(status / 100)}xx`] ?? 0) + 1;
      counters.byRoute[route] = (counters.byRoute[route] ?? 0) + 1;
      const i = BUCKETS_MS.findIndex((b) => durationMs <= b);
      histogram[i === -1 ? BUCKETS_MS.length : i] += 1;
      samples.push(durationMs);
      if (samples.length > 10_000) samples.splice(0, samples.length - 10_000);
    },
    snapshot(breakers) {
      const sorted = [...samples].sort((a, b) => a - b);
      const pct = (p) => (sorted.length ? Math.round(sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))] * 100) / 100 : null);
      const lookups = counters.cache.hit + counters.cache.miss;
      return {
        startedAt,
        ...counters,
        cacheHitRatio: lookups ? Math.round((counters.cache.hit / lookups) * 1000) / 1000 : null,
        latencyMs: { p50: pct(50), p95: pct(95), p99: pct(99), sampleSize: sorted.length },
        latencyHistogram: Object.fromEntries([...BUCKETS_MS.map((b, i) => [`<=${b}ms`, histogram[i]]), ['>5000ms', histogram.at(-1)]]),
        circuits: Object.fromEntries([...breakers].map(([name, b]) => [name, b.state])),
        process: { rssMb: Math.round(process.memoryUsage().rss / 1048576), uptimeSeconds: Math.round(process.uptime()) },
      };
    },
  };
}
