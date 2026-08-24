// Gateway request pipeline:
//
//   path safety → route match → authenticate (JWT) → rate limit → authorize (RBAC)
//   → read & validate body → cache lookup → forward (signed) → cache store / invalidate
//
// Authentication runs before rate limiting so limits can be per user, but its
// failure is only reported after the limiter, so floods of bad tokens are throttled too.
import { performance } from 'node:perf_hooks';
import express from 'express';
import helmet from 'helmet';
import { HttpError, accessLog, errorHandler, requestId, runChecks } from '../../../shared/http.js';
import { isCacheableResponse } from './cache.js';
import { UpstreamError, copyResponseHeaders, forward } from './proxy.js';
import { setRateLimitHeaders } from './rateLimiter.js';
import { authorize, findPolicy, matchRoute } from './routes.js';

const BODY_CONTENT_TYPES = new Set(['application/json', 'application/x-www-form-urlencoded']);
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export function createGatewayApp({ config, redis, logger, authenticator, limiter, cache, metrics, routes, breakers }) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);
  app.set('etag', false);

  app.use(helmet({
    contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
    strictTransportSecurity: { maxAge: 31_536_000, includeSubDomains: true },
    referrerPolicy: { policy: 'no-referrer' },
  }));
  app.use(requestId());
  app.use(accessLog(logger));
  app.use(cors(config.corsOrigins));

  const rawBody = express.raw({ type: () => true, limit: config.bodyLimit });
  const readBody = (req, res) => new Promise((resolve, reject) => {
    rawBody(req, res, (err) => (err ? reject(err) : resolve(Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0))));
  });

  // ---- gateway-owned endpoints -------------------------------------------------

  const readinessChecks = {
    redis: () => redis.ping(),
    authKeys: async () => {
      const r = await fetch(config.jwksUrl, { signal: AbortSignal.timeout(1500) });
      if (!r.ok) throw new Error(`JWKS status ${r.status}`);
    },
  };
  app.get('/health', (req, res) => res.json({ status: 'ok', service: 'gateway', uptimeSeconds: Math.round(process.uptime()) }));
  app.get('/ready', async (req, res) => {
    const checks = await runChecks(readinessChecks);
    const ok = Object.values(checks).every((c) => c.status === 'ok');
    res.status(ok ? 200 : 503).json({ status: ok ? 'ok' : 'degraded', service: 'gateway', checks });
  });

  const adminOnly = async (req) => {
    const authz = req.headers.authorization;
    const auth = await authenticator.authenticate(authz);
    if (auth.error) throw new HttpError(auth.status, auth.error, { code: 'invalid_token' });
    const decision = authorize({ roles: ['admin'], scopes: ['metrics:read'] }, auth.identity);
    if (!decision.allow) throw new HttpError(decision.status, decision.reason, { code: 'forbidden' });
    req.identity = auth.identity;
  };

  // Aggregated readiness of every backend, for operators.
  app.get('/health/services', async (req, res) => {
    await adminOnly(req);
    const upstreams = Object.fromEntries(Object.entries(config.upstreams).map(([name, url]) => [name, async () => {
      const r = await fetch(new URL('/ready', url), { signal: AbortSignal.timeout(2000) });
      if (!r.ok) throw new Error(`status ${r.status}`);
    }]));
    const checks = await runChecks({ ...readinessChecks, ...upstreams }, 2500);
    const ok = Object.values(checks).every((c) => c.status === 'ok');
    res.status(ok ? 200 : 503).json({ status: ok ? 'ok' : 'degraded', checks });
  });

  app.get('/admin/metrics', async (req, res) => {
    await adminOnly(req);
    res.set('Cache-Control', 'no-store').json(metrics.snapshot(breakers));
  });

  // ---- proxied routes -----------------------------------------------------------

  app.use(async (req, res) => {
    const started = performance.now();
    let routeName = 'unmatched';
    res.on('finish', () => metrics.observe(routeName, res.statusCode, performance.now() - started));

    assertSafePath(req.path);
    const match = matchRoute(routes, req.path);
    if (!match) throw new HttpError(404, 'No route for this path', { code: 'not_found' });
    const { route, subPath } = match;
    routeName = route.name;
    const policy = findPolicy(route, req.method, subPath);

    // 1. Authenticate. `Basic` credentials belong to the OAuth token endpoint, not to us.
    const authz = req.headers.authorization;
    const auth = authz && !/^Basic /i.test(authz) ? await authenticator.authenticate(authz) : {};
    const identity = auth.identity;
    req.identity = identity;

    // 2. Rate limit: per user when authenticated, otherwise per client IP.
    const tier = policy?.rateLimitTier ?? tierFor(identity);
    const subject = tier === 'auth' || !identity ? `ip:${req.ip}` : `sub:${identity.sub}`;
    const rl = await limiter.consume(`${tier}:${subject}`, config.rateLimits[tier]);
    setRateLimitHeaders(res, rl);
    if (!rl.allowed) {
      metrics.counters.rateLimited += 1;
      logger.warn('rate limit exceeded', { requestId: req.id, tier, subject, path: req.path });
      throw new HttpError(429, 'Too many requests, slow down', { code: 'rate_limited' });
    }

    // 3. Reject bad tokens (public endpoints just treat the caller as anonymous).
    if (auth.error && !policy?.public) {
      metrics.counters.authFailures += 1;
      throw new HttpError(auth.status, auth.error, {
        code: auth.status === 401 ? 'invalid_token' : 'auth_unavailable',
        expose: true,
        headers: auth.status === 401 ? { 'WWW-Authenticate': `Bearer realm="sdag", error="invalid_token"` } : {},
      });
    }

    // 4. Authorize (RBAC + scopes).
    const decision = authorize(policy, identity);
    if (!decision.allow) {
      if (decision.status === 401) metrics.counters.authFailures += 1;
      else metrics.counters.forbidden += 1;
      logger.warn('access denied', { requestId: req.id, sub: identity?.sub, method: req.method, path: req.path, reason: decision.reason });
      const challenge = decision.insufficientScope
        ? `Bearer realm="sdag", error="insufficient_scope", scope="${decision.insufficientScope.join(' ')}"`
        : 'Bearer realm="sdag"';
      throw new HttpError(decision.status, decision.reason, {
        code: decision.status === 401 ? 'unauthorized' : 'forbidden',
        headers: { 'WWW-Authenticate': challenge },
      });
    }

    // 5. Body: size-limited by the raw parser, and only formats our services parse.
    const body = await readBody(req, res);
    if (body.length && req.method !== 'GET' && req.method !== 'HEAD') {
      const type = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
      if (!BODY_CONTENT_TYPES.has(type)) throw new HttpError(415, 'Content-Type must be application/json', { code: 'unsupported_media_type' });
    }

    const queryAt = req.originalUrl.indexOf('?');
    const search = queryAt >= 0 ? req.originalUrl.slice(queryAt) : '';
    const upstreamPath = `${route.rewrite}${subPath === '/' ? '' : subPath}`.replace(/^$/, '/') + search;

    // 6. Cache lookup (authorization already passed, so a hit is never served to someone who couldn't fetch it).
    const cacheable = Boolean(route.cache) && req.method === 'GET' && policy.cache !== false;
    const bypass = cacheable && /\bno-cache\b/i.test(req.headers['cache-control'] ?? '');
    if (cacheable && !bypass) {
      const hit = await cache.get(route.name, upstreamPath);
      if (hit) {
        metrics.counters.cache.hit += 1;
        res.set({ 'X-Cache': 'HIT', Age: String(Math.floor((Date.now() - hit.storedAt) / 1000)), 'Cache-Control': 'private, no-cache' });
        return res.status(hit.status).type(hit.contentType || 'application/json').send(hit.body);
      }
      metrics.counters.cache.miss += 1;
    } else if (bypass) {
      metrics.counters.cache.bypass += 1;
    }

    // 7. Forward.
    let upstream;
    try {
      upstream = await forward({
        req, route, upstreamPath, body, identity,
        secret: config.internalSecret,
        timeoutMs: config.upstreamTimeoutMs,
        breaker: breakers.get(route.target),
      });
    } catch (err) {
      if (!(err instanceof UpstreamError)) throw err;
      if (err.status === 503) metrics.counters.circuitOpenRejections += 1;
      else metrics.counters.upstreamErrors += 1;
      logger.error('upstream request failed', { requestId: req.id, route: route.name, status: err.status, reason: err.message });
      throw new HttpError(err.status, err.message, { code: 'upstream_error', expose: true });
    }

    // 8. Cache store / invalidate.
    if (cacheable && isCacheableResponse(upstream.status, upstream.headers)) {
      cache.set(route.name, upstreamPath, {
        status: upstream.status, contentType: upstream.headers.get('content-type'), body: upstream.body,
      }, route.cache.ttlSeconds);
    }
    if (route.cache && WRITE_METHODS.has(req.method) && upstream.status < 400) {
      const removed = await cache.invalidate(route.name);
      metrics.counters.cache.invalidations += 1;
      logger.info('cache invalidated', { requestId: req.id, route: route.name, entries: removed });
    }

    copyResponseHeaders(res, upstream.headers);
    if (cacheable) res.setHeader('X-Cache', bypass ? 'BYPASS' : 'MISS');
    // Responses carrying user data must not be stored by browsers or intermediaries.
    if (!upstream.headers.has('cache-control')) res.setHeader('Cache-Control', cacheable ? 'private, no-cache' : 'no-store');
    res.status(upstream.status).send(upstream.body);
  });

  app.use(errorHandler(logger));
  return app;
}

function tierFor(identity) {
  if (!identity) return 'anonymous';
  if (identity.roles.includes('admin')) return 'admin';
  if (identity.roles.includes('service')) return 'service';
  return 'user';
}

/**
 * Rejects dot-segments, encoded separators and double encoding before routing.
 * Without this, `/api/products/..%2F..%2Fusers` could match the products policy
 * but be normalised by the URL parser into a different upstream path.
 */
function assertSafePath(path) {
  let decoded;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    throw new HttpError(400, 'Malformed URL encoding', { code: 'bad_request' });
  }
  if (/(^|\/)\.\.?(\/|$)/.test(decoded) || /[\\\0%]/.test(decoded) || /%2f|%5c/i.test(path) || /\/\//.test(path)) {
    throw new HttpError(400, 'Invalid path', { code: 'bad_request' });
  }
}

function cors(allowedOrigins) {
  const allowed = new Set(allowedOrigins);
  return (req, res, next) => {
    const origin = req.headers.origin;
    if (!origin) return next();
    res.vary('Origin');
    if (!allowed.has(origin)) {
      return req.method === 'OPTIONS' ? res.status(403).json({ error: 'forbidden', message: 'Origin not allowed' }) : next();
    }
    res.set({
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Expose-Headers': 'X-Request-Id, X-Cache, RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset, Retry-After',
    });
    if (req.method === 'OPTIONS') {
      res.set({
        'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE',
        'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Request-Id, Cache-Control',
        'Access-Control-Max-Age': '600',
      });
      return res.status(204).end();
    }
    next();
  };
}
