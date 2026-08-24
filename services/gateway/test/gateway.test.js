import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import RedisMock from 'ioredis-mock';
import { createResponseCache } from '../src/cache.js';
import { CircuitBreaker } from '../src/circuitBreaker.js';
import { createRateLimiter } from '../src/rateLimiter.js';
import { authorize, buildRoutes, findPolicy, matchRoute } from '../src/routes.js';

const logger = { warn() {}, info() {}, error() {} };
const newRedis = () => new RedisMock({ keyPrefix: `t${Math.random()}:` });

describe('sliding window rate limiter', () => {
  it('allows up to the limit then rejects with Retry-After', async () => {
    const limiter = createRateLimiter({ redis: newRedis(), windowMs: 60_000, logger });
    const now = 60_000 * 1000; // start of a window
    for (let i = 0; i < 5; i += 1) assert.equal((await limiter.consume('k', 5, now)).allowed, true);
    const blocked = await limiter.consume('k', 5, now);
    assert.equal(blocked.allowed, false);
    assert.ok(blocked.retryAfterSeconds >= 1);
  });

  it('weights the previous window, smoothing the boundary burst', async () => {
    const limiter = createRateLimiter({ redis: newRedis(), windowMs: 60_000, logger });
    const start = 60_000 * 2000;
    for (let i = 0; i < 10; i += 1) await limiter.consume('k', 10, start + 59_000);
    // 25% into the next window, 75% of the previous 10 still count → only 2 more allowed.
    const next = start + 60_000 + 15_000;
    const results = [];
    for (let i = 0; i < 5; i += 1) results.push((await limiter.consume('k', 10, next)).allowed);
    assert.deepEqual(results, [true, true, false, false, false]);
  });

  it('rejected requests do not consume quota', async () => {
    const limiter = createRateLimiter({ redis: newRedis(), windowMs: 60_000, logger });
    const now = 60_000 * 3000;
    await limiter.consume('k', 2, now);
    await limiter.consume('k', 2, now);
    for (let i = 0; i < 10; i += 1) assert.equal((await limiter.consume('k', 2, now)).allowed, false);
    // Halfway through the next window: 2 * 0.5 + 1 = 2 → allowed. Had the 10 rejections
    // counted, it would be 12 * 0.5 + 1 = 7 → blocked.
    assert.equal((await limiter.consume('k', 2, now + 60_000 + 30_000)).allowed, true);
  });

  it('fails open (configurable) when Redis is down', async () => {
    const broken = { multi: () => ({ incr() { return this; }, pexpire() { return this; }, get() { return this; }, exec: async () => { throw new Error('down'); } }) };
    assert.equal((await createRateLimiter({ redis: broken, logger }).consume('k', 1)).allowed, true);
    assert.equal((await createRateLimiter({ redis: broken, logger, failOpen: false }).consume('k', 1)).allowed, false);
  });
});

describe('response cache', () => {
  it('stores, returns and invalidates per route', async () => {
    const cache = createResponseCache({ redis: newRedis(), logger });
    await cache.set('products', '/products?a=1', { status: 200, contentType: 'application/json', body: Buffer.from('{"x":1}') }, 60);
    await cache.set('products', '/products?a=2', { status: 200, contentType: 'application/json', body: Buffer.from('{"x":2}') }, 60);
    assert.equal((await cache.get('products', '/products?a=1')).body.toString(), '{"x":1}');
    assert.equal(await cache.invalidate('products'), 2);
    assert.equal(await cache.get('products', '/products?a=1'), null);
  });
});

describe('circuit breaker', () => {
  it('opens after N failures, half-opens after the timeout, closes on success', () => {
    const b = new CircuitBreaker({ failureThreshold: 3, resetTimeoutMs: 1000 });
    for (let i = 0; i < 3; i += 1) b.onFailure(0);
    assert.equal(b.state, 'open');
    assert.equal(b.canRequest(500), false);
    assert.equal(b.canRequest(1000), true); // the single trial
    assert.equal(b.canRequest(1000), false); // others still blocked
    b.onSuccess();
    assert.equal(b.state, 'closed');
  });
});

describe('route policies (RBAC)', () => {
  const routes = buildRoutes({ auth: 'http://a', products: 'http://p', orders: 'http://o', logs: 'http://l' });
  const user = { sub: 'u', roles: ['user'], scopes: ['products:read', 'orders:read', 'orders:write'] };
  const admin = { sub: 'a', roles: ['admin'], scopes: ['products:read', 'products:write', 'users:read', 'logs:read'] };
  const decide = (method, path, identity) => {
    const { route, subPath } = matchRoute(routes, path);
    return authorize(findPolicy(route, method, subPath), identity);
  };

  it('requires authentication on protected routes', () => {
    assert.equal(decide('GET', '/api/products', undefined).status, 401);
    assert.equal(decide('POST', '/auth/oauth/token', undefined).allow, true);
  });
  it('enforces roles and scopes', () => {
    assert.equal(decide('GET', '/api/products', user).allow, true);
    assert.equal(decide('POST', '/api/products', user).status, 403);
    assert.equal(decide('POST', '/api/products', admin).allow, true);
    assert.equal(decide('GET', '/admin/users', user).status, 403);
    assert.equal(decide('GET', '/admin/logs', admin).allow, true);
  });
  it('denies by default when no policy matches', () => {
    assert.equal(decide('DELETE', '/api/orders/1', admin).status, 403);
    assert.equal(decide('GET', '/auth/users', admin).status, 403); // internal auth paths not exposed
  });
  it('does not match prefixes partially', () => {
    assert.equal(matchRoute(routes, '/api/productsX'), null);
  });
});
