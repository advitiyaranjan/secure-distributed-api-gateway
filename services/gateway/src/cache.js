// Redis-backed response cache for safe, caller-independent GET routes.
//
// Entries are indexed per route in a Redis SET so a successful write
// (POST/PUT/PATCH/DELETE) through the gateway can invalidate every cached page of
// that route at once. Cache failures degrade to a miss and never fail a request.
import { createHash } from 'node:crypto';

const MAX_ENTRY_BYTES = 256 * 1024;

export function createResponseCache({ redis, prefix = 'cache', logger }) {
  const indexKey = (route) => `${prefix}:index:${route}`;
  const entryKey = (route, url) => `${prefix}:${route}:${createHash('sha256').update(url).digest('hex')}`;

  async function get(route, url) {
    try {
      const raw = await redis.get(entryKey(route, url));
      if (!raw) return null;
      const entry = JSON.parse(raw);
      return { ...entry, body: Buffer.from(entry.body, 'base64') };
    } catch (err) {
      logger.warn('cache read failed', { err: err.message });
      return null;
    }
  }

  async function set(route, url, { status, contentType, body }, ttlSeconds) {
    if (body.length > MAX_ENTRY_BYTES) return false;
    const key = entryKey(route, url);
    const value = JSON.stringify({ status, contentType, body: body.toString('base64'), storedAt: Date.now() });
    try {
      await redis.multi()
        .set(key, value, 'EX', ttlSeconds)
        .sadd(indexKey(route), key)
        .expire(indexKey(route), ttlSeconds * 2)
        .exec();
      return true;
    } catch (err) {
      logger.warn('cache write failed', { err: err.message });
      return false;
    }
  }

  async function invalidate(route) {
    try {
      const keys = await redis.smembers(indexKey(route));
      if (keys.length) await redis.del(...keys, indexKey(route));
      return keys.length;
    } catch (err) {
      logger.warn('cache invalidation failed', { err: err.message });
      return 0;
    }
  }

  return { get, set, invalidate };
}

/** Honour the upstream's wishes: never cache private/no-store responses. */
export function isCacheableResponse(status, headers) {
  if (status !== 200) return false;
  const cc = headers.get('cache-control') ?? '';
  return !/\b(no-store|private)\b/i.test(cc) && !headers.has('set-cookie');
}
