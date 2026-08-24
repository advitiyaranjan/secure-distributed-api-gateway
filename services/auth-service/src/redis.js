import Redis from 'ioredis';

/** REDIS_URL=mock uses an in-process fake (local dev/tests without a Redis server). */
export async function createRedis(url, logger) {
  if (url === 'mock') {
    const { default: RedisMock } = await import('ioredis-mock');
    return new RedisMock();
  }
  const redis = new Redis(url, { maxRetriesPerRequest: 2, enableOfflineQueue: false, lazyConnect: true });
  redis.on('error', (err) => logger.warn('redis error', { err: err.message }));
  await redis.connect().catch((err) => logger.warn('redis not reachable yet', { err: err.message }));
  return redis;
}
