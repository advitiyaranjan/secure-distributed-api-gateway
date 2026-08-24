// Distributed rate limiting with the sliding-window-counter algorithm.
//
// Each client gets one Redis counter per fixed window. The effective count is
//     previousWindow * (1 - elapsedFractionOfCurrentWindow) + currentWindow
// which smooths out the burst-at-the-boundary problem of plain fixed windows while
// using O(1) memory per client (a sliding *log* would store every timestamp).
// Because the state lives in Redis, the limit holds across all gateway replicas.

export function createRateLimiter({ redis, windowMs = 60_000, prefix = 'rl', failOpen = true, logger }) {
  async function consume(key, limit, now = Date.now()) {
    const window = Math.floor(now / windowMs);
    const elapsed = (now % windowMs) / windowMs;
    const currentKey = `${prefix}:${key}:${window}`;
    const previousKey = `${prefix}:${key}:${window - 1}`;
    const resetSeconds = Math.ceil((windowMs - (now % windowMs)) / 1000);

    let current;
    let previous;
    try {
      const results = await redis.multi().incr(currentKey).pexpire(currentKey, windowMs * 2).get(previousKey).exec();
      const failed = results.find(([err]) => err);
      if (failed) throw failed[0];
      current = Number(results[0][1]);
      previous = Number(results[2][1] ?? 0);
    } catch (err) {
      logger?.warn('rate limiter unavailable', { err: err.message, failOpen });
      // Fail open keeps the API up if Redis dies; fail closed protects backends instead.
      return { allowed: failOpen, limit, remaining: failOpen ? limit : 0, resetSeconds, retryAfterSeconds: 1, degraded: true };
    }

    const estimated = previous * (1 - elapsed) + current;
    if (estimated <= limit) {
      return { allowed: true, limit, remaining: Math.max(0, Math.floor(limit - estimated)), resetSeconds, retryAfterSeconds: 0 };
    }

    // Rejected requests don't consume quota, so a client that backs off recovers on schedule.
    await redis.decr(currentKey).catch(() => {});
    current -= 1;
    // Earliest moment the weighted count drops enough to admit one more request.
    let retryAfterSeconds = resetSeconds;
    if (previous > 0 && current + 1 <= limit) {
      const neededElapsed = 1 - (limit - current - 1) / previous;
      retryAfterSeconds = Math.max(1, Math.ceil(((neededElapsed - elapsed) * windowMs) / 1000));
    }
    return { allowed: false, limit, remaining: 0, resetSeconds, retryAfterSeconds };
  }

  return { consume };
}

export function setRateLimitHeaders(res, result) {
  res.setHeader('RateLimit-Limit', result.limit);
  res.setHeader('RateLimit-Remaining', result.remaining);
  res.setHeader('RateLimit-Reset', result.resetSeconds);
  if (!result.allowed) res.setHeader('Retry-After', result.retryAfterSeconds);
}
