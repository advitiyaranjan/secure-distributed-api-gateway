// HTTP plumbing shared by every service: request IDs, access logs, errors,
// health/readiness probes and graceful shutdown.
import { randomUUID } from 'node:crypto';

export class HttpError extends Error {
  /** `expose` defaults to true for 4xx; set it for 5xx messages that are safe to show (e.g. gateway errors). */
  constructor(status, message, { code, headers, details, expose } = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.headers = headers;
    this.details = details;
    this.expose = expose ?? status < 500;
  }
}

const REQUEST_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;

/** Reuses a well-formed incoming X-Request-Id (for cross-service correlation), else mints one. */
export function requestId() {
  return (req, res, next) => {
    const incoming = req.headers['x-request-id'];
    req.id = typeof incoming === 'string' && REQUEST_ID_RE.test(incoming) ? incoming : randomUUID();
    res.setHeader('x-request-id', req.id);
    next();
  };
}

export function accessLog(logger, { skip = ['/health', '/ready'] } = {}) {
  return (req, res, next) => {
    const start = process.hrtime.bigint();
    res.on('finish', () => {
      if (skip.includes(req.path)) return;
      const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
      const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
      logger[level]('request completed', {
        requestId: req.id,
        method: req.method,
        path: req.path,
        status: res.statusCode,
        durationMs: Math.round(durationMs * 100) / 100,
        userId: req.identity?.sub,
        ip: req.ip,
      });
    });
    next();
  };
}

export function notFound() {
  return (req, res) => res.status(404).json({ error: 'not_found', message: 'Resource not found' });
}

/** Final error handler. Never leaks stack traces or internal messages for 5xx. */
export function errorHandler(logger) {
  // eslint-disable-next-line no-unused-vars
  return (err, req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const expose = status < 500 || (err instanceof HttpError && err.expose);
    if (status >= 500 && !expose) logger.error('unhandled error', { requestId: req.id, path: req.path, err });
    if (res.headersSent) return res.end();
    for (const [k, v] of Object.entries(err.headers ?? {})) res.setHeader(k, v);
    const body = {
      error: (typeof err.code === 'string' && err instanceof HttpError && err.code)
        || (status === 413 ? 'payload_too_large' : status >= 500 ? 'internal_error' : 'bad_request'),
      message: expose ? err.message : 'Internal server error',
      requestId: req.id,
    };
    if (err.details && status < 500) body.details = err.details;
    res.status(status).json(body);
  };
}

/**
 * /health  - liveness: the process is up and serving.
 * /ready   - readiness: dependencies (DB, Redis, upstreams) are reachable. Docker
 *            health checks and compose `depends_on: service_healthy` use this.
 */
export function registerHealth(app, { service, checks = {}, timeoutMs = 2000 }) {
  app.get('/health', (req, res) => {
    res.json({ status: 'ok', service, uptimeSeconds: Math.round(process.uptime()) });
  });
  app.get('/ready', async (req, res) => {
    const results = await runChecks(checks, timeoutMs);
    const ok = Object.values(results).every((r) => r.status === 'ok');
    res.status(ok ? 200 : 503).json({ status: ok ? 'ok' : 'degraded', service, checks: results });
  });
}

export async function runChecks(checks, timeoutMs = 2000) {
  const entries = await Promise.all(Object.entries(checks).map(async ([name, fn]) => {
    const start = Date.now();
    try {
      await Promise.race([
        fn(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), timeoutMs).unref()),
      ]);
      return [name, { status: 'ok', latencyMs: Date.now() - start }];
    } catch (err) {
      return [name, { status: 'fail', error: err.message, latencyMs: Date.now() - start }];
    }
  }));
  return Object.fromEntries(entries);
}

export function gracefulShutdown({ servers, logger, cleanup = async () => {}, timeoutMs = 10_000 }) {
  let stopping = false;
  const stop = async (signal) => {
    if (stopping) return;
    stopping = true;
    logger.info('shutting down', { signal });
    setTimeout(() => process.exit(1), timeoutMs).unref();
    await Promise.all(servers.map((s) => new Promise((resolve) => s.close(resolve))));
    try {
      await cleanup();
    } finally {
      await logger.close?.();
      process.exit(0);
    }
  };
  process.on('SIGTERM', () => stop('SIGTERM'));
  process.on('SIGINT', () => stop('SIGINT'));
}
