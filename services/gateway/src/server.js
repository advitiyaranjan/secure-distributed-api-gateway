import http from 'node:http';
import https from 'node:https';
import { createLogger } from '../../../shared/logger.js';
import { createGatewayApp } from './app.js';
import { createAuthenticator } from './authenticator.js';
import { createResponseCache } from './cache.js';
import { CircuitBreaker } from './circuitBreaker.js';
import { createMetrics } from './metrics.js';
import { createRateLimiter } from './rateLimiter.js';
import { createRedis } from './redis.js';
import { buildRoutes } from './routes.js';
import { loadCertificate } from './tls.js';

function loadConfig(env) {
  if (!env.INTERNAL_SECRET || env.INTERNAL_SECRET.length < 32) {
    throw new Error('INTERNAL_SECRET must be set (at least 32 characters)');
  }
  const multiplier = Number(env.RATE_LIMIT_MULTIPLIER || 1);
  const perMinute = (name, fallback) => Math.max(1, Math.round(Number(env[`RATE_LIMIT_${name}`] || fallback) * multiplier));
  const upstreams = {
    auth: env.AUTH_SERVICE_URL || 'http://localhost:4001',
    products: env.PRODUCT_SERVICE_URL || 'http://localhost:4002',
    orders: env.ORDER_SERVICE_URL || 'http://localhost:4003',
    logs: env.LOG_COLLECTOR_URL || 'http://localhost:4004',
  };
  return {
    httpPort: Number(env.HTTP_PORT || 8080),
    httpsPort: Number(env.HTTPS_PORT || 8443),
    tlsEnabled: env.TLS_ENABLED !== 'false',
    publicHost: env.PUBLIC_HOSTNAME || 'localhost',
    publicHttpsPort: Number(env.PUBLIC_HTTPS_PORT || env.HTTPS_PORT || 8443),
    internalSecret: env.INTERNAL_SECRET,
    upstreams,
    jwksUrl: `${upstreams.auth}/.well-known/jwks.json`,
    issuer: env.JWT_ISSUER || 'https://auth.sdag.local',
    audience: env.JWT_AUDIENCE || 'sdag-api',
    trustProxy: env.TRUST_PROXY ? (Number.isNaN(Number(env.TRUST_PROXY)) ? env.TRUST_PROXY : Number(env.TRUST_PROXY)) : false,
    corsOrigins: (env.CORS_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean),
    bodyLimit: env.BODY_LIMIT || '100kb',
    upstreamTimeoutMs: Number(env.UPSTREAM_TIMEOUT_MS || 5000),
    // Requests per minute. The `auth` tier guards login/token endpoints (brute force)
    // and is intentionally exempt from RATE_LIMIT_MULTIPLIER.
    rateLimits: {
      anonymous: perMinute('ANONYMOUS', 60),
      user: perMinute('USER', 300),
      service: perMinute('SERVICE', 1200),
      admin: perMinute('ADMIN', 1200),
      auth: Math.max(1, Number(env.RATE_LIMIT_AUTH || 20)),
    },
    rateLimitFailOpen: env.RATE_LIMIT_FAIL_OPEN !== 'false',
    revocationFailOpen: env.REVOCATION_FAIL_OPEN === 'true',
    certDir: env.CERT_DIR || './data/certs',
  };
}

export async function start(env = process.env) {
  const logger = createLogger({
    service: 'gateway', level: env.LOG_LEVEL, collectorUrl: env.LOG_COLLECTOR_URL, internalSecret: env.INTERNAL_SECRET,
  });
  const config = loadConfig(env);
  const redis = await createRedis(env.REDIS_URL || 'redis://localhost:6379', logger);
  const routes = buildRoutes(config.upstreams);
  const breakers = new Map(Object.values(config.upstreams).map((url) => [url, new CircuitBreaker({ name: url, logger })]));

  const app = createGatewayApp({
    config,
    redis,
    logger,
    routes,
    breakers,
    metrics: createMetrics(),
    cache: createResponseCache({ redis, logger }),
    limiter: createRateLimiter({ redis, failOpen: config.rateLimitFailOpen, logger }),
    authenticator: createAuthenticator({
      jwksUrl: config.jwksUrl, issuer: config.issuer, audience: config.audience, redis, logger,
      revocationFailOpen: config.revocationFailOpen,
    }),
  });

  const servers = [];
  const harden = (server) => {
    // Slowloris protection: bound how long a client may take to send headers / a request.
    server.headersTimeout = 10_000;
    server.requestTimeout = 30_000;
    server.keepAliveTimeout = 5_000;
    servers.push(server);
    return server;
  };

  if (config.tlsEnabled) {
    const { cert, key, source } = await loadCertificate({
      certPath: env.TLS_CERT_PATH, keyPath: env.TLS_KEY_PATH, generatedDir: config.certDir, hostname: config.publicHost, logger,
    });
    harden(https.createServer({ cert, key, minVersion: 'TLSv1.2' }, app))
      .listen(config.httpsPort, () => logger.info('HTTPS listening', { port: config.httpsPort, cert: source }));

    // Plain HTTP only redirects to HTTPS (plus health probes for the container runtime).
    // The redirect target comes from config, never the Host header (no host-header injection).
    harden(http.createServer((req, res) => {
      if (req.url === '/health' || req.url === '/ready') return app(req, res);
      const location = `https://${config.publicHost}${config.publicHttpsPort === 443 ? '' : `:${config.publicHttpsPort}`}${req.url}`;
      res.writeHead(308, { Location: location, 'Content-Length': 0 }).end();
    })).listen(config.httpPort, () => logger.info('HTTP redirect listening', { port: config.httpPort }));
  } else {
    // TLS terminated upstream (e.g. by a cloud load balancer).
    harden(http.createServer(app)).listen(config.httpPort, () => logger.info('HTTP listening (TLS disabled)', { port: config.httpPort }));
  }

  logger.info('gateway configured', { upstreams: config.upstreams, rateLimits: config.rateLimits, routes: routes.map((r) => r.prefix) });
  return { app, servers, logger, close: async () => redis.disconnect() };
}
