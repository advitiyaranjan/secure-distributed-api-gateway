import express from 'express';
import { captureRawBody, requireInternal } from '../../../shared/internal-auth.js';
import { accessLog, errorHandler, notFound, registerHealth, requestId } from '../../../shared/http.js';
import { createLogger } from '../../../shared/logger.js';
import { ALL_SCOPES } from '../../../shared/rbac.js';
import { openDatabase } from './db.js';
import { loadSigningKey } from './keys.js';
import { oauthErrorHandler, oauthRouter } from './oauth.js';
import { createRedis } from './redis.js';
import { createRepo } from './repo.js';
import { createTokenService } from './tokens.js';
import { usersRouter } from './users.js';

const SERVICE = 'auth-service';

export async function start(env = process.env) {
  const logger = createLogger({
    service: SERVICE, level: env.LOG_LEVEL, collectorUrl: env.LOG_COLLECTOR_URL, internalSecret: env.INTERNAL_SECRET,
  });
  const config = {
    port: Number(env.PORT || 4001),
    issuer: env.JWT_ISSUER || 'https://auth.sdag.local',
    audience: env.JWT_AUDIENCE || 'sdag-api',
    publicBaseUrl: env.PUBLIC_BASE_URL || 'https://localhost:8443/auth',
    accessTtl: Number(env.ACCESS_TOKEN_TTL || 900),
    refreshTtl: Number(env.REFRESH_TOKEN_TTL || 7 * 24 * 3600),
  };

  const db = openDatabase(env.DB_PATH || './data/auth.db');
  const redis = await createRedis(env.REDIS_URL || 'redis://localhost:6379', logger);
  config.signingKey = await loadSigningKey({ keyDir: env.KEY_DIR ?? './data/keys', logger });
  const repo = createRepo(db);
  const tokens = createTokenService({ db, redis, signingKey: config.signingKey, ...config, logger });

  await seed(repo, env, logger);

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', false);
  app.use(requestId());
  app.use(accessLog(logger));
  registerHealth(app, {
    service: SERVICE,
    checks: {
      database: () => db.prepare('SELECT 1').get(),
      redis: () => redis.ping(),
    },
  });
  app.use(express.json({ limit: '32kb', verify: captureRawBody }));
  app.use(express.urlencoded({ extended: false, limit: '32kb', verify: captureRawBody }));
  // JWKS + metadata are public so the gateway (and any resource server) can fetch them.
  app.use(requireInternal({ secret: env.INTERNAL_SECRET, logger, exempt: ['/.well-known'] }));
  app.use(oauthRouter({ repo, tokens, redis, logger, config }));
  app.use(usersRouter({ repo, logger }));
  app.use(notFound());
  app.use(oauthErrorHandler());
  app.use(errorHandler(logger));

  const server = app.listen(config.port, () => logger.info('listening', { port: config.port, kid: config.signingKey.kid }));
  const close = async () => {
    tokens.close();
    redis.disconnect();
    db.close();
  };
  return { app, server, logger, close };
}

async function seed(repo, env, logger) {
  const ensureUser = async (username, password, roles) => {
    if (!password) return logger.warn(`no password configured for seed user "${username}", skipping`);
    if (!repo.findUserByName(username)) {
      await repo.createUser({ username, password, roles });
      logger.info('seeded user', { username, roles });
    }
  };
  await ensureUser(env.ADMIN_USERNAME || 'admin', env.ADMIN_PASSWORD, ['admin']);
  await ensureUser('alice', env.DEMO_USER_PASSWORD, ['user']);

  // First-party SPA/CLI: public client, so it must use PKCE (no secret to keep).
  await repo.upsertClient({
    clientId: 'web-app',
    name: 'SDAG Web App',
    type: 'public',
    grantTypes: ['authorization_code', 'refresh_token', ...(env.ENABLE_PASSWORD_GRANT === 'false' ? [] : ['password'])],
    scopes: ALL_SCOPES,
    redirectUris: (env.WEB_APP_REDIRECT_URIS || 'http://localhost:3000/callback').split(','),
  });
  // Machine client for back-office jobs: read-only reporting across all orders.
  if (env.REPORTING_CLIENT_SECRET) {
    await repo.upsertClient({
      clientId: 'reporting-service',
      name: 'Reporting Service',
      type: 'confidential',
      secret: env.REPORTING_CLIENT_SECRET,
      grantTypes: ['client_credentials'],
      scopes: ['products:read', 'orders:read', 'orders:read:all'],
    });
  }
}
